package agent

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	proxyfake "github.com/ryanbekhen/armada/internal/proxy/fake"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
	"github.com/ryanbekhen/armada/internal/store"
)

func newAgent(t *testing.T) (*Agent, *fake.Driver) {
	t.Helper()
	d := fake.New()
	// Never probe real addresses from unit tests.
	ok := func(context.Context, string, string) error { return nil }
	return New(Config{NodeID: "n1", PrivateIP: "10.0.0.2", Driver: d, CPUMillis: 1000, MemoryBytes: 1 << 30, Check: ok}), d
}

func replica(id, image string, port int32) *armadav1.ReplicaSpec {
	return &armadav1.ReplicaSpec{
		Id: id, App: "web", Revision: "web--r1", Image: image, Port: port,
		Command: []string{"/bin/web"}, Args: []string{"--x"},
		Env:         []*armadav1.EnvVar{{Name: "A", Value: "1"}},
		MemoryBytes: 256 << 20, PidsLimit: 1024,
	}
}

func TestReconcileUnpublished(t *testing.T) {
	t.Parallel()
	d := fake.New()
	d.BridgeIPs = "10.120.0."
	ok := func(context.Context, string, string) error { return nil }
	a := New(Config{NodeID: "n1", PrivateIP: "10.0.0.2", Driver: d, Check: ok, Unpublished: true})
	a.setDesired([]*armadav1.ReplicaSpec{replica("web-r1-a", "nginx:1", 8080), replica("job-r1-a", "busybox", 0)}, nil)
	report, err := a.Reconcile(context.Background())
	if err != nil || len(report.Replicas) != 2 {
		t.Fatalf("%v %v", report, err)
	}
	// With the cluster network nothing is published on the private IP, and
	// replicas are reached at their own address (ADR 0025).
	got := map[string]string{}
	for _, r := range report.Replicas {
		got[r.Id] = r.Address
	}
	if !strings.HasPrefix(got["web-r1-a"], "10.120.0.") || !strings.HasSuffix(got["web-r1-a"], ":8080") || got["job-r1-a"] != "" {
		t.Errorf("addresses %v", got)
	}
	cs, _ := d.List(context.Background(), nil)
	for _, c := range cs {
		if spec, _ := d.Spec(c.ID); spec.Port != 0 || spec.HostIP != "" || c.HostPort != 0 {
			t.Errorf("%s published: %+v", c.Name, spec)
		}
	}
	// Every replica reports its container address, ingress or not: the
	// firewalls key on it (ADR 0026).
	for _, r := range report.Replicas {
		if !strings.HasPrefix(r.Ip, "10.120.0.") {
			t.Errorf("%s reported IP %q", r.Id, r.Ip)
		}
	}
	// A container that still has a published port (started before) keeps
	// being reported there.
	if got := a.state(t.Context(), replica("x", "nginx:1", 80), runtime.Container{State: runtime.StateRunning, IP: "10.120.0.9", HostIP: "10.0.0.2", HostPort: 21000}).Address; got != "10.0.0.2:21000" {
		t.Errorf("published container reported at %q", got)
	}
}

// recordingNet stands in for the cluster network.
type recordingNet struct {
	mu    sync.Mutex
	calls int
	local map[netip.Addr]string
}

func (n *recordingNet) Apply(_ context.Context, _ *armadav1.NetworkConfig, local map[netip.Addr]string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls++
	n.local = maps.Clone(local)
	return nil
}

// clientProxy is a proxy whose internal frontend checks callers.
type clientProxy struct {
	proxyfake.Driver
	mu      sync.Mutex
	clients map[netip.Addr]string
}

func (p *clientProxy) SetClients(_ context.Context, c map[netip.Addr]string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clients = maps.Clone(c)
	return nil
}

// The firewall, the DNS server, and the proxy learn a new container's
// address as soon as it starts, and the full list on every pass (ADR 0026).
func TestNetworkKnowsLocalContainers(t *testing.T) {
	t.Parallel()
	d := fake.New()
	d.BridgeIPs = "10.120.0."
	ok := func(context.Context, string, string) error { return nil }
	nw, dns, px := &recordingNet{}, &recordingDNS{}, &clientProxy{}
	a := New(Config{NodeID: "n1", PrivateIP: "10.0.0.2", Driver: d, Check: ok, Unpublished: true, Network: nw, DNS: dns, Proxy: px})
	a.setNetwork(&armadav1.NetworkConfig{Mode: "plain"})
	web := replica("web-r1-a", "nginx:1", 8080)
	api := replica("api-r1-a", "nginx:1", 8080)
	api.App = "api.shop"
	a.setDesired([]*armadav1.ReplicaSpec{web, api}, nil)
	report, err := a.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[netip.Addr]string{}
	for _, r := range report.Replicas {
		app := "web"
		if r.Id == "api-r1-a" {
			app = "api.shop"
		}
		want[netip.MustParseAddr(r.Ip)] = app
	}
	nw.mu.Lock()
	calls, local := nw.calls, nw.local
	nw.mu.Unlock()
	// Once for the starts, before the report, and once at the end of the pass.
	if calls != 2 || !maps.Equal(local, want) {
		t.Errorf("network applied %d times with %v, want 2 with %v", calls, local, want)
	}
	dns.mu.Lock()
	defer dns.mu.Unlock()
	if !maps.Equal(dns.clients, want) {
		t.Errorf("DNS clients = %v, want %v", dns.clients, want)
	}
	px.mu.Lock()
	defer px.mu.Unlock()
	if !maps.Equal(px.clients, want) {
		t.Errorf("proxy clients = %v, want %v", px.clients, want)
	}
}

func TestReconcileBeforeAssignmentIsNoop(t *testing.T) {
	t.Parallel()

	a, d := newAgent(t)
	d.Add(runtime.Container{ID: "old", Name: "armada-x", State: runtime.StateRunning, Labels: map[string]string{runtime.LabelManaged: "true", runtime.LabelReplica: "x"}})

	report, err := a.Reconcile(context.Background())
	if err != nil || report != nil {
		t.Fatalf("Reconcile() = %v, %v; want nil, nil", report, err)
	}
	if cs, _ := d.List(context.Background(), nil); len(cs) != 1 {
		t.Error("agent removed containers before receiving an assignment")
	}
}

func TestReconcileStartsAndAdopts(t *testing.T) {
	t.Parallel()

	a, d := newAgent(t)
	d.Digests = map[string]string{"nginx:1": "nginx@sha256:abc"}
	a.setDesired([]*armadav1.ReplicaSpec{replica("web-r1-a", "nginx:1", 80), replica("web-r1-b", "nginx:1", 80)}, nil)

	report, err := a.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Replicas) != 2 {
		t.Fatalf("report = %v", report)
	}
	for _, r := range report.Replicas {
		if r.State != store.ReplicaRunning || r.ImageDigest != "nginx@sha256:abc" || r.ContainerId == "" {
			t.Errorf("replica state = %v", r)
		}
		if r.Address == "" || r.Address[:9] != "10.0.0.2:" {
			t.Errorf("address = %q, want published on private IP", r.Address)
		}
	}
	cs, _ := d.List(context.Background(), nil)
	if len(cs) != 2 {
		t.Fatalf("containers = %d", len(cs))
	}
	spec, _ := d.Spec(cs[0].ID)
	if spec.HostIP != "10.0.0.2" || spec.Name != "armada-web-r1-a" || spec.Entrypoint[0] != "/bin/web" || spec.Cmd[0] != "--x" || spec.Env[0] != "A=1" {
		t.Errorf("container spec = %+v", spec)
	}
	if spec.Labels[runtime.LabelManaged] != "true" || spec.Labels[runtime.LabelApp] != "web" || spec.Labels[runtime.LabelSpecHash] == "" {
		t.Errorf("labels = %v", spec.Labels)
	}

	// A second pass adopts the existing containers instead of recreating them.
	pulls := len(d.Pulls)
	if _, err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	cs2, _ := d.List(context.Background(), nil)
	if len(cs2) != 2 || cs2[0].ID != cs[0].ID || len(d.Pulls) != pulls {
		t.Error("second reconcile recreated containers or pulled again")
	}

	// A fresh agent (e.g. after restart) adopts them too.
	b := New(Config{NodeID: "n1", PrivateIP: "10.0.0.2", Driver: d, CPUMillis: 1, MemoryBytes: 1})
	b.setDesired([]*armadav1.ReplicaSpec{replica("web-r1-a", "nginx:1", 80), replica("web-r1-b", "nginx:1", 80)}, nil)
	if _, err := b.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	cs3, _ := d.List(context.Background(), nil)
	if len(cs3) != 2 || cs3[0].ID != cs[0].ID {
		t.Error("restarted agent did not adopt containers")
	}
}

func TestReconcileImagePinningDoesNotRestart(t *testing.T) {
	t.Parallel()

	a, d := newAgent(t)
	a.setDesired([]*armadav1.ReplicaSpec{replica("web-r1-a", "nginx:1", 80)}, nil)
	if _, err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, _ := d.List(context.Background(), nil)

	a.setDesired([]*armadav1.ReplicaSpec{replica("web-r1-a", "nginx@sha256:abc", 80)}, nil)
	if _, err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, _ := d.List(context.Background(), nil)
	if after[0].ID != before[0].ID {
		t.Error("switching tag to pinned digest restarted the container")
	}
}

func TestReconcileRecreatesOnSpecChange(t *testing.T) {
	t.Parallel()

	a, d := newAgent(t)
	a.setDesired([]*armadav1.ReplicaSpec{replica("web-r1-a", "nginx:1", 80)}, nil)
	_, _ = a.Reconcile(context.Background())
	before, _ := d.List(context.Background(), nil)

	changed := replica("web-r1-a", "nginx:1", 80)
	changed.MemoryBytes = 512 << 20
	a.setDesired([]*armadav1.ReplicaSpec{changed}, nil)
	if _, err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, _ := d.List(context.Background(), nil)
	if len(after) != 1 || after[0].ID == before[0].ID {
		t.Errorf("container not recreated: before=%v after=%v", before, after)
	}
}

func TestReconcileRemovesUnwanted(t *testing.T) {
	t.Parallel()

	a, d := newAgent(t)
	managed := map[string]string{runtime.LabelManaged: "true"}
	d.Add(runtime.Container{ID: "stale", Name: "armada-stale", State: runtime.StateRunning, Labels: map[string]string{runtime.LabelManaged: "true", runtime.LabelReplica: "gone"}})
	a.setDesired([]*armadav1.ReplicaSpec{replica("web-r1-a", "nginx:1", 80)}, nil)
	_, _ = a.Reconcile(context.Background())
	// Duplicate container for the same replica (e.g. from a crash mid-create).
	cs, _ := d.List(context.Background(), managed)
	dup := cs[0]
	dup.ID, dup.Name = "dup", "armada-dup"
	d.Add(dup)
	// Unmanaged containers are never touched.
	d.Add(runtime.Container{ID: "user", Name: "postgres", State: runtime.StateRunning, Labels: map[string]string{}})

	if _, err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	cs, _ = d.List(context.Background(), managed)
	if len(cs) != 1 || cs[0].Labels[runtime.LabelReplica] != "web-r1-a" {
		t.Errorf("managed containers = %+v", cs)
	}
	if _, err := d.Inspect(context.Background(), "user"); err != nil {
		t.Error("agent removed an unmanaged container")
	}

	a.setDesired(nil, nil)
	report, err := a.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Replicas) != 0 {
		t.Errorf("report = %v", report)
	}
	if cs, _ = d.List(context.Background(), managed); len(cs) != 0 {
		t.Errorf("empty assignment left containers: %v", cs)
	}
}

func TestReconcileReportsFailures(t *testing.T) {
	t.Parallel()

	a, d := newAgent(t)
	d.PullErr = map[string]error{"nginx:nope": errors.New("manifest unknown")}
	a.setDesired([]*armadav1.ReplicaSpec{replica("bad", "nginx:nope", 80), replica("good", "nginx:1", 0)}, nil)

	report, err := a.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*armadav1.ReplicaState{}
	for _, r := range report.Replicas {
		got[r.Id] = r
	}
	if got["bad"].State != store.ReplicaFailed || got["bad"].Message != "manifest unknown" {
		t.Errorf("bad = %v", got["bad"])
	}
	if got["good"].State != store.ReplicaRunning || got["good"].Address != "" {
		t.Errorf("good = %v (no port means no address)", got["good"])
	}

	// A stopped container is recreated; a crash loop backs off.
	a.crashBase = 200 * time.Millisecond
	goodState := func() *armadav1.ReplicaState {
		t.Helper()
		report, _ := a.Reconcile(context.Background())
		for _, r := range report.Replicas {
			if r.Id == "good" {
				return r
			}
		}
		t.Fatal("good missing from report")
		return nil
	}
	crash := func() string {
		t.Helper()
		cs, _ := d.List(context.Background(), map[string]string{runtime.LabelReplica: "good"})
		d.SetState(cs[0].ID, runtime.StateExited, 137)
		return cs[0].ID
	}
	first := crash()
	if r := goodState(); r.State != store.ReplicaRunning || r.ContainerId == first || r.Message != "restarted: exited with code 137" {
		t.Errorf("after first crash = %v", r)
	}
	second := crash()
	if r := goodState(); r.State != store.ReplicaExited || r.ContainerId != second || !strings.HasPrefix(r.Message, "exited with code 137; restarting in") {
		t.Errorf("crash loop not backed off: %v", r)
	}
	time.Sleep(250 * time.Millisecond)
	if r := goodState(); r.State != store.ReplicaRunning || r.ContainerId == second {
		t.Errorf("not recreated after the backoff: %v", r)
	}
	// The next delay doubled.
	crash()
	time.Sleep(250 * time.Millisecond)
	if r := goodState(); r.State != store.ReplicaExited {
		t.Errorf("backoff did not grow: %v", r)
	}

	d.RunErr = errors.New("no space left")
	a.setDesired([]*armadav1.ReplicaSpec{replica("new", "nginx:1", 0)}, nil)
	report, _ = a.Reconcile(context.Background())
	if report.Replicas[0].State != store.ReplicaFailed {
		t.Errorf("run failure = %v", report.Replicas[0])
	}
}

func TestStateMapping(t *testing.T) {
	t.Parallel()

	a, _ := newAgent(t)
	s := replica("r", "img", 80)
	for state, want := range map[string]string{
		runtime.StateRunning: store.ReplicaRunning, runtime.StateCreated: store.ReplicaStarting,
		runtime.StateRestarting: store.ReplicaStarting, runtime.StateDead: store.ReplicaExited,
	} {
		if got := a.state(t.Context(), s, runtime.Container{State: state}).State; got != want {
			t.Errorf("state(%s) = %s, want %s", state, got, want)
		}
	}
	if got := a.state(t.Context(), s, runtime.Container{State: runtime.StateRunning, HostIP: "fd00::1", HostPort: 80}).Address; got != "[fd00::1]:80" {
		t.Errorf("IPv6 address = %q", got)
	}
}

func TestSpecHash(t *testing.T) {
	t.Parallel()

	a := replica("r", "nginx:1", 80)
	b := replica("r", "nginx@sha256:x", 80)
	if specHash(a) != specHash(b) {
		t.Error("hash depends on image")
	}
	c := replica("r", "nginx:1", 81)
	if specHash(a) == specHash(c) {
		t.Error("hash ignores port")
	}
	if a.Image != "nginx:1" {
		t.Error("specHash mutated its input")
	}
	// Replicas created before the server sent CPU reservations keep their
	// hash: a server upgrade must not recreate them.
	d := replica("r", "nginx:1", 80)
	d.CpuReserveMillis = 100
	if specHash(a) != specHash(d) {
		t.Error("hash depends on the CPU reservation")
	}
}

func TestParseMemTotal(t *testing.T) {
	t.Parallel()

	in := []byte("MemFree:  100 kB\nMemTotal:       4028416 kB\n")
	if got := parseMemTotal(in); got != 4028416*1024 {
		t.Errorf("parseMemTotal = %d", got)
	}
	for _, bad := range []string{"", "MemTotal: x kB\n", "MemTotal: 10 MB\n", "MemTotal: -1 kB\n"} {
		if got := parseMemTotal([]byte(bad)); got != 0 {
			t.Errorf("parseMemTotal(%q) = %d", bad, got)
		}
	}
	cpu, _ := detectCapacity()
	if cpu < 1000 {
		t.Errorf("cpu = %d", cpu)
	}
}

func TestNewDetectsCapacity(t *testing.T) {
	t.Parallel()

	a := New(Config{NodeID: "n", Driver: fake.New()})
	if a.cfg.CPUMillis < 1000 || a.cfg.Resync != defaultResync || a.log == nil {
		t.Errorf("defaults not applied: %+v", a.cfg)
	}
}

func TestReconcileAppliesProxy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	px := &proxyfake.Driver{}
	a := New(Config{NodeID: "n1", PrivateIP: "10.0.0.2", Driver: fake.New(), Proxy: px, CPUMillis: 1, MemoryBytes: 1})

	cfg := &armadav1.ProxyConfig{
		Backends: []*armadav1.ProxyBackend{{Name: "web", Servers: []*armadav1.ProxyServer{{Name: "web-r1-a", Address: "10.0.0.2:32768"}}}},
		Rules:    []*armadav1.ProxyRule{{Host: "web.apps.example.org", PathPrefix: "/", Backend: "web"}},
	}
	a.setDesired(nil, cfg)
	if _, err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	n, got := px.Applied()
	if n != 1 || got.Rules[0].Host != "web.apps.example.org" {
		t.Fatalf("applied %d: %+v", n, got)
	}
	// Unchanged config is not re-applied.
	_, _ = a.Reconcile(ctx)
	if n, _ := px.Applied(); n != 1 {
		t.Errorf("applied %d times", n)
	}
	// A proxy that stopped is started again with the same config.
	px.Stop()
	_, _ = a.Reconcile(ctx)
	if n, _ := px.Applied(); n != 2 {
		t.Errorf("stopped proxy: applied %d times, want 2", n)
	}
	if err := px.Health(ctx); err != nil {
		t.Errorf("proxy still down: %v", err)
	}
	_, _ = a.Reconcile(ctx)
	if n, _ := px.Applied(); n != 2 {
		t.Errorf("healthy proxy re-applied: %d", n)
	}
	// An assignment without proxy config keeps the current one.
	a.setDesired(nil, nil)
	_, _ = a.Reconcile(ctx)
	if n, _ := px.Applied(); n != 2 {
		t.Errorf("nil proxy config re-applied or cleared")
	}

	// Failures are retried on the next reconcile.
	px.SetErr(errors.New("haproxy -c failed"))
	cfg2 := &armadav1.ProxyConfig{Backends: cfg.Backends}
	a.setDesired(nil, cfg2)
	if _, err := a.Reconcile(ctx); err != nil {
		t.Fatal("proxy failure must not fail container reconciliation")
	}
	px.SetErr(nil)
	_, _ = a.Reconcile(ctx)
	if n, got := px.Applied(); n != 3 || len(got.Rules) != 0 {
		t.Errorf("retry: applied %d, %+v", n, got)
	}

	// A malicious config from a compromised server is refused by the driver.
	a.setDesired(nil, &armadav1.ProxyConfig{Rules: []*armadav1.ProxyRule{{Host: "x.id\n  bind :22", PathPrefix: "/", Backend: "web"}}})
	_, _ = a.Reconcile(ctx)
	if n, _ := px.Applied(); n != 3 {
		t.Error("invalid proxy config applied")
	}
}

// recordingDNS stands in for the node-local resolver.
type recordingDNS struct {
	mu      sync.Mutex
	names   []string
	clients map[netip.Addr]string
}

func (r *recordingDNS) SetClients(c map[netip.Addr]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients = maps.Clone(c)
}

func (r *recordingDNS) Address() string { return "172.17.0.1" }
func (r *recordingDNS) SetNames(apps []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names = slices.Clone(apps)
}

func TestInternalDNS(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := fake.New()
	dns := &recordingDNS{}
	a := New(Config{NodeID: "n1", PrivateIP: "10.0.0.2", Driver: d, Proxy: &proxyfake.Driver{}, DNS: dns, CPUMillis: 1, MemoryBytes: 1})
	a.setDesired([]*armadav1.ReplicaSpec{replica("web-r1-a", "nginx:1", 80)}, &armadav1.ProxyConfig{
		Backends: []*armadav1.ProxyBackend{{Name: "web"}, {Name: "shop-api"}, {Name: "db"}},
		// An internal TCP app resolves too (ADR 0039).
		TcpRoutes: []*armadav1.ProxyTCPRoute{{Port: 5432, Backend: "db"}},
		Rules: []*armadav1.ProxyRule{
			{Host: "web.apps.example.org", PathPrefix: "/", Backend: "web"},
			{Host: "web.internal", PathPrefix: "/", Backend: "web", Internal: true},
			{Host: "shop-api.internal", PathPrefix: "/", Backend: "shop-api", Internal: true},
			{Host: "shop-api.internal", PathPrefix: "/v1", Backend: "shop-api", Internal: true},
		},
	})
	if _, err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	dns.mu.Lock()
	names := slices.Sorted(slices.Values(dns.names))
	dns.mu.Unlock()
	if !slices.Equal(names, []string{"db", "shop-api", "web"}) {
		t.Errorf("internal names = %v", names)
	}
	cs, _ := d.List(ctx, nil)
	spec, _ := d.Spec(cs[0].ID)
	if !slices.Equal(spec.DNS, []string{"172.17.0.1"}) {
		t.Errorf("container DNS = %v", spec.DNS)
	}
	// The resolver is not part of the spec hash, so turning it on or off
	// does not restart running replicas.
	if cs[0].Labels[runtime.LabelSpecHash] != specHash(replica("web-r1-a", "nginx:1", 80)) {
		t.Error("spec hash depends on the DNS setting")
	}
}

func TestReportsImagePlatforms(t *testing.T) {
	t.Parallel()

	a, d := newAgent(t)
	d.Platforms = map[string][]string{"nginx:1": {"linux/amd64", "linux/arm64"}}
	d.PullErr = map[string]error{"amd64only:1": fmt.Errorf("start: %w", &runtime.PlatformError{Image: "amd64only:1", Want: "linux/arm64", Have: []string{"linux/amd64"}})}
	a.setDesired([]*armadav1.ReplicaSpec{replica("web-r1-a", "nginx:1", 80), replica("web-r1-b", "amd64only:1", 80)}, nil)

	report, err := a.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range report.Replicas {
		switch r.Id {
		case "web-r1-a":
			if r.State != store.ReplicaRunning || !slices.Equal(r.ImagePlatforms, []string{"linux/amd64", "linux/arm64"}) {
				t.Errorf("pulled replica = %v", r)
			}
		case "web-r1-b":
			// The server learns where the image can run.
			if r.State != store.ReplicaFailed || !slices.Equal(r.ImagePlatforms, []string{"linux/amd64"}) ||
				!strings.Contains(r.Message, "has no linux/arm64 variant (it has linux/amd64)") {
				t.Errorf("replica of an image for another platform = %v", r)
			}
		}
	}
}

// reportStream records what an agent sends.
type reportStream struct {
	armadav1.AgentService_ConnectClient
	reports chan *armadav1.ReplicaReport
}

func (s *reportStream) Send(m *armadav1.AgentMessage) error {
	if r := m.GetReport(); r != nil {
		s.reports <- r
	}
	return nil
}

// A replica taking long to start must not hide that the others are ready:
// the server takes replicas it does not hear are ready out of the proxies.
func TestReportsWhileReplicasStart(t *testing.T) {
	t.Parallel()
	a, d := newAgent(t)
	ctx := context.Background()
	a.setDesired([]*armadav1.ReplicaSpec{replica("a-1", "nginx:1", 80)}, nil)
	ready := false
	for range 200 {
		r, err := a.Reconcile(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.GetReplicas()) == 1 && r.GetReplicas()[0].GetReady() {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("replica never ready")
	}

	release := make(chan struct{})
	d.RunHook = func(context.Context, runtime.ContainerSpec) { <-release }
	stream := &reportStream{reports: make(chan *armadav1.ReplicaReport, 16)}
	a.streamMu.Lock()
	a.stream = stream
	a.streamMu.Unlock()
	a.setDesired([]*armadav1.ReplicaSpec{replica("a-1", "nginx:1", 80), replica("b-1", "nginx:1", 80)}, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := a.Reconcile(ctx); err != nil {
			t.Error(err)
		}
	}()
	select {
	case r := <-stream.reports:
		if len(r.GetReplicas()) != 1 || r.GetReplicas()[0].GetId() != "a-1" || !r.GetReplicas()[0].GetReady() {
			t.Errorf("report while starting: %v", r)
		}
	case <-time.After(10 * time.Second):
		t.Error("no report while a replica starts")
	}
	close(release)
	<-done
}

func TestStartsRunAtOnceWithALimit(t *testing.T) {
	t.Parallel()
	a, d := newAgent(t)
	var now, peak atomic.Int32
	var specs []*armadav1.ReplicaSpec
	for i := range 3 * maxConcurrentStarts {
		specs = append(specs, replica(fmt.Sprintf("r-%d", i), "nginx:1", 80))
	}
	d.RunHook = func(context.Context, runtime.ContainerSpec) {
		n := now.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		now.Add(-1)
	}
	a.setDesired(specs, nil)
	r, err := a.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.GetReplicas()) != len(specs) {
		t.Errorf("%d replicas reported, want %d", len(r.GetReplicas()), len(specs))
	}
	for i := 1; i < len(r.GetReplicas()); i++ {
		if r.GetReplicas()[i-1].GetId() >= r.GetReplicas()[i].GetId() {
			t.Fatalf("report not sorted: %v", r)
		}
	}
	if p := peak.Load(); p < 2 || p > maxConcurrentStarts {
		t.Errorf("%d starts at once, want 2 to %d", p, maxConcurrentStarts)
	}
}

// Replicas starting together share a pull, but only with the same
// credentials: an image is never handed over on another's credentials.
func TestPullOnce(t *testing.T) {
	t.Parallel()
	d := fake.New()
	p := newPullOnce(d)
	auth := &runtime.RegistryAuth{Username: "u", Password: "secret"}
	other := &runtime.RegistryAuth{Username: "u", Password: "other"}
	for _, c := range []struct {
		image string
		auth  *runtime.RegistryAuth
	}{{"a:1", nil}, {"a:1", auth}, {"a:1", other}, {"b:1", auth}} {
		if _, err := p.pull(context.Background(), c.image, c.auth); err != nil {
			t.Fatal(err)
		}
		found := false
		for i, img := range d.Pulls {
			if img == c.image && d.PullAuths[i] == c.auth {
				found = true
			}
		}
		if !found {
			t.Errorf("no pull of %s with its own credentials", c.image)
		}
	}
	// Sharing, with a pull held open until everyone asked.
	release := make(chan struct{})
	s := &pullOnce{driver: blockingPuller{Driver: d, release: release}}
	before := len(d.Pulls)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := s.pull(context.Background(), "c:1", nil); err != nil {
				t.Error(err)
			}
		})
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if n := len(d.Pulls) - before; n != 1 {
		t.Errorf("%d pulls for replicas starting together, want 1", n)
	}
}

type blockingPuller struct {
	*fake.Driver
	release chan struct{}
}

func (b blockingPuller) Pull(ctx context.Context, image string, auth *runtime.RegistryAuth) (runtime.Image, error) {
	<-b.release
	return b.Driver.Pull(ctx, image, auth)
}

// A container that ran before the agent started keeps the status the server
// has until its probes say something, so restarting an agent takes nothing
// out of the proxies.
func TestAdoptedReplicaWaitsForProbes(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, _ := newAgent(t)
	verdict := make(chan error)
	a.cfg.Check = func(c context.Context, _, _ string) error {
		select {
		case err := <-verdict:
			return err
		case <-c.Done():
			return c.Err()
		}
	}
	a.setDesired([]*armadav1.ReplicaSpec{replica("a-1", "nginx:1", 80)}, nil)
	first, err := a.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Started by this agent: reported as not ready, as always.
	if len(first.GetReplicas()) != 1 || first.GetReplicas()[0].GetReady() {
		t.Fatalf("new container: %v", first)
	}

	// The agent restarts: the same container is now older than the agent.
	a.stopProbes("a-1")
	a.began = time.Now().Add(time.Hour)
	waiting, err := a.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(waiting.GetReplicas()) != 0 {
		t.Fatalf("adopted container without a verdict was reported: %v", waiting)
	}

	verdict <- nil
	var ready *armadav1.ReplicaReport
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if ready, err = a.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		if len(ready.GetReplicas()) == 1 {
			break
		}
	}
	if len(ready.GetReplicas()) != 1 || !ready.GetReplicas()[0].GetReady() {
		t.Fatalf("after a passing probe: %v", ready)
	}
}

// An adopted container that fails its first check is reported at once.
func TestAdoptedReplicaFailingProbeIsReported(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, _ := newAgent(t)
	a.cfg.Check = func(context.Context, string, string) error { return errors.New("refused") }
	a.setDesired([]*armadav1.ReplicaSpec{replica("a-1", "nginx:1", 80)}, nil)
	if _, err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	a.stopProbes("a-1")
	a.began = time.Now().Add(time.Hour)
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		r, err := a.Reconcile(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.GetReplicas()) == 1 {
			if st := r.GetReplicas()[0]; st.GetReady() || !strings.Contains(st.GetMessage(), "refused") {
				t.Fatalf("after a failing probe: %v", st)
			}
			return
		}
	}
	t.Fatal("the failing replica was never reported")
}

func TestPruneImagesKeepsAssignedImages(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, d := newAgent(t)
	// Before the first assignment nothing is pruned.
	a.PruneImages(ctx)
	if len(d.Prunes) != 0 {
		t.Fatalf("pruned before an assignment: %v", d.Prunes)
	}
	d.Digests = map[string]string{"nginx:1": "nginx@sha256:abc"}
	a.setDesired([]*armadav1.ReplicaSpec{replica("web-r1-a", "nginx:1", 80), replica("job-r1-a", "busybox", 0)}, nil)
	if _, err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	a.PruneImages(ctx)
	if len(d.Prunes) != 1 || !slices.Equal(d.Prunes[0], []string{"busybox", "nginx:1", "nginx@sha256:abc"}) {
		t.Errorf("kept %v", d.Prunes)
	}
}

func TestReconcileMachineRestarted(t *testing.T) {
	t.Parallel()

	a, d := newAgent(t)
	a.setDesired([]*armadav1.ReplicaSpec{replica("web", "nginx:1", 0)}, nil)
	if _, err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	cs, _ := d.List(context.Background(), map[string]string{runtime.LabelReplica: "web"})
	// The machine booted after the container started: its task is gone and
	// the runtime reports exit code 255.
	a.booted = time.Now().Add(2 * time.Second)
	d.SetState(cs[0].ID, runtime.StateExited, 255)
	report, err := a.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r := report.Replicas[0]; r.State != store.ReplicaRunning || r.ContainerId == cs[0].ID || r.Message != "restarted: the machine restarted" {
		t.Errorf("after the reboot = %v", r)
	}

	// A container started after the boot that exits crashed.
	cs, _ = d.List(context.Background(), map[string]string{runtime.LabelReplica: "web"})
	a.booted = time.Now().Add(-time.Hour)
	d.SetState(cs[0].ID, runtime.StateExited, 1)
	report, _ = a.Reconcile(context.Background())
	if r := report.Replicas[0]; r.Message != "restarted: exited with code 1" {
		t.Errorf("crash after the boot = %v", r)
	}
}

func TestParseBootTime(t *testing.T) {
	t.Parallel()
	stat := []byte("cpu  1 2 3\nintr 5\nctxt 7\nbtime 1794068497\nprocesses 9\n")
	if got := parseBootTime(stat); !got.Equal(time.Unix(1794068497, 0)) {
		t.Errorf("btime = %v", got)
	}
	for _, bad := range []string{"", "btime\n", "btime x\n", "btime 0\n", "btime 1 2\n"} {
		if got := parseBootTime([]byte(bad)); !got.IsZero() {
			t.Errorf("%q: %v, want zero", bad, got)
		}
	}
}

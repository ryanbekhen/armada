package haproxy

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/proxy"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
)

var update = flag.Bool("update", false, "rewrite golden files")

func cert(t *testing.T) []byte {
	t.Helper()
	b, err := selfSignedPEM()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sampleConfig(t *testing.T) proxy.Config {
	return proxy.Config{
		ACMEAddress: "10.0.0.1:7480",
		Backends: []proxy.Backend{
			{Name: "frontend", LocalFirst: true, Servers: []proxy.Server{{Name: "frontend-r1-a", Address: "10.0.0.2:32768"}}},
			{Name: "api-bengkel", HealthPath: "/healthz", Servers: []proxy.Server{
				{Name: "api-bengkel-r3-b", Address: "10.0.0.3:32770", Weight: 230}, // split traffic
				{Name: "api-bengkel-r3-a", Address: "10.0.0.2:32769", Weight: 26},
			}},
			{Name: "admin-panel", Servers: nil, Wake: true, LocalFirst: true}, // scaled to zero
			// Its project limits requests (ADR 0026).
			{Name: "shop", LocalFirst: true, HealthPath: "/ready", TimeoutSeconds: 300, Servers: []proxy.Server{
				{Name: "shop-r2-a", Address: "10.0.0.3:32771"},
				{Name: "shop-r2-b", Address: "10.0.0.2:32772"},
			}},
			// An app of another project, named by its ID (ADR 0026).
			{Name: "shop.staging", Servers: []proxy.Server{{Name: "shop.staging-r1-a", Address: "10.0.0.3:32773"}}},
		},
		Rules: []proxy.Rule{
			{Host: "example.org", PathPrefix: "/", Backend: "frontend"},
			{Host: "example.org", PathPrefix: "/api", StripPrefix: true, Backend: "api-bengkel"},
			{Host: "example.org", PathPrefix: "/admin", Backend: "admin-panel"},
			{Host: "example.org", PathPrefix: "/api/v1.2", StripPrefix: true, Backend: "api-bengkel"},
			{Host: "api-bengkel.apps.example.org", PathPrefix: "/", Backend: "api-bengkel"},
			{Host: "api-bengkel.internal", PathPrefix: "/", Backend: "api-bengkel", Internal: true},
			{Host: "api-bengkel.internal", PathPrefix: "/v1", StripPrefix: true, Backend: "api-bengkel", Internal: true},
			{Host: "shop.example.org", PathPrefix: "/", Backend: "shop"},
			{Host: "shop.internal", PathPrefix: "/", Backend: "shop", Internal: true},
			{Host: "staging.example.org", PathPrefix: "/", Backend: "shop.staging"},
			{Host: "shop.staging.internal", PathPrefix: "/", Backend: "shop.staging", Internal: true},
		},
		Certificates: []proxy.Certificate{{Name: "example.org", PEM: cert(t)}},
	}
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if string(want) != string(got) {
		t.Errorf("%s mismatch (run go test -update to accept):\n--- got ---\n%s", name, got)
	}
}

func TestRenderGolden(t *testing.T) {
	t.Parallel()

	cfg := sampleConfig(t)
	layout := assignLayout(nil, cfg, renderOptions{PrivateIP: "10.0.0.2"}.node())
	golden(t, "full.cfg", render(cfg, layout, renderOptions{PrivateIP: "10.0.0.2", InternalIP: "172.17.0.1"}))

	empty := proxy.Config{}
	golden(t, "empty.cfg", render(empty, assignLayout(nil, empty, renderOptions{PrivateIP: ""}.node()), renderOptions{}))

	// On the cluster network the internal frontend checks who calls (ADR
	// 0026).
	cc := callersConfig(t)
	opts := callersOptions()
	golden(t, "callers.cfg", render(cc, assignLayout(nil, cc, opts.node()), opts))
}

func callersOptions() renderOptions {
	return renderOptions{PrivateIP: "10.0.0.2", InternalIP: "10.120.0.1", Subnet: "10.120.0.0/24"}
}

// callersConfig has apps in two projects, one with ingress.allow and a
// revision label.
func callersConfig(t *testing.T) proxy.Config {
	t.Helper()
	cfg := sampleConfig(t)
	for i := range cfg.Backends {
		for j := range cfg.Backends[i].Servers {
			cfg.Backends[i].Servers[j].Address = strings.Replace(cfg.Backends[i].Servers[j].Address, "10.0.0.", "10.120.0.", 1)
		}
	}
	cfg.Backends = append(cfg.Backends,
		// A label shares its app's request counter.
		proxy.Backend{Name: "db.staging", Servers: []proxy.Server{{Name: "db.staging-r1-a", Address: "10.120.1.4:5000"}}},
		proxy.Backend{Name: "canary--db.staging", Servers: []proxy.Server{{Name: "db.staging-r1-a", Address: "10.120.1.4:5000"}}},
	)
	allow := []string{"db.staging", "shop.staging"}
	cfg.Rules = append(cfg.Rules,
		proxy.Rule{Host: "db.staging.internal", PathPrefix: "/", Backend: "db.staging", Internal: true, Allow: allow},
		proxy.Rule{Host: "canary--db.staging.internal", PathPrefix: "/", Backend: "canary--db.staging", Internal: true, Allow: allow},
	)
	return cfg
}

func TestRenderRouteOrder(t *testing.T) {
	t.Parallel()

	out := string(render(sampleConfig(t), assignLayout(nil, sampleConfig(t), renderOptions{PrivateIP: ""}.node()), renderOptions{}))
	// The longest prefix must be considered first, and "/" last.
	iV12 := strings.Index(out, "-m str /api/v1.2 }")
	iAPI := strings.Index(out, "-m str /api }")
	iRoot := strings.Index(out, ",map(")
	if iV12 < 0 || iAPI < 0 || iRoot < 0 || iV12 > iAPI || iAPI > iRoot {
		t.Errorf("route order wrong: v1.2=%d api=%d root=%d", iV12, iAPI, iRoot)
	}
	if !strings.Contains(out, "set-path /%[path,field(4,/,0)] if { var(txn.route) -m str r0 }") ||
		!strings.Contains(out, "set-path /%[path,field(3,/,0)] if { var(txn.route) -m str r2 }") {
		t.Errorf("strip prefix must skip the prefix's segments:\n%s", out)
	}
	if strings.Contains(out, "regsub") || strings.Contains(out, "replace-path") {
		t.Error("user paths must never become regular expressions")
	}
	if strings.Contains(out, "set-path /%[path,field(4,/,0)] if { var(txn.route) -m str r1 }") || strings.Count(out, "http-request set-path") != 2 {
		t.Error("route without stripPrefix must not rewrite the path")
	}
}

func TestRenderInternalFrontend(t *testing.T) {
	t.Parallel()

	cfg := sampleConfig(t)
	out := string(render(cfg, assignLayout(nil, cfg, renderOptions{PrivateIP: ""}.node()), renderOptions{InternalIP: "172.17.0.1"}))
	i := strings.Index(out, "frontend internal")
	if i < 0 || !strings.Contains(out, "    bind 172.17.0.1:80\n") {
		t.Fatalf("internal frontend missing:\n%s", out)
	}
	pub, internal := out[:i], out[i:strings.Index(out[i:], "\nbackend ")+i]
	// Internal names are routed only on the internal frontend, public names
	// only on the public ones.
	if strings.Contains(pub, ".internal") {
		t.Error("an internal name is routed on a public frontend")
	}
	if strings.Contains(internal, "example.org") {
		t.Error("a public name is routed on the internal frontend")
	}
	if !strings.Contains(internal, "set-path /%[path,field(3,/,0)] if { var(txn.route) -m str i0 }") {
		t.Errorf("internal strip prefix:\n%s", internal)
	}
	// Without a bridge address there is no internal frontend at all.
	if strings.Contains(string(render(cfg, assignLayout(nil, cfg, renderOptions{PrivateIP: ""}.node()), renderOptions{})), "frontend internal") {
		t.Error("internal frontend rendered without an internal IP")
	}
}

// Client address headers survive only from trusted proxies, on the public
// frontend. The internal one keeps what an app's own proxy passes on.
func TestRenderClientAddressHeaders(t *testing.T) {
	t.Parallel()
	opts := renderOptions{InternalIP: "10.120.0.1"}
	frontends := func(out string) (https, internal string) {
		https = out[strings.Index(out, "frontend https"):]
		if i := strings.Index(https, "frontend internal"); i >= 0 {
			https, internal = https[:i], https[i:]
		}
		return https, internal
	}
	rendered := func(c proxy.Config) string { return string(render(c, assignLayout(nil, c, opts.node()), opts)) }
	none := rendered(proxy.Config{})
	https, internal := frontends(none)
	for _, h := range proxy.ClientAddressHeaders {
		if !strings.Contains(https, "http-request del-header "+h+"\n") {
			t.Errorf("%s is kept with no trusted proxies:\n%s", h, https)
		}
		if strings.Contains(internal, "del-header "+h) {
			t.Errorf("%s is removed on the internal frontend", h)
		}
	}
	if strings.Contains(none, "trusted_proxy") {
		t.Error("an empty trusted proxy list reached the configuration")
	}

	https, _ = frontends(rendered(proxy.Config{TrustedProxies: []string{"192.0.2.0/24", "2001:db8::/32"}}))
	if !strings.Contains(https, "acl trusted_proxy src 192.0.2.0/24 2001:db8::/32\n") {
		t.Errorf("no acl:\n%s", https)
	}
	for _, h := range proxy.ClientAddressHeaders {
		if !strings.Contains(https, "http-request del-header "+h+" unless trusted_proxy\n") {
			t.Errorf("%s is not limited to trusted proxies:\n%s", h, https)
		}
	}

	if out := rendered(proxy.Config{TrustedProxies: []string{"192.0.2.0/24\n    bind :22"}}); out != "" {
		t.Error("rendered a value with a line break")
	}
}

func TestRenderNoPublicMetrics(t *testing.T) {
	t.Parallel()

	out := string(render(proxy.Config{}, Layout{}, renderOptions{PrivateIP: "fd00::2"}))
	if !strings.Contains(out, "bind [fd00::2]:8404") {
		t.Errorf("metrics bind missing:\n%s", out)
	}
	if strings.Contains(out, "bind :8404") || strings.Contains(out, "bind *:8404") {
		t.Error("metrics bound on all interfaces")
	}
	if strings.Contains(string(render(proxy.Config{}, Layout{}, renderOptions{})), "frontend metrics") {
		t.Error("metrics frontend rendered without a private IP")
	}
}

// directive matches the start of every line HAProxy could interpret as a
// section or keyword. Every rendered line must be one we expect.
var allowedLine = regexp.MustCompile(`^(#.*|global|defaults|frontend [a-z]+|backend be_[a-z0-9_-]+|    [a-z].*|)$`)

// FuzzRender feeds arbitrary hostnames, paths, and names through validation
// and checks that anything accepted renders without injecting new lines or
// sections.
func FuzzRender(f *testing.F) {
	f.Add("example.org", "/api", "web", "/healthz", "10.0.0.2:80")
	f.Add("a.b", "/", "x", "", "127.0.0.1:1")
	f.Add("a.b\nbind :1", "/x }", "w\n", "/h h", "10.0.0.1:80 backup")
	f.Fuzz(func(t *testing.T, host, path, name, health, addr string) {
		cfg := proxy.Config{
			Backends: []proxy.Backend{{Name: name, HealthPath: health, Servers: []proxy.Server{{Name: "r", Address: addr}}}},
			Rules:    []proxy.Rule{{Host: host, PathPrefix: path, Backend: name}},
		}
		if cfg.Validate() != nil {
			return
		}
		out := render(cfg, assignLayout(nil, cfg, renderOptions{PrivateIP: ""}.node()), renderOptions{})
		for _, line := range strings.Split(string(out), "\n") {
			if !allowedLine.MatchString(line) {
				t.Fatalf("unexpected line %q", line)
			}
			if strings.Count(line, "{") != strings.Count(line, "}") {
				t.Fatalf("unbalanced ACL braces in %q", line)
			}
		}
		if n := strings.Count(string(out), "\nbackend "); n != 2 {
			t.Fatalf("expected 2 backends, rendered %d", n)
		}
	})
}

// FuzzRenderCallers renders an internal rule that names its callers, on a
// node that checks them (ADR 0026).
func FuzzRenderCallers(f *testing.F) {
	f.Add("db.shop", "api.shop")
	f.Add("db", "api")
	f.Add("db.shop", "api.shop }  or { always_true")
	f.Add("canary--db.shop", "x.shop\nbind :1")
	f.Fuzz(func(t *testing.T, name, caller string) {
		cfg := proxy.Config{
			Backends: []proxy.Backend{{Name: name, Servers: []proxy.Server{{Name: "r", Address: "10.120.0.5:80"}}}},
			Rules:    []proxy.Rule{{Host: name + ".internal", PathPrefix: "/", Backend: name, Internal: true, Allow: []string{caller}}},
		}
		if cfg.Validate() != nil {
			return
		}
		opts := renderOptions{InternalIP: "10.120.0.1", Subnet: "10.120.0.0/24"}
		out := render(cfg, assignLayout(nil, cfg, opts.node()), opts)
		if out == nil {
			t.Fatal("valid config refused")
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Count(line, "{") != strings.Count(line, "}") {
				t.Fatalf("unbalanced ACL braces in %q", line)
			}
			if strings.Contains(line, "txn.capp) -m str") && !strings.HasSuffix(line, "-m str "+caller+" }") {
				t.Fatalf("caller check %q does not name exactly %q", line, caller)
			}
		}
	})
}

func TestSlotCount(t *testing.T) {
	t.Parallel()
	for n, want := range map[int]int{0: 10, 1: 10, 10: 10, 11: 20, 20: 20, 95: 100} {
		if got := slotCount(n); got != want {
			t.Errorf("slotCount(%d) = %d, want %d", n, got, want)
		}
	}
}

func TestAssignLayoutIsStable(t *testing.T) {
	t.Parallel()

	cfg := proxy.Config{Backends: []proxy.Backend{{Name: "web", Servers: []proxy.Server{{Name: "b"}, {Name: "a"}}}}}
	l1 := assignLayout(nil, cfg, renderOptions{PrivateIP: ""}.node())
	if l1["be_web"][0] != "a" || l1["be_web"][1] != "b" || len(l1["be_web"]) != 10 {
		t.Fatalf("layout = %v", l1["be_web"])
	}
	// Removing "a" frees slot 0 without moving "b"; a new replica fills the gap.
	cfg.Backends[0].Servers = []proxy.Server{{Name: "b"}, {Name: "c"}}
	l2 := assignLayout(l1, cfg, renderOptions{PrivateIP: ""}.node())
	if l2["be_web"][0] != "c" || l2["be_web"][1] != "b" {
		t.Errorf("layout = %v, want b to keep slot 1", l2["be_web"])
	}
	// Growing past 10 replicas adds a slot band.
	for i := range 11 {
		cfg.Backends[0].Servers = append(cfg.Backends[0].Servers, proxy.Server{Name: fmt.Sprintf("n%02d", i)})
	}
	if l3 := assignLayout(l2, cfg, renderOptions{PrivateIP: ""}.node()); len(l3["be_web"]) != 20 || l3["be_web"][1] != "b" {
		t.Errorf("layout after growth = %v", l3["be_web"])
	}
}

func TestSignatureIgnoresServerAddresses(t *testing.T) {
	t.Parallel()

	cfg := sampleConfig(t)
	l := assignLayout(nil, cfg, renderOptions{PrivateIP: ""}.node())
	s1 := signature(cfg, l, renderOptions{PrivateIP: "10.0.0.2"})
	cfg.Backends[0].Servers[0].Address = "10.0.0.9:40000"
	cfg.Certificates[0].PEM = cert(t)
	if signature(cfg, l, renderOptions{PrivateIP: "10.0.0.2"}) != s1 {
		t.Error("address or certificate content change altered the signature")
	}
	cfg.Rules = cfg.Rules[1:]
	if signature(cfg, l, renderOptions{PrivateIP: "10.0.0.2"}) == s1 {
		t.Error("rule change did not alter the signature")
	}
	if signature(sampleConfig(t), l, renderOptions{PrivateIP: "10.0.0.3"}) == s1 {
		t.Error("private IP change did not alter the signature")
	}
	if signature(sampleConfig(t), l, renderOptions{PrivateIP: "10.0.0.2", InternalIP: "172.17.0.1"}) == s1 {
		t.Error("internal IP change did not alter the signature")
	}
}

// fakeEngine and fakeAPI record calls made by the driver.
type fakeEngine struct {
	mu          sync.Mutex
	running     bool
	starts      int
	reloads     int
	validations []string
	validateErr error
	startErr    error
}

func (e *fakeEngine) Running(context.Context) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running, nil
}
func (e *fakeEngine) Start(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.startErr != nil {
		return e.startErr
	}
	e.starts++
	e.running = true
	return nil
}
func (e *fakeEngine) Validate(_ context.Context, f string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.validations = append(e.validations, f)
	return e.validateErr
}
func (e *fakeEngine) Reload(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.reloads++
	return nil
}

type fakeAPI struct {
	mu   sync.Mutex
	cmds []string
	err  error
	// reply answers a command; nil answers nothing.
	reply func(cmd string) string
}

func (a *fakeAPI) Command(_ context.Context, cmd string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cmds = append(a.cmds, cmd)
	if a.reply != nil {
		return a.reply(cmd), a.err
	}
	if strings.HasPrefix(cmd, "prepare map") {
		return "New version created: 7", a.err
	}
	return "", a.err
}
func (a *fakeAPI) Payload(_ context.Context, cmd, payload string) (string, error) {
	// The same check as the real socket.
	if err := checkPayload(payload); err != nil {
		return "", err
	}
	return a.Command(context.Background(), cmd+" <<payload:"+fmt.Sprint(len(payload)))
}

func newDriver(t *testing.T) (*Driver, *fakeEngine, *fakeAPI, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "haproxy")
	e, a := &fakeEngine{}, &fakeAPI{}
	d, err := New(Config{Dir: dir, PrivateIP: "10.0.0.2", Engine: e, API: a})
	if err != nil {
		t.Fatal(err)
	}
	return d, e, a, dir
}

func TestNewPreparesDirectories(t *testing.T) {
	t.Parallel()

	_, _, _, dir := newDriver(t)
	for _, p := range []string{dir, etcDir(dir), filepath.Join(etcDir(dir), certDir), runDir(dir), filepath.Join(etcDir(dir), defaultCertFile)} {
		if err := fsutil.CheckPrivate(p); err != nil {
			t.Error(err)
		}
	}
	if _, err := New(Config{Dir: t.TempDir()}); err == nil {
		t.Error("New accepted nil engine")
	}
	if _, err := New(Config{Dir: t.TempDir(), Engine: &fakeEngine{}, PrivateIP: "nope"}); err == nil {
		t.Error("New accepted invalid private IP")
	}
	for _, bad := range []string{"nope", "8.8.8.0/24", "10.120.3.1/24", "10.120.3.0/24\n"} {
		if _, err := New(Config{Dir: t.TempDir(), Engine: &fakeEngine{}, Subnet: bad}); err == nil {
			t.Errorf("New accepted subnet %q", bad)
		}
	}
}

func TestApplyWeights(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d, e, a, dir := newDriver(t)
	cfg := proxy.Config{Backends: []proxy.Backend{{Name: "web", Servers: []proxy.Server{
		{Name: "web-r1-a", Address: "10.0.0.2:32768", Weight: 230},
		{Name: "web-r2-a", Address: "10.0.0.3:32768", Weight: 26},
	}}}}
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	live, _ := os.ReadFile(filepath.Join(etcDir(dir), configFile))
	if !strings.Contains(string(live), "server s1 10.0.0.2:32768 weight 230") || !strings.Contains(string(live), "server s2 10.0.0.3:32768 weight 26") {
		t.Errorf("weights not rendered:\n%s", live)
	}
	step := func(name string, servers []proxy.Server, want ...string) {
		t.Helper()
		a.cmds = nil
		cfg.Backends[0].Servers = servers
		if err := d.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if strings.Join(a.cmds, "|") != strings.Join(want, "|") || e.reloads != 0 {
			t.Errorf("%s: commands = %q, want %q (reloads %d)", name, a.cmds, want, e.reloads)
		}
	}
	// Moving traffic changes weights live, without a reload.
	step("shift", []proxy.Server{
		{Name: "web-r1-a", Address: "10.0.0.2:32768", Weight: 128},
		{Name: "web-r2-a", Address: "10.0.0.3:32768", Weight: 128},
	}, "set server be_web/s1 weight 128", "set server be_web/s2 weight 128")
	// A slot in maintenance keeps its old weight in HAProxy, so reusing it
	// sets the weight again.
	step("remove", []proxy.Server{{Name: "web-r1-a", Address: "10.0.0.2:32768", Weight: 128}}, "set server be_web/s2 state maint")
	step("reuse", []proxy.Server{
		{Name: "web-r1-a", Address: "10.0.0.2:32768", Weight: 128},
		{Name: "web-r3-a", Address: "10.0.0.4:32768"},
	}, "set server be_web/s2 weight 1", "set server be_web/s2 addr 10.0.0.4 port 32768", "set server be_web/s2 state ready")
	for _, w := range []int{-1, proxy.MaxWeight + 1} {
		bad := cfg
		bad.Backends = []proxy.Backend{{Name: "web", Servers: []proxy.Server{{Name: "x", Address: "10.0.0.2:1", Weight: w}}}}
		if err := d.Apply(ctx, bad); err == nil {
			t.Errorf("weight %d accepted", w)
		}
	}
}

func TestApplyLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d, e, a, dir := newDriver(t)
	cfg := sampleConfig(t)
	for i := range cfg.Backends[1].Servers {
		cfg.Backends[1].Servers[i].Weight = 0 // TestApplyWeights covers weights
	}

	// First apply starts HAProxy with the rendered config.
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if e.starts != 1 || e.reloads != 0 {
		t.Errorf("starts=%d reloads=%d", e.starts, e.reloads)
	}
	live, _ := os.ReadFile(filepath.Join(etcDir(dir), configFile))
	if !strings.Contains(string(live), "server s1 10.0.0.2:32769") {
		t.Errorf("live config missing server:\n%s", live)
	}
	if err := fsutil.CheckPrivate(filepath.Join(etcDir(dir), certDir, "example.org.pem")); err != nil {
		t.Error(err)
	}

	// Identical config: nothing to do.
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if e.reloads != 0 || len(a.cmds) != 0 || len(e.validations) != 0 {
		t.Errorf("no-op apply did work: reloads=%d cmds=%v validations=%v", e.reloads, a.cmds, e.validations)
	}

	// Replica moved and one added: Runtime API only, no reload.
	cfg.Backends[1].Servers = []proxy.Server{
		{Name: "api-bengkel-r3-a", Address: "10.0.0.2:32769"},
		{Name: "api-bengkel-r3-c", Address: "10.0.0.4:32771"},
	}
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if e.reloads != 0 {
		t.Error("server change caused a reload")
	}
	want := []string{
		"set server be_api-bengkel/s2 addr 10.0.0.4 port 32771",
		"set server be_api-bengkel/s2 state ready",
	}
	if strings.Join(a.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("runtime commands = %q, want %q", a.cmds, want)
	}
	if len(e.validations) != 0 {
		t.Errorf("validations = %v: only servers changed", e.validations)
	}

	// Removing a replica puts its slot in maintenance.
	a.cmds = nil
	cfg.Backends[1].Servers = cfg.Backends[1].Servers[1:]
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if strings.Join(a.cmds, "|") != "set server be_api-bengkel/s1 state maint" {
		t.Errorf("runtime commands = %q", a.cmds)
	}

	// Replacing the only replica: the new server is enabled before the old
	// slot goes into maintenance. (Slot keys sort as strings, so without
	// the two passes "s10" would be disabled before "s2" is enabled.)
	a.cmds = nil
	cfg.Backends[1].Servers = []proxy.Server{{Name: "api-bengkel-r4-a", Address: "10.0.0.5:32772"}}
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	want = []string{
		"set server be_api-bengkel/s1 addr 10.0.0.5 port 32772",
		"set server be_api-bengkel/s1 state ready",
		"set server be_api-bengkel/s2 state maint",
	}
	if strings.Join(a.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("replacement commands = %q, want %q", a.cmds, want)
	}

	// Certificate renewal: live update through the Runtime API.
	a.cmds = nil
	cfg.Certificates[0].PEM = cert(t)
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if len(a.cmds) != 2 || !strings.HasPrefix(a.cmds[0], "set ssl cert /usr/local/etc/haproxy/certs/example.org.pem <<") ||
		a.cmds[1] != "commit ssl cert /usr/local/etc/haproxy/certs/example.org.pem" || e.reloads != 0 {
		t.Errorf("cert update cmds = %q reloads=%d", a.cmds, e.reloads)
	}

	// Issued bundles have empty lines between their blocks; the live update
	// leaves them out.
	a.cmds = nil
	blank := cert(t)
	blank = append(bytes.ReplaceAll(blank, []byte("-----\n-----BEGIN"), []byte("-----\n\n\n-----BEGIN")), '\n', '\n')
	if !bytes.Contains(blank, []byte("\n\n")) {
		t.Fatal("test certificate has no empty line")
	}
	cfg.Certificates[0].PEM = blank
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if len(a.cmds) != 2 || !strings.HasPrefix(a.cmds[0], "set ssl cert ") || e.reloads != 0 {
		t.Errorf("renewal with empty lines: cmds = %q reloads=%d", a.cmds, e.reloads)
	}

	// A live update that still fails reloads, so the new file is served.
	a.cmds = nil
	a.err = errors.New("injected")
	cfg.Certificates[0].PEM = cert(t)
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	a.err = nil
	if e.reloads != 1 {
		t.Errorf("failed live update: reloads=%d", e.reloads)
	}
	e.reloads = 0

	// New route: structural change, validated then reloaded.
	cfg.Rules = append(cfg.Rules, proxy.Rule{Host: "www.example.org", PathPrefix: "/", Backend: "frontend"})
	cfg.Certificates = append(cfg.Certificates, proxy.Certificate{Name: "www.example.org", PEM: cert(t)})
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if e.reloads != 1 {
		t.Errorf("reloads = %d, want 1", e.reloads)
	}

	// Removed certificate files are deleted.
	cfg.Certificates = cfg.Certificates[:1]
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(etcDir(dir), certDir, "www.example.org.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Error("stale certificate not removed")
	}
	if err := d.Health(ctx); err != nil {
		t.Error(err)
	}
}

func TestApplyKeepsOldConfigWhenInvalid(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d, e, _, dir := newDriver(t)
	cfg := sampleConfig(t)
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(etcDir(dir), configFile))

	e.validateErr = errors.New("[ALERT] parsing error")
	cfg.Rules = cfg.Rules[:1]
	err := d.Apply(ctx, cfg)
	if err == nil || !strings.Contains(err.Error(), "keeping the current one") {
		t.Fatalf("err = %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(etcDir(dir), configFile))
	if string(before) != string(after) || e.reloads != 0 {
		t.Error("invalid config replaced the live one or triggered a reload")
	}
	if _, err := os.Stat(filepath.Join(etcDir(dir), configFile+".new")); !errors.Is(err, os.ErrNotExist) {
		t.Error("rejected config left behind")
	}

	// Once validation passes again, the change goes through.
	e.validateErr = nil
	if err := d.Apply(ctx, cfg); err != nil || e.reloads != 1 {
		t.Errorf("retry: err=%v reloads=%d", err, e.reloads)
	}
}

func TestApplyRejectsInvalidConfig(t *testing.T) {
	t.Parallel()
	d, e, _, _ := newDriver(t)
	cfg := sampleConfig(t)
	cfg.Rules[0].Host = "evil.com }\n    use_backend be_x"
	if err := d.Apply(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "refusing invalid") {
		t.Errorf("err = %v", err)
	}
	if e.starts != 0 {
		t.Error("HAProxy started with invalid config")
	}
}

func TestApplyStartFailure(t *testing.T) {
	t.Parallel()
	d, e, _, _ := newDriver(t)
	e.startErr = errors.New("port 80 in use")
	if err := d.Apply(context.Background(), sampleConfig(t)); err == nil || !strings.Contains(err.Error(), "port 80 in use") {
		t.Errorf("err = %v", err)
	}
	if err := d.Health(context.Background()); err == nil {
		t.Error("Health ok while not running")
	}
}

func TestRuntimeAPIErrorPropagates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d, _, a, _ := newDriver(t)
	cfg := sampleConfig(t)
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	a.err = errors.New("No such server")
	cfg.Backends[0].Servers[0].Address = "10.0.0.2:40000"
	if err := d.Apply(ctx, cfg); err == nil {
		t.Error("runtime API failure not reported")
	}
	// The failed change is retried on the next apply.
	a.err = nil
	a.cmds = nil
	if err := d.Apply(ctx, cfg); err != nil || len(a.cmds) != 2 {
		t.Errorf("retry: err=%v cmds=%v", err, a.cmds)
	}
}

// fakeSocket serves canned Runtime API answers on a Unix socket.
func fakeSocket(t *testing.T, answer func(req string) string) (string, *[]string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "hap") // short path for the socket limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var reqs []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 64<<10)
				var req strings.Builder
				for {
					n, err := c.Read(buf)
					req.Write(buf[:n])
					s := req.String()
					if err != nil || (strings.HasSuffix(s, "\n") && (!strings.Contains(s, "<<\n") || strings.HasSuffix(s, "\n\n"))) {
						break
					}
				}
				mu.Lock()
				reqs = append(reqs, req.String())
				mu.Unlock()
				_, _ = io.WriteString(c, answer(req.String()))
			}()
		}
	}()
	return path, &reqs
}

func TestSocket(t *testing.T) {
	t.Parallel()

	path, reqs := fakeSocket(t, func(req string) string {
		switch {
		case strings.HasPrefix(req, "show info"):
			return "Name: HAProxy\nVersion: 3.2\n"
		case strings.HasPrefix(req, "set server be_x/s1 addr"):
			return "No such server.\n"
		case strings.HasPrefix(req, "set ssl cert"):
			return "Transaction created for certificate /c.pem!\n"
		}
		return "\n"
	})
	s := Socket{Path: path}
	ctx := context.Background()

	out, err := s.Command(ctx, "show info")
	if err != nil || !strings.Contains(out, "HAProxy") {
		t.Errorf("show info = %q, %v", out, err)
	}
	if _, err := s.Command(ctx, "set server be_x/s1 addr 10.0.0.1 port 80"); err == nil {
		t.Error("error response not detected")
	}
	if _, err := s.Command(ctx, "set server be_x/s2 state ready"); err != nil {
		t.Errorf("empty response treated as error: %v", err)
	}
	if _, err := s.Payload(ctx, "set ssl cert /c.pem", "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"); err != nil {
		t.Errorf("payload: %v", err)
	}
	for _, bad := range []string{"show info\nshutdown sessions", "show info; disable frontend https"} {
		if _, err := s.Command(ctx, bad); err == nil {
			t.Errorf("multi-statement command %q accepted", bad)
		}
	}
	if _, err := s.Payload(ctx, "set ssl cert /c.pem", "a\n\nshutdown frontend https"); err == nil {
		t.Error("payload with empty line accepted (would end the payload early)")
	}
	if _, err := s.Payload(ctx, "x\ny", "a"); err == nil {
		t.Error("multi-line payload command accepted")
	}

	got := strings.Join(*reqs, "")
	if !strings.Contains(got, "set ssl cert /c.pem <<\n-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n\n") {
		t.Errorf("payload framing wrong: %q", got)
	}
	if _, err := (Socket{Path: filepath.Join(t.TempDir(), "none")}).Command(ctx, "show info"); err == nil {
		t.Error("missing socket not reported")
	}
}

func TestContainerEngine(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	rt := fake.New()
	dir := t.TempDir()
	e := &ContainerEngine{Runtime: rt, System: rt, Dir: dir, StartWait: time.Millisecond}

	if ok, _ := e.Running(ctx); ok {
		t.Error("running before start")
	}
	if err := e.Validate(ctx, "/x"); err == nil {
		t.Error("Validate without container succeeded")
	}
	if err := e.Reload(ctx); err == nil {
		t.Error("Reload without container succeeded")
	}

	// A stale HAProxy from an older image is replaced.
	rt.Add(runtime.Container{ID: "old", State: runtime.StateRunning, Labels: map[string]string{runtime.LabelSystem: systemLabel, imageLabel: "haproxy:2.8"}})
	if ok, _ := e.Running(ctx); ok {
		t.Error("container with a different image counted as running")
	}
	// So is one serving another data directory.
	rt.Add(runtime.Container{ID: "elsewhere", State: runtime.StateRunning, Labels: map[string]string{runtime.LabelSystem: systemLabel, imageLabel: Image, dirLabel: "/var/lib/other"}})
	if ok, _ := e.Running(ctx); ok {
		t.Error("container mounting another directory counted as running")
	}
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"old", "elsewhere"} {
		if _, err := rt.Inspect(ctx, id); !errors.Is(err, runtime.ErrNotFound) {
			t.Errorf("stale HAProxy container %s not removed", id)
		}
	}
	if ok, _ := e.Running(ctx); !ok {
		t.Error("not running after start")
	}
	if len(rt.Pulls) != 1 || rt.Pulls[0] != Image {
		t.Errorf("pulls = %v", rt.Pulls)
	}
	s := rt.Systems[0]
	if s.User != "0:0" || len(s.CapAdd) != 1 || s.CapAdd[0] != "NET_BIND_SERVICE" {
		t.Errorf("system spec = %+v", s)
	}
	if !s.Mounts[0].ReadOnly || s.Mounts[0].Source != etcDir(dir) || s.Mounts[1].ReadOnly {
		t.Errorf("mounts = %+v", s.Mounts)
	}
	if s.Labels[runtime.LabelManaged] != "" {
		t.Error("system container must not carry the app-managed label (the agent would remove it)")
	}
	if !strings.Contains(Image, "@sha256:") {
		t.Error("HAProxy image must be pinned by digest")
	}

	rt.ExecFunc = func(_ string, cmd []string) (string, int, error) {
		if strings.Join(cmd, " ") != "haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg.new" {
			t.Errorf("exec = %v", cmd)
		}
		return "[ALERT] config : parsing [haproxy.cfg.new:3]", 1, nil
	}
	if err := e.Validate(ctx, "/usr/local/etc/haproxy/haproxy.cfg.new"); err == nil || !strings.Contains(err.Error(), "ALERT") {
		t.Errorf("Validate = %v", err)
	}
	rt.ExecFunc = nil
	if err := e.Validate(ctx, "/usr/local/etc/haproxy/haproxy.cfg.new"); err != nil {
		t.Error(err)
	}
	if err := e.Reload(ctx); err != nil || rt.Signals[0] != "SIGUSR2" {
		t.Errorf("Reload = %v, signals = %v", err, rt.Signals)
	}
}

func TestContainerEngineStartFailure(t *testing.T) {
	t.Parallel()
	rt := fake.New()
	rt.SystemExits = 1
	rt.LogLines = []runtime.LogFrame{{Stream: runtime.Stderr, Data: []byte("[ALERT] cannot bind socket :80")}}
	e := &ContainerEngine{Runtime: rt, System: rt, Dir: t.TempDir(), StartWait: time.Millisecond}
	err := e.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "cannot bind socket") {
		t.Errorf("err = %v, want HAProxy's own error", err)
	}
}

// render must refuse smuggled directives even when validation is bypassed.
func TestRenderRefusesUnsafeTokens(t *testing.T) {
	t.Parallel()
	for name, mut := range map[string]func(*proxy.Config){
		"server address": func(c *proxy.Config) { c.Backends[0].Servers[0].Address = "[fd00::1%x\n    global x]:80" },
		"backend name":   func(c *proxy.Config) { c.Backends[0].Name = "web\nbind :1" },
		"rule host":      func(c *proxy.Config) { c.Rules[0].Host = "a.test }  or { always_true" },
		"health path":    func(c *proxy.Config) { c.Backends[0].HealthPath = "/h\r\nx" },
		"acme":           func(c *proxy.Config) { c.ACMEAddress = "10.0.0.2:80\tbackup" },
		"caller":         func(c *proxy.Config) { c.Rules[5].Allow = []string{"api-bengkel }  or { always_true"} },
	} {
		cfg := sampleConfig(t)
		mut(&cfg)
		if out := render(cfg, assignLayout(nil, cfg, renderOptions{PrivateIP: ""}.node()), renderOptions{}); out != nil {
			t.Errorf("%s: rendered an unsafe config", name)
		}
	}
	if render(sampleConfig(t), assignLayout(nil, sampleConfig(t), renderOptions{PrivateIP: ""}.node()), renderOptions{}) == nil {
		t.Error("valid config refused")
	}
}

func TestLocalFirst(t *testing.T) {
	t.Parallel()
	cfg := sampleConfig(t)
	opts := renderOptions{PrivateIP: "10.0.0.2"}
	out := string(render(cfg, assignLayout(nil, cfg, opts.node()), opts))
	backend := func(out, name string) string {
		_, rest, ok := strings.Cut(out, "backend "+name+"\n")
		if !ok {
			t.Fatalf("no backend %s", name)
		}
		body, _, _ := strings.Cut(rest, "\n\n")
		return body
	}
	// This node's replica weighs more; requests in progress decide.
	shop := backend(out, "be_shop")
	for _, want := range []string{"balance leastconn", "server s1 10.0.0.3:32771 weight 10", "server s2 10.0.0.2:32772 weight 11"} {
		if !strings.Contains(shop, want) {
			t.Errorf("be_shop misses %q:\n%s", want, shop)
		}
	}
	// Traffic splitting keeps its weights and takes turns.
	split := backend(out, "be_api-bengkel")
	if !strings.Contains(split, "balance roundrobin") || !strings.Contains(split, "weight 230") {
		t.Errorf("a split app changed:\n%s", split)
	}
	// Without the node's private IP nothing is local.
	out = string(render(cfg, assignLayout(nil, cfg, renderOptions{}.node()), renderOptions{}))
	if strings.Contains(out, "leastconn") || strings.Contains(backend(out, "be_shop"), "weight") {
		t.Errorf("local-first without a private IP:\n%s", backend(out, "be_shop"))
	}
	at := func(ip, subnet string) node { return renderOptions{PrivateIP: ip, Subnet: subnet}.node() }
	if !at("fd00::2", "").has("[fd00::2]:80") || at("10.0.0.2", "").has("10.0.0.20:80") || at("10.0.0.2", "").has("nope") {
		t.Error("node.has with published ports")
	}
	// With the cluster network, the node's replicas have addresses in its
	// subnet (ADR 0025); other nodes' subnets are not local.
	n := at("10.0.0.2", "10.120.3.0/24")
	if !n.has("10.120.3.7:8080") || !n.has("10.0.0.2:21000") || n.has("10.120.4.7:8080") || at("", "10.120.3.0/24").has("10.120.3.7:8080") {
		t.Error("node.has with a subnet")
	}
	p := backendPool(proxy.Backend{Name: "web", LocalFirst: true, Servers: []proxy.Server{
		{Name: "web-a", Address: "10.120.3.7:8080"}, {Name: "web-b", Address: "10.120.4.7:8080"},
	}}, n)
	if p.servers[0].Weight != localWeight || p.servers[1].Weight != remoteWeight {
		t.Errorf("weights %+v", p.servers)
	}
}

// The first replica on a node, and the last one leaving it, only change a
// server: no reload, and the other replicas keep serving.
func TestLocalFirstMovesWithoutReload(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d, e, a, _ := newDriver(t)
	cfg := proxy.Config{
		Backends: []proxy.Backend{{Name: "web", LocalFirst: true, Servers: []proxy.Server{{Name: "web-a", Address: "10.0.0.9:80"}}}},
		Rules:    []proxy.Rule{{Host: "web.example.org", PathPrefix: "/", Backend: "web"}},
	}
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	e.running = true
	before := e.reloads
	cfg.Backends[0].Servers = append(cfg.Backends[0].Servers, proxy.Server{Name: "web-b", Address: "10.0.0.2:80"})
	a.cmds = nil
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	f := containerConfDir + "/" + localFile
	want := []string{"set server be_web/s2 weight 11", "set server be_web/s2 addr 10.0.0.2 port 80", "set server be_web/s2 state ready",
		"prepare map " + f, "add map @7 " + f + " <<payload:48", "commit map @7 " + f}
	if strings.Join(a.cmds, "|") != strings.Join(want, "|") || e.reloads != before {
		t.Errorf("commands = %q, want %q (reloads %d)", a.cmds, want, e.reloads-before)
	}
	cfg.Backends[0].Servers = cfg.Backends[0].Servers[:1]
	a.cmds = nil
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	want = []string{"set server be_web/s2 state maint", "prepare map " + f, "commit map @7 " + f}
	if strings.Join(a.cmds, "|") != strings.Join(want, "|") || e.reloads != before {
		t.Errorf("commands = %q, want %q (reloads %d)", a.cmds, want, e.reloads-before)
	}
}

func TestLocalMap(t *testing.T) {
	t.Parallel()
	n := renderOptions{PrivateIP: "10.0.0.2", Subnet: "10.120.3.0/24"}.node()
	cfg := proxy.Config{Backends: []proxy.Backend{
		{Name: "two", LocalFirst: true, Servers: []proxy.Server{
			{Name: "a", Address: "10.120.4.7:80"}, {Name: "b", Address: "10.120.3.7:80"}, {Name: "c", Address: "10.0.0.2:81"},
		}},
		{Name: "away", LocalFirst: true, Servers: []proxy.Server{{Name: "d", Address: "10.120.4.8:80"}}},
		{Name: "split", Servers: []proxy.Server{{Name: "e", Address: "10.120.3.9:80"}}},
	}}
	got := string(localMap(cfg, assignLayout(nil, cfg, n), n))
	want := "be_two/0 s2\nbe_two/1 s3\nbe_two/2 s2\nbe_two/3 s3\n"
	if got != want {
		t.Errorf("map %q, want %q", got, want)
	}
	if got := localMap(cfg, assignLayout(nil, cfg, node{}), node{}); len(got) != 0 {
		t.Errorf("a map without the node's address: %q", got)
	}
}

func TestMapChunks(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	for i := range 3000 {
		fmt.Fprintf(&b, "be_app%d/0 s1\n", i)
	}
	chunks := mapChunks([]byte(b.String()), 1024)
	var joined []byte
	for _, c := range chunks {
		if len(c) > 1024 || c[len(c)-1] != '\n' {
			t.Fatalf("chunk of %d bytes ending in %q", len(c), c[len(c)-1])
		}
		joined = append(joined, c...)
	}
	if string(joined) != b.String() {
		t.Error("chunks lost content")
	}
	if got := mapChunks(nil, 1024); len(got) != 0 {
		t.Errorf("chunks of nothing: %q", got)
	}
}

// Balancing is part of the configuration, so leaving local-first reloads.
func TestLocalFirstChangeReloads(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d, e, _, _ := newDriver(t)
	cfg := proxy.Config{Backends: []proxy.Backend{{Name: "web", LocalFirst: true, Servers: []proxy.Server{{Name: "web-a", Address: "10.0.0.9:80"}}}}}
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	e.running = true
	before := e.reloads
	cfg.Backends[0].LocalFirst = false
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if e.reloads != before+1 {
		t.Errorf("reloads = %d, want 1", e.reloads-before)
	}
}

// A changed list of trusted proxies only takes effect through a reload: the
// frontend's rules are not something the Runtime API can change.
func TestTrustedProxiesChangeReloads(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d, e, _, _ := newDriver(t)
	cfg := proxy.Config{Backends: []proxy.Backend{{Name: "web", Servers: []proxy.Server{{Name: "web-1", Address: "10.0.0.2:80"}}}}}
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	e.running = true
	for _, trusted := range [][]string{{"192.0.2.0/24"}, {"192.0.2.0/24", "198.51.100.0/24"}, nil} {
		before := e.reloads
		cfg.TrustedProxies = trusted
		if err := d.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if e.reloads != before+1 {
			t.Errorf("%v: reloads = %d, want 1", trusted, e.reloads-before)
		}
	}
	before := e.reloads
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if e.reloads != before {
		t.Error("reloaded with nothing changed")
	}
}

func TestSetClients(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "haproxy")
	e := &fakeEngine{}
	a := &fakeAPI{reply: func(cmd string) string {
		if strings.HasPrefix(cmd, "prepare map") {
			return "New version created: 7"
		}
		return ""
	}}
	d, err := New(Config{Dir: dir, PrivateIP: "10.0.0.2", InternalIP: "10.120.0.1", Subnet: "10.120.0.0/24", Engine: e, API: a})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "etc", clientsFile)
	if b, err := os.ReadFile(file); err != nil || len(b) != 0 {
		t.Fatalf("clients map at start = %q, %v", b, err)
	}
	clients := map[netip.Addr]string{
		netip.MustParseAddr("10.120.0.9"): "db.staging",
		netip.MustParseAddr("10.120.0.3"): "web",
	}
	// Not running: only the file changes.
	if err := d.SetClients(ctx, clients); err != nil {
		t.Fatal(err)
	}
	want := "10.120.0.3 default:web\n10.120.0.9 staging:db.staging\n"
	if b, _ := os.ReadFile(file); string(b) != want {
		t.Errorf("clients map = %q, want %q", b, want)
	}
	if len(a.cmds) != 0 {
		t.Errorf("commands while stopped: %q", a.cmds)
	}
	// Running: the map is swapped live, in one version.
	e.running = true
	clients[netip.MustParseAddr("10.120.0.4")] = "web"
	if err := d.SetClients(ctx, clients); err != nil {
		t.Fatal(err)
	}
	m := containerConfDir + "/" + clientsFile
	wantCmds := []string{"prepare map " + m, fmt.Sprintf("add map @7 %s <<payload:%d", m, len(want)+len("10.120.0.4 default:web\n")), "commit map @7 " + m}
	if !slices.Equal(a.cmds, wantCmds) {
		t.Errorf("commands = %q, want %q", a.cmds, wantCmds)
	}
	// Unchanged: nothing to do.
	a.cmds = nil
	if err := d.SetClients(ctx, clients); err != nil || len(a.cmds) != 0 {
		t.Errorf("unchanged map: %v %q", err, a.cmds)
	}
	// Every container gone: an empty version is committed.
	if err := d.SetClients(ctx, map[netip.Addr]string{}); err != nil || len(a.cmds) != 2 {
		t.Errorf("empty map: %v %q", err, a.cmds)
	}
	// Addresses outside the node subnet and invalid apps are refused, and
	// the map stays as it was.
	for name, bad := range map[string]map[netip.Addr]string{
		"other subnet": {netip.MustParseAddr("10.120.1.3"): "web"},
		"bad app":      {netip.MustParseAddr("10.120.0.3"): "web shop"},
		"IPv6":         {netip.MustParseAddr("fd00::3"): "web"},
		"injection":    {netip.MustParseAddr("10.120.0.3"): "web\n10.120.0.66 staging:db.staging"},
	} {
		if err := d.SetClients(ctx, bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if b, _ := os.ReadFile(file); len(b) != 0 {
		t.Errorf("map changed by refused clients: %q", b)
	}
	// An odd answer to prepare map stops the update.
	a.reply = func(string) string { return "New version created: 7; show info" }
	if err := d.SetClients(ctx, clients); err == nil {
		t.Error("odd prepare answer accepted")
	}
	// Nodes off the cluster network do not check callers.
	plain, pe, pa, _ := newDriver(t)
	pe.running = true
	if err := plain.SetClients(ctx, clients); err != nil || len(pa.cmds) != 0 {
		t.Errorf("node without a subnet: %v %q", err, pa.cmds)
	}
}

// A request's cost must not grow with the apps of the cluster, with or
// without a replica on this node: an app without paths adds no rule to a
// frontend.
func TestRulesPerFrontendStayConstant(t *testing.T) {
	t.Parallel()
	opts := renderOptions{PrivateIP: "10.0.0.2", InternalIP: "10.120.3.1", Subnet: "10.120.3.0/24"}
	for _, addr := range []string{"10.120.3.7:80", "10.120.4.7:80"} {
		rules := func(apps int) int {
			cfg := proxy.Config{}
			for i := range apps {
				name := fmt.Sprintf("app%d", i)
				cfg.Backends = append(cfg.Backends, proxy.Backend{Name: name, LocalFirst: true, Servers: []proxy.Server{{Name: name + "-a", Address: addr}}})
				cfg.Rules = append(cfg.Rules, proxy.Rule{Host: name + ".internal", PathPrefix: "/", Backend: name, Internal: true})
			}
			out, _, _ := strings.Cut(string(render(cfg, assignLayout(nil, cfg, opts.node()), opts)), "\nbackend ")
			return strings.Count(out, "http-request") + strings.Count(out, "use_backend")
		}
		if few, many := rules(2), rules(400); few != many {
			t.Errorf("replicas at %s: %d rules with 2 apps, %d with 400", addr, few, many)
		}
	}
}

func TestRouteMap(t *testing.T) {
	t.Parallel()
	backends := map[string]proxy.Backend{"web.shop": {Name: "web.shop"}, "wake": {Name: "wake", Wake: true}}
	rules := []proxy.Rule{
		{Host: "web.shop.internal", PathPrefix: "/", Backend: "web.shop", Internal: true},
		{Host: "api.shop.internal", PathPrefix: "/v1", Backend: "web.shop", Internal: true},
		{Host: "only.shop.internal", PathPrefix: "/", Backend: "web.shop", Internal: true, Allow: []string{"a.shop"}},
		{Host: "wake.internal", PathPrefix: "/", Backend: "wake", Internal: true},
	}
	name, content := routeMap(routesInternal, rules, backends, true)
	// The key holds the project: another project's caller finds no route.
	if want := "shop/web.shop.internal be_web.shop\n"; string(content) != want {
		t.Errorf("map %q, want %q", content, want)
	}
	if !strings.HasPrefix(name, routeFilePrefix+routesInternal+"-") || !strings.HasSuffix(name, ".map") {
		t.Errorf("name %q", name)
	}
	if other, _ := routeMap(routesInternal, rules[:0], backends, true); other != "" {
		t.Errorf("a map without mapped rules: %q", other)
	}
	if plain, _ := routeMap(routesPublic, rules[:1], backends, false); plain == name {
		t.Error("the frontends share a map name")
	}
}

func TestApplyWritesRouteMaps(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d, _, _, dir := newDriver(t)
	cfg := sampleConfig(t)
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	list := func() []string {
		m, err := filepath.Glob(filepath.Join(etcDir(dir), routeFilePrefix+"*"))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	first := list()
	if len(first) == 0 {
		t.Fatal("no route map")
	}
	content, err := os.ReadFile(first[0])
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(first[0]); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, err %v", fi.Mode(), err)
	}
	if !strings.Contains(string(content), " be_") {
		t.Errorf("content %q", content)
	}
	// A changed map replaces the old one once the proxy reloaded.
	cfg.Rules = append(cfg.Rules, proxy.Rule{Host: "new.example.com", PathPrefix: "/", Backend: cfg.Rules[0].Backend})
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if next := list(); len(next) != len(first) || slices.Equal(next, first) {
		t.Errorf("route maps %v after %v", next, first)
	}
}

// A silent WebSocket outlives the request timeouts, and a reload's old process
// does not stay forever for the connections it still holds.
func TestLongLivedConnectionLimits(t *testing.T) {
	out := string(render(proxy.Config{}, Layout{}, renderOptions{}))
	for _, want := range []string{"    timeout tunnel 1h\n", "    hard-stop-after 1h\n", "    timeout server 60s\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("config lacks %q", want)
		}
	}
}

// A new agent keeps a proxy that still runs the right structure: no reload,
// each replica in its slot, and only what changed goes through the Runtime API.
func TestApplyTakesOverRunningProxy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d, e, _, dir := newDriver(t)
	cfg := proxy.Config{Backends: []proxy.Backend{{Name: "web", Servers: []proxy.Server{
		{Name: "a", Address: "10.0.0.2:81"}, {Name: "b", Address: "10.0.0.3:82"},
	}}}}
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	e.running = true
	e.mu.Unlock()

	state := "1\n# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_port\n" +
		// Reversed slots, one replica since gone, and a free slot with an old address.
		"3 be_web 1 s1 10.0.0.3 2 0 1 82\n3 be_web 2 s2 10.0.0.2 2 0 1 81\n3 be_web 3 s3 10.0.0.9 2 0 1 89\n3 be_web 4 s4 10.0.0.8 0 5 1 88\n"
	a2 := &fakeAPI{reply: func(cmd string) string {
		if cmd == "show servers state" {
			return state
		}
		if strings.HasPrefix(cmd, "prepare map") {
			return "New version created: 7"
		}
		return ""
	}}
	d2, err := New(Config{Dir: dir, PrivateIP: "10.0.0.2", Engine: e, API: a2})
	if err != nil {
		t.Fatal(err)
	}
	reloads := e.reloads
	if err := d2.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if e.reloads != reloads {
		t.Errorf("reloaded a proxy with the right structure")
	}
	joined := strings.Join(a2.cmds, "\n")
	if strings.Contains(joined, "s1 addr") || strings.Contains(joined, "s2 addr") {
		t.Errorf("moved replicas between slots:\n%s", joined)
	}
	if !strings.Contains(joined, "set server be_web/s3 state maint") {
		t.Errorf("left a slot serving a gone replica:\n%s", joined)
	}
	if strings.Contains(joined, "be_web/s4") {
		t.Errorf("touched a free slot:\n%s", joined)
	}

	// A structure the proxy does not run needs a reload, as does a new agent
	// that cannot read it.
	d3, _ := New(Config{Dir: dir, PrivateIP: "10.0.0.2", Engine: e, API: a2})
	more := proxy.Config{Backends: append(slices.Clone(cfg.Backends), proxy.Backend{Name: "api", Servers: []proxy.Server{{Name: "c", Address: "10.0.0.3:83"}}})}
	if err := d3.Apply(ctx, more); err != nil {
		t.Fatal(err)
	}
	if e.reloads != reloads+1 {
		t.Errorf("no reload for a new backend")
	}
	a4 := &fakeAPI{err: errors.New("no socket")}
	d4, _ := New(Config{Dir: dir, PrivateIP: "10.0.0.2", Engine: e, API: a4})
	_ = d4.Apply(ctx, more)
	if e.reloads != reloads+2 {
		t.Errorf("no reload when the proxy cannot say what it runs")
	}
}

// A change only of servers goes through the Runtime API, and the file keeps up
// without a configuration check; a new structure is checked first.
func TestValidateOnlyNewStructure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d, e, _, dir := newDriver(t)
	cfg := func(addr string, names ...string) proxy.Config {
		var c proxy.Config
		for _, n := range names {
			c.Backends = append(c.Backends, proxy.Backend{Name: n, Servers: []proxy.Server{{Name: n + "-1", Address: addr}}})
		}
		return c
	}
	if err := d.Apply(ctx, cfg("10.0.0.2:81", "web")); err != nil {
		t.Fatal(err)
	}
	n := len(e.validations)
	if err := d.Apply(ctx, cfg("10.0.0.2:82", "web")); err != nil {
		t.Fatal(err)
	}
	if len(e.validations) != n {
		t.Errorf("checked a configuration that only moved a server")
	}
	b, err := os.ReadFile(filepath.Join(dir, "etc", configFile))
	if err != nil || !strings.Contains(string(b), "10.0.0.2:82") {
		t.Errorf("file not updated: %v", err)
	}
	if err := d.Apply(ctx, cfg("10.0.0.2:82", "web", "api")); err != nil {
		t.Fatal(err)
	}
	if len(e.validations) != n+1 {
		t.Errorf("a new backend was not checked")
	}
}

func TestBackendTimeout(t *testing.T) {
	t.Parallel()
	cfg := proxy.Config{Backends: []proxy.Backend{{Name: "web", TimeoutSeconds: 300}}}
	out := string(render(cfg, assignLayout(nil, cfg, node{}), renderOptions{}))
	if !strings.Contains(out, "backend be_web\n    timeout server 300s\n") {
		t.Errorf("no timeout in the backend:\n%s", out)
	}
	for _, bad := range []int{-1, proxy.MaxTimeoutSeconds + 1} {
		cfg.Backends[0].TimeoutSeconds = bad
		if err := cfg.Validate(); err == nil {
			t.Errorf("accepted a timeout of %d", bad)
		}
	}
	// A change is structural: it needs a reload.
	a, b := proxy.Config{Backends: []proxy.Backend{{Name: "web"}}}, proxy.Config{Backends: []proxy.Backend{{Name: "web", TimeoutSeconds: 300}}}
	l := assignLayout(nil, a, node{})
	if signature(a, l, renderOptions{}) == signature(b, l, renderOptions{}) {
		t.Error("the signature does not see the timeout")
	}
}

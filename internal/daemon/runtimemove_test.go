package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/proxy/haproxy"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
	"github.com/ryanbekhen/armada/internal/store"
)

// When the leader moves a containerd node (ADR 0054), the running agent
// does what runtime migrate does with its own runtime: every container
// goes, agent.json records the supervisor, containerd stops, and the
// node's service restarts; when systemd cannot restart it, the process
// exits so the unit starts it again.
func TestNodeMove(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ac := &agentConfig{NodeID: "n1", PrivateIP: "10.0.0.2", Servers: []string{"10.0.0.2:7443"}, Runtime: runtimeEmbedded}
	if err := saveAgentConfig(dir, *ac); err != nil {
		t.Fatal(err)
	}
	if err := saveRuntimeMovePlan(dir, &armadav1.RuntimeMovePlan{State: "moving"}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	d := fake.New()
	if _, err := d.Run(ctx, runtime.ContainerSpec{Name: "armada-web", Image: "x", Labels: map[string]string{runtime.LabelManaged: "true"}}); err != nil {
		t.Fatal(err)
	}
	var (
		calls  []string
		exited []int
	)
	sysErr := map[string]error{}
	m := nodeMove{dataDir: dir, mu: &sync.Mutex{}, ac: ac, rt: d, unit: unitAgent, log: slog.New(slog.DiscardHandler),
		systemctl: func(_ context.Context, args ...string) error {
			c := strings.Join(args, " ")
			calls = append(calls, c)
			return sysErr[c]
		},
		exit: func(code int) { exited = append(exited, code) },
	}

	if err := m.run(ctx, "embedded"); err == nil {
		t.Error("moved to containerd")
	}
	if err := m.run(ctx, runtimeSupervisor); err != nil {
		t.Fatal(err)
	}
	if cs, _ := d.List(ctx, nil); len(cs) != 0 {
		t.Errorf("containers left: %v", cs)
	}
	got, err := loadAgentConfig(dir)
	if err != nil || got.Runtime != runtimeSupervisor || got.NodeID != "n1" || ac.Runtime != runtimeSupervisor {
		t.Fatalf("agent.json %+v (%v), in memory %q", got, err, ac.Runtime)
	}
	if strings.Join(calls, "; ") != "stop armada-runtime; --no-block restart armada-agent" || len(exited) != 0 {
		t.Errorf("systemctl %q, exits %v", calls, exited)
	}
	if _, err := os.Stat(filepath.Join(dir, fileRuntimeMove)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the leader's plan is kept after the move: %v", err)
	}
	// Moved already: refused.
	if err := m.run(ctx, runtimeSupervisor); err == nil {
		t.Error("moved a supervisor node")
	}

	// A server machine whose unit cannot be restarted exits instead.
	ac.Runtime = runtimeEmbedded
	calls = nil
	m.unit = unitServer
	sysErr["--no-block restart armada-server"] = errors.New("no systemd")
	if err := m.run(ctx, runtimeSupervisor); err != nil {
		t.Fatal(err)
	}
	if len(exited) != 1 || exited[0] != 1 {
		t.Errorf("exits %v after %q", exited, calls)
	}

	// A container that cannot be removed keeps the node on containerd.
	ac.Runtime = runtimeEmbedded
	if err := saveAgentConfig(dir, *ac); err != nil {
		t.Fatal(err)
	}
	m.rt = failingRemove{d}
	if _, err := d.Run(ctx, runtime.ContainerSpec{Name: "armada-db", Image: "x", Labels: map[string]string{runtime.LabelManaged: "true"}}); err != nil {
		t.Fatal(err)
	}
	if err := m.run(ctx, runtimeSupervisor); err == nil || !strings.Contains(err.Error(), "still runs on embedded") {
		t.Errorf("with a container left: %v", err)
	}
	if got, _ := loadAgentConfig(dir); got.Runtime != runtimeEmbedded || ac.Runtime != runtimeEmbedded {
		t.Errorf("runtime recorded %q (memory %q) with a container left", got.Runtime, ac.Runtime)
	}
}

// The move writes only the runtime into agent.json as it is on disk: what
// the agent saved since it started (a new control plane list, the network's
// new mode) stays, though the agent's own copy is older. A lab cluster lost
// its leader's machine for good when the move put back the list of one
// server the agent had started with.
func TestNodeMoveKeepsNewerAgentConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	started := agentConfig{NodeID: "lab1", PrivateIP: "10.0.0.1", Servers: []string{"10.0.0.1:7443"}, Runtime: runtimeEmbedded, Network: "plain", ContainerSubnet: "10.120.0.0/24"}
	if err := saveAgentConfig(dir, started); err != nil {
		t.Fatal(err)
	}
	ac, err := loadAgentConfig(dir) // the agent's copy at its start
	if err != nil {
		t.Fatal(err)
	}
	// Later writers: the control plane list (onServers), the network's
	// mode (nodeNet), an endpoint (armadad endpoint set).
	all := []string{"10.0.0.1:7443", "10.0.0.2:7443", "10.0.0.3:7443"}
	if _, err := updateAgentConfig(dir, func(c *agentConfig) error {
		c.Servers = all
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := updateAgentConfig(dir, func(c *agentConfig) error {
		c.Network, c.Endpoint = "wireguard", "203.0.113.5"
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	m := nodeMove{dataDir: dir, mu: &sync.Mutex{}, ac: ac, rt: fake.New(), unit: unitServer, log: slog.New(slog.DiscardHandler),
		systemctl: func(context.Context, ...string) error { return nil }, exit: func(int) { t.Error("exited") }}
	if err := m.run(context.Background(), runtimeSupervisor); err != nil {
		t.Fatal(err)
	}
	got, err := loadAgentConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := started
	want.Servers, want.Network, want.Endpoint, want.Runtime = all, "wireguard", "203.0.113.5", runtimeSupervisor
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("agent.json after the move\n got %+v\nwant %+v", *got, want)
	}

	// runtime migrate with an older copy too.
	ac.Runtime = runtimeSupervisor
	if err := migrateRuntime(context.Background(), dir, ac, fake.New(), runtimeEmbedded, io.Discard, io.Discard, func(context.Context, ...string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	got, _ = loadAgentConfig(dir)
	want.Runtime = runtimeEmbedded
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("agent.json after migrate\n got %+v\nwant %+v", *got, want)
	}
}

// Before the move removes anything, the node pulls its proxy's image with
// the pack's armada-node into armada-node's store, by the pinned digest and
// with no credentials, as the restarted agent's Driver.Pull will; a failed
// pull is only logged, and a node that will not run containers through
// armada-node pulls nothing.
func TestNodeMovePrepare(t *testing.T) {
	dir := t.TempDir()
	ac := &agentConfig{NodeID: "n1", Runtime: runtimeEmbedded}
	type pulled struct{ bin, image string }
	var (
		pulls []pulled
		fail  error
	)
	m := nodeMove{dataDir: dir, mu: &sync.Mutex{}, ac: ac, log: slog.New(slog.DiscardHandler),
		images: []string{haproxy.Image},
		pull: func(ctx context.Context, bin, image string) error {
			if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > prePullTimeout {
				t.Errorf("pull deadline %v (%v)", dl, ok)
			}
			pulls = append(pulls, pulled{bin, image})
			return fail
		},
	}
	ctx := context.Background()

	// No armada-node in the pack yet: nothing to pull with.
	m.prepare(ctx, runtimeSupervisor)
	if len(pulls) != 0 {
		t.Fatalf("pulled without armada-node: %v", pulls)
	}
	bin := filepath.Join(runtimePaths(dir).Bin(), embedded.BinNode)
	if err := os.MkdirAll(filepath.Dir(bin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	m.prepare(ctx, runtimeEmbedded)
	if len(pulls) != 0 {
		t.Fatalf("pulled for a move to containerd: %v", pulls)
	}
	m.prepare(ctx, runtimeSupervisor)
	if want := []pulled{{bin, haproxy.Image}}; !slices.Equal(pulls, want) {
		t.Fatalf("pulls %v, want %v", pulls, want)
	}
	// A failed pull is logged, and the move goes on.
	fail = errors.New("registry unreachable")
	m.prepare(ctx, runtimeSupervisor)
	if len(pulls) != 2 {
		t.Errorf("pulls %v", pulls)
	}
	// Go's code after the restart opens Go's store: nothing pulled.
	ac.RuntimeAgent = runtimeAgentGo
	m.prepare(ctx, runtimeSupervisor)
	if len(pulls) != 2 {
		t.Errorf("pulled for Go's code: %v", pulls)
	}
	// --proxy none: no image.
	ac.RuntimeAgent, m.images = "", nil
	m.prepare(ctx, runtimeSupervisor)
	if len(pulls) != 2 {
		t.Errorf("pulled with no proxy: %v", pulls)
	}
}

// pullIntoNode runs armada-node runtime pull on the store the supervisor
// runtime opens (<data dir>/node/images) with the reference alone: no
// credentials, so the record is one anyone may use.
func TestPullIntoNode(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "call")
	bin := filepath.Join(dir, "armada-node")
	script := "#!/bin/sh\necho \"$@\" >" + out + "\ncat >>" + out + "\necho '{\"ref\":\"x\"}'\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := pullIntoNode(context.Background(), dir, bin, haproxy.Image); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	want := "runtime pull " + filepath.Join(dir, "node", "images") + "\n" + `{"image":"` + haproxy.Image + `"}`
	if string(got) != want {
		t.Errorf("armada-node got\n%s\nwant\n%s", got, want)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho '{\"error\":\"pull haproxy: refused\"}'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := pullIntoNode(context.Background(), dir, bin, haproxy.Image); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("failed pull: %v", err)
	}
}

// systemctl restarting its own unit is stopped by systemd: that is the
// restart, not a failure to exit on.
func TestStoppedBySystemd(t *testing.T) {
	err := systemctlLike(exec.Command("sh", "-c", "kill -TERM $$"))
	if !stoppedBySystemd(err) {
		t.Errorf("SIGTERM: %v", err)
	}
	if err := systemctlLike(exec.Command("sh", "-c", "exit 1")); stoppedBySystemd(err) {
		t.Errorf("exit 1 counted as stopped: %v", err)
	}
	if stoppedBySystemd(errors.New("no systemd")) {
		t.Error("a plain error counted as stopped")
	}
}

// systemctlLike wraps a command's error as systemctl does.
func systemctlLike(c *exec.Cmd) error {
	if err := c.Run(); err != nil {
		return fmt.Errorf("systemctl restart: %w: ", err)
	}
	return nil
}

// A server machine's agent starts with every server the state records after
// agent.json's own, so it finds the leader when agent.json names only its
// own machine.
func TestKnownServers(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := saveAgentConfig(dir, agentConfig{NodeID: "lab1", PrivateIP: "10.0.0.1", Servers: []string{"10.0.0.1:7443"}}); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	st := serverLister{servers: []store.Server{{Name: "lab2", APIAddr: "10.0.0.2:7443"}, {Name: "lab1", APIAddr: "10.0.0.1:7443"}, {Name: "lab3", APIAddr: "10.0.0.3:7443"}}}
	if got := knownServers(context.Background(), st, dir, log); !slices.Equal(got, []string{"10.0.0.1:7443", "10.0.0.2:7443", "10.0.0.3:7443"}) {
		t.Errorf("servers %v", got)
	}
	if got := knownServers(context.Background(), serverLister{err: errors.New("no quorum")}, dir, log); got != nil {
		t.Errorf("with no state: %v", got)
	}
	bad := serverLister{servers: []store.Server{{Name: "x", APIAddr: "203.0.113.9:7443"}}}
	if got := knownServers(context.Background(), bad, dir, log); got != nil {
		t.Errorf("with a public address: %v", got)
	}
}

type serverLister struct {
	store.Store
	servers []store.Server
	err     error
}

func (s serverLister) ListServers(context.Context) ([]store.Server, error) { return s.servers, s.err }

type failingRemove struct{ *fake.Driver }

func (failingRemove) Remove(context.Context, string) error { return errors.New("busy") }

// The leader's plan for a containerd node is kept for doctor, which says
// what the cluster does with the node.
func TestRuntimeMovePlanForDoctor(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	read := func() (runtimeMoveNote, bool) { return readRuntimeMovePlan(fsutil.ReadPrivateFile, dir) }
	cases := []struct {
		plan *armadav1.RuntimeMovePlan
		want string
	}{
		{nil, "moves this node to the supervisor runtime by itself"},
		{&armadav1.RuntimeMovePlan{State: "moving"}, "is moving this node"},
		{&armadav1.RuntimeMovePlan{State: "queued", Reason: "one node moves at a time"}, "when its turn comes (one node moves at a time)"},
		{&armadav1.RuntimeMovePlan{State: "off"}, "turned off"},
		{&armadav1.RuntimeMovePlan{State: "waiting", Reason: "holds volumes of db", Operator: true}, "does not move this node by itself (holds volumes of db): drain it"},
		{&armadav1.RuntimeMovePlan{State: "waiting", Reason: "the other nodes have no room"}, "once it can (the other nodes have no room)"},
	}
	for _, c := range cases {
		if err := saveRuntimeMovePlan(dir, c.plan); err != nil {
			t.Fatal(err)
		}
		env := doctorEnv{euid: 0, driver: reportingDriver{fake.New(), runtime.AgentStatus{Agent: runtime.AgentContainerd}}, runtime: runtimeEmbedded, movePlan: read}
		got := runtimeAgentCheck(env)
		if len(got) != 1 || got[0].Status != checkWarn || !strings.Contains(got[0].Detail, c.want) {
			t.Errorf("plan %v: %+v, want %q", c.plan, got, c.want)
		}
	}
	if fi, err := os.Stat(filepath.Join(dir, fileRuntimeMove)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("note %v, %v", fi, err)
	}
}

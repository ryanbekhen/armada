//go:build linux

package clusternet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/encoding/protojson"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// fakeNode is a stand-in armada-node: for `net OP ...` it keeps its
// standard input in in-OP and prints out-OP, exiting with code-OP.
type fakeNode struct {
	dir, bin string
}

func newFakeNode(t *testing.T) *fakeNode {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "armada-node")
	script := fmt.Sprintf("#!/bin/sh\nop=$2\ncat > %[1]q/in-$op\ncat %[1]q/out-$op 2>/dev/null\nexit $(cat %[1]q/code-$op 2>/dev/null || echo 0)\n", dir)
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return &fakeNode{dir: dir, bin: bin}
}

// answer sets what the stand-in prints for op, and its exit code.
func (f *fakeNode) answer(t *testing.T, op, out string, code int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "out-"+op), []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "code-"+op), []byte(fmt.Sprint(code)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// input is what the stand-in last read for op.
func (f *fakeNode) input(t *testing.T, op string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, "in-"+op))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// logs keeps what a Net logs.
type logs struct {
	mu    sync.Mutex
	lines []string
}

func (l *logs) Enabled(context.Context, slog.Level) bool { return true }
func (l *logs) WithAttrs([]slog.Attr) slog.Handler       { return l }
func (l *logs) WithGroup(string) slog.Handler            { return l }
func (l *logs) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, r.Level.String()+" "+r.Message)
	return nil
}

func (l *logs) count(prefix string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, s := range l.lines {
		if strings.HasPrefix(s, prefix) {
			n++
		}
	}
	return n
}

// programNet is a Net running the stand-in, whose Go passes are counted
// instead of done.
func programNet(t *testing.T, f *fakeNode) (*Net, *logs, *int) {
	t.Helper()
	l := &logs{}
	key, err := LoadOrCreateKey(filepath.Join(t.TempDir(), "network.key"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := New(Config{Node: "a", PrivateIP: self, Key: key, KeyPath: filepath.Join(t.TempDir(), "network.key"),
		Logger: slog.New(l), Program: func() string { return f.bin }})
	if err != nil {
		t.Fatal(err)
	}
	goPasses := 0
	n.goApply = func(*armadav1.NetworkConfig, map[netip.Addr]string) error {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.takeOver()
		goPasses++
		return nil
	}
	return n, l, &goPasses
}

func twoNodes() *armadav1.NetworkConfig {
	return config(np("a", "10.0.0.1", "10.120.0.0/24"), np("b", "10.0.0.2", "10.120.1.0/24"))
}

// A pass through armada-node sends the node, its key, its containers, and
// what Net keeps, and takes back what armada-node kept; the probe it
// starts runs beside the agent and its answer makes the switch ready.
func TestProgramApply(t *testing.T) {
	f := newFakeNode(t)
	n, l, goPasses := programNet(t, f)
	bKey := newKey(t).PublicKey()
	n.wgSince = map[wgtypes.Key]wgPeerSeen{bKey: {node: "b", since: time.Unix(50, 0)}}
	n.nextClean, n.last = true, "before"
	f.answer(t, "apply", fmt.Sprintf(`{"error":"","needsUserspace":false,"state":{"Previous":{"cidr":"10.120.0.0/16"},
		"Clean":{"Next":false,"Site":true},"Switch":{"To":"wireguard","Step":"prepare","Error":"","Peers":["b"],"Reached":[],
		"Probed":false,"Probing":true,"Moved":false},"Since":[{"Key":%q,"Node":"b","Since":100}],"Last":"plain"},
		"probe":{"from":"10.120.0.0","peers":[{"node":"b","address":"10.120.1.0"}]},"done":["created armada-next"],
		"log":[{"level":"info","msg":"cluster network applied"},{"level":"warn","msg":"keep the peer list: no"}]}`, bKey), 0)
	f.answer(t, "probe", `{"reached":["b"],"error":""}`, 0)
	cfg := twoNodes()
	cfg.SwitchTo, cfg.SwitchStep = ModeWireGuard, SwitchPrepare
	local := map[netip.Addr]string{netip.MustParseAddr("10.120.0.5"): "web"}
	if err := n.Apply(context.Background(), cfg, local); err != nil {
		t.Fatal(err)
	}
	if *goPasses != 0 {
		t.Fatalf("Go did %d pass(es)", *goPasses)
	}
	var req struct {
		Config          json.RawMessage
		Node, PrivateIP string
		Key             string
		Local           map[string]string
		State           programState
		Userspace       bool
	}
	if err := json.Unmarshal(f.input(t, "apply"), &req); err != nil {
		t.Fatal(err)
	}
	sent := &armadav1.NetworkConfig{}
	if err := protojson.Unmarshal(req.Config, sent); err != nil || sent.GetSwitchTo() != ModeWireGuard {
		t.Fatalf("config %s, %v", req.Config, err)
	}
	if req.Node != "a" || req.PrivateIP != "10.0.0.1" || req.Key != n.cfg.Key.k.String() || req.Local["10.120.0.5"] != "web" {
		t.Fatalf("request %+v", req)
	}
	if string(req.State.Previous) != "null" || !req.State.Clean.Next || req.State.Last != "before" ||
		len(req.State.Since) != 1 || req.State.Since[0].Since != 50 || req.State.Since[0].Node != "b" {
		t.Fatalf("state sent %+v", req.State)
	}
	n.mu.Lock()
	if n.nextClean || !n.siteClean || n.last != "plain" || n.wgSince[bKey].since.Unix() != 100 || !n.prog.last ||
		string(n.prog.previous) != `{"cidr":"10.120.0.0/16"}` || !slices.Equal(n.prog.done, []string{"created armada-next"}) {
		t.Errorf("state kept: clean %v %v, last %q, since %v, previous %s", n.nextClean, n.siteClean, n.last, n.wgSince, n.prog.previous)
	}
	n.mu.Unlock()
	if l.count("WARN keep the peer list") != 1 || l.count("INFO cluster network applied") != 1 || l.count("INFO armada-node applies") != 1 {
		t.Errorf("logs %q", l.lines)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := n.SwitchStatus()
		if st.GetReady() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not ready after the probe: %v", st)
		}
		time.Sleep(20 * time.Millisecond)
	}
	var probe probeRequest
	if err := json.Unmarshal(f.input(t, "probe"), &probe); err != nil || probe.From != "10.120.0.0" || probe.Peers[0].Address != "10.120.1.0" {
		t.Fatalf("probe %+v, %v", probe, err)
	}
	// The next pass sends what armada-node kept, and that a probe runs.
	if err := n.Apply(context.Background(), cfg, nil); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(f.input(t, "apply"), &req); err != nil {
		t.Fatal(err)
	}
	if string(req.State.Previous) != `{"cidr":"10.120.0.0/16"}` || !req.State.Switch.Probing || !req.State.Switch.Probed ||
		!slices.Equal(req.State.Switch.Reached, []string{"b"}) || req.Local != nil {
		t.Errorf("second state sent %+v", req.State)
	}
}

// When armada-node fails, Go does the pass and builds the isolation tables
// again; each distinct failure is logged once, and a pass that needs the
// userspace device goes to Go without a warning.
func TestProgramFallsBack(t *testing.T) {
	f := newFakeNode(t)
	n, l, goPasses := programNet(t, f)
	f.answer(t, "apply", "", 1)
	for range 2 {
		n.mu.Lock()
		n.isolated = &policy{}
		n.mu.Unlock()
		if err := n.Apply(context.Background(), twoNodes(), nil); err != nil {
			t.Fatal(err)
		}
		n.mu.Lock()
		if n.isolated != nil || n.prog.last || n.prog.previous != nil {
			t.Errorf("Go's pass keeps the isolation policy %v (armada-node's last: %v)", n.isolated, n.prog.last)
		}
		n.mu.Unlock()
	}
	if *goPasses != 2 || l.count("WARN armada-node failed; Go did it instead") != 1 {
		t.Fatalf("%d Go passes, logs %q", *goPasses, l.lines)
	}
	// A pass error with the state: the state is taken, Go does the pass.
	f.answer(t, "apply", `{"error":"create armada-net: boom","state":{"Previous":null,"Clean":{"Next":true,"Site":true},"Switch":{},"Last":"x"}}`, 1)
	if err := n.Apply(context.Background(), twoNodes(), nil); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	if !n.nextClean || !n.siteClean || n.last != "x" {
		t.Errorf("state of the failed pass not taken: %v %v %q", n.nextClean, n.siteClean, n.last)
	}
	n.mu.Unlock()
	if *goPasses != 3 || l.count("WARN armada-node failed") != 2 {
		t.Fatalf("%d Go passes, logs %q", *goPasses, l.lines)
	}
	f.answer(t, "apply", `{"error":"no kernel WireGuard","needsUserspace":true,"state":{"Clean":{},"Switch":{}}}`, 0)
	if err := n.Apply(context.Background(), twoNodes(), nil); err != nil {
		t.Fatal(err)
	}
	if *goPasses != 4 || l.count("WARN") != 2 || l.count("INFO the kernel has no WireGuard") != 1 {
		t.Fatalf("%d Go passes, logs %q", *goPasses, l.lines)
	}
	// While the userspace device runs, armada-node is not asked.
	n.user = &userDevice{}
	f.answer(t, "apply", "", 1)
	if err := os.Remove(filepath.Join(f.dir, "in-apply")); err != nil {
		t.Fatal(err)
	}
	if err := n.Apply(context.Background(), twoNodes(), nil); err != nil {
		t.Fatal(err)
	}
	n.user = nil
	if _, err := os.Stat(filepath.Join(f.dir, "in-apply")); err == nil || *goPasses != 5 {
		t.Errorf("armada-node ran beside the userspace device (%d Go passes)", *goPasses)
	}
	// Without a program, Go.
	n.cfg.Program = func() string { return "" }
	if err := n.Apply(context.Background(), twoNodes(), nil); err != nil || *goPasses != 6 {
		t.Fatalf("no program: %v, %d Go passes", err, *goPasses)
	}
}

// Net's fields make the same state again after armada-node gives them
// back unchanged.
func TestProgramStateRoundTrip(t *testing.T) {
	n, err := New(Config{Node: "a", PrivateIP: self})
	if err != nil {
		t.Fatal(err)
	}
	k1, k2 := newKey(t).PublicKey(), newKey(t).PublicKey()
	n.wgSince = map[wgtypes.Key]wgPeerSeen{k1: {node: "b", since: time.Unix(10, 0)}, k2: {node: "c", since: time.Unix(20, 0)}}
	n.sw = switchState{to: ModePlain, step: SwitchPrepare, err: "e", peers: []string{"b", "c"}, reached: map[string]bool{"c": true, "b": false},
		probed: true, probing: true}
	n.nextClean, n.last = true, "summary"
	n.prog.last, n.prog.previous = true, json.RawMessage(`{"cidr":"x"}`)
	st := n.programState()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var back programState
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	m, err := New(Config{Node: "a", PrivateIP: self})
	if err != nil {
		t.Fatal(err)
	}
	m.takeProgramState(back)
	if again := m.programState(); !bytes.Equal(mustJSON(t, again), b) {
		t.Fatalf("round trip:\n%s\n%s", b, mustJSON(t, again))
	}
	if !m.sw.reached["c"] || m.sw.reached["b"] || m.wgSince[k2].node != "c" || !m.nextClean || m.last != "summary" {
		t.Errorf("fields %+v %+v", m.sw, m.wgSince)
	}
	// After a pass of Go's, armada-node builds the tables again.
	n.takeOver()
	if st := n.programState(); string(st.Previous) != "null" {
		t.Errorf("previous after Go's pass: %s", st.Previous)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// UnreachablePeers asks armada-node with when each peer was configured,
// nothing while a switch runs.
func TestProgramUnreachable(t *testing.T) {
	f := newFakeNode(t)
	n, _, _ := programNet(t, f)
	k := newKey(t).PublicKey()
	n.wgSince = map[wgtypes.Key]wgPeerSeen{k: {node: "b", since: time.Unix(7, 0)}}
	f.answer(t, "unreachable", `{"peers":["b"]}`, 0)
	if got := n.UnreachablePeers(); !slices.Equal(got, []string{"b"}) {
		t.Fatalf("got %v", got)
	}
	var req struct{ Since []programSeen }
	if err := json.Unmarshal(f.input(t, "unreachable"), &req); err != nil || len(req.Since) != 1 || req.Since[0].Key != k.String() || req.Since[0].Since != 7 {
		t.Fatalf("request %+v, %v", req, err)
	}
	f.answer(t, "unreachable", `{"peers":[]}`, 0)
	if got := n.UnreachablePeers(); got != nil {
		t.Fatalf("none: %#v", got)
	}
	n.sw.to = ModeWireGuard
	f.answer(t, "unreachable", `{"peers":["b"]}`, 0)
	if got := n.UnreachablePeers(); got != nil {
		t.Fatalf("while switching: %v", got)
	}
}

// RotateKey has armada-node write the key and takes it from the file; Go
// rotates it when armada-node fails.
func TestProgramRotateKey(t *testing.T) {
	f := newFakeNode(t)
	n, _, _ := programNet(t, f)
	made, err := LoadOrCreateKey(filepath.Join(t.TempDir(), "made.key"))
	if err != nil {
		t.Fatal(err)
	}
	// The stand-in for net key rotate: write the key made above.
	script := fmt.Sprintf("#!/bin/sh\ncp %q \"$4\" && echo %s\n", filepath.Join(filepath.Dir(f.bin), "made.key"), made.Public())
	if err := os.WriteFile(filepath.Join(f.dir, "made.key"), []byte(made.k.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rotate := filepath.Join(f.dir, "rotate")
	if err := os.WriteFile(rotate, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	n.cfg.Program = func() string { return rotate }
	pub, err := n.RotateKey()
	if err != nil || pub != made.Public() || n.cfg.Key.Public() != made.Public() {
		t.Fatalf("rotate: %q, %v", pub, err)
	}
	n.cfg.Program = func() string { return f.bin }
	f.answer(t, "key", "", 1)
	pub, err = n.RotateKey()
	if err != nil || pub == made.Public() || n.cfg.Key.Public() != pub {
		t.Fatalf("Go's rotation: %q, %v", pub, err)
	}
}

// DiagnoseWith takes armada-node's checks, and Go's when armada-node
// leaves the userspace device to Go or fails; RemoveWith runs net remove.
func TestProgramDiagnoseAndRemove(t *testing.T) {
	f := newFakeNode(t)
	f.answer(t, "diagnose", `{"checks":[{"name":"network","level":1,"detail":"from armada-node"}],"needsUserspace":false}`, 0)
	got := DiagnoseWith(f.bin, ModePlain, self, netip.Addr{}, Sites{Cache: "/c", Node: "a"})
	if len(got) != 1 || got[0] != (Check{Name: "network", Level: CheckWarn, Detail: "from armada-node"}) {
		t.Fatalf("got %+v", got)
	}
	var req map[string]string
	if err := json.Unmarshal(f.input(t, "diagnose"), &req); err != nil || req["Mode"] != ModePlain || req["PrivateIP"] != "10.0.0.1" ||
		req["Endpoint"] != "" || req["Cache"] != "/c" || req["Node"] != "a" {
		t.Fatalf("request %v, %v", req, err)
	}
	f.answer(t, "diagnose", `{"checks":[],"needsUserspace":true}`, 0)
	if got := DiagnoseWith(f.bin, ModePlain, self, netip.Addr{}, Sites{}); len(got) == 0 || got[len(got)-1].Name != "isolation" {
		t.Fatalf("Go's checks: %+v", got)
	}
	f.answer(t, "remove", "", 0)
	if err := RemoveWith(f.bin); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "in-remove")); err != nil {
		t.Error("net remove did not run")
	}
}

// armada-node net diagnose says what Go's Diagnose says of this machine:
// its uplinks, tunnels (none), WireGuard, isolation tables (unreadable
// without root), and the peer lists of other sites, shadowed or not, and
// relays. CI sets ARMADA_NODE_BIN (make node).
func TestArmadaNodeNetDiagnoseMatchesGo(t *testing.T) {
	bin := nodeBin(t)
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	ips := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("192.0.2.9")}
	var local netip.Prefix
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP.To4()); ok {
			ips = append(ips, ip)
			if !ip.IsLoopback() && !local.IsValid() {
				ones, _ := a.Mask.Size()
				local = netip.PrefixFrom(ip, ones)
			}
		}
	}
	dir := t.TempDir()
	caches := map[string]string{"none": ""}
	write := func(name string, cfg *armadav1.NetworkConfig) {
		path := filepath.Join(dir, name+".json")
		if err := saveMeshCache(path, cfg); err != nil {
			t.Fatal(err)
		}
		caches[name] = path
	}
	far := config(sitePeer(t, "a", "10.0.0.1", "10.120.0.0/24", "203.0.113.1", ""),
		sitePeer(t, "b", "10.5.0.2", "10.120.1.0/24", "203.0.113.2", "far"))
	write("far", far)
	if local.IsValid() {
		// A peer of another site inside this machine's own network.
		shadow := config(sitePeer(t, "a", "10.0.0.1", "10.120.0.0/24", "203.0.113.1", ""),
			sitePeer(t, "b", local.Masked().Addr().Next().String(), "10.120.1.0/24", "203.0.113.2", "far"))
		if shadow.Peers[1].PrivateIp == "" || netip.MustParseAddr(shadow.Peers[1].PrivateIp) == netip.MustParseAddr("10.0.0.1") {
			shadow.Peers[1].PrivateIp = "10.9.9.9"
		}
		write("shadow", shadow)
	}
	write("nat", natCluster(t))
	write("other node", config(np("z", "10.0.0.1", "10.120.0.0/24")))
	if err := os.WriteFile(filepath.Join(dir, "open.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	caches["open"] = filepath.Join(dir, "open.json")
	cases := 0
	for _, mode := range []string{ModePlain, ModeWireGuard, ModeMesh} {
		for _, ip := range ips {
			for _, ep := range []netip.Addr{{}, ips[len(ips)-1], InternetProbe} {
				for name, cache := range caches {
					nodes := []string{"a"}
					if name == "nat" {
						nodes = []string{"a", "n1", "r1", "r2"}
					}
					for _, node := range nodes {
						sites := Sites{Cache: cache, Node: node}
						want := Diagnose(mode, ip, ep, sites)
						got, ok := diagnoseVia(bin, mode, ip, ep, sites)
						if !ok {
							t.Fatalf("%s %s %s %s %s: armada-node failed", mode, ip, ep, name, node)
						}
						if !slices.Equal(got, want) {
							t.Errorf("%s ip %s endpoint %s cache %s node %s:\n armada-node %+v\n Go          %+v", mode, ip, ep, name, node, got, want)
						}
						cases++
					}
				}
			}
		}
	}
	t.Logf("%d cases", cases)
}

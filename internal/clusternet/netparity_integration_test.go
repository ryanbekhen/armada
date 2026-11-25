//go:build integration && linux

package clusternet

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

// TestIntegrationNetParity applies the same passes with this package's Net
// in one network namespace and armada-node's (ADR 0054) in another, both as
// the same node with the same key, and after every pass compares what the
// kernel holds: interfaces, addresses, routes, neighbour and forwarding
// entries, WireGuard devices (handshakes and counters masked), nftables,
// and iptables, plus the kept peer list, each pass's error, the switch
// status, the peers UnreachablePeers names, and doctor's checks. It ends
// with Remove on both. It needs root, the kernel's VXLAN and WireGuard,
// and ip, bridge, wg, nft, and iptables-save:
//
//	make node
//	go test -c -tags integration ./internal/clusternet -o t
//	sudo ARMADA_NODE_BIN=$PWD/target/x86_64-unknown-linux-musl/release/armada-node ./t -test.run IntegrationNetParity -test.v
func TestIntegrationNetParity(t *testing.T) {
	bin := os.Getenv("ARMADA_NODE_BIN")
	if bin == "" {
		t.Skip("ARMADA_NODE_BIN is not set (make node)")
	}
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	sides := map[string]*switchNode{}
	for _, name := range []string{"go", "rust"} {
		full := "armada-parity-" + name
		_ = netns.DeleteNamed(full)
		h, err := netns.NewNamed(full)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = h.Close(); _ = netns.DeleteNamed(full) })
		sides[name] = &switchNode{name: name, ns: h}
	}
	if err := netns.Set(orig); err != nil {
		t.Fatal(err)
	}
	runtime.UnlockOSThread()

	// Node a's machine: an uplink with its private and public addresses,
	// a route to another site's private network, and the container bridge.
	for _, s := range sides {
		if err := s.in(t, func() error {
			lo, err := netlink.LinkByName("lo")
			if err != nil {
				return err
			}
			if err := netlink.LinkSetUp(lo); err != nil {
				return err
			}
			eth := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0", MTU: 1500}}
			if err := netlink.LinkAdd(eth); err != nil {
				return err
			}
			for _, a := range []string{"10.99.0.1/24", "203.0.113.1/24"} {
				if err := netlink.AddrAdd(eth, &netlink.Addr{IPNet: prefixNet(netip.MustParsePrefix(a))}); err != nil {
					return err
				}
			}
			if err := netlink.LinkSetUp(eth); err != nil {
				return err
			}
			if err := netlink.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Dst: prefixNet(netip.MustParsePrefix("0.0.0.0/0")), Gw: net.ParseIP("203.0.113.254")}); err != nil {
				return err
			}
			br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: embedded.BridgeName}}
			if err := netlink.LinkAdd(br); err != nil {
				return err
			}
			if err := netlink.AddrAdd(br, &netlink.Addr{IPNet: &net.IPNet{IP: net.IPv4(10, 120, 1, 1), Mask: net.CIDRMask(24, 32)}}); err != nil {
				return err
			}
			return netlink.LinkSetUp(br)
		}); err != nil {
			t.Fatal(err)
		}
	}

	keyFile := func() PrivateKey {
		k, err := LoadOrCreateKey(filepath.Join(t.TempDir(), "network.key"))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	self := keyFile()
	keys := map[string]string{"a": self.Public()}
	for _, n := range []string{"b", "c", "d", "e", "f"} {
		keys[n] = keyFile().Public()
	}
	type peerSpec struct {
		node, ip, subnet, endpoint, site string
		nat, relay                       bool
	}
	all := []peerSpec{
		{node: "a", ip: "10.99.0.1", subnet: "10.120.1.0/24", endpoint: "203.0.113.1"},
		{node: "b", ip: "10.99.0.2", subnet: "10.120.2.0/24", endpoint: "203.0.113.2"},
		{node: "c", ip: "10.99.0.3", subnet: "10.120.3.0/24", endpoint: "203.0.113.3"},
	}
	far := []peerSpec{
		{node: "d", ip: "10.98.0.4", subnet: "10.120.4.0/24", endpoint: "198.51.100.4", site: "far", relay: true},
		{node: "e", ip: "10.98.0.5", subnet: "10.120.5.0/24", site: "far", nat: true},
	}
	config := func(mode, to, step, mesh string, peers ...peerSpec) *armadav1.NetworkConfig {
		cfg := &armadav1.NetworkConfig{Mode: mode, ClusterCidr: "10.120.0.0/16", SwitchTo: to, SwitchStep: step, MeshCidr: mesh,
			Endpoints: []*armadav1.NetworkEndpoint{{Address: "10.120.1.5", App: "web"}, {Address: "10.120.2.7", App: "db.p1"}},
			TcpPorts:  []uint32{5432}}
		for _, p := range peers {
			cfg.Peers = append(cfg.Peers, &armadav1.NetworkPeer{Node: p.node, PrivateIp: p.ip, Subnet: p.subnet, PublicKey: keys[p.node],
				Endpoint: p.endpoint, Site: p.site, BehindNat: p.nat, Relay: p.relay})
		}
		return cfg
	}
	moved := slices.Clone(all)
	moved[2].subnet = "10.120.9.0/24" // c's subnet changes: its old entries go
	// The passes, in order: what each implementation applies (nil: Up from
	// the kept list).
	type pass struct {
		name  string
		cfg   *armadav1.NetworkConfig
		local map[netip.Addr]string
		up    bool
	}
	local := map[netip.Addr]string{netip.MustParseAddr("10.120.1.5"): "web"}
	passes := []pass{
		{name: "plain", cfg: config(ModePlain, "", "", "", all...), local: local},
		{name: "plain, a peer moved and one gone", cfg: config(ModePlain, "", "", "", moved[:3]...), local: local},
		{name: "plain again", cfg: config(ModePlain, "", "", "", all...)},
		{name: "plain with another site", cfg: config(ModePlain, "", "", "", append(slices.Clone(all), far...)...), local: local},
		{name: "plain back to one site", cfg: config(ModePlain, "", "", "", all...), local: local},
		{name: "prepare plain → wireguard", cfg: config(ModePlain, ModeWireGuard, SwitchPrepare, "", all...)},
		{name: "move plain → wireguard", cfg: config(ModePlain, ModeWireGuard, SwitchMove, "", all...)},
		{name: "wireguard", cfg: config(ModeWireGuard, "", "", "", all...), local: local},
		{name: "wireguard with another site", cfg: config(ModeWireGuard, "", "", "", append(slices.Clone(all), far...)...)},
		{name: "prepare wireguard → plain", cfg: config(ModeWireGuard, ModePlain, SwitchPrepare, "", all...)},
		{name: "switch given up", cfg: config(ModeWireGuard, "", "", "", all...)},
		{name: "prepare wireguard → plain again", cfg: config(ModeWireGuard, ModePlain, SwitchPrepare, "", all...)},
		{name: "move wireguard → plain", cfg: config(ModeWireGuard, ModePlain, SwitchMove, "", all...)},
		{name: "plain after the switch", cfg: config(ModePlain, "", "", "", all...)},
		{name: "plain with a mesh range", cfg: config(ModePlain, "", "", "10.122.0.0/16", append(slices.Clone(all), far...)...)},
		{name: "up from the kept list", up: true},
	}
	cache := map[string]string{"go": filepath.Join(t.TempDir(), "mesh.json"), "rust": filepath.Join(t.TempDir(), "mesh.json")}
	nodeCfg := func(side string) Config {
		return Config{Node: "a", PrivateIP: netip.MustParseAddr("10.99.0.1"), Endpoint: netip.MustParseAddr("203.0.113.1"),
			Key: self, MeshCache: cache[side]}
	}
	goNet, err := New(nodeCfg("go"))
	if err != nil {
		t.Fatal(err)
	}
	impls := map[string]netImpl{"go": goNet, "rust": newRustNet(t, nodeCfg("rust"))}
	for _, p := range passes {
		errs := map[string]string{}
		for side, s := range sides {
			err := s.in(t, func() error {
				if p.up {
					return impls[side].Up(nil)
				}
				return impls[side].Apply(context.Background(), p.cfg, p.local)
			})
			if err != nil {
				errs[side] = err.Error()
			}
		}
		if errs["go"] != errs["rust"] {
			t.Fatalf("%s: the passes end differently:\n Go:          %q\n armada-node: %q", p.name, errs["go"], errs["rust"])
		}
		if r, ok := impls["rust"].(*rustNet); ok {
			t.Logf("%s: armada-node did %q", p.name, r.done())
		}
		compareKernels(t, p.name, sides)
		compareCaches(t, p.name, cache)
		mode := ModePlain
		if p.cfg != nil {
			mode = p.cfg.GetMode()
		}
		compareReadings(t, p.name, bin, sides, impls, mode, nodeCfg("go"), cache)
	}

	// The mesh mode: a node whose private IP is its mesh address.
	for side, s := range sides {
		if err := s.in(t, func() error {
			eth, err := netlink.LinkByName("eth0")
			if err != nil {
				return err
			}
			return netlink.AddrDel(eth, &netlink.Addr{IPNet: prefixNet(netip.MustParsePrefix("10.99.0.1/24"))})
		}); err != nil {
			t.Fatal(err)
		}
		cfg := nodeCfg(side)
		cfg.PrivateIP = netip.MustParseAddr("10.122.0.1")
		if side == "rust" {
			impls[side] = newRustNet(t, cfg)
		} else if impls[side], err = New(cfg); err != nil {
			t.Fatal(err)
		}
	}
	mesh := config(ModeMesh, "", "", "10.122.0.0/16",
		peerSpec{node: "a", ip: "10.122.0.1", subnet: "10.120.1.0/24", endpoint: "203.0.113.1"},
		peerSpec{node: "b", ip: "10.122.0.2", subnet: "10.120.2.0/24", endpoint: "203.0.113.2"},
		peerSpec{node: "f", ip: "10.122.0.6", subnet: "10.120.6.0/24", endpoint: "198.51.100.6"})
	for _, step := range []string{"mesh up", "mesh applied"} {
		errs := map[string]string{}
		for side, s := range sides {
			if err := s.in(t, func() error {
				if step == "mesh up" {
					return impls[side].Up(mesh)
				}
				return impls[side].Apply(context.Background(), mesh, nil)
			}); err != nil {
				errs[side] = err.Error()
			}
		}
		if errs["go"] != errs["rust"] {
			t.Fatalf("%s: the passes end differently:\n Go:          %q\n armada-node: %q", step, errs["go"], errs["rust"])
		}
		compareKernels(t, step, sides)
		compareCaches(t, step, cache)
		mcfg := nodeCfg("go")
		mcfg.PrivateIP = netip.MustParseAddr("10.122.0.1")
		compareReadings(t, step, bin, sides, impls, ModeMesh, mcfg, cache)
	}

	// A node that leaves.
	for side, s := range sides {
		if err := s.in(t, func() error {
			if side == "rust" {
				return removeRust(bin)
			}
			return Remove()
		}); err != nil {
			t.Fatalf("%s: remove: %v", side, err)
		}
	}
	compareKernels(t, "removed", sides)
}

// compareReadings fails the test when the two sides tell differently of
// the network they hold: the switch status, the peers with no recent
// handshake (with every peer configured long enough ago), and doctor's
// checks, Go's against armada-node's.
func compareReadings(t *testing.T, when, bin string, sides map[string]*switchNode, impls map[string]netImpl, mode string, cfg Config, cache map[string]string) {
	t.Helper()
	// A probe a pass started ends within probeWait: wait for it on both
	// sides, so the statuses compare what each probe found.
	for _, impl := range impls {
		deadline := time.Now().Add(2 * probeEvery)
		for probeRunning(impl) && time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
		}
	}
	got := map[string]string{}
	for side, s := range sides {
		age(impls[side], 4*time.Minute)
		var checks []Check
		var unreachable []string
		_ = s.in(t, func() error {
			unreachable = impls[side].UnreachablePeers()
			sites := Sites{Cache: cache[side], Node: cfg.Node}
			if side == "rust" {
				var ok bool
				if checks, ok = diagnoseVia(bin, mode, cfg.PrivateIP, cfg.Endpoint, sites); !ok {
					t.Errorf("%s: armada-node net diagnose failed", when)
				}
			} else {
				checks = Diagnose(mode, cfg.PrivateIP, cfg.Endpoint, sites)
			}
			return nil
		})
		b, _ := json.Marshal(map[string]any{"switch": impls[side].SwitchStatus(), "unreachable": unreachable, "checks": checks})
		got[side] = string(b)
	}
	if got["go"] != got["rust"] {
		t.Errorf("%s: the readings differ:\n Go:          %s\n armada-node: %s", when, got["go"], got["rust"])
	}
}

// probeRunning reports whether the first probe of a prepare step has not
// ended yet.
func probeRunning(n netImpl) bool {
	net := netOf(n)
	if net == nil {
		return false
	}
	net.mu.Lock()
	defer net.mu.Unlock()
	return net.sw.step == SwitchPrepare && net.sw.probing && !net.sw.probed
}

// compareKernels fails the test when the two namespaces hold different
// networks.
func compareKernels(t *testing.T, when string, sides map[string]*switchNode) {
	t.Helper()
	dumps := map[string]map[string]string{}
	for side, s := range sides {
		var d map[string]string
		_ = s.in(t, func() error {
			d = dumpKernel(t)
			return nil
		})
		dumps[side] = d
	}
	for _, what := range slices.Sorted(maps.Keys(dumps["go"])) {
		if g, r := dumps["go"][what], dumps["rust"][what]; g != r {
			t.Errorf("%s: %s differs:\n--- Go\n%s\n--- armada-node\n%s", when, what, g, r)
		}
	}
}

// compareCaches fails the test when the kept peer lists differ.
func compareCaches(t *testing.T, when string, cache map[string]string) {
	t.Helper()
	g, gerr := loadMeshCache(cache["go"])
	r, rerr := loadMeshCache(cache["rust"])
	if (gerr == nil) != (rerr == nil) || !proto.Equal(g, r) {
		t.Errorf("%s: the kept peer lists differ:\n Go:          %v %v\n armada-node: %v %v", when, g, gerr, r, rerr)
	}
}

// dropKeys are what differs between two namespaces holding the same
// network: interface numbers, counters, ages, and nftables handles.
var dropKeys = map[string]bool{"ifindex": true, "link_index": true, "stats": true, "stats64": true, "used": true, "updated": true,
	"confirmed": true, "valid_life_time": true, "preferred_life_time": true, "handle": true, "metainfo": true, "link_netnsid": true,
	"probes": true, "gc_timer": true, "hello_timer": true, "tcn_timer": true, "topology_change_timer": true}

// normalize drops dropKeys from v, and nftables' version object; with
// sorted, it sorts a list at the top, whose order follows creation (links,
// addresses, entries) rather than meaning.
func normalize(v any, sorted bool) any {
	switch x := v.(type) {
	case map[string]any:
		for k := range x {
			if dropKeys[k] {
				delete(x, k)
				continue
			}
			x[k] = normalize(x[k], false)
		}
		return x
	case []any:
		out := []any{}
		for _, e := range x {
			if m, ok := e.(map[string]any); ok {
				if _, meta := m["metainfo"]; meta {
					continue
				}
			}
			out = append(out, normalize(e, false))
		}
		if sorted {
			slices.SortFunc(out, func(a, b any) int {
				return strings.Compare(string(canonicalJSON(a)), string(canonicalJSON(b)))
			})
		}
		return out
	}
	return v
}

var counters = regexp.MustCompile(`\[\d+:\d+\]`)

// solicited are IPv6 solicited-node multicast addresses, which follow an
// interface's link-local address and so its MAC address.
var solicited = regexp.MustCompile(`33:33:ff:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}`)

// dumpKernel is the current namespace's network, normalized, by tool.
func dumpKernel(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	run := func(name string, args ...string) (string, bool) {
		b, err := exec.Command(name, args...).Output()
		if err != nil {
			if _, lookErr := exec.LookPath(name); lookErr != nil {
				t.Logf("%s is not installed; not compared", name)
				return "", false
			}
			return fmt.Sprintf("error: %v", err), true
		}
		return string(b), true
	}
	// The test's own interfaces (the uplink, the bridge) get random MAC
	// addresses in each namespace; Armada's tunnels have fixed ones.
	fixtures := map[string]string{}
	if s, ok := run("ip", "-j", "link", "show"); ok {
		var links []struct {
			Name    string `json:"ifname"`
			Address string `json:"address"`
		}
		if json.Unmarshal([]byte(s), &links) == nil {
			for _, l := range links {
				if l.Name != Interface && l.Name != Next && l.Name != SiteInterface && l.Address != "" && l.Address != "00:00:00:00:00:00" {
					fixtures[l.Address] = "mac-of-" + l.Name
				}
			}
		}
	}
	jsonOf := func(key string, sorted bool, name string, args ...string) {
		s, ok := run(name, args...)
		if !ok {
			return
		}
		for mac, name := range fixtures {
			s = strings.ReplaceAll(s, mac, name)
		}
		s = solicited.ReplaceAllString(s, "33:33:ff:solicited")
		var v any
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			out[key] = s
			return
		}
		out[key] = string(canonicalJSON(normalize(v, sorted)))
	}
	// IPv4 only: IPv6 link-local addresses come and go with duplicate
	// address detection's timing.
	jsonOf("ip -d link", true, "ip", "-d", "-j", "link", "show")
	jsonOf("ip addr", true, "ip", "-4", "-j", "addr", "show")
	jsonOf("ip route", false, "ip", "-4", "-j", "route", "show")
	jsonOf("ip neigh", true, "ip", "-4", "-j", "neigh", "show")
	jsonOf("bridge fdb", true, "bridge", "-j", "fdb", "show")
	jsonOf("nft ruleset", false, "nft", "-j", "list", "ruleset")
	if s, ok := run("wg", "show", "all", "dump"); ok {
		var lines []string
		for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
			f := strings.Split(l, "\t")
			if len(f) == 9 {
				// A peer: its handshake and counters move.
				f[5], f[6], f[7] = "-", "-", "-"
			}
			lines = append(lines, strings.Join(f, "\t"))
		}
		slices.Sort(lines)
		out["wg"] = strings.Join(lines, "\n")
	}
	if s, ok := run("iptables-save"); ok {
		var lines []string
		for _, l := range strings.Split(s, "\n") {
			if !strings.HasPrefix(l, "#") {
				lines = append(lines, counters.ReplaceAllString(l, "[0:0]"))
			}
		}
		out["iptables"] = strings.Join(lines, "\n")
	}
	return out
}

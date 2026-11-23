//go:build integration && linux

package clusternet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

// switchNode is one node of TestIntegrationSwitch, in a network namespace
// of its own.
type switchNode struct {
	name   string
	ns     netns.NsHandle
	ip     netip.Addr
	subnet netip.Prefix
	net    netImpl
}

// in runs fn in the node's network namespace.
func (n *switchNode) in(t *testing.T, fn func() error) error {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = orig.Close() }()
	if err := netns.Set(n.ns); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := netns.Set(orig); err != nil {
			panic(err)
		}
	}()
	return fn()
}

// TestIntegrationSwitch switches two nodes from plain to wireguard and back
// (ADR 0050), checking that their subnets reach each other at every step,
// gives up a switch in its prepare step, and removes the network. It needs
// root and the kernel's VXLAN and WireGuard:
//
//	go test -c -tags integration ./internal/clusternet -o t && sudo ./t -test.run IntegrationSwitch -test.v
//
// With ARMADA_NET_IMPL=rust ARMADA_NODE_BIN=<armada-node> the nodes run
// armada-node's cluster network instead (netimpl_integration_test.go).
func TestIntegrationSwitch(t *testing.T) {
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	nodes := []*switchNode{
		{name: "a", ip: netip.MustParseAddr("10.99.0.1"), subnet: netip.MustParsePrefix("10.120.1.0/24")},
		{name: "b", ip: netip.MustParseAddr("10.99.0.2"), subnet: netip.MustParsePrefix("10.120.2.0/24")},
	}
	for _, n := range nodes {
		name := fmt.Sprintf("armada-switch-%s", n.name)
		_ = netns.DeleteNamed(name)
		if n.ns, err = netns.NewNamed(name); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = n.ns.Close(); _ = netns.DeleteNamed(name) })
	}
	if err := netns.Set(orig); err != nil {
		t.Fatal(err)
	}
	runtime.UnlockOSThread()

	// A wire between the two, and a bridge with the gateway address on
	// each, standing in for the containers.
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "armt-a", Namespace: netlink.NsFd(nodes[0].ns)}, PeerName: "armt-b", PeerNamespace: netlink.NsFd(nodes[1].ns)}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	keys := map[string]PrivateKey{}
	for i, n := range nodes {
		key, err := LoadOrCreateKey(filepath.Join(t.TempDir(), "network.key"))
		if err != nil {
			t.Fatal(err)
		}
		keys[n.name] = key
		wire := []string{"armt-a", "armt-b"}[i]
		if err := n.in(t, func() error {
			lo, err := netlink.LinkByName("lo")
			if err != nil {
				return err
			}
			if err := netlink.LinkSetUp(lo); err != nil {
				return err
			}
			w, err := netlink.LinkByName(wire)
			if err != nil {
				return err
			}
			if err := netlink.AddrAdd(w, &netlink.Addr{IPNet: &net.IPNet{IP: n.ip.AsSlice(), Mask: net.CIDRMask(24, 32)}}); err != nil {
				return err
			}
			if err := netlink.LinkSetUp(w); err != nil {
				return err
			}
			br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: embedded.BridgeName}}
			if err := netlink.LinkAdd(br); err != nil {
				return err
			}
			gw := n.subnet.Addr().Next()
			if err := netlink.AddrAdd(br, &netlink.Addr{IPNet: &net.IPNet{IP: gw.AsSlice(), Mask: net.CIDRMask(24, 32)}}); err != nil {
				return err
			}
			return netlink.LinkSetUp(br)
		}); err != nil {
			t.Fatal(err)
		}
		n.net = newNetImpl(t, Config{Node: n.name, PrivateIP: n.ip, Key: key})
	}

	config := func(mode, to, step string) *armadav1.NetworkConfig {
		cfg := &armadav1.NetworkConfig{Mode: mode, ClusterCidr: "10.120.0.0/16", SwitchTo: to, SwitchStep: step}
		for _, n := range nodes {
			cfg.Peers = append(cfg.Peers, &armadav1.NetworkPeer{Node: n.name, PrivateIp: n.ip.String(), Subnet: n.subnet.String(), PublicKey: keys[n.name].Public()})
		}
		return cfg
	}
	apply := func(cfg *armadav1.NetworkConfig) {
		t.Helper()
		for _, n := range nodes {
			if err := n.in(t, func() error { return n.net.Apply(context.Background(), cfg, nil) }); err != nil {
				t.Fatalf("%s: apply %s→%s %s: %v", n.name, cfg.GetMode(), cfg.GetSwitchTo(), cfg.GetSwitchStep(), err)
			}
		}
	}
	// reach pings b's gateway from a's.
	reach := func(when string) {
		t.Helper()
		var out []byte
		err := nodes[0].in(t, func() error {
			var err error
			out, err = exec.Command("ping", "-c", "1", "-W", "2", "-I", "10.120.1.1", "10.120.2.1").CombinedOutput()
			return err
		})
		if err != nil {
			t.Fatalf("%s: a's subnet does not reach b's: %v\n%s", when, err, out)
		}
	}
	kind := func(n *switchNode, name string) string {
		var k string
		_ = n.in(t, func() error {
			l, err := linkNamed(name)
			if err == nil && l != nil {
				k = l.Type()
			}
			return nil
		})
		return k
	}
	ready := func(to, step string) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for _, n := range nodes {
			for {
				// Passes keep coming, as they do from the agent.
				apply(config(map[string]string{ModeWireGuard: ModePlain, ModePlain: ModeWireGuard}[to], to, step))
				st := n.net.SwitchStatus()
				if st != nil && st.GetReady() {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("%s is not ready for %s %s: %v", n.name, to, step, st)
				}
				time.Sleep(time.Second)
			}
		}
	}

	for _, sw := range []struct{ from, to, kind string }{
		{ModePlain, ModeWireGuard, "wireguard"},
		{ModeWireGuard, ModePlain, "vxlan"},
	} {
		apply(config(sw.from, "", ""))
		reach(sw.from)
		ready(sw.to, SwitchPrepare)
		reach(sw.from + " → " + sw.to + " prepare")
		// One node moves before the other.
		half := config(sw.from, sw.to, SwitchMove)
		if err := nodes[0].in(t, func() error { return nodes[0].net.Apply(context.Background(), half, nil) }); err != nil {
			t.Fatal(err)
		}
		reach(sw.from + " → " + sw.to + " half moved")
		ready(sw.to, SwitchMove)
		reach(sw.from + " → " + sw.to + " move")
		apply(config(sw.to, "", ""))
		reach(sw.to)
		for _, n := range nodes {
			if got := kind(n, Interface); got != sw.kind {
				t.Fatalf("%s: %s is %q after the switch to %s, want %s", n.name, Interface, got, sw.to, sw.kind)
			}
			if got := kind(n, Next); got != "" {
				t.Fatalf("%s: %s is left after the switch (%s)", n.name, Next, got)
			}
			if n.net.SwitchStatus() != nil {
				t.Fatalf("%s: a switch status is left", n.name)
			}
			// The peers have had their handshakes, however long ago they
			// were configured.
			age(n.net, 4*time.Minute)
			var unreachable []string
			_ = n.in(t, func() error { unreachable = n.net.UnreachablePeers(); return nil })
			if unreachable != nil {
				t.Fatalf("%s: unreachable peers %v after the switch to %s", n.name, unreachable, sw.to)
			}
		}
	}

	// Given up in the prepare step: the target transport goes.
	ready(ModeWireGuard, SwitchPrepare)
	apply(config(ModePlain, "", ""))
	reach("switch given up")
	for _, n := range nodes {
		if got := kind(n, Interface); got != "vxlan" {
			t.Fatalf("%s: %s is %q after a switch was given up", n.name, Interface, got)
		}
		if got := kind(n, Next); got != "" {
			t.Fatalf("%s: %s is left after a switch was given up (%s)", n.name, Next, got)
		}
	}

	// A node that leaves takes the network off.
	for _, n := range nodes {
		if err := n.in(t, removeNet); err != nil {
			t.Fatalf("%s: remove: %v", n.name, err)
		}
		if got := kind(n, Interface); got != "" {
			t.Fatalf("%s: %s is left after Remove (%s)", n.name, Interface, got)
		}
	}
}

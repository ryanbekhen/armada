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

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

// TestIntegrationSites builds three nodes in network namespaces on one
// wire: a and b share a private network, c has a private address of its
// own in another site, and every node has a public address. In both modes
// a and b reach each other in the cluster's mode and c over WireGuard at its
// endpoint, containers and node addresses alike (ADR 0050). It needs root
// and the kernel's VXLAN and WireGuard:
//
//	go test -c -tags integration ./internal/clusternet -o t && sudo ./t -test.run IntegrationSites -test.v
func TestIntegrationSites(t *testing.T) {
	type node struct {
		*switchNode
		private, public netip.Prefix
		site            string
	}
	nodes := []*node{
		{switchNode: &switchNode{name: "a", subnet: netip.MustParsePrefix("10.120.1.0/24")}, private: netip.MustParsePrefix("10.99.0.1/24"), public: netip.MustParsePrefix("203.0.113.1/24")},
		{switchNode: &switchNode{name: "b", subnet: netip.MustParsePrefix("10.120.2.0/24")}, private: netip.MustParsePrefix("10.99.0.2/24"), public: netip.MustParsePrefix("203.0.113.2/24")},
		{switchNode: &switchNode{name: "c", subnet: netip.MustParsePrefix("10.120.3.0/24")}, private: netip.MustParsePrefix("10.98.0.3/24"), public: netip.MustParsePrefix("203.0.113.3/24"), site: "far"},
	}
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	newNS := func(name string) netns.NsHandle {
		_ = netns.DeleteNamed(name)
		h, err := netns.NewNamed(name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = h.Close(); _ = netns.DeleteNamed(name) })
		return h
	}
	wire := newNS("armada-sites-wire")
	for _, n := range nodes {
		n.ns = newNS("armada-sites-" + n.name)
	}
	if err := netns.Set(orig); err != nil {
		t.Fatal(err)
	}
	runtime.UnlockOSThread()
	w := &switchNode{name: "wire", ns: wire}

	// The wire: a bridge every node's link is plugged into.
	if err := w.in(t, func() error {
		br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "wire"}}
		if err := netlink.LinkAdd(br); err != nil {
			return err
		}
		return netlink.LinkSetUp(br)
	}); err != nil {
		t.Fatal(err)
	}
	keys := map[string]PrivateKey{}
	for _, n := range nodes {
		n.ip = n.private.Addr()
		key, err := LoadOrCreateKey(filepath.Join(t.TempDir(), "network.key"))
		if err != nil {
			t.Fatal(err)
		}
		keys[n.name] = key
		veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "w-" + n.name, Namespace: netlink.NsFd(wire)}, PeerName: "eth0", PeerNamespace: netlink.NsFd(n.ns)}
		if err := netlink.LinkAdd(veth); err != nil {
			t.Fatal(err)
		}
		if err := w.in(t, func() error {
			l, err := netlink.LinkByName("w-" + n.name)
			if err != nil {
				return err
			}
			br, err := netlink.LinkByName("wire")
			if err != nil {
				return err
			}
			if err := netlink.LinkSetMaster(l, br); err != nil {
				return err
			}
			return netlink.LinkSetUp(l)
		}); err != nil {
			t.Fatal(err)
		}
		if err := n.in(t, func() error {
			for _, name := range []string{"lo", "eth0"} {
				l, err := netlink.LinkByName(name)
				if err != nil {
					return err
				}
				if err := netlink.LinkSetUp(l); err != nil {
					return err
				}
			}
			eth, err := netlink.LinkByName("eth0")
			if err != nil {
				return err
			}
			for _, a := range []netip.Prefix{n.private, n.public} {
				if err := netlink.AddrAdd(eth, &netlink.Addr{IPNet: prefixNet(a)}); err != nil {
					return err
				}
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
		if n.net, err = New(Config{Node: n.name, PrivateIP: n.ip, Key: keys[n.name], MeshCache: filepath.Join(t.TempDir(), "mesh.json")}); err != nil {
			t.Fatal(err)
		}
	}
	config := func(mode string, sites map[string]string) *armadav1.NetworkConfig {
		cfg := &armadav1.NetworkConfig{Mode: mode, ClusterCidr: "10.120.0.0/16"}
		for _, n := range nodes {
			cfg.Peers = append(cfg.Peers, &armadav1.NetworkPeer{Node: n.name, PrivateIp: n.ip.String(), Subnet: n.subnet.String(),
				PublicKey: keys[n.name].Public(), Endpoint: n.public.Addr().String(), Site: sites[n.name]})
		}
		return cfg
	}
	apply := func(cfg *armadav1.NetworkConfig) {
		t.Helper()
		for _, n := range nodes {
			if err := n.in(t, func() error { return n.net.Apply(context.Background(), cfg, nil) }); err != nil {
				t.Fatalf("%s: apply %s: %v", n.name, cfg.GetMode(), err)
			}
		}
	}
	ping := func(from *node, src, dst string) error {
		var out []byte
		err := from.in(t, func() error {
			var err error
			out, err = exec.Command("ping", "-c", "1", "-W", "3", "-I", src, dst).CombinedOutput()
			return err
		})
		if err != nil {
			return fmt.Errorf("%s: %s → %s: %w\n%s", from.name, src, dst, err, out)
		}
		return nil
	}
	reachAll := func(when string) {
		t.Helper()
		for _, from := range nodes {
			for _, to := range nodes {
				if from == to {
					continue
				}
				// Containers, then node addresses.
				if err := ping(from, from.subnet.Addr().Next().String(), to.subnet.Addr().Next().String()); err != nil {
					t.Errorf("%s: %v", when, err)
				}
				if err := ping(from, from.ip.String(), to.ip.String()); err != nil {
					t.Errorf("%s: %v", when, err)
				}
			}
		}
	}
	kind := func(n *node, name string) string {
		var k string
		_ = n.in(t, func() error {
			if l, err := linkNamed(name); err == nil && l != nil {
				k = l.Type()
			}
			return nil
		})
		return k
	}
	sites := map[string]string{"c": "far"}

	apply(config(ModePlain, sites))
	reachAll("plain with two sites")
	for _, n := range nodes {
		if got := kind(n, Interface); got != "vxlan" {
			t.Errorf("%s: %s is %q", n.name, Interface, got)
		}
		if got := kind(n, SiteInterface); got != "wireguard" {
			t.Errorf("%s: %s is %q, want wireguard", n.name, SiteInterface, got)
		}
	}

	apply(config(ModeWireGuard, sites))
	reachAll("wireguard with two sites")
	if got := kind(nodes[0], SiteInterface); got != "" {
		t.Errorf("wireguard: %s left (%s)", SiteInterface, got)
	}

	// One site again: the site interface goes, and a and b still meet.
	apply(config(ModePlain, nil))
	for _, n := range nodes[:2] {
		if got := kind(n, SiteInterface); got != "" {
			t.Errorf("%s: %s left after the last other site went (%s)", n.name, SiteInterface, got)
		}
	}
	if err := ping(nodes[0], "10.120.1.1", "10.120.2.1"); err != nil {
		t.Error(err)
	}
}

//go:build linux

package containerd

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/containernetworking/cni/libcni"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/vishvananda/netlink"
)

// fakePlugins keeps one cached result per container ID, as the plugins'
// cache does, and drops it on DEL.
type fakePlugins struct {
	cache  map[string]cnitypes.Result
	dels   []string
	delErr error
	// order records "del" and "forget" in the order they happened.
	order *[]string
}

func (f *fakePlugins) AddNetworkList(context.Context, *libcni.NetworkConfigList, *libcni.RuntimeConf) (cnitypes.Result, error) {
	return nil, errors.New("not used")
}

func (f *fakePlugins) DelNetworkList(_ context.Context, _ *libcni.NetworkConfigList, rt *libcni.RuntimeConf) error {
	if f.delErr != nil {
		return f.delErr
	}
	f.dels = append(f.dels, rt.ContainerID)
	*f.order = append(*f.order, "del")
	delete(f.cache, rt.ContainerID)
	return nil
}

func (f *fakePlugins) GetNetworkListCachedResult(_ *libcni.NetworkConfigList, rt *libcni.RuntimeConf) (cnitypes.Result, error) {
	return f.cache[rt.ContainerID], nil
}

func result(ip string) cnitypes.Result {
	return &types100.Result{CNIVersion: "1.0.0", IPs: []*types100.IPConfig{{
		Address: net.IPNet{IP: net.ParseIP(ip).To4(), Mask: net.CIDRMask(24, 32)},
	}}}
}

func testNetwork(cache map[string]cnitypes.Result) (*cniNetwork, *fakePlugins, *[]netip.Addr, *[]string) {
	var order []string
	var forgot []netip.Addr
	p := &fakePlugins{cache: cache, order: &order}
	n := &cniNetwork{cni: p, forget: func(a netip.Addr) error {
		forgot = append(forgot, a)
		order = append(order, "forget")
		return nil
	}}
	return n, p, &forgot, &order
}

// Releasing a container's address, or a sandbox's (no namespace left
// here: the plugins release it all the same), forgets the connections of
// that address, after the plugins gave it back.
func TestTeardownForgetsConnections(t *testing.T) {
	n, p, forgot, order := testNetwork(map[string]cnitypes.Result{
		"armada-web-r1-ab12":   result("10.120.3.7"),
		"sandbox-worker.space": result("10.120.3.9"),
	})
	ctx := context.Background()
	if err := n.Teardown(ctx, "armada-web-r1-ab12", "", nil); err != nil {
		t.Fatal(err)
	}
	if err := n.Teardown(ctx, "sandbox-worker.space", "/nonexistent/sandbox", nil); err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("10.120.3.7"), netip.MustParseAddr("10.120.3.9")}
	if len(*forgot) != 2 || (*forgot)[0] != want[0] || (*forgot)[1] != want[1] {
		t.Fatalf("forgot %v, want %v", *forgot, want)
	}
	if got := *order; len(got) != 4 || got[0] != "del" || got[1] != "forget" {
		t.Fatalf("order %v: connections must be forgotten after the address is released", got)
	}
	if len(p.dels) != 2 {
		t.Fatalf("dels %v", p.dels)
	}

	// Releasing again: no cached address, nothing to forget.
	if err := n.Teardown(ctx, "armada-web-r1-ab12", "", nil); err != nil {
		t.Fatal(err)
	}
	if len(*forgot) != 2 {
		t.Fatalf("forgot %v after a second release", *forgot)
	}
}

// A failed release keeps the address, so nothing is forgotten; a failed
// forget does not fail the release.
func TestTeardownForgetErrors(t *testing.T) {
	n, p, forgot, _ := testNetwork(map[string]cnitypes.Result{"c": result("10.120.3.7")})
	p.delErr = errors.New("plugin failed")
	if err := n.Teardown(context.Background(), "c", "", nil); err == nil {
		t.Fatal("want the plugins' error")
	}
	if len(*forgot) != 0 {
		t.Fatalf("forgot %v after a failed release", *forgot)
	}

	p.delErr = nil
	n.forget = func(netip.Addr) error { return errors.New("netlink failed") }
	if err := n.Teardown(context.Background(), "c", "", nil); err != nil {
		t.Fatalf("a failed forget failed the release: %v", err)
	}
}

// The filters match an entry by any of its addresses, and nothing else.
func TestConnFilters(t *testing.T) {
	addr := netip.MustParseAddr("10.120.3.7")
	filters, err := connFilters(addr)
	if err != nil {
		t.Fatal(err)
	}
	ip := func(s string) net.IP { return net.ParseIP(s).To4() }
	flow := func(os, od, rs, rd string) *netlink.ConntrackFlow {
		f := &netlink.ConntrackFlow{FamilyType: 2}
		f.Forward.SrcIP, f.Forward.DstIP = ip(os), ip(od)
		f.Reverse.SrcIP, f.Reverse.DstIP = ip(rs), ip(rd)
		return f
	}
	for _, c := range []struct {
		name string
		flow *netlink.ConntrackFlow
		want bool
	}{
		{"container sends", flow("10.120.3.7", "10.120.4.2", "10.120.4.2", "10.120.3.7"), true},
		{"peer sends", flow("10.120.4.2", "10.120.3.7", "10.120.3.7", "10.120.4.2"), true},
		{"DNAT to the container", flow("203.0.113.5", "10.0.0.4", "10.120.3.7", "203.0.113.5"), true},
		{"SNAT from the container", flow("10.120.3.7", "198.51.100.1", "198.51.100.1", "10.0.0.4"), true},
		{"another container", flow("10.120.3.8", "10.120.4.2", "10.120.4.2", "10.120.3.8"), false},
	} {
		got := false
		for _, f := range filters {
			if f.MatchConntrackFlow(c.flow) {
				got = true
			}
		}
		if got != c.want {
			t.Errorf("%s: match %v, want %v", c.name, got, c.want)
		}
	}
}

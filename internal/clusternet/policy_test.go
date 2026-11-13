package clusternet

import (
	"net/netip"
	"slices"
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

func ep(addr, app string) *armadav1.NetworkEndpoint {
	return &armadav1.NetworkEndpoint{Address: addr, App: app}
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func TestParseEndpoints(t *testing.T) {
	t.Parallel()
	cfg := config(np("a", "10.0.0.1", "10.120.0.0/24"), np("b", "10.0.0.2", "10.120.1.0/24"))
	cfg.Endpoints = []*armadav1.NetworkEndpoint{
		ep("10.120.0.5", "web"), ep("10.120.1.7", "api.shop"),
		// Claimed twice: left out.
		ep("10.120.1.9", "web"), ep("10.120.1.9", "api.shop"),
	}
	p, err := parse(cfg, "a", self)
	if err != nil {
		t.Fatal(err)
	}
	want := map[netip.Addr]string{netip.MustParseAddr("10.120.0.5"): "web", netip.MustParseAddr("10.120.1.7"): "api.shop"}
	if len(p.endpoints) != len(want) {
		t.Fatalf("endpoints = %v", p.endpoints)
	}
	for a, app := range want {
		if p.endpoints[a] != app {
			t.Errorf("endpoint %s = %q, want %q", a, p.endpoints[a], app)
		}
	}
	for name, e := range map[string]*armadav1.NetworkEndpoint{
		"outside the CIDR":    ep("10.121.0.5", "web"),
		"public":              ep("8.8.8.8", "web"),
		"tunnel end":          ep("10.120.1.0", "web"),
		"gateway":             ep("10.120.1.1", "web"),
		"broadcast":           ep("10.120.1.255", "web"),
		"IPv6":                ep("fd00::5", "web"),
		"not an address":      ep("10.120.1.5/32", "web"),
		"bad app":             ep("10.120.1.5", "Web;drop"),
		"default as space":    ep("10.120.1.5", "web.default"),
		"label is not an app": ep("10.120.1.5", "canary--web"),
	} {
		cfg := config(np("a", "10.0.0.1", "10.120.0.0/24"))
		cfg.Endpoints = []*armadav1.NetworkEndpoint{e}
		if _, err := parse(cfg, "a", self); err == nil {
			t.Errorf("%s: accepted %v", name, e)
		}
	}
}

func TestBuildPolicy(t *testing.T) {
	t.Parallel()
	cfg := config(np("a", "10.0.0.1", "10.120.0.0/24"), np("b", "10.0.0.2", "10.120.1.0/24"))
	cfg.Endpoints = []*armadav1.NetworkEndpoint{
		ep("10.120.1.7", "api.shop"), ep("10.120.1.8", "web"),
		// Stale for this node: the local list wins in its own subnet.
		ep("10.120.0.9", "gone"),
	}
	p, err := parse(cfg, "a", self)
	if err != nil {
		t.Fatal(err)
	}
	local := map[netip.Addr]string{
		netip.MustParseAddr("10.120.0.5"): "web",
		netip.MustParseAddr("10.120.0.6"): "api.shop",
		// Not this node's: ignored.
		netip.MustParseAddr("10.120.1.99"): "web",
		netip.MustParseAddr("10.120.0.1"):  "web",
	}
	pol := buildPolicy(p, local)
	if pol.subnet.String() != "10.120.0.0/24" || pol.gateway.String() != "10.120.0.1" {
		t.Errorf("subnet %s gateway %s", pol.subnet, pol.gateway)
	}
	if !slices.Equal(pol.apps, []string{"api.shop", "web"}) {
		t.Errorf("apps = %v", pol.apps)
	}
	if got := pol.members["web"]; !slices.Equal(got, addrs("10.120.0.5", "10.120.1.8")) {
		t.Errorf("web = %v", got)
	}
	if got := pol.members["api.shop"]; !slices.Equal(got, addrs("10.120.0.6", "10.120.1.7")) {
		t.Errorf("api.shop = %v", got)
	}
	// Only this node's default-space containers are open; the shop
	// space's never are.
	if !slices.Equal(pol.open, addrs("10.120.0.5")) {
		t.Errorf("open = %v", pol.open)
	}
	if !slices.Equal(pol.nodes, addrs("10.0.0.1", "10.0.0.2")) {
		t.Errorf("nodes = %v", pol.nodes)
	}

	// With the default space isolated, nothing is open.
	cfg.IsolateDefault = true
	p, _ = parse(cfg, "a", self)
	if pol := buildPolicy(p, local); len(pol.open) != 0 {
		t.Errorf("isolated default: open = %v", pol.open)
	}

	// Without a local list the control plane's is used for this node too.
	cfg.IsolateDefault = false
	p, _ = parse(cfg, "a", self)
	if pol := buildPolicy(p, nil); !slices.Equal(pol.members["gone"], addrs("10.120.0.9")) || !slices.Equal(pol.open, addrs("10.120.0.9")) {
		t.Errorf("no local list: %+v", pol)
	}
}

package clusternet

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// sitePeer is a peer with a key, an endpoint, and a site.
func sitePeer(t *testing.T, node, ip, subnet, endpoint, site string) *armadav1.NetworkPeer {
	t.Helper()
	return &armadav1.NetworkPeer{Node: node, PrivateIp: ip, Subnet: subnet, PublicKey: key(t).String(), Endpoint: endpoint, Site: site}
}

// Peers of another site are marked remote, kept only with a key and an
// endpoint; peers of this node's site are not, in either mode (ADR 0050).
func TestParseSites(t *testing.T) {
	t.Parallel()
	a := sitePeer(t, "a", "10.0.0.1", "10.120.0.0/24", "203.0.113.1", "")
	b := sitePeer(t, "b", "10.0.0.2", "10.120.1.0/24", "", "")
	c := sitePeer(t, "c", "10.5.0.3", "10.120.2.0/24", "203.0.113.3", "far")
	noEndpoint := sitePeer(t, "d", "10.5.0.4", "10.120.3.0/24", "", "far")
	noKey := &armadav1.NetworkPeer{Node: "e", PrivateIp: "10.5.0.5", Subnet: "10.120.4.0/24", Endpoint: "203.0.113.5", Site: "far"}
	for _, mode := range []string{ModePlain, ModeWireGuard} {
		cfg := &armadav1.NetworkConfig{Mode: mode, ClusterCidr: "10.120.0.0/16", Peers: []*armadav1.NetworkPeer{a, b, c, noEndpoint, noKey}}
		p, err := parse(cfg, "a", self)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if len(p.peers) != 2 || p.peers[0].node != "b" || p.peers[0].remote || p.peers[1].node != "c" || !p.peers[1].remote {
			t.Errorf("%s: peers %+v", mode, p.peers)
		}
		if l, r := p.local(), p.remote(); len(l) != 1 || len(r) != 1 || r[0].endpoint.String() != "203.0.113.3" {
			t.Errorf("%s: local %+v, remote %+v", mode, l, r)
		}
		// Seen from c, a and b are the other site.
		p, err = parse(cfg, "c", netip.MustParseAddr("10.5.0.3"))
		if err != nil {
			t.Fatal(err)
		}
		if r := p.remote(); len(r) != 1 || r[0].node != "a" {
			t.Errorf("%s from c: remote %+v (b has no endpoint)", mode, r)
		}
	}
	// The mesh reaches every peer at its endpoint already: no peer is
	// remote there.
	mesh := &armadav1.NetworkConfig{Mode: ModeMesh, ClusterCidr: "10.120.0.0/16", MeshCidr: "10.122.0.0/16", Peers: []*armadav1.NetworkPeer{
		sitePeer(t, "a", "10.122.0.1", "10.120.0.0/24", "203.0.113.1", ""), sitePeer(t, "c", "10.122.0.3", "10.120.2.0/24", "203.0.113.3", "far")}}
	if p, err := parse(mesh, "a", netip.MustParseAddr("10.122.0.1")); err != nil || len(p.remote()) != 0 || len(p.peers) != 1 {
		t.Errorf("mesh: %+v, %v", p, err)
	}
	// Invalid sites, and switching with another site, are refused.
	bad := &armadav1.NetworkConfig{Mode: ModePlain, ClusterCidr: "10.120.0.0/16", Peers: []*armadav1.NetworkPeer{a, sitePeer(t, "x", "10.0.0.9", "10.120.9.0/24", "203.0.113.9", "Far Away")}}
	if _, err := parse(bad, "a", self); err == nil {
		t.Error("invalid site accepted")
	}
	sw := &armadav1.NetworkConfig{Mode: ModePlain, ClusterCidr: "10.120.0.0/16", Peers: []*armadav1.NetworkPeer{a, c}, SwitchTo: ModeWireGuard, SwitchStep: SwitchPrepare}
	if _, err := parse(sw, "a", self); err == nil {
		t.Error("switch with another site accepted")
	}
}

// A peer of another site is reached at its endpoint and allowed its node
// address and subnet; a peer of this site at its private IP, its subnet
// only. A roamed endpoint of another site's peer is kept while fresh.
func TestPeerChangesSites(t *testing.T) {
	t.Parallel()
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	near := peer{node: "b", ip: netip.MustParseAddr("10.0.0.2"), subnet: netip.MustParsePrefix("10.120.1.0/24"), key: key(t)}
	far := peer{node: "c", ip: netip.MustParseAddr("10.5.0.3"), subnet: netip.MustParsePrefix("10.120.2.0/24"), key: key(t), endpoint: netip.MustParseAddr("203.0.113.3"), remote: true}
	cfg := peerChanges(&wgtypes.Device{}, priv, ModeWireGuard, []peer{near, far}, time.Now())
	if cfg == nil || len(cfg.Peers) != 2 {
		t.Fatalf("config %+v", cfg)
	}
	byKey := map[wgtypes.Key]wgtypes.PeerConfig{}
	for _, pc := range cfg.Peers {
		byKey[pc.PublicKey] = pc
	}
	if pc := byKey[near.key]; pc.Endpoint.String() != "10.0.0.2:51820" || len(pc.AllowedIPs) != 1 {
		t.Errorf("this site's peer %+v", pc)
	}
	if pc := byKey[far.key]; pc.Endpoint.String() != "203.0.113.3:51820" || len(pc.AllowedIPs) != 2 || pc.AllowedIPs[0].String() != "10.5.0.3/32" {
		t.Errorf("other site's peer %+v", pc)
	}
}

// Another site's peers: the WireGuard port from anywhere, their node
// addresses only through WireGuard, and containers kept from their
// endpoints (ADR 0050).
func TestSiteRules(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{ModePlain, ModeWireGuard} {
		cfg := &armadav1.NetworkConfig{Mode: mode, ClusterCidr: "10.120.0.0/16", Peers: []*armadav1.NetworkPeer{
			sitePeer(t, "a", "10.0.0.1", "10.120.0.0/24", "203.0.113.1", ""),
			sitePeer(t, "b", "10.0.0.2", "10.120.1.0/24", "", ""),
			sitePeer(t, "c", "10.5.0.3", "10.120.2.0/24", "203.0.113.3", "far"),
		}}
		p, err := parse(cfg, "a", self)
		if err != nil {
			t.Fatal(err)
		}
		dev := Interface
		if mode == ModePlain {
			dev = SiteInterface
		}
		spoof := joinRules(spoofRules(p))
		for _, want := range []string{
			"-d 203.0.113.3/32 -i armada0 -p udp -m udp --dport 51820 -j DROP",
			"-s 10.5.0.3/32 ! -i " + dev + " -j DROP",
			"-s 10.5.0.3/32 -i " + dev + " -j RETURN",
			"! -s 10.120.0.0/16 -i " + dev + " -j DROP",
		} {
			if !slices.Contains(spoof, want) {
				t.Errorf("%s: %q missing:\n%v", mode, want, spoof)
			}
		}
		// The node address returns before the drop of sources outside the
		// cluster's range on the same interface.
		if slices.Index(spoof, "-s 10.5.0.3/32 -i "+dev+" -j RETURN") > slices.Index(spoof, "! -s 10.120.0.0/16 -i "+dev+" -j DROP") {
			t.Errorf("%s: return after the drop:\n%v", mode, spoof)
		}
		if mesh := joinRules(meshRules(p)); !slices.Equal(mesh, []string{"-s 10.5.0.3/32 -d 10.0.0.1/32 -j ACCEPT", "-j RETURN"}) {
			t.Errorf("%s: accept chain %v", mode, mesh)
		}
		if got := tunnels(p); mode == ModePlain && !slices.Equal(got, []string{Interface, SiteInterface}) || mode == ModeWireGuard && !slices.Equal(got, []string{Interface}) {
			t.Errorf("%s: tunnels %v", mode, got)
		}
	}
}

func joinRules(rules [][]string) []string {
	var out []string
	for _, r := range rules {
		s := ""
		for i, f := range r {
			if i > 0 {
				s += " "
			}
			s += f
		}
		out = append(out, s)
	}
	return out
}

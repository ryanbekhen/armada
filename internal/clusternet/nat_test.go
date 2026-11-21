package clusternet

import (
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// natCluster is a plain cluster with two sites, "" and "far", each with a
// relay (r1, r2) and two nodes behind NAT (n1, n2 and m1, m2); x is a node
// of "far" with an endpoint that is not its relay.
func natCluster(t *testing.T) *armadav1.NetworkConfig {
	t.Helper()
	nat := func(node, ip, subnet, site string) *armadav1.NetworkPeer {
		p := sitePeer(t, node, ip, subnet, "", site)
		p.BehindNat = true
		return p
	}
	relay := func(node, ip, subnet, endpoint, site string) *armadav1.NetworkPeer {
		p := sitePeer(t, node, ip, subnet, endpoint, site)
		p.Relay = true
		return p
	}
	return &armadav1.NetworkConfig{Mode: ModePlain, ClusterCidr: "10.120.0.0/16", Peers: []*armadav1.NetworkPeer{
		relay("r1", "10.0.0.1", "10.120.0.0/24", "203.0.113.1", ""),
		nat("n1", "10.0.0.2", "10.120.1.0/24", ""),
		nat("n2", "10.0.0.3", "10.120.2.0/24", ""),
		relay("r2", "10.5.0.1", "10.120.3.0/24", "203.0.113.2", "far"),
		nat("m1", "10.5.0.2", "10.120.4.0/24", "far"),
		nat("m2", "10.5.0.3", "10.120.5.0/24", "far"),
		sitePeer(t, "x", "10.5.0.4", "10.120.6.0/24", "203.0.113.4", "far"),
	}}
}

func names(peers []peer) []string {
	var out []string
	for _, pe := range peers {
		out = append(out, pe.node)
	}
	return out
}

// A node behind NAT reaches the nodes behind NAT of another site through
// the relay of the site that sorts first, its own site's nodes and every
// node with an endpoint directly; a node with an endpoint reaches every
// node, those behind NAT with no endpoint of their own (ADR 0050).
func TestParseBehindNAT(t *testing.T) {
	t.Parallel()
	cfg := natCluster(t)
	p, err := parse(cfg, "n1", netip.MustParseAddr("10.0.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	if got := names(p.peers); !slices.Equal(got, []string{"r1", "n2", "r2", "x"}) {
		t.Errorf("n1's direct peers %v", got)
	}
	if got := names(p.relayed); !slices.Equal(got, []string{"m1", "m2"}) {
		t.Errorf("n1's relayed peers %v", got)
	}
	// "" sorts before "far": r1 carries both, and it is in n1's own site.
	for _, pe := range p.peers {
		want := 0
		if pe.node == "r1" {
			want = 2
		}
		if len(pe.carried) != want {
			t.Errorf("n1: %s carries %v", pe.node, pe.carried)
		}
	}
	// m1 takes the same relay, r1, in the other site: both directions of a
	// pair cross one relay.
	p, err = parse(cfg, "m1", netip.MustParseAddr("10.5.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(p.peers, func(pe peer) bool { return pe.node == "r1" })
	if i < 0 || !p.peers[i].remote || len(p.peers[i].carried) != 2 {
		t.Fatalf("m1's entry for r1: %+v", p.peers)
	}
	if got := names(p.relayed); !slices.Equal(got, []string{"n1", "n2"}) {
		t.Errorf("m1's relayed peers %v", got)
	}
	// r1 relays every pair across the sites; r2 none.
	p, err = parse(cfg, "r1", netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.relaying) != 4 || len(p.relayed) != 0 || len(p.peers) != 6 {
		t.Errorf("r1: relaying %v, peers %v", p.relaying, names(p.peers))
	}
	for _, pe := range p.peers {
		if pe.node == "m1" && (!pe.remote || pe.endpoint.IsValid()) {
			t.Errorf("r1's entry for m1: %+v", pe)
		}
	}
	if p, err := parse(cfg, "r2", netip.MustParseAddr("10.5.0.1")); err != nil || len(p.relaying) != 0 {
		t.Errorf("r2: relaying %v, %v", p.relaying, err)
	}
	// x has an endpoint: everyone is direct.
	if p, err := parse(cfg, "x", netip.MustParseAddr("10.5.0.4")); err != nil || len(p.peers) != 6 || len(p.relayed) != 0 {
		t.Errorf("x: %v, %v", names(p.peers), err)
	}
}

// Without a relay in the site that sorts first, the other site's relay
// carries the pair; with none, the pair is unreachable and doctor says so.
func TestParseBehindNATRelayFallback(t *testing.T) {
	t.Parallel()
	cfg := natCluster(t)
	cfg.Peers[0].Relay = false
	p, err := parse(cfg, "n1", netip.MustParseAddr("10.0.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	for _, pe := range p.peers {
		if (pe.node == "r2") != (len(pe.carried) == 2) {
			t.Errorf("n1: %s carries %v", pe.node, pe.carried)
		}
	}
	cfg.Peers[3].Relay = false
	p, err = parse(cfg, "n1", netip.MustParseAddr("10.0.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.relayed) != 0 || !slices.Equal(p.unreachable, []string{"m1", "m2"}) || slices.Contains(names(p.peers), "m1") {
		t.Errorf("no relay: relayed %v, unreachable %v, peers %v", names(p.relayed), p.unreachable, names(p.peers))
	}
}

// Nodes behind NAT in two sites without a relay take the relay of the
// site that sorts first of all those with one.
func TestParseBehindNATThirdSite(t *testing.T) {
	t.Parallel()
	cfg := natCluster(t)
	home := sitePeer(t, "h1", "192.168.1.2", "10.120.7.0/24", "", "home")
	home.BehindNat = true
	office := sitePeer(t, "o1", "192.168.2.2", "10.120.8.0/24", "", "office")
	office.BehindNat = true
	cfg.Peers = append(cfg.Peers, home, office)
	p, err := parse(cfg, "h1", netip.MustParseAddr("192.168.1.2"))
	if err != nil {
		t.Fatal(err)
	}
	// "" sorts first: r1 carries o1, and n1, n2 (h1's pairs with the first
	// site); "far" sorts before "home": r2 carries m1, m2.
	for _, pe := range p.peers {
		switch pe.node {
		case "r1":
			if !slices.Contains(pe.carried, netip.MustParsePrefix("10.120.8.0/24")) || len(pe.carried) != 3 {
				t.Errorf("r1 carries %v", pe.carried)
			}
		case "r2":
			if len(pe.carried) != 2 {
				t.Errorf("r2 carries %v", pe.carried)
			}
		}
	}
	p, err = parse(cfg, "r1", netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	want := [2]netip.Prefix{netip.MustParsePrefix("10.120.7.0/24"), netip.MustParsePrefix("10.120.8.0/24")}
	if !slices.Contains(p.relaying, want) {
		t.Errorf("r1 relays %v, not h1-o1", p.relaying)
	}
}

// A node behind NAT that claims to relay, or one that sends an endpoint,
// is refused or has the endpoint ignored.
func TestParseBehindNATChecks(t *testing.T) {
	t.Parallel()
	cfg := natCluster(t)
	cfg.Peers[1].Relay = true
	if _, err := parse(cfg, "r1", netip.MustParseAddr("10.0.0.1")); err == nil {
		t.Error("a relay behind NAT accepted")
	}
	cfg = natCluster(t)
	cfg.Peers[4].Endpoint = "203.0.113.9"
	p, err := parse(cfg, "r1", netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, pe := range p.peers {
		if pe.node == "m1" && pe.endpoint.IsValid() {
			t.Errorf("an endpoint of a node behind NAT was kept: %s", pe.endpoint)
		}
	}
}

// A peer behind NAT gets no endpoint, keeps the one WireGuard learned, and
// a relay's entry allows the subnets it carries.
func TestPeerChangesBehindNAT(t *testing.T) {
	t.Parallel()
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	nat := peer{node: "m1", ip: netip.MustParseAddr("10.5.0.2"), subnet: netip.MustParsePrefix("10.120.4.0/24"), key: key(t), remote: true, nat: true}
	relay := peer{node: "r1", ip: netip.MustParseAddr("10.0.0.1"), subnet: netip.MustParsePrefix("10.120.0.0/24"), key: key(t),
		endpoint: netip.MustParseAddr("203.0.113.1"), remote: true, carried: []netip.Prefix{netip.MustParsePrefix("10.120.1.0/24")}}
	cfg := peerChanges(&wgtypes.Device{}, priv, ModePlain, []peer{nat, relay}, time.Now())
	if cfg == nil || len(cfg.Peers) != 2 {
		t.Fatalf("config %+v", cfg)
	}
	if cfg.Peers[0].Endpoint != nil {
		t.Errorf("an endpoint for a node behind NAT: %v", cfg.Peers[0].Endpoint)
	}
	if got := cfg.Peers[1].AllowedIPs; len(got) != 3 || got[2].String() != "10.120.1.0/24" {
		t.Errorf("relay allowed %v", got)
	}
	// WireGuard learned where m1 is: nothing changes, however old its
	// handshake.
	ka := keepalive
	d := &wgtypes.Device{PrivateKey: priv, ListenPort: WireGuardPort, Peers: []wgtypes.Peer{
		{PublicKey: nat.key, Endpoint: &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 40000}, AllowedIPs: cfg.Peers[0].AllowedIPs, PersistentKeepaliveInterval: ka},
		{PublicKey: relay.key, Endpoint: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: WireGuardPort}, AllowedIPs: cfg.Peers[1].AllowedIPs, PersistentKeepaliveInterval: ka},
	}}
	if c := peerChanges(d, priv, ModePlain, []peer{nat, relay}, time.Now()); c != nil {
		t.Errorf("changes %+v", c)
	}
}

// A WireGuard peer is unreachable once it has had no handshake for 3
// minutes, counted from when it was configured (ADR 0025).
func TestStalePeers(t *testing.T) {
	t.Parallel()
	now := time.Now()
	old, fresh, unknown := key(t), key(t), key(t)
	recent := key(t)
	since := map[wgtypes.Key]wgPeerSeen{
		old:    {node: "b", since: now.Add(-time.Hour)},
		fresh:  {node: "c", since: now.Add(-time.Minute)},
		recent: {node: "a", since: now.Add(-time.Hour)},
	}
	devs := []*wgtypes.Device{{Peers: []wgtypes.Peer{
		{PublicKey: old, LastHandshakeTime: now.Add(-4 * time.Minute)},
		{PublicKey: fresh},
		{PublicKey: unknown},
		{PublicKey: recent, LastHandshakeTime: now.Add(-time.Minute)},
	}}, {Peers: []wgtypes.Peer{{PublicKey: old}}}}
	if got := stalePeers(devs, since, now); !slices.Equal(got, []string{"b"}) {
		t.Errorf("stale %v, want [b]", got)
	}
}

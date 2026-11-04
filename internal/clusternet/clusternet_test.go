package clusternet

import (
	"net/netip"
	"strings"
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

func config(peers ...*armadav1.NetworkPeer) *armadav1.NetworkConfig {
	return &armadav1.NetworkConfig{Mode: ModePlain, ClusterCidr: "10.120.0.0/16", Peers: peers}
}

func np(node, ip, subnet string) *armadav1.NetworkPeer {
	return &armadav1.NetworkPeer{Node: node, PrivateIp: ip, Subnet: subnet}
}

var self = netip.MustParseAddr("10.0.0.1")

func TestParse(t *testing.T) {
	t.Parallel()
	p, err := parse(config(np("a", "10.0.0.1", "10.120.0.0/24"), np("b", "10.0.0.2", "10.120.1.0/24"), np("c", "10.0.0.3", "10.120.2.0/24")), "a", self)
	if err != nil {
		t.Fatal(err)
	}
	if p.self.subnet.String() != "10.120.0.0/24" || len(p.peers) != 2 || p.peers[1].node != "c" {
		t.Errorf("plan = %+v", p)
	}
	// Another node sees the first one as a peer.
	if p, err := parse(config(np("a", "10.0.0.1", "10.120.0.0/24"), np("b", "10.0.0.2", "10.120.1.0/24")), "b", netip.MustParseAddr("10.0.0.2")); err != nil || p.peers[0].node != "a" {
		t.Errorf("node b: %+v, %v", p, err)
	}
	// A cluster of one node has no peers.
	if p, err := parse(config(np("a", "10.0.0.1", "10.120.0.0/24")), "a", self); err != nil || len(p.peers) != 0 {
		t.Errorf("single node: %+v, %v", p, err)
	}
}

func TestParseRefuses(t *testing.T) {
	t.Parallel()
	a := np("a", "10.0.0.1", "10.120.0.0/24")
	for name, c := range map[string]*armadav1.NetworkConfig{
		"unknown mode":       {Mode: "wireguard", ClusterCidr: "10.120.0.0/16", Peers: []*armadav1.NetworkPeer{a}},
		"public CIDR":        {Mode: ModePlain, ClusterCidr: "8.8.0.0/16", Peers: []*armadav1.NetworkPeer{a}},
		"IPv6 CIDR":          {Mode: ModePlain, ClusterCidr: "fd00::/48", Peers: []*armadav1.NetworkPeer{a}},
		"CIDR not canonical": {Mode: ModePlain, ClusterCidr: "10.120.0.1/16", Peers: []*armadav1.NetworkPeer{a}},
		"not in list":        config(np("b", "10.0.0.2", "10.120.1.0/24")),
		"self elsewhere":     config(np("a", "10.0.0.9", "10.120.0.0/24")),
		"bad name":           config(a, np("B;rm", "10.0.0.2", "10.120.1.0/24")),
		"public peer":        config(a, np("b", "1.1.1.1", "10.120.1.0/24")),
		"loopback peer":      config(a, np("b", "127.0.0.1", "10.120.1.0/24")),
		"peer in CIDR":       config(a, np("b", "10.120.9.9", "10.120.1.0/24")),
		"subnet outside":     config(a, np("b", "10.0.0.2", "10.121.1.0/24")),
		"subnet too large":   config(a, np("b", "10.0.0.2", "10.120.0.0/23")),
		"subnet host bits":   config(a, np("b", "10.0.0.2", "10.120.1.5/24")),
		"default route":      config(a, np("b", "10.0.0.2", "0.0.0.0/0")),
		"duplicate subnet":   config(a, np("b", "10.0.0.2", "10.120.0.0/24")),
		"duplicate address":  config(a, np("b", "10.0.0.1", "10.120.1.0/24")),
		"duplicate name":     config(a, np("a", "10.0.0.2", "10.120.1.0/24")),
	} {
		if _, err := parse(c, "a", self); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	many := config(a)
	for range maxPeers {
		many.Peers = append(many.Peers, a)
	}
	if _, err := parse(many, "a", self); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("too many peers: %v", err)
	}
}

func TestVTEP(t *testing.T) {
	t.Parallel()
	sub := netip.MustParsePrefix("10.120.3.0/24")
	if vtepAddr(sub).String() != "10.120.3.0" || vtepMAC(sub).String() != "02:42:0a:78:03:00" {
		t.Errorf("vtep %s %s", vtepAddr(sub), vtepMAC(sub))
	}
	if TunnelMTU(1450) != 1400 || TunnelMTU(1500) != 1450 {
		t.Error("tunnel MTU")
	}
}

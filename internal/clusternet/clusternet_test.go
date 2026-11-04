package clusternet

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

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
		"unknown mode":       {Mode: "ipsec", ClusterCidr: "10.120.0.0/16", Peers: []*armadav1.NetworkPeer{a}},
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
	if TunnelMTU(ModePlain, 1450) != 1400 || TunnelMTU(ModeWireGuard, 1500) != 1420 {
		t.Error("tunnel MTU")
	}
}

func key(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey()
}

func TestParseWireGuard(t *testing.T) {
	t.Parallel()
	ka, kb := key(t), key(t)
	withKey := func(p *armadav1.NetworkPeer, k wgtypes.Key) *armadav1.NetworkPeer {
		p.PublicKey = k.String()
		return p
	}
	wg := func(peers ...*armadav1.NetworkPeer) *armadav1.NetworkConfig {
		c := config(peers...)
		c.Mode = ModeWireGuard
		return c
	}
	// A node that has not announced a key yet is left out until it does.
	p, err := parse(wg(withKey(np("a", "10.0.0.1", "10.120.0.0/24"), ka), withKey(np("b", "10.0.0.2", "10.120.1.0/24"), kb), np("c", "10.0.0.3", "10.120.2.0/24")), "a", self)
	if err != nil || len(p.peers) != 1 || p.peers[0].key != kb {
		t.Fatalf("plan %+v, %v", p, err)
	}
	for name, c := range map[string]*armadav1.NetworkConfig{
		"bad key":       wg(np("a", "10.0.0.1", "10.120.0.0/24"), &armadav1.NetworkPeer{Node: "b", PrivateIp: "10.0.0.2", Subnet: "10.120.1.0/24", PublicKey: "not-a-key"}),
		"zero key":      wg(np("a", "10.0.0.1", "10.120.0.0/24"), withKey(np("b", "10.0.0.2", "10.120.1.0/24"), wgtypes.Key{})),
		"duplicate key": wg(withKey(np("a", "10.0.0.1", "10.120.0.0/24"), ka), withKey(np("b", "10.0.0.2", "10.120.1.0/24"), ka)),
	} {
		if _, err := parse(c, "a", self); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPeerChanges(t *testing.T) {
	t.Parallel()
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	kb, kc, gone := key(t), key(t), key(t)
	peers := []peer{
		{node: "b", ip: netip.MustParseAddr("10.0.0.2"), subnet: netip.MustParsePrefix("10.120.1.0/24"), key: kb},
		{node: "c", ip: netip.MustParseAddr("10.0.0.3"), subnet: netip.MustParsePrefix("10.120.2.0/24"), key: kc},
	}
	// A new device gets the key, the port, and every peer.
	cfg := peerChanges(&wgtypes.Device{}, priv, peers)
	if cfg == nil || cfg.PrivateKey == nil || *cfg.ListenPort != WireGuardPort || len(cfg.Peers) != 2 {
		t.Fatalf("new device: %+v", cfg)
	}
	if pc := cfg.Peers[0]; pc.Endpoint.String() != "10.0.0.2:51820" || len(pc.AllowedIPs) != 1 || pc.AllowedIPs[0].String() != "10.120.1.0/24" || !pc.ReplaceAllowedIPs || *pc.PersistentKeepaliveInterval != keepalive {
		t.Errorf("peer config %+v", pc)
	}
	// A device that matches needs nothing, so sessions are left alone.
	asPeer := func(p peer) wgtypes.Peer {
		return wgtypes.Peer{PublicKey: p.key, Endpoint: &net.UDPAddr{IP: p.ip.AsSlice(), Port: WireGuardPort},
			AllowedIPs: []net.IPNet{*prefixNet(p.subnet)}, PersistentKeepaliveInterval: keepalive, LastHandshakeTime: time.Now()}
	}
	d := &wgtypes.Device{PrivateKey: priv, ListenPort: WireGuardPort, Peers: []wgtypes.Peer{asPeer(peers[0]), asPeer(peers[1])}}
	if cfg := peerChanges(d, priv, peers); cfg != nil {
		t.Errorf("matching device changed: %+v", cfg)
	}
	// A node that left is removed; a moved one is updated; others stay.
	d.Peers = append(d.Peers, wgtypes.Peer{PublicKey: gone})
	moved := peers[1]
	moved.ip = netip.MustParseAddr("10.0.0.9")
	cfg = peerChanges(d, priv, []peer{peers[0], moved})
	if cfg == nil || cfg.PrivateKey != nil || cfg.ListenPort != nil || len(cfg.Peers) != 2 {
		t.Fatalf("changes %+v", cfg)
	}
	for _, pc := range cfg.Peers {
		switch pc.PublicKey {
		case kc:
			if pc.Endpoint.String() != "10.0.0.9:51820" {
				t.Errorf("moved peer %+v", pc)
			}
		case gone:
			if !pc.Remove {
				t.Error("departed peer not removed")
			}
		default:
			t.Errorf("unchanged peer touched: %+v", pc)
		}
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "network.key")
	k, err := LoadOrCreateKey(path)
	if err != nil || k.IsZero() {
		t.Fatalf("%v %v", k.IsZero(), err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %o", fi.Mode().Perm())
	}
	again, err := LoadOrCreateKey(path)
	if err != nil || again.Public() != k.Public() {
		t.Errorf("reloaded key differs: %v", err)
	}
	// The private key never prints itself.
	raw, _ := os.ReadFile(path)
	for _, s := range []string{k.String(), fmt.Sprint(k), fmt.Sprintf("%v %+v", k, k), k.LogValue().String()} {
		if strings.Contains(s, strings.TrimSpace(string(raw))) || !strings.Contains(s, "redacted") {
			t.Errorf("key printed: %q", s)
		}
	}
	// A key file others can read is refused, and so is garbage.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(path); err == nil {
		t.Error("world-readable key accepted")
	}
	bad := filepath.Join(t.TempDir(), "network.key")
	if err := os.WriteFile(bad, []byte("nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(bad); err == nil {
		t.Error("invalid key accepted")
	}
}

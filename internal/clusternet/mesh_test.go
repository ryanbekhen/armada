package clusternet

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

func meshConfig(peers ...*armadav1.NetworkPeer) *armadav1.NetworkConfig {
	return &armadav1.NetworkConfig{Mode: ModeMesh, ClusterCidr: "10.120.0.0/16", MeshCidr: "10.121.0.0/16", Peers: peers}
}

func meshPeer(t *testing.T, node, ip, subnet, endpoint string) *armadav1.NetworkPeer {
	t.Helper()
	return &armadav1.NetworkPeer{Node: node, PrivateIp: ip, Subnet: subnet, PublicKey: key(t).String(), Endpoint: endpoint}
}

var meshSelf = netip.MustParseAddr("10.121.0.1")

func TestParseMesh(t *testing.T) {
	t.Parallel()
	a := meshPeer(t, "a", "10.121.0.1", "10.120.0.0/24", "")
	b := meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "203.0.113.2")
	noEndpoint := meshPeer(t, "c", "10.121.0.3", "10.120.2.0/24", "")
	p, err := parse(meshConfig(a, b, noEndpoint), "a", meshSelf)
	if err != nil {
		t.Fatal(err)
	}
	// A peer with nowhere to send to is left out until it announces one.
	if p.mesh.String() != "10.121.0.0/16" || len(p.peers) != 1 || p.peers[0].endpoint.String() != "203.0.113.2" {
		t.Errorf("plan %+v", p)
	}
	for name, c := range map[string]*armadav1.NetworkConfig{
		"no mesh CIDR":        {Mode: ModeMesh, ClusterCidr: "10.120.0.0/16", Peers: []*armadav1.NetworkPeer{a}},
		"public mesh CIDR":    {Mode: ModeMesh, ClusterCidr: "10.120.0.0/16", MeshCidr: "8.8.0.0/16", Peers: []*armadav1.NetworkPeer{a}},
		"overlapping CIDRs":   {Mode: ModeMesh, ClusterCidr: "10.120.0.0/16", MeshCidr: "10.0.0.0/8", Peers: []*armadav1.NetworkPeer{a}},
		"mesh CIDR too small": {Mode: ModeMesh, ClusterCidr: "10.120.0.0/16", MeshCidr: "10.121.0.0/30", Peers: []*armadav1.NetworkPeer{a}},
		"address outside":     meshConfig(a, meshPeer(t, "b", "10.0.0.2", "10.120.1.0/24", "203.0.113.2")),
		"endpoint loopback":   meshConfig(a, meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "127.0.0.1")),
		"endpoint multicast":  meshConfig(a, meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "224.0.0.1")),
		"endpoint link-local": meshConfig(a, meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "169.254.169.254")),
		"endpoint IPv6":       meshConfig(a, meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "2001:db8::1")),
		"endpoint with port":  meshConfig(a, meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "203.0.113.2:51820")),
		"endpoint in mesh":    meshConfig(a, meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "10.121.0.9")),
		"endpoint in cluster": meshConfig(a, meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "10.120.5.5")),
	} {
		if _, err := parse(c, "a", meshSelf); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if TunnelMTU(ModeMesh, 1500) != 1420 || port(ModeMesh) != WireGuardPort {
		t.Error("the mesh mode is not WireGuard's MTU or port")
	}
}

func TestPeerChangesMesh(t *testing.T) {
	t.Parallel()
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	b := peer{node: "b", ip: netip.MustParseAddr("10.121.0.2"), subnet: netip.MustParsePrefix("10.120.1.0/24"), key: key(t), endpoint: netip.MustParseAddr("203.0.113.2")}
	now := time.Now()
	// A peer is reached at its endpoint and allowed its mesh address and
	// its subnet, nothing else.
	cfg := peerChanges(&wgtypes.Device{}, priv, ModeMesh, []peer{b}, now)
	if cfg == nil || len(cfg.Peers) != 1 {
		t.Fatalf("new device: %+v", cfg)
	}
	pc := cfg.Peers[0]
	if pc.Endpoint.String() != "203.0.113.2:51820" || len(pc.AllowedIPs) != 2 || pc.AllowedIPs[0].String() != "10.121.0.2/32" || pc.AllowedIPs[1].String() != "10.120.1.0/24" {
		t.Errorf("peer config %+v", pc)
	}
	// The kernel lists allowed addresses in its own order.
	roamed := &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 40000}
	device := func(ep *net.UDPAddr, handshake time.Time) *wgtypes.Device {
		return &wgtypes.Device{PrivateKey: priv, ListenPort: WireGuardPort, Peers: []wgtypes.Peer{{
			PublicKey: b.key, Endpoint: ep, PersistentKeepaliveInterval: keepalive, LastHandshakeTime: handshake,
			AllowedIPs: []net.IPNet{*prefixNet(b.subnet), *prefixNet(netip.PrefixFrom(b.ip, 32))},
		}}}
	}
	if cfg := peerChanges(device(&net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: WireGuardPort}, now), priv, ModeMesh, []peer{b}, now); cfg != nil {
		t.Errorf("matching device changed: %+v", cfg)
	}
	// An endpoint WireGuard moved to with a fresh handshake stays.
	if cfg := peerChanges(device(roamed, now.Add(-time.Minute)), priv, ModeMesh, []peer{b}, now); cfg != nil {
		t.Errorf("roamed endpoint reset: %+v", cfg)
	}
	// Once the handshake is stale, the announced endpoint comes back.
	cfg = peerChanges(device(roamed, now.Add(-10*time.Minute)), priv, ModeMesh, []peer{b}, now)
	if cfg == nil || cfg.Peers[0].Endpoint.String() != "203.0.113.2:51820" {
		t.Errorf("stale roamed endpoint kept: %+v", cfg)
	}
	// Outside the mesh mode the announced address always wins.
	w := b
	w.ip = netip.MustParseAddr("10.0.0.2")
	d := device(roamed, now)
	d.Peers[0].AllowedIPs = []net.IPNet{*prefixNet(w.subnet)}
	if cfg := peerChanges(d, priv, ModeWireGuard, []peer{w}, now); cfg == nil || cfg.Peers[0].Endpoint.String() != "10.0.0.2:51820" {
		t.Errorf("wireguard mode: %+v", cfg)
	}
}

func TestMeshCache(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "mesh.json")
	if cfg, err := loadMeshCache(path); cfg != nil || err != nil {
		t.Fatalf("no file: %v %v", cfg, err)
	}
	full := meshConfig(meshPeer(t, "a", "10.121.0.1", "10.120.0.0/24", "203.0.113.1"))
	full.Endpoints = []*armadav1.NetworkEndpoint{{Address: "10.120.0.5", App: "web"}}
	full.TcpPorts = []uint32{5432}
	if err := saveMeshCache(path, full); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi, err)
	}
	got, err := loadMeshCache(path)
	if err != nil {
		t.Fatal(err)
	}
	// Only what the tunnel needs is kept: isolation waits for the control
	// plane.
	if !proto.Equal(got, meshCacheOf(full)) || len(got.GetEndpoints()) != 0 || len(got.GetTcpPorts()) != 0 {
		t.Errorf("cache %v", got)
	}
	// Unchanged lists are not written again.
	fi, _ := os.Stat(path)
	old := fi.ModTime().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if err := saveMeshCache(path, full); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); !fi.ModTime().Equal(old) {
		t.Error("unchanged list rewritten")
	}
	// A file others can read is refused, like the node's key.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMeshCache(path); err == nil {
		t.Error("readable cache accepted")
	}
	if err := RemoveMeshCache(path); err != nil {
		t.Fatal(err)
	}
	if err := RemoveMeshCache(path); err != nil {
		t.Errorf("second remove: %v", err)
	}
}

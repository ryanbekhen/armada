package daemon

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/store"
)

// A mesh cluster's first node takes the first mesh address, brings its
// tunnel up alone before etcd starts, and records its endpoint (ADR 0049).
func TestInitMesh(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	code, out, stderr := run(t, "init", "--data-dir", dataDir, "--config", filepath.Join(dir, "home", "config"), "--network", "mesh", "--endpoint", "203.0.113.5", "--node-name", "m1")
	if code != 0 || !strings.Contains(out, "network:     mesh, 10.120.0.0/16") || !strings.Contains(out, "mesh:        10.122.0.0/16 at 10.122.0.1, endpoint 203.0.113.5") {
		t.Fatalf("init: %d %q %q", code, out, stderr)
	}
	ac, err := loadAgentConfig(dataDir)
	if err != nil || ac.Network != store.NetworkMesh || ac.PrivateIP != "10.122.0.1" || ac.Endpoint != "203.0.113.5" ||
		ac.ClusterCIDR != "10.120.0.0/16" || ac.MeshCIDR != "10.122.0.0/16" || ac.ContainerSubnet != "10.120.0.0/24" || ac.Servers[0] != "10.122.0.1:7443" {
		t.Fatalf("agent config %+v, %v", ac, err)
	}
	v, ok := meshUps.Load(dataDir)
	if !ok {
		t.Fatal("the tunnel never came up")
	}
	cfg := v.(*armadav1.NetworkConfig)
	if cfg.GetMeshCidr() != "10.122.0.0/16" || len(cfg.GetPeers()) != 1 || cfg.GetPeers()[0].GetEndpoint() != "203.0.113.5" ||
		cfg.GetPeers()[0].GetPrivateIp() != "10.122.0.1" || cfg.GetPeers()[0].GetSubnet() != "10.120.0.0/24" || cfg.GetPeers()[0].GetPublicKey() == "" {
		t.Errorf("tunnel config %v", cfg)
	}
}

func TestInitMeshRefuses(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := []string{"init", "--data-dir", filepath.Join(dir, "d"), "--config", filepath.Join(dir, "c")}
	for name, args := range map[string][]string{
		"private IP in a mesh":    {"--network", "mesh", "--endpoint", "203.0.113.5", "--private-ip", "10.0.0.1"},
		"endpoint outside a mesh": {"--private-ip", "10.0.0.1", "--endpoint", "203.0.113.5"},
		"mesh CIDR outside":       {"--private-ip", "10.0.0.1", "--mesh-cidr", "10.123.0.0/16"},
		"loopback endpoint":       {"--network", "mesh", "--endpoint", "127.0.0.1"},
		"public mesh CIDR":        {"--network", "mesh", "--endpoint", "203.0.113.5", "--mesh-cidr", "198.51.100.0/24"},
		"overlapping CIDRs":       {"--network", "mesh", "--endpoint", "203.0.113.5", "--mesh-cidr", "10.120.0.0/20"},
		"endpoint in the mesh":    {"--network", "mesh", "--endpoint", "10.122.0.9"},
	} {
		if code, _, _ := run(t, append(append([]string{}, base...), args...)...); code == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

type changed map[string]bool

func (c changed) Changed(name string) bool { return c[name] }

func TestPrepareJoin(t *testing.T) {
	t.Parallel()
	// A public join address is a mesh cluster's or the leader's for
	// another site; a private IP the machine finds goes along.
	ip, mesh, err := prepareJoin(changed{}, "203.0.113.1:7444", "", "198.51.100.2")
	if err != nil || !mesh.on || mesh.endpoint != netip.MustParseAddr("198.51.100.2") {
		t.Errorf("mesh join: %v %+v %v", ip, mesh, err)
	}
	// Over a public address, a machine of another site sends its private
	// IP too (ADR 0050); a mesh does not use it.
	ip, mesh, err = prepareJoin(changed{"private-ip": true}, "203.0.113.1:7444", "10.0.0.2", "198.51.100.2")
	if err != nil || ip != netip.MustParseAddr("10.0.0.2") || !mesh.on {
		t.Errorf("site join: %v %+v %v", ip, mesh, err)
	}
	if a, err := mesh.address(ip, store.NetworkPlain, ""); err != nil || a != ip {
		t.Errorf("site join answer: %v %v", a, err)
	}
	if _, err := mesh.address(netip.Addr{}, store.NetworkWireGuard, ""); err == nil {
		t.Error("a site join without a private IP accepted")
	}
	ip, mesh, err = prepareJoin(changed{"private-ip": true}, "10.0.0.1:7444", "10.0.0.2", "")
	if err != nil || mesh.on || ip != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("private join: %v %+v %v", ip, mesh, err)
	}
	if _, _, err := prepareJoin(changed{"endpoint": true}, "10.0.0.1:7444", "10.0.0.2", "198.51.100.2"); err == nil {
		t.Error("--endpoint accepted outside a mesh")
	}
	for _, addr := range []string{"203.0.113.1", "0.0.0.0:7444", "224.0.0.1:7444"} {
		if _, _, err := prepareJoin(changed{}, addr, "10.0.0.2", "198.51.100.2"); err == nil {
			t.Errorf("join address %s accepted", addr)
		}
	}
	// The answer must match: a mesh address only from a mesh.
	if _, err := mesh.address(netip.Addr{}, store.NetworkMesh, "10.121.0.2"); err == nil {
		t.Error("a private join took a mesh answer")
	}
	m := joinMesh{on: true}
	if a, err := m.address(netip.Addr{}, store.NetworkMesh, "10.121.0.2"); err != nil || a.String() != "10.121.0.2" {
		t.Errorf("mesh address %v %v", a, err)
	}
	for _, bad := range []string{"", "127.0.0.1", "203.0.113.9"} {
		if _, err := m.address(netip.Addr{}, store.NetworkMesh, bad); err == nil {
			t.Errorf("mesh address %q accepted", bad)
		}
	}
}

func TestMeshJoinListen(t *testing.T) {
	t.Parallel()
	if a, err := meshJoinListen("10.121.0.1:7444", netip.MustParseAddr("203.0.113.5")); err != nil || a != "203.0.113.5:7444" {
		t.Errorf("%q %v", a, err)
	}
	if _, err := meshJoinListen("10.121.0.1:7444", netip.Addr{}); err == nil {
		t.Error("no endpoint accepted")
	}
}

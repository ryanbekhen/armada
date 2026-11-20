package store

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCheckClusterCIDR(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		in string
		ok bool
	}{
		{"10.120.0.0/16", true},
		{"10.0.0.0/12", true},
		{"172.20.0.0/20", true},
		{"10.120.0.0/11", false},  // too large
		{"10.120.0.0/21", false},  // fewer than 16 node subnets
		{"10.120.1.0/16", false},  // not canonical
		{"100.64.0.0/16", false},  // not RFC 1918
		{"203.0.113.0/20", false}, // public
		{"fd00::/16", false},
	} {
		if err := CheckClusterCIDR(netip.MustParsePrefix(c.in)); (err == nil) != c.ok {
			t.Errorf("CheckClusterCIDR(%s) = %v, want ok=%v", c.in, err, c.ok)
		}
	}
}

func TestNodeSubnets(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if _, err := s.GetNetwork(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("network of a new store = %v", err)
	}
	if err := s.InitNetwork(ctx, Network{Mode: "vxlan", ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}); err == nil {
		t.Error("unknown mode accepted")
	}
	cidr := netip.MustParsePrefix("10.120.0.0/20")
	if err := s.InitNetwork(ctx, Network{Mode: NetworkPlain, ClusterCIDR: cidr}); err != nil {
		t.Fatal(err)
	}
	if err := s.InitNetwork(ctx, Network{Mode: NetworkWireGuard, ClusterCIDR: cidr}); !errors.Is(err, ErrConflict) {
		t.Errorf("second InitNetwork = %v", err)
	}
	if n, err := s.GetNetwork(ctx); err != nil || n.Mode != NetworkPlain || n.ClusterCIDR != cidr {
		t.Errorf("GetNetwork = %+v, %v", n, err)
	}

	// The first node (init) and joined nodes get the lowest free subnet,
	// and keep it when their record is rewritten.
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.1", CPUMillis: 1000}); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	for _, id := range []string{"t2", "t3"} {
		if err := s.CreateJoinToken(ctx, JoinToken{ID: id, SecretHash: "h", ExpiresAt: exp, CreatedBy: "admin:a"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RedeemJoinToken(ctx, "t2", accept, Node{ID: "n2", PrivateIP: "10.0.0.2"}, issued("s2", exp)); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"n1": "10.120.0.0/24", "n2": "10.120.1.0/24"}
	for id, sub := range want {
		if n, err := s.GetNode(ctx, id); err != nil || n.Subnet != sub {
			t.Errorf("%s subnet = %q, %v; want %s", id, n.Subnet, err, sub)
		}
	}

	// A node whose private IP is inside the cluster CIDR is refused, and
	// the token stays usable.
	if err := s.RedeemJoinToken(ctx, "t3", accept, Node{ID: "n3", PrivateIP: "10.120.9.9"}, issued("s3", exp)); !errors.Is(err, ErrPrecondition) {
		t.Errorf("private IP in the cluster CIDR = %v", err)
	}

	// A removed node's subnet is given to the next node.
	if err := s.RemoveNode(ctx, "n1", true, "admin:a"); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemJoinToken(ctx, "t3", accept, Node{ID: "n3", PrivateIP: "10.0.0.3"}, issued("s3", exp)); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.GetNode(ctx, "n3"); n.Subnet != "10.120.0.0/24" {
		t.Errorf("n3 subnet = %q, want the freed 10.120.0.0/24", n.Subnet)
	}

	// The network cannot be set once nodes exist.
	s2 := open(t)
	if err := s2.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := s2.InitNetwork(ctx, Network{Mode: NetworkPlain, ClusterCIDR: cidr}); !errors.Is(err, ErrPrecondition) {
		t.Errorf("InitNetwork with nodes = %v", err)
	}
	if n, _ := s2.GetNode(ctx, "n1"); n.Subnet != "" {
		t.Errorf("node of a cluster without network has subnet %q", n.Subnet)
	}
}

func TestFreeSubnetExhausted(t *testing.T) {
	t.Parallel()
	cidr := netip.MustParsePrefix("10.120.0.0/20")
	used := map[string]bool{}
	for range 16 {
		p, err := freeSubnet(cidr, used)
		if err != nil {
			t.Fatal(err)
		}
		used[p.String()] = true
	}
	if _, err := freeSubnet(cidr, used); !errors.Is(err, ErrPrecondition) {
		t.Errorf("17th subnet of a /20 = %v", err)
	}
}

func TestNodeNetworkKey(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	for _, id := range []string{"n1", "n2"} {
		if err := s.UpsertNode(ctx, Node{ID: id, PrivateIP: "10.0.0." + id[1:]}); err != nil {
			t.Fatal(err)
		}
	}
	st := NodeStatus{State: NodeReady, LastSeen: time.Now(), NetworkKey: "key-1"}
	if err := s.SetNodeStatus(ctx, "n1", st); err != nil {
		t.Fatal(err)
	}
	// An empty key keeps the recorded one, as does rewriting the node.
	if err := s.SetNodeStatus(ctx, "n1", NodeStatus{State: NodeUnknown}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.1", CPUMillis: 500}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.GetNode(ctx, "n1"); n.NetworkKey != "key-1" {
		t.Errorf("key = %q", n.NetworkKey)
	}
	// Another node cannot take it.
	if err := s.SetNodeStatus(ctx, "n2", st); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate key = %v", err)
	}
	if n, _ := s.GetNode(ctx, "n2"); n.NetworkKey != "" {
		t.Errorf("n2 key = %q", n.NetworkKey)
	}
	// A node may change its own.
	st.NetworkKey = "key-2"
	if err := s.SetNodeStatus(ctx, "n1", st); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.GetNode(ctx, "n1"); n.NetworkKey != "key-2" {
		t.Errorf("changed key = %q", n.NetworkKey)
	}
}

func TestDefaultIsolation(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if err := s.SetDefaultIsolation(ctx, true, "admin:a"); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("without a network = %v, want ErrPrecondition", err)
	}
	if err := s.InitNetwork(ctx, Network{Mode: NetworkPlain, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.GetNetwork(ctx); n.IsolateDefault {
		t.Fatal("isolated by default")
	}
	for _, on := range []bool{true, true, false} {
		if err := s.SetDefaultIsolation(ctx, on, "admin:a"); err != nil {
			t.Fatal(err)
		}
		n, _ := s.GetNetwork(ctx)
		if n.IsolateDefault != on || n.Mode != NetworkPlain || n.ClusterCIDR.String() != "10.120.0.0/16" {
			t.Errorf("after %t: %+v", on, n)
		}
	}
	audit, _ := s.ListAudit(ctx, 10)
	changes := 0
	for _, e := range audit {
		if e.Action == "space.set" {
			changes++
		}
	}
	if changes != 2 {
		t.Errorf("%d audit events, want 2 (an unchanged setting is not recorded)", changes)
	}
}

func TestMeshNetwork(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	cidr, mesh := netip.MustParsePrefix("10.120.0.0/16"), netip.MustParsePrefix("10.121.0.0/16")
	for name, n := range map[string]Network{
		"no mesh CIDR":      {Mode: NetworkMesh, ClusterCIDR: cidr},
		"public mesh CIDR":  {Mode: NetworkMesh, ClusterCIDR: cidr, MeshCIDR: netip.MustParsePrefix("203.0.113.0/24")},
		"overlap":           {Mode: NetworkMesh, ClusterCIDR: cidr, MeshCIDR: netip.MustParsePrefix("10.0.0.0/8")},
		"mesh CIDR in host": {Mode: NetworkMesh, ClusterCIDR: cidr, MeshCIDR: netip.MustParsePrefix("10.121.0.1/16")},
		"mesh CIDR in wg":   {Mode: NetworkWireGuard, ClusterCIDR: cidr, MeshCIDR: mesh},
	} {
		if err := s.InitNetwork(ctx, n); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := s.InitNetwork(ctx, Network{Mode: NetworkMesh, ClusterCIDR: cidr, MeshCIDR: mesh}); err != nil {
		t.Fatal(err)
	}
	if n, err := s.GetNetwork(ctx); err != nil || n.Mode != NetworkMesh || n.MeshCIDR != mesh {
		t.Fatalf("network %+v, %v", n, err)
	}
	// A node's address is a mesh address.
	if err := s.UpsertNode(ctx, Node{ID: "n0", PrivateIP: "10.0.0.1"}); !errors.Is(err, ErrPrecondition) {
		t.Errorf("address outside the mesh = %v", err)
	}
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.121.0.1"}); err != nil {
		t.Fatal(err)
	}
	// The agent announces its endpoint; an empty one keeps it.
	if err := s.SetNodeStatus(ctx, "n1", NodeStatus{State: NodeReady, LastSeen: time.Now(), Endpoint: "203.0.113.1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeStatus(ctx, "n1", NodeStatus{State: NodeReady, LastSeen: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.121.0.1", CPUMillis: 500}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.GetNode(ctx, "n1"); n.Endpoint != "203.0.113.1" || n.Subnet == "" {
		t.Errorf("node %+v", n)
	}
}

// Machines joining a mesh get the lowest free mesh address, and a key
// another node holds is refused; open tokens are listed for the join
// listener with the address they name (ADR 0049).
func TestMeshJoinRecords(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if _, err := s.FreeMeshAddress(ctx); !errors.Is(err, ErrPrecondition) {
		t.Errorf("free mesh address without a mesh = %v", err)
	}
	if err := s.InitNetwork(ctx, Network{Mode: NetworkMesh, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16"), MeshCIDR: netip.MustParsePrefix("10.121.0.0/30")}); err == nil {
		t.Fatal("a /30 mesh accepted")
	}
	if err := s.InitNetwork(ctx, Network{Mode: NetworkMesh, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16"), MeshCIDR: netip.MustParsePrefix("10.121.0.0/24")}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNode(ctx, Node{ID: "a", PrivateIP: "10.121.0.1", NetworkKey: "key-a", Endpoint: "203.0.113.1"}); err != nil {
		t.Fatal(err)
	}
	if a, err := s.FreeMeshAddress(ctx); err != nil || a != "10.121.0.2" {
		t.Fatalf("free = %q, %v", a, err)
	}
	exp := time.Now().Add(time.Hour)
	for _, tok := range []JoinToken{{ID: "t1", SecretHash: "h", ExpiresAt: exp, From: "198.51.100.9"}, {ID: "t2", SecretHash: "h", ExpiresAt: exp}} {
		if err := s.CreateJoinToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	toks, err := s.OpenJoinTokens(ctx)
	if err != nil || len(toks) != 2 {
		t.Fatalf("open tokens %+v, %v", toks, err)
	}
	for _, tok := range toks {
		if tok.SecretHash != "" || (tok.ID == "t1") != (tok.From == "198.51.100.9") {
			t.Errorf("token %+v", tok)
		}
	}
	if err := s.RedeemJoinToken(ctx, "t1", accept, Node{ID: "b", PrivateIP: "10.121.0.2", NetworkKey: "key-a", Endpoint: "203.0.113.2"}, issued("s1", exp)); !errors.Is(err, ErrConflict) {
		t.Errorf("another node's key = %v", err)
	}
	if err := s.RedeemJoinToken(ctx, "t1", accept, Node{ID: "b", PrivateIP: "10.121.0.2", NetworkKey: "key-b", Endpoint: "203.0.113.2"}, issued("s1", exp)); err != nil {
		t.Fatal(err)
	}
	if n, err := s.GetNode(ctx, "b"); err != nil || n.NetworkKey != "key-b" || n.Endpoint != "203.0.113.2" || n.Subnet == "" {
		t.Errorf("node b %+v, %v", n, err)
	}
	if toks, _ := s.OpenJoinTokens(ctx); len(toks) != 1 || toks[0].ID != "t2" {
		t.Errorf("open after redeem %+v", toks)
	}
	if a, err := s.FreeMeshAddress(ctx); err != nil || a != "10.121.0.3" {
		t.Errorf("free = %q, %v", a, err)
	}
}

func TestFreeMeshAddress(t *testing.T) {
	t.Parallel()
	mesh := netip.MustParsePrefix("10.121.0.0/24")
	used := map[netip.Addr]bool{}
	for i := 1; i <= 254; i++ {
		a, err := freeMeshAddress(mesh, used)
		if err != nil {
			t.Fatalf("after %d: %v", i-1, err)
		}
		if a.String() == "10.121.0.0" || a.String() == "10.121.0.255" {
			t.Fatalf("network or broadcast address %s", a)
		}
		used[a] = true
	}
	if _, err := freeMeshAddress(mesh, used); !errors.Is(err, ErrPrecondition) {
		t.Errorf("full mesh = %v", err)
	}
}

// A running cluster switches between plain and wireguard in two steps; it
// can give a switch up only before the routes move (ADR 0050).
func TestNetworkSwitch(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if err := s.StartNetworkSwitch(ctx, NetworkWireGuard, "user:a"); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("without a network = %v, want ErrPrecondition", err)
	}
	if err := s.InitNetwork(ctx, Network{Mode: NetworkPlain, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	for _, to := range []string{NetworkMesh, "ipsec"} {
		if err := s.StartNetworkSwitch(ctx, to, "user:a"); !errors.Is(err, ErrPrecondition) {
			t.Errorf("to %s = %v, want ErrPrecondition", to, err)
		}
	}
	// The current mode is no switch.
	if err := s.StartNetworkSwitch(ctx, NetworkPlain, "user:a"); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.GetNetwork(ctx); n.Switch != nil {
		t.Fatalf("switch %+v to the current mode", n.Switch)
	}
	sw := func() *NetworkSwitch {
		t.Helper()
		n, err := s.GetNetwork(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return n.Switch
	}
	if err := s.StartNetworkSwitch(ctx, NetworkWireGuard, "user:a"); err != nil {
		t.Fatal(err)
	}
	if got := sw(); got == nil || got.To != NetworkWireGuard || got.Step != SwitchPrepare || got.Since.IsZero() {
		t.Fatalf("switch = %+v", got)
	}
	if err := s.StartNetworkSwitch(ctx, NetworkWireGuard, "user:a"); !errors.Is(err, ErrConflict) {
		t.Errorf("a second switch = %v, want ErrConflict", err)
	}
	// Given up while preparing.
	if err := s.StartNetworkSwitch(ctx, NetworkPlain, "user:a"); err != nil || sw() != nil {
		t.Fatalf("give up = %v, switch %+v", err, sw())
	}
	if err := s.StartNetworkSwitch(ctx, NetworkWireGuard, "user:a"); err != nil {
		t.Fatal(err)
	}
	// Only from the step it is at.
	if err := s.AdvanceNetworkSwitch(ctx, NetworkWireGuard, SwitchMove); !errors.Is(err, ErrConflict) {
		t.Errorf("advance from the wrong step = %v", err)
	}
	if err := s.AdvanceNetworkSwitch(ctx, NetworkPlain, SwitchPrepare); !errors.Is(err, ErrConflict) {
		t.Errorf("advance to the wrong mode = %v", err)
	}
	if err := s.AdvanceNetworkSwitch(ctx, NetworkWireGuard, SwitchPrepare); err != nil {
		t.Fatal(err)
	}
	if got := sw(); got == nil || got.Step != SwitchMove {
		t.Fatalf("after prepare: %+v", got)
	}
	// Once the routes move, the switch finishes.
	if err := s.StartNetworkSwitch(ctx, NetworkPlain, "user:a"); !errors.Is(err, ErrConflict) {
		t.Errorf("give up while moving = %v, want ErrConflict", err)
	}
	if err := s.AdvanceNetworkSwitch(ctx, NetworkWireGuard, SwitchMove); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.GetNetwork(ctx); n.Mode != NetworkWireGuard || n.Switch != nil || n.ClusterCIDR.String() != "10.120.0.0/16" {
		t.Fatalf("after the switch: %+v", n)
	}
	audit, _ := s.ListAudit(ctx, 20)
	n := 0
	for _, e := range audit {
		if e.Action == "network.switch" {
			n++
		}
	}
	if n != 3 {
		t.Errorf("%d audit events, want 3 (two starts and a give-up)", n)
	}

	mesh := open(t)
	if err := mesh.InitNetwork(ctx, Network{Mode: NetworkMesh, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16"), MeshCIDR: netip.MustParsePrefix("10.122.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	if err := mesh.StartNetworkSwitch(ctx, NetworkWireGuard, "user:a"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("mesh = %v, want ErrPrecondition", err)
	}
}

// Sites and switches exclude each other (ADR 0050): a switch moves only the
// first site's transport, so it waits for nodes elsewhere to come back, and
// a node changes site only while no switch runs.
func TestNetworkSwitchSites(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if err := s.InitNetwork(ctx, Network{Mode: NetworkPlain, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNode(ctx, Node{ID: "far", PrivateIP: "10.0.0.9"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeSite(ctx, "far", "office", "user:a"); err != nil {
		t.Fatal(err)
	}
	err := s.StartNetworkSwitch(ctx, NetworkWireGuard, "user:a")
	if !errors.Is(err, ErrPrecondition) || !strings.Contains(err.Error(), "far") {
		t.Fatalf("switch with a node in another site = %v, want ErrPrecondition naming it", err)
	}
	if err := s.SetNodeSite(ctx, "far", "", "user:a"); err != nil {
		t.Fatal(err)
	}
	if err := s.StartNetworkSwitch(ctx, NetworkWireGuard, "user:a"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeSite(ctx, "far", "office", "user:a"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("site during a switch = %v, want ErrPrecondition", err)
	}
	// Setting the site a node already has changes nothing and passes.
	if err := s.SetNodeSite(ctx, "far", "", "user:a"); err != nil {
		t.Errorf("unchanged site during a switch = %v", err)
	}
}

// A plain or wireguard cluster gives machines with no private network mesh
// addresses from a range recorded with the first of them (ADR 0050).
func TestMeshAddressesOutsideMesh(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if _, err := s.FreeMeshAddress(ctx); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("FreeMeshAddress without a network = %v", err)
	}
	if err := s.InitNetwork(ctx, Network{Mode: NetworkPlain, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	// A private network inside the default range: allowed until the
	// range is recorded, and then in the way of recording it.
	if err := s.UpsertNode(ctx, Node{ID: "a", PrivateIP: "10.122.0.1"}); err != nil {
		t.Fatal(err)
	}
	a, err := s.FreeMeshAddress(ctx)
	if err != nil || a != "10.122.0.2" {
		t.Fatalf("FreeMeshAddress = %q, %v; want the default range past a's address", a, err)
	}
	if err := s.UpsertNode(ctx, Node{ID: "m", PrivateIP: a, MeshAddress: true}); !errors.Is(err, ErrPrecondition) || !strings.Contains(err.Error(), "--mesh-cidr") {
		t.Fatalf("mesh address with a node in the range = %v", err)
	}
	for _, bad := range []string{"10.120.0.0/24", "10.122.0.0/16", "10.0.0.0/25", "8.8.0.0/16"} {
		if err := s.SetMeshCIDR(ctx, netip.MustParsePrefix(bad), "user:a"); !errors.Is(err, ErrPrecondition) {
			t.Errorf("SetMeshCIDR(%s) = %v, want ErrPrecondition", bad, err)
		}
	}
	mesh := netip.MustParsePrefix("10.123.0.0/24")
	if err := s.SetMeshCIDR(ctx, mesh, "user:a"); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.GetNetwork(ctx); n.MeshCIDR != mesh {
		t.Fatalf("mesh CIDR = %v", n.MeshCIDR)
	}
	if a, err = s.FreeMeshAddress(ctx); err != nil || a != "10.123.0.1" {
		t.Fatalf("FreeMeshAddress = %q, %v", a, err)
	}
	if err := s.UpsertNode(ctx, Node{ID: "m", PrivateIP: "10.0.0.9", MeshAddress: true}); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("mesh address outside the range = %v", err)
	}
	if err := s.UpsertNode(ctx, Node{ID: "m", PrivateIP: a, MeshAddress: true, Endpoint: "203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	if n, err := s.GetNode(ctx, "m"); err != nil || !n.MeshAddress {
		t.Fatalf("node m = %+v, %v; want a mesh address", n, err)
	}
	// The range is taken now: no private IP in it, no other range.
	if err := s.UpsertNode(ctx, Node{ID: "b", PrivateIP: "10.123.0.7"}); !errors.Is(err, ErrPrecondition) || !strings.Contains(err.Error(), "--no-private-ip") {
		t.Errorf("private IP in the mesh range = %v", err)
	}
	if err := s.SetMeshCIDR(ctx, netip.MustParsePrefix("10.124.0.0/24"), "user:a"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("SetMeshCIDR with a mesh address held = %v", err)
	}
	if err := s.SetMeshCIDR(ctx, mesh, "user:a"); err != nil {
		t.Errorf("SetMeshCIDR to the same range = %v", err)
	}
}

// The first mesh address records the default range.
func TestMeshAddressRecordsDefaultRange(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if err := s.InitNetwork(ctx, Network{Mode: NetworkWireGuard, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNode(ctx, Node{ID: "m", PrivateIP: "10.122.0.1", MeshAddress: true}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.GetNetwork(ctx); n.MeshCIDR.String() != DefaultMeshCIDR {
		t.Fatalf("mesh CIDR = %v, want %s", n.MeshCIDR, DefaultMeshCIDR)
	}
	m := openMesh(t)
	if err := m.SetMeshCIDR(ctx, netip.MustParsePrefix("10.124.0.0/24"), "user:a"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("SetMeshCIDR in a mesh cluster = %v", err)
	}
}

func openMesh(t *testing.T) *Etcd {
	t.Helper()
	s := open(t)
	if err := s.InitNetwork(context.Background(), Network{Mode: NetworkMesh, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16"), MeshCIDR: netip.MustParsePrefix("10.121.0.0/24")}); err != nil {
		t.Fatal(err)
	}
	return s
}

package store

import (
	"context"
	"errors"
	"net/netip"
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

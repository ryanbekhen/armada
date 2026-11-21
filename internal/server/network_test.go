package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"maps"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
)

func TestValidNetworkKey(t *testing.T) {
	t.Parallel()
	good := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	if !validNetworkKey(good) {
		t.Errorf("%s refused", good)
	}
	for _, bad := range []string{
		"",
		"not a key",
		base64.StdEncoding.EncodeToString(make([]byte, 32)),                   // zero
		base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 31))),    // short
		base64.URLEncoding.EncodeToString([]byte(strings.Repeat("\xff", 32))), // other alphabet
		good[:43] + "\n",
	} {
		if validNetworkKey(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// A mesh node's agent announces its endpoint, which the leader keeps only
// when it is a unicast IPv4 address and hands to every node with the mesh
// range (ADR 0049).
func TestMeshEndpoint(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	if err := c.store.InitNetwork(c.ctx, store.Network{Mode: store.NetworkMesh, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16"), MeshCIDR: netip.MustParsePrefix("10.121.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	if err := c.store.UpsertNode(c.ctx, store.Node{ID: "n1", PrivateIP: "10.121.0.2"}); err != nil {
		t.Fatal(err)
	}
	connect := func(endpoint string) {
		t.Helper()
		ctx, cancel := context.WithCancel(c.ctx)
		defer cancel()
		ag := armadav1.NewAgentServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindNode, Name: "n1"}))
		stream, err := ag.Connect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.Send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Hello{Hello: &armadav1.Hello{PrivateIp: "10.121.0.2", Endpoint: endpoint}}}); err != nil {
			t.Fatal(err)
		}
		c.eventually("ready", func() bool { n, _ := c.store.GetNode(c.ctx, "n1"); return n.State == store.NodeReady })
	}
	connect("127.0.0.1")
	if n, _ := c.store.GetNode(c.ctx, "n1"); n.Endpoint != "" {
		t.Errorf("loopback endpoint kept: %q", n.Endpoint)
	}
	c.eventually("disconnected", func() bool { n, _ := c.store.GetNode(c.ctx, "n1"); return n.State != store.NodeReady })
	connect("203.0.113.2")
	n, err := c.store.GetNode(c.ctx, "n1")
	if err != nil || n.Endpoint != "203.0.113.2" {
		t.Fatalf("endpoint %q, %v", n.Endpoint, err)
	}
	cfg, err := c.srv.buildNetwork(c.ctx, []store.Node{n}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GetMode() != store.NetworkMesh || cfg.GetMeshCidr() != "10.121.0.0/16" || len(cfg.GetPeers()) != 1 || cfg.GetPeers()[0].GetEndpoint() != "203.0.113.2" || cfg.GetPeers()[0].GetPrivateIp() != "10.121.0.2" {
		t.Errorf("network %v", cfg)
	}
}

// Every peer carries its node's site (ADR 0050), and sites and switches
// refuse each other through the API.
func TestNetworkSites(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	if err := c.store.InitNetwork(c.ctx, store.Network{Mode: store.NetworkPlain, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"n1", "n2"} {
		if err := c.store.UpsertNode(c.ctx, store.Node{ID: id, PrivateIP: "10.0.0." + id[1:]}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.admin.SetNodeSite(c.ctx, &armadav1.SetNodeSiteRequest{Node: "n2", Site: "office"}); err != nil {
		t.Fatal(err)
	}
	nodes, err := c.store.ListNodes(c.ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := c.srv.buildNetwork(c.ctx, nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	sites := map[string]string{}
	for _, p := range cfg.GetPeers() {
		sites[p.GetNode()] = p.GetSite()
	}
	if len(sites) != 2 || sites["n1"] != "" || sites["n2"] != "office" {
		t.Fatalf("peer sites %v", sites)
	}
	if _, err := c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{SetNetwork: true, Config: &armadav1.ClusterConfig{Network: store.NetworkWireGuard}}); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "n2") {
		t.Errorf("switch with n2 in another site: %v", err)
	}
	if _, err := c.admin.SetNodeSite(c.ctx, &armadav1.SetNodeSiteRequest{Node: "n2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{SetNetwork: true, Config: &armadav1.ClusterConfig{Network: store.NetworkWireGuard}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.admin.SetNodeSite(c.ctx, &armadav1.SetNodeSiteRequest{Node: "n2", Site: "office"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("site during a switch: %v", err)
	}
}

// Sites with a node behind NAT get a relay: a ready node of the site with
// an endpoint, the one an admin chose while it can relay, else the same
// one every pass; nodes behind NAT cannot be chosen (ADR 0050).
func TestNetworkRelays(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	if err := c.store.InitNetwork(c.ctx, store.Network{Mode: store.NetworkPlain, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for i, id := range []string{"a1", "a2", "a3", "nat", "b1"} {
		if err := c.store.UpsertNode(c.ctx, store.Node{ID: id, PrivateIP: fmt.Sprintf("10.0.0.%d", i+1)}); err != nil {
			t.Fatal(err)
		}
		k, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		keys[id] = k.PublicKey().String()
		st := store.NodeStatus{State: store.NodeReady, LastSeen: time.Now(), NetworkKey: keys[id], Endpoint: fmt.Sprintf("203.0.113.%d", i+1)}
		if id == "nat" {
			st.Endpoint, st.BehindNAT = "", true
		}
		if err := c.store.SetNodeStatus(c.ctx, id, st); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.admin.SetNodeSite(c.ctx, &armadav1.SetNodeSiteRequest{Node: "b1", Site: "far"}); err != nil {
		t.Fatal(err)
	}
	relays := func() map[string]bool {
		t.Helper()
		nodes, err := c.store.ListNodes(c.ctx)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := c.srv.buildNetwork(c.ctx, nodes, nil)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, p := range cfg.GetPeers() {
			if p.GetRelay() {
				out[p.GetNode()] = true
			}
			if p.GetNode() == "nat" && (!p.GetBehindNat() || p.GetEndpoint() != "") {
				t.Errorf("peer nat: %v", p)
			}
		}
		return out
	}
	// One per site with a node that can relay: b1 in far, one of a1..a3
	// in the first.
	first := relays()
	if len(first) != 2 || !first["b1"] || first["nat"] {
		t.Fatalf("relays %v", first)
	}
	if again := relays(); !maps.Equal(first, again) {
		t.Errorf("relay moved: %v, then %v", first, again)
	}
	// An admin's choice wins; a node behind NAT cannot be chosen.
	if _, err := c.admin.SetNodeRelay(c.ctx, &armadav1.SetNodeRelayRequest{Node: "nat"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("relay behind NAT: %v", err)
	}
	pick := "a1"
	if first["a1"] {
		pick = "a2"
	}
	if _, err := c.admin.SetNodeRelay(c.ctx, &armadav1.SetNodeRelayRequest{Node: pick}); err != nil {
		t.Fatal(err)
	}
	if r := relays(); len(r) != 2 || !r[pick] {
		t.Errorf("chosen %s, relays %v", pick, r)
	}
	// A drained choice gives way, and comes back when resumed.
	if err := c.store.SetNodeCordoned(c.ctx, pick, true, "admin:a"); err != nil {
		t.Fatal(err)
	}
	if r := relays(); len(r) != 2 || r[pick] {
		t.Errorf("drained %s, relays %v", pick, r)
	}
	if err := c.store.SetNodeCordoned(c.ctx, pick, false, "admin:a"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.admin.SetNodeRelay(c.ctx, &armadav1.SetNodeRelayRequest{Node: pick, Clear: true}); err != nil {
		t.Fatal(err)
	}
	if r := relays(); !maps.Equal(r, first) {
		t.Errorf("after clear %v, want %v", r, first)
	}
	// The status shows it.
	st, err := c.admin.Status(c.ctx, &armadav1.StatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range st.GetNodes() {
		if n.GetRelay() != first[n.GetId()] || n.GetBehindNat() != (n.GetId() == "nat") {
			t.Errorf("status of %s: relay %v, behind NAT %v", n.GetId(), n.GetRelay(), n.GetBehindNat())
		}
	}
}

package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/agent"
	"github.com/ryanbekhen/armada/internal/alert"
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
	// One choice per site: choosing another node of the site moves it,
	// names the node that had it, and tells that node's history.
	other := "a3"
	resp, err := c.admin.SetNodeRelay(c.ctx, &armadav1.SetNodeRelayRequest{Node: other})
	if err != nil || !slices.Equal(resp.GetReplaced(), []string{pick}) {
		t.Fatalf("choosing %s: %v, %v", other, resp, err)
	}
	if r := relays(); len(r) != 2 || !r[other] {
		t.Errorf("chosen %s, relays %v", other, r)
	}
	evs, _ := c.store.ListEvents(c.ctx, time.Time{})
	if !slices.ContainsFunc(evs, func(e store.Event) bool {
		return e.Object == pick && e.Reason == "RelayCleared" && strings.Contains(e.Message, "now node "+other)
	}) || !slices.ContainsFunc(evs, func(e store.Event) bool {
		return e.Object == other && e.Reason == "RelayChosen" && strings.Contains(e.Message, "in place of node "+pick)
	}) {
		t.Errorf("events %v", evs)
	}
	if _, err := c.admin.SetNodeRelay(c.ctx, &armadav1.SetNodeRelayRequest{Node: pick}); err != nil {
		t.Fatal(err)
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

// A node's report of WireGuard peers with no recent handshake raises one
// PeerUnreachable event, with valid names only, until a report names none
// (ADR 0025).
func TestPeerUnreachable(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	events := func() []store.Event {
		t.Helper()
		evs, err := c.store.ListEvents(c.ctx, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		var out []store.Event
		for _, e := range evs {
			if e.Reason == "PeerUnreachable" {
				out = append(out, e)
			}
		}
		return out
	}
	c.srv.peersChecked(c.ctx, "n1", &armadav1.UsageReport{})
	c.srv.peersChecked(c.ctx, "n1", &armadav1.UsageReport{PeersChecked: true})
	if len(events()) != 0 {
		t.Fatal("an event without unreachable peers")
	}
	for range 2 {
		c.srv.peersChecked(c.ctx, "n1", &armadav1.UsageReport{PeersChecked: true, UnreachablePeers: []string{"b", "Not A Name", "c"}})
	}
	evs := events()
	if len(evs) != 1 || evs[0].Node != "n1" || !strings.HasSuffix(evs[0].Message, "with b, c") {
		t.Fatalf("events %+v", evs)
	}
	// Cleared, then raised again: a second event.
	c.srv.peersChecked(c.ctx, "n1", &armadav1.UsageReport{PeersChecked: true})
	c.srv.peersChecked(c.ctx, "n1", &armadav1.UsageReport{PeersChecked: true, UnreachablePeers: []string{"b"}})
	if got := checkedPeers(slices.Repeat([]string{"x"}, 40)); len(got) != maxUnreachablePeers {
		t.Errorf("%d peers kept", len(got))
	}
}

// rotatingNet is a cluster network whose key the agent can replace.
type rotatingNet struct {
	fakeNet
	keys chan string
}

func (n *rotatingNet) RotateKey() (string, error) {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", err
	}
	n.keys <- k.PublicKey().String()
	return k.PublicKey().String(), nil
}

// armada node rotate-key: the agent makes a new key, announces it, and the
// leader records it, pushes it to the other nodes, and says so (ADR 0025).
// A node that cannot rotate, or is not connected, is refused.
func TestRotateNodeKey(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	if err := c.store.InitNetwork(c.ctx, store.Network{Mode: store.NetworkWireGuard, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	nets := map[string]*rotatingNet{"n1": {keys: make(chan string, 1)}, "n2": {keys: make(chan string, 1)}}
	c.agentConfig = func(id string, cfg *agent.Config) {
		k, _ := wgtypes.GeneratePrivateKey()
		cfg.Network, cfg.NetworkKey = nets[id], k.PublicKey().String()
	}
	c.addNode("n1", "10.0.0.11")
	c.addNode("n2", "10.0.0.12")
	before, _ := c.store.GetNode(c.ctx, "n1")
	if before.NetworkKey == "" {
		t.Fatal("n1 announced no key")
	}
	if _, err := c.admin.RotateNodeKey(c.ctx, &armadav1.RotateNodeKeyRequest{Node: "n1"}); err != nil {
		t.Fatal(err)
	}
	var key string
	select {
	case key = <-nets["n1"].keys:
	case <-time.After(10 * time.Second):
		t.Fatal("the agent made no key")
	}
	c.eventually("new key recorded and pushed to n2", func() bool {
		n, _ := c.store.GetNode(c.ctx, "n1")
		nets["n2"].mu.Lock()
		defer nets["n2"].mu.Unlock()
		for _, p := range nets["n2"].cfg.GetPeers() {
			if p.GetNode() == "n1" {
				return n.NetworkKey == key && p.GetPublicKey() == key
			}
		}
		return false
	})
	c.eventually("event", func() bool {
		evs, _ := c.store.ListEvents(c.ctx, time.Time{})
		return slices.ContainsFunc(evs, func(e store.Event) bool { return e.Reason == "NetworkKeyRotated" && e.Node == "n1" })
	})
	audit, _ := c.store.ListAudit(c.ctx, 50)
	if !slices.ContainsFunc(audit, func(e store.AuditEvent) bool { return e.Action == "node.rotate-key" && e.Target == "n1" }) {
		t.Error("no audit entry")
	}
	// Another node's key is refused.
	c.srv.networkKeyChanged(c.ctx, "n2", key)
	if n2, _ := c.store.GetNode(c.ctx, "n2"); n2.NetworkKey == key {
		t.Error("n2 took n1's key")
	}
	if _, err := c.admin.RotateNodeKey(c.ctx, &armadav1.RotateNodeKeyRequest{Node: "ghost"}); status.Code(err) != codes.NotFound {
		t.Errorf("unknown node: %v", err)
	}
	c.stopAgent("n2")
	if _, err := c.admin.RotateNodeKey(c.ctx, &armadav1.RotateNodeKeyRequest{Node: "n2"}); status.Code(err) != codes.Unavailable {
		t.Errorf("disconnected node: %v", err)
	}
}

// A node whose WireGuard runs in userspace raises one WireGuardUserspace
// event, a warning for alerts, until a report says it no longer does; a
// report that checked nothing changes nothing (ADR 0025).
func TestWireGuardUserspace(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	events := func() []store.Event {
		t.Helper()
		evs, err := c.store.ListEvents(c.ctx, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		var out []store.Event
		for _, e := range evs {
			if e.Reason == "WireGuardUserspace" {
				out = append(out, e)
			}
		}
		return out
	}
	c.srv.peersChecked(c.ctx, "n1", &armadav1.UsageReport{WireguardUserspace: true})
	c.srv.peersChecked(c.ctx, "n1", &armadav1.UsageReport{PeersChecked: true})
	if len(events()) != 0 {
		t.Fatal("an event without userspace WireGuard")
	}
	for range 2 {
		c.srv.peersChecked(c.ctx, "n1", &armadav1.UsageReport{PeersChecked: true, WireguardUserspace: true})
	}
	evs := events()
	if len(evs) != 1 || evs[0].Node != "n1" || evs[0].Kind != eventNode || !strings.Contains(evs[0].Message, "Linux 5.6") {
		t.Fatalf("events %+v", evs)
	}
	if !alert.Warning("WireGuardUserspace") {
		t.Error("WireGuardUserspace is not an alert warning")
	}
}

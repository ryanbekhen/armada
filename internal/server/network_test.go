package server

import (
	"context"
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"

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

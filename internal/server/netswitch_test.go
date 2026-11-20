package server

import (
	"context"
	"crypto/tls"
	"net/netip"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/store/storetest"
)

// The leader moves a network switch on once every connected node reports
// the step done, and the nodes get each step in their network config
// (ADR 0050).
func TestNetworkSwitchSteps(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := storetest.Open(t)
	if err := st.InitNetwork(ctx, store.Network{Mode: store.NetworkPlain, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1_700_000_000_000)
	for i, id := range []string{"n1", "n2", "n3"} {
		if err := st.UpsertNode(ctx, store.Node{ID: id, PrivateIP: netip.AddrFrom4([4]byte{10, 0, 0, byte(2 + i)}).String()}); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"n1", "n2"} {
		if err := st.SetNodeStatus(ctx, id, store.NodeStatus{State: store.NodeReady, LastSeen: now}); err != nil {
			t.Fatal(err)
		}
	}
	// n3 never connected: nothing waits for it.
	srv, err := New(Config{Store: st, TLS: &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	connect := func(id string, switches bool) {
		srv.sessions[id] = &session{nodeID: id, netSwitch: switches, send: make(chan *armadav1.ServerMessage, 64), done: make(chan struct{})}
	}
	connect("n1", true)
	connect("n2", false)
	if err := srv.setNetwork(ctx, store.NetworkWireGuard); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("with an old agent = %v, want FailedPrecondition", err)
	}
	connect("n2", true)
	if err := srv.setNetwork(ctx, store.NetworkMesh); status.Code(err) != codes.InvalidArgument {
		t.Errorf("to mesh = %v", err)
	}
	if err := srv.setNetwork(ctx, store.NetworkWireGuard); err != nil {
		t.Fatal(err)
	}
	pass := func() (*armadav1.NetworkConfig, *armadav1.NetworkSwitchProgress) {
		t.Helper()
		if err := srv.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		nodes, err := st.ListNodes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := srv.buildNetwork(ctx, nodes, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := srv.ClusterStatus(srv.internalContext(ctx), &armadav1.ClusterStatusRequest{})
		if err != nil {
			t.Fatal(err)
		}
		return cfg, resp.NetworkSwitch
	}
	report := func(id, step string, ready bool, unreached ...string) {
		srv.usage.set(id, &armadav1.UsageReport{NetworkSwitch: &armadav1.NetworkSwitchStatus{To: store.NetworkWireGuard, Step: step, Ready: ready, Unreached: unreached}}, now)
	}

	cfg, p := pass()
	if cfg.SwitchTo != store.NetworkWireGuard || cfg.SwitchStep != store.SwitchPrepare || cfg.Mode != store.NetworkPlain {
		t.Fatalf("config %v", cfg)
	}
	if p == nil || p.WaitingTotal != 2 || p.From != store.NetworkPlain || p.Step != store.SwitchPrepare {
		t.Fatalf("progress %v", p)
	}
	report("n1", store.SwitchPrepare, true)
	report("n2", store.SwitchPrepare, false, "n1", "Bad;Name")
	if _, p = pass(); p.WaitingTotal != 1 || p.Waiting[0].Node != "n2" || len(p.Waiting[0].Unreached) != 1 {
		t.Fatalf("progress %v", p)
	}
	// A report for another step does not count.
	report("n2", store.SwitchMove, true)
	if _, p = pass(); p.WaitingTotal != 1 {
		t.Fatalf("progress %v", p)
	}
	report("n2", store.SwitchPrepare, true)
	if cfg, _ = pass(); cfg.SwitchStep != store.SwitchMove {
		t.Fatalf("after prepare: %v", cfg)
	}
	// The routes have moved: giving up is too late.
	if err := srv.setNetwork(ctx, store.NetworkPlain); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("give up while moving = %v", err)
	}
	report("n1", store.SwitchMove, true)
	// A disconnected node holds the step until it is lost.
	delete(srv.sessions, "n2")
	if _, p = pass(); p.WaitingTotal != 1 || !p.Waiting[0].Disconnected {
		t.Fatalf("progress %v", p)
	}
	connect("n2", true)
	report("n2", store.SwitchMove, true)
	cfg, p = pass()
	if cfg.Mode != store.NetworkWireGuard || cfg.SwitchTo != "" || cfg.SwitchStep != "" || p != nil {
		t.Fatalf("after the switch: %v, %v", cfg, p)
	}
	cc, err := srv.GetClusterConfig(ctx, nil)
	if err != nil || cc.Network != store.NetworkWireGuard || cc.NetworkSwitchTo != "" {
		t.Errorf("cluster config %v, %v", cc, err)
	}

	// Started again and given up while preparing.
	if err := srv.setNetwork(ctx, store.NetworkPlain); err != nil {
		t.Fatal(err)
	}
	if cc, _ := srv.GetClusterConfig(ctx, nil); cc.NetworkSwitchTo != store.NetworkPlain {
		t.Errorf("cluster config %v", cc)
	}
	if err := srv.setNetwork(ctx, store.NetworkWireGuard); err != nil {
		t.Fatal(err)
	}
	if cfg, _ = pass(); cfg.Mode != store.NetworkWireGuard || cfg.SwitchTo != "" {
		t.Errorf("after giving up: %v", cfg)
	}
}

// What a node says about its side of a switch is bounded.
func TestCleanSwitchStatus(t *testing.T) {
	t.Parallel()
	if cleanSwitchStatus(&armadav1.NetworkSwitchStatus{To: "mesh", Step: "prepare", Ready: true}) != nil {
		t.Error("unknown target kept")
	}
	if cleanSwitchStatus(&armadav1.NetworkSwitchStatus{To: "plain", Step: "cleanup", Ready: true}) != nil {
		t.Error("unknown step kept")
	}
	many := make([]string, 100)
	for i := range many {
		many[i] = "n1"
	}
	st := cleanSwitchStatus(&armadav1.NetworkSwitchStatus{To: "plain", Step: "move", Ready: true, Unreached: many, Error: "no\x1b[2Jkernel"})
	if len(st.Unreached) != maxSwitchUnreached || st.Ready || strings.ContainsRune(st.Error, 0x1b) {
		t.Errorf("status %v", st)
	}
}

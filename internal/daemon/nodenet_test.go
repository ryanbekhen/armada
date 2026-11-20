package daemon

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/store"
)

type fakeSwitcher struct{ applied int }

func (f *fakeSwitcher) Apply(context.Context, *armadav1.NetworkConfig, map[netip.Addr]string) error {
	f.applied++
	return nil
}

func (*fakeSwitcher) SwitchStatus() *armadav1.NetworkSwitchStatus { return nil }

// A switch of the cluster network's mode (ADR 0050) ends in agent.json once
// it is done, not while it runs.
func TestNodeNetRecordsSwitchedMode(t *testing.T) {
	dir := t.TempDir()
	if err := saveAgentConfig(dir, agentConfig{NodeID: "n1", PrivateIP: "10.0.0.1", Servers: []string{"10.0.0.1:7443"}, Runtime: runtimeEmbedded, Network: store.NetworkPlain}); err != nil {
		t.Fatal(err)
	}
	n := &nodeNet{NetworkSwitcher: &fakeSwitcher{}, dataDir: dir, mode: store.NetworkPlain, log: slog.New(slog.DiscardHandler)}
	mode := func() string {
		t.Helper()
		ac, err := loadAgentConfig(dir)
		if err != nil {
			t.Fatal(err)
		}
		return ac.Network
	}
	for _, step := range []string{"prepare", "move"} {
		if err := n.Apply(context.Background(), &armadav1.NetworkConfig{Mode: store.NetworkPlain, SwitchTo: store.NetworkWireGuard, SwitchStep: step}, nil); err != nil {
			t.Fatal(err)
		}
		if got := mode(); got != store.NetworkPlain {
			t.Fatalf("during %s: agent.json says %q", step, got)
		}
	}
	if err := n.Apply(context.Background(), &armadav1.NetworkConfig{Mode: store.NetworkWireGuard}, nil); err != nil {
		t.Fatal(err)
	}
	if got := mode(); got != store.NetworkWireGuard {
		t.Fatalf("after the switch: agent.json says %q", got)
	}
	// Nothing else in agent.json changes.
	if ac, _ := loadAgentConfig(dir); ac.NodeID != "n1" || ac.PrivateIP != "10.0.0.1" {
		t.Errorf("agent.json = %+v", ac)
	}
}

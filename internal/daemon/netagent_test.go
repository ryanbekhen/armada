package daemon

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/ryanbekhen/armada/internal/clusternet"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

// Every node runs the cluster network through the runtime pack's
// armada-node (ADR 0054), while the pack has it, unless agent.json netAgent
// is "go".
func TestNetAgentDefault(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.DiscardHandler)
	if (agentConfig{NetAgent: netAgentGo}).netProgram(dir) != nil {
		t.Error(`netAgent "go" runs armada-node`)
	}
	ac := &agentConfig{NodeID: "a", PrivateIP: "10.0.0.1", Network: "plain"}
	for _, v := range []string{"", "rust", "Go", "anything"} {
		ac.NetAgent = v
		cfg, err := meshConfig(dir, ac, clusternet.PrivateKey{}, log)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Program == nil {
			t.Fatalf("netAgent %q keeps Go's code", v)
		}
		if cfg.Program() != "" {
			t.Fatal("armada-node found in an empty runtime pack")
		}
	}
	bin := filepath.Join(runtimePaths(dir).Bin(), embedded.BinNode)
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ac.NetAgent = ""
	cfg, _ := meshConfig(dir, ac, clusternet.PrivateKey{}, log)
	if got := cfg.Program(); got != bin {
		t.Fatalf("program %q, want %q", got, bin)
	}
	ac.NetAgent = netAgentGo
	if cfg, _ := meshConfig(dir, ac, clusternet.PrivateKey{}, log); cfg.Program != nil {
		t.Error(`a node with netAgent "go" runs armada-node`)
	}
}

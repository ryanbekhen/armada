package daemon

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/ryanbekhen/armada/internal/clusternet"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

// Only agent.json netAgent "rust" runs the cluster network through the
// runtime pack's armada-node (ADR 0054), and only while the pack has it.
func TestNetAgentOptIn(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.DiscardHandler)
	for _, v := range []string{"", "go", "Rust", "rust "} {
		if (agentConfig{NetAgent: v}).netProgram(dir) != nil {
			t.Errorf("netAgent %q runs armada-node", v)
		}
	}
	ac := &agentConfig{NodeID: "a", PrivateIP: "10.0.0.1", Network: "plain", NetAgent: netAgentRust}
	cfg, err := meshConfig(dir, ac, clusternet.PrivateKey{}, log)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Program == nil || cfg.Program() != "" {
		t.Fatal("armada-node found in an empty runtime pack")
	}
	bin := filepath.Join(runtimePaths(dir).Bin(), embedded.BinNode)
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Program(); got != bin {
		t.Fatalf("program %q, want %q", got, bin)
	}
	ac.NetAgent = ""
	if cfg, _ := meshConfig(dir, ac, clusternet.PrivateKey{}, log); cfg.Program != nil {
		t.Error("a node that did not opt in runs armada-node")
	}
}

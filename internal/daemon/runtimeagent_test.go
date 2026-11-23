package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

// The supervisor runtime goes through armada-node only on a supervisor
// node whose agent.json says "runtimeAgent": "rust", and only while the
// runtime pack has it (ADR 0054 step 4).
func TestRuntimeAgent(t *testing.T) {
	dir := t.TempDir()
	rust := agentConfig{Runtime: runtimeSupervisor, RuntimeAgent: runtimeAgentRust}
	if got := rust.runtimeProgram(dir); got != "" {
		t.Errorf("armada-node %q found in an empty runtime pack", got)
	}
	bin := filepath.Join(runtimePaths(dir).Bin(), embedded.BinNode)
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := rust.runtimeProgram(dir); got != bin {
		t.Errorf("program %q, want %q", got, bin)
	}
	for _, ac := range []agentConfig{
		{Runtime: runtimeSupervisor},
		{Runtime: runtimeSupervisor, RuntimeAgent: "go"},
		{Runtime: runtimeSupervisor, RuntimeAgent: "Rust"},
		{Runtime: runtimeEmbedded, RuntimeAgent: runtimeAgentRust},
		{RuntimeAgent: runtimeAgentRust},
	} {
		if got := ac.runtimeProgram(dir); got != "" {
			t.Errorf("%+v runs containers through %q", ac, got)
		}
	}
}

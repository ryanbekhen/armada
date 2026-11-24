package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
)

// The supervisor runtime goes through armada-node by default, while the
// runtime pack has it (ADR 0054 step 4); "runtimeAgent": "go" keeps Go's
// code, and containerd nodes never use it.
func TestRuntimeAgent(t *testing.T) {
	dir := t.TempDir()
	def := agentConfig{Runtime: runtimeSupervisor}
	if got := def.runtimeProgram(dir); got != "" {
		t.Errorf("armada-node %q found in an empty runtime pack", got)
	}
	bin := filepath.Join(runtimePaths(dir).Bin(), embedded.BinNode)
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, ac := range []agentConfig{
		def,
		{Runtime: runtimeSupervisor, RuntimeAgent: "rust"},
		{Runtime: runtimeSupervisor, RuntimeAgent: "Go"},
	} {
		if got := ac.runtimeProgram(dir); got != bin {
			t.Errorf("%+v: program %q, want %q", ac, got, bin)
		}
	}
	for _, ac := range []agentConfig{
		{Runtime: runtimeSupervisor, RuntimeAgent: runtimeAgentGo},
		{Runtime: runtimeEmbedded},
		{Runtime: runtimeEmbedded, RuntimeAgent: "rust"},
		{},
	} {
		if got := ac.runtimeProgram(dir); got != "" {
			t.Errorf("%+v runs containers through %q", ac, got)
		}
	}
}

// reportingDriver is a runtime that says how it runs containers.
type reportingDriver struct {
	*fake.Driver
	st runtime.AgentStatus
}

func (d reportingDriver) RuntimeAgent() runtime.AgentStatus { return d.st }

// Doctor's runtime-agent check: ok on armada-node, a warning on Go's code
// (saying how to move), on containerd, on a conversion not done or
// failed, and while images left out are not pulled again.
func TestDoctorRuntimeAgent(t *testing.T) {
	cases := []struct {
		name, agentJSON string
		st              runtime.AgentStatus
		want            []string // status: detail fragment
	}{
		{"rust", "", runtime.AgentStatus{Agent: runtime.AgentSupervisorRust, Converted: true}, []string{"ok:armada-node runs containers"}},
		{"rust old containers", "", runtime.AgentStatus{Agent: runtime.AgentSupervisorRust, Converted: true, GoImages: true}, []string{"ok:last container made from it"}},
		{"skipped", "", runtime.AgentStatus{Agent: runtime.AgentSupervisorRust, Converted: true, ImagesToPull: 2}, []string{"ok:armada-node runs", "warn:2 images were left out"}},
		{"not converted", "", runtime.AgentStatus{Agent: runtime.AgentSupervisorRust, GoImages: true}, []string{"warn:not converted yet"}},
		{"failed", "", runtime.AgentStatus{Agent: runtime.AgentSupervisorRust, GoImages: true, Error: "disk full"}, []string{"warn:failed (disk full)"}},
		{"go opt-out", runtimeAgentGo, runtime.AgentStatus{Agent: runtime.AgentSupervisorGo}, []string{"warn:remove the field"}},
		{"go no pack", "", runtime.AgentStatus{Agent: runtime.AgentSupervisorGo}, []string{"warn:runtime pack has no armada-node"}},
		{"containerd", "", runtime.AgentStatus{Agent: runtime.AgentContainerd}, []string{"warn:runtime migrate --to supervisor"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := doctorEnv{euid: 0, driver: reportingDriver{fake.New(), c.st}, runtime: runtimeSupervisor, runtimeAgent: c.agentJSON}
			var got []checkResult
			for _, r := range checkRuntime(context.Background(), env) {
				if r.Name == "runtime-agent" {
					got = append(got, r)
				}
			}
			if len(got) != len(c.want) {
				t.Fatalf("checks %+v, want %v", got, c.want)
			}
			for i, w := range c.want {
				status, detail, _ := strings.Cut(w, ":")
				if got[i].Status != status || !strings.Contains(got[i].Detail, detail) {
					t.Errorf("check %d: %s %q, want %s ... %q", i, got[i].Status, got[i].Detail, status, detail)
				}
			}
		})
	}
	// A runtime that does not say: no check.
	for _, r := range checkRuntime(context.Background(), doctorEnv{driver: fake.New(), runtime: runtimeSupervisor}) {
		if r.Name == "runtime-agent" {
			t.Errorf("a check without a report: %+v", r)
		}
	}
}

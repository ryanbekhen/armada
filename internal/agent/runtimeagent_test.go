package agent

import (
	"testing"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// What the runtime says about itself becomes the report's RuntimeStatus:
// converting while anything of Go's runtime is left on an armada-node
// node, and nothing from a runtime that says nothing (ADR 0054).
func TestRuntimeStatus(t *testing.T) {
	if runtimeStatus(runtime.AgentStatus{}) != nil {
		t.Error("a report from a runtime that says nothing")
	}
	cases := []struct {
		in         runtime.AgentStatus
		converting bool
	}{
		{runtime.AgentStatus{Agent: runtime.AgentSupervisorRust, Converted: true}, false},
		{runtime.AgentStatus{Agent: runtime.AgentSupervisorRust, Converted: true, GoImages: true}, true},
		{runtime.AgentStatus{Agent: runtime.AgentSupervisorRust}, true},
		{runtime.AgentStatus{Agent: runtime.AgentSupervisorRust, Converted: true, Error: "x"}, true},
		{runtime.AgentStatus{Agent: runtime.AgentSupervisorGo, GoImages: true}, false},
		{runtime.AgentStatus{Agent: runtime.AgentContainerd}, false},
	}
	for _, c := range cases {
		got := runtimeStatus(c.in)
		if got.GetAgent() != c.in.Agent || got.GetConverting() != c.converting || got.GetError() != c.in.Error {
			t.Errorf("%+v: %v", c.in, got)
		}
	}
	if got := runtimeStatus(runtime.AgentStatus{Agent: runtime.AgentSupervisorRust, Converted: true, ImagesToPull: 1 << 40}); got.GetImagesToPull() != 1<<20 {
		t.Errorf("images to pull %d", got.GetImagesToPull())
	}
}

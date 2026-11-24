package server

import (
	"fmt"
	"strings"
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/store"
)

// Each agent reports how its node runs containers; ClusterStatus counts
// the nodes on armada-node and names the others, and the node's status
// carries its own (ADR 0054). A node with no report is named too.
func TestRuntimeProgress(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	c.addNode("n1", "127.0.0.1").SetRuntimeAgent(runtime.AgentStatus{Agent: runtime.AgentSupervisorRust, Converted: true})
	c.addNode("n2", "127.0.0.2").SetRuntimeAgent(runtime.AgentStatus{Agent: runtime.AgentSupervisorRust, Converted: true, GoImages: true, ImagesToPull: 3})
	c.addNode("n3", "127.0.0.3").SetRuntimeAgent(runtime.AgentStatus{Agent: runtime.AgentContainerd})
	c.addNode("n4", "127.0.0.4") // an agent that says nothing

	cluster := func() *armadav1.RuntimeProgress {
		t.Helper()
		resp, err := c.admin.ClusterStatus(c.ctx, &armadav1.ClusterStatusRequest{})
		if err != nil {
			t.Fatal(err)
		}
		return resp.GetRuntime()
	}
	c.eventually("reports", func() bool {
		p := cluster()
		return p.GetMoved() == 1 && len(p.GetOthers()) == 3 && p.GetOthers()[0].GetStatus() != nil && p.GetOthers()[1].GetStatus() != nil
	})
	p := cluster()
	if p.GetNodes() != 4 || p.GetOthersTotal() != 3 {
		t.Fatalf("progress %v", p)
	}
	n2, n3, n4 := p.GetOthers()[0], p.GetOthers()[1], p.GetOthers()[2]
	if n2.GetNode() != "n2" || !n2.GetStatus().GetConverting() || n2.GetStatus().GetImagesToPull() != 3 || n2.GetStatus().GetAgent() != runtime.AgentSupervisorRust {
		t.Errorf("n2 %v", n2)
	}
	if n3.GetNode() != "n3" || n3.GetStatus().GetAgent() != runtime.AgentContainerd || n3.GetStatus().GetConverting() {
		t.Errorf("n3 %v", n3)
	}
	if n4.GetNode() != "n4" || n4.GetStatus() != nil {
		t.Errorf("n4 %v", n4)
	}

	st, err := c.admin.Status(c.ctx, &armadav1.StatusRequest{NodesOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range st.GetNodes() {
		want := map[string]string{"n1": runtime.AgentSupervisorRust, "n2": runtime.AgentSupervisorRust, "n3": runtime.AgentContainerd}[n.GetId()]
		if n.GetRuntime().GetAgent() != want {
			t.Errorf("node %s runtime %v, want %q", n.GetId(), n.GetRuntime(), want)
		}
	}

	// n2's old containers went and its images were pulled again.
	c.nodes["n2"].d.SetRuntimeAgent(runtime.AgentStatus{Agent: runtime.AgentSupervisorRust, Converted: true})
	c.eventually("n2 moved", func() bool { return cluster().GetMoved() == 2 })

	// A node that disconnects has no status.
	c.stopAgent("n1")
	c.forgetUsage("n1")
	if p := cluster(); p.GetMoved() != 1 {
		t.Errorf("a disconnected node counted: %v", p)
	}
}

// forgetUsage drops what the leader keeps of a node's reports, as a
// disconnect does once the session ends.
func (c *cluster) forgetUsage(id string) {
	c.t.Helper()
	c.eventually("usage of "+id+" forgotten", func() bool {
		_, ok := c.srv.usage.node(id, c.srv.now())
		return !ok
	})
}

// What a node reports is bounded: an unknown runtime is dropped, an error
// marks it converting and loses its control characters, and a count is
// kept within bounds.
func TestCleanRuntimeStatus(t *testing.T) {
	t.Parallel()
	if got := cleanRuntimeStatus(&armadav1.RuntimeStatus{Agent: "docker"}); got != nil {
		t.Errorf("unknown runtime kept: %v", got)
	}
	if got := cleanRuntimeStatus(nil); got != nil {
		t.Errorf("nil: %v", got)
	}
	got := cleanRuntimeStatus(&armadav1.RuntimeStatus{Agent: runtime.AgentSupervisorRust, ImagesToPull: -4, Error: "bad\x1b[31m" + strings.Repeat("x", 2000)})
	if !got.GetConverting() || got.GetImagesToPull() != 0 || strings.ContainsRune(got.GetError(), 0x1b) || len(got.GetError()) > maxEventMessage {
		t.Errorf("cleaned %v", got)
	}
	got = cleanRuntimeStatus(&armadav1.RuntimeStatus{Agent: runtime.AgentContainerd, Converting: true, ImagesToPull: 9, Error: "x"})
	if got.GetConverting() || got.GetImagesToPull() != 0 || got.GetError() != "" {
		t.Errorf("containerd carries the move's fields: %v", got)
	}
	if got := cleanRuntimeStatus(&armadav1.RuntimeStatus{Agent: runtime.AgentSupervisorRust, ImagesToPull: 1 << 30}); got.GetImagesToPull() != maxImagesToPull {
		t.Errorf("bound %v", got)
	}
}

// ClusterStatus names at most maxRuntimeOthers nodes, sorted.
func TestRuntimeProgressBounded(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	var nodes []store.Node
	for i := range maxRuntimeOthers + 5 {
		nodes = append(nodes, store.Node{ID: fmt.Sprintf("n%02d", 40-i)})
	}
	p := c.srv.runtimeProgress(nodes, c.srv.now())
	if p.GetNodes() != int32(len(nodes)) || p.GetOthersTotal() != int32(len(nodes)) || len(p.GetOthers()) != maxRuntimeOthers || p.GetOthers()[0].GetNode() != "n16" {
		t.Errorf("progress %v", p)
	}
}

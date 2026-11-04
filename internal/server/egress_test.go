package server

import (
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

func (c *clockServer) setEgress(node string, on bool) {
	c.t.Helper()
	if err := c.st.SetNodeStatus(c.ctx, node, store.NodeStatus{State: store.NodeReady, LastSeen: c.clock, Egress: on}); err != nil {
		c.t.Fatal(err)
	}
}

// Replicas of a project with an egress limit run only on nodes that limit
// egress, with the limit in their spec; with none, nothing is placed
// without it, and status and events say why (ADR 0029).
func TestEgressLimitedPlacement(t *testing.T) {
	t.Parallel()
	c := placementSetup(t, nil, nil)
	if _, err := c.st.CreateProject(c.ctx, "net", spec.IsolationContainer, "t", ""); err != nil {
		t.Fatal(err)
	}
	if err := c.st.SetProjectQuota(c.ctx, "net", spec.Quota{EgressBits: 20_000_000}, "t"); err != nil {
		t.Fatal(err)
	}
	rev := c.deployIn("net", "name: web\nimage: nginx:1\nscale:\n  min: 2\n")
	if rev.EgressBits != 20_000_000 {
		t.Fatalf("revision egress = %d", rev.EgressBits)
	}
	for _, r := range c.replicas() {
		if r.App == "web.net" {
			t.Fatalf("replica %s placed on %s, which cannot limit egress", r.ID, r.NodeID)
		}
	}
	nodes, _ := c.st.ListNodes(c.ctx)
	all, _ := c.st.ListReplicas(c.ctx, store.ReplicaFilter{})
	app, err := c.st.GetApp(c.ctx, "web.net")
	if err != nil {
		t.Fatal(err)
	}
	if msg := placementMessage(c.ctx, &revisionCache{store: c.st, m: map[string]store.Revision{}}, nodes, all, app); !strings.Contains(msg, "egress") {
		t.Errorf("placement message = %q", msg)
	}
	if !c.hasEvent("NoIsolation", "web.net") {
		t.Error("no NoIsolation event")
	}

	c.setEgress("n2", true)
	c.advance(time.Second)
	n := 0
	for _, r := range c.replicas() {
		if r.App != "web.net" {
			continue
		}
		n++
		if r.NodeID != "n2" {
			t.Errorf("replica on %s", r.NodeID)
		}
		if rs, err := replicaSpec(r, rev, nil); err != nil || rs.GetEgressBits() != 20_000_000 {
			t.Errorf("replica %s spec egress = %d (%v)", r.ID, rs.GetEgressBits(), err)
		}
	}
	if n != 2 {
		t.Errorf("%d replicas after a node limits egress", n)
	}
	// Apps without a limit still run anywhere.
	def := c.deployIn("default", "name: api\nimage: nginx:1\nscale:\n  min: 2\n")
	for _, r := range c.replicas() {
		if r.App == "api" {
			if rs, _ := replicaSpec(r, def, nil); rs.GetEgressBits() != 0 {
				t.Errorf("default replica %s limited", r.ID)
			}
		}
	}
}

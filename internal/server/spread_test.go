package server

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/store"
)

// spreadSetup returns a server with nodes n1–n3 in region java, n4 in
// region papua, and n5 without a region; nodes in mem get that much
// memory, the others an unknown amount.
func spreadSetup(t *testing.T, mem map[string]int64) *clockServer {
	t.Helper()
	c := newClockServer(t)
	for i, region := range []string{"java", "java", "java", "papua", ""} {
		id := "n" + string(rune('1'+i))
		n := store.Node{ID: id, PrivateIP: "10.0.0." + string(rune('2'+i)), State: store.NodeReady, MemoryBytes: mem[id]}
		if region != "" {
			n.Labels = map[string]string{"region": region}
		}
		if err := c.st.UpsertNode(c.ctx, n); err != nil {
			t.Fatal(err)
		}
		if err := c.st.SetNodeStatus(c.ctx, id, store.NodeStatus{State: store.NodeReady, LastSeen: c.clock, MemoryBytes: mem[id]}); err != nil {
			t.Fatal(err)
		}
		if region != "" {
			if _, err := c.st.SetNodeLabels(c.ctx, id, map[string]string{"region": region}, nil, "t"); err != nil {
				t.Fatal(err)
			}
		}
	}
	return c
}

func spreadSpec(n string) string {
	return "name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\nscale:\n  min: " + n + "\nplacement:\n  spreadBy: region\n"
}

// byRegion counts the live replicas per region, and per node.
func (c *clockServer) byRegion() (map[string]int, map[string]int) {
	c.t.Helper()
	region := map[string]string{"n1": "java", "n2": "java", "n3": "java", "n4": "papua"}
	perRegion, perNode := map[string]int{}, map[string]int{}
	for _, r := range c.replicas() {
		if r.Draining() {
			continue
		}
		perRegion[region[r.NodeID]]++
		perNode[r.NodeID]++
	}
	return perRegion, perNode
}

func (c *clockServer) settle() {
	c.t.Helper()
	for i := 0; i < 40; i++ {
		c.serveAll()
	}
}

func TestSpreadByEvensOutLabelValues(t *testing.T) {
	t.Parallel()
	c := spreadSetup(t, nil)
	c.deploy(spreadSpec("4"))
	c.settle()
	perRegion, perNode := c.byRegion()
	// Two per region although java has three nodes, and nothing on n5,
	// which has no region.
	if perRegion["java"] != 2 || perRegion["papua"] != 2 || perNode["n5"] != 0 {
		t.Fatalf("per region %v, per node %v", perRegion, perNode)
	}
	if perNode["n1"] > 1 || perNode["n2"] > 1 || perNode["n3"] > 1 {
		t.Errorf("java not spread over its nodes: %v", perNode)
	}
	if msg := c.placementNote(); msg != "" {
		t.Errorf("placement note for an even spread: %q", msg)
	}

	// Scaling down keeps the regions even at once, not by moving replicas
	// afterwards.
	if err := c.st.SetReplicas(c.ctx, "web", 2, "t"); err != nil {
		t.Fatal(err)
	}
	c.reconcile()
	if perRegion, _ = c.byRegion(); perRegion["java"] != 1 || perRegion["papua"] != 1 {
		t.Errorf("after scaling to 2: %v", perRegion)
	}
}

// Six replicas: three on papua's one node, one on each java node. The
// per-node and per-region rules must not undo each other.
func TestSpreadByIsStable(t *testing.T) {
	t.Parallel()
	c := spreadSetup(t, nil)
	c.deploy(spreadSpec("6"))
	c.settle()
	before := c.replicas()
	c.settle()
	perRegion, perNode := c.byRegion()
	if perRegion["java"] != 3 || perRegion["papua"] != 3 || perNode["n4"] != 3 {
		t.Fatalf("per region %v, per node %v", perRegion, perNode)
	}
	ids := func(rs map[string]store.Replica) []string {
		return slices.Sorted(maps.Keys(rs))
	}
	if !slices.Equal(ids(before), ids(c.replicas())) {
		t.Error("replicas kept moving once spread evenly")
	}

	// Down to four: two per region at once. By node load alone, both would
	// come off papua's node, which runs three.
	if err := c.st.SetReplicas(c.ctx, "web", 4, "t"); err != nil {
		t.Fatal(err)
	}
	c.reconcile()
	if perRegion, _ = c.byRegion(); perRegion["java"] != 2 || perRegion["papua"] != 2 {
		t.Errorf("after scaling to 4: %v", perRegion)
	}
}

// The spread yields to capacity: with no room in papua the replicas go to
// java, status says why, and they spread back once papua has room.
func TestSpreadByYieldsToCapacity(t *testing.T) {
	t.Parallel()
	// papua's node keeps 128Mi for Armada and fits one 256Mi replica.
	c := spreadSetup(t, map[string]int64{"n4": 500 << 20})
	c.deploy(spreadSpec("4"))
	c.settle()
	perRegion, _ := c.byRegion()
	if perRegion["java"] != 3 || perRegion["papua"] != 1 {
		t.Fatalf("per region %v, want java 3 and papua 1", perRegion)
	}
	if msg := c.placementNote(); !strings.Contains(msg, "replicas spread unevenly over region (java=3, papua=1): no node with region=papua has") {
		t.Errorf("placement note = %q", msg)
	}

	if err := c.st.SetNodeStatus(c.ctx, "n4", store.NodeStatus{State: store.NodeReady, LastSeen: c.clock, MemoryBytes: 4 << 30}); err != nil {
		t.Fatal(err)
	}
	c.advance(rebalanceBackoff)
	c.settle()
	if perRegion, _ = c.byRegion(); perRegion["java"] != 2 || perRegion["papua"] != 2 {
		t.Errorf("after papua has room: %v", perRegion)
	}
	if msg := c.placementNote(); msg != "" {
		t.Errorf("placement note after the rebalance: %q", msg)
	}
}

// Without a node that has the label, nothing runs and status says which
// label is missing.
func TestSpreadByNeedsTheLabel(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	c.deploy(strings.Replace(spreadSpec("2"), "region", "rack", 1))
	if n := len(c.replicas()); n != 0 {
		t.Errorf("%d replicas on nodes without a rack label", n)
	}
	if msg := c.placementNote(); !strings.Contains(msg, "no ready node matches the placement (rack=*)") {
		t.Errorf("placement note = %q", msg)
	}
}

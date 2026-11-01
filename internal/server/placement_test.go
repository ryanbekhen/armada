package server

import (
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/store"
)

// placementSetup returns a server with n1 (10.0.0.2) and n2 (10.0.0.3),
// labelled as given.
func placementSetup(t *testing.T, n1, n2 map[string]string) *clockServer {
	t.Helper()
	c := newClockServer(t)
	if err := c.st.UpsertNode(c.ctx, store.Node{ID: "n2", PrivateIP: "10.0.0.3", State: store.NodeReady}); err != nil {
		t.Fatal(err)
	}
	for id, labels := range map[string]map[string]string{"n1": n1, "n2": n2} {
		if len(labels) == 0 {
			continue
		}
		if _, err := c.st.SetNodeLabels(c.ctx, id, labels, nil, "t"); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func (c *clockServer) deploy(spec string) {
	c.t.Helper()
	if _, _, err := c.st.Deploy(c.ctx, mustSpec(c.t, spec), "t"); err != nil {
		c.t.Fatal(err)
	}
	c.reconcile()
}

// serveAll reports every live replica ready and lets the warm-up pass.
func (c *clockServer) serveAll() {
	c.t.Helper()
	for _, r := range c.replicas() {
		if !r.Draining() && !r.Ready {
			c.readyOn(r)
		}
	}
	c.advance(10 * time.Second)
}

func (c *clockServer) placementNote() string {
	c.t.Helper()
	nodes, _ := c.st.ListNodes(c.ctx)
	all, _ := c.st.ListReplicas(c.ctx, store.ReplicaFilter{})
	revs := &revisionCache{store: c.st, m: map[string]store.Revision{}}
	return placementMessage(c.ctx, revs, nodes, all, c.app())
}

const placedSpec = "name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\nscale:\n  min: 2\n"

func TestPlacementRequireKeepsReplicasOnMatchingNodes(t *testing.T) {
	t.Parallel()
	c := placementSetup(t, map[string]string{"region": "java"}, map[string]string{"region": "sulawesi"})
	c.deploy(placedSpec + "placement:\n  require:\n    region: sulawesi\n")
	c.serveAll()
	byNode, _ := c.split()
	if len(byNode["n1"]) != 0 || len(byNode["n2"]) != 2 {
		t.Fatalf("replicas by node = %v, want both on n2", byNode)
	}
	if msg := c.placementNote(); msg != "" {
		t.Errorf("placement note with room: %q", msg)
	}

	// No node in papua: the new revision is not placed anywhere else, the
	// old replicas keep serving, and status explains why.
	c.deploy(placedSpec + "placement:\n  require:\n    region: papua\n")
	c.advance(time.Second)
	byNode, _ = c.split()
	if len(byNode["n1"]) != 0 || len(byNode["n2"]) != 2 {
		t.Fatalf("replicas by node = %v after an unplaceable rollout", byNode)
	}
	for _, r := range byNode["n2"] {
		if r.Revision != c.app().ActiveRevision {
			t.Errorf("replica %s of %s placed despite no matching node", r.ID, r.Revision)
		}
	}
	if msg := c.placementNote(); !strings.Contains(msg, "no ready node matches the placement (region=papua)") {
		t.Errorf("placement note = %q", msg)
	}
}

func TestRestrictedNodeOnlyTakesAppsThatSelectIt(t *testing.T) {
	t.Parallel()
	c := placementSetup(t, nil, map[string]string{"kind": "gpu"})
	if err := c.st.SetNodeRestricted(c.ctx, "n2", true, "t"); err != nil {
		t.Fatal(err)
	}
	c.deploy(placedSpec)
	c.serveAll()
	if byNode, _ := c.split(); len(byNode["n2"]) != 0 {
		t.Fatalf("app without placement on a restricted node: %v", byNode)
	}
	c.deploy("name: ml\nimage: nginx:1\nscale:\n  min: 1\nplacement:\n  require:\n    kind: gpu\n")
	for _, r := range c.replicas() {
		if r.App == "ml" && r.NodeID != "n2" {
			t.Errorf("ml replica on %s, want n2", r.NodeID)
		}
	}
}

func TestRestrictingANodeMovesOtherAppsAway(t *testing.T) {
	t.Parallel()
	c := placementSetup(t, nil, map[string]string{"kind": "gpu"})
	c.deploy(placedSpec)
	c.serveAll()
	if byNode, _ := c.split(); len(byNode["n1"]) != 1 || len(byNode["n2"]) != 1 {
		t.Fatalf("not spread before restricting: %v", byNode)
	}
	if err := c.st.SetNodeRestricted(c.ctx, "n2", true, "t"); err != nil {
		t.Fatal(err)
	}
	// Replace first: the replica on n2 keeps serving until its replacement
	// on n1 has served through the warm-up.
	c.advance(time.Millisecond)
	byNode, _ := c.split()
	if len(byNode["n1"]) != 2 || len(byNode["n2"]) != 1 {
		t.Fatalf("replacement not scheduled first: %v", byNode)
	}
	c.serveAll()
	c.advance(time.Millisecond)
	if byNode, _ = c.split(); len(byNode["n1"]) != 2 || len(byNode["n2"]) != 0 {
		t.Fatalf("after the move: %v", byNode)
	}
}

func TestLostNodeReplacedOnlyOnEligibleNodes(t *testing.T) {
	t.Parallel()
	c := placementSetup(t, map[string]string{"region": "sulawesi"}, map[string]string{"region": "sulawesi"})
	if err := c.st.UpsertNode(c.ctx, store.Node{ID: "n3", PrivateIP: "10.0.0.4", State: store.NodeReady,
		Labels: map[string]string{"region": "java"}}); err != nil {
		t.Fatal(err)
	}
	c.deploy(placedSpec + "placement:\n  require:\n    region: sulawesi\n")
	c.serveAll()
	if err := c.st.SetNodeStatus(c.ctx, "n2", store.NodeStatus{State: store.NodeUnknown, LastSeen: c.clock}); err != nil {
		t.Fatal(err)
	}
	c.advance(DefaultNodeLostTimeout + time.Second)
	for _, r := range c.replicas() {
		if r.NodeID == "n3" {
			t.Fatalf("replica %s moved to n3, outside the placement", r.ID)
		}
	}
	if byNode, _ := c.split(); len(byNode["n1"]) != 2 {
		t.Errorf("replacement not on n1: %v", byNode)
	}
}

func TestPlacementNoteWhenMatchingNodesAreFull(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	if err := c.st.UpsertNode(c.ctx, store.Node{ID: "n1", PrivateIP: "10.0.0.2", State: store.NodeReady, MemoryBytes: 128 << 20}); err != nil {
		t.Fatal(err)
	}
	c.deploy(placedSpec)
	if msg := c.placementNote(); !strings.Contains(msg, "1 node(s) may run the app, none has 256Mi of memory free") {
		t.Errorf("placement note = %q", msg)
	}
}

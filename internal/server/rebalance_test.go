package server

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/store"
)

func TestRebalanceVictim(t *testing.T) {
	t.Parallel()
	mem := func(store.Replica) resources { return resources{mem: 512 << 20} }
	ready := func(ids ...string) []store.Node {
		var ns []store.Node
		for _, id := range ids {
			ns = append(ns, store.Node{ID: id, State: store.NodeReady})
		}
		return ns
	}
	on := func(nodes ...string) []store.Replica {
		var rs []store.Replica
		for i, n := range nodes {
			rs = append(rs, store.Replica{ID: "web-" + strconv.Itoa(i), App: "web", NodeID: n})
		}
		return rs
	}

	rs := on("a", "a", "b")
	v, to, ok := rebalanceVictim(ready("a", "b", "c"), rs, rs, "", resources{}, mem)
	if !ok || v.NodeID != "a" || to != "c" {
		t.Errorf("2/1/0: moved %+v to %q (%v), want one from a to c", v, to, ok)
	}
	for name, tc := range map[string]struct {
		nodes []store.Node
		rs    []store.Replica
	}{
		"balanced":          {ready("a", "b", "c"), on("a", "b", "c")},
		"off by one":        {ready("a", "b"), on("a", "a", "b")},
		"one node":          {ready("a"), on("a", "a")},
		"no replicas":       {ready("a", "b"), nil},
		"empty node cordon": {append(ready("a", "b"), store.Node{ID: "c", State: store.NodeReady, Cordoned: true}), on("a", "a", "b")},
		"empty node down":   {append(ready("a", "b"), store.Node{ID: "c", State: store.NodeUnknown}), on("a", "a", "b")},
	} {
		if v, to, ok := rebalanceVictim(tc.nodes, tc.rs, tc.rs, "", resources{}, mem); ok {
			t.Errorf("%s: moved %s to %s", name, v.ID, to)
		}
	}
	// The empty node cannot fit the replica: nothing to gain.
	small := []store.Node{{ID: "a", State: store.NodeReady}, {ID: "b", State: store.NodeReady, MemoryBytes: 256 << 20}}
	if v, to, ok := rebalanceVictim(small, on("a", "a"), on("a", "a"), "", resources{mem: 512 << 20}, mem); ok {
		t.Errorf("full node: moved %s to %s", v.ID, to)
	}
	// Other apps on the empty node do not matter: only this app's spread.
	busy := append(on("a", "a"), store.Replica{ID: "db-0", App: "db", NodeID: "b"})
	if _, to, ok := rebalanceVictim(ready("a", "b"), busy, on("a", "a"), "", resources{}, mem); !ok || to != "b" {
		t.Errorf("app spread ignored: to %q, %v", to, ok)
	}
}

// rebalanceSetup runs two serving replicas on n1, then adds an empty n2.
func rebalanceSetup(t *testing.T) *clockServer {
	t.Helper()
	c := newClockServer(t)
	spec := "name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\nscale:\n  min: 2\n  max: 10\n"
	if _, _, err := c.st.Deploy(c.ctx, mustSpec(t, spec), "t"); err != nil {
		t.Fatal(err)
	}
	c.reconcile()
	for _, r := range c.replicas() {
		c.readyOn(r)
	}
	c.advance(10 * time.Second)
	if err := c.st.UpsertNode(c.ctx, store.Node{ID: "n2", PrivateIP: "10.0.0.3", State: store.NodeReady}); err != nil {
		t.Fatal(err)
	}
	return c
}

// readyOn reports r ready from whatever node it runs on.
func (c *clockServer) readyOn(r store.Replica) {
	c.t.Helper()
	ip := map[string]string{"n1": "10.0.0.2", "n2": "10.0.0.3"}[r.NodeID]
	c.port++
	st := store.ReplicaStatus{ID: r.ID, State: store.ReplicaRunning, Address: ip + ":" + strconv.Itoa(32000+c.port), Ready: true}
	if err := c.st.UpdateReplicaStatus(c.ctx, r.NodeID, st); err != nil {
		c.t.Fatal(err)
	}
}

// split returns the replicas that are not draining, by node, and the
// moving ones.
func (c *clockServer) split() (byNode map[string][]store.Replica, moving []store.Replica) {
	byNode = map[string][]store.Replica{}
	for _, r := range c.replicas() {
		if r.Draining() {
			continue
		}
		byNode[r.NodeID] = append(byNode[r.NodeID], r)
		if r.Moving() {
			moving = append(moving, r)
		}
	}
	return byNode, moving
}

func TestRebalanceMovesReplicaToNewNode(t *testing.T) {
	t.Parallel()
	c := rebalanceSetup(t)

	c.advance(time.Second)
	_, moving := c.split()
	if len(moving) != 1 || moving[0].NodeID != "n1" {
		t.Fatalf("moving = %+v", moving)
	}
	c.advance(time.Millisecond)
	byNode, _ := c.split()
	if len(byNode["n2"]) != 1 || len(byNode["n1"]) != 2 {
		t.Fatalf("replacement not scheduled on n2: %+v", byNode)
	}
	// The moving replica keeps serving until its replacement has served
	// through the warm-up.
	c.readyOn(byNode["n2"][0])
	c.advance(3*time.Second - time.Millisecond)
	if byNode, _ = c.split(); len(byNode["n1"]) != 2 {
		t.Fatal("moving replica retired before its replacement warmed up")
	}
	c.advance(time.Millisecond)
	byNode, moving = c.split()
	if len(byNode["n1"]) != 1 || len(byNode["n2"]) != 1 || len(moving) != 0 {
		t.Fatalf("after the move: %+v, moving %+v", byNode, moving)
	}
	// Balanced: nothing else moves.
	c.advance(time.Minute)
	if _, moving = c.split(); len(moving) != 0 {
		t.Errorf("balanced app still moving: %+v", moving)
	}
}

func TestRebalanceGivesUpOnReplacementThatNeverServes(t *testing.T) {
	t.Parallel()
	c := rebalanceSetup(t)
	c.advance(time.Second)
	c.advance(time.Millisecond)
	byNode, moving := c.split()
	if len(moving) != 1 || len(byNode["n2"]) != 1 {
		t.Fatalf("move not started: %+v", byNode)
	}

	// The replacement never becomes ready (progress deadline 1m).
	c.advance(time.Minute - 2*time.Millisecond)
	if _, moving = c.split(); len(moving) != 1 {
		t.Fatal("move abandoned before the deadline")
	}
	c.advance(time.Second)
	byNode, moving = c.split()
	if len(moving) != 0 || len(byNode["n1"]) != 2 || len(byNode["n2"]) != 0 {
		t.Fatalf("after giving up: %+v, moving %+v", byNode, moving)
	}
	for _, r := range byNode["n1"] {
		if r.Draining() {
			t.Errorf("serving replica %s drained", r.ID)
		}
	}
	// The app is left alone for a while instead of trying again at once.
	c.advance(time.Minute)
	if _, moving = c.split(); len(moving) != 0 {
		t.Error("move retried during the backoff")
	}
	c.advance(rebalanceBackoff)
	if _, moving = c.split(); len(moving) != 1 {
		t.Error("move not retried after the backoff")
	}
}

// A rollout spreads the new revision by its own replicas: replicas of the
// old revision, or still draining, do not count, so no move is needed
// afterwards.
func TestRolloutSpreadsNewRevisionEvenly(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	for i, id := range []string{"n2", "n3", "n4"} {
		if err := c.st.UpsertNode(c.ctx, store.Node{ID: id, PrivateIP: fmt.Sprintf("10.0.0.%d", i+3), State: store.NodeReady}); err != nil {
			t.Fatal(err)
		}
	}
	spec := "name: web\nimage: nginx:%d\ningress:\n  type: external\n  port: 80\nscale:\n  min: 4\n"
	for v := 1; v <= 3; v++ {
		c.deploy(fmt.Sprintf(spec, v))
		// Replicas become ready one at a time, as on real nodes, while
		// older ones are still draining.
		for i := 0; i < 200 && c.app().Rolling(); i++ {
			for _, r := range c.replicas() {
				if !r.Draining() && !r.Ready {
					c.readyOn(r)
					break
				}
			}
			c.advance(2 * time.Second)
		}
		if c.app().Rolling() {
			t.Fatalf("v%d: rollout did not finish", v)
		}
		byNode, moving := c.split()
		if len(moving) != 0 {
			t.Fatalf("v%d: replica moved after the rollout: %v", v, moving[0].ID)
		}
		for _, id := range []string{"n1", "n2", "n3", "n4"} {
			if len(byNode[id]) != 1 {
				t.Fatalf("v%d: replicas by node = %v, want one each", v, byNode)
			}
		}
	}
}

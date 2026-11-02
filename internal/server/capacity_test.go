package server

import (
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/store"
)

func TestAllocatableKeepsCapacityForArmada(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	if err := c.st.UpsertServer(c.ctx, store.Server{Name: "cp-1", PrivateIP: "10.0.0.2", APIAddr: "10.0.0.2:7443", MemberID: 1}); err != nil {
		t.Fatal(err)
	}
	got, err := c.srv.allocatable(c.ctx, []store.Node{
		{ID: "server", PrivateIP: "10.0.0.2", CPUMillis: 1000, MemoryBytes: 1 << 30},
		{ID: "node", PrivateIP: "10.0.0.3", CPUMillis: 1000, MemoryBytes: 1 << 30},
		{ID: "tiny", PrivateIP: "10.0.0.4", CPUMillis: 50, MemoryBytes: 64 << 20},
		{ID: "unknown", PrivateIP: "10.0.0.5"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []resources{
		{cpu: 800, mem: 896 << 20}, // the control plane runs here too
		{cpu: 900, mem: 896 << 20},
		{cpu: 1, mem: 1}, // full, not unknown
		{},               // unknown stays unknown
	}
	for i, n := range got {
		if r := (resources{cpu: n.CPUMillis, mem: n.MemoryBytes}); r != want[i] {
			t.Errorf("%s: allocatable %+v, want %+v", n.ID, r, want[i])
		}
	}
}

// A replica reserves its CPU (resources.cpu, or the default 100m) on the
// node, with nothing overcommitted, and status says why the rest waits.
func TestReplicasReserveCPU(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	if err := c.st.SetNodeStatus(c.ctx, "n1", store.NodeStatus{State: store.NodeReady, LastSeen: c.clock, CPUMillis: 1000, MemoryBytes: 8 << 30}); err != nil {
		t.Fatal(err)
	}
	// 900m left for replicas: three of 300m, not four.
	c.deploy("name: web\nimage: nginx:1\nresources:\n  cpu: 300m\nscale:\n  min: 4\n")
	c.serveAll()
	if n := len(c.replicas()); n != 3 {
		t.Fatalf("%d replicas scheduled, want 3", n)
	}
	if msg := c.placementNote(); !strings.Contains(msg, "none has 300m of CPU free") {
		t.Errorf("placement note = %q", msg)
	}
	// Two left: 300m holds three replicas with the default 100m.
	if err := c.st.SetReplicas(c.ctx, "web", 2, "t"); err != nil {
		t.Fatal(err)
	}
	// A draining replica keeps its reservation until it is gone.
	c.reconcile()
	c.advance(15 * time.Second)
	c.deploy("name: api\nimage: nginx:1\nscale:\n  min: 5\n")
	c.serveAll()
	api := 0
	for _, r := range c.replicas() {
		if r.App == "api" {
			api++
		}
	}
	if api != 3 {
		t.Errorf("%d api replicas with the default reservation, want 3", api)
	}
}

// Replicas placed before reservations counted (an upgraded cluster) stay
// where they are even if the node is now over its allocatable capacity;
// only new replicas need room.
func TestReplicasOverCapacityStay(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	c.deploy("name: web\nimage: nginx:1\nscale:\n  min: 4\n")
	c.serveAll()
	if n := len(c.replicas()); n != 4 {
		t.Fatalf("%d replicas before the capacity report", n)
	}
	// The node now reports 300m: 200m left for replicas, half of what the
	// four reserve.
	if err := c.st.SetNodeStatus(c.ctx, "n1", store.NodeStatus{State: store.NodeReady, LastSeen: c.clock, CPUMillis: 300, MemoryBytes: 8 << 30}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		c.serveAll()
	}
	for _, r := range c.replicas() {
		if r.Draining() {
			t.Errorf("replica %s retired for capacity", r.ID)
		}
	}
	if n := len(c.replicas()); n != 4 {
		t.Errorf("%d replicas, want the 4 kept", n)
	}
}

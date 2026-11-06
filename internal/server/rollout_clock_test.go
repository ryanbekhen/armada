package server

import (
	"context"
	"crypto/tls"
	"strconv"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/store/storetest"
)

// clockServer is a Server driven by hand: no agents, a fake clock, and
// replica status written straight to the store.
type clockServer struct {
	t     *testing.T
	ctx   context.Context
	st    *store.Etcd
	srv   *Server
	clock time.Time
	port  int
}

func newClockServer(t *testing.T) *clockServer {
	t.Helper()
	ctx := context.Background()
	st := storetest.Open(t)
	if err := st.UpsertNode(ctx, store.Node{ID: "n1", PrivateIP: "10.0.0.2", State: store.NodeReady}); err != nil {
		t.Fatal(err)
	}
	cs := &clockServer{t: t, ctx: ctx, st: st, clock: time.UnixMilli(1_700_000_000_000)}
	st.SetNow(func() time.Time { return cs.clock })
	var err error
	cs.srv, err = New(Config{
		Store: st, TLS: &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13},
		DrainTimeout: 10 * time.Second, Warmup: 3 * time.Second, ProgressDeadline: time.Minute,
		Now: func() time.Time { return cs.clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func (c *clockServer) reconcile() {
	c.t.Helper()
	if err := c.srv.Reconcile(c.ctx); err != nil {
		c.t.Fatal(err)
	}
}

func (c *clockServer) advance(d time.Duration) {
	c.clock = c.clock.Add(d)
	c.reconcile()
}

func (c *clockServer) replicas() map[string]store.Replica {
	c.t.Helper()
	rs, err := c.st.ListReplicas(c.ctx, store.ReplicaFilter{})
	if err != nil {
		c.t.Fatal(err)
	}
	out := map[string]store.Replica{}
	for _, r := range rs {
		out[r.Revision+"/"+r.ID] = r
	}
	return out
}

// only returns the single replica of revision.
func (c *clockServer) only(revision string) store.Replica {
	c.t.Helper()
	var found []store.Replica
	for _, r := range c.replicas() {
		if r.Revision == revision {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		c.t.Fatalf("revision %s has %d replicas: %+v", revision, len(found), found)
	}
	return found[0]
}

func (c *clockServer) ready(r store.Replica) {
	c.t.Helper()
	c.port++
	addr := "10.0.0.2:" + strconv.Itoa(32000+c.port)
	if err := c.st.UpdateReplicaStatus(c.ctx, "n1", store.ReplicaStatus{ID: r.ID, State: store.ReplicaRunning, Address: addr, Ready: true}); err != nil {
		c.t.Fatal(err)
	}
}

func (c *clockServer) app() store.App {
	c.t.Helper()
	a, err := c.st.GetApp(c.ctx, "web")
	if err != nil {
		c.t.Fatal(err)
	}
	return a
}

func TestRolloutWaitsForWarmupAndDrain(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	if _, _, err := c.st.Deploy(c.ctx, mustSpec(t, "name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\n"), "t"); err != nil {
		t.Fatal(err)
	}
	c.reconcile()
	v1 := c.only("web--r1")
	c.ready(v1)

	if _, _, err := c.st.Deploy(c.ctx, mustSpec(t, "name: web\nimage: nginx:2\ningress:\n  type: external\n  port: 80\n"), "t"); err != nil {
		t.Fatal(err)
	}
	c.advance(10 * time.Second) // v1 has long passed its warm-up
	v2 := c.only("web--r2")
	if c.only("web--r1").Draining() {
		t.Fatal("old replica drained before the new one is ready")
	}

	// v2 becomes ready, but the old replica stays until v2 has served for
	// the warm-up period, so every proxy has it and health-checked it.
	c.ready(v2)
	c.advance(3*time.Second - time.Millisecond)
	if c.only("web--r1").Draining() {
		t.Fatal("old replica drained during the new replica's warm-up")
	}
	if c.app().ActiveRevision != "web--r1" {
		t.Fatal("rollout completed during warm-up")
	}
	c.advance(time.Millisecond)
	if !c.only("web--r1").Draining() {
		t.Fatal("old replica not drained after warm-up")
	}
	if a := c.app(); a.ActiveRevision != "web--r2" || a.Rolling() {
		t.Errorf("rollout not complete once the old replica drains: %+v", a)
	}

	// Draining keeps the replica scheduled (its container finishes
	// in-flight requests) until the drain timeout.
	c.advance(10*time.Second - time.Millisecond)
	if _, ok := c.replicas()["web--r1/"+v1.ID]; !ok {
		t.Fatal("draining replica removed before the drain timeout")
	}
	c.advance(time.Millisecond)
	if _, ok := c.replicas()["web--r1/"+v1.ID]; ok {
		t.Fatal("draining replica kept after the drain timeout")
	}
}

func TestRolloutDeadline(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	if _, _, err := c.st.Deploy(c.ctx, mustSpec(t, "name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\n"), "t"); err != nil {
		t.Fatal(err)
	}
	c.reconcile()
	c.ready(c.only("web--r1"))
	c.advance(time.Minute)

	// The readiness probe may take up to 3 x 10s, which extends the deadline.
	if _, _, err := c.st.Deploy(c.ctx, mustSpec(t, "name: web\nimage: nginx:bad\ningress:\n  type: external\n  port: 80\nprobes:\n  readiness: /ready\n"), "t"); err != nil {
		t.Fatal(err)
	}
	c.reconcile()
	bad := c.only("web--r2")
	if err := c.st.UpdateReplicaStatus(c.ctx, "n1", store.ReplicaStatus{ID: bad.ID, State: store.ReplicaRunning, Message: "readiness probe failed: HTTP 500"}); err != nil {
		t.Fatal(err)
	}
	c.advance(time.Minute + 30*time.Second - time.Millisecond)
	if !c.app().Rolling() {
		t.Fatal("rollout aborted before deadline + probe budget")
	}
	c.advance(time.Millisecond)
	a := c.app()
	if a.Rolling() || a.RolloutState != store.RolloutFailed || a.ActiveRevision != "web--r1" {
		t.Fatalf("rollout not aborted: %+v", a)
	}
	if want := "no progress within 1m30s; " + bad.ID + ": readiness probe failed: HTTP 500"; a.RolloutMessage != want {
		t.Errorf("message = %q, want %q", a.RolloutMessage, want)
	}
	// The never-ready replica goes at once; the old one keeps serving.
	if _, ok := c.replicas()["web--r2/"+bad.ID]; ok {
		t.Error("failed replica kept")
	}
	if r := c.only("web--r1"); r.Draining() {
		t.Error("old replica drained after a failed rollout")
	}
}

func (c *clockServer) fail(r store.Replica) {
	c.t.Helper()
	if err := c.st.UpdateReplicaStatus(c.ctx, r.NodeID, store.ReplicaStatus{ID: r.ID, State: store.ReplicaFailed, Message: "no address"}); err != nil {
		c.t.Fatal(err)
	}
}

// A replica that keeps failing to start moves to another node that fits.
func TestFailedReplicaMoves(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	c.deploy("name: web\nimage: nginx:1\n")
	c.serveAll()
	var failing store.Replica
	for _, r := range c.replicas() {
		failing = r
	}
	// With no other node it stays and keeps retrying.
	c.fail(failing)
	c.reconcile()
	c.advance(2 * failedMoveAfter)
	c.reconcile()
	if _, ok := c.replicas()[failing.Revision+"/"+failing.ID]; !ok {
		t.Fatal("moved with nowhere to go")
	}
	if err := c.st.UpsertNode(c.ctx, store.Node{ID: "n2", PrivateIP: "10.0.0.3", State: store.NodeReady}); err != nil {
		t.Fatal(err)
	}
	c.reconcile()
	rs := c.replicas()
	if _, ok := rs[failing.Revision+"/"+failing.ID]; ok || len(rs) != 1 {
		t.Fatalf("replicas after a node has room: %v", rs)
	}
	for _, r := range rs {
		if r.NodeID != "n2" {
			t.Errorf("replacement on %s, want n2", r.NodeID)
		}
	}
}

// A replica failing only briefly, or as part of a rollout, stays.
func TestFailedReplicaWaits(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	if err := c.st.UpsertNode(c.ctx, store.Node{ID: "n2", PrivateIP: "10.0.0.3", State: store.NodeReady}); err != nil {
		t.Fatal(err)
	}
	c.deploy("name: web\nimage: nginx:1\n")
	c.serveAll()
	var r store.Replica
	for _, x := range c.replicas() {
		r = x
	}
	c.fail(r)
	c.reconcile()
	c.advance(failedMoveAfter / 2)
	c.reconcile()
	if _, ok := c.replicas()[r.Revision+"/"+r.ID]; !ok {
		t.Error("moved before failedMoveAfter")
	}
	// It started after all: the clock starts over.
	c.readyOn(r)
	c.reconcile()
	c.advance(2 * failedMoveAfter)
	c.fail(r)
	c.reconcile()
	if _, ok := c.replicas()[r.Revision+"/"+r.ID]; !ok {
		t.Error("moved although it had recovered in between")
	}
}

// A leaving replica keeps its requests for its revision's drain, not the default.
func TestDrainFromSpec(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	c.deploy("name: web\nimage: nginx:1\ndrain: 1m\ningress:\n  type: external\n  port: 80\nscale:\n  min: 2\n")
	c.serveAll()
	if err := c.st.SetReplicas(c.ctx, "web", 1, "admin:test"); err != nil {
		t.Fatal(err)
	}
	c.reconcile()
	c.advance(30 * time.Second)
	c.reconcile()
	if n := len(c.replicas()); n != 2 {
		t.Fatalf("%d replicas after 30s, want 2: the leaving one still drains", n)
	}
	c.advance(31 * time.Second)
	c.reconcile()
	if n := len(c.replicas()); n != 1 {
		t.Errorf("%d replicas after the drain, want 1", n)
	}
}

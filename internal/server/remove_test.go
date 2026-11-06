package server

import (
	"errors"
	"strings"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/store"
)

// A serving replica drains before it goes, then the app goes with it.
func TestRemoveAppDrainsFirst(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	c.deploy("name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\nscale:\n  min: 2\n")
	c.serveAll()
	if len(c.replicas()) != 2 {
		t.Fatalf("%d replicas", len(c.replicas()))
	}
	if err := c.st.MarkAppRemoving(c.ctx, "web", "admin:test"); err != nil {
		t.Fatal(err)
	}
	c.reconcile()
	for _, r := range c.replicas() {
		if !r.Draining() {
			t.Errorf("replica %s not draining", r.ID)
		}
	}
	if len(c.replicas()) != 2 {
		t.Error("replicas gone before their drain ended, or a new one started")
	}
	if msg := c.placementNote(); !strings.Contains(msg, "being removed") {
		t.Errorf("placement note = %q", msg)
	}
	// A deploy has to wait until the app is gone.
	if _, _, err := c.st.Deploy(c.ctx, c.app().Spec, "admin:test"); !errors.Is(err, store.ErrPrecondition) {
		t.Errorf("deploy while removing: %v", err)
	}
	c.advance(time.Minute)
	c.reconcile()
	if _, err := c.st.GetApp(c.ctx, "web"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("app after its drain: %v", err)
	}
	if len(c.replicas()) != 0 {
		t.Errorf("replicas left: %v", c.replicas())
	}
	// The name is free again.
	c.deploy("name: web\nimage: nginx:2\n")
	if a := c.app(); a.Removing || a.Spec.Image != "nginx:2" {
		t.Errorf("redeployed app: %+v", a)
	}
}

// The real path: the RPC, the agent removing the container, jobs refused.
func TestRemoveAppRPC(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	d := c.addNode("n1", "10.0.0.11")
	c.deploy("name: web\nimage: nginx:1\n")
	c.eventually("container started", func() bool { return containerCount(d) == 1 })
	if _, err := c.admin.RemoveApp(c.ctx, &armadav1.RemoveAppRequest{App: "ghost"}); err == nil {
		t.Error("removed an unknown app")
	}
	if _, err := c.admin.RemoveApp(c.ctx, &armadav1.RemoveAppRequest{App: "web"}); err != nil {
		t.Fatal(err)
	}
	c.eventually("container removed", func() bool { return containerCount(d) == 0 })
	c.deploy("kind: job\nname: migrate\nimage: busybox:1\n")
	if _, err := c.admin.RemoveApp(c.ctx, &armadav1.RemoveAppRequest{App: "migrate"}); err == nil {
		t.Error("removed a job as an app")
	}
}

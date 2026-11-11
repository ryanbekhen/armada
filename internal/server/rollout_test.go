package server

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/proxy"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
	"github.com/ryanbekhen/armada/internal/store"
)

func (c *cluster) app(name string) *armadav1.AppStatus {
	c.t.Helper()
	resp, err := c.admin.Status(c.ctx, &armadav1.StatusRequest{App: name})
	if err != nil {
		c.t.Fatal(err)
	}
	return resp.Apps[0]
}

func backendServers(cfg proxy.Config, app string) []string {
	for _, b := range cfg.Backends {
		if b.Name == app {
			var names []string
			for _, s := range b.Servers {
				names = append(names, s.Name)
			}
			return names
		}
	}
	return nil
}

func containerCount(ds ...*fake.Driver) int {
	n := 0
	for _, d := range ds {
		cs, _ := d.List(context.Background(), nil)
		n += len(cs)
	}
	return n
}

func TestRollingUpdateKeepsCapacity(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	d1 := c.addNode("n1", "127.0.0.1")
	d2 := c.addNode("n2", "127.0.0.2")

	c.deploy(webSpec("nginx:1", 2))
	c.eventually("v1 in proxy", func() bool {
		_, cfg := c.proxies["n1"].Applied()
		return len(backendServers(cfg, "web")) == 2
	})
	start := len(c.proxies["n1"].History())

	// Sample scheduled replicas while the rollout runs: at most one above
	// the desired count, not counting replicas that are draining (they
	// already left the proxies and only finish in-flight requests).
	var maxReplicas atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			rs, _ := c.store.ListReplicas(c.ctx, store.ReplicaFilter{App: "web"})
			n := int64(0)
			for _, r := range rs {
				if !r.Draining() {
					n++
				}
			}
			if n > maxReplicas.Load() {
				maxReplicas.Store(n)
			}
			time.Sleep(2 * time.Millisecond)
		}
	})

	if resp := c.deploy(webSpec("nginx:2", 2)); resp.Revision != "web--r2" {
		t.Fatalf("deploy = %v", resp)
	}
	// v1 keeps serving while v2 rolls out.
	if a := c.app("web"); a.ActiveRevision != "web--r1" || a.TargetRevision != "web--r2" || a.RolloutState != store.RolloutProgressing {
		t.Errorf("status right after deploy = %v", a)
	}
	c.eventually("rollout complete", func() bool {
		a := c.app("web")
		return a.ActiveRevision == "web--r2" && a.RolloutState == "" && containerCount(d1, d2) == 2
	})
	close(stop)
	wg.Wait()
	if n := maxReplicas.Load(); n > 3 {
		t.Errorf("up to %d replicas in service during the rollout, want at most desired+surge = 3", n)
	}

	// Every proxy config applied during the rollout kept two servers.
	history := c.proxies["n1"].History()[start:]
	if len(history) == 0 {
		t.Fatal("no proxy update during the rollout")
	}
	for i, cfg := range history {
		if n := len(backendServers(cfg, "web")); n < 2 {
			t.Errorf("proxy config %d had %d servers: %v", i, n, backendServers(cfg, "web"))
		}
	}
	for _, name := range backendServers(history[len(history)-1], "web") {
		if !strings.HasPrefix(name, "web-r2-") {
			t.Errorf("old replica %s still in the proxy", name)
		}
	}
}

func TestDrainKeepsOldReplicaRunning(t *testing.T) {
	t.Parallel()
	c := newCluster(t, func(cfg *Config) { cfg.DrainTimeout = 600 * time.Millisecond })
	d1 := c.addNode("n1", "127.0.0.1")

	c.deploy(webSpec("nginx:1", 1))
	c.eventually("v1 serving", func() bool {
		_, cfg := c.proxies["n1"].Applied()
		return len(backendServers(cfg, "web")) == 1
	})
	_, cfg := c.proxies["n1"].Applied()
	old := backendServers(cfg, "web")[0]

	c.deploy(webSpec("nginx:2", 1))
	c.eventually("old replica out of the proxy", func() bool {
		_, cfg := c.proxies["n1"].Applied()
		s := backendServers(cfg, "web")
		return len(s) == 1 && s[0] != old
	})
	// Out of the proxy, but its container keeps running for in-flight
	// requests until the drain timeout.
	reps := c.app("web").Replicas
	draining := false
	for _, r := range reps {
		if r.Id == old && r.Draining {
			draining = true
		}
	}
	if !draining {
		t.Errorf("old replica not reported as draining: %v", reps)
	}
	if containerCount(d1) != 2 {
		t.Errorf("old container stopped before the drain timeout")
	}
	c.eventually("old replica removed after drain", func() bool { return containerCount(d1) == 1 })
}

func TestBrokenRolloutIsAborted(t *testing.T) {
	t.Parallel()
	// Long enough for the agent to report the failed probe before the
	// abort, even on a loaded machine; the message must name it.
	c := newCluster(t, func(cfg *Config) { cfg.ProgressDeadline = 2 * time.Second })
	d1 := c.addNode("n1", "127.0.0.1")
	d2 := c.addNode("n2", "127.0.0.2")
	c.checks["n1"].breakImage("nginx:broken")
	c.checks["n2"].breakImage("nginx:broken")

	c.deploy(webSpec("nginx:1", 2))
	c.eventually("v1 serving", func() bool { return len(c.running("web")) == 2 })
	c.deploy(webSpec("nginx:broken", 2))

	c.eventually("rollout aborted", func() bool { return c.app("web").RolloutState == store.RolloutFailed })
	a := c.app("web")
	if a.ActiveRevision != "web--r1" || a.TargetRevision != "web--r1" || !strings.Contains(a.RolloutMessage, "web--r2 made no progress within") ||
		!strings.Contains(a.RolloutMessage, "readiness probe failed") {
		t.Errorf("after abort = %v", a)
	}
	c.eventually("broken replicas removed", func() bool {
		for _, r := range c.app("web").Replicas {
			if r.Revision != "web--r1" {
				return false
			}
		}
		return containerCount(d1, d2) == 2
	})
	// v1 never stopped serving.
	for _, cfg := range c.proxies["n1"].History() {
		for _, s := range backendServers(cfg, "web") {
			if strings.HasPrefix(s, "web-r2-") {
				t.Errorf("unready replica %s reached the proxy", s)
			}
		}
	}
	if n := len(c.running("web")); n != 2 {
		t.Errorf("%d v1 replicas running after abort", n)
	}
}

func TestRollback(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	d1 := c.addNode("n1", "127.0.0.1")

	_, err := c.admin.Rollback(c.ctx, &armadav1.RollbackRequest{App: "web"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("rollback of unknown app = %v", err)
	}
	c.deploy(webSpec("nginx:1", 1))
	if _, err := c.admin.Rollback(c.ctx, &armadav1.RollbackRequest{App: "web"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("rollback without history = %v", err)
	}
	c.eventually("digest pinned", func() bool {
		rev, err := c.store.GetRevision(c.ctx, "web--r1")
		return err == nil && rev.ImageDigest != ""
	})
	c.deploy(webSpec("nginx:2", 1))
	c.eventually("v2 active", func() bool { a := c.app("web"); return a.ActiveRevision == "web--r2" && a.RolloutState == "" })

	resp, err := c.admin.Rollback(c.ctx, &armadav1.RollbackRequest{App: "web"})
	if err != nil || resp.Revision != "web--r1" {
		t.Fatalf("rollback = %v, %v", resp, err)
	}
	c.eventually("v1 active again", func() bool {
		a := c.app("web")
		return a.ActiveRevision == "web--r1" && a.RolloutState == "" && containerCount(d1) == 1
	})
	// The rollback runs the exact image v1 ran: its pinned digest.
	cs, _ := d1.List(c.ctx, nil)
	if !strings.HasPrefix(cs[0].Image, "nginx@sha256:1111") {
		t.Errorf("rolled back to image %q, want the pinned digest", cs[0].Image)
	}

	revs, err := c.admin.ListRevisions(c.ctx, &armadav1.ListRevisionsRequest{App: "web"})
	if err != nil || len(revs.Revisions) != 2 {
		t.Fatalf("ListRevisions = %v, %v", revs, err)
	}
	if r := revs.Revisions[1]; r.Name != "web--r1" || !r.Active || !r.Target || !strings.HasPrefix(r.ImageDigest, "nginx@sha256:") {
		t.Errorf("revision r1 = %v", r)
	}
	if _, err := c.admin.Rollback(c.ctx, &armadav1.RollbackRequest{App: "web", Revision: "other--r1"}); status.Code(err) != codes.NotFound {
		t.Errorf("rollback to a foreign revision = %v", err)
	}
	audit, _ := c.store.ListAudit(c.ctx, 10)
	found := false
	for _, e := range audit {
		if e.Action == "rollback" && e.Actor == "user:ryan" && e.Detail == "web--r1" {
			found = true
		}
	}
	if !found {
		t.Errorf("rollback not audited: %+v", audit)
	}
}

func TestRollbackCancelsRollout(t *testing.T) {
	t.Parallel()
	c := newCluster(t, func(cfg *Config) { cfg.ProgressDeadline = time.Hour })
	c.addNode("n1", "127.0.0.1")
	c.checks["n1"].breakImage("nginx:broken")
	c.deploy(webSpec("nginx:1", 1))
	c.eventually("v1 serving", func() bool { return len(c.running("web")) == 1 })
	c.deploy(webSpec("nginx:broken", 1))

	resp, err := c.admin.Rollback(c.ctx, &armadav1.RollbackRequest{App: "web"})
	if err != nil || resp.Revision != "web--r1" {
		t.Fatalf("rollback mid-rollout = %v, %v", resp, err)
	}
	c.eventually("rollout cancelled", func() bool {
		a := c.app("web")
		return a.TargetRevision == "web--r1" && a.RolloutState == "" && len(a.Replicas) == 1 && a.Replicas[0].Revision == "web--r1"
	})
}

// Workers publish no port and so have no address; their rollouts must still
// complete.
func TestRolloutWithoutIngress(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	d1 := c.addNode("n1", "127.0.0.1")
	c.deploy("name: worker\nimage: nginx:1\n")
	c.eventually("v1 running", func() bool { return len(c.running("worker")) == 1 })
	c.deploy("name: worker\nimage: nginx:2\n")
	c.eventually("rollout complete", func() bool {
		a := c.app("worker")
		return a.ActiveRevision == "worker--r2" && a.RolloutState == "" && containerCount(d1) == 1
	})
}

// A first revision that never served must not keep the next one from fitting:
// on a node with room for two replicas, two that never became ready give way
// to the new revision at once.
func TestRolloutFreesReplicasThatNeverServed(t *testing.T) {
	t.Parallel()
	c := newCluster(t, func(cfg *Config) { cfg.ProgressDeadline = time.Hour })
	c.addNode("n1", "127.0.0.1")
	c.checks["n1"].breakImage("nginx:broken")
	spec := func(image string) string {
		return "name: web\nimage: " + image + "\ningress:\n  type: external\n  port: 80\nscale:\n  min: 2\n  max: 2\nresources:\n  memory: 768Mi\n"
	}
	c.deploy(spec("nginx:broken"))
	c.eventually("two replicas that never serve", func() bool {
		rs, _ := c.store.ListReplicas(c.ctx, store.ReplicaFilter{App: "web"})
		return len(rs) == 2
	})
	c.deploy(spec("nginx:2"))
	c.eventually("the new revision serves on both", func() bool {
		a := c.app("web")
		r := c.running("web")
		return a.ActiveRevision == "web--r2" && a.RolloutState == "" && len(r) == 2 && r[0].Revision == "web--r2" && r[1].Revision == "web--r2"
	})
}

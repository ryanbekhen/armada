package server

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/agent"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
	"github.com/ryanbekhen/armada/internal/store"
)

// movingNodes stands in for the node side of the move to the supervisor
// runtime (ADR 0054): each agent's MoveRuntime removes the node's
// containers and makes its runtime report the supervisor, as a restart on
// it would; fail makes a node refuse.
type movingNodes struct {
	c     *cluster
	mu    sync.Mutex
	order []string
	fail  map[string]error
	// problems found while a node moved.
	problems []string
}

func newMovingNodes(c *cluster) *movingNodes {
	m := &movingNodes{c: c, fail: map[string]error{}}
	c.agentConfig = func(id string, cfg *agent.Config) {
		d := cfg.Driver.(*fake.Driver)
		cfg.MoveRuntime = func(ctx context.Context, to string) error {
			m.mu.Lock()
			err := m.fail[id]
			m.mu.Unlock()
			if err != nil {
				return err
			}
			if to != "supervisor" {
				m.problem("asked to move to " + to)
			}
			// The leader's record names this node, and nothing of an app
			// is placed on it.
			if rec, err := c.srv.loadRuntimeMove(ctx); err != nil || rec.Move == nil || rec.Move.Node != id || rec.Move.Step != moveMigrating {
				m.problem("move record while " + id + " moved: " + recString(rec))
			}
			if rs, _ := c.store.ListReplicas(ctx, store.ReplicaFilter{}); slices.ContainsFunc(rs, func(r store.Replica) bool { return r.NodeID == id && !r.Done }) {
				m.problem("replicas left on " + id)
			}
			cs, _ := d.List(ctx, nil)
			for _, ct := range cs {
				_ = d.Remove(ctx, ct.ID)
			}
			d.SetRuntimeAgent(runtime.AgentStatus{Agent: runtime.AgentSupervisorRust, Converted: true})
			m.mu.Lock()
			m.order = append(m.order, id)
			m.mu.Unlock()
			return nil
		}
	}
	return m
}

func recString(rec runtimeMoveRec) string {
	if rec.Move == nil {
		return "none"
	}
	return rec.Move.Node + "/" + rec.Move.Step
}

func (m *movingNodes) problem(p string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.problems = append(m.problems, p)
}

func (m *movingNodes) moved() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.order)
}

func (m *movingNodes) check(t *testing.T) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.problems {
		t.Error(p)
	}
}

func onContainerd(ds ...*fake.Driver) {
	for _, d := range ds {
		d.SetRuntimeAgent(runtime.AgentStatus{Agent: runtime.AgentContainerd})
	}
}

func (c *cluster) moveStatus() *armadav1.RuntimeMoveStatus {
	c.t.Helper()
	resp, err := c.admin.ClusterStatus(c.ctx, &armadav1.ClusterStatusRequest{})
	if err != nil {
		c.t.Fatal(err)
	}
	return resp.GetRuntimeMove()
}

func (c *cluster) reasons(node string) []string {
	c.t.Helper()
	evs, err := c.store.ListEvents(c.ctx, time.Time{})
	if err != nil {
		c.t.Fatal(err)
	}
	var out []string
	for _, e := range evs {
		if e.Node == node && strings.HasPrefix(e.Reason, "RuntimeMove") {
			out = append(out, e.Reason)
		}
	}
	return out
}

func serving(c *cluster, app string) int {
	rs, err := c.store.ListReplicas(c.ctx, store.ReplicaFilter{App: app})
	if err != nil {
		return 0
	}
	n := 0
	for _, r := range rs {
		if r.State == store.ReplicaRunning && r.Ready && !r.Draining() {
			n++
		}
	}
	return n
}

// The leader moves every containerd node, one at a time in name order:
// each is drained first (its replicas serve elsewhere before they leave),
// asked to move with nothing left on it, and takes replicas again once it
// reports the supervisor. The app keeps serving throughout, an admin's
// cordon stays, and the move never writes a node's record.
func TestRuntimeMoveOneAtATime(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	m := newMovingNodes(c)
	d1, d2, d3 := c.addNode("n1", "127.0.0.1"), c.addNode("n2", "127.0.0.2"), c.addNode("n3", "127.0.0.3")
	c.deploy(webSpec("nginx:1", 2))
	c.eventually("web serves", func() bool { return serving(c, "web") == 2 })
	if _, err := c.admin.CordonNode(c.ctx, &armadav1.CordonNodeRequest{Node: "n3", Cordoned: true}); err != nil {
		t.Fatal(err)
	}

	var low sync.Once
	stop := make(chan struct{})
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
			if n := serving(c, "web"); n < 2 {
				low.Do(func() { m.problem("web served by fewer than 2 replicas during the move") })
			}
			if n, err := c.store.GetNode(c.ctx, "n1"); err == nil && n.Cordoned {
				m.problem("the move wrote n1's cordon")
			}
		}
	}()

	// Off until every node reported containerd, so the order is the
	// leader's, not the reports'.
	setMove := func(on bool) {
		t.Helper()
		if _, err := c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{SetRuntimeMove: true, Config: &armadav1.ClusterConfig{RuntimeMoveOff: !on}}); err != nil {
			t.Fatal(err)
		}
	}
	setMove(false)
	onContainerd(d1, d2, d3)
	c.eventually("every node on containerd", func() bool {
		p := c.srv.runtimeProgress([]store.Node{{ID: "n1"}, {ID: "n2"}, {ID: "n3"}}, c.srv.now())
		return p.GetOthersTotal() == 3 && slices.IndexFunc(p.GetOthers(), func(o *armadav1.NodeRuntime) bool { return o.GetStatus() == nil }) < 0
	})
	setMove(true)
	c.eventually("every node moved", func() bool { return len(m.moved()) == 3 && c.moveStatus() == nil })
	close(stop)
	<-watched
	m.check(t)
	if got := m.moved(); !slices.Equal(got, []string{"n1", "n2", "n3"}) {
		t.Errorf("moved %v, want n1, n2, n3 one after another", got)
	}
	for _, id := range []string{"n1", "n2"} {
		if got := c.reasons(id); !slices.Equal(got, []string{"RuntimeMoveStarted", "RuntimeMoveDraining", "RuntimeMoveMigrating", "RuntimeMoveDone"}) &&
			!slices.Equal(got, []string{"RuntimeMoveStarted", "RuntimeMoveMigrating", "RuntimeMoveDone"}) {
			t.Errorf("%s events %v", id, got)
		}
	}
	// n3 held nothing (cordoned): no draining.
	if got := c.reasons("n3"); !slices.Equal(got, []string{"RuntimeMoveStarted", "RuntimeMoveMigrating", "RuntimeMoveDone"}) {
		t.Errorf("n3 events %v", got)
	}
	if n, _ := c.store.GetNode(c.ctx, "n3"); !n.Cordoned {
		t.Error("the admin's cordon of n3 was lifted")
	}
	// Moved nodes take replicas again.
	c.deploy(webSpec("nginx:1", 4))
	c.eventually("web on n1 and n2 again", func() bool {
		rs, _ := c.store.ListReplicas(c.ctx, store.ReplicaFilter{App: "web"})
		on := map[string]bool{}
		for _, r := range rs {
			on[r.NodeID] = true
		}
		return on["n1"] && on["n2"]
	})
}

// A cluster of one node waits for its operator, and so does a node holding
// local volumes; the others move. Turning the move off stops it, audited,
// and turning it on again resumes it.
func TestRuntimeMoveWaits(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	m := newMovingNodes(c)
	d1 := c.addNode("n1", "127.0.0.1")
	onContainerd(d1)
	c.eventually("the only node waits", func() bool {
		st := c.moveStatus()
		return st != nil && len(st.GetWaiting()) == 1 && st.GetWaiting()[0].GetOperator() && strings.Contains(st.GetWaiting()[0].GetReason(), "no other node")
	})

	// Off: nothing moves even with a second node.
	if _, err := c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{SetRuntimeMove: true, Config: &armadav1.ClusterConfig{RuntimeMoveOff: true}}); err != nil {
		t.Fatal(err)
	}
	if cc, err := c.admin.GetClusterConfig(c.ctx, &armadav1.GetClusterConfigRequest{}); err != nil || !cc.GetRuntimeMoveOff() {
		t.Fatalf("config %v, %v", cc, err)
	}
	d2 := c.addNode("n2", "127.0.0.2")
	c.deploy(volumeSpec("nginx:1"))
	c.eventually("web runs", func() bool { return serving(c, "web") == 1 })
	onContainerd(d2)
	c.eventually("off in the status", func() bool { st := c.moveStatus(); return st.GetOff() && len(st.GetWaiting()) >= 1 })
	time.Sleep(300 * time.Millisecond)
	if got := m.moved(); len(got) != 0 {
		t.Fatalf("moved %v while off", got)
	}
	audit, err := c.store.ListAudit(c.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(audit, func(a store.AuditEvent) bool {
		return a.Action == "cluster.runtime_move" && a.Detail == "off" && a.Actor != ""
	}) {
		t.Errorf("not audited: %+v", audit)
	}

	if _, err := c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{SetRuntimeMove: true, Config: &armadav1.ClusterConfig{}}); err != nil {
		t.Fatal(err)
	}
	rs, err := c.store.ListReplicas(c.ctx, store.ReplicaFilter{App: "web"})
	if err != nil || len(rs) != 1 {
		t.Fatalf("replicas %v, %v", rs, err)
	}
	holder, other := rs[0].NodeID, map[string]string{"n1": "n2", "n2": "n1"}[rs[0].NodeID]
	c.eventually("the node without volumes moved", func() bool { return slices.Equal(m.moved(), []string{other}) })
	c.eventually("the volume node waits for its operator", func() bool {
		st := c.moveStatus()
		return st != nil && st.GetNode() == "" && len(st.GetWaiting()) == 1 && st.GetWaiting()[0].GetNode() == holder &&
			st.GetWaiting()[0].GetOperator() && strings.Contains(st.GetWaiting()[0].GetReason(), "holds volumes of web")
	})
	time.Sleep(200 * time.Millisecond)
	m.check(t)
	if got := m.moved(); len(got) != 1 {
		t.Errorf("moved %v", got)
	}
}

// A node that does not move in time is given up on: it takes replicas again,
// stays on containerd, and the condition RuntimeMoveGivenUp says why (what
// the node said); after the backoff it is tried again and moves.
func TestRuntimeMoveGivesUp(t *testing.T) {
	t.Parallel()
	c := newCluster(t, func(cfg *Config) {
		cfg.RuntimeMigrateLimit = 300 * time.Millisecond
		cfg.RuntimeMoveBackoff = 2 * time.Second
	})
	m := newMovingNodes(c)
	m.fail["n1"] = errors.New("the disk is full")
	d1, d2 := c.addNode("n1", "127.0.0.1"), c.addNode("n2", "127.0.0.2")
	onContainerd(d1, d2)
	c.eventually("n1 given up", func() bool {
		return slices.Contains(c.reasons("n1"), "RuntimeMoveGivenUp")
	})
	rec, err := c.srv.loadRuntimeMove(c.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if g, ok := rec.GivenUp["n1"]; !ok || !strings.Contains(g.Reason, "the disk is full") {
		t.Errorf("given up %+v", rec.GivenUp)
	}
	// n1 takes replicas again while n2 moves.
	c.eventually("n2 moved", func() bool { return slices.Contains(m.moved(), "n2") })
	c.deploy(webSpec("nginx:1", 2))
	c.eventually("web on n1", func() bool {
		rs, _ := c.store.ListReplicas(c.ctx, store.ReplicaFilter{App: "web"})
		return slices.ContainsFunc(rs, func(r store.Replica) bool { return r.NodeID == "n1" })
	})

	m.mu.Lock()
	delete(m.fail, "n1")
	m.mu.Unlock()
	c.eventually("n1 tried again and moved", func() bool { return slices.Contains(m.moved(), "n1") && c.moveStatus() == nil })
	m.check(t)
	rec, _ = c.srv.loadRuntimeMove(c.ctx)
	if len(rec.GivenUp) != 0 || rec.Move != nil {
		t.Errorf("record %+v", rec)
	}
}

// A new leader carries on with the move its predecessor recorded: the node
// in the record moves first, from the step it was at.
func TestRuntimeMoveContinuesAfterFailover(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	m := newMovingNodes(c)
	d1, d2 := c.addNode("n1", "127.0.0.1"), c.addNode("n2", "127.0.0.2")
	since := time.Now().Add(-time.Minute).UnixMilli()
	c.srv.moveMu.Lock()
	err := c.srv.saveRuntimeMove(c.ctx, runtimeMoveRec{Move: &runtimeMove{Node: "n2", Step: moveMigrating, Since: since, StepSince: time.Now().UnixMilli()}})
	c.srv.moveMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	onContainerd(d1, d2)
	c.eventually("both moved", func() bool { return len(m.moved()) == 2 })
	m.check(t)
	if got := m.moved(); got[0] != "n2" {
		t.Errorf("moved %v, want n2 first", got)
	}
	if got := c.reasons("n2"); !slices.Equal(got, []string{"RuntimeMoveDone"}) {
		t.Errorf("n2 events %v", got)
	}
}

// An older agent that cannot move itself waits for its operator; the
// leader never asks it.
func TestRuntimeMoveOldAgent(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	c.agentConfig = func(string, *agent.Config) {}
	d1, d2 := c.addNode("n1", "127.0.0.1"), c.addNode("n2", "127.0.0.2")
	onContainerd(d1, d2)
	c.eventually("both wait for an upgrade", func() bool {
		st := c.moveStatus()
		return st != nil && st.GetNode() == "" && st.GetWaitingTotal() == 2 && strings.Contains(st.GetWaiting()[0].GetReason(), "upgrade")
	})
}

// Workers move before servers, the leader's own machine last.
func TestRuntimeMoveOrder(t *testing.T) {
	t.Parallel()
	c := newCluster(t, func(cfg *Config) { cfg.Name = "lead" })
	for _, sv := range []store.Server{{Name: "lead", PrivateIP: "10.0.0.1"}, {Name: "s2", PrivateIP: "10.0.0.3"}} {
		if err := c.store.UpsertServer(c.ctx, sv); err != nil {
			t.Fatal(err)
		}
	}
	nodes := []store.Node{{ID: "a", PrivateIP: "10.0.0.1"}, {ID: "b", PrivateIP: "10.0.0.2"}, {ID: "c", PrivateIP: "10.0.0.3"}, {ID: "d", PrivateIP: "10.0.0.4"}}
	var got []string
	for _, n := range c.srv.moveOrder(c.ctx, nodes) {
		got = append(got, n.ID)
	}
	if !slices.Equal(got, []string{"b", "d", "c", "a"}) {
		t.Errorf("order %v", got)
	}
}

// What a containerd node says about its move is bounded.
func TestCleanRuntimeStatusMoveError(t *testing.T) {
	t.Parallel()
	got := cleanRuntimeStatus(&armadav1.RuntimeStatus{Agent: runtime.AgentContainerd, MoveError: "no\x1b[31m" + strings.Repeat("x", 2000)})
	if strings.ContainsRune(got.GetMoveError(), 0x1b) || len(got.GetMoveError()) > maxEventMessage || !strings.HasPrefix(got.GetMoveError(), "no") {
		t.Errorf("cleaned %v", got)
	}
	if got := cleanRuntimeStatus(&armadav1.RuntimeStatus{Agent: runtime.AgentSupervisorRust, MoveError: "x"}); got.GetMoveError() != "" {
		t.Errorf("a supervisor node carries a move error: %v", got)
	}
}

// A node whose replicas do not leave in time (a job attempt runs on) is
// given up on in the draining step: it takes replicas again, stays on
// containerd, and is never asked to move.
func TestRuntimeMoveDrainTimeout(t *testing.T) {
	t.Parallel()
	c := newCluster(t, func(cfg *Config) {
		cfg.RuntimeDrainLimit = 400 * time.Millisecond
		cfg.RuntimeMoveBackoff = time.Hour
	})
	m := newMovingNodes(c)
	d1 := c.addNode("n1", "127.0.0.1")
	c.deploy("kind: job\nname: slow\nimage: busybox:1\n")
	if _, err := c.admin.RunJob(c.ctx, &armadav1.RunJobRequest{Job: "slow"}); err != nil {
		t.Fatal(err)
	}
	c.eventually("attempt running", func() bool { return c.runState("slow", 1).GetState() == store.RunRunning })
	// Only n1 moves: n2 already runs on the supervisor.
	d2 := c.addNode("n2", "127.0.0.2")
	d2.SetRuntimeAgent(runtime.AgentStatus{Agent: runtime.AgentSupervisorRust, Converted: true})
	onContainerd(d1)
	c.eventually("n1 given up", func() bool {
		rec, _ := c.srv.loadRuntimeMove(c.ctx)
		g, ok := rec.GivenUp["n1"]
		return ok && rec.Move == nil && strings.Contains(g.Reason, "did not leave it") && strings.Contains(g.Reason, "slow")
	})
	if got := c.reasons("n1"); !slices.Contains(got, "RuntimeMoveDraining") || slices.Contains(got, "RuntimeMoveMigrating") || !slices.Contains(got, "RuntimeMoveGivenUp") {
		t.Errorf("n1 events %v", got)
	}
	if st := c.moveStatus(); st.GetNode() != "" || len(st.GetWaiting()) != 1 || !strings.Contains(st.GetWaiting()[0].GetReason(), "given up") || st.GetWaiting()[0].GetOperator() {
		t.Errorf("status %v", st)
	}
	// n1 takes replicas again.
	c.deploy(webSpec("nginx:1", 2))
	c.eventually("web on n1", func() bool {
		rs, _ := c.store.ListReplicas(c.ctx, store.ReplicaFilter{App: "web"})
		return slices.ContainsFunc(rs, func(r store.Replica) bool { return r.NodeID == "n1" })
	})
	if got := m.moved(); len(got) != 0 {
		t.Errorf("moved %v", got)
	}
}

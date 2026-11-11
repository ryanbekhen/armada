package server

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/agent"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// fakeRedisServer answers AUTH with password pw and LLEN with length; it
// returns its address.
func fakeRedisServer(t *testing.T, pw string, length *atomic.Int64) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				for {
					line, err := r.ReadString('\n')
					if err != nil || len(line) < 2 {
						return
					}
					n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
					args := make([]string, n)
					for i := range args {
						_, _ = r.ReadString('\n')
						a, _ := r.ReadString('\n')
						args[i] = strings.TrimSuffix(a, "\r\n")
					}
					switch {
					case len(args) == 2 && args[0] == "AUTH" && args[1] == pw:
						_, _ = conn.Write([]byte("+OK\r\n"))
					case len(args) == 2 && args[0] == "LLEN":
						_, _ = conn.Write([]byte(":" + strconv.FormatInt(length.Load(), 10) + "\r\n"))
					default:
						_, _ = conn.Write([]byte("-ERR\r\n"))
					}
				}
			}()
		}
	}()
	return l.Addr().String()
}

const mailerJob = "kind: job\nname: mailer\nimage: busybox:1\ntrigger:\n  queue:\n    type: redis\n    urlSecretRef: redis-url\n    list: mail\n    perRun: 10\n  parallelism: 2\n"

func TestProbeNode(t *testing.T) {
	t.Parallel()
	rev := store.Revision{Spec: &spec.App{Kind: spec.KindJob, Name: "mailer"}}
	node := func(id string) store.Node {
		return store.Node{ID: id, State: store.NodeReady, Jobs: true, Subnet: "10.120.0.0/24"}
	}
	all := []store.Node{node("a"), node("b"), node("c"), node("d")}
	on := map[string]bool{"a": true, "b": true, "c": true, "d": true}
	first, ok := probeNode("mailer", all, rev, nil, on)
	if !ok {
		t.Fatal("no node")
	}
	// Every leader picks the same, whatever the order.
	reversed := slices.Clone(all)
	slices.Reverse(reversed)
	if again, _ := probeNode("mailer", reversed, rev, nil, on); again != first {
		t.Errorf("reversed order picks %s, want %s", again, first)
	}
	// Jobs spread over nodes.
	picked := map[string]bool{}
	for i := range 40 {
		n, _ := probeNode("job-"+strconv.Itoa(i), all, rev, nil, on)
		picked[n] = true
	}
	if len(picked) < 3 {
		t.Errorf("40 jobs read from %d nodes", len(picked))
	}
	// It moves only when its node stops fitting.
	others := slices.DeleteFunc(slices.Clone(all), func(n store.Node) bool { return n.ID == first })
	moved, _ := probeNode("mailer", others, rev, nil, on)
	if moved == first || moved == "" {
		t.Errorf("moved to %q", moved)
	}
	for name, ex := range map[string]func(*store.Node, map[string]bool, map[string]bool){
		"lost":         func(_ *store.Node, lost, _ map[string]bool) { lost[first] = true },
		"disconnected": func(_ *store.Node, _, on map[string]bool) { delete(on, first) },
		"no subnet":    func(n *store.Node, _, _ map[string]bool) { n.Subnet = "" },
		"no jobs":      func(n *store.Node, _, _ map[string]bool) { n.Jobs = false },
		"cordoned":     func(n *store.Node, _, _ map[string]bool) { n.Cordoned = true },
	} {
		nodes := slices.Clone(all)
		lost, conn := map[string]bool{}, map[string]bool{"a": true, "b": true, "c": true, "d": true}
		for i := range nodes {
			if nodes[i].ID == first {
				ex(&nodes[i], lost, conn)
			}
		}
		if got, _ := probeNode("mailer", nodes, rev, lost, conn); got == first || got == "" {
			t.Errorf("%s: picked %q", name, got)
		}
	}
	if got, ok := probeNode("mailer", all, rev, nil, nil); ok {
		t.Errorf("picked %s with no node keeping sandboxes", got)
	}
	// Placement holds: a job that requires a label reads from such a node.
	req := store.Revision{Spec: &spec.App{Kind: spec.KindJob, Name: "mailer", Placement: &spec.Placement{Require: map[string]spec.LabelValues{"zone": {"x"}}}}}
	labelled := slices.Clone(all)
	labelled[2].Labels = map[string]string{"zone": "x"}
	if got, _ := probeNode("mailer", labelled, req, nil, on); got != "c" {
		t.Errorf("with placement: %s", got)
	}
}

func TestSandboxReadings(t *testing.T) {
	t.Parallel()
	u := newUsageStore()
	now := time.Now()
	report := func(q ...*armadav1.SandboxQueue) *armadav1.UsageReport { return &armadav1.UsageReport{Sandboxes: q} }
	if u.set("n1", report(&armadav1.SandboxQueue{Job: "mailer", Ip: "10.120.0.9"}), now) {
		t.Error("an address without a reading is a reading")
	}
	if !u.set("n1", report(&armadav1.SandboxQueue{Job: "mailer", Ip: "10.120.0.9", Measured: true, Length: 1 << 50, AgeMillis: 3000, Reading: 1}), now) {
		t.Error("a first reading is not new")
	}
	n, _ := u.node("n1", now)
	r := n.sandboxes["mailer"]
	if r.length != maxQueueLength || !r.at.Equal(now.Add(-3*time.Second)) || r.ip != "10.120.0.9" {
		t.Errorf("reading %+v", r)
	}
	if u.set("n1", report(&armadav1.SandboxQueue{Job: "mailer", Ip: "10.120.0.9", Measured: true, Length: 4, AgeMillis: 9000, Reading: 1}), now) {
		t.Error("the same reading again is new")
	}
	if !u.set("n1", report(&armadav1.SandboxQueue{Job: "mailer", Ip: "10.120.0.9", Measured: true, Length: 4, Reading: 2}), now) {
		t.Error("a second reading is not new")
	}
	// Ages are bounded, as are names and the number of entries.
	u.set("n1", report(&armadav1.SandboxQueue{Job: "mailer", Measured: true, AgeMillis: -5, Reading: 3},
		&armadav1.SandboxQueue{Job: "../etc", Measured: true, Reading: 1}), now)
	n, _ = u.node("n1", now)
	if r := n.sandboxes["mailer"]; !r.at.Equal(now) || len(n.sandboxes) != 1 {
		t.Errorf("sandboxes %+v", n.sandboxes)
	}
	many := make([]*armadav1.SandboxQueue, maxSandboxReports+1)
	for i := range many {
		many[i] = &armadav1.SandboxQueue{Job: "j" + strconv.Itoa(i), Measured: true, Reading: 1}
	}
	if u.set("n1", report(many...), now) {
		t.Error("an oversized report counts")
	}
}

// triggerUnit is a cluster with one node record, connected only in name: the
// test feeds the leader's usage store and runs triggerJob itself.
func triggerUnit(t *testing.T) (*cluster, func(sandboxNodes map[string]bool, lost map[string]bool) (*reconcileRun, []store.JobRun)) {
	t.Helper()
	c := newCluster(t, withKeys(t))
	if err := c.store.InitNetwork(c.ctx, store.Network{Mode: store.NetworkPlain, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	if err := c.store.UpsertNode(c.ctx, store.Node{ID: "n1", PrivateIP: "10.0.0.11"}); err != nil {
		t.Fatal(err)
	}
	if err := c.store.SetNodeStatus(c.ctx, "n1", store.NodeStatus{State: store.NodeReady, LastSeen: time.Now(), Jobs: true, CPUMillis: 2000, MemoryBytes: 2 << 30}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.admin.SetSecret(c.ctx, &armadav1.SetSecretRequest{App: "mailer", Name: "redis-url", Value: []byte("redis://:pw@10.0.0.50:6379")}); err != nil {
		t.Fatal(err)
	}
	c.deploy(mailerJob)
	// The test runs the leader's passes itself.
	c.stop()
	<-c.stopped
	c.ctx = t.Context()
	pass := func(sandboxNodes, lost map[string]bool) (*reconcileRun, []store.JobRun) {
		t.Helper()
		job, err := c.store.GetApp(c.ctx, "mailer")
		if err != nil {
			t.Fatal(err)
		}
		nodes, _ := c.store.ListNodes(c.ctx)
		revs := revisionCache{store: c.store, keys: c.srv.keys, m: map[string]store.Revision{}, opened: c.srv.opened}
		rc := &reconcileRun{now: c.srv.now(), revs: &revs, lost: lost, sandboxNodes: sandboxNodes,
			sandboxes: map[string][]*armadav1.QueueSandbox{}, triggered: map[string]bool{}}
		runs, _ := c.store.ListJobRuns(c.ctx, "mailer")
		return rc, c.srv.triggerJob(c.ctx, rc, job, runs, nodes, &revs)
	}
	return c, pass
}

// The leader's decision: ⌈length ÷ perRun⌉ runs at most parallelism, less
// the active ones, once per reading; nothing on stale or missing readings,
// and no node to read from when none fits (ADR 0040).
func TestTriggerDecision(t *testing.T) {
	t.Parallel()
	c, pass := triggerUnit(t)
	on := map[string]bool{"n1": true}
	reading := func(length, n int64, age time.Duration) {
		c.srv.usage.set("n1", &armadav1.UsageReport{Sandboxes: []*armadav1.SandboxQueue{
			{Job: "mailer", Ip: "10.120.0.9", Measured: true, Length: length, AgeMillis: age.Milliseconds(), Reading: n},
		}}, c.srv.now())
	}
	active := func(runs []store.JobRun) int {
		n := 0
		for _, r := range runs {
			if r.Active() {
				n++
			}
		}
		return n
	}

	// No reading yet: the node is asked to read the queue, with the URL from
	// the pinned secret, and nothing starts.
	rc, runs := pass(on, nil)
	if len(runs) != 0 {
		t.Fatalf("runs without a reading: %v", runs)
	}
	sb := rc.sandboxes["n1"]
	if len(sb) != 1 || sb[0].GetJob() != "mailer" || sb[0].GetProbe().GetUrl() != "redis://:pw@10.0.0.50:6379" || sb[0].GetProbe().GetUrlRef() != "redis-url@v1" ||
		sb[0].GetProbe().GetName() != "mail" || sb[0].GetIntervalSeconds() != 30 {
		t.Fatalf("sandboxes %v", sb)
	}
	if c.srv.triggers.node("mailer") != "n1" {
		t.Errorf("probe node %q", c.srv.triggers.node("mailer"))
	}

	// 25 waiting at 10 per run wants 3; parallelism caps it at 2.
	reading(25, 1, 0)
	rc, runs = pass(on, nil)
	if active(runs) != 2 || runs[0].Trigger != store.TriggerQueue {
		t.Fatalf("runs %+v", runs)
	}
	// The sandbox's address is the job's, for every node's firewall.
	if len(rc.sandboxAddrs) != 1 || rc.sandboxAddrs[0].IP != "10.120.0.9" || rc.sandboxAddrs[0].App != "mailer" || rc.sandboxAddrs[0].NodeID != "n1" {
		t.Errorf("addresses %+v", rc.sandboxAddrs)
	}
	// The same reading starts nothing more, even once the runs end.
	for _, r := range runs {
		r.State, r.FinishedAt = store.RunSucceeded, time.Now()
		if err := c.store.UpdateJobRun(c.ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, runs = pass(on, nil); active(runs) != 0 || len(runs) != 2 {
		t.Fatalf("a reading acted on twice: %+v", runs)
	}
	// A new reading of 5 wants one.
	reading(5, 2, 0)
	if _, runs = pass(on, nil); active(runs) != 1 || len(runs) != 3 {
		t.Fatalf("after a reading of 5: %+v", runs)
	}
	// With one active, a reading of 15 wants two: one more.
	reading(15, 3, 0)
	if _, runs = pass(on, nil); active(runs) != 2 || len(runs) != 4 {
		t.Fatalf("after a reading of 15: %+v", runs)
	}
	// Two active, an empty queue: nothing ends or starts.
	reading(0, 4, 0)
	if _, runs = pass(on, nil); active(runs) != 2 || len(runs) != 4 {
		t.Fatalf("after an empty queue: %+v", runs)
	}
	for _, r := range runs {
		if r.Active() {
			r.State, r.FinishedAt = store.RunSucceeded, time.Now()
			_ = c.store.UpdateJobRun(c.ctx, r)
		}
	}
	// A stale reading starts nothing.
	reading(100, 5, 10*time.Minute)
	if _, runs = pass(on, nil); active(runs) != 0 {
		t.Fatalf("a stale reading started runs: %+v", runs)
	}
	// A reading from a node that no longer reads the queue counts for
	// nothing; nor does anything while no node can read it.
	reading(100, 6, 0)
	rc, runs = pass(on, map[string]bool{"n1": true})
	if active(runs) != 0 || len(rc.sandboxes) != 0 || c.srv.triggers.node("mailer") != "" {
		t.Fatalf("lost node: runs %+v, sandboxes %v", runs, rc.sandboxes)
	}
	if rc, runs = pass(nil, nil); active(runs) != 0 || len(rc.sandboxes) != 0 {
		t.Fatalf("no node keeping sandboxes: runs %+v, sandboxes %v", runs, rc.sandboxes)
	}
	evs, _ := c.store.ListEvents(c.ctx, time.Time{})
	var reasons []string
	for _, e := range evs {
		reasons = append(reasons, e.Reason)
	}
	if !slices.Contains(reasons, "QueueTriggered") || !slices.Contains(reasons, "QueueUnread") {
		t.Errorf("events %v", reasons)
	}
	for _, e := range evs {
		if strings.Contains(e.Message, "pw@") {
			t.Errorf("event carries the URL: %+v", e)
		}
	}
}

// fakeNet stands in for the cluster network and keeps what it was given.
type fakeNet struct {
	mu  sync.Mutex
	cfg *armadav1.NetworkConfig
}

func (n *fakeNet) Apply(_ context.Context, cfg *armadav1.NetworkConfig, _ map[netip.Addr]string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.cfg = cfg
	return nil
}

func (n *fakeNet) endpoint(addr string) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, e := range n.cfg.GetEndpoints() {
		if e.GetAddress() == addr {
			return e.GetApp()
		}
	}
	return ""
}

// A queue-triggered job end to end: a node keeps a sandbox for it and reads
// the list from there, runs start while the list holds messages, up to the
// job's parallelism, and none while it is empty; the sandbox moves when its
// node goes and is removed with the job (ADR 0040).
func TestQueueTriggeredJob(t *testing.T) {
	t.Parallel()
	var length atomic.Int64
	addr := fakeRedisServer(t, "pw", &length)
	c := newCluster(t, withKeys(t))

	// Without a cluster network a queue trigger is refused.
	if _, err := c.admin.Deploy(c.ctx, &armadav1.DeployRequest{Spec: []byte(mailerJob)}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("deploy without a cluster network: %v", err)
	}
	if err := c.store.InitNetwork(c.ctx, store.Network{Mode: store.NetworkPlain, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	nets := map[string]*fakeNet{}
	var netsMu sync.Mutex
	c.agentConfig = func(id string, cfg *agent.Config) {
		n, err := c.store.GetNode(c.ctx, id)
		if err != nil || n.Subnet == "" {
			t.Errorf("node %s has no subnet: %v", id, err)
			return
		}
		netsMu.Lock()
		if nets[id] == nil {
			nets[id] = &fakeNet{}
		}
		cfg.Network = nets[id]
		netsMu.Unlock()
		cfg.Unpublished, cfg.SandboxInterval = true, 20*time.Millisecond
		c.nodes[id].d.BridgeIPs = strings.TrimSuffix(n.Subnet, "0/24")
	}
	d1 := c.addNode("n1", "10.0.0.11")
	d2 := c.addNode("n2", "10.0.0.12")
	drivers := map[string]interface{ Sandboxes() []string }{"n1": d1, "n2": d2}
	if _, err := c.admin.SetSecret(c.ctx, &armadav1.SetSecretRequest{App: "mailer", Name: "redis-url", Value: []byte("redis://:pw@" + addr)}); err != nil {
		t.Fatal(err)
	}
	c.deploy(mailerJob)

	trigger := func() *armadav1.JobTrigger {
		resp, err := c.admin.ListJobs(c.ctx, &armadav1.ListJobsRequest{})
		if err != nil || len(resp.Jobs) != 1 {
			return nil
		}
		return resp.Jobs[0].GetTrigger()
	}
	var probe string
	c.eventually("the queue read from one node's sandbox", func() bool {
		tr := trigger()
		probe = tr.GetNode()
		return tr.GetMeasured() && tr.GetLength() == 0 && probe != "" && slices.Equal(drivers[probe].Sandboxes(), []string{"mailer"})
	})
	other := map[string]string{"n1": "n2", "n2": "n1"}[probe]
	if len(drivers[other].Sandboxes()) != 0 {
		t.Errorf("a sandbox on %s too", other)
	}
	if tr := trigger(); tr.GetType() != "redis" || tr.GetName() != "mail" || tr.GetPerRun() != 10 || tr.GetParallelism() != 2 || tr.GetPollingIntervalSeconds() != 30 {
		t.Errorf("trigger %v", tr)
	}
	// Every node's firewall knows the sandbox's address as the job's.
	ip := ""
	c.eventually("the sandbox is an endpoint of the job", func() bool {
		for _, n := range []string{"n1", "n2"} {
			found := false
			nets[n].mu.Lock()
			for _, e := range nets[n].cfg.GetEndpoints() {
				if e.GetApp() == "mailer" {
					found, ip = true, e.GetAddress()
				}
			}
			nets[n].mu.Unlock()
			if !found {
				return false
			}
		}
		return true
	})
	if ip == "" || nets[other].endpoint(ip) != "mailer" {
		t.Errorf("endpoint %q", ip)
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(c.runs("mailer")); n != 0 {
		t.Fatalf("%d runs for an empty queue", n)
	}

	// 25 waiting at 10 per run: 3 wanted, 2 at most.
	length.Store(25)
	c.eventually("two runs running", func() bool {
		rs := c.runs("mailer")
		return len(rs) == 2 && rs[0].GetState() == store.RunRunning && rs[1].GetState() == store.RunRunning
	})
	time.Sleep(200 * time.Millisecond)
	if n := len(c.runs("mailer")); n != 2 {
		t.Errorf("%d runs, parallelism is 2", n)
	}
	if rs := c.runs("mailer"); rs[0].GetTrigger() != store.TriggerQueue {
		t.Errorf("trigger %q", rs[0].GetTrigger())
	}
	if _, err := c.admin.RunJob(c.ctx, &armadav1.RunJobRequest{Job: "mailer"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a manual run past parallelism: %v", err)
	}

	// The queue empties and the runs end: nothing starts again.
	length.Store(0)
	time.Sleep(100 * time.Millisecond)
	for _, r := range c.runs("mailer") {
		exitAttempt(t, []*fake.Driver{d1, d2}, r.GetReplica(), 0)
	}
	c.eventually("both runs succeeded", func() bool {
		for _, r := range c.runs("mailer") {
			if r.GetState() != store.RunSucceeded {
				return false
			}
		}
		return true
	})
	time.Sleep(300 * time.Millisecond)
	if n := len(c.runs("mailer")); n != 2 {
		t.Fatalf("%d runs after the queue emptied", n)
	}

	// Five more: one run.
	length.Store(5)
	c.eventually("a third run", func() bool { return len(c.runs("mailer")) == 3 })
	time.Sleep(200 * time.Millisecond)
	if n := len(c.runs("mailer")); n != 3 {
		t.Errorf("%d runs for 5 messages", n)
	}
	length.Store(0)

	// The node that reads the queue goes: the other one takes over.
	c.stopAgent(probe)
	c.eventually("the sandbox moved", func() bool {
		tr := trigger()
		return tr.GetNode() == other && tr.GetMeasured() && slices.Equal(drivers[other].Sandboxes(), []string{"mailer"})
	})

	// Deleting the job removes its sandbox.
	if _, err := c.admin.DeleteJob(c.ctx, &armadav1.DeleteJobRequest{Job: "mailer"}); err != nil {
		t.Fatal(err)
	}
	c.eventually("the sandbox removed", func() bool { return len(drivers[other].Sandboxes()) == 0 })
}

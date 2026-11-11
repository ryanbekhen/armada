package server

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

const scaledSpec = "name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\nresources:\n  cpu: 500m\n  memory: 256Mi\nscale:\n  min: 2\n  max: 10\n  rules:\n"

func scaledApp(t *testing.T, rules string, replicas int) store.App {
	t.Helper()
	sp, err := spec.Parse([]byte(scaledSpec + rules))
	if err != nil {
		t.Fatal(err)
	}
	return store.App{Name: "web", ActiveRevision: "web--r1", TargetRevision: "web--r1", Replicas: replicas, Spec: sp}
}

func readyReplicas(n int) []store.Replica {
	var out []store.Replica
	for i := range n {
		out = append(out, store.Replica{ID: fmt.Sprintf("web-%d", i), App: "web", Revision: "web--r1", NodeID: fmt.Sprintf("n%d", i%2), State: store.ReplicaRunning, Ready: true})
	}
	return out
}

// loadOf reports in-flight requests per replica, as one node's proxy.
func loadOf(now time.Time, reps []store.Replica, per int64) scaleInputs {
	u := newUsageStore()
	r := &armadav1.UsageReport{LoadMeasured: true}
	for _, rep := range reps {
		r.Load = append(r.Load, &armadav1.ReplicaLoad{Id: rep.ID, InFlight: per})
	}
	u.set("n0", r, now)
	in := scaleInputs{now: now, usage: u}
	in.load, in.loadMeasured = u.load(now)
	return in
}

func TestDecideHTTP(t *testing.T) {
	t.Parallel()
	now := time.Now()
	a := scaledApp(t, "    - type: http\n      concurrent: 10\n", 3)
	reps := readyReplicas(3)
	res := resources{cpu: 500, mem: 256 << 20}
	st := &appScaling{since: now}

	// 25 per replica against 10: 3 * 2.5 = 7.5, capped at double: 6.
	n, why, status := decide(a, res, reps, loadOf(now, reps, 25), st)
	if n != 6 || !strings.Contains(why, "http 25 of 10 per replica") {
		t.Errorf("scale up: %d %q", n, why)
	}
	if len(status.Rules) != 1 || status.Rules[0].Current != 25 || !status.Rules[0].Measured || status.Min != 2 || status.Max != 10 {
		t.Errorf("status %v", status)
	}
	// Within 10% of the target: hold.
	if n, _, _ := decide(a, res, reps, loadOf(now, reps, 10), st); n != 3 {
		t.Errorf("within tolerance: %d", n)
	}
	// Quiet, but a recent recommendation was higher: hold.
	if n, _, _ := decide(a, res, reps, loadOf(now.Add(time.Minute), reps, 0), st); n != 3 {
		t.Errorf("early scale down: %d", n)
	}
	// A new leader waits a full window before scaling down.
	if n, _, s := decide(a, res, reps, loadOf(now, reps, 0), &appScaling{since: now}); n != 3 || !strings.Contains(s.Message, "would scale down") {
		t.Errorf("scale down right after start: %d %v", n, s)
	}
	// After the window, the highest recent recommendation wins: here the
	// one a minute ago (hold at 3, then 2).
	later := now.Add(scaleDownWindow + 30*time.Second)
	if n, _, _ := decide(a, res, reps, loadOf(later, reps, 0), st); n != 2 {
		t.Errorf("scale down after the window: %d", n)
	}
	// Never above max.
	big := scaledApp(t, "    - type: http\n      concurrent: 10\n", 8)
	if n, _, _ := decide(big, res, readyReplicas(8), loadOf(now, readyReplicas(8), 1000), &appScaling{since: now}); n != 10 {
		t.Errorf("max: %d", n)
	}
}

func TestDecideHolds(t *testing.T) {
	t.Parallel()
	now := time.Now()
	res := resources{cpu: 500, mem: 256 << 20}
	a := scaledApp(t, "    - type: cpu\n      utilization: 50\n", 2)
	reps := readyReplicas(2)

	// No samples at all.
	if n, _, s := decide(a, res, reps, scaleInputs{now: now, usage: newUsageStore()}, &appScaling{since: now}); n != 2 || !strings.Contains(s.Message, "not enough samples") || s.Rules[0].Measured {
		t.Errorf("no samples: %d %v", n, s)
	}
	// A sample reported by another node than the replica's does not count.
	u := newUsageStore()
	u.set("n9", &armadav1.UsageReport{Replicas: []*armadav1.ReplicaUsage{{Id: "web-0", CpuMillis: 500}, {Id: "web-1", CpuMillis: 500}}}, now)
	if n, _, _ := decide(a, res, reps, scaleInputs{now: now, usage: u}, &appScaling{since: now}); n != 2 {
		t.Errorf("foreign samples: %d", n)
	}
	// Own samples: 100% of 500m against 50% doubles.
	u.set("n0", &armadav1.UsageReport{Replicas: []*armadav1.ReplicaUsage{{Id: "web-0", CpuMillis: 500}}}, now)
	u.set("n1", &armadav1.UsageReport{Replicas: []*armadav1.ReplicaUsage{{Id: "web-1", CpuMillis: 500}}}, now)
	if n, why, _ := decide(a, res, reps, scaleInputs{now: now, usage: u}, &appScaling{since: now}); n != 4 || !strings.Contains(why, "cpu 100 of 50%") {
		t.Errorf("cpu: %d %q", n, why)
	}
	// A rollout freezes the count.
	rolling := a
	rolling.TargetRevision, rolling.RolloutState = "web--r2", store.RolloutProgressing
	if n, _, s := decide(rolling, res, reps, scaleInputs{now: now, usage: u}, &appScaling{since: now}); n != 2 || !strings.Contains(s.Message, "rollout") {
		t.Errorf("rolling: %d %v", n, s)
	}
	// No ready replica: nothing to measure.
	if n, _, _ := decide(a, res, nil, scaleInputs{now: now, usage: u}, &appScaling{since: now}); n != 2 {
		t.Errorf("none ready: %d", n)
	}
}

// Several rules: the one asking for the most replicas wins.
func TestDecideHighestRule(t *testing.T) {
	t.Parallel()
	now := time.Now()
	a := scaledApp(t, "    - type: http\n      concurrent: 100\n    - type: memory\n      utilization: 50\n", 2)
	reps := readyReplicas(2)
	in := loadOf(now, reps, 10)
	in.usage.set("n1", &armadav1.UsageReport{Replicas: []*armadav1.ReplicaUsage{{Id: "web-1", MemoryBytes: 192 << 20}}}, now)
	in.usage.set("n0", &armadav1.UsageReport{LoadMeasured: true, Load: []*armadav1.ReplicaLoad{{Id: "web-0", InFlight: 10}, {Id: "web-1", InFlight: 10}},
		Replicas: []*armadav1.ReplicaUsage{{Id: "web-0", MemoryBytes: 192 << 20}}}, now)
	n, why, _ := decide(a, resources{cpu: 500, mem: 256 << 20}, reps, in, &appScaling{since: now})
	if n != 3 || !strings.Contains(why, "memory 75 of 50%") {
		t.Errorf("highest rule: %d %q", n, why)
	}
}

func TestAutoscaleCluster(t *testing.T) {
	t.Parallel()
	c := newCluster(t, func(cfg *Config) { cfg.AutoscaleInterval = 50 * time.Millisecond })
	c.addNode("n1", "127.0.0.1")
	c.addNode("n2", "127.0.0.2")
	c.deploy(scaledSpec + "    - type: http\n      concurrent: 10\n")
	c.eventually("2 running", func() bool { return len(c.running("web")) == 2 })

	// Manual scaling is refused: the autoscaler owns the count.
	_, err := c.admin.Scale(c.ctx, &armadav1.ScaleRequest{App: "web", Replicas: 5})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("scale an autoscaled app: %v", err)
	}
	// The message says what to run instead, and ends with no sentinel.
	if msg := status.Convert(err).Message(); !strings.Contains(msg, "armada app update web --min N") || strings.HasSuffix(msg, "failed precondition") {
		t.Errorf("message = %q", msg)
	}

	// 30 requests in progress per replica, seen at n1's proxy.
	load := func(per int64) {
		m := map[string]int64{}
		for _, r := range c.running("web") {
			m[r.Id] = per
		}
		c.proxies["n1"].SetLoad(m)
	}
	load(30)
	c.eventually("scaled to 4", func() bool {
		load(30)
		st, err := c.admin.Status(c.ctx, &armadav1.StatusRequest{App: "web"})
		return err == nil && st.Apps[0].DesiredReplicas >= 4
	})
	st, _ := c.admin.Status(c.ctx, &armadav1.StatusRequest{App: "web"})
	as := st.Apps[0].Autoscale
	if as == nil || as.Min != 2 || as.Max != 10 || len(as.Rules) != 1 || as.Rules[0].Type != "http" {
		t.Errorf("autoscale status %v", as)
	}
	if as.GetLastScaledAt() == nil || time.Since(as.GetLastScaledAt().AsTime()) > time.Minute {
		t.Errorf("last scaled at %v", as.GetLastScaledAt())
	}
	evs, _ := c.store.ListEvents(c.ctx, time.Time{})
	found := false
	for _, e := range evs {
		found = found || (e.Kind == eventApp && e.Reason == "ScaledUp" && strings.Contains(e.Message, "http"))
	}
	if !found {
		t.Errorf("no ScaledUp event in %+v", evs)
	}

	// A redeploy keeps the count within the new bounds.
	c.deploy(strings.Replace(scaledSpec, "max: 10", "max: 3", 1) + "    - type: http\n      concurrent: 10\n")
	a, _ := c.store.GetApp(c.ctx, "web")
	if a.Replicas != 3 {
		t.Errorf("replicas after redeploy with max 3: %d", a.Replicas)
	}
}

const zeroSpec = "name: web\nimage: nginx:1\ningress:\n  type: internal\n  port: 80\nscale:\n  min: 0\n  max: 4\n  idleAfter: 10m\n  rules:\n    - type: http\n      concurrent: 10\n"

func TestDecideScaleToZero(t *testing.T) {
	t.Parallel()
	sp, err := spec.Parse([]byte(zeroSpec))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a := store.App{Name: "web", ActiveRevision: "web--r1", TargetRevision: "web--r1", Replicas: 1, Spec: sp}
	reps := readyReplicas(1)
	res := resources{cpu: 100, mem: 256 << 20}

	// Quiet rules never go below one replica.
	st := &appScaling{since: now}
	if n, _, _ := decide(a, res, reps, loadOf(now, reps, 0), st); n != 1 {
		t.Errorf("rules took it to %d", n)
	}
	// A request a minute ago keeps it up, even ten minutes into the term.
	st.lastActive = now.Add(9 * time.Minute)
	if n, _, _ := decide(a, res, reps, loadOf(now.Add(10*time.Minute), reps, 0), st); n != 1 {
		t.Errorf("active app scaled to %d", n)
	}
	// Idle for idleAfter: zero.
	n, why, status := decide(a, res, reps, loadOf(now.Add(19*time.Minute+time.Second), reps, 0), st)
	if n != 0 || !strings.Contains(why, "no requests for 10m") || !strings.Contains(status.Message, "zero") {
		t.Errorf("idle: %d %q %v", n, why, status)
	}
	// A new leader waits idleAfter from its start.
	if n, _, _ := decide(a, res, reps, loadOf(now.Add(5*time.Minute), reps, 0), &appScaling{since: now}); n != 1 {
		t.Errorf("new leader scaled to %d", n)
	}
	// Without proxy samples, nothing is known to be idle.
	if n, _, _ := decide(a, res, reps, scaleInputs{now: now.Add(time.Hour), usage: newUsageStore()}, &appScaling{since: now}); n != 1 {
		t.Errorf("unmeasured app scaled to %d", n)
	}
	// At zero it holds until woken.
	zero := a
	zero.Replicas = 0
	if n, _, s := decide(zero, res, nil, loadOf(now, nil, 0), st); n != 0 || !strings.Contains(s.Message, "wakes") {
		t.Errorf("at zero: %d %v", n, s)
	}
}

func TestUsageLastActive(t *testing.T) {
	t.Parallel()
	u := newUsageStore()
	t0 := time.Now()
	u.set("n1", &armadav1.UsageReport{LoadMeasured: true, Load: []*armadav1.ReplicaLoad{{Id: "a", Requests: 3}, {Id: "b"}}}, t0)
	u.set("n1", &armadav1.UsageReport{LoadMeasured: true, Load: []*armadav1.ReplicaLoad{{Id: "a"}, {Id: "b"}}}, t0.Add(10*time.Second))
	if got := u.lastActive([]string{"a", "b"}); !got.Equal(t0) {
		t.Errorf("last active %v, want %v (a quiet report must not erase it)", got, t0)
	}
	u.set("n2", &armadav1.UsageReport{LoadMeasured: true, Load: []*armadav1.ReplicaLoad{{Id: "b", InFlight: 1}}}, t0.Add(20*time.Second))
	if got := u.lastActive([]string{"a", "b"}); !got.Equal(t0.Add(20 * time.Second)) {
		t.Errorf("last active %v", got)
	}
	if got := u.lastActive([]string{"c"}); !got.IsZero() {
		t.Errorf("unknown replica active at %v", got)
	}
}

func TestWakeApp(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	c.addNode("n1", "127.0.0.1")
	c.deploy(zeroSpec)
	c.eventually("1 running", func() bool { return len(c.running("web")) == 1 })
	if err := c.store.AutoscaleReplicas(c.ctx, "web", 1, 0, autoscaleActor); err != nil {
		t.Fatal(err)
	}
	c.eventually("scaled to zero", func() bool { return len(c.running("web")) == 0 })

	// Wakes for unknown or invalid apps change nothing.
	for _, app := range []string{"ghost", "Bad Name", "web\n", ""} {
		c.srv.wakeApp(c.ctx, "n1", app)
	}
	if a, _ := c.store.GetApp(c.ctx, "web"); a.Replicas != 0 {
		t.Fatalf("woken by a bad wake: %d", a.Replicas)
	}
	c.srv.wakeApp(c.ctx, "n1", "web")
	c.eventually("woken", func() bool { return len(c.running("web")) == 1 })
	evs, _ := c.store.ListEvents(c.ctx, time.Time{})
	woken := false
	for _, e := range evs {
		woken = woken || (e.Reason == "Woken" && e.Node == "n1")
	}
	if !woken {
		t.Errorf("no Woken event: %+v", evs)
	}
	// A second wake while it runs changes nothing.
	c.srv.wakeApp(c.ctx, "n1", "web")
	if a, _ := c.store.GetApp(c.ctx, "web"); a.Replicas != 1 {
		t.Errorf("replicas after a second wake: %d", a.Replicas)
	}
}

// queueOf reports a queue length read in reps[0], on its own node.
func queueOf(now time.Time, reps []store.Replica, length int64) scaleInputs {
	u := newUsageStore()
	u.set(reps[0].NodeID, &armadav1.UsageReport{Queues: []*armadav1.QueueLength{{Id: reps[0].ID, Length: length}}}, now)
	return scaleInputs{now: now, usage: u}
}

func TestDecideQueue(t *testing.T) {
	t.Parallel()
	now := time.Now()
	a := scaledApp(t, "    - type: queue\n      command: [queue-length]\n      length: 100\n", 2)
	reps := readyReplicas(2)
	res := resources{cpu: 500, mem: 256 << 20}

	// 700 items at 100 per replica: 7, capped at double the ready: 4.
	n, why, status := decide(a, res, reps, queueOf(now, reps, 700), &appScaling{since: now})
	if n != 4 || !strings.Contains(why, "queue 700 for 100 per replica") {
		t.Errorf("scale up: %d %q", n, why)
	}
	if r := status.Rules[0]; r.Type != "queue" || r.Current != 700 || r.Target != 100 || !r.Measured {
		t.Errorf("status %v", status.Rules)
	}
	// 210 for 2 replicas is within 10% of 200: hold.
	if n, _, _ := decide(a, res, reps, queueOf(now, reps, 210), &appScaling{since: now}); n != 2 {
		t.Errorf("within tolerance: %d", n)
	}
	// No reading: hold, never scale down.
	if n, _, s := decide(a, res, reps, scaleInputs{now: now, usage: newUsageStore()}, &appScaling{since: now}); n != 2 || !strings.Contains(s.Message, "not enough samples") {
		t.Errorf("unmeasured: %d %v", n, s)
	}
	// A reading from a node the replica is not on does not count.
	u := newUsageStore()
	u.set("elsewhere", &armadav1.UsageReport{Queues: []*armadav1.QueueLength{{Id: reps[0].ID, Length: 900}}}, now)
	if n, _, _ := decide(a, res, reps, scaleInputs{now: now, usage: u}, &appScaling{since: now}); n != 2 {
		t.Errorf("foreign reading: %d", n)
	}
	// An empty queue goes down to scale.min once the window has passed.
	st := &appScaling{since: now.Add(-2 * scaleDownWindow)}
	if n, _, _ := decide(a, res, reps, queueOf(now, reps, 0), st); n != 2 {
		t.Errorf("empty queue at min: %d", n)
	}
	// Absurd reports are bounded.
	if n, _, _ := decide(a, res, reps, queueOf(now, reps, 1<<62), &appScaling{since: now}); n != 4 {
		t.Errorf("huge queue: %d", n)
	}
}

func TestDecideSchedule(t *testing.T) {
	t.Parallel()
	res := resources{cpu: 500, mem: 256 << 20}
	reps := readyReplicas(2)
	// Every day from 08:00 UTC for 10 hours, at least 6.
	only := scaledApp(t, "    - type: schedule\n      schedule: \"0 8 * * *\"\n      duration: 10h\n      replicas: 6\n", 2)
	day := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	n, why, status := decide(only, res, reps, scaleInputs{now: day, usage: newUsageStore()}, &appScaling{since: day})
	if n != 4 || !strings.Contains(why, "schedule 6 until") {
		t.Errorf("open window: %d %q", n, why)
	}
	if r := status.Rules[0]; r.Current != 6 || r.Target != 6 || r.GetUntil().AsTime() != day.Add(9*time.Hour) {
		t.Errorf("status %v", r)
	}
	// Closed, with only schedules: back to scale.min after the window.
	night := time.Date(2026, 11, 11, 22, 0, 0, 0, time.UTC)
	big := only
	big.Replicas = 6
	if n, _, s := decide(big, res, readyReplicas(6), scaleInputs{now: night, usage: newUsageStore()}, &appScaling{since: night.Add(-time.Hour)}); n != 2 || s.Rules[0].Current != 0 {
		t.Errorf("closed window: %d %v", n, s)
	}
	// With a metric rule that has no samples, an open window still raises,
	// and a closed one holds.
	mixed := scaledApp(t, "    - type: cpu\n      utilization: 50\n    - type: schedule\n      schedule: \"0 8 * * *\"\n      duration: 10h\n      replicas: 3\n", 2)
	if n, _, _ := decide(mixed, res, reps, scaleInputs{now: day, usage: newUsageStore()}, &appScaling{since: day}); n != 3 {
		t.Errorf("open window, cpu unmeasured: %d", n)
	}
	if n, _, s := decide(mixed, res, reps, scaleInputs{now: night, usage: newUsageStore()}, &appScaling{since: night}); n != 2 || !strings.Contains(s.Message, "not enough samples") {
		t.Errorf("closed window, cpu unmeasured: %d %v", n, s)
	}
}

// An app that scales to zero stays up while a schedule window is open.
func TestDecideScheduleKeepsZeroAway(t *testing.T) {
	t.Parallel()
	sp, err := spec.Parse([]byte(zeroSpec + "    - type: schedule\n      schedule: \"0 8 * * *\"\n      duration: 10h\n      replicas: 2\n"))
	if err != nil {
		t.Fatal(err)
	}
	a := store.App{Name: "web", ActiveRevision: "web--r1", TargetRevision: "web--r1", Replicas: 1, Spec: sp}
	reps := readyReplicas(1)
	day := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	idle := &appScaling{since: day.Add(-time.Hour)}
	if n, _, _ := decide(a, resources{}, reps, loadOf(day, reps, 0), idle); n == 0 {
		t.Error("scaled to zero inside a schedule window")
	}
	night := time.Date(2026, 11, 11, 22, 0, 0, 0, time.UTC)
	if n, _, _ := decide(a, resources{}, reps, loadOf(night, reps, 0), &appScaling{since: night.Add(-time.Hour)}); n != 0 {
		t.Errorf("outside the window: %d, want 0", n)
	}
}

// A queue rule end to end: the agent runs the command in a replica, and the
// leader scales the app to the queue's length (ADR 0034).
func TestQueueCluster(t *testing.T) {
	t.Parallel()
	c := newCluster(t, func(cfg *Config) { cfg.AutoscaleInterval = 50 * time.Millisecond })
	d := c.addNode("n1", "127.0.0.1")
	var length atomic.Int64
	length.Store(450)
	d.ExecAppFunc = func(_ context.Context, _ string, o runtime.ExecOptions) (int, error) {
		if len(o.Cmd) == 0 || o.Cmd[0] != "queue-length" {
			return 1, nil
		}
		_, _ = fmt.Fprintf(o.Stdout, "%d\n", length.Load())
		return 0, nil
	}
	c.deploy("name: worker\nimage: w:1\nscale:\n  min: 1\n  max: 6\n  rules:\n    - type: queue\n      command: [queue-length]\n      length: 100\n")
	c.eventually("scaled to 5", func() bool {
		st, err := c.admin.Status(c.ctx, &armadav1.StatusRequest{App: "worker"})
		return err == nil && st.Apps[0].DesiredReplicas == 5
	})
	st, _ := c.admin.Status(c.ctx, &armadav1.StatusRequest{App: "worker"})
	if r := st.Apps[0].GetAutoscale().GetRules(); len(r) != 1 || r[0].GetCurrent() != 450 || r[0].GetTarget() != 100 {
		t.Errorf("rules %v", r)
	}
}

// A redis rule end to end: the URL comes from the app's secret, the agent
// dials the list's server from the replica, and the leader scales on LLEN.
func TestRedisCluster(t *testing.T) {
	t.Parallel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var auths atomic.Int32
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
					if err != nil {
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
					case args[0] == "AUTH" && args[1] == "pw":
						auths.Add(1)
						_, _ = conn.Write([]byte("+OK\r\n"))
					case args[0] == "LLEN" && args[1] == "jobs":
						_, _ = conn.Write([]byte(":260\r\n"))
					default:
						_, _ = conn.Write([]byte("-ERR\r\n"))
					}
				}
			}()
		}
	}()
	keys := withKeys(t)
	c := newCluster(t, func(cfg *Config) { keys(cfg); cfg.AutoscaleInterval = 50 * time.Millisecond })
	c.addNode("n1", "127.0.0.1")
	if _, err := c.admin.SetSecret(c.ctx, &armadav1.SetSecretRequest{App: "worker", Name: "redis-url", Value: []byte("redis://:pw@" + l.Addr().String())}); err != nil {
		t.Fatal(err)
	}
	c.deploy("name: worker\nimage: w:1\nscale:\n  min: 1\n  max: 6\n  rules:\n    - type: redis\n      urlSecretRef: redis-url\n      list: jobs\n      length: 100\n")
	c.eventually("scaled to 3", func() bool {
		st, err := c.admin.Status(c.ctx, &armadav1.StatusRequest{App: "worker"})
		return err == nil && st.Apps[0].DesiredReplicas == 3
	})
	if auths.Load() == 0 {
		t.Error("the agent never authenticated")
	}
}

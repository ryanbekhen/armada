package server

import (
	"fmt"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/store"
)

// Scenarios of scaling (ADR 0055, pull request 11), run against both
// servers by runParity: the autoscaler's evaluations of http, cpu,
// memory, queue, and schedule rules from fake agents' usage reports, the
// tolerance, the doubling cap, the bounds, the window before scaling
// down (also for a leader's first evaluation), the freeze during
// rollouts, scale to zero, wakes and their limit, the events of each,
// out-of-memory events, and the autoscale fields of Status. They move
// what autoscale_test.go checks onto both servers; those tests stay.

const parityScaled = "name: web\nimage: nginx:%s\ningress:\n  type: external\n  port: 80\nresources:\n  cpu: 500m\n  memory: 256Mi\nscale:\n  min: %d\n  max: 10\n  rules:\n"

func scaledYAML(image string, lo int, rules string) string {
	return fmt.Sprintf(parityScaled, image, lo) + rules
}

// scaleAgents records ready nodes and connects their agents.
func (sc *scenario) scaleAgents(ids ...string) map[string]*parityAgent {
	sc.t.Helper()
	out := map[string]*parityAgent{}
	for i, id := range ids {
		ip := fmt.Sprintf("10.0.0.%d", 11+i)
		sc.node(id, ip, 8000, 16<<30, map[string]string{"name": id})
		a, err := sc.connectAgent(id, sc.nodeAgent(id), &armadav1.Hello{PrivateIp: ip, CpuMillis: 8000, MemoryBytes: 16 << 30, Containers: true})
		if err != nil {
			sc.t.Fatal(err)
		}
		out[id] = a
	}
	return out
}

// usage sends a usage report through node's agent and waits until the
// server has it: a replica report sent after it on the same stream
// changes the message of one of the node's replicas, and the store shows
// it once the server read both.
func (sc *scenario) usage(a *parityAgent, u *armadav1.UsageReport) {
	sc.t.Helper()
	a.send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Usage{Usage: u}})
	sc.barrier(a)
}

// barrier waits until the server read what a's agent sent before.
func (sc *scenario) barrier(a *parityAgent) {
	sc.t.Helper()
	rs, err := sc.st.ListReplicas(sc.ctx, store.ReplicaFilter{NodeID: a.id})
	if err != nil {
		sc.t.Fatal(err)
	}
	var mark *store.Replica
	for i := range rs {
		if !rs[i].Done {
			mark = &rs[i]
			break
		}
	}
	if mark == nil {
		sc.t.Fatalf("%s: no replica on %s to mark", sc.sut.kind(), a.id)
	}
	sc.mu.Lock()
	sc.marks++
	msg := fmt.Sprintf("mark %d", sc.marks)
	sc.mu.Unlock()
	a.send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Report{Report: &armadav1.ReplicaReport{Replicas: []*armadav1.ReplicaState{{
		Id: mark.ID, State: mark.State, Ready: mark.Ready, ContainerId: mark.ContainerID, Address: mark.Address, Ip: mark.IP, Message: msg,
	}}}}})
	sc.eventually(msg, func() bool {
		rs, err := sc.st.ListReplicas(sc.ctx, store.ReplicaFilter{NodeID: a.id})
		if err != nil {
			return false
		}
		for _, r := range rs {
			if r.ID == mark.ID {
				return r.Message == msg
			}
		}
		return false
	})
}

// load is a proxy's report of per requests in progress for every replica
// of app that is not draining, with requests counted since the last one.
func (sc *scenario) load(app string, per, requests int64) *armadav1.UsageReport {
	sc.t.Helper()
	rs, err := sc.st.ListReplicas(sc.ctx, store.ReplicaFilter{App: app})
	if err != nil {
		sc.t.Fatal(err)
	}
	u := &armadav1.UsageReport{LoadMeasured: true}
	for _, r := range rs {
		if !r.Draining() {
			u.Load = append(u.Load, &armadav1.ReplicaLoad{Id: r.ID, InFlight: per, Requests: requests})
		}
	}
	return u
}

// onNode returns the IDs of app's replicas on node that are not
// draining, by ID.
func (sc *scenario) onNode(app, node string) []string {
	sc.t.Helper()
	rs, err := sc.st.ListReplicas(sc.ctx, store.ReplicaFilter{App: app, NodeID: node})
	if err != nil {
		sc.t.Fatal(err)
	}
	var out []string
	for _, r := range rs {
		if !r.Draining() {
			out = append(out, r.ID)
		}
	}
	return out
}

// evaluate runs an evaluation of the autoscaler and records the apps and
// the autoscale fields of each app's Status.
func (sc *scenario) evaluate(label string, apps ...string) {
	sc.t.Helper()
	sc.sut.autoscale(sc.t)
	sc.note(label, sc.appList())
	for _, app := range apps {
		sc.scaleStatus(label+" "+app, app)
	}
}

// scaleStatus records the autoscale fields of app's Status.
func (sc *scenario) scaleStatus(label, app string) {
	sc.t.Helper()
	resp, err := sc.admin.Status(sc.ctx, &armadav1.StatusRequest{App: app})
	if err != nil {
		sc.note(label, err)
		return
	}
	sc.note(fmt.Sprintf("%s (desired %d)", label, resp.Apps[0].GetDesiredReplicas()), resp.Apps[0].GetAutoscale())
}

// rollOut passes, serves, and waits out warm-ups until app's rollout is
// over.
func (sc *scenario) rollOut(label, app string) {
	sc.t.Helper()
	for i := range 20 {
		a, err := sc.st.GetApp(sc.ctx, app)
		if err != nil {
			sc.t.Fatal(err)
		}
		if !a.Rolling() {
			return
		}
		sc.pass(fmt.Sprintf("%s %d", label, i))
		sc.serve(app)
		sc.advance(time.Second)
	}
	sc.t.Fatalf("%s: %s still rolling out", sc.sut.kind(), app)
}

// TestDecideHTTP and TestAutoscaleCluster on both servers: an http rule
// through the proxies' load, summed across nodes, within the tolerance,
// at most double the ready replicas and scale.max per step, the window
// before scaling down, its events, and Status's autoscale fields.
func TestParityAutoscaleHTTP(t *testing.T) {
	runParity(t, parityConfig{drain: time.Second}, func(sc *scenario) {
		agents := sc.scaleAgents("n1", "n2")
		sc.deploy("deploy", scaledYAML("1", 2, "    - type: http\n      concurrent: 10\n"))
		sc.scaleStatus("before any evaluation", "web")
		sc.pass("placed")
		sc.evaluate("none ready", "web")
		sc.serve("web")
		sc.evaluate("no samples", "web")
		sc.usage(agents["n1"], sc.load("web", 25, 3))
		sc.evaluate("25 per replica", "web")
		sc.pass("scaled up")
		sc.serve("web")
		sc.usage(agents["n1"], sc.load("web", 10, 0))
		sc.evaluate("within the tolerance", "web")
		// Each proxy sees half of what the replicas serve.
		sc.usage(agents["n1"], sc.load("web", 15, 0))
		sc.usage(agents["n2"], sc.load("web", 15, 0))
		sc.evaluate("two proxies", "web")
		sc.pass("doubled")
		sc.serve("web")
		sc.usage(agents["n1"], sc.load("web", 1000, 0))
		sc.evaluate("at most max", "web")
		sc.pass("at max")
		sc.serve("web")
		sc.usage(agents["n1"], sc.load("web", 0, 0))
		sc.usage(agents["n2"], sc.load("web", 0, 0))
		sc.evaluate("quiet, but higher recently", "web")
		sc.advance(2 * time.Minute)
		sc.usage(agents["n1"], sc.load("web", 0, 0))
		sc.evaluate("still within the window", "web")
		sc.advance(3*time.Minute + 30*time.Second)
		sc.evaluate("the samples are old", "web")
		sc.usage(agents["n1"], sc.load("web", 0, 0))
		sc.evaluate("down to the highest of the window", "web")
		sc.pass("scaling down")
		sc.later("drained", 2*time.Second)
		sc.status("status", "web")
		sc.keyspace("keyspace")
	})
}

// TestDecideHolds on both servers: a rollout freezes the count, and a
// leader's first evaluation waits a full window before scaling down, as a
// new leader does.
func TestParityAutoscaleRollout(t *testing.T) {
	runParity(t, parityConfig{drain: time.Second, warmup: time.Second}, func(sc *scenario) {
		agents := sc.scaleAgents("n1", "n2")
		rule := "    - type: http\n      concurrent: 10\n"
		sc.deploy("deploy with min 4", scaledYAML("1", 4, rule))
		sc.pass("placed")
		sc.serve("web")
		sc.deploy("min 2 keeps the count", scaledYAML("2", 2, rule))
		sc.rollOut("rolling out", "web")
		sc.later("old drained", 2*time.Second)
		sc.usage(agents["n1"], sc.load("web", 0, 0))
		sc.evaluate("the first evaluation watches first", "web")
		sc.deploy("v3", scaledYAML("3", 2, rule))
		sc.pass("v3 surge")
		sc.usage(agents["n1"], sc.load("web", 50, 0))
		sc.evaluate("frozen during the rollout", "web")
		sc.rollOut("v3 rolling out", "web")
		sc.later("v2 drained", 2*time.Second)
		sc.advance(5 * time.Minute)
		sc.usage(agents["n1"], sc.load("web", 0, 0))
		sc.evaluate("after the window", "web")
		sc.pass("down")
		sc.keyspace("keyspace")
	})
}

// TestDecideHolds and TestDecideHighestRule on both servers: cpu and
// memory rules count samples only from a replica's own node and only
// when at least half the ready replicas were sampled; the rule asking for
// the most wins; out-of-memory kills reported by a replica's own node are
// events.
func TestParityAutoscaleResources(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		agents := sc.scaleAgents("n1", "n2")
		sc.deploy("deploy", scaledYAML("1", 2, "    - type: cpu\n      utilization: 50\n    - type: memory\n      utilization: 50\n"))
		sc.pass("placed")
		sc.serve("web")
		sc.evaluate("no samples", "web")
		on1, on2 := sc.onNode("web", "n1"), sc.onNode("web", "n2")
		sc.note("spread", []int{len(on1), len(on2)})
		sample := func(ids []string, cpu, mem int64) []*armadav1.ReplicaUsage {
			var out []*armadav1.ReplicaUsage
			for _, id := range ids {
				out = append(out, &armadav1.ReplicaUsage{Id: id, CpuMillis: cpu, MemoryBytes: mem})
			}
			return out
		}
		// n1 reports n2's replica: not its own.
		sc.usage(agents["n1"], &armadav1.UsageReport{Replicas: sample(on2, 500, 256<<20)})
		sc.evaluate("a foreign sample", "web")
		sc.usage(agents["n1"], &armadav1.UsageReport{Replicas: sample(on1, 500, 192<<20)})
		sc.usage(agents["n2"], &armadav1.UsageReport{Replicas: sample(on2, 250, 256<<20)})
		sc.evaluate("memory asks for more", "web")
		sc.pass("scaled up")
		sc.serve("web")
		on1, on2 = sc.onNode("web", "n1"), sc.onNode("web", "n2")
		// One of four sampled: fewer than half.
		sc.usage(agents["n1"], &armadav1.UsageReport{})
		sc.usage(agents["n2"], &armadav1.UsageReport{Replicas: sample(on2[:1], 500, 256<<20)})
		sc.evaluate("fewer than half sampled", "web")
		sc.usage(agents["n1"], &armadav1.UsageReport{Replicas: sample(on1, 260, 128<<20)})
		sc.usage(agents["n2"], &armadav1.UsageReport{Replicas: sample(on2, 240, 130<<20)})
		sc.evaluate("at the target", "web")
		sc.usage(agents["n1"], &armadav1.UsageReport{Replicas: sample(on1, 50, 32<<20)})
		sc.usage(agents["n2"], &armadav1.UsageReport{Replicas: sample(on2, 50, 32<<20)})
		sc.evaluate("lower, within the window", "web")

		// Memory kills: only the replica's own node is believed, once a
		// pass has seen the replica.
		sc.pass("owners")
		oom := []*armadav1.ReplicaUsage{{Id: on1[0], OomKills: 3}, {Id: on2[0], OomKills: 2}}
		sc.usage(agents["n1"], &armadav1.UsageReport{Replicas: oom})
		sc.usage(agents["n2"], &armadav1.UsageReport{Replicas: []*armadav1.ReplicaUsage{{Id: on2[0], OomKills: 1 << 40}}})
		sc.note("out of memory", []int{sc.eventCount(on1[0], "OutOfMemory"), sc.eventCount(on2[0], "OutOfMemory")})
		sc.keyspace("keyspace")
	})
}

// TestDecideQueue, TestQueueCluster, and TestRedisCluster on both
// servers: queue rules read in replicas (the command and redis rules'
// probes in the assignments, with the URL from the secret), lengths only
// from a replica's own node and of the rule's own type, the tolerance,
// the doubling cap, bounded reports, stale samples, and an empty queue
// back to scale.min after the window.
func TestParityAutoscaleQueue(t *testing.T) {
	runParity(t, parityConfig{masterKey: true, drain: time.Second}, func(sc *scenario) {
		agents := sc.scaleAgents("n1")
		_, err := sc.admin.SetSecret(sc.ctx, &armadav1.SetSecretRequest{App: "mailer", Name: "redis-url", Value: []byte("redis://:pw@10.0.0.50:6379")})
		sc.note("secret", err)
		sc.deploy("worker", "name: worker\nimage: w:1\nscale:\n  min: 1\n  max: 6\n  rules:\n    - type: queue\n      command: [queue-length]\n      length: 100\n")
		sc.deploy("mailer", "name: mailer\nimage: m:1\nscale:\n  min: 1\n  max: 6\n  rules:\n    - type: redis\n      urlSecretRef: redis-url\n      list: jobs\n      length: 50\n")
		sc.pass("placed")
		sc.serve("worker")
		sc.serve("mailer")
		sc.note("n1 assignment", agents["n1"].assignment())
		sc.evaluate("no readings", "worker", "mailer")
		queues := func(worker, mailer int64, mailerType string) *armadav1.UsageReport {
			u := &armadav1.UsageReport{}
			for _, id := range sc.onNode("worker", "n1")[:1] {
				u.Queues = append(u.Queues, &armadav1.QueueLength{Id: id, Length: worker})
			}
			for _, id := range sc.onNode("mailer", "n1")[:1] {
				u.Queues = append(u.Queues, &armadav1.QueueLength{Id: id, Length: mailer, Type: mailerType})
			}
			return u
		}
		sc.usage(agents["n1"], queues(450, 260, "rabbitmq"))
		sc.evaluate("450 and another rule's type", "worker", "mailer")
		sc.usage(agents["n1"], queues(450, 260, "redis"))
		sc.evaluate("doubling", "worker", "mailer")
		sc.pass("scaled")
		sc.serve("worker")
		sc.serve("mailer")
		sc.usage(agents["n1"], queues(210, 1<<62, "redis"))
		sc.evaluate("within the tolerance and bounded", "worker", "mailer")
		sc.pass("mailer up")
		sc.serve("mailer")
		sc.advance(36 * time.Second)
		sc.evaluate("stale", "worker", "mailer")
		sc.usage(agents["n1"], queues(0, 0, "redis"))
		sc.evaluate("empty, within the window", "worker", "mailer")
		sc.advance(5*time.Minute + time.Second)
		sc.usage(agents["n1"], queues(0, 0, "redis"))
		sc.evaluate("empty after the window", "worker", "mailer")
		sc.pass("down")
		sc.keyspace("keyspace")
	})
}

// TestDecideSchedule, TestDecideScheduleKeepsZeroAway, and
// TestDecideScheduleWakesZero on both servers: windows in a time zone
// across days and fires, windows that chain, a metric rule without
// samples beside an open window, an app that scales to zero kept up by a
// window and woken by one, and back to scale.min or zero once the windows
// close.
func TestParityAutoscaleSchedule(t *testing.T) {
	runParity(t, parityConfig{drain: time.Second}, func(sc *scenario) {
		agents := sc.scaleAgents("n1")
		sc.deploy("office", "name: office\nimage: o:1\nscale:\n  min: 1\n  max: 8\n  rules:\n    - type: schedule\n      schedule: \"0 8 * * 1-5\"\n      timeZone: Asia/Jakarta\n      duration: 10h\n      replicas: 4\n")
		sc.deploy("batch", "name: batch\nimage: b:1\nscale:\n  min: 1\n  max: 8\n  rules:\n    - type: cpu\n      utilization: 50\n    - type: schedule\n      schedule: \"*/30 * * * *\"\n      duration: 45m\n      replicas: 3\n")
		sc.deploy("night", "name: night\nimage: n:1\ningress:\n  type: internal\n  port: 80\nscale:\n  min: 0\n  max: 4\n  idleAfter: 10m\n  rules:\n    - type: http\n      concurrent: 10\n    - type: schedule\n      schedule: \"0 22 * * *\"\n      duration: 2h\n      replicas: 2\n")
		apps := []string{"office", "batch", "night"}
		serve := func() {
			for _, a := range apps {
				sc.serve(a)
			}
		}
		sc.pass("placed")
		serve()
		// Friday 10:00 UTC, 17:00 in Jakarta.
		sc.evaluate("friday afternoon", apps...)
		sc.pass("up")
		serve()
		sc.evaluate("friday afternoon again", apps...)
		sc.pass("up again")
		serve()
		sc.advance(time.Hour)
		sc.usage(agents["n1"], sc.load("night", 0, 0))
		sc.evaluate("friday evening", apps...)
		sc.pass("down")
		sc.later("drained", 2*time.Second)
		sc.evaluate("at zero", "night")
		// Friday 22:01 UTC: night's window opens.
		sc.advance(11*time.Hour + time.Minute)
		sc.evaluate("night's window", apps...)
		sc.pass("night woken")
		serve()
		sc.advance(30 * time.Minute)
		sc.usage(agents["n1"], sc.load("night", 0, 0))
		sc.evaluate("kept up in its window", apps...)
		// Saturday 00:31 UTC: closed, idle.
		sc.advance(2 * time.Hour)
		sc.usage(agents["n1"], sc.load("night", 0, 0))
		sc.evaluate("after night's window", apps...)
		sc.pass("night down")
		sc.later("night drained", 2*time.Second)
		// Monday 01:00 UTC, 08:00 in Jakarta.
		sc.advance(48*time.Hour + 29*time.Minute)
		sc.evaluate("monday morning", apps...)
		sc.keyspace("keyspace")
	})
}

const parityZero = "name: web\nimage: nginx:1\ningress:\n  type: internal\n  port: 80\nscale:\n  min: 0\n  max: 4\n  idleAfter: 10m\n  rules:\n    - type: http\n      concurrent: 10\n"

// TestDecideScaleToZero, TestWakeApp, and TestWakeReplacesTheZeroMessage
// on both servers: an idle app goes to zero only once its proxies were
// read and idleAfter passed since its last request and the leader's first
// look, wakes raise it from zero to one and nothing else, and each node's
// wakes are limited.
func TestParityScaleToZero(t *testing.T) {
	runParity(t, parityConfig{drain: time.Second}, func(sc *scenario) {
		agents := sc.scaleAgents("n1", "n2")
		sc.deploy("web", parityZero)
		// pin keeps a replica on n1, to mark what n1's agent sent.
		sc.deploy("pin", "name: pin\nimage: p:1\nplacement:\n  require:\n    name: n1\n")
		sc.pass("placed")
		sc.serve("web")
		sc.serve("pin")
		sc.evaluate("no proxy read", "web")
		sc.usage(agents["n1"], sc.load("web", 0, 5))
		sc.evaluate("a request", "web")
		sc.advance(9 * time.Minute)
		sc.usage(agents["n1"], sc.load("web", 0, 0))
		sc.evaluate("quiet for 9 minutes", "web")
		sc.advance(time.Minute)
		sc.usage(agents["n1"], sc.load("web", 0, 0))
		sc.evaluate("idle", "web")
		sc.pass("to zero")
		sc.later("drained", 2*time.Second)
		sc.evaluate("at zero", "web")

		wake := func(a *parityAgent, apps ...string) {
			for _, app := range apps {
				a.send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Wake{Wake: &armadav1.Wake{App: app}}})
			}
		}
		// Wakes for unknown, invalid, and fixed apps change nothing.
		wake(agents["n1"], "Bad Name", "", "web\n", "ghost", "pin")
		sc.barrier(agents["n1"])
		sc.note("bad wakes", sc.appList())
		wake(agents["n1"], "web", "web")
		sc.barrier(agents["n1"])
		sc.note("woken", sc.appList())
		sc.scaleStatus("woken status", "web")
		sc.pass("starting")
		sc.serve("web")
		sc.usage(agents["n1"], sc.load("web", 0, 0))
		sc.evaluate("up again", "web")

		// Back to zero, then n1's wakes run out; n2 still wakes it.
		sc.advance(10 * time.Minute)
		sc.usage(agents["n1"], sc.load("web", 0, 0))
		sc.evaluate("idle again", "web")
		sc.pass("to zero again")
		sc.later("drained again", 2*time.Second)
		ghosts := make([]string, 16)
		for i := range ghosts {
			ghosts[i] = "ghost"
		}
		wake(agents["n1"], ghosts...)
		wake(agents["n1"], "web")
		sc.barrier(agents["n1"])
		sc.note("n1 limited", sc.appList())
		before := sc.eventCount("web", "Woken")
		wake(agents["n2"], "web")
		sc.eventually("woken by n2", func() bool { return sc.eventCount("web", "Woken") > before })
		sc.note("n2 woke it", sc.appList())
		sc.scaleStatus("n2 status", "web")
		sc.keyspace("keyspace")
	})
}

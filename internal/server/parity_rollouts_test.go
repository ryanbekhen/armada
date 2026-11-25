package server

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/store"
)

// Scenarios of placement and rollouts (ADR 0055, pull request 9), run
// against both servers by runParity: scheduling, placement, rollouts,
// drains, evacuation, self-healing, rebalancing, removal, secrets'
// rollouts, traffic splits, and the AdminService methods of those parts.
// Most drive the store and the clock by hand and run every pass
// themselves, as rollout_clock_test.go does; TestParityRolloutWithAgents
// goes through agents' reports.

// node records a ready node with capacity, labels, and what its agent
// runs (Containers, Volumes, NFS).
func (sc *scenario) node(id, ip string, cpu, mem int64, labels map[string]string, caps ...string) {
	sc.t.Helper()
	if err := sc.st.UpsertNode(sc.ctx, store.Node{ID: id, PrivateIP: ip, State: store.NodeReady, CPUMillis: cpu, MemoryBytes: mem, Labels: labels}); err != nil {
		sc.t.Fatal(err)
	}
	if len(caps) > 0 {
		st := store.NodeStatus{State: store.NodeReady, LastSeen: sc.clock.now(), CPUMillis: cpu, MemoryBytes: mem,
			Containers: slices.Contains(caps, "containers"), Volumes: slices.Contains(caps, "volumes"), NFS: slices.Contains(caps, "nfs")}
		if err := sc.st.SetNodeStatus(sc.ctx, id, st); err != nil {
			sc.t.Fatal(err)
		}
	}
}

// deploy deploys a spec through the API as the scenario's admin.
func (sc *scenario) deploy(label, y string) *armadav1.DeployResponse {
	sc.t.Helper()
	resp, err := sc.admin.Deploy(sc.ctx, &armadav1.DeployRequest{Spec: []byte(y)})
	sc.answer(label, resp, err)
	return resp
}

// replicaList is the store's replicas, one line each, by ID.
func (sc *scenario) replicaList() []string {
	sc.t.Helper()
	rs, err := sc.st.ListReplicas(sc.ctx, store.ReplicaFilter{})
	if err != nil {
		sc.t.Fatal(err)
	}
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		line := fmt.Sprintf("%s %s on %s %s", r.ID, r.Revision, r.NodeID, r.State)
		if r.Ready {
			line += " ready"
		}
		if r.Draining() {
			line += " draining"
		}
		if r.Moving() {
			line += " moving"
		}
		out = append(out, line)
	}
	slices.Sort(out)
	return out
}

// appList is the store's apps, one line each.
func (sc *scenario) appList() []string {
	sc.t.Helper()
	as, err := sc.st.ListApps(sc.ctx)
	if err != nil {
		sc.t.Fatal(err)
	}
	var out []string
	for _, a := range as {
		line := fmt.Sprintf("%s active=%s target=%s replicas=%d state=%q message=%q", a.Name, a.ActiveRevision, a.TargetRevision, a.Replicas, a.RolloutState, a.RolloutMessage)
		for _, t := range a.Traffic {
			line += fmt.Sprintf(" %s:%d:%s", t.Revision, t.Weight, t.Label)
		}
		if a.Removing {
			line += " removing"
		}
		out = append(out, line)
	}
	return out
}

// pass runs a pass and records the apps and replicas after it.
func (sc *scenario) pass(label string) {
	sc.t.Helper()
	sc.sut.reconcile(sc.t)
	sc.note(label, map[string]any{"apps": sc.appList(), "replicas": sc.replicaList()})
}

// later moves the clock by d, then passes.
func (sc *scenario) later(label string, d time.Duration) {
	sc.t.Helper()
	sc.advance(d)
	sc.pass(label)
}

// replicaOf returns the replica whose ID starts with prefix (the last
// made, by ID).
func (sc *scenario) replicaOf(prefix string) store.Replica {
	sc.t.Helper()
	rs, err := sc.st.ListReplicas(sc.ctx, store.ReplicaFilter{})
	if err != nil {
		sc.t.Fatal(err)
	}
	var found []store.Replica
	for _, r := range rs {
		if strings.HasPrefix(r.ID, prefix) && !r.Draining() {
			found = append(found, r)
		}
	}
	if len(found) == 0 {
		sc.t.Fatalf("%s: no replica %s*: %v", sc.sut.kind(), prefix, sc.replicaList())
	}
	return found[len(found)-1]
}

// report writes a replica's status as its agent would report it.
func (sc *scenario) report(r store.Replica, state string, ready bool, message string) {
	sc.t.Helper()
	n, err := sc.st.GetNode(sc.ctx, r.NodeID)
	if err != nil {
		sc.t.Fatal(err)
	}
	st := store.ReplicaStatus{ID: r.ID, State: state, Ready: ready, Message: message, ContainerID: "c-" + r.ID}
	if state == store.ReplicaRunning {
		port := 31000
		for _, c := range r.ID {
			port += int(c)
		}
		st.Address = fmt.Sprintf("%s:%d", n.PrivateIP, port)
	}
	if err := sc.st.UpdateReplicaStatus(sc.ctx, r.NodeID, st); err != nil {
		sc.t.Fatal(err)
	}
}

// serve reports every pending or starting replica of app running and
// ready.
func (sc *scenario) serve(app string) {
	sc.t.Helper()
	rs, err := sc.st.ListReplicas(sc.ctx, store.ReplicaFilter{App: app})
	if err != nil {
		sc.t.Fatal(err)
	}
	for _, r := range rs {
		if !r.Ready && !r.Draining() {
			sc.report(r, store.ReplicaRunning, true, "")
		}
	}
}

// status records Status for app ("" for all).
func (sc *scenario) status(label, app string) {
	sc.t.Helper()
	resp, err := sc.admin.Status(sc.ctx, &armadav1.StatusRequest{App: app})
	sc.answer(label, resp, err)
}

const parityWeb = "name: web\nimage: nginx:%s\ningress:\n  type: external\n  port: 80\nscale:\n  min: %d\n"

func webYAML(image string, n int) string { return fmt.Sprintf(parityWeb, image, n) }

// A deploy and a rollout through agents: assignments, reports of states,
// readiness, and addresses, the warm-up, retirement, drains, a rollback,
// a restart, and the read methods on the way.
func TestParityRolloutWithAgents(t *testing.T) {
	runParity(t, parityConfig{progress: time.Minute}, func(sc *scenario) {
		for _, n := range []store.Node{{ID: "n1", PrivateIP: "10.0.0.11"}, {ID: "n2", PrivateIP: "10.0.0.12"}} {
			if err := sc.st.UpsertNode(sc.ctx, n); err != nil {
				t.Fatal(err)
			}
		}
		agents := map[string]*parityAgent{}
		for id, ip := range map[string]string{"n1": "10.0.0.11", "n2": "10.0.0.12"} {
			a, err := sc.connectAgent(id, sc.nodeAgent(id), &armadav1.Hello{PrivateIp: ip, CpuMillis: 2000, MemoryBytes: 4 << 30})
			if err != nil {
				t.Fatal(err)
			}
			agents[id] = a
		}
		// Each agent reports what it was assigned running and ready.
		report := func(label string) {
			for _, id := range []string{"n1", "n2"} {
				a := agents[id]
				as := a.assignment()
				sc.note(label+" "+id, as)
				var states []*armadav1.ReplicaState
				for i, r := range as.GetReplicas() {
					states = append(states, &armadav1.ReplicaState{Id: r.Id, State: "running", Ready: true, ContainerId: "c-" + r.Id,
						Address: fmt.Sprintf("10.0.0.1%s:%d", id[1:], 32000+i)})
				}
				a.send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Report{Report: &armadav1.ReplicaReport{Replicas: states}}})
				sc.eventually("report of "+id, func() bool {
					rs, err := sc.st.ListReplicas(sc.ctx, store.ReplicaFilter{NodeID: id})
					if err != nil {
						return false
					}
					for _, s := range states {
						if !slicesContainsState(rs, s.Id, "running") {
							return false
						}
					}
					return true
				})
			}
		}
		_, err := sc.admin.SetClusterConfig(sc.ctx, &armadav1.SetClusterConfigRequest{SetRootDomain: true, Config: &armadav1.ClusterConfig{RootDomain: "apps.example.com"}})
		sc.note("root domain", err)
		sc.deploy("deploy v1", webYAML("1", 2))
		sc.pass("v1 placed")
		report("v1")
		sc.later("v1 warmed up", 5*time.Second)
		sc.status("status of web", "web")
		apps, err := sc.admin.ListApps(sc.ctx, &armadav1.ListAppsRequest{})
		sc.answer("list apps", apps, err)

		sc.deploy("deploy v2", webYAML("2", 2))
		sc.pass("surge")
		report("v2 first")
		sc.later("first v2 serving", 5*time.Second)
		sc.pass("second v2")
		report("v2 second")
		sc.later("rollout done", 5*time.Second)
		sc.later("drains end", 11*time.Second)
		revs, err := sc.admin.ListRevisions(sc.ctx, &armadav1.ListRevisionsRequest{App: "web"})
		sc.answer("revisions", revs, err)
		spec, err := sc.admin.GetAppSpec(sc.ctx, &armadav1.GetAppSpecRequest{App: "web"})
		sc.answer("spec", spec, err)

		rb, err := sc.admin.Rollback(sc.ctx, &armadav1.RollbackRequest{App: "web"})
		sc.answer("rollback", rb, err)
		sc.pass("rolling back")
		report("v1 again")
		sc.later("rolled back", 5*time.Second)
		rs, err := sc.admin.RestartApp(sc.ctx, &armadav1.RestartAppRequest{App: "web"})
		sc.answer("restart", rs, err)
		sc.pass("restarting")
		sc.status("status while restarting", "")
		sc.keyspace("keyspace")
	})
}

// TestRolloutWaitsForWarmupAndDrain, TestRolloutDeadline, and
// TestDrainFromSpec on both servers.
func TestParityRolloutClock(t *testing.T) {
	runParity(t, parityConfig{drain: 10 * time.Second, warmup: 3 * time.Second, progress: time.Minute}, func(sc *scenario) {
		sc.node("n1", "10.0.0.2", 0, 0, nil)
		sc.deploy("v1", "name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\n")
		sc.pass("v1 placed")
		sc.serve("web")
		sc.deploy("v2", "name: web\nimage: nginx:2\ningress:\n  type: external\n  port: 80\n")
		sc.later("v2 placed", 10*time.Second)
		sc.serve("web")
		sc.later("v2 warming up", 3*time.Second-time.Millisecond)
		sc.later("v2 warmed up", time.Millisecond)
		sc.later("still draining", 10*time.Second-time.Millisecond)
		sc.later("drained", time.Millisecond)

		// A rollout that never serves is aborted at the deadline, and the
		// message names why its replica fails.
		sc.deploy("v3 broken", "name: web\nimage: nginx:broken\ningress:\n  type: external\n  port: 80\n")
		sc.pass("v3 placed")
		sc.report(sc.replicaOf("web-r3-"), store.ReplicaFailed, false, "pull access denied")
		sc.later("before the deadline", time.Minute-time.Millisecond)
		sc.later("deadline", time.Millisecond)
		sc.status("failed rollout", "web")

		// The spec's own drain.
		sc.deploy("v4 with drain", "name: web\nimage: nginx:4\ndrain: 30s\ningress:\n  type: external\n  port: 80\n")
		sc.pass("v4 placed")
		sc.serve("web")
		sc.later("v4 serves", 3*time.Second)
		sc.later("v2 drains for v2's 10s", 10*time.Second)
		sc.deploy("v5", "name: web\nimage: nginx:5\ndrain: 30s\ningress:\n  type: external\n  port: 80\n")
		sc.pass("v5 placed")
		sc.serve("web")
		sc.later("v5 serves", 3*time.Second)
		sc.later("v4 still draining", 29*time.Second)
		sc.later("v4 drained", time.Second)
		sc.keyspace("keyspace")
	})
}

// TestRolloutAtMaxReplicas, TestUpdateKeepsOldReplicasWarmingUp, and
// TestRolloutFreesReplicasThatNeverServed on both servers, with probes
// that lengthen the deadline.
func TestParityRolloutSurge(t *testing.T) {
	runParity(t, parityConfig{warmup: 3 * time.Second, progress: time.Minute}, func(sc *scenario) {
		sc.node("n1", "10.0.0.2", 0, 0, nil)
		sc.node("n2", "10.0.0.3", 0, 0, nil)
		sc.deploy("v1", webYAML("1", 3))
		sc.pass("three placed")
		sc.serve("web")
		sc.later("serving", 5*time.Second)
		sc.deploy("v2", webYAML("2", 3))
		sc.pass("one surge replica")
		sc.serve("web")
		// A new deploy while v2 warms up: v2's replica goes, v1 keeps
		// serving.
		sc.deploy("v3", "name: web\nimage: nginx:3\ningress:\n  type: external\n  port: 80\nscale:\n  min: 3\nprobes:\n  readiness:\n    path: /\n    initialDelay: 10s\n    period: 5s\n    failureThreshold: 2\n")
		sc.later("v3 placed", time.Second)
		for i := 0; i < 4; i++ {
			sc.serve("web")
			sc.later(fmt.Sprintf("v3 step %d", i), 4*time.Second)
		}
		sc.later("done", 20*time.Second)
		// A first revision whose replicas never serve is replaced by the
		// next one at once.
		sc.deploy("api v1", "name: api\nimage: api:1\nscale:\n  min: 2\n")
		sc.pass("api placed")
		sc.report(sc.replicaOf("api-r1-"), store.ReplicaFailed, false, "boom")
		sc.deploy("api v2", "name: api\nimage: api:2\nscale:\n  min: 2\n")
		sc.pass("api v2")
		sc.serve("api")
		sc.later("api v2 serving", 4*time.Second)
		sc.keyspace("keyspace")
	})
}

// TestFailedReplicaMoves and TestFailedReplicaWaits: a replica that keeps
// failing to start moves to another node after a minute, one at a time.
func TestParityFailedReplicaMoves(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		sc.node("n1", "10.0.0.2", 0, 0, nil)
		sc.deploy("v1", "name: web\nimage: nginx:1\nscale:\n  min: 2\n")
		sc.pass("placed")
		for _, r := range []string{"web-r1-aaaab", "web-r1-aaaac"} {
			sc.report(sc.replicaOf(r), store.ReplicaFailed, false, "no address left")
		}
		sc.pass("failing, no other node")
		sc.later("a minute on, nowhere to go", time.Minute)
		sc.node("n2", "10.0.0.3", 0, 0, nil)
		sc.later("one moves", time.Second)
		sc.later("the next one", time.Second)
		sc.keyspace("keyspace")
	})
}

// Placement (ADR 0014): required labels, restricted nodes, image
// platforms, capacity, a full subnet, and the messages that explain each,
// on both servers (placement_test.go, platforms_test.go).
func TestParityPlacement(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		sc.node("n1", "10.0.0.2", 1000, 1<<30, map[string]string{"disk": "ssd"})
		sc.node("n2", "10.0.0.3", 1000, 1<<30, map[string]string{"disk": "hdd"})
		sc.node("n3", "10.0.0.4", 4000, 8<<30, map[string]string{"gpu": "yes"})
		if err := sc.st.SetNodeRestricted(sc.ctx, "n3", true, "t"); err != nil {
			t.Fatal(err)
		}
		sc.deploy("ssd app", "name: db\nimage: db:1\nplacement:\n  require:\n    disk: ssd\nscale:\n  min: 2\nresources:\n  memory: 400Mi\n")
		sc.deploy("gpu app", "name: ml\nimage: ml:1\nplacement:\n  require:\n    gpu: \"yes\"\n")
		sc.deploy("plain app", "name: web\nimage: web:1\nscale:\n  min: 3\nresources:\n  cpu: 400m\n")
		sc.deploy("big app", "name: big\nimage: big:1\nresources:\n  memory: 2Gi\n")
		sc.deploy("nowhere", "name: lost\nimage: x:1\nplacement:\n  require:\n    zone: mars\n")
		sc.pass("placed")
		sc.status("messages", "")
		sc.status("db", "db")
		sc.status("big", "big")
		// The image turns out to be built for arm64 only.
		if err := sc.st.SetRevisionPlatforms(sc.ctx, "web--r1", []string{"linux/arm64"}); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"n1", "n2"} {
			if err := sc.st.SetNodeStatus(sc.ctx, id, store.NodeStatus{State: store.NodeReady, LastSeen: sc.clock.now(), CPUMillis: 1000, MemoryBytes: 1 << 30, OS: "linux", Arch: "amd64"}); err != nil {
				t.Fatal(err)
			}
		}
		sc.pass("wrong platform")
		sc.status("platform message", "web")
		// A label change moves db away once another node fits.
		if _, err := sc.st.SetNodeLabels(sc.ctx, "n2", map[string]string{"disk": "ssd"}, nil, "t"); err != nil {
			t.Fatal(err)
		}
		if _, err := sc.st.SetNodeLabels(sc.ctx, "n1", map[string]string{"disk": "hdd"}, nil, "t"); err != nil {
			t.Fatal(err)
		}
		sc.pass("labels changed")
		sc.serve("db")
		sc.later("db moved", 5*time.Second)
		sc.status("after the move", "")
		sc.keyspace("keyspace")
	})
}

// Cordons and lost nodes (ADR 0008): evacuation while enough others
// serve, the partition guard, and a node's return (nodes_test.go).
func TestParityEvacuation(t *testing.T) {
	runParity(t, parityConfig{nodeLost: time.Minute}, func(sc *scenario) {
		sc.node("n1", "10.0.0.2", 0, 0, nil)
		sc.node("n2", "10.0.0.3", 0, 0, nil)
		sc.node("n3", "10.0.0.4", 0, 0, nil)
		sc.deploy("v1", webYAML("1", 3))
		sc.pass("spread")
		sc.serve("web")
		sc.later("serving", 5*time.Second)
		_, err := sc.admin.CordonNode(sc.ctx, &armadav1.CordonNodeRequest{Node: "n1", Cordoned: true})
		sc.note("cordon n1", err)
		sc.pass("replacement placed")
		sc.serve("web")
		sc.later("evacuated", 5*time.Second)
		sc.later("drained", 11*time.Second)
		_, err = sc.admin.CordonNode(sc.ctx, &armadav1.CordonNodeRequest{Node: "n1"})
		sc.note("uncordon n1", err)

		// n2 goes away: first away (drains wait), then lost.
		if err := sc.st.SetNodeStatus(sc.ctx, "n2", store.NodeStatus{State: store.NodeUnknown, LastSeen: sc.clock.now()}); err != nil {
			t.Fatal(err)
		}
		sc.later("n2 away", 30*time.Second)
		sc.later("n2 lost", 30*time.Second)
		sc.serve("web")
		sc.later("replacements serve", 5*time.Second)
		sc.status("status with a lost node", "")
		// Two of three lost: the control plane is more likely cut off.
		if err := sc.st.SetNodeStatus(sc.ctx, "n3", store.NodeStatus{State: store.NodeUnknown, LastSeen: sc.clock.now()}); err != nil {
			t.Fatal(err)
		}
		sc.later("n3 lost too", 2*time.Minute)
		for _, id := range []string{"n2", "n3"} {
			if err := sc.st.SetNodeStatus(sc.ctx, id, store.NodeStatus{State: store.NodeReady, LastSeen: sc.clock.now()}); err != nil {
				t.Fatal(err)
			}
		}
		sc.later("back", time.Second)
		sc.serve("web")
		sc.later("settled", 5*time.Second)
		sc.later("rebalanced", 11*time.Second)
		sc.keyspace("keyspace")
	})
}

// spreadBy and rebalancing (ADR 0013, 0014): even over a label's values,
// moves to a new node, a move whose replacement never serves, and the
// backoff (spread_test.go, rebalance_test.go).
func TestParitySpreadAndRebalance(t *testing.T) {
	runParity(t, parityConfig{warmup: 3 * time.Second, progress: time.Minute}, func(sc *scenario) {
		sc.node("n1", "10.0.0.2", 0, 0, map[string]string{"region": "java"})
		sc.node("n2", "10.0.0.3", 0, 0, map[string]string{"region": "java"})
		sc.node("n3", "10.0.0.4", 0, 0, map[string]string{"region": "java"})
		sc.node("n4", "10.0.0.5", 0, 0, map[string]string{"region": "papua"})
		sc.node("n5", "10.0.0.6", 0, 0, nil)
		sc.deploy("spread", "name: web\nimage: nginx:1\nplacement:\n  spreadBy: region\nscale:\n  min: 6\n")
		sc.pass("six placed")
		sc.serve("web")
		sc.later("serving", 4*time.Second)
		sc.status("spread message", "web")
		sc.deploy("scale to 2", "name: web\nimage: nginx:1\nplacement:\n  spreadBy: region\nscale:\n  min: 2\n")
		sc.pass("scaled down")
		sc.later("drained", 11*time.Second)

		// Rebalancing without spreadBy: three replicas on one node, then a
		// second node.
		sc.node("m1", "10.0.1.2", 0, 0, map[string]string{"pool": "b"})
		sc.deploy("api", "name: api\nimage: api:1\nplacement:\n  require:\n    pool: b\nscale:\n  min: 3\n")
		sc.pass("api on m1")
		sc.serve("api")
		sc.later("api serving", 4*time.Second)
		sc.node("m2", "10.0.1.3", 0, 0, map[string]string{"pool": "b"})
		sc.later("move starts", time.Second)
		sc.later("replacement placed", time.Millisecond)
		sc.later("never serves", time.Minute-2*time.Millisecond)
		sc.later("given up", time.Second)
		sc.later("backoff", time.Minute)
		sc.later("retried", rebalanceBackoff)
		sc.later("replacement again", time.Millisecond)
		sc.serve("api")
		sc.later("warming up", 3*time.Second-time.Millisecond)
		sc.later("moved", time.Millisecond)
		sc.later("balanced", time.Minute)
		sc.keyspace("keyspace")
	})
}

// Removing an app (remove_test.go): its replicas drain, a node away holds
// the drain, then the app and its revisions and secret go.
func TestParityRemoveApp(t *testing.T) {
	runParity(t, parityConfig{masterKey: true, nodeLost: 5 * time.Minute}, func(sc *scenario) {
		sc.node("n1", "10.0.0.2", 0, 0, nil)
		sc.node("n2", "10.0.0.3", 0, 0, nil)
		sc.deploy("v1", webYAML("1", 2))
		sc.deploy("other", "name: api\nimage: api:1\n")
		_, err := sc.admin.SetSecret(sc.ctx, &armadav1.SetSecretRequest{App: "web", Name: "TOKEN", Value: []byte("x")})
		sc.note("secret", err)
		sc.pass("placed")
		sc.serve("web")
		sc.serve("api")
		sc.later("serving", 5*time.Second)
		_, err = sc.admin.RemoveApp(sc.ctx, &armadav1.RemoveAppRequest{App: "web"})
		sc.note("remove", err)
		_, err = sc.admin.RemoveApp(sc.ctx, &armadav1.RemoveAppRequest{App: "nope"})
		sc.note("remove unknown", err)
		sc.deploy("deploy while removing", webYAML("2", 2))
		sc.pass("draining")
		sc.status("removing", "")
		apps, err := sc.admin.ListApps(sc.ctx, &armadav1.ListAppsRequest{})
		sc.answer("list while removing", apps, err)
		if err := sc.st.SetNodeStatus(sc.ctx, "n2", store.NodeStatus{State: store.NodeUnknown, LastSeen: sc.clock.now()}); err != nil {
			t.Fatal(err)
		}
		sc.later("held for the away node", 11*time.Second)
		sc.later("hold ends", time.Minute)
		sc.status("removed", "web")
		sc.keyspace("keyspace")
	})
}

// Secrets through the API (secrets_test.go): validation, versions, a
// rollout of every app using a key, other secrets of the space (ADR
// 0052), listings, and deletion.
func TestParitySecrets(t *testing.T) {
	runParity(t, parityConfig{masterKey: true}, func(sc *scenario) {
		sc.node("n1", "10.0.0.2", 0, 0, nil)
		set := func(label string, req *armadav1.SetSecretRequest) {
			resp, err := sc.admin.SetSecret(sc.ctx, req)
			sc.answer(label, resp, err)
		}
		set("bad key", &armadav1.SetSecretRequest{App: "web", Name: "bad key!", Value: []byte("x")})
		set("bad secret", &armadav1.SetSecretRequest{App: "Web!", Name: "K", Value: []byte("x")})
		set("too big", &armadav1.SetSecretRequest{App: "web", Name: "K", Value: make([]byte, secrets.MaxSize+1)})
		set("no space", &armadav1.SetSecretRequest{App: "web.nowhere", Name: "K", Value: []byte("x")})
		set("db v1", &armadav1.SetSecretRequest{App: "db", Name: "url", Value: []byte("postgres://a")})
		set("own v1", &armadav1.SetSecretRequest{App: "web", Name: "TOKEN", Value: []byte("t1")})
		sc.deploy("web", "name: web\nimage: nginx:1\nenv:\n  - name: TOKEN\n    secretRef: TOKEN\n  - name: DB\n    secretRef: db/url\n")
		sc.deploy("api", "name: api\nimage: api:1\nenvFrom:\n  - secret: db\n")
		sc.pass("placed")
		sc.serve("web")
		sc.serve("api")
		sc.later("serving", 5*time.Second)
		set("db v2 with rollout", &armadav1.SetSecretRequest{App: "db", Name: "url", Value: []byte("postgres://b"), Rollout: true})
		set("own v2 without", &armadav1.SetSecretRequest{App: "web", Name: "TOKEN", Value: []byte("t2")})
		sc.pass("rolling out")
		sc.serve("web")
		sc.serve("api")
		sc.later("rolled out", 5*time.Second)
		for _, s := range []string{"web", "db", "Bad!"} {
			resp, err := sc.admin.ListSecrets(sc.ctx, &armadav1.ListSecretsRequest{App: s})
			sc.answer("list "+s, resp, err)
		}
		for _, sp := range []string{"", "default", "Nope!"} {
			resp, err := sc.admin.ListSpaceSecrets(sc.ctx, &armadav1.ListSpaceSecretsRequest{Space: sp})
			sc.answer("space secrets "+sp, resp, err)
		}
		for _, req := range []*armadav1.DeleteSecretRequest{
			{App: "db", Name: "url"},
			{App: "db", Name: "url", Whole: true},
			{App: "web", Name: "UNUSED"},
			{App: "web", Whole: true},
		} {
			_, err := sc.admin.DeleteSecret(sc.ctx, req)
			sc.note(fmt.Sprintf("delete %s %s %t", req.App, req.Name, req.Whole), err)
		}
		set("unused key", &armadav1.SetSecretRequest{App: "web", Name: "SPARE", Value: []byte("s")})
		_, err := sc.admin.DeleteSecret(sc.ctx, &armadav1.DeleteSecretRequest{App: "web", Name: "SPARE"})
		sc.note("delete the spare", err)
		set("spare again", &armadav1.SetSecretRequest{App: "web", Name: "SPARE", Value: []byte("s2")})
		rs, err := sc.admin.RestartApp(sc.ctx, &armadav1.RestartAppRequest{App: "api"})
		sc.answer("restart api", rs, err)
		sc.pass("restarting api")
		sc.keyspace("keyspace")
	})
}

func TestParitySecretsWithoutKey(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		_, err := sc.admin.SetSecret(sc.ctx, &armadav1.SetSecretRequest{App: "web", Name: "K", Value: []byte("x")})
		sc.note("no master key", err)
	})
}

// Traffic splitting (ADR 0022, traffic_test.go): shares per revision,
// labels and their URLs, SetTraffic, refusals, and back to one revision.
func TestParityTraffic(t *testing.T) {
	runParity(t, parityConfig{plainHTTP: true}, func(sc *scenario) {
		sc.node("n1", "10.0.0.2", 0, 0, nil)
		sc.node("n2", "10.0.0.3", 0, 0, nil)
		_, err := sc.admin.SetClusterConfig(sc.ctx, &armadav1.SetClusterConfigRequest{SetRootDomain: true, Config: &armadav1.ClusterConfig{RootDomain: "apps.example.com"}})
		sc.note("root domain", err)
		sc.deploy("v1", "name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\n  domains: [www.example.org, shop.example.org]\n  routes:\n    - path: /\n    - path: /api\nscale:\n  min: 4\n")
		if err := sc.st.SetDomainVerification(sc.ctx, "www.example.org", true, ""); err != nil {
			t.Fatal(err)
		}
		sc.pass("v1")
		sc.serve("web")
		sc.later("v1 serving", 5*time.Second)
		sc.status("v1 with domains", "web")
		apps, err := sc.admin.ListApps(sc.ctx, &armadav1.ListAppsRequest{})
		sc.answer("v1 listed", apps, err)
		split := "name: web\nimage: nginx:2\ningress:\n  type: external\n  port: 80\nscale:\n  min: 4\nrevisions:\n  mode: multiple\n  traffic:\n" +
			"    - revision: web--r1\n      weight: 75\n    - revision: latest\n      weight: 25\n      label: canary\n"
		sc.deploy("split", split)
		sc.pass("split placed")
		sc.serve("web")
		sc.later("split serving", 5*time.Second)
		sc.later("settled", 11*time.Second)
		sc.status("split status", "web")
		_, err = sc.admin.Rollback(sc.ctx, &armadav1.RollbackRequest{App: "web", Revision: "web--r1"})
		sc.note("rollback refused", err)
		for _, tr := range [][]*armadav1.TrafficTarget{
			{{Revision: "web--r2", Weight: 90}},
			{{Revision: "web--r9", Weight: 100}},
			make([]*armadav1.TrafficTarget, 11),
			{{Revision: "web--r1", Weight: 50}, {Revision: "web--r2", Weight: 50}},
		} {
			resp, err := sc.admin.SetTraffic(sc.ctx, &armadav1.SetTrafficRequest{App: "web", Traffic: tr})
			sc.answer(fmt.Sprintf("set traffic %d", len(tr)), resp, err)
		}
		sc.pass("50/50")
		sc.serve("web")
		sc.later("50/50 serving", 5*time.Second)
		sc.later("50/50 settled", 11*time.Second)
		resp, err := sc.admin.SetTraffic(sc.ctx, &armadav1.SetTrafficRequest{App: "web", Traffic: []*armadav1.TrafficTarget{{Revision: "web--r2", Weight: 100}}})
		sc.answer("all on r2", resp, err)
		sc.pass("all on r2")
		sc.serve("web")
		sc.later("r2 serving", 5*time.Second)
		sc.later("r1 gone", 11*time.Second)
		sc.deploy("back to one revision", "name: web\nimage: nginx:3\ningress:\n  type: external\n  port: 80\nscale:\n  min: 2\n")
		sc.pass("leaving multiple mode")
		sc.serve("web")
		sc.later("r3 serving", 5*time.Second)
		sc.later("r3 settled", 11*time.Second)
		sc.serve("web")
		sc.later("r3 serves", 5*time.Second)
		sc.later("r3 placed again", time.Second)
		sc.serve("web")
		sc.later("r3 done", 5*time.Second)
		sc.later("r2 drained", 11*time.Second)
		sc.status("single again", "web")
		sc.keyspace("keyspace")
	})
}

// Deploy's checks and the read methods' answers for people with roles of
// a space: placement labels and NFS exports a deployer may not add,
// stored revisions, TCP and queue triggers without a cluster network,
// deploy options, jobs, listings, and access.
func TestParityDeployChecks(t *testing.T) {
	runParity(t, parityConfig{masterKey: true}, func(sc *scenario) {
		sc.node("n1", "10.0.0.2", 0, 0, map[string]string{"disk": "ssd"}, "containers", "nfs")
		if _, err := sc.st.CreateSpace(sc.ctx, "team", "user:ryan", nil); err != nil {
			t.Fatal(err)
		}
		p, err := sc.st.CreateUser(sc.ctx, store.Principal{Name: "dev", Roles: []store.Grant{{Role: "deployer", Space: "team"}}}, "user:ryan")
		if err != nil {
			t.Fatal(err)
		}
		_ = p
		dev := sc.adminClient(pki.Identity{Kind: pki.KindUser, Name: "dev"})
		viewer, err := sc.st.CreateUser(sc.ctx, store.Principal{Name: "eve", Roles: []store.Grant{{Role: "viewer", Space: "team"}}}, "user:ryan")
		if err != nil {
			t.Fatal(err)
		}
		_ = viewer
		eve := sc.adminClient(pki.Identity{Kind: pki.KindUser, Name: "eve"})
		dep := func(label string, c armadav1.AdminServiceClient, req *armadav1.DeployRequest) {
			resp, err := c.Deploy(sc.ctx, req)
			sc.answer(label, resp, err)
		}
		team := func(y string) *armadav1.DeployRequest { return &armadav1.DeployRequest{Space: "team", Spec: []byte(y)} }
		dep("invalid spec", sc.admin, &armadav1.DeployRequest{Spec: []byte("name: Web!\n")})
		dep("unknown field", sc.admin, &armadav1.DeployRequest{Spec: []byte("name: web\nimage: x\nbogus: 1\n")})
		dep("no such space", sc.admin, &armadav1.DeployRequest{Space: "nope", Spec: []byte("name: web\nimage: x\n")})
		dep("deployer in default", dev, &armadav1.DeployRequest{Spec: []byte("name: web\nimage: x\n")})
		dep("deployer label", dev, team("name: web\nimage: x\nplacement:\n  require:\n    disk: ssd\n"))
		dep("deployer nfs", dev, team("name: web\nimage: x\nvolumes:\n  - name: data\n    path: /data\n    nfs:\n      server: 10.0.0.9\n      path: /export\n"))
		dep("deployer tcp", dev, team("name: db\nimage: x\ningress:\n  type: internal\n  protocol: tcp\n  port: 5432\n"))
		dep("queue trigger", sc.admin, &armadav1.DeployRequest{Spec: []byte("kind: job\nname: q\nimage: x\ntrigger:\n  queue:\n    type: redis\n    urlSecretRef: url\n    list: jobs\n    perRun: 1\n")})
		dep("deployer web", dev, team("name: web\nimage: web:1\n"))
		dep("must create again", dev, &armadav1.DeployRequest{Space: "team", MustCreate: true, Spec: []byte("name: web\nimage: web:2\n")})
		dep("must exist", dev, &armadav1.DeployRequest{Space: "team", MustExist: true, Spec: []byte("name: api\nimage: api:1\n")})
		dep("stale base", dev, &armadav1.DeployRequest{Space: "team", MustExist: true, BaseRevision: "web.team--r9", Spec: []byte("name: web\nimage: web:2\n")})
		dep("current base", dev, &armadav1.DeployRequest{Space: "team", MustExist: true, BaseRevision: "web.team--r1", Spec: []byte("name: web\nimage: web:2\n")})
		dep("same spec again", dev, team("name: web\nimage: web:2\n"))
		dep("viewer", eve, team("name: web\nimage: web:3\n"))
		dep("admin nfs", sc.admin, team("name: files\nimage: f:1\nvolumes:\n  - name: data\n    path: /data\n    nfs:\n      server: 10.0.0.9\n      path: /export\n      readOnly: false\n"))
		dep("deployer keeps the export read-only", dev, team("name: files\nimage: f:2\nvolumes:\n  - name: data\n    path: /data\n    nfs:\n      server: 10.0.0.9\n      path: /export\n      readOnly: true\n"))
		dep("admin label", sc.admin, team("name: pinned\nimage: p:1\nplacement:\n  require:\n    disk: ssd\n"))
		dep("deployer drops the label", dev, team("name: pinned\nimage: p:2\n"))
		rb, err := dev.Rollback(sc.ctx, &armadav1.RollbackRequest{App: "pinned.team"})
		sc.answer("deployer rolls back to the label", rb, err)
		rb, err = sc.admin.Rollback(sc.ctx, &armadav1.RollbackRequest{App: "web.team", Revision: "web.team--r1"})
		sc.answer("admin rolls back", rb, err)
		rb, err = sc.admin.Rollback(sc.ctx, &armadav1.RollbackRequest{App: "web.team"})
		sc.answer("cancel the rollback's rollout", rb, err)
		rb, err = sc.admin.Rollback(sc.ctx, &armadav1.RollbackRequest{App: "web.team", Revision: "web.team--r9"})
		sc.answer("unknown revision", rb, err)
		dep("first of solo", sc.admin, &armadav1.DeployRequest{Spec: []byte("name: solo\nimage: s:1\n")})
		rb, err = sc.admin.Rollback(sc.ctx, &armadav1.RollbackRequest{App: "solo"})
		sc.answer("nothing earlier", rb, err)
		dep("job", sc.admin, &armadav1.DeployRequest{Spec: []byte("kind: job\nname: batch\nimage: b:1\ncommand: [true]\n")})
		dep("job again", sc.admin, &armadav1.DeployRequest{Spec: []byte("kind: job\nname: batch\nimage: b:2\ncommand: [true]\n")})
		dep("autoscaled", sc.admin, &armadav1.DeployRequest{Spec: []byte("name: auto\nimage: a:1\ningress:\n  type: internal\n  port: 80\nscale:\n  min: 1\n  max: 4\n  rules:\n    - type: cpu\n      utilization: 70\n")})
		dep("multiple", sc.admin, &armadav1.DeployRequest{Spec: []byte("name: multi\nimage: m:1\ningress:\n  type: internal\n  port: 80\nrevisions:\n  mode: multiple\n  traffic:\n    - revision: latest\n      weight: 100\n      label: blue\n")})
		sc.pass("placed")
		sc.status("job status", "batch")
		sc.status("unknown app", "nope")
		for _, who := range []struct {
			name string
			c    armadav1.AdminServiceClient
		}{{"admin", sc.admin}, {"dev", dev}, {"eve", eve}} {
			st, err := who.c.Status(sc.ctx, &armadav1.StatusRequest{})
			sc.answer("status as "+who.name, st, err)
			st, err = who.c.Status(sc.ctx, &armadav1.StatusRequest{NodesOnly: true})
			sc.answer("nodes as "+who.name, st, err)
			for _, req := range []*armadav1.ListAppsRequest{{}, {Space: "team"}, {AllSpaces: true}, {AllSpaces: true, PageSize: 2}, {AllSpaces: true, PageSize: 2, PageToken: "files.team"}} {
				l, err := who.c.ListApps(sc.ctx, req)
				sc.answer(fmt.Sprintf("list as %s %v", who.name, req), l, err)
			}
			spec, err := who.c.GetAppSpec(sc.ctx, &armadav1.GetAppSpecRequest{App: "web.team"})
			sc.answer("spec as "+who.name, spec, err)
			revs, err := who.c.ListRevisions(sc.ctx, &armadav1.ListRevisionsRequest{App: "web.team"})
			sc.answer("revisions as "+who.name, revs, err)
			_, err = who.c.RemoveApp(sc.ctx, &armadav1.RemoveAppRequest{App: "solo"})
			sc.note("remove solo as "+who.name, err)
		}
		for _, req := range []*armadav1.SetSecretRequest{
			{App: "web.team", Name: "TOKEN", Value: []byte("t")},
			{App: "shared.team", Name: "url", Value: []byte("u"), Rollout: true},
			{App: "web", Name: "TOKEN", Value: []byte("t")},
		} {
			ss, err := dev.SetSecret(sc.ctx, req)
			sc.answer("deployer sets "+req.App, ss, err)
		}
		for _, who := range []struct {
			name string
			c    armadav1.AdminServiceClient
		}{{"dev", dev}, {"eve", eve}} {
			l, err := who.c.ListSpaceSecrets(sc.ctx, &armadav1.ListSpaceSecretsRequest{Space: "team"})
			sc.answer("team secrets as "+who.name, l, err)
			ls, err := who.c.ListSecrets(sc.ctx, &armadav1.ListSecretsRequest{App: "web.team"})
			sc.answer("web.team secrets as "+who.name, ls, err)
			_, err = who.c.DeleteSecret(sc.ctx, &armadav1.DeleteSecretRequest{App: "shared.team", Whole: true})
			sc.note("delete shared.team as "+who.name, err)
		}
		resp, err := dev.RestartApp(sc.ctx, &armadav1.RestartAppRequest{App: "pinned.team"})
		sc.answer("restart as deployer", resp, err)
		resp, err = sc.admin.RestartApp(sc.ctx, &armadav1.RestartAppRequest{App: "batch"})
		sc.answer("restart a job", resp, err)
		sc.keyspace("keyspace")
	})
}

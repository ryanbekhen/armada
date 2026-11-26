package server

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
)

// Scenarios of jobs (ADR 0055, pull request 10), run against both servers
// by runParity: runs started by hand, attempts placed on nodes whose
// agents run jobs, exits, failed starts, lost nodes, timeouts, retries
// with their backoff, cancels, history and the containers kept for logs,
// cron schedules with their missed and skipped fires and concurrency,
// runs of several tasks, queue triggers fed by the agents' usage reports,
// and the AdminService methods of jobs for people with roles. They move
// what jobs_test.go, jobtasks_test.go, and triggers_test.go check onto
// both servers; those tests stay.

// jobLines are the store's runs, one line each, with their tasks.
func (sc *scenario) jobLines() []string {
	sc.t.Helper()
	runs, err := sc.st.ListJobRuns(sc.ctx, "")
	if err != nil {
		sc.t.Fatal(err)
	}
	var out []string
	for _, r := range runs {
		line := fmt.Sprintf("%s#%d %s %s attempts=%d replica=%s node=%s exit=%d message=%q", r.Job, r.Seq, r.Trigger, r.State,
			r.Attempts, r.Replica, r.Node, r.ExitCode, r.Message)
		for _, t := range r.Tasks {
			line += fmt.Sprintf(" [t%d %s %d %s %d %q]", t.Index, t.State, t.Attempts, t.Replica, t.ExitCode, t.Message)
		}
		out = append(out, line)
	}
	return out
}

// jobReplicas are the store's replicas with what jobs add to them.
func (sc *scenario) jobReplicas() []string {
	sc.t.Helper()
	rs, err := sc.st.ListReplicas(sc.ctx, store.ReplicaFilter{})
	if err != nil {
		sc.t.Fatal(err)
	}
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		line := fmt.Sprintf("%s %s on %s %s run=%d task=%d", r.ID, r.Revision, r.NodeID, r.State, r.Run, r.Task)
		if r.Done {
			line += " done"
		}
		if r.Finished {
			line += fmt.Sprintf(" finished=%d", r.ExitCode)
		}
		out = append(out, line)
	}
	slices.Sort(out)
	return out
}

// jobPass runs a pass and records the runs and replicas after it.
func (sc *scenario) jobPass(label string) {
	sc.t.Helper()
	sc.sut.reconcile(sc.t)
	sc.note(label, map[string]any{"runs": sc.jobLines(), "replicas": sc.jobReplicas()})
}

// jobLater moves the clock by d, then passes.
func (sc *scenario) jobLater(label string, d time.Duration) {
	sc.t.Helper()
	sc.advance(d)
	sc.jobPass(label)
}

// exit reports a job attempt's container exited with code, as its agent
// would.
func (sc *scenario) exit(id string, code int) {
	sc.t.Helper()
	rs, err := sc.st.ListReplicas(sc.ctx, store.ReplicaFilter{})
	if err != nil {
		sc.t.Fatal(err)
	}
	for _, r := range rs {
		if r.ID == id {
			if err := sc.st.UpdateReplicaStatus(sc.ctx, r.NodeID, store.ReplicaStatus{ID: id, State: store.ReplicaExited,
				ContainerID: "c-" + id, Finished: true, ExitCode: code}); err != nil {
				sc.t.Fatal(err)
			}
			return
		}
	}
	sc.t.Fatalf("%s: no replica %s: %v", sc.sut.kind(), id, sc.jobReplicas())
}

// attempt returns the replica of a run's latest attempt (of task task,
// or of the run with task < 0).
func (sc *scenario) attempt(job string, seq int64, task int) string {
	sc.t.Helper()
	runs, err := sc.st.ListJobRuns(sc.ctx, job)
	if err != nil {
		sc.t.Fatal(err)
	}
	for _, r := range runs {
		if r.Seq != seq {
			continue
		}
		if task < 0 {
			return r.Replica
		}
		return r.Tasks[task].Replica
	}
	sc.t.Fatalf("%s: no run %d of %s: %v", sc.sut.kind(), seq, job, sc.jobLines())
	return ""
}

// runJob starts a run through the API as the scenario's admin.
func (sc *scenario) runJob(label, job string) {
	sc.t.Helper()
	resp, err := sc.admin.RunJob(sc.ctx, &armadav1.RunJobRequest{Job: job})
	sc.answer(label, resp, err)
}

// jobRuns records ListJobRuns and ListJobs.
func (sc *scenario) jobViews(label, job string) {
	sc.t.Helper()
	runs, err := sc.admin.ListJobRuns(sc.ctx, &armadav1.ListJobRunsRequest{Job: job})
	sc.answer(label+" runs", runs, err)
	jobs, err := sc.admin.ListJobs(sc.ctx, &armadav1.ListJobsRequest{})
	sc.answer(label+" jobs", jobs, err)
}

// jobAgent connects node id's agent, which runs jobs and keeps queue
// sandboxes when sandboxes is true.
func (sc *scenario) jobAgent(id, ip string, sandboxes bool) *parityAgent {
	sc.t.Helper()
	a, err := sc.connectAgent(id, sc.nodeAgent(id), &armadav1.Hello{PrivateIp: ip, CpuMillis: 2000, MemoryBytes: 4 << 30,
		Jobs: true, QueueSandboxes: sandboxes, Containers: true})
	if err != nil {
		sc.t.Fatal(err)
	}
	return a
}

// Runs started by hand through agents: a node without jobs gets nothing,
// the attempt's spec knows its run, a second run is refused while one is
// active, the agent's report of the exit ends it, and the finished
// attempt is kept done for its logs, then removed after a day; a job is
// not an app to Status, RunJob refuses unknown names and apps, and
// DeleteJob removes it all.
func TestParityJobWithAgents(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		sc.node("old", "10.0.0.10", 4000, 8<<30, nil)
		if err := sc.st.UpsertNode(sc.ctx, store.Node{ID: "n1", PrivateIP: "10.0.0.11"}); err != nil {
			t.Fatal(err)
		}
		sc.deploy("deploy migrate", "kind: job\nname: migrate\nimage: busybox:1\ncommand: [\"/migrate\"]\nenv:\n  - name: MODE\n    value: all\n")
		sc.deploy("deploy web", "name: web\nimage: nginx:1\n")
		sc.status("status leaves jobs out", "")
		sc.status("status of a job", "migrate")
		sc.runJob("run unknown", "ghost")
		sc.runJob("run an app", "web")
		sc.jobViews("before runs", "migrate")
		_, err := sc.admin.ListJobRuns(sc.ctx, &armadav1.ListJobRunsRequest{Job: "web"})
		sc.note("runs of an app", err)

		sc.runJob("run 1", "migrate")
		sc.jobPass("no node runs jobs")
		sc.runJob("run while one is pending", "migrate")
		a := sc.jobAgent("n1", "10.0.0.11", false)
		sc.jobPass("placed on n1")
		sc.note("n1 assignment", a.assignment())
		rep := sc.attempt("migrate", 1, -1)
		a.send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Report{Report: &armadav1.ReplicaReport{Replicas: []*armadav1.ReplicaState{
			{Id: rep, State: store.ReplicaRunning, ContainerId: "c-" + rep},
		}}}})
		sc.eventually("running", func() bool { return slices.Contains(sc.jobReplicas(), rep+" migrate--r1 on n1 running run=1 task=0") })
		sc.jobPass("running")
		a.send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Report{Report: &armadav1.ReplicaReport{Replicas: []*armadav1.ReplicaState{
			{Id: rep, State: store.ReplicaExited, ContainerId: "c-" + rep, Finished: true},
		}}}})
		sc.eventually("finished", func() bool {
			return slices.Contains(sc.jobReplicas(), rep+" migrate--r1 on n1 exited run=1 task=0 finished=0")
		})
		sc.later("succeeded", 90*time.Second)
		sc.jobPass("after")
		sc.note("n1 assignment after", a.assignment())
		sc.jobViews("after run 1", "migrate")
		sc.jobLater("a day minus a second", 24*time.Hour-91*time.Second)
		sc.jobLater("the logs' day is over", time.Second)

		// The job runs again on another revision; deleting it removes its
		// runs and replicas.
		sc.deploy("deploy migrate v2", "kind: job\nname: migrate\nimage: busybox:2\n")
		sc.runJob("run 2", "migrate")
		sc.jobPass("run 2 placed")
		_, err = sc.admin.DeleteJob(sc.ctx, &armadav1.DeleteJobRequest{Job: "migrate"})
		sc.note("delete", err)
		_, err = sc.admin.DeleteJob(sc.ctx, &armadav1.DeleteJobRequest{Job: "web"})
		sc.note("delete an app", err)
		sc.jobPass("deleted")
		sc.note("n1 assignment deleted", a.assignment())
		sc.jobViews("deleted", "migrate")
		sc.keyspace("keyspace")
	})
}

// TestJobRetriesThenFails, TestJobTimeoutAndCancel, and the ends of an
// attempt Go's tests reach through drivers: exits with codes, retries
// after a doubling delay with only the latest attempt kept, failed
// starts, lost nodes, replicas gone from the store, timeouts before and
// after the container started, nodes that cannot run it in time, a
// revision that no longer exists, and cancels.
func TestParityJobAttempts(t *testing.T) {
	runParity(t, parityConfig{nodeLost: time.Minute}, func(sc *scenario) {
		sc.node("n1", "10.0.0.11", 4000, 8<<30, nil, "jobs")
		sc.node("n2", "10.0.0.12", 4000, 8<<30, nil, "jobs")
		sc.node("n3", "10.0.0.13", 4000, 8<<30, nil, "jobs")

		sc.deploy("deploy flaky", "kind: job\nname: flaky\nimage: busybox:1\nretries: 2\n")
		sc.runJob("run flaky", "flaky")
		sc.jobPass("attempt 1")
		sc.exit(sc.attempt("flaky", 1, -1), 3)
		sc.jobPass("retrying")
		sc.jobLater("before the retry", 10*time.Second-time.Millisecond)
		sc.jobLater("attempt 2", time.Millisecond)
		sc.report(sc.replicaOf("flaky-j1-"), store.ReplicaFailed, false, "pull access denied")
		sc.jobPass("failed to start")
		sc.jobLater("before the second retry", 20*time.Second-time.Millisecond)
		sc.jobLater("attempt 3", time.Millisecond)
		sc.exit(sc.attempt("flaky", 1, -1), 4)
		sc.jobPass("failed for good")
		sc.jobViews("flaky", "flaky")

		// Timeouts: before the container started, and after.
		sc.deploy("deploy slow", "kind: job\nname: slow\nimage: busybox:1\ntimeout: 1m\n")
		sc.runJob("run slow", "slow")
		sc.jobPass("slow placed")
		sc.jobLater("before the timeout", time.Minute-time.Millisecond)
		sc.jobLater("timed out", time.Millisecond)
		sc.runJob("run slow again", "slow")
		sc.jobPass("slow 2 placed")
		sc.report(sc.replicaOf("slow-j2-"), store.ReplicaRunning, false, "")
		sc.jobLater("timed out running", time.Minute)

		// A lost node and a replica gone from the store.
		sc.deploy("deploy lost", "kind: job\nname: lost\nimage: busybox:1\nretries: 1\nplacement:\n  require:\n    disk: [ssd]\n")
		if _, err := sc.st.SetNodeLabels(sc.ctx, "n3", map[string]string{"disk": "ssd"}, nil, "user:ryan"); err != nil {
			t.Fatal(err)
		}
		sc.runJob("run lost", "lost")
		sc.jobPass("lost placed on n3")
		if err := sc.st.SetNodeStatus(sc.ctx, "n3", store.NodeStatus{State: store.NodeUnknown, LastSeen: sc.clock.now(), CPUMillis: 4000, MemoryBytes: 8 << 30, Jobs: true}); err != nil {
			t.Fatal(err)
		}
		sc.jobLater("n3 away", 30*time.Second)
		sc.jobLater("n3 lost", 30*time.Second)
		sc.jobLater("no node for the retry yet", 10*time.Second)
		sc.jobLater("unplaced until its timeout", time.Hour)
		if err := sc.st.SetNodeStatus(sc.ctx, "n3", store.NodeStatus{State: store.NodeReady, LastSeen: sc.clock.now(), CPUMillis: 4000, MemoryBytes: 8 << 30, Jobs: true}); err != nil {
			t.Fatal(err)
		}
		sc.runJob("run lost again", "lost")
		sc.jobPass("lost 2 placed")
		if err := sc.st.DeleteReplica(sc.ctx, sc.attempt("lost", 2, -1)); err != nil {
			t.Fatal(err)
		}
		sc.jobPass("its replica disappeared")

		// Cancel a running run and a pending one.
		sc.deploy("deploy long", "kind: job\nname: long\nimage: busybox:1\nconcurrency: replace\n")
		sc.runJob("run long", "long")
		sc.jobPass("long placed")
		sc.runJob("run long replaces it", "long")
		sc.jobPass("long 2 placed")
		resp, err := sc.admin.CancelJob(sc.ctx, &armadav1.CancelJobRequest{Job: "long"})
		sc.answer("cancel long", resp, err)
		resp, err = sc.admin.CancelJob(sc.ctx, &armadav1.CancelJobRequest{Job: "long"})
		sc.answer("cancel nothing", resp, err)
		sc.jobPass("cancelled")

		// A revision that no longer exists ends its pending run.
		sc.deploy("deploy gone", "kind: job\nname: gone\nimage: busybox:1\n")
		if _, err := sc.st.CreateJobRun(sc.ctx, "gone", store.TriggerManual, time.Time{}, "user:ryan"); err != nil {
			t.Fatal(err)
		}
		if err := sc.st.UpdateJobRun(sc.ctx, store.JobRun{Job: "gone", Seq: 1, Revision: "gone--r9", Trigger: store.TriggerManual, State: store.RunPending,
			CreatedAt: sc.clock.now()}); err != nil {
			t.Fatal(err)
		}
		sc.jobPass("revision gone")
		sc.jobViews("end", "flaky")
		sc.keyspace("keyspace")
	})
}

// TestJobHistory, and jobs placed by capacity and placement: finished
// runs past the job's history are removed with their replicas, done
// attempts reserve nothing, and runs wait for room.
func TestParityJobHistoryAndCapacity(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		sc.node("n1", "10.0.0.11", 1000, 1<<30, nil, "jobs")
		sc.deploy("deploy tick", "kind: job\nname: tick\nimage: busybox:1\nhistory: 2\nresources:\n  cpu: 800m\n  memory: 512Mi\n")
		for run := int64(1); run <= 4; run++ {
			sc.runJob(fmt.Sprintf("run %d", run), "tick")
			sc.jobPass(fmt.Sprintf("run %d placed", run))
			sc.exit(sc.attempt("tick", run, -1), 0)
			sc.jobLater(fmt.Sprintf("run %d done", run), time.Second)
		}
		sc.jobViews("history", "tick")
		// A second job does not fit beside a running attempt; a done one
		// reserves nothing.
		sc.deploy("deploy big", "kind: job\nname: big\nimage: busybox:1\ntimeout: 1m\nresources:\n  cpu: 800m\n")
		sc.runJob("run tick 5", "tick")
		sc.jobPass("tick 5 placed")
		sc.runJob("run big", "big")
		sc.jobPass("big waits")
		sc.exit(sc.attempt("tick", 5, -1), 0)
		sc.jobPass("tick 5 done")
		sc.jobPass("big placed")
		sc.keyspace("keyspace")
	})
}

// TestScheduleJob and TestScheduleJobMissed on both servers: a due fire
// starts a run once, a later fire while a run is active is skipped with
// concurrency forbid and replaces it with replace, fires missed by more
// than an hour are recorded and not run, and a schedule in a time zone.
func TestParityJobSchedule(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		sc.node("n1", "10.0.0.11", 4000, 8<<30, nil, "jobs")
		sc.deploy("deploy tick", "kind: job\nname: tick\nimage: busybox:1\nschedule: \"*/10 * * * *\"\n")
		sc.deploy("deploy swap", "kind: job\nname: swap\nimage: busybox:1\nschedule: \"*/10 * * * *\"\nconcurrency: replace\n")
		sc.deploy("deploy daily", "kind: job\nname: daily\nimage: busybox:1\nschedule: \"30 3 * * *\"\ntimeZone: Asia/Jakarta\n")
		sc.jobLater("before the first fire", time.Second)
		sc.jobViews("scheduled", "tick")
		sc.jobLater("first fire", 10*time.Minute)
		sc.jobLater("same fire again", 10*time.Second)
		sc.jobLater("second fire while active", 10*time.Minute)
		for _, job := range []string{"tick", "swap"} {
			runs, err := sc.st.ListJobRuns(sc.ctx, job)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range runs {
				if r.Active() && r.Replica != "" {
					sc.exit(r.Replica, 0)
				}
			}
		}
		sc.jobPass("runs done")
		// The control plane was away until 22:00 UTC: daily's fire at
		// 03:30 in Jakarta (20:30 UTC) is missed, not run; the others run
		// their latest fire.
		sc.jobLater("missed", 11*time.Hour+40*time.Minute)
		// The next day's fire runs; tick's run is still active.
		sc.jobLater("daily fired", 22*time.Hour+30*time.Minute)
		sc.jobViews("after", "daily")
		sc.keyspace("keyspace")
	})
}

// TestJobTasks, TestJobTaskFailsRun, and TestJobTasksCancel on both
// servers, with tasks that wait for a node and fail when none comes.
func TestParityJobTasks(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		sc.node("n1", "10.0.0.11", 4000, 8<<30, nil, "jobs")
		sc.node("n2", "10.0.0.12", 4000, 8<<30, nil, "jobs")
		a := sc.jobAgent("n1", "10.0.0.11", false)
		sc.deploy("deploy report", "kind: job\nname: report\nimage: busybox:1\ntasks: 3\nparallelism: 2\nretries: 1\n")
		sc.runJob("run report", "report")
		sc.jobPass("two tasks")
		sc.note("n1 assignment", a.assignment())
		sc.exit(sc.attempt("report", 1, 0), 0)
		sc.jobPass("task 0 done, task 2 starts")
		sc.exit(sc.attempt("report", 1, 1), 4)
		sc.jobPass("task 1 retrying")
		sc.jobLater("task 1 again", 10*time.Second)
		sc.exit(sc.attempt("report", 1, 1), 0)
		sc.exit(sc.attempt("report", 1, 2), 0)
		sc.jobPass("all done")
		sc.jobViews("report", "report")

		// A task failing for good fails the run and stops the others.
		sc.deploy("deploy sync", "kind: job\nname: sync\nimage: busybox:1\ntasks: 2\n")
		sc.runJob("run sync", "sync")
		sc.jobPass("sync tasks")
		sc.exit(sc.attempt("sync", 1, 0), 2)
		sc.jobPass("sync failed")

		// Cancelling a run with tasks cancels every task.
		sc.deploy("deploy batch", "kind: job\nname: batch\nimage: busybox:1\ntasks: 3\nparallelism: 1\n")
		sc.runJob("run batch", "batch")
		sc.jobPass("batch task 0")
		resp, err := sc.admin.CancelJob(sc.ctx, &armadav1.CancelJobRequest{Job: "batch"})
		sc.answer("cancel batch", resp, err)
		sc.jobPass("batch cancelled")

		// Tasks that find no node wait, and fail once they waited past the
		// timeout.
		sc.deploy("deploy wide", "kind: job\nname: wide\nimage: busybox:1\ntasks: 2\ntimeout: 1m\nplacement:\n  require:\n    zone: [x]\n")
		sc.runJob("run wide", "wide")
		sc.jobPass("wide waits")
		sc.jobLater("wide still waits", 30*time.Second)
		sc.jobLater("wide tasks fail", 30*time.Second)
		sc.jobPass("wide failed")
		sc.jobViews("tasks", "wide")
		sc.keyspace("keyspace")
	})
}

const parityMailer = "kind: job\nname: mailer\nimage: busybox:1\ntrigger:\n  queue:\n    type: redis\n    urlSecretRef: redis-url\n    list: mail\n    perRun: 10\n  parallelism: 2\n"

// TestTriggerDecision and TestQueueTriggeredJob on both servers, through
// agents and their usage reports: the node that reads the queue gets the
// sandbox with the URL from the pinned secret, ⌈length ÷ perRun⌉ runs
// start up to the parallelism once per reading, nothing on stale
// readings, a dropped sandbox and a node's read failures are conditions,
// the sandbox moves when its node goes, and RunJob keeps to the
// parallelism.
func TestParityQueueTrigger(t *testing.T) {
	runParity(t, parityConfig{masterKey: true}, func(sc *scenario) {
		sc.deploy("without a cluster network", parityMailer)
		if err := sc.st.InitNetwork(sc.ctx, store.Network{Mode: store.NetworkPlain, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}); err != nil {
			t.Fatal(err)
		}
		for _, n := range [][2]string{{"n1", "10.0.0.11"}, {"n2", "10.0.0.12"}} {
			if err := sc.st.UpsertNode(sc.ctx, store.Node{ID: n[0], PrivateIP: n[1]}); err != nil {
				t.Fatal(err)
			}
		}
		_, err := sc.admin.SetSecret(sc.ctx, &armadav1.SetSecretRequest{App: "mailer", Name: "redis-url", Value: []byte("redis://:pw@10.0.0.50:6379")})
		sc.note("secret", err)
		sc.deploy("deploy mailer", parityMailer)
		sc.jobPass("no node reads it")
		sc.jobViews("unread", "mailer")
		agents := map[string]*parityAgent{"n1": sc.jobAgent("n1", "10.0.0.11", true), "n2": sc.jobAgent("n2", "10.0.0.12", true)}
		sc.jobPass("a node reads it")
		trigger := func() *armadav1.JobTrigger {
			resp, err := sc.admin.ListJobs(sc.ctx, &armadav1.ListJobsRequest{})
			if err != nil || len(resp.Jobs) != 1 {
				return nil
			}
			return resp.Jobs[0].GetTrigger()
		}
		probe := trigger().GetNode()
		other := map[string]string{"n1": "n2", "n2": "n1"}[probe]
		sc.alias(probe, "<probe>")
		sc.alias(other, "<other>")
		sc.note("probe assignment", agents[probe].assignment())
		sc.note("other assignment", agents[other].assignment())

		// What the probe node reports; reading waits until the server has it.
		reading := 0
		report := func(label string, q *armadav1.SandboxQueue, dropped ...string) {
			if q != nil && q.Measured {
				reading++
				q.Reading = int64(reading)
			}
			u := &armadav1.UsageReport{DroppedSandboxes: dropped}
			if q != nil {
				q.Job = "mailer"
				u.Sandboxes = []*armadav1.SandboxQueue{q}
			}
			agents[probe].send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Usage{Usage: u}})
			want := q != nil && q.Measured && q.AgeMillis < 60_000
			sc.eventually(label, func() bool {
				tr := trigger()
				return tr.GetMeasured() == want && (!want || tr.GetLength() == q.Length)
			})
			// A last message to the probe's session, after the usage report.
			sc.jobPass(label)
		}
		finish := func() {
			runs, err := sc.st.ListJobRuns(sc.ctx, "mailer")
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range runs {
				if r.Active() && r.Replica != "" {
					sc.exit(r.Replica, 0)
				}
			}
		}

		report("an empty queue", &armadav1.SandboxQueue{Ip: "10.120.0.9", Measured: true})
		sc.jobViews("measured", "mailer")
		report("25 waiting", &armadav1.SandboxQueue{Ip: "10.120.0.9", Measured: true, Length: 25})
		sc.runJob("run past parallelism", "mailer")
		finish()
		sc.jobPass("runs done, the same reading")
		report("5 waiting", &armadav1.SandboxQueue{Ip: "10.120.0.9", Measured: true, Length: 5})
		report("15 waiting with one active", &armadav1.SandboxQueue{Ip: "10.120.0.9", Measured: true, Length: 15})
		report("0 waiting with two active", &armadav1.SandboxQueue{Ip: "10.120.0.9", Measured: true, Length: 0})
		finish()
		sc.jobPass("done again")
		report("a stale reading", &armadav1.SandboxQueue{Ip: "10.120.0.9", Measured: true, Length: 100, AgeMillis: 10 * 60_000})
		report("no reading", nil)
		report("dropped", nil, "mailer")
		report("a broker's refusal", &armadav1.SandboxQueue{Ip: "10.120.0.9", Error: "the broker refused the URL's virtual host"})
		report("read after the refusal", &armadav1.SandboxQueue{Ip: "10.120.0.9", Measured: true, Length: 0})
		// Any other text becomes a fixed one: never the URL.
		report("an agent's own text", &armadav1.SandboxQueue{Ip: "10.120.0.9", Error: "amqp://u:pw@h refused"})
		report("reads again", &armadav1.SandboxQueue{Ip: "10.120.0.9", Measured: true, Length: 0})
		sc.jobViews("read again", "mailer")

		// A reading too old for the node's sample.
		sc.jobLater("the sample is old", 36*time.Second)
		sc.jobViews("old sample", "mailer")

		// The node that reads the queue goes: the other takes over.
		before := sc.eventCount(probe, "Disconnected")
		agents[probe].stop()
		sc.eventually("disconnected", func() bool { return sc.eventCount(probe, "Disconnected") > before })
		sc.jobPass("moved")
		sc.note("other assignment moved", agents[other].assignment())
		sc.jobViews("moved", "mailer")
		agents[other].stop()
		sc.eventually("both gone", func() bool { return sc.eventCount(other, "Disconnected") > 0 })
		sc.jobPass("no node left")
		_, err = sc.admin.DeleteJob(sc.ctx, &armadav1.DeleteJobRequest{Job: "mailer"})
		sc.note("delete", err)
		sc.jobPass("deleted")
		sc.keyspace("keyspace")
	})
}

// TestPlaceQueues on both servers: no node reads more queues than an agent
// keeps, and jobs are placed one space at a time.
func TestParityQueuePlacement(t *testing.T) {
	runParity(t, parityConfig{masterKey: true}, func(sc *scenario) {
		if err := sc.st.InitNetwork(sc.ctx, store.Network{Mode: store.NetworkPlain, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}); err != nil {
			t.Fatal(err)
		}
		if err := sc.st.UpsertNode(sc.ctx, store.Node{ID: "n1", PrivateIP: "10.0.0.11"}); err != nil {
			t.Fatal(err)
		}
		for _, sp := range []string{"evil", "prod"} {
			if _, err := sc.st.CreateSpace(sc.ctx, sp, "user:ryan", nil); err != nil {
				t.Fatal(err)
			}
		}
		job := func(name, space string) {
			_, err := sc.admin.SetSecret(sc.ctx, &armadav1.SetSecretRequest{App: qualify(name, space), Name: "u", Value: []byte("redis://10.0.0.50:6379")})
			if err != nil {
				t.Fatal(err)
			}
			y := "kind: job\nname: " + name + "\nimage: busybox:1\ntrigger:\n  queue:\n    type: redis\n    urlSecretRef: u\n    list: l\n    perRun: 1\n"
			if _, err := sc.admin.Deploy(sc.ctx, &armadav1.DeployRequest{Spec: []byte(y), Space: space}); err != nil {
				t.Fatal(err)
			}
		}
		for i := range 66 {
			job(fmt.Sprintf("a%02d", i), "evil")
		}
		job("mailer", "")
		job("worker", "prod")
		sc.deploy("deploy cron", "kind: job\nname: cron\nimage: busybox:1\n")
		a := sc.jobAgent("n1", "10.0.0.11", true)
		sc.sut.reconcile(t)
		resp, err := sc.admin.ListJobs(sc.ctx, &armadav1.ListJobsRequest{})
		if err != nil {
			t.Fatal(err)
		}
		placed := map[string]int{}
		var lines []string
		for _, j := range resp.Jobs {
			if tr := j.GetTrigger(); tr != nil {
				placed[tr.GetNode()]++
				if !strings.HasPrefix(j.Name, "a") {
					lines = append(lines, j.Name+" on "+tr.GetNode())
				}
			}
		}
		sc.note("placed", map[string]any{"count": placed, "others": lines})
		sc.note("sandboxes on n1", len(a.assignment().GetQueueSandboxes()))
	})
}

func qualify(name, space string) string {
	if space == "" {
		return name
	}
	return name + "." + space
}

// The AdminService methods of jobs for people with roles: a viewer of a
// space lists and reads its jobs but starts, cancels, and deletes
// nothing, a deployer starts and cancels, an admin of the space deletes,
// and nobody reaches another space's jobs.
func TestParityJobAccess(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		if _, err := sc.st.CreateSpace(sc.ctx, "team", "user:ryan", nil); err != nil {
			t.Fatal(err)
		}
		for _, p := range []struct {
			name string
			g    store.Grant
		}{{"vera", store.Grant{Role: store.RoleViewer, Space: "team"}}, {"dana", store.Grant{Role: store.RoleDeployer, Space: "team"}},
			{"ada", store.Grant{Role: store.RoleAdmin, Space: "team"}}} {
			if _, err := sc.st.CreateUser(sc.ctx, store.Principal{Name: p.name, Since: sc.clock.now().Add(-time.Hour)}, "user:ryan"); err != nil {
				t.Fatal(err)
			}
			if _, err := sc.st.Assign(sc.ctx, store.KindUser, p.name, p.g, "user:ryan"); err != nil {
				t.Fatal(err)
			}
		}
		y := "kind: job\nname: sync\nimage: busybox:1\nschedule: \"0 * * * *\"\n"
		_, err := sc.admin.Deploy(sc.ctx, &armadav1.DeployRequest{Spec: []byte(y), Space: "team"})
		sc.note("deploy team", err)
		sc.deploy("deploy default", "kind: job\nname: sync\nimage: busybox:1\n")
		for _, who := range []string{"vera", "dana"} {
			c := sc.adminClient(pki.Identity{Kind: pki.KindUser, Name: who})
			for _, job := range []string{"sync.team", "sync", "ghost.team"} {
				run, err := c.RunJob(sc.ctx, &armadav1.RunJobRequest{Job: job})
				sc.answer(who+" run "+job, run, err)
				runs, err := c.ListJobRuns(sc.ctx, &armadav1.ListJobRunsRequest{Job: job})
				sc.answer(who+" runs "+job, runs, err)
				cancel, err := c.CancelJob(sc.ctx, &armadav1.CancelJobRequest{Job: job})
				sc.answer(who+" cancel "+job, cancel, err)
			}
			jobs, err := c.ListJobs(sc.ctx, &armadav1.ListJobsRequest{})
			sc.answer(who+" jobs", jobs, err)
		}
		vera := sc.adminClient(pki.Identity{Kind: pki.KindUser, Name: "vera"})
		_, err = vera.DeleteJob(sc.ctx, &armadav1.DeleteJobRequest{Job: "sync.team"})
		sc.note("vera delete", err)
		dana := sc.adminClient(pki.Identity{Kind: pki.KindUser, Name: "dana"})
		_, err = dana.DeleteJob(sc.ctx, &armadav1.DeleteJobRequest{Job: "sync"})
		sc.note("dana delete default", err)
		_, err = dana.DeleteJob(sc.ctx, &armadav1.DeleteJobRequest{Job: "sync.team"})
		sc.note("dana delete team", err)
		ada := sc.adminClient(pki.Identity{Kind: pki.KindUser, Name: "ada"})
		_, err = ada.DeleteJob(sc.ctx, &armadav1.DeleteJobRequest{Job: "sync"})
		sc.note("ada delete default", err)
		_, err = ada.DeleteJob(sc.ctx, &armadav1.DeleteJobRequest{Job: "sync.team"})
		sc.note("ada delete team", err)
		jobs, err := ada.ListJobs(sc.ctx, &armadav1.ListJobsRequest{})
		sc.answer("ada jobs", jobs, err)
		node := sc.adminClient(pki.Identity{Kind: pki.KindNode, Name: "n1"})
		_, err = node.RunJob(sc.ctx, &armadav1.RunJobRequest{Job: "sync"})
		sc.note("a node runs a job", err)
		sc.keyspace("keyspace")
	})
}

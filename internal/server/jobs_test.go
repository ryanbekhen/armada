package server

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/store/storetest"
)

func (c *cluster) runs(job string) []*armadav1.JobRunInfo {
	resp, err := c.admin.ListJobRuns(c.ctx, &armadav1.ListJobRunsRequest{Job: job})
	if err != nil {
		c.t.Fatal(err)
	}
	return resp.Runs
}

func (c *cluster) runState(job string, run int64) *armadav1.JobRunInfo {
	for _, r := range c.runs(job) {
		if r.Run == run {
			return r
		}
	}
	return nil
}

// exitAttempt makes the running container of a job's latest attempt exit.
func exitAttempt(t *testing.T, ds []*fake.Driver, replica string, code int) {
	t.Helper()
	for _, d := range ds {
		cs, _ := d.List(context.Background(), nil)
		for _, c := range cs {
			if c.Labels[runtime.LabelReplica] == replica {
				d.SetState(c.ID, runtime.StateExited, code)
				return
			}
		}
	}
	t.Fatalf("no container for %s", replica)
}

func TestJobRunSucceeds(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	d := c.addNode("n1", "10.0.0.11")
	c.deploy("kind: job\nname: migrate\nimage: busybox:1\ncommand: [\"/migrate\"]\n")
	if st, _ := c.admin.Status(c.ctx, &armadav1.StatusRequest{}); len(st.GetApps()) != 0 {
		t.Errorf("a job in status: %v", st.GetApps())
	}
	resp, err := c.admin.RunJob(c.ctx, &armadav1.RunJobRequest{Job: "migrate"})
	if err != nil || resp.Run != 1 {
		t.Fatalf("run: %v %v", resp, err)
	}
	var replica string
	c.eventually("attempt running", func() bool {
		r := c.runState("migrate", 1)
		replica = r.GetReplica()
		return r.GetState() == store.RunRunning && containerCount(d) == 1
	})
	// The container knows its run.
	cs, _ := d.List(c.ctx, nil)
	sp, _ := d.Spec(cs[0].ID)
	if !slicesContains(sp.Env, "ARMADA_JOB_RUN=1") {
		t.Errorf("env %v", sp.Env)
	}
	// A second run is refused while this one runs (concurrency forbid).
	if _, err := c.admin.RunJob(c.ctx, &armadav1.RunJobRequest{Job: "migrate"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("second run: %v", err)
	}

	exitAttempt(t, []*fake.Driver{d}, replica, 0)
	c.eventually("succeeded", func() bool { return c.runState("migrate", 1).GetState() == store.RunSucceeded })
	r := c.runState("migrate", 1)
	if r.Attempts != 1 || r.Node != "n1" || r.FinishedAt == nil || r.Trigger != store.TriggerManual {
		t.Errorf("run %v", r)
	}
	// The container is kept for its logs, and reserves nothing.
	time.Sleep(200 * time.Millisecond)
	if containerCount(d) != 1 {
		t.Error("finished attempt's container removed")
	}
	reps, _ := c.store.ListReplicas(c.ctx, store.ReplicaFilter{App: "migrate"})
	if len(reps) != 1 || !reps[0].Done {
		t.Errorf("attempt %+v", reps)
	}
	evs, _ := c.store.ListEvents(c.ctx, time.Time{})
	var reasons []string
	for _, e := range evs {
		if e.Kind == eventJob {
			reasons = append(reasons, e.Reason)
		}
	}
	if strings.Join(reasons, ",") != "Deployed,Started,Succeeded" {
		t.Errorf("job events %v", reasons)
	}
	if got := testutilCounter(c.srv.jobRuns.WithLabelValues("migrate", store.RunSucceeded)); got != 1 {
		t.Errorf("armada_job_runs_total = %v", got)
	}

	// Jobs are not apps: no scaling, no rollback, no status.
	if _, err := c.admin.Scale(c.ctx, &armadav1.ScaleRequest{App: "migrate", Replicas: 2}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("scale a job: %v", err)
	}
	if _, err := c.admin.Status(c.ctx, &armadav1.StatusRequest{App: "migrate"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("status of a job: %v", err)
	}
	if _, err := c.admin.RunJob(c.ctx, &armadav1.RunJobRequest{Job: "ghost"}); status.Code(err) != codes.NotFound {
		t.Errorf("run unknown: %v", err)
	}

	// Deleting the job removes its runs and containers.
	if _, err := c.admin.DeleteJob(c.ctx, &armadav1.DeleteJobRequest{Job: "migrate"}); err != nil {
		t.Fatal(err)
	}
	c.eventually("container removed", func() bool { return containerCount(d) == 0 })
}

func TestJobRetriesThenFails(t *testing.T) {
	t.Parallel()
	c := newCluster(t, func(cfg *Config) { cfg.JobRetryBase = 50 * time.Millisecond })
	d1 := c.addNode("n1", "10.0.0.11")
	d2 := c.addNode("n2", "10.0.0.12")
	ds := []*fake.Driver{d1, d2}
	c.deploy("kind: job\nname: flaky\nimage: busybox:1\nretries: 1\n")
	if _, err := c.admin.RunJob(c.ctx, &armadav1.RunJobRequest{Job: "flaky"}); err != nil {
		t.Fatal(err)
	}
	for attempt := int32(1); attempt <= 2; attempt++ {
		var replica string
		c.eventually("attempt running", func() bool {
			r := c.runState("flaky", 1)
			replica = r.GetReplica()
			return r.GetState() == store.RunRunning && r.GetAttempts() == attempt && containerCount(ds...) >= 1
		})
		c.eventually("container", func() bool {
			for _, d := range ds {
				cs, _ := d.List(c.ctx, nil)
				for _, ct := range cs {
					if ct.Labels[runtime.LabelReplica] == replica && ct.State == runtime.StateRunning {
						return true
					}
				}
			}
			return false
		})
		exitAttempt(t, ds, replica, 3)
	}
	c.eventually("failed", func() bool { return c.runState("flaky", 1).GetState() == store.RunFailed })
	r := c.runState("flaky", 1)
	if r.Attempts != 2 || r.ExitCode != 3 || !strings.Contains(r.Message, "code 3") {
		t.Errorf("run %v", r)
	}
	// Only the latest attempt's container is kept.
	if reps, _ := c.store.ListReplicas(c.ctx, store.ReplicaFilter{App: "flaky"}); len(reps) != 1 {
		t.Errorf("attempts kept %+v", reps)
	}
}

func TestJobTimeoutAndCancel(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	d := c.addNode("n1", "10.0.0.11")
	c.deploy("kind: job\nname: slow\nimage: busybox:1\ntimeout: 1s\n")
	if _, err := c.admin.RunJob(c.ctx, &armadav1.RunJobRequest{Job: "slow"}); err != nil {
		t.Fatal(err)
	}
	c.eventually("timed out", func() bool { return c.runState("slow", 1).GetState() == store.RunFailed })
	if r := c.runState("slow", 1); !strings.Contains(r.Message, "timed out") {
		t.Errorf("run %v", r)
	}
	c.eventually("container stopped", func() bool {
		cs, _ := d.List(c.ctx, nil)
		return len(cs) == 1 && cs[0].State != runtime.StateRunning
	})

	c.deploy("kind: job\nname: slow\nimage: busybox:1\ntimeout: 1h\n")
	if _, err := c.admin.RunJob(c.ctx, &armadav1.RunJobRequest{Job: "slow"}); err != nil {
		t.Fatal(err)
	}
	c.eventually("running", func() bool { return c.runState("slow", 2).GetState() == store.RunRunning })
	resp, err := c.admin.CancelJob(c.ctx, &armadav1.CancelJobRequest{Job: "slow"})
	if err != nil || len(resp.Runs) != 1 || resp.Runs[0] != 2 {
		t.Fatalf("cancel %v %v", resp, err)
	}
	if r := c.runState("slow", 2); r.State != store.RunCancelled || !strings.Contains(r.Message, "admin:ryan") {
		t.Errorf("cancelled run %v", r)
	}
	c.eventually("cancelled container stopped", func() bool {
		cs, _ := d.List(c.ctx, nil)
		for _, ct := range cs {
			if ct.State == runtime.StateRunning {
				return false
			}
		}
		return true
	})

	// Only admins manage jobs.
	agent := armadav1.NewAdminServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindNode, Name: "n1"}))
	if _, err := agent.RunJob(c.ctx, &armadav1.RunJobRequest{Job: "slow"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("node runs a job: %v", err)
	}
}

func TestJobHistory(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	d := c.addNode("n1", "10.0.0.11")
	c.deploy("kind: job\nname: tick\nimage: busybox:1\nhistory: 1\n")
	for run := int64(1); run <= 2; run++ {
		if _, err := c.admin.RunJob(c.ctx, &armadav1.RunJobRequest{Job: "tick"}); err != nil {
			t.Fatal(err)
		}
		var replica string
		c.eventually("running", func() bool {
			r := c.runState("tick", run)
			replica = r.GetReplica()
			return r.GetState() == store.RunRunning && containerCount(d) >= 1
		})
		c.eventually("container", func() bool {
			cs, _ := d.List(c.ctx, nil)
			for _, ct := range cs {
				if ct.Labels[runtime.LabelReplica] == replica {
					return true
				}
			}
			return false
		})
		exitAttempt(t, []*fake.Driver{d}, replica, 0)
		c.eventually("succeeded", func() bool { return c.runState("tick", run).GetState() == store.RunSucceeded })
	}
	c.eventually("first run pruned", func() bool {
		runs := c.runs("tick")
		return len(runs) == 1 && runs[0].Run == 2 && containerCount(d) == 1
	})
	jobs, err := c.admin.ListJobs(c.ctx, &armadav1.ListJobsRequest{})
	if err != nil || len(jobs.Jobs) != 1 || jobs.Jobs[0].LastRun.GetRun() != 2 || jobs.Jobs[0].NextRun != nil {
		t.Errorf("jobs %v %v", jobs, err)
	}
}

// Scheduling: a due fire starts a run once, a fire missed by more than the
// starting deadline is skipped, and with concurrency forbid a fire while a
// run is active is skipped.
func TestScheduleJob(t *testing.T) {
	t.Parallel()
	st := storetest.Open(t)
	ctx := context.Background()
	sp, err := spec.Parse([]byte("kind: job\nname: tick\nimage: busybox:1\nschedule: \"*/10 * * * *\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	rev, _, err := st.Deploy(ctx, sp, "admin:test")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{store: st, log: slog.New(slog.DiscardHandler), events: newEventRecorder(), jobRuns: newJobRunsCounter(), now: time.Now}
	revs := &revisionCache{store: st, m: map[string]store.Revision{}}
	sched := func(at time.Time) []store.JobRun {
		t.Helper()
		job, err := st.GetApp(ctx, "tick")
		if err != nil {
			t.Fatal(err)
		}
		runs, _ := st.ListJobRuns(ctx, "tick")
		rc := &reconcileRun{now: at}
		out, err := s.scheduleJob(ctx, rc, job, runs, revs)
		if err != nil {
			t.Fatal(err)
		}
		if rc.wake <= 0 || rc.wake > 10*time.Minute {
			t.Errorf("wake %v", rc.wake)
		}
		return out
	}
	created := rev.CreatedAt
	if runs := sched(created.Add(time.Second)); len(runs) != 0 {
		t.Fatalf("ran before the first fire: %v", runs)
	}
	first := created.Truncate(10 * time.Minute).Add(10 * time.Minute)
	runs := sched(first.Add(30 * time.Second))
	if len(runs) != 1 || !runs[0].CreatedAt.Equal(first) || runs[0].Trigger != store.TriggerSchedule {
		t.Fatalf("first fire: %+v", runs)
	}
	if again := sched(first.Add(40 * time.Second)); len(again) != 1 {
		t.Errorf("one fire ran twice: %+v", again)
	}
	// The next fire comes while run 1 is still pending: skipped.
	if runs := sched(first.Add(10*time.Minute + time.Second)); len(runs) != 1 {
		t.Errorf("forbid: %+v", runs)
	}
	// An hour later, with run 1 over: the latest fire runs.
	r := runs[0]
	r.State, r.FinishedAt = store.RunSucceeded, first.Add(time.Minute)
	if err := st.UpdateJobRun(ctx, r); err != nil {
		t.Fatal(err)
	}
	if runs := sched(first.Add(10*time.Minute + 61*time.Minute)); len(runs) != 2 {
		t.Errorf("a fire within the deadline: %+v", runs)
	}
	evs, _ := st.ListEvents(ctx, time.Time{})
	var reasons []string
	for _, e := range evs {
		reasons = append(reasons, e.Reason)
	}
	if !strings.Contains(strings.Join(reasons, ","), "Skipped") {
		t.Errorf("events %v", reasons)
	}
}

// A fire missed by more than an hour is recorded and not run.
func TestScheduleJobMissed(t *testing.T) {
	t.Parallel()
	st := storetest.Open(t)
	ctx := context.Background()
	sp, _ := spec.Parse([]byte("kind: job\nname: daily\nimage: busybox:1\nschedule: \"0 3 * * *\"\n"))
	rev, _, err := st.Deploy(ctx, sp, "admin:test")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{store: st, log: slog.New(slog.DiscardHandler), events: newEventRecorder(), jobRuns: newJobRunsCounter(), now: time.Now}
	job, _ := st.GetApp(ctx, "daily")
	fire, _ := sp.JobSchedule()
	due := fire.Next(rev.CreatedAt)
	rc := &reconcileRun{now: due.Add(90 * time.Minute)}
	runs, err := s.scheduleJob(ctx, rc, job, nil, &revisionCache{store: st, m: map[string]store.Revision{}})
	if err != nil || len(runs) != 0 {
		t.Fatalf("missed fire ran: %v %v", runs, err)
	}
	if job, _ := st.GetApp(ctx, "daily"); !job.LastScheduled.Equal(due) {
		t.Errorf("last scheduled %v, want %v", job.LastScheduled, due)
	}
	evs, _ := st.ListEvents(ctx, time.Time{})
	if len(evs) != 1 || evs[0].Reason != "Missed" {
		t.Errorf("events %+v", evs)
	}
}

// Runs go only to nodes whose agent runs jobs.
func TestJobNeedsJobNodes(t *testing.T) {
	t.Parallel()
	st := storetest.Open(t)
	ctx := context.Background()
	sp, _ := spec.Parse([]byte("kind: job\nname: once\nimage: busybox:1\n"))
	if _, _, err := st.Deploy(ctx, sp, "admin:test"); err != nil {
		t.Fatal(err)
	}
	run, err := st.CreateJobRun(ctx, "once", store.TriggerManual, time.Time{}, "admin:test")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{store: st, log: slog.New(slog.DiscardHandler), events: newEventRecorder(), jobRuns: newJobRunsCounter(), now: time.Now}
	job, _ := st.GetApp(ctx, "once")
	old := []store.Node{{ID: "old", State: store.NodeReady, CPUMillis: 4000, MemoryBytes: 8 << 30}}
	rc := &reconcileRun{now: time.Now()}
	all, err := s.startAttempt(ctx, rc, job, &run, old, nil, &revisionCache{store: st, m: map[string]store.Revision{}})
	if err != nil || len(all) != 0 || run.State != store.RunPending {
		t.Errorf("placed on a node without jobs: %v %+v %v", all, run, err)
	}
	evs, _ := st.ListEvents(ctx, time.Time{})
	if len(evs) != 1 || evs[0].Reason != "Unschedulable" {
		t.Errorf("events %+v", evs)
	}
}

func testutilCounter(c prometheus.Counter) float64 {
	var m dto.Metric
	_ = c.Write(&m)
	return m.GetCounter().GetValue()
}

func slicesContains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

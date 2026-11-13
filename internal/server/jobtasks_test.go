package server

import (
	"strings"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
	"github.com/ryanbekhen/armada/internal/store"
)

// task returns task i of a job's run.
func (c *cluster) task(job string, run int64, i int) *armadav1.JobTaskInfo {
	r := c.runState(job, run)
	if r == nil || i >= len(r.Tasks) {
		return nil
	}
	return r.Tasks[i]
}

// taskRunning waits until task i of run 1 runs in a container, and returns
// its replica.
func (c *cluster) taskRunning(ds []*fake.Driver, job string, i int, attempt int32) string {
	c.t.Helper()
	var replica string
	c.eventually("task running", func() bool {
		t := c.task(job, 1, i)
		if t.GetState() != store.RunRunning || t.GetAttempts() != attempt {
			return false
		}
		replica = t.GetReplica()
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
	return replica
}

func running(r *armadav1.JobRunInfo) int {
	n := 0
	for _, t := range r.GetTasks() {
		if t.State == store.RunRunning {
			n++
		}
	}
	return n
}

func TestJobTasks(t *testing.T) {
	t.Parallel()
	c := newCluster(t, func(cfg *Config) { cfg.JobRetryBase = 50 * time.Millisecond })
	ds := []*fake.Driver{c.addNode("n1", "10.0.0.11"), c.addNode("n2", "10.0.0.12")}
	c.deploy("kind: job\nname: report\nimage: busybox:1\ntasks: 3\nparallelism: 2\nretries: 1\n")
	if _, err := c.admin.RunJob(c.ctx, &armadav1.RunJobRequest{Job: "report"}); err != nil {
		t.Fatal(err)
	}
	r0 := c.taskRunning(ds, "report", 0, 1)
	r1 := c.taskRunning(ds, "report", 1, 1)
	time.Sleep(200 * time.Millisecond)
	if r := c.runState("report", 1); running(r) != 2 || r.Tasks[2].State != store.RunPending || r.State != store.RunRunning {
		t.Fatalf("parallelism 2: %v", r)
	}
	// Each container knows its task and how many there are.
	found := false
	for _, d := range ds {
		cs, _ := d.List(c.ctx, nil)
		for _, ct := range cs {
			if ct.Labels[runtime.LabelReplica] == r1 {
				sp, _ := d.Spec(ct.ID)
				found = slicesContains(sp.Env, "ARMADA_JOB_TASK=1") && slicesContains(sp.Env, "ARMADA_JOB_TASKS=3")
			}
		}
	}
	if !found {
		t.Error("task env missing")
	}

	// A finished task frees its place for the next.
	exitAttempt(t, ds, r0, 0)
	r2 := c.taskRunning(ds, "report", 2, 1)
	// A failed task is retried on its own.
	exitAttempt(t, ds, r1, 4)
	r1 = c.taskRunning(ds, "report", 1, 2)
	if r := c.runState("report", 1); r.State != store.RunRunning || r.Tasks[0].State != store.RunSucceeded {
		t.Fatalf("after a retry: %v", r)
	}
	exitAttempt(t, ds, r1, 0)
	exitAttempt(t, ds, r2, 0)
	c.eventually("succeeded", func() bool { return c.runState("report", 1).GetState() == store.RunSucceeded })
	if r := c.runState("report", 1); r.Attempts != 4 {
		t.Errorf("attempts %d, want 4", r.Attempts)
	}
	// Each task keeps its latest attempt's container for its logs.
	reps, _ := c.store.ListReplicas(c.ctx, store.ReplicaFilter{App: "report"})
	if len(reps) != 3 {
		t.Errorf("replicas kept %+v", reps)
	}
	task := int32(1)
	if rep, err := c.srv.runReplica(c.ctx, "report", 1, &task); err != nil || rep != r1 {
		t.Errorf("logs of task 1: %q %v, want %q", rep, err, r1)
	}
	task = 3
	if _, err := c.srv.runReplica(c.ctx, "report", 1, &task); err == nil {
		t.Error("logs of a task that does not exist")
	}
}

func TestJobTaskFailsRun(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	ds := []*fake.Driver{c.addNode("n1", "10.0.0.11")}
	c.deploy("kind: job\nname: sync\nimage: busybox:1\ntasks: 2\n")
	if _, err := c.admin.RunJob(c.ctx, &armadav1.RunJobRequest{Job: "sync"}); err != nil {
		t.Fatal(err)
	}
	r0 := c.taskRunning(ds, "sync", 0, 1)
	r1 := c.taskRunning(ds, "sync", 1, 1)
	exitAttempt(t, ds, r0, 2)
	c.eventually("failed", func() bool { return c.runState("sync", 1).GetState() == store.RunFailed })
	r := c.runState("sync", 1)
	if r.ExitCode != 2 || !strings.Contains(r.Message, "task 0 exited with code 2") || r.Tasks[1].State != store.RunCancelled {
		t.Errorf("run %v", r)
	}
	// The other task's container is stopped and kept.
	c.eventually("other task stopped", func() bool {
		cs, _ := ds[0].List(c.ctx, nil)
		for _, ct := range cs {
			if ct.Labels[runtime.LabelReplica] == r1 {
				return ct.State != runtime.StateRunning
			}
		}
		return false
	})
}

func TestJobTasksCancel(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	ds := []*fake.Driver{c.addNode("n1", "10.0.0.11")}
	c.deploy("kind: job\nname: sync\nimage: busybox:1\ntasks: 3\nparallelism: 1\n")
	if _, err := c.admin.RunJob(c.ctx, &armadav1.RunJobRequest{Job: "sync"}); err != nil {
		t.Fatal(err)
	}
	c.taskRunning(ds, "sync", 0, 1)
	if _, err := c.admin.CancelJob(c.ctx, &armadav1.CancelJobRequest{Job: "sync"}); err != nil {
		t.Fatal(err)
	}
	r := c.runState("sync", 1)
	for _, tk := range r.Tasks {
		if tk.State != store.RunCancelled {
			t.Errorf("task %d %s after cancel", tk.Index, tk.State)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if reps, _ := c.store.ListReplicas(c.ctx, store.ReplicaFilter{App: "sync"}); len(reps) != 1 {
		t.Errorf("a cancelled run started more tasks: %+v", reps)
	}
}

package agent

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/store"
)

func attemptSpec(done bool) *armadav1.ReplicaSpec {
	s := replica("backup-j1-aaaaa", "busybox:1", 0)
	s.App = "backup"
	s.Job = &armadav1.JobAttempt{Job: "backup", Run: 1, Done: done}
	return s
}

func onlyState(t *testing.T, r *armadav1.ReplicaReport) *armadav1.ReplicaState {
	t.Helper()
	if r == nil || len(r.Replicas) != 1 {
		t.Fatalf("report %v", r)
	}
	return r.Replicas[0]
}

// A job attempt runs once: it reports its exit code and is never restarted.
func TestJobAttemptRunsOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, d := newAgent(t)
	a.setDesired([]*armadav1.ReplicaSpec{attemptSpec(false)}, nil)
	report, err := a.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st := onlyState(t, report); st.State != store.ReplicaRunning || st.Finished {
		t.Fatalf("running attempt %v", st)
	}
	cs, _ := d.List(ctx, nil)
	if len(cs) != 1 {
		t.Fatalf("containers %v", cs)
	}
	d.SetState(cs[0].ID, runtime.StateExited, 3)
	for range 3 {
		report, _ = a.Reconcile(ctx)
		st := onlyState(t, report)
		if st.State != store.ReplicaExited || !st.Finished || st.ExitCode != 3 {
			t.Fatalf("finished attempt %v", st)
		}
	}
	if after, _ := d.List(ctx, nil); len(after) != 1 || after[0].ID != cs[0].ID {
		t.Errorf("attempt restarted: %v", after)
	}

	if n := d.Released[cs[0].ID]; n == 0 {
		t.Error("the finished attempt kept its address")
	}

	// Marking it done keeps the stopped container for its logs.
	a.setDesired([]*armadav1.ReplicaSpec{attemptSpec(true)}, nil)
	if _, err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if after, _ := d.List(ctx, nil); len(after) != 1 || after[0].ID != cs[0].ID {
		t.Errorf("done attempt's container: %v", after)
	}
}

// A done attempt that still runs (timed out, cancelled) is stopped, and a
// done attempt whose container is gone is never started.
func TestJobAttemptDone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, d := newAgent(t)
	a.setDesired([]*armadav1.ReplicaSpec{attemptSpec(false)}, nil)
	if _, err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	cs, _ := d.List(ctx, nil)
	a.setDesired([]*armadav1.ReplicaSpec{attemptSpec(true)}, nil)
	report, _ := a.Reconcile(ctx)
	if st := onlyState(t, report); st.State != store.ReplicaExited {
		t.Errorf("stopped attempt %v", st)
	}
	if c, _ := d.Inspect(ctx, cs[0].ID); c.State == runtime.StateRunning {
		t.Error("done attempt still runs")
	}
	if err := d.Remove(ctx, cs[0].ID); err != nil {
		t.Fatal(err)
	}
	report, _ = a.Reconcile(ctx)
	if len(report.GetReplicas()) != 0 {
		t.Errorf("report for a gone done attempt: %v", report)
	}
	if after, _ := d.List(ctx, nil); len(after) != 0 {
		t.Errorf("done attempt started again: %v", after)
	}
}

// A container created but never started has not run the job: it is
// started afresh.
func TestJobAttemptCreatedNotStarted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, d := newAgent(t)
	s := attemptSpec(false)
	d.Add(runtime.Container{ID: "half", Name: "armada-" + s.Id, State: runtime.StateCreated, Labels: map[string]string{
		runtime.LabelManaged: "true", runtime.LabelReplica: s.Id, runtime.LabelSpecHash: specHash(s)}})
	a.setDesired([]*armadav1.ReplicaSpec{s}, nil)
	report, _ := a.Reconcile(ctx)
	if st := onlyState(t, report); st.State != store.ReplicaRunning || st.ContainerId == "half" {
		t.Errorf("created attempt %v", st)
	}
}

// Marking an attempt done does not change its spec hash: the container is
// stopped, never recreated.
func TestJobDoneOutsideSpecHash(t *testing.T) {
	t.Parallel()
	running, done := attemptSpec(false), attemptSpec(true)
	if specHash(running) != specHash(done) {
		t.Error("done changes the spec hash")
	}
	if !proto.Equal(running.Job, attemptSpec(false).Job) {
		t.Error("specHash modified its argument")
	}
}

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/spec"
)

func deployJob(t *testing.T, s *Etcd, yaml string) Revision {
	t.Helper()
	sp, err := spec.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	rev, _, err := s.Deploy(context.Background(), sp, "admin:test")
	if err != nil {
		t.Fatal(err)
	}
	return rev
}

func TestJobDeployAndRuns(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	r1 := deployJob(t, s, "kind: job\nname: backup\nimage: busybox:1\nschedule: \"0 3 * * *\"\n")
	a, err := s.GetApp(ctx, "backup")
	if err != nil {
		t.Fatal(err)
	}
	if a.ActiveRevision != r1.Name || a.Rolling() || a.Replicas != 0 {
		t.Fatalf("job app %+v", a)
	}
	// A new spec is active at once: jobs have no rollouts.
	r2 := deployJob(t, s, "kind: job\nname: backup\nimage: busybox:2\nschedule: \"0 3 * * *\"\n")
	if a, _ := s.GetApp(ctx, "backup"); a.ActiveRevision != r2.Name || a.Rolling() {
		t.Errorf("redeploy: %+v", a)
	}

	// Jobs and apps never share a name, either way round.
	app, _ := spec.Parse([]byte("name: backup\nimage: nginx\n"))
	if _, _, err := s.Deploy(ctx, app, "admin:test"); !errors.Is(err, ErrConflict) {
		t.Errorf("app over a job: %v", err)
	}
	deployJob(t, s, "name: web\nimage: nginx\n")
	job, _ := spec.Parse([]byte("kind: job\nname: web\nimage: busybox\n"))
	if _, _, err := s.Deploy(ctx, job, "admin:test"); !errors.Is(err, ErrConflict) {
		t.Errorf("job over an app: %v", err)
	}
	if _, err := s.CreateJobRun(ctx, "web", TriggerManual, time.Time{}, "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("run an app: %v", err)
	}
	if err := s.SetReplicas(ctx, "backup", 3, "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("scale a job: %v", err)
	}
	if _, err := s.Rollback(ctx, "backup", r1.Name, "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("roll back a job: %v", err)
	}

	// A schedule fire runs once.
	at := time.Date(2026, 11, 3, 3, 0, 0, 0, time.UTC)
	run, err := s.CreateJobRun(ctx, "backup", TriggerSchedule, at, "")
	if err != nil {
		t.Fatal(err)
	}
	if run.Seq != 1 || run.State != RunPending || run.Revision != r2.Name || !run.CreatedAt.Equal(at) {
		t.Errorf("run %+v", run)
	}
	if _, err := s.CreateJobRun(ctx, "backup", TriggerSchedule, at, ""); !errors.Is(err, ErrConflict) {
		t.Errorf("same fire twice: %v", err)
	}
	if err := s.SkipJobSchedule(ctx, "backup", at.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if a, _ := s.GetApp(ctx, "backup"); !a.LastScheduled.Equal(at.Add(24 * time.Hour)) {
		t.Errorf("last scheduled %v", a.LastScheduled)
	}
	manual, err := s.CreateJobRun(ctx, "backup", TriggerManual, time.Time{}, "admin:test")
	if err != nil || manual.Seq != 2 {
		t.Fatalf("manual run %+v %v", manual, err)
	}

	// Attempts are replicas of the run; done is sticky, results kept.
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	rep := Replica{ID: "backup-j1-aaaaa", App: "backup", Revision: run.Revision, NodeID: "n1", Run: 1}
	if err := s.CreateReplica(ctx, rep); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateReplicaStatus(ctx, "n1", ReplicaStatus{ID: rep.ID, State: ReplicaExited, Finished: true, ExitCode: 3}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetReplicaDone(ctx, rep.ID); err != nil {
		t.Fatal(err)
	}
	// The stopped container of a done attempt reports another code.
	_ = s.UpdateReplicaStatus(ctx, "n1", ReplicaStatus{ID: rep.ID, State: ReplicaExited, Finished: true, ExitCode: 143})
	reps, _ := s.ListReplicas(ctx, ReplicaFilter{App: "backup"})
	if len(reps) != 1 || reps[0].Run != 1 || !reps[0].Done || !reps[0].Finished || reps[0].ExitCode != 3 {
		t.Errorf("attempt %+v", reps)
	}

	// The revision of a pending run survives redeploys.
	for i := 3; i < 10; i++ {
		deployJob(t, s, "kind: job\nname: backup\nimage: busybox:"+string(rune('0'+i))+"\n")
	}
	if _, err := s.GetRevision(ctx, r2.Name); err != nil {
		t.Errorf("revision of pending runs pruned: %v", err)
	}

	cancelled, err := s.CancelJobRuns(ctx, "backup", "admin:test")
	if err != nil || len(cancelled) != 2 {
		t.Fatalf("cancel: %v %v", cancelled, err)
	}
	runs, _ := s.ListJobRuns(ctx, "backup")
	for _, r := range runs {
		if r.State != RunCancelled || r.FinishedAt.IsZero() {
			t.Errorf("after cancel %+v", r)
		}
	}
	if err := s.DeleteJobRun(ctx, "backup", 1); err != nil {
		t.Fatal(err)
	}
	if reps, _ := s.ListReplicas(ctx, ReplicaFilter{App: "backup"}); len(reps) != 0 {
		t.Errorf("attempt left after its run: %+v", reps)
	}
	// Run numbers are never reused.
	if r, _ := s.CreateJobRun(ctx, "backup", TriggerManual, time.Time{}, "admin:test"); r.Seq != 3 {
		t.Errorf("seq after prune %d", r.Seq)
	}

	if err := s.DeleteJob(ctx, "web", "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("delete an app as a job: %v", err)
	}
	if err := s.DeleteJob(ctx, "backup", "admin:test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetApp(ctx, "backup"); !errors.Is(err, ErrNotFound) {
		t.Errorf("job after delete: %v", err)
	}
	if runs, _ := s.ListJobRuns(ctx, "backup"); len(runs) != 0 {
		t.Errorf("runs after delete: %v", runs)
	}
}

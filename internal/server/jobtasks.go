package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ryanbekhen/armada/internal/store"
)

// reconcileTasks moves a run whose job has several tasks (spec tasks, ADR
// 0019): it watches the running tasks, retries or fails those that ended
// badly, starts pending ones while fewer than the job's parallelism run, and
// ends the run once every task succeeded or one failed for good.
func (s *Server) reconcileTasks(ctx context.Context, rc *reconcileRun, job store.App, r *store.JobRun, nodes []store.Node, all []store.Replica, revs *revisionCache) ([]store.Replica, error) {
	rev, err := revs.get(ctx, r.Revision)
	if errors.Is(err, store.ErrNotFound) {
		all, err = s.stopTasks(ctx, r, all)
		if err != nil {
			return nil, err
		}
		return all, s.endRun(ctx, r, store.RunFailed, 0, "revision "+r.Revision+" no longer exists")
	}
	if err != nil {
		return nil, err
	}
	timeout, retries := rev.Spec.JobTimeout(), rev.Spec.Retries
	changed := false

	for i := range r.Tasks {
		t := &r.Tasks[i]
		if t.State != store.RunRunning {
			continue
		}
		idx := slices.IndexFunc(all, func(x store.Replica) bool { return x.ID == t.Replica })
		var (
			over, succeeded = true, false
			code            int
			msg             = "its replica disappeared"
		)
		if idx >= 0 {
			over, succeeded, code, msg = attemptOutcome(rc, all[idx], t.AttemptAt, timeout)
		}
		if !over {
			continue
		}
		if idx >= 0 {
			if err := s.store.SetReplicaDone(ctx, t.Replica); err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
			all[idx].Done = true
		}
		changed = true
		switch {
		case succeeded:
			t.State, t.ExitCode, t.Message, t.FinishedAt = store.RunSucceeded, 0, "", rc.now
		case t.Attempts > retries:
			t.State, t.ExitCode, t.Message, t.FinishedAt = store.RunFailed, code, msg, rc.now
		default:
			wait := min(s.jobRetryBase<<min(t.Attempts-1, 10), jobRetryMax)
			t.State, t.ExitCode, t.Message, t.AttemptAt = store.RunPending, code, msg, rc.now.Add(wait)
			s.record(ctx, store.Event{Kind: eventJob, Object: runObject(*r), App: r.Job, Node: t.Node, Reason: "Retrying",
				Message: fmt.Sprintf("task %d: attempt %d %s; attempt %d in %s", t.Index, t.Attempts, msg, t.Attempts+1, wait)})
		}
	}

	if i := slices.IndexFunc(r.Tasks, func(t store.RunTask) bool { return t.State == store.RunFailed }); i >= 0 {
		failed := r.Tasks[i]
		if all, err = s.stopTasks(ctx, r, all); err != nil {
			return nil, err
		}
		return all, s.endRun(ctx, r, store.RunFailed, failed.ExitCode, fmt.Sprintf("task %d %s", failed.Index, failed.Message))
	}
	if !slices.ContainsFunc(r.Tasks, func(t store.RunTask) bool { return t.State != store.RunSucceeded }) {
		return all, s.endRun(ctx, r, store.RunSucceeded, 0, "")
	}

	running := 0
	for _, t := range r.Tasks {
		if t.State == store.RunRunning {
			running++
		}
	}
	var fit []store.Node
	for _, n := range eligible(nodes, rev) {
		if n.Jobs {
			fit = append(fit, n)
		}
	}
	unplaced := false
	for i := range r.Tasks {
		t := &r.Tasks[i]
		if t.State != store.RunPending || running >= rev.Spec.JobParallelism() {
			continue
		}
		if t.AttemptAt.After(rc.now) {
			rc.wakeAt(t.AttemptAt)
			continue
		}
		if unplaced {
			continue // the tasks of a run need the same: no node now
		}
		spread := slices.DeleteFunc(slices.Clone(all), func(x store.Replica) bool { return x.App != job.Name || x.Done })
		node, ok := pickNode(fit, all, spread, "", reservation(rev), revs.reserved(ctx))
		if !ok {
			unplaced = true
			if t.WaitingSince.IsZero() {
				t.WaitingSince, changed = rc.now, true
			}
			if rc.now.Sub(t.WaitingSince) >= timeout {
				t.State, t.Message, t.FinishedAt, changed = store.RunFailed, fmt.Sprintf("no node could run it within %s", timeout), rc.now, true
				continue
			}
			rc.wakeAt(t.WaitingSince.Add(timeout))
			continue
		}
		if t.Replica != "" {
			// Only the latest attempt's container is kept for its logs.
			if err := s.store.DeleteReplica(ctx, t.Replica); err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
			all = without(all, t.Replica)
		}
		rep := store.Replica{
			ID:       fmt.Sprintf("%s-j%d-t%d-%s", job.Name, r.Seq, t.Index, randomID(5)),
			App:      job.Name,
			Revision: rev.Name,
			NodeID:   node.ID,
			State:    store.ReplicaPending,
			Run:      r.Seq,
			Task:     t.Index,
		}
		if err := s.store.CreateReplica(ctx, rep); err != nil {
			return nil, err
		}
		all = append(all, rep)
		running++
		changed = true
		t.State, t.Replica, t.Node, t.Message, t.WaitingSince = store.RunRunning, rep.ID, node.ID, "", time.Time{}
		t.Attempts++
		t.AttemptAt = rc.now
		r.State, r.Replica, r.Node = store.RunRunning, rep.ID, node.ID
		r.Attempts++
		r.AttemptAt = rc.now
		if r.StartedAt.IsZero() {
			r.StartedAt = rc.now
		}
		s.log.Info("job task placed", "job", job.Name, "run", r.Seq, "task", t.Index, "attempt", t.Attempts, "node", node.ID)
		s.record(ctx, store.Event{Kind: eventJob, Object: runObject(*r), App: job.Name, Node: node.ID, Reason: "Started",
			Message: fmt.Sprintf("task %d attempt %d on %s (%s)", t.Index, t.Attempts, node.ID, r.Trigger)})
		rc.wakeAt(rc.now.Add(timeout))
	}
	s.condition(ctx, "job-unplaced:"+runObject(*r), unplaced, store.Event{Kind: eventJob, Object: runObject(*r), App: job.Name, Reason: "Unschedulable",
		Message: "no node can run its next task now (placement, capacity, or no agent that runs jobs); see armada job show"})
	if i := slices.IndexFunc(r.Tasks, func(t store.RunTask) bool { return t.State == store.RunFailed }); i >= 0 {
		// A task found no node in time: the run fails on the next pass.
		rc.wakeAt(rc.now)
	}
	if !changed {
		return all, nil
	}
	return all, s.store.UpdateJobRun(ctx, *r)
}

// stopTasks ends the tasks of r that have not ended as cancelled, and
// marks their attempts done so their agents stop them.
func (s *Server) stopTasks(ctx context.Context, r *store.JobRun, all []store.Replica) ([]store.Replica, error) {
	for i := range r.Tasks {
		t := &r.Tasks[i]
		if t.State != store.RunPending && t.State != store.RunRunning {
			continue
		}
		if t.State == store.RunRunning {
			if err := s.store.SetReplicaDone(ctx, t.Replica); err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
			if idx := slices.IndexFunc(all, func(x store.Replica) bool { return x.ID == t.Replica }); idx >= 0 {
				all[idx].Done = true
			}
		}
		t.State, t.FinishedAt = store.RunCancelled, s.now()
	}
	return all, nil
}

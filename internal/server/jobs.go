package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// Jobs (ADR 0019).
const (
	// jobStartingDeadline is how late a scheduled run may still start, for
	// fires missed while the control plane was down.
	jobStartingDeadline = time.Hour
	// jobLogsKept is how long the container of a finished run is kept for
	// its logs.
	jobLogsKept = 24 * time.Hour
	// maxScheduleCatchUp bounds the fires walked to find the latest due one.
	maxScheduleCatchUp = 100_000
	eventJob           = "job"
	jobActor           = "armada:schedule"
)

// The delay before a retry doubles with each failed attempt, from
// Config.JobRetryBase up to jobRetryMax.
const (
	defaultJobRetryBase = 10 * time.Second
	jobRetryMax         = 5 * time.Minute
)

func newJobRunsCounter() *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "armada_job_runs_total", Help: "Job runs that ended, by job and result (succeeded, failed, cancelled).",
	}, []string{"job", "result"})
}

// reconcileJobs schedules runs, places and watches their attempts, and
// prunes old runs. all is updated with the replicas it creates, marks
// done, or deletes.
func (s *Server) reconcileJobs(ctx context.Context, rc *reconcileRun, jobs []store.App, nodes []store.Node, all []store.Replica, revs *revisionCache) ([]store.Replica, error) {
	if len(jobs) == 0 {
		return all, nil
	}
	runs, err := s.store.ListJobRuns(ctx, "")
	if err != nil {
		return nil, err
	}
	byJob := map[string][]store.JobRun{}
	for _, r := range runs {
		byJob[r.Job] = append(byJob[r.Job], r)
	}
	for _, job := range jobs {
		if all, err = s.reconcileJob(ctx, rc, job, byJob[job.Name], nodes, all, revs); err != nil {
			return nil, fmt.Errorf("job %s: %w", job.Name, err)
		}
	}
	return all, nil
}

func (s *Server) reconcileJob(ctx context.Context, rc *reconcileRun, job store.App, runs []store.JobRun, nodes []store.Node, all []store.Replica, revs *revisionCache) ([]store.Replica, error) {
	runs, err := s.scheduleJob(ctx, rc, job, runs, revs)
	if err != nil {
		return nil, err
	}
	for i := range runs {
		r := &runs[i]
		switch r.State {
		case store.RunPending:
			all, err = s.startAttempt(ctx, rc, job, r, nodes, all, revs)
		case store.RunRunning:
			all, err = s.watchAttempt(ctx, rc, job, r, all)
		}
		if err != nil {
			return nil, err
		}
	}
	return s.pruneRuns(ctx, rc, job, runs, all)
}

// scheduleJob creates the run for the latest due fire of job's schedule,
// if any, and returns runs with it.
func (s *Server) scheduleJob(ctx context.Context, rc *reconcileRun, job store.App, runs []store.JobRun, revs *revisionCache) ([]store.JobRun, error) {
	sched, ok := job.Spec.JobSchedule()
	if !ok {
		return runs, nil
	}
	// A schedule counts from its last fire or the revision that set it,
	// so a new schedule does not fire for times before it existed.
	base := job.LastScheduled
	if rev, err := revs.get(ctx, job.ActiveRevision); err == nil && rev.CreatedAt.After(base) {
		base = rev.CreatedAt
	}
	next := sched.Next(base)
	if next.After(rc.now) {
		rc.wakeAt(next)
		return runs, nil
	}
	due := next
	for range maxScheduleCatchUp {
		n := sched.Next(due)
		if n.After(rc.now) {
			break
		}
		due = n
	}
	rc.wakeAt(sched.Next(due))
	at := due.UTC().Format(time.RFC3339)
	event := store.Event{Kind: eventJob, Object: job.Name, App: job.Name}
	if late := rc.now.Sub(due); late > jobStartingDeadline {
		if err := s.store.SkipJobSchedule(ctx, job.Name, due); err != nil {
			return nil, err
		}
		event.Reason, event.Message = "Missed", fmt.Sprintf("not run for %s: the control plane was down for %s past it", at, late.Round(time.Minute))
		s.record(ctx, event)
		return runs, nil
	}
	var active []store.JobRun
	for _, r := range runs {
		if r.Active() {
			active = append(active, r)
		}
	}
	if len(active) > 0 {
		if job.Spec.JobConcurrency() == spec.ConcurrencyForbid {
			if err := s.store.SkipJobSchedule(ctx, job.Name, due); err != nil {
				return nil, err
			}
			event.Reason, event.Message = "Skipped", fmt.Sprintf("not run for %s: run %d is still active", at, active[len(active)-1].Seq)
			s.record(ctx, event)
			return runs, nil
		}
		cancelled, err := s.store.CancelJobRuns(ctx, job.Name, jobActor)
		if err != nil {
			return nil, err
		}
		runs = s.cancelled(ctx, runs, cancelled, "replaced by the run for "+at)
	}
	run, err := s.store.CreateJobRun(ctx, job.Name, store.TriggerSchedule, due, "")
	if errors.Is(err, store.ErrConflict) {
		return runs, nil // already created
	}
	if err != nil {
		return nil, err
	}
	return append(runs, run), nil
}

// cancelled updates runs with the runs the store cancelled and records it.
func (s *Server) cancelled(ctx context.Context, runs, cancelled []store.JobRun, why string) []store.JobRun {
	for _, c := range cancelled {
		for i := range runs {
			if runs[i].Seq == c.Seq {
				runs[i] = c
			}
		}
		s.jobRuns.WithLabelValues(c.Job, store.RunCancelled).Inc()
		s.record(ctx, store.Event{Kind: eventJob, Object: runObject(c), App: c.Job, Node: c.Node, Reason: "Cancelled", Message: why})
	}
	return runs
}

func runObject(r store.JobRun) string { return r.Job + "#" + strconv.FormatInt(r.Seq, 10) }

// startAttempt places the next attempt of a pending run once its retry
// delay has passed.
func (s *Server) startAttempt(ctx context.Context, rc *reconcileRun, job store.App, r *store.JobRun, nodes []store.Node, all []store.Replica, revs *revisionCache) ([]store.Replica, error) {
	if r.AttemptAt.After(rc.now) {
		rc.wakeAt(r.AttemptAt)
		return all, nil
	}
	rev, err := revs.get(ctx, r.Revision)
	if errors.Is(err, store.ErrNotFound) {
		return all, s.endRun(ctx, r, store.RunFailed, 0, "revision "+r.Revision+" no longer exists")
	}
	if err != nil {
		return nil, err
	}
	var fit []store.Node
	for _, n := range eligible(nodes, rev) {
		if n.Jobs {
			fit = append(fit, n)
		}
	}
	node, ok := pickNode(fit, all, nil, "", reservation(rev), revs.reserved(ctx))
	waitingSince := r.CreatedAt
	if r.AttemptAt.After(waitingSince) {
		waitingSince = r.AttemptAt
	}
	s.condition(ctx, "job-unplaced:"+runObject(*r), !ok, store.Event{Kind: eventJob, Object: runObject(*r), App: job.Name, Reason: "Unschedulable",
		Message: "no node can run it now (placement, capacity, or no agent that runs jobs); see armada job show"})
	if !ok {
		timeout := rev.Spec.JobTimeout()
		if rc.now.Sub(waitingSince) >= timeout {
			return all, s.endRun(ctx, r, store.RunFailed, 0, fmt.Sprintf("no node could run it within %s", timeout))
		}
		rc.wakeAt(waitingSince.Add(timeout))
		return all, nil
	}
	if r.Replica != "" {
		// Only the latest attempt's container is kept for its logs.
		if err := s.store.DeleteReplica(ctx, r.Replica); err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		all = without(all, r.Replica)
	}
	rep := store.Replica{
		ID:       fmt.Sprintf("%s-j%d-%s", job.Name, r.Seq, randomID(5)),
		App:      job.Name,
		Revision: rev.Name,
		NodeID:   node.ID,
		State:    store.ReplicaPending,
		Run:      r.Seq,
	}
	err = s.store.CreateReplica(ctx, rep)
	if err != nil {
		return nil, err
	}
	all = append(all, rep)
	r.State, r.Replica, r.Node, r.Message = store.RunRunning, rep.ID, node.ID, ""
	r.Attempts++
	r.AttemptAt = rc.now
	if r.StartedAt.IsZero() {
		r.StartedAt = rc.now
	}
	if err := s.store.UpdateJobRun(ctx, *r); err != nil {
		return nil, err
	}
	s.log.Info("job attempt placed", "job", job.Name, "run", r.Seq, "attempt", r.Attempts, "node", node.ID)
	s.record(ctx, store.Event{Kind: eventJob, Object: runObject(*r), App: job.Name, Node: node.ID, Reason: "Started",
		Message: fmt.Sprintf("attempt %d on %s (%s)", r.Attempts, node.ID, r.Trigger)})
	rc.wakeAt(rc.now.Add(rev.Spec.JobTimeout()))
	return all, nil
}

// watchAttempt ends a running attempt that finished, failed to start, lost
// its node, or ran past its timeout.
func (s *Server) watchAttempt(ctx context.Context, rc *reconcileRun, job store.App, r *store.JobRun, all []store.Replica) ([]store.Replica, error) {
	idx := slices.IndexFunc(all, func(x store.Replica) bool { return x.ID == r.Replica })
	if idx < 0 {
		return all, s.attemptFailed(ctx, rc, job, r, 0, "its replica disappeared")
	}
	rep := all[idx]
	timeout := job.Spec.JobTimeout()
	if rev, err := s.store.GetRevision(ctx, r.Revision); err == nil {
		timeout = rev.Spec.JobTimeout()
	}
	var (
		code      int
		msg       string
		succeeded bool
	)
	switch {
	case rep.Finished && rep.ExitCode == 0:
		succeeded = true
	case rep.Finished:
		code, msg = rep.ExitCode, "exited with code "+strconv.Itoa(rep.ExitCode)
	case rep.State == store.ReplicaFailed:
		msg = "could not start: " + rep.Message
	case rc.lost[rep.NodeID]:
		msg = "its node " + rep.NodeID + " was lost"
	case rc.now.Sub(r.AttemptAt) >= timeout:
		msg = fmt.Sprintf("timed out after %s", timeout)
		if rep.ContainerID == "" {
			msg += " before its container started (pulling the image?)"
		}
	default:
		rc.wakeAt(r.AttemptAt.Add(timeout))
		return all, nil
	}
	if err := s.store.SetReplicaDone(ctx, rep.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	rep.Done = true
	all[idx] = rep
	if succeeded {
		return all, s.endRun(ctx, r, store.RunSucceeded, 0, "")
	}
	return all, s.attemptFailed(ctx, rc, job, r, code, msg)
}

// attemptFailed retries a run if its job allows another attempt, or ends it
// as failed.
func (s *Server) attemptFailed(ctx context.Context, rc *reconcileRun, job store.App, r *store.JobRun, code int, msg string) error {
	retries := job.Spec.Retries
	if rev, err := s.store.GetRevision(ctx, r.Revision); err == nil {
		retries = rev.Spec.Retries
	}
	if r.Attempts > retries {
		return s.endRun(ctx, r, store.RunFailed, code, msg)
	}
	wait := min(s.jobRetryBase<<min(r.Attempts-1, 10), jobRetryMax)
	r.State, r.ExitCode, r.Message, r.AttemptAt = store.RunPending, code, msg, rc.now.Add(wait)
	if err := s.store.UpdateJobRun(ctx, *r); err != nil {
		return err
	}
	rc.wakeAt(r.AttemptAt)
	s.record(ctx, store.Event{Kind: eventJob, Object: runObject(*r), App: r.Job, Node: r.Node, Reason: "Retrying",
		Message: fmt.Sprintf("attempt %d %s; attempt %d in %s", r.Attempts, msg, r.Attempts+1, wait)})
	return nil
}

// endRun records the end of a run.
func (s *Server) endRun(ctx context.Context, r *store.JobRun, state string, code int, msg string) error {
	r.State, r.ExitCode, r.Message, r.FinishedAt = state, code, msg, s.now()
	if err := s.store.UpdateJobRun(ctx, *r); err != nil {
		return err
	}
	s.jobRuns.WithLabelValues(r.Job, state).Inc()
	reason := "Succeeded"
	if state != store.RunSucceeded {
		reason = "Failed"
	}
	if msg == "" && !r.StartedAt.IsZero() {
		msg = fmt.Sprintf("after %s", r.FinishedAt.Sub(r.StartedAt).Round(time.Second))
	}
	s.log.Info("job run ended", "job", r.Job, "run", r.Seq, "state", state, "attempts", r.Attempts)
	s.record(ctx, store.Event{Kind: eventJob, Object: runObject(*r), App: r.Job, Node: r.Node, Reason: reason, Message: msg})
	return nil
}

// pruneRuns keeps the newest finished runs the job's history allows, and
// the containers of finished runs for jobLogsKept.
func (s *Server) pruneRuns(ctx context.Context, rc *reconcileRun, job store.App, runs []store.JobRun, all []store.Replica) ([]store.Replica, error) {
	var ended []store.JobRun
	for _, r := range runs {
		if !r.Active() {
			ended = append(ended, r)
		}
	}
	keep := job.Spec.JobHistory()
	for i, r := range ended {
		if i < len(ended)-keep {
			if err := s.store.DeleteJobRun(ctx, r.Job, r.Seq); err != nil {
				return nil, err
			}
			all = slices.DeleteFunc(all, func(x store.Replica) bool { return x.App == r.Job && x.Run == r.Seq })
			continue
		}
		expires := r.FinishedAt.Add(jobLogsKept)
		if expires.After(rc.now) {
			rc.wakeAt(expires)
			continue
		}
		for _, x := range all {
			if x.App == r.Job && x.Run == r.Seq {
				if err := s.store.DeleteReplica(ctx, x.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
					return nil, err
				}
			}
		}
		all = slices.DeleteFunc(all, func(x store.Replica) bool { return x.App == r.Job && x.Run == r.Seq })
	}
	return all, nil
}

// jobOf returns the job named name, or a gRPC error.
func (s *Server) jobOf(ctx context.Context, name string) (store.App, error) {
	a, err := s.store.GetApp(ctx, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.App{}, status.Errorf(codes.NotFound, "job %s not found", name)
		}
		return store.App{}, storeErr(err)
	}
	if !a.Spec.IsJob() {
		return store.App{}, status.Errorf(codes.FailedPrecondition, "%s is an app, not a job", name)
	}
	return a, nil
}

// RunJob starts a run of a job now. With concurrency forbid it refuses
// while a run is active; with replace it cancels that run.
func (s *Server) RunJob(ctx context.Context, req *armadav1.RunJobRequest) (*armadav1.RunJobResponse, error) {
	if err := accessFrom(ctx).app(req.GetJob()); err != nil {
		return nil, err
	}
	job, err := s.jobOf(ctx, req.GetJob())
	if err != nil {
		return nil, err
	}
	runs, err := s.store.ListJobRuns(ctx, job.Name)
	if err != nil {
		return nil, storeErr(err)
	}
	for _, r := range runs {
		if !r.Active() {
			continue
		}
		if job.Spec.JobConcurrency() == spec.ConcurrencyForbid {
			return nil, status.Errorf(codes.FailedPrecondition, "run %d is still %s; cancel it with `armada job cancel %s` first", r.Seq, r.State, job.Name)
		}
		cancelled, err := s.store.CancelJobRuns(ctx, job.Name, actor(ctx))
		if err != nil {
			return nil, storeErr(err)
		}
		s.cancelled(ctx, nil, cancelled, "replaced by a run started by "+actor(ctx))
		break
	}
	run, err := s.store.CreateJobRun(ctx, job.Name, store.TriggerManual, time.Time{}, actor(ctx))
	if err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("job run requested", "job", job.Name, "run", run.Seq, "by", actor(ctx))
	s.Trigger()
	return &armadav1.RunJobResponse{Run: run.Seq}, nil
}

// ListJobs describes every job.
func (s *Server) ListJobs(ctx context.Context, _ *armadav1.ListJobsRequest) (*armadav1.ListJobsResponse, error) {
	apps, err := s.store.ListApps(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	runs, err := s.store.ListJobRuns(ctx, "")
	if err != nil {
		return nil, storeErr(err)
	}
	acc := accessFrom(ctx)
	resp := &armadav1.ListJobsResponse{}
	for _, a := range apps {
		if !a.Spec.IsJob() || !acc.sees(a.Name) {
			continue
		}
		info := &armadav1.JobInfo{Name: a.Name, Revision: a.ActiveRevision, Image: a.Spec.Image, Schedule: a.Spec.Schedule, TimeZone: a.Spec.TimeZone}
		for _, r := range runs {
			if r.Job != a.Name {
				continue
			}
			info.LastRun = runInfo(r)
			if r.Active() {
				info.Active++
			}
		}
		if sched, ok := a.Spec.JobSchedule(); ok {
			info.NextRun = timestamppb.New(sched.Next(s.now()))
		}
		resp.Jobs = append(resp.Jobs, info)
	}
	return resp, nil
}

// ListJobRuns lists a job's runs, newest first.
func (s *Server) ListJobRuns(ctx context.Context, req *armadav1.ListJobRunsRequest) (*armadav1.ListJobRunsResponse, error) {
	if err := accessFrom(ctx).app(req.GetJob()); err != nil {
		return nil, err
	}
	if _, err := s.jobOf(ctx, req.GetJob()); err != nil {
		return nil, err
	}
	runs, err := s.store.ListJobRuns(ctx, req.GetJob())
	if err != nil {
		return nil, storeErr(err)
	}
	resp := &armadav1.ListJobRunsResponse{}
	for i := len(runs) - 1; i >= 0; i-- {
		resp.Runs = append(resp.Runs, runInfo(runs[i]))
	}
	return resp, nil
}

func runInfo(r store.JobRun) *armadav1.JobRunInfo {
	ts := func(t time.Time) *timestamppb.Timestamp {
		if t.IsZero() {
			return nil
		}
		return timestamppb.New(t)
	}
	return &armadav1.JobRunInfo{
		Job: r.Job, Run: r.Seq, State: r.State, Trigger: r.Trigger, Revision: r.Revision,
		Attempts: int32(min(r.Attempts, 1<<31-1)), //nolint:gosec // bounded above
		Node:     r.Node, Replica: r.Replica,
		ExitCode: int32(r.ExitCode), //nolint:gosec // exit codes are small
		Message:  r.Message, CreatedAt: ts(r.CreatedAt), StartedAt: ts(r.StartedAt), FinishedAt: ts(r.FinishedAt),
	}
}

// CancelJob ends a job's active runs.
func (s *Server) CancelJob(ctx context.Context, req *armadav1.CancelJobRequest) (*armadav1.CancelJobResponse, error) {
	if err := accessFrom(ctx).app(req.GetJob()); err != nil {
		return nil, err
	}
	if _, err := s.jobOf(ctx, req.GetJob()); err != nil {
		return nil, err
	}
	cancelled, err := s.store.CancelJobRuns(ctx, req.GetJob(), actor(ctx))
	if err != nil {
		return nil, storeErr(err)
	}
	s.cancelled(ctx, nil, cancelled, "by "+actor(ctx))
	resp := &armadav1.CancelJobResponse{}
	for _, r := range cancelled {
		resp.Runs = append(resp.Runs, r.Seq)
	}
	s.log.Info("job runs cancelled", "job", req.GetJob(), "runs", len(cancelled), "by", actor(ctx))
	s.Trigger()
	return resp, nil
}

// DeleteJob removes a job with its runs; their containers are removed.
func (s *Server) DeleteJob(ctx context.Context, req *armadav1.DeleteJobRequest) (*armadav1.DeleteJobResponse, error) {
	if err := accessFrom(ctx).app(req.GetJob()); err != nil {
		return nil, err
	}
	if _, err := s.jobOf(ctx, req.GetJob()); err != nil {
		return nil, err
	}
	if err := s.store.DeleteJob(ctx, req.GetJob(), actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("job deleted", "job", req.GetJob(), "by", actor(ctx))
	s.record(ctx, store.Event{Kind: eventJob, Object: req.GetJob(), App: req.GetJob(), Reason: "Deleted", Message: "by " + actor(ctx)})
	s.Trigger()
	return &armadav1.DeleteJobResponse{}, nil
}

// runReplica returns the replica of the latest attempt of a job's run (the
// newest run if seq is 0), whose container holds its logs.
func (s *Server) runReplica(ctx context.Context, job string, seq int64) (string, error) {
	runs, err := s.store.ListJobRuns(ctx, job)
	if err != nil {
		return "", storeErr(err)
	}
	for i := len(runs) - 1; i >= 0; i-- {
		r := runs[i]
		if seq != 0 && r.Seq != seq {
			continue
		}
		switch {
		case r.Replica == "":
			return "", status.Errorf(codes.FailedPrecondition, "run %d of %s has not started", r.Seq, job)
		case !r.Active() && s.now().Sub(r.FinishedAt) >= jobLogsKept:
			return "", status.Errorf(codes.NotFound, "the logs of run %d of %s were removed %s after it finished", r.Seq, job, jobLogsKept)
		}
		return r.Replica, nil
	}
	if seq != 0 {
		return "", status.Errorf(codes.NotFound, "run %d of %s not found (finished runs beyond the job's history are removed)", seq, job)
	}
	return "", status.Errorf(codes.FailedPrecondition, "%s has no runs yet; start one with `armada job run %s`", job, job)
}

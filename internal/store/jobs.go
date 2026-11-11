package store

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

// Job run states (ADR 0019).
const (
	RunPending   = "pending"
	RunRunning   = "running"
	RunSucceeded = "succeeded"
	RunFailed    = "failed"
	RunCancelled = "cancelled"
)

// What started a run.
const (
	TriggerSchedule = "schedule"
	TriggerManual   = "manual"
	// TriggerQueue: the job's queue held messages (ADR 0040).
	TriggerQueue = "queue"
)

// JobRun is one run of a job: one or more attempts, each a replica.
type JobRun struct {
	Job      string
	Seq      int64
	Revision string
	Trigger  string
	State    string
	// Attempts is how many attempts have started; Replica and Node belong
	// to the latest.
	Attempts int
	Replica  string
	Node     string
	ExitCode int
	Message  string
	// CreatedAt is when the run was asked for (for scheduled runs, the time
	// the schedule fired); StartedAt when its first attempt was placed;
	// AttemptAt when its latest attempt was placed, or, while pending
	// after a failed attempt, when the next may start; FinishedAt when it
	// ended.
	CreatedAt, StartedAt, AttemptAt, FinishedAt time.Time
}

// Active reports whether the run has not ended.
func (r JobRun) Active() bool { return r.State == RunPending || r.State == RunRunning }

type jobRunRec struct {
	Job        string `json:"job"`
	Seq        int64  `json:"seq"`
	Revision   string `json:"revision"`
	Trigger    string `json:"trigger"`
	State      string `json:"state"`
	Attempts   int    `json:"attempts,omitempty"`
	Replica    string `json:"replica,omitempty"`
	Node       string `json:"node,omitempty"`
	ExitCode   int    `json:"exitCode,omitempty"`
	Message    string `json:"message,omitempty"`
	CreatedAt  int64  `json:"createdAt"`
	StartedAt  int64  `json:"startedAt,omitempty"`
	AttemptAt  int64  `json:"attemptAt,omitempty"`
	FinishedAt int64  `json:"finishedAt,omitempty"`
}

func runKey(job string, seq int64) string { return fmt.Sprintf("%s%s/%010d", pfxRuns, job, seq) }

func toRunRec(r JobRun) jobRunRec {
	return jobRunRec{Job: r.Job, Seq: r.Seq, Revision: r.Revision, Trigger: r.Trigger, State: r.State, Attempts: r.Attempts,
		Replica: r.Replica, Node: r.Node, ExitCode: r.ExitCode, Message: r.Message, CreatedAt: ms(r.CreatedAt),
		StartedAt: ms(r.StartedAt), AttemptAt: ms(r.AttemptAt), FinishedAt: ms(r.FinishedAt)}
}

func (r jobRunRec) run() JobRun {
	return JobRun{Job: r.Job, Seq: r.Seq, Revision: r.Revision, Trigger: r.Trigger, State: r.State, Attempts: r.Attempts,
		Replica: r.Replica, Node: r.Node, ExitCode: r.ExitCode, Message: r.Message, CreatedAt: fromMS(r.CreatedAt),
		StartedAt: fromMS(r.StartedAt), AttemptAt: fromMS(r.AttemptAt), FinishedAt: fromMS(r.FinishedAt)}
}

// job returns the app record of a job, or an error if name is not a job.
func (t *etx) job(name string) (appRec, Revision, error) {
	a, ok, err := t.app(name)
	if err != nil {
		return appRec{}, Revision{}, err
	}
	if !ok {
		return appRec{}, Revision{}, notFoundf("job %s", name)
	}
	rev, err := t.revision(a.ActiveRevision)
	if err != nil {
		return appRec{}, Revision{}, err
	}
	if !rev.Spec.IsJob() {
		return appRec{}, Revision{}, fmt.Errorf("%s is an app, not a job: %w", name, ErrPrecondition)
	}
	return a, rev, nil
}

// CreateJobRun adds a pending run of job with its current revision. For a
// scheduled run, at is when the schedule fired; it must be later than the
// last time it fired, and becomes it (ErrConflict otherwise, so a fire is
// run once). For a manual run, at is ignored and actor is audited.
func (s *Etcd) CreateJobRun(ctx context.Context, job, trigger string, at time.Time, actor string) (JobRun, error) {
	var out JobRun
	err := s.tx(ctx, func(t *etx) error {
		a, rev, err := t.job(job)
		if err != nil {
			return err
		}
		now := s.now()
		created := now
		if trigger == TriggerSchedule {
			if ms(at) <= a.LastScheduled {
				return fmt.Errorf("job %s already ran for %s: %w", job, at.UTC().Format(time.RFC3339), ErrConflict)
			}
			a.LastScheduled, created = ms(at), at
		}
		seq := a.LastRun + 1
		a.LastRun = seq
		if err := t.put(pfxApps+job, a); err != nil {
			return err
		}
		out = JobRun{Job: job, Seq: seq, Revision: rev.Name, Trigger: trigger, State: RunPending, CreatedAt: created}
		if err := t.put(runKey(job, seq), toRunRec(out)); err != nil {
			return err
		}
		if trigger == TriggerManual {
			return t.audit(now, actor, "job.run", job, "run="+strconv.FormatInt(seq, 10))
		}
		return nil
	})
	return out, err
}

// SkipJobSchedule records that job's schedule fired at at without a run.
func (s *Etcd) SkipJobSchedule(ctx context.Context, job string, at time.Time) error {
	return s.tx(ctx, func(t *etx) error {
		a, _, err := t.job(job)
		if err != nil {
			return err
		}
		if ms(at) <= a.LastScheduled {
			return nil
		}
		a.LastScheduled = ms(at)
		return t.put(pfxApps+job, a)
	})
}

// UpdateJobRun replaces a run's record.
func (s *Etcd) UpdateJobRun(ctx context.Context, r JobRun) error {
	return s.tx(ctx, func(t *etx) error {
		if _, ok, err := t.getRaw(runKey(r.Job, r.Seq)); err != nil {
			return err
		} else if !ok {
			return notFoundf("run %d of job %s", r.Seq, r.Job)
		}
		return t.put(runKey(r.Job, r.Seq), toRunRec(r))
	})
}

// ListJobRuns returns the runs of job, or of every job if job is empty,
// oldest first.
func (s *Etcd) ListJobRuns(ctx context.Context, job string) ([]JobRun, error) {
	prefix := pfxRuns
	if job != "" {
		prefix += job + "/"
	}
	var out []JobRun
	err := s.view(ctx, func(t *etx) error {
		out = nil
		return listInto(t, prefix, func(_ string, r jobRunRec) error {
			out = append(out, r.run())
			return nil
		})
	})
	return out, err
}

// DeleteJobRun removes a run and the replicas of its attempts.
func (s *Etcd) DeleteJobRun(ctx context.Context, job string, seq int64) error {
	return s.tx(ctx, func(t *etx) error {
		t.delete(runKey(job, seq))
		return appReplicas(t, job, func(key string, r replicaRec) error {
			if r.Run == seq {
				t.delete(key)
			}
			return nil
		})
	})
}

// SetReplicaDone marks a job attempt as over: its agent stops the container
// and keeps it for its logs.
func (s *Etcd) SetReplicaDone(ctx context.Context, id string) error {
	return s.tx(ctx, func(t *etx) error {
		var r replicaRec
		ok, err := t.get(pfxReplicas+id, &r)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("replica %s", id)
		}
		if r.Done {
			return nil
		}
		r.Done = true
		return t.put(pfxReplicas+id, r)
	})
}

// CancelJobRuns ends job's active runs as cancelled and returns them; the
// agents stop their containers.
func (s *Etcd) CancelJobRuns(ctx context.Context, job, actor string) ([]JobRun, error) {
	var out []JobRun
	err := s.tx(ctx, func(t *etx) error {
		out = nil
		if _, _, err := t.job(job); err != nil {
			return err
		}
		now := s.now()
		err := listInto(t, pfxRuns+job+"/", func(key string, r jobRunRec) error {
			if r.State != RunPending && r.State != RunRunning {
				return nil
			}
			r.State, r.Message, r.FinishedAt = RunCancelled, "cancelled by "+actor, ms(now)
			out = append(out, r.run())
			return t.put(key, r)
		})
		if err != nil {
			return err
		}
		cancelled := map[int64]bool{}
		for _, r := range out {
			cancelled[r.Seq] = true
		}
		err = appReplicas(t, job, func(key string, r replicaRec) error {
			if cancelled[r.Run] && !r.Done {
				r.Done = true
				return t.put(key, r)
			}
			return nil
		})
		if err != nil || len(out) == 0 {
			return err
		}
		return t.audit(now, actor, "job.cancel", job, fmt.Sprintf("runs=%d", len(out)))
	})
	return out, err
}

// DeleteJob removes a job, its revisions, runs, and replicas (whose
// containers its agents then remove). Its secrets are kept.
func (s *Etcd) DeleteJob(ctx context.Context, job, actor string) error {
	return s.tx(ctx, func(t *etx) error {
		if _, _, err := t.job(job); err != nil {
			return err
		}
		t.delete(pfxApps + job)
		t.deletePrefix(pfxRevs + job + "/")
		t.deletePrefix(pfxRuns + job + "/")
		err := appReplicas(t, job, func(key string, _ replicaRec) error {
			t.delete(key)
			return nil
		})
		if err != nil {
			return err
		}
		return t.audit(s.now(), actor, "job.delete", job, "")
	})
}

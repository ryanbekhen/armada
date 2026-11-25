//! Job runs (jobs.go, ADR 0019).

use std::collections::HashSet;

use armada_spec::gotime::{Location, Time};

use crate::error::{Result, conflict, not_found, precondition};
use crate::gojson::{from_ms, ms};
use crate::records::{AppRec, JobRunRec, RunTaskRec};
use crate::tx::*;
use crate::types::*;

/// Job run states.
pub const RUN_PENDING: &str = "pending";
pub const RUN_RUNNING: &str = "running";
pub const RUN_SUCCEEDED: &str = "succeeded";
pub const RUN_FAILED: &str = "failed";
pub const RUN_CANCELLED: &str = "cancelled";

/// What started a run.
pub const TRIGGER_SCHEDULE: &str = "schedule";
pub const TRIGGER_MANUAL: &str = "manual";
pub const TRIGGER_QUEUE: &str = "queue";

fn run_key(job: &str, seq: i64) -> String {
    format!("{PFX_RUNS}{job}/{seq:010}")
}

fn to_run_rec(r: &JobRun) -> JobRunRec {
    JobRunRec {
        job: r.job.clone(),
        seq: r.seq,
        revision: r.revision.clone(),
        trigger: r.trigger.clone(),
        state: r.state.clone(),
        attempts: r.attempts,
        replica: r.replica.clone(),
        node: r.node.clone(),
        exit_code: r.exit_code,
        message: r.message.clone(),
        created_at: ms(&r.created_at),
        started_at: ms(&r.started_at),
        attempt_at: ms(&r.attempt_at),
        finished_at: ms(&r.finished_at),
        tasks: r
            .tasks
            .iter()
            .map(|t| RunTaskRec {
                index: t.index,
                state: t.state.clone(),
                attempts: t.attempts,
                replica: t.replica.clone(),
                node: t.node.clone(),
                exit_code: t.exit_code,
                message: t.message.clone(),
                attempt_at: ms(&t.attempt_at),
                waiting_since: ms(&t.waiting_since),
                finished_at: ms(&t.finished_at),
            })
            .collect(),
    }
}

fn run_of(r: &JobRunRec) -> JobRun {
    JobRun {
        job: r.job.clone(),
        seq: r.seq,
        revision: r.revision.clone(),
        trigger: r.trigger.clone(),
        state: r.state.clone(),
        attempts: r.attempts,
        replica: r.replica.clone(),
        node: r.node.clone(),
        exit_code: r.exit_code,
        message: r.message.clone(),
        created_at: from_ms(r.created_at),
        started_at: from_ms(r.started_at),
        attempt_at: from_ms(r.attempt_at),
        finished_at: from_ms(r.finished_at),
        tasks: r
            .tasks
            .iter()
            .map(|t| RunTask {
                index: t.index,
                state: t.state.clone(),
                attempts: t.attempts,
                replica: t.replica.clone(),
                node: t.node.clone(),
                exit_code: t.exit_code,
                message: t.message.clone(),
                attempt_at: from_ms(t.attempt_at),
                waiting_since: from_ms(t.waiting_since),
                finished_at: from_ms(t.finished_at),
            })
            .collect(),
    }
}

/// Format(time.RFC3339) of t in UTC.
fn rfc3339_utc(t: &Time) -> String {
    let u = Time {
        unix: t.unix,
        nsec: 0,
        loc: Location::utc(),
    };
    u.rfc3339_nano()
}

impl Etx<'_> {
    /// job: the app record of a job, an error if name is not a job.
    async fn job(&self, name: &str) -> Result<(AppRec, Revision)> {
        let Some(a) = self.app(name).await? else {
            return Err(not_found!("job {name}"));
        };
        let rev = self.revision(&a.active_revision).await?;
        if !rev.spec().is_job() {
            return Err(precondition!("{name} is an app, not a job"));
        }
        Ok((a, rev))
    }
}

impl Etcd {
    /// CreateJobRun adds a pending run of job with its current revision.
    pub async fn create_job_run(
        &self,
        job: &str,
        trigger: &str,
        at: &Time,
        actor: &str,
    ) -> Result<JobRun> {
        let mut out = None;
        tx!(self, |t| {
            let (mut a, rev) = t.job(job).await?;
            let now = self.now();
            let mut created = now.clone();
            if trigger == TRIGGER_SCHEDULE {
                if ms(at) <= a.last_scheduled {
                    return Err(conflict!("job {job} already ran for {}", rfc3339_utc(at)));
                }
                a.last_scheduled = ms(at);
                created = at.clone();
            }
            let seq = a.last_run + 1;
            a.last_run = seq;
            t.put(&format!("{PFX_APPS}{job}"), &a)?;
            let mut run = JobRun {
                job: job.to_string(),
                seq,
                revision: rev.name.clone(),
                trigger: trigger.to_string(),
                state: RUN_PENDING.to_string(),
                attempts: 0,
                replica: String::new(),
                node: String::new(),
                exit_code: 0,
                message: String::new(),
                created_at: created,
                started_at: Time::zero(),
                attempt_at: Time::zero(),
                finished_at: Time::zero(),
                tasks: Vec::new(),
            };
            let n = rev.spec().job_tasks();
            if n > 1 {
                for i in 0..n {
                    run.tasks.push(RunTask {
                        index: i,
                        state: RUN_PENDING.to_string(),
                        attempts: 0,
                        replica: String::new(),
                        node: String::new(),
                        exit_code: 0,
                        message: String::new(),
                        attempt_at: Time::zero(),
                        waiting_since: Time::zero(),
                        finished_at: Time::zero(),
                    });
                }
            }
            t.put(&run_key(job, seq), &to_run_rec(&run))?;
            out = Some(run);
            if trigger == TRIGGER_MANUAL {
                return t
                    .audit(&now, actor, "job.run", job, &format!("run={seq}"))
                    .await;
            }
            Ok(())
        })?;
        Ok(out.expect("set by the transaction"))
    }

    /// SkipJobSchedule records that job's schedule fired at at without a
    /// run.
    pub async fn skip_job_schedule(&self, job: &str, at: &Time) -> Result<()> {
        tx!(self, |t| {
            let (mut a, _) = t.job(job).await?;
            if ms(at) <= a.last_scheduled {
                return Ok(());
            }
            a.last_scheduled = ms(at);
            t.put(&format!("{PFX_APPS}{job}"), &a)
        })
    }

    /// UpdateJobRun replaces a run's record.
    pub async fn update_job_run(&self, r: &JobRun) -> Result<()> {
        tx!(self, |t| {
            let k = run_key(&r.job, r.seq);
            if t.get_raw(&k).await?.is_none() {
                return Err(not_found!("run {} of job {}", r.seq, r.job));
            }
            t.put(&k, &to_run_rec(r))
        })
    }

    /// ListJobRuns returns the runs of job, or of every job, oldest first.
    pub async fn list_job_runs(&self, job: &str) -> Result<Vec<JobRun>> {
        let prefix = if job.is_empty() {
            PFX_RUNS.to_string()
        } else {
            format!("{PFX_RUNS}{job}/")
        };
        let mut out = Vec::new();
        view!(self, |t| {
            out = t
                .list_into::<JobRunRec>(&prefix)
                .await?
                .iter()
                .map(|(_, r)| run_of(r))
                .collect();
            Ok(())
        })?;
        Ok(out)
    }

    /// DeleteJobRun removes a run and the replicas of its attempts.
    pub async fn delete_job_run(&self, job: &str, seq: i64) -> Result<()> {
        tx!(self, |t| {
            t.delete(&run_key(job, seq));
            for (k, r) in t.app_replicas(job).await? {
                if r.run == seq {
                    t.delete(&k);
                }
            }
            Ok(())
        })
    }

    /// CancelJobRuns ends job's active runs as cancelled and returns them.
    pub async fn cancel_job_runs(&self, job: &str, actor: &str) -> Result<Vec<JobRun>> {
        let mut out = Vec::new();
        tx!(self, |t| {
            out.clear();
            t.job(job).await?;
            let now = self.now();
            for (k, mut r) in t
                .list_into::<JobRunRec>(&format!("{PFX_RUNS}{job}/"))
                .await?
            {
                if r.state != RUN_PENDING && r.state != RUN_RUNNING {
                    continue;
                }
                r.state = RUN_CANCELLED.to_string();
                r.message = format!("cancelled by {actor}");
                r.finished_at = ms(&now);
                for task in &mut r.tasks {
                    if task.state == RUN_PENDING || task.state == RUN_RUNNING {
                        task.state = RUN_CANCELLED.to_string();
                        task.finished_at = ms(&now);
                    }
                }
                out.push(run_of(&r));
                t.put(&k, &r)?;
            }
            let cancelled: HashSet<i64> = out.iter().map(|r| r.seq).collect();
            for (k, mut r) in t.app_replicas(job).await? {
                if cancelled.contains(&r.run) && !r.done {
                    r.done = true;
                    t.put(&k, &r)?;
                }
            }
            if out.is_empty() {
                return Ok(());
            }
            t.audit(
                &now,
                actor,
                "job.cancel",
                job,
                &format!("runs={}", out.len()),
            )
            .await
        })?;
        Ok(out)
    }

    /// DeleteJob removes a job, its revisions, runs, and replicas.
    pub async fn delete_job(&self, job: &str, actor: &str) -> Result<()> {
        tx!(self, |t| {
            t.job(job).await?;
            t.delete(&format!("{PFX_APPS}{job}"));
            t.delete_prefix(&format!("{PFX_REVS}{job}/"));
            t.delete_prefix(&format!("{PFX_RUNS}{job}/"));
            for (k, _) in t.app_replicas(job).await? {
                t.delete(&k);
            }
            t.audit(&self.now(), actor, "job.delete", job, "").await
        })
    }
}

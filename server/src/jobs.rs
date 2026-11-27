//! Jobs (ADR 0019): the reconcile pass
//! schedules runs from cron fires, starts runs for queues (`triggers`),
//! places and watches each attempt, retries with backoff, runs the tasks
//! of runs with several, and prunes old runs; and the AdminService methods
//! of jobs, with the counter of ended runs on the metrics endpoint. Job
//! logs are the logs module's.

use std::collections::HashMap;

use armada_proto::armada::v1::*;
use armada_spec::go::format_duration;
use armada_spec::gotime::{Location, Time};
use armada_spec::{App as Spec, CONCURRENCY_FORBID, Trigger};
use armada_store::jobs::{
    RUN_CANCELLED, RUN_FAILED, RUN_PENDING, RUN_RUNNING, RUN_SUCCEEDED, TRIGGER_MANUAL,
    TRIGGER_SCHEDULE,
};
use armada_store::{App, JobRun, Kind, Node, REPLICA_FAILED, REPLICA_PENDING, Replica, RunTask};
use tonic::{Code, Status};

use crate::events::timestamp;
use crate::grpc::Auth;
use crate::reconcile::{Run, app_event, sub};
use crate::schedule::{eligible, pick_node, reservation};
use crate::triggers::JOB;
use crate::{Server, store_err};

type Result<T> = std::result::Result<T, armada_store::Error>;

const SECOND: i64 = 1_000_000_000;
const MINUTE: i64 = 60 * SECOND;
/// How late a scheduled run may still start.
const JOB_STARTING_DEADLINE: i64 = 60 * MINUTE;
/// How long the container of a finished run is kept.
pub(crate) const JOB_LOGS_KEPT: i64 = 24 * 60 * MINUTE;
/// Bounds the fires walked to find the latest due one.
const MAX_SCHEDULE_CATCH_UP: usize = 100_000;
const JOB_ACTOR: &str = "armada:schedule";
/// The delay before a retry doubles with each failed attempt, from the
/// server's base up to five minutes.
pub(crate) const DEFAULT_JOB_RETRY_BASE: std::time::Duration = std::time::Duration::from_secs(10);
const JOB_RETRY_MAX: i64 = 5 * MINUTE;

/// d rounded to the nearest multiple of m, halfway away from zero,
/// saturating at the i64 bounds; m <= 0 leaves d as it is.
pub(crate) fn round(d: i64, m: i64) -> i64 {
    if m <= 0 {
        return d;
    }
    let half = |x: i64| (x as u64).wrapping_add(x as u64) < m as u64;
    let mut r = d % m;
    if d < 0 {
        r = -r;
        if half(r) {
            return d + r;
        }
        let d1 = d - m + r;
        if d1 < d {
            return d1;
        }
        return i64::MIN;
    }
    if half(r) {
        return d - r;
    }
    match d.checked_add(m - r) {
        Some(d1) if d1 > d => d1,
        _ => i64::MAX,
    }
}

/// A run's name in events.
pub(crate) fn run_object(r: &JobRun) -> String {
    format!("{}#{}", r.job, r.seq)
}

fn spec_of(a: &App) -> &Spec {
    a.spec.as_deref().expect("a stored app has a spec")
}

fn run_event(r: &JobRun, reason: &str, msg: &str) -> armada_store::Event {
    let mut e = app_event(JOB, &run_object(r), &r.job, reason, msg);
    e.node = r.node.clone();
    e
}

/// The delay before the attempt after `attempts` failed ones.
fn retry_wait(base: i64, attempts: i64) -> i64 {
    let shift = (attempts - 1).clamp(0, 10) as u32;
    base.checked_shl(shift)
        .unwrap_or(i64::MAX)
        .min(JOB_RETRY_MAX)
}

/// Whether the attempt rep, placed at `at`, is over:
/// finished, failed to start, lost its node, or ran past timeout.
fn attempt_outcome(
    rc: &Run<'_>,
    rep: &Replica,
    at: &Time,
    timeout: i64,
) -> (bool, bool, i64, String) {
    if rep.finished && rep.exit_code == 0 {
        return (true, true, 0, String::new());
    }
    if rep.finished {
        return (
            true,
            false,
            rep.exit_code,
            format!("exited with code {}", rep.exit_code),
        );
    }
    if rep.state == REPLICA_FAILED {
        return (true, false, 0, format!("could not start: {}", rep.message));
    }
    if rc.lost.contains(&rep.node_id) {
        return (true, false, 0, format!("its node {} was lost", rep.node_id));
    }
    if sub(&rc.now, at) >= timeout {
        let mut msg = format!("timed out after {}", format_duration(timeout));
        if rep.container_id.is_empty() {
            msg.push_str(" before its container started (pulling the image?)");
        }
        return (true, false, 0, msg);
    }
    rc.wake_at(&at.add(timeout));
    (false, false, 0, String::new())
}

fn ts(t: &Time) -> Option<armada_proto::google::protobuf::Timestamp> {
    (!t.is_zero()).then(|| timestamp(t))
}

fn run_info(r: &JobRun) -> JobRunInfo {
    JobRunInfo {
        job: r.job.clone(),
        run: r.seq,
        state: r.state.clone(),
        trigger: r.trigger.clone(),
        revision: r.revision.clone(),
        attempts: r.attempts.min(i64::from(i32::MAX)) as i32,
        node: r.node.clone(),
        replica: r.replica.clone(),
        exit_code: r.exit_code as i32,
        message: r.message.clone(),
        created_at: ts(&r.created_at),
        started_at: ts(&r.started_at),
        finished_at: ts(&r.finished_at),
        tasks: r
            .tasks
            .iter()
            .map(|t| JobTaskInfo {
                index: t.index as i32,
                state: t.state.clone(),
                attempts: t.attempts.min(i64::from(i32::MAX)) as i32,
                node: t.node.clone(),
                replica: t.replica.clone(),
                exit_code: t.exit_code as i32,
                message: t.message.clone(),
            })
            .collect(),
    }
}

fn not_deleted(r: Result<()>) -> Result<()> {
    match r {
        Err(e) if e.kind == Kind::NotFound => Ok(()),
        r => r,
    }
}

impl Server {
    fn job_retry_base(&self) -> i64 {
        crate::reconcile::nanos(self.0.job_retry_base)
    }

    /// Schedules runs, places and watches their attempts,
    /// and prunes old runs.
    pub(crate) async fn reconcile_jobs(
        &self,
        rc: &mut Run<'_>,
        jobs: &[App],
        nodes: &[Node],
    ) -> Result<()> {
        let res = self.reconcile_jobs_in(rc, jobs, nodes).await;
        self.0.triggers.keep(&rc.triggered);
        res
    }

    async fn reconcile_jobs_in(
        &self,
        rc: &mut Run<'_>,
        jobs: &[App],
        nodes: &[Node],
    ) -> Result<()> {
        if jobs.is_empty() {
            return Ok(());
        }
        let runs = self.store().list_job_runs("").await?;
        let mut by_job: HashMap<String, Vec<JobRun>> = HashMap::new();
        for r in runs {
            by_job.entry(r.job.clone()).or_default().push(r);
        }
        rc.queue_nodes = self.place_queues(rc, jobs, nodes).await;
        for job in jobs {
            let runs = by_job.remove(&job.name).unwrap_or_default();
            self.reconcile_job(rc, job, runs, nodes)
                .await
                .map_err(|e| e.context(format!("job {}", job.name)))?;
        }
        Ok(())
    }

    async fn reconcile_job(
        &self,
        rc: &mut Run<'_>,
        job: &App,
        runs: Vec<JobRun>,
        nodes: &[Node],
    ) -> Result<()> {
        let runs = self.schedule_job(rc, job, runs).await?;
        let mut runs = self.trigger_job(rc, job, runs).await;
        for r in runs.iter_mut() {
            if !r.tasks.is_empty() && r.active() {
                self.reconcile_tasks(rc, job, r, nodes).await?;
            } else if r.state == RUN_PENDING {
                self.start_attempt(rc, job, r, nodes).await?;
            } else if r.state == RUN_RUNNING {
                self.watch_attempt(rc, job, r).await?;
            }
        }
        self.prune_runs(rc, job, &runs).await
    }

    /// Creates the run for the latest due fire of job's
    /// schedule, if any.
    async fn schedule_job(
        &self,
        rc: &mut Run<'_>,
        job: &App,
        mut runs: Vec<JobRun>,
    ) -> Result<Vec<JobRun>> {
        let sp = spec_of(job);
        let Some(sched) = sp.job_schedule() else {
            return Ok(runs);
        };
        // A schedule counts from its last fire or the revision that set
        // it, so a new schedule does not fire for times before it existed.
        let mut base = job.last_scheduled.clone();
        if let Ok(rev) = rc.revs.get(&job.active_revision).await
            && rev.created_at.after(&base)
        {
            base = rev.created_at.clone();
        }
        let next = sched.next(&base);
        if next.after(&rc.now) {
            rc.wake_at(&next);
            return Ok(runs);
        }
        let mut due = next;
        for _ in 0..MAX_SCHEDULE_CATCH_UP {
            let n = sched.next(&due);
            if n.after(&rc.now) {
                break;
            }
            due = n;
        }
        rc.wake_at(&sched.next(&due));
        let at = due.in_loc(&Location::utc()).rfc3339_nano();
        let late = sub(&rc.now, &due);
        if late > JOB_STARTING_DEADLINE {
            self.store().skip_job_schedule(&job.name, &due).await?;
            self.record(app_event(
                JOB,
                &job.name,
                &job.name,
                "Missed",
                &format!(
                    "not run for {at}: the control plane was down for {} past it",
                    format_duration(round(late, MINUTE))
                ),
            ))
            .await;
            return Ok(runs);
        }
        let active: Vec<&JobRun> = runs.iter().filter(|r| r.active()).collect();
        if let Some(last) = active.last() {
            if sp.job_concurrency() == CONCURRENCY_FORBID {
                let seq = last.seq;
                self.store().skip_job_schedule(&job.name, &due).await?;
                self.record(app_event(
                    JOB,
                    &job.name,
                    &job.name,
                    "Skipped",
                    &format!("not run for {at}: run {seq} is still active"),
                ))
                .await;
                return Ok(runs);
            }
            let cancelled = self.store().cancel_job_runs(&job.name, JOB_ACTOR).await?;
            runs = self
                .cancelled(runs, &cancelled, &format!("replaced by the run for {at}"))
                .await;
        }
        match self
            .store()
            .create_job_run(&job.name, TRIGGER_SCHEDULE, &due, "")
            .await
        {
            Err(e) if e.kind == Kind::Conflict => Ok(runs), // already created
            Err(e) => Err(e),
            Ok(run) => {
                runs.push(run);
                Ok(runs)
            }
        }
    }

    /// cancelled updates runs with the runs the store cancelled and
    /// records it.
    async fn cancelled(
        &self,
        mut runs: Vec<JobRun>,
        cancelled: &[JobRun],
        why: &str,
    ) -> Vec<JobRun> {
        for c in cancelled {
            for r in runs.iter_mut() {
                if r.seq == c.seq {
                    *r = c.clone();
                }
            }
            self.0.metrics.job_run(&c.job, RUN_CANCELLED);
            self.record(run_event(c, "Cancelled", why)).await;
        }
        runs
    }

    /// Places the next attempt of a pending run once its
    /// retry delay has passed.
    async fn start_attempt(
        &self,
        rc: &mut Run<'_>,
        job: &App,
        r: &mut JobRun,
        nodes: &[Node],
    ) -> Result<()> {
        if r.attempt_at.after(&rc.now) {
            rc.wake_at(&r.attempt_at);
            return Ok(());
        }
        let rev = match rc.revs.get(&r.revision).await {
            Err(e) if e.kind == Kind::NotFound => {
                let msg = format!("revision {} no longer exists", r.revision);
                return self.end_run(r, RUN_FAILED, 0, &msg).await;
            }
            res => res?,
        };
        let fit: Vec<Node> = eligible(nodes, &rev)
            .into_iter()
            .filter(|n| n.jobs)
            .collect();
        let res = rc.revs.reserved(&rc.all).await;
        let node = pick_node(&fit, &rc.all, &[], "", reservation(&rev), &res);
        let waiting_since = if r.attempt_at.after(&r.created_at) {
            r.attempt_at.clone()
        } else {
            r.created_at.clone()
        };
        let obj = run_object(r);
        self.condition(
            &format!("job-unplaced:{obj}"),
            node.is_none(),
            app_event(
                JOB,
                &obj,
                &job.name,
                "Unschedulable",
                "no node can run it now (placement, capacity, or no agent that runs jobs); see armada job show",
            ),
        )
        .await;
        let Some(node) = node else {
            let timeout = rev.spec().job_timeout();
            if sub(&rc.now, &waiting_since) >= timeout {
                let msg = format!("no node could run it within {}", format_duration(timeout));
                return self.end_run(r, RUN_FAILED, 0, &msg).await;
            }
            rc.wake_at(&waiting_since.add(timeout));
            return Ok(());
        };
        if !r.replica.is_empty() {
            // Only the latest attempt's container is kept for its logs.
            not_deleted(self.store().delete_replica(&r.replica).await)?;
            rc.without(&r.replica.clone());
        }
        let rep = Replica {
            id: format!("{}-j{}-{}", job.name, r.seq, (self.0.new_id)(5)),
            app: job.name.clone(),
            revision: rev.name.clone(),
            node_id: node.id.clone(),
            state: REPLICA_PENDING.to_string(),
            run: r.seq,
            ..Default::default()
        };
        self.store().create_replica(&rep).await?;
        rc.push(rep.clone());
        r.state = RUN_RUNNING.to_string();
        r.replica = rep.id.clone();
        r.node = node.id.clone();
        r.message = String::new();
        r.attempts += 1;
        r.attempt_at = rc.now.clone();
        if r.started_at.is_zero() {
            r.started_at = rc.now.clone();
        }
        self.store().update_job_run(r).await?;
        self.0.log.info(
            "job attempt placed",
            &[
                ("job", job.name.clone()),
                ("run", r.seq.to_string()),
                ("attempt", r.attempts.to_string()),
                ("node", node.id.clone()),
            ],
        );
        self.record(run_event(
            r,
            "Started",
            &format!("attempt {} on {} ({})", r.attempts, node.id, r.trigger),
        ))
        .await;
        rc.wake_at(&rc.now.add(rev.spec().job_timeout()));
        Ok(())
    }

    /// The timeout and retries of r's revision, else of the job.
    async fn run_limits(&self, rc: &mut Run<'_>, job: &App, r: &JobRun) -> (i64, i64) {
        match rc.revs.get(&r.revision).await {
            Ok(rev) => (rev.spec().job_timeout(), rev.spec().retries),
            Err(_) => (spec_of(job).job_timeout(), spec_of(job).retries),
        }
    }

    /// Ends a running attempt that finished, failed to start,
    /// lost its node, or ran past its timeout.
    async fn watch_attempt(&self, rc: &mut Run<'_>, job: &App, r: &mut JobRun) -> Result<()> {
        let Some(rep) = rc.all.iter().find(|x| x.id == r.replica).cloned() else {
            return self
                .attempt_failed(rc, job, r, 0, "its replica disappeared")
                .await;
        };
        let (timeout, _) = self.run_limits(rc, job, r).await;
        let (over, succeeded, code, msg) = attempt_outcome(rc, &rep, &r.attempt_at, timeout);
        if !over {
            return Ok(());
        }
        not_deleted(self.store().set_replica_done(&rep.id).await)?;
        let mut done = rep;
        done.done = true;
        rc.replace(&done);
        if succeeded {
            return self.end_run(r, RUN_SUCCEEDED, 0, "").await;
        }
        self.attempt_failed(rc, job, r, code, &msg).await
    }

    /// Retries a run if its job allows another attempt, or
    /// ends it as failed.
    async fn attempt_failed(
        &self,
        rc: &mut Run<'_>,
        job: &App,
        r: &mut JobRun,
        code: i64,
        msg: &str,
    ) -> Result<()> {
        let (_, retries) = self.run_limits(rc, job, r).await;
        if r.attempts > retries {
            return self.end_run(r, RUN_FAILED, code, msg).await;
        }
        let wait = retry_wait(self.job_retry_base(), r.attempts);
        r.state = RUN_PENDING.to_string();
        r.exit_code = code;
        r.message = msg.to_string();
        r.attempt_at = rc.now.add(wait);
        self.store().update_job_run(r).await?;
        rc.wake_at(&r.attempt_at);
        self.record(run_event(
            r,
            "Retrying",
            &format!(
                "attempt {} {msg}; attempt {} in {}",
                r.attempts,
                r.attempts + 1,
                format_duration(wait)
            ),
        ))
        .await;
        Ok(())
    }

    /// Records the end of a run.
    async fn end_run(&self, r: &mut JobRun, state: &str, code: i64, msg: &str) -> Result<()> {
        r.state = state.to_string();
        r.exit_code = code;
        r.message = msg.to_string();
        r.finished_at = self.now();
        self.store().update_job_run(r).await?;
        self.0.metrics.job_run(&r.job, state);
        let reason = if state == RUN_SUCCEEDED {
            "Succeeded"
        } else {
            "Failed"
        };
        let mut msg = msg.to_string();
        if msg.is_empty() && !r.started_at.is_zero() {
            msg = format!(
                "after {}",
                format_duration(round(sub(&r.finished_at, &r.started_at), SECOND))
            );
        }
        self.0.log.info(
            "job run ended",
            &[
                ("job", r.job.clone()),
                ("run", r.seq.to_string()),
                ("state", state.to_string()),
                ("attempts", r.attempts.to_string()),
            ],
        );
        self.record(run_event(r, reason, &msg)).await;
        Ok(())
    }

    /// Keeps the newest finished runs the job's history allows,
    /// and the containers of finished runs for jobLogsKept.
    async fn prune_runs(&self, rc: &mut Run<'_>, job: &App, runs: &[JobRun]) -> Result<()> {
        let ended: Vec<&JobRun> = runs.iter().filter(|r| !r.active()).collect();
        let keep = spec_of(job).job_history();
        let n = ended.len() as i64;
        for (i, r) in ended.into_iter().enumerate() {
            let of_run = |rc: &Run<'_>| -> Vec<String> {
                rc.all
                    .iter()
                    .filter(|x| x.app == r.job && x.run == r.seq)
                    .map(|x| x.id.clone())
                    .collect()
            };
            if (i as i64) < n - keep {
                self.store().delete_job_run(&r.job, r.seq).await?;
                for id in of_run(rc) {
                    rc.without(&id);
                }
                continue;
            }
            let expires = r.finished_at.add(JOB_LOGS_KEPT);
            if expires.after(&rc.now) {
                rc.wake_at(&expires);
                continue;
            }
            let ids = of_run(rc);
            for id in &ids {
                not_deleted(self.store().delete_replica(id).await)?;
            }
            for id in &ids {
                rc.without(id);
            }
        }
        Ok(())
    }

    /// Moves a run with several tasks: watches the running
    /// ones, retries or fails those that ended badly, starts pending ones
    /// while fewer than the parallelism run, and ends the run once every
    /// task succeeded or one failed for good.
    async fn reconcile_tasks(
        &self,
        rc: &mut Run<'_>,
        job: &App,
        r: &mut JobRun,
        nodes: &[Node],
    ) -> Result<()> {
        let rev = match rc.revs.get(&r.revision).await {
            Err(e) if e.kind == Kind::NotFound => {
                self.stop_tasks(rc, r).await?;
                let msg = format!("revision {} no longer exists", r.revision);
                return self.end_run(r, RUN_FAILED, 0, &msg).await;
            }
            res => res?,
        };
        let timeout = rev.spec().job_timeout();
        let retries = rev.spec().retries;
        let mut changed = false;

        for i in 0..r.tasks.len() {
            if r.tasks[i].state != RUN_RUNNING {
                continue;
            }
            let rep = rc.all.iter().find(|x| x.id == r.tasks[i].replica).cloned();
            let (over, succeeded, code, msg) = match &rep {
                Some(rep) => attempt_outcome(rc, rep, &r.tasks[i].attempt_at, timeout),
                None => (true, false, 0, "its replica disappeared".to_string()),
            };
            if !over {
                continue;
            }
            if let Some(rep) = rep {
                not_deleted(self.store().set_replica_done(&rep.id).await)?;
                let mut done = rep;
                done.done = true;
                rc.replace(&done);
            }
            changed = true;
            let now = rc.now.clone();
            let t = &mut r.tasks[i];
            if succeeded {
                t.state = RUN_SUCCEEDED.to_string();
                t.exit_code = 0;
                t.message = String::new();
                t.finished_at = now;
            } else if t.attempts > retries {
                t.state = RUN_FAILED.to_string();
                t.exit_code = code;
                t.message = msg;
                t.finished_at = now;
            } else {
                let wait = retry_wait(self.job_retry_base(), t.attempts);
                t.state = RUN_PENDING.to_string();
                t.exit_code = code;
                t.message = msg.clone();
                t.attempt_at = now.add(wait);
                let (index, attempts, node) = (t.index, t.attempts, t.node.clone());
                let mut e = app_event(
                    JOB,
                    &run_object(r),
                    &r.job,
                    "Retrying",
                    &format!(
                        "task {index}: attempt {attempts} {msg}; attempt {} in {}",
                        attempts + 1,
                        format_duration(wait)
                    ),
                );
                e.node = node;
                self.record(e).await;
            }
        }

        if let Some(failed) = r.tasks.iter().find(|t| t.state == RUN_FAILED).cloned() {
            self.stop_tasks(rc, r).await?;
            let msg = format!("task {} {}", failed.index, failed.message);
            return self.end_run(r, RUN_FAILED, failed.exit_code, &msg).await;
        }
        if r.tasks.iter().all(|t| t.state == RUN_SUCCEEDED) {
            return self.end_run(r, RUN_SUCCEEDED, 0, "").await;
        }

        let mut running = r.tasks.iter().filter(|t| t.state == RUN_RUNNING).count() as i64;
        let fit: Vec<Node> = eligible(nodes, &rev)
            .into_iter()
            .filter(|n| n.jobs)
            .collect();
        let mut unplaced = false;
        for i in 0..r.tasks.len() {
            if r.tasks[i].state != RUN_PENDING || running >= rev.spec().job_parallelism() {
                continue;
            }
            if r.tasks[i].attempt_at.after(&rc.now) {
                rc.wake_at(&r.tasks[i].attempt_at.clone());
                continue;
            }
            if unplaced {
                continue; // the tasks of a run need the same: no node now
            }
            let spread: Vec<Replica> = rc
                .all
                .iter()
                .filter(|x| x.app == job.name && !x.done)
                .cloned()
                .collect();
            let res = rc.revs.reserved(&rc.all).await;
            let node = pick_node(&fit, &rc.all, &spread, "", reservation(&rev), &res);
            let Some(node) = node else {
                unplaced = true;
                let now = rc.now.clone();
                let t = &mut r.tasks[i];
                if t.waiting_since.is_zero() {
                    t.waiting_since = now.clone();
                    changed = true;
                }
                if sub(&now, &t.waiting_since) >= timeout {
                    t.state = RUN_FAILED.to_string();
                    t.message = format!("no node could run it within {}", format_duration(timeout));
                    t.finished_at = now;
                    changed = true;
                    continue;
                }
                let at = t.waiting_since.add(timeout);
                rc.wake_at(&at);
                continue;
            };
            let old = r.tasks[i].replica.clone();
            if !old.is_empty() {
                // Only the latest attempt's container is kept for its logs.
                not_deleted(self.store().delete_replica(&old).await)?;
                rc.without(&old);
            }
            let index = r.tasks[i].index;
            let rep = Replica {
                id: format!("{}-j{}-t{index}-{}", job.name, r.seq, (self.0.new_id)(5)),
                app: job.name.clone(),
                revision: rev.name.clone(),
                node_id: node.id.clone(),
                state: REPLICA_PENDING.to_string(),
                run: r.seq,
                task: index,
                ..Default::default()
            };
            self.store().create_replica(&rep).await?;
            rc.push(rep.clone());
            running += 1;
            changed = true;
            let now = rc.now.clone();
            let t: &mut RunTask = &mut r.tasks[i];
            t.state = RUN_RUNNING.to_string();
            t.replica = rep.id.clone();
            t.node = node.id.clone();
            t.message = String::new();
            t.waiting_since = Time::zero();
            t.attempts += 1;
            t.attempt_at = now.clone();
            let attempts = t.attempts;
            r.state = RUN_RUNNING.to_string();
            r.replica = rep.id.clone();
            r.node = node.id.clone();
            r.attempts += 1;
            r.attempt_at = now.clone();
            if r.started_at.is_zero() {
                r.started_at = now.clone();
            }
            self.0.log.info(
                "job task placed",
                &[
                    ("job", job.name.clone()),
                    ("run", r.seq.to_string()),
                    ("task", index.to_string()),
                    ("attempt", attempts.to_string()),
                    ("node", node.id.clone()),
                ],
            );
            self.record(run_event(
                r,
                "Started",
                &format!(
                    "task {index} attempt {attempts} on {} ({})",
                    node.id, r.trigger
                ),
            ))
            .await;
            rc.wake_at(&now.add(timeout));
        }
        let obj = run_object(r);
        self.condition(
            &format!("job-unplaced:{obj}"),
            unplaced,
            app_event(
                JOB,
                &obj,
                &job.name,
                "Unschedulable",
                "no node can run its next task now (placement, capacity, or no agent that runs jobs); see armada job show",
            ),
        )
        .await;
        if r.tasks.iter().any(|t| t.state == RUN_FAILED) {
            // A task found no node in time: the run fails on the next pass.
            rc.wake_at(&rc.now.clone());
        }
        if !changed {
            return Ok(());
        }
        self.store().update_job_run(r).await
    }

    /// Ends the tasks of r that have not ended as cancelled, and
    /// marks their attempts done so their agents stop them.
    async fn stop_tasks(&self, rc: &mut Run<'_>, r: &mut JobRun) -> Result<()> {
        for i in 0..r.tasks.len() {
            let state = r.tasks[i].state.clone();
            if state != RUN_PENDING && state != RUN_RUNNING {
                continue;
            }
            if state == RUN_RUNNING {
                let id = r.tasks[i].replica.clone();
                not_deleted(self.store().set_replica_done(&id).await)?;
                if let Some(x) = rc.all.iter().find(|x| x.id == id).cloned() {
                    let mut done = x;
                    done.done = true;
                    rc.replace(&done);
                }
            }
            r.tasks[i].state = RUN_CANCELLED.to_string();
            r.tasks[i].finished_at = self.now();
        }
        Ok(())
    }

    /// The job named name, or a gRPC error.
    async fn job_of(&self, name: &str) -> std::result::Result<App, Status> {
        let a = match self.store().get_app(name).await {
            Ok(a) => a,
            Err(e) if e.kind == Kind::NotFound => {
                return Err(Status::new(Code::NotFound, format!("job {name} not found")));
            }
            Err(e) => return Err(store_err(&e)),
        };
        if !a.spec.as_deref().is_some_and(Spec::is_job) {
            return Err(Status::new(
                Code::FailedPrecondition,
                format!("{name} is an app, not a job"),
            ));
        }
        Ok(a)
    }

    /// RunJob starts a run of a job now. With concurrency forbid it
    /// refuses while a run is active; with replace it cancels that run.
    pub(crate) async fn run_job(
        &self,
        a: &Auth,
        req: RunJobRequest,
    ) -> std::result::Result<RunJobResponse, Status> {
        a.acc.app(&req.job)?;
        let job = self.job_of(&req.job).await?;
        let sp = spec_of(&job);
        let mut runs = self
            .store()
            .list_job_runs(&job.name)
            .await
            .map_err(|e| store_err(&e))?;
        if let Some(t) = &sp.trigger {
            // A job its queue starts keeps up to its parallelism, whoever
            // started them (ADR 0040).
            let active = runs.iter().filter(|r| r.active()).count() as i64;
            if active >= Trigger::max_runs(Some(t)) {
                return Err(Status::new(
                    Code::FailedPrecondition,
                    format!(
                        "{active} run(s) of {} are active, as many as trigger.parallelism allows",
                        job.name
                    ),
                ));
            }
            runs.clear();
        }
        if let Some(r) = runs.iter().find(|r| r.active()) {
            if sp.job_concurrency() == CONCURRENCY_FORBID {
                return Err(Status::new(
                    Code::FailedPrecondition,
                    format!(
                        "run {} is still {}; cancel it with `armada job cancel {}` first",
                        r.seq, r.state, job.name
                    ),
                ));
            }
            let cancelled = self
                .store()
                .cancel_job_runs(&job.name, &a.actor())
                .await
                .map_err(|e| store_err(&e))?;
            self.cancelled(
                Vec::new(),
                &cancelled,
                &format!("replaced by a run started by {}", a.actor()),
            )
            .await;
        }
        let run = self
            .store()
            .create_job_run(&job.name, TRIGGER_MANUAL, &Time::zero(), &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "job run requested",
            &[
                ("job", job.name.clone()),
                ("run", run.seq.to_string()),
                ("by", a.actor()),
            ],
        );
        self.trigger();
        Ok(RunJobResponse { run: run.seq })
    }

    /// ListJobs describes every job the caller sees.
    pub(crate) async fn list_jobs(
        &self,
        a: &Auth,
        _req: ListJobsRequest,
    ) -> std::result::Result<ListJobsResponse, Status> {
        self.jobs_and_runs(a).await.map(|(resp, _)| resp)
    }

    /// The jobs the caller sees, with every job's runs (one
    /// read).
    pub(crate) async fn jobs_and_runs(
        &self,
        a: &Auth,
    ) -> std::result::Result<(ListJobsResponse, HashMap<String, Vec<JobRun>>), Status> {
        let apps = self.store().list_apps().await.map_err(|e| store_err(&e))?;
        let runs = self
            .store()
            .list_job_runs("")
            .await
            .map_err(|e| store_err(&e))?;
        let mut by_job: HashMap<String, Vec<JobRun>> = HashMap::new();
        for r in runs {
            by_job.entry(r.job.clone()).or_default().push(r);
        }
        let mut resp = ListJobsResponse::default();
        for app in &apps {
            let Some(sp) = app.spec.as_deref() else {
                continue;
            };
            if !sp.is_job() || !a.acc.sees(&app.name) {
                continue;
            }
            let mut info = JobInfo {
                name: app.name.clone(),
                revision: app.active_revision.clone(),
                image: sp.image.clone(),
                schedule: sp.schedule.clone(),
                time_zone: sp.time_zone.clone(),
                ..Default::default()
            };
            for r in by_job.get(&app.name).into_iter().flatten() {
                info.last_run = Some(run_info(r));
                if r.active() {
                    info.active += 1;
                }
            }
            if let Some(sched) = sp.job_schedule() {
                info.next_run = Some(timestamp(&sched.next(&self.now())));
            }
            info.trigger = self.job_trigger(app);
            resp.jobs.push(info);
        }
        Ok((resp, by_job))
    }

    /// ListJobRuns lists a job's runs, newest first.
    pub(crate) async fn list_job_runs(
        &self,
        a: &Auth,
        req: ListJobRunsRequest,
    ) -> std::result::Result<ListJobRunsResponse, Status> {
        a.acc.app(&req.job)?;
        self.job_of(&req.job).await?;
        let runs = self
            .store()
            .list_job_runs(&req.job)
            .await
            .map_err(|e| store_err(&e))?;
        Ok(ListJobRunsResponse {
            runs: runs.iter().rev().map(run_info).collect(),
        })
    }

    /// CancelJob ends a job's active runs.
    pub(crate) async fn cancel_job(
        &self,
        a: &Auth,
        req: CancelJobRequest,
    ) -> std::result::Result<CancelJobResponse, Status> {
        a.acc.app(&req.job)?;
        self.job_of(&req.job).await?;
        let cancelled = self
            .store()
            .cancel_job_runs(&req.job, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        self.cancelled(Vec::new(), &cancelled, &format!("by {}", a.actor()))
            .await;
        self.0.log.info(
            "job runs cancelled",
            &[
                ("job", req.job.clone()),
                ("runs", cancelled.len().to_string()),
                ("by", a.actor()),
            ],
        );
        self.trigger();
        Ok(CancelJobResponse {
            runs: cancelled.iter().map(|r| r.seq).collect(),
        })
    }

    /// DeleteJob removes a job with its runs; their containers are removed.
    pub(crate) async fn delete_job(
        &self,
        a: &Auth,
        req: DeleteJobRequest,
    ) -> std::result::Result<DeleteJobResponse, Status> {
        a.acc.app(&req.job)?;
        self.job_of(&req.job).await?;
        self.store()
            .delete_job(&req.job, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        self.end_app_conditions(&req.job).await;
        self.0.log.info(
            "job deleted",
            &[("job", req.job.clone()), ("by", a.actor())],
        );
        self.record(app_event(
            JOB,
            &req.job,
            &req.job,
            "Deleted",
            &format!("by {}", a.actor()),
        ))
        .await;
        self.trigger();
        Ok(DeleteJobResponse {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds() {
        assert_eq!(round(90 * SECOND, MINUTE), 2 * MINUTE);
        assert_eq!(round(89 * SECOND, MINUTE), MINUTE);
        assert_eq!(round(1_499_999_999, SECOND), SECOND);
        assert_eq!(round(1_500_000_000, SECOND), 2 * SECOND);
        assert_eq!(round(-90 * SECOND, MINUTE), -2 * MINUTE);
    }

    #[test]
    fn retries_back_off() {
        let base = 10 * SECOND;
        assert_eq!(retry_wait(base, 1), 10 * SECOND);
        assert_eq!(retry_wait(base, 2), 20 * SECOND);
        assert_eq!(retry_wait(base, 6), JOB_RETRY_MAX);
        assert_eq!(retry_wait(base, 100), JOB_RETRY_MAX);
    }
}

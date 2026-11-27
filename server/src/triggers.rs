//! Queue triggers (ADR 0040): one node reads each
//! queue-triggered job's queue from a network sandbox the leader puts in
//! its assignment, and the leader starts runs for what waits in it.
//!
//! The sandbox's address is the job's for every node's firewall: the pass
//! keeps it ([`Run::sandbox_addrs`](crate::reconcile::Run)) for the
//! cluster network's endpoints.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use armada_proto::armada::v1::{JobTrigger, QueueProbe, QueueSandbox};
use armada_spec::gotime::Time;
use armada_spec::{MAX_JOB_PARALLELISM, MAX_NODE_QUEUE_SANDBOXES, Trigger, fair_order};
use armada_store::jobs::TRIGGER_QUEUE;
use armada_store::{App, JobRun, Node, Replica, Revision};

use crate::Server;
use crate::events::timestamp;
use crate::reconcile::{Run, app_event, sub};
use crate::schedule::eligible;
use crate::usage::{SandboxReading, USAGE_MAX_AGE};

const SECOND: i64 = 1_000_000_000;
pub(crate) const JOB: &str = "job";

/// What the leader keeps about jobs a queue starts, in memory only: a new
/// leader picks the same nodes and has a reading
/// again after one polling interval.
#[derive(Default)]
pub(crate) struct QueueTriggers {
    st: Mutex<TriggerState>,
}

#[derive(Default)]
struct TriggerState {
    /// The node that reads each job's queue, from the latest pass; ""
    /// when no node can.
    nodes: HashMap<String, String>,
    /// The reading runs were last started for, by job (node, reading):
    /// each reading starts runs once.
    acted: HashMap<String, (String, i64)>,
}

impl QueueTriggers {
    fn lock(&self) -> std::sync::MutexGuard<'_, TriggerState> {
        self.st.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn node(&self, job: &str) -> String {
        self.lock().nodes.get(job).cloned().unwrap_or_default()
    }

    /// keep forgets jobs that no longer have a queue trigger.
    pub(crate) fn keep(&self, jobs: &HashSet<String>) {
        let mut st = self.lock();
        st.nodes.retain(|j, _| jobs.contains(j));
        st.acted.retain(|j, _| jobs.contains(j));
    }
}

/// FNV-1a, 64 bits (hash/fnv's New64a).
fn fnv64a(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for x in b {
        h ^= u64::from(*x);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Picks the node that reads a job's queue: one the job may run
/// on, with a subnet, running jobs, not lost, whose agent keeps sandboxes,
/// and with room (none: any). Of those, the one whose hash with the job is
/// highest, so every leader picks the same.
pub(crate) fn probe_node(
    job: &str,
    nodes: &[Node],
    rev: &Revision,
    lost: &HashSet<String>,
    sandboxes: &HashSet<String>,
    room: Option<&dyn Fn(&str) -> bool>,
) -> Option<String> {
    let mut best = String::new();
    let mut best_hash = 0u64;
    for n in eligible(nodes, rev) {
        if n.subnet.is_empty()
            || !n.jobs
            || lost.contains(&n.id)
            || !sandboxes.contains(&n.id)
            || room.is_some_and(|f| !f(&n.id))
        {
            continue;
        }
        let v = fnv64a(format!("{job}\x00{}", n.id).as_bytes());
        if best.is_empty() || v > best_hash || (v == best_hash && n.id < best) {
            best = n.id.clone();
            best_hash = v;
        }
    }
    (!best.is_empty()).then_some(best)
}

impl Server {
    /// The connected nodes whose agents read job queues from
    /// network sandboxes.
    pub(crate) fn sandbox_nodes(&self) -> HashSet<String> {
        self.sessions()
            .into_iter()
            .filter(|s| s.caps.sandboxes)
            .map(|s| s.node_id.clone())
            .collect()
    }

    /// The node that reads each queue-triggered job's queue
    /// in this pass ("" for none), at most MaxNodeQueueSandboxes per node,
    /// jobs placed one space at a time.
    pub(crate) async fn place_queues(
        &self,
        rc: &mut Run<'_>,
        jobs: &[App],
        nodes: &[Node],
    ) -> HashMap<String, String> {
        let mut out = HashMap::new();
        let mut queued: HashMap<String, Revision> = HashMap::new();
        let mut ids = Vec::new();
        for job in jobs {
            let Ok(rev) = rc.revs.get(&job.active_revision).await else {
                continue;
            };
            if rev.spec().queue_trigger().is_none() {
                continue;
            }
            queued.insert(job.name.clone(), rev);
            ids.push(job.name.clone());
        }
        ids.sort();
        let placed: std::cell::RefCell<HashMap<String, i64>> = Default::default();
        let room =
            |node: &str| placed.borrow().get(node).copied().unwrap_or(0) < MAX_NODE_QUEUE_SANDBOXES;
        for id in fair_order(&ids) {
            let node = probe_node(
                &id,
                nodes,
                &queued[&id],
                &rc.lost,
                &rc.sandbox_nodes,
                Some(&room),
            );
            if let Some(n) = &node {
                *placed.borrow_mut().entry(n.clone()).or_default() += 1;
            }
            out.insert(id, node.unwrap_or_default());
        }
        out
    }

    /// What node last reported of job's sandbox, if the
    /// node's sample is recent; fresh says the length was read within two
    /// polling intervals too.
    pub(crate) fn queue_reading(
        &self,
        job: &str,
        node: &str,
        every: i64,
        now: &Time,
    ) -> (SandboxReading, bool) {
        let Some(n) = self.0.usage.node(node, now) else {
            return (SandboxReading::default(), false);
        };
        let Some(r) = n.sandboxes.get(job).cloned() else {
            return (SandboxReading::default(), false);
        };
        let fresh = r.measured
            && r.at
                .as_ref()
                .is_some_and(|at| sub(now, at) <= 2 * every + USAGE_MAX_AGE);
        (r, fresh)
    }

    /// Keeps the job's queue read from a sandbox on one node and
    /// starts runs for what waits in it: ⌈length ÷ perRun⌉, at most the
    /// trigger's parallelism, less the active runs, once per reading.
    pub(crate) async fn trigger_job(
        &self,
        rc: &mut Run<'_>,
        job: &App,
        mut runs: Vec<JobRun>,
    ) -> Vec<JobRun> {
        let Ok(rev) = rc.revs.get(&job.active_revision).await else {
            return runs;
        };
        let t = rev.spec().trigger.clone();
        let Some(q) = rev.spec().queue_trigger().cloned() else {
            return runs;
        };
        rc.triggered.insert(job.name.clone());
        let node = rc.queue_nodes.get(&job.name).cloned().unwrap_or_default();
        let mut ok = !node.is_empty();
        let mut msg = format!(
            "no node can read the queue: it needs a connected node the job may run on, in the cluster network, whose agent reads queues, and that reads fewer than {MAX_NODE_QUEUE_SANDBOXES} queues"
        );
        if ok && self.0.usage.dropped_sandbox(&node, &job.name, &rc.now) {
            // The node keeps fewer sandboxes than the leader placed there.
            msg = format!("node {node} does not read the queue: it keeps no more queue sandboxes");
            ok = false;
        }
        self.condition(
            &format!("job-queue:{}", job.name),
            !ok,
            app_event(JOB, &job.name, &job.name, "QueueUnread", &msg),
        )
        .await;
        self.0
            .triggers
            .lock()
            .nodes
            .insert(job.name.clone(), node.clone());
        if node.is_empty() {
            self.condition(
                &format!("job-queue-read:{}", job.name),
                false,
                app_event(JOB, &job.name, &job.name, "QueueReadFailed", ""),
            )
            .await;
            return runs;
        }
        let url = match rc.revs.secrets(&rev).await {
            Ok(vals) => vals.get(&q.url_secret_ref).cloned(),
            Err(e) => {
                self.0.log.error(
                    "job queue URL",
                    &[("job", job.name.clone()), ("err", e.to_string())],
                );
                None
            }
        };
        let Some(url) = url else {
            // The job keeps its runs; the queue is not read until the
            // secret opens.
            return runs;
        };
        let every = Trigger::poll_every(t.as_ref());
        let version = rev.secrets.get(&q.url_secret_ref).copied().unwrap_or(0);
        rc.sandboxes
            .entry(node.clone())
            .or_default()
            .push(QueueSandbox {
                job: job.name.clone(),
                probe: Some(QueueProbe {
                    r#type: q.typ.clone(),
                    url: String::from_utf8_lossy(url.bytes()).into_owned(),
                    name: q.name().to_string(),
                    url_ref: format!("{}@v{version}", q.url_secret_ref),
                    ..Default::default()
                }),
                interval_seconds: every / SECOND,
            });
        let (r, fresh) = self.queue_reading(&job.name, &node, every, &rc.now);
        // The node's own word on why it cannot read the queue: a fixed
        // text, never the URL or what the broker sent.
        self.condition(
            &format!("job-queue-read:{}", job.name),
            !r.failed.is_empty(),
            app_event(
                JOB,
                &job.name,
                &job.name,
                "QueueReadFailed",
                &format!("node {node} cannot read the queue: {}", r.failed),
            ),
        )
        .await;
        if !r.ip.is_empty() {
            // The firewalls of every node know the sandbox as the job's.
            rc.sandbox_addrs.push(Replica {
                id: format!("sandbox:{}", job.name),
                app: job.name.clone(),
                node_id: node.clone(),
                ip: r.ip.clone(),
                ..Default::default()
            });
        }
        if !fresh {
            return runs;
        }
        let key = (node.clone(), r.reading);
        let acted = {
            let mut st = self.0.triggers.lock();
            let acted = st.acted.get(&job.name) == Some(&key);
            st.acted.insert(job.name.clone(), key);
            acted
        };
        if acted {
            return runs;
        }
        let active = runs.iter().filter(|x| x.active()).count() as i64;
        let wanted = t.as_ref().map_or(0, |t| t.runs_wanted(r.length));
        let start = (wanted - active).min(MAX_JOB_PARALLELISM);
        if start <= 0 {
            return runs;
        }
        let mut started = 0;
        for _ in 0..start {
            match self
                .store()
                .create_job_run(&job.name, TRIGGER_QUEUE, &Time::zero(), "")
                .await
            {
                Ok(run) => {
                    runs.push(run);
                    started += 1;
                }
                Err(e) => {
                    self.0.log.error(
                        "start a run for the job's queue",
                        &[("job", job.name.clone()), ("err", e.to_string())],
                    );
                    break;
                }
            }
        }
        if started > 0 {
            self.0.log.info(
                "job runs started for its queue",
                &[
                    ("job", job.name.clone()),
                    ("runs", started.to_string()),
                    ("length", r.length.to_string()),
                ],
            );
            self.record(app_event(
                JOB,
                &job.name,
                &job.name,
                "QueueTriggered",
                &format!(
                    "{started} run(s) started: {} message(s) waiting, {} per run, {active} already active, at most {}",
                    r.length,
                    q.per_run,
                    Trigger::max_runs(t.as_ref())
                ),
            ))
            .await;
        }
        runs
    }

    /// A job's queue trigger with what was last read.
    pub(crate) fn job_trigger(&self, a: &App) -> Option<JobTrigger> {
        let sp = a.spec.as_deref()?;
        let q = sp.queue_trigger()?;
        let t = sp.trigger.as_ref();
        let every = Trigger::poll_every(t);
        let mut out = JobTrigger {
            r#type: q.typ.clone(),
            name: q.name().to_string(),
            per_run: q.per_run,
            parallelism: Trigger::max_runs(t) as i32,
            polling_interval_seconds: every / SECOND,
            node: self.0.triggers.node(&a.name),
            ..Default::default()
        };
        if out.node.is_empty() {
            return Some(out);
        }
        let (r, fresh) = self.queue_reading(&a.name, &out.node, every, &self.now());
        if fresh {
            out.measured = true;
            out.length = r.length;
            out.measured_at = r.at.as_ref().map(timestamp);
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv() {
        // FNV-1a 64 of "" and of "a".
        assert_eq!(fnv64a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv64a(b"a"), 0xaf63_dc4c_8601_ec8c);
    }
}

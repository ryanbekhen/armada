//! What the leader keeps of agents' usage reports (Go's usageStore in
//! top.go), in memory only: so far the part queue triggers read (ADR
//! 0040), each node's network sandboxes with the latest length of each
//! job's queue and the jobs whose sandboxes it dropped. Replica samples,
//! proxy load, queue rules' lengths, volumes, and the space counters come
//! with scaling and watching (pull requests 11 and 15 of ADR 0055).

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use armada_proto::armada::v1::{SandboxQueue, UsageReport};
use armada_spec::gotime::Time;
use armada_spec::validate::valid_app_id;

use crate::reconcile::sub;

const SECOND: i64 = 1_000_000_000;
/// usageMaxAge: how long a node's sample counts.
pub(crate) const USAGE_MAX_AGE: i64 = 35 * SECOND;
/// maxUsageReplicas: a report with more replicas is dropped.
const MAX_USAGE_REPLICAS: usize = 1024;
/// maxQueueLength bounds a reported queue length.
const MAX_QUEUE_LENGTH: i64 = 1 << 40;
/// maxSandboxReports and maxSandboxAge bound what a report says about
/// network sandboxes.
const MAX_SANDBOX_REPORTS: usize = 256;
const MAX_SANDBOX_AGE_MS: i64 = 3_600_000;

/// queuelen's fixed texts, in the order Reason tries them.
const QUEUE_REASONS: &[&str] = &[
    "the URL in the secret is not valid for this rule",
    "cannot reach the broker from the replica",
    "the broker refused the URL's credentials",
    "the broker answered something unexpected",
    "the queue does not exist",
    "timed out",
    "the broker refused the URL's virtual host",
    "the URL names an authentication mechanism other than PLAIN, AMQPLAIN, or EXTERNAL",
    "the broker offers none of the URL's authentication mechanisms",
];

/// A job's network sandbox on a node and the length of its queue read
/// from it, if measured (Go's sandboxReading).
#[derive(Clone, Debug, Default)]
pub(crate) struct SandboxReading {
    pub ip: String,
    pub measured: bool,
    pub length: i64,
    /// When the length was read.
    pub at: Option<Time>,
    /// The agent's count of readings.
    pub reading: i64,
    /// Why the latest reading failed: one of queuelen's fixed texts, or "".
    pub failed: String,
}

/// One node's latest sample.
#[derive(Clone, Debug)]
pub(crate) struct NodeUsage {
    pub at: Time,
    pub sandboxes: HashMap<String, SandboxReading>,
    pub dropped: HashSet<String>,
}

/// The latest sample of each node.
#[derive(Default)]
pub(crate) struct Usage {
    nodes: Mutex<HashMap<String, NodeUsage>>,
}

/// sandboxFailure: queuelen.Reason(queuelen.FromText(text)): a fixed text
/// stays, any other becomes the generic one.
pub(crate) fn sandbox_failure(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    if QUEUE_REASONS.contains(&text) {
        return text.to_string();
    }
    "the queue could not be read".to_string()
}

/// sandboxReadings: what a report says about the node's sandboxes,
/// bounded. Which jobs the node may read is checked when a reading is used.
fn sandbox_readings(list: &[SandboxQueue], at: &Time) -> HashMap<String, SandboxReading> {
    let mut out = HashMap::new();
    if list.is_empty() || list.len() > MAX_SANDBOX_REPORTS {
        return out;
    }
    for q in list {
        if !valid_app_id(&q.job) || q.ip.len() > 64 {
            continue;
        }
        let mut s = SandboxReading {
            ip: q.ip.clone(),
            failed: sandbox_failure(&q.error),
            ..Default::default()
        };
        if q.measured {
            let age = q.age_millis.clamp(0, MAX_SANDBOX_AGE_MS) * 1_000_000;
            s.measured = true;
            s.length = q.length.clamp(0, MAX_QUEUE_LENGTH);
            s.at = Some(at.add(-age));
            s.reading = q.reading;
        }
        out.insert(q.job.clone(), s);
    }
    out
}

impl Usage {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, NodeUsage>> {
        self.nodes.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// set replaces node's sample. Reports are untrusted: values are
    /// bounded, and a report with too many replicas is dropped. It returns
    /// true when the report brings a new reading of a job's queue, so the
    /// leader reconciles at once.
    pub(crate) fn set(&self, node: &str, r: &UsageReport, at: Time) -> bool {
        if r.replicas.len() > MAX_USAGE_REPLICAS {
            self.forget(node);
            return false;
        }
        let sandboxes = sandbox_readings(&r.sandboxes, &at);
        let mut dropped = HashSet::new();
        if !r.dropped_sandboxes.is_empty() && r.dropped_sandboxes.len() <= MAX_SANDBOX_REPORTS {
            for job in &r.dropped_sandboxes {
                if valid_app_id(job) {
                    dropped.insert(job.clone());
                }
            }
        }
        let mut m = self.lock();
        let mut fresh = false;
        for (job, s) in &sandboxes {
            let prev = m.get(node).and_then(|n| n.sandboxes.get(job));
            if s.measured && prev.is_none_or(|p| !p.measured || p.reading != s.reading) {
                fresh = true;
            }
        }
        m.insert(
            node.to_string(),
            NodeUsage {
                at,
                sandboxes,
                dropped,
            },
        );
        fresh
    }

    /// Drops node's sample (its session ended).
    pub(crate) fn forget(&self, node: &str) {
        self.lock().remove(node);
    }

    /// node's sample if it is recent.
    pub(crate) fn node(&self, node: &str, now: &Time) -> Option<NodeUsage> {
        let m = self.lock();
        let n = m.get(node)?;
        if sub(now, &n.at) > USAGE_MAX_AGE {
            return None;
        }
        Some(n.clone())
    }

    /// droppedSandbox: node's recent sample says it does not keep job's
    /// sandbox.
    pub(crate) fn dropped_sandbox(&self, node: &str, job: &str, now: &Time) -> bool {
        self.node(node, now)
            .is_some_and(|n| n.dropped.contains(job))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_are_fixed_texts() {
        assert_eq!(sandbox_failure(""), "");
        assert_eq!(
            sandbox_failure("the broker refused the URL's virtual host"),
            "the broker refused the URL's virtual host"
        );
        assert_eq!(
            sandbox_failure("amqp://u:pw@h refused"),
            "the queue could not be read"
        );
    }

    #[test]
    fn readings_are_bounded() {
        let at = Time::zero().add(100 * SECOND);
        let list = vec![
            SandboxQueue {
                job: "mailer".into(),
                ip: "10.120.0.9".into(),
                measured: true,
                length: -5,
                age_millis: 10 * 3_600_000,
                reading: 3,
                error: String::new(),
            },
            SandboxQueue {
                job: "Not An ID".into(),
                ..Default::default()
            },
        ];
        let m = sandbox_readings(&list, &at);
        assert_eq!(m.len(), 1);
        let r = &m["mailer"];
        assert_eq!(r.length, 0);
        let want = at.add(-MAX_SANDBOX_AGE_MS * 1_000_000);
        let got = r.at.as_ref().expect("measured");
        assert_eq!((got.unix, got.nsec), (want.unix, want.nsec));
    }

    #[test]
    fn a_new_reading_is_fresh() {
        let u = Usage::default();
        let at = Time::zero().add(SECOND);
        let rep = |n| UsageReport {
            sandboxes: vec![SandboxQueue {
                job: "mailer".into(),
                measured: true,
                reading: n,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(u.set("n1", &rep(1), at.clone()));
        assert!(!u.set("n1", &rep(1), at.clone()));
        assert!(u.set("n1", &rep(2), at.clone()));
        assert!(u.node("n1", &at.add(USAGE_MAX_AGE)).is_some());
        assert!(u.node("n1", &at.add(USAGE_MAX_AGE + 1)).is_none());
    }
}

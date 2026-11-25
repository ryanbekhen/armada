//! What the leader keeps of agents' usage reports (Go's usageStore in
//! top.go), in memory only: each node's replica samples (CPU and memory,
//! ADR 0016), its proxy's load per replica (ADR 0020), the queue lengths
//! its queue rules read (ADR 0034), its network sandboxes with the latest
//! length of each job's queue and the jobs whose sandboxes it dropped (ADR
//! 0040); when a proxy last reported a request for each replica (ADR
//! 0021); and which app and node each replica belongs to, from the latest
//! pass, for the events of processes killed at the memory limit; and each
//! node's volume sizes (ADR 0023); its connection tracking table, its side
//! of a switch of the network's mode (ADR 0050), and how it runs
//! containers (ADR 0054); and the requests and egress counted per space
//! since the first pass (ADR 0026).

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use armada_proto::armada::v1::{NetworkSwitchStatus, RuntimeStatus, SandboxQueue, UsageReport};
use armada_spec::gotime::Time;
use armada_spec::validate::{split_app_id, valid_app_id, valid_name};
use armada_spec::{MAX_IDLE_AFTER, SCALE_QUEUE};
use armada_store::{Event, Replica};

use crate::events::{REPLICA, event};
use crate::network::clean_switch_status;
use crate::reconcile::sub;
use crate::runtimemove::clean_runtime_status;

const SECOND: i64 = 1_000_000_000;
/// usageMaxAge: how long a node's sample counts.
pub(crate) const USAGE_MAX_AGE: i64 = 35 * SECOND;
/// maxUsageReplicas: a report with more replicas is dropped.
const MAX_USAGE_REPLICAS: usize = 1024;
/// maxQueueLength bounds a reported queue length.
const MAX_QUEUE_LENGTH: i64 = 1 << 40;
/// maxReplicaIDLen bounds a replica ID in a report.
const MAX_REPLICA_ID_LEN: usize = 128;
/// maxInFlight bounds one node's count of requests in progress for a
/// replica.
const MAX_IN_FLIGHT: i64 = 1_000_000;
/// proxy.MaxLoadEntries: a report with more load entries leaves the load
/// unmeasured.
const MAX_LOAD_ENTRIES: usize = 20_000;
/// maxActive bounds the last request times kept.
const MAX_ACTIVE: usize = 8192;
/// maxNodeCPUMillis and maxNodeMemory bound a replica's sample.
const MAX_NODE_CPU_MILLIS: i64 = 1024 * 1000;
const MAX_NODE_MEMORY: i64 = 16 << 40;
/// maxOOMEvents and maxOOMReport bound what a report says about processes
/// killed at the memory limit.
const MAX_OOM_EVENTS: usize = 8;
const MAX_OOM_REPORT: i64 = 1 << 20;
/// maxSandboxReports and maxSandboxAge bound what a report says about
/// network sandboxes.
const MAX_SANDBOX_REPORTS: usize = 256;
const MAX_SANDBOX_AGE_MS: i64 = 3_600_000;
/// volumeUsageMaxAge: how long a node's volume measurement counts, a few
/// of its agent's one-minute measurements.
const VOLUME_USAGE_MAX_AGE: i64 = 210 * SECOND;
/// maxVolumeReports bounds the volumes of one report: a node with more is
/// unmeasured.
const MAX_VOLUME_REPORTS: usize = 1024;
const MAX_VOLUME_BYTES: i64 = 1 << 50;
/// maxConntrack bounds a node's reported connection tracking numbers.
const MAX_CONNTRACK: i64 = 1 << 32;

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

/// A replica's sample: millicores and bytes.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ReplicaUsage {
    pub cpu: i64,
    pub mem: i64,
}

/// One node's latest sample.
#[derive(Clone, Debug)]
pub(crate) struct NodeUsage {
    pub at: Time,
    pub replicas: HashMap<String, ReplicaUsage>,
    /// The requests in progress at the node's proxy per replica, for any
    /// replica, if load_measured (ADR 0020).
    pub load: HashMap<String, i64>,
    pub load_measured: bool,
    /// The length each queue rule read, by the replica it was read from
    /// and the rule's type (ADR 0034).
    pub queues: HashMap<(String, String), i64>,
    pub sandboxes: HashMap<String, SandboxReading>,
    pub dropped: HashSet<String>,
    /// The node's connection tracking table (ADR 0025); max 0 when unknown.
    #[allow(dead_code)]
    pub conntrack_entries: i64,
    #[allow(dead_code)]
    pub conntrack_max: i64,
    /// The node's side of a switch of the network's mode (ADR 0050),
    /// bounded by clean_switch_status.
    pub net_switch: Option<NetworkSwitchStatus>,
    /// How the node runs containers (ADR 0054), bounded by
    /// clean_runtime_status.
    pub runtime: Option<RuntimeStatus>,
}

/// Which space, app, and node a replica belongs to (Go's replicaOwner).
#[derive(Clone, Debug)]
struct Owner {
    space: String,
    app: String,
    node: String,
}

/// A space's counters (Go's spaceTotals).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SpaceTotals {
    pub requests: i64,
    pub egress: i64,
}

/// maxReportRequests and maxReportEgress bound what one report adds to a
/// space's counters for one replica.
const MAX_REPORT_REQUESTS: i64 = 1 << 30;
const MAX_REPORT_EGRESS: i64 = 1 << 40;

#[derive(Default)]
struct State {
    nodes: HashMap<String, NodeUsage>,
    /// When a proxy last reported a request for each replica (ADR 0021),
    /// kept across reports so none is missed between evaluations.
    active: HashMap<String, Time>,
    /// The owners of replicas from the latest pass.
    owners: HashMap<String, Owner>,
    /// Each node's latest volume measurement (ADR 0023): when, and the
    /// bytes by "app/name".
    volumes: HashMap<String, (Time, HashMap<String, i64>)>,
    /// Requests and egress per space since `since` (the first pass).
    totals: HashMap<String, SpaceTotals>,
    since: Option<Time>,
}

/// The latest sample of each node.
#[derive(Default)]
pub(crate) struct Usage {
    st: Mutex<State>,
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

/// count adds a report to the space counters. Egress counts only from a
/// replica's own node; requests from every node's proxy, like the load of
/// ADR 0020.
fn count(st: &mut State, node: &str, r: &UsageReport) {
    for ru in &r.replicas {
        if let Some(o) = st.owners.get(&ru.id)
            && o.node == node
        {
            let space = o.space.clone();
            let t = st.totals.entry(space).or_default();
            t.egress = t
                .egress
                .saturating_add(ru.egress_bytes.clamp(0, MAX_REPORT_EGRESS));
        }
    }
    if !r.load_measured {
        return;
    }
    for l in &r.load {
        if let Some(o) = st.owners.get(&l.id) {
            let space = o.space.clone();
            let t = st.totals.entry(space).or_default();
            t.requests = t
                .requests
                .saturating_add(l.requests.clamp(0, MAX_REPORT_REQUESTS));
        }
    }
}

fn valid_report_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_REPLICA_ID_LEN
}

impl Usage {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// set replaces node's sample. Reports are untrusted: values are
    /// bounded, and a report with too many replicas is dropped. Which
    /// replicas belong to the node is only checked when the sample is
    /// read, so a report costs no store access. It returns true when the
    /// report brings a new reading of a job's queue, or a node newly ready
    /// for a step of a network switch, so the leader reconciles at once.
    pub(crate) fn set(&self, node: &str, r: &UsageReport, at: Time) -> bool {
        if r.replicas.len() > MAX_USAGE_REPLICAS {
            self.forget(node);
            return false;
        }
        // Load covers every replica the node's proxy routes to, across the
        // cluster: too much of it makes the load unmeasured, not the node.
        let measured = r.load_measured && r.load.len() <= MAX_LOAD_ENTRIES;
        let mut reps = HashMap::new();
        for ru in &r.replicas {
            if valid_report_id(&ru.id) {
                reps.insert(
                    ru.id.clone(),
                    ReplicaUsage {
                        cpu: ru.cpu_millis.clamp(0, MAX_NODE_CPU_MILLIS),
                        mem: ru.memory_bytes.clamp(0, MAX_NODE_MEMORY),
                    },
                );
            }
        }
        let mut load = HashMap::new();
        let mut busy = Vec::new();
        if measured {
            for l in &r.load {
                if valid_report_id(&l.id) {
                    load.insert(l.id.clone(), l.in_flight.clamp(0, MAX_IN_FLIGHT));
                    if l.in_flight > 0 || l.requests > 0 {
                        busy.push(l.id.clone());
                    }
                }
            }
        }
        let mut queues = HashMap::new();
        if !r.queues.is_empty() && r.queues.len() <= MAX_USAGE_REPLICAS {
            for l in &r.queues {
                if valid_report_id(&l.id) && l.r#type.len() <= 16 {
                    let typ = if l.r#type.is_empty() {
                        SCALE_QUEUE.to_string()
                    } else {
                        l.r#type.clone()
                    };
                    queues.insert((l.id.clone(), typ), l.length.clamp(0, MAX_QUEUE_LENGTH));
                }
            }
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
        let mut st = self.lock();
        let mut fresh = false;
        for (job, s) in &sandboxes {
            let prev = st.nodes.get(node).and_then(|n| n.sandboxes.get(job));
            if s.measured && prev.is_none_or(|p| !p.measured || p.reading != s.reading) {
                fresh = true;
            }
        }
        let net_switch = clean_switch_status(r.network_switch.as_ref());
        let prev = st.nodes.get(node).and_then(|n| n.net_switch.as_ref());
        if let Some(ns) = &net_switch
            && ns.ready
            && prev.is_none_or(|p| !p.ready || p.to != ns.to || p.step != ns.step)
        {
            fresh = true;
        }
        count(&mut st, node, r);
        for id in busy {
            st.active.insert(id, at.clone());
        }
        if st.active.len() > MAX_ACTIVE {
            let ids: Vec<String> = st.active.keys().cloned().collect();
            for id in ids {
                let old = st
                    .active
                    .get(&id)
                    .is_some_and(|t| sub(&at, t) > MAX_IDLE_AFTER);
                if old || st.active.len() > MAX_ACTIVE {
                    st.active.remove(&id);
                }
            }
        }
        st.nodes.insert(
            node.to_string(),
            NodeUsage {
                at,
                replicas: reps,
                load,
                load_measured: measured,
                queues,
                sandboxes,
                dropped,
                conntrack_entries: r.conntrack_entries.clamp(0, MAX_CONNTRACK),
                conntrack_max: r.conntrack_max.clamp(0, MAX_CONNTRACK),
                net_switch,
                runtime: clean_runtime_status(r.runtime.as_ref()),
            },
        );
        fresh
    }

    /// outOfMemory: an event for each replica of node whose processes the
    /// kernel killed at the memory limit since the previous report, at
    /// most eight. The container lives on when that was not its main
    /// process, so nothing else would show it.
    pub(crate) fn out_of_memory(&self, node: &str, r: &UsageReport) -> Vec<Event> {
        let st = self.lock();
        let mut out = Vec::new();
        for ru in &r.replicas {
            if ru.oom_kills <= 0 || out.len() == MAX_OOM_EVENTS {
                continue;
            }
            if let Some(o) = st.owners.get(&ru.id)
                && o.node == node
            {
                let mut e = event(
                    REPLICA,
                    &ru.id,
                    node,
                    "OutOfMemory",
                    &format!(
                        "processes killed at the memory limit: {}",
                        ru.oom_kills.min(MAX_OOM_REPORT)
                    ),
                );
                e.app = o.app.clone();
                out.push(e);
            }
        }
        out
    }

    /// setOwners: replaces what reports are counted against, from a pass's
    /// replicas.
    /// Counting starts with the first call.
    pub(crate) fn set_owners(&self, reps: &[Replica], now: &Time) {
        let mut owners = HashMap::with_capacity(reps.len());
        for r in reps {
            if let Some((space, _)) = split_app_id(&r.app) {
                owners.insert(
                    r.id.clone(),
                    Owner {
                        space: space.to_string(),
                        app: r.app.clone(),
                        node: r.node_id.clone(),
                    },
                );
            }
        }
        let mut st = self.lock();
        st.owners = owners;
        if st.since.is_none() {
            st.since = Some(now.clone());
        }
    }

    /// spaceTotals: a space's counters and when counting began.
    pub(crate) fn space_totals(&self, space: &str) -> (SpaceTotals, Option<Time>) {
        let st = self.lock();
        (
            st.totals.get(space).copied().unwrap_or_default(),
            st.since.clone(),
        )
    }

    /// forgetSpace drops a removed space's counters.
    pub(crate) fn forget_space(&self, space: &str) {
        self.lock().totals.remove(space);
    }

    /// Drops node's sample (its session ended).
    pub(crate) fn forget(&self, node: &str) {
        let mut st = self.lock();
        st.nodes.remove(node);
        st.volumes.remove(node);
    }

    /// setVolumes keeps node's volume measurement. Like other usage it is
    /// untrusted: values are bounded, and names are checked.
    pub(crate) fn set_volumes(&self, node: &str, r: &UsageReport, at: Time) {
        let mut st = self.lock();
        if r.volumes.len() > MAX_VOLUME_REPORTS {
            st.volumes.remove(node);
            return;
        }
        let mut m = HashMap::with_capacity(r.volumes.len());
        for v in &r.volumes {
            if valid_app_id(&v.app) && valid_name(&v.volume) {
                m.insert(
                    format!("{}/{}", v.app, v.volume),
                    v.bytes.clamp(0, MAX_VOLUME_BYTES),
                );
            }
        }
        st.volumes.insert(node.to_string(), (at, m));
    }

    /// volume: the latest size of a volume measured on node.
    pub(crate) fn volume(&self, node: &str, app: &str, name: &str, now: &Time) -> Option<i64> {
        let st = self.lock();
        let (at, m) = st.volumes.get(node)?;
        if sub(now, at) > VOLUME_USAGE_MAX_AGE {
            return None;
        }
        m.get(&format!("{app}/{name}")).copied()
    }

    /// node's sample if it is recent.
    pub(crate) fn node(&self, node: &str, now: &Time) -> Option<NodeUsage> {
        let st = self.lock();
        let n = st.nodes.get(node)?;
        if sub(now, &n.at) > USAGE_MAX_AGE {
            return None;
        }
        Some(n.clone())
    }

    /// switchStatus: the latest side of a network switch node reported.
    pub(crate) fn switch_status(&self, node: &str) -> Option<NetworkSwitchStatus> {
        self.lock()
            .nodes
            .get(node)
            .and_then(|n| n.net_switch.clone())
    }

    /// runtimeOf: the latest RuntimeStatus node reported, if recent.
    pub(crate) fn runtime_of(&self, node: &str, now: &Time) -> Option<RuntimeStatus> {
        self.node(node, now).and_then(|n| n.runtime)
    }

    /// droppedSandbox: node's recent sample says it does not keep job's
    /// sandbox.
    pub(crate) fn dropped_sandbox(&self, node: &str, job: &str, now: &Time) -> bool {
        self.node(node, now)
            .is_some_and(|n| n.dropped.contains(job))
    }

    /// lastActive: when a proxy last reported a request for any of ids;
    /// the zero time when none did.
    pub(crate) fn last_active<'a>(&self, ids: impl IntoIterator<Item = &'a str>) -> Time {
        let st = self.lock();
        let mut last = Time::zero();
        for id in ids {
            if let Some(t) = st.active.get(id)
                && t.after(&last)
            {
                last = t.clone();
            }
        }
        last
    }

    /// load: the requests in progress per replica summed over every node
    /// whose proxy was read recently; false if no node's proxy was.
    pub(crate) fn load(&self, now: &Time) -> (HashMap<String, i64>, bool) {
        let st = self.lock();
        let mut out: HashMap<String, i64> = HashMap::new();
        let mut ok = false;
        for n in st.nodes.values() {
            if !n.load_measured || sub(now, &n.at) > USAGE_MAX_AGE {
                continue;
            }
            ok = true;
            for (id, v) in &n.load {
                *out.entry(id.clone()).or_default() += v;
            }
        }
        (out, ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use armada_proto::armada::v1::ReplicaLoad;

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

    fn load(entries: &[(&str, i64, i64)]) -> UsageReport {
        UsageReport {
            load_measured: true,
            load: entries
                .iter()
                .map(|(id, in_flight, requests)| ReplicaLoad {
                    id: id.to_string(),
                    in_flight: *in_flight,
                    requests: *requests,
                })
                .collect(),
            ..Default::default()
        }
    }

    // Go's TestUsageLastActive.
    #[test]
    fn last_active_survives_quiet_reports() {
        let u = Usage::default();
        let t0 = Time::zero().add(1000 * SECOND);
        u.set("n1", &load(&[("a", 0, 3), ("b", 0, 0)]), t0.clone());
        u.set(
            "n1",
            &load(&[("a", 0, 0), ("b", 0, 0)]),
            t0.add(10 * SECOND),
        );
        let got = u.last_active(["a", "b"]);
        assert_eq!((got.unix, got.nsec), (t0.unix, t0.nsec));
        u.set("n2", &load(&[("b", 1, 0)]), t0.add(20 * SECOND));
        let got = u.last_active(["a", "b"]);
        assert_eq!(got.unix, t0.unix + 20);
        assert!(u.last_active(["c"]).is_zero());
    }

    #[test]
    fn load_sums_fresh_nodes() {
        let u = Usage::default();
        let t0 = Time::zero().add(1000 * SECOND);
        u.set("n1", &load(&[("a", 3, 0), ("b", -4, 0)]), t0.clone());
        u.set("n2", &load(&[("a", 2_000_000, 0)]), t0.add(40 * SECOND));
        let (m, ok) = u.load(&t0.add(40 * SECOND));
        assert!(ok);
        assert_eq!(m["a"], MAX_IN_FLIGHT);
        assert!(!m.contains_key("b"));
        let (m, ok) = u.load(&t0.add(10 * SECOND));
        assert!(ok);
        assert_eq!(m["a"], MAX_IN_FLIGHT + 3);
        assert_eq!(m["b"], 0);
        assert!(!u.load(&t0.add(100 * SECOND)).1);
    }
}

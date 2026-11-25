//! Network sandboxes for job queue triggers (ADR 0040; Go's sandbox.go):
//! the agent keeps the sandboxes the leader asks for (at most 64, one
//! space at a time past that), removes the others, reads each one's queue
//! every polling interval from inside it, and reports the readings and the
//! jobs it dropped.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use armada_proto::armada::v1 as pb;
use tokio::sync::Notify;

use crate::agent::{Inner, lock};
use crate::network::parse_addr;
use crate::runtime::Runtime;

/// The sandboxes one node keeps; the leader places no more on a node.
pub const MAX_SANDBOXES: usize = armada_spec::spec::MAX_NODE_QUEUE_SANDBOXES as usize;
/// How often the agent checks for sandboxes to make, remove, or read.
pub const SANDBOX_TICK: Duration = Duration::from_secs(1);
/// The readings that run at once, and those of one space's jobs.
pub const MAX_SANDBOX_READS: usize = 8;
pub const MAX_SANDBOX_READS_PER_SPACE: usize = 2;
/// The dropped jobs a node reports at most.
pub const MAX_DROPPED_SANDBOXES: usize = 64;

#[derive(Default)]
struct State {
    ip: String,
    probe: Option<pb::QueueProbe>,
    measured: bool,
    length: i64,
    at: Option<SystemTime>,
    reading: i64,
    next: Option<SystemTime>,
    busy: bool,
    failed: String,
    reason: String,
}

#[derive(Default)]
struct Inner_ {
    /// None until the first assignment: an agent that restarts while the
    /// server is down removes nothing.
    want: Option<BTreeMap<String, pb::QueueSandbox>>,
    have: HashMap<String, State>,
    dropped: Vec<String>,
    running: usize,
    spaces: HashMap<String, usize>,
}

/// What the agent knows of its network sandboxes (Go's sandboxes).
#[derive(Default)]
pub struct Sandboxes {
    m: Mutex<Inner_>,
    pub(crate) kick: Notify,
}

impl Sandboxes {
    /// Whether no reading runs.
    pub(crate) fn idle(&self) -> bool {
        lock(&self.m).running == 0
    }
}

/// Go's runtime.CheckSandboxID.
pub fn check_sandbox_id(id: &str) -> bool {
    !(id.is_empty()
        || id.len() > 128
        || id.starts_with('.')
        || id.starts_with('-')
        || id.contains(".."))
        && id
            .chars()
            .all(|r| r.is_ascii_lowercase() || r.is_ascii_digit() || r == '-' || r == '.')
}

fn same_probe(x: &pb::QueueProbe, y: &pb::QueueProbe) -> bool {
    x.r#type == y.r#type && x.name == y.name && x.url_ref == y.url_ref
}

impl<R: Runtime> Inner<R> {
    /// Whether the node reads job queues from sandboxes: only in its subnet
    /// of a cluster network (sandboxesOn).
    pub(crate) fn sandboxes_on(&self) -> bool {
        self.cfg.unpublished && self.cfg.network.is_some() && self.rt.can_sandbox()
    }

    /// Takes an assignment's sandboxes (setSandboxes).
    pub(crate) fn set_sandboxes(&self, list: &[pb::QueueSandbox]) {
        let mut valid: BTreeMap<String, pb::QueueSandbox> = BTreeMap::new();
        for s in list {
            let t = s.probe.as_ref().map(|p| p.r#type.as_str()).unwrap_or("");
            if valid.len() == MAX_DROPPED_SANDBOXES + MAX_SANDBOXES
                || !armada_spec::validate::valid_app_id(&s.job)
                || !check_sandbox_id(&s.job)
                || (t != "redis" && t != "rabbitmq")
            {
                continue;
            }
            valid.insert(s.job.clone(), s.clone());
        }
        let ids: Vec<String> = valid.keys().cloned().collect();
        let mut want = BTreeMap::new();
        let mut dropped = Vec::new();
        for id in armada_spec::spec::fair_order(&ids) {
            if want.len() < MAX_SANDBOXES {
                if let Some(s) = valid.remove(&id) {
                    want.insert(id, s);
                }
            } else {
                dropped.push(id);
            }
        }
        if !dropped.is_empty() {
            self.log.warn(
                "queue sandboxes past what the node keeps",
                &[
                    ("kept", want.len().to_string()),
                    ("dropped", dropped.len().to_string()),
                ],
            );
        }
        dropped.sort();
        {
            let mut m = lock(&self.side.sb.m);
            m.want = Some(want);
            m.dropped = dropped;
        }
        self.side.sb.kick.notify_one();
    }

    /// Keeps the sandboxes the leader asks for and reads them
    /// (sandboxLoop).
    pub(crate) async fn sandbox_loop(self: Arc<Self>) {
        if !self.sandboxes_on() {
            return;
        }
        let mut t = tokio::time::interval(SANDBOX_TICK);
        loop {
            self.sync_sandboxes().await;
            tokio::select! {
                _ = t.tick() => {}
                _ = self.side.sb.kick.notified() => {}
            }
        }
    }

    /// Makes the node's sandboxes match the assignment and starts the
    /// readings that are due (syncSandboxes).
    pub(crate) async fn sync_sandboxes(self: &Arc<Self>) {
        let Some(want) = lock(&self.side.sb.m).want.clone() else {
            return;
        };
        let existing = match self.rt.list_sandboxes().await {
            Ok(e) => e,
            Err(e) => {
                self.log
                    .warn("list network sandboxes", &[("err", e.to_string())]);
                return;
            }
        };
        let mut changed = false;
        let mut listed: HashMap<String, String> = HashMap::new();
        for s in existing {
            if want.contains_key(&s.id) {
                listed.insert(s.id, s.ip);
                continue;
            }
            if let Err(e) = self.rt.remove_sandbox(&s.id).await {
                self.log.warn(
                    "remove network sandbox",
                    &[("job", s.id.clone()), ("err", e.to_string())],
                );
                continue;
            }
            self.log
                .info("removed network sandbox", &[("job", s.id.clone())]);
            if let Some(ip) = parse_addr(&s.ip)
                && let Some(l) = lock(&self.st).local.as_mut()
            {
                l.remove(&ip);
            }
            changed = true;
        }
        lock(&self.side.sb.m)
            .have
            .retain(|id, _| want.contains_key(id));
        for id in want.keys() {
            let mut ip = listed.get(id).cloned().unwrap_or_default();
            if ip.is_empty() {
                match self.rt.ensure_sandbox(id).await {
                    Err(e) => {
                        self.log.warn(
                            "make network sandbox",
                            &[("job", id.clone()), ("err", e.to_string())],
                        );
                        continue;
                    }
                    Ok(s) => {
                        ip = s.ip;
                        if !listed.contains_key(id) {
                            self.log.info(
                                "made network sandbox",
                                &[("job", id.clone()), ("ip", ip.clone())],
                            );
                        }
                        changed = true;
                    }
                }
            }
            {
                let mut m = lock(&self.side.sb.m);
                let st = m.have.entry(id.clone()).or_default();
                if st.ip != ip {
                    // A new sandbox reads anew, once the firewall knows it.
                    st.ip = ip.clone();
                    st.next = None;
                }
            }
            if let Some(addr) = parse_addr(&ip) {
                lock(&self.st)
                    .local
                    .get_or_insert_with(Default::default)
                    .insert(addr, id.clone());
            }
        }
        if changed && self.cfg.network.is_some() {
            // The firewall and the internal DNS know a sandbox before
            // anything is dialled from it.
            self.apply_network_now().await;
        }
        self.read_sandboxes(&want);
    }

    /// How often a sandbox's queue is read.
    fn sandbox_interval(&self, w: &pb::QueueSandbox) -> Duration {
        if let Some(d) = self.cfg.side.sandbox_interval.filter(|d| !d.is_zero()) {
            return d;
        }
        let d = w.interval_seconds.saturating_mul(1_000_000_000);
        let lo = armada_spec::spec::MIN_POLLING_INTERVAL;
        let hi = armada_spec::spec::MAX_POLLING_INTERVAL;
        Duration::from_nanos(d.clamp(lo, hi) as u64)
    }

    /// Starts the readings that are due, longest waiting first, and returns
    /// without waiting for them (readSandboxes).
    fn read_sandboxes(self: &Arc<Self>, want: &BTreeMap<String, pb::QueueSandbox>) {
        let now = SystemTime::now();
        struct Job {
            id: String,
            space: String,
            probe: pb::QueueProbe,
            every: Duration,
            next: Option<SystemTime>,
        }
        let mut m = lock(&self.side.sb.m);
        let mut due = Vec::new();
        for (id, w) in want {
            let Some(st) = m.have.get_mut(id) else {
                continue;
            };
            if st.ip.is_empty() || st.busy {
                continue;
            }
            let probe = w.probe.clone().unwrap_or_default();
            if st.probe.as_ref().is_some_and(|p| !same_probe(p, &probe)) {
                // Another queue or broker: the last length says nothing.
                st.measured = false;
                st.next = None;
            }
            if st.next.is_some_and(|n| now < n) {
                continue;
            }
            let space = armada_spec::validate::split_app_id(id)
                .map(|(s, _)| s)
                .unwrap_or_default();
            due.push(Job {
                id: id.clone(),
                space,
                probe,
                every: self.sandbox_interval(w),
                next: st.next,
            });
        }
        due.sort_by(|x, y| x.next.cmp(&y.next).then(x.id.cmp(&y.id)));
        for j in due {
            if m.running >= MAX_SANDBOX_READS {
                break;
            }
            if m.spaces.get(&j.space).copied().unwrap_or(0) >= MAX_SANDBOX_READS_PER_SPACE {
                continue; // the space's other readings first
            }
            if let Some(st) = m.have.get_mut(&j.id) {
                st.busy = true;
            }
            m.running += 1;
            *m.spaces.entry(j.space.clone()).or_insert(0) += 1;
            let me = self.clone();
            tokio::spawn(async move {
                let r = me.read_sandbox(&j.id, &j.probe).await;
                let mut m = lock(&me.side.sb.m);
                m.running -= 1;
                if let Some(n) = m.spaces.get_mut(&j.space) {
                    *n -= 1;
                    if *n == 0 {
                        m.spaces.remove(&j.space);
                    }
                }
                let Some(st) = m.have.get_mut(&j.id) else {
                    return;
                };
                st.busy = false;
                st.next = Some(SystemTime::now() + j.every);
                st.probe = Some(j.probe.clone());
                match r {
                    Err(e) => {
                        // Only the kind of failure: never the URL or what
                        // the broker sent.
                        if e != st.failed {
                            me.log.warn(
                                "job queue not read",
                                &[
                                    ("job", j.id.clone()),
                                    ("type", j.probe.r#type.clone()),
                                    ("err", e.clone()),
                                ],
                            );
                            st.failed = e.clone();
                        }
                        st.reason = super::queue::reason(&e);
                    }
                    Ok(n) => {
                        if !st.failed.is_empty() {
                            me.log
                                .info("job queue read again", &[("job", j.id.clone())]);
                            st.failed.clear();
                        }
                        st.reason.clear();
                        st.measured = true;
                        st.length = n;
                        st.at = Some(SystemTime::now());
                        st.reading += 1;
                    }
                }
            });
        }
    }

    /// Reads the job's queue from its sandbox (readSandbox).
    async fn read_sandbox(&self, id: &str, p: &pb::QueueProbe) -> Result<i64, String> {
        let read = async {
            if p.r#type != "redis" && p.r#type != "rabbitmq" {
                return Err("unknown queue type".to_string());
            }
            let dial = |net: &'static str, addr: String| async move {
                self.rt
                    .dial_sandbox(id, net, &addr)
                    .await
                    .map_err(|e| e.to_string())
            };
            let q = self.queue_read(p, dial).await?;
            self.rt
                .read_sandbox_queue(id, &q)
                .await
                .map_err(|e| e.to_string())
        };
        tokio::time::timeout(super::queue::QUEUE_TIMEOUT, read)
            .await
            .unwrap_or_else(|_| Err(super::queue::ERR_TIMEOUT.into()))
    }

    /// The jobs of the last assignment the node does not keep.
    pub(crate) fn dropped_sandboxes(&self) -> Vec<String> {
        lock(&self.side.sb.m).dropped.clone()
    }

    /// Every sandbox with its address and, when recent, its latest reading
    /// (sandboxReport).
    pub(crate) fn sandbox_report(&self, now: SystemTime) -> Vec<pb::SandboxQueue> {
        let m = lock(&self.side.sb.m);
        let Some(want) = &m.want else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (id, st) in &m.have {
            let Some(w) = want.get(id) else { continue };
            if st.ip.is_empty() {
                continue;
            }
            let mut q = pb::SandboxQueue {
                job: id.clone(),
                ip: st.ip.clone(),
                error: st.reason.clone(),
                ..Default::default()
            };
            // A reading counts for two intervals; then the leader goes
            // without.
            let age = st.at.map(|a| crate::clock::sub(now, a)).unwrap_or(i64::MAX);
            let limit = (2 * self.sandbox_interval(w) + SANDBOX_TICK).as_nanos() as i64;
            if st.measured && age <= limit {
                q.measured = true;
                q.length = st.length;
                q.age_millis = (age / 1_000_000).max(0);
                q.reading = st.reading;
            }
            out.push(q);
        }
        out.sort_by(|a, b| a.job.cmp(&b.job));
        out
    }

    /// Adds the node's sandboxes to local, as addresses of their jobs
    /// (localSandboxes).
    pub(crate) async fn local_sandboxes(&self, local: &mut crate::proxy::Clients) {
        if !self.sandboxes_on() {
            return;
        }
        let Ok(list) = self.rt.list_sandboxes().await else {
            return;
        };
        for s in list {
            if let Some(ip) = parse_addr(&s.ip)
                && armada_spec::validate::valid_app_id(&s.id)
            {
                local.insert(ip, s.id);
            }
        }
    }
}

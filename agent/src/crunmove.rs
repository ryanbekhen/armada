//! Moving the containers runc created to crun (ADR 0056): the agent
//! recreates them, one replica at a time per node, the next only once the
//! one before is ready again, and HAProxy's system container last, so the
//! runtime pack can leave runc out.
//!
//! A replica is first reported starting with no address while its runc
//! container still runs, so the proxies stop sending it requests; DRAIN
//! later its container is stopped (with the usual grace) and created again
//! on crun, as for a new spec. A replica that is the only server of its app the node's proxy
//! configuration lists waits a while first, as another node may be moving
//! the app's other replica at that moment. Job attempts run to their end
//! on runc (an attempt runs once); held, fenced, and paused replicas wait
//! until they run again. A move whose replica does not get ready again
//! holds the next ones back, longer after each such failure.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use armada_proto::armada::v1 as pb;

use crate::agent::{Inner, lock};
use crate::clock;
use crate::runtime::{Container, LABEL_SPEC_HASH, OCI_CRUN, Runtime, STATE_RUNNING, stopped};
use crate::spec::spec_hash;

/// How long a replica is reported starting before its runc container is
/// stopped: the leader takes it out of the proxies meanwhile.
pub const DRAIN: Duration = Duration::from_secs(5);
/// How long the next move waits for a recreated replica to be ready.
pub const READY_WAIT: Duration = Duration::from_secs(5 * 60);
/// How long a replica that is the only server of its app in the proxy
/// configuration waits before it is moved anyway (an app with one
/// replica, or one whose other replicas are not ready).
pub const ALONE_WAIT: Duration = Duration::from_secs(2 * 60);
/// After a move whose replica did not get ready again, or a failed move of
/// the proxy, the next waits BACKOFF, doubling up to MAX_BACKOFF.
pub const BACKOFF: Duration = Duration::from_secs(10 * 60);
pub const MAX_BACKOFF: Duration = Duration::from_secs(2 * 3600);

/// The restart note of a moved replica.
pub const MOVED_NOTE: &str = "its container moved from runc to crun";

/// A replica being moved.
#[derive(Clone, Debug)]
pub(crate) struct Moving {
    pub replica: String,
    /// Its runc container.
    pub container: String,
    /// When it was taken out of service, then when its container was
    /// removed.
    pub since: SystemTime,
    /// Whether its runc container was removed.
    pub removed: bool,
    /// Whether it was ready before: only then does the move wait for it to
    /// be ready again.
    pub was_ready: bool,
}

/// Where the move stands, in the agent's state.
#[derive(Default)]
pub(crate) struct CrunMove {
    pub current: Option<Moving>,
    /// When each replica was first seen alone in its app's backends.
    pub alone: HashMap<String, SystemTime>,
    pub failures: u32,
    pub not_before: Option<SystemTime>,
    /// Whether the agent said it moves replicas (logged once per round).
    pub announced: bool,
    pub proxy_busy: bool,
    pub proxy_done: bool,
    pub proxy_failures: u32,
    pub proxy_not_before: Option<SystemTime>,
}

/// What a pass does about the move.
#[derive(Default)]
pub(crate) struct Plan {
    /// The replica reported starting while its runc container still runs.
    pub draining: Option<String>,
    /// The replica the pass recreates on crun.
    pub move_now: Option<String>,
    /// Whether every replica the agent moves is on crun and none is being
    /// moved: the proxy's turn.
    pub replicas_done: bool,
}

/// The wait after `failures` failed moves.
pub fn backoff(failures: u32) -> Duration {
    let n = failures.saturating_sub(1).min(16);
    (BACKOFF * 2u32.pow(n)).min(MAX_BACKOFF)
}

fn later(t: SystemTime, d: Duration) -> SystemTime {
    clock::from_unix_nanos(clock::unix_nanos(t) + d.as_nanos() as i128)
}

fn passed(now: SystemTime, since: SystemTime, d: Duration) -> bool {
    i128::from(clock::sub(now, since)) >= d.as_nanos() as i128
}

/// Whether replica is the only server its app's backends list (the app's
/// own and its labelled revisions', `<label>--<app>`).
pub(crate) fn alone(px: Option<&pb::ProxyConfig>, app: &str, replica: &str) -> bool {
    let Some(px) = px else { return false };
    let label = format!("--{app}");
    let mut listed = false;
    for b in px
        .backends
        .iter()
        .filter(|b| b.name == app || b.name.ends_with(&label))
    {
        for s in &b.servers {
            if s.name != replica {
                return false;
            }
            listed = true;
        }
    }
    listed
}

impl<R: Runtime> Inner<R> {
    /// The pass's part of the move: whether the replica moved last is
    /// ready again, and which replica to move now.
    pub(crate) fn crun_plan(
        self: &Arc<Self>,
        desired: &BTreeMap<String, pb::ReplicaSpec>,
        by_replica: &BTreeMap<String, Container>,
    ) -> Plan {
        let now = self.now();
        let mut plan = Plan::default();
        let current = lock(&self.st).crun.current.clone();
        if let Some(m) = current.as_ref().filter(|m| !m.removed) {
            let still = by_replica
                .get(&m.replica)
                .is_some_and(|c| c.id == m.container && !stopped(&c.state));
            if !desired.contains_key(&m.replica) || !still {
                // Removed, or recreated for another reason: on crun now.
                lock(&self.st).crun.current = None;
            } else if passed(now, m.since, DRAIN) {
                plan.move_now = Some(m.replica.clone());
                return plan;
            } else {
                plan.draining = Some(m.replica.clone());
                return plan;
            }
        } else if let Some(m) = current {
            let new = by_replica
                .get(&m.replica)
                .filter(|c| c.id != m.container && !c.on_runc() && c.state == STATE_RUNNING);
            match (desired.get(&m.replica), new) {
                (None, _) => {
                    lock(&self.st).crun.current = None;
                }
                (Some(spec), Some(c)) if !m.was_ready || self.readiness(spec, c).0 => {
                    self.log.info(
                        "moved replica to crun",
                        &[("replica", m.replica.clone()), ("container", c.id.clone())],
                    );
                    let mut st = lock(&self.st);
                    st.crun.current = None;
                    st.crun.failures = 0;
                }
                _ if passed(now, m.since, READY_WAIT) => {
                    let mut st = lock(&self.st);
                    st.crun.current = None;
                    if m.was_ready {
                        st.crun.failures += 1;
                        let wait = backoff(st.crun.failures);
                        st.crun.not_before = Some(later(now, wait));
                        self.log.warn(
                            "a replica moved to crun is not ready again; moving the next later",
                            &[
                                ("replica", m.replica.clone()),
                                ("wait", clock::duration_string(wait.as_nanos() as i64)),
                            ],
                        );
                    }
                }
                _ => return plan,
            }
        }

        let mut candidates: Vec<(&String, &pb::ReplicaSpec)> = Vec::new();
        let mut recent: Vec<(&pb::ReplicaSpec, &Container)> = Vec::new();
        {
            let st = lock(&self.st);
            for (id, spec) in desired {
                let Some(c) = by_replica.get(id) else {
                    continue;
                };
                if spec.job.is_some()
                    || spec.hold
                    || stopped(&c.state)
                    || st.restarts.contains_key(&c.id)
                {
                    continue;
                }
                if !c.on_runc() {
                    if c.oci_runtime == OCI_CRUN
                        && c.started_at.is_some_and(|t| !passed(now, t, READY_WAIT))
                    {
                        recent.push((spec, c));
                    }
                    continue;
                }
                if c.label(LABEL_SPEC_HASH) != spec_hash(spec) {
                    continue; // recreated for its spec this pass
                }
                candidates.push((id, spec));
            }
        }
        // A replica created on crun lately and not ready yet, such as one
        // moved before the agent restarted, is waited for as one moved in
        // this run.
        let settling = recent.iter().any(|(spec, c)| {
            c.state == STATE_RUNNING && !self.readiness(spec, c).0 || c.state != STATE_RUNNING
        });
        // Fenced and paused replicas wait: they run again first.
        candidates.retain(|(_, s)| !self.fenced(s) && !self.is_paused(&s.app));

        let mut st = lock(&self.st);
        let ids: Vec<&String> = candidates.iter().map(|(id, _)| *id).collect();
        st.crun.alone.retain(|k, _| ids.contains(&k));
        if candidates.is_empty() {
            if st.crun.announced {
                st.crun.announced = false;
                self.log.info("every replica on the node runs on crun", &[]);
            }
            plan.replicas_done = !settling;
            return plan;
        }
        if !st.crun.announced {
            st.crun.announced = true;
            self.log.info(
                "moving replicas from runc to crun, one at a time",
                &[("replicas", candidates.len().to_string())],
            );
        }
        let held = st.crun.not_before.is_some_and(|t| now < t);
        if settling
            || held
            || !st.contact_up
            || self.moving.load(std::sync::atomic::Ordering::SeqCst)
        {
            return plan;
        }
        let px = st.proxy_desired.clone();
        for (id, spec) in candidates {
            if alone(px.as_ref(), &spec.app, id) {
                let since = *st.crun.alone.entry(id.clone()).or_insert(now);
                if !passed(now, since, ALONE_WAIT) {
                    continue;
                }
            } else {
                st.crun.alone.remove(id);
            }
            let c = &by_replica[id];
            let was_ready = c.state == STATE_RUNNING
                && st
                    .probes
                    .get(id)
                    .is_some_and(|w| w.container_id == c.id && w.status().0);
            st.crun.alone.remove(id);
            st.crun.current = Some(Moving {
                replica: id.clone(),
                container: c.id.clone(),
                since: now,
                removed: false,
                was_ready,
            });
            drop(st);
            self.log.info(
                "moving replica to crun",
                &[("replica", id.clone()), ("container", c.id.clone())],
            );
            plan.draining = Some(id.clone());
            // The pass after the drain stops its runc container.
            let inner = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(DRAIN).await;
                inner.trigger.notify_one();
            });
            break;
        }
        plan
    }

    /// The report of a replica being taken out of service before its move:
    /// starting, no address, its runc container.
    pub(crate) fn crun_draining(&self, id: &str, c: &Container) -> pb::ReplicaState {
        let note = format!("{}{MOVED_NOTE}", crate::agent::RESTART_NOTE);
        lock(&self.st).notes.insert(id.to_string(), note.clone());
        pb::ReplicaState {
            id: id.to_string(),
            state: crate::agent::REPLICA_STARTING.into(),
            container_id: c.id.clone(),
            message: note,
            ..Default::default()
        }
    }

    /// Removes the runc container of the replica being moved: the pass
    /// starts it again on crun.
    pub(crate) fn begin_crun_move(&self, id: &str) {
        let now = self.now();
        let mut st = lock(&self.st);
        if let Some(m) = st.crun.current.as_mut().filter(|m| m.replica == id) {
            m.removed = true;
            m.since = now;
        }
    }

    /// The proxy's turn, once every replica moved: its container is
    /// replaced on crun in the background, as the proxy's driver can do it
    /// with no gap.
    pub(crate) fn move_proxy_to_crun(self: &Arc<Self>, replicas_done: bool) {
        let Some(px) = self.cfg.proxy.clone() else {
            return;
        };
        if !replicas_done || !px.moves_to_crun() {
            return;
        }
        let now = self.now();
        {
            let mut st = lock(&self.st);
            let c = &mut st.crun;
            if c.proxy_done || c.proxy_busy || c.proxy_not_before.is_some_and(|t| now < t) {
                return;
            }
            if !st.contact_up {
                return;
            }
            st.crun.proxy_busy = true;
        }
        let inner = self.clone();
        tokio::spawn(async move {
            let res = match px.on_runc().await {
                Ok(false) => Ok(()),
                Ok(true) => {
                    inner.log.info("moving the proxy to crun", &[]);
                    let r = px.move_to_crun().await;
                    if r.is_ok() {
                        inner.log.info("moved the proxy to crun", &[]);
                    }
                    r
                }
                Err(e) => Err(e),
            };
            let now = inner.now();
            let mut st = lock(&inner.st);
            let c = &mut st.crun;
            c.proxy_busy = false;
            match res {
                Ok(()) => {
                    c.proxy_done = true;
                    c.proxy_failures = 0;
                }
                Err(e) => {
                    c.proxy_failures += 1;
                    let wait = backoff(c.proxy_failures);
                    c.proxy_not_before = Some(later(now, wait));
                    inner.log.warn(
                        "move the proxy to crun",
                        &[
                            ("err", e),
                            ("retry in", clock::duration_string(wait.as_nanos() as i64)),
                        ],
                    );
                }
            }
        });
    }
}

#[cfg(test)]
mod tests;

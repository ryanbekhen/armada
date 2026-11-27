//! Containers runc created (ADR 0056). The runtime pack carries crun
//! alone, and crun cannot manage runc's containers, so a container whose
//! bundle record names runc (or no runtime: every record of a release
//! before crun) cannot be stopped, signalled as a whole, deleted, or
//! entered through its runtime any more. v0.1.0-alpha.44 moves them all to
//! crun at a pace before an upgrade; a node upgraded before its move
//! finished still has some. The agent ends each one without runc (the
//! runtime kills every process in its cgroup and removes it with its
//! bundle, root filesystem, and runc's state) and creates it again on
//! crun, driven from every pass, the first one at its start included,
//! and never waiting in one:
//!
//! - Per app, one replica of the node at a time. A replica of an app that
//!   has another ready replica (on this node, or a server of the app's
//!   backends in the node's proxy configuration, which lists ready
//!   replicas of every node) is first reported starting with no address
//!   while its runc container still runs, so the leader takes it out of
//!   every proxy, and ended DRAIN later; one with no other ready replica
//!   is ended at once, as there is nothing to drain to. Either way it is
//!   created again on crun in the same pass, reported starting with its
//!   old container meanwhile, as after a crash. Its restart note says why
//!   (`RUNC_NOTE`). The app's next replica waits until the recreated one
//!   runs and is ready, for at most READY_WAIT. Apps go in parallel. A
//!   replica created on crun in the last READY_WAIT and not ready yet
//!   counts as its app's recovery, so an agent restarted in the middle
//!   waits for the one it recreated. A runc container that has stopped
//!   serves nothing and is ended at once.
//! - A job attempt still running is left to end by itself: it needs
//!   nothing from runc while it runs, and an attempt runs once. A finished
//!   one is removed with the job's history, as any other.
//! - HAProxy's system container is replaced by the proxy's driver with a
//!   new one on crun beside it (`Proxy::move_to_crun`), in the background;
//!   a failure is tried again after a wait that doubles up to two hours.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use armada_proto::armada::v1 as pb;

use crate::agent::{Inner, lock};
use crate::clock;
use crate::runtime::{Container, LABEL_SPEC_HASH, Runtime, STATE_RUNNING, stopped};
use crate::spec::spec_hash;

/// The restart note of a replica whose container runc created.
pub const RUNC_NOTE: &str =
    "its container was created by runc, which this release does not carry; recreated on crun";

/// How long a replica is reported starting before its runc container is
/// ended: the leader takes it out of the proxies meanwhile.
pub const DRAIN: Duration = Duration::from_secs(5);
/// How long an app's next replica waits for the one recreated before it
/// to run and be ready.
pub const READY_WAIT: Duration = Duration::from_secs(5 * 60);

/// After a failed move of the proxy, the next waits BACKOFF, doubling up
/// to MAX_BACKOFF.
pub const BACKOFF: Duration = Duration::from_secs(10 * 60);
pub const MAX_BACKOFF: Duration = Duration::from_secs(2 * 3600);

/// What the agent keeps about containers runc created.
#[derive(Default)]
pub(crate) struct RuncLeft {
    /// The containers already said to be ended (each logged once).
    pub ended: HashSet<String>,
    /// Each app's replica in recovery on this node, by app.
    pub recovering: HashMap<String, Recovery>,
    pub proxy_busy: bool,
    pub proxy_done: bool,
    pub proxy_failures: u32,
    pub proxy_not_before: Option<SystemTime>,
}

/// An app's replica in recovery.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Recovery {
    pub replica: String,
    /// Its runc container (empty for one rebuilt after a restart).
    pub container: String,
    pub step: Step,
    /// When the step began.
    pub since: SystemTime,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Step {
    /// Reported starting while its runc container still runs.
    Draining,
    /// Ended and created again on crun: waited for until ready.
    Ended,
}

/// What a pass does with the replicas runc created.
#[derive(Default, Debug)]
pub(crate) struct Pace {
    /// Reported starting, their runc containers left running.
    pub drain: HashSet<String>,
    /// Ended now and created again on crun.
    pub end: HashSet<String>,
}

/// Whether the app's backends in the proxy configuration (its own and its
/// labelled revisions', `<label>--<app>`) list a server other than
/// replica: the leader lists only ready replicas.
pub(crate) fn served_elsewhere(px: Option<&pb::ProxyConfig>, app: &str, replica: &str) -> bool {
    let Some(px) = px else { return false };
    let label = format!("--{app}");
    px.backends
        .iter()
        .filter(|b| b.name == app || b.name.ends_with(&label))
        .flat_map(|b| &b.servers)
        .any(|s| s.name != replica)
}

fn passed(now: SystemTime, since: SystemTime, d: Duration) -> bool {
    i128::from(clock::sub(now, since)) >= d.as_nanos() as i128
}

/// The wait after `failures` failed moves of the proxy.
pub fn backoff(failures: u32) -> Duration {
    let n = failures.saturating_sub(1).min(16);
    (BACKOFF * 2u32.pow(n)).min(MAX_BACKOFF)
}

fn later(t: SystemTime, d: Duration) -> SystemTime {
    clock::from_unix_nanos(clock::unix_nanos(t) + d.as_nanos() as i128)
}

impl<R: Runtime> Inner<R> {
    /// The pass's part of the recovery: which replicas runc created are
    /// drained and which are ended now, one per app; the rest wait.
    pub(crate) fn runc_pace(
        self: &Arc<Self>,
        desired: &BTreeMap<String, pb::ReplicaSpec>,
        by_replica: &BTreeMap<String, Container>,
    ) -> Pace {
        let now = self.now();
        let mut pace = Pace::default();
        // The replicas the pass would otherwise leave running, by app.
        let mut cands: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (id, spec) in desired {
            let Some(c) = by_replica.get(id) else {
                continue;
            };
            if !c.on_runc()
                || stopped(&c.state)
                || spec.job.is_some()
                || spec.hold
                || c.label(LABEL_SPEC_HASH) != spec_hash(spec)
                || self.fenced(spec)
                || self.is_paused(&spec.app)
                || !crate::containers::member_down(spec, c).is_empty()
                || lock(&self.st).restarts.contains_key(&c.id)
            {
                continue;
            }
            cands.entry(spec.app.clone()).or_default().push(id.clone());
        }

        // After a restart: a replica created on crun lately and not ready
        // yet is its app's recovery.
        let known: HashSet<String> = lock(&self.st).runc.recovering.keys().cloned().collect();
        for app in cands.keys().filter(|a| !known.contains(*a)) {
            for (id, spec) in desired.iter().filter(|(_, s)| &s.app == app) {
                let Some(c) = by_replica.get(id) else {
                    continue;
                };
                let Some(started) = c.started_at else {
                    continue;
                };
                if c.on_runc() || spec.job.is_some() || passed(now, started, READY_WAIT) {
                    continue;
                }
                if c.state != STATE_RUNNING || !self.readiness(spec, c).0 {
                    lock(&self.st).runc.recovering.insert(
                        app.clone(),
                        Recovery {
                            replica: id.clone(),
                            container: String::new(),
                            step: Step::Ended,
                            since: started,
                        },
                    );
                    break;
                }
            }
        }

        let entries: Vec<(String, Recovery)> = lock(&self.st)
            .runc
            .recovering
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (app, r) in entries {
            let spec = desired.get(&r.replica);
            let keep = match r.step {
                Step::Draining => {
                    let still = cands.get(&app).is_some_and(|v| v.contains(&r.replica))
                        && by_replica
                            .get(&r.replica)
                            .is_some_and(|c| c.id == r.container);
                    if !still {
                        // Recreated, removed, or stopped meanwhile.
                        None
                    } else if passed(now, r.since, DRAIN) {
                        pace.end.insert(r.replica.clone());
                        Some(Recovery {
                            step: Step::Ended,
                            since: now,
                            ..r
                        })
                    } else {
                        pace.drain.insert(r.replica.clone());
                        Some(r)
                    }
                }
                Step::Ended => match spec {
                    None => None,
                    Some(spec) => {
                        let new = by_replica
                            .get(&r.replica)
                            .filter(|c| c.id != r.container && !c.on_runc());
                        let ready = new
                            .is_some_and(|c| c.state == STATE_RUNNING && self.readiness(spec, c).0);
                        if ready {
                            if !r.container.is_empty() {
                                self.log.info(
                                    "recreated a replica on crun",
                                    &[("replica", r.replica.clone())],
                                );
                            }
                            None
                        } else if passed(now, r.since, READY_WAIT) {
                            self.log.warn(
                                "a replica recreated on crun is not ready; going on with its app's next",
                                &[
                                    ("replica", r.replica.clone()),
                                    (
                                        "waited",
                                        clock::duration_string(READY_WAIT.as_nanos() as i64),
                                    ),
                                ],
                            );
                            None
                        } else {
                            Some(r)
                        }
                    }
                },
            };
            let mut st = lock(&self.st);
            match keep {
                Some(r) => {
                    st.runc.recovering.insert(app, r);
                }
                None => {
                    st.runc.recovering.remove(&app);
                }
            }
        }
        lock(&self.st)
            .runc
            .recovering
            .retain(|_, r| desired.contains_key(&r.replica));

        for (app, ids) in &cands {
            if lock(&self.st).runc.recovering.contains_key(app) {
                continue;
            }
            let id = &ids[0];
            let c = &by_replica[id];
            let others = self.other_ready(desired, by_replica, app, id);
            let step = if others { Step::Draining } else { Step::Ended };
            lock(&self.st).runc.recovering.insert(
                app.clone(),
                Recovery {
                    replica: id.clone(),
                    container: c.id.clone(),
                    step,
                    since: now,
                },
            );
            if others {
                self.log.info(
                    "taking a replica runc created out of service before recreating it on crun",
                    &[("replica", id.clone()), ("container", c.id.clone())],
                );
                pace.drain.insert(id.clone());
                // The pass after the drain ends it.
                let inner = self.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(DRAIN).await;
                    inner.trigger.notify_one();
                });
            } else {
                pace.end.insert(id.clone());
            }
        }
        pace
    }

    /// Whether app has a ready replica other than replica: on this node,
    /// or listed in its backends.
    fn other_ready(
        &self,
        desired: &BTreeMap<String, pb::ReplicaSpec>,
        by_replica: &BTreeMap<String, Container>,
        app: &str,
        replica: &str,
    ) -> bool {
        let st = lock(&self.st);
        if served_elsewhere(st.proxy_desired.as_ref(), app, replica) {
            return true;
        }
        desired
            .iter()
            .filter(|(id, s)| s.app == app && *id != replica && s.job.is_none())
            .any(|(id, _)| {
                by_replica.get(id).is_some_and(|c| {
                    c.state == STATE_RUNNING
                        && st
                            .probes
                            .get(id)
                            .is_some_and(|w| w.container_id == c.id && w.status().0)
                })
            })
    }

    /// The report of a replica taken out of service before it is ended:
    /// starting, no address, its runc container.
    pub(crate) fn runc_draining(&self, id: &str, c: &Container) -> pb::ReplicaState {
        let note = format!("{}{RUNC_NOTE}", crate::agent::RESTART_NOTE);
        lock(&self.st).notes.insert(id.to_string(), note.clone());
        pb::ReplicaState {
            id: id.to_string(),
            state: crate::agent::REPLICA_STARTING.into(),
            container_id: c.id.clone(),
            message: note,
            ..Default::default()
        }
    }

    /// Ends a replica's container that runc created and removes it: no
    /// grace, as nothing can wait for it through its runtime. The pass
    /// then creates the replica again on crun.
    pub(crate) async fn end_runc_replica(&self, id: &str, c: &Container) {
        let first = lock(&self.st).runc.ended.insert(c.id.clone());
        if first {
            self.log.info(
                "ended a container runc created; recreating it on crun",
                &[("replica", id.to_string()), ("container", c.id.clone())],
            );
        }
        lock(&self.st).notes.insert(
            id.to_string(),
            format!("{}{RUNC_NOTE}", crate::agent::RESTART_NOTE),
        );
        if let Err(e) = self.rt.stop(&c.id, Duration::ZERO).await
            && e != crate::runtime::Error::NotFound
        {
            self.log.warn(
                "end a container runc created",
                &[("container", c.id.clone()), ("err", e.to_string())],
            );
        }
        if let Err(e) = self.rt.remove(&c.id).await
            && e != crate::runtime::Error::NotFound
        {
            self.log.warn(
                "remove a container runc created",
                &[("container", c.id.clone()), ("err", e.to_string())],
            );
        }
    }

    /// Forgets the containers said to be ended that are gone.
    pub(crate) fn forget_ended(&self, listed: &[Container]) {
        let mut st = lock(&self.st);
        st.runc
            .ended
            .retain(|id| listed.iter().any(|c| &c.id == id));
    }

    /// The proxy's container moved to crun when runc created it, in the
    /// background (the proxy's driver does it with no gap), one at a time,
    /// a failure tried again later.
    pub(crate) fn move_proxy_to_crun(self: &Arc<Self>) {
        let Some(px) = self.cfg.proxy.clone() else {
            return;
        };
        if !px.moves_to_crun() {
            return;
        }
        let now = self.now();
        {
            let mut st = lock(&self.st);
            let r = &mut st.runc;
            if r.proxy_done || r.proxy_busy || r.proxy_not_before.is_some_and(|t| now < t) {
                return;
            }
            r.proxy_busy = true;
        }
        let inner = self.clone();
        tokio::spawn(async move {
            let res = match px.on_runc().await {
                Ok(false) => Ok(()),
                Ok(true) => {
                    inner.log.info("moving the proxy from runc to crun", &[]);
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
            let r = &mut st.runc;
            r.proxy_busy = false;
            match res {
                Ok(()) => {
                    r.proxy_done = true;
                    r.proxy_failures = 0;
                }
                Err(e) => {
                    r.proxy_failures += 1;
                    let wait = backoff(r.proxy_failures);
                    r.proxy_not_before = Some(later(now, wait));
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

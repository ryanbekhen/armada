//! Containers runc created (ADR 0056). The runtime pack carries crun
//! alone, and crun cannot manage runc's containers, so a container whose
//! bundle record names runc (or no runtime: every record of a release
//! before crun) cannot be stopped, signalled as a whole, deleted, or
//! entered through its runtime any more. v0.1.0-alpha.44 moves them all to
//! crun at a pace before an upgrade; a node upgraded before its move
//! finished still has some. The agent ends each one without runc (the
//! runtime kills every process in its cgroup and removes it with its
//! bundle, root filesystem, and runc's state) and creates it again on
//! crun, in every pass, the first one at its start included:
//!
//! - A replica's container is ended and the replica created again at once,
//!   reported starting with its old container meanwhile, as after a crash,
//!   so the proxies stop sending it requests. Its restart note says why
//!   (`RUNC_NOTE`).
//! - A job attempt still running is left to end by itself: it needs
//!   nothing from runc while it runs, and an attempt runs once. A finished
//!   one is removed with the job's history, as any other.
//! - HAProxy's system container is replaced by the proxy's driver with a
//!   new one on crun beside it (`Proxy::move_to_crun`), in the background;
//!   a failure is tried again after a wait that doubles up to two hours.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::agent::{Inner, lock};
use crate::clock;
use crate::runtime::{Container, Runtime};

/// The restart note of a replica whose container runc created.
pub const RUNC_NOTE: &str =
    "its container was created by runc, which this release does not carry; recreated on crun";

/// After a failed move of the proxy, the next waits BACKOFF, doubling up
/// to MAX_BACKOFF.
pub const BACKOFF: Duration = Duration::from_secs(10 * 60);
pub const MAX_BACKOFF: Duration = Duration::from_secs(2 * 3600);

/// What the agent keeps about containers runc created.
#[derive(Default)]
pub(crate) struct RuncLeft {
    /// The containers already said to be ended (each logged once).
    pub ended: std::collections::HashSet<String>,
    pub proxy_busy: bool,
    pub proxy_done: bool,
    pub proxy_failures: u32,
    pub proxy_not_before: Option<SystemTime>,
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

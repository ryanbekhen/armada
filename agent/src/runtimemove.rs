//! The node's move to the supervisor runtime (ADR 0054, "The runtime's
//! move", step 4; Go's runtimemove.go): once nothing of the node's
//! assignment runs, Config.prepare_runtime_move readies what the node
//! needs right after its restart while everything still runs, then
//! Config.move_runtime removes every container, records the runtime, and
//! restarts the node's service. Why it did not move is reported with the
//! node's runtime until the next request.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use armada_proto::armada::v1 as pb;

use crate::agent::{Agent, Inner, lock};
use crate::proxy::BoxFut;
use crate::runtime::{AGENT_CONTAINERD, Runtime};

/// Bounds one move: stopping and removing every container, then recording
/// the runtime.
pub const MOVE_RUNTIME_TIMEOUT: Duration = Duration::from_secs(600);

/// Moves the node to the runtime named (Config.move_runtime).
pub type MoveFn = Arc<dyn Fn(String) -> BoxFut<'static, Result<(), String>> + Send + Sync>;
/// Readies the move (Config.prepare_runtime_move); it only logs failures.
pub type PrepareFn = Arc<dyn Fn(String) -> BoxFut<'static, ()> + Send + Sync>;
/// Receives the leader's plan for the node's move when it changes.
pub type PlanFn = Arc<dyn Fn(Option<pb::RuntimeMovePlan>) + Send + Sync>;

/// The replicas that keep a node from moving, sorted: every one but
/// finished job attempts. None before the first assignment.
pub fn movable_left(desired: Option<&BTreeMap<String, pb::ReplicaSpec>>) -> Option<Vec<String>> {
    let d = desired?;
    Some(
        d.iter()
            .filter(|(_, r)| !r.job.as_ref().is_some_and(|j| j.done))
            .map(|(id, _)| id.clone())
            .collect(),
    )
}

impl<R: Runtime> Agent<R> {
    /// A MoveRuntime request from the leader.
    pub async fn move_runtime(&self, to: &str) {
        self.inner.move_runtime(to).await
    }
}

impl<R: Runtime> Inner<R> {
    /// Moves the node to `to`; one move at a time, and none after one
    /// succeeded.
    pub(crate) async fn move_runtime(&self, to: &str) {
        if self.cfg.move_runtime.is_none()
            || self
                .moving
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            return;
        }
        let res = match tokio::time::timeout(MOVE_RUNTIME_TIMEOUT, self.try_move_runtime(to)).await
        {
            Ok(r) => r,
            Err(_) => Err("context deadline exceeded".to_string()),
        };
        match res {
            Err(e) => {
                self.log.warn(
                    "did not move the node to another runtime",
                    &[("to", to.to_string()), ("err", e.clone())],
                );
                *lock(&self.move_err) = e;
                self.moving.store(false, Ordering::SeqCst);
            }
            Ok(()) => lock(&self.move_err).clear(),
        }
    }

    async fn try_move_runtime(&self, to: &str) -> Result<(), String> {
        if let Some(prepare) = &self.cfg.prepare_runtime_move {
            // Checked first, so a node that cannot move does no work for
            // it; the preparation runs outside reconcile_mu.
            self.movable()?;
            prepare(to.to_string()).await;
        }
        // No replica starts while the containers go.
        let _g = self.reconcile_mu.lock().await;
        self.movable()?;
        self.log.warn(
            "moving this node to the supervisor runtime: removing its containers, its proxy's too, and restarting the service",
            &[("to", to.to_string())],
        );
        let Some(mv) = &self.cfg.move_runtime else {
            return Ok(());
        };
        mv(to.to_string()).await
    }

    /// Why the node cannot move now.
    fn movable(&self) -> Result<(), String> {
        let left = movable_left(lock(&self.st).desired.as_ref());
        match left {
            None => Err("no assignment from the control plane yet".to_string()),
            Some(mut left) if !left.is_empty() => {
                let mut more = String::new();
                if left.len() > 5 {
                    more = format!(" and {} more", left.len() - 5);
                    left.truncate(5);
                }
                Err(format!(
                    "replicas are still assigned to this node: {}{more}",
                    left.join(", ")
                ))
            }
            Some(_) if self.volume_ops.load(Ordering::SeqCst) > 0 => {
                Err("a volume operation runs on this node".to_string())
            }
            Some(_) => Ok(()),
        }
    }

    /// Hands the leader's plan to Config.on_runtime_move when it changes.
    pub(crate) fn set_runtime_move_plan(&self, p: Option<&pb::RuntimeMovePlan>) {
        let Some(on) = &self.cfg.on_runtime_move else {
            return;
        };
        let same = {
            let mut st = lock(&self.st);
            let same = st.move_plan.as_ref() == Some(&p.cloned());
            st.move_plan = Some(p.cloned());
            same
        };
        if !same {
            on(p.cloned());
        }
    }

    /// Adds why the node last did not move to its runtime status.
    pub(crate) fn with_move_error(
        &self,
        st: Option<pb::RuntimeStatus>,
    ) -> Option<pb::RuntimeStatus> {
        let mut st = st?;
        if st.agent != AGENT_CONTAINERD {
            return Some(st);
        }
        let e = lock(&self.move_err).clone();
        if !e.is_empty() {
            st.move_error = e;
        }
        Some(st)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn left_replicas() {
        assert_eq!(movable_left(None), None);
        let mut d = BTreeMap::new();
        d.insert(
            "j-j1-a".to_string(),
            pb::ReplicaSpec {
                job: Some(pb::JobAttempt {
                    done: true,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        assert_eq!(movable_left(Some(&d)), Some(vec![]));
        d.insert("web-r1-b".into(), pb::ReplicaSpec::default());
        d.insert("web-r1-a".into(), pb::ReplicaSpec::default());
        assert_eq!(
            movable_left(Some(&d)),
            Some(vec!["web-r1-a".to_string(), "web-r1-b".to_string()])
        );
    }
}

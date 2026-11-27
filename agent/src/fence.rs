//! Fencing (ADR 0041): a replica whose volumes fail over to
//! another node stops once its agent has been cut off from the control
//! plane for the time the server set, before the server restores the
//! volumes elsewhere.

use armada_proto::armada::v1 as pb;

use crate::agent::{Inner, VOLUME_STOP_GRACE, lock, managed};
use crate::clock;
use crate::runtime::{LABEL_FENCE_AFTER, LABEL_REPLICA, Runtime, stopped};

/// A fenced replica's status.
pub const FENCED_MESSAGE: &str =
    "stopped: cut off from the control plane, so its volumes may be restored on another node";

/// Bounds the label read back from a container.
const MAX_FENCE_AFTER: i64 = 7 * 24 * 3600;

impl<R: Runtime> Inner<R> {
    /// Records whether the agent has a session with the server.
    pub(crate) fn set_contact(&self, up: bool) {
        let now = self.now();
        let mut st = lock(&self.st);
        st.contact_up = up;
        if !up {
            st.contact_lost = Some(now);
        }
    }

    /// How long the agent has been without a session (ns): since the last
    /// one ended, or since it started.
    pub(crate) fn cut_off(&self) -> i64 {
        let now = self.now();
        let st = lock(&self.st);
        if st.contact_up {
            return 0;
        }
        clock::sub(now, st.contact_lost.unwrap_or(self.began))
    }

    /// Whether s must not run now.
    pub(crate) fn fenced(&self, s: &pb::ReplicaSpec) -> bool {
        let n = s.fence_after_seconds;
        n > 0 && i128::from(self.cut_off()) >= i128::from(n) * 1_000_000_000
    }

    pub(crate) fn mark_fenced(&self, id: &str) {
        lock(&self.st).fenced_ids.insert(id.to_string());
    }

    /// Forgets a fenced container; whether it was one.
    pub(crate) fn unfence(&self, id: &str) -> bool {
        lock(&self.st).fenced_ids.remove(id)
    }

    /// Stops containers that carry a fence time before the agent has an
    /// assignment, such as after a restart while the control plane is out
    /// of reach.
    pub(crate) async fn fence_unassigned(&self) {
        if lock(&self.st).desired.is_some() {
            return;
        }
        let cut = self.cut_off();
        if cut == 0 {
            return;
        }
        let Ok(cs) = self.rt.list(&managed()).await else {
            return;
        };
        for c in cs {
            let Some(v) = c.labels.get(LABEL_FENCE_AFTER) else {
                continue;
            };
            if stopped(&c.state) {
                continue;
            }
            let n = match armada_spec::go::atoi(v) {
                Ok(n) => n,
                Err(_) => continue,
            };
            if n <= 0 || n > MAX_FENCE_AFTER || i128::from(cut) < i128::from(n) * 1_000_000_000 {
                continue;
            }
            self.log.warn(
                "stopping a replica cut off from the control plane",
                &[("replica", c.label(LABEL_REPLICA).to_string())],
            );
            let _ = self.rt.stop(&c.id, VOLUME_STOP_GRACE).await;
            self.mark_fenced(&c.id);
        }
    }
}

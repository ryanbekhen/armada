//! Job attempts (ADR 0019): a container that runs once, never
//! restarted; its exit code is reported, and a done attempt is stopped if
//! it still runs, never started, and kept for its logs.

use std::sync::Arc;

use armada_proto::armada::v1 as pb;

use crate::agent::{Inner, REPLICA_EXITED, REPLICA_FAILED, STOP_GRACE};
use crate::runtime::{Container, Runtime, STATE_CREATED, stopped};

impl<R: Runtime> Inner<R> {
    /// Runs one attempt of a job run; None when there is nothing to report.
    pub(crate) async fn attempt(
        self: &Arc<Self>,
        s: &pb::ReplicaSpec,
        hash: &str,
        mut c: Container,
        mut ok: bool,
    ) -> Option<pb::ReplicaState> {
        let done = s.job.as_ref().is_some_and(|j| j.done);
        if ok && c.state == STATE_CREATED && !done {
            // Created but never started: starting it afresh runs it once.
            self.remove(&c.id).await;
            ok = false;
        }
        if !ok {
            if done {
                return None;
            }
            match self.start(s, hash, None).await {
                Ok(started) => c = started,
                Err(e) => {
                    self.log.error(
                        "start job attempt failed",
                        &[("replica", s.id.clone()), ("err", e.to_string())],
                    );
                    return Some(pb::ReplicaState {
                        id: s.id.clone(),
                        state: REPLICA_FAILED.into(),
                        message: e.to_string(),
                        ..Default::default()
                    });
                }
            }
        }
        if !stopped(&c.state) {
            if !done {
                return Some(self.state(s, &c));
            }
            self.log
                .info("stopping job attempt", &[("replica", s.id.clone())]);
            if let Err(e) = self.rt.stop(&c.id, STOP_GRACE).await {
                self.log.warn(
                    "stop failed",
                    &[("container", c.id.clone()), ("err", e.to_string())],
                );
            }
        }
        // Listing does not include the exit code.
        let full = match self.rt.inspect(&c.id).await {
            Ok(f) => f,
            Err(e) => {
                return Some(pb::ReplicaState {
                    id: s.id.clone(),
                    state: REPLICA_EXITED.into(),
                    container_id: c.id.clone(),
                    message: format!("exit code unknown: {e}"),
                    ..Default::default()
                });
            }
        };
        if !stopped(&full.state) {
            return Some(self.state(s, &full));
        }
        // The attempt ends with the job's own container: its sidecars stop
        // with it (ADR 0038).
        if !full.members.is_empty()
            && let Err(e) = self.rt.stop(&c.id, STOP_GRACE).await
        {
            self.log.warn(
                "stop sidecars failed",
                &[("container", c.id.clone()), ("err", e.to_string())],
            );
        }
        // The kept container is only for its logs: its address goes back.
        if let Some(Err(e)) = self.rt.release_network(&c.id).await {
            self.log.warn(
                "release network",
                &[("container", c.id.clone()), ("err", e.to_string())],
            );
        }
        let mut st = self.state(s, &full);
        st.state = REPLICA_EXITED.into();
        st.finished = true;
        st.exit_code = full.exit_code as i32;
        st.message = format!("exited with code {}", full.exit_code);
        // An init container that failed ends the attempt with its code.
        let down = crate::containers::member_down(s, &full);
        if !down.is_empty() {
            st.message = down;
            if let Some(m) = full.failed_init() {
                st.exit_code = m.exit_code as i32;
            }
        }
        Some(st)
    }
}

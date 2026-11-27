//! Held replicas (ADR 0023): during a rollout of an app with
//! volumes the server first sends the new replica held. The agent pulls its
//! images and says so, but starts nothing while the old replica still uses
//! the volume.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use armada_proto::armada::v1 as pb;

use crate::agent::{HeldPull, Inner, REPLICA_FAILED, REPLICA_PULLED, REPLICA_PULLING, lock};
use crate::clock;
use crate::runtime::{Error, Runtime};
use crate::spec::{has_members, registry_auth};

/// Bounds one attempt to pull a held replica's images.
pub const HOLD_PULL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// How long a failed pull waits before the next attempt.
pub const HOLD_RETRY: Duration = Duration::from_secs(30);

impl<R: Runtime> Inner<R> {
    /// A held replica's state; its images are pulled in the background,
    /// once, or again a while after a failure.
    pub(crate) fn held(self: &Arc<Self>, s: &pb::ReplicaSpec) -> pb::ReplicaState {
        let id = s.id.clone();
        let mut out = pb::ReplicaState {
            id: id.clone(),
            ..Default::default()
        };
        let now = self.now();
        let mut st = lock(&self.st);
        let mut p = st.holds.get(&id).cloned();
        if let Some(cell) = &p {
            let h = lock(cell);
            if h.err.is_some()
                && h.failed_at
                    .is_some_and(|f| clock::sub(now, f) >= HOLD_RETRY.as_nanos() as i64)
            {
                drop(h);
                p = None;
            }
        }
        let cell = match p {
            Some(c) => c,
            None => {
                let c = Arc::new(Mutex::new(HeldPull::default()));
                st.holds.insert(id.clone(), c.clone());
                let inner = self.clone();
                let spec = s.clone();
                let cell = c.clone();
                tokio::spawn(async move { inner.pull_held(spec, cell).await });
                c
            }
        };
        let h = lock(&cell);
        if !h.done {
            out.state = REPLICA_PULLING.into();
            out.message = "pulling its images; it starts once the old replica stops".into();
        } else if let Some(e) = &h.err {
            out.state = REPLICA_FAILED.into();
            out.message = e.to_string();
            out.image_platforms = h.platforms.clone();
        } else {
            out.state = REPLICA_PULLED.into();
            out.message = "images pulled; it starts once the old replica stops".into();
            out.image_digest = st.digests.get(&s.image).cloned().unwrap_or_default();
            out.image_platforms = st.platforms.get(&s.image).cloned().unwrap_or_default();
        }
        out
    }

    async fn pull_held(self: Arc<Self>, s: pb::ReplicaSpec, cell: Arc<Mutex<HeldPull>>) {
        let work = async {
            let auth = registry_auth(&s);
            let img = self.rt.pull(&s.image, auth.as_ref()).await?;
            {
                let mut st = lock(&self.st);
                if !img.reference.is_empty() {
                    st.digests.insert(s.image.clone(), img.reference.clone());
                }
                if !img.platforms.is_empty() {
                    st.platforms.insert(s.image.clone(), img.platforms.clone());
                }
            }
            if has_members(&s) {
                self.pull_members(&s, None).await?;
            }
            Ok::<(), Error>(())
        };
        let err = match tokio::time::timeout(HOLD_PULL_TIMEOUT, work).await {
            Ok(r) => r.err(),
            Err(_) => Some(Error::other("context deadline exceeded")),
        };
        let platforms = match &err {
            Some(Error::Platform { have, .. }) => have.clone(),
            _ => Vec::new(),
        };
        match &err {
            Some(e) => self.log.warn(
                "pull held replica's images failed",
                &[("replica", s.id.clone()), ("err", e.to_string())],
            ),
            None => self
                .log
                .info("pulled held replica's images", &[("replica", s.id.clone())]),
        }
        let now = self.now();
        {
            let _st = lock(&self.st);
            let mut h = lock(&cell);
            h.done = true;
            h.platforms = platforms;
            if err.is_some() {
                h.failed_at = Some(now);
            }
            h.err = err;
        }
        self.trigger.notify_one();
    }

    /// Drops the pulls of replicas that are no longer held.
    pub(crate) fn forget_holds(&self, desired: &BTreeMap<String, pb::ReplicaSpec>) {
        lock(&self.st)
            .holds
            .retain(|id, _| desired.get(id).is_some_and(|s| s.hold));
    }
}

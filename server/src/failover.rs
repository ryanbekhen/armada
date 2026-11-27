//! Failover (ADR 0041): when the node holding an app's
//! volumes is lost and every volume of the app says failover: restore, the
//! leader restores each volume's latest backup on another node and binds
//! the volumes there; the app then starts on that node. The lost node's
//! agent stops the app first (the replica's fence time, assign.rs), so two
//! copies are never written at once.

use std::collections::HashMap;
use std::sync::Mutex;

use armada_proto::armada::v1::VolumeRequest;
use armada_proto::armada::v1::volume_request::Op;
use armada_spec::go::format_duration;
use armada_spec::gotime::Time;
use armada_store::{Node, Revision};

use crate::Server;
use crate::backups::{BACKUP_RETRY, BACKUP_TIMEOUT};
use crate::reconcile::{APP, Run, app_event};
use crate::schedule::{eligible, pick_node, reservation};

/// Who the audit log names for automatic rebinding.
pub(crate) const FAILOVER_ACTOR: &str = "armada:failover";

/// Failovers in progress and when a failed one may be tried
/// again. Memory only: a new leader starts over.
#[derive(Default)]
pub struct FailoverRuns {
    m: Mutex<HashMap<String, (bool, Time)>>,
}

impl FailoverRuns {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (bool, Time)>> {
        self.m.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn start(&self, app: &str, now: &Time) -> bool {
        let mut m = self.lock();
        if let Some((running, retry_at)) = m.get(app)
            && (*running || now.before(retry_at))
        {
            return false;
        }
        m.insert(app.to_string(), (true, Time::zero()));
        true
    }

    fn fail(&self, app: &str, retry_at: Time) {
        self.lock().insert(app.to_string(), (false, retry_at));
    }

    fn done(&self, app: &str) {
        self.lock().remove(app);
    }
}

impl Server {
    /// A failover that failed: tried again after backupRetry.
    async fn failover_failed(&self, app: &str, from: &str, msg: &str) {
        self.0.failovers.fail(app, self.now().add(BACKUP_RETRY));
        let mut e = app_event(
            APP,
            app,
            app,
            "VolumeFailoverFailed",
            &format!("{msg}; trying again in {}", format_duration(BACKUP_RETRY)),
        );
        e.node = from.to_string();
        self.condition(&format!("failover-failed:{app}"), true, e)
            .await;
        self.0.log.warn(
            "volume failover failed",
            &[
                ("app", app.to_string()),
                ("from", from.to_string()),
                ("err", msg.to_string()),
            ],
        );
    }

    /// Starts restoring app's volumes on another node, unless
    /// one is running or a failed one waits for its retry.
    pub(crate) async fn fail_over(
        &self,
        rc: &mut Run<'_>,
        app: &str,
        from: &str,
        target: &Revision,
        nodes: &[Node],
    ) {
        if !self.0.failovers.start(app, &rc.now) {
            return;
        }
        let fit: Vec<Node> = eligible(nodes, target)
            .into_iter()
            .filter(|n| {
                n.id != from
                    && !rc.lost.contains(&n.id)
                    && self.session(&n.id).is_some_and(|s| s.caps.backups)
            })
            .collect();
        let res = rc.revs.reserved(&rc.all).await;
        let Some(node) = pick_node(&fit, &rc.all, &[], "", reservation(target), &res) else {
            self.failover_failed(
                app,
                from,
                "no other connected node that backs volumes up can take the app",
            )
            .await;
            return;
        };
        self.0.log.info(
            "failing over volumes",
            &[
                ("app", app.to_string()),
                ("from", from.to_string()),
                ("to", node.id.clone()),
            ],
        );
        let s = self.clone();
        let (app, from, target, to) = (
            app.to_string(),
            from.to_string(),
            target.clone(),
            node.id.clone(),
        );
        tokio::spawn(async move {
            // An unexpected spec fails this failover, never the server.
            let inner = {
                let (s, app, from, target, to) = (
                    s.clone(),
                    app.clone(),
                    from.clone(),
                    target.clone(),
                    to.clone(),
                );
                tokio::spawn(async move {
                    let run = s.restore_elsewhere(&app, &from, &target, &to);
                    if tokio::time::timeout(BACKUP_TIMEOUT, run).await.is_err() {
                        s.failover_failed(&app, &from, "context deadline exceeded")
                            .await;
                    }
                })
            };
            if inner.await.is_err() {
                s.0.log
                    .error("volume failover panicked", &[("app", app.clone())]);
                s.failover_failed(&app, &from, "internal error").await;
            }
        });
    }

    async fn restore_elsewhere(&self, app: &str, from: &str, target: &Revision, to: &str) {
        let mut restored = Vec::new();
        for v in &target.spec().volumes {
            if !v.local() {
                continue; // an NFS volume stays on its server
            }
            let bt = match self.backup_target(v.backup.as_ref(), target).await {
                Ok(bt) => bt,
                Err(e) => {
                    self.failover_failed(app, from, &format!("volume {}: {e}", v.name))
                        .await;
                    return;
                }
            };
            let (m, err) = self
                .repo_op(
                    to,
                    VolumeRequest {
                        op: Op::RestoreSnapshot as i32,
                        app: app.to_string(),
                        volume: v.name.clone(),
                        backup: Some(bt),
                        snapshot: "latest".to_string(),
                        ..Default::default()
                    },
                )
                .await;
            if let Some(e) = err {
                self.failover_failed(
                    app,
                    from,
                    &format!("restoring volume {} on {to}: {}", v.name, e.message()),
                )
                .await;
                return;
            }
            let id = m
                .and_then(|m| m.snapshot)
                .and_then(|s| s.snapshot)
                .map(|s| s.id)
                .unwrap_or_default();
            restored.push(format!("{} from {id}", v.name));
        }
        // Never bind while the old node is back: its replica may run.
        if self.session(from).is_some() {
            self.0.failovers.done(app);
            self.0.log.info(
                "volume failover abandoned: the node is back",
                &[("app", app.to_string()), ("node", from.to_string())],
            );
            return;
        }
        for v in &target.spec().volumes {
            if !v.local() {
                continue;
            }
            if let Err(e) = self
                .store()
                .bind_volume(app, &v.name, to, FAILOVER_ACTOR)
                .await
            {
                self.failover_failed(
                    app,
                    from,
                    &format!("binding volume {} to {to}: {e}", v.name),
                )
                .await;
                return;
            }
        }
        self.0.failovers.done(app);
        self.condition(
            &format!("failover-failed:{app}"),
            false,
            app_event(APP, app, app, "VolumeFailoverFailed", ""),
        )
        .await;
        let mut e = app_event(
            APP,
            app,
            app,
            "VolumeFailedOver",
            &format!(
                "node {from} was lost; restored {} on {to}",
                restored.join(", ")
            ),
        );
        e.node = to.to_string();
        self.record(e).await;
        self.trigger();
    }
}

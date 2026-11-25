//! Volumes (Go's volumes.go, ADR 0023): apps whose target revision mounts
//! local volumes run at most one replica, on the node their volumes are
//! bound to, and a new replica starts only once every other one is gone
//! (recreate), its images pulled first into a held replica while the old
//! one serves; nothing moves off a cordoned or lost node. The volume
//! methods (ListVolumes, RemoveVolume, BackupVolume, RestoreVolume) reach
//! a node's agent through a VolumeRequest on its Connect stream and the
//! VolumeSession the agent opens for it (the router pairs them, once and
//! only for the node the request went to).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use armada_proto::armada::v1::restore_volume_message::Msg as RestoreMsg;
use armada_proto::armada::v1::server_message::Msg;
use armada_proto::armada::v1::volume_request::Op;
use armada_proto::armada::v1::*;
use armada_spec::Volume as SpecVolume;
use armada_spec::validate::{valid_app_id, valid_name};
use armada_store::{
    App, Kind, NODE_READY, Node, REPLICA_PENDING, REPLICA_PULLED, Replica, ReplicaFilter, Revision,
};
use tokio::sync::{mpsc, oneshot};
use tonic::{Code, Request, Response, Status, Streaming};

use crate::Server;
use crate::access::Access;
use crate::admin::Out;
use crate::events::{REPLICA, clean_message, event, timestamp};
use crate::grpc::{Auth, auth};
use crate::guard::Guard;
use crate::reconcile::{APP, Publishes, Run, app_event, publishes_port};
use crate::schedule::{eligible, pick_node, pick_victim, placement_allows, reservation};
use crate::store_err;

type Result<T> = std::result::Result<T, armada_store::Error>;

/// volumeChunk: the most archive data one message carries.
pub(crate) const VOLUME_CHUNK: usize = 64 << 10;
/// attachTimeout: how long an agent has to open the session.
const ATTACH_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a request waits for room in a session's queue (Go's offer).
const OFFER_TIMEOUT: Duration = Duration::from_secs(5);

type Check = Box<dyn Fn(&Access) -> std::result::Result<(), Status> + Send + Sync>;

/// An agent's session for a volume request, as the router hands it over.
struct Attached {
    first: VolumeData,
    inbound: Streaming<VolumeData>,
    out: mpsc::Sender<std::result::Result<VolumeData, Status>>,
}

struct Pending {
    node: String,
    tx: oneshot::Sender<Attached>,
}

/// volumeRouter: pairs volume requests with the agent streams that serve
/// them.
#[derive(Default)]
pub struct VolumeRouter {
    pending: Mutex<HashMap<String, Pending>>,
}

impl VolumeRouter {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pending>> {
        self.pending.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn register(&self, node: &str) -> (String, oneshot::Receiver<Attached>) {
        let id = crate::random_id(20);
        let (tx, rx) = oneshot::channel();
        self.lock().insert(
            id.clone(),
            Pending {
                node: node.to_string(),
                tx,
            },
        );
        (id, rx)
    }

    /// attach: claims a pending request for node with the agent's stream,
    /// once and only by the node it was sent to.
    fn attach(
        &self,
        id: &str,
        node: &str,
        first: VolumeData,
        inbound: Streaming<VolumeData>,
    ) -> Option<mpsc::Receiver<std::result::Result<VolumeData, Status>>> {
        let p = {
            let mut m = self.lock();
            match m.get(id) {
                Some(p) if p.node == node => {}
                _ => return None,
            }
            m.remove(id)?
        };
        let (out, rx) = mpsc::channel(16);
        // The requester may have given up meanwhile: the session then ends
        // at once.
        let _ = p.tx.send(Attached {
            first,
            inbound,
            out,
        });
        Some(rx)
    }

    fn cancel(&self, id: &str) {
        self.lock().remove(id);
    }
}

/// An open VolumeSession with an agent; dropping it ends the agent's
/// stream.
pub(crate) struct VolumeSession {
    pub first: VolumeData,
    inbound: Option<Streaming<VolumeData>>,
    out: mpsc::Sender<std::result::Result<VolumeData, Status>>,
}

impl VolumeSession {
    /// The agent's next message; None once its stream ended or failed.
    pub(crate) async fn recv(&mut self) -> Option<VolumeData> {
        match self.inbound.as_mut()?.message().await {
            Ok(Some(m)) => Some(m),
            _ => None,
        }
    }

    async fn send(&self, m: VolumeData) -> bool {
        self.out.send(Ok(m)).await.is_ok()
    }

    fn take_inbound(&mut self) -> Option<Streaming<VolumeData>> {
        self.inbound.take()
    }
}

/// checkVolumeArgs.
pub(crate) fn check_volume_args(app: &str, name: &str) -> std::result::Result<(), Status> {
    if !valid_app_id(app) || !valid_name(name) {
        return Err(Status::new(
            Code::InvalidArgument,
            "invalid app or volume name",
        ));
    }
    Ok(())
}

fn ts(t: &armada_spec::gotime::Time) -> Option<armada_proto::google::protobuf::Timestamp> {
    Some(timestamp(t))
}

/// The volumes a spec mounts on a node's disk, by name.
fn local_volumes(sp: &armada_spec::App, out: &mut HashMap<String, SpecVolume>) {
    for v in &sp.volumes {
        if v.local() {
            out.insert(v.name.clone(), v.clone());
        }
    }
}

impl Server {
    /// holdsAt: the agent of node is connected and keeps held replicas.
    fn holds_at(&self, node: &str) -> bool {
        self.session(node).is_some_and(|s| s.caps.holds)
    }

    /// volumeNode: the node the volumes of rev's app are bound to ("" if
    /// none is yet), and whether they are bound to different nodes.
    async fn volume_node(&self, app: &str, rev: &Revision) -> Result<(String, bool)> {
        let vols = self.store().list_volumes(app).await?;
        let mut node = String::new();
        let mut split = false;
        for v in vols {
            if !rev
                .spec()
                .volumes
                .iter()
                .any(|sv| sv.name == v.name && sv.local())
            {
                continue;
            }
            if !node.is_empty() && node != v.node {
                split = true;
            }
            if node.is_empty() {
                node = v.node;
            }
        }
        self.condition(
            &format!("volume-split:{app}"),
            split,
            app_event(
                APP,
                app,
                app,
                "VolumesSplit",
                "its volumes are bound to different nodes; restore them onto one node (armada volume restore --node)",
            ),
        )
        .await;
        Ok((node, split))
    }

    /// Records a new replica of target on node; false when a volume was
    /// bound elsewhere meanwhile (the next pass sees where).
    async fn create_volume_replica(
        &self,
        rc: &mut Run<'_>,
        app: &App,
        target: &Revision,
        node: &str,
        held: bool,
    ) -> Result<Option<Replica>> {
        let r = Replica {
            id: format!("{}-r{}-{}", app.name, target.seq, (self.0.new_id)(5)),
            app: app.name.clone(),
            revision: target.name.clone(),
            node_id: node.to_string(),
            state: REPLICA_PENDING.to_string(),
            held,
            ..Replica::default()
        };
        match self.store().create_replica(&r).await {
            Err(e) if e.kind == Kind::Precondition => {
                self.0.log.warn(
                    "volume bound elsewhere",
                    &[("app", app.name.clone()), ("err", e.to_string())],
                );
                return Ok(None);
            }
            Err(e) => return Err(e),
            Ok(()) => {}
        }
        let msg = if held {
            self.0.log.info(
                "pulling ahead",
                &[
                    ("replica", r.id.clone()),
                    ("revision", r.revision.clone()),
                    ("node", node.to_string()),
                ],
            );
            format!(
                "revision {} on {node}, held until its images are pulled and the old replica stops",
                r.revision
            )
        } else {
            self.0.log.info(
                "scheduled replica",
                &[
                    ("replica", r.id.clone()),
                    ("revision", r.revision.clone()),
                    ("node", node.to_string()),
                ],
            );
            format!("revision {} on {node}", r.revision)
        };
        let mut e = event(REPLICA, &r.id, node, "Scheduled", &msg);
        e.app = app.name.clone();
        self.record(e).await;
        rc.push(r.clone());
        Ok(Some(r))
    }

    /// reconcileVolumeApp: at most one replica, always on the node its
    /// volumes are bound to, and a new one only once every other replica
    /// of the app is gone, so two containers never write the same volume.
    pub(crate) async fn reconcile_volume_app(
        &self,
        rc: &mut Run<'_>,
        app: &mut App,
        target: &Revision,
        nodes: &[Node],
    ) -> Result<()> {
        let pubs = Publishes::of_all(target.name.clone(), publishes_port(target.spec()));
        let (pinned, split) = self.volume_node(&app.name, target).await?;

        let mine: Vec<Replica> = rc
            .view()
            .await
            .by_app
            .get(&app.name)
            .cloned()
            .unwrap_or_default();
        let mut current = Vec::new();
        let mut old = Vec::new();
        let mut others = 0;
        for r in mine {
            if r.draining() {
                self.finish_drain(rc, &r, false).await?;
                if rc.all.iter().any(|o| o.id == r.id) {
                    others += 1;
                }
            } else if r.revision == app.target_revision
                && (pinned.is_empty() || r.node_id == pinned)
            {
                current.push(r);
            } else {
                // The serving revision's replica during a rollout, or one
                // left on a node the volume is no longer bound to.
                old.push(r);
            }
        }

        if app.rolling() {
            let aborted = self.check_rollout(rc, app, target, &current, &pubs).await?;
            if aborted {
                // The serving revision is the target again; the next pass
                // replaces this revision's replica with one of it, and
                // keeps the replica that serves.
                for r in &current {
                    self.retire(rc, r).await?;
                }
                return Ok(());
            }
        }

        let pn = nodes.iter().find(|n| n.id == pinned).cloned();
        let known = pn.is_some();
        let pn = pn.unwrap_or_default();

        // Pull first: during a rollout the old replica keeps serving while
        // the volume's node pulls the new revision's images into a held
        // replica. A failed pull never stops the old one; the rollout
        // fails instead.
        let mut keep_old = false;
        if app.rolling()
            && app.replicas > 0
            && !pinned.is_empty()
            && !split
            && !old.is_empty()
            && !old.iter().any(|r| r.node_id != pinned)
            && self.holds_at(&pinned)
        {
            if current.is_empty()
                && known
                && !rc.lost.contains(&pinned)
                && pn.state == NODE_READY
                && placement_allows(&pn, target)
            {
                let res = rc.revs.reserved(&rc.all).await;
                if let Some(node) = pick_node(
                    std::slice::from_ref(&pn),
                    &rc.all,
                    &[],
                    "",
                    reservation(target),
                    &res,
                ) && let Some(r) = self
                    .create_volume_replica(rc, app, target, &node.id, true)
                    .await?
                {
                    current.push(r);
                    keep_old = true;
                }
            } else if !current.is_empty()
                && !current.iter().any(|r| !r.held || r.state == REPLICA_PULLED)
            {
                // Still pulling, or the pull failed: the rollout's deadline
                // decides.
                keep_old = true;
            }
        }
        for r in &old {
            if keep_old {
                others += 1;
                continue;
            }
            self.retire(rc, r).await?;
            if rc.all.iter().any(|o| o.id == r.id) {
                others += 1;
            }
        }
        if others == 0 {
            // Nothing else uses the volume: held replicas start.
            for r in current.iter_mut() {
                if !r.held {
                    continue;
                }
                self.store().release_replica(&r.id).await?;
                r.held = false;
                rc.replace(r);
            }
        }

        while current.len() as i64 > app.replicas {
            let victim = pick_victim(&current, &None);
            self.retire(rc, &victim).await?;
            current.retain(|r| r.id != victim.id);
        }

        let unavailable = !split && !pinned.is_empty() && (!known || rc.lost.contains(&pinned));
        let lost_msg = if target.spec().fails_over() {
            format!(
                "its volumes are on node {pinned}, which is unreachable or removed; their latest backups are being restored on another node (failover: restore)"
            )
        } else {
            format!(
                "its volumes are on node {pinned}, which is unreachable or removed; it stays down until the node returns or a volume backup is restored on another node (armada volume restore --node)"
            )
        };
        let mut e = app_event(APP, &app.name, &app.name, "VolumeUnavailable", &lost_msg);
        e.node = pinned.clone();
        self.condition(&format!("volume-lost:{}", app.name), unavailable, e)
            .await;
        if unavailable && target.spec().fails_over() {
            self.fail_over(rc, &app.name, &pinned, target, nodes).await;
        }
        let mut e = app_event(
            APP,
            &app.name,
            &app.name,
            "VolumeOnCordonedNode",
            &format!(
                "node {pinned} is cordoned, but the app keeps running there because its volumes are on it"
            ),
        );
        e.node = pinned.clone();
        self.condition(
            &format!("volume-cordoned:{}", app.name),
            known && pn.cordoned,
            e,
        )
        .await;

        let mut unplaced = false;
        if (current.len() as i64) < app.replicas && others == 0 && !unavailable && !split {
            let fit = if pinned.is_empty() {
                eligible(nodes, target)
            } else if pn.state == NODE_READY && placement_allows(&pn, target) {
                // A cordoned node keeps the app whose volumes it holds.
                vec![pn.clone()]
            } else {
                Vec::new()
            };
            let res = rc.revs.reserved(&rc.all).await;
            match pick_node(&fit, &rc.all, &current, "", reservation(target), &res) {
                None => unplaced = true,
                Some(node) => {
                    if let Some(r) = self
                        .create_volume_replica(rc, app, target, &node.id, false)
                        .await?
                    {
                        current.push(r);
                    }
                }
            }
        }
        let msg = if pinned.is_empty() {
            "no node can fit its replica; see armada node top".to_string()
        } else {
            format!(
                "its volumes are on node {pinned}, which cannot take the replica now (not ready, out of capacity, or not allowed by its placement)"
            )
        };
        self.condition(
            &format!("unplaced:{}", app.name),
            unplaced,
            app_event(APP, &app.name, &app.name, "Unschedulable", &msg),
        )
        .await;

        if app.rolling()
            && others == 0
            && current.len() as i64 == app.replicas
            && current.iter().all(|r| self.serving(rc, r, pubs.of(r)))
        {
            self.complete(rc, app).await?;
        }
        Ok(())
    }

    /// mountedVolumes: the local volumes app's serving and target revisions
    /// mount, by name (none when the app is gone).
    pub(crate) async fn mounted_volumes(&self, app: &str) -> Result<HashMap<String, SpecVolume>> {
        let a = match self.store().get_app(app).await {
            Err(e) if e.kind == Kind::NotFound => return Ok(HashMap::new()),
            Err(e) => return Err(e),
            Ok(a) => a,
        };
        let mut out = HashMap::new();
        for rn in [&a.active_revision, &a.target_revision] {
            if rn.is_empty() {
                continue;
            }
            let rev = self.store().get_revision(rn).await?;
            local_volumes(rev.spec(), &mut out);
        }
        Ok(out)
    }

    /// mountedVolumesOf: mountedVolumes for the apps of vols, read in one
    /// batch of apps and one of revisions.
    async fn mounted_volumes_of(
        &self,
        vols: &[armada_store::Volume],
    ) -> Result<HashMap<String, HashMap<String, SpecVolume>>> {
        let mut names: Vec<String> = Vec::new();
        for v in vols {
            if !names.contains(&v.app) {
                names.push(v.app.clone());
            }
        }
        if names.is_empty() {
            return Ok(HashMap::new());
        }
        let apps = self.store().get_apps(&names).await?;
        let targets: Vec<String> = apps
            .values()
            .filter(|a| !a.target_revision.is_empty() && a.target_revision != a.active_revision)
            .map(|a| a.target_revision.clone())
            .collect();
        let revs = if targets.is_empty() {
            HashMap::new()
        } else {
            self.store().get_revisions(&targets).await?
        };
        let mut out = HashMap::new();
        for (name, a) in apps {
            let mut m = HashMap::new();
            if let Some(sp) = &a.spec {
                local_volumes(sp, &mut m);
            }
            if !a.target_revision.is_empty() && a.target_revision != a.active_revision {
                let Some(rev) = revs.get(&a.target_revision) else {
                    return Err(armada_store::Error::wrap(
                        Kind::NotFound,
                        format!("revision {}", a.target_revision),
                    ));
                };
                local_volumes(rev.spec(), &mut m);
            }
            out.insert(name, m);
        }
        Ok(out)
    }

    /// ListVolumes: volumes, where they are, and how much they hold.
    pub(crate) async fn list_volumes(
        &self,
        a: &Auth,
        req: ListVolumesRequest,
    ) -> std::result::Result<ListVolumesResponse, Status> {
        if !req.app.is_empty() {
            a.acc.app(&req.app)?;
            if !valid_app_id(&req.app) {
                return Err(Status::new(Code::InvalidArgument, "invalid app name"));
            }
        }
        let mut vols = self
            .store()
            .list_volumes(&req.app)
            .await
            .map_err(|e| store_err(&e))?;
        vols.retain(|v| a.acc.sees(&v.app));
        let now = self.now();
        let mounted = self
            .mounted_volumes_of(&vols)
            .await
            .map_err(|e| store_err(&e))?;
        let mut resp = ListVolumesResponse::default();
        for v in vols {
            let mut out = Volume {
                app: v.app.clone(),
                name: v.name.clone(),
                node: v.node.clone(),
                created_at: ts(&v.created_at),
                used_bytes: -1,
                ..Default::default()
            };
            if let Some(sv) = mounted.get(&v.app).and_then(|m| m.get(&v.name)) {
                out.in_use = true;
                out.path = sv.path.clone();
                crate::backups::volume_backup_info(&mut out, sv.backup.as_ref(), &v.backup, &now);
            }
            if let Some(b) = self.0.usage.volume(&v.node, &v.app, &v.name, &now) {
                out.used_bytes = b;
            }
            resp.volumes.push(out);
        }
        Ok(resp)
    }

    /// RemoveVolume deletes a volume's data on its node, then its record.
    pub(crate) async fn remove_volume(
        &self,
        a: &Auth,
        req: RemoveVolumeRequest,
    ) -> std::result::Result<RemoveVolumeResponse, Status> {
        a.acc.app(&req.app)?;
        check_volume_args(&req.app, &req.name)?;
        let v = self
            .store()
            .get_volume(&req.app, &req.name)
            .await
            .map_err(|e| store_err(&e))?;
        let m = self
            .mounted_volumes(&v.app)
            .await
            .map_err(|e| store_err(&e))?;
        if m.contains_key(&v.name) {
            return Err(Status::new(
                Code::FailedPrecondition,
                format!(
                    "app {} still mounts volume {}; deploy it without the volume first",
                    v.app, v.name
                ),
            ));
        }
        let reps = self
            .store()
            .list_replicas(&ReplicaFilter {
                app: v.app.clone(),
                ..Default::default()
            })
            .await
            .map_err(|e| store_err(&e))?;
        for r in reps {
            let rev = self
                .store()
                .get_revision(&r.revision)
                .await
                .map_err(|e| store_err(&e))?;
            if rev.spec().volumes.iter().any(|sv| sv.name == v.name) {
                return Err(Status::new(
                    Code::FailedPrecondition,
                    format!(
                        "replica {} still uses volume {}; try again once it has stopped",
                        r.id, v.name
                    ),
                ));
            }
        }
        match self.store().get_node(&v.node).await {
            Ok(_) => {
                self.volume_op(
                    &v.node,
                    VolumeRequest {
                        op: Op::Remove as i32,
                        app: v.app.clone(),
                        volume: v.name.clone(),
                        stop: true,
                        ..Default::default()
                    },
                )
                .await?;
            }
            Err(e) if e.kind == Kind::NotFound => {}
            Err(e) => return Err(store_err(&e)),
        }
        self.store()
            .delete_volume(&v.app, &v.name, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "volume removed",
            &[
                ("app", v.app.clone()),
                ("volume", v.name.clone()),
                ("node", v.node.clone()),
                ("by", a.actor()),
            ],
        );
        let mut e = app_event(
            APP,
            &v.app,
            &v.app,
            "VolumeRemoved",
            &format!("volume {} removed", v.name),
        );
        e.node = v.node.clone();
        self.record(e).await;
        Ok(RemoveVolumeResponse {})
    }

    /// A stream's guard for a principal (Go's streamGuard), and its first
    /// check.
    fn stream_guard(
        &self,
        a: &Auth,
        method: &str,
        check: Check,
    ) -> std::result::Result<Option<std::sync::Arc<Guard>>, Status> {
        if a.acc.p.is_none() {
            check(&a.acc)?;
            return Ok(None);
        }
        let g = Guard::start(self, a.acc.clone(), a.cert.clone(), method);
        if let Err(e) = g.require(check) {
            g.stop();
            return Err(e);
        }
        Ok(Some(g))
    }

    /// BackupVolume streams a gzipped tar of a volume from its node.
    pub(crate) async fn backup_volume(
        &self,
        a: &Auth,
        req: BackupVolumeRequest,
    ) -> std::result::Result<Response<Out<VolumeData>>, Status> {
        let app = req.app.clone();
        let guard = self.stream_guard(
            a,
            "/armada.v1.AdminService/BackupVolume",
            Box::new(move |acc| acc.app(&app)),
        )?;
        let stop = |e: Status| {
            if let Some(g) = &guard {
                g.stop();
            }
            e
        };
        check_volume_args(&req.app, &req.name).map_err(stop)?;
        let v = self
            .store()
            .get_volume(&req.app, &req.name)
            .await
            .map_err(|e| stop(store_err(&e)))?;
        self.store()
            .record_audit(
                &a.actor(),
                "volume.backup",
                &v.app,
                &format!("volume={} node={} stop={}", v.name, v.node, req.stop),
            )
            .await
            .map_err(|e| stop(store_err(&e)))?;
        self.0.log.info(
            "volume backup",
            &[
                ("app", v.app.clone()),
                ("volume", v.name.clone()),
                ("node", v.node.clone()),
                ("stop", req.stop.to_string()),
                ("by", a.actor()),
            ],
        );
        let mut sess = self
            .open_volume_session(
                &v.node,
                VolumeRequest {
                    op: Op::Backup as i32,
                    app: v.app.clone(),
                    volume: v.name.clone(),
                    stop: req.stop,
                    ..Default::default()
                },
            )
            .await
            .map_err(stop)?;
        let (tx, rx) = mpsc::channel(16);
        let srv = self.clone();
        tokio::spawn(async move {
            let cancelled = async {
                match &guard {
                    Some(g) => g.cancelled().await,
                    None => std::future::pending().await,
                }
            };
            tokio::pin!(cancelled);
            loop {
                let m = tokio::select! {
                    m = sess.recv() => m,
                    _ = &mut cancelled => {
                        if let Some(err) = guard.as_ref().and_then(|g| g.ended()) {
                            let _ = tx.send(Err(err)).await;
                        }
                        break;
                    }
                    _ = tx.closed() => break,
                };
                let Some(m) = m else {
                    let _ = tx
                        .send(Err(Status::new(
                            Code::Unavailable,
                            "the node ended the backup",
                        )))
                        .await;
                    break;
                };
                if !m.error.is_empty() {
                    let _ = tx
                        .send(Err(Status::new(
                            Code::FailedPrecondition,
                            clean_message(&m.error),
                        )))
                        .await;
                    break;
                }
                if m.data.len() > VOLUME_CHUNK {
                    let _ = tx
                        .send(Err(Status::new(
                            Code::DataLoss,
                            "the node sent an oversized chunk",
                        )))
                        .await;
                    break;
                }
                let done = m.done;
                let out = VolumeData {
                    data: m.data,
                    done,
                    ..Default::default()
                };
                if tx.send(Ok(out)).await.is_err() {
                    break;
                }
                if done {
                    let mut e = app_event(
                        APP,
                        &v.app,
                        &v.app,
                        "VolumeBackedUp",
                        &format!("volume {}", v.name),
                    );
                    e.node = v.node.clone();
                    srv.record(e).await;
                    break;
                }
            }
            if let Some(g) = &guard {
                g.stop();
            }
            drop(sess);
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }

    /// RestoreVolume replaces a volume's contents with a gzipped tar from
    /// the admin, on its node or, with start.node, on another node it is
    /// then bound to.
    pub(crate) async fn restore_volume(
        &self,
        request: Request<Streaming<RestoreVolumeMessage>>,
    ) -> std::result::Result<RestoreVolumeResponse, Status> {
        let a = auth(&request)?;
        let mut stream = request.into_inner();
        let Some(first) = stream.message().await? else {
            return Err(Status::new(Code::Unknown, "EOF"));
        };
        let Some(RestoreMsg::Start(start)) = first.msg else {
            return Err(Status::new(
                Code::InvalidArgument,
                "the first message must be start",
            ));
        };
        let app_id = start.app.clone();
        let guard = self.stream_guard(
            &a,
            "/armada.v1.AdminService/RestoreVolume",
            Box::new(move |acc| acc.app(&app_id)),
        )?;
        let res = self
            .restore_volume_with(&a, start, &mut stream, guard.clone())
            .await;
        if let Some(g) = &guard {
            g.stop();
        }
        res
    }

    async fn restore_volume_with(
        &self,
        a: &Auth,
        start: RestoreVolumeStart,
        stream: &mut Streaming<RestoreVolumeMessage>,
        guard: Option<std::sync::Arc<Guard>>,
    ) -> std::result::Result<RestoreVolumeResponse, Status> {
        if !start.node.is_empty() && !a.acc.admin() {
            return Err(Status::new(
                Code::PermissionDenied,
                "restoring a volume onto another node needs cluster-admin",
            ));
        }
        check_volume_args(&start.app, &start.name)?;
        let (app, name) = (start.app.clone(), start.name.clone());
        let (bound, vnode) = match self.store().get_volume(&app, &name).await {
            Ok(v) => (true, v.node),
            Err(e) if e.kind == Kind::NotFound => (false, String::new()),
            Err(e) => return Err(store_err(&e)),
        };
        let mut node = vnode.clone();
        if !start.node.is_empty() && start.node != node {
            node = start.node.clone();
            self.store()
                .get_node(&node)
                .await
                .map_err(|e| store_err(&e))?;
            // Never leave two copies that could both be written.
            if bound && self.session(&vnode).is_some() {
                return Err(Status::new(
                    Code::FailedPrecondition,
                    format!(
                        "node {vnode}, which holds the volume, is connected; restore without --node"
                    ),
                ));
            }
        }
        if !bound && start.node.is_empty() {
            return Err(Status::new(
                Code::NotFound,
                format!(
                    "volume {name} of app {app} not found; name a node with --node to restore it there"
                ),
            ));
        }
        if !bound {
            let m = self
                .mounted_volumes(&app)
                .await
                .map_err(|e| store_err(&e))?;
            if !m.contains_key(&name) {
                return Err(Status::new(
                    Code::NotFound,
                    format!("app {app} has no volume {name}"),
                ));
            }
        }
        self.store()
            .record_audit(
                &a.actor(),
                "volume.restore",
                &app,
                &format!("volume={name} node={node}"),
            )
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "volume restore",
            &[
                ("app", app.clone()),
                ("volume", name.clone()),
                ("node", node.clone()),
                ("by", a.actor()),
            ],
        );
        let mut sess = self
            .open_volume_session(
                &node,
                VolumeRequest {
                    op: Op::Restore as i32,
                    app: app.clone(),
                    volume: name.clone(),
                    stop: true,
                    ..Default::default()
                },
            )
            .await?;
        let (rtx, mut result) = oneshot::channel::<std::result::Result<(), Status>>();
        let mut inbound = sess.take_inbound();
        tokio::spawn(async move {
            let res = loop {
                let m = match inbound.as_mut() {
                    Some(s) => s.message().await,
                    None => Ok(None),
                };
                match m {
                    Ok(Some(m)) if !m.error.is_empty() => {
                        break Err(Status::new(
                            Code::FailedPrecondition,
                            clean_message(&m.error),
                        ));
                    }
                    Ok(Some(m)) if m.done => break Ok(()),
                    Ok(Some(_)) => continue,
                    _ => {
                        break Err(Status::new(Code::Unavailable, "the node ended the restore"));
                    }
                }
            };
            let _ = rtx.send(res);
        });
        let ended = || Status::new(Code::Unavailable, "the node ended the restore");
        let cancelled = async {
            match &guard {
                Some(g) => g.cancelled().await,
                None => std::future::pending().await,
            }
        };
        tokio::pin!(cancelled);
        loop {
            let m = tokio::select! {
                m = stream.message() => m,
                _ = &mut cancelled => {
                    return Err(guard.as_ref().and_then(|g| g.ended()).unwrap_or_else(|| Status::new(Code::Cancelled, "context canceled")));
                }
            };
            let m = match m {
                Ok(None) => {
                    if !sess
                        .send(VolumeData {
                            done: true,
                            ..Default::default()
                        })
                        .await
                    {
                        return Err(ended());
                    }
                    break;
                }
                Err(e) => return Err(e),
                Ok(Some(m)) => m,
            };
            let data = match m.msg {
                Some(RestoreMsg::Data(d)) if d.len() <= VOLUME_CHUNK => d,
                None => Vec::new(),
                _ => {
                    return Err(Status::new(
                        Code::InvalidArgument,
                        "expected archive data of at most 64 KiB per message",
                    ));
                }
            };
            if !sess
                .send(VolumeData {
                    data,
                    ..Default::default()
                })
                .await
            {
                if let Ok(Err(e)) = result.try_recv() {
                    return Err(e);
                }
                return Err(ended());
            }
            match result.try_recv() {
                Ok(Ok(())) => {
                    return Err(Status::new(
                        Code::Internal,
                        "the node finished before the archive ended",
                    ));
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {}
            }
        }
        tokio::select! {
            r = &mut result => {
                if let Ok(Err(e)) = r {
                    return Err(e);
                }
            }
            _ = &mut cancelled => {
                return Err(guard.as_ref().and_then(|g| g.ended()).unwrap_or_else(|| Status::new(Code::Cancelled, "context canceled")));
            }
        }
        drop(sess);
        if !bound || vnode != node {
            self.store()
                .bind_volume(&app, &name, &node, &a.actor())
                .await
                .map_err(|e| store_err(&e))?;
            self.trigger();
        }
        let mut e = app_event(
            APP,
            &app,
            &app,
            "VolumeRestored",
            &format!("volume {name} on {node}"),
        );
        e.node = node.clone();
        self.record(e).await;
        Ok(RestoreVolumeResponse { node })
    }

    /// openVolumeSession: asks node's agent to serve req and waits for its
    /// session. An error in the agent's first message is returned.
    pub(crate) async fn open_volume_session(
        &self,
        node: &str,
        mut req: VolumeRequest,
    ) -> std::result::Result<VolumeSession, Status> {
        let Some(sess) = self.session(node) else {
            return Err(Status::new(
                Code::Unavailable,
                format!("node {node} is not connected"),
            ));
        };
        let (id, rx) = self.0.volumes.register(node);
        req.request_id = id.clone();
        let msg = ServerMessage {
            msg: Some(Msg::VolumeRequest(req)),
        };
        if !sess.offer(msg, OFFER_TIMEOUT).await {
            self.0.volumes.cancel(&id);
            return Err(Status::new(
                Code::Unavailable,
                format!("node {node} did not accept the volume request"),
            ));
        }
        let att = match tokio::time::timeout(ATTACH_TIMEOUT, rx).await {
            Ok(Ok(att)) => att,
            _ => {
                self.0.volumes.cancel(&id);
                return Err(Status::new(
                    Code::Unavailable,
                    format!("node {node} did not start the volume session"),
                ));
            }
        };
        if !att.first.error.is_empty() {
            return Err(Status::new(
                Code::FailedPrecondition,
                att.first.error.clone(),
            ));
        }
        Ok(VolumeSession {
            first: att.first,
            inbound: Some(att.inbound),
            out: att.out,
        })
    }

    /// volumeOp: a request whose answer is the agent's first message.
    async fn volume_op(
        &self,
        node: &str,
        req: VolumeRequest,
    ) -> std::result::Result<VolumeData, Status> {
        let sess = self.open_volume_session(node, req).await?;
        if !sess.first.done {
            return Err(Status::new(
                Code::Internal,
                "the node did not finish the volume request",
            ));
        }
        Ok(sess.first.clone())
    }

    /// VolumeSession: the session stream for a pending volume request,
    /// from the agent it was sent to, held until the requester is done.
    pub(crate) async fn volume_session(
        &self,
        request: Request<Streaming<VolumeData>>,
    ) -> std::result::Result<Response<Out<VolumeData>>, Status> {
        let a = auth(&request)?;
        let mut inbound = request.into_inner();
        let Some(first) = inbound.message().await? else {
            return Err(Status::new(Code::Unknown, "EOF"));
        };
        let id = first.request_id.clone();
        let Some(rx) = self.0.volumes.attach(&id, &a.id.name, first, inbound) else {
            return Err(Status::new(
                Code::PermissionDenied,
                "unknown volume request",
            ));
        };
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
}

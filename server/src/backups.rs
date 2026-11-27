//! Scheduled volume backups (ADR 0041): the backup loop starts the backups
//! that are due, at most one per volume and one scheduled per node, on the
//! volume's node through a volume session carrying the bucket and key from
//! the revision's pinned secrets; outcomes are kept on the volume's record,
//! with the VolumeBackupFailed and VolumeBackupUnsupported conditions. The
//! methods ListVolumeSnapshots, CreateVolumeSnapshot, and
//! RestoreVolumeSnapshot run there too, or, for a listing or a restore
//! elsewhere while the volume's node is away, on a node that may hold the
//! app's secrets. The bucket checks of deploys, rollbacks, and secret
//! changes keep a bucket on a private address to cluster-admins.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use armada_node::volbackup::target as volbackup;
use armada_proto::armada::v1::volume_request::Op;
use armada_proto::armada::v1::*;
use armada_secrets::Value;
use armada_spec::gotime::Time;
use armada_spec::validate::secret_source;
use armada_spec::{App as Spec, MIN_BACKUP_KEY_LEN, VolumeBackup};
use armada_store::{Kind, NODE_READY, Node, Revision, VolumeBackupState};
use tokio::sync::watch;
use tonic::{Code, Status};

use crate::Server;
use crate::access::Access;
use crate::assign::Revisions;
use crate::events::{clean_message, timestamp};
use crate::grpc::Auth;
use crate::reconcile::{APP, app_event};
use crate::schedule::placement_allows;
use crate::store_err;
use crate::volumes::check_volume_args;

pub(crate) const DEFAULT_BACKUP_INTERVAL: Duration = Duration::from_secs(30);
/// The longest wait after a failed backup.
pub(crate) const BACKUP_RETRY: i64 = 5 * 60 * 1_000_000_000;
/// Bounds one backup or restore.
pub(crate) const BACKUP_TIMEOUT: Duration = Duration::from_secs(6 * 3600);

/// The backups in flight, one per volume, one scheduled per
/// node.
#[derive(Default)]
pub struct BackupRuns {
    st: Mutex<(HashSet<String>, HashSet<String>)>,
}

impl BackupRuns {
    /// start claims the volume and, for scheduled backups, its node; false
    /// if either is busy.
    pub(crate) fn start(&self, volume: &str, node: &str, scheduled: bool) -> bool {
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        if st.0.contains(volume) || (scheduled && st.1.contains(node)) {
            return false;
        }
        st.0.insert(volume.to_string());
        if scheduled {
            st.1.insert(node.to_string());
        }
        true
    }

    pub(crate) fn done(&self, volume: &str, node: &str, scheduled: bool) {
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        st.0.remove(volume);
        if scheduled {
            st.1.remove(node);
        }
    }
}

/// Releases a claim of BackupRuns when dropped.
struct Claim<'a> {
    runs: &'a BackupRuns,
    volume: String,
    node: String,
    scheduled: bool,
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        self.runs.done(&self.volume, &self.node, self.scheduled);
    }
}

/// When a volume's next backup is due, on the schedule after
/// the last success, and after a failure no later than backupRetry.
pub(crate) fn backup_due(b: &VolumeBackup, st: &VolumeBackupState) -> Time {
    let mut due = b.next(&st.last_at);
    if st.failed_at.after(&st.last_at) {
        let mut retry = st.failed_at.add(BACKUP_RETRY);
        if b.every.0 != 0 && b.every.0 < BACKUP_RETRY {
            retry = st.failed_at.add(b.every.0);
        }
        if retry.after(&due) {
            due = retry;
        }
    }
    due
}

/// Fills a listed volume's backup fields.
pub(crate) fn volume_backup_info(
    out: &mut Volume,
    b: Option<&VolumeBackup>,
    st: &VolumeBackupState,
    now: &Time,
) {
    let Some(b) = b else { return };
    out.backup = true;
    if !st.last_at.is_zero() {
        out.last_backup_at = Some(timestamp(&st.last_at));
    }
    if st.failed_at.after(&st.last_at) {
        out.backup_failed_at = Some(timestamp(&st.failed_at));
        out.backup_error = st.error.clone();
    }
    out.backup_stored_bytes = st.stored;
    out.backup_snapshots = st.snapshots.min(1 << 30) as i32;
    let mut next = backup_due(b, st);
    if next.before(now) {
        next = now.clone(); // due
    }
    out.next_backup_at = Some(timestamp(&next));
}

/// n is ready and the placement of every revision in revs
/// allows it, so n may be sent the secrets they pin.
pub(crate) fn may_hold_secrets(n: &Node, revs: &[Revision]) -> bool {
    n.state == NODE_READY && !revs.is_empty() && revs.iter().all(|r| placement_allows(n, r))
}

/// Target.PrivateIP: the bucket's host when it is a private IP address.
fn private_ip(t: &volbackup::Target) -> Option<IpAddr> {
    let e = &t.endpoint;
    let trimmed = e.strip_prefix('[').unwrap_or(e);
    let mut host = trimmed.strip_suffix(']').unwrap_or(trimmed).to_string();
    if let Some((h, _)) = split_host_port(&t.endpoint) {
        host = h;
    }
    let ip = volbackup::parse_addr(host.as_bytes())?;
    volbackup::is_private(ip).then(|| volbackup::unmap(ip))
}

/// The host and port of what ParseTarget writes as an endpoint.
fn split_host_port(s: &str) -> Option<(String, String)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        return Some((h.to_string(), p.to_string()));
    }
    let (h, p) = s.rsplit_once(':')?;
    if h.contains(':') {
        return None;
    }
    Some((h.to_string(), p.to_string()))
}

fn has_backups(sp: &Spec) -> bool {
    sp.volumes.iter().any(|v| v.backup.is_some())
}

/// A failure of a backup step that is not a gRPC status: Unknown here,
/// and CreateVolumeSnapshot answers it as
/// FailedPrecondition.
fn plain(msg: impl Into<String>) -> Status {
    Status::new(Code::Unknown, msg.into())
}

impl Server {
    pub(crate) async fn backup_loop(&self, mut shutdown: watch::Receiver<bool>) {
        let every = self.0.backup_interval;
        loop {
            tokio::select! {
                _ = crate::stopped(&mut shutdown) => return,
                _ = tokio::time::sleep(every) => {}
            }
            if let Err(e) = self.schedule_backups(Some(shutdown.clone())).await
                && !*shutdown.borrow()
            {
                self.0
                    .log
                    .error("volume backups", &[("err", e.to_string())]);
            }
        }
    }

    /// The backup settings of a volume from the revision
    /// the app serves (or rolls out, before it serves any), with it.
    async fn volume_backup_spec(
        &self,
        app: &str,
        name: &str,
    ) -> Result<(Option<VolumeBackup>, Option<Revision>), armada_store::Error> {
        let a = self.store().get_app(app).await?;
        let rn = if a.active_revision.is_empty() {
            &a.target_revision
        } else {
            &a.active_revision
        };
        if rn.is_empty() {
            return Ok((None, None));
        }
        let rev = self.store().get_revision(rn).await?;
        let b = rev
            .spec()
            .volumes
            .iter()
            .find(|v| v.name == name && v.backup.is_some())
            .and_then(|v| v.backup.clone());
        Ok((b, Some(rev)))
    }

    /// Starts the backups that are due; each runs on its
    /// own (until shutdown, when given), and the handles say when they end.
    pub async fn schedule_backups(
        &self,
        shutdown: Option<watch::Receiver<bool>>,
    ) -> Result<Vec<tokio::task::JoinHandle<()>>, armada_store::Error> {
        let vols = self.store().list_volumes("").await?;
        let now = self.now();
        let mut started = Vec::new();
        for v in vols {
            let (b, rev) = match self.volume_backup_spec(&v.app, &v.name).await {
                Err(e) if e.kind == Kind::NotFound => continue, // the app is gone
                Err(e) => return Err(e),
                Ok((None, _)) | Ok((_, None)) => continue, // no backups
                Ok((Some(b), Some(rev))) => (b, rev),
            };
            if backup_due(&b, &v.backup).after(&now) {
                continue;
            }
            if self
                .0
                .usage
                .volume(&v.node, &v.app, &v.name, &now)
                .is_none()
            {
                continue; // its node has not reported the volume's directory yet
            }
            let sess = self.session(&v.node);
            let mut e = app_event(
                APP,
                &v.app,
                &v.app,
                "VolumeBackupUnsupported",
                &format!(
                    "volume {} is not backed up: the agent on node {} is too old; upgrade it",
                    v.name, v.node
                ),
            );
            e.node = v.node.clone();
            let unsupported = sess.as_ref().is_some_and(|s| !s.caps.backups);
            self.condition(
                &format!("backup-agent:{}/{}", v.app, v.name),
                unsupported,
                e,
            )
            .await;
            if sess.is_none_or(|s| !s.caps.backups) {
                continue;
            }
            let key = format!("{}/{}", v.app, v.name);
            if !self.0.backups.start(&key, &v.node, true) {
                continue;
            }
            // A backup may have finished since the list was read.
            match self.store().get_volume(&v.app, &v.name).await {
                Ok(cur) if !backup_due(&b, &cur.backup).after(&self.now()) => {}
                _ => {
                    self.0.backups.done(&key, &v.node, true);
                    continue;
                }
            }
            let s = self.clone();
            let mut sd = shutdown.clone();
            started.push(tokio::spawn(async move {
                let _claim = Claim {
                    runs: &s.0.backups,
                    volume: key,
                    node: v.node.clone(),
                    scheduled: true,
                };
                let run = s.run_snapshot(&v, &b, &rev);
                match sd.as_mut() {
                    Some(sd) => {
                        tokio::select! {
                            _ = run => {}
                            _ = crate::stopped(sd) => {}
                        }
                    }
                    None => {
                        let _ = run.await;
                    }
                }
            }));
        }
        Ok(started)
    }

    /// The request's bucket and key from the revision's
    /// pinned secrets.
    pub(crate) async fn backup_target(
        &self,
        b: Option<&VolumeBackup>,
        rev: &Revision,
    ) -> Result<BackupTarget, String> {
        let Some(b) = b else {
            return Err("the volume has no backup (volumes[].backup)".to_string());
        };
        let mut revs = Revisions::new(self);
        let vals = revs.secrets(rev).await.map_err(|e| e.to_string())?;
        let (Some(url), Some(key)) = (vals.get(&b.url_secret_ref), vals.get(&b.key_secret_ref))
        else {
            return Err("the backup's secrets are not set".to_string());
        };
        let url = String::from_utf8_lossy(url.bytes()).into_owned();
        volbackup::parse(&url)?;
        if key.bytes().len() < MIN_BACKUP_KEY_LEN {
            return Err(format!(
                "secret {} must hold at least {MIN_BACKUP_KEY_LEN} bytes to encrypt backups",
                b.key_secret_ref
            ));
        }
        let k = b.keep;
        Ok(BackupTarget {
            url,
            key: key.bytes().to_vec(),
            time_zone: b.time_zone.clone(),
            keep: Some(BackupKeep {
                last: k.last as i32,
                hourly: k.hourly as i32,
                daily: k.daily as i32,
                weekly: k.weekly as i32,
                monthly: k.monthly as i32,
            }),
        })
    }

    /// Backs a volume up on its node and records how it went.
    async fn run_snapshot(
        &self,
        v: &armada_store::Volume,
        b: &VolumeBackup,
        rev: &Revision,
    ) -> Result<Option<CreateVolumeSnapshotResponse>, Status> {
        let run = async {
            let target = self
                .backup_target(Some(b), rev)
                .await
                .map_err(|e| (None, plain(e)))?;
            let (m, err) = self
                .repo_op(
                    &v.node,
                    VolumeRequest {
                        op: Op::Snapshot as i32,
                        app: v.app.clone(),
                        volume: v.name.clone(),
                        stop: b.stop,
                        backup: Some(target),
                        ..Default::default()
                    },
                )
                .await;
            let res = m.and_then(|m| m.snapshot);
            match err {
                Some(e) => Err((res, e)),
                None => Ok(res),
            }
        };
        let out = match tokio::time::timeout(BACKUP_TIMEOUT, run).await {
            Ok(Ok(res)) => Ok(res),
            Ok(Err((res, e))) => Err((res, e)),
            Err(_) => Err((None, plain("context deadline exceeded"))),
        };
        let (res, err) = match &out {
            Ok(res) => (res.clone(), None),
            Err((res, e)) => (res.clone(), Some(e.clone())),
        };
        let (mut id, mut stored, mut snaps) = (String::new(), 0, 0);
        if let Some(r) = &res
            && let Some(s) = &r.snapshot
        {
            id = s.id.clone();
            stored = r.stored_bytes;
            snaps = i64::from(r.snapshots);
        }
        let msg = err
            .as_ref()
            .map(|e| e.message().to_string())
            .unwrap_or_default();
        if let Err(e) = self
            .store()
            .record_volume_backup(&v.app, &v.name, &id, stored, snaps, &msg)
            .await
        {
            self.0.log.warn(
                "record volume backup",
                &[
                    ("app", v.app.clone()),
                    ("volume", v.name.clone()),
                    ("err", e.to_string()),
                ],
            );
        }
        let mut e = app_event(
            APP,
            &v.app,
            &v.app,
            "VolumeBackupFailed",
            &format!("volume {}: {msg}", v.name),
        );
        e.node = v.node.clone();
        self.condition(
            &format!("backup-failed:{}/{}", v.app, v.name),
            err.is_some(),
            e,
        )
        .await;
        match &err {
            Some(_) => self.0.log.warn(
                "volume backup failed",
                &[
                    ("app", v.app.clone()),
                    ("volume", v.name.clone()),
                    ("node", v.node.clone()),
                    ("err", msg.clone()),
                ],
            ),
            None => self.0.log.info(
                "volume backed up",
                &[
                    ("app", v.app.clone()),
                    ("volume", v.name.clone()),
                    ("backup", id.clone()),
                    (
                        "new_bytes",
                        res.as_ref().map_or(0, |r| r.new_bytes).to_string(),
                    ),
                ],
            ),
        }
        match err {
            Some(e) => Err(e),
            None => Ok(res),
        }
    }

    /// A bucket operation on node; the agent's answer is its last
    /// message, which may carry a result and an error together.
    pub(crate) async fn repo_op(
        &self,
        node: &str,
        req: VolumeRequest,
    ) -> (Option<VolumeData>, Option<Status>) {
        let mut sess = match self.open_volume_session(node, req).await {
            Ok(s) => s,
            Err(e) => return (None, Some(e)),
        };
        loop {
            let Some(m) = sess.recv().await else {
                return (
                    None,
                    Some(Status::new(
                        Code::Unavailable,
                        format!("node {node} ended the volume operation"),
                    )),
                );
            };
            if !m.error.is_empty() {
                let e = Status::new(Code::FailedPrecondition, clean_message(&m.error));
                return (Some(m), Some(e));
            }
            if m.done {
                return (Some(m), None);
            }
        }
    }

    /// Where a bucket operation runs: the volume's node, or,
    /// when it is not connected and the operation needs no data, a
    /// connected node that backs volumes up and may hold the app's
    /// secrets.
    async fn repo_node(
        &self,
        v: &armada_store::Volume,
        needs_data: bool,
        revs: &[Revision],
    ) -> Result<String, Status> {
        if let Some(sess) = self.session(&v.node) {
            if !sess.caps.backups {
                return Err(Status::new(
                    Code::FailedPrecondition,
                    format!(
                        "the agent on node {} is too old to back volumes up; upgrade it",
                        v.node
                    ),
                ));
            }
            return Ok(v.node.clone());
        }
        if needs_data {
            return Err(Status::new(
                Code::Unavailable,
                format!("node {}, which holds the volume, is not connected", v.node),
            ));
        }
        let nodes = self.store().list_nodes().await.map_err(|e| store_err(&e))?;
        let mut best = String::new();
        for n in nodes {
            if (!best.is_empty() && n.id >= best) || !may_hold_secrets(&n, revs) {
                continue;
            }
            if self.session(&n.id).is_some_and(|s| s.caps.backups) {
                best = n.id.clone();
            }
        }
        if best.is_empty() {
            return Err(Status::new(
                Code::Unavailable,
                format!(
                    "node {}, which holds the volume, is not connected, and no other connected node that backs volumes up may run {}",
                    v.node, v.app
                ),
            ));
        }
        Ok(best)
    }

    /// heading: rev and, while the app rolls out to another revision, that
    /// one too.
    async fn heading(&self, app: &str, rev: &Revision) -> Result<Vec<Revision>, Status> {
        let a = self.store().get_app(app).await.map_err(|e| store_err(&e))?;
        let mut out = vec![rev.clone()];
        if !a.target_revision.is_empty() && a.target_revision != rev.name {
            out.push(
                self.store()
                    .get_revision(&a.target_revision)
                    .await
                    .map_err(|e| store_err(&e))?,
            );
        }
        Ok(out)
    }

    /// The volume and its backup settings for a method.
    async fn backup_for(
        &self,
        app: &str,
        name: &str,
    ) -> Result<(armada_store::Volume, VolumeBackup, Revision), Status> {
        check_volume_args(app, name)?;
        let v = self
            .store()
            .get_volume(app, name)
            .await
            .map_err(|e| store_err(&e))?;
        let (b, rev) = self
            .volume_backup_spec(app, name)
            .await
            .map_err(|e| store_err(&e))?;
        match (b, rev) {
            (Some(b), Some(rev)) => Ok((v, b, rev)),
            _ => Err(Status::new(
                Code::FailedPrecondition,
                format!("the spec of {app} has no backup for volume {name} (volumes[].backup)"),
            )),
        }
    }

    /// ListVolumeSnapshots: the backups in a volume's bucket.
    pub(crate) async fn list_volume_snapshots(
        &self,
        a: &Auth,
        req: ListVolumeSnapshotsRequest,
    ) -> Result<ListVolumeSnapshotsResponse, Status> {
        a.acc.app(&req.app)?;
        let (v, b, rev) = self.backup_for(&req.app, &req.name).await?;
        let revs = self.heading(&v.app, &rev).await?;
        let node = self.repo_node(&v, false, &revs).await?;
        let target = self
            .backup_target(Some(&b), &rev)
            .await
            .map_err(|e| Status::new(Code::FailedPrecondition, e))?;
        let (m, err) = self
            .repo_op(
                &node,
                VolumeRequest {
                    op: Op::Snapshots as i32,
                    app: v.app.clone(),
                    volume: v.name.clone(),
                    backup: Some(target),
                    ..Default::default()
                },
            )
            .await;
        if let Some(e) = err {
            return Err(e);
        }
        Ok(ListVolumeSnapshotsResponse {
            snapshots: m.map(|m| m.snapshots).unwrap_or_default(),
        })
    }

    /// CreateVolumeSnapshot backs a volume up now.
    pub(crate) async fn create_volume_snapshot(
        &self,
        a: &Auth,
        req: CreateVolumeSnapshotRequest,
    ) -> Result<CreateVolumeSnapshotResponse, Status> {
        a.acc.app(&req.app)?;
        let (v, b, rev) = self.backup_for(&req.app, &req.name).await?;
        self.repo_node(&v, true, &[]).await?;
        let key = format!("{}/{}", v.app, v.name);
        if !self.0.backups.start(&key, &v.node, false) {
            return Err(Status::new(
                Code::Aborted,
                format!(
                    "a backup of volume {} of {} is already running",
                    v.name, v.app
                ),
            ));
        }
        let _claim = Claim {
            runs: &self.0.backups,
            volume: key,
            node: v.node.clone(),
            scheduled: false,
        };
        self.store()
            .record_audit(
                &a.actor(),
                "volume.snapshot",
                &v.app,
                &format!("volume={}", v.name),
            )
            .await
            .map_err(|e| store_err(&e))?;
        match self.run_snapshot(&v, &b, &rev).await {
            Err(e) if e.code() == Code::Unknown => {
                Err(Status::new(Code::FailedPrecondition, e.message()))
            }
            Err(e) => Err(e),
            Ok(res) => Ok(res.unwrap_or_default()),
        }
    }

    /// RestoreVolumeSnapshot replaces a volume's contents with a backup
    /// from its bucket, on its node or, while that node is not connected,
    /// on another.
    pub(crate) async fn restore_volume_snapshot(
        &self,
        a: &Auth,
        req: RestoreVolumeSnapshotRequest,
    ) -> Result<RestoreVolumeResponse, Status> {
        a.acc.app(&req.app)?;
        if !req.node.is_empty() && !a.acc.admin() {
            return Err(Status::new(
                Code::PermissionDenied,
                "restoring a volume onto another node needs cluster-admin",
            ));
        }
        if req.snapshot.is_empty() || req.snapshot.len() > 64 {
            return Err(Status::new(
                Code::InvalidArgument,
                "name a backup, or latest",
            ));
        }
        let (v, b, rev) = self.backup_for(&req.app, &req.name).await?;
        let mut node = v.node.clone();
        if !req.node.is_empty() && req.node != node {
            node = req.node.clone();
            let n = self
                .store()
                .get_node(&node)
                .await
                .map_err(|e| store_err(&e))?;
            // The request carries the app's bucket credentials and key.
            let revs = self.heading(&v.app, &rev).await?;
            if !may_hold_secrets(&n, &revs) {
                return Err(Status::new(
                    Code::FailedPrecondition,
                    format!(
                        "node {node} is not ready, or the app may not run there (placement, restricted node, or capabilities)"
                    ),
                ));
            }
            // Never leave two copies that could both be written.
            if self.session(&v.node).is_some() {
                return Err(Status::new(
                    Code::FailedPrecondition,
                    format!(
                        "node {}, which holds the volume, is connected; restore without --node",
                        v.node
                    ),
                ));
            }
        }
        if self.session(&node).is_none_or(|s| !s.caps.backups) {
            return Err(Status::new(
                Code::Unavailable,
                format!("node {node} is not connected, or its agent is too old to restore backups"),
            ));
        }
        let target = self
            .backup_target(Some(&b), &rev)
            .await
            .map_err(|e| Status::new(Code::FailedPrecondition, e))?;
        let key = format!("{}/{}", v.app, v.name);
        if !self.0.backups.start(&key, &node, false) {
            return Err(Status::new(
                Code::Aborted,
                format!(
                    "a backup of volume {} of {} is running; try again when it is done",
                    v.name, v.app
                ),
            ));
        }
        let _claim = Claim {
            runs: &self.0.backups,
            volume: key,
            node: node.clone(),
            scheduled: false,
        };
        self.store()
            .record_audit(
                &a.actor(),
                "volume.restore",
                &v.app,
                &format!("volume={} node={node} backup={}", v.name, req.snapshot),
            )
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "volume restore from backup",
            &[
                ("app", v.app.clone()),
                ("volume", v.name.clone()),
                ("node", node.clone()),
                ("backup", req.snapshot.clone()),
                ("by", a.actor()),
            ],
        );
        let op = self.repo_op(
            &node,
            VolumeRequest {
                op: Op::RestoreSnapshot as i32,
                app: v.app.clone(),
                volume: v.name.clone(),
                backup: Some(target),
                snapshot: req.snapshot.clone(),
                ..Default::default()
            },
        );
        let (m, err) = tokio::time::timeout(BACKUP_TIMEOUT, op).await.unwrap_or((
            None,
            Some(Status::new(
                Code::DeadlineExceeded,
                "context deadline exceeded",
            )),
        ));
        if let Some(e) = err {
            return Err(e);
        }
        if node != v.node {
            self.store()
                .bind_volume(&v.app, &v.name, &node, &a.actor())
                .await
                .map_err(|e| store_err(&e))?;
            self.trigger();
        }
        let id = m
            .and_then(|m| m.snapshot)
            .and_then(|s| s.snapshot)
            .map(|s| s.id)
            .unwrap_or_default();
        let mut e = app_event(
            APP,
            &v.app,
            &v.app,
            "VolumeRestored",
            &format!("volume {} on {node} from backup {id}", v.name),
        );
        e.node = node.clone();
        self.record(e).await;
        Ok(RestoreVolumeResponse { node })
    }

    /// Only cluster-admins point an app's volume
    /// backups at a bucket on a private IP address (ADR 0041). A change
    /// that keeps the private addresses of the revision the app is heading
    /// to is anyone's who may deploy it. value reads the URL secret sp
    /// would use; a secret that is not set yet is left to the backup.
    pub(crate) async fn check_backup_targets(
        &self,
        acc: &Access,
        app_id: &str,
        sp: &Spec,
        value: &mut UrlSource<'_>,
    ) -> Result<(), Status> {
        if acc.admin() || !has_backups(sp) {
            return Ok(());
        }
        let approved = self.approved_backup_ips(app_id).await?;
        for v in &sp.volumes {
            let Some(b) = &v.backup else { continue };
            let Some(raw) = value.get(self, &b.url_secret_ref).await? else {
                continue;
            };
            let t = volbackup::parse(&String::from_utf8_lossy(&raw)).map_err(|e| {
                Status::new(Code::InvalidArgument, format!("volume {}: {e}", v.name))
            })?;
            if let Some(ip) = private_ip(&t)
                && !approved.contains(&ip)
            {
                return Err(Status::new(
                    Code::PermissionDenied,
                    format!(
                        "volume {}: a backup bucket on a private address ({ip}) needs cluster-admin, since nodes reach it from their own addresses; use an https:// bucket by name, or ask a cluster-admin to deploy it once",
                        v.name
                    ),
                ));
            }
        }
        Ok(())
    }

    /// The private bucket addresses of the revision the
    /// app is heading to (its target, else its active one).
    async fn approved_backup_ips(&self, app_id: &str) -> Result<HashSet<IpAddr>, Status> {
        let mut out = HashSet::new();
        let a = match self.store().get_app(app_id).await {
            Err(e) if e.kind == Kind::NotFound => return Ok(out),
            Err(e) => return Err(store_err(&e)),
            Ok(a) => a,
        };
        let rn = if a.target_revision.is_empty() {
            a.active_revision
        } else {
            a.target_revision
        };
        if rn.is_empty() {
            return Ok(out);
        }
        let rev = self
            .store()
            .get_revision(&rn)
            .await
            .map_err(|e| store_err(&e))?;
        let Some(sp) = rev.spec.as_deref() else {
            return Ok(out);
        };
        if !has_backups(sp) {
            return Ok(out);
        }
        let vals = self.revision_secrets(&rev).await?;
        for v in &sp.volumes {
            let Some(b) = &v.backup else { continue };
            let Some(val) = vals.get(&b.url_secret_ref) else {
                continue;
            };
            if let Ok(t) = volbackup::parse(&String::from_utf8_lossy(val.bytes()))
                && let Some(ip) = private_ip(&t)
            {
                out.insert(ip);
            }
        }
        Ok(out)
    }

    /// The secret versions rev pins.
    async fn revision_secrets(&self, rev: &Revision) -> Result<BTreeMap<String, Value>, Status> {
        Revisions::new(self).secrets(rev).await.map_err(|_| {
            Status::new(
                Code::FailedPrecondition,
                "cannot read the app's backup secrets",
            )
        })
    }

    /// check_backup_targets on the revision a rollback
    /// restores, with the secret versions it pins.
    pub(crate) async fn check_rollback_backups(
        &self,
        acc: &Access,
        app_id: &str,
        target: &str,
    ) -> Result<(), Status> {
        if acc.admin() {
            return Ok(());
        }
        let rev = self
            .store()
            .get_revision(target)
            .await
            .map_err(|e| store_err(&e))?;
        let Some(sp) = rev.spec.clone() else {
            return Ok(());
        };
        if rev.app != app_id || !has_backups(&sp) {
            return Ok(());
        }
        let vals = self.revision_secrets(&rev).await?;
        self.check_backup_targets(acc, app_id, &sp, &mut UrlSource::Pinned(vals))
            .await
    }

    /// check_backup_targets when a change to a secret's
    /// key sets the bucket URL of the revision an app is heading to, for
    /// the secret's own app and every app whose revisions pin the key.
    pub(crate) async fn check_secret_backups(
        &self,
        acc: &Access,
        secret: &str,
        key: &str,
        value: &[u8],
    ) -> Result<(), Status> {
        if acc.admin() {
            return Ok(());
        }
        let mut apps = vec![secret.to_string()];
        let infos = match self.store().list_secrets(secret).await {
            Err(e) if e.kind == Kind::NotFound => Vec::new(),
            Err(e) => return Err(store_err(&e)),
            Ok(i) => i,
        };
        for info in infos {
            if info.name != key {
                continue;
            }
            for rn in &info.used_by {
                if let Some(i) = rn.rfind("--r")
                    && i > 0
                    && !apps.iter().any(|a| a == &rn[..i])
                {
                    apps.push(rn[..i].to_string());
                }
            }
        }
        for app_id in apps {
            self.check_app_secret_backups(acc, &app_id, secret, key, value)
                .await?;
        }
        Ok(())
    }

    async fn check_app_secret_backups(
        &self,
        acc: &Access,
        app_id: &str,
        secret: &str,
        key: &str,
        value: &[u8],
    ) -> Result<(), Status> {
        let a = match self.store().get_app(app_id).await {
            Err(e) if e.kind == Kind::NotFound => return Ok(()),
            Err(e) => return Err(store_err(&e)),
            Ok(a) => a,
        };
        let rn = if a.target_revision.is_empty() {
            a.active_revision
        } else {
            a.target_revision
        };
        if rn.is_empty() {
            return Ok(());
        }
        let rev = self
            .store()
            .get_revision(&rn)
            .await
            .map_err(|e| store_err(&e))?;
        let Some(sp) = rev.spec.clone() else {
            return Ok(());
        };
        let names = |r: &str| {
            let (sid, k) = secret_source(app_id, r);
            sid == secret && k == key
        };
        if !sp
            .volumes
            .iter()
            .any(|v| v.backup.as_ref().is_some_and(|b| names(&b.url_secret_ref)))
        {
            return Ok(());
        }
        self.check_backup_targets(
            acc,
            app_id,
            &sp,
            &mut UrlSource::Changed {
                app: app_id.to_string(),
                secret: secret.to_string(),
                key: key.to_string(),
                value: value.to_vec(),
            },
        )
        .await
    }
}

/// Where checkBackupTargets reads a URL secret from: the versions a
/// revision pins, the latest version a deploy would pin, or the value a
/// secret change sets.
pub(crate) enum UrlSource<'a> {
    Pinned(BTreeMap<String, Value>),
    /// The latest values, with the secrets listed so far.
    Latest {
        app: &'a str,
        infos: BTreeMap<String, Vec<armada_store::SecretInfo>>,
    },
    Changed {
        app: String,
        secret: String,
        key: String,
        value: Vec<u8>,
    },
}

impl UrlSource<'_> {
    async fn get(&mut self, srv: &Server, r: &str) -> Result<Option<Vec<u8>>, Status> {
        match self {
            UrlSource::Pinned(vals) => Ok(vals.get(r).map(|v| v.bytes().to_vec())),
            UrlSource::Changed {
                app,
                secret,
                key,
                value,
            } => {
                let (sid, k) = secret_source(app, r);
                Ok((sid == *secret && k == *key).then(|| value.clone()))
            }
            UrlSource::Latest { app, infos } => {
                let Some(keys) = &srv.0.keys else {
                    return Ok(None);
                };
                let (secret, key) = secret_source(app, r);
                if !infos.contains_key(&secret) {
                    let list = match srv.store().list_secrets(&secret).await {
                        Err(e) if e.kind == Kind::NotFound => Vec::new(),
                        Err(e) => return Err(store_err(&e)),
                        Ok(l) => l,
                    };
                    infos.insert(secret.clone(), list);
                }
                for info in &infos[&secret] {
                    if info.name != key {
                        continue;
                    }
                    let sealed = srv
                        .store()
                        .get_secret(&secret, &key, info.version)
                        .await
                        .map_err(|e| store_err(&e))?;
                    let v = keys
                        .open(&sealed, &secret, &key, info.version)
                        .map_err(|_| {
                            Status::new(
                                Code::FailedPrecondition,
                                "cannot read the app's backup secrets",
                            )
                        })?;
                    return Ok(Some(v.bytes().to_vec()));
                }
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: i64 = 60 * 1_000_000_000;

    fn at(unix: i64) -> Time {
        Time::zero().add(unix * 1_000_000_000)
    }

    fn state(last: i64, failed: i64) -> VolumeBackupState {
        VolumeBackupState {
            last_at: if last == 0 { Time::zero() } else { at(last) },
            last_id: String::new(),
            failed_at: if failed == 0 {
                Time::zero()
            } else {
                at(failed)
            },
            error: String::new(),
            stored: 0,
            snapshots: 0,
        }
    }

    #[test]
    fn due() {
        let hourly = VolumeBackup {
            every: armada_spec::Duration(60 * MINUTE),
            ..Default::default()
        };
        // After a success: on the schedule.
        assert_eq!(backup_due(&hourly, &state(1000, 0)).unix, at(4600).unix);
        // After a failure: no later than five minutes.
        assert_eq!(backup_due(&hourly, &state(1000, 2000)).unix, at(4600).unix);
        assert_eq!(backup_due(&hourly, &state(1000, 4500)).unix, at(4800).unix);
        // A schedule more often than the retry retries on it.
        let often = VolumeBackup {
            every: armada_spec::Duration(2 * MINUTE),
            ..Default::default()
        };
        assert_eq!(backup_due(&often, &state(1000, 1100)).unix, at(1220).unix);
    }

    #[test]
    fn private_buckets() {
        for (url, want) in [
            ("http://k:s@10.0.0.9:9000/bk1", Some("10.0.0.9")),
            ("https://k:s@10.0.0.9/bk1", Some("10.0.0.9")),
            ("https://k:s@[fd00::1]:9000/bk1", Some("fd00::1")),
            ("https://k:s@[fd00::1]/bk1", Some("fd00::1")),
            ("https://k:s@s3.example.com/bk1", None),
            ("https://k:s@8.8.8.8/bk1", None),
        ] {
            let t = volbackup::parse(url).unwrap();
            assert_eq!(
                private_ip(&t).map(|ip| ip.to_string()).as_deref(),
                want,
                "{url}"
            );
        }
    }

    #[test]
    fn runs() {
        let r = BackupRuns::default();
        assert!(r.start("web/data", "n1", true));
        assert!(!r.start("web/data", "n2", false));
        assert!(!r.start("api/data", "n1", true));
        assert!(r.start("api/data", "n1", false));
        r.done("web/data", "n1", true);
        assert!(r.start("db/data", "n1", true));
    }
}

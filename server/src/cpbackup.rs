//! Scheduled backups of the control plane to a bucket (ADR 0051; Go's
//! cpbackup.go): the settings SetClusterConfig stores (the bucket's URL
//! and the key sealed with the master key), the leader's loop that backs
//! the control plane up when due into the repository at
//! `<prefix>_control-plane/` (armada-node's volbackup) and prunes it with
//! the keep policy, the state it keeps, its condition and metrics, and
//! what ClusterStatus and the metrics endpoint show of it. What a backup
//! holds is staged by the daemon ([`ControlPlaneBackup`], Go's
//! Config.ControlPlaneBackup).

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use armada_node::volbackup::gotime::{Instant, Keep};
use armada_node::volbackup::repo::{Repo, Snapshot, Usage};
use armada_node::volbackup::s3::Bucket;
use armada_node::volbackup::target;
use armada_proto::armada::v1::{ControlPlaneBackupStatus, SetClusterConfigRequest};
use armada_spec::gotime::{Time, parse_rfc3339};
use armada_spec::{BackupKeep, Duration, VolumeBackup};
use armada_store::VolumeBackupState;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use tonic::{Code, Status};

use crate::Server;
use crate::backups::{BACKUP_TIMEOUT, backup_due};
use crate::events::{clean_message, event, timestamp};
use crate::grpc::Auth;
use crate::settings::{SealedJson, TOKEN_SCOPE, read_meta};
use crate::store_err;

/// The bucket URL and the key are sealed like the DNS token.
const CP_BACKUP_URL_NAME: &str = "backup-url";
const CP_BACKUP_KEY_NAME: &str = "backup-key";
/// The failure condition's key, and the control plane's name in events.
const CP_BACKUP_CONDITION: &str = "control-plane-backup";
const CP_BACKUP_OBJECT: &str = "control-plane";
const EVENT_CLUSTER: &str = "cluster";

/// A backup's files, staged in a directory removed when this is dropped.
pub struct Staged {
    pub dir: PathBuf,
    pub cleanup: Option<Box<dyn FnOnce() + Send>>,
}

impl Drop for Staged {
    fn drop(&mut self) {
        if let Some(f) = self.cleanup.take() {
            f();
        }
    }
}

/// Stages the files of a backup of this server's control plane (what
/// `armadad backup` writes) in a directory (Go's ControlPlaneBackup).
pub type ControlPlaneBackup =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<Staged, String>> + Send>> + Send + Sync>;

fn not_zero(n: &i64) -> bool {
    *n == 0
}

/// spec.BackupKeep as encoding/json writes it.
#[derive(Clone, Default, Serialize, Deserialize)]
struct KeepJson {
    #[serde(default, skip_serializing_if = "not_zero")]
    last: i64,
    #[serde(default, skip_serializing_if = "not_zero")]
    hourly: i64,
    #[serde(default, skip_serializing_if = "not_zero")]
    daily: i64,
    #[serde(default, skip_serializing_if = "not_zero")]
    weekly: i64,
    #[serde(default, skip_serializing_if = "not_zero")]
    monthly: i64,
}

/// The meta record of the settings (Go's cpBackupSettings).
#[derive(Clone, Default, Serialize, Deserialize)]
struct CpRec {
    #[serde(rename = "everySeconds", default, skip_serializing_if = "not_zero")]
    every_seconds: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    schedule: String,
    #[serde(rename = "timeZone", default, skip_serializing_if = "String::is_empty")]
    time_zone: String,
    #[serde(default)]
    keep: KeepJson,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    bucket: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    url: Option<SealedJson>,
    #[serde(rename = "urlVersion", default, skip_serializing_if = "not_zero")]
    url_version: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<SealedJson>,
    #[serde(rename = "keyVersion", default, skip_serializing_if = "not_zero")]
    key_version: i64,
}

impl CpRec {
    fn plan(&self) -> VolumeBackup {
        VolumeBackup {
            every: Duration(self.every_seconds.saturating_mul(1_000_000_000)),
            schedule: self.schedule.clone(),
            time_zone: self.time_zone.clone(),
            keep: BackupKeep {
                last: self.keep.last,
                hourly: self.keep.hourly,
                daily: self.keep.daily,
                weekly: self.keep.weekly,
                monthly: self.keep.monthly,
            },
            ..Default::default()
        }
    }
}

/// The state record (Go's cpBackupState) as encoding/json writes it.
#[derive(Serialize)]
struct CpStateRec {
    #[serde(rename = "urlVersion")]
    url_version: i64,
    #[serde(rename = "keyVersion")]
    key_version: i64,
    #[serde(rename = "lastAt", skip_serializing_if = "Option::is_none")]
    last_at: Option<String>,
    #[serde(rename = "lastId", skip_serializing_if = "String::is_empty")]
    last_id: String,
    #[serde(rename = "lastServer", skip_serializing_if = "String::is_empty")]
    last_server: String,
    #[serde(rename = "lastBytes", skip_serializing_if = "not_zero")]
    last_bytes: i64,
    #[serde(skip_serializing_if = "not_zero")]
    stored: i64,
    #[serde(skip_serializing_if = "not_zero")]
    snapshots: i64,
    #[serde(rename = "failedAt", skip_serializing_if = "Option::is_none")]
    failed_at: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

fn opt_time(t: &Time) -> Option<String> {
    (!t.is_zero()).then(|| t.rfc3339_nano())
}

fn instant(t: &Time) -> Instant {
    Instant::from_nanos(i128::from(t.unix) * 1_000_000_000 + i128::from(t.nsec))
}

fn bad(code: Code, msg: impl Into<String>) -> Status {
    Status::new(code, msg.into())
}

const META_CP_BACKUP: &str = "control-plane-backup";
const META_CP_BACKUP_STATE: &str = "control-plane-backup-state";

fn int(v: &Json, k: &str) -> i64 {
    v.get(k).and_then(Json::as_i64).unwrap_or_default()
}

fn text(v: &Json, k: &str) -> String {
    v.get(k)
        .and_then(Json::as_str)
        .unwrap_or_default()
        .to_string()
}

fn time(v: &Json, k: &str) -> Time {
    v.get(k)
        .and_then(Json::as_str)
        .and_then(parse_rfc3339)
        .unwrap_or_else(Time::zero)
}

/// The settings (Go's cpBackupSettings) the status and the loop need.
pub(crate) struct CpSettings {
    pub plan: VolumeBackup,
    pub bucket: String,
    pub url_version: i64,
    pub key_version: i64,
    on: bool,
    url: Option<SealedJson>,
    key: Option<SealedJson>,
}

/// The state (Go's cpBackupState).
pub(crate) struct CpState {
    pub last_at: Time,
    pub last_id: String,
    pub last_server: String,
    pub last_bytes: i64,
    pub stored: i64,
    pub snapshots: i64,
    pub failed_at: Time,
    pub error: String,
}

impl Default for CpState {
    fn default() -> Self {
        CpState {
            last_at: Time::zero(),
            last_id: String::new(),
            last_server: String::new(),
            last_bytes: 0,
            stored: 0,
            snapshots: 0,
            failed_at: Time::zero(),
            error: String::new(),
        }
    }
}

impl Server {
    /// cpBackupSettings, or none when backups are off.
    pub(crate) async fn cp_backup_settings(
        &self,
    ) -> Result<Option<CpSettings>, armada_store::Error> {
        let Some(b) = read_meta(self.store(), META_CP_BACKUP).await? else {
            return Ok(None);
        };
        let set = |k: &str| b.get(k).is_some_and(|v| !v.is_null());
        let keep = b.get("keep").cloned().unwrap_or(Json::Null);
        let s = CpSettings {
            plan: VolumeBackup {
                every: Duration(int(&b, "everySeconds").saturating_mul(1_000_000_000)),
                schedule: text(&b, "schedule"),
                time_zone: text(&b, "timeZone"),
                keep: BackupKeep {
                    last: int(&keep, "last"),
                    hourly: int(&keep, "hourly"),
                    daily: int(&keep, "daily"),
                    weekly: int(&keep, "weekly"),
                    monthly: int(&keep, "monthly"),
                },
                ..Default::default()
            },
            bucket: text(&b, "bucket"),
            url_version: int(&b, "urlVersion"),
            key_version: int(&b, "keyVersion"),
            on: set("url") && set("key"),
            url: b
                .get("url")
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
            key: b
                .get("key")
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
        };
        Ok(s.on.then_some(s))
    }

    /// cpBackupState: the state of the settings' bucket and key; a new
    /// bucket or key starts afresh.
    pub(crate) async fn cp_backup_state(
        &self,
        set: &CpSettings,
    ) -> Result<CpState, armada_store::Error> {
        let Some(v) = read_meta(self.store(), META_CP_BACKUP_STATE).await? else {
            return Ok(CpState::default());
        };
        if int(&v, "urlVersion") != set.url_version || int(&v, "keyVersion") != set.key_version {
            return Ok(CpState::default());
        }
        Ok(CpState {
            last_at: time(&v, "lastAt"),
            last_id: text(&v, "lastId"),
            last_server: text(&v, "lastServer"),
            last_bytes: int(&v, "lastBytes"),
            stored: int(&v, "stored"),
            snapshots: int(&v, "snapshots"),
            failed_at: time(&v, "failedAt"),
            error: text(&v, "error"),
        })
    }

    /// controlPlaneBackupStatus: none while backups are off.
    pub(crate) async fn control_plane_backup_status(
        &self,
    ) -> Result<Option<ControlPlaneBackupStatus>, armada_store::Error> {
        let Some(set) = self.cp_backup_settings().await? else {
            return Ok(None);
        };
        let st = self.cp_backup_state(&set).await?;
        let due = backup_due(
            &set.plan,
            &VolumeBackupState {
                last_at: st.last_at.clone(),
                last_id: String::new(),
                failed_at: st.failed_at.clone(),
                error: String::new(),
                stored: 0,
                snapshots: 0,
            },
        );
        let mut out = ControlPlaneBackupStatus {
            bucket: set.bucket.clone(),
            last_snapshot: st.last_id.clone(),
            last_server: st.last_server.clone(),
            last_size_bytes: st.last_bytes,
            stored_bytes: st.stored,
            snapshots: st.snapshots as i32,
            next_at: Some(timestamp(&due)),
            ..Default::default()
        };
        if !st.last_at.is_zero() {
            out.last_at = Some(timestamp(&st.last_at));
        }
        if !st.error.is_empty() {
            out.failed_at = Some(timestamp(&st.failed_at));
            out.error = st.error.clone();
        }
        Ok(Some(out))
    }
}

impl Server {
    /// setControlPlaneBackup: stores the backup settings the request
    /// names. The URL and the key are sealed and never logged, audited,
    /// or returned.
    pub(crate) async fn set_control_plane_backup(
        &self,
        a: &Auth,
        req: &SetClusterConfigRequest,
    ) -> Result<(), Status> {
        let changes =
            req.set_backup_plan || req.set_backup_keep || req.set_backup_url || req.set_backup_key;
        if !changes && !req.set_backup_off {
            return Ok(());
        }
        if changes && req.set_backup_off {
            return Err(bad(
                Code::InvalidArgument,
                "--backup none turns control plane backups off: give no other backup setting with it",
            ));
        }
        let mut set: CpRec = match read_meta(self.store(), META_CP_BACKUP)
            .await
            .map_err(|e| store_err(&e))?
        {
            None => CpRec::default(),
            Some(v) => serde_json::from_value(v).map_err(|e| {
                store_err(&armada_store::Error::other(format!(
                    "{META_CP_BACKUP}: {e}"
                )))
            })?,
        };
        let mut what: Vec<String> = Vec::new();
        if req.set_backup_off {
            // The versions stay, so a later URL or key never reuses one.
            set = CpRec {
                url_version: set.url_version,
                key_version: set.key_version,
                ..Default::default()
            };
            what.push("off".into());
        }
        let c = req.config.clone().unwrap_or_default();
        if req.set_backup_plan {
            set.every_seconds = c.backup_every_seconds;
            set.schedule = armada_spec::go::trim_space(&c.backup_schedule).to_string();
            set.time_zone = armada_spec::go::trim_space(&c.backup_time_zone).to_string();
            if set.every_seconds < 0 {
                return Err(bad(
                    Code::InvalidArgument,
                    "the backup interval must be positive",
                ));
            }
            if set.every_seconds != 0 {
                what.push(format!(
                    "every={}",
                    armada_spec::go::format_duration(
                        set.every_seconds.saturating_mul(1_000_000_000)
                    )
                ));
            } else {
                what.push(format!("schedule={}", set.schedule));
            }
            if !set.time_zone.is_empty() {
                what.push(format!("time_zone={}", set.time_zone));
            }
        }
        if req.set_backup_keep {
            let k = c.backup_keep.unwrap_or_default();
            set.keep = KeepJson {
                last: i64::from(k.last),
                hourly: i64::from(k.hourly),
                daily: i64::from(k.daily),
                weekly: i64::from(k.weekly),
                monthly: i64::from(k.monthly),
            };
            what.push(format!(
                "keep=last:{},hourly:{},daily:{},weekly:{},monthly:{}",
                k.last, k.hourly, k.daily, k.weekly, k.monthly
            ));
        }
        let keys = match &self.0.keys {
            None if req.set_backup_url || req.set_backup_key => {
                return Err(bad(
                    Code::FailedPrecondition,
                    "this server has no master key to encrypt the backup URL and key with",
                ));
            }
            k => k.clone(),
        };
        if req.set_backup_url
            && let Some(keys) = &keys
        {
            let raw = armada_node::gostr::trim_space(&req.backup_url).to_vec();
            if raw.is_empty() {
                return Err(bad(
                    Code::InvalidArgument,
                    "the backup URL is empty; --backup none turns backups off",
                ));
            }
            // ParseTarget's errors never hold the URL.
            let t = target::parse(&String::from_utf8_lossy(&raw))
                .map_err(|e| bad(Code::InvalidArgument, e))?;
            let sealed = keys
                .seal(
                    TOKEN_SCOPE,
                    CP_BACKUP_URL_NAME,
                    set.url_version + 1,
                    &armada_secrets::Value::new(&raw),
                )
                .map_err(|_| bad(Code::Internal, "seal the backup URL"))?;
            set.url_version += 1;
            set.url = Some(SealedJson::of(&sealed));
            set.bucket = format!("{}/{}/{}", t.endpoint, t.bucket, t.prefix);
            what.push("url".into());
        }
        if req.set_backup_key
            && let Some(keys) = &keys
        {
            let key = armada_node::gostr::trim_space(&req.backup_key).to_vec();
            if key.len() < armada_spec::MIN_BACKUP_KEY_LEN {
                return Err(bad(
                    Code::InvalidArgument,
                    format!(
                        "the backup key must hold at least {} bytes",
                        armada_spec::MIN_BACKUP_KEY_LEN
                    ),
                ));
            }
            let sealed = keys
                .seal(
                    TOKEN_SCOPE,
                    CP_BACKUP_KEY_NAME,
                    set.key_version + 1,
                    &armada_secrets::Value::new(&key),
                )
                .map_err(|_| bad(Code::Internal, "seal the backup key"))?;
            set.key_version += 1;
            set.key = Some(SealedJson::of(&sealed));
            what.push("key".into());
        }
        if !req.set_backup_off {
            if set.url.is_none() || set.key.is_none() {
                return Err(bad(
                    Code::FailedPrecondition,
                    "control plane backups need a bucket and a key: --backup-url FILE --backup-key FILE, with --backup-every D (or --backup-schedule CRON) and --backup-keep N",
                ));
            }
            if set.every_seconds == 0 && set.schedule.is_empty() {
                return Err(bad(
                    Code::InvalidArgument,
                    "control plane backups need --backup-every D or --backup-schedule CRON",
                ));
            }
            armada_spec::validate::check_backup_plan(&set.plan())
                .map_err(|e| bad(Code::InvalidArgument, e))?;
        }
        let b = serde_json::to_string(&set).map_err(|e| bad(Code::Internal, e.to_string()))?;
        self.store()
            .set_meta(META_CP_BACKUP, &b)
            .await
            .map_err(|e| store_err(&e))?;
        let detail = what.join(" ");
        self.store()
            .record_audit(&a.actor(), "cluster.backup", "cluster", &detail)
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "control plane backups changed",
            &[("changed", detail), ("by", a.actor())],
        );
        self.0.cp_wake.notify_one();
        Ok(())
    }

    /// controlPlaneBackupLoop: backs the control plane up whenever it is
    /// due, one backup at a time, while this server leads.
    pub(crate) async fn control_plane_backup_loop(
        &self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        if self.0.cp_backup.is_none() {
            return;
        }
        let every = self.0.backup_interval;
        let mut t = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        loop {
            let res = tokio::select! {
                r = self.control_plane_backup_pass() => r,
                _ = crate::stopped(&mut shutdown) => return,
            };
            if let Err(e) = res
                && !*shutdown.borrow()
            {
                self.0
                    .log
                    .error("control plane backups", &[("err", e.to_string())]);
            }
            tokio::select! {
                _ = crate::stopped(&mut shutdown) => return,
                _ = t.tick() => {}
                _ = self.0.cp_wake.notified() => {}
            }
        }
    }

    /// controlPlaneBackupPass: runs a backup when one is due.
    pub async fn control_plane_backup_pass(&self) -> Result<(), armada_store::Error> {
        let Some(set) = self.cp_backup_settings().await? else {
            self.condition(
                CP_BACKUP_CONDITION,
                false,
                event(
                    EVENT_CLUSTER,
                    CP_BACKUP_OBJECT,
                    "",
                    "ControlPlaneBackupFailed",
                    "",
                ),
            )
            .await;
            return Ok(());
        };
        let st = self.cp_backup_state(&set).await?;
        if cp_backup_due(&set, &st).after(&self.now()) {
            return Ok(());
        }
        self.run_control_plane_backup(&set).await
    }

    /// runControlPlaneBackup: backs the control plane up, prunes the
    /// bucket, and records how it went.
    async fn run_control_plane_backup(&self, set: &CpSettings) -> Result<(), armada_store::Error> {
        let (snap, usage, err) =
            match tokio::time::timeout(BACKUP_TIMEOUT, self.back_up_control_plane(set)).await {
                Ok(r) => r,
                Err(_) => (
                    None,
                    Usage::default(),
                    Some("context deadline exceeded".into()),
                ),
            };
        let mut st = self.cp_backup_state(set).await?;
        let now = self.now();
        if let Some(snap) = &snap {
            st.last_at = Time {
                unix: snap.time.sec,
                nsec: i64::from(snap.time.nsec),
                loc: armada_spec::gotime::Location::utc(),
            };
            st.last_id = snap.id.clone();
            st.last_server = self.0.name.clone();
            st.last_bytes = snap.bytes;
            st.stored = usage.stored;
            st.snapshots = usage.snapshots;
            st.failed_at = Time::zero();
            st.error.clear();
        }
        let msg = err.as_deref().map(clean_message).unwrap_or_default();
        if err.is_some() {
            st.failed_at = now;
            st.error = msg.clone();
            self.0.metrics.control_plane_backup_failed();
        }
        let rec = CpStateRec {
            url_version: set.url_version,
            key_version: set.key_version,
            last_at: opt_time(&st.last_at),
            last_id: st.last_id.clone(),
            last_server: st.last_server.clone(),
            last_bytes: st.last_bytes,
            stored: st.stored,
            snapshots: st.snapshots,
            failed_at: opt_time(&st.failed_at),
            error: st.error.clone(),
        };
        let written = match serde_json::to_string(&rec) {
            Ok(b) => self.store().set_meta(META_CP_BACKUP_STATE, &b).await,
            Err(e) => Err(armada_store::Error::other(e.to_string())),
        };
        if let Err(e) = written {
            self.0
                .log
                .warn("record control plane backup", &[("err", e.to_string())]);
        }
        self.condition(
            CP_BACKUP_CONDITION,
            err.is_some(),
            event(
                EVENT_CLUSTER,
                CP_BACKUP_OBJECT,
                "",
                "ControlPlaneBackupFailed",
                &format!(
                    "backup of the control plane to {} failed: {msg}",
                    set.bucket
                ),
            ),
        )
        .await;
        match (&err, &snap) {
            (Some(_), _) => self.0.log.warn(
                "control plane backup failed",
                &[("bucket", set.bucket.clone()), ("err", msg)],
            ),
            (None, Some(snap)) => self.0.log.info(
                "control plane backed up",
                &[
                    ("bucket", set.bucket.clone()),
                    ("backup", snap.id.clone()),
                    ("bytes", snap.bytes.to_string()),
                    ("kept", usage.snapshots.to_string()),
                    ("deleted", usage.deleted_snapshots.to_string()),
                ],
            ),
            _ => {}
        }
        Ok(())
    }

    /// backUpControlPlane: a snapshot written to the bucket and the bucket
    /// pruned. A snapshot comes back also when the error says only the
    /// pruning failed.
    async fn back_up_control_plane(
        &self,
        set: &CpSettings,
    ) -> (Option<Snapshot>, Usage, Option<String>) {
        let fail = |e: String| (None, Usage::default(), Some(e));
        let Some(keys) = &self.0.keys else {
            return fail(
                "this server has no master key to open the backup URL and key with".into(),
            );
        };
        let url = match set.url.as_ref().map(|u| {
            keys.open(
                &u.sealed(),
                TOKEN_SCOPE,
                CP_BACKUP_URL_NAME,
                set.url_version,
            )
        }) {
            Some(Ok(v)) => v,
            _ => return fail("open the backup URL: the master key does not match".into()),
        };
        let key = match set.key.as_ref().map(|k| {
            keys.open(
                &k.sealed(),
                TOKEN_SCOPE,
                CP_BACKUP_KEY_NAME,
                set.key_version,
            )
        }) {
            Some(Ok(v)) => v,
            _ => return fail("open the backup key: the master key does not match".into()),
        };
        let t = match target::parse(&String::from_utf8_lossy(url.bytes())) {
            Ok(t) => t,
            Err(e) => return fail(e),
        };
        let bucket = match Bucket::new(t.clone(), None) {
            Ok(b) => b,
            Err(e) => return fail(e),
        };
        let root = format!("{}_control-plane/", t.prefix);
        let secret = key.bytes().to_vec();
        let opened = tokio::task::spawn_blocking(move || Repo::open(&bucket, &root, &secret)).await;
        let mut repo = match opened {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return fail(e),
            Err(e) => return fail(e.to_string()),
        };
        let Some(stage) = self.0.cp_backup.clone() else {
            return fail("no control plane backup".into());
        };
        let staged = match stage().await {
            Ok(s) => s,
            Err(e) => return fail(e),
        };
        let (name, now) = (self.0.name.clone(), instant(&self.now()));
        let clock = self.0.clock.clone();
        let plan = set.plan.clone();
        let done = tokio::task::spawn_blocking(move || {
            let dir = staged.dir.as_os_str().as_encoded_bytes().to_vec();
            let snap = repo.backup(&dir, &name, now).map(|(s, _)| s);
            drop(staged);
            let snap = match snap {
                Ok(s) => s,
                Err(f) => return (None, Usage::default(), Some(f.text)),
            };
            let k = &plan.keep;
            let keep = Keep {
                last: k.last,
                hourly: k.hourly,
                daily: k.daily,
                weekly: k.weekly,
                monthly: k.monthly,
            };
            let zone = plan.location().zone_table();
            let (usage, err) = repo.prune(&keep, &zone, instant(&clock()));
            let err = err.map(|e| {
                format!(
                    "backup {} worked, but removing old backups failed: {e}",
                    snap.id
                )
            });
            (Some(snap), usage, err)
        })
        .await;
        match done {
            Ok(r) => r,
            Err(e) => fail(e.to_string()),
        }
    }
}

/// cpBackupDue: when the next backup is due, on the plan after the last
/// success, and after a failure no later than backupRetry.
fn cp_backup_due(set: &CpSettings, st: &CpState) -> Time {
    backup_due(
        &set.plan,
        &VolumeBackupState {
            last_at: st.last_at.clone(),
            last_id: String::new(),
            failed_at: st.failed_at.clone(),
            error: String::new(),
            stored: 0,
            snapshots: 0,
        },
    )
}

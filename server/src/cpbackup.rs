//! What the leader shows of the control plane's backups (ADR 0051; Go's
//! controlPlaneBackupStatus in cpbackup.go): the settings and the state
//! the backup loop keeps in meta records, for ClusterStatus and the
//! metrics endpoint. The loop and the settings of SetClusterConfig follow
//! with the second part of watching (pull request 15 of ADR 0055).

use armada_proto::armada::v1::ControlPlaneBackupStatus;
use armada_spec::gotime::{Time, parse_rfc3339};
use armada_spec::{BackupKeep, Duration, VolumeBackup};
use armada_store::VolumeBackupState;
use serde_json::Value as Json;

use crate::Server;
use crate::backups::backup_due;
use crate::events::timestamp;
use crate::settings::read_meta;

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

/// The settings (Go's cpBackupSettings) the status needs.
pub(crate) struct CpSettings {
    pub plan: VolumeBackup,
    pub bucket: String,
    pub url_version: i64,
    pub key_version: i64,
    on: bool,
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

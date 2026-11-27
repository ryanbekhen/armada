//! The records under the store's prefix, field for field in the
//! keyspace's format (names, order, empty fields left out), so every
//! release reads and rewrites what another wrote byte for byte.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::gojson::{b64, is_false, is_zero_i64};

fn is_empty_str(s: &str) -> bool {
    s.is_empty()
}

fn is_zero_int(v: &i64) -> bool {
    *v == 0
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct NodeRec {
    pub id: String,
    #[serde(rename = "privateIp")]
    pub private_ip: String,
    #[serde(rename = "cpuMillis")]
    pub cpu_millis: i64,
    #[serde(rename = "memoryBytes")]
    pub memory_bytes: i64,
    pub state: String,
    #[serde(rename = "lastSeen")]
    pub last_seen: i64,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    pub cordoned: bool,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub version: String,
    #[serde(rename = "legacyCerts", skip_serializing_if = "is_false")]
    pub legacy_certs: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "is_false")]
    pub restricted: bool,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub os: String,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub arch: String,
    #[serde(skip_serializing_if = "is_false")]
    pub jobs: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub volumes: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub containers: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub nfs: bool,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub subnet: String,
    #[serde(rename = "networkKey", skip_serializing_if = "is_empty_str")]
    pub network_key: String,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub endpoint: String,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub site: String,
    #[serde(rename = "meshAddress", skip_serializing_if = "is_false")]
    pub mesh_address: bool,
    #[serde(rename = "behindNat", skip_serializing_if = "is_false")]
    pub behind_nat: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub relay: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct CertRec {
    pub serial: String,
    pub node: String,
    #[serde(rename = "notAfter")]
    pub not_after: i64,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct TokenRec {
    pub id: String,
    #[serde(rename = "secretHash")]
    pub secret_hash: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "usedAt")]
    pub used_at: i64,
    #[serde(rename = "usedBy")]
    pub used_by: String,
    #[serde(skip_serializing_if = "is_false")]
    pub server: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub from: String,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub site: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct ServerRec {
    pub name: String,
    #[serde(rename = "privateIp")]
    pub private_ip: String,
    #[serde(rename = "apiAddr")]
    pub api_addr: String,
    #[serde(rename = "joinAddr", skip_serializing_if = "is_empty_str")]
    pub join_addr: String,
    #[serde(rename = "memberId")]
    pub member_id: u64,
    #[serde(skip_serializing_if = "is_zero_int")]
    pub schema: i64,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub version: String,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    /// ADR 0057: the server's armada-kv peer URL for the move.
    #[serde(rename = "kvPeerUrl", default, skip_serializing_if = "is_empty_str")]
    pub kv_peer_url: String,
}

/// spec.TrafficTarget as encoding/json writes it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct TrafficRec {
    pub revision: String,
    pub weight: i64,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub label: String,
}

impl TrafficRec {
    pub fn from_spec(t: &armada_spec::TrafficTarget) -> TrafficRec {
        TrafficRec {
            revision: t.revision.clone(),
            weight: t.weight,
            label: t.label.clone(),
        }
    }
    pub fn to_spec(&self) -> armada_spec::TrafficTarget {
        armada_spec::TrafficTarget {
            revision: self.revision.clone(),
            weight: self.weight,
            label: self.label.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct AppRec {
    pub name: String,
    #[serde(rename = "activeRevision")]
    pub active_revision: String,
    #[serde(rename = "targetRevision")]
    pub target_revision: String,
    pub replicas: i64,
    #[serde(rename = "rolloutState")]
    pub rollout_state: String,
    #[serde(rename = "rolloutMessage")]
    pub rollout_message: String,
    #[serde(rename = "rolloutProgressAt")]
    pub rollout_progress_at: i64,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    #[serde(rename = "updatedAt")]
    pub updated_at: i64,
    #[serde(rename = "lastScheduled", skip_serializing_if = "is_zero_i64")]
    pub last_scheduled: i64,
    #[serde(rename = "lastRun", skip_serializing_if = "is_zero_i64")]
    pub last_run: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub traffic: Vec<TrafficRec>,
    #[serde(skip_serializing_if = "is_false")]
    pub removing: bool,
    #[serde(rename = "scaledAt", skip_serializing_if = "is_zero_i64")]
    pub scaled_at: i64,
}

fn null_raw() -> Box<RawValue> {
    RawValue::from_string("null".to_string()).expect("null is JSON")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RevRec {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub app: String,
    #[serde(default)]
    pub seq: i64,
    #[serde(default = "null_raw")]
    pub spec: Box<RawValue>,
    #[serde(rename = "imageDigest", default)]
    pub image_digest: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub secrets: Option<BTreeMap<String, i64>>,
    #[serde(rename = "createdAt", default)]
    pub created_at: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct ReplicaRec {
    pub id: String,
    pub app: String,
    pub revision: String,
    #[serde(rename = "nodeId")]
    pub node_id: String,
    pub state: String,
    #[serde(rename = "containerId")]
    pub container_id: String,
    pub address: String,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub ip: String,
    pub message: String,
    pub ready: bool,
    #[serde(rename = "readySince")]
    pub ready_since: i64,
    #[serde(rename = "drainingSince")]
    pub draining_since: i64,
    #[serde(rename = "movingSince", skip_serializing_if = "is_zero_i64")]
    pub moving_since: i64,
    #[serde(rename = "updatedAt")]
    pub updated_at: i64,
    #[serde(rename = "createdAt", skip_serializing_if = "is_zero_i64")]
    pub created_at: i64,
    #[serde(skip_serializing_if = "is_zero_int")]
    pub restarts: i64,
    #[serde(rename = "lastRestartAt", skip_serializing_if = "is_zero_i64")]
    pub last_restart_at: i64,
    #[serde(rename = "lastRestart", skip_serializing_if = "is_empty_str")]
    pub last_restart: String,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub run: i64,
    #[serde(skip_serializing_if = "is_false")]
    pub done: bool,
    #[serde(skip_serializing_if = "is_zero_int")]
    pub task: i64,
    #[serde(skip_serializing_if = "is_false")]
    pub finished: bool,
    #[serde(rename = "exitCode", skip_serializing_if = "is_zero_int")]
    pub exit_code: i64,
    #[serde(skip_serializing_if = "is_false")]
    pub held: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct SecretRec {
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "wrappedKey", with = "b64")]
    pub wrapped_key: Option<Vec<u8>>,
    #[serde(with = "b64")]
    pub ciphertext: Option<Vec<u8>>,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct DomainRec {
    pub name: String,
    pub token: String,
    pub verified: bool,
    #[serde(rename = "verifiedAt")]
    pub verified_at: i64,
    pub message: String,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub space: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct AuditRec {
    pub id: i64,
    pub at: i64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct EventRec {
    pub kind: String,
    pub object: String,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub app: String,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub node: String,
    pub reason: String,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub message: String,
    pub count: i64,
    pub first: i64,
    pub last: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct PlacementRec {
    pub app: String,
    pub node: String,
    pub at: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct RunTaskRec {
    pub index: i64,
    pub state: String,
    #[serde(skip_serializing_if = "is_zero_int")]
    pub attempts: i64,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub replica: String,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub node: String,
    #[serde(rename = "exitCode", skip_serializing_if = "is_zero_int")]
    pub exit_code: i64,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub message: String,
    #[serde(rename = "attemptAt", skip_serializing_if = "is_zero_i64")]
    pub attempt_at: i64,
    #[serde(rename = "waitingSince", skip_serializing_if = "is_zero_i64")]
    pub waiting_since: i64,
    #[serde(rename = "finishedAt", skip_serializing_if = "is_zero_i64")]
    pub finished_at: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct JobRunRec {
    pub job: String,
    pub seq: i64,
    pub revision: String,
    pub trigger: String,
    pub state: String,
    #[serde(skip_serializing_if = "is_zero_int")]
    pub attempts: i64,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub replica: String,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub node: String,
    #[serde(rename = "exitCode", skip_serializing_if = "is_zero_int")]
    pub exit_code: i64,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub message: String,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    #[serde(rename = "startedAt", skip_serializing_if = "is_zero_i64")]
    pub started_at: i64,
    #[serde(rename = "attemptAt", skip_serializing_if = "is_zero_i64")]
    pub attempt_at: i64,
    #[serde(rename = "finishedAt", skip_serializing_if = "is_zero_i64")]
    pub finished_at: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tasks: Vec<RunTaskRec>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct VolumeRec {
    pub app: String,
    pub name: String,
    pub node: String,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    #[serde(rename = "backupAt", skip_serializing_if = "is_zero_i64")]
    pub backup_at: i64,
    #[serde(rename = "backupId", skip_serializing_if = "is_empty_str")]
    pub backup_id: String,
    #[serde(rename = "backupFailedAt", skip_serializing_if = "is_zero_i64")]
    pub backup_failed_at: i64,
    #[serde(rename = "backupError", skip_serializing_if = "is_empty_str")]
    pub backup_error: String,
    #[serde(rename = "backupStored", skip_serializing_if = "is_zero_i64")]
    pub backup_stored: i64,
    #[serde(rename = "backupSnapshots", skip_serializing_if = "is_zero_int")]
    pub backup_snapshots: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct NetworkSwitchRec {
    pub to: String,
    pub step: String,
    /// A time.Time as encoding/json wrote it, kept as written.
    pub since: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct NetworkRec {
    pub mode: String,
    #[serde(rename = "clusterCidr")]
    pub cluster_cidr: String,
    #[serde(rename = "isolateDefault", skip_serializing_if = "is_false")]
    pub isolate_default: bool,
    #[serde(rename = "meshCidr", skip_serializing_if = "is_empty_str")]
    pub mesh_cidr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub switch: Option<NetworkSwitchRec>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct SpaceRec {
    pub name: String,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    #[serde(rename = "createdBy", skip_serializing_if = "is_empty_str")]
    pub created_by: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct GrantRec {
    pub role: String,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub space: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct PrincipalRec {
    pub name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<GrantRec>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, Vec<String>>,
    #[serde(rename = "createdAt", skip_serializing_if = "is_zero_i64")]
    pub created_at: i64,
    #[serde(rename = "createdBy", skip_serializing_if = "is_empty_str")]
    pub created_by: String,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub since: i64,
    #[serde(rename = "sinceSerial", skip_serializing_if = "is_empty_str")]
    pub since_serial: String,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub cutoff: i64,
    #[serde(skip_serializing_if = "is_false")]
    pub removed: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub certs: Vec<CertRec>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct MetricsRec {
    pub name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub certs: Vec<CertRec>,
}

/// adminRec and automationRec of schema 8 (migrateAccess).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct AdminRec {
    pub name: String,
    pub since: i64,
    pub removed: bool,
    #[serde(rename = "addedAt")]
    pub added_at: i64,
    #[serde(rename = "addedBy")]
    pub added_by: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct AutomationRec {
    pub name: String,
    #[serde(rename = "projects")]
    pub spaces: Vec<String>,
    #[serde(rename = "createProjects")]
    pub create_spaces: bool,
    pub labels: BTreeMap<String, Vec<String>>,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    pub certs: Vec<CertRec>,
}

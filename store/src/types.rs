//! What the store's methods take and return. They serialize with the
//! recordings' field names (for the parity program's answers).

use std::collections::BTreeMap;
use std::sync::Arc;

use armada_spec::App as Spec;
use armada_spec::TrafficTarget;
use armada_spec::gotime::Time;
use serde::{Serialize, Serializer};

use crate::gojson::time_text;

/// Node states.
pub const NODE_READY: &str = "ready";
pub const NODE_UNKNOWN: &str = "unknown";

/// Replica states reported by agents.
pub const REPLICA_PENDING: &str = "pending";
pub const REPLICA_PULLING: &str = "pulling";
pub const REPLICA_PULLED: &str = "pulled";
pub const REPLICA_STARTING: &str = "starting";
pub const REPLICA_RUNNING: &str = "running";
pub const REPLICA_EXITED: &str = "exited";
pub const REPLICA_FAILED: &str = "failed";

/// Rollout states.
pub const ROLLOUT_NONE: &str = "";
pub const ROLLOUT_PROGRESSING: &str = "progressing";
pub const ROLLOUT_FAILED: &str = "failed";

/// RevisionsToKeep is how many revisions per app are retained.
pub const REVISIONS_TO_KEEP: i64 = 10;

/// RestartNote starts the messages an agent reports for a container it
/// recreated.
pub const RESTART_NOTE: &str = "restarted: ";

fn spec_json<S: Serializer>(v: &Option<Arc<Spec>>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        None => s.serialize_none(),
        Some(a) => {
            let raw = serde_json::value::RawValue::from_string(a.to_json())
                .map_err(serde::ser::Error::custom)?;
            raw.serialize(s)
        }
    }
}

fn traffic_json<S: Serializer>(v: &[TrafficTarget], s: S) -> Result<S::Ok, S::Error> {
    let recs: Vec<crate::records::TrafficRec> = v
        .iter()
        .map(crate::records::TrafficRec::from_spec)
        .collect();
    recs.serialize(s)
}

/// A machine running an agent.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Node {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "PrivateIP")]
    pub private_ip: String,
    #[serde(rename = "CPUMillis")]
    pub cpu_millis: i64,
    pub memory_bytes: i64,
    pub state: String,
    #[serde(with = "time_text")]
    pub last_seen: Time,
    #[serde(with = "time_text")]
    pub created_at: Time,
    pub cordoned: bool,
    pub version: String,
    #[serde(with = "time_text")]
    pub cert_not_after: Time,
    /// None (no map, unlike an empty one): UpsertNode then keeps the
    /// recorded labels.
    pub labels: Option<BTreeMap<String, String>>,
    #[serde(rename = "OS")]
    pub os: String,
    pub arch: String,
    pub restricted: bool,
    pub jobs: bool,
    pub volumes: bool,
    pub containers: bool,
    #[serde(rename = "NFS")]
    pub nfs: bool,
    pub subnet: String,
    pub network_key: String,
    pub endpoint: String,
    pub site: String,
    pub mesh_address: bool,
    #[serde(rename = "BehindNAT")]
    pub behind_nat: bool,
    pub relay: bool,
}

impl Default for Node {
    fn default() -> Node {
        Node {
            id: String::new(),
            private_ip: String::new(),
            cpu_millis: 0,
            memory_bytes: 0,
            state: String::new(),
            last_seen: Time::zero(),
            created_at: Time::zero(),
            cordoned: false,
            version: String::new(),
            cert_not_after: Time::zero(),
            labels: None,
            os: String::new(),
            arch: String::new(),
            restricted: false,
            jobs: false,
            volumes: false,
            containers: false,
            nfs: false,
            subnet: String::new(),
            network_key: String::new(),
            endpoint: String::new(),
            site: String::new(),
            mesh_address: false,
            behind_nat: false,
            relay: false,
        }
    }
}

impl Node {
    /// AllLabels: the admin labels plus armada.os, armada.arch, and
    /// armada.site.
    pub fn all_labels(&self) -> BTreeMap<String, String> {
        let mut out = self.labels.clone().unwrap_or_default();
        if !self.os.is_empty() {
            out.insert(armada_spec::validate::LABEL_OS.to_string(), self.os.clone());
        }
        if !self.arch.is_empty() {
            out.insert(
                armada_spec::validate::LABEL_ARCH.to_string(),
                self.arch.clone(),
            );
        }
        if !self.site.is_empty() {
            out.insert(
                armada_spec::validate::LABEL_SITE.to_string(),
                self.site.clone(),
            );
        }
        out
    }
}

/// A stored join token; the secret itself is never stored.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct JoinToken {
    #[serde(rename = "ID")]
    pub id: String,
    pub secret_hash: String,
    #[serde(with = "time_text")]
    pub expires_at: Time,
    #[serde(with = "time_text")]
    pub created_at: Time,
    pub created_by: String,
    pub server: bool,
    pub labels: BTreeMap<String, String>,
    pub from: String,
    pub site: String,
}

impl Default for JoinToken {
    fn default() -> JoinToken {
        JoinToken {
            id: String::new(),
            secret_hash: String::new(),
            expires_at: Time::zero(),
            created_at: Time::zero(),
            created_by: String::new(),
            server: false,
            labels: BTreeMap::new(),
            from: String::new(),
            site: String::new(),
        }
    }
}

/// A control plane node.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Server {
    pub name: String,
    #[serde(rename = "PrivateIP")]
    pub private_ip: String,
    #[serde(rename = "APIAddr")]
    pub api_addr: String,
    pub join_addr: String,
    #[serde(rename = "MemberID")]
    pub member_id: u64,
    pub schema: i64,
    pub version: String,
    #[serde(with = "time_text")]
    pub created_at: Time,
    /// The peer URL this server's armada-kv member takes when the state
    /// moves (ADR 0057); empty for a release that cannot run armada-kv.
    #[serde(rename = "KvPeerURL", skip_serializing_if = "String::is_empty")]
    pub kv_peer_url: String,
}

/// An issued certificate on record.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct NodeCert {
    pub serial: String,
    #[serde(with = "time_text")]
    pub not_after: Time,
}

/// A deployed application.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct App {
    pub name: String,
    pub active_revision: String,
    pub target_revision: String,
    pub replicas: i64,
    #[serde(serialize_with = "spec_json")]
    pub spec: Option<Arc<Spec>>,
    pub rollout_state: String,
    pub rollout_message: String,
    #[serde(with = "time_text")]
    pub rollout_progress_at: Time,
    #[serde(with = "time_text")]
    pub created_at: Time,
    #[serde(with = "time_text")]
    pub updated_at: Time,
    #[serde(with = "time_text")]
    pub last_scheduled: Time,
    #[serde(serialize_with = "traffic_json")]
    pub traffic: Vec<TrafficTarget>,
    pub removing: bool,
    #[serde(with = "time_text")]
    pub scaled_at: Time,
}

impl App {
    /// Rolling reports whether a rollout is in progress.
    pub fn rolling(&self) -> bool {
        self.rollout_state == ROLLOUT_PROGRESSING && self.target_revision != self.active_revision
    }
}

/// An immutable snapshot of an app spec.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Revision {
    pub name: String,
    pub app: String,
    pub seq: i64,
    #[serde(serialize_with = "spec_json")]
    pub spec: Option<Arc<Spec>>,
    pub image_digest: String,
    pub platforms: Vec<String>,
    pub secrets: BTreeMap<String, i64>,
    #[serde(with = "time_text")]
    pub created_at: Time,
}

impl Revision {
    /// The spec, which every stored revision has.
    pub fn spec(&self) -> &Spec {
        self.spec.as_deref().expect("a stored revision has a spec")
    }

    /// Image: the digest-pinned reference if known, else the spec's.
    pub fn image(&self) -> String {
        if !self.image_digest.is_empty() {
            return self.image_digest.clone();
        }
        self.spec().image.clone()
    }
}

/// One scheduled instance of a revision on a node.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Replica {
    #[serde(rename = "ID")]
    pub id: String,
    pub app: String,
    pub revision: String,
    #[serde(rename = "NodeID")]
    pub node_id: String,
    pub state: String,
    #[serde(rename = "ContainerID")]
    pub container_id: String,
    pub address: String,
    #[serde(rename = "IP")]
    pub ip: String,
    pub message: String,
    pub ready: bool,
    #[serde(with = "time_text")]
    pub ready_since: Time,
    #[serde(with = "time_text")]
    pub draining_since: Time,
    #[serde(with = "time_text")]
    pub moving_since: Time,
    #[serde(with = "time_text")]
    pub updated_at: Time,
    #[serde(with = "time_text")]
    pub created_at: Time,
    pub restarts: i64,
    #[serde(with = "time_text")]
    pub last_restart_at: Time,
    pub last_restart: String,
    pub run: i64,
    pub done: bool,
    pub finished: bool,
    pub exit_code: i64,
    pub task: i64,
    pub held: bool,
}

impl Default for Replica {
    fn default() -> Replica {
        Replica {
            id: String::new(),
            app: String::new(),
            revision: String::new(),
            node_id: String::new(),
            state: String::new(),
            container_id: String::new(),
            address: String::new(),
            ip: String::new(),
            message: String::new(),
            ready: false,
            ready_since: Time::zero(),
            draining_since: Time::zero(),
            moving_since: Time::zero(),
            updated_at: Time::zero(),
            created_at: Time::zero(),
            restarts: 0,
            last_restart_at: Time::zero(),
            last_restart: String::new(),
            run: 0,
            done: false,
            finished: false,
            exit_code: 0,
            task: 0,
            held: false,
        }
    }
}

impl Replica {
    pub fn moving(&self) -> bool {
        !self.moving_since.is_zero()
    }
    pub fn draining(&self) -> bool {
        !self.draining_since.is_zero()
    }
}

/// ReplicaFilter restricts ListReplicas; empty fields match everything.
#[derive(Clone, Debug, Default)]
pub struct ReplicaFilter {
    pub app: String,
    pub node_id: String,
}

/// The actual state of a replica as its agent reports it.
#[derive(Clone, Debug, Default)]
pub struct ReplicaStatus {
    pub id: String,
    pub state: String,
    pub container_id: String,
    pub address: String,
    pub ip: String,
    pub message: String,
    pub ready: bool,
    pub finished: bool,
    pub exit_code: i64,
}

/// What an agent reports about its node.
#[derive(Clone, Debug)]
pub struct NodeStatus {
    pub state: String,
    pub last_seen: Time,
    pub cpu_millis: i64,
    pub memory_bytes: i64,
    pub version: String,
    pub os: String,
    pub arch: String,
    pub jobs: bool,
    pub volumes: bool,
    pub containers: bool,
    pub nfs: bool,
    pub egress: bool,
    pub network_key: String,
    pub endpoint: String,
    pub behind_nat: bool,
}

impl Default for NodeStatus {
    fn default() -> NodeStatus {
        NodeStatus {
            state: String::new(),
            last_seen: Time::zero(),
            cpu_millis: 0,
            memory_bytes: 0,
            version: String::new(),
            os: String::new(),
            arch: String::new(),
            jobs: false,
            volumes: false,
            containers: false,
            nfs: false,
            egress: false,
            network_key: String::new(),
            endpoint: String::new(),
            behind_nat: false,
        }
    }
}

/// A custom domain referenced by at least one app.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Domain {
    pub name: String,
    pub token: String,
    pub verified: bool,
    #[serde(with = "time_text")]
    pub verified_at: Time,
    pub message: String,
    #[serde(with = "time_text")]
    pub created_at: Time,
}

/// The latest version of a secret's key, never its value.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SecretInfo {
    pub app: String,
    pub name: String,
    pub version: i64,
    #[serde(with = "time_text")]
    pub updated_at: Time,
    pub updated_by: String,
    pub used_by: Vec<String>,
}

/// One secret of a space, never its values.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SpaceSecret {
    #[serde(rename = "ID")]
    pub id: String,
    pub name: String,
    pub keys: i64,
    #[serde(with = "time_text")]
    pub updated_at: Time,
    pub updated_by: String,
    pub used_by: Vec<String>,
}

/// A change to desired state.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuditEvent {
    #[serde(rename = "ID")]
    pub id: i64,
    #[serde(with = "time_text")]
    pub at: Time,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
}

/// The checks of a deploy a person or tool asked for (ADR 0032).
#[derive(Clone, Debug, Default)]
pub struct DeployOptions {
    pub must_create: bool,
    pub must_exist: bool,
    pub base_revision: String,
}

/// Something the cluster did (ADR 0018).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Event {
    pub key: String,
    pub kind: String,
    pub object: String,
    pub app: String,
    pub node: String,
    pub reason: String,
    pub message: String,
    pub count: i64,
    #[serde(with = "time_text")]
    pub first: Time,
    #[serde(with = "time_text")]
    pub last: Time,
}

/// A persistent volume of an app (ADR 0023).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Volume {
    pub app: String,
    pub name: String,
    pub node: String,
    #[serde(with = "time_text")]
    pub created_at: Time,
    pub backup: VolumeBackupState,
}

/// The outcome of a volume's backups (ADR 0041).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct VolumeBackupState {
    #[serde(with = "time_text")]
    pub last_at: Time,
    #[serde(rename = "LastID")]
    pub last_id: String,
    #[serde(with = "time_text")]
    pub failed_at: Time,
    pub error: String,
    pub stored: i64,
    pub snapshots: i64,
}

/// A space (ADR 0026).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Space {
    pub name: String,
    #[serde(with = "time_text")]
    pub created_at: Time,
    pub created_by: String,
}

/// A role given to a principal, in a space or over the cluster.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Grant {
    pub role: String,
    pub space: String,
}

impl std::fmt::Display for Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.space.is_empty() {
            f.write_str(&self.role)
        } else {
            write!(f, "{} in {}", self.role, self.space)
        }
    }
}

/// A user or a service and what it may do (ADR 0033).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Principal {
    pub kind: String,
    pub name: String,
    pub roles: Vec<Grant>,
    pub labels: BTreeMap<String, Vec<String>>,
    #[serde(with = "time_text")]
    pub created_at: Time,
    pub created_by: String,
    #[serde(with = "time_text")]
    pub since: Time,
    pub since_serial: String,
    pub removed: bool,
    pub certs: Vec<NodeCert>,
}

impl Default for Principal {
    fn default() -> Principal {
        Principal {
            kind: String::new(),
            name: String::new(),
            roles: Vec::new(),
            labels: BTreeMap::new(),
            created_at: Time::zero(),
            created_by: String::new(),
            since: Time::zero(),
            since_serial: String::new(),
            removed: false,
            certs: Vec::new(),
        }
    }
}

impl Principal {
    /// Has reports whether p holds g.
    pub fn has(&self, g: &Grant) -> bool {
        self.roles.contains(g)
    }
}

/// A metrics scraper and its certificates on record.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MetricsCredential {
    pub name: String,
    pub certs: Vec<NodeCert>,
}

/// One run of a job (ADR 0019).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct JobRun {
    pub job: String,
    pub seq: i64,
    pub revision: String,
    pub trigger: String,
    pub state: String,
    pub attempts: i64,
    pub replica: String,
    pub node: String,
    pub exit_code: i64,
    pub message: String,
    #[serde(with = "time_text")]
    pub created_at: Time,
    #[serde(with = "time_text")]
    pub started_at: Time,
    #[serde(with = "time_text")]
    pub attempt_at: Time,
    #[serde(with = "time_text")]
    pub finished_at: Time,
    pub tasks: Vec<RunTask>,
}

impl JobRun {
    pub fn active(&self) -> bool {
        self.state == crate::jobs::RUN_PENDING || self.state == crate::jobs::RUN_RUNNING
    }
}

/// One task of a run with several.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RunTask {
    pub index: i64,
    pub state: String,
    pub attempts: i64,
    pub replica: String,
    pub node: String,
    pub exit_code: i64,
    pub message: String,
    #[serde(with = "time_text")]
    pub attempt_at: Time,
    #[serde(with = "time_text")]
    pub waiting_since: Time,
    #[serde(with = "time_text")]
    pub finished_at: Time,
}

//! The container runtime as the agent's loop sees it: the part of Go's
//! `runtime.Driver` and its optional interfaces the loop calls (ADR 0055).
//! The supervisor runtime over armada-node's library implements it in a
//! later part; the parity tests implement it with a fake the test drives.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::time::{Duration, SystemTime};

/// Labels set on every container Armada manages.
pub const LABEL_MANAGED: &str = "armada.managed";
pub const LABEL_APP: &str = "armada.app";
pub const LABEL_REVISION: &str = "armada.revision";
pub const LABEL_REPLICA: &str = "armada.replica";
pub const LABEL_SPEC_HASH: &str = "armada.spec-hash";
/// How many seconds without the control plane stop the container (ADR
/// 0041); absent: never.
pub const LABEL_FENCE_AFTER: &str = "armada.fence-after";
/// Armada's own infrastructure containers (the proxy).
pub const LABEL_SYSTEM: &str = "armada.system";
/// The role and name of an init container or sidecar (ADR 0038).
pub const LABEL_ROLE: &str = "armada.role";
pub const LABEL_CONTAINER: &str = "armada.container";

/// Roles of a replica's other containers.
pub const ROLE_INIT: &str = "init";
pub const ROLE_SIDECAR: &str = "sidecar";

/// Container states.
pub const STATE_CREATED: &str = "created";
pub const STATE_RUNNING: &str = "running";
pub const STATE_RESTARTING: &str = "restarting";
pub const STATE_EXITED: &str = "exited";
pub const STATE_PAUSED: &str = "paused";
pub const STATE_DEAD: &str = "dead";
/// A replica's container whose init containers or sidecars the runtime is
/// still starting.
pub const STATE_STARTING: &str = "starting";

/// The OCI runtimes a container may have been created with (ADR 0056):
/// crun for every new one, runc for those created before.
pub const OCI_RUNC: &str = "runc";
pub const OCI_CRUN: &str = "crun";

/// The runtimes and whose code runs them (AgentStatus.agent).
pub const AGENT_CONTAINERD: &str = "containerd";
pub const AGENT_SUPERVISOR_GO: &str = "supervisor-go";
pub const AGENT_SUPERVISOR_RUST: &str = "supervisor-rust";

/// A runtime's failure, with Go's texts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// runtime.ErrNotFound.
    NotFound,
    /// runtime.PlatformError: the image has no variant for the node.
    Platform {
        image: String,
        want: String,
        have: Vec<String>,
    },
    /// Anything else, as its text.
    Other(String),
}

impl Error {
    pub fn other(s: impl Into<String>) -> Error {
        Error::Other(s.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotFound => f.write_str("not found"),
            Error::Platform { image, want, have } => write!(
                f,
                "image {image} has no {want} variant (it has {})",
                have.join(", ")
            ),
            Error::Other(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// A pulled image.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Image {
    /// The digest-pinned reference, or "" when the runtime reports none.
    pub reference: String,
    /// The image's platforms as "os/arch", sorted; empty when unknown.
    pub platforms: Vec<String>,
}

/// Credentials for a private registry. Its Debug leaves the password out.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RegistryAuth {
    pub username: String,
    pub password: String,
    pub server_address: String,
}

impl fmt::Debug for RegistryAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}@{} (password redacted)",
            self.username, self.server_address
        )
    }
}

/// A host file bind-mounted read-only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileMount {
    pub source: String,
    pub target: String,
}

/// A persistent volume's mount (ADR 0023).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VolumeMount {
    pub source: String,
    pub target: String,
    pub shared: bool,
    pub read_only: bool,
}

/// An init container or sidecar of a replica (ADR 0038).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemberSpec {
    pub name: String,
    pub image: String,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub memory_bytes: i64,
    pub nano_cpus: i64,
    pub cpu_reserve_millis: i64,
    pub pids_limit: i64,
    pub files: Vec<FileMount>,
    pub volumes: Vec<VolumeMount>,
}

/// A container to run (runtime.ContainerSpec).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContainerSpec {
    pub name: String,
    pub image: String,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub labels: BTreeMap<String, String>,
    pub port: i64,
    pub host_ip: String,
    pub memory_bytes: i64,
    pub nano_cpus: i64,
    pub cpu_reserve_millis: i64,
    pub pids_limit: i64,
    pub files: Vec<FileMount>,
    pub dns: Vec<String>,
    pub dns_search: Vec<String>,
    pub volumes: Vec<VolumeMount>,
    pub init: Vec<MemberSpec>,
    pub sidecars: Vec<MemberSpec>,
}

/// The observed state of an init container or sidecar.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Member {
    pub id: String,
    pub name: String,
    pub role: String,
    pub state: String,
    pub exit_code: i64,
    pub started_at: Option<SystemTime>,
    /// The OCI runtime that created it, when the runtime says (ADR 0056):
    /// OCI_RUNC or OCI_CRUN; empty otherwise.
    pub oci_runtime: String,
}

/// The observed state of a container.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    pub labels: BTreeMap<String, String>,
    pub state: String,
    pub exit_code: i64,
    pub host_ip: String,
    pub host_port: i64,
    pub ip: String,
    pub started_at: Option<SystemTime>,
    pub members: Vec<Member>,
    pub start_error: String,
    /// The OCI runtime that created it, when the runtime says (ADR 0056):
    /// OCI_RUNC or OCI_CRUN; empty otherwise.
    pub oci_runtime: String,
}

impl Container {
    /// The init container that exited with another code than 0.
    pub fn failed_init(&self) -> Option<&Member> {
        self.members
            .iter()
            .find(|m| m.role == ROLE_INIT && m.state == STATE_EXITED && m.exit_code != 0)
    }

    /// A sidecar that no longer runs.
    pub fn stopped_sidecar(&self) -> Option<&Member> {
        self.members
            .iter()
            .find(|m| m.role == ROLE_SIDECAR && m.state != STATE_RUNNING)
    }

    /// Whether runc created it or one of its init containers and
    /// sidecars (ADR 0056): the agent moves it to crun.
    pub fn on_runc(&self) -> bool {
        self.oci_runtime == OCI_RUNC || self.members.iter().any(|m| m.oci_runtime == OCI_RUNC)
    }

    /// The label `k`, or "".
    pub fn label(&self, k: &str) -> &str {
        self.labels.get(k).map(String::as_str).unwrap_or("")
    }
}

/// What a container uses (ADR 0016).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// CPU time since the container started.
    pub cpu: Duration,
    pub memory_bytes: i64,
    pub egress_bytes: i64,
    pub network_lost: bool,
    pub oom_kills: i64,
}

/// How a node runs containers (ADR 0054).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentStatus {
    pub agent: String,
    pub go_images: bool,
    pub converted: bool,
    pub images_to_pull: i64,
    pub error: String,
    /// Containers runc created that are still on the node (ADR 0056):
    /// app containers, their init containers and sidecars, job attempts,
    /// and system containers.
    pub runc_containers: i64,
}

impl AgentStatus {
    /// Whether anything of Go's runtime is left on a supervisor-rust node.
    pub fn converting(&self) -> bool {
        self.agent == AGENT_SUPERVISOR_RUST
            && (self.go_images || !self.converted || !self.error.is_empty())
    }
}

/// A container runtime as the agent uses it. Every method may be cancelled
/// by dropping its future (Go's context).
pub trait Runtime: Send + Sync + 'static {
    /// Checks the runtime is reachable.
    fn ping(&self) -> impl Future<Output = Result<()>> + Send;
    /// Told when the agent starts, after ping (runtime.AgentStarter); an
    /// error is only logged.
    fn agent_start(&self) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }
    /// Pulls image for the node's platform.
    fn pull(
        &self,
        image: &str,
        auth: Option<&RegistryAuth>,
    ) -> impl Future<Output = Result<Image>> + Send;
    /// Creates and starts a container.
    fn run(&self, spec: &ContainerSpec) -> impl Future<Output = Result<String>> + Send;
    /// Stops a container, then its sidecars, each with grace.
    fn stop(&self, id: &str, grace: Duration) -> impl Future<Output = Result<()>> + Send;
    /// Removes a container with its init containers and sidecars.
    fn remove(&self, id: &str) -> impl Future<Output = Result<()>> + Send;
    /// Containers carrying every label given.
    fn list(
        &self,
        labels: &BTreeMap<String, String>,
    ) -> impl Future<Output = Result<Vec<Container>>> + Send;
    fn inspect(&self, id: &str) -> impl Future<Output = Result<Container>> + Send;

    /// Whether it runs init containers and sidecars.
    fn can_run_members(&self) -> bool {
        false
    }
    /// Whether it mounts volumes into app containers.
    fn can_mount_volumes(&self) -> bool {
        false
    }
    /// Whether it runs commands in app containers (exec_app).
    fn can_exec(&self) -> bool {
        false
    }
    /// Runs cmd in a running app container with its output dropped and
    /// returns the exit code (probes' commands).
    fn exec_app(&self, _id: &str, _cmd: &[String]) -> impl Future<Output = Result<i64>> + Send {
        async { Err(Error::other("this runtime runs no commands")) }
    }
    /// Whether it samples containers (stats).
    fn can_stats(&self) -> bool {
        false
    }
    fn stats(&self, _id: &str) -> impl Future<Output = Result<Stats>> + Send {
        async { Err(Error::other("this runtime samples no containers")) }
    }
    /// Samples many containers in one round (runtime.StatsBatcher); None
    /// when it has no such call.
    fn stats_batch(
        &self,
        _ids: &[String],
    ) -> impl Future<Output = Option<Vec<Result<Stats>>>> + Send {
        async { None }
    }
    /// Frees a kept container's network (runtime.NetworkReleaser); None
    /// when it has no such call.
    fn release_network(&self, _id: &str) -> impl Future<Output = Option<Result<()>>> + Send {
        async { None }
    }
    /// Removes unneeded images (runtime.ImagePruner); None when it has no
    /// such call.
    fn prune_images(
        &self,
        _keep: &[String],
        _grace: Duration,
    ) -> impl Future<Output = Option<Result<Vec<String>>>> + Send {
        async { None }
    }
    /// How the node runs containers (runtime.AgentReporter); None when it
    /// does not say.
    fn runtime_agent(&self) -> impl Future<Output = Option<AgentStatus>> + Send {
        async { None }
    }
    /// Whether it keeps network sandboxes (runtime.CanSandbox).
    fn can_sandbox(&self) -> bool {
        false
    }
    /// Whether it keeps a log history (runtime.LogSearcher).
    fn has_log_history(&self) -> bool {
        false
    }
    /// Whether it tails logs for export (runtime.LogTailer).
    fn tails_logs(&self) -> bool {
        false
    }

    // The sessions and loops beside the reconcile pass (ADR 0055 item 16,
    // third part): exec, logs, queues, and sandboxes. Their types are in
    // crate::side.

    /// Runs a command in a running app container (or sidecar) with its
    /// streams (runtime.Execer's ExecApp): input until its channel ends,
    /// output in the order written, resizes of a terminal. It returns the
    /// exit code once the command ended and its output was sent.
    fn exec_session(
        &self,
        _id: &str,
        _opts: crate::side::ExecOptions,
    ) -> impl Future<Output = Result<i64>> + Send {
        async { Err(Error::other("this runtime runs no commands")) }
    }
    /// A container's output (Driver.Logs): frames until the channel ends.
    fn logs(
        &self,
        _id: &str,
        _opts: &crate::side::LogOptions,
    ) -> impl Future<Output = Result<crate::side::LogFrames>> + Send {
        async { Err(Error::other("this runtime keeps no logs")) }
    }
    /// Searches the log history (runtime.LogSearcher): the newest matching
    /// entries, oldest first, and a notice when it stopped early.
    fn search_logs(
        &self,
        _q: &crate::side::LogQuery,
    ) -> impl Future<Output = Result<(Vec<crate::side::LogRecord>, String)>> + Send {
        async { Err(Error::other("this node keeps no log history")) }
    }
    /// Whether it bounds its log history (runtime.LogPruner).
    fn prunes_logs(&self) -> bool {
        false
    }
    fn prune_logs(
        &self,
        _retention: Duration,
        _max_bytes: i64,
    ) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }
    /// Whether tail_logs renders requests itself
    /// (runtime.EncodingLogTailer).
    fn encodes_logs(&self) -> bool {
        false
    }
    /// Output written since the last committed tail for target, at most
    /// about max_bytes (runtime.LogTailer); rendered as requests when enc
    /// is given and the runtime encodes.
    fn tail_logs(
        &self,
        _target: &str,
        _max_bytes: i64,
        _enc: Option<&crate::side::LogEncoding>,
    ) -> impl Future<Output = Result<crate::side::LogTail>> + Send {
        async { Err(Error::other("this runtime tails no logs")) }
    }
    /// Whether it dials from containers (runtime.CanDial).
    fn can_dial(&self) -> bool {
        false
    }
    /// A socket connected to address (an IP and port) from the network
    /// namespace of the running container id (runtime.ContainerDialer).
    fn dial_container(
        &self,
        _id: &str,
        _network: &str,
        _address: &str,
    ) -> impl Future<Output = Result<std::os::fd::OwnedFd>> + Send {
        async {
            Err(Error::other(
                "this node's runtime cannot dial from containers",
            ))
        }
    }
    /// Reads a Redis or RabbitMQ queue's length from the container's
    /// network namespace (runtime.QueueReader); errors are queuelen's
    /// texts.
    fn read_queue(
        &self,
        _container: &str,
        _q: &crate::side::QueueRead,
    ) -> impl Future<Output = Result<i64>> + Send {
        async { Err(Error::other(crate::side::queue::ERR_DIAL)) }
    }
    /// Network sandboxes for job queues (runtime.NetworkSandboxer).
    fn ensure_sandbox(
        &self,
        _id: &str,
    ) -> impl Future<Output = Result<crate::side::Sandbox>> + Send {
        async { Err(Error::other("this runtime keeps no network sandboxes")) }
    }
    fn remove_sandbox(&self, _id: &str) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }
    fn list_sandboxes(&self) -> impl Future<Output = Result<Vec<crate::side::Sandbox>>> + Send {
        async { Ok(Vec::new()) }
    }
    fn dial_sandbox(
        &self,
        _id: &str,
        _network: &str,
        _address: &str,
    ) -> impl Future<Output = Result<std::os::fd::OwnedFd>> + Send {
        async { Err(Error::other("this runtime keeps no network sandboxes")) }
    }
    fn read_sandbox_queue(
        &self,
        _id: &str,
        _q: &crate::side::QueueRead,
    ) -> impl Future<Output = Result<i64>> + Send {
        async { Err(Error::other(crate::side::queue::ERR_DIAL)) }
    }
}

/// Whether a container in `state` has stopped.
pub fn stopped(state: &str) -> bool {
    matches!(state, STATE_EXITED | STATE_DEAD | STATE_CREATED)
}

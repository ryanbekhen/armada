//! The sessions and loops beside the reconcile pass (ADR 0055 item 16,
//! third part; Go's exec.go, agent.go's serveLogs, loghistory.go,
//! logexport.go, volume.go, backup.go, nativevolume.go, nativesnapshot.go,
//! queue.go, sandbox.go, nfs.go, and usage.go's volumes and connection
//! tracking): exec, log, and volume sessions the control plane opens on
//! the Connect stream, the log history's prune, the log export, queue
//! readings, network sandboxes for job queues, NFS volumes, and what usage
//! reports say of them.
//!
//! Volume archives, restores, sizes, and backups ([`volume::Volumes`]),
//! NFS mounts ([`nfs::Nfs`]), and the connection tracking table
//! ([`conntrack::Conntrack`]) are seams; their implementations here run
//! the runtime pack's armada-node as Go's agent does (nativevolume.go,
//! nativesnapshot.go, nfs.go, conntrack.Table.WithProgram), with no Go
//! fallback: there is one implementation.

pub mod conntrack;
pub mod dns;
mod exec;
pub mod logexport;
pub mod logs;
pub mod nfs;
pub mod nodeprog;
pub mod queue;
pub mod sandbox;
pub mod volume;

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI32};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use armada_proto::armada::v1 as pb;
use tokio::sync::{Semaphore, mpsc, watch};

use crate::agent::{Agent, Inner, lock};
use crate::proxy::BoxFut;
use crate::runtime::Runtime;
use crate::session::ServerConn;

pub use queue::QueueLengths;
pub use sandbox::Sandboxes;

/// A terminal's size in character cells.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TermSize {
    pub rows: u16,
    pub cols: u16,
}

/// Output of a command: stdout (true) or stderr, as written.
pub type Output = (bool, Vec<u8>);

/// What an exec runs and its streams (runtime.ExecOptions).
#[derive(Default)]
pub struct ExecOptions {
    pub cmd: Vec<String>,
    pub tty: bool,
    pub size: TermSize,
    /// None: no input; the channel's end is the input's end.
    pub stdin: Option<mpsc::Receiver<Vec<u8>>>,
    /// None: the output is dropped.
    pub output: Option<mpsc::Sender<Output>>,
    pub resize: Option<mpsc::Receiver<TermSize>>,
}

/// How a container's output is read (runtime.LogOptions).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogOptions {
    pub follow: bool,
    /// 0 means all, negative none (with follow: only new output).
    pub tail: i64,
    /// Keeps lines containing it, ignoring case (lower case; empty: all).
    pub grep: String,
}

/// One write of a container (runtime.LogFrame).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogFrame {
    pub stderr: bool,
    pub data: Vec<u8>,
    /// When the line was written, if the runtime says.
    pub time: Option<SystemTime>,
}

/// A container's output, until the channel ends (EOF).
pub type LogFrames = mpsc::Receiver<crate::runtime::Result<LogFrame>>;

/// A window of an app's output from the node's log history (ADR 0043).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogQuery {
    pub app: String,
    pub replica: String,
    pub container: String,
    pub since: SystemTime,
    /// None: now.
    pub until: Option<SystemTime>,
    pub grep: String,
    pub limit: i64,
    pub max_bytes: i64,
}

/// One entry of the log history or of a tail (runtime.LogRecord).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRecord {
    pub time: SystemTime,
    pub stderr: bool,
    pub data: Vec<u8>,
    pub replica: String,
    pub container: String,
    /// Set by tails.
    pub app: String,
    pub revision: String,
}

/// How an encoding runtime renders a tail (runtime.LogEncoding; the split
/// of app IDs is armada-spec's).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEncoding {
    pub format: String,
    pub node: String,
    pub batch_records: i64,
    pub batch_bytes: i64,
}

/// Records a tail as sent.
pub type CommitFn =
    Box<dyn FnOnce() -> BoxFut<'static, crate::runtime::Result<()>> + Send + 'static>;

/// Output a tail read (runtime.LogTail).
#[derive(Default)]
pub struct LogTail {
    pub records: Vec<LogRecord>,
    /// Requests already rendered by the runtime, when it encodes.
    pub bodies: Option<Vec<Vec<u8>>>,
    /// The bytes of output the bodies carry.
    pub size: i64,
    pub commit: Option<CommitFn>,
}

/// One reading of a queue's length (runtime.QueueRead). The URL holds the
/// broker's credentials, so Debug leaves it out.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct QueueRead {
    /// "redis" or "rabbitmq".
    pub kind: String,
    pub url: String,
    pub name: String,
    /// The broker's addresses when the URL names it by a name, resolved
    /// from the same namespace, tried in order.
    pub addresses: Vec<SocketAddr>,
}

impl fmt::Debug for QueueRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "queue {} {}", self.kind, self.name)
    }
}

/// A network sandbox (runtime.Sandbox).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sandbox {
    pub id: String,
    pub ip: String,
}

/// How the sessions and loops are set up (Go's agent.Config, their part).
#[derive(Clone)]
pub struct SideConfig {
    /// How often queue rules are read (ADR 0034).
    pub queue_interval: Duration,
    /// Reads every job queue that often instead of its trigger's polling
    /// interval (tests; ADR 0040).
    pub sandbox_interval: Option<Duration>,
    /// How often the log history is bounded (ADR 0043).
    pub log_prune: Duration,
    /// How often new output is sent to the log endpoint (ADR 0044).
    pub log_export: Duration,
    /// How often volumes are measured (ADR 0023).
    pub volume_interval: Duration,
    /// Holds the mount points of NFS volumes (ADR 0042); empty disables
    /// them.
    pub nfs_dir: String,
    /// Mounts, reads, and unmounts NFS exports; None: the node mounts none.
    pub nfs: Option<Arc<dyn nfs::Nfs>>,
    /// Archives, restores, measures, and backs up volumes; None: volume
    /// sessions fail and volumes are not measured.
    pub volumes: Option<Arc<dyn volume::Volumes>>,
    /// The node's connection tracking table; None leaves it alone.
    pub conntrack: Option<Arc<dyn conntrack::Conntrack>>,
    /// The TLS configuration of the log export's requests (tests); None:
    /// the machine's roots.
    pub export_tls: Option<Arc<rustls::ClientConfig>>,
}

impl Default for SideConfig {
    fn default() -> SideConfig {
        SideConfig {
            queue_interval: queue::DEFAULT_QUEUE_INTERVAL,
            sandbox_interval: None,
            log_prune: logs::LOG_PRUNE_EVERY,
            log_export: logexport::LOG_EXPORT_EVERY,
            volume_interval: volume::VOLUME_MEASURE_EVERY,
            nfs_dir: String::new(),
            nfs: None,
            volumes: None,
            conntrack: None,
            export_tls: None,
        }
    }
}

/// The server's side of a bidirectional session stream. The call is
/// started at once and its answer awaited only when the agent reads: the
/// server answers the stream's headers once it read the agent's first
/// message, as grpc-go's streams allow.
pub(crate) struct Inbound<T> {
    call: Option<
        tokio::task::JoinHandle<Result<tonic::Response<tonic::Streaming<T>>, tonic::Status>>,
    >,
    stream: Option<tonic::Streaming<T>>,
}

impl<T: Send + 'static> Inbound<T> {
    pub(crate) fn new(
        call: impl Future<Output = Result<tonic::Response<tonic::Streaming<T>>, tonic::Status>>
        + Send
        + 'static,
    ) -> Inbound<T> {
        Inbound {
            call: Some(tokio::spawn(call)),
            stream: None,
        }
    }

    /// The next message, None at the stream's end, or why it failed.
    pub(crate) async fn next(&mut self) -> Result<Option<T>, String> {
        if let Some(c) = self.call.take() {
            match c.await {
                Ok(Ok(r)) => self.stream = Some(r.into_inner()),
                Ok(Err(e)) => return Err(e.message().to_string()),
                Err(e) => return Err(e.to_string()),
            }
        }
        match self.stream.as_mut() {
            None => Ok(None),
            Some(s) => s.message().await.map_err(|e| e.message().to_string()),
        }
    }

    /// The next message; None at the stream's end or failure.
    pub(crate) async fn message(&mut self) -> Option<T> {
        self.next().await.ok().flatten()
    }

    /// Reads until the server ends the stream.
    pub(crate) async fn drain(&mut self) {
        while self.message().await.is_some() {}
    }
}

use std::future::Future;

/// One lock per key (Go's keyedMutex).
#[derive(Default)]
pub struct KeyedMutex {
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl KeyedMutex {
    pub async fn lock(&self, key: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let l = lock(&self.locks)
            .entry(key.to_string())
            .or_default()
            .clone();
        l.lock_owned().await
    }
}

/// What the sessions and loops keep (Go's Agent fields of their part).
pub struct Side {
    /// The connection the session opens streams on.
    pub conn: Mutex<Option<Arc<ServerConn>>>,
    /// Log requests in flight, cancelled by LogCancel.
    pub cancels: Mutex<HashMap<String, watch::Sender<bool>>>,
    /// Running exec sessions (MAX_EXEC_SESSIONS).
    pub execs: AtomicI32,
    /// The live log streams and history searches served at once.
    pub live_logs: Arc<Semaphore>,
    pub searches: Arc<Semaphore>,
    /// The latest Assignment.logs; None before the first assignment.
    pub logs: Mutex<Option<pb::LogSettings>>,
    /// How sending logs goes, for usage reports.
    pub export: Mutex<Option<pb::LogExportStatus>>,
    pub queues: QueueLengths,
    pub sb: Sandboxes,
    /// One backup operation per volume, one mount per NFS volume.
    pub repos: KeyedMutex,
    pub nfs_mounts: KeyedMutex,
    /// Whether a failure to raise the conntrack limit was logged.
    pub conntrack_warned: AtomicBool,
    /// When volumes were last measured.
    pub measured: Mutex<Option<tokio::time::Instant>>,
}

impl Default for Side {
    fn default() -> Side {
        Side {
            conn: Mutex::new(None),
            cancels: Mutex::new(HashMap::new()),
            execs: AtomicI32::new(0),
            live_logs: Arc::new(Semaphore::new(logs::MAX_LIVE_LOGS)),
            searches: Arc::new(Semaphore::new(logs::MAX_SEARCHES)),
            logs: Mutex::new(None),
            export: Mutex::new(None),
            queues: QueueLengths::default(),
            sb: Sandboxes::default(),
            repos: KeyedMutex::default(),
            nfs_mounts: KeyedMutex::default(),
            conntrack_warned: AtomicBool::new(false),
            measured: Mutex::new(None),
        }
    }
}

/// Go's strconv.Quote for the texts that name things.
pub(crate) fn quote(s: &str) -> String {
    armada_spec::go::quote(s)
}

type Timestamp = armada_proto::google::protobuf::Timestamp;

/// timestamppb.New.
pub(crate) fn ts(t: SystemTime) -> Timestamp {
    let n = crate::clock::unix_nanos(t);
    Timestamp {
        seconds: n.div_euclid(1_000_000_000) as i64,
        nanos: n.rem_euclid(1_000_000_000) as i32,
    }
}

impl<R: Runtime> Inner<R> {
    /// The usage report's volumes, connection tracking, queues, sandboxes,
    /// and log export (usageLoop's part).
    pub(crate) async fn side_usage(&self, report: &mut pb::UsageReport) {
        if self.mounts_volumes() {
            let due = lock(&self.side.measured)
                .is_none_or(|m| m.elapsed() >= self.cfg.side.volume_interval);
            if due && let Some(v) = self.measure_volumes().await {
                report.volumes = v;
                report.volumes_measured = true;
                *lock(&self.side.measured) = Some(tokio::time::Instant::now());
            }
        }
        self.sample_conntrack(report).await;
        let now = SystemTime::now();
        report.queues = self
            .side
            .queues
            .fresh(now, 2 * self.cfg.side.queue_interval);
        report.sandboxes = self.sandbox_report(now);
        report.dropped_sandboxes = self.dropped_sandboxes();
        report.log_export = lock(&self.side.export).clone();
    }
}

impl<R: Runtime> Agent<R> {
    /// The connection exec, log, and volume sessions open their streams
    /// on (set by run).
    pub fn set_connection(&self, conn: Arc<ServerConn>) {
        *lock(&self.inner.side.conn) = Some(conn);
    }

    /// Runs an exec request to its end.
    pub async fn serve_exec(&self, req: pb::ExecRequest) {
        self.inner.clone().serve_exec(req).await
    }

    /// Runs a log request to its end.
    pub async fn serve_logs(&self, req: pb::LogRequest) {
        self.inner.clone().serve_logs(req).await
    }

    /// Ends a log request.
    pub fn cancel_logs(&self, id: &str) {
        self.inner.cancel_logs(id)
    }

    /// Runs a volume request to its end.
    pub async fn serve_volume(&self, req: pb::VolumeRequest) {
        self.inner.clone().serve_volume(req).await
    }

    /// Bounds the log history with the cluster's settings.
    pub async fn prune_logs(&self) {
        self.inner.prune_logs().await
    }

    /// Reads every queue rule once.
    pub async fn measure_queues(&self) {
        self.inner.measure_queues().await
    }

    /// Makes the node's sandboxes match the assignment and starts the
    /// readings that are due.
    pub async fn sync_sandboxes(&self) {
        self.inner.sync_sandboxes().await
    }

    /// Whether no sandbox reading runs.
    pub fn sandbox_reads_idle(&self) -> bool {
        self.inner.side.sb.idle()
    }

    /// One round of the log export; the wait before the next.
    pub async fn export_round(&self, st: &mut logexport::ExportState) -> Duration {
        self.inner.export_round(st).await
    }

    /// Unmounts the NFS volumes no assigned replica names.
    pub async fn clean_nfs(&self) {
        let desired = lock(&self.inner.st).desired.clone().unwrap_or_default();
        self.inner.clean_nfs(&desired).await
    }
}

/// Timestamp.AsTime: the Unix epoch for none.
pub(crate) fn from_ts(t: Option<&Timestamp>) -> SystemTime {
    let t = t.cloned().unwrap_or_default();
    crate::clock::from_unix_nanos(i128::from(t.seconds) * 1_000_000_000 + i128::from(t.nanos))
}

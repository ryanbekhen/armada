//! The agent's loop: assignments in, containers reconciled, reports out

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use armada_proto::armada::v1 as pb;
use std::sync::atomic::AtomicI32;

use tokio::sync::{Notify, OnceCell, Semaphore, mpsc, watch};

use crate::check::{CheckFn, default_check};
use crate::clock::{self, Clock, SystemClock};
use crate::log::Logger;
use crate::network::Network;
use crate::probe::ProbeWorker;
use crate::proxy::{CachedCert, CertificateSource, Clients, InternalDns, Proxy};
use crate::runtime::{
    self, Container, Error, Image, LABEL_MANAGED, LABEL_REPLICA, LABEL_ROLE, LABEL_SPEC_HASH,
    RegistryAuth, Runtime, STATE_CREATED, STATE_RESTARTING, STATE_RUNNING, STATE_STARTING, stopped,
};
use crate::spec::{container_spec, has_members, member_images, registry_auth, spec_hash};

/// How often containers are reconciled without a trigger.
pub const DEFAULT_RESYNC: Duration = Duration::from_secs(10);
/// The replicas a node starts at a time.
pub const MAX_CONCURRENT_STARTS: usize = 8;
/// How often the server hears from an agent busy starting replicas.
pub const START_REPORT_INTERVAL: Duration = Duration::from_secs(1);
pub(crate) const STOP_GRACE: Duration = Duration::from_secs(10);
/// Recreates wait CRASH_BACKOFF, doubling up to MAX_CRASH_BACKOFF; the
/// count resets after CRASH_RESET without a crash.
pub const CRASH_BACKOFF: Duration = Duration::from_secs(1);
pub const MAX_CRASH_BACKOFF: Duration = Duration::from_secs(5 * 60);
pub const CRASH_RESET: Duration = Duration::from_secs(10 * 60);
/// Unused images are removed every DEFAULT_IMAGE_PRUNE once pulled more
/// than IMAGE_PRUNE_GRACE ago.
pub const DEFAULT_IMAGE_PRUNE: Duration = Duration::from_secs(10 * 60);
pub const IMAGE_PRUNE_GRACE: Duration = Duration::from_secs(3600);
/// How long an app's container gets to stop when it is cut off or paused
/// for a volume operation.
pub(crate) const VOLUME_STOP_GRACE: Duration = Duration::from_secs(30);
/// What a replica stopped for a volume operation reports.
pub(crate) const PAUSED_MESSAGE: &str = "stopped while its volume is backed up or restored";
/// Why a container started before the machine's boot is recreated.
pub const MACHINE_RESTARTED: &str = "the machine restarted";
/// The prefix of a restart's reason in a report.
pub const RESTART_NOTE: &str = "restarted: ";

/// Replica states reported.
pub const REPLICA_STARTING: &str = "starting";
pub const REPLICA_RUNNING: &str = "running";
pub const REPLICA_EXITED: &str = "exited";
pub const REPLICA_FAILED: &str = "failed";
pub const REPLICA_PULLING: &str = "pulling";
pub const REPLICA_PULLED: &str = "pulled";

/// How an Agent is set up.
#[derive(Clone)]
pub struct Config {
    pub node_id: String,
    pub private_ip: String,
    pub logger: Logger,
    /// How often containers are reconciled without a trigger.
    pub resync: Duration,
    /// How often replicas are sampled (ADR 0016).
    pub usage_interval: Duration,
    /// How often unused images are removed; None turns it off.
    pub image_prune: Option<Duration>,
    /// When the machine last booted; None reads /proc/stat.
    pub boot_time: Option<SystemTime>,
    /// Capacity reported to the scheduler; 0 is detected.
    pub cpu_millis: i64,
    pub memory_bytes: i64,
    /// Replicas publish no port and are reported at their own address.
    pub unpublished: bool,
    /// Runs health checks (default: default_check).
    pub check: Option<CheckFn>,
    /// Holds persistent volumes; empty: the node mounts none.
    pub volumes_dir: String,
    /// A private tmpfs directory for secret files; empty: replicas with
    /// secret files fail to start.
    pub secrets_dir: String,
    /// The node's resolver for `<app>.internal`; None leaves containers
    /// with the runtime's default.
    pub dns: Option<Arc<dyn InternalDns>>,
    /// The node's proxy; None: no ingress on this node.
    pub proxy: Option<Arc<dyn Proxy>>,
    /// The cluster network; None when the node is not part of one.
    pub network: Option<Arc<dyn Network>>,
    /// Where certificates named by reference come from; None: the
    /// session's connection.
    pub certificates: Option<Arc<dyn CertificateSource>>,
    /// Where the proxy sends requests for apps with no replica up (ADR
    /// 0021), in a directory only root reaches; empty disables it.
    pub wake_socket: String,
    /// The platform reported (default: this machine's, such as linux and
    /// amd64).
    pub os: String,
    pub arch: String,
    /// The control plane addresses; on_servers receives a new list.
    pub servers: Vec<String>,
    pub on_servers: Option<Arc<dyn Fn(Vec<String>) + Send + Sync>>,
    /// The node's WireGuard public key, mesh endpoint, and NAT (Hello).
    pub network_key: String,
    pub endpoint: String,
    pub behind_nat: bool,
    /// The agent's version in Hello.
    pub version: String,
    pub clock: Arc<dyn Clock>,
    /// The sessions and loops beside the reconcile pass.
    pub side: crate::side::SideConfig,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            node_id: String::new(),
            private_ip: String::new(),
            logger: Logger::discard(),
            resync: DEFAULT_RESYNC,
            usage_interval: crate::usage::DEFAULT_USAGE_INTERVAL,
            image_prune: Some(DEFAULT_IMAGE_PRUNE),
            boot_time: None,
            cpu_millis: 0,
            memory_bytes: 0,
            unpublished: false,
            check: None,
            volumes_dir: String::new(),
            secrets_dir: String::new(),
            dns: None,
            proxy: None,
            network: None,
            certificates: None,
            wake_socket: String::new(),
            os: String::new(),
            arch: String::new(),
            servers: Vec::new(),
            on_servers: None,
            network_key: String::new(),
            endpoint: String::new(),
            behind_nat: false,
            version: env!("CARGO_PKG_VERSION").to_string(),
            clock: Arc::new(SystemClock),
            side: crate::side::SideConfig::default(),
        }
    }
}

/// How often a replica's container stopped.
#[derive(Clone, Copy, Default)]
pub(crate) struct CrashLoop {
    pub count: u32,
    pub last: Option<SystemTime>,
    pub next: Option<SystemTime>,
}

/// The pull of a held replica's images (ADR 0023).
#[derive(Default)]
pub(crate) struct HeldPull {
    pub done: bool,
    pub err: Option<Error>,
    pub failed_at: Option<SystemTime>,
    pub platforms: Vec<String>,
}

/// What the agent knows, under one lock.
#[derive(Default)]
pub(crate) struct State {
    pub network_key: String,
    pub desired: Option<BTreeMap<String, pb::ReplicaSpec>>,
    pub servers: Vec<String>,
    pub digests: HashMap<String, String>,
    pub platforms: HashMap<String, Vec<String>>,
    pub probes: HashMap<String, Arc<ProbeWorker>>,
    /// Containers a probe asked to restart, with the reason.
    pub restarts: HashMap<String, String>,
    /// Why a replica was restarted, for its next reports.
    pub notes: HashMap<String, String>,
    pub crashes: HashMap<String, CrashLoop>,
    pub holds: HashMap<String, Arc<Mutex<HeldPull>>>,
    pub contact_up: bool,
    pub contact_lost: Option<SystemTime>,
    pub fenced_ids: HashSet<String>,
    /// The first recreate delay in nanoseconds (CRASH_BACKOFF).
    pub crash_base: i64,
    /// Apps paused for a volume operation (ADR 0023).
    pub paused: HashMap<String, i64>,
    pub proxy_desired: Option<pb::ProxyConfig>,
    pub proxy_applied: Option<pb::ProxyConfig>,
    /// Certificates fetched by reference, by name.
    pub certs: HashMap<String, CachedCert>,
    /// The last cluster network received, and the last error applying it
    /// (logged once per change).
    pub network_desired: Option<pb::NetworkConfig>,
    pub network_failed: String,
    /// This node's containers in the node subnet (unpublished only).
    pub local: Option<Clients>,
    /// Containers runc created, ended and created again on crun (ADR
    /// 0056).
    pub runc: crate::runcleft::RuncLeft,
}

/// The stream of the current session, if one is open.
#[derive(Default)]
pub(crate) struct StreamState {
    pub tx: Option<mpsc::Sender<pb::AgentMessage>>,
    pub last_sent: Option<pb::ReplicaReport>,
}

pub(crate) struct Inner<R: Runtime> {
    pub cfg: Config,
    pub rt: R,
    pub log: Logger,
    pub began: SystemTime,
    pub booted: Option<SystemTime>,
    pub st: Mutex<State>,
    pub reconcile_mu: tokio::sync::Mutex<()>,
    pub trigger: Notify,
    pub stream: Mutex<StreamState>,
    pub check: CheckFn,
    /// The session's certificate source.
    pub cert_source: Mutex<Option<Arc<dyn CertificateSource>>>,
    /// Counts proxy configurations applied.
    pub proxy_changed: watch::Sender<u64>,
    /// One key rotation at a time.
    pub key_mu: tokio::sync::Mutex<()>,
    /// Running volume sessions.
    pub volume_ops: AtomicI32,
    /// Requests held for apps scaled to zero (ADR 0021).
    pub wakes: crate::wake::Waker,
    /// What the sessions and loops beside the pass keep.
    pub side: crate::side::Side,
}

/// The node agent: reconciles the node's containers with the replicas the
/// control plane assigns.
pub struct Agent<R: Runtime> {
    pub(crate) inner: Arc<Inner<R>>,
}

impl<R: Runtime> Clone for Agent<R> {
    fn clone(&self) -> Self {
        Agent {
            inner: self.inner.clone(),
        }
    }
}

/// A replica Reconcile creates a container for.
#[derive(Clone)]
pub(crate) struct PendingStart {
    pub id: String,
    pub spec: pb::ReplicaSpec,
    pub hash: String,
    /// The container this start replaces; empty for a first start.
    pub replaced: String,
}

/// A replica with a container, whatever its state.
pub(crate) struct Running {
    pub spec: pb::ReplicaSpec,
    pub container: Container,
}

/// The labels of every container Armada manages.
pub(crate) fn managed() -> BTreeMap<String, String> {
    BTreeMap::from([(LABEL_MANAGED.to_string(), "true".to_string())])
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// This program's OS and architecture, named linux, amd64, arm64, and so on.
pub fn go_platform() -> (&'static str, &'static str) {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        a => a,
    };
    (std::env::consts::OS, arch)
}

impl<R: Runtime> Agent<R> {
    /// An agent for runtime `rt`.
    pub fn new(mut cfg: Config, rt: R) -> Agent<R> {
        if cfg.resync.is_zero() {
            cfg.resync = DEFAULT_RESYNC;
        }
        if cfg.usage_interval.is_zero() {
            cfg.usage_interval = crate::usage::DEFAULT_USAGE_INTERVAL;
        }
        if cfg.cpu_millis == 0 || cfg.memory_bytes == 0 {
            let (cpu, mem) = crate::boot::detect_capacity();
            if cfg.cpu_millis == 0 {
                cfg.cpu_millis = cpu;
            }
            if cfg.memory_bytes == 0 {
                cfg.memory_bytes = mem;
            }
        }
        let booted = cfg.boot_time.or_else(crate::boot::machine_boot);
        let log = cfg
            .logger
            .with("component", "agent")
            .with("node", &cfg.node_id);
        let check = cfg.check.clone().unwrap_or_else(default_check);
        let began = cfg.clock.now();
        let st = State {
            servers: cfg.servers.clone(),
            crash_base: CRASH_BACKOFF.as_nanos() as i64,
            ..State::default()
        };
        Agent {
            inner: Arc::new(Inner {
                cfg,
                rt,
                log,
                began,
                booted,
                st: Mutex::new(st),
                reconcile_mu: tokio::sync::Mutex::new(()),
                trigger: Notify::new(),
                stream: Mutex::new(StreamState::default()),
                check,
                cert_source: Mutex::new(None),
                proxy_changed: watch::channel(0).0,
                key_mu: tokio::sync::Mutex::new(()),
                volume_ops: AtomicI32::new(0),
                wakes: crate::wake::Waker::default(),
                side: crate::side::Side::default(),
            }),
        }
    }

    /// The runtime.
    pub fn runtime(&self) -> &R {
        &self.inner.rt
    }

    /// Takes an assignment: the network, the replicas and the proxy, the
    /// servers, the log settings, and the queue sandboxes.
    pub fn set_assignment(&self, a: &pb::Assignment) {
        self.inner.assign(a);
    }

    /// Asks for a reconcile as soon as possible.
    pub fn trigger(&self) {
        self.inner.trigger.notify_one();
    }

    /// Makes the node's containers match the assignment and returns their
    /// status; None before the first assignment.
    pub async fn reconcile(&self) -> runtime::Result<Option<pb::ReplicaReport>> {
        self.inner.reconcile().await
    }

    /// Removes images neither a container nor an assigned replica needs.
    pub async fn prune_images(&self) {
        self.inner.prune_images().await
    }

    /// Records whether a session with the server is open (fencing).
    pub fn set_contact(&self, up: bool) {
        self.inner.set_contact(up)
    }

    /// Stops fenced containers before the first assignment.
    pub async fn fence_unassigned(&self) {
        self.inner.fence_unassigned().await
    }

    /// Replaces the first recreate delay (tests).
    pub fn set_crash_base(&self, d: Duration) {
        lock(&self.inner.st).crash_base = d.as_nanos() as i64;
    }

    /// Stops every probe (the agent's end).
    pub fn shutdown(&self) {
        let mut st = lock(&self.inner.st);
        for (_, w) in st.probes.drain() {
            w.cancel();
        }
    }
}

impl<R: Runtime> Inner<R> {
    pub(crate) fn now(&self) -> SystemTime {
        self.cfg.clock.now()
    }

    pub(crate) fn set_servers(&self, servers: &[String]) {
        let Some(on) = &self.cfg.on_servers else {
            return;
        };
        if servers.is_empty() {
            return;
        }
        let changed = {
            let mut st = lock(&self.st);
            let changed = st.servers != servers;
            if changed {
                st.servers = servers.to_vec();
            }
            changed
        };
        if changed {
            on(servers.to_vec());
        }
    }

    /// One assignment from the server: network, replicas and proxy, servers,
    /// log settings, then sandboxes.
    pub(crate) fn assign(&self, a: &pb::Assignment) {
        self.set_network(a.network.as_ref());
        self.set_desired(&a.replicas, a.proxy.as_ref());
        self.set_servers(&a.servers);
        self.set_log_settings(a.logs.as_ref());
        if self.sandboxes_on() {
            self.set_sandboxes(&a.queue_sandboxes);
        }
    }

    pub(crate) fn set_desired(&self, replicas: &[pb::ReplicaSpec], px: Option<&pb::ProxyConfig>) {
        let d: BTreeMap<String, pb::ReplicaSpec> =
            replicas.iter().map(|r| (r.id.clone(), r.clone())).collect();
        {
            let mut st = lock(&self.st);
            st.desired = Some(d);
            if let Some(px) = px {
                st.proxy_desired = Some(px.clone());
            }
        }
        self.trigger.notify_one();
    }

    pub(crate) fn send_report(&self, r: &pb::ReplicaReport) {
        let mut s = lock(&self.stream);
        let Some(tx) = s.tx.clone() else { return };
        if s.last_sent.as_ref() == Some(r) {
            return;
        }
        let msg = pb::AgentMessage {
            msg: Some(pb::agent_message::Msg::Report(r.clone())),
        };
        if let Err(e) = tx.try_send(msg) {
            self.log
                .warn("send report failed", &[("err", e.to_string())]);
            return;
        }
        s.last_sent = Some(r.clone());
    }

    pub(crate) async fn prune_images(&self) {
        let _g = self.reconcile_mu.lock().await;
        let keep = {
            let st = lock(&self.st);
            let Some(desired) = &st.desired else { return };
            let mut keep = Vec::new();
            for s in desired.values() {
                for image in std::iter::once(s.image.clone()).chain(member_images(s)) {
                    keep.push(image.clone());
                    if let Some(r) = st.digests.get(&image).filter(|r| !r.is_empty()) {
                        keep.push(r.clone());
                    }
                }
            }
            keep
        };
        let Some(res) = self.rt.prune_images(&keep, IMAGE_PRUNE_GRACE).await else {
            return;
        };
        match res {
            Ok(removed) if !removed.is_empty() => self
                .log
                .info("removed unused images", &[("images", removed.join(" "))]),
            Ok(_) => {}
            Err(e) => self
                .log
                .warn("remove unused images", &[("err", e.to_string())]),
        }
    }

    pub(crate) async fn remove(&self, id: &str) {
        if let Err(e) = self.rt.stop(id, STOP_GRACE).await
            && e != Error::NotFound
        {
            self.log.warn(
                "stop failed",
                &[("container", id.to_string()), ("err", e.to_string())],
            );
        }
        if let Err(e) = self.rt.remove(id).await
            && e != Error::NotFound
        {
            self.log.warn(
                "remove failed",
                &[("container", id.to_string()), ("err", e.to_string())],
            );
        }
    }

    pub(crate) fn is_paused(&self, app: &str) -> bool {
        lock(&self.st).paused.get(app).copied().unwrap_or(0) > 0
    }

    pub(crate) async fn reconcile(self: &Arc<Self>) -> runtime::Result<Option<pb::ReplicaReport>> {
        let _g = self.reconcile_mu.lock().await;
        let Some(desired) = lock(&self.st).desired.clone() else {
            return Ok(None);
        };
        let containers = self.rt.list(&managed()).await?;
        self.forget_ended(&containers);

        let mut by_replica: BTreeMap<String, Container> = BTreeMap::new();
        let mut strays = Vec::new();
        for c in containers {
            let id = c.label(LABEL_REPLICA).to_string();
            let want = desired.contains_key(&id);
            let dup = by_replica.contains_key(&id);
            // An init container or sidecar listed by itself has lost its
            // replica's container (ADR 0038): removed like a stray.
            if !want || dup || !c.label(LABEL_ROLE).is_empty() {
                strays.push(c);
                continue;
            }
            by_replica.insert(id, c);
        }
        if !strays.is_empty() {
            // The proxy first: an agent back after a while may hold a
            // configuration that still routes to these replicas, and a
            // request sent to a removed container waits for its timeout.
            self.apply_proxy().await;
        }
        for c in &strays {
            self.log.info(
                "removing container",
                &[
                    ("container", c.name.clone()),
                    ("replica", c.label(LABEL_REPLICA).to_string()),
                ],
            );
            self.remove(&c.id).await;
        }

        let mut settled: Vec<pb::ReplicaState> = Vec::new();
        let mut running: Vec<Running> = Vec::new();
        let mut pending: Vec<PendingStart> = Vec::new();
        for (id, spec) in &desired {
            let hash = spec_hash(spec);
            let (c, mut ok) = match by_replica.get(id) {
                Some(c) => (c.clone(), true),
                None => (Container::default(), false),
            };
            if ok && c.label(LABEL_SPEC_HASH) != hash {
                self.log
                    .info("spec changed, recreating", &[("replica", id.clone())]);
                self.remove(&c.id).await;
                ok = false;
            }
            if self.fenced(spec) {
                // Cut off from the control plane: its volumes may be
                // restored on another node (ADR 0041).
                if ok && !stopped(&c.state) {
                    self.log.warn(
                        "stopping a replica cut off from the control plane",
                        &[("replica", id.clone())],
                    );
                    let _ = self.rt.stop(&c.id, VOLUME_STOP_GRACE).await;
                }
                if ok {
                    self.mark_fenced(&c.id);
                }
                self.stop_probes(id);
                settled.push(pb::ReplicaState {
                    id: id.clone(),
                    state: REPLICA_EXITED.into(),
                    container_id: c.id.clone(),
                    message: crate::fence::FENCED_MESSAGE.into(),
                    ..Default::default()
                });
                continue;
            }
            if ok && stopped(&c.state) && self.unfence(&c.id) {
                // Back in touch: start it again at once.
                self.remove(&c.id).await;
                ok = false;
            }
            if self.is_paused(&spec.app) && spec.job.is_none() {
                if ok && !stopped(&c.state) {
                    let _ = self.rt.stop(&c.id, VOLUME_STOP_GRACE).await;
                }
                self.stop_probes(id);
                settled.push(pb::ReplicaState {
                    id: id.clone(),
                    state: REPLICA_EXITED.into(),
                    container_id: c.id.clone(),
                    message: PAUSED_MESSAGE.into(),
                    ..Default::default()
                });
                continue;
            }
            if spec.hold {
                // Its volume is still in use by the old replica (ADR 0023).
                if ok {
                    self.log.info(
                        "removing container of a held replica",
                        &[("replica", id.clone())],
                    );
                    self.remove(&c.id).await;
                }
                self.stop_probes(id);
                settled.push(self.held(spec));
                continue;
            }
            if spec.job.is_some() {
                // An attempt runs once, whatever happens.
                lock(&self.st).restarts.remove(&c.id);
                if let Some(st) = self.attempt(spec, &hash, c, ok).await {
                    settled.push(st);
                }
                continue;
            }
            if ok {
                let restart = {
                    let mut st = lock(&self.st);
                    let r = st.restarts.remove(&c.id);
                    if let Some(reason) = &r {
                        st.notes
                            .insert(id.clone(), format!("{RESTART_NOTE}{reason}"));
                    }
                    r.is_some()
                };
                if restart {
                    self.remove(&c.id).await;
                    ok = false;
                }
            }
            if ok && c.on_runc() {
                // runc created it, and the runtime pack has no runc (ADR
                // 0056): ended through its cgroup, then created again on
                // crun, reported starting meanwhile.
                self.end_runc_replica(id, &c).await;
                ok = false;
            }
            if ok && (stopped(&c.state) || !crate::containers::member_down(spec, &c).is_empty()) {
                // The runtime restarts nothing itself (ADR 0011): crashes,
                // containers a reboot left exited, failed starts, and
                // replicas whose init container failed or sidecar stopped
                // are recreated here with crash backoff.
                let (msg, wait) = self.crashed(spec, &c).await;
                if wait > 0 {
                    settled.push(pb::ReplicaState {
                        id: id.clone(),
                        state: REPLICA_EXITED.into(),
                        container_id: c.id.clone(),
                        message: format!(
                            "{msg}; restarting in {}",
                            clock::duration_string(clock::round(wait, 1_000_000_000))
                        ),
                        ..Default::default()
                    });
                    continue;
                }
                self.log.warn(
                    "container stopped, recreating",
                    &[("replica", id.clone()), ("reason", msg.clone())],
                );
                lock(&self.st)
                    .notes
                    .insert(id.clone(), format!("{RESTART_NOTE}{msg}"));
                self.remove(&c.id).await;
                ok = false;
            }
            if !ok {
                let replaced = by_replica.get(id).map(|o| o.id.clone()).unwrap_or_default();
                pending.push(PendingStart {
                    id: id.clone(),
                    spec: spec.clone(),
                    hash,
                    replaced,
                });
                continue;
            }
            running.push(Running {
                spec: spec.clone(),
                container: c,
            });
        }
        let report = self.start_pending(pending, settled, running).await;
        self.forget_holds(&desired);
        self.clean_secret_files(&desired);
        self.clean_nfs(&desired).await;
        {
            let mut st = lock(&self.st);
            let gone: Vec<String> = st
                .probes
                .keys()
                .filter(|k| !desired.contains_key(*k))
                .cloned()
                .collect();
            for id in gone {
                if let Some(w) = st.probes.remove(&id) {
                    w.cancel();
                }
            }
            st.notes.retain(|k, _| desired.contains_key(k));
            st.crashes.retain(|k, _| desired.contains_key(k));
        }
        self.apply_network().await;
        self.apply_proxy().await;
        self.move_proxy_to_crun();
        Ok(Some(report))
    }

    /// The report of every replica (built for `start_pending`).
    fn build(
        self: &Arc<Self>,
        settled: &[pb::ReplicaState],
        pending: &[PendingStart],
        started: &HashSet<String>,
        running: &[Running],
    ) -> pb::ReplicaReport {
        let mut r = pb::ReplicaReport {
            replicas: settled.to_vec(),
        };
        for p in pending {
            if !p.replaced.is_empty() && !started.contains(&p.id) {
                r.replicas.push(self.recreating(p));
            }
        }
        for x in running {
            // In this order: a verdict seen here is one state reports.
            self.readiness(&x.spec, &x.container);
            if !self.awaits_verdict(&x.spec, &x.container) {
                r.replicas.push(self.state(&x.spec, &x.container));
            }
        }
        r.replicas.sort_by(|a, b| a.id.cmp(&b.id));
        r
    }

    /// Starts replicas, at most MAX_CONCURRENT_STARTS at a time, and
    /// returns the status of every replica, telling the server what it
    /// knows every START_REPORT_INTERVAL meanwhile. A replica starting for
    /// the first time is left out of the reports; one whose container is
    /// being recreated is reported starting with no address from the first
    /// report on (T21).
    async fn start_pending(
        self: &Arc<Self>,
        pending: Vec<PendingStart>,
        mut settled: Vec<pb::ReplicaState>,
        mut running: Vec<Running>,
    ) -> pb::ReplicaReport {
        let mut started = HashSet::new();
        if pending.is_empty() {
            return self.build(&settled, &pending, &started, &running);
        }
        // The server hears which replicas lost their address before any
        // new container can take one.
        self.send_report(&self.build(&settled, &pending, &started, &running));
        let (tx, mut rx) = mpsc::unbounded_channel();
        let pull = Arc::new(PullOnce::default());
        let limit = Arc::new(Semaphore::new(MAX_CONCURRENT_STARTS));
        {
            let inner = self.clone();
            let pending = pending.clone();
            tokio::spawn(async move {
                for p in pending {
                    let Ok(permit) = limit.clone().acquire_owned().await else {
                        return;
                    };
                    let inner = inner.clone();
                    let pull = pull.clone();
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        let r = inner.start(&p.spec, &p.hash, Some(&pull)).await;
                        drop(permit);
                        let _ = tx.send((p, r));
                    });
                }
            });
        }
        let mut finished: Vec<(PendingStart, runtime::Result<Container>)> = Vec::new();
        let absorb = |finished: &mut Vec<(PendingStart, runtime::Result<Container>)>,
                      started: &mut HashSet<String>,
                      running: &mut Vec<Running>,
                      settled: &mut Vec<pb::ReplicaState>| {
            for (p, r) in finished.drain(..) {
                started.insert(p.id.clone());
                match r {
                    Ok(c) => running.push(Running {
                        spec: p.spec,
                        container: c,
                    }),
                    Err(e) => {
                        self.log.error(
                            "start replica failed",
                            &[("replica", p.id.clone()), ("err", e.to_string())],
                        );
                        self.stop_probes(&p.id);
                        let mut failed = pb::ReplicaState {
                            id: p.id,
                            state: REPLICA_FAILED.into(),
                            message: e.to_string(),
                            ..Default::default()
                        };
                        // The server learns where the image can run.
                        if let Error::Platform { have, .. } = e {
                            failed.image_platforms = have;
                        }
                        settled.push(failed);
                    }
                }
            }
        };
        let mut tick = tokio::time::interval_at(
            tokio::time::Instant::now() + START_REPORT_INTERVAL,
            START_REPORT_INTERVAL,
        );
        let mut left = pending.len();
        // Finished starts become part of what is reported once the
        // firewall knows their containers.
        let firewall = self.cfg.unpublished && self.cfg.network.is_some();
        while left > 0 {
            tokio::select! {
                r = rx.recv() => {
                    let Some(r) = r else { break };
                    finished.push(r);
                    left -= 1;
                }
                _ = tick.tick() => {
                    if firewall && !finished.is_empty() {
                        self.apply_network_now().await;
                    }
                    absorb(&mut finished, &mut started, &mut running, &mut settled);
                    self.apply_proxy().await;
                    self.send_report(&self.build(&settled, &pending, &started, &running));
                }
            }
        }
        if firewall && !finished.is_empty() {
            self.apply_network_now().await;
        }
        absorb(&mut finished, &mut started, &mut running, &mut settled);
        self.build(&settled, &pending, &started, &running)
    }

    /// A replica whose container is being recreated: starting, not ready,
    /// no address, the old container's ID.
    pub(crate) fn recreating(&self, p: &PendingStart) -> pb::ReplicaState {
        let msg = lock(&self.st)
            .notes
            .get(&p.id)
            .cloned()
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| "recreating its container".to_string());
        pb::ReplicaState {
            id: p.id.clone(),
            state: REPLICA_STARTING.into(),
            container_id: p.replaced.clone(),
            message: msg,
            ..Default::default()
        }
    }

    /// Whether the kernel killed a process of a stopped container at its
    /// memory limit.
    async fn out_of_memory(&self, id: &str) -> bool {
        if !self.rt.can_stats() {
            return false;
        }
        matches!(self.rt.stats(id).await, Ok(s) if s.oom_kills > 0)
    }

    /// Why c stopped, and how long to wait before recreating it (0: now).
    async fn crashed(&self, s: &pb::ReplicaSpec, c: &Container) -> (String, i64) {
        let mut msg = format!("container {}", c.state);
        if self.started_before_boot(c.started_at) {
            // Its process ended with the machine: not a crash, no backoff.
            return (MACHINE_RESTARTED.to_string(), 0);
        }
        let down = crate::containers::member_down(s, c);
        if !down.is_empty() {
            msg = down;
        } else if let Ok(full) = self.rt.inspect(&c.id).await
            && full.state != STATE_CREATED
        {
            msg = format!("exited with code {}", full.exit_code);
            if self.out_of_memory(&c.id).await {
                msg = format!("out of memory at its limit, {msg}");
            }
        }
        (msg, self.backoff(&s.id))
    }

    /// How long to wait before recreating replica's container (0: now,
    /// which counts as a recreate); each recreate doubles the next delay.
    pub(crate) fn backoff(&self, replica: &str) -> i64 {
        let now = self.now();
        let mut st = lock(&self.st);
        let base = st.crash_base;
        let mut cl = st.crashes.get(replica).copied().unwrap_or_default();
        let next = cl.next.map(|n| clock::sub(n, now)).unwrap_or(i64::MIN);
        if next > 0 {
            return next;
        }
        if cl.last.map(|l| clock::sub(now, l)).unwrap_or(i64::MAX) > CRASH_RESET.as_nanos() as i64 {
            cl.count = 0;
        }
        let delay = base.checked_shl(cl.count.min(20)).unwrap_or(i64::MAX);
        cl.count += 1;
        cl.last = Some(now);
        let wait = delay.min(MAX_CRASH_BACKOFF.as_nanos() as i64);
        cl.next = Some(clock::from_unix_nanos(
            clock::unix_nanos(now) + wait as i128,
        ));
        st.crashes.insert(replica.to_string(), cl);
        0
    }

    pub(crate) fn stop_probes(&self, replica: &str) {
        if let Some(w) = lock(&self.st).probes.remove(replica) {
            w.cancel();
        }
    }

    /// Makes sure c's probes run and returns their verdict; probes start
    /// once the container runs.
    pub(crate) fn readiness(
        self: &Arc<Self>,
        s: &pb::ReplicaSpec,
        c: &Container,
    ) -> (bool, String) {
        if c.state != STATE_RUNNING {
            return (false, String::new());
        }
        let w = {
            let mut st = lock(&self.st);
            let mut w = st.probes.get(&s.id).cloned();
            if let Some(old) = &w
                && old.container_id != c.id
            {
                old.cancel();
                w = None;
            }
            match w {
                Some(w) => w,
                None => {
                    let note = st.notes.get(&s.id).cloned().unwrap_or_default();
                    let w = self.start_probes(s, c, note);
                    st.probes.insert(s.id.clone(), w.clone());
                    w
                }
            }
        };
        w.status()
    }

    /// Whether c ran before this agent started and its probes have not
    /// said anything yet: left out of reports until they do.
    pub(crate) fn awaits_verdict(&self, s: &pb::ReplicaSpec, c: &Container) -> bool {
        let Some(started) = c.started_at else {
            return false;
        };
        if c.state != STATE_RUNNING || clock::sub(started, self.began) >= 0 {
            return false;
        }
        let w = lock(&self.st).probes.get(&s.id).cloned();
        w.is_some_and(|w| !w.has_verdict())
    }

    /// Pulls an image with `pull` (or the runtime) and runs a replica's
    /// container.
    pub(crate) async fn start(
        self: &Arc<Self>,
        s: &pb::ReplicaSpec,
        hash: &str,
        pull: Option<&PullOnce>,
    ) -> runtime::Result<Container> {
        let auth = registry_auth(s);
        let img = self.pull_with(pull, &s.image, auth.as_ref()).await?;
        {
            let mut st = lock(&self.st);
            if !img.reference.is_empty() {
                st.digests.insert(s.image.clone(), img.reference.clone());
            }
            if !img.platforms.is_empty() {
                st.platforms.insert(s.image.clone(), img.platforms.clone());
            }
        }
        if has_members(s) {
            if !self.rt.can_run_members() {
                return Err(Error::other(
                    "this node's container runtime runs no init containers or sidecars",
                ));
            }
            self.pull_members(s, pull).await?;
        }
        let mut cs = container_spec(s, &self.cfg.private_ip, hash);
        if self.cfg.unpublished {
            cs.port = 0;
            cs.host_ip.clear();
        }
        if let Some(dns) = &self.cfg.dns {
            cs.dns = vec![dns.address()];
            let d = armada_spec::validate::internal_search_domain(&s.app);
            if !d.is_empty() {
                cs.dns_search = vec![d];
            }
        }
        cs.files = self.write_secret_files(s).map_err(Error::Other)?;
        cs.volumes = self.prepare_volumes(s).await.map_err(Error::Other)?;
        crate::containers::with_member_mounts(s, &mut cs).map_err(Error::Other)?;
        let id = self.rt.run(&cs).await?;
        let c = self.rt.inspect(&id).await?;
        self.note_local(&c.ip, &s.app);
        Ok(c)
    }

    pub(crate) async fn pull_with(
        &self,
        pull: Option<&PullOnce>,
        image: &str,
        auth: Option<&RegistryAuth>,
    ) -> runtime::Result<Image> {
        match pull {
            Some(p) => p.pull(&self.rt, image, auth).await,
            None => self.rt.pull(image, auth).await,
        }
    }

    /// A replica's state from its container.
    pub(crate) fn state(self: &Arc<Self>, s: &pb::ReplicaSpec, c: &Container) -> pb::ReplicaState {
        let mut st = pb::ReplicaState {
            id: s.id.clone(),
            container_id: c.id.clone(),
            ..Default::default()
        };
        {
            let g = lock(&self.st);
            st.image_digest = g.digests.get(&s.image).cloned().unwrap_or_default();
            st.image_platforms = g.platforms.get(&s.image).cloned().unwrap_or_default();
        }
        match c.state.as_str() {
            STATE_RUNNING => {
                st.state = REPLICA_RUNNING.into();
                (st.ready, st.message) = self.readiness(s, c);
                if st.ready {
                    // This report carries the restart note; later ones do
                    // not.
                    let mut g = lock(&self.st);
                    g.notes.remove(&s.id);
                    if let Some(w) = g.probes.get(&s.id) {
                        w.clear_note();
                    }
                }
            }
            STATE_CREATED | STATE_RESTARTING | STATE_STARTING => {
                st.state = REPLICA_STARTING.into();
                if c.state == STATE_STARTING {
                    st.message = "starting its init containers and sidecars".into();
                }
            }
            _ => {
                st.state = REPLICA_EXITED.into();
                st.message = format!("exit code {}", c.exit_code);
                let down = crate::containers::member_down(s, c);
                if !down.is_empty() {
                    st.message = down;
                }
            }
        }
        if c.host_port != 0 {
            st.address = join_host_port(&c.host_ip, c.host_port);
        } else if self.cfg.unpublished && !c.ip.is_empty() && s.port != 0 {
            st.address = join_host_port(&c.ip, i64::from(s.port));
        }
        if self.cfg.unpublished {
            st.ip = c.ip.clone();
        }
        st
    }

    /// Whether a container started before the machine last booted (btime
    /// is whole seconds, so a start within the boot's second does not
    /// count).
    pub(crate) fn started_before_boot(&self, started: Option<SystemTime>) -> bool {
        let (Some(booted), Some(started)) = (self.booted, started) else {
            return false;
        };
        let b = clock::unix_nanos(booted);
        let truncated = b - b.rem_euclid(1_000_000_000);
        clock::unix_nanos(started) < truncated
    }
}

/// host:port, with an IPv6 host in brackets.
pub(crate) fn join_host_port(host: &str, port: i64) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Pulls each image once for the replicas starting together, sharing the
/// registry's answer or failure: a pull in
/// flight is joined, a finished one forgotten. Other credentials pull for
/// themselves.
#[derive(Default)]
pub(crate) struct PullOnce {
    flight: Mutex<HashMap<String, Arc<OnceCell<runtime::Result<Image>>>>>,
}

impl PullOnce {
    async fn pull<R: Runtime>(
        &self,
        rt: &R,
        image: &str,
        auth: Option<&RegistryAuth>,
    ) -> runtime::Result<Image> {
        use sha2::{Digest, Sha256};
        let mut key = vec![image];
        if let Some(a) = auth {
            key.extend([
                a.username.as_str(),
                a.password.as_str(),
                a.server_address.as_str(),
            ]);
        }
        let mut h = Sha256::new();
        for v in key {
            h.update(format!("{}:{v}", v.len()).as_bytes());
        }
        let key: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        let cell = lock(&self.flight)
            .entry(key.clone())
            .or_insert_with(|| Arc::new(OnceCell::new()))
            .clone();
        let r = cell.get_or_init(|| rt.pull(image, auth)).await.clone();
        let mut f = lock(&self.flight);
        if f.get(&key).is_some_and(|c| Arc::ptr_eq(c, &cell)) {
            f.remove(&key);
        }
        r
    }
}

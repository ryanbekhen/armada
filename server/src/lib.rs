//! The control plane (ADR 0055): a port of Go's `internal/server` and of
//! the server side of `armadad server`, checked against Go by the
//! scenario parity tests (`internal/server`, `ARMADA_SERVER_BIN`).
//!
//! This is the core (pull request 8 of ADR 0055): one leadership term's
//! server ([`Server`]: the API with access control and stream checks,
//! joins, sessions with agents, and the assignments of the replicas the
//! store holds), the terms themselves ([`lifecycle`]), and the renewal of
//! the server's own certificates ([`renew`]); with placement and rollouts
//! (pull request 9): the reconcile pass's scheduling, placement, rollouts,
//! drains, evacuation, self-healing, rebalancing, removal of apps, and
//! traffic splits (`reconcile`, `schedule`), and the AdminService methods
//! of apps and secrets (`apps`, `secret_api`); with jobs (pull request
//! 10): cron schedules, retries, tasks, queue triggers with the usage
//! reports' sandboxes that feed them, and the AdminService methods of jobs
//! (`jobs`, `triggers`, `usage`); with scaling (pull request 11): the
//! autoscaler's evaluations of http, cpu, memory, queue, and schedule
//! rules, scale to zero and wakes, and the usage samples they read
//! (`autoscale`, `usage`); with volumes (pull request 12): apps with
//! local volumes recreated on their node with held replicas, the volume
//! methods through agents' volume sessions, the volume sizes of usage
//! reports, scheduled backups and their methods, the checks of backup
//! buckets, and failover (`volumes`, `backups`, `failover`). The cluster
//! network, ingress, and watching follow in their own pull requests; their
//! AdminService methods answer `Unimplemented` until then
//! ([`admin::LATER`]).

pub mod access;
mod admin;
pub mod agents;
mod apps;
mod assign;
mod autoscale;
mod backups;
pub mod cluster;
pub mod conn;
mod events;
mod failover;
mod grpc;
pub mod guard;
mod jobs;
mod join;
pub mod lifecycle;
mod limiter;
pub mod log;
mod netutil;
mod nodes;
mod rbac;
mod reconcile;
pub mod renew;
mod schedule;
mod secret_api;
mod servers;
mod settings;
mod spaces;
pub mod tls;
mod triggers;
mod usage;
mod volumes;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicI64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use armada_pki::Ca;
use armada_secrets::Keyring;
use armada_spec::gotime::Time;
use armada_store::{Etcd, Kind};
use tokio::net::TcpListener;
use tokio::sync::{Notify, watch};
use tonic::{Code, Status};

pub use admin::LATER;
pub use cluster::{Cluster, MemberInfo};
pub use settings::{
    Settings, check_acme_ca, check_dns_provider, check_dns_token, check_email,
    check_node_lost_timeout, load_settings, save_settings,
};

/// The clock the server reads where Go's reads `s.now()` (tests replace
/// it); where Go reads `time.Now()` the wall clock is read too.
pub type Clock = armada_store::Clock;

/// Go's defaultResync.
pub const DEFAULT_RESYNC: Duration = Duration::from_secs(5);
/// Go's streamRecheckEvery.
pub const STREAM_RECHECK_EVERY: Duration = Duration::from_secs(5);
/// Go's DefaultNodeLostTimeout.
pub const DEFAULT_NODE_LOST_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Go's shutdownGrace: how long in-flight calls get when the server stops.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);

/// How one term's server is set up (Go's server.Config, the parts this
/// pull request ports).
pub struct Config {
    /// The store, fenced on the term's election key.
    pub store: Etcd,
    /// The server's certificate: the API's and the join listener's.
    pub cert: Arc<tls::ServerCert>,
    /// Signs node certificates for joining and renewing nodes; none
    /// disables both.
    pub ca: Option<Arc<Ca>>,
    /// The master key; none disables secrets.
    pub keys: Option<Arc<Keyring>>,
    /// This control plane node's name.
    pub name: String,
    /// The control plane address given to joining agents.
    pub api_addr: String,
    /// The join listener's address; empty disables joining.
    pub join_addr: String,
    /// The join listener already listening on join_addr (tests).
    pub join_listener: Option<std::net::TcpListener>,
    /// A mesh cluster's join listener (ADR 0049).
    pub join_public: bool,
    /// The leader's public endpoint for machines of other sites (ADR 0050).
    pub join_site_addr: String,
    /// Closes idle join connections sooner than 15 seconds (tests).
    pub join_idle: Duration,
    /// Replaces the join listener's burst per source address (tests).
    pub join_burst: u32,
    /// The lifetime of issued node certificates (default and most:
    /// pki::NODE_VALIDITY).
    pub node_cert_validity: Duration,
    pub resync: Duration,
    pub stream_recheck: Duration,
    pub node_lost_timeout: Duration,
    pub clock: Option<Clock>,
    /// Manages the etcd membership; none disables adding and removing
    /// servers.
    pub cluster: Option<Arc<dyn Cluster>>,
    /// Called after the cluster's server settings changed (ADR 0031).
    pub on_settings_changed: Option<Arc<dyn Fn() + Send + Sync>>,
    /// What GetClusterConfig shows of the term's certificate settings.
    pub tls_on: bool,
    pub acme_email: String,
    pub acme_ca: String,
    pub dns_provider: String,
    pub metrics_addr: String,
    /// The cluster obtains no certificates: external apps' URLs are http.
    pub plain_http: bool,
    /// Rollout timing; zero values use the defaults: how long a replica
    /// keeps running after leaving the proxies, how long a new replica
    /// serves before old ones go, and how long a rollout may go without a
    /// new replica serving.
    pub drain_timeout: Duration,
    pub warmup: Duration,
    pub progress_deadline: Duration,
    /// The delay before a job's first retry, doubling up to five minutes;
    /// zero uses ten seconds.
    pub job_retry_base: Duration,
    /// How often the autoscaler evaluates apps; zero uses 15 seconds.
    pub autoscale_interval: Duration,
    /// How often due volume backups are started; zero uses 30 seconds.
    pub backup_interval: Duration,
    /// Passes run only when [`Server::reconcile`] is called, and the
    /// autoscaler evaluates only when [`Server::autoscale`] is (the
    /// scenario parity tests, which drive both, and the backups with
    /// [`Server::schedule_backups`]): the loop only promotes learners.
    pub manual_passes: bool,
    /// Makes the random part of new replica IDs (tests make them
    /// predictable); none uses random letters and digits.
    pub new_id: Option<Arc<dyn Fn(usize) -> String + Send + Sync>>,
    pub log: log::Logger,
}

impl Config {
    /// A config with the defaults Go's New fills in.
    pub fn new(store: Etcd, cert: Arc<tls::ServerCert>) -> Config {
        Config {
            store,
            cert,
            ca: None,
            keys: None,
            name: String::new(),
            api_addr: String::new(),
            join_addr: String::new(),
            join_listener: None,
            join_public: false,
            join_site_addr: String::new(),
            join_idle: Duration::ZERO,
            join_burst: 0,
            node_cert_validity: Duration::ZERO,
            resync: Duration::ZERO,
            stream_recheck: Duration::ZERO,
            node_lost_timeout: Duration::ZERO,
            clock: None,
            cluster: None,
            on_settings_changed: None,
            tls_on: false,
            acme_email: String::new(),
            acme_ca: String::new(),
            dns_provider: String::new(),
            metrics_addr: String::new(),
            plain_http: false,
            drain_timeout: Duration::ZERO,
            warmup: Duration::ZERO,
            progress_deadline: Duration::ZERO,
            job_retry_base: Duration::ZERO,
            autoscale_interval: Duration::ZERO,
            backup_interval: Duration::ZERO,
            manual_passes: false,
            new_id: None,
            log: log::Logger::discard(),
        }
    }
}

/// The control plane of one leadership term. Clones share it.
#[derive(Clone)]
pub struct Server(pub(crate) Arc<Inner>);

pub(crate) struct Inner {
    pub store: Etcd,
    pub keys: Option<Arc<Keyring>>,
    pub ca: Option<Arc<Ca>>,
    pub cert: Arc<tls::ServerCert>,
    pub name: String,
    pub api_addr: String,
    pub join_addr: String,
    pub join_listener: Mutex<Option<std::net::TcpListener>>,
    pub join_public: bool,
    pub join_site_addr: String,
    pub join_idle: Duration,
    pub node_cert_validity: Duration,
    pub resync: Duration,
    pub stream_recheck: Duration,
    pub node_lost_timeout: Duration,
    pub clock: Clock,
    pub cluster: Option<Arc<dyn Cluster>>,
    pub on_settings: Option<Arc<dyn Fn() + Send + Sync>>,
    pub tls_on: bool,
    pub acme_email: String,
    pub acme_ca: String,
    pub dns_provider: String,
    pub metrics_addr: String,
    pub plain_http: bool,
    pub drain_timeout: Duration,
    pub warmup: Duration,
    pub progress_deadline: Duration,
    pub job_retry_base: Duration,
    pub autoscale_interval: Duration,
    pub backup_interval: Duration,
    pub manual_passes: bool,
    pub new_id: Arc<dyn Fn(usize) -> String + Send + Sync>,
    /// When this server started leading: drains a previous leader began
    /// are counted from then.
    pub term_start: Time,
    pub log: log::Logger,

    pub trigger: Notify,
    pub sessions: Mutex<HashMap<String, Arc<agents::Session>>>,
    pub events: events::Recorder,
    pub endpoints_seen: Mutex<Option<(Vec<String>, tokio::time::Instant)>>,
    pub join_gate: join::Gate,
    pub join_limit: limiter::Keyed,
    pub join_global: limiter::Bucket,
    pub renew_limit: limiter::Keyed,
    pub user_renew_limit: limiter::Keyed,
    pub opened: assign::Opened,
    pub learned: agents::Learned,
    pub cluster_size: AtomicI64,
    /// One pass at a time.
    pub pass: tokio::sync::Mutex<()>,
    pub memory: Mutex<reconcile::Memory>,
    /// The latest usage sample of each node (memory only).
    pub usage: usage::Usage,
    /// Which node reads each queue-triggered job's queue (memory only).
    pub triggers: triggers::QueueTriggers,
    /// What the autoscaler remembers between evaluations (memory only).
    pub scaler: autoscale::Autoscaler,
    /// Wakes per node (ADR 0021), on the server's clock.
    pub wake_limit: limiter::ClockKeyed,
    /// Volume requests waiting for their agents' sessions.
    pub volumes: volumes::VolumeRouter,
    /// The volume backups in flight (memory only).
    pub backups: backups::BackupRuns,
    /// Failovers in progress and their retries (memory only).
    pub failovers: failover::FailoverRuns,
    /// The next pass a wake-up asked for, and its timer.
    pub wake: Mutex<Option<(tokio::time::Instant, tokio::task::AbortHandle)>>,
}

impl Server {
    /// Builds a server (Go's New).
    pub fn new(cfg: Config) -> Result<Server, String> {
        if !cfg.join_addr.is_empty() {
            if cfg.ca.is_none() || cfg.api_addr.is_empty() {
                return Err("server: joining needs CA, JoinTLS, and APIAddr".to_string());
            }
            if cfg.join_public {
                let ap: SocketAddr = cfg.join_addr.parse().map_err(|_| {
                    format!("server: join listener: invalid address {:?}", cfg.join_addr)
                })?;
                if ap.port() == 0 {
                    return Err(format!(
                        "server: join listener: invalid address {:?}",
                        cfg.join_addr
                    ));
                }
            }
            if !cfg.join_site_addr.is_empty() && cfg.join_public {
                return Err("server: a mesh cluster's join listener is already public".to_string());
            }
        }
        let clock = cfg
            .clock
            .unwrap_or_else(|| Arc::new(armada_store::gojson::now));
        let validity = if cfg.node_cert_validity.is_zero()
            || cfg.node_cert_validity > armada_pki::NODE_VALIDITY
        {
            armada_pki::NODE_VALIDITY
        } else {
            cfg.node_cert_validity
        };
        let term_start = clock();
        Ok(Server(Arc::new(Inner {
            store: cfg.store,
            keys: cfg.keys,
            ca: cfg.ca,
            cert: cfg.cert,
            name: cfg.name,
            api_addr: cfg.api_addr,
            join_addr: cfg.join_addr,
            join_listener: Mutex::new(cfg.join_listener),
            join_public: cfg.join_public,
            join_site_addr: cfg.join_site_addr,
            join_idle: cfg.join_idle,
            node_cert_validity: validity,
            resync: nonzero(cfg.resync, DEFAULT_RESYNC),
            stream_recheck: nonzero(cfg.stream_recheck, STREAM_RECHECK_EVERY),
            node_lost_timeout: nonzero(cfg.node_lost_timeout, DEFAULT_NODE_LOST_TIMEOUT),
            clock,
            cluster: cfg.cluster,
            on_settings: cfg.on_settings_changed,
            tls_on: cfg.tls_on,
            acme_email: cfg.acme_email,
            acme_ca: cfg.acme_ca,
            dns_provider: cfg.dns_provider,
            metrics_addr: cfg.metrics_addr,
            plain_http: cfg.plain_http,
            drain_timeout: nonzero(cfg.drain_timeout, reconcile::DEFAULT_DRAIN_TIMEOUT),
            warmup: nonzero(cfg.warmup, reconcile::DEFAULT_WARMUP),
            progress_deadline: nonzero(cfg.progress_deadline, reconcile::DEFAULT_PROGRESS_DEADLINE),
            job_retry_base: nonzero(cfg.job_retry_base, jobs::DEFAULT_JOB_RETRY_BASE),
            autoscale_interval: nonzero(
                cfg.autoscale_interval,
                autoscale::DEFAULT_AUTOSCALE_INTERVAL,
            ),
            backup_interval: nonzero(cfg.backup_interval, backups::DEFAULT_BACKUP_INTERVAL),
            manual_passes: cfg.manual_passes,
            new_id: cfg.new_id.unwrap_or_else(|| Arc::new(random_id)),
            term_start,
            log: cfg.log.with("component", "server"),
            trigger: Notify::new(),
            sessions: Mutex::new(HashMap::new()),
            events: events::Recorder::default(),
            endpoints_seen: Mutex::new(None),
            join_gate: join::Gate::default(),
            join_limit: limiter::Keyed::new(
                if cfg.join_burst > 0 {
                    cfg.join_burst
                } else {
                    join::JOIN_BURST
                },
                join::JOIN_REFILL,
            ),
            join_global: limiter::Bucket::new(join::JOIN_GLOBAL_BURST, join::JOIN_GLOBAL_REFILL),
            renew_limit: limiter::Keyed::new(5, (validity / 10).max(Duration::from_secs(1))),
            user_renew_limit: limiter::Keyed::new(5, Duration::from_secs(60)),
            opened: assign::Opened::default(),
            learned: agents::Learned::default(),
            cluster_size: AtomicI64::new(0),
            pass: tokio::sync::Mutex::new(()),
            memory: Mutex::new(reconcile::Memory::default()),
            usage: usage::Usage::default(),
            triggers: triggers::QueueTriggers::default(),
            scaler: autoscale::Autoscaler::default(),
            wake_limit: limiter::ClockKeyed::new(autoscale::WAKE_BURST, autoscale::WAKE_REFILL),
            volumes: volumes::VolumeRouter::default(),
            backups: backups::BackupRuns::default(),
            failovers: failover::FailoverRuns::default(),
            wake: Mutex::new(None),
        })))
    }

    pub(crate) fn now(&self) -> Time {
        (self.0.clock)()
    }

    pub(crate) fn store(&self) -> &Etcd {
        &self.0.store
    }

    /// Requests a reconcile as soon as possible.
    pub fn trigger(&self) {
        self.0.trigger.notify_one();
    }

    /// Accepts connections on `lis` and runs the term's loops until
    /// `shutdown` turns true (Go's Serve).
    pub async fn serve(
        &self,
        lis: TcpListener,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), String> {
        self.start_term()
            .await
            .map_err(|e| format!("start term: {e}"))?;
        if !self.0.join_addr.is_empty() {
            self.serve_join(shutdown.clone()).await?;
        }
        {
            let s = self.clone();
            let sd = shutdown.clone();
            tokio::spawn(async move { s.reconcile_loop(sd).await });
        }
        if !self.0.manual_passes {
            let s = self.clone();
            let sd = shutdown.clone();
            tokio::spawn(async move { s.autoscale_loop(sd).await });
            let s = self.clone();
            let sd = shutdown.clone();
            tokio::spawn(async move { s.backup_loop(sd).await });
        }
        let addr = lis.local_addr().map(|a| a.to_string()).unwrap_or_default();
        self.0.log.info("listening", &[("addr", addr)]);
        let tls = self.0.cert.api_config()?;
        let (stop_tx, stop_rx) = watch::channel(false);
        let (kill_tx, kill_rx) = watch::channel(false);
        let incoming = conn::accept(
            lis,
            tokio_rustls::TlsAcceptor::from(Arc::new(tls)),
            conn::Limits::default(),
            stop_rx,
            kill_rx,
        );
        let svc = grpc::Dispatch::new(self.clone());
        let signal = {
            let mut sd = shutdown.clone();
            async move {
                crate::stopped(&mut sd).await;
            }
        };
        tokio::spawn(async move {
            crate::stopped(&mut shutdown).await;
            let _ = stop_tx.send(true);
            // Agent streams never finish on their own: in-flight calls get
            // a short grace, then every connection is closed.
            tokio::time::sleep(SHUTDOWN_GRACE).await;
            let _ = kill_tx.send(true);
        });
        tonic::transport::Server::builder()
            .http2_keepalive_interval(Some(Duration::from_secs(30)))
            .http2_keepalive_timeout(Some(Duration::from_secs(10)))
            .serve_with_incoming_shutdown(
                svc,
                tokio_stream::wrappers::ReceiverStream::new(incoming),
                signal,
            )
            .await
            .map_err(|e| e.to_string())
    }

    async fn reconcile_loop(&self, mut shutdown: watch::Receiver<bool>) {
        loop {
            let res = if self.0.manual_passes {
                Ok(())
            } else {
                self.reconcile().await
            };
            if let Err(e) = res
                && !*shutdown.borrow()
            {
                self.0
                    .log
                    .error("reconcile failed", &[("err", e.to_string())]);
            }
            self.promote_learners().await;
            tokio::select! {
                _ = crate::stopped(&mut shutdown) => return,
                _ = tokio::time::sleep(self.0.resync) => {}
                _ = self.0.trigger.notified() => {}
            }
        }
    }
}

fn nonzero(d: Duration, def: Duration) -> Duration {
    if d.is_zero() { def } else { d }
}

const ID_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// randomID: n random characters from [a-z0-9].
pub fn random_id(n: usize) -> String {
    use ring::rand::SecureRandom;
    let mut b = vec![0u8; n];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .expect("the system's random source");
    b.iter()
        .map(|x| ID_ALPHABET[usize::from(*x) % ID_ALPHABET.len()] as char)
        .collect()
}

/// Go's storeErr: the gRPC status of a store error.
pub(crate) fn store_err(e: &armada_store::Error) -> Status {
    match e.kind {
        Kind::NotFound => Status::new(Code::NotFound, e.msg.clone()),
        Kind::Conflict => Status::new(Code::AlreadyExists, sentence(e)),
        Kind::Precondition => Status::new(Code::FailedPrecondition, sentence(e)),
        Kind::NotLeader => Status::new(Code::Unavailable, e.msg.clone()),
        Kind::Other => Status::new(Code::Internal, "internal error"),
    }
}

/// Go's sentence: a store error's message without the sentinel at its end.
fn sentence(e: &armada_store::Error) -> String {
    let suffix = format!(": {}", e.kind.text());
    e.msg.strip_suffix(&suffix).unwrap_or(&e.msg).to_string()
}

/// Resolves once the signal turns true; never when its sender is gone
/// without turning it.
pub async fn stopped(rx: &mut watch::Receiver<bool>) {
    let gone = rx.wait_for(|v| *v).await.is_err();
    if gone {
        std::future::pending::<()>().await;
    }
}

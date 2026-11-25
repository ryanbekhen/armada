//! Joining (ADR 0003; Go's nodes.go and servers.go): the join listener,
//! its bounds and its gate, JoinService for nodes and servers, and join
//! tokens.

use std::collections::HashSet;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use armada_pki::{IssueRequest, KIND_SERVER, KIND_USER, SERVER_NAME};
use armada_proto::armada::v1::join_service_server::{JoinService, JoinServiceServer};
use armada_proto::armada::v1::{
    CreateJoinTokenRequest, CreateJoinTokenResponse, JoinRequest, JoinResponse, JoinServerRequest,
    JoinServerResponse,
};
use armada_spec::go::{parse_addr, quote};
use armada_spec::validate::{MAX_NODE_LABELS, check_admin_label, check_label_value, validate_name};
use armada_store::network::NETWORK_MESH;
use armada_store::{JoinToken, Kind, Node};
use tokio::net::TcpListener;
use tokio::sync::{Notify, watch};
use tonic::body::Body;
use tonic::codegen::http;
use tonic::{Code, Request, Response, Status};

use crate::conn::{self, PeerInfo};
use crate::events::{self, event};
use crate::grpc::Auth;
use crate::netutil::{check_endpoint, check_node_ip, ip_of};
use crate::{Server, store_err};

pub const JOIN_BURST: u32 = 5;
pub const JOIN_REFILL: Duration = Duration::from_secs(6);
pub const JOIN_GLOBAL_BURST: u32 = 30;
pub const JOIN_GLOBAL_REFILL: Duration = Duration::from_secs(1);
const MAX_CSR_SIZE: usize = 4 << 10;
const JOIN_MAX_CONNS: usize = 256;
const JOIN_MAX_CONNS_PER_SOURCE: usize = 16;
const JOIN_IDLE: Duration = Duration::from_secs(15);
const JOIN_MAX_AGE: Duration = Duration::from_secs(120);
const JOIN_STOP_GRACE: Duration = Duration::from_secs(5);
/// joinGateEvery: how often the leader looks whether the tokens that open
/// its public join listener expired.
const JOIN_GATE_EVERY: Duration = Duration::from_secs(5);

const DEFAULT_TOKEN_TTL: i64 = 3600;
const MAX_TOKEN_TTL: i64 = 24 * 3600;
const MAX_SERVER_TOKEN_TTL: i64 = 3600;
const DEFAULT_SERVER_TOKEN_TTL: i64 = 15 * 60;
const DEFAULT_MESH_TOKEN_TTL: i64 = 10 * 60;
const MAX_MESH_TOKEN_TTL: i64 = 3600;
const MIN_TOKEN_TTL: i64 = 60;

/// The state of the leader's public join listener.
#[derive(Default)]
pub struct Gate {
    wake: Notify,
    /// The addresses open tokens name, or none when one names none and
    /// any address may join.
    from: Mutex<Option<HashSet<IpAddr>>>,
}

/// How a machine joins (Go's joining).
#[derive(Default)]
struct Joining {
    on: bool,
    away: bool,
    meshed: bool,
    key: String,
    endpoint: String,
    behind_nat: bool,
}

impl Joining {
    fn node(&self, name: &str, ip: &str) -> Node {
        Node {
            id: name.to_string(),
            private_ip: ip.to_string(),
            network_key: self.key.clone(),
            endpoint: self.endpoint.clone(),
            mesh_address: self.meshed,
            behind_nat: self.behind_nat,
            ..Default::default()
        }
    }
}

/// validNetworkKey: a WireGuard public key, 32 bytes in standard base64,
/// not all zero.
pub(crate) fn valid_network_key(s: &str) -> bool {
    if s.len() != 44 {
        return false;
    }
    match armada_pki::encoding::base64_decode(s.as_bytes()) {
        Some(b) => b.len() == 32 && b.iter().any(|&x| x != 0),
        None => false,
    }
}

/// netip's IsGlobalUnicast.
fn global_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !(v.is_unspecified()
                || v.is_loopback()
                || v.is_multicast()
                || v.is_link_local()
                || v.is_broadcast())
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return global_unicast(IpAddr::V4(v4));
            }
            !(v.is_unspecified()
                || v.is_loopback()
                || v.is_multicast()
                || (v.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

fn ts(t: &armada_spec::gotime::Time) -> armada_proto::google::protobuf::Timestamp {
    events::timestamp(t)
}

impl Server {
    /// Starts the join listener (Go's serveJoin).
    pub(crate) async fn serve_join(&self, shutdown: watch::Receiver<bool>) -> Result<(), String> {
        if self.0.join_public {
            let s = self.clone();
            tokio::spawn(async move {
                s.gate_join(s.0.join_addr.clone(), false, shutdown).await;
            });
            return Ok(());
        }
        let std_l = self
            .0
            .join_listener
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        let l = match std_l {
            Some(l) => {
                l.set_nonblocking(true).map_err(|e| e.to_string())?;
                TcpListener::from_std(l).map_err(|e| e.to_string())?
            }
            None => TcpListener::bind(&self.0.join_addr)
                .await
                .map_err(|e| format!("join listener: {e}"))?,
        };
        let stop = self.start_join(l, false, None)?;
        let mut sd = shutdown.clone();
        tokio::spawn(async move {
            crate::stopped(&mut sd).await;
            stop.stop().await;
        });
        self.0
            .log
            .info("join listener", &[("addr", self.0.join_addr.clone())]);
        if !self.0.join_site_addr.is_empty() {
            let s = self.clone();
            tokio::spawn(async move {
                s.gate_join(s.0.join_site_addr.clone(), true, shutdown)
                    .await;
            });
        }
        Ok(())
    }

    /// The site of this server's node, "" for the first site.
    async fn leader_site(&self) -> Result<String, armada_store::Error> {
        match self.store().get_node(&self.0.name).await {
            Err(e) if e.kind == Kind::NotFound => Ok(String::new()),
            Err(e) => Err(e),
            Ok(n) => Ok(n.site),
        }
    }

    /// The tokens for a site other than the leader's.
    async fn other_sites(&self, toks: Vec<JoinToken>) -> Vec<JoinToken> {
        match self.leader_site().await {
            Err(e) => {
                self.0
                    .log
                    .warn("read the leader's site", &[("err", e.to_string())]);
                Vec::new()
            }
            Ok(site) => toks.into_iter().filter(|t| t.site != site).collect(),
        }
    }

    /// Makes the leader look at the tokens of its public join listener now.
    pub(crate) fn wake_join(&self) {
        self.0.join_gate.wake.notify_one();
    }

    /// Keeps a join listener on the leader's public endpoint open only
    /// while a join token that opens it is unused and unexpired, answering
    /// only the addresses those tokens name (Go's gateJoin).
    async fn gate_join(
        &self,
        addr: String,
        other_sites: bool,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut stop: Option<Stopper> = None;
        loop {
            match self.store().open_join_tokens().await {
                Err(e) => self
                    .0
                    .log
                    .warn("read join tokens", &[("err", e.to_string())]),
                Ok(toks) => {
                    let toks = if other_sites {
                        self.other_sites(toks).await
                    } else {
                        toks
                    };
                    *self
                        .0
                        .join_gate
                        .from
                        .lock()
                        .unwrap_or_else(|p| p.into_inner()) = join_sources(&toks);
                    if !toks.is_empty() && stop.is_none() {
                        let l = match self
                            .0
                            .join_listener
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .take()
                        {
                            Some(l) => l
                                .set_nonblocking(true)
                                .and_then(|_| TcpListener::from_std(l)),
                            None => match std::net::TcpListener::bind(&addr) {
                                Ok(l) => l
                                    .set_nonblocking(true)
                                    .and_then(|_| TcpListener::from_std(l)),
                                Err(e) => Err(e),
                            },
                        };
                        match l {
                            Err(e) => self.0.log.error(
                                "open the join listener",
                                &[("addr", addr.clone()), ("err", e.to_string())],
                            ),
                            Ok(l) => {
                                let s = self.clone();
                                let allow: Arc<dyn Fn(IpAddr) -> bool + Send + Sync> =
                                    Arc::new(move |a| s.join_allowed(a));
                                match self.start_join(l, true, Some(allow)) {
                                    Ok(st) => {
                                        stop = Some(st);
                                        self.0.log.info(
                                            "join listener open while a join token is",
                                            &[("addr", addr.clone())],
                                        );
                                    }
                                    Err(e) => self.0.log.error(
                                        "open the join listener",
                                        &[("addr", addr.clone()), ("err", e)],
                                    ),
                                }
                            }
                        }
                    } else if toks.is_empty()
                        && let Some(st) = stop.take()
                    {
                        st.stop().await;
                        self.0.log.info(
                            "join listener closed: no open join token",
                            &[("addr", addr.clone())],
                        );
                    }
                }
            }
            tokio::select! {
                _ = crate::stopped(&mut shutdown) => {
                    if let Some(st) = stop.take() {
                        st.stop().await;
                    }
                    return;
                }
                _ = tokio::time::sleep(JOIN_GATE_EVERY) => {}
                _ = self.0.join_gate.wake.notified() => {}
            }
        }
    }

    /// Whether a connection from addr may reach the public join listener.
    fn join_allowed(&self, addr: IpAddr) -> bool {
        let from = self
            .0
            .join_gate
            .from
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        match &*from {
            None => true,
            Some(m) => m.contains(&addr.to_canonical()),
        }
    }

    /// Serves JoinService on l until the returned stopper is stopped.
    fn start_join(
        &self,
        l: TcpListener,
        public: bool,
        allow: Option<Arc<dyn Fn(IpAddr) -> bool + Send + Sync>>,
    ) -> Result<Stopper, String> {
        let idle = if self.0.join_idle.is_zero() {
            JOIN_IDLE
        } else {
            self.0.join_idle
        };
        let tls = self.0.cert.join_config()?;
        let (stop_tx, stop_rx) = watch::channel(false);
        let (kill_tx, kill_rx) = watch::channel(false);
        let incoming = conn::accept(
            l,
            tokio_rustls::TlsAcceptor::from(Arc::new(tls)),
            conn::Limits {
                total: JOIN_MAX_CONNS,
                per_source: JOIN_MAX_CONNS_PER_SOURCE,
                idle: Some(idle),
                allow,
            },
            stop_rx.clone(),
            kill_rx,
        );
        let svc = JoinDispatch {
            srv: self.clone(),
            join: JoinServiceServer::new(JoinApi {
                srv: self.clone(),
                public,
            })
            .max_decoding_message_size(64 << 10),
        };
        let mut sig = stop_rx;
        let done = tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .max_concurrent_streams(4)
                .http2_keepalive_interval(Some(idle))
                .http2_keepalive_timeout(Some(Duration::from_secs(10)))
                .max_connection_age(JOIN_MAX_AGE)
                .max_connection_age_grace(Duration::from_secs(10))
                .serve_with_incoming_shutdown(
                    svc,
                    tokio_stream::wrappers::ReceiverStream::new(incoming),
                    async move {
                        crate::stopped(&mut sig).await;
                    },
                )
                .await;
        });
        Ok(Stopper {
            stop: stop_tx,
            kill: kill_tx,
            done,
        })
    }

    /// CreateJoinToken creates a single-use join token.
    pub(crate) async fn create_join_token(
        &self,
        a: &Auth,
        req: CreateJoinTokenRequest,
    ) -> Result<CreateJoinTokenResponse, Status> {
        if self.0.join_addr.is_empty() {
            return Err(Status::new(
                Code::FailedPrecondition,
                "joining is disabled on this server (no join listener)",
            ));
        }
        if !req.site.is_empty()
            && let Err(e) = check_label_value(&req.site)
        {
            return Err(Status::new(Code::InvalidArgument, format!("site: {e}")));
        }
        let (mut join_addr, mut public) = (self.0.join_addr.clone(), self.0.join_public);
        if !public {
            let leader = self.leader_site().await.map_err(|e| store_err(&e))?;
            if req.site != leader {
                if self.0.join_site_addr.is_empty() {
                    return Err(Status::new(
                        Code::FailedPrecondition,
                        "machines of another site join over the leader's public address, and the leader has none: set it with `sudo armadad endpoint set IP` on the leader",
                    ));
                }
                join_addr = self.0.join_site_addr.clone();
                public = true;
            }
        }
        let mut ttl = req.ttl_seconds;
        let (def, most) = if public {
            (DEFAULT_MESH_TOKEN_TTL, MAX_MESH_TOKEN_TTL)
        } else if req.server {
            (DEFAULT_SERVER_TOKEN_TTL, MAX_TOKEN_TTL)
        } else {
            (DEFAULT_TOKEN_TTL, MAX_TOKEN_TTL)
        };
        if ttl == 0 {
            ttl = def;
        }
        let dur = |s: i64| armada_spec::go::format_duration(s * 1_000_000_000);
        if !(MIN_TOKEN_TTL..=most).contains(&ttl) {
            return Err(Status::new(
                Code::InvalidArgument,
                format!(
                    "token lifetime must be between {} and {}",
                    dur(MIN_TOKEN_TTL),
                    dur(most)
                ),
            ));
        }
        let from = req.from.clone();
        if !from.is_empty() {
            if !public {
                return Err(Status::new(
                    Code::InvalidArgument,
                    "--from is for joins over the leader's public address (mesh clusters, and other sites than the leader's); this one is on the private network",
                ));
            }
            let ok = parse_addr(&from).is_some_and(|a| {
                a.zone.is_empty() && a.string() == from && global_unicast(ip_of(&a))
            });
            if !ok {
                return Err(Status::new(
                    Code::InvalidArgument,
                    format!(
                        "--from {}: want the unicast IP address the machine joins from",
                        quote(&from)
                    ),
                ));
            }
        }
        if req.server {
            if self.0.cluster.is_none() || self.0.keys.is_none() {
                return Err(Status::new(
                    Code::FailedPrecondition,
                    "this server cannot add control plane nodes",
                ));
            }
            if ttl > MAX_SERVER_TOKEN_TTL {
                return Err(Status::new(
                    Code::InvalidArgument,
                    format!(
                        "server token lifetime must be at most {}",
                        dur(MAX_SERVER_TOKEN_TTL)
                    ),
                ));
            }
        }
        for (k, v) in &req.labels {
            check_admin_label(k, v).map_err(|e| Status::new(Code::InvalidArgument, e))?;
        }
        if req.labels.len() > MAX_NODE_LABELS {
            return Err(Status::new(
                Code::InvalidArgument,
                format!("at most {MAX_NODE_LABELS} labels"),
            ));
        }
        let tok = armada_pki::new_join_token()
            .map_err(|_| Status::new(Code::Internal, "generate token"))?;
        let expires = self.now().add(ttl * 1_000_000_000);
        self.store()
            .create_join_token(&JoinToken {
                id: tok.id.clone(),
                secret_hash: tok.secret_hash(),
                expires_at: expires.clone(),
                created_by: a.actor(),
                server: req.server,
                labels: req.labels.clone(),
                from: from.clone(),
                site: req.site.clone(),
                ..Default::default()
            })
            .await
            .map_err(|e| store_err(&e))?;
        self.wake_join();
        self.0.log.info(
            "join token created",
            &[
                ("token", tok.id.clone()),
                ("server", req.server.to_string()),
                ("by", a.actor()),
            ],
        );
        let ca = self.0.ca.as_ref().expect("joining needs a CA");
        Ok(CreateJoinTokenResponse {
            token: tok.reveal(),
            ca_hash: armada_pki::ca_hash(&ca.cert),
            join_addr,
            expires_at: Some(ts(&expires)),
            version: self.version(),
        })
    }

    /// The release this server is, as `version.Get().Version`.
    pub(crate) fn version(&self) -> String {
        std::env::var("ARMADA_SERVER_VERSION").unwrap_or_else(|_| "dev".to_string())
    }

    /// Checks the address a machine joins with (Go's joiningAddress).
    async fn joining_address(
        &self,
        private_ip: &str,
        key: &str,
        endpoint: &str,
        away: bool,
        behind_nat: bool,
    ) -> Result<(String, Joining), Status> {
        let check_endpoint_ = || -> Result<(), Status> {
            if behind_nat {
                if !endpoint.is_empty() {
                    return Err(Status::new(
                        Code::InvalidArgument,
                        "a machine behind NAT sends no endpoint",
                    ));
                }
                return Ok(());
            }
            check_endpoint(endpoint)
                .map(|_| ())
                .map_err(|e| Status::new(Code::InvalidArgument, format!("endpoint: {e}")))
        };
        let n = match self.store().get_network().await {
            Ok(n) => Some(n),
            Err(e) if e.kind == Kind::NotFound => None,
            Err(_) => {
                return Err(Status::new(Code::Internal, "read the cluster network"));
            }
        };
        let has_cidr = n.as_ref().is_some_and(|n| n.cluster_cidr.is_some());
        let node_ip = |s: &str| -> Result<String, Status> {
            let ip = check_node_ip(s)
                .map_err(|e| Status::new(Code::InvalidArgument, format!("private IP: {e}")))?;
            if has_cidr && !ip.is4 {
                return Err(Status::new(
                    Code::InvalidArgument,
                    format!(
                        "private IP {} is not an IPv4 address; the cluster network carries IPv4 only: join with the machine's private IPv4 address (--private-ip)",
                        ip.string()
                    ),
                ));
            }
            Ok(ip.string())
        };
        if n.as_ref().is_none_or(|n| n.mode != NETWORK_MESH) {
            if !away {
                let ip = node_ip(private_ip)?;
                return Ok((
                    ip,
                    Joining {
                        behind_nat,
                        ..Default::default()
                    },
                ));
            }
            if !valid_network_key(key) {
                return Err(Status::new(
                    Code::InvalidArgument,
                    "a machine of another site needs its WireGuard public key",
                ));
            }
            check_endpoint_()?;
            let mut j = Joining {
                away: true,
                key: key.to_string(),
                endpoint: endpoint.to_string(),
                behind_nat,
                ..Default::default()
            };
            if !private_ip.is_empty() {
                let ip = node_ip(private_ip)?;
                return Ok((ip, j));
            }
            j.meshed = true;
            let ip = self.free_mesh_address().await?;
            return Ok((ip, j));
        }
        if !valid_network_key(key) {
            return Err(Status::new(
                Code::InvalidArgument,
                "a mesh cluster needs the machine's WireGuard public key",
            ));
        }
        check_endpoint_()?;
        let ip = self.free_mesh_address().await?;
        Ok((
            ip,
            Joining {
                on: true,
                key: key.to_string(),
                endpoint: endpoint.to_string(),
                behind_nat,
                ..Default::default()
            },
        ))
    }

    async fn free_mesh_address(&self) -> Result<String, Status> {
        let a = self
            .store()
            .free_mesh_address()
            .await
            .map_err(|e| store_err(&e))?;
        match parse_addr(&a) {
            Some(ip) => Ok(ip.string()),
            None => Err(Status::new(Code::Internal, "mesh address")),
        }
    }

    /// The cluster network's mode for join responses.
    async fn network_mode(&self) -> Result<String, Status> {
        match self.store().get_network().await {
            Ok(n) => Ok(n.mode),
            Err(e) if e.kind == Kind::NotFound => Ok(String::new()),
            Err(_) => Err(Status::new(Code::Internal, "read the cluster network")),
        }
    }
}

/// The addresses open tokens name, or none when a token names none.
fn join_sources(toks: &[JoinToken]) -> Option<HashSet<IpAddr>> {
    let mut m = HashSet::new();
    for t in toks {
        let a = parse_addr(&t.from)?;
        m.insert(ip_of(&a).to_canonical());
    }
    Some(m)
}

/// Stops a join listener: joins in flight get a few seconds.
pub(crate) struct Stopper {
    stop: watch::Sender<bool>,
    kill: watch::Sender<bool>,
    done: tokio::task::JoinHandle<()>,
}

impl Stopper {
    pub(crate) async fn stop(self) {
        let _ = self.stop.send(true);
        let mut done = self.done;
        if tokio::time::timeout(JOIN_STOP_GRACE, &mut done)
            .await
            .is_err()
        {
            let _ = self.kill.send(true);
            let _ = done.await;
        }
        let _ = self.kill.send(true);
    }
}

/// The join listener's one service: only the two join methods, rate
/// limited per source address and overall.
#[derive(Clone)]
struct JoinDispatch {
    srv: Server,
    join: JoinServiceServer<JoinApi>,
}

const JOIN: &str = "/armada.v1.JoinService/Join";
const JOIN_SERVER: &str = "/armada.v1.JoinService/JoinServer";

impl tower::Service<http::Request<Body>> for JoinDispatch {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<http::Response<Body>, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        let srv = self.srv.clone();
        let mut join = self.join.clone();
        Box::pin(async move {
            let path = req.uri().path();
            // grpc-go answers what it does not serve before the interceptor,
            // which refuses anything but the two join methods.
            if path != JOIN && path != JOIN_SERVER {
                return Ok(crate::grpc::unknown_service(path, "armada.v1.JoinService").into_http());
            }
            let src = req
                .extensions()
                .get::<PeerInfo>()
                .map(|p| p.addr.ip().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let now = Instant::now();
            if !srv.0.join_limit.allow(&src, now) || !srv.0.join_global.allow(now) {
                return Ok(Status::new(
                    Code::ResourceExhausted,
                    "too many join attempts; try again later",
                )
                .into_http());
            }
            tower::Service::call(&mut join, req).await
        })
    }
}

#[derive(Clone)]
struct JoinApi {
    srv: Server,
    /// A join listener on the leader's public endpoint.
    public: bool,
}

fn peer_addr<T>(r: &Request<T>) -> String {
    r.extensions()
        .get::<PeerInfo>()
        .map(|p| p.addr.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn peer_sock<T>(r: &Request<T>) -> Option<SocketAddr> {
    r.extensions().get::<PeerInfo>().map(|p| p.addr)
}

impl JoinApi {
    /// Whether a join comes from another site than the leader's (ADR 0050).
    async fn another_site(&self, tok_id: &str) -> Result<bool, Status> {
        let s = &self.srv;
        if !self.public || s.0.join_public {
            return Ok(false);
        }
        let toks = s
            .store()
            .open_join_tokens()
            .await
            .map_err(|_| Status::new(Code::Internal, "read join tokens"))?;
        for t in toks {
            if t.id != tok_id {
                continue;
            }
            let site = s
                .leader_site()
                .await
                .map_err(|_| Status::new(Code::Internal, "read the leader's site"))?;
            if t.site == site {
                return Err(Status::new(
                    Code::PermissionDenied,
                    "this token is for the leader's own site: join at the leader's private address",
                ));
            }
            return Ok(true);
        }
        Err(Status::new(Code::Unauthenticated, "invalid join token"))
    }
}

/// The peer list a machine joining a mesh or from another site brings its
/// tunnels up with comes with the cluster network (pull request 13).
fn needs_network() -> Status {
    Status::new(
        Code::Unimplemented,
        "joining over the leader's public address needs the cluster network's peer list, which this server does not build yet",
    )
}

fn redeem_err(e: armada_store::Error) -> Status {
    match e.kind {
        Kind::NotFound => Status::new(Code::Unauthenticated, "invalid join token"),
        Kind::Conflict => Status::new(Code::AlreadyExists, e.msg),
        _ => Status::new(Code::InvalidArgument, format!("join failed: {}", e.msg)),
    }
}

#[tonic::codegen::async_trait]
impl JoinService for JoinApi {
    /// Join registers a node presenting a valid join token and returns
    /// its certificate. The token secret is never logged.
    async fn join(&self, request: Request<JoinRequest>) -> Result<Response<JoinResponse>, Status> {
        let s = &self.srv;
        let from = peer_addr(&request);
        let _ = peer_sock(&request);
        let req = request.into_inner();
        let tok = armada_pki::parse_join_token(&format!("{}.{}", req.token_id, req.token_secret))
            .map_err(|_| Status::new(Code::Unauthenticated, "invalid join token"))?;
        let name = req.node_name.clone();
        validate_name(&name)
            .map_err(|e| Status::new(Code::InvalidArgument, format!("node name: {e}")))?;
        let away = self.another_site(&tok.id).await?;
        let (ip, mesh) = s
            .joining_address(
                &req.private_ip,
                &req.network_key,
                &req.endpoint,
                away,
                req.behind_nat,
            )
            .await?;
        if req.csr.is_empty() || req.csr.len() > MAX_CSR_SIZE {
            return Err(Status::new(
                Code::InvalidArgument,
                "missing or oversized CSR",
            ));
        }
        if mesh.on || mesh.away {
            return Err(needs_network());
        }
        let ca =
            s.0.ca
                .clone()
                .ok_or_else(|| Status::new(Code::FailedPrecondition, "joining is disabled"))?;
        let issued: Mutex<Option<armada_pki::NodeCert>> = Mutex::new(None);
        let validity = s.0.node_cert_validity;
        let secret = tok.secret().to_string();
        let res = s
            .store()
            .redeem_join_token(
                &tok.id,
                &|hash| armada_pki::token_secret_matches(&secret, hash),
                &mesh.node(&name, &ip),
                &|| {
                    let c = ca
                        .sign_node_csr(&req.csr, &name, validity)
                        .map_err(|e| armada_store::Error::other(e.to_string()))?;
                    let rec = armada_store::NodeCert {
                        serial: c.serial.clone(),
                        not_after: armada_store::gojson::from_unix(c.not_after),
                    };
                    *issued.lock().unwrap_or_else(|p| p.into_inner()) = Some(c);
                    Ok(rec)
                },
            )
            .await;
        if let Err(e) = res {
            match e.kind {
                Kind::NotFound => s.0.log.warn(
                    "join rejected: bad token",
                    &[
                        ("token", tok.id.clone()),
                        ("node", name.clone()),
                        ("from", from.clone()),
                    ],
                ),
                Kind::Conflict => {}
                _ => s.0.log.warn(
                    "join failed",
                    &[
                        ("token", tok.id.clone()),
                        ("node", name.clone()),
                        ("from", from.clone()),
                        ("err", e.to_string()),
                    ],
                ),
            }
            return Err(redeem_err(e));
        }
        let cert_pem = issued
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .map(|c| c.pem)
            .unwrap_or_default();
        let eps = s
            .endpoints()
            .await
            .map_err(|_| Status::new(Code::Internal, "list servers"))?;
        let n = s
            .store()
            .get_node(&name)
            .await
            .map_err(|_| Status::new(Code::Internal, "read the new node"))?;
        let mode = s.network_mode().await?;
        let mut resp = JoinResponse {
            node_cert: cert_pem,
            ca_cert: ca.cert_pem.clone(),
            servers: eps,
            node_subnet: n.subnet.clone(),
            network_mode: mode,
            ..Default::default()
        };
        if mesh.on || mesh.meshed {
            resp.mesh_ip = ip.clone();
        }
        s.wake_join();
        s.0.log.info(
            "node joined",
            &[
                ("node", name.clone()),
                ("private_ip", ip.clone()),
                ("subnet", n.subnet),
                ("token", tok.id.clone()),
                ("version", req.version),
            ],
        );
        s.record(event(
            events::NODE,
            &name,
            &name,
            "Joined",
            &format!("joined from {ip}"),
        ))
        .await;
        s.trigger();
        Ok(Response::new(resp))
    }

    /// JoinServer adds a control plane node presenting a valid server
    /// token: it registers the server and its node, adds its etcd member
    /// as a learner, and returns the cluster's keys. The token secret and
    /// the keys are never logged.
    async fn join_server(
        &self,
        request: Request<JoinServerRequest>,
    ) -> Result<Response<JoinServerResponse>, Status> {
        let s = &self.srv;
        let (Some(cluster), Some(keys), Some(ca)) =
            (s.0.cluster.clone(), s.0.keys.clone(), s.0.ca.clone())
        else {
            return Err(Status::new(
                Code::FailedPrecondition,
                "this server cannot add control plane nodes",
            ));
        };
        let from = peer_addr(&request);
        let req = request.into_inner();
        let tok = armada_pki::parse_join_token(&format!("{}.{}", req.token_id, req.token_secret))
            .map_err(|_| Status::new(Code::Unauthenticated, "invalid join token"))?;
        let name = req.name.clone();
        validate_name(&name)
            .map_err(|e| Status::new(Code::InvalidArgument, format!("server name: {e}")))?;
        let away = self.another_site(&tok.id).await?;
        let (ip, mesh) = s
            .joining_address(
                &req.private_ip,
                &req.network_key,
                &req.endpoint,
                away,
                false,
            )
            .await?;
        if req.node_csr.is_empty() || req.node_csr.len() > MAX_CSR_SIZE {
            return Err(Status::new(
                Code::InvalidArgument,
                "missing or oversized CSR",
            ));
        }
        let mut ports = vec![req.api_port, req.etcd_peer_port];
        if req.join_port != 0 {
            ports.push(req.join_port);
        }
        for p in ports {
            if !(1..=65535).contains(&p) {
                return Err(Status::new(
                    Code::InvalidArgument,
                    format!("invalid port {p}"),
                ));
            }
        }
        if mesh.on || mesh.away {
            return Err(needs_network());
        }
        let ip_addr = ip_of(&parse_addr(&ip).expect("a checked address"));
        let host = SocketAddr::new(ip_addr, 0);
        let join_host = |port: i32| {
            let mut a = host;
            a.set_port(port as u16);
            a.to_string()
        };
        let api_addr = join_host(req.api_port);
        let join_addr = if req.join_port != 0 {
            join_host(req.join_port)
        } else {
            String::new()
        };
        let mut srv = armada_store::Server {
            name: name.clone(),
            private_ip: ip.clone(),
            api_addr,
            join_addr,
            member_id: 0,
            schema: 0,
            version: String::new(),
            created_at: armada_spec::gotime::Time::zero(),
        };
        let issued: Mutex<Option<armada_pki::NodeCert>> = Mutex::new(None);
        let validity = s.0.node_cert_validity;
        let secret = tok.secret().to_string();
        let res = s
            .store()
            .redeem_server_token(
                &tok.id,
                &|hash| armada_pki::token_secret_matches(&secret, hash),
                &srv,
                &mesh.node(&name, &ip),
                &|| {
                    let c = ca
                        .sign_node_csr(&req.node_csr, &name, validity)
                        .map_err(|e| armada_store::Error::other(e.to_string()))?;
                    let rec = armada_store::NodeCert {
                        serial: c.serial.clone(),
                        not_after: armada_store::gojson::from_unix(c.not_after),
                    };
                    *issued.lock().unwrap_or_else(|p| p.into_inner()) = Some(c);
                    Ok(rec)
                },
            )
            .await;
        if let Err(e) = res {
            match e.kind {
                Kind::NotFound => s.0.log.warn(
                    "server join rejected: bad token",
                    &[
                        ("token", tok.id.clone()),
                        ("server", name.clone()),
                        ("from", from.clone()),
                    ],
                ),
                Kind::Conflict => {}
                _ => s.0.log.warn(
                    "server join failed",
                    &[
                        ("token", tok.id.clone()),
                        ("server", name.clone()),
                        ("from", from.clone()),
                        ("err", e.to_string()),
                    ],
                ),
            }
            return Err(redeem_err(e));
        }
        let node_cert_pem = issued
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .map(|c| c.pem)
            .unwrap_or_default();
        // The token is spent; if the rest fails, undo the registration so
        // the name and IP can be used with a new token.
        let undo = |cause: String| {
            let s = s.clone();
            let name = name.clone();
            let actor = format!("token:{}", tok.id);
            let from = from.clone();
            async move {
                let r1 = s.store().remove_server(&name, &actor).await;
                let r2 = s.store().remove_node(&name, true, &actor).await;
                let cleanup: Vec<String> = [r1.err(), r2.err()]
                    .into_iter()
                    .flatten()
                    .map(|e| e.to_string())
                    .collect();
                s.0.log.warn(
                    "server join failed",
                    &[
                        ("server", name),
                        ("from", from),
                        ("err", cause.clone()),
                        ("cleanup_err", cleanup.join("\n")),
                    ],
                );
                Status::new(Code::FailedPrecondition, format!("join failed: {cause}"))
            }
        };
        let added = tokio::time::timeout(
            Duration::from_secs(20),
            cluster.add_learner(&name, ip_addr, req.etcd_peer_port as u16),
        )
        .await
        .unwrap_or_else(|_| Err("context deadline exceeded".to_string()));
        let (member_id, initial) = match added {
            Ok(v) => v,
            Err(e) => return Err(undo(e).await),
        };
        srv.member_id = member_id;
        if let Err(e) = s.store().upsert_server(&srv).await {
            let _ = cluster.remove_member(member_id).await;
            return Err(undo(e.to_string()).await);
        }
        let (srv_cert, srv_key) = ca
            .issue(&IssueRequest {
                identity: armada_pki::Identity::new(KIND_SERVER, &name),
                dns_names: vec![SERVER_NAME.to_string()],
                ips: vec![ip_addr],
                server: true,
                ..Default::default()
            })
            .map_err(|_| Status::new(Code::Internal, "issue server certificate"))?;
        let eps = s
            .endpoints()
            .await
            .map_err(|_| Status::new(Code::Internal, "list servers"))?;
        let n = s
            .store()
            .get_node(&name)
            .await
            .map_err(|_| Status::new(Code::Internal, "read the new node"))?;
        let mode = s.network_mode().await?;
        // The joining machine signs a user certificate for its admin
        // configs with the CA it receives: record the name first.
        let mut recorded = false;
        let u = req.user_name.clone();
        if !u.is_empty() {
            if armada_pki::parse_identity(&format!("{KIND_USER}:{u}")).is_err() {
                s.0.log.warn(
                    "server join: invalid user name; no client config",
                    &[("server", name.clone())],
                );
            } else if let Err(e) = s.store().know_user(&u).await {
                s.0.log.warn(
                    "server join: could not record the user; no client config",
                    &[
                        ("server", name.clone()),
                        ("user", u.clone()),
                        ("err", e.to_string()),
                    ],
                );
            } else {
                recorded = true;
            }
        }
        s.0.log.info(
            "server joined",
            &[
                ("server", name.clone()),
                ("private_ip", ip.clone()),
                ("subnet", n.subnet.clone()),
                ("token", tok.id.clone()),
                ("version", req.version.clone()),
                ("user_recorded", recorded.to_string()),
            ],
        );
        let mut resp = JoinServerResponse {
            ca_cert: ca.cert_pem.clone(),
            ca_key: ca.key_pem().expose().to_vec(),
            master_key: keys.export().bytes().to_vec(),
            server_cert: srv_cert,
            server_key: srv_key.expose().to_vec(),
            node_cert: node_cert_pem,
            initial_cluster: initial,
            servers: eps,
            node_subnet: n.subnet,
            network_mode: mode,
            user_recorded: recorded,
            ..Default::default()
        };
        if mesh.on || mesh.meshed {
            resp.mesh_ip = ip;
        }
        s.wake_join();
        s.trigger();
        Ok(Response::new(resp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        assert!(valid_network_key(
            "zUiUUFo68E2u1IYbL+/4fuSeNfPVSTmKuhjVqJzBAzk="
        ));
        assert!(!valid_network_key(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        ));
        assert!(!valid_network_key("short"));
    }

    #[test]
    fn unicast() {
        assert!(global_unicast("8.8.8.8".parse().unwrap()));
        assert!(global_unicast("10.0.0.1".parse().unwrap()));
        assert!(!global_unicast("127.0.0.1".parse().unwrap()));
        assert!(!global_unicast("fe80::1".parse().unwrap()));
    }
}

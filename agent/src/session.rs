//! The session with the control plane (Go's Agent.Run and session): the
//! node certificate's mTLS connection to the servers in order, Hello, the
//! Connect stream, the reconnect timing, and the loops that run beside it.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use armada_proto::armada::v1 as pb;
use pb::agent_service_client::AgentServiceClient;
use rustls_pki_types::ServerName;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint, Uri};

use crate::agent::{Agent, Inner, StreamState, go_platform, lock};
use crate::clock;
use crate::creds::Credentials;
use crate::proxy::{BoxFut, CertificateSource};
use crate::runtime::Runtime;

/// The pause after a session the server had accepted.
pub const RECONNECT_DELAY: Duration = Duration::from_millis(100);
/// For FAILOVER_WINDOW after a session ends the agent tries again every
/// FAILOVER_RETRY (plus up to a quarter of it): electing a leader takes
/// seconds, and the node's proxy keeps the old configuration meanwhile.
pub const FAILOVER_WINDOW: Duration = Duration::from_secs(120);
pub const FAILOVER_RETRY: Duration = Duration::from_secs(1);
/// How long the agent waits for the server's first message.
pub const SESSION_ANSWER: Duration = Duration::from_secs(10);
/// The longest wait between attempts outside a failover.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// The largest message the agent takes from the server.
pub const AGENT_MAX_RECV: usize = 64 << 20;

/// How long the agent waits before connecting again, and its backoff and
/// the time the last accepted session ended afterwards (Go's
/// reconnectWait); jitter is added to failover retries (below a quarter
/// of FAILOVER_RETRY).
pub fn reconnect_wait(
    accepted: bool,
    backoff: Duration,
    lost: Option<SystemTime>,
    now: SystemTime,
    jitter: Duration,
) -> (Duration, Duration, Option<SystemTime>) {
    if accepted {
        // A session the server accepted is not a failure to back off from.
        return (RECONNECT_DELAY, Duration::from_secs(1), Some(now));
    }
    if let Some(l) = lost
        && clock::sub(now, l) < FAILOVER_WINDOW.as_nanos() as i64
    {
        // The servers are choosing a new leader: ask again every second.
        return (FAILOVER_RETRY + jitter, backoff, lost);
    }
    (backoff, (backoff * 2).min(MAX_BACKOFF), lost)
}

/// A jitter below a quarter of FAILOVER_RETRY (not security sensitive).
fn jitter() -> Duration {
    use std::hash::{BuildHasher, RandomState};
    let n = RandomState::new().hash_one(SystemTime::now());
    Duration::from_nanos(n % (FAILOVER_RETRY.as_nanos() as u64 / 4))
}

/// The agent's connection to the control plane: the servers tried in
/// order with the node certificate, the connection replaced by `redial`
/// so the next handshake uses a renewed certificate.
pub struct ServerConn {
    creds: Arc<Credentials>,
    servers: Arc<Mutex<Vec<String>>>,
    ch: Mutex<Channel>,
}

impl ServerConn {
    /// A connection to `servers` (host:port each), made on first use.
    pub fn new(creds: Arc<Credentials>, servers: Vec<String>) -> Result<ServerConn, String> {
        if servers.is_empty() {
            return Err("no control plane address".to_string());
        }
        let servers = Arc::new(Mutex::new(servers));
        let ch = dial(&creds, &servers)?;
        Ok(ServerConn {
            creds,
            servers,
            ch: Mutex::new(ch),
        })
    }

    /// The AgentService client of the current connection.
    pub fn client(&self) -> AgentServiceClient<Channel> {
        AgentServiceClient::new(lock(&self.ch).clone()).max_decoding_message_size(AGENT_MAX_RECV)
    }

    /// Replaces the connection, ending its streams.
    pub fn redial(&self) -> Result<(), String> {
        let ch = dial(&self.creds, &self.servers)?;
        *lock(&self.ch) = ch;
        Ok(())
    }

    /// Replaces the servers tried by the next connection.
    pub fn set_servers(&self, servers: Vec<String>) {
        if !servers.is_empty() {
            *lock(&self.servers) = servers;
        }
    }

    pub fn credentials(&self) -> &Arc<Credentials> {
        &self.creds
    }
}

fn dial(creds: &Arc<Credentials>, servers: &Arc<Mutex<Vec<String>>>) -> Result<Channel, String> {
    let tls = tokio_rustls::TlsConnector::from(Arc::new(creds.tls_config()?));
    let name =
        ServerName::try_from(armada_pki::SERVER_NAME.to_string()).map_err(|e| e.to_string())?;
    let ep = Endpoint::from_static("http://control-plane")
        .tcp_nodelay(true)
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(10))
        .keep_alive_while_idle(true);
    let servers = servers.clone();
    let connector = tower::service_fn(move |_: Uri| {
        let tls = tls.clone();
        let name = name.clone();
        let addrs = lock(&servers).clone();
        async move {
            let mut last = std::io::Error::other("no control plane address");
            // pick_first: the servers in order, the first that answers.
            for a in addrs {
                let tcp = match tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::net::TcpStream::connect(&a),
                )
                .await
                {
                    Ok(Ok(t)) => t,
                    Ok(Err(e)) => {
                        last = e;
                        continue;
                    }
                    Err(_) => {
                        last = std::io::Error::other(format!("dial tcp {a}: i/o timeout"));
                        continue;
                    }
                };
                tcp.set_nodelay(true)?;
                match tls.connect(name.clone(), tcp).await {
                    Ok(s) => return Ok(hyper_util::rt::TokioIo::new(s)),
                    Err(e) => last = e,
                }
            }
            Err(last)
        }
    });
    Ok(ep.connect_with_connector_lazy(connector))
}

impl CertificateSource for ServerConn {
    fn get_certificates(
        &self,
        names: Vec<String>,
    ) -> BoxFut<'_, Result<Vec<pb::ProxyCertificate>, String>> {
        let mut client = self.client();
        Box::pin(async move {
            client
                .get_certificates(pb::GetCertificatesRequest { names })
                .await
                .map(|r| r.into_inner().certificates)
                .map_err(|e| e.message().to_string())
        })
    }
}

impl<R: Runtime> Agent<R> {
    /// The Hello the agent opens every session with.
    pub fn hello(&self) -> pb::Hello {
        self.inner.hello()
    }

    /// Connects to the server and reconciles until the future is dropped;
    /// it ends early only when the runtime cannot be reached.
    pub async fn run(&self, conn: Arc<ServerConn>) -> Result<(), String> {
        let inner = &self.inner;
        inner
            .rt
            .ping()
            .await
            .map_err(|e| format!("container runtime: {e}"))?;
        if let Err(e) = inner.rt.agent_start().await {
            inner
                .log
                .warn("container runtime start", &[("err", e.to_string())]);
        }
        *lock(&inner.cert_source) = Some(conn.clone());
        let mut loops = JoinSet::new();
        loops.spawn(inner.clone().reconcile_loop());
        loops.spawn(inner.clone().usage_loop());
        if !inner.cfg.wake_socket.is_empty() {
            loops.spawn(inner.clone().serve_wake(inner.cfg.wake_socket.clone()));
        }
        let mut backoff = Duration::from_secs(1);
        let mut lost = None;
        loop {
            let start = tokio::time::Instant::now();
            let (established, err) = inner.session(&conn).await;
            let accepted = established || start.elapsed() > Duration::from_secs(60);
            let wait;
            (wait, backoff, lost) = reconnect_wait(accepted, backoff, lost, inner.now(), jitter());
            inner.log.warn(
                "disconnected from server",
                &[
                    ("err", err),
                    ("retry_in", clock::duration_string(wait.as_nanos() as i64)),
                ],
            );
            tokio::time::sleep(wait).await;
        }
    }

    /// Renews the node certificate once it enters the last third of its
    /// lifetime (checked every interval), then redials.
    pub async fn renew_loop(&self, conn: Arc<ServerConn>, interval: Duration) {
        let log = &self.inner.log;
        loop {
            let creds = conn.credentials().clone();
            if armada_pki::needs_renewal(&creds.leaf(), SystemTime::now()) {
                match creds.renew(&mut conn.client()).await {
                    Err(e) => log.warn("node certificate renewal failed; retrying", &[("err", e)]),
                    Ok(()) => {
                        log.info("node certificate renewed", &[]);
                        if let Err(e) = conn.redial() {
                            log.warn("reconnect after renewal failed", &[("err", e)]);
                        }
                    }
                }
            }
            tokio::time::sleep(interval).await;
        }
    }
}

impl<R: Runtime> Inner<R> {
    pub(crate) fn hello(&self) -> pb::Hello {
        let network_key = {
            let st = lock(&self.st);
            if st.network_key.is_empty() {
                self.cfg.network_key.clone()
            } else {
                st.network_key.clone()
            }
        };
        let (os, arch) = go_platform();
        pb::Hello {
            cpu_millis: self.cfg.cpu_millis,
            memory_bytes: self.cfg.memory_bytes,
            version: self.cfg.version.clone(),
            private_ip: self.cfg.private_ip.clone(),
            os: if self.cfg.os.is_empty() {
                os.into()
            } else {
                self.cfg.os.clone()
            },
            arch: if self.cfg.arch.is_empty() {
                arch.into()
            } else {
                self.cfg.arch.clone()
            },
            jobs: true,
            volumes: self.mounts_volumes(),
            containers: self.rt.can_run_members(),
            network_key: network_key.clone(),
            endpoint: self.cfg.endpoint.clone(),
            behind_nat: self.cfg.behind_nat,
            key_rotation: self.cfg.network.as_ref().is_some_and(|n| n.rotates_keys())
                && !network_key.is_empty(),
            certificate_refs: true,
            // Queue sandboxes and NFS need the parts of a later pull
            // request: announced as a Go agent without them does.
            queue_sandboxes: false,
            held_replicas: true,
            volume_backups: self.mounts_volumes(),
            nfs: false,
            log_history: self.rt.has_log_history(),
            network_switch: self.switcher().is_some(),
            runtime_move: self.cfg.move_runtime.is_some(),
        }
    }

    /// Runs one stream; whether the server accepted it (sent a message),
    /// and why it ended.
    pub(crate) async fn session(self: &Arc<Self>, conn: &ServerConn) -> (bool, String) {
        let (tx, rx) = mpsc::channel(64);
        let hello = pb::AgentMessage {
            msg: Some(pb::agent_message::Msg::Hello(self.hello())),
        };
        if tx.send(hello).await.is_err() {
            return (false, "the stream closed".into());
        }
        let mut client = conn.client();
        // Reports go on the stream from now on, as Go's agent sends them
        // once its Hello is out.
        *lock(&self.stream) = StreamState {
            tx: Some(tx),
            last_sent: None,
        };
        // A server answers a hello at once; one that does not is given up
        // on, so the agent finds the leader again.
        let first = tokio::time::timeout(SESSION_ANSWER, async {
            let mut inbound = client
                .connect(ReceiverStream::new(rx))
                .await
                .map_err(|e| e.message().to_string())?
                .into_inner();
            let m = inbound
                .message()
                .await
                .map_err(|e| e.message().to_string())?;
            Ok::<_, String>((inbound, m))
        })
        .await;
        let (mut inbound, first) = match first {
            Ok(Ok((i, Some(m)))) => (i, m),
            other => {
                lock(&self.stream).tx = None;
                return match other {
                    Err(_) => (false, "context canceled".into()),
                    Ok(Err(e)) => (false, e),
                    _ => (false, "EOF".into()),
                };
            }
        };
        self.set_contact(true);
        self.log.info("connected to server", &[]);
        let mut msg = first;
        let err = loop {
            self.handle(msg);
            msg = match inbound.message().await {
                Ok(Some(m)) => m,
                Ok(None) => break "EOF".to_string(),
                Err(e) => break e.message().to_string(),
            };
        };
        lock(&self.stream).tx = None;
        self.set_contact(false);
        (true, err)
    }

    /// One message from the server. Log, exec, and volume sessions come
    /// with a later part.
    fn handle(self: &Arc<Self>, msg: pb::ServerMessage) {
        use pb::server_message::Msg;
        match msg.msg {
            Some(Msg::Assignment(a)) => self.assign(&a),
            Some(Msg::RotateNetworkKey(_)) => {
                let me = self.clone();
                tokio::spawn(async move { me.rotate_network_key().await });
            }
            Some(Msg::MoveRuntime(m)) => {
                let me = self.clone();
                tokio::spawn(async move { me.move_runtime(&m.to).await });
            }
            _ => {}
        }
    }

    pub(crate) async fn reconcile_loop(self: Arc<Self>) {
        let every = self.cfg.resync;
        let mut t = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        let mut last_prune = tokio::time::Instant::now();
        loop {
            tokio::select! {
                _ = t.tick() => {}
                _ = self.trigger.notified() => {}
            }
            self.fence_unassigned().await;
            match self.reconcile().await {
                Err(e) => {
                    self.log
                        .error("reconcile failed", &[("err", e.to_string())]);
                    continue;
                }
                Ok(Some(r)) => self.send_report(&r),
                Ok(None) => {}
            }
            if let Some(p) = self.cfg.image_prune
                && last_prune.elapsed() >= p
            {
                last_prune = tokio::time::Instant::now();
                self.prune_images().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_waits() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let s = Duration::from_secs;
        assert_eq!(
            reconnect_wait(true, s(8), None, now, Duration::ZERO),
            (RECONNECT_DELAY, s(1), Some(now))
        );
        let j = Duration::from_millis(100);
        assert_eq!(
            reconnect_wait(false, s(1), Some(now), now + s(5), j),
            (FAILOVER_RETRY + j, s(1), Some(now))
        );
        assert_eq!(
            reconnect_wait(false, s(16), Some(now), now + FAILOVER_WINDOW, j),
            (s(16), MAX_BACKOFF, Some(now))
        );
        assert_eq!(
            reconnect_wait(false, s(1), None, now, j),
            (s(1), s(2), None)
        );
    }
}

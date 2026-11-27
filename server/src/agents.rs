//! Sessions with agents: the Connect stream, the Hello
//! that opens it, the queue of messages each session sends, and the
//! reports agents send back, checked as untrusted input before they reach
//! the store. Usage samples go to the usage store (`usage`: replica
//! samples, proxy load, queue lengths, and sandboxes' readings) with an
//! event for each replica whose processes were killed at the memory
//! limit, volume sizes, and wake requests to the autoscaler
//! (`autoscale`), the network switch's and runtime's reports, and the
//! requests and egress counted per space; the conditions a usage report
//! starts (unreachable peers, WireGuard in userspace, a failing log
//! export) are recorded here.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use armada_proto::armada::v1::agent_message::Msg as AgentMsg;
use armada_proto::armada::v1::server_message::Msg;
use armada_proto::armada::v1::*;
use armada_spec::go::{parse_addr, parse_prefix, quote};
use armada_spec::validate::{MAX_NODE_LABELS, check_label_value, validate_name};
use armada_store::{
    Kind, NODE_READY, NODE_UNKNOWN, Node, NodeStatus, REPLICA_RUNNING, ReplicaFilter, ReplicaStatus,
};
use tokio::sync::{Notify, mpsc, watch};
use tonic::{Code, Request, Response, Status, Streaming};

use crate::Server;
use crate::admin::Out;
use crate::events::{self, event};
use crate::grpc::auth;
use crate::join::valid_network_key;
use crate::netutil::check_endpoint;

/// The queue of one session.
const QUEUE: usize = 64;
const MAX_NODE_CPU_MILLIS: i64 = 1024 * 1000;
const MAX_NODE_MEMORY: i64 = 16 << 40;
const MAX_UNREACHABLE_PEERS: usize = 32;
const FILE_NETWORK_KEY_HINT: &str = "network.key in the data directory";
const WIREGUARD_USERSPACE_MESSAGE: &str = "the kernel has no WireGuard: traffic to other nodes is encrypted in userspace inside the agent, markedly slower and with more CPU; use a kernel with WireGuard (Linux 5.6 or later) and restart armada-server or armada-agent";

/// What the agent announced it can do (Hello).
#[derive(Clone, Copy, Default)]
pub struct Caps {
    pub cert_refs: bool,
    pub sandboxes: bool,
    pub holds: bool,
    pub backups: bool,
    pub log_history: bool,
    pub net_switch: bool,
    pub key_rotation: bool,
}

struct Queue {
    msgs: VecDeque<ServerMessage>,
    last: Option<Assignment>,
}

/// One connected agent.
pub struct Session {
    pub node_id: String,
    pub caps: Caps,
    q: Mutex<Queue>,
    ready: Notify,
    space: Notify,
    done: watch::Sender<bool>,
}

impl Session {
    fn new(node_id: &str, caps: Caps) -> Session {
        Session {
            node_id: node_id.to_string(),
            caps,
            q: Mutex::new(Queue {
                msgs: VecDeque::new(),
                last: None,
            }),
            ready: Notify::new(),
            space: Notify::new(),
            done: watch::channel(false).0,
        }
    }

    /// Queues a if it differs from the last one sent; with the queue full
    /// it is dropped and retried on the next reconcile.
    pub fn offer_assignment(&self, a: Assignment) {
        let mut q = self.q.lock().unwrap_or_else(|p| p.into_inner());
        if q.last.as_ref() == Some(&a) {
            return;
        }
        if q.msgs.len() < QUEUE {
            q.msgs.push_back(ServerMessage {
                msg: Some(Msg::Assignment(a.clone())),
            });
            q.last = Some(a);
            self.ready.notify_one();
        }
    }

    /// Queues a as the last message of a session that ends: messages still
    /// queued are dropped to make room.
    pub fn end_with(&self, a: Assignment) {
        let mut q = self.q.lock().unwrap_or_else(|p| p.into_inner());
        while q.msgs.len() >= QUEUE {
            q.msgs.pop_front();
        }
        q.msgs.push_back(ServerMessage {
            msg: Some(Msg::Assignment(a.clone())),
        });
        q.last = Some(a);
        self.ready.notify_one();
    }

    /// Queues m when there is room, without waiting.
    pub fn try_offer(&self, m: ServerMessage) -> bool {
        let mut q = self.q.lock().unwrap_or_else(|p| p.into_inner());
        if q.msgs.len() >= QUEUE {
            return false;
        }
        q.msgs.push_back(m);
        self.ready.notify_one();
        true
    }

    /// Queues m, waiting for room at most timeout; false once the session
    /// ended or the wait ran out.
    pub async fn offer(&self, m: ServerMessage, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut done = self.done.subscribe();
        loop {
            let space = self.space.notified();
            {
                let mut q = self.q.lock().unwrap_or_else(|p| p.into_inner());
                if *done.borrow() {
                    return false;
                }
                if q.msgs.len() < QUEUE {
                    q.msgs.push_back(m);
                    self.ready.notify_one();
                    return true;
                }
            }
            tokio::select! {
                _ = space => {}
                _ = crate::stopped(&mut done) => return false,
                _ = tokio::time::sleep_until(deadline) => return false,
            }
        }
    }

    fn pop(&self) -> Option<ServerMessage> {
        let m = self
            .q
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .msgs
            .pop_front();
        if m.is_some() {
            self.space.notify_one();
        }
        m
    }

    /// Ends the session.
    pub fn close(&self) {
        self.done.send_replace(true);
    }

    fn closed(&self) -> bool {
        *self.done.borrow()
    }
}

/// What reports already recorded about revisions, so repeating it costs
/// no reads.
#[derive(Default)]
pub struct Learned(Mutex<HashMap<String, u8>>);

const LEARNED_DIGEST: u8 = 1;
const LEARNED_PLATFORMS: u8 = 2;
const MAX_LEARNED: usize = 1 << 16;

impl Learned {
    fn has(&self, rev: &str, what: u8) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(rev)
            .is_some_and(|v| v & what != 0)
    }

    fn add(&self, rev: &str, what: u8) {
        let mut m = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if m.len() >= MAX_LEARNED {
            m.clear();
        }
        *m.entry(rev.to_string()).or_default() |= what;
    }
}

/// At most the first n bytes of s (a cut character becomes U+FFFD).
fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    String::from_utf8_lossy(&s.as_bytes()[..n]).into_owned()
}

/// A version as `^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$` matches it.
fn valid_version(v: &str) -> bool {
    let b = v.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_alphanumeric()
        && b[1..]
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'+' | b'_' | b'-'))
}

/// A container address of the node subnet: never the network address,
/// the gateway, or the broadcast address.
fn in_node_subnet(a: &armada_spec::go::Addr, subnet: &str) -> bool {
    let Some(p) = parse_prefix(subnet) else {
        return false;
    };
    if !p.addr.is4 || !p.contains(a) {
        return false;
    }
    let host = a.bytes[3];
    p.bits == 24 && host != 0 && host != 1 && host != 255
}

/// "<node private IP>:<port>", or with the cluster
/// network "<address in the node's subnet>:<port>", canonical.
pub(crate) fn valid_replica_address(addr: &str, node_ip: &str, subnet: &str) -> bool {
    let (host, port) = if let Some(rest) = addr.strip_prefix('[') {
        let Some((h, p)) = rest.split_once("]:") else {
            return false;
        };
        (h, p)
    } else {
        let Some((h, p)) = addr.rsplit_once(':') else {
            return false;
        };
        if h.contains(':') {
            return false;
        }
        (h, p)
    };
    let Some(ip) = parse_addr(host) else {
        return false;
    };
    let Ok(port) = port.parse::<u16>() else {
        return false;
    };
    if port == 0 || !ip.zone.is_empty() || port.to_string() != port_text(addr) {
        return false;
    }
    let canon = if ip.is4 {
        format!("{}:{port}", ip.string())
    } else {
        format!("[{}]:{port}", ip.string())
    };
    if canon != addr {
        return false;
    }
    if ip.string() == node_ip {
        return true;
    }
    in_node_subnet(&ip, subnet)
}

fn port_text(addr: &str) -> &str {
    addr.rsplit_once(':').map(|(_, p)| p).unwrap_or("")
}

/// A container address in the node's subnet, canonical.
pub(crate) fn valid_replica_ip(ip: &str, subnet: &str) -> bool {
    parse_addr(ip)
        .is_some_and(|a| a.zone.is_empty() && a.string() == ip && in_node_subnet(&a, subnet))
}

/// `@sha256:[a-f0-9]{64}$`.
fn digest_ok(d: &str) -> bool {
    let Some(i) = d.rfind("@sha256:") else {
        return false;
    };
    let hex = &d[i + 8..];
    hex.len() == 64
        && hex
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn image_repo(r: &str) -> &str {
    if let Some(i) = r.find('@') {
        return &r[..i];
    }
    let slash = r.rfind('/').map(|i| i as isize).unwrap_or(-1);
    if let Some(i) = r.rfind(':')
        && i as isize > slash
    {
        return &r[..i];
    }
    r
}

fn normalize_repo(r: &str) -> &str {
    let r = r.strip_prefix("docker.io/").unwrap_or(r);
    r.strip_prefix("library/").unwrap_or(r)
}

/// Valid "os/arch" entries, sorted, without duplicates.
fn clean_platforms(reported: &[String]) -> Option<Vec<String>> {
    if reported.len() > MAX_NODE_LABELS {
        return None;
    }
    let mut out: Vec<String> = Vec::new();
    for p in reported {
        let (os, arch) = p.split_once('/')?;
        if check_label_value(os).is_err() || check_label_value(arch).is_err() {
            return None;
        }
        if !out.contains(p) {
            out.push(p.clone());
        }
    }
    out.sort();
    (!out.is_empty()).then_some(out)
}

fn same_status(have: &armada_store::Replica, st: &ReplicaStatus) -> bool {
    have.state == st.state
        && have.container_id == st.container_id
        && have.address == st.address
        && have.ip == st.ip
        && have.message == st.message
        && have.ready == (st.ready && st.state == REPLICA_RUNNING)
        && have.finished == st.finished
        && (have.finished || have.exit_code == st.exit_code)
}

fn wall() -> armada_spec::gotime::Time {
    armada_store::gojson::now()
}

impl Server {
    pub(crate) fn session(&self, node: &str) -> Option<Arc<Session>> {
        self.0
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(node)
            .cloned()
    }

    pub(crate) fn sessions(&self) -> Vec<Arc<Session>> {
        self.0
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .cloned()
            .collect()
    }

    /// Connect handles an agent's control stream.
    pub(crate) async fn connect(
        &self,
        request: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Out<ServerMessage>>, Status> {
        let a = auth(&request)?;
        let mut stream = request.into_inner();
        let mut node = match self.store().get_node(&a.id.name).await {
            Ok(n) => n,
            Err(e) if e.kind == Kind::NotFound => {
                return Err(Status::new(
                    Code::PermissionDenied,
                    format!("node {} is not registered", a.id.name),
                ));
            }
            Err(_) => return Err(Status::new(Code::Internal, "load node")),
        };
        let first = match stream.message().await? {
            Some(m) => m,
            None => return Err(Status::new(Code::Unknown, "EOF")),
        };
        let Some(AgentMsg::Hello(mut hello)) = first.msg else {
            return Err(Status::new(
                Code::InvalidArgument,
                "first message must be hello",
            ));
        };
        if hello.private_ip != node.private_ip {
            return Err(Status::new(
                Code::FailedPrecondition,
                format!(
                    "agent reports private IP {} but node is registered with {}",
                    quote(&hello.private_ip),
                    quote(&node.private_ip)
                ),
            ));
        }
        let sess = Arc::new(Session::new(
            &node.id,
            Caps {
                cert_refs: hello.certificate_refs,
                sandboxes: hello.queue_sandboxes,
                holds: hello.held_replicas,
                backups: hello.volume_backups,
                log_history: hello.log_history,
                net_switch: hello.network_switch,
                key_rotation: hello.key_rotation,
            },
        ));
        {
            let mut m = self.0.sessions.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(old) = m.insert(node.id.clone(), sess.clone()) {
                old.close();
            }
        }
        // Self-reported and untrusted: bounded to plausible values.
        hello.cpu_millis = hello.cpu_millis.clamp(0, MAX_NODE_CPU_MILLIS);
        hello.memory_bytes = hello.memory_bytes.clamp(0, MAX_NODE_MEMORY);
        node.cpu_millis = hello.cpu_millis;
        node.memory_bytes = hello.memory_bytes;
        node.jobs = hello.jobs;
        node.volumes = hello.volumes;
        node.containers = hello.containers;
        node.nfs = hello.nfs;
        if !valid_version(&hello.version) {
            hello.version.clear();
        }
        if check_label_value(&hello.os).is_err() {
            hello.os.clear();
        }
        if check_label_value(&hello.arch).is_err() {
            hello.arch.clear();
        }
        if !valid_network_key(&hello.network_key) {
            hello.network_key.clear();
        }
        if check_endpoint(&hello.endpoint).is_err() || hello.behind_nat {
            hello.endpoint.clear();
        }
        let res = self
            .store()
            .set_node_status(
                &node.id,
                &NodeStatus {
                    state: NODE_READY.to_string(),
                    last_seen: wall(),
                    cpu_millis: hello.cpu_millis,
                    memory_bytes: hello.memory_bytes,
                    version: hello.version.clone(),
                    os: hello.os.clone(),
                    arch: hello.arch.clone(),
                    jobs: hello.jobs,
                    volumes: hello.volumes,
                    containers: hello.containers,
                    nfs: hello.nfs,
                    network_key: hello.network_key.clone(),
                    endpoint: hello.endpoint.clone(),
                    behind_nat: hello.behind_nat,
                    ..Default::default()
                },
            )
            .await;
        if let Err(e) = res {
            self.end_session(&node, &hello, &sess).await;
            if e.kind == Kind::Conflict {
                self.0.log.warn(
                    "agent announced another node's network key",
                    &[("node", node.id.clone())],
                );
                return Err(Status::new(
                    Code::FailedPrecondition,
                    format!(
                        "the network key is already used by another node; remove {FILE_NETWORK_KEY_HINT} on this node and restart the agent"
                    ),
                ));
            }
            return Err(Status::new(Code::Internal, "update node"));
        }
        self.0.log.info(
            "agent connected",
            &[
                ("node", node.id.clone()),
                ("version", hello.version.clone()),
            ],
        );
        let mut connected = event(events::NODE, &node.id, &node.id, "Connected", "");
        if !hello.version.is_empty() {
            connected.message = format!("agent {}", hello.version);
        }
        self.record(connected).await;
        self.trigger();

        let (out, rx) = mpsc::channel::<Result<ServerMessage, Status>>(1);
        let srv = self.clone();
        let expiry = (UNIX_EPOCH + Duration::from_secs(a.cert.not_after.max(0) as u64))
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        tokio::spawn(async move {
            let (errc_tx, mut errc) = mpsc::channel::<Option<Status>>(2);
            {
                let srv = srv.clone();
                let node = node.clone();
                let errc_tx = errc_tx.clone();
                tokio::spawn(async move {
                    loop {
                        match stream.message().await {
                            Ok(Some(m)) => srv.handle_agent_message(&node, m).await,
                            Ok(None) => {
                                let _ = errc_tx.send(None).await;
                                return;
                            }
                            Err(e) => {
                                let _ = errc_tx.send(Some(e)).await;
                                return;
                            }
                        }
                    }
                });
            }
            let expired = tokio::time::sleep(expiry);
            tokio::pin!(expired);
            let mut done = sess.done.subscribe();
            let end: Option<Status> = loop {
                if let Some(m) = sess.pop() {
                    if out.send(Ok(m)).await.is_err() {
                        break None;
                    }
                    continue;
                }
                let ready = sess.ready.notified();
                if sess.closed() {
                    // What was queued before the end still goes out: a
                    // removed node's last assignment stops its replicas.
                    while let Some(m) = sess.pop() {
                        if out.send(Ok(m)).await.is_err() {
                            break;
                        }
                    }
                    break Some(Status::new(Code::Aborted, "replaced by a newer connection"));
                }
                tokio::select! {
                    _ = &mut expired => break Some(Status::new(
                        Code::Unauthenticated,
                        "client certificate expired; reconnect with a renewed one",
                    )),
                    _ = ready => {}
                    _ = crate::stopped(&mut done) => {}
                    _ = out.closed() => break None,
                    e = errc.recv() => break e.flatten(),
                }
            };
            srv.end_session(&node, &hello, &sess).await;
            if let Some(e) = end {
                let _ = out.send(Err(e)).await;
            }
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }

    /// The end of a session.
    async fn end_session(&self, node: &Node, hello: &Hello, sess: &Arc<Session>) {
        let current = {
            let mut m = self.0.sessions.lock().unwrap_or_else(|p| p.into_inner());
            let cur = m.get(&node.id).is_some_and(|s| Arc::ptr_eq(s, sess));
            if cur {
                m.remove(&node.id);
                sess.close();
            }
            cur
        };
        if !current {
            return;
        }
        self.0.usage.forget(&node.id);
        let _ = self
            .store()
            .set_node_status(
                &node.id,
                &NodeStatus {
                    state: NODE_UNKNOWN.to_string(),
                    last_seen: wall(),
                    cpu_millis: hello.cpu_millis,
                    memory_bytes: hello.memory_bytes,
                    jobs: hello.jobs,
                    volumes: hello.volumes,
                    containers: hello.containers,
                    nfs: hello.nfs,
                    ..Default::default()
                },
            )
            .await;
        self.0
            .log
            .info("agent disconnected", &[("node", node.id.clone())]);
        self.record(event(events::NODE, &node.id, &node.id, "Disconnected", ""))
            .await;
    }

    async fn handle_agent_message(&self, node: &Node, m: AgentMessage) {
        match m.msg {
            Some(AgentMsg::Report(r)) => self.apply_report(node, &r).await,
            Some(AgentMsg::Usage(u)) => {
                if self.0.usage.set(&node.id, &u, self.now()) {
                    // A new length of a job's queue may start runs.
                    self.trigger();
                }
                for e in self.0.usage.out_of_memory(&node.id, &u) {
                    self.record(e).await;
                }
                if u.volumes_measured {
                    self.0.usage.set_volumes(&node.id, &u, self.now());
                }
                self.peers_checked(&node.id, &u).await;
                let le = u.log_export.unwrap_or_default();
                let mut e = event(
                    events::NODE,
                    &node.id,
                    &node.id,
                    "LogExportFailing",
                    &format!("sending logs failed: {}", le.error),
                );
                e.node = node.id.clone();
                self.condition(&format!("log-export:{}", node.id), le.failing, e)
                    .await;
            }
            Some(AgentMsg::Wake(w)) => self.wake_app(&node.id, &w.app).await,
            Some(AgentMsg::NetworkKey(k)) => {
                self.network_key_changed(&node.id, &k.public_key).await
            }
            _ => {}
        }
    }

    /// Stores status from an agent. Every field is untrusted: replicas
    /// must belong to the node, addresses must be on the node's private IP,
    /// and digests must match the revision's repository.
    async fn apply_report(&self, node: &Node, r: &ReplicaReport) {
        if let Err(e) = self
            .store()
            .set_node_status(
                &node.id,
                &NodeStatus {
                    state: NODE_READY.to_string(),
                    last_seen: wall(),
                    cpu_millis: node.cpu_millis,
                    memory_bytes: node.memory_bytes,
                    jobs: node.jobs,
                    volumes: node.volumes,
                    containers: node.containers,
                    nfs: node.nfs,
                    ..Default::default()
                },
            )
            .await
        {
            self.0
                .log
                .warn("update node status", &[("err", e.to_string())]);
        }
        let Ok(owned) = self
            .store()
            .list_replicas(&ReplicaFilter {
                node_id: node.id.clone(),
                ..Default::default()
            })
            .await
        else {
            return;
        };
        let prev: HashMap<String, armada_store::Replica> =
            owned.into_iter().map(|r| (r.id.clone(), r)).collect();
        let mut changed = false;
        for st in &r.replicas {
            let Some(p) = prev.get(&st.id) else {
                continue; // stale or foreign replica
            };
            let rev = p.revision.clone();
            let mut addr = st.address.clone();
            if !addr.is_empty() && !valid_replica_address(&addr, &node.private_ip, &node.subnet) {
                self.0.log.warn(
                    "ignoring invalid replica address",
                    &[
                        ("node", node.id.clone()),
                        ("replica", st.id.clone()),
                        ("address", quote(&truncate(&addr, 128))),
                    ],
                );
                addr.clear();
            }
            let mut ip = st.ip.clone();
            if !ip.is_empty() && !valid_replica_ip(&ip, &node.subnet) {
                self.0.log.warn(
                    "ignoring invalid replica IP",
                    &[
                        ("node", node.id.clone()),
                        ("replica", st.id.clone()),
                        ("ip", quote(&truncate(&ip, 64))),
                    ],
                );
                ip.clear();
            }
            let next = ReplicaStatus {
                id: st.id.clone(),
                state: truncate(&st.state, 32),
                container_id: truncate(&st.container_id, 128),
                address: addr,
                ip,
                message: truncate(&st.message, 512),
                ready: st.ready,
                finished: st.finished,
                exit_code: i64::from(st.exit_code),
            };
            if p.state != next.state
                || p.ready != (next.ready && next.state == REPLICA_RUNNING)
                || p.address != next.address
                || p.ip != next.ip
                || p.finished != next.finished
            {
                changed = true;
            }
            if !same_status(p, &next) {
                match self.store().update_replica_status(&node.id, &next).await {
                    Ok(()) if p.run == 0 => self.replica_event(p, &next).await,
                    Ok(()) => {}
                    Err(e) if e.kind != Kind::NotFound => self
                        .0
                        .log
                        .warn("update replica status", &[("err", e.to_string())]),
                    Err(_) => {}
                }
            }
            if !st.image_digest.is_empty() {
                self.record_digest(&rev, &st.image_digest).await;
            }
            if !st.image_platforms.is_empty() {
                self.record_platforms(&node.id, &rev, &st.image_platforms)
                    .await;
            }
        }
        if changed {
            self.trigger();
        }
    }

    /// Keeps the first valid list of image platforms reported for a
    /// revision (ADR 0014).
    async fn record_platforms(&self, node: &str, rev_name: &str, reported: &[String]) {
        if self.0.learned.has(rev_name, LEARNED_PLATFORMS) {
            return;
        }
        let Ok(rev) = self.store().get_revision(rev_name).await else {
            return;
        };
        if !rev.platforms.is_empty() {
            self.0.learned.add(rev_name, LEARNED_PLATFORMS);
            return;
        }
        let Some(ps) = clean_platforms(reported) else {
            self.0.log.warn(
                "ignoring invalid image platforms",
                &[
                    ("node", node.to_string()),
                    ("revision", rev_name.to_string()),
                    ("count", reported.len().to_string()),
                ],
            );
            return;
        };
        if let Err(e) = self.store().set_revision_platforms(rev_name, &ps).await {
            self.0
                .log
                .warn("record image platforms", &[("err", e.to_string())]);
            return;
        }
        self.0.learned.add(rev_name, LEARNED_PLATFORMS);
        self.0.log.info(
            "image platforms",
            &[
                ("revision", rev_name.to_string()),
                ("platforms", ps.join(",")),
            ],
        );
        self.trigger();
    }

    async fn record_digest(&self, rev_name: &str, digest: &str) {
        if self.0.learned.has(rev_name, LEARNED_DIGEST) {
            return;
        }
        let Ok(rev) = self.store().get_revision(rev_name).await else {
            return;
        };
        if !rev.image_digest.is_empty() {
            self.0.learned.add(rev_name, LEARNED_DIGEST);
            return;
        }
        let image = rev.spec().image.clone();
        let repo = digest.split('@').next().unwrap_or("");
        if !digest_ok(digest) || normalize_repo(repo) != normalize_repo(image_repo(&image)) {
            self.0.log.warn(
                "ignoring image digest that does not match revision image",
                &[
                    ("revision", rev_name.to_string()),
                    ("digest", digest.to_string()),
                ],
            );
            return;
        }
        // A spec that pins a digest runs that digest on every node.
        if let Some(i) = image.rfind('@') {
            let j = digest.rfind('@').unwrap_or(0);
            if image[i..] != digest[j..] {
                self.0.log.warn(
                    "ignoring image digest that differs from the pinned one",
                    &[
                        ("revision", rev_name.to_string()),
                        ("digest", digest.to_string()),
                    ],
                );
                return;
            }
        }
        if let Err(e) = self.store().set_revision_digest(rev_name, digest).await {
            self.0.log.warn("record digest", &[("err", e.to_string())]);
            return;
        }
        self.0.learned.add(rev_name, LEARNED_DIGEST);
        self.trigger();
    }

    /// Keeps a PeerUnreachable condition on a node while its report names
    /// WireGuard peers with no recent handshake, and a WireGuardUserspace
    /// one while its WireGuard runs in userspace (ADR 0025).
    async fn peers_checked(&self, node: &str, u: &UsageReport) {
        if !u.peers_checked {
            return;
        }
        let peers: Vec<String> = u
            .unreachable_peers
            .iter()
            .filter(|n| validate_name(n).is_ok())
            .take(MAX_UNREACHABLE_PEERS)
            .cloned()
            .collect();
        self.condition(
            &format!("peers:{node}"),
            !peers.is_empty(),
            event(
                events::NODE,
                node,
                node,
                "PeerUnreachable",
                &format!(
                    "no WireGuard handshake for 3 minutes with {}",
                    peers.join(", ")
                ),
            ),
        )
        .await;
        self.condition(
            &format!("wireguard-userspace:{node}"),
            u.wireguard_userspace,
            event(
                events::NODE,
                node,
                node,
                "WireGuardUserspace",
                WIREGUARD_USERSPACE_MESSAGE,
            ),
        )
        .await;
    }

    /// Records the key a node made when asked to rotate it (ADR 0025).
    async fn network_key_changed(&self, node: &str, key: &str) {
        if !valid_network_key(key) {
            self.0.log.warn(
                "agent announced an invalid network key",
                &[("node", node.to_string())],
            );
            return;
        }
        match self.store().set_node_network_key(node, key).await {
            Err(e) if e.kind == Kind::Conflict => {
                self.0.log.warn(
                    "agent announced another node's network key",
                    &[("node", node.to_string())],
                );
                return;
            }
            Err(e) => {
                self.0.log.warn(
                    "record the new network key",
                    &[("node", node.to_string()), ("err", e.to_string())],
                );
                return;
            }
            Ok(()) => {}
        }
        self.0
            .log
            .info("network key rotated", &[("node", node.to_string())]);
        self.record(event(
            events::NODE,
            node,
            node,
            "NetworkKeyRotated",
            "the node has a new WireGuard key",
        ))
        .await;
        self.trigger();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert!(valid_replica_address("10.0.0.1:8080", "10.0.0.1", ""));
        assert!(!valid_replica_address("10.0.0.2:8080", "10.0.0.1", ""));
        assert!(valid_replica_address(
            "10.120.3.7:80",
            "10.0.0.1",
            "10.120.3.0/24"
        ));
        assert!(!valid_replica_address(
            "10.120.3.1:80",
            "10.0.0.1",
            "10.120.3.0/24"
        ));
        assert!(!valid_replica_address("10.0.0.1:0", "10.0.0.1", ""));
        assert!(!valid_replica_address("10.0.0.1:080", "10.0.0.1", ""));
        assert!(!valid_replica_address("10.0.0.1:x", "10.0.0.1", ""));
        assert!(valid_replica_ip("10.120.3.7", "10.120.3.0/24"));
        assert!(!valid_replica_ip("10.120.4.7", "10.120.3.0/24"));
    }

    #[test]
    fn versions_and_digests() {
        assert!(valid_version("v0.1.0-alpha.41"));
        assert!(!valid_version("bad version"));
        assert!(digest_ok(&format!("nginx@sha256:{}", "a".repeat(64))));
        assert!(!digest_ok("nginx@sha256:xyz"));
        assert_eq!(image_repo("nginx:1"), "nginx");
        assert_eq!(image_repo("reg:5000/app"), "reg:5000/app");
        assert_eq!(normalize_repo("docker.io/library/nginx"), "nginx");
    }

    #[test]
    fn platforms() {
        assert_eq!(
            clean_platforms(&[
                "linux/arm64".into(),
                "linux/amd64".into(),
                "linux/amd64".into()
            ]),
            Some(vec!["linux/amd64".to_string(), "linux/arm64".to_string()])
        );
        assert_eq!(clean_platforms(&["linux".into()]), None);
    }

    #[tokio::test]
    async fn queue() {
        let s = Session::new("n1", Caps::default());
        s.offer_assignment(Assignment::default());
        s.offer_assignment(Assignment::default());
        assert!(s.pop().is_some());
        assert!(s.pop().is_none());
        for i in 0..QUEUE + 3 {
            s.end_with(Assignment {
                servers: vec![i.to_string()],
                ..Default::default()
            });
        }
        let mut n = 0;
        while s.pop().is_some() {
            n += 1;
        }
        assert_eq!(n, QUEUE);
        s.close();
        assert!(
            !s.offer(ServerMessage::default(), Duration::from_millis(10))
                .await
        );
    }
}

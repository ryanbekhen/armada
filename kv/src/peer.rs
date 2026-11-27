//! What members say to each other (ADR 0057): a small gRPC service of
//! armada-kv's own, `armadakv.Peer`, with hand-written protobuf messages:
//!
//! - `Call` (unary): Raft's AppendEntries, RequestVote, and PreVote; a
//!   command, a ReadIndex, or a lease keep-alive forwarded to the leader by
//!   the member a client called; the membership changes etcd's Cluster
//!   service asks for, forwarded likewise; and the member list a new member
//!   reads to learn its ID.
//! - `Snapshot` (client streaming): a snapshot sent to a member far
//!   behind, in chunks.
//!
//! Every request names the cluster and the member it is meant for; a
//! member refuses one meant for another (a member list request, made by a
//! member that does not know its ID yet, names neither).
//!
//! How a member reaches another is a [`Connector`]:
//! [`crate::tls::TlsConnector`] dials the peer URL over mutual TLS with the
//! cluster CA's member certificate; [`UnixConnector`] reaches members on
//! Unix sockets in one process (tests, and a scratch cluster). The peer
//! listener requires the member certificate of every caller, the member
//! list a new member asks for included (crate::tls).

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use armada_proto::etcd::etcdserverpb as pb;
use openraft::RaftNetworkV2;
use openraft::errors::{RPCError, ReplicationClosed, StreamingError, Unreachable};
use openraft::network::{RPCOption, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendResult, SnapshotResponse, VoteRequest, VoteResponse,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tonic::body::Body;
use tonic::codegen::http;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Request, Response, Status, Streaming};

use crate::command::Command;
use crate::error::{Error, Result};
use crate::node::Node;
use crate::raft::{
    Peer, Tc, Vote, WAppend, WAppendReply, WApplied, WError, WSnapshotMeta, WVote, WVoteReply,
    WVoteRequest,
};

/// The service's paths.
const PATH_CALL: &str = "/armadakv.Peer/Call";
const PATH_SNAPSHOT: &str = "/armadakv.Peer/Snapshot";

/// The largest message between members: AppendEntries carries at most
/// [`crate::node::MAX_PAYLOAD_ENTRIES`] entries of at most a request each.
pub const MAX_PEER_MESSAGE: usize = 128 << 20;

/// A snapshot is sent in chunks of this size.
const SNAPSHOT_CHUNK: usize = 1 << 20;

/// A request between members.
#[derive(Clone, PartialEq, prost::Message)]
pub struct PeerRequest {
    /// The cluster the sender is a member of (0 in a member list request
    /// of a member that has not joined yet).
    #[prost(uint64, tag = "1")]
    pub cluster: u64,
    /// The member the request is meant for.
    #[prost(uint64, tag = "2")]
    pub to: u64,
    #[prost(uint64, tag = "3")]
    pub from: u64,
    #[prost(oneof = "PeerOp", tags = "4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15")]
    pub op: Option<PeerOp>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum PeerOp {
    #[prost(message, tag = "4")]
    Append(WAppend),
    #[prost(message, tag = "5")]
    Vote(WVoteRequest),
    #[prost(message, tag = "6")]
    PreVote(WVoteRequest),
    /// A command for the leader to propose.
    #[prost(message, tag = "7")]
    Propose(Command),
    /// The leader's ReadIndex.
    #[prost(bool, tag = "8")]
    ReadIndex(bool),
    #[prost(message, tag = "9")]
    KeepAlive(pb::LeaseKeepAliveRequest),
    /// The cluster's ID and members.
    #[prost(bool, tag = "10")]
    Members(bool),
    #[prost(message, tag = "11")]
    MemberAdd(pb::MemberAddRequest),
    #[prost(message, tag = "12")]
    MemberRemove(pb::MemberRemoveRequest),
    #[prost(message, tag = "13")]
    MemberUpdate(pb::MemberUpdateRequest),
    #[prost(message, tag = "14")]
    MemberPromote(pb::MemberPromoteRequest),
    /// A started member's name and client URLs.
    #[prost(message, tag = "15")]
    Publish(pb::Member),
}

/// The answer to a request between members.
#[derive(Clone, PartialEq, prost::Message)]
pub struct PeerReply {
    #[prost(
        oneof = "PeerResult",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13"
    )]
    pub result: Option<PeerResult>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum PeerResult {
    #[prost(message, tag = "1")]
    Error(WError),
    #[prost(message, tag = "2")]
    Append(WAppendReply),
    #[prost(message, tag = "3")]
    Vote(WVoteReply),
    #[prost(message, tag = "4")]
    Applied(WApplied),
    #[prost(uint64, tag = "5")]
    ReadIndex(u64),
    #[prost(int64, tag = "6")]
    Ttl(i64),
    #[prost(message, tag = "7")]
    Members(WMembers),
    #[prost(message, tag = "8")]
    MemberAdd(pb::MemberAddResponse),
    #[prost(message, tag = "9")]
    MemberRemove(pb::MemberRemoveResponse),
    #[prost(message, tag = "10")]
    MemberUpdate(pb::MemberUpdateResponse),
    #[prost(message, tag = "11")]
    MemberPromote(pb::MemberPromoteResponse),
    #[prost(bool, tag = "12")]
    Done(bool),
    /// The receiver's vote after installing a snapshot.
    #[prost(message, tag = "13")]
    Snapshot(WVote),
}

impl PeerReply {
    pub fn of(r: PeerResult) -> PeerReply {
        PeerReply { result: Some(r) }
    }

    pub fn error(e: &Error) -> PeerReply {
        PeerReply::of(PeerResult::Error(e.into()))
    }
}

/// The cluster's ID and its members.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WMembers {
    #[prost(uint64, tag = "1")]
    pub cluster: u64,
    #[prost(message, repeated, tag = "2")]
    pub members: Vec<pb::Member>,
}

/// A chunk of a snapshot; the first names the sender's vote and the
/// snapshot's metadata.
#[derive(Clone, PartialEq, prost::Message)]
pub struct SnapshotChunk {
    #[prost(uint64, tag = "1")]
    pub cluster: u64,
    #[prost(uint64, tag = "2")]
    pub to: u64,
    #[prost(uint64, tag = "3")]
    pub from: u64,
    #[prost(message, optional, tag = "4")]
    pub vote: Option<WVote>,
    #[prost(message, optional, tag = "5")]
    pub meta: Option<WSnapshotMeta>,
    #[prost(bytes = "vec", tag = "6")]
    pub data: Vec<u8>,
}

/// A connection to another member.
pub trait Io: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Io for T {}

pub type BoxIo = Box<dyn Io>;
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Opens connections to other members by their peer URL.
pub trait Connector: Send + Sync + 'static {
    fn connect(&self, peer_url: &str) -> BoxFuture<io::Result<BoxIo>>;
}

/// Reaches members whose peer URLs are `unix://<path>`: Unix sockets of
/// this machine (in one process, or a scratch cluster in a private
/// directory). A socket path may be longer than a socket address holds: it
/// is reached through its directory's descriptor.
#[derive(Clone, Debug, Default)]
pub struct UnixConnector;

impl UnixConnector {
    /// The socket of a `unix://` URL.
    pub fn path(url: &str) -> io::Result<PathBuf> {
        url.strip_prefix("unix://")
            .map(PathBuf::from)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("{url}: not unix://"))
            })
    }
}

/// Connects to the Unix socket at path through its directory.
pub async fn connect_unix(path: &Path) -> io::Result<tokio::net::UnixStream> {
    use std::os::fd::AsRawFd;
    let dir = std::fs::File::open(path.parent().unwrap_or(Path::new(".")))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no socket name"))?;
    let short = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name);
    let s = tokio::net::UnixStream::connect(short).await;
    drop(dir);
    s
}

impl Connector for UnixConnector {
    fn connect(&self, peer_url: &str) -> BoxFuture<io::Result<BoxIo>> {
        let path = UnixConnector::path(peer_url);
        Box::pin(async move {
            let s = connect_unix(&path?).await?;
            Ok(Box::new(s) as BoxIo)
        })
    }
}

/// The channels to other members, one per peer URL.
pub(crate) struct Peers {
    connector: Option<Arc<dyn Connector>>,
    channels: Mutex<HashMap<String, Channel>>,
}

impl Peers {
    pub fn new(connector: Option<Arc<dyn Connector>>) -> Peers {
        Peers {
            connector,
            channels: Mutex::new(HashMap::new()),
        }
    }

    fn channel(&self, url: &str) -> Result<Channel> {
        let Some(connector) = self.connector.clone() else {
            return Err(Error::Unavailable(
                "this member has no way to reach other members".into(),
            ));
        };
        let mut chans = self.channels.lock().expect("not poisoned");
        if let Some(c) = chans.get(url) {
            return Ok(c.clone());
        }
        let u = url.to_string();
        let ch = Endpoint::from_static("http://armada-kv.peer")
            .connect_timeout(Duration::from_secs(2))
            .tcp_nodelay(true)
            .http2_keep_alive_interval(Duration::from_secs(10))
            .keep_alive_timeout(Duration::from_secs(5))
            .connect_with_connector_lazy(tower::service_fn(move |_: Uri| {
                let c = connector.clone();
                let u = u.clone();
                async move {
                    let io = c.connect(&u).await?;
                    Ok::<_, io::Error>(hyper_util::rt::TokioIo::new(io))
                }
            }));
        chans.insert(url.to_string(), ch.clone());
        Ok(ch)
    }

    fn grpc(&self, url: &str) -> Result<tonic::client::Grpc<Channel>> {
        Ok(tonic::client::Grpc::new(self.channel(url)?)
            .max_decoding_message_size(MAX_PEER_MESSAGE)
            .max_encoding_message_size(MAX_PEER_MESSAGE))
    }

    /// One request to the member at url, answered within wait.
    pub async fn call(&self, url: &str, req: PeerRequest, wait: Duration) -> Result<PeerReply> {
        let mut g = self.grpc(url)?;
        let call = async move {
            g.ready().await.map_err(|e| unreachable_peer(url, e))?;
            let codec = tonic_prost::ProstCodec::<PeerRequest, PeerReply>::default();
            g.unary(
                Request::new(req),
                http::uri::PathAndQuery::from_static(PATH_CALL),
                codec,
            )
            .await
            .map(Response::into_inner)
            .map_err(|e| unreachable_peer(url, e))
        };
        tokio::time::timeout(wait, call)
            .await
            .map_err(|_| Error::Unavailable(format!("{url}: no answer within {wait:?}")))?
    }

    /// A snapshot sent to the member at url in chunks.
    pub async fn snapshot(
        &self,
        url: &str,
        chunks: Vec<SnapshotChunk>,
        wait: Duration,
    ) -> Result<PeerReply> {
        let mut g = self.grpc(url)?;
        let call = async move {
            g.ready().await.map_err(|e| unreachable_peer(url, e))?;
            let codec = tonic_prost::ProstCodec::<SnapshotChunk, PeerReply>::default();
            g.client_streaming(
                Request::new(tokio_stream::iter(chunks)),
                http::uri::PathAndQuery::from_static(PATH_SNAPSHOT),
                codec,
            )
            .await
            .map(Response::into_inner)
            .map_err(|e| unreachable_peer(url, e))
        };
        tokio::time::timeout(wait, call)
            .await
            .map_err(|_| Error::Unavailable(format!("{url}: no answer within {wait:?}")))?
    }
}

fn unreachable_peer(url: &str, e: impl std::fmt::Display) -> Error {
    Error::Unavailable(format!("{url}: {e}"))
}

/// What the Raft network needs of the member: who it is and how it
/// reaches the others.
pub(crate) struct PeerCtx {
    pub peers: Peers,
    pub me: u64,
    pub cluster: u64,
}

/// openraft's network: a client per member it replicates to.
pub(crate) struct NetFactory(pub Arc<PeerCtx>);

impl RaftNetworkFactory<Tc> for NetFactory {
    type Network = Net;

    async fn new_client(&mut self, target: u64, node: &Peer) -> Net {
        Net {
            ctx: self.0.clone(),
            target,
            url: node.peer_urls.first().cloned(),
        }
    }
}

pub(crate) struct Net {
    ctx: Arc<PeerCtx>,
    target: u64,
    url: Option<String>,
}

fn unreachable(e: Error) -> RPCError<Tc> {
    RPCError::Unreachable(Unreachable::new(&e))
}

impl Net {
    fn request(&self, op: PeerOp) -> PeerRequest {
        PeerRequest {
            cluster: self.ctx.cluster,
            to: self.target,
            from: self.ctx.me,
            op: Some(op),
        }
    }

    async fn call(&self, op: PeerOp, wait: Duration) -> Result<PeerResult> {
        let Some(url) = &self.url else {
            return Err(Error::Unavailable(format!(
                "member {:x} has no peer URL",
                self.target
            )));
        };
        let reply = self.ctx.peers.call(url, self.request(op), wait).await?;
        match reply.result {
            Some(PeerResult::Error(e)) => Err(e.into()),
            Some(r) => Ok(r),
            None => Err(Error::Unavailable(format!("{url}: an empty answer"))),
        }
    }
}

fn unexpected() -> Error {
    Error::Unavailable("a peer answered another request".into())
}

impl RaftNetworkV2<Tc> for Net {
    type SnapshotData = Vec<u8>;

    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<Tc>,
        option: RPCOption,
    ) -> std::result::Result<AppendResult<Tc>, RPCError<Tc>> {
        match self
            .call(PeerOp::Append((&rpc).into()), option.soft_ttl())
            .await
            .map_err(unreachable)?
        {
            PeerResult::Append(w) => w.try_into().map_err(unreachable),
            _ => Err(unreachable(unexpected())),
        }
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<Tc>,
        option: RPCOption,
    ) -> std::result::Result<VoteResponse<Tc>, RPCError<Tc>> {
        match self
            .call(PeerOp::Vote((&rpc).into()), option.soft_ttl())
            .await
            .map_err(unreachable)?
        {
            PeerResult::Vote(w) => Ok(w.into()),
            _ => Err(unreachable(unexpected())),
        }
    }

    async fn pre_vote(
        &mut self,
        rpc: VoteRequest<Tc>,
        option: RPCOption,
    ) -> std::result::Result<VoteResponse<Tc>, RPCError<Tc>> {
        match self
            .call(PeerOp::PreVote((&rpc).into()), option.soft_ttl())
            .await
            .map_err(unreachable)?
        {
            PeerResult::Vote(w) => Ok(w.into()),
            _ => Err(unreachable(unexpected())),
        }
    }

    async fn full_snapshot(
        &mut self,
        vote: Vote,
        snapshot: crate::raft::Snapshot,
        cancel: impl Future<Output = ReplicationClosed> + Send + 'static,
        option: RPCOption,
    ) -> std::result::Result<SnapshotResponse<Tc>, StreamingError<Tc>> {
        let Some(url) = self.url.clone() else {
            return Err(StreamingError::Unreachable(Unreachable::new(
                &Error::Unavailable(format!("member {:x} has no peer URL", self.target)),
            )));
        };
        let mut chunks: Vec<SnapshotChunk> = snapshot
            .snapshot
            .chunks(SNAPSHOT_CHUNK)
            .map(|c| SnapshotChunk {
                data: c.to_vec(),
                ..Default::default()
            })
            .collect();
        if chunks.is_empty() {
            chunks.push(SnapshotChunk::default());
        }
        chunks[0].cluster = self.ctx.cluster;
        chunks[0].to = self.target;
        chunks[0].from = self.ctx.me;
        chunks[0].vote = Some((&vote).into());
        chunks[0].meta = Some((&snapshot.meta).into());
        let wait = option.hard_ttl().max(Duration::from_secs(60));
        let ctx = self.ctx.clone();
        let send = async move { ctx.peers.snapshot(&url, chunks, wait).await };
        let reply = tokio::select! {
            r = send => r,
            closed = cancel => return Err(StreamingError::Closed(closed)),
        };
        let unreach = |e: Error| StreamingError::Unreachable(Unreachable::new(&e));
        match reply.map_err(unreach)?.result {
            Some(PeerResult::Snapshot(v)) => Ok(SnapshotResponse::new(v.into())),
            Some(PeerResult::Error(e)) => Err(unreach(e.into())),
            _ => Err(unreach(unexpected())),
        }
    }
}

/// The peer service behind a tower service: what a member's peer listener
/// serves (over mutual TLS, [`crate::tls::serve_peer_tls`]; on a Unix socket in
/// [`serve_peer_unix`]).
#[derive(Clone)]
pub struct PeerDispatch {
    node: Node,
}

impl PeerDispatch {
    pub fn new(node: Node) -> PeerDispatch {
        PeerDispatch { node }
    }
}

impl tower::Service<http::Request<Body>> for PeerDispatch {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<http::Response<Body>, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        let node = self.node.clone();
        match req.uri().path() {
            PATH_CALL => Box::pin(async move {
                let svc = tower::service_fn(move |r: Request<PeerRequest>| {
                    let node = node.clone();
                    async move { Ok::<_, Status>(Response::new(node.handle_peer(r.into_inner()).await)) }
                });
                let mut g = tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                    PeerReply,
                    PeerRequest,
                >::default())
                .apply_max_message_size_config(Some(MAX_PEER_MESSAGE), Some(MAX_PEER_MESSAGE));
                Ok(g.unary(svc, req).await)
            }),
            PATH_SNAPSHOT => Box::pin(async move {
                let svc = tower::service_fn(move |r: Request<Streaming<SnapshotChunk>>| {
                    let node = node.clone();
                    async move {
                        Ok::<_, Status>(Response::new(node.handle_snapshot(r.into_inner()).await))
                    }
                });
                let mut g = tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                    PeerReply,
                    SnapshotChunk,
                >::default())
                .apply_max_message_size_config(Some(MAX_PEER_MESSAGE), Some(MAX_PEER_MESSAGE));
                Ok(g.client_streaming(svc, req).await)
            }),
            p => {
                let p = p.to_string();
                Box::pin(async move {
                    Ok(Status::unimplemented(format!("unknown method {p}")).into_http())
                })
            }
        }
    }
}

/// Serves the member's peer service on a Unix socket at path (created
/// 0600) until shutdown resolves.
pub async fn serve_peer_unix(
    node: Node,
    path: &Path,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    crate::service::serve_unix_with(PeerDispatch::new(node), path, shutdown).await
}

/// Reads a snapshot's chunks: the first one's header, then the data.
pub(crate) async fn read_chunks(
    mut s: Streaming<SnapshotChunk>,
) -> Result<(SnapshotChunk, Vec<u8>)> {
    let bad = |e: Status| Error::Unavailable(format!("a snapshot stream: {}", e.message()));
    let Some(mut first) = s.message().await.map_err(bad)? else {
        return Err(Error::Unavailable("an empty snapshot stream".into()));
    };
    let mut data = std::mem::take(&mut first.data);
    while let Some(c) = s.message().await.map_err(bad)? {
        data.extend_from_slice(&c.data);
    }
    Ok((first, data))
}

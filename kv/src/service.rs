//! The member's gRPC API: the subset of etcd's v3 services armada-store
//! uses (ADR 0057), with etcd's messages, and `Unimplemented` for the rest.
//!
//! - KV: Range, Put, DeleteRange, Txn, Compact.
//! - Watch: create (from a revision, a key or range, prev_kv, filters),
//!   cancel, progress.
//! - Lease: LeaseGrant, LeaseRevoke, LeaseKeepAlive.
//! - Cluster: MemberList, MemberAdd (as a learner), MemberPromote,
//!   MemberUpdate (peer URLs), MemberRemove.
//! - Maintenance: Status, Snapshot (the store's own format, crate::snapshot).
//!
//! Reads are linearizable unless they ask to be serializable (crate::node).

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use armada_proto::etcd::etcdserverpb as pb;
use armada_proto::etcd::mvccpb;
use pb::cluster_server::{Cluster, ClusterServer};
use pb::kv_server::{Kv, KvServer};
use pb::lease_server::{Lease, LeaseServer};
use pb::maintenance_server::{Maintenance, MaintenanceServer};
use pb::watch_server::{Watch, WatchServer};
use prost::Message;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::body::Body;
use tonic::codegen::http;
use tonic::{Request, Response, Status, Streaming};

use crate::command::{Command, Op};
use crate::error::Error;
use crate::mvcc;
use crate::node::Node;

/// etcd's MaxRequestBytes: the largest request the store takes.
pub const MAX_REQUEST_BYTES: usize = 3 << 19;

/// What gRPC decodes at most: a request and etcd's allowance for its
/// framing (grpcOverheadBytes).
const MAX_DECODING: usize = MAX_REQUEST_BYTES + (512 << 10);

/// The blobs a snapshot is streamed in.
const SNAPSHOT_CHUNK: usize = 32 << 10;

/// How long calls in flight may take once serving is to stop.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// Events in one watch response at most.
const WATCH_BATCH: usize = 1000;

type Answer<T> = std::result::Result<Response<T>, Status>;

fn unimplemented(what: &str) -> Status {
    Error::Unimplemented(what.to_string()).status()
}

fn too_large(m: &impl Message) -> Result<(), Status> {
    if m.encoded_len() > MAX_REQUEST_BYTES {
        return Err(Error::RequestTooLarge.status());
    }
    Ok(())
}

/// The member's services.
#[derive(Clone)]
pub struct Api(pub Node);

impl Api {
    async fn apply(&self, op: Op) -> Result<mvcc::Response, Status> {
        Ok(self
            .0
            .propose(Command::new(op))
            .await
            .map_err(|e| e.status())?
            .response)
    }

    async fn read<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mvcc::Store) -> crate::Result<T> + Send + 'static,
    ) -> Result<T, Status> {
        let store = self.0.store().clone();
        tokio::task::spawn_blocking(move || f(&store))
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .map_err(|e| e.status())
    }
}

fn wrong() -> Status {
    Status::internal("armada-kv: a command answered otherwise")
}

#[tonic::async_trait]
impl Kv for Api {
    async fn range(&self, req: Request<pb::RangeRequest>) -> Answer<pb::RangeResponse> {
        let r = req.into_inner();
        if !r.serializable {
            self.0.linearize().await.map_err(|e| e.status())?;
        }
        Ok(Response::new(self.read(move |s| s.range(&r)).await?))
    }

    type RangeStreamStream = ReceiverStream<Result<pb::RangeStreamResponse, Status>>;

    async fn range_stream(
        &self,
        _req: Request<pb::RangeRequest>,
    ) -> Answer<Self::RangeStreamStream> {
        Err(unimplemented("KV.RangeStream"))
    }

    async fn put(&self, req: Request<pb::PutRequest>) -> Answer<pb::PutResponse> {
        let r = req.into_inner();
        too_large(&r)?;
        match self.apply(Op::Put(r)).await? {
            mvcc::Response::Put(p) => Ok(Response::new(p)),
            _ => Err(wrong()),
        }
    }

    async fn delete_range(
        &self,
        req: Request<pb::DeleteRangeRequest>,
    ) -> Answer<pb::DeleteRangeResponse> {
        match self.apply(Op::DeleteRange(req.into_inner())).await? {
            mvcc::Response::DeleteRange(d) => Ok(Response::new(d)),
            _ => Err(wrong()),
        }
    }

    async fn txn(&self, req: Request<pb::TxnRequest>) -> Answer<pb::TxnResponse> {
        let t = req.into_inner();
        too_large(&t)?;
        // A transaction that only reads needs no commit.
        let reads_only = t.success.iter().chain(&t.failure).all(|o| {
            matches!(
                o.request,
                Some(pb::request_op::Request::RequestRange(_)) | None
            )
        });
        if reads_only {
            // As etcd: serializable only when every range is.
            let serializable = t.success.iter().chain(&t.failure).all(|o| {
                matches!(&o.request, Some(pb::request_op::Request::RequestRange(r)) if r.serializable)
            });
            if !serializable {
                self.0.linearize().await.map_err(|e| e.status())?;
            }
            let max = self.0.options().limits.max_txn_ops;
            return Ok(Response::new(
                self.read(move |s| s.read_txn(&t, max)).await?,
            ));
        }
        match self.apply(Op::Txn(t)).await? {
            mvcc::Response::Txn(t) => Ok(Response::new(t)),
            _ => Err(wrong()),
        }
    }

    async fn compact(&self, req: Request<pb::CompactionRequest>) -> Answer<pb::CompactionResponse> {
        match self.apply(Op::Compact(req.into_inner())).await? {
            mvcc::Response::Compact(c) => Ok(Response::new(c)),
            _ => Err(wrong()),
        }
    }
}

#[tonic::async_trait]
impl Lease for Api {
    async fn lease_grant(
        &self,
        req: Request<pb::LeaseGrantRequest>,
    ) -> Answer<pb::LeaseGrantResponse> {
        Ok(Response::new(
            self.0
                .grant(req.into_inner())
                .await
                .map_err(|e| e.status())?,
        ))
    }

    async fn lease_revoke(
        &self,
        req: Request<pb::LeaseRevokeRequest>,
    ) -> Answer<pb::LeaseRevokeResponse> {
        match self.apply(Op::LeaseRevoke(req.into_inner())).await? {
            mvcc::Response::LeaseRevoke(r) => Ok(Response::new(r)),
            _ => Err(wrong()),
        }
    }

    type LeaseKeepAliveStream = ReceiverStream<Result<pb::LeaseKeepAliveResponse, Status>>;

    async fn lease_keep_alive(
        &self,
        req: Request<Streaming<pb::LeaseKeepAliveRequest>>,
    ) -> Answer<Self::LeaseKeepAliveStream> {
        let mut input = req.into_inner();
        let (tx, rx) = mpsc::channel(16);
        let node = self.0.clone();
        tokio::spawn(async move {
            while let Ok(Some(r)) = input.message().await {
                let ttl = match node.keep_alive(r.id).await {
                    Ok(t) => t,
                    Err(e) => {
                        let _ = tx.send(Err(e.status())).await;
                        return;
                    }
                };
                let rev = *node.revisions().borrow();
                let a = pb::LeaseKeepAliveResponse {
                    header: Some(node.header(rev)),
                    id: r.id,
                    ttl,
                };
                if tx.send(Ok(a)).await.is_err() {
                    return;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn lease_time_to_live(
        &self,
        _req: Request<pb::LeaseTimeToLiveRequest>,
    ) -> Answer<pb::LeaseTimeToLiveResponse> {
        Err(unimplemented("Lease.LeaseTimeToLive"))
    }

    async fn lease_leases(
        &self,
        _req: Request<pb::LeaseLeasesRequest>,
    ) -> Answer<pb::LeaseLeasesResponse> {
        Err(unimplemented("Lease.LeaseLeases"))
    }
}

/// One watch of a stream.
struct Watcher {
    key: Vec<u8>,
    end: Vec<u8>,
    /// The next revision to send.
    next: i64,
    prev_kv: bool,
    no_put: bool,
    no_delete: bool,
}

#[tonic::async_trait]
impl Watch for Api {
    type WatchStream = ReceiverStream<Result<pb::WatchResponse, Status>>;

    async fn watch(&self, req: Request<Streaming<pb::WatchRequest>>) -> Answer<Self::WatchStream> {
        let input = req.into_inner();
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(watch_stream(self.clone(), input, tx));
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

type WatchTx = mpsc::Sender<Result<pb::WatchResponse, Status>>;

async fn watch_stream(api: Api, mut input: Streaming<pb::WatchRequest>, tx: WatchTx) {
    use pb::watch_request::RequestUnion;
    let mut revs = api.0.revisions();
    let mut watchers: HashMap<i64, Watcher> = HashMap::new();
    let mut next_id = 0i64;
    loop {
        tokio::select! {
            m = input.message() => {
                let Ok(Some(m)) = m else { return };
                let rev = *revs.borrow_and_update();
                let header = Some(api.0.header(rev));
                match m.request_union {
                    Some(RequestUnion::CreateRequest(c)) => {
                        let id = if c.watch_id != 0 {
                            c.watch_id
                        } else {
                            while watchers.contains_key(&next_id) {
                                next_id += 1;
                            }
                            next_id
                        };
                        if watchers.contains_key(&id) {
                            let a = pb::WatchResponse {
                                header,
                                watch_id: id,
                                created: true,
                                canceled: true,
                                cancel_reason: "etcdserver: duplicate watch ID".to_string(),
                                ..Default::default()
                            };
                            if tx.send(Ok(a)).await.is_err() {
                                return;
                            }
                            continue;
                        }
                        use pb::watch_create_request::FilterType;
                        watchers.insert(id, Watcher {
                            key: c.key,
                            end: c.range_end,
                            next: if c.start_revision > 0 { c.start_revision } else { rev + 1 },
                            prev_kv: c.prev_kv,
                            no_put: c.filters.contains(&(FilterType::Noput as i32)),
                            no_delete: c.filters.contains(&(FilterType::Nodelete as i32)),
                        });
                        let a = pb::WatchResponse { header, watch_id: id, created: true, ..Default::default() };
                        if tx.send(Ok(a)).await.is_err() {
                            return;
                        }
                    }
                    Some(RequestUnion::CancelRequest(c)) => {
                        if watchers.remove(&c.watch_id).is_some() {
                            let a = pb::WatchResponse {
                                header,
                                watch_id: c.watch_id,
                                canceled: true,
                                ..Default::default()
                            };
                            if tx.send(Ok(a)).await.is_err() {
                                return;
                            }
                        }
                    }
                    Some(RequestUnion::ProgressRequest(_)) => {
                        let a = pb::WatchResponse { header, watch_id: -1, ..Default::default() };
                        if tx.send(Ok(a)).await.is_err() {
                            return;
                        }
                    }
                    None => {}
                }
            }
            r = revs.changed() => {
                if r.is_err() {
                    return;
                }
            }
            _ = tx.closed() => return,
        }
        if deliver(&api, &mut watchers, &tx).await.is_err() {
            return;
        }
    }
}

/// Sends every watcher the events it has not seen; a watcher whose next
/// revision was compacted is canceled with the compacted revision.
async fn deliver(api: &Api, watchers: &mut HashMap<i64, Watcher>, tx: &WatchTx) -> Result<(), ()> {
    let mut ended = Vec::new();
    for (&id, w) in watchers.iter_mut() {
        let (from, key, end, prev) = (w.next, w.key.clone(), w.end.clone(), w.prev_kv);
        let read = match api.read(move |s| s.events(from, &key, &end, prev)).await {
            Ok(r) => r,
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                return Err(());
            }
        };
        let header = Some(api.0.header(read.revision));
        if w.next < read.compacted {
            let a = pb::WatchResponse {
                header,
                watch_id: id,
                canceled: true,
                compact_revision: read.compacted,
                ..Default::default()
            };
            tx.send(Ok(a)).await.map_err(|_| ())?;
            ended.push(id);
            continue;
        }
        if w.next > read.revision {
            continue;
        }
        w.next = read.revision + 1;
        let events: Vec<mvccpb::Event> = read
            .events
            .into_iter()
            .filter(|e| {
                let put = e.r#type == mvccpb::event::EventType::Put as i32;
                !(put && w.no_put || !put && w.no_delete)
            })
            .collect();
        for chunk in events.chunks(WATCH_BATCH) {
            let a = pb::WatchResponse {
                header,
                watch_id: id,
                events: chunk.to_vec(),
                ..Default::default()
            };
            tx.send(Ok(a)).await.map_err(|_| ())?;
        }
    }
    for id in ended {
        watchers.remove(&id);
    }
    Ok(())
}

#[tonic::async_trait]
impl Cluster for Api {
    async fn member_add(
        &self,
        req: Request<pb::MemberAddRequest>,
    ) -> Answer<pb::MemberAddResponse> {
        let r = req.into_inner();
        too_large(&r)?;
        Ok(Response::new(
            self.0.member_add(r).await.map_err(|e| e.status())?,
        ))
    }

    async fn member_remove(
        &self,
        req: Request<pb::MemberRemoveRequest>,
    ) -> Answer<pb::MemberRemoveResponse> {
        Ok(Response::new(
            self.0
                .member_remove(req.into_inner())
                .await
                .map_err(|e| e.status())?,
        ))
    }

    async fn member_update(
        &self,
        req: Request<pb::MemberUpdateRequest>,
    ) -> Answer<pb::MemberUpdateResponse> {
        let r = req.into_inner();
        too_large(&r)?;
        Ok(Response::new(
            self.0.member_update(r).await.map_err(|e| e.status())?,
        ))
    }

    async fn member_list(
        &self,
        req: Request<pb::MemberListRequest>,
    ) -> Answer<pb::MemberListResponse> {
        if req.into_inner().linearizable {
            self.0.linearize().await.map_err(|e| e.status())?;
        }
        let rev = *self.0.revisions().borrow();
        Ok(Response::new(pb::MemberListResponse {
            header: Some(self.0.header(rev)),
            members: self.0.members(),
        }))
    }

    async fn member_promote(
        &self,
        req: Request<pb::MemberPromoteRequest>,
    ) -> Answer<pb::MemberPromoteResponse> {
        Ok(Response::new(
            self.0
                .member_promote(req.into_inner())
                .await
                .map_err(|e| e.status())?,
        ))
    }
}

#[tonic::async_trait]
impl Maintenance for Api {
    async fn alarm(&self, _req: Request<pb::AlarmRequest>) -> Answer<pb::AlarmResponse> {
        Err(unimplemented("Maintenance.Alarm"))
    }

    async fn status(&self, _req: Request<pb::StatusRequest>) -> Answer<pb::StatusResponse> {
        let (state, size) = self.read(|s| Ok((s.state()?, s.size()))).await?;
        let ids = self.0.store().ids();
        let (leader, index, term, applied, learner) = self.0.raft_status();
        Ok(Response::new(pb::StatusResponse {
            header: Some(ids.header(state.revision)),
            version: env!("CARGO_PKG_VERSION").to_string(),
            db_size: size as i64,
            leader,
            raft_index: index,
            raft_term: term,
            raft_applied_index: applied,
            errors: Vec::new(),
            db_size_in_use: size as i64,
            is_learner: learner,
            storage_version: format!("armada-kv/{}", mvcc::FORMAT),
            db_size_quota: self.0.options().limits.quota_bytes as i64,
            downgrade_info: None,
        }))
    }

    async fn defragment(
        &self,
        _req: Request<pb::DefragmentRequest>,
    ) -> Answer<pb::DefragmentResponse> {
        Err(unimplemented("Maintenance.Defragment"))
    }

    async fn hash(&self, _req: Request<pb::HashRequest>) -> Answer<pb::HashResponse> {
        Err(unimplemented("Maintenance.Hash"))
    }

    async fn hash_kv(&self, _req: Request<pb::HashKvRequest>) -> Answer<pb::HashKvResponse> {
        Err(unimplemented("Maintenance.HashKV"))
    }

    type SnapshotStream = ReceiverStream<Result<pb::SnapshotResponse, Status>>;

    async fn snapshot(&self, _req: Request<pb::SnapshotRequest>) -> Answer<Self::SnapshotStream> {
        let (b, rev) = self
            .read(|s| {
                let b = s.snapshot()?;
                let rev = crate::snapshot::read(&b)?.revision;
                Ok((b, rev))
            })
            .await?;
        let header = Some(self.0.header(rev));
        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            let total = b.len();
            let mut sent = 0;
            for chunk in b.chunks(SNAPSHOT_CHUNK) {
                sent += chunk.len();
                let a = pb::SnapshotResponse {
                    header,
                    remaining_bytes: (total - sent) as u64,
                    blob: chunk.to_vec(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                };
                if tx.send(Ok(a)).await.is_err() {
                    return;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn move_leader(
        &self,
        _req: Request<pb::MoveLeaderRequest>,
    ) -> Answer<pb::MoveLeaderResponse> {
        Err(unimplemented("Maintenance.MoveLeader"))
    }

    async fn downgrade(
        &self,
        _req: Request<pb::DowngradeRequest>,
    ) -> Answer<pb::DowngradeResponse> {
        Err(unimplemented("Maintenance.Downgrade"))
    }
}

/// The five services behind one tower service, by path.
#[derive(Clone)]
pub struct Dispatch {
    kv: KvServer<Api>,
    watch: WatchServer<Api>,
    lease: LeaseServer<Api>,
    cluster: ClusterServer<Api>,
    maintenance: MaintenanceServer<Api>,
}

impl Dispatch {
    pub fn new(node: Node) -> Dispatch {
        let api = Api(node);
        Dispatch {
            kv: KvServer::new(api.clone())
                .max_decoding_message_size(MAX_DECODING)
                .max_encoding_message_size(usize::MAX),
            watch: WatchServer::new(api.clone())
                .max_decoding_message_size(MAX_DECODING)
                .max_encoding_message_size(usize::MAX),
            lease: LeaseServer::new(api.clone()).max_decoding_message_size(MAX_DECODING),
            cluster: ClusterServer::new(api.clone()).max_decoding_message_size(MAX_DECODING),
            maintenance: MaintenanceServer::new(api).max_decoding_message_size(MAX_DECODING),
        }
    }
}

impl tower::Service<http::Request<Body>> for Dispatch {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<http::Response<Body>, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        let path = req.uri().path().to_string();
        let svc = path
            .trim_start_matches('/')
            .split_once('/')
            .map_or("", |(s, _)| s)
            .to_string();
        match svc.as_str() {
            "etcdserverpb.KV" => Box::pin(tower::Service::call(&mut self.kv, req)),
            "etcdserverpb.Watch" => Box::pin(tower::Service::call(&mut self.watch, req)),
            "etcdserverpb.Lease" => Box::pin(tower::Service::call(&mut self.lease, req)),
            "etcdserverpb.Cluster" => Box::pin(tower::Service::call(&mut self.cluster, req)),
            "etcdserverpb.Maintenance" => {
                Box::pin(tower::Service::call(&mut self.maintenance, req))
            }
            _ => Box::pin(async move {
                Ok(Status::unimplemented(format!("unknown service {svc}")).into_http())
            }),
        }
    }
}

/// Serves the member on a Unix socket at path (created 0600; the
/// directory is the access control, as for a scratch etcd member) until
/// shutdown resolves.
pub async fn serve_unix(
    node: Node,
    path: &Path,
    shutdown: impl Future<Output = ()>,
) -> crate::Result<()> {
    serve_unix_with(Dispatch::new(node), path, shutdown).await
}

/// Serves a gRPC service on a Unix socket at path (created 0600) until
/// shutdown resolves.
pub(crate) async fn serve_unix_with<S>(
    svc: S,
    path: &Path,
    shutdown: impl Future<Output = ()>,
) -> crate::Result<()>
where
    S: tower::Service<http::Request<Body>, Response = http::Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    let fail = |e: std::io::Error| Error::Storage(format!("{}: {e}", path.display()));
    // A socket's address holds at most 108 bytes: the socket is bound
    // through its directory's descriptor.
    let parent = path.parent().unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| Error::Storage(format!("{}: no file name", path.display())))?;
    let dir = std::fs::File::open(parent).map_err(fail)?;
    let short = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name);
    let lis = tokio::net::UnixListener::bind(&short).map_err(fail)?;
    std::fs::set_permissions(&short, std::fs::Permissions::from_mode(0o600)).map_err(fail)?;
    drop(dir);
    let (tx, rx) = mpsc::channel(16);
    let accept = tokio::spawn(async move {
        loop {
            let r = lis.accept().await.map(|(s, _)| s);
            if tx.send(r).await.is_err() {
                return;
            }
        }
    });
    // Calls in flight get a grace once shutdown resolves; watches and
    // keep-alives never end on their own, so the server stops after it.
    let notify = std::sync::Arc::new(tokio::sync::Notify::new());
    let signal = {
        let n = notify.clone();
        async move { n.notified().await }
    };
    let serve = tonic::transport::Server::builder().serve_with_incoming_shutdown(
        svc,
        ReceiverStream::new(rx),
        signal,
    );
    tokio::pin!(serve);
    tokio::pin!(shutdown);
    let r = tokio::select! {
        r = &mut serve => r,
        _ = &mut shutdown => {
            notify.notify_one();
            accept.abort();
            tokio::time::timeout(SHUTDOWN_GRACE, &mut serve).await.unwrap_or(Ok(()))
        }
    };
    accept.abort();
    r.map_err(|e| Error::Storage(e.to_string()))
}

//! A client of an etcd member, as the control plane uses one: gRPC over
//! HTTP/2 on TLS 1.3, the member's CA as the only root, and the
//! `etcd:member` client certificate read from the member's directory on
//! every handshake, so a renewed certificate is used without a restart.
//! Only the part of etcd's API the control plane uses: ranges, puts,
//! deletes, transactions, leases with their keep-alive, watches, the
//! membership, and snapshots.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use armada_proto::etcd::etcdserverpb as pb;
use armada_proto::etcd::mvccpb;
use pb::cluster_client::ClusterClient;
use pb::kv_client::KvClient;
use pb::lease_client::LeaseClient;
use pb::maintenance_client::MaintenanceClient;
use pb::watch_client::WatchClient;
use rustls::client::ResolvesClientCert;
use rustls::crypto::CryptoProvider;
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint, Uri};

use crate::error::{Error, Result, other};

/// The files of a member's directory the client reads.
pub const FILE_CA: &str = "ca.crt";
pub const FILE_CERT: &str = "member.crt";
pub const FILE_KEY: &str = "member.key";

/// A connection to one etcd member. Clones share it.
#[derive(Clone)]
pub struct Client {
    ch: Channel,
}

/// The client certificate, read on every handshake (clientTLS's
/// GetClientCertificate).
#[derive(Debug)]
struct MemberCert {
    dir: PathBuf,
    provider: Arc<CryptoProvider>,
}

impl MemberCert {
    fn load(&self) -> std::result::Result<CertifiedKey, String> {
        let cert = std::fs::read(self.dir.join(FILE_CERT)).map_err(|e| e.to_string())?;
        let key = std::fs::read(self.dir.join(FILE_KEY)).map_err(|e| e.to_string())?;
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert)
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| e.to_string())?;
        if certs.is_empty() {
            return Err("etcd: no member certificate".to_string());
        }
        let key = PrivateKeyDer::from_pem_slice(&key).map_err(|e| e.to_string())?;
        let key = self
            .provider
            .key_provider
            .load_private_key(key)
            .map_err(|e| e.to_string())?;
        Ok(CertifiedKey::new(certs, key))
    }
}

impl ResolvesClientCert for MemberCert {
    fn resolve(&self, _hints: &[&[u8]], _schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        self.load().ok().map(Arc::new)
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// The TLS configuration of clientTLS: TLS 1.3 only, the member's CA, the
/// member certificate per handshake, and HTTP/2.
fn tls_config(dir: &Path) -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let ca = std::fs::read(dir.join(FILE_CA)).map_err(|e| other!("{e}"))?;
    let mut roots = RootCertStore::empty();
    let mut any = false;
    for c in CertificateDer::pem_slice_iter(&ca) {
        let c = c.map_err(|_| other!("etcd: invalid CA certificate"))?;
        roots
            .add(c)
            .map_err(|_| other!("etcd: invalid CA certificate"))?;
        any = true;
    }
    if !any {
        return Err(other!("etcd: invalid CA certificate"));
    }
    let cert = MemberCert {
        dir: dir.to_path_buf(),
        provider: provider.clone(),
    };
    // As tls.X509KeyPair at the start: a broken pair fails now, not at the
    // first handshake.
    cert.load().map_err(Error::other)?;
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| other!("{e}"))?
        .with_root_certificates(roots)
        .with_client_cert_resolver(Arc::new(cert));
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(cfg)
}

impl Client {
    /// Connects to the member at endpoint ("https://10.0.0.1:2379" or
    /// "10.0.0.1:2379") with the certificates in its directory dir. The
    /// connection is made on first use and again whenever it breaks.
    pub fn connect(endpoint: &str, dir: &Path) -> Result<Client> {
        let host_port = endpoint
            .strip_prefix("https://")
            .unwrap_or(endpoint)
            .trim_end_matches('/')
            .to_string();
        let (host, _) = host_port
            .rsplit_once(':')
            .ok_or_else(|| other!("etcd endpoint {endpoint:?} has no port"))?;
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let name: ServerName<'static> = match host.parse::<IpAddr>() {
            Ok(ip) => ServerName::IpAddress(ip.into()),
            Err(_) => ServerName::try_from(host.clone())
                .map_err(|e| other!("etcd endpoint {endpoint:?}: {e}"))?,
        };
        let tls = tokio_rustls::TlsConnector::from(Arc::new(tls_config(dir)?));
        let ep = Endpoint::from_shared(format!("http://{host_port}"))
            .map_err(|e| other!("etcd endpoint {endpoint:?}: {e}"))?
            .connect_timeout(Duration::from_secs(5))
            .tcp_nodelay(true)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(10));
        let addr = host_port.clone();
        let connector = tower::service_fn(move |_: Uri| {
            let tls = tls.clone();
            let name = name.clone();
            let addr = addr.clone();
            async move {
                let tcp = tokio::net::TcpStream::connect(addr).await?;
                tcp.set_nodelay(true)?;
                let s = tls.connect(name, tcp).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(s))
            }
        });
        Ok(Client {
            ch: ep.connect_with_connector_lazy(connector),
        })
    }

    /// Connects to a member listening on the Unix socket at path, without
    /// TLS: a scratch member of this machine's own, in a private directory
    /// (`armadad backup` and `restore` check a snapshot in one).
    /// The path may be longer than a socket address holds: the socket is
    /// reached through its directory's descriptor.
    pub fn connect_unix(path: &Path) -> Result<Client> {
        let dir = path.parent().unwrap_or(Path::new("."));
        let name = path
            .file_name()
            .ok_or_else(|| other!("etcd: socket {} has no name", path.display()))?
            .to_os_string();
        let dir = std::fs::File::open(dir).map_err(|e| other!("{e}"))?;
        let ep = Endpoint::from_static("http://localhost").connect_timeout(Duration::from_secs(5));
        let dir = Arc::new(dir);
        let connector = tower::service_fn(move |_: Uri| {
            let p = PathBuf::from(format!(
                "/proc/self/fd/{}",
                std::os::fd::AsRawFd::as_raw_fd(&*dir)
            ))
            .join(&name);
            async move {
                let s = tokio::net::UnixStream::connect(p).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(s))
            }
        });
        Ok(Client {
            ch: ep.connect_with_connector_lazy(connector),
        })
    }

    fn kv(&self) -> KvClient<Channel> {
        KvClient::new(self.ch.clone()).max_decoding_message_size(usize::MAX)
    }

    /// A range request.
    pub async fn range(&self, r: pb::RangeRequest) -> Result<pb::RangeResponse> {
        Ok(self.kv().range(r).await?.into_inner())
    }

    /// A put.
    pub async fn put(&self, key: &str, val: &[u8]) -> Result<pb::PutResponse> {
        let r = pb::PutRequest {
            key: key.as_bytes().to_vec(),
            value: val.to_vec(),
            ..Default::default()
        };
        Ok(self.kv().put(r).await?.into_inner())
    }

    /// A delete of one key, or of [key, end) with end.
    pub async fn delete(&self, key: &str, end: Option<&str>) -> Result<pb::DeleteRangeResponse> {
        let r = pb::DeleteRangeRequest {
            key: key.as_bytes().to_vec(),
            range_end: end.map(|e| e.as_bytes().to_vec()).unwrap_or_default(),
            ..Default::default()
        };
        Ok(self.kv().delete_range(r).await?.into_inner())
    }

    /// A transaction.
    pub async fn txn(&self, r: pb::TxnRequest) -> Result<pb::TxnResponse> {
        Ok(self.kv().txn(r).await?.into_inner())
    }

    /// The member's status (Maintenance.Status).
    pub async fn status(&self) -> Result<pb::StatusResponse> {
        Ok(MaintenanceClient::new(self.ch.clone())
            .status(pb::StatusRequest {})
            .await?
            .into_inner())
    }

    /// Maintenance.Snapshot: a consistent copy of the member's database,
    /// in the stream's blobs, ending with its SHA-256 (clientv3's
    /// Snapshot reader).
    pub async fn snapshot(&self) -> Result<tonic::Streaming<pb::SnapshotResponse>> {
        Ok(MaintenanceClient::new(self.ch.clone())
            .max_decoding_message_size(usize::MAX)
            .snapshot(pb::SnapshotRequest {})
            .await?
            .into_inner())
    }

    /// Cluster.MemberList.
    pub async fn member_list(&self) -> Result<Vec<pb::Member>> {
        Ok(ClusterClient::new(self.ch.clone())
            .member_list(pb::MemberListRequest {
                linearizable: false,
            })
            .await?
            .into_inner()
            .members)
    }

    /// Cluster.MemberUpdate: the member's peer URLs replaced.
    pub async fn member_update(&self, id: u64, peer_urls: Vec<String>) -> Result<()> {
        ClusterClient::new(self.ch.clone())
            .member_update(pb::MemberUpdateRequest {
                id,
                peer_ur_ls: peer_urls,
            })
            .await?;
        Ok(())
    }

    /// Cluster.MemberAdd as a learner: the added member's ID.
    pub async fn member_add_learner(&self, peer_urls: Vec<String>) -> Result<u64> {
        let r = ClusterClient::new(self.ch.clone())
            .member_add(pb::MemberAddRequest {
                peer_ur_ls: peer_urls,
                is_learner: true,
            })
            .await?
            .into_inner();
        Ok(r.member.map(|m| m.id).unwrap_or_default())
    }

    /// Cluster.MemberPromote.
    pub async fn member_promote(&self, id: u64) -> Result<()> {
        ClusterClient::new(self.ch.clone())
            .member_promote(pb::MemberPromoteRequest { id })
            .await?;
        Ok(())
    }

    /// Cluster.MemberRemove.
    pub async fn member_remove(&self, id: u64) -> Result<()> {
        ClusterClient::new(self.ch.clone())
            .member_remove(pb::MemberRemoveRequest { id })
            .await?;
        Ok(())
    }

    /// Grants a lease of ttl seconds.
    pub async fn grant(&self, ttl: i64) -> Result<i64> {
        let r = LeaseClient::new(self.ch.clone())
            .lease_grant(pb::LeaseGrantRequest { ttl, id: 0 })
            .await?
            .into_inner();
        if !r.error.is_empty() {
            return Err(Error::other(r.error));
        }
        Ok(r.id)
    }

    /// Revokes a lease and deletes its keys.
    pub async fn revoke(&self, id: i64) -> Result<()> {
        LeaseClient::new(self.ch.clone())
            .lease_revoke(pb::LeaseRevokeRequest { id })
            .await?;
        Ok(())
    }

    /// Keeps lease id alive (clientv3's KeepAlive): a renewal every third
    /// of its TTL, the stream opened again when it breaks, until the lease
    /// is gone or no renewal was answered within the TTL. The returned
    /// handle tells when that happened.
    pub fn keep_alive(&self, id: i64, ttl: i64) -> KeepAlive {
        let (tx, rx) = watch::channel(false);
        let c = self.clone();
        let task = tokio::spawn(async move {
            c.keep_alive_loop(id, ttl).await;
            let _ = tx.send(true);
        });
        KeepAlive { done: rx, task }
    }

    async fn keep_alive_loop(&self, id: i64, ttl: i64) {
        let mut deadline = tokio::time::Instant::now() + Duration::from_secs(ttl.max(1) as u64);
        loop {
            if tokio::time::Instant::now() >= deadline {
                return;
            }
            let (tx, rx) = mpsc::channel(1);
            // etcd (grpc-go) answers a stream's headers only once it read
            // the first message, so the first request goes in before the
            // call is awaited; otherwise the call waits out the lease.
            if tx.try_send(pb::LeaseKeepAliveRequest { id }).is_err() {
                return;
            }
            let mut lc = LeaseClient::new(self.ch.clone());
            let call = lc.lease_keep_alive(ReceiverStream::new(rx));
            let mut stream = match tokio::time::timeout_at(deadline, call).await {
                Err(_) => return,
                Ok(Err(_)) => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
                Ok(Ok(s)) => s.into_inner(),
            };
            loop {
                match tokio::time::timeout_at(deadline, stream.message()).await {
                    Err(_) => return,
                    Ok(Ok(Some(r))) => {
                        if r.ttl <= 0 {
                            return; // the lease is gone
                        }
                        let now = tokio::time::Instant::now();
                        deadline = now + Duration::from_secs(r.ttl as u64);
                        tokio::time::sleep(Duration::from_millis(r.ttl as u64 * 1000 / 3)).await;
                        if tx.send(pb::LeaseKeepAliveRequest { id }).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        break;
                    }
                }
            }
        }
    }

    /// waitDelete: returns once key is deleted at or after revision rev.
    pub async fn wait_delete(&self, key: &str, rev: i64) -> Result<()> {
        let (tx, rx) = mpsc::channel(1);
        let create = pb::WatchRequest {
            request_union: Some(pb::watch_request::RequestUnion::CreateRequest(
                pb::WatchCreateRequest {
                    key: key.as_bytes().to_vec(),
                    start_revision: rev,
                    ..Default::default()
                },
            )),
        };
        tx.send(create)
            .await
            .map_err(|_| other!("etcd: watch closed"))?;
        let mut stream = WatchClient::new(self.ch.clone())
            .watch(ReceiverStream::new(rx))
            .await?
            .into_inner();
        while let Some(r) = stream.message().await? {
            if r.canceled {
                if r.compact_revision != 0 {
                    return Err(other!(
                        "etcdserver: mvcc: required revision has been compacted"
                    ));
                }
                return Err(Error::other(if r.cancel_reason.is_empty() {
                    "lost watcher waiting for delete".to_string()
                } else {
                    r.cancel_reason
                }));
            }
            if r.events
                .iter()
                .any(|e| e.r#type == mvccpb::event::EventType::Delete as i32)
            {
                drop(tx);
                return Ok(());
            }
        }
        Err(other!("lost watcher waiting for delete"))
    }
}

/// A lease kept alive by Client::keep_alive.
pub struct KeepAlive {
    done: watch::Receiver<bool>,
    task: JoinHandle<()>,
}

impl KeepAlive {
    /// Resolves once the lease is no longer kept alive.
    pub async fn done(&self) {
        let mut rx = self.done.clone();
        let _ = rx.wait_for(|d| *d).await;
    }

    /// Reports whether the lease is no longer kept alive.
    pub fn is_done(&self) -> bool {
        *self.done.borrow() || self.task.is_finished()
    }

    /// Stops renewing the lease.
    pub fn stop(&self) {
        self.task.abort();
    }
}

impl Drop for KeepAlive {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Requests and comparisons in clientv3's terms.
pub mod op {
    use super::pb;

    /// clientv3.GetPrefixRangeEnd.
    pub fn prefix_end(p: &str) -> Vec<u8> {
        let mut end = p.as_bytes().to_vec();
        while let Some(&last) = end.last() {
            if last < 0xff {
                *end.last_mut().expect("not empty") += 1;
                return end;
            }
            end.pop();
        }
        vec![0]
    }

    /// Get of one key at revision rev (0: the latest).
    pub fn get(key: &str, rev: i64) -> pb::RangeRequest {
        pb::RangeRequest {
            key: key.as_bytes().to_vec(),
            revision: rev,
            ..Default::default()
        }
    }

    /// Get of every key under prefix at revision rev.
    pub fn get_prefix(prefix: &str, rev: i64) -> pb::RangeRequest {
        pb::RangeRequest {
            key: prefix.as_bytes().to_vec(),
            range_end: prefix_end(prefix),
            revision: rev,
            ..Default::default()
        }
    }

    pub fn range(r: pb::RangeRequest) -> pb::RequestOp {
        pb::RequestOp {
            request: Some(pb::request_op::Request::RequestRange(r)),
        }
    }

    pub fn put(key: &str, val: &[u8], lease: i64) -> pb::RequestOp {
        pb::RequestOp {
            request: Some(pb::request_op::Request::RequestPut(pb::PutRequest {
                key: key.as_bytes().to_vec(),
                value: val.to_vec(),
                lease,
                ..Default::default()
            })),
        }
    }

    pub fn delete(key: &str) -> pb::RequestOp {
        pb::RequestOp {
            request: Some(pb::request_op::Request::RequestDeleteRange(
                pb::DeleteRangeRequest {
                    key: key.as_bytes().to_vec(),
                    ..Default::default()
                },
            )),
        }
    }

    pub fn delete_range(key: &str, end: &str) -> pb::RequestOp {
        pb::RequestOp {
            request: Some(pb::request_op::Request::RequestDeleteRange(
                pb::DeleteRangeRequest {
                    key: key.as_bytes().to_vec(),
                    range_end: end.as_bytes().to_vec(),
                    ..Default::default()
                },
            )),
        }
    }

    fn compare(
        key: &str,
        target: pb::compare::CompareTarget,
        u: pb::compare::TargetUnion,
    ) -> pb::Compare {
        pb::Compare {
            result: pb::compare::CompareResult::Equal as i32,
            target: target as i32,
            key: key.as_bytes().to_vec(),
            range_end: Vec::new(),
            target_union: Some(u),
        }
    }

    /// Compare(ModRevision(key), "=", rev).
    pub fn mod_is(key: &str, rev: i64) -> pb::Compare {
        compare(
            key,
            pb::compare::CompareTarget::Mod,
            pb::compare::TargetUnion::ModRevision(rev),
        )
    }

    /// Compare(CreateRevision(key), "=", rev).
    pub fn created_at(key: &str, rev: i64) -> pb::Compare {
        compare(
            key,
            pb::compare::CompareTarget::Create,
            pb::compare::TargetUnion::CreateRevision(rev),
        )
    }

    /// The range of the response to request i of a transaction.
    pub fn range_of(r: &pb::TxnResponse, i: usize) -> Option<&pb::RangeResponse> {
        match r.responses.get(i)?.response.as_ref()? {
            pb::response_op::Response::ResponseRange(rr) => Some(rr),
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn prefix_ends() {
            assert_eq!(prefix_end("a/"), b"a0");
            assert_eq!(prefix_end("a\u{7f}"), b"a\x80");
            assert_eq!(prefix_end(""), vec![0]);
        }
    }
}

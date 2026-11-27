//! A member served on a Unix socket, called with etcd's gRPC clients:
//! watches, lease expiry and keep-alive, snapshots, the member list and
//! status, what is refused, and a member opened again.

use std::path::{Path, PathBuf};
use std::time::Duration;

use armada_kv::{Node, Options};
use armada_proto::etcd::etcdserverpb as pb;
use armada_proto::etcd::mvccpb;
use pb::cluster_client::ClusterClient;
use pb::kv_client::KvClient;
use pb::lease_client::LeaseClient;
use pb::maintenance_client::MaintenanceClient;
use pb::watch_client::WatchClient;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint, Uri};

fn dir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("kvg-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

struct Served {
    node: Node,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
    ch: Channel,
}

impl Served {
    async fn shut(self) {
        let Served {
            node,
            stop,
            task,
            ch,
        } = self;
        drop(ch);
        let _ = stop.unwrap().send(());
        let _ = task.await;
        node.close().await;
    }
}

async fn serve(d: &Path) -> Served {
    let node = Node::open(&d.join("member"), Options::default())
        .await
        .unwrap();
    let sock = d.join("client.sock");
    let _ = std::fs::remove_file(&sock);
    let (stop, rx) = oneshot::channel::<()>();
    let n = node.clone();
    let s = sock.clone();
    let task = tokio::spawn(async move {
        armada_kv::serve_unix(n, &s, async {
            let _ = rx.await;
        })
        .await
        .unwrap();
    });
    while !sock.exists() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let ch = Endpoint::from_static("http://localhost")
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let p = sock.clone();
            async move {
                let s = tokio::net::UnixStream::connect(p).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(s))
            }
        }))
        .await
        .unwrap();
    Served {
        node,
        stop: Some(stop),
        task,
        ch,
    }
}

async fn put(ch: &Channel, k: &str, v: &str, lease: i64) -> i64 {
    KvClient::new(ch.clone())
        .put(pb::PutRequest {
            key: k.into(),
            value: v.into(),
            lease,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .header
        .unwrap()
        .revision
}

async fn exists(ch: &Channel, k: &str) -> bool {
    !KvClient::new(ch.clone())
        .range(pb::RangeRequest {
            key: k.into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .kvs
        .is_empty()
}

async fn grant(ch: &Channel, ttl: i64) -> i64 {
    let g = LeaseClient::new(ch.clone())
        .lease_grant(pb::LeaseGrantRequest { ttl, id: 0 })
        .await
        .unwrap()
        .into_inner();
    assert!(g.id > 0);
    assert_eq!(g.ttl, ttl.max(2));
    g.id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watch_and_leases() {
    let d = dir("watch");
    let s = serve(&d).await;
    let ch = s.ch.clone();

    // A watch from a past revision sees a delete that happens later.
    let rev = put(&ch, "w/a", "1", 0).await;
    let (tx, rx) = mpsc::channel(4);
    tx.send(pb::WatchRequest {
        request_union: Some(pb::watch_request::RequestUnion::CreateRequest(
            pb::WatchCreateRequest {
                key: "w/a".into(),
                start_revision: rev,
                ..Default::default()
            },
        )),
    })
    .await
    .unwrap();
    let mut w = WatchClient::new(ch.clone())
        .watch(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let created = w.message().await.unwrap().unwrap();
    assert!(created.created);
    let first = w.message().await.unwrap().unwrap();
    assert_eq!(first.events[0].r#type, mvccpb::event::EventType::Put as i32);
    KvClient::new(ch.clone())
        .delete_range(pb::DeleteRangeRequest {
            key: "w/a".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let del = tokio::time::timeout(Duration::from_secs(5), w.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        del.events[0].r#type,
        mvccpb::event::EventType::Delete as i32
    );
    assert_eq!(del.events[0].kv.as_ref().unwrap().mod_revision, rev + 1);
    drop(tx);

    // A lease not kept alive expires and takes its key; one kept alive
    // keeps it.
    let gone = grant(&ch, 1).await;
    let kept = grant(&ch, 2).await;
    put(&ch, "l/gone", "x", gone).await;
    put(&ch, "l/kept", "x", kept).await;
    let (ktx, krx) = mpsc::channel(4);
    ktx.send(pb::LeaseKeepAliveRequest { id: kept })
        .await
        .unwrap();
    let mut ka = LeaseClient::new(ch.clone())
        .lease_keep_alive(ReceiverStream::new(krx))
        .await
        .unwrap()
        .into_inner();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    while tokio::time::Instant::now() < deadline {
        let a = ka.message().await.unwrap().unwrap();
        assert_eq!((a.id, a.ttl), (kept, 2));
        tokio::time::sleep(Duration::from_millis(500)).await;
        ktx.send(pb::LeaseKeepAliveRequest { id: kept })
            .await
            .unwrap();
    }
    assert!(!exists(&ch, "l/gone").await, "expired with its lease");
    assert!(exists(&ch, "l/kept").await, "kept alive");
    // A keep-alive of a lease that is gone answers TTL 0.
    ktx.send(pb::LeaseKeepAliveRequest { id: gone })
        .await
        .unwrap();
    let _ = ka.message().await.unwrap().unwrap();
    let a = ka.message().await.unwrap().unwrap();
    assert_eq!((a.id, a.ttl), (gone, 0));
    LeaseClient::new(ch.clone())
        .lease_revoke(pb::LeaseRevokeRequest { id: kept })
        .await
        .unwrap();
    assert!(!exists(&ch, "l/kept").await);
    let e = LeaseClient::new(ch.clone())
        .lease_revoke(pb::LeaseRevokeRequest { id: kept })
        .await
        .unwrap_err();
    assert_eq!(e.code(), tonic::Code::NotFound);
    assert_eq!(e.message(), "etcdserver: requested lease not found");
    drop((w, ka, ktx));
    drop(ch);
    s.shut().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maintenance_and_reopen() {
    let d = dir("maint");
    let s = serve(&d).await;
    let ch = s.ch.clone();
    put(&ch, "a", "1", 0).await;
    let rev = put(&ch, "b", "2", 0).await;

    let st = MaintenanceClient::new(ch.clone())
        .status(pb::StatusRequest {})
        .await
        .unwrap()
        .into_inner();
    let member = st.header.unwrap().member_id;
    assert_eq!(st.header.unwrap().revision, rev);
    assert_eq!(st.leader, member);
    assert!(!st.is_learner);
    let members = ClusterClient::new(ch.clone())
        .member_list(pb::MemberListRequest {
            linearizable: false,
        })
        .await
        .unwrap()
        .into_inner()
        .members;
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].id, member);

    let mut snap = MaintenanceClient::new(ch.clone())
        .snapshot(pb::SnapshotRequest {})
        .await
        .unwrap()
        .into_inner();
    let mut b = Vec::new();
    while let Some(m) = snap.message().await.unwrap() {
        b.extend_from_slice(&m.blob);
    }
    let read = armada_kv::snapshot::read(&b).unwrap();
    assert_eq!(read.revision, rev);
    assert_eq!(read.kvs.len(), 2);

    // Outside the subset: Unimplemented.
    let e = LeaseClient::new(ch.clone())
        .lease_time_to_live(pb::LeaseTimeToLiveRequest { id: 1, keys: false })
        .await
        .unwrap_err();
    assert_eq!(e.code(), tonic::Code::Unimplemented);
    let e = ClusterClient::new(ch.clone())
        .member_add(pb::MemberAddRequest::default())
        .await
        .unwrap_err();
    assert_eq!(e.code(), tonic::Code::Unimplemented);
    // Errors keep etcd's codes and texts.
    let e = KvClient::new(ch.clone())
        .range(pb::RangeRequest {
            key: "a".into(),
            revision: rev + 10,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(e.code(), tonic::Code::OutOfRange);
    assert_eq!(
        e.message(),
        "etcdserver: mvcc: required revision is a future revision"
    );
    let e = KvClient::new(ch.clone())
        .put(pb::PutRequest {
            key: "big".into(),
            value: vec![0; armada_kv::service::MAX_REQUEST_BYTES],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(e.message(), "etcdserver: request is too large");
    drop(ch);
    s.shut().await;

    // Opened again: the same member, revision, and keys.
    let s = serve(&d).await;
    let st = MaintenanceClient::new(s.ch.clone())
        .status(pb::StatusRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(st.header.unwrap().member_id, member);
    assert_eq!(st.header.unwrap().revision, rev);
    assert!(exists(&s.ch, "b").await);
    s.shut().await;
}

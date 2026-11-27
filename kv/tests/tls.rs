//! The member's listeners on the network (ADR 0057): two members on
//! loopback over mutual TLS (the client API, the peer service, and the
//! connector between them), and every connection without a member's
//! certificate of the cluster CA refused on both listeners: no
//! certificate, another CA's, another identity's (a node's, a user's, a
//! server's), an expired one, and TLS 1.2. The member list a new member
//! asks for is refused likewise. The member's certificate is read on every
//! handshake.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use armada_kv::peer::{Connector, PeerOp, PeerReply, PeerRequest, PeerResult};
use armada_kv::tls::{self, TlsConnector};
use armada_kv::{Node, Options, Start, Timing};
use armada_pki::{Ca, Identity, IssueRequest};
use armada_proto::etcd::etcdserverpb as pb;
use pb::cluster_client::ClusterClient;
use pb::kv_client::KvClient;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tonic::transport::{Channel, Endpoint, Uri};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn dir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("kvt-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn private(d: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// A certificate of ca for identity, valid for validity (zero: a year).
fn issue(ca: &Ca, identity: Identity, validity: Duration) -> (Vec<u8>, Vec<u8>) {
    let (cert, key) = ca
        .issue(&IssueRequest {
            identity,
            ips: vec![LOOPBACK],
            server: true,
            client: true,
            validity,
            ..Default::default()
        })
        .unwrap();
    (cert, key.expose().to_vec())
}

/// Writes a member's files: the CA it trusts and its certificate.
fn write_member(d: &Path, ca: &Ca, cert: &[u8], key: &[u8]) {
    std::fs::create_dir_all(d).unwrap();
    private(d);
    std::fs::write(d.join(tls::FILE_CA), &ca.cert_pem).unwrap();
    std::fs::write(d.join(tls::FILE_CERT), cert).unwrap();
    std::fs::write(d.join(tls::FILE_KEY), key).unwrap();
}

fn member_files(d: &Path, ca: &Ca) {
    let (c, k) = issue(ca, armada_pki::etcd_member(), Duration::ZERO);
    write_member(d, ca, &c, &k);
}

fn fast() -> Timing {
    Timing {
        heartbeat: Duration::from_millis(50),
        election_min: Duration::from_millis(300),
        election_max: Duration::from_millis(600),
        ..Timing::default()
    }
}

/// A member's listeners on loopback, bound before it opens: their ports
/// name it.
struct Bound {
    api: TcpListener,
    peer: TcpListener,
}

impl Bound {
    async fn new() -> Bound {
        let any = SocketAddr::new(LOOPBACK, 0);
        Bound {
            api: tls::bind(any).await.unwrap(),
            peer: tls::bind(any).await.unwrap(),
        }
    }

    fn peer_url(&self) -> String {
        format!("https://{}", self.peer.local_addr().unwrap())
    }

    /// The member opened in d and served on the listeners.
    async fn start(self, d: &Path, name: &str, start: Start) -> Member {
        let client = self.api.local_addr().unwrap();
        let peer_addr = self.peer.local_addr().unwrap();
        let opts = Options {
            name: name.to_string(),
            peer_urls: vec![self.peer_url()],
            client_urls: vec![format!("https://{client}")],
            start,
            timing: fast(),
            connector: Some(Arc::new(TlsConnector::new(d).unwrap())),
            ..Options::default()
        };
        let cfg = tls::server_config(d).unwrap();
        let node = Node::open(&d.join("member"), opts).await.unwrap();
        let (stop, rx) = watch::channel(false);
        let mut tasks = Vec::new();
        for (lis, peer) in [(self.api, false), (self.peer, true)] {
            let n = node.clone();
            let cfg = cfg.clone();
            let mut rx = rx.clone();
            tasks.push(tokio::spawn(async move {
                let shutdown = async move {
                    let _ = rx.wait_for(|v| *v).await;
                };
                if peer {
                    tls::serve_peer_tls(n, lis, cfg, shutdown).await.unwrap();
                } else {
                    tls::serve_api_tls(n, lis, cfg, shutdown).await.unwrap();
                }
            }));
        }
        Member {
            node,
            client,
            peer: peer_addr,
            stop,
            tasks,
        }
    }
}

/// A member on loopback over mutual TLS.
struct Member {
    node: Node,
    client: SocketAddr,
    peer: SocketAddr,
    stop: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Member {
    async fn start(d: &Path, name: &str, start: Start) -> Member {
        Bound::new().await.start(d, name, start).await
    }

    async fn shut(self) {
        let _ = self.stop.send(true);
        for t in self.tasks {
            let _ = t.await;
        }
        self.node.close().await;
    }
}

/// A gRPC channel to addr over TLS with cfg.
fn channel(addr: SocketAddr, cfg: Arc<rustls::ClientConfig>) -> Channel {
    let tls = tokio_rustls::TlsConnector::from(cfg);
    Endpoint::from_static("http://armada-kv")
        .connect_timeout(Duration::from_secs(3))
        .connect_with_connector_lazy(tower::service_fn(move |_: Uri| {
            let tls = tls.clone();
            async move {
                let tcp = TcpStream::connect(addr).await?;
                let s = tls
                    .connect(ServerName::IpAddress(addr.ip().into()), tcp)
                    .await?;
                Ok::<_, io::Error>(hyper_util::rt::TokioIo::new(s))
            }
        }))
}

/// A client configuration trusting ca, presenting cert and key (none
/// without), on the protocol versions given.
fn client_with(
    ca: &Ca,
    cert: Option<(&[u8], &[u8])>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(&ca.cert_pem).unwrap())
        .unwrap();
    let b = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots);
    let mut cfg = match cert {
        None => b.with_no_client_auth(),
        Some((c, k)) => b
            .with_client_auth_cert(
                vec![CertificateDer::from_pem_slice(c).unwrap()],
                PrivateKeyDer::from_pem_slice(k).unwrap(),
            )
            .unwrap(),
    };
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(cfg)
}

async fn member_list(ch: Channel) -> Result<pb::MemberListResponse, tonic::Status> {
    tokio::time::timeout(
        Duration::from_secs(5),
        ClusterClient::new(ch).member_list(pb::MemberListRequest::default()),
    )
    .await
    .expect("an answer or an error within 5 s")
    .map(tonic::Response::into_inner)
}

/// The member list over the peer service, as a new member asks for it.
async fn peer_members(ch: Channel) -> Result<PeerReply, tonic::Status> {
    let mut g = tonic::client::Grpc::new(ch);
    let call = async move {
        g.ready()
            .await
            .map_err(|e| tonic::Status::unavailable(e.to_string()))?;
        g.unary(
            tonic::Request::new(PeerRequest {
                op: Some(PeerOp::Members(true)),
                ..Default::default()
            }),
            tonic::codegen::http::uri::PathAndQuery::from_static("/armadakv.Peer/Call"),
            tonic_prost::ProstCodec::<PeerRequest, PeerReply>::default(),
        )
        .await
        .map(tonic::Response::into_inner)
    };
    tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("an answer or an error within 5 s")
}

async fn put(ch: Channel, k: &str, v: &str) {
    KvClient::new(ch)
        .put(pb::PutRequest {
            key: k.into(),
            value: v.into(),
            ..Default::default()
        })
        .await
        .unwrap();
}

async fn get(ch: Channel, k: &str, serializable: bool) -> Option<Vec<u8>> {
    let r = KvClient::new(ch)
        .range(pb::RangeRequest {
            key: k.into(),
            serializable,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    r.kvs.first().map(|kv| kv.value.clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_members_over_mutual_tls() {
    let d = dir("two");
    let ca = Ca::new("kv-test").unwrap();
    let (da, db) = (d.join("a"), d.join("b"));
    member_files(&da, &ca);
    member_files(&db, &ca);
    let a = Member::start(&da, "a", Start::New).await;
    let cha = channel(a.client, tls::client_config(&da).unwrap());
    put(cha.clone(), "/k", "one").await;

    // b is added as a learner with its peer URL (its listener bound
    // first), then joins through a's peer listener over mutual TLS.
    let bound = Bound::new().await;
    let added = ClusterClient::new(cha.clone())
        .member_add(pb::MemberAddRequest {
            peer_ur_ls: vec![bound.peer_url()],
            is_learner: true,
        })
        .await
        .unwrap()
        .into_inner();
    let b_id = added.member.unwrap().id;
    let b = bound
        .start(&db, "b", Start::Join(vec![format!("https://{}", a.peer)]))
        .await;
    assert_eq!(b.node.id(), b_id);
    // The leader replicates to b over the connector; b is promoted once in
    // sync (etcd's text until then).
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let r = ClusterClient::new(cha.clone())
            .member_promote(pb::MemberPromoteRequest { id: b_id })
            .await;
        match r {
            Ok(_) => break,
            Err(e) if Instant::now() < deadline => {
                assert!(
                    e.message().contains("in sync with leader"),
                    "{}",
                    e.message()
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("b not promoted: {e}"),
        }
    }
    // A write through b reaches a (forwarded to the leader over the peer
    // service), and a linearizable read through b sees it.
    let chb = channel(b.client, tls::client_config(&db).unwrap());
    put(chb.clone(), "/k", "two").await;
    assert_eq!(
        get(chb.clone(), "/k", false).await.as_deref(),
        Some(&b"two"[..])
    );
    assert_eq!(
        get(cha.clone(), "/k", false).await.as_deref(),
        Some(&b"two"[..])
    );
    // b announces its name; every member sees two voters.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let ms = member_list(chb.clone()).await.unwrap().members;
        if ms.len() == 2 && ms.iter().all(|m| !m.is_learner && !m.name.is_empty()) {
            break;
        }
        assert!(Instant::now() < deadline, "members: {ms:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    b.shut().await;
    a.shut().await;
}

/// Every caller without a member's certificate of the cluster CA is
/// refused, on the client listener and on the peer listener alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listeners_refuse_all_but_members() {
    let d = dir("refuse");
    let ca = Ca::new("kv-test").unwrap();
    let other = Ca::new("another").unwrap();
    let dm = d.join("m");
    member_files(&dm, &ca);
    let m = Member::start(&dm, "m", Start::New).await;

    let member = issue(&ca, armada_pki::etcd_member(), Duration::ZERO);
    let foreign = issue(&other, armada_pki::etcd_member(), Duration::ZERO);
    let node = issue(
        &ca,
        Identity::new(armada_pki::KIND_NODE, "n1"),
        Duration::ZERO,
    );
    let user = issue(
        &ca,
        Identity::new(armada_pki::KIND_USER, "ops"),
        Duration::ZERO,
    );
    let server = issue(
        &ca,
        Identity::new(armada_pki::KIND_SERVER, "s1"),
        Duration::ZERO,
    );
    let expiring = issue(&ca, armada_pki::etcd_member(), Duration::from_secs(1));
    let tls13: &[&'static rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
    let tls12: &[&'static rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];

    // A member's certificate is let in on both listeners, the member list
    // of the peer service included.
    let ok = client_with(&ca, Some((&member.0, &member.1)), tls13);
    member_list(channel(m.client, ok.clone())).await.unwrap();
    match peer_members(channel(m.peer, ok)).await.unwrap().result {
        Some(PeerResult::Members(w)) => assert_ne!(w.cluster, 0),
        r => panic!("peer member list answered {r:?}"),
    }

    // The certificate expires while the test waits.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let refused = [
        ("no client certificate", client_with(&ca, None, tls13)),
        (
            "another CA's member certificate",
            client_with(&ca, Some((&foreign.0, &foreign.1)), tls13),
        ),
        (
            "a node certificate",
            client_with(&ca, Some((&node.0, &node.1)), tls13),
        ),
        (
            "a user certificate",
            client_with(&ca, Some((&user.0, &user.1)), tls13),
        ),
        (
            "a server certificate",
            client_with(&ca, Some((&server.0, &server.1)), tls13),
        ),
        (
            "an expired member certificate",
            client_with(&ca, Some((&expiring.0, &expiring.1)), tls13),
        ),
        (
            "TLS 1.2",
            client_with(&ca, Some((&member.0, &member.1)), tls12),
        ),
    ];
    for (what, cfg) in refused {
        // The handshake fails (TLS 1.2), or the member's alert ends the
        // connection before any request is read.
        let e = member_list(channel(m.client, cfg.clone()))
            .await
            .expect_err(what);
        assert!(
            matches!(e.code(), tonic::Code::Unavailable | tonic::Code::Unknown),
            "client API, {what}: {e}"
        );
        let e = peer_members(channel(m.peer, cfg)).await.expect_err(what);
        assert!(
            matches!(e.code(), tonic::Code::Unavailable | tonic::Code::Unknown),
            "peer service, {what}: {e}"
        );
    }
    // The member still serves members.
    let ok = client_with(&ca, Some((&member.0, &member.1)), tls13);
    member_list(channel(m.client, ok)).await.unwrap();
    m.shut().await;
}

/// The connector talks only to a member: a listener of the same CA whose
/// certificate is another identity's, or names another address, is
/// refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connector_reaches_only_members() {
    let d = dir("connector");
    let ca = Ca::new("kv-test").unwrap();
    let dm = d.join("m");
    member_files(&dm, &ca);
    let connector = TlsConnector::new(&dm).unwrap();

    // A TLS listener presenting cert, accepting any member's client
    // certificate (the server side is not under test here).
    async fn listener(ca: &Ca, cert: (Vec<u8>, Vec<u8>)) -> SocketAddr {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(&ca.cert_pem).unwrap())
            .unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()
        .unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![CertificateDer::from_pem_slice(&cert.0).unwrap()],
                PrivateKeyDer::from_pem_slice(&cert.1).unwrap(),
            )
            .unwrap();
        let acc = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let lis = TcpListener::bind(SocketAddr::new(LOOPBACK, 0))
            .await
            .unwrap();
        let addr = lis.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = lis.accept().await {
                let acc = acc.clone();
                tokio::spawn(async move {
                    if let Ok(mut s) = acc.accept(tcp).await {
                        let mut b = [0u8; 1];
                        let _ = tokio::io::AsyncReadExt::read(&mut s, &mut b).await;
                    }
                });
            }
        });
        addr
    }

    let member = listener(&ca, issue(&ca, armada_pki::etcd_member(), Duration::ZERO)).await;
    assert!(
        connector
            .connect(&format!("https://{member}"))
            .await
            .is_ok()
    );
    let server = listener(
        &ca,
        issue(
            &ca,
            Identity::new(armada_pki::KIND_SERVER, "s1"),
            Duration::ZERO,
        ),
    )
    .await;
    let e = connector
        .connect(&format!("https://{server}"))
        .await
        .err()
        .expect("a server certificate refused");
    assert!(e.to_string().contains("not a member's"), "{e}");
    // A member certificate that names 127.0.0.1 only, dialled at
    // 127.0.0.2: the address does not match.
    let elsewhere = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), member.port());
    let lis2 = TcpListener::bind(elsewhere).await;
    if let Ok(lis2) = lis2 {
        // Forward 127.0.0.2 to the member listener.
        tokio::spawn(async move {
            while let Ok((mut a, _)) = lis2.accept().await {
                tokio::spawn(async move {
                    if let Ok(mut b) = TcpStream::connect(member).await {
                        let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
                    }
                });
            }
        });
        assert!(
            connector
                .connect(&format!("https://{elsewhere}"))
                .await
                .is_err()
        );
    }
    assert!(
        connector
            .connect("https://member.example:7446")
            .await
            .is_err()
    );
}

/// A renewed member certificate is served from the next handshake on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn certificate_read_per_handshake() {
    let d = dir("renew");
    let ca = Ca::new("kv-test").unwrap();
    let dm = d.join("m");
    member_files(&dm, &ca);
    let m = Member::start(&dm, "m", Start::New).await;
    let served = |cfg: Arc<rustls::ClientConfig>| async move {
        let tcp = TcpStream::connect(m.client).await.unwrap();
        let s = tokio_rustls::TlsConnector::from(cfg)
            .connect(ServerName::IpAddress(m.client.ip().into()), tcp)
            .await
            .unwrap();
        s.get_ref().1.peer_certificates().unwrap()[0]
            .as_ref()
            .to_vec()
    };
    let cfg = tls::client_config(&dm).unwrap();
    let before = served(cfg.clone()).await;
    let (c, k) = issue(&ca, armada_pki::etcd_member(), Duration::ZERO);
    write_member(&dm, &ca, &c, &k);
    let after = served(cfg).await;
    assert_ne!(before, after);
    assert_eq!(after, CertificateDer::from_pem_slice(&c).unwrap().as_ref());
    m.shut().await;
}

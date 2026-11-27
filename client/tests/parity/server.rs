//! The stand-in AdminService: scripted answers over mTLS with
//! certificates issued for the run. Every
//! call is served as a stream of raw messages; requests are kept as their
//! protobuf JSON and answers encoded from theirs, by method.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use armada_proto::armada::v1 as pb;
use prost::Message;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::{Code, Status, Streaming};

macro_rules! methods {
    ($($name:literal => $req:ident, $resp:ident;)*) => {
        /// A request of method as its protobuf JSON.
        fn decode_request(method: &str, b: &[u8]) -> Result<Value, String> {
            match method {
                $($name => {
                    let m = pb::$req::decode(b).map_err(|e| format!("{method} request: {e}"))?;
                    serde_json::to_value(&m).map_err(|e| e.to_string())
                })*
                _ => Err(format!("unknown method {method}")),
            }
        }

        /// An answer of method from its protobuf JSON.
        fn encode_response(method: &str, v: &Value) -> Result<Vec<u8>, String> {
            match method {
                $($name => {
                    let m: pb::$resp = serde_json::from_value(v.clone()).map_err(|e| format!("{method} answer: {e}"))?;
                    Ok(m.encode_to_vec())
                })*
                _ => Err(format!("unknown method {method}")),
            }
        }
    };
}

// AdminService's methods with their request and response types (the rpc
// lines of api/armada/v1/armada.proto).
methods! {
    "Deploy" => DeployRequest, DeployResponse;
    "Status" => StatusRequest, StatusResponse;
    "ListApps" => ListAppsRequest, ListAppsResponse;
    "ClusterStatus" => ClusterStatusRequest, ClusterStatusResponse;
    "GetAppSpec" => GetAppSpecRequest, GetAppSpecResponse;
    "SetTraffic" => SetTrafficRequest, SetTrafficResponse;
    "ListVolumes" => ListVolumesRequest, ListVolumesResponse;
    "RemoveVolume" => RemoveVolumeRequest, RemoveVolumeResponse;
    "BackupVolume" => BackupVolumeRequest, VolumeData;
    "RestoreVolume" => RestoreVolumeMessage, RestoreVolumeResponse;
    "ListVolumeSnapshots" => ListVolumeSnapshotsRequest, ListVolumeSnapshotsResponse;
    "CreateVolumeSnapshot" => CreateVolumeSnapshotRequest, CreateVolumeSnapshotResponse;
    "RestoreVolumeSnapshot" => RestoreVolumeSnapshotRequest, RestoreVolumeResponse;
    "Logs" => LogsRequest, LogEntry;
    "GetClusterConfig" => GetClusterConfigRequest, ClusterConfig;
    "SetClusterConfig" => SetClusterConfigRequest, ClusterConfig;
    "ListDomains" => ListDomainsRequest, ListDomainsResponse;
    "VerifyDomain" => VerifyDomainRequest, Domain;
    "ListRevisions" => ListRevisionsRequest, ListRevisionsResponse;
    "Rollback" => RollbackRequest, RollbackResponse;
    "RestartApp" => RestartAppRequest, RestartAppResponse;
    "SetSecret" => SetSecretRequest, SetSecretResponse;
    "ListSecrets" => ListSecretsRequest, ListSecretsResponse;
    "DeleteSecret" => DeleteSecretRequest, DeleteSecretResponse;
    "ListSpaceSecrets" => ListSpaceSecretsRequest, ListSpaceSecretsResponse;
    "CreateJoinToken" => CreateJoinTokenRequest, CreateJoinTokenResponse;
    "CordonNode" => CordonNodeRequest, CordonNodeResponse;
    "LabelNode" => LabelNodeRequest, LabelNodeResponse;
    "RestrictNode" => RestrictNodeRequest, RestrictNodeResponse;
    "SetNodeSite" => SetNodeSiteRequest, SetNodeSiteResponse;
    "SetNodeRelay" => SetNodeRelayRequest, SetNodeRelayResponse;
    "RotateNodeKey" => RotateNodeKeyRequest, RotateNodeKeyResponse;
    "RemoveNode" => RemoveNodeRequest, RemoveNodeResponse;
    "ListServers" => ListServersRequest, ListServersResponse;
    "RemoveServer" => RemoveServerRequest, RemoveServerResponse;
    "CreateSpace" => CreateSpaceRequest, SpaceInfo;
    "ListSpaces" => ListSpacesRequest, ListSpacesResponse;
    "DeleteSpace" => DeleteSpaceRequest, DeleteSpaceResponse;
    "UpdateSpace" => UpdateSpaceRequest, SpaceInfo;
    "CreateUser" => CreateUserRequest, IssueMetricsCertificateResponse;
    "IssueUserCertificate" => IssuePrincipalCertificateRequest, IssueMetricsCertificateResponse;
    "CreateService" => CreateServiceRequest, Principal;
    "IssueServiceCertificate" => IssuePrincipalCertificateRequest, IssueMetricsCertificateResponse;
    "ListPrincipals" => ListPrincipalsRequest, ListPrincipalsResponse;
    "UpdatePrincipal" => UpdatePrincipalRequest, Principal;
    "DeletePrincipal" => DeletePrincipalRequest, DeletePrincipalResponse;
    "CreateAssignment" => AssignmentRequest, Principal;
    "DeleteAssignment" => AssignmentRequest, Principal;
    "ListRoles" => ListRolesRequest, ListRolesResponse;
    "RenewOwnCertificate" => RenewOwnCertificateRequest, IssueMetricsCertificateResponse;
    "Exec" => ExecClientMessage, ExecServerMessage;
    "Top" => TopRequest, TopResponse;
    "IssueMetricsCertificate" => IssueMetricsCertificateRequest, IssueMetricsCertificateResponse;
    "ListMetricsCredentials" => ListMetricsCredentialsRequest, ListMetricsCredentialsResponse;
    "RevokeMetricsCredentials" => RevokeMetricsCredentialsRequest, RevokeMetricsCredentialsResponse;
    "Events" => EventsRequest, EventInfo;
    "CreateAlertChannel" => AlertChannelRequest, AlertChannel;
    "UpdateAlertChannel" => AlertChannelRequest, AlertChannel;
    "ListAlertChannels" => ListAlertChannelsRequest, ListAlertChannelsResponse;
    "DeleteAlertChannel" => DeleteAlertChannelRequest, DeleteAlertChannelResponse;
    "TestAlertChannel" => TestAlertChannelRequest, TestAlertChannelResponse;
    "RunJob" => RunJobRequest, RunJobResponse;
    "ListJobs" => ListJobsRequest, ListJobsResponse;
    "ListJobRuns" => ListJobRunsRequest, ListJobRunsResponse;
    "CancelJob" => CancelJobRequest, CancelJobResponse;
    "DeleteJob" => DeleteJobRequest, DeleteJobResponse;
    "RemoveApp" => RemoveAppRequest, RemoveAppResponse;
}

/// One scripted reply: msg, or a stream of messages (None
/// waits for the end of an Exec's input), then code and text.
#[derive(Clone, Debug)]
pub struct Answer {
    pub msg: Option<Value>,
    pub code: i32,
    pub text: String,
    pub servers: String,
    pub stream: Option<Vec<Option<Value>>>,
}

/// A request the fake received, as the recording writes it.
#[derive(Clone, Debug, PartialEq)]
pub struct Call {
    pub method: String,
    /// The request's protobuf JSON, or "" for a method the fake does not
    /// know.
    pub request: Option<Value>,
    /// RestoreVolume's start message.
    pub start: Option<Value>,
    /// RestoreVolume's archive, or an Exec's input.
    pub data: Option<Vec<u8>>,
    /// What ended an Exec's input, and its other messages.
    pub rest: Option<Vec<Value>>,
}

#[derive(Default)]
struct Script {
    answers: HashMap<String, Vec<Answer>>,
    calls: Vec<Call>,
}

#[derive(Clone, Default)]
pub struct Fake(Arc<Mutex<Script>>);

impl Fake {
    pub fn reset(&self, answers: HashMap<String, Vec<Answer>>) {
        let mut s = self.0.lock().unwrap();
        s.answers = answers;
        s.calls.clear();
    }

    pub fn calls(&self) -> Vec<Call> {
        self.0.lock().unwrap().calls.clone()
    }

    /// The next answer of method, the last one repeated, recording c.
    fn next(&self, c: Call) -> Option<Answer> {
        let mut s = self.0.lock().unwrap();
        let method = c.method.clone();
        s.calls.push(c);
        let list = s.answers.get_mut(&method)?;
        if list.is_empty() {
            return None;
        }
        Some(if list.len() > 1 {
            list.remove(0)
        } else {
            list[0].clone()
        })
    }

    fn record(&self, c: Call) {
        self.0.lock().unwrap().calls.push(c);
    }
}

fn call(method: &str, request: Value) -> Call {
    Call {
        method: method.to_string(),
        request: Some(request),
        start: None,
        data: None,
        rest: None,
    }
}

fn unscripted(method: &str) -> Status {
    Status::new(
        Code::Unimplemented,
        format!("no answer scripted for {method}"),
    )
}

fn status(a: &Answer) -> Option<Status> {
    (a.code != 0).then(|| Status::new(Code::from_i32(a.code), a.text.clone()))
}

/// Messages as their bytes.
#[derive(Clone, Copy, Default)]
struct Raw;

impl Codec for Raw {
    type Encode = Vec<u8>;
    type Decode = Vec<u8>;
    type Encoder = Raw;
    type Decoder = Raw;
    fn encoder(&mut self) -> Raw {
        Raw
    }
    fn decoder(&mut self) -> Raw {
        Raw
    }
}

impl Encoder for Raw {
    type Item = Vec<u8>;
    type Error = Status;
    fn encode(&mut self, item: Vec<u8>, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        bytes_put(dst, &item);
        Ok(())
    }
}

fn bytes_put(dst: &mut EncodeBuf<'_>, b: &[u8]) {
    use prost::bytes::BufMut;
    dst.put_slice(b);
}

impl Decoder for Raw {
    type Item = Vec<u8>;
    type Error = Status;
    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Vec<u8>>, Status> {
        use prost::bytes::Buf;
        let mut out = vec![0; src.remaining()];
        src.copy_to_slice(&mut out);
        Ok(Some(out))
    }
}

type Out = mpsc::Sender<Result<Vec<u8>, Status>>;
type Reply = Result<tonic::Response<ReceiverStream<Result<Vec<u8>, Status>>>, Status>;

/// Serves one call of method: unary, or streamed for Logs, Events,
/// BackupVolume, RestoreVolume, and Exec. An answer
/// that ends in an error before any message is a status alone, as
/// grpc-go sends it.
async fn serve(fake: Fake, method: String, mut input: Streaming<Vec<u8>>) -> Reply {
    let (tx, rx) = mpsc::channel(64);
    let reply = |meta: Option<String>| {
        let mut r = tonic::Response::new(ReceiverStream::new(rx));
        if let Some(s) = meta
            && let Ok(v) = s.parse()
        {
            r.metadata_mut().insert("armada-servers", v);
        }
        Ok(r)
    };
    let first = match input.message().await {
        Ok(Some(m)) => Some(m),
        Ok(None) => None,
        Err(e) => return Err(e),
    };
    match method.as_str() {
        "Logs" | "Events" | "BackupVolume" => {
            let req =
                decode_request(&method, &first.unwrap_or_default()).map_err(Status::internal)?;
            let a = fake
                .next(call(&method, req))
                .ok_or_else(|| unscripted(&method))?;
            let msgs = a.stream.clone().unwrap_or_default();
            if msgs.is_empty()
                && let Some(st) = status(&a)
            {
                return Err(st);
            }
            send_all(&tx, &method, &msgs, &a).await;
            drop(tx);
            reply(None)
        }
        "RestoreVolume" => {
            let mut start = Value::Null;
            let mut data = Vec::new();
            let mut msg = first;
            while let Some(m) = msg {
                let v = decode_request(&method, &m).map_err(Status::internal)?;
                if let Some(s) = v.get("start") {
                    start = s.clone();
                }
                if let Some(Value::String(d)) = v.get("data") {
                    data.extend(crate::base64_decode(d).unwrap_or_default());
                }
                msg = input.message().await?;
            }
            let c = Call {
                method: method.clone(),
                request: None,
                start: Some(start),
                data: Some(data),
                rest: None,
            };
            let a = fake.next(c).ok_or_else(|| unscripted(&method))?;
            if a.code == 0 {
                let b = encode_response(&method, a.msg.as_ref().unwrap_or(&json!({})))
                    .map_err(Status::internal)?;
                let _ = tx.send(Ok(b)).await;
                drop(tx);
                return reply(None);
            }
            let msgs = a.stream.clone().unwrap_or_default();
            if msgs.is_empty() {
                return Err(status(&a).unwrap());
            }
            send_all(&tx, &method, &msgs, &a).await;
            drop(tx);
            reply(None)
        }
        "Exec" => {
            let req =
                decode_request(&method, &first.unwrap_or_default()).map_err(Status::internal)?;
            let a = fake
                .next(call(&method, req))
                .ok_or_else(|| unscripted(&method))?;
            let msgs = a.stream.clone().unwrap_or_default();
            if msgs.is_empty()
                && let Some(st) = status(&a)
            {
                return Err(st);
            }
            tokio::spawn(async move {
                for m in &msgs {
                    match m {
                        Some(v) => {
                            let b = encode_response(&method, v).unwrap();
                            if tx.send(Ok(b)).await.is_err() {
                                return;
                            }
                        }
                        None => exec_input(&fake, &method, &mut input).await,
                    }
                }
                if let Some(st) = status(&a) {
                    let _ = tx.send(Err(st)).await;
                }
            });
            reply(None)
        }
        _ => {
            let req = match decode_request(&method, &first.unwrap_or_default()) {
                Ok(v) => v,
                Err(_) => {
                    fake.record(Call {
                        method: method.clone(),
                        request: None,
                        start: None,
                        data: None,
                        rest: None,
                    });
                    return Err(unscripted(&method));
                }
            };
            let a = fake
                .next(call(&method, req))
                .ok_or_else(|| unscripted(&method))?;
            if let Some(st) = status(&a) {
                return Err(st);
            }
            let b = encode_response(&method, a.msg.as_ref().unwrap_or(&json!({})))
                .map_err(Status::internal)?;
            let _ = tx.send(Ok(b)).await;
            drop(tx);
            reply((!a.servers.is_empty()).then(|| a.servers.clone()))
        }
    }
}

async fn send_all(tx: &Out, method: &str, msgs: &[Option<Value>], a: &Answer) {
    for v in msgs.iter().flatten() {
        let b = encode_response(method, v).unwrap();
        if tx.send(Ok(b)).await.is_err() {
            return;
        }
    }
    if let Some(st) = status(a) {
        let _ = tx.send(Err(st)).await;
    }
}

/// The input of an Exec until it ends or closes: stdin in one, the rest
/// as their JSON.
async fn exec_input(fake: &Fake, method: &str, input: &mut Streaming<Vec<u8>>) {
    let mut stdin = Vec::new();
    let mut rest = Vec::new();
    loop {
        let m = match input.message().await {
            Ok(Some(m)) => m,
            _ => {
                rest.push(Value::String("end".into()));
                break;
            }
        };
        let Ok(v) = decode_request(method, &m) else {
            rest.push(Value::String("end".into()));
            break;
        };
        let inp = v.get("input");
        if let Some(Value::String(s)) = inp.and_then(|i| i.get("stdin")) {
            stdin.extend(crate::base64_decode(s).unwrap_or_default());
            continue;
        }
        if inp.and_then(|i| i.get("closeStdin")) == Some(&Value::Bool(true)) {
            rest.push(Value::String("close".into()));
            break;
        }
        rest.push(v);
    }
    fake.record(Call {
        method: "ExecInput".into(),
        request: None,
        start: None,
        data: Some(stdin),
        rest: Some(rest),
    });
}

#[derive(Clone)]
struct Dispatch(Fake);

impl tower::Service<tonic::codegen::http::Request<tonic::body::Body>> for Dispatch {
    type Response = tonic::codegen::http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: tonic::codegen::http::Request<tonic::body::Body>) -> Self::Future {
        let fake = self.0.clone();
        Box::pin(async move {
            let method = req
                .uri()
                .path()
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_string();
            let svc = tower::service_fn(move |r: tonic::Request<Streaming<Vec<u8>>>| {
                serve(fake.clone(), method.clone(), r.into_inner())
            });
            let mut grpc = tonic::server::Grpc::new(Raw);
            Ok(grpc.streaming(svc, req).await)
        })
    }
}

/// A TLS connection tonic's server takes.
struct Conn(tokio_rustls::server::TlsStream<TcpStream>);

impl tonic::transport::server::Connected for Conn {
    type ConnectInfo = ();
    fn connect_info(&self) {}
}

impl AsyncRead for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// The certificates of a run: the same kinds the recorded run used.
pub struct Certs {
    pub ca: String,
    pub cert: String,
    pub key: String,
    server: rustls::ServerConfig,
}

impl Certs {
    pub fn new() -> Certs {
        use armada_pki::{Ca, Identity, IssueRequest};
        use rustls_pki_types::pem::PemObject;
        use rustls_pki_types::{CertificateDer, PrivateKeyDer};
        let ca = Ca::new("parity").unwrap();
        let (srv_cert, srv_key) = ca
            .issue(&IssueRequest {
                identity: Identity::new("server", "s1"),
                dns_names: vec![armada_pki::SERVER_NAME.to_string()],
                server: true,
                ..Default::default()
            })
            .unwrap();
        let (user_cert, user_key) = ca
            .issue(&IssueRequest {
                identity: Identity::new("user", "ada"),
                client: true,
                ..Default::default()
            })
            .unwrap();
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
        let chain = vec![CertificateDer::from_pem_slice(&srv_cert).unwrap()];
        let key = PrivateKeyDer::from_pem_slice(srv_key.expose()).unwrap();
        let mut server = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)
            .unwrap();
        server.alpn_protocols = vec![b"h2".to_vec()];
        Certs {
            ca: String::from_utf8(ca.cert_pem.clone()).unwrap(),
            cert: String::from_utf8(user_cert).unwrap(),
            key: String::from_utf8(user_key.expose().to_vec()).unwrap(),
            server,
        }
    }
}

/// Starts the fake on a loopback port: its address.
pub async fn start(fake: Fake, certs: &Certs) -> String {
    let lis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = lis.local_addr().unwrap().to_string();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(certs.server.clone()));
    let (tx, rx) = mpsc::channel::<Result<Conn, io::Error>>(16);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = lis.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    let _ = tx.send(Ok(Conn(tls))).await;
                }
            });
        }
    });
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .serve_with_incoming(Dispatch(fake), ReceiverStream::new(rx))
            .await;
    });
    addr
}

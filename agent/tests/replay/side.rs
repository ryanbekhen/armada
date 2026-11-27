//! The sessions' harness: a control plane's exec, log, and volume sessions
//! over mTLS, a log endpoint, and the fake armada-node
//! (src/bin/armada-agent-fake-node.rs) with its script and log in the run's
//! directory.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use armada_proto::armada::v1 as pb;
use pb::agent_service_server::{AgentService, AgentServiceServer};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::Connected;
use tonic::{Request, Response, Status, Streaming};

use super::gofmt::quote;

/// The runtime the sessions' servers run on, shared by every run.
fn rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    })
}

/// What the control plane's side records and sends.
#[derive(Default)]
struct Server {
    log: Mutex<Vec<String>>,
    exec_in: Mutex<Vec<pb::ExecInput>>,
    vol_in: Mutex<Vec<pb::VolumeData>>,
    /// The whole session: the assignment sent on every Connect, the Hellos and
    /// reports received.
    session: Mutex<Session>,
}

/// What a session's control plane saw.
#[derive(Default, Clone)]
pub struct Session {
    pub assignment: Option<pb::Assignment>,
    pub hellos: Vec<pb::Hello>,
    pub reports: Vec<pb::ReplicaReport>,
}

impl Server {
    fn note(&self, s: String) {
        self.log.lock().unwrap().push(s);
    }
}

/// Data quoted, or by its length and first 16 bytes past 64 bytes.
fn short(b: &[u8]) -> String {
    if b.len() > 64 {
        return format!("{} bytes {}...", b.len(), quote(&b[..16]));
    }
    quote(b)
}

fn exec_text(m: &pb::ExecSessionOutput) -> String {
    use pb::exec_session_output::Output;
    match &m.output {
        Some(Output::Stdout(b)) => format!("stdout {}", short(b)),
        Some(Output::Stderr(b)) => format!("stderr {}", short(b)),
        Some(Output::ExitCode(c)) => format!("exit {c}"),
        Some(Output::Error(e)) => format!("error {}", quote(e.as_bytes())),
        None => format!("attach {}", m.request_id),
    }
}

/// RFC 3339 with nanoseconds, trailing zeros dropped.
fn rfc3339_nano(secs: i64, nanos: i32) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let mut out = format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    );
    if nanos != 0 {
        let f = format!("{nanos:09}");
        out.push('.');
        out.push_str(f.trim_end_matches('0'));
    }
    out.push('Z');
    out
}

type Out<T> = ReceiverStream<Result<T, Status>>;

/// The service over the shared state.
#[derive(Clone)]
struct Svc(Arc<Server>);

impl std::ops::Deref for Svc {
    type Target = Server;
    fn deref(&self) -> &Server {
        &self.0
    }
}

#[tonic::async_trait]
impl AgentService for Svc {
    type ConnectStream = Out<pb::ServerMessage>;
    type ExecSessionStream = Out<pb::ExecInput>;
    type VolumeSessionStream = Out<pb::VolumeData>;

    async fn connect(
        &self,
        req: Request<Streaming<pb::AgentMessage>>,
    ) -> Result<Response<Self::ConnectStream>, Status> {
        use pb::agent_message::Msg;
        let mut st = req.into_inner();
        let Ok(Some(first)) = st.message().await else {
            return Err(Status::cancelled("no hello"));
        };
        let (n, asg) = {
            let mut s = self.session.lock().unwrap();
            if let Some(Msg::Hello(h)) = first.msg {
                s.hellos.push(h);
            }
            (s.hellos.len(), s.assignment.clone().unwrap_or_default())
        };
        let (tx, rx) = mpsc::channel(16);
        let _ = tx
            .send(Ok(pb::ServerMessage {
                msg: Some(pb::server_message::Msg::Assignment(asg)),
            }))
            .await;
        let me = self.0.clone();
        tokio::spawn(async move {
            if n > 1 {
                // Held open until the agent goes.
                while let Ok(Some(_)) = st.message().await {}
                drop(tx);
                return;
            }
            while let Ok(Some(m)) = st.message().await {
                if let Some(Msg::Report(r)) = m.msg {
                    let done = r.replicas.len() == 1 && r.replicas[0].ready;
                    me.session.lock().unwrap().reports.push(r);
                    if done {
                        return; // the session ends: the agent reconnects
                    }
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn push_logs(
        &self,
        req: Request<Streaming<pb::LogPush>>,
    ) -> Result<Response<pb::PushLogsResponse>, Status> {
        let mut st = req.into_inner();
        while let Ok(Some(m)) = st.message().await {
            let t = m
                .time
                .as_ref()
                .map(|t| format!(" at {}", rfc3339_nano(t.seconds, t.nanos)))
                .unwrap_or_default();
            self.note(format!(
                "logs {} stream={} data={} error={} replica={}{t}",
                m.request_id,
                m.stream,
                short(&m.data),
                quote(m.error.as_bytes()),
                quote(m.replica.as_bytes())
            ));
        }
        Ok(Response::new(pb::PushLogsResponse::default()))
    }

    async fn exec_session(
        &self,
        req: Request<Streaming<pb::ExecSessionOutput>>,
    ) -> Result<Response<Self::ExecSessionStream>, Status> {
        use pb::exec_session_output::Output;
        let mut st = req.into_inner();
        let input = self.exec_in.lock().unwrap().clone();
        let (tx, rx) = mpsc::channel(16);
        let me = self.0.clone();
        tokio::spawn(async move {
            let mut sent = false;
            while let Ok(Some(m)) = st.message().await {
                me.note(format!("exec {}", exec_text(&m)));
                match m.output {
                    Some(Output::ExitCode(_)) | Some(Output::Error(_)) => return,
                    None if !sent => {
                        sent = true;
                        for x in &input {
                            if tx.send(Ok(x.clone())).await.is_err() {
                                return;
                            }
                        }
                    }
                    _ => {}
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn volume_session(
        &self,
        req: Request<Streaming<pb::VolumeData>>,
    ) -> Result<Response<Self::VolumeSessionStream>, Status> {
        let mut st = req.into_inner();
        let input = self.vol_in.lock().unwrap().clone();
        let (tx, rx) = mpsc::channel(16);
        let me = self.0.clone();
        tokio::spawn(async move {
            let mut sent = false;
            let mut data: Vec<u8> = Vec::new();
            while let Ok(Some(m)) = st.message().await {
                if m.data.len() > 64 << 10 {
                    me.note(format!("volume chunk of {} bytes", m.data.len()));
                }
                let d = pb::VolumeData {
                    request_id: m.request_id.clone(),
                    done: m.done,
                    error: m.error.clone(),
                    snapshot: m.snapshot.clone(),
                    snapshots: m.snapshots.clone(),
                    data: Vec::new(),
                };
                data.extend(&m.data);
                if !m.data.is_empty()
                    && d.request_id.is_empty()
                    && !d.done
                    && d.error.is_empty()
                    && d.snapshot.is_none()
                    && d.snapshots.is_empty()
                {
                    continue;
                }
                if !data.is_empty() {
                    me.note(format!("volume data={}", short(&data)));
                    data.clear();
                }
                me.note(format!(
                    "volume {}",
                    serde_json::to_string(&d).unwrap_or_default()
                ));
                if m.done || !m.error.is_empty() {
                    return;
                }
                if !sent {
                    sent = true;
                    for x in &input {
                        if tx.send(Ok(x.clone())).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn renew_certificate(
        &self,
        _: Request<pb::RenewCertificateRequest>,
    ) -> Result<Response<pb::RenewCertificateResponse>, Status> {
        Err(Status::unimplemented("renew"))
    }

    async fn get_certificates(
        &self,
        _: Request<pb::GetCertificatesRequest>,
    ) -> Result<Response<pb::GetCertificatesResponse>, Status> {
        Err(Status::unimplemented("certificates"))
    }
}

/// An accepted TLS connection, as tonic's server takes it.
struct Conn(tokio_rustls::server::TlsStream<tokio::net::TcpStream>);

impl Connected for Conn {
    type ConnectInfo = ();
    fn connect_info(&self) {}
}

impl AsyncRead for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// The log endpoint: each request with its gunzipped body.
#[derive(Default)]
struct Export {
    log: Mutex<Vec<String>>,
    status: Mutex<i64>,
}

fn observed(body: &str) -> String {
    let key = "\"observedTimeUnixNano\":\"";
    let mut out = String::new();
    let mut rest = body;
    while let Some(i) = rest.find(key) {
        out.push_str(&rest[..i + key.len()]);
        let after = &rest[i + key.len()..];
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 && after[digits..].starts_with('"') {
            out.push_str("NOW");
        } else {
            out.push_str(&after[..digits]);
        }
        rest = &after[digits..];
    }
    out.push_str(rest);
    out
}

impl Export {
    fn serve(self: Arc<Self>, lis: TcpListener) {
        for conn in lis.incoming() {
            let Ok(conn) = conn else { break };
            let me = self.clone();
            std::thread::spawn(move || me.handle(conn));
        }
    }

    fn handle(&self, conn: std::net::TcpStream) {
        let mut r = BufReader::new(conn.try_clone().unwrap());
        let mut w = conn;
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let mut parts = line.split_whitespace();
            let method = parts.next().unwrap_or("").to_string();
            let path = parts.next().unwrap_or("").to_string();
            let mut headers: Vec<(String, String)> = Vec::new();
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).unwrap_or(0) == 0 {
                    return;
                }
                let h = h.trim_end();
                if h.is_empty() {
                    break;
                }
                if let Some((k, v)) = h.split_once(':') {
                    headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
                }
            }
            let get = |k: &str| {
                headers
                    .iter()
                    .find(|(n, _)| n == k)
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default()
            };
            let n: usize = get("content-length").parse().unwrap_or(0);
            let mut raw = vec![0u8; n];
            if r.read_exact(&mut raw).is_err() {
                return;
            }
            let mut body = "(not gzip)".to_string();
            let mut dec = flate2::read::GzDecoder::new(&raw[..]);
            let mut out = Vec::new();
            // An empty body is no gzip stream.
            if !raw.is_empty() && dec.read_to_end(&mut out).is_ok() {
                body = observed(&String::from_utf8_lossy(&out));
            }
            self.log.lock().unwrap().push(format!(
                "{method} {path} type={} encoding={} agent={} auth={} tenant={} {body}",
                get("content-type"),
                get("content-encoding"),
                get("user-agent"),
                quote(get("authorization").as_bytes()),
                quote(get("x-scope-orgid").as_bytes()),
            ));
            let status = *self.status.lock().unwrap();
            let resp = if status != 0 {
                let b = "too many\nrequests secret-token";
                format!(
                    "HTTP/1.1 {status} Status\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{b}",
                    b.len()
                )
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string()
            };
            if w.write_all(resp.as_bytes()).is_err() {
                return;
            }
        }
    }
}

/// One run's control plane, fake armada-node, and log endpoint.
pub struct Side {
    pub root: PathBuf,
    bin: PathBuf,
    creds: PathBuf,
    addr: String,
    srv: Arc<Server>,
    export: Arc<Export>,
    export_addr: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Side {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
    }
}

fn write_private(p: &std::path::Path, b: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(p)
        .unwrap();
    f.write_all(b).unwrap();
}

impl Side {
    pub fn start(root: PathBuf) -> Side {
        let bin = root.join("armada-node");
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\nARMADA_FAKE_NODE_ROOT={} exec {} \"$@\"\n",
                root.display(),
                env!("CARGO_BIN_EXE_armada-agent-fake-node")
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        for d in ["volumes", "nfs", "conntrack"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.join(d), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        // The CA, the control plane's certificate, and the node's.
        let ca = armada_pki::Ca::new("test").unwrap();
        let (cert, key) = ca
            .issue(&armada_pki::IssueRequest {
                identity: armada_pki::Identity::new(armada_pki::KIND_SERVER, "s1"),
                dns_names: vec![armada_pki::SERVER_NAME.to_string()],
                server: true,
                ..Default::default()
            })
            .unwrap();
        let creds = root.join("creds");
        std::fs::create_dir_all(&creds).unwrap();
        let (node_key, csr) = armada_pki::new_node_csr("n1").unwrap();
        let node = ca
            .sign_node_csr(&csr, "n1", Duration::from_secs(3600))
            .unwrap();
        write_private(&creds.join("ca.crt"), &ca.cert_pem);
        write_private(&creds.join("node.crt"), &node.pem);
        write_private(&creds.join("node.key"), node_key.expose());

        let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            rustls_pki_types::pem::PemObject::pem_slice_iter(&cert)
                .collect::<Result<_, _>>()
                .unwrap();
        let key = <rustls_pki_types::PrivateKeyDer<'static> as rustls_pki_types::pem::PemObject>::from_pem_slice(key.expose()).unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        let mut tls = tls;
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let srv = Arc::new(Server::default());
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let addr = {
            let _g = rt().enter();
            let lis = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = lis.local_addr().unwrap().to_string();
            lis.set_nonblocking(true).unwrap();
            let lis = tokio::net::TcpListener::from_std(lis).unwrap();
            let (ctx, crx) = mpsc::channel::<Result<Conn, std::io::Error>>(16);
            rt().spawn(async move {
                loop {
                    let Ok((tcp, _)) = lis.accept().await else {
                        return;
                    };
                    let acceptor = acceptor.clone();
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        if let Ok(s) = acceptor.accept(tcp).await {
                            let _ = ctx.send(Ok(Conn(s))).await;
                        }
                    });
                }
            });
            let svc = AgentServiceServer::new(Svc(srv.clone()));
            rt().spawn(async move {
                let _ = tonic::transport::Server::builder()
                    .serve_with_incoming_shutdown(svc, ReceiverStream::new(crx), async {
                        let _ = stop_rx.await;
                    })
                    .await;
            });
            addr
        };
        let export = Arc::new(Export::default());
        let lis = TcpListener::bind("127.0.0.1:0").unwrap();
        let export_addr = lis.local_addr().unwrap().to_string();
        {
            let e = export.clone();
            std::thread::spawn(move || e.serve(lis));
        }
        let sh = Side {
            root,
            bin,
            creds,
            addr,
            srv,
            export,
            export_addr,
            stop: Some(stop_tx),
        };
        sh.script(&json!({}));
        sh
    }

    pub fn export_url(&self) -> String {
        format!("http://{}", self.export_addr)
    }

    pub fn rust_config(&self) -> Value {
        json!({
            "nodeBin": self.bin.display().to_string(),
            "nfsDir": self.root.join("nfs").display().to_string(),
            "conntrackDir": self.root.join("conntrack").display().to_string(),
            "conntrackMemory": 1i64 << 30, "queueMs": 15_000, "sandboxMs": 3_600_000,
        })
    }

    pub fn connect(&self) -> Value {
        json!({"dataDir": self.creds.display().to_string(), "node": "n1", "servers": [self.addr]})
    }

    /// Writes the fake armada-node's script.
    pub fn script(&self, sc: &Value) {
        let mut m = json!({
            "archive": sc["archive"].as_str().unwrap_or(""),
            "archiveAnswer": sc["archiveAnswer"].clone(),
            "restoreAnswer": sc["restoreAnswer"].clone(),
            "answers": sc["answers"].clone(),
            "readySnapshot": sc["readySnapshot"].as_str().unwrap_or(""),
        });
        if let Some(r) = sc.get("archiveRepeat") {
            m["archive"] = json!(
                r["byte"]
                    .as_str()
                    .unwrap_or("")
                    .repeat(r["n"].as_u64().unwrap_or(0) as usize)
            );
        }
        std::fs::write(self.root.join("script.json"), m.to_string()).unwrap();
    }

    /// The fake armada-node's calls since the last time.
    pub fn node_calls(&self) -> Vec<String> {
        let p = self.root.join("node.log");
        let b = std::fs::read_to_string(&p).unwrap_or_default();
        let _ = std::fs::remove_file(&p);
        let t = b.trim();
        if t.is_empty() {
            return Vec::new();
        }
        t.split('\n').map(str::to_string).collect()
    }

    /// The control plane's input for a side step, and the log endpoint's
    /// answer.
    pub fn set_input(&self, st: &Value) {
        let decode = |k: &str| -> Vec<Value> { st[k].as_array().cloned().unwrap_or_default() };
        *self.srv.exec_in.lock().unwrap() = decode("execIn")
            .into_iter()
            .map(|v| serde_json::from_value(v).unwrap())
            .collect();
        *self.srv.vol_in.lock().unwrap() = decode("volIn")
            .into_iter()
            .map(|v| serde_json::from_value(v).unwrap())
            .collect();
        *self.export.status.lock().unwrap() = st["exportStatus"].as_i64().unwrap_or(0);
    }

    /// Sets the assignment every session gets.
    pub fn set_session(&self, a: pb::Assignment) {
        self.srv.session.lock().unwrap().assignment = Some(a);
    }

    pub fn session(&self) -> Session {
        self.srv.session.lock().unwrap().clone()
    }

    pub fn server_take(&self) -> Vec<String> {
        std::mem::take(&mut *self.srv.log.lock().unwrap())
    }

    pub fn export_take(&self) -> Vec<String> {
        std::mem::take(&mut *self.export.log.lock().unwrap())
    }
}

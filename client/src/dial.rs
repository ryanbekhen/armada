//! Dialing the control plane as Go's clientconfig.Dial does: TLS 1.3 with
//! the user's certificate, the server verified against the config's CA as
//! armada-server, the config's servers tried in order (only the leader
//! answers) and then the machine's, and through `ssh -W` when the config
//! names an SSH host (ADR 0048).

use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::transport::{Channel, Endpoint, Uri};

use crate::config::{self, Config};

/// The name every server certificate carries (pki.ServerName).
pub const SERVER_NAME: &str = "armada-server";

/// How long one address may take to connect (gRPC's MinConnectTimeout).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The program the SSH dialer runs, found through PATH.
const SSH_PROGRAM: &str = "ssh";

trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

/// pki.ClientTLS: TLS 1.3 only, the CA as the only root, the certificate
/// and key, HTTP/2.
pub fn client_tls(ca: &[u8], cert: &[u8], key: &[u8]) -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    let mut any = false;
    for c in CertificateDer::pem_slice_iter(ca).flatten() {
        if roots.add(c).is_ok() {
            any = true;
        }
    }
    if !any {
        return Err("invalid CA certificate".to_string());
    }
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert)
        .filter_map(|c| c.ok())
        .collect();
    if certs.is_empty() {
        return Err("tls: failed to find any PEM data in certificate input".to_string());
    }
    let key = PrivateKeyDer::from_pem_slice(key)
        .map_err(|_| "tls: failed to find any PEM data in key input".to_string())?;
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|_| "tls: private key does not match public key".to_string())?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(cfg)
}

/// A lazy channel to whichever of addrs serves; with ssh, every address is
/// reached through `ssh -W ADDR -- DEST`.
pub fn dial(c: &Config) -> Result<Channel, String> {
    let tls = client_tls(c.ca.as_bytes(), c.cert.as_bytes(), c.key.as_bytes())?;
    let mut addrs = c.servers.clone();
    let ssh = c.ssh.clone();
    if !ssh.is_empty() {
        config::check_ssh(&ssh)?;
    } else {
        // The config's servers first, then the machine's it lacks.
        for a in config::machine_servers() {
            if !addrs.contains(&a) {
                addrs.push(a);
            }
        }
    }
    if addrs.is_empty() {
        return Err("no control plane address".to_string());
    }
    let tls = tokio_rustls::TlsConnector::from(Arc::new(tls));
    let name: ServerName<'static> = ServerName::try_from(SERVER_NAME).expect("a DNS name");
    let ep = Endpoint::from_static("http://control-plane")
        .tcp_nodelay(true)
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(10))
        .keep_alive_while_idle(true);
    let addrs = Arc::new(addrs);
    let connector = tower::service_fn(move |_: Uri| {
        let tls = tls.clone();
        let name = name.clone();
        let addrs = addrs.clone();
        let ssh = ssh.clone();
        async move {
            let mut last = io::Error::other("no control plane address");
            for addr in addrs.iter() {
                // gRPC-go's texts for a connection that failed, which the
                // client prints as they are.
                let dialing = |e: String| {
                    io::Error::other(format!(
                        "connection error: desc = \"transport: Error while dialing: {e}\""
                    ))
                };
                let attempt = async {
                    let stream: Box<dyn Io> = if ssh.is_empty() {
                        let tcp = tokio::net::TcpStream::connect(addr.as_str())
                            .await
                            .map_err(|e| {
                                dialing(format!(
                                    "dial tcp {addr}: connect: {}",
                                    armada_fsutil::errno_text(&e)
                                ))
                            })?;
                        tcp.set_nodelay(true).map_err(|e| dialing(e.to_string()))?;
                        Box::new(tcp)
                    } else {
                        Box::new(dial_ssh(&ssh, addr).map_err(|e| dialing(e.to_string()))?)
                    };
                    let s = tls.connect(name.clone(), stream).await.map_err(|e| {
                        io::Error::other(format!(
                            "connection error: desc = \"transport: authentication handshake failed: {}\"",
                            handshake_error(&e)
                        ))
                    })?;
                    Ok::<_, io::Error>(s)
                };
                match tokio::time::timeout(CONNECT_TIMEOUT, attempt).await {
                    Ok(Ok(s)) => {
                        let b: Box<dyn Io> = Box::new(s);
                        return Ok(hyper_util::rt::TokioIo::new(b));
                    }
                    Ok(Err(e)) => last = e,
                    Err(_) => {
                        last = io::Error::new(
                            io::ErrorKind::TimedOut,
                            "connection error: desc = \"transport: Error while dialing: context deadline exceeded\"",
                        )
                    }
                }
            }
            Err(last)
        }
    });
    Ok(ep.connect_with_connector_lazy(connector))
}

/// The text of a failed TLS handshake: an I/O error as Go's net package
/// words it, or rustls's own.
fn handshake_error(e: &io::Error) -> String {
    if e.raw_os_error().is_some() {
        return armada_fsutil::errno_text(e);
    }
    if e.kind() == io::ErrorKind::UnexpectedEof {
        return "EOF".to_string();
    }
    e.to_string()
}

/// Reaches addr through `ssh -o ExitOnForwardFailure=yes -W ADDR -- DEST`,
/// the user's own ssh with their keys and ~/.ssh/config: mTLS runs inside
/// the channel, so the SSH host only relays bytes.
fn dial_ssh(dest: &str, addr: &str) -> io::Result<SshStream> {
    if addr.starts_with('-') {
        return Err(io::Error::other(format!(
            "control plane address {}",
            armada_spec::go::quote(addr)
        )));
    }
    let (ours, theirs) = StdUnixStream::pair()?;
    let theirs_out: OwnedFd = theirs.try_clone()?.into();
    let theirs_in: OwnedFd = theirs.into();
    let mut child = Command::new(SSH_PROGRAM)
        .args(["-o", "ExitOnForwardFailure=yes", "-W", addr, "--", dest])
        .stdin(Stdio::from(theirs_in))
        .stdout(Stdio::from(theirs_out))
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::other(format!("ssh {dest}: {}", exec_error(&e))))?;
    let stderr = Arc::new(Mutex::new(Vec::new()));
    if let Some(mut pipe) = child.stderr.take() {
        let buf = stderr.clone();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 1024];
            while let Ok(n) = io::Read::read(&mut pipe, &mut chunk) {
                if n == 0 {
                    break;
                }
                let mut b = buf.lock().expect("stderr buffer");
                let room = 4096usize.saturating_sub(b.len());
                b.extend_from_slice(&chunk[..n.min(room)]);
            }
        });
    }
    let exited = Arc::new(AtomicBool::new(false));
    {
        let exited = exited.clone();
        std::thread::spawn(move || {
            let _ = child.wait();
            exited.store(true, Ordering::SeqCst);
        });
    }
    ours.set_nonblocking(true)?;
    let stream = tokio::net::UnixStream::from_std(ours)?;
    Ok(SshStream {
        stream,
        stderr,
        exited,
        dest: dest.to_string(),
        addr: addr.to_string(),
    })
}

/// exec's error for a program that could not start, as Go's os/exec says it.
fn exec_error(e: &io::Error) -> String {
    if e.kind() == io::ErrorKind::NotFound {
        return format!("exec: \"{SSH_PROGRAM}\": executable file not found in $PATH");
    }
    armada_fsutil::errno_text(e)
}

/// A connection over an ssh -W process.
struct SshStream {
    stream: tokio::net::UnixStream,
    stderr: Arc<Mutex<Vec<u8>>>,
    exited: Arc<AtomicBool>,
    dest: String,
    addr: String,
}

impl SshStream {
    /// ssh's last line on stderr, once it exited (or after 100 ms).
    fn why(&self) -> String {
        for _ in 0..10 {
            if self.exited.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let b = self.stderr.lock().expect("stderr buffer");
        let text = String::from_utf8_lossy(&b);
        let text = text.trim();
        text.rsplit('\n').next().unwrap_or("").trim().to_string()
    }
}

impl SshStream {
    /// The error ssh's own message makes of an end or a failure of the
    /// connection, else e.
    fn ssh_error(&self, e: Option<io::Error>) -> Option<io::Error> {
        let msg = self.why();
        if !msg.is_empty() {
            return Some(io::Error::other(format!(
                "ssh {} to {}: {msg}",
                self.dest, self.addr
            )));
        }
        e
    }
}

impl AsyncRead for SshStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.stream).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if buf.filled().len() == before && buf.remaining() > 0 => {
                match self.ssh_error(None) {
                    Some(e) => Poll::Ready(Err(e)),
                    None => Poll::Ready(Ok(())),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(self.ssh_error(Some(e)).expect("an error"))),
            r => r,
        }
    }
}

impl AsyncWrite for SshStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.stream).poll_write(cx, buf) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(self.ssh_error(Some(e)).expect("an error"))),
            r => r,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

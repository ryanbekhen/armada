//! A member's listeners on the network (ADR 0057): the client API and the
//! peer service, each on the server's private address, as etcd's are:
//!
//! - TLS 1.3 only, with ring (rustls).
//! - Client certificates required on both, chaining to the cluster CA
//!   (`ca.crt` in the member's directory, read when the listener starts)
//!   and naming the `etcd:member` identity, the rule etcd's `allowed-cn`
//!   enforces: a user's, a node's, or a server's certificate signed by the
//!   same CA is refused in the handshake.
//! - The member's own certificate and key (`member.crt`, `member.key`) read
//!   on every handshake, so a renewed certificate is served and presented
//!   without a restart.
//! - [`TlsConnector`] reaches other members at their `https://IP:PORT`
//!   peer URLs over the same mutual TLS, checking the peer's certificate
//!   against the CA and its address, and then its `etcd:member` identity.
//!
//! A listener never binds a wildcard address ([`bind`]).

use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::client::ResolvesClientCert;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tonic::body::Body;
use tonic::codegen::http;

use crate::error::{Error, Result};
use crate::node::Node;
use crate::peer::{BoxFuture, BoxIo, Connector, PeerDispatch};
use crate::service::Dispatch;

/// The files of the member's directory the listeners and the connector
/// read (the names armada-store's client reads too).
pub const FILE_CA: &str = "ca.crt";
pub const FILE_CERT: &str = "member.crt";
pub const FILE_KEY: &str = "member.key";

/// The one identity both listeners accept, and a peer must present.
pub const MEMBER_IDENTITY: &str = "etcd:member";

/// How long a connection may take to finish its handshake.
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(10);

/// Handshakes in progress at once per listener; more wait to be accepted.
const MAX_HANDSHAKES: usize = 256;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn tls_error(what: &str, e: impl fmt::Display) -> Error {
    Error::Storage(format!("TLS: {what}: {e}"))
}

/// The cluster CA, the only root.
fn roots(dir: &Path) -> Result<Arc<RootCertStore>> {
    let path = dir.join(FILE_CA);
    let pem = std::fs::read(&path).map_err(|e| tls_error(&path.display().to_string(), e))?;
    let mut roots = RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(&pem) {
        let c = c.map_err(|_| tls_error(FILE_CA, "invalid CA certificate"))?;
        roots
            .add(c)
            .map_err(|_| tls_error(FILE_CA, "invalid CA certificate"))?;
    }
    if roots.is_empty() {
        return Err(tls_error(FILE_CA, "no CA certificate"));
    }
    Ok(Arc::new(roots))
}

/// The member's certificate and key, read from its directory on every
/// handshake, on both sides of a connection.
struct MemberCert {
    dir: PathBuf,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for MemberCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemberCert")
            .field("dir", &self.dir)
            .finish()
    }
}

impl MemberCert {
    fn load(&self) -> std::result::Result<CertifiedKey, String> {
        let cert = std::fs::read(self.dir.join(FILE_CERT)).map_err(|e| e.to_string())?;
        let key = std::fs::read(self.dir.join(FILE_KEY)).map_err(|e| e.to_string())?;
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert)
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| e.to_string())?;
        if certs.is_empty() {
            return Err("no member certificate".to_string());
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

impl ResolvesServerCert for MemberCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.load().ok().map(Arc::new)
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

/// Whether a certificate names the member identity.
fn is_member(der: &CertificateDer<'_>) -> bool {
    armada_pki::Certificate::from_der(der.as_ref()).is_ok_and(|c| c.common_name == MEMBER_IDENTITY)
}

fn not_member() -> rustls::Error {
    rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
}

/// The CA's client verifier, then the identity.
#[derive(Debug)]
struct MemberClients(Arc<dyn ClientCertVerifier>);

impl ClientCertVerifier for MemberClients {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.0.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        let ok = self.0.verify_client_cert(end_entity, intermediates, now)?;
        if !is_member(end_entity) {
            return Err(not_member());
        }
        Ok(ok)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

/// Checks the member's files once, as a listener or connector starts: a
/// broken pair fails now, not at the first handshake.
fn member_cert(dir: &Path, provider: &Arc<CryptoProvider>) -> Result<MemberCert> {
    let c = MemberCert {
        dir: dir.to_path_buf(),
        provider: provider.clone(),
    };
    c.load().map_err(|e| tls_error("member certificate", e))?;
    Ok(c)
}

/// What both listeners serve with: TLS 1.3 only, the member's certificate
/// per handshake, client certificates of the CA with the member identity
/// required, HTTP/2.
pub fn server_config(dir: &Path) -> Result<Arc<rustls::ServerConfig>> {
    let provider = provider();
    let inner = WebPkiClientVerifier::builder_with_provider(roots(dir)?, provider.clone())
        .build()
        .map_err(|e| tls_error("client verifier", e))?;
    let cert = member_cert(dir, &provider)?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| tls_error("server", e))?
        .with_client_cert_verifier(Arc::new(MemberClients(inner)))
        .with_cert_resolver(Arc::new(cert));
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

/// What the connector dials with: TLS 1.3 only, the CA as the only root,
/// the peer's address checked against its certificate, the member's
/// certificate per handshake, HTTP/2. The peer's identity is checked once
/// the handshake is done ([`TlsConnector`]).
pub fn client_config(dir: &Path) -> Result<Arc<rustls::ClientConfig>> {
    let provider = provider();
    let roots = roots(dir)?;
    let cert = member_cert(dir, &provider)?;
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| tls_error("client", e))?
        .with_root_certificates(roots)
        .with_client_cert_resolver(Arc::new(cert));
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

/// The address of an `https://IP:PORT` URL; a name is refused, since the
/// member certificates name addresses only.
pub fn url_addr(url: &str) -> io::Result<SocketAddr> {
    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{url}: not https://IP:PORT"),
        )
    };
    let host = url.strip_prefix("https://").ok_or_else(bad)?;
    let host = host.strip_suffix('/').unwrap_or(host);
    host.parse::<SocketAddr>().map_err(|_| bad())
}

/// Reaches other members at their `https://IP:PORT` peer URLs over mutual
/// TLS with the member's certificate.
#[derive(Clone)]
pub struct TlsConnector {
    tls: tokio_rustls::TlsConnector,
}

impl TlsConnector {
    /// The connector of the member whose files are in dir.
    pub fn new(dir: &Path) -> Result<TlsConnector> {
        Ok(TlsConnector {
            tls: tokio_rustls::TlsConnector::from(client_config(dir)?),
        })
    }
}

impl Connector for TlsConnector {
    fn connect(&self, peer_url: &str) -> BoxFuture<io::Result<BoxIo>> {
        let tls = self.tls.clone();
        let addr = url_addr(peer_url);
        Box::pin(async move {
            let addr = addr?;
            let tcp = TcpStream::connect(addr).await?;
            tcp.set_nodelay(true)?;
            let name = ServerName::IpAddress(addr.ip().into());
            let s = tls.connect(name, tcp).await?;
            // The CA signs every certificate of the cluster: only a
            // member's may answer on a peer URL.
            let member = s
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .is_some_and(is_member);
            if !member {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("{addr}: the peer's certificate is not a member's ({MEMBER_IDENTITY})"),
                ));
            }
            Ok(Box::new(s) as BoxIo)
        })
    }
}

/// A listener on addr, which must name one address: a wildcard
/// (0.0.0.0, ::) is refused, so the store never listens on every
/// interface by mistake.
pub async fn bind(addr: SocketAddr) -> Result<TcpListener> {
    if addr.ip().is_unspecified() {
        return Err(Error::Storage(format!(
            "listen {addr}: a member listens on one private address, never a wildcard"
        )));
    }
    TcpListener::bind(addr)
        .await
        .map_err(|e| Error::Storage(format!("listen {addr}: {e}")))
}

/// A TLS connection a listener accepted, as tonic's server takes it.
pub struct TlsConn {
    s: tokio_rustls::server::TlsStream<TcpStream>,
    peer: Option<SocketAddr>,
}

impl tonic::transport::server::Connected for TlsConn {
    type ConnectInfo = Option<SocketAddr>;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.peer
    }
}

impl AsyncRead for TlsConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.s).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.s).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.s).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.s).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.s).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.s.is_write_vectored()
    }
}

/// Accepts connections on lis and finishes their handshakes (at most
/// [`MAX_HANDSHAKES`] at once, each within [`HANDSHAKE_LIMIT`]); a
/// connection whose handshake fails is closed and never reaches the
/// service.
fn accept_tls(
    lis: TcpListener,
    cfg: Arc<rustls::ServerConfig>,
    tx: mpsc::Sender<io::Result<TlsConn>>,
) -> tokio::task::JoinHandle<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
    let slots = Arc::new(Semaphore::new(MAX_HANDSHAKES));
    tokio::spawn(async move {
        loop {
            let Ok(slot) = slots.clone().acquire_owned().await else {
                return;
            };
            let (tcp, peer) = match lis.accept().await {
                Ok(v) => v,
                Err(_) => {
                    // Out of descriptors and the like: try again shortly.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let _ = tcp.set_nodelay(true);
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let hs = tokio::time::timeout(HANDSHAKE_LIMIT, acceptor.accept(tcp)).await;
                drop(slot);
                if let Ok(Ok(s)) = hs {
                    let _ = tx
                        .send(Ok(TlsConn {
                            s,
                            peer: Some(peer),
                        }))
                        .await;
                }
            });
        }
    })
}

async fn serve_tls_with<S>(
    svc: S,
    lis: TcpListener,
    cfg: Arc<rustls::ServerConfig>,
    shutdown: impl Future<Output = ()>,
) -> Result<()>
where
    S: tower::Service<http::Request<Body>, Response = http::Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    let (tx, rx) = mpsc::channel(16);
    let accept = accept_tls(lis, cfg, tx);
    crate::service::serve_incoming(svc, rx, accept, shutdown).await
}

/// Serves the member's client API (etcd's services) over TLS on lis until
/// shutdown resolves.
pub async fn serve_api_tls(
    node: Node,
    lis: TcpListener,
    cfg: Arc<rustls::ServerConfig>,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    serve_tls_with(Dispatch::new(node), lis, cfg, shutdown).await
}

/// Serves the member's peer service over TLS on lis until shutdown
/// resolves.
pub async fn serve_peer_tls(
    node: Node,
    lis: TcpListener,
    cfg: Arc<rustls::ServerConfig>,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    serve_tls_with(PeerDispatch::new(node), lis, cfg, shutdown).await
}

/// Whether ip may carry a member's listeners: a private, shared-space
/// (100.64.0.0/10), unique-local, or loopback address.
pub fn listen_addr_ok(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let b = v.octets();
            v.is_private() || v.is_loopback() || (b[0] == 100 && b[1] & 0xc0 == 64)
        }
        IpAddr::V6(v) => match v.to_ipv4_mapped() {
            Some(v4) => listen_addr_ok(&IpAddr::V4(v4)),
            None => v.octets()[0] & 0xfe == 0xfc || v.is_loopback(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_urls_name_addresses() {
        assert_eq!(
            url_addr("https://10.0.0.5:7446").unwrap(),
            "10.0.0.5:7446".parse().unwrap()
        );
        assert_eq!(
            url_addr("https://[fd00::5]:7446/").unwrap(),
            "[fd00::5]:7446".parse().unwrap()
        );
        assert!(url_addr("http://10.0.0.5:7446").is_err());
        assert!(url_addr("https://kv.example:7446").is_err());
        assert!(url_addr("unix:///run/kv.sock").is_err());
    }

    #[test]
    fn listen_addresses_are_private() {
        for ok in [
            "10.0.0.5",
            "192.168.1.2",
            "100.64.0.1",
            "127.0.0.1",
            "fd00::1",
        ] {
            assert!(listen_addr_ok(&ok.parse().unwrap()), "{ok}");
        }
        for bad in ["0.0.0.0", "8.8.8.8", "::", "2001:db8::1", "169.254.0.1"] {
            assert!(!listen_addr_ok(&bad.parse().unwrap()), "{bad}");
        }
    }

    #[tokio::test]
    async fn wildcards_are_refused() {
        for a in ["0.0.0.0:0", "[::]:0"] {
            let e = bind(a.parse().unwrap()).await.unwrap_err().to_string();
            assert!(e.contains("never a wildcard"), "{e}");
        }
    }
}

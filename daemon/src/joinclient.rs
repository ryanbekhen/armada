//! A joining machine's side of the join listener (Go's pki.FetchPinnedCA
//! and JoinClientTLS): the cluster CA taken from the chain the listener
//! presents and pinned by its hash, then a connection that trusts only it.
//!
//! Certificate verification is never turned off: the first handshake runs
//! against an empty trust store, so its verifier refuses the chain before
//! any application data is sent; it only keeps the chain it refused, from
//! which the CA is pinned and the server certificate verified.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use armada_pki::{Certificate, SERVER_NAME};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tonic::transport::{Channel, Endpoint, Uri};

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Refuses every chain, keeping the last one it saw.
#[derive(Debug)]
struct Refuse {
    seen: Mutex<Vec<Vec<u8>>>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Refuse {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = vec![end_entity.to_vec()];
        chain.extend(intermediates.iter().map(|c| c.to_vec()));
        *self.seen.lock().unwrap_or_else(|p| p.into_inner()) = chain;
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ))
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// A TCP connection to addr within the deadline.
async fn tcp(addr: &str, deadline: Duration) -> Result<tokio::net::TcpStream, String> {
    match tokio::time::timeout(deadline, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(t)) => Ok(t),
        Ok(Err(e)) => Err(format!(
            "connect to {addr}: dial tcp {addr}: {}",
            io_text(&e)
        )),
        Err(_) => Err(format!("connect to {addr}: dial tcp {addr}: i/o timeout")),
    }
}

fn io_text(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(_) => format!("connect: {}", armada_fsutil::errno_text(e)),
        None => e.to_string(),
    }
}

/// FetchPinnedCA: the cluster CA of the join listener at addr, pinned by
/// ca_hash (hex, from parse_ca_hash).
pub async fn fetch_pinned_ca(addr: &str, ca_hash: &str) -> Result<Certificate, String> {
    let p = provider();
    let refuse = Arc::new(Refuse {
        seen: Mutex::new(Vec::new()),
        algs: p.signature_verification_algorithms,
    });
    let cfg = rustls::ClientConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(refuse.clone())
        .with_no_client_auth();
    let name = ServerName::try_from(SERVER_NAME.to_string()).map_err(|e| e.to_string())?;
    let conn = tcp(addr, Duration::from_secs(60)).await?;
    let res = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(name, conn)
        .await;
    if res.is_ok() {
        return Err("join listener passed verification against an empty trust store".to_string());
    }
    let chain = refuse
        .seen
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    if chain.is_empty() {
        let e = res.err().map(|e| e.to_string()).unwrap_or_default();
        return Err(format!("TLS handshake with {addr}: {e}"));
    }
    let certs: Vec<Certificate> = chain
        .iter()
        .map(|d| Certificate::from_der(d))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("TLS handshake with {addr}: {e}"))?;
    armada_pki::pin_ca(&certs, ca_hash, SystemTime::now()).map_err(|e| e.to_string())
}

/// JoinClientTLS: a channel to the join listener at addr that trusts only
/// ca and requires the server name; no client certificate.
pub fn join_channel(addr: &str, ca: &Certificate) -> Result<Channel, String> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca.raw.clone()))
        .map_err(|e| e.to_string())?;
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let name = ServerName::try_from(SERVER_NAME.to_string()).map_err(|e| e.to_string())?;
    let addr = addr.to_string();
    let connector = tower::service_fn(move |_: Uri| {
        let tls = tls.clone();
        let name = name.clone();
        let addr = addr.clone();
        async move {
            let t = tokio::net::TcpStream::connect(&addr).await?;
            t.set_nodelay(true)?;
            let s = tls.connect(name, t).await?;
            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(s))
        }
    });
    Ok(Endpoint::from_static("http://join")
        .connect_timeout(Duration::from_secs(10))
        .connect_with_connector_lazy(connector))
}

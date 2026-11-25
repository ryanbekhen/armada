//! The node's certificate and key, renewed in place (Go's credentials.go):
//! loaded from the data directory, checked against the cluster's CA and
//! the node's own identity, and presented on every handshake as they are
//! now, so a renewed certificate is used by the next connection.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use armada_pki::{Certificate, ExtKeyUsage, Identity, KIND_NODE, parse_cert_pem};
use armada_proto::armada::v1 as pb;
use rustls::client::ResolvesClientCert;
use rustls::crypto::CryptoProvider;
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::agent::lock;

/// Node credential files in the data directory.
pub const FILE_CA_CERT: &str = "ca.crt";
pub const FILE_NODE_CERT: &str = "node.crt";
pub const FILE_NODE_KEY: &str = "node.key";
const PENDING_EXT: &str = ".new";

/// The node's certificate and key.
pub struct Credentials {
    dir: PathBuf,
    node: String,
    ca_pem: Vec<u8>,
    ca: Certificate,
    provider: Arc<CryptoProvider>,
    cur: Mutex<(Arc<CertifiedKey>, Certificate)>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Credentials(node:{})", self.node)
    }
}

fn read_private(p: &Path) -> Result<Vec<u8>, String> {
    armada_fsutil::read_private_file(p).map_err(|e| e.to_string())
}

/// Moves node.crt.new and node.key.new into place if both exist and match;
/// otherwise discards them.
fn promote_pending(dir: &Path, provider: &Arc<CryptoProvider>) -> Result<(), String> {
    let crt = dir.join(format!("{FILE_NODE_CERT}{PENDING_EXT}"));
    let key = dir.join(format!("{FILE_NODE_KEY}{PENDING_EXT}"));
    let c = armada_fsutil::read_private_file(&crt);
    let k = armada_fsutil::read_private_file(&key);
    let gone = |r: &Result<Vec<u8>, armada_fsutil::Error>| matches!(r, Err(e) if e.kind() == armada_fsutil::ErrorKind::NotFound);
    if gone(&c) && gone(&k) {
        return Ok(());
    }
    if let (Ok(c), Ok(k)) = (&c, &k)
        && key_pair(provider, c, k).is_ok()
    {
        std::fs::rename(&key, dir.join(FILE_NODE_KEY)).map_err(|e| e.to_string())?;
        return std::fs::rename(&crt, dir.join(FILE_NODE_CERT)).map_err(|e| e.to_string());
    }
    let _ = std::fs::remove_file(&crt);
    let _ = std::fs::remove_file(&key);
    Ok(())
}

/// Go's tls.X509KeyPair: the chain and a key that matches its leaf.
fn key_pair(
    provider: &Arc<CryptoProvider>,
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<CertifiedKey, String> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("tls: {e}"))?;
    if certs.is_empty() {
        return Err("tls: failed to find any PEM data in certificate input".into());
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| format!("tls: {e}"))?;
    let key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| format!("tls: {e}"))?;
    let ck = CertifiedKey::new(certs, key);
    ck.keys_match()
        .map_err(|_| "tls: private key does not match public key".to_string())?;
    Ok(ck)
}

impl Credentials {
    /// Reads the node's CA, certificate, and key from dir, completing a
    /// renewal that was interrupted after writing both new files.
    pub fn load(dir: &Path, node: &str) -> Result<Credentials, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        promote_pending(dir, &provider)?;
        let ca_pem = read_private(&dir.join(FILE_CA_CERT))?;
        let ca = parse_cert_pem(&ca_pem).map_err(|_| "invalid CA certificate".to_string())?;
        let cert = read_private(&dir.join(FILE_NODE_CERT))?;
        let key = read_private(&dir.join(FILE_NODE_KEY))?;
        let (ck, leaf) = Self::check(&provider, &ca, node, &cert, &key)?;
        Ok(Credentials {
            dir: dir.to_path_buf(),
            node: node.to_string(),
            ca_pem,
            ca,
            provider,
            cur: Mutex::new((Arc::new(ck), leaf)),
        })
    }

    /// A pair for this node, signed by the CA for client authentication.
    fn check(
        provider: &Arc<CryptoProvider>,
        ca: &Certificate,
        node: &str,
        cert: &[u8],
        key: &[u8],
    ) -> Result<(CertifiedKey, Certificate), String> {
        let ck = key_pair(provider, cert, key)?;
        let leaf = Certificate::from_der(ck.cert[0].as_ref()).map_err(|e| e.to_string())?;
        leaf.verify(ca, None, ExtKeyUsage::ClientAuth, SystemTime::now())
            .map_err(|e| format!("node certificate: {e}"))?;
        let id = leaf.identity().map_err(|e| e.to_string())?;
        if id != Identity::new(KIND_NODE, node) {
            return Err(format!("node certificate is for {id}, not node:{node}"));
        }
        Ok((ck, leaf))
    }

    /// The current certificate.
    pub fn leaf(&self) -> Certificate {
        lock(&self.cur).1.clone()
    }

    /// A client config presenting the current certificate on every
    /// handshake: TLS 1.3, the cluster's CA, HTTP/2.
    pub fn tls_config(self: &Arc<Self>) -> Result<rustls::ClientConfig, String> {
        let mut roots = RootCertStore::empty();
        for c in CertificateDer::pem_slice_iter(&self.ca_pem) {
            let c = c.map_err(|_| "invalid CA certificate".to_string())?;
            roots
                .add(c)
                .map_err(|_| "invalid CA certificate".to_string())?;
        }
        let mut cfg = rustls::ClientConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_client_cert_resolver(Arc::new(Current(self.clone())));
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        Ok(cfg)
    }

    /// Obtains a certificate for a new key and stores both; the new files
    /// go next to the old ones and are renamed into place.
    pub async fn renew(
        &self,
        client: &mut pb::agent_service_client::AgentServiceClient<tonic::transport::Channel>,
    ) -> Result<(), String> {
        let (key_pem, csr) = armada_pki::new_node_csr(&self.node).map_err(|e| e.to_string())?;
        let resp = client
            .renew_certificate(pb::RenewCertificateRequest { csr })
            .await
            .map_err(|e| e.message().to_string())?
            .into_inner();
        let cert_pem = resp.cert;
        // The server must have certified our new key under our identity.
        let (ck, leaf) = Self::check(
            &self.provider,
            &self.ca,
            &self.node,
            &cert_pem,
            key_pem.expose(),
        )
        .map_err(|e| format!("renewed certificate: {e}"))?;
        let crt = self.dir.join(format!("{FILE_NODE_CERT}{PENDING_EXT}"));
        let key = self.dir.join(format!("{FILE_NODE_KEY}{PENDING_EXT}"));
        armada_fsutil::write_file_atomic(&key, key_pem.expose(), 0o600)
            .map_err(|e| e.to_string())?;
        armada_fsutil::write_file_atomic(&crt, &cert_pem, 0o600).map_err(|e| e.to_string())?;
        promote_pending(&self.dir, &self.provider)?;
        *lock(&self.cur) = (Arc::new(ck), leaf);
        Ok(())
    }
}

/// Resolves the client certificate to the credentials' current pair.
#[derive(Debug)]
struct Current(Arc<Credentials>);

impl ResolvesClientCert for Current {
    fn resolve(&self, _hints: &[&[u8]], _schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(lock(&self.0.cur).0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

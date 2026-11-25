//! The server's TLS: Go's pki.ServerCert (a server certificate replaced in
//! place when it is renewed, picked on every handshake), the API's config
//! (TLS 1.3, client certificates of the CA required and verified), and the
//! join listener's (TLS 1.3, no client certificates, the CA sent after the
//! leaf so a joining machine can pin it).

use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use armada_pki::{Certificate, parse_cert_pem, verify_server};
use rustls::RootCertStore;
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

struct Pair {
    api: Arc<CertifiedKey>,
    join: Arc<CertifiedKey>,
    leaf: Arc<Certificate>,
}

/// A server's certificate, replaced in place when it is renewed.
pub struct ServerCert {
    ca: Certificate,
    provider: Arc<CryptoProvider>,
    cur: RwLock<Pair>,
}

impl std::fmt::Debug for ServerCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerCert").finish_non_exhaustive()
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

impl ServerCert {
    /// Loads a server certificate signed by the CA in `ca_pem`.
    pub fn new(ca_pem: &[u8], cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<ServerCert>, String> {
        let ca = parse_cert_pem(ca_pem).map_err(|e| e.to_string())?;
        let provider = provider();
        let pair = load(&ca, &provider, cert_pem, key_pem)?;
        Ok(Arc::new(ServerCert {
            ca,
            provider,
            cur: RwLock::new(pair),
        }))
    }

    /// Installs a new certificate after checking it is a server
    /// certificate of this CA for the server name.
    pub fn set(&self, cert_pem: &[u8], key_pem: &[u8]) -> Result<(), String> {
        let pair = load(&self.ca, &self.provider, cert_pem, key_pem)?;
        *self.cur.write().unwrap_or_else(|p| p.into_inner()) = pair;
        Ok(())
    }

    /// The current certificate.
    pub fn leaf(&self) -> Arc<Certificate> {
        self.cur
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .leaf
            .clone()
    }

    /// The API's config: TLS 1.3, client certificates of the CA required.
    pub fn api_config(self: &Arc<Self>) -> Result<rustls::ServerConfig, String> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.ca.raw.clone()))
            .map_err(|e| e.to_string())?;
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
                .build()
                .map_err(|e| e.to_string())?;
        let mut cfg = rustls::ServerConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| e.to_string())?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(Resolver {
                cert: self.clone(),
                join: false,
            }));
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        Ok(cfg)
    }

    /// The join listener's config, like JoinServerTLS.
    pub fn join_config(self: &Arc<Self>) -> Result<rustls::ServerConfig, String> {
        let mut cfg = rustls::ServerConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Resolver {
                cert: self.clone(),
                join: true,
            }));
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        Ok(cfg)
    }
}

fn load(
    ca: &Certificate,
    provider: &Arc<CryptoProvider>,
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<Pair, String> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|_| "tls: failed to find any PEM data in certificate input".to_string())?;
    let Some(first) = certs.first() else {
        return Err("tls: failed to find any PEM data in certificate input".to_string());
    };
    let key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|_| "tls: failed to find any PEM data in key input".to_string())?;
    let key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| e.to_string())?;
    let leaf = Certificate::from_der(first.as_ref()).map_err(|e| e.to_string())?;
    verify_server(&leaf, ca, SystemTime::now()).map_err(|e| e.to_string())?;
    let api = Arc::new(CertifiedKey::new(certs.clone(), key.clone()));
    let mut chain = certs;
    chain.push(CertificateDer::from(ca.raw.clone()));
    let join = Arc::new(CertifiedKey::new(chain, key));
    Ok(Pair {
        api,
        join,
        leaf: Arc::new(leaf),
    })
}

#[derive(Debug)]
struct Resolver {
    cert: Arc<ServerCert>,
    join: bool,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let cur = self.cert.cur.read().unwrap_or_else(|p| p.into_inner());
        Some(if self.join {
            cur.join.clone()
        } else {
            cur.api.clone()
        })
    }
}

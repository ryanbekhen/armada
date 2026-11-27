//! The cluster's certificate authority.
//!
//! Identities are encoded in the certificate common name as
//! `<kind>:<name>`. Certificates are issued in one fixed form: the
//! subject (organization `armada`, then the identity, each a
//! PrintableString when it can be one, else a UTF8String), the extensions
//! in one order and encoding
//! (key usage, extended key usages, basic constraints, the CA's subject key
//! identifier, the authority key identifier, subject alternative names),
//! P-256 keys in PKCS#8 PEM, random 128-bit serial numbers, NotBefore
//! backdated by [`CLOCK_SKEW`], and fixed lifetimes. The recorded cases
//! (tests/parity.rs) check it against the certificates they hold.

use std::fmt;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime};

use ring::rand::{SecureRandom, SystemRandom};
use x509_parser::prelude::FromDer;

mod cert;
pub mod encoding;
mod identity;
mod join;
mod key;

pub use cert::{
    Certificate, ExtKeyUsage, KEY_USAGE_CERT_SIGN, KEY_USAGE_CRL_SIGN, KEY_USAGE_DIGITAL_SIGNATURE,
    parse_cert_pem, verify_server,
};
pub use identity::{
    Identity, KIND_ADMIN, KIND_AUTOMATION, KIND_ETCD, KIND_METRICS, KIND_NODE, KIND_SERVER,
    KIND_SERVICE, KIND_USER, etcd_member, go_quote, parse_identity, valid_name,
};
pub use join::{
    JoinToken, ca_hash, hash_token_secret, new_join_token, parse_ca_hash, parse_join_token, pin_ca,
    token_secret_matches,
};
pub use key::{PrivateKey, SecretBytes};

use encoding::oid;
use key::P256Public;

/// The DNS name every server certificate carries. Clients verify against
/// it, so the server's address can change without reissuing their config.
pub const SERVER_NAME: &str = "armada-server";

const DAY: u64 = 24 * 60 * 60;
/// The CA's lifetime.
pub const CA_VALIDITY: Duration = Duration::from_secs(10 * 365 * DAY);
/// Server and user certificates.
pub const LEAF_VALIDITY: Duration = Duration::from_secs(365 * DAY);
/// Node certificates; agents renew them ([`needs_renewal`]).
pub const NODE_VALIDITY: Duration = Duration::from_secs(30 * DAY);
/// Service certificates; tools renew them with `armada service renew`.
pub const SERVICE_VALIDITY: Duration = Duration::from_secs(90 * DAY);
/// How far certificates are backdated, so machines whose clocks lag
/// accept them: a certificate was issued at NotBefore + CLOCK_SKEW.
pub const CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);

/// The data directory's CA files.
pub const FILE_CA_CERT: &str = "ca.crt";
pub const FILE_CA_KEY: &str = "ca.key";

/// An error, with the text the recordings hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl Error {
    pub fn new(s: impl Into<String>) -> Self {
        Error(s.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<armada_fsutil::Error> for Error {
    fn from(e: armada_fsutil::Error) -> Self {
        Error(e.to_string())
    }
}

/// The cluster certificate authority. `Debug` leaves the key out.
pub struct Ca {
    pub cert: Certificate,
    pub cert_pem: Vec<u8>,
    key: PrivateKey,
}

impl fmt::Debug for Ca {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ca")
            .field("subject", &self.cert.common_name)
            .field("fingerprint", &self.cert.fingerprint())
            .finish_non_exhaustive()
    }
}

/// A leaf certificate to issue with a new key.
#[derive(Debug, Clone, Default)]
pub struct IssueRequest {
    pub identity: Identity,
    pub dns_names: Vec<String>,
    pub ips: Vec<IpAddr>,
    /// Server authentication usage.
    pub server: bool,
    /// Client authentication usage.
    pub client: bool,
    /// Zero means [`LEAF_VALIDITY`].
    pub validity: Duration,
}

/// A certificate issued from a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCert {
    pub pem: Vec<u8>,
    /// The serial number as lowercase hex.
    pub serial: String,
    /// The start of validity (backdated by the clock skew allowance), as
    /// encoded: whole seconds, Unix.
    pub not_before: i64,
    /// The end of validity, Unix seconds.
    pub not_after: i64,
}

/// The fields of one certificate to sign.
struct Template<'a> {
    common_name: &'a str,
    not_before: i64,
    not_after: i64,
    key_usage: u16,
    ext_key_usage: &'a [ExtKeyUsage],
    is_ca: bool,
    subject_key_id: Option<Vec<u8>>,
    authority_key_id: Option<Vec<u8>>,
    dns_names: &'a [String],
    ips: &'a [IpAddr],
}

impl Ca {
    /// A new self-signed CA for `cluster_name`.
    pub fn new(cluster_name: &str) -> Result<Self, Error> {
        let key = PrivateKey::generate()?;
        let now = cert::unix(SystemTime::now()).0;
        let cn = format!("armada-ca:{cluster_name}");
        // The subject key identifier of a CA: the leftmost 160 bits of the
        // SHA-256 of the public key (RFC 7093).
        let ski =
            ring::digest::digest(&ring::digest::SHA256, key.public_key()).as_ref()[..20].to_vec();
        let t = Template {
            common_name: &cn,
            not_before: now - CLOCK_SKEW.as_secs() as i64,
            not_after: now + CA_VALIDITY.as_secs() as i64,
            key_usage: KEY_USAGE_CERT_SIGN | KEY_USAGE_CRL_SIGN,
            ext_key_usage: &[],
            is_ca: true,
            subject_key_id: Some(ski),
            authority_key_id: None,
            dns_names: &[],
            ips: &[],
        };
        let signer = key.rcgen()?;
        let params = t.params()?;
        let der = params
            .self_signed(&signer)
            .map_err(|e| Error::new(format!("x509: {e}")))?
            .der()
            .to_vec();
        let cert = Certificate::from_der(&der)?;
        Ok(Ca {
            cert_pem: encoding::pem_encode("CERTIFICATE", &der),
            cert,
            key,
        })
    }

    /// Parses a CA certificate and its private key.
    pub fn load(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, Error> {
        let cert = parse_cert_pem(cert_pem)?;
        if !cert.is_ca {
            return Err(Error::new("certificate is not a CA"));
        }
        let key = PrivateKey::from_pem(key_pem)?;
        if !cert.public_key_p256 || key.public_key() != cert.public_key.as_slice() {
            return Err(Error::new("CA key does not match certificate"));
        }
        Ok(Ca {
            cert,
            cert_pem: cert_pem.to_vec(),
            key,
        })
    }

    /// Reads `ca.crt` and `ca.key` from a data directory, refusing files
    /// group or others may read.
    pub fn load_dir(data_dir: &Path) -> Result<Self, Error> {
        let cert = armada_fsutil::read_private_file(&data_dir.join(FILE_CA_CERT))?;
        let key = SecretBytes::new(armada_fsutil::read_private_file(
            &data_dir.join(FILE_CA_KEY),
        )?);
        Self::load(&cert, key.expose())
    }

    /// Writes `ca.crt` and `ca.key` into a data directory (0600 each, as
    /// `armadad init` and `server join` write them).
    pub fn write_dir(&self, data_dir: &Path) -> Result<(), Error> {
        armada_fsutil::write_file_atomic(&data_dir.join(FILE_CA_CERT), &self.cert_pem, 0o600)?;
        armada_fsutil::write_file_atomic(
            &data_dir.join(FILE_CA_KEY),
            self.key_pem().expose(),
            0o600,
        )?;
        Ok(())
    }

    /// The CA's private key in PEM form. Callers store it with mode 0600.
    pub fn key_pem(&self) -> SecretBytes {
        self.key.to_pem()
    }

    /// Creates a new key pair and a certificate signed by the CA.
    pub fn issue(&self, req: &IssueRequest) -> Result<(Vec<u8>, SecretBytes), Error> {
        parse_identity(&req.identity.to_string())?;
        if !req.server && !req.client {
            return Err(Error::new("certificate needs server or client usage"));
        }
        let key = PrivateKey::generate()?;
        let validity = if req.validity.is_zero() {
            LEAF_VALIDITY
        } else {
            req.validity
        };
        let mut usage = Vec::new();
        if req.server {
            usage.push(ExtKeyUsage::ServerAuth);
        }
        if req.client {
            usage.push(ExtKeyUsage::ClientAuth);
        }
        let cn = req.identity.to_string();
        let (not_before, not_after) = self.period(validity);
        let der = self.sign(
            &Template {
                common_name: &cn,
                not_before,
                not_after,
                key_usage: KEY_USAGE_DIGITAL_SIGNATURE,
                ext_key_usage: &usage,
                is_ca: false,
                subject_key_id: None,
                authority_key_id: None,
                dns_names: &req.dns_names,
                ips: &req.ips,
            },
            key.public_key(),
        )?;
        Ok((encoding::pem_encode("CERTIFICATE", &der), key.to_pem()))
    }

    /// Signs a new certificate for the key, identity, names, and usages of
    /// `old`, which this CA must have signed, valid for `validity` from now
    /// (zero means [`LEAF_VALIDITY`]). Only the serial and the validity
    /// period change, so the private key on disk stays as it is.
    pub fn reissue(&self, old: &Certificate, validity: Duration) -> Result<Vec<u8>, Error> {
        old.check_signature_from(&self.cert)
            .map_err(|e| Error::new(format!("certificate is not signed by this CA: {e}")))?;
        parse_identity(&old.common_name)?;
        if old.ext_key_usage.is_empty() {
            return Err(Error::new("certificate has no extended key usage"));
        }
        if !old.public_key_p256 {
            return Err(Error::new("certificate key must be ECDSA P-256"));
        }
        let validity = if validity.is_zero() {
            LEAF_VALIDITY
        } else {
            validity
        };
        let (not_before, not_after) = self.period(validity);
        let der = self.sign(
            &Template {
                common_name: &old.common_name,
                not_before,
                not_after,
                key_usage: KEY_USAGE_DIGITAL_SIGNATURE,
                ext_key_usage: &old.ext_key_usage,
                is_ca: false,
                subject_key_id: None,
                authority_key_id: None,
                dns_names: &old.dns_names,
                ips: &old.ip_addresses,
            },
            &old.public_key,
        )?;
        Ok(encoding::pem_encode("CERTIFICATE", &der))
    }

    /// Issues a client certificate for `node` from a CSR. Only the CSR's public key is used: the identity,
    /// usages, and lifetime come from the CA, so a node cannot ask for
    /// another name, a server certificate, or extra extensions. The key
    /// must be ECDSA P-256 and the CSR self-signed. A zero `validity`, or
    /// one past [`NODE_VALIDITY`], is NODE_VALIDITY.
    pub fn sign_node_csr(
        &self,
        csr_der: &[u8],
        node: &str,
        validity: Duration,
    ) -> Result<NodeCert, Error> {
        let validity = if validity.is_zero() || validity > NODE_VALIDITY {
            NODE_VALIDITY
        } else {
            validity
        };
        self.sign_client_csr(csr_der, &Identity::new(KIND_NODE, node), validity)
    }

    /// A user's client certificate (ADR 0033) from a CSR, for
    /// [`LEAF_VALIDITY`].
    pub fn sign_user_csr(&self, csr_der: &[u8], name: &str) -> Result<NodeCert, Error> {
        self.sign_client_csr(csr_der, &Identity::new(KIND_USER, name), LEAF_VALIDITY)
    }

    /// A service's client certificate (ADR 0033) from a CSR, for
    /// [`SERVICE_VALIDITY`].
    pub fn sign_service_csr(&self, csr_der: &[u8], name: &str) -> Result<NodeCert, Error> {
        self.sign_client_csr(
            csr_der,
            &Identity::new(KIND_SERVICE, name),
            SERVICE_VALIDITY,
        )
    }

    /// A metrics scraper's client certificate (ADR 0017) from a CSR, for
    /// [`LEAF_VALIDITY`].
    pub fn sign_metrics_csr(&self, csr_der: &[u8], name: &str) -> Result<NodeCert, Error> {
        self.sign_client_csr(csr_der, &Identity::new(KIND_METRICS, name), LEAF_VALIDITY)
    }

    fn sign_client_csr(
        &self,
        csr_der: &[u8],
        id: &Identity,
        validity: Duration,
    ) -> Result<NodeCert, Error> {
        parse_identity(&id.to_string())?;
        let public = csr_public_key(csr_der)?;
        let cn = id.to_string();
        let (not_before, not_after) = self.period(validity);
        let der = self.sign(
            &Template {
                common_name: &cn,
                not_before,
                not_after,
                key_usage: KEY_USAGE_DIGITAL_SIGNATURE,
                ext_key_usage: &[ExtKeyUsage::ClientAuth],
                is_ca: false,
                subject_key_id: None,
                authority_key_id: None,
                dns_names: &[],
                ips: &[],
            },
            &public,
        )?;
        let cert = Certificate::from_der(&der)?;
        Ok(NodeCert {
            pem: encoding::pem_encode("CERTIFICATE", &der),
            serial: cert.serial_string(),
            not_before: cert.not_before,
            not_after: cert.not_after,
        })
    }

    /// NotBefore and NotAfter of a certificate issued now for `validity`,
    /// capped at the CA's own NotAfter.
    fn period(&self, validity: Duration) -> (i64, i64) {
        let now = cert::unix(SystemTime::now()).0;
        let not_after = (now + validity.as_secs() as i64).min(self.cert.not_after);
        (now - CLOCK_SKEW.as_secs() as i64, not_after)
    }

    fn sign(&self, t: &Template<'_>, public: &[u8]) -> Result<Vec<u8>, Error> {
        // The CA's subject key identifier is the authority key identifier
        // of every certificate it signs.
        let t = Template {
            common_name: t.common_name,
            not_before: t.not_before,
            not_after: t.not_after,
            key_usage: t.key_usage,
            ext_key_usage: t.ext_key_usage,
            is_ca: false,
            subject_key_id: None,
            authority_key_id: (!self.cert.subject_key_id.is_empty())
                .then(|| self.cert.subject_key_id.clone()),
            dns_names: t.dns_names,
            ips: t.ips,
        };
        let params = t.params()?;
        let signer = self.key.rcgen()?;
        let issuer = rcgen::Issuer::from_ca_cert_der(&self.cert.raw.as_slice().into(), &signer)
            .map_err(|e| Error::new(format!("x509: {e}")))?;
        let der = params
            .signed_by(&P256Public(public.to_vec()), &issuer)
            .map_err(|e| Error::new(format!("x509: {e}")))?
            .der()
            .to_vec();
        // The issuer must be the CA's subject bytes as they are;
        // rcgen writes it again from its parts, which must give the same
        // bytes, or chains would not build.
        let issued = Certificate::from_der(&der)?;
        if issued.raw_issuer != self.cert.raw_subject {
            return Err(Error::new(
                "x509: the issuer name does not encode as the CA's subject",
            ));
        }
        issued.check_signature_from(&self.cert)?;
        Ok(der)
    }
}

impl Template<'_> {
    fn params(&self) -> Result<rcgen::CertificateParams, Error> {
        let mut p = rcgen::CertificateParams::default();
        let mut serial = [0u8; 16];
        SystemRandom::new()
            .fill(&mut serial)
            .map_err(|_| Error::new("crypto/rand: read failed"))?;
        p.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
        p.not_before = time::OffsetDateTime::from_unix_timestamp(self.not_before)
            .map_err(|e| Error::new(format!("x509: {e}")))?;
        p.not_after = time::OffsetDateTime::from_unix_timestamp(self.not_after)
            .map_err(|e| Error::new(format!("x509: {e}")))?;
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::OrganizationName, subject_string("armada")?);
        dn.push(rcgen::DnType::CommonName, subject_string(self.common_name)?);
        p.distinguished_name = dn;
        p.is_ca = rcgen::IsCa::NoCa;
        p.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(Vec::new());
        p.custom_extensions = self.extensions();
        Ok(p)
    }

    /// The extensions, in this order: key usage,
    /// extended key usage, basic constraints, subject key identifier,
    /// authority key identifier, subject alternative names.
    fn extensions(&self) -> Vec<rcgen::CustomExtension> {
        let ext = |arc: u64, critical: bool, value: Vec<u8>| {
            let mut e = rcgen::CustomExtension::from_oid_content(&[2, 5, 29, arc], value);
            e.set_criticality(critical);
            e
        };
        let mut out = Vec::new();
        if self.key_usage != 0 {
            out.push(ext(oid::KEY_USAGE, true, key_usage_value(self.key_usage)));
        }
        if !self.ext_key_usage.is_empty() {
            let oids: Vec<Vec<u8>> = self
                .ext_key_usage
                .iter()
                .map(|u| encoding::tlv(0x06, &u.oid()))
                .collect();
            out.push(ext(oid::EXT_KEY_USAGE, false, encoding::seq(&oids)));
        }
        // basicConstraints: cA only when true, pathLenConstraint 0
        // for the CA (MaxPathLenZero).
        let bc = if self.is_ca {
            encoding::seq(&[vec![0x01, 0x01, 0xff], vec![0x02, 0x01, 0x00]])
        } else {
            encoding::seq(&[])
        };
        out.push(ext(oid::BASIC_CONSTRAINTS, true, bc));
        if let Some(ski) = &self.subject_key_id {
            out.push(ext(oid::SUBJECT_KEY_ID, false, encoding::tlv(0x04, ski)));
        }
        if let Some(aki) = &self.authority_key_id {
            out.push(ext(
                oid::AUTHORITY_KEY_ID,
                false,
                encoding::seq(&[encoding::tlv(0x80, aki)]),
            ));
        }
        if !self.dns_names.is_empty() || !self.ips.is_empty() {
            let mut names: Vec<Vec<u8>> = self
                .dns_names
                .iter()
                .map(|n| encoding::tlv(0x82, n.as_bytes()))
                .collect();
            for ip in self.ips {
                let b = match ip {
                    IpAddr::V4(v4) => v4.octets().to_vec(),
                    // An IPv4-mapped address is written in its four bytes.
                    IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                        Some(v4) => v4.octets().to_vec(),
                        None => v6.octets().to_vec(),
                    },
                };
                names.push(encoding::tlv(0x87, &b));
            }
            out.push(ext(oid::SUBJECT_ALT_NAME, false, encoding::seq(&names)));
        }
        out
    }
}

/// The key usage encoding: bit i of the usage at bit i of the BIT STRING,
/// one or two bytes, the bit length up to the last bit set.
fn key_usage_value(ku: u16) -> Vec<u8> {
    let mut a = [0u8; 2];
    for i in 0..9 {
        if (ku >> i) & 1 == 1 {
            a[i / 8] |= 0x80 >> (i % 8);
        }
    }
    let bytes = if a[1] != 0 { &a[..] } else { &a[..1] };
    let last = bytes[bytes.len() - 1];
    let unused = if last == 0 {
        0
    } else {
        last.trailing_zeros() as u8
    };
    let mut content = vec![unused];
    content.extend_from_slice(bytes);
    encoding::tlv(0x03, &content)
}

/// A subject string with its ASN.1 type: a
/// PrintableString when every byte may be one, else a UTF8String.
fn subject_string(s: &str) -> Result<rcgen::DnValue, Error> {
    let printable = s.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b' ' | b'\'' | b'(' | b')' | b'+' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?'
            )
    });
    if printable {
        let p = rcgen::string::PrintableString::try_from(s)
            .map_err(|e| Error::new(format!("x509: {e}")))?;
        Ok(rcgen::DnValue::PrintableString(p))
    } else {
        Ok(rcgen::DnValue::Utf8String(s.to_string()))
    }
}

/// Parses a CSR, checks its signature, and returns its P-256 public point,
/// with the `parse CSR:` texts of the recordings.
fn csr_public_key(csr_der: &[u8]) -> Result<Vec<u8>, Error> {
    let (rest, csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(csr_der)
            .map_err(|e| Error::new(format!("parse CSR: {e}")))?;
    if !rest.is_empty() {
        return Err(Error::new("parse CSR: x509: trailing data"));
    }
    csr.verify_signature().map_err(|e| {
        let alg = &csr
            .certification_request_info
            .subject_pki
            .algorithm
            .algorithm;
        Error::new(match e {
            x509_parser::error::X509Error::SignatureVerificationError
                if alg.as_bytes() == oid::EC_PUBLIC_KEY =>
            {
                "CSR signature: x509: ECDSA verification failure".to_string()
            }
            x509_parser::error::X509Error::SignatureVerificationError => {
                "CSR signature: crypto/rsa: verification error".to_string()
            }
            e => format!("CSR signature: x509: {e}"),
        })
    })?;
    let spki = &csr.certification_request_info.subject_pki;
    let point = spki.subject_public_key.data.to_vec();
    let p256 = spki.algorithm.algorithm.as_bytes() == oid::EC_PUBLIC_KEY
        && spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .is_some_and(|o| o.as_bytes() == oid::P256)
        && point.len() == 65
        && point[0] == 4;
    if !p256 {
        return Err(Error::new("CSR key must be ECDSA P-256"));
    }
    Ok(point)
}

/// A node key and a certificate request for it. The
/// key never leaves the node.
pub fn new_node_csr(node: &str) -> Result<(SecretBytes, Vec<u8>), Error> {
    new_csr(&Identity::new(KIND_NODE, node))
}

/// A key and a certificate request for `id`: the common
/// name only, signed with the key. The CA decides the identity it signs
/// anyway.
pub fn new_csr(id: &Identity) -> Result<(SecretBytes, Vec<u8>), Error> {
    parse_identity(&id.to_string())?;
    let key = PrivateKey::generate()?;
    let mut p = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, subject_string(&id.to_string())?);
    p.distinguished_name = dn;
    let csr = p
        .serialize_request(&key.rcgen()?)
        .map_err(|e| Error::new(format!("x509: {e}")))?;
    Ok((key.to_pem(), csr.der().to_vec()))
}

/// Whether a certificate that renews itself should be renewed now: once
/// less than a third of its lifetime is left.
pub fn renew_due(c: &Certificate, now: SystemTime) -> bool {
    let life = nanos(c.not_after - c.not_before) - nanos_d(CLOCK_SKEW);
    left(c, now) < life / 3
}

/// Whether a node certificate should be renewed: in the last third of its
/// lifetime, or if it outlives [`NODE_VALIDITY`] (issued before node
/// certificates became short-lived).
pub fn needs_renewal(c: &Certificate, now: SystemTime) -> bool {
    let life = nanos(c.not_after - c.not_before) - nanos_d(CLOCK_SKEW);
    life > nanos_d(NODE_VALIDITY) + nanos_d(CLOCK_SKEW) || left(c, now) < life / 3
}

fn nanos(secs: i64) -> i128 {
    i128::from(secs) * 1_000_000_000
}

fn nanos_d(d: Duration) -> i128 {
    d.as_nanos() as i128
}

fn left(c: &Certificate, now: SystemTime) -> i128 {
    let (s, n) = cert::unix(now);
    nanos(c.not_after) - (nanos(s) + i128::from(n))
}

#[cfg(test)]
mod tests;

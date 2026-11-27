//! Reading certificates (x509-parser), checking their signatures (ring
//! through x509-parser), and the verification rules of the one-CA chains
//! Armada builds, with the `x509:` error texts the recordings hold.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use x509_parser::prelude::*;

use crate::encoding::{self, oid};
use crate::identity::{self, Identity};
use crate::{Error, SERVER_NAME};

/// An extended key usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtKeyUsage {
    Any,
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    IpsecEndSystem,
    IpsecTunnel,
    IpsecUser,
    TimeStamping,
    OcspSigning,
    MicrosoftServerGatedCrypto,
    NetscapeServerGatedCrypto,
    MicrosoftCommercialCodeSigning,
    MicrosoftKernelCodeSigning,
}

impl ExtKeyUsage {
    /// The encoded object identifier.
    pub fn oid(self) -> Vec<u8> {
        let pkix = |n: u8| {
            let mut v = oid::EKU_PREFIX.to_vec();
            v.push(n);
            v
        };
        match self {
            ExtKeyUsage::Any => oid::EKU_ANY.to_vec(),
            ExtKeyUsage::ServerAuth => pkix(1),
            ExtKeyUsage::ClientAuth => pkix(2),
            ExtKeyUsage::CodeSigning => pkix(3),
            ExtKeyUsage::EmailProtection => pkix(4),
            ExtKeyUsage::IpsecEndSystem => pkix(5),
            ExtKeyUsage::IpsecTunnel => pkix(6),
            ExtKeyUsage::IpsecUser => pkix(7),
            ExtKeyUsage::TimeStamping => pkix(8),
            ExtKeyUsage::OcspSigning => pkix(9),
            ExtKeyUsage::MicrosoftServerGatedCrypto => oid::EKU_MS_SGC.to_vec(),
            ExtKeyUsage::NetscapeServerGatedCrypto => oid::EKU_NS_SGC.to_vec(),
            ExtKeyUsage::MicrosoftCommercialCodeSigning => oid::EKU_MS_COMMERCIAL.to_vec(),
            ExtKeyUsage::MicrosoftKernelCodeSigning => oid::EKU_MS_KERNEL.to_vec(),
        }
    }

    fn from_oid(b: &[u8]) -> Option<Self> {
        const ALL: [ExtKeyUsage; 14] = [
            ExtKeyUsage::Any,
            ExtKeyUsage::ServerAuth,
            ExtKeyUsage::ClientAuth,
            ExtKeyUsage::CodeSigning,
            ExtKeyUsage::EmailProtection,
            ExtKeyUsage::IpsecEndSystem,
            ExtKeyUsage::IpsecTunnel,
            ExtKeyUsage::IpsecUser,
            ExtKeyUsage::TimeStamping,
            ExtKeyUsage::OcspSigning,
            ExtKeyUsage::MicrosoftServerGatedCrypto,
            ExtKeyUsage::NetscapeServerGatedCrypto,
            ExtKeyUsage::MicrosoftCommercialCodeSigning,
            ExtKeyUsage::MicrosoftKernelCodeSigning,
        ];
        ALL.into_iter().find(|u| u.oid() == b)
    }
}

/// Key usage bits (bit i is the i-th named bit of RFC 5280's KeyUsage).
pub const KEY_USAGE_DIGITAL_SIGNATURE: u16 = 1;
pub const KEY_USAGE_CERT_SIGN: u16 = 1 << 5;
pub const KEY_USAGE_CRL_SIGN: u16 = 1 << 6;

/// A parsed certificate, with the fields Armada's code reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// The DER bytes.
    pub raw: Vec<u8>,
    pub raw_subject: Vec<u8>,
    pub raw_issuer: Vec<u8>,
    /// The subject's last common name ("" without one).
    pub common_name: String,
    /// The subject's organizations.
    pub organization: Vec<String>,
    /// The serial number's magnitude, big-endian, no leading zeros.
    pub serial: Vec<u8>,
    pub serial_negative: bool,
    pub version: u32,
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    pub basic_constraints_valid: bool,
    pub is_ca: bool,
    /// -1 when absent.
    pub max_path_len: i64,
    pub key_usage: u16,
    /// Known extended key usages in the certificate's order.
    pub ext_key_usage: Vec<ExtKeyUsage>,
    /// Usages not in [`ExtKeyUsage`], as encoded object identifiers.
    pub unknown_ext_key_usage: Vec<Vec<u8>>,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<IpAddr>,
    /// Whether the certificate has a subject alternative name extension.
    pub has_san: bool,
    pub subject_key_id: Vec<u8>,
    pub authority_key_id: Vec<u8>,
    /// The subject public key's BIT STRING contents (a P-256 point for
    /// every key Armada makes).
    pub public_key: Vec<u8>,
    /// Whether the key is ECDSA, and on P-256.
    pub public_key_ecdsa: bool,
    pub public_key_p256: bool,
}

impl Certificate {
    /// Parses a DER certificate. Data after it is refused.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let (rest, c) = X509Certificate::from_der(der)
            .map_err(|e| Error::new(format!("x509: malformed certificate: {e}")))?;
        if !rest.is_empty() {
            return Err(Error::new("x509: trailing data"));
        }
        let raw = der[..der.len() - rest.len()].to_vec();
        let tbs = &c.tbs_certificate;
        let common_name = tbs
            .subject
            .iter_common_name()
            .last()
            .and_then(|a| a.as_str().ok())
            .unwrap_or_default()
            .to_string();
        let organization = tbs
            .subject
            .iter_organization()
            .filter_map(|a| a.as_str().ok().map(str::to_string))
            .collect();
        let serial: Vec<u8> = {
            let s = tbs.raw_serial();
            let mut s = s;
            while s.len() > 1 && s[0] == 0 {
                s = &s[1..];
            }
            s.to_vec()
        };
        let serial_negative = tbs.raw_serial().first().is_some_and(|b| b & 0x80 != 0);
        let mut cert = Certificate {
            raw,
            raw_subject: tbs.subject.as_raw().to_vec(),
            raw_issuer: tbs.issuer.as_raw().to_vec(),
            common_name,
            organization,
            serial,
            serial_negative,
            version: tbs.version.0 + 1,
            not_before: tbs.validity.not_before.timestamp(),
            not_after: tbs.validity.not_after.timestamp(),
            basic_constraints_valid: false,
            is_ca: false,
            max_path_len: -1,
            key_usage: 0,
            ext_key_usage: Vec::new(),
            unknown_ext_key_usage: Vec::new(),
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            has_san: false,
            subject_key_id: Vec::new(),
            authority_key_id: Vec::new(),
            public_key: tbs.subject_pki.subject_public_key.data.to_vec(),
            public_key_ecdsa: false,
            public_key_p256: false,
        };
        let alg = &tbs.subject_pki.algorithm;
        if alg.algorithm.as_bytes() == oid::EC_PUBLIC_KEY {
            cert.public_key_ecdsa = true;
            cert.public_key_p256 = alg
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .is_some_and(|o| o.as_bytes() == oid::P256)
                && cert.public_key.len() == 65
                && cert.public_key[0] == 4;
        }
        for ext in tbs.extensions() {
            let arcs: Vec<u64> = match ext.oid.iter() {
                Some(a) => a.collect(),
                None => continue,
            };
            if arcs.len() != 4 || arcs[..3] != [2, 5, 29] {
                continue;
            }
            match arcs[3] {
                oid::BASIC_CONSTRAINTS => {
                    if let ParsedExtension::BasicConstraints(bc) = ext.parsed_extension() {
                        cert.basic_constraints_valid = true;
                        cert.is_ca = bc.ca;
                        cert.max_path_len = bc.path_len_constraint.map_or(-1, i64::from);
                    }
                }
                oid::KEY_USAGE => {
                    if let ParsedExtension::KeyUsage(ku) = ext.parsed_extension() {
                        cert.key_usage = ku.flags;
                    }
                }
                oid::EXT_KEY_USAGE => {
                    // Read by hand to keep the certificate's order.
                    let Some((0x30, mut body, _)) = encoding::read_tlv(ext.value) else {
                        return Err(Error::new("x509: invalid extended key usages"));
                    };
                    while !body.is_empty() {
                        let Some((0x06, o, rest)) = encoding::read_tlv(body) else {
                            return Err(Error::new("x509: invalid extended key usages"));
                        };
                        match ExtKeyUsage::from_oid(o) {
                            Some(u) => cert.ext_key_usage.push(u),
                            None => cert.unknown_ext_key_usage.push(o.to_vec()),
                        }
                        body = rest;
                    }
                }
                oid::SUBJECT_ALT_NAME => {
                    cert.has_san = true;
                    if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                        for n in &san.general_names {
                            match n {
                                GeneralName::DNSName(s) => cert.dns_names.push(s.to_string()),
                                GeneralName::IPAddress(b) => match b.len() {
                                    4 => cert.ip_addresses.push(IpAddr::from(
                                        <[u8; 4]>::try_from(*b).expect("four bytes"),
                                    )),
                                    16 => cert.ip_addresses.push(IpAddr::from(
                                        <[u8; 16]>::try_from(*b).expect("sixteen bytes"),
                                    )),
                                    n => {
                                        return Err(Error::new(format!(
                                            "x509: cannot parse IP address of length {n}"
                                        )));
                                    }
                                },
                                _ => {}
                            }
                        }
                    }
                }
                oid::SUBJECT_KEY_ID => {
                    if let ParsedExtension::SubjectKeyIdentifier(k) = ext.parsed_extension() {
                        cert.subject_key_id = k.0.to_vec();
                    }
                }
                oid::AUTHORITY_KEY_ID => {
                    if let ParsedExtension::AuthorityKeyIdentifier(k) = ext.parsed_extension()
                        && let Some(id) = &k.key_identifier
                    {
                        cert.authority_key_id = id.0.to_vec();
                    }
                }
                _ => {}
            }
        }
        Ok(cert)
    }

    /// The identity in the common name.
    pub fn identity(&self) -> Result<Identity, Error> {
        identity::parse_identity(&self.common_name)
    }

    /// The hex SHA-256 of the DER bytes.
    pub fn fingerprint(&self) -> String {
        encoding::hex(ring::digest::digest(&ring::digest::SHA256, &self.raw).as_ref())
    }

    /// The serial number as lowercase hex, no leading zeros.
    pub fn serial_string(&self) -> String {
        let h = encoding::hex(&self.serial);
        let t = h.trim_start_matches('0');
        let t = if t.is_empty() { "0" } else { t };
        if self.serial_negative {
            format!("-{t}")
        } else {
            t.to_string()
        }
    }

    /// Checks that `parent` signed this certificate: the parent must be a
    /// CA allowed to sign certificates, and the signature must verify.
    pub fn check_signature_from(&self, parent: &Certificate) -> Result<(), Error> {
        if (parent.version == 3 && !parent.basic_constraints_valid)
            || (parent.basic_constraints_valid && !parent.is_ca)
            || (parent.key_usage != 0 && parent.key_usage & KEY_USAGE_CERT_SIGN == 0)
        {
            return Err(Error::new(
                "x509: invalid signature: parent certificate cannot sign this kind of certificate",
            ));
        }
        let (_, c) = X509Certificate::from_der(&self.raw)
            .map_err(|e| Error::new(format!("x509: malformed certificate: {e}")))?;
        let (_, p) = X509Certificate::from_der(&parent.raw)
            .map_err(|e| Error::new(format!("x509: malformed certificate: {e}")))?;
        c.verify_signature(Some(p.public_key())).map_err(|_| {
            Error::new(if parent.public_key_ecdsa {
                "x509: ECDSA verification failure"
            } else {
                "x509: signature verification failure"
            })
        })
    }

    /// Verifies a chain of this certificate and `root` for a DNS name and
    /// key usages, at `now`. Checks run in a fixed order, so the first
    /// failure always gives the same text.
    pub fn verify(
        &self,
        root: &Certificate,
        dns_name: Option<&str>,
        usage: ExtKeyUsage,
        now: SystemTime,
    ) -> Result<(), Error> {
        self.check_time(now)?;
        if let Some(host) = dns_name {
            self.verify_hostname(host)?;
        }
        let unknown = "x509: certificate signed by unknown authority";
        if self.raw_issuer != root.raw_subject {
            return Err(Error::new(unknown));
        }
        if let Err(e) = self.check_signature_from(root) {
            let name = if !root.common_name.is_empty() {
                root.common_name.clone()
            } else if let Some(o) = root.organization.first() {
                o.clone()
            } else {
                format!("serial:{}", root.serial_decimal())
            };
            return Err(Error::new(format!(
                "{unknown} (possibly because of {} while trying to verify candidate authority certificate {})",
                identity::go_quote(&e.to_string()),
                identity::go_quote(&name)
            )));
        }
        root.check_time(now)?;
        for c in [root, self] {
            if c.ext_key_usage.is_empty() && c.unknown_ext_key_usage.is_empty() {
                continue;
            }
            if c.ext_key_usage.contains(&ExtKeyUsage::Any) || usage == ExtKeyUsage::Any {
                continue;
            }
            let ok = c.ext_key_usage.contains(&usage)
                || (usage == ExtKeyUsage::ServerAuth
                    && (c
                        .ext_key_usage
                        .contains(&ExtKeyUsage::NetscapeServerGatedCrypto)
                        || c.ext_key_usage
                            .contains(&ExtKeyUsage::MicrosoftServerGatedCrypto)));
            if !ok {
                return Err(Error::new(
                    "x509: certificate specifies an incompatible key usage",
                ));
            }
        }
        Ok(())
    }

    fn check_time(&self, now: SystemTime) -> Result<(), Error> {
        let (secs, nanos) = unix(now);
        let detail = if secs < self.not_before {
            format!(
                "current time {} is before {}",
                rfc3339(secs),
                rfc3339(self.not_before)
            )
        } else if secs > self.not_after || (secs == self.not_after && nanos > 0) {
            format!(
                "current time {} is after {}",
                rfc3339(secs),
                rfc3339(self.not_after)
            )
        } else {
            return Ok(());
        };
        Err(Error::new(format!(
            "x509: certificate has expired or is not yet valid: {detail}"
        )))
    }

    fn verify_hostname(&self, host: &str) -> Result<(), Error> {
        let want = host.trim_end_matches('.').to_ascii_lowercase();
        if self
            .dns_names
            .iter()
            .any(|n| n.trim_end_matches('.').eq_ignore_ascii_case(&want))
        {
            return Ok(());
        }
        let text = if !self.has_san && self.common_name.eq_ignore_ascii_case(host) {
            "x509: certificate relies on legacy Common Name field, use SANs instead".to_string()
        } else if self.dns_names.is_empty() {
            format!("x509: certificate is not valid for any names, but wanted to match {host}")
        } else {
            format!(
                "x509: certificate is valid for {}, not {host}",
                self.dns_names.join(", ")
            )
        };
        Err(Error::new(text))
    }

    fn serial_decimal(&self) -> String {
        // Repeated division of the big-endian magnitude by ten.
        let mut digits = Vec::new();
        let mut n = self.serial.clone();
        while n.iter().any(|&b| b != 0) {
            let mut rem = 0u32;
            for b in n.iter_mut() {
                let cur = (rem << 8) | u32::from(*b);
                *b = (cur / 10) as u8;
                rem = cur % 10;
            }
            digits.push(b'0' + rem as u8);
        }
        if digits.is_empty() {
            digits.push(b'0');
        }
        digits.reverse();
        let s = String::from_utf8(digits).expect("digits");
        if self.serial_negative {
            format!("-{s}")
        } else {
            s
        }
    }
}

/// Parses the first certificate in a PEM block.
pub fn parse_cert_pem(b: &[u8]) -> Result<Certificate, Error> {
    match encoding::pem_decode(b) {
        Some(block) if block.kind == "CERTIFICATE" => Certificate::from_der(&block.bytes),
        _ => Err(Error::new("no PEM certificate found")),
    }
}

/// Checks a server certificate the way `ServerCert.Set` does before it
/// serves one: signed by `ca`, valid now, for [`SERVER_NAME`] with server
/// authentication.
pub fn verify_server(leaf: &Certificate, ca: &Certificate, now: SystemTime) -> Result<(), Error> {
    leaf.verify(ca, Some(SERVER_NAME), ExtKeyUsage::ServerAuth, now)
        .map_err(|e| Error::new(format!("server certificate: {e}")))
}

pub(crate) fn unix(t: SystemTime) -> (i64, u32) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            if d.subsec_nanos() == 0 {
                (-(d.as_secs() as i64), 0)
            } else {
                (-(d.as_secs() as i64) - 1, 1_000_000_000 - d.subsec_nanos())
            }
        }
    }
}

/// RFC 3339 of a UTC time in Unix seconds (`2006-01-02T15:04:05Z`).
pub(crate) fn rfc3339(secs: i64) -> String {
    match ::time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(t) => format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        ),
        Err(_) => secs.to_string(),
    }
}

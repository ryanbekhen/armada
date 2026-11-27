//! P-256 private keys in PKCS#8 (with the curve named in the algorithm
//! identifier and the public key included), as ring reads them.

use std::fmt;

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

use crate::Error;
use crate::encoding::{self, oid};

/// Bytes cleared when dropped, redacted in `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(b: Vec<u8>) -> Self {
        SecretBytes(b)
    }

    /// The contents.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        for x in self.0.iter_mut() {
            // SAFETY: x is a valid, aligned, exclusive reference.
            unsafe { std::ptr::write_volatile(x, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// An ECDSA P-256 private key. `Debug` shows only the public key's
/// fingerprint.
pub struct PrivateKey {
    pkcs8: SecretBytes,
    public: Vec<u8>,
}

impl PrivateKey {
    /// A new random key.
    pub fn generate() -> Result<Self, Error> {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|_| Error::new("ecdsa: key generation failed"))?;
        Self::from_pkcs8(doc.as_ref())
    }

    /// Reads a PKCS#8 key, refusing every key but ECDSA P-256 with the
    /// `x509:` texts of the recordings.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, Error> {
        let malformed = || Error::new("x509: failed to parse private key");
        let (0x30, body, []) = encoding::read_tlv(der).ok_or_else(malformed)? else {
            return Err(malformed());
        };
        let (0x02, _, rest) = encoding::read_tlv(body).ok_or_else(malformed)? else {
            return Err(malformed());
        };
        let (0x30, alg, _) = encoding::read_tlv(rest).ok_or_else(malformed)? else {
            return Err(malformed());
        };
        let (0x06, alg_oid, params) = encoding::read_tlv(alg).ok_or_else(malformed)? else {
            return Err(malformed());
        };
        if [oid::RSA, oid::ED25519, oid::X25519].contains(&alg_oid) {
            return Err(Error::new("private key is not ECDSA"));
        }
        if alg_oid != oid::EC_PUBLIC_KEY {
            return Err(Error::new(
                "x509: PKCS#8 wrapping contained private key with unknown algorithm",
            ));
        }
        match encoding::read_tlv(params) {
            Some((0x06, curve, _)) if curve == oid::P256 => {}
            _ => return Err(Error::new("x509: unsupported elliptic curve")),
        }
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, der, &SystemRandom::new())
                .map_err(|_| malformed())?;
        Ok(PrivateKey {
            public: pair.public_key().as_ref().to_vec(),
            pkcs8: SecretBytes(der.to_vec()),
        })
    }

    /// Parses a `PRIVATE KEY` PEM block.
    pub fn from_pem(b: &[u8]) -> Result<Self, Error> {
        match encoding::pem_decode(b) {
            Some(block) if block.kind == "PRIVATE KEY" => {
                let der = SecretBytes(block.bytes);
                Self::from_pkcs8(der.expose())
            }
            _ => Err(Error::new("no PEM private key found")),
        }
    }

    /// The PKCS#8 DER bytes.
    pub fn pkcs8(&self) -> &SecretBytes {
        &self.pkcs8
    }

    /// The key in PEM form. Callers store it with mode 0600.
    pub fn to_pem(&self) -> SecretBytes {
        SecretBytes(encoding::pem_encode("PRIVATE KEY", self.pkcs8.expose()))
    }

    /// The uncompressed public point.
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    pub(crate) fn rcgen(&self) -> Result<rcgen::KeyPair, Error> {
        rcgen::KeyPair::try_from(self.pkcs8.expose())
            .map_err(|e| Error::new(format!("signing key: {e}")))
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id = ring::digest::digest(&ring::digest::SHA256, &self.public);
        write!(f, "PrivateKey(p256, {})", &encoding::hex(id.as_ref())[..16])
    }
}

/// The public half of a P-256 key, for rcgen.
pub(crate) struct P256Public(pub Vec<u8>);

impl rcgen::PublicKeyData for P256Public {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

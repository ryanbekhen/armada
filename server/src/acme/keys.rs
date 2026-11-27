//! ECDSA P-256 keys as certmagic keeps them: generated for every account
//! and certificate, written as SEC 1 "EC PRIVATE KEY" PEM blocks and read
//! from SEC 1 or PKCS#8; the account's JWK and its thumbprint (RFC 7638)
//! as acmez writes them, ES256 signatures as fixed-size r||s, and
//! certificate requests with only DNS or IP names.

use armada_pki::SecretBytes;
use armada_pki::encoding::{pem_decode, pem_encode, read_tlv, seq, tlv};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

use super::b64url;

/// id-ecPublicKey (1.2.840.10045.2.1).
const OID_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// prime256v1 (1.2.840.10045.3.1.7).
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// An ECDSA P-256 key pair. `Debug` shows nothing of the private key.
pub struct EcKey {
    pair: EcdsaKeyPair,
    private: SecretBytes,
    public: Vec<u8>,
}

impl std::fmt::Debug for EcKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EcKey([REDACTED])")
    }
}

impl EcKey {
    /// A new random key.
    pub fn generate() -> Result<EcKey, String> {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| "generating private key: ECDSA P-256".to_string())?;
        let (private, public) =
            from_pkcs8(doc.as_ref()).ok_or_else(|| "unknown private key type".to_string())?;
        EcKey::from_parts(private, public)
    }

    fn from_parts(private: Vec<u8>, public: Vec<u8>) -> Result<EcKey, String> {
        // MarshalECPrivateKey pads the scalar to the curve's size.
        if private.len() > 32 {
            return Err("unknown private key type".to_string());
        }
        let mut scalar = vec![0u8; 32 - private.len()];
        scalar.extend_from_slice(&private);
        let pair = EcdsaKeyPair::from_private_key_and_public_key(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &scalar,
            &public,
            &SystemRandom::new(),
        )
        .map_err(|_| "unknown private key type".to_string())?;
        Ok(EcKey {
            pair,
            private: SecretBytes::new(scalar),
            public,
        })
    }

    /// A key from PEM: the first PEM
    /// block, a type of "PRIVATE KEY" or "... PRIVATE KEY", SEC 1 or
    /// PKCS#8 holding a P-256 key.
    pub fn from_pem(b: &[u8]) -> Result<EcKey, String> {
        let block = pem_decode(b)
            .ok_or_else(|| "failed to decode PEM block containing private key".to_string())?;
        if block.kind != "PRIVATE KEY" && !block.kind.ends_with(" PRIVATE KEY") {
            return Err(format!(
                "unknown PEM header {}",
                armada_spec::go::quote(&block.kind)
            ));
        }
        let der = SecretBytes::new(block.bytes);
        let (private, public) = from_pkcs8(der.expose())
            .or_else(|| from_sec1(der.expose()))
            .ok_or_else(|| "unknown private key type".to_string())?;
        EcKey::from_parts(private, public)
    }

    /// An "EC PRIVATE KEY" block of the key's SEC 1 encoding with its
    /// curve and public key.
    pub fn to_pem(&self) -> SecretBytes {
        let mut bits = vec![0u8];
        bits.extend_from_slice(&self.public);
        let der = SecretBytes::new(seq(&[
            tlv(0x02, &[1]),
            tlv(0x04, self.private.expose()),
            tlv(0xa0, &tlv(0x06, OID_P256)),
            tlv(0xa1, &tlv(0x03, &bits)),
        ]));
        SecretBytes::new(pem_encode("EC PRIVATE KEY", der.expose()))
    }

    /// The key as PKCS#8, for rcgen.
    fn pkcs8(&self) -> SecretBytes {
        let mut bits = vec![0u8];
        bits.extend_from_slice(&self.public);
        let inner = SecretBytes::new(seq(&[
            tlv(0x02, &[1]),
            tlv(0x04, self.private.expose()),
            tlv(0xa1, &tlv(0x03, &bits)),
        ]));
        SecretBytes::new(seq(&[
            tlv(0x02, &[0]),
            seq(&[tlv(0x06, OID_EC), tlv(0x06, OID_P256)]),
            tlv(0x04, inner.expose()),
        ]))
    }

    /// The uncompressed public point.
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// An ES256 signature of msg: r||s, 32 bytes each.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        self.pair
            .sign(&SystemRandom::new(), msg)
            .map(|s| s.as_ref().to_vec())
            .map_err(|_| "signing failed".to_string())
    }

    /// The public key as acmez writes it, members in order.
    pub fn jwk(&self) -> String {
        let p = self.pair.public_key().as_ref();
        format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            b64url(&p[1..33]),
            b64url(&p[33..65])
        )
    }

    /// The JWK thumbprint (RFC 7638).
    pub fn thumbprint(&self) -> String {
        b64url(ring::digest::digest(&ring::digest::SHA256, self.jwk().as_bytes()).as_ref())
    }

    /// A CSR for one name: no subject, the name as a DNS or IP
    /// subject alternative name.
    pub fn csr(&self, name: &str) -> Result<Vec<u8>, String> {
        let pkcs8 = self.pkcs8();
        let kp = rcgen::KeyPair::try_from(pkcs8.expose()).map_err(|e| e.to_string())?;
        let mut params =
            rcgen::CertificateParams::new(vec![name.to_string()]).map_err(|e| e.to_string())?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        let req = params.serialize_request(&kp).map_err(|e| e.to_string())?;
        Ok(req.der().to_vec())
    }
}

/// The private scalar and public point of a PKCS#8 P-256 key.
fn from_pkcs8(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (tag, body, rest) = read_tlv(der)?;
    if tag != 0x30 || !rest.is_empty() {
        return None;
    }
    let (tag, version, body) = read_tlv(body)?;
    if tag != 0x02 || version != [0] {
        return None;
    }
    let (tag, alg, body) = read_tlv(body)?;
    if tag != 0x30 {
        return None;
    }
    let (t1, a, alg_rest) = read_tlv(alg)?;
    let (t2, c, _) = read_tlv(alg_rest)?;
    if t1 != 0x06 || a != OID_EC || t2 != 0x06 || c != OID_P256 {
        return None;
    }
    let (tag, inner, _) = read_tlv(body)?;
    if tag != 0x04 {
        return None;
    }
    from_sec1(inner)
}

/// The private scalar and public point of a SEC 1 P-256 key (the public
/// key is required).
fn from_sec1(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (tag, body, rest) = read_tlv(der)?;
    if tag != 0x30 || !rest.is_empty() {
        return None;
    }
    let (tag, version, body) = read_tlv(body)?;
    if tag != 0x02 || version != [1] {
        return None;
    }
    let (tag, private, mut body) = read_tlv(body)?;
    if tag != 0x04 {
        return None;
    }
    let mut public = None;
    while !body.is_empty() {
        let (tag, content, rest) = read_tlv(body)?;
        match tag {
            0xa0 => {
                let (t, oid, _) = read_tlv(content)?;
                if t != 0x06 || oid != OID_P256 {
                    return None;
                }
            }
            0xa1 => {
                let (t, bits, _) = read_tlv(content)?;
                if t != 0x03 || bits.first() != Some(&0) {
                    return None;
                }
                public = Some(bits[1..].to_vec());
            }
            _ => {}
        }
        body = rest;
    }
    let public = public?;
    if public.len() != 65 || public[0] != 4 {
        return None;
    }
    Some((private.to_vec(), public))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip() {
        let k = EcKey::generate().unwrap();
        let pem = k.to_pem();
        let text = String::from_utf8(pem.expose().to_vec()).unwrap();
        assert!(text.starts_with("-----BEGIN EC PRIVATE KEY-----\n"));
        let back = EcKey::from_pem(pem.expose()).unwrap();
        assert_eq!(back.public(), k.public());
        assert_eq!(back.thumbprint(), k.thumbprint());
        // PKCS#8 reads too.
        let p8 = pem_encode("PRIVATE KEY", k.pkcs8().expose());
        assert_eq!(EcKey::from_pem(&p8).unwrap().public(), k.public());
        assert_eq!(
            EcKey::from_pem(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
                .unwrap_err(),
            "unknown PEM header \"CERTIFICATE\""
        );
        assert_eq!(k.sign(b"x").unwrap().len(), 64);
        assert!(!k.csr("a.example.org").unwrap().is_empty());
    }
}

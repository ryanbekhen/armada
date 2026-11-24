//! volbackup's keys: derived from the key secret with HKDF-SHA-256 salted
//! with the repository's ID; chunks named by HMAC-SHA-256 of their
//! plaintext; objects sealed with AES-256-GCM, the object's name as
//! additional data, a random 12-byte nonce in front.

use ring::{aead, hkdf, hmac, rand::SecureRandom};

/// MinKeyLen.
pub const MIN_KEY_LEN: usize = 32;

/// errSealed.
pub const ERR_SEALED: &str =
    "an object of the backup repository does not open with the backup key: damaged or replaced";

pub struct Keys {
    seal: aead::LessSafeKey,
    id: hmac::Key,
    pub gear: [u64; 256],
    pub check: String,
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// hkdf.Key(sha256.New, secret, salt, info, n).
fn derive(secret: &[u8], salt: &[u8], info: &str, n: usize) -> Vec<u8> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(secret);
    let info = format!("armada volume backup {info}");
    let parts = [info.as_bytes()];
    let okm = prk
        .expand(&parts, Len(n))
        .expect("HKDF output within 255 blocks");
    let mut out = vec![0u8; n];
    okm.fill(&mut out).expect("HKDF fill of its own length");
    out
}

pub fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[usize::from(x >> 4)] as char);
        s.push(H[usize::from(x & 15)] as char);
    }
    s
}

/// hex.DecodeString: either case.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let v = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| Some(v(p[0])? << 4 | v(p[1])?))
        .collect()
}

pub fn random(n: usize) -> Result<Vec<u8>, String> {
    let mut b = vec![0u8; n];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| "crypto/rand: no randomness".to_string())?;
    Ok(b)
}

impl Keys {
    /// deriveKeys.
    pub fn derive(secret: &[u8], repo_id: &[u8]) -> Result<Keys, String> {
        if secret.len() < MIN_KEY_LEN {
            return Err(format!(
                "the backup key must be at least {MIN_KEY_LEN} bytes"
            ));
        }
        let seal = derive(secret, repo_id, "seal", 32);
        let seal = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &seal).expect("a 32-byte key"),
        );
        let id = hmac::Key::new(hmac::HMAC_SHA256, &derive(secret, repo_id, "chunk id", 32));
        let g = derive(secret, repo_id, "gear", 256 * 8);
        let mut gear = [0u64; 256];
        for (i, v) in gear.iter_mut().enumerate() {
            *v = u64::from_le_bytes(g[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
        }
        let check = hex(&derive(secret, repo_id, "check", 32));
        Ok(Keys {
            seal,
            id,
            gear,
            check,
        })
    }

    /// chunkID.
    pub fn chunk_id(&self, plain: &[u8]) -> String {
        hex(hmac::sign(&self.id, plain).as_ref())
    }

    /// seal: nonce, ciphertext, tag.
    pub fn seal(&self, name: &str, plain: &[u8]) -> Result<Vec<u8>, String> {
        let nonce = random(aead::NONCE_LEN)?;
        let mut out = Vec::with_capacity(nonce.len() + plain.len() + 16);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plain);
        let n = aead::Nonce::try_assume_unique_for_key(&nonce).expect("12 bytes");
        let tag = self
            .seal
            .seal_in_place_separate_tag(n, aead::Aad::from(name.as_bytes()), &mut out[12..])
            .map_err(|_| "seal failed".to_string())?;
        out.extend_from_slice(tag.as_ref());
        Ok(out)
    }

    /// open.
    pub fn open(&self, name: &str, mut sealed: Vec<u8>) -> Result<Vec<u8>, String> {
        if sealed.len() < aead::NONCE_LEN + 16 {
            return Err(ERR_SEALED.into());
        }
        let n = aead::Nonce::try_assume_unique_for_key(&sealed[..12]).expect("12 bytes");
        let len = self
            .seal
            .open_in_place(n, aead::Aad::from(name.as_bytes()), &mut sealed[12..])
            .map_err(|_| ERR_SEALED.to_string())?
            .len();
        sealed.truncate(12 + len);
        sealed.drain(..12);
        Ok(sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_and_refuses() {
        let k = Keys::derive(&[7u8; 32], &[1u8; 16]).unwrap();
        let s = k.seal("a/b", b"hello").unwrap();
        assert_eq!(k.open("a/b", s.clone()).unwrap(), b"hello");
        assert_eq!(k.open("a/c", s).unwrap_err(), ERR_SEALED);
        assert!(Keys::derive(&[7u8; 31], &[1u8; 16]).is_err());
        assert_eq!(unhex("0aFf"), Some(vec![0x0a, 0xff]));
        assert_eq!(hex(&[0x0a, 0xff]), "0aff");
    }
}

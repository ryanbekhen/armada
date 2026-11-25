//! Join tokens and the CA pin joining machines check (Go's `join.go`).

use std::fmt;
use std::time::SystemTime;

use ring::rand::{SecureRandom, SystemRandom};

use crate::cert::{Certificate, ExtKeyUsage};
use crate::{Error, SERVER_NAME, encoding};

/// Authorizes one machine to join the cluster, written `<id>.<secret>`:
/// the ID is public and names the token, the secret proves possession. The
/// server stores only a hash of the secret. `Debug` and `Display` leave the
/// secret out.
#[derive(Clone, PartialEq, Eq)]
pub struct JoinToken {
    pub id: String,
    secret: String,
}

impl JoinToken {
    /// The whole token. Only `armada node join-token` and `armada server
    /// join-token` print it.
    pub fn reveal(&self) -> String {
        format!("{}.{}", self.id, self.secret)
    }

    /// The secret half.
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// What the server stores for the token.
    pub fn secret_hash(&self) -> String {
        hash_token_secret(&self.secret)
    }
}

impl fmt::Display for JoinToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.[REDACTED]", self.id)
    }
}

impl fmt::Debug for JoinToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.[REDACTED]", self.id)
    }
}

/// A token with a 48-bit ID and a 256-bit secret.
pub fn new_join_token() -> Result<JoinToken, Error> {
    let rng = SystemRandom::new();
    let mut id = [0u8; 6];
    let mut secret = [0u8; 32];
    rng.fill(&mut id)
        .and_then(|_| rng.fill(&mut secret))
        .map_err(|_| Error::new("crypto/rand: read failed"))?;
    Ok(JoinToken {
        id: encoding::hex(&id),
        secret: encoding::hex(&secret),
    })
}

fn lower_hex(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parses `<id>.<secret>`: 12 and 64 lowercase hex digits, white space
/// around them ignored.
pub fn parse_join_token(s: &str) -> Result<JoinToken, Error> {
    let s = s.trim();
    match s.split_once('.') {
        Some((id, secret)) if lower_hex(id, 12) && lower_hex(secret, 64) => Ok(JoinToken {
            id: id.to_string(),
            secret: secret.to_string(),
        }),
        _ => Err(Error::new("malformed join token (want <12 hex>.<64 hex>)")),
    }
}

/// Hashes a token secret for storage: hex SHA-256.
pub fn hash_token_secret(secret: &str) -> String {
    encoding::hex(ring::digest::digest(&ring::digest::SHA256, secret.as_bytes()).as_ref())
}

/// Compares a presented secret with a stored hash in constant time.
pub fn token_secret_matches(secret: &str, stored_hash: &str) -> bool {
    constant_time_eq(hash_token_secret(secret).as_bytes(), stored_hash.as_bytes())
}

/// Go's `subtle.ConstantTimeCompare`: false at once for different lengths,
/// else time independent of the contents.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= std::hint::black_box(x ^ y);
    }
    std::hint::black_box(d) == 0
}

/// The pin of a CA certificate, `sha256:<hex>`.
pub fn ca_hash(ca: &Certificate) -> String {
    format!("sha256:{}", ca.fingerprint())
}

/// Validates a CA pin and returns its hex digest.
pub fn parse_ca_hash(s: &str) -> Result<String, Error> {
    match s.trim().strip_prefix("sha256:") {
        Some(h) if lower_hex(h, 64) => Ok(h.to_string()),
        _ => Err(Error::new("malformed CA hash (want sha256:<64 hex>)")),
    }
}

/// Finds the certificate matching `ca_hash` (hex, from [`parse_ca_hash`])
/// in a chain a join listener presented, and verifies the leaf against it
/// for [`SERVER_NAME`] at `now` (Go's `pinCA`).
pub fn pin_ca(chain: &[Certificate], ca_hash: &str, now: SystemTime) -> Result<Certificate, Error> {
    if chain.len() < 2 {
        return Err(Error::new("server did not present its CA certificate"));
    }
    let mut ca = None;
    for c in &chain[1..] {
        if constant_time_eq(c.fingerprint().as_bytes(), ca_hash.as_bytes()) {
            ca = Some(c);
        }
    }
    let Some(ca) = ca else {
        return Err(Error::new(
            "the server's CA does not match the CA hash in the join command; refusing to join (possible man-in-the-middle)",
        ));
    };
    if !ca.is_ca || !ca.basic_constraints_valid {
        return Err(Error::new("pinned certificate is not a CA"));
    }
    chain[0]
        .verify(ca, Some(SERVER_NAME), ExtKeyUsage::ServerAuth, now)
        .map_err(|e| {
            Error::new(format!(
                "server certificate is not valid for the pinned CA: {e}"
            ))
        })?;
    Ok(ca.clone())
}

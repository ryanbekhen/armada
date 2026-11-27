//! Secret values at rest, with envelope encryption (ADR 0006).
//!
//! Every secret version is encrypted with its own random data key
//! (AES-256-GCM); the data key is encrypted with the cluster master key.
//! Both layers bind the secret's scope, name, and version as additional
//! data, so a ciphertext cannot be moved to another secret or version. The
//! format is fixed byte for byte (tests/parity.rs): values sealed by any
//! release open in every other.

use std::fmt;
use std::path::Path;

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};

/// The largest secret value accepted.
pub const MAX_SIZE: usize = 64 << 10;

const KEY_SIZE: usize = 32;
const TAG_LEN: usize = 16;
const REDACTED: &str = "[REDACTED]";

/// The text of [`Error::WrongKey`].
pub const WRONG_KEY: &str = "secret was encrypted with a different master key";

/// What went wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The secret was sealed with another master key.
    WrongKey,
    /// Anything else, with its text.
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::WrongKey => f.write_str(WRONG_KEY),
            Error::Other(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for Error {}

impl From<armada_fsutil::Error> for Error {
    fn from(e: armada_fsutil::Error) -> Self {
        Error::Other(e.to_string())
    }
}

fn other(s: impl Into<String>) -> Error {
    Error::Other(s.into())
}

/// Bytes cleared when dropped.
struct Wiped(Vec<u8>);

impl Drop for Wiped {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        // SAFETY: x is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(x, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// A secret's plaintext. It redacts itself in `Debug` and `Display`; use
/// [`Value::bytes`] to read the contents. Cleared when dropped.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Value {
    b: Vec<u8>,
}

impl Value {
    /// Copies `b` into a Value.
    pub fn new(b: &[u8]) -> Self {
        Value { b: b.to_vec() }
    }

    /// The plaintext.
    pub fn bytes(&self) -> &[u8] {
        &self.b
    }

    /// The plaintext's length.
    pub fn len(&self) -> usize {
        self.b.len()
    }

    /// Whether the plaintext is empty.
    pub fn is_empty(&self) -> bool {
        self.b.is_empty()
    }
}

impl From<Vec<u8>> for Value {
    fn from(b: Vec<u8>) -> Self {
        Value { b }
    }
}

impl Drop for Value {
    fn drop(&mut self) {
        wipe(&mut self.b);
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// An encrypted secret version as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// The master key that wrapped the data key.
    pub key_id: String,
    /// nonce || AES-GCM(master key, data key).
    pub wrapped_key: Vec<u8>,
    /// nonce || AES-GCM(data key, plaintext).
    pub ciphertext: Vec<u8>,
}

/// The cluster master key. `Debug` and `Display` show only its ID.
pub struct Keyring {
    key: Wiped,
    id: String,
}

impl Keyring {
    /// Wraps a 32-byte master key.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        if key.len() != KEY_SIZE {
            return Err(other(format!(
                "master key must be {KEY_SIZE} bytes, got {}",
                key.len()
            )));
        }
        let sum = digest::digest(&digest::SHA256, key);
        Ok(Keyring {
            key: Wiped(key.to_vec()),
            id: hex(&sum.as_ref()[..8]),
        })
    }

    /// Identifies the master key without revealing it.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The master key in the key file's encoding, for a control plane
    /// machine that joins the cluster.
    pub fn export(&self) -> Value {
        Value::from(format!("{}\n", hex(&self.key.0)).into_bytes())
    }

    /// Encrypts `v` as `version` of secret `name` in `scope`.
    pub fn seal(&self, scope: &str, name: &str, version: i64, v: &Value) -> Result<Sealed, Error> {
        if v.len() > MAX_SIZE {
            return Err(other(format!(
                "secret is {} bytes; the limit is {MAX_SIZE}",
                v.len()
            )));
        }
        let rng = SystemRandom::new();
        let mut data_key = Wiped(vec![0u8; KEY_SIZE]);
        rng.fill(&mut data_key.0)
            .map_err(|_| other("crypto/rand: read failed"))?;
        let ad = additional_data(scope, name, version);
        let ciphertext = seal(&rng, &data_key.0, &v.b, &ad)?;
        let wrapped_key = seal(&rng, &self.key.0, &data_key.0, &ad)?;
        Ok(Sealed {
            key_id: self.id.clone(),
            wrapped_key,
            ciphertext,
        })
    }

    /// Decrypts `s`, which must have been sealed for the same scope, name,
    /// and version.
    pub fn open(&self, s: &Sealed, scope: &str, name: &str, version: i64) -> Result<Value, Error> {
        if s.key_id != self.id {
            return Err(Error::WrongKey);
        }
        let ad = additional_data(scope, name, version);
        let data_key = open(&self.key.0, &s.wrapped_key, &ad)
            .map_err(|e| other(format!("unwrap data key of {scope}/{name} v{version}: {e}")))?;
        let data_key = Wiped(data_key);
        let pt = open(&data_key.0, &s.ciphertext, &ad)
            .map_err(|e| other(format!("decrypt {scope}/{name} v{version}: {e}")))?;
        Ok(Value::from(pt))
    }
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "keyring({})", self.id)
    }
}

impl fmt::Display for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "keyring({})", self.id)
    }
}

/// Writes a new random master key to `path` (mode 0600), as hex and a
/// newline. It fails if the file exists.
pub fn generate_key_file(path: &Path) -> Result<(), Error> {
    let mut key = Wiped(vec![0u8; KEY_SIZE]);
    SystemRandom::new()
        .fill(&mut key.0)
        .map_err(|_| other("crypto/rand: read failed"))?;
    let enc = Wiped(format!("{}\n", hex(&key.0)).into_bytes());
    armada_fsutil::write_file_exclusive(path, &enc.0, 0o600)?;
    Ok(())
}

/// Writes a master key [`Keyring::export`] returned to `path` (mode 0600).
/// It fails if the file exists or the key is invalid.
pub fn write_key_file(path: &Path, v: &Value) -> Result<(), Error> {
    let key = unhex(trim_space(v.bytes())).ok_or_else(|| other("master key is not valid hex"))?;
    let key = Wiped(key);
    Keyring::new(&key.0)?;
    armada_fsutil::write_file_exclusive(path, v.bytes(), 0o600)?;
    Ok(())
}

/// Reads a master key written by [`generate_key_file`], refusing files
/// group or others may read.
pub fn load_key_file(path: &Path) -> Result<Keyring, Error> {
    let b = Wiped(armada_fsutil::read_private_file(path)?);
    let key = unhex(trim_space(&b.0))
        .ok_or_else(|| other(format!("master key {} is not valid hex", path.display())))?;
    let key = Wiped(key);
    Keyring::new(&key.0)
}

fn additional_data(scope: &str, name: &str, version: i64) -> Vec<u8> {
    format!("armada-secret-v1\x00{scope}\x00{name}\x00{version}").into_bytes()
}

fn aead_key(key: &[u8]) -> Result<LessSafeKey, Error> {
    let k = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| other(format!("crypto/aes: invalid key size {}", key.len())))?;
    Ok(LessSafeKey::new(k))
}

fn seal(rng: &SystemRandom, key: &[u8], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, Error> {
    let k = aead_key(key)?;
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce)
        .map_err(|_| other("crypto/rand: read failed"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(plaintext);
    let tag = k
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(ad),
            &mut out[NONCE_LEN..],
        )
        .map_err(|_| other("encryption failed"))?;
    out.extend_from_slice(tag.as_ref());
    Ok(out)
}

fn open(key: &[u8], sealed: &[u8], ad: &[u8]) -> Result<Vec<u8>, Error> {
    let k = aead_key(key)?;
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(other("ciphertext too short"));
    }
    let nonce = Nonce::try_assume_unique_for_key(&sealed[..NONCE_LEN])
        .map_err(|_| other("authentication failed"))?;
    let mut buf = sealed[NONCE_LEN..].to_vec();
    let n = match k.open_in_place(nonce, Aad::from(ad), &mut buf) {
        Ok(pt) => pt.len(),
        Err(_) => {
            wipe(&mut buf);
            return Err(other("authentication failed"));
        }
    };
    buf.truncate(n);
    Ok(buf)
}

fn hex(b: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(DIGITS[(x >> 4) as usize] as char);
        s.push(DIGITS[(x & 15) as usize] as char);
    }
    s
}

/// Decodes hex: either case, an even length.
fn unhex(s: &[u8]) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    s.chunks(2)
        .map(|p| Some(digit(p[0])? << 4 | digit(p[1])?))
        .collect()
}

/// Trims leading and trailing white space
/// (ASCII, and Unicode's in valid UTF-8).
fn trim_space(b: &[u8]) -> &[u8] {
    match std::str::from_utf8(b) {
        Ok(s) => s.trim().as_bytes(),
        Err(_) => b.trim_ascii(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn keyring() -> Keyring {
        let mut key = [0u8; 32];
        SystemRandom::new().fill(&mut key).unwrap();
        Keyring::new(&key).unwrap()
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "armada-secrets-{name}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn values_never_print() {
        let v = Value::new(b"hunter2");
        for s in [
            format!("{v}"),
            format!("{v:?}"),
            format!("{v:#?}"),
            format!("{:>20}", v),
        ] {
            assert!(!s.contains("hunter2"), "{s}");
            assert!(s.contains(REDACTED));
        }
        let k = keyring();
        let shown = format!("{k} {k:?}");
        assert!(!shown.contains(&hex(&k.key.0)));
        assert_eq!(format!("{k}"), format!("keyring({})", k.id()));
        let s = k.export();
        assert!(!format!("{s:?}").contains(&hex(&k.key.0)));
    }

    #[test]
    fn seal_open() {
        let k = keyring();
        let v = Value::new(b"postgres://u:p@db/app");
        let s = k.seal("web", "DB_URL", 3, &v).unwrap();
        assert_eq!(s.key_id, k.id());
        assert_eq!(s.ciphertext.len(), 12 + v.len() + 16);
        assert_eq!(s.wrapped_key.len(), 12 + 32 + 16);
        assert_eq!(k.open(&s, "web", "DB_URL", 3).unwrap(), v);
        let empty = k.seal("web", "E", 1, &Value::default()).unwrap();
        assert!(k.open(&empty, "web", "E", 1).unwrap().is_empty());
    }

    #[test]
    fn open_refuses_tampering() {
        let k = keyring();
        let s = k.seal("web", "K", 1, &Value::new(b"v")).unwrap();
        let cases: Vec<(&str, Sealed, &str, &str, i64)> = vec![
            ("other scope", s.clone(), "api", "K", 1),
            ("other name", s.clone(), "web", "L", 1),
            ("other version", s.clone(), "web", "K", 2),
            (
                "ciphertext",
                Sealed {
                    ciphertext: flip(&s.ciphertext),
                    ..s.clone()
                },
                "web",
                "K",
                1,
            ),
            (
                "wrapped key",
                Sealed {
                    wrapped_key: flip(&s.wrapped_key),
                    ..s.clone()
                },
                "web",
                "K",
                1,
            ),
            (
                "short",
                Sealed {
                    ciphertext: vec![1, 2, 3],
                    ..s.clone()
                },
                "web",
                "K",
                1,
            ),
            (
                "swapped",
                Sealed {
                    ciphertext: s.wrapped_key.clone(),
                    wrapped_key: s.ciphertext.clone(),
                    ..s.clone()
                },
                "web",
                "K",
                1,
            ),
        ];
        for (what, sealed, scope, name, version) in cases {
            assert!(k.open(&sealed, scope, name, version).is_err(), "{what}");
        }
        assert_eq!(
            k.open(&s, "api", "K", 1).unwrap_err().to_string(),
            "unwrap data key of api/K v1: authentication failed"
        );
        let short = Sealed {
            ciphertext: vec![1, 2, 3],
            ..s.clone()
        };
        assert_eq!(
            k.open(&short, "web", "K", 1).unwrap_err().to_string(),
            "decrypt web/K v1: ciphertext too short"
        );
        assert_eq!(
            keyring().open(&s, "web", "K", 1).unwrap_err(),
            Error::WrongKey
        );
    }

    fn flip(b: &[u8]) -> Vec<u8> {
        let mut b = b.to_vec();
        let n = b.len() - 1;
        b[n] ^= 1;
        b
    }

    #[test]
    fn limits() {
        let k = keyring();
        assert!(k.seal("s", "n", 1, &Value::new(&vec![0; MAX_SIZE])).is_ok());
        assert_eq!(
            k.seal("s", "n", 1, &Value::new(&vec![0; MAX_SIZE + 1]))
                .unwrap_err()
                .to_string(),
            "secret is 65537 bytes; the limit is 65536"
        );
        assert_eq!(
            Keyring::new(&[0; 16]).unwrap_err().to_string(),
            "master key must be 32 bytes, got 16"
        );
    }

    #[test]
    fn key_files() {
        let dir = temp_dir("keys");
        let path = dir.join("master.key");
        generate_key_file(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(generate_key_file(&path).is_err(), "overwrote a key");
        let k = load_key_file(&path).unwrap();
        let again = load_key_file(&path).unwrap();
        assert_eq!(k.id(), again.id());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            load_key_file(&path)
                .unwrap_err()
                .to_string()
                .contains("insecure permissions")
        );

        let bad = dir.join("bad.key");
        std::fs::write(&bad, b"zz\n").unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            load_key_file(&bad).unwrap_err().to_string(),
            format!("master key {} is not valid hex", bad.display())
        );
        let short = dir.join("short.key");
        std::fs::write(&short, b"abcd\n").unwrap();
        std::fs::set_permissions(&short, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            load_key_file(&short).unwrap_err().to_string(),
            "master key must be 32 bytes, got 2"
        );

        let exported = dir.join("exported.key");
        write_key_file(&exported, &again.export()).unwrap();
        assert_eq!(load_key_file(&exported).unwrap().id(), again.id());
        assert!(write_key_file(&dir.join("x"), &Value::new(b"nothex")).is_err());
        assert!(write_key_file(&dir.join("y"), &Value::new(b"abcd")).is_err());
        assert!(
            write_key_file(&exported, &again.export()).is_err(),
            "overwrote"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}

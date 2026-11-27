//! WireGuard keys: standard base64 (padded) of 32 bytes, the public half by
//! X25519, and the node's `network.key` file: the private key and a newline,
//! owner-only (0600).

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// A WireGuard key (wgtypes.Key).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord, Debug)]
pub struct Key(pub [u8; 32]);

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// base64.StdEncoding.DecodeString: padded, newlines ignored, unused bits
/// of the last character not checked.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let src: Vec<u8> = s.bytes().filter(|&c| c != b'\n' && c != b'\r').collect();
    if !src.len().is_multiple_of(4) {
        return None;
    }
    let value = |c: u8| ALPHABET.iter().position(|&a| a == c).map(|v| v as u32);
    let mut out = Vec::with_capacity(src.len() / 4 * 3);
    let quanta = src.len() / 4;
    for (q, chunk) in src.chunks(4).enumerate() {
        let last = q + 1 == quanta;
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut acc = 0u32;
        for &c in &chunk[..4 - pad] {
            acc = (acc << 6) | value(c)?;
        }
        acc <<= 6 * pad as u32;
        let bytes = acc.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - pad]);
    }
    Some(out)
}

/// base64.StdEncoding.EncodeToString.
pub fn b64_encode(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for chunk in b.chunks(3) {
        let mut n = [0u8; 3];
        n[..chunk.len()].copy_from_slice(chunk);
        let v = (u32::from(n[0]) << 16) | (u32::from(n[1]) << 8) | u32::from(n[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((v >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

impl Key {
    /// wgtypes.ParseKey.
    pub fn parse(s: &str) -> Option<Key> {
        let b = b64_decode(s)?;
        Some(Key(b.try_into().ok()?))
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 32]
    }

    /// wgtypes.Key.PublicKey: the public half of a private key.
    pub fn public(&self) -> Key {
        let secret = x25519_dalek::StaticSecret::from(self.0);
        Key(x25519_dalek::PublicKey::from(&secret).to_bytes())
    }

    /// wgtypes.GeneratePrivateKey: random bytes from the kernel, clamped.
    pub fn generate() -> io::Result<Key> {
        let mut k = [0u8; 32];
        fs::File::open("/dev/urandom")?.read_exact(&mut k)?;
        k[0] &= 248;
        k[31] = (k[31] & 127) | 64;
        Ok(Key(k))
    }
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&b64_encode(&self.0))
    }
}

/// fsutil.ReadPrivateFile: the file, only when group and others have no
/// access to it.
pub fn read_private_file(path: &Path) -> io::Result<Vec<u8>> {
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} has mode {mode:04o}, want no group/other access (chmod go-rwx): insecure permissions",
                path.display()
            ),
        ));
    }
    fs::read(path)
}

/// fsutil.WriteFileAtomic: through a temporary file in the same directory,
/// renamed into place, so readers never see part of it.
pub fn write_file_atomic(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let base = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut n = Key::generate()?.0;
    let mut attempt = 0;
    let (tmp, mut f) = loop {
        let tmp = dir.join(format!(
            ".{base}.tmp-{}",
            b64_encode(&n[..6]).replace('/', "_")
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
        {
            Ok(f) => break (tmp, f),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempt < 100 => {
                attempt += 1;
                n = Key::generate()?.0;
            }
            Err(e) => return Err(e),
        }
    };
    let result = (|| {
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// fsutil.WriteFileExclusive: a new file, never one that exists.
fn write_file_exclusive(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    let result = (|| {
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.write_all(data)?;
        f.sync_all()
    })();
    if result.is_err() {
        drop(f);
        let _ = fs::remove_file(path);
    }
    result
}

/// LoadOrCreateKey: the node's key from path, or a new one written there
/// the first time (ADR 0025).
pub fn load_or_create(path: &Path) -> Result<Key, String> {
    match read_private_file(path) {
        Ok(b) => {
            let s = String::from_utf8_lossy(&b);
            match Key::parse(s.trim()) {
                Some(k) if !k.is_zero() => Ok(k),
                _ => Err(format!("{} does not hold a valid key", path.display())),
            }
        }
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e.to_string()),
        Err(_) => {
            let k = Key::generate().map_err(|e| e.to_string())?;
            write_file_exclusive(path, format!("{k}\n").as_bytes(), 0o600)
                .map_err(|e| e.to_string())?;
            Ok(k)
        }
    }
}

/// RotateKey: a new key in path, written atomically.
pub fn rotate(path: &Path) -> Result<Key, String> {
    let k = Key::generate().map_err(|e| e.to_string())?;
    write_file_atomic(path, format!("{k}\n").as_bytes(), 0o600).map_err(|e| e.to_string())?;
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_standard() {
        assert_eq!(b64_decode("").unwrap(), b"");
        assert_eq!(b64_decode("YQ==").unwrap(), b"a");
        assert_eq!(b64_decode("YWI=").unwrap(), b"ab");
        assert_eq!(b64_decode("YW\nJj").unwrap(), b"abc");
        // Unused bits are not checked (non-strict decoding).
        assert_eq!(b64_decode("YR==").unwrap(), b"a");
        for bad in ["YQ", "Y===", "YQ==YQ==", "not-a-key", "YQ=="[..3].as_ref()] {
            assert!(b64_decode(bad).is_none(), "{bad}");
        }
        for n in 0..40u8 {
            let b: Vec<u8> = (0..n).map(|i| i.wrapping_mul(37)).collect();
            assert_eq!(b64_decode(&b64_encode(&b)).unwrap(), b);
        }
    }

    #[test]
    fn public_key() {
        // RFC 7748, section 6.1: Alice's keys.
        let mut sk = [0u8; 32];
        let hex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        for (i, b) in sk.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        let pk = Key(sk).public();
        let want = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        let got: String = pk.0.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn key_file() {
        let dir = std::env::temp_dir().join(format!("armada-node-key-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("network.key");
        let k = load_or_create(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), format!("{k}\n"));
        assert_eq!(load_or_create(&path).unwrap(), k);
        let r = rotate(&path).unwrap();
        assert_ne!(r, k);
        assert_eq!(load_or_create(&path).unwrap(), r);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            load_or_create(&path)
                .unwrap_err()
                .contains("insecure permissions")
        );
        let bad = dir.join("bad.key");
        fs::write(&bad, "nope\n").unwrap();
        fs::set_permissions(&bad, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            load_or_create(&bad)
                .unwrap_err()
                .ends_with("does not hold a valid key")
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}

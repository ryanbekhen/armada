//! Downloads over HTTPS only, kept in a cache named by their SHA-256 and
//! returned only when it matches. curl does the transfer (`--proto =https`
//! for the request and every redirect), so the tool links no TLS stack.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

/// The largest download accepted: 512 MiB.
pub const MAX_DOWNLOAD: u64 = 512 << 20;

pub fn sum_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// fetch: the artifact at url from the cache or the network, only if its
/// SHA-256 is want.
pub fn fetch(url: &str, want: &str, cache: &Path) -> Result<Vec<u8>, String> {
    let cached = cache.join(want);
    if let Ok(b) = std::fs::read(&cached)
        && sum_hex(&b) == want
    {
        return Ok(b);
    }
    let b = download(url, cache)?;
    let got = sum_hex(&b);
    if got != want {
        return Err(format!(
            "checksum mismatch for {url}: got {got}, want {want}"
        ));
    }
    keep(&cached, &b);
    Ok(b)
}

/// download: url's bytes, unchecked; the caller checks them.
pub fn download(url: &str, cache: &Path) -> Result<Vec<u8>, String> {
    if !url.starts_with("https://") {
        return Err(format!("refusing non-HTTPS URL {url}"));
    }
    std::fs::create_dir_all(cache).map_err(|e| format!("{}: {e}", cache.display()))?;
    let part = temp_path(cache);
    let out = Command::new("curl")
        .args([
            "-fsSL",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--retry",
            "3",
            "--max-time",
            "600",
            "--max-filesize",
            &MAX_DOWNLOAD.to_string(),
            "-o",
        ])
        .arg(&part)
        .arg("--")
        .arg(url)
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&part);
        return Err(format!(
            "GET {url}: curl {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let b = std::fs::read(&part).map_err(|e| format!("{}: {e}", part.display()));
    let _ = std::fs::remove_file(&part);
    let b = b?;
    if b.len() as u64 > MAX_DOWNLOAD {
        return Err(format!("{url}: larger than {MAX_DOWNLOAD} bytes"));
    }
    Ok(b)
}

/// keep writes a checked download into the cache; a failure only costs a
/// download next time.
pub fn keep(path: &Path, b: &[u8]) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
        let tmp = temp_path(dir);
        if std::fs::write(&tmp, b).is_ok() && std::fs::rename(&tmp, path).is_ok() {
            return;
        }
        let _ = std::fs::remove_file(&tmp);
    }
}

fn temp_path(dir: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    dir.join(format!(
        ".part-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

//! Armada's latest release (ADR 0030): one request
//! to GitHub's API for the last 100 releases, the newest stable one by
//! version, an hour-long cache shared with `armada version`, and the notice
//! the client shows at most once a day.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};

/// The repository releases come from.
pub const REPO: &str = "ryanbekhen/armada";

/// Turns every look for a newer release off when set.
pub const DISABLE_ENV: &str = "ARMADA_NO_UPDATE_CHECK";

/// How long a look may take.
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(3);

const API_HOST: &str = "api.github.com";
const CACHE_FOR: i64 = 3600;
const NOTICE_EVERY: i64 = 24 * 3600;

/// IsRelease: `^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`.
pub fn is_release(v: &str) -> bool {
    let Some(rest) = v.strip_prefix('v') else {
        return false;
    };
    let (core, pre) = match rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (rest, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|p| p.is_empty() || !p.bytes().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    match pre {
        None => true,
        Some(p) => !p.is_empty() && p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.'),
    }
}

/// URL: the page of a release.
pub fn url(tag: &str) -> String {
    format!("https://github.com/{REPO}/releases/tag/{tag}")
}

/// Newer: whether release a is newer than release b by semver.
pub fn newer(a: &str, b: &str) -> bool {
    is_release(a) && is_release(b) && compare(a, b) > 0
}

fn compare(a: &str, b: &str) -> i32 {
    let (ac, ap) = a[1..].split_once('-').unwrap_or((&a[1..], ""));
    let (bc, bp) = b[1..].split_once('-').unwrap_or((&b[1..], ""));
    let c = compare_idents(
        &ac.split('.').collect::<Vec<_>>(),
        &bc.split('.').collect::<Vec<_>>(),
    );
    if c != 0 {
        return c;
    }
    if ap == bp {
        return 0;
    }
    if ap.is_empty() {
        return 1;
    }
    if bp.is_empty() {
        return -1;
    }
    compare_idents(
        &ap.split('.').collect::<Vec<_>>(),
        &bp.split('.').collect::<Vec<_>>(),
    )
}

fn compare_idents(a: &[&str], b: &[&str]) -> i32 {
    for (x, y) in a.iter().zip(b) {
        let xn = parse_u64(x);
        let yn = parse_u64(y);
        match (xn, yn) {
            (Some(x), Some(y)) if x != y => return if x > y { 1 } else { -1 },
            (Some(_), Some(_)) => {}
            (Some(_), None) => return -1,
            (None, Some(_)) => return 1,
            (None, None) => match x.cmp(y) {
                std::cmp::Ordering::Less => return -1,
                std::cmp::Ordering::Greater => return 1,
                std::cmp::Ordering::Equal => {}
            },
        }
    }
    match a.len().cmp(&b.len()) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Greater => 1,
        std::cmp::Ordering::Equal => 0,
    }
}

/// A decimal 64-bit unsigned integer.
fn parse_u64(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// The user's cache directory: $XDG_CACHE_HOME or ~/.cache, and
/// ~/Library/Caches on macOS.
pub fn user_cache_dir() -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        let home = std::env::var("HOME").ok().filter(|h| !h.is_empty())?;
        return Some(Path::new(&home).join("Library/Caches"));
    }
    if let Ok(x) = std::env::var("XDG_CACHE_HOME")
        && !x.is_empty()
    {
        if !x.starts_with('/') {
            return None;
        }
        return Some(PathBuf::from(x));
    }
    let home = std::env::var("HOME").ok().filter(|h| !h.is_empty())?;
    Some(Path::new(&home).join(".cache"))
}

/// The latest release found and when.
#[derive(Clone, Debug, Default)]
pub struct Found {
    pub tag: String,
    pub checked: i64,
}

fn now_unix() -> i64 {
    (crate::commands::now_nanos() / 1_000_000_000) as i64
}

/// LatestCached: through cacheDir/armada/latest.json, an answer less than
/// an hour old used as is; on a failed look an older answer comes back
/// with the error.
pub fn latest_cached(cache_dir: Option<&Path>, now: i64) -> (Found, Option<String>) {
    let mut stored = Found::default();
    if let Some(dir) = cache_dir {
        let path = dir.join("armada/latest.json");
        let parsed = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| {
                let tag = v.get("tag")?.as_str()?.to_string();
                let checked = v.get("checked").map(|c| c.as_i64()).unwrap_or(Some(0))?;
                Some(Found { tag, checked })
            });
        match parsed {
            Some(f) if is_release(&f.tag) => {
                if now - f.checked < CACHE_FOR && f.checked <= now {
                    return (f, None);
                }
                stored = f;
            }
            _ => {}
        }
    }
    match latest() {
        Err(e) => {
            if !stored.tag.is_empty() {
                return (stored, Some(e));
            }
            (Found::default(), Some(e))
        }
        Ok(tag) => {
            if let Some(dir) = cache_dir {
                let d = dir.join("armada");
                let body = format!(
                    "{{\"tag\":{},\"checked\":{now}}}",
                    crate::config::json_string(&tag)
                );
                if armada_fsutil::mkdir_private(&d).is_ok() {
                    let _ = armada_fsutil::write_file_atomic(
                        &d.join("latest.json"),
                        body.as_bytes(),
                        0o600,
                    );
                }
            }
            (Found { tag, checked: now }, None)
        }
    }
}

/// LatestLine: how this version compares with the latest release.
pub fn latest_line(current: &str) -> Vec<String> {
    if std::env::var_os(DISABLE_ENV).is_some_and(|v| !v.is_empty()) {
        return Vec::new();
    }
    let dir = user_cache_dir();
    let (f, _) = latest_cached(dir.as_deref(), now_unix());
    let tag = f.tag;
    if tag.is_empty() {
        return vec!["latest: unknown".to_string()];
    }
    if newer(&tag, current) {
        return vec![format!("latest: {tag}, {}", url(&tag))];
    }
    if is_release(current) {
        return vec![format!("latest: {tag} (up to date)")];
    }
    vec![format!("latest: {tag}")]
}

/// StartNotice: begins looking for a release newer than current, at most
/// once a day; the returned function waits up to its argument for the line
/// to show.
pub fn start_notice(current: &str) -> Box<dyn FnOnce(Duration) -> String> {
    let none: Box<dyn FnOnce(Duration) -> String> = Box::new(|_| String::new());
    let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
    if set(DISABLE_ENV) || set("CI") || !is_release(current) {
        return none;
    }
    let Some(cache) = user_cache_dir() else {
        return none;
    };
    let now = now_unix();
    let dir = cache.join("armada");
    let path = dir.join("release.json");
    if let Some(checked) = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| {
            v.get("checked")
                .map(|c| c.as_i64().unwrap_or(0))
                .or(Some(0))
        })
        && now - checked < NOTICE_EVERY
        && checked <= now
    {
        return none;
    }
    let body = format!("{{\"checked\":{now}}}");
    if armada_fsutil::mkdir_private(&dir).is_err()
        || armada_fsutil::write_file_atomic(&path, body.as_bytes(), 0o600).is_err()
    {
        return none;
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (f, err) = latest_cached(Some(&cache), now);
        let _ = tx.send(if err.is_some() { String::new() } else { f.tag });
    });
    let current = current.to_string();
    Box::new(move |wait| match rx.recv_timeout(wait) {
        Ok(tag) if newer(&tag, &current) => {
            format!(
                "armada {tag} is available (this is {current}): {}",
                url(&tag)
            )
        }
        _ => String::new(),
    })
}

/// Latest: the newest stable release, else the newest pre-release.
pub fn latest() -> Result<String, String> {
    let body = get(API_HOST, &format!("/repos/{REPO}/releases?per_page=100"))?;
    let list: Vec<serde_json::Value> =
        serde_json::from_slice(&body).map_err(|e| format!("look for the latest release: {e}"))?;
    let mut stable = String::new();
    let mut newest = String::new();
    for r in list {
        let tag = r.get("tag_name").and_then(|t| t.as_str()).unwrap_or("");
        let draft = r.get("draft").and_then(|d| d.as_bool()).unwrap_or(false);
        if draft || !is_release(tag) {
            continue;
        }
        if newest.is_empty() || newer(tag, &newest) {
            newest = tag.to_string();
        }
        if !tag.contains('-') && (stable.is_empty() || newer(tag, &stable)) {
            stable = tag.to_string();
        }
    }
    if !stable.is_empty() {
        return Ok(stable);
    }
    if !newest.is_empty() {
        return Ok(newest);
    }
    Err("look for the latest release: no release found".to_string())
}

/// The files the machine's root certificates are read from.
const ROOT_FILES: [&str; 6] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

pub fn roots() -> RootCertStore {
    let mut store = RootCertStore::empty();
    let mut files: Vec<String> = Vec::new();
    if let Ok(f) = std::env::var("SSL_CERT_FILE")
        && !f.is_empty()
    {
        files.push(f);
    } else {
        files.extend(ROOT_FILES.iter().map(|s| s.to_string()));
    }
    for f in files {
        if let Ok(b) = std::fs::read(&f) {
            for c in CertificateDer::pem_slice_iter(&b).flatten() {
                let _ = store.add(c);
            }
            if !store.is_empty() {
                break;
            }
        }
    }
    store
}

/// An HTTPS GET of path on host, with GitHub's rate limit and statuses
/// worded in the client's own texts.
fn get(host: &str, path: &str) -> Result<Vec<u8>, String> {
    let fail = |e: &dyn std::fmt::Display| format!("look for the latest release: {e}");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| fail(&e))?
        .with_root_certificates(roots())
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_string()).map_err(|e| fail(&e))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), name).map_err(|e| fail(&e))?;
    let deadline = std::time::Instant::now() + CHECK_TIMEOUT;
    let addr = std::net::ToSocketAddrs::to_socket_addrs(&(host, 443))
        .map_err(|e| fail(&e))?
        .next()
        .ok_or_else(|| fail(&"no address"))?;
    let mut tcp =
        std::net::TcpStream::connect_timeout(&addr, CHECK_TIMEOUT).map_err(|e| fail(&e))?;
    let left = deadline
        .saturating_duration_since(std::time::Instant::now())
        .max(Duration::from_millis(1));
    tcp.set_read_timeout(Some(left)).map_err(|e| fail(&e))?;
    tcp.set_write_timeout(Some(left)).map_err(|e| fail(&e))?;
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: armada\r\nAccept: application/vnd.github+json\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes()).map_err(|e| fail(&e))?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 16384];
    loop {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > 4 << 20 {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => break,
            Err(e) => return Err(fail(&e)),
        }
    }
    parse_response(&raw)
}

/// The body of an HTTP/1.1 response, or getJSON's error for its status.
fn parse_response(raw: &[u8]) -> Result<Vec<u8>, String> {
    let fail = |e: &str| format!("look for the latest release: {e}");
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| fail("malformed HTTP response"))?;
    let head = String::from_utf8_lossy(&raw[..end]);
    let body = &raw[end + 4..];
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line.split_once(' ').map_or("", |x| x.1).to_string();
    let code: u16 = status
        .split(' ')
        .next()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let mut chunked = false;
    let mut remaining = String::new();
    let mut reset = String::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let v = v.trim();
            match k.trim().to_ascii_lowercase().as_str() {
                "transfer-encoding" => chunked = v.eq_ignore_ascii_case("chunked"),
                "x-ratelimit-remaining" => remaining = v.to_string(),
                "x-ratelimit-reset" => reset = v.to_string(),
                _ => {}
            }
        }
    }
    if code == 429 || (code == 403 && remaining == "0") {
        let mut msg =
            "look for the latest release: GitHub's limit for requests from this address is reached"
                .to_string();
        if let Ok(n) = reset.parse::<i64>()
            && n > 0
        {
            let t = armada_proto::google::protobuf::Timestamp {
                seconds: n,
                nanos: 0,
            };
            let c = crate::commands::local_civil(&t);
            msg.push_str(&format!(" until {:02}:{:02}", c.hour, c.minute));
        }
        return Err(msg);
    }
    if code != 200 {
        return Err(fail(&status));
    }
    let mut body = if chunked {
        dechunk(body)
    } else {
        body.to_vec()
    };
    body.truncate(1 << 20);
    Ok(body)
}

fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(eol) = b.windows(2).position(|w| w == b"\r\n") {
        let size_text = String::from_utf8_lossy(&b[..eol]);
        let size_text = size_text.split(';').next().unwrap_or("").trim().to_string();
        let Ok(size) = usize::from_str_radix(&size_text, 16) else {
            break;
        };
        b = &b[eol + 2..];
        if size == 0 || b.len() < size {
            out.extend_from_slice(&b[..size.min(b.len())]);
            break;
        }
        out.extend_from_slice(&b[..size]);
        b = &b[(size + 2).min(b.len())..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert!(is_release("v0.1.0-alpha.3"));
        assert!(!is_release("v0.1.0-alpha.3-2-gabc1234"));
        assert!(!is_release("dev"));
        assert!(newer("v0.1.0", "v0.1.0-alpha.4"));
        assert!(newer("v0.1.0-alpha.10", "v0.1.0-alpha.5"));
        assert!(!newer("v0.1.0-alpha.5", "v0.1.0-alpha.10"));
        assert!(!newer("dev", "v0.1.0"));
    }

    #[test]
    fn responses() {
        let ok = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n[{}]\r\n0\r\n\r\n";
        assert_eq!(parse_response(ok).unwrap(), b"[{}]");
        let limited = b"HTTP/1.1 403 Forbidden\r\nX-RateLimit-Remaining: 0\r\n\r\n";
        assert!(parse_response(limited).unwrap_err().contains("limit"));
        let missing = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            parse_response(missing).unwrap_err(),
            "look for the latest release: 404 Not Found"
        );
    }
}

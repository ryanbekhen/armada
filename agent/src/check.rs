//! The production health check (Go's DefaultCheck): an HTTP GET of a path,
//! or a TCP connect when the path is empty, with Go's error texts, which
//! reach reports as "readiness probe failed: ...". The request follows no
//! redirect and uses no proxy: probes reach the container and nothing else.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A check's future.
pub type CheckFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

/// Runs one health check against addr ("ip:port"): an HTTP GET of path,
/// or a TCP connect when path is empty, within the timeout given.
pub type CheckFn = Arc<dyn Fn(String, String, Duration) -> CheckFuture + Send + Sync>;

/// The production CheckFn.
pub fn default_check() -> CheckFn {
    Arc::new(|addr, path, timeout| Box::pin(check(addr, path, timeout, crate::VERSION)))
}

/// Go's net error text of a failed connect.
fn dial_error(addr: &str, e: &std::io::Error) -> String {
    format!("dial tcp {addr}: connect: {}", armada_fsutil::errno_text(e))
}

/// One check, as DefaultCheck does it.
pub async fn check(
    addr: String,
    path: String,
    timeout: Duration,
    version: &str,
) -> Result<(), String> {
    if path.is_empty() {
        return match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
            Err(_) => Err(format!("dial tcp {addr}: i/o timeout")),
            Ok(Err(e)) => Err(dial_error(&addr, &e)),
            Ok(Ok(_)) => Ok(()),
        };
    }
    let url = format!("http://{addr}{path}");
    let get = |e: String| format!("Get {}: {e}", armada_spec::go::quote(&url));
    let req = async {
        let mut s = TcpStream::connect(&addr)
            .await
            .map_err(|e| get(dial_error(&addr, &e)))?;
        let head = format!(
            "GET {path} HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: armada-probe/{version}\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n"
        );
        s.write_all(head.as_bytes())
            .await
            .map_err(|e| get(armada_fsutil::errno_text(&e)))?;
        // The status line, then at most 4 KiB of the rest.
        let mut buf = Vec::with_capacity(512);
        let mut chunk = [0u8; 512];
        let line_end = loop {
            if let Some(i) = buf.windows(2).position(|w| w == b"\r\n") {
                break i;
            }
            if buf.len() > 4096 {
                return Err(get(
                    "net/http: HTTP/1.x transport connection broken: malformed HTTP response"
                        .into(),
                ));
            }
            let n = s
                .read(&mut chunk)
                .await
                .map_err(|e| get(armada_fsutil::errno_text(&e)))?;
            if n == 0 {
                return Err(get(if buf.is_empty() {
                    "EOF".into()
                } else {
                    "unexpected EOF".into()
                }));
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let line = String::from_utf8_lossy(&buf[..line_end]).into_owned();
        let code = parse_status(&line).ok_or_else(|| {
            get(format!(
                "net/http: HTTP/1.x transport connection broken: malformed HTTP response {}",
                armada_spec::go::quote(&line)
            ))
        })?;
        let mut rest = buf.len();
        while rest < 4096 + line_end {
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => rest += n,
            }
        }
        if !(200..400).contains(&code) {
            return Err(format!("HTTP {code}"));
        }
        Ok(())
    };
    match tokio::time::timeout(timeout, req).await {
        Err(_) => Err(get("context deadline exceeded".into())),
        Ok(r) => r,
    }
}

/// The code of an "HTTP/1.x NNN reason" status line.
fn parse_status(line: &str) -> Option<u16> {
    let rest = line
        .strip_prefix("HTTP/1.1 ")
        .or_else(|| line.strip_prefix("HTTP/1.0 "))?;
    let code = rest.get(..3)?;
    if !code.bytes().all(|b| b.is_ascii_digit()) || rest.len() > 3 && !rest[3..].starts_with(' ') {
        return None;
    }
    code.parse().ok()
}

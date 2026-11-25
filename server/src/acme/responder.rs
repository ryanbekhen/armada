//! The ACME HTTP-01 responder (Go's Serve: an http.Server with the
//! manager's HTTPHandler on the ACME address, 7480 by default): every
//! node's HAProxy forwards `/.well-known/acme-challenge/` from port 80 to
//! the leader's responder, which answers a challenge's key authorization
//! and 404 to anything else. HTTP/1.1, one request per connection, the
//! request head read within 5 seconds (ReadHeaderTimeout) and at most
//! 1 MiB and 4 KiB long (DefaultMaxHeaderBytes).

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::certs::Certs;

const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEADER: usize = (1 << 20) + 4096;

/// Serves until shutdown turns true.
pub async fn serve(lis: TcpListener, certs: Arc<dyn Certs>, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = crate::stopped(&mut shutdown) => return,
            r = lis.accept() => {
                let Ok((conn, _)) = r else { continue };
                let certs = certs.clone();
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(30), handle(conn, certs)).await;
                });
            }
        }
    }
}

/// One request: method, target, Host.
struct Head {
    method: String,
    path: String,
    host: String,
}

fn parse_head(b: &[u8]) -> Option<Head> {
    let text = std::str::from_utf8(b).ok()?;
    let mut lines = text.split("\r\n");
    let first = lines.next()?;
    let mut parts = first.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || !version.starts_with("HTTP/1.") || method.is_empty() {
        return None;
    }
    let mut host = String::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':')
            && k.eq_ignore_ascii_case("host")
        {
            host = v.trim().to_string();
        }
    }
    // An absolute target names the host itself.
    let (path, from_target) = if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        let end = rest.find('/').unwrap_or(rest.len());
        let p = if end == rest.len() { "/" } else { &rest[end..] };
        (p.to_string(), Some(rest[..end].to_string()))
    } else if target.starts_with('/') {
        (target.to_string(), None)
    } else {
        return None;
    };
    if let Some(h) = from_target {
        host = h;
    }
    let path = path.split(['?', '#']).next().unwrap_or("/");
    Some(Head {
        method: method.to_string(),
        path: percent_decode(path)?,
        host,
    })
}

/// URL.Path: the target's escapes decoded.
fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

async fn handle(mut conn: TcpStream, certs: Arc<dyn Certs>) {
    let mut buf = Vec::with_capacity(1024);
    let read = async {
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                return Some(end);
            }
            if buf.len() > MAX_HEADER {
                return None;
            }
            match conn.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    };
    let end = match tokio::time::timeout(HEADER_TIMEOUT, read).await {
        Ok(Some(end)) => end,
        Ok(None) if buf.len() > MAX_HEADER => {
            let _ = conn
                .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n431 Request Header Fields Too Large")
                .await;
            return;
        }
        _ => return,
    };
    let Some(head) = parse_head(&buf[..end]) else {
        let _ = conn
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request")
            .await;
        return;
    };
    let answer = certs
        .http_challenge(&head.method, &head.host, &head.path)
        .await;
    let resp = match answer {
        Some(body) => {
            let mut r = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            r.extend_from_slice(&body);
            r
        }
        // http.NotFoundHandler.
        None => b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-Length: 19\r\nConnection: close\r\n\r\n404 page not found\n".to_vec(),
    };
    let _ = conn.write_all(&resp).await;
    let _ = conn.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_request_heads() {
        let h = parse_head(
            b"GET /.well-known/acme-challenge/abc?x=1 HTTP/1.1\r\nHost: a.test\r\nUser-Agent: x",
        )
        .unwrap();
        assert_eq!(h.method, "GET");
        assert_eq!(h.path, "/.well-known/acme-challenge/abc");
        assert_eq!(h.host, "a.test");
        let h = parse_head(b"GET http://b.test:80/x HTTP/1.1\r\nHost: a.test").unwrap();
        assert_eq!(h.host, "b.test:80");
        assert_eq!(h.path, "/x");
        assert!(parse_head(b"GET x HTTP/1.1").is_none());
    }
}

//! Release downloads for `armadad upgrade`: an HTTPS GET over rustls with
//! the machine's roots, following at most 10 redirects and only to https,
//! the body streamed to a writer (as Go's http.Client with upgrade's
//! CheckRedirect).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls_pki_types::ServerName;

/// Copies the body of url (https) to w, at most limit bytes; returns the
/// bytes copied, or the error text after Go's "download NAME: ".
pub fn https_get(
    url: &str,
    w: &mut dyn Write,
    limit: u64,
    timeout: Duration,
) -> Result<u64, String> {
    let deadline = Instant::now() + timeout;
    let mut url = url.to_string();
    for _ in 0..=10 {
        let (host, port, path) = split_url(&url)?;
        let mut conn = connect(&host, port, deadline)
            .map_err(|e| format!("Get {}: {e}", armada_spec::go::quote(&url)))?;
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Go-http-client/1.1\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        );
        conn.write_all(req.as_bytes())
            .map_err(|e| format!("Get {}: {e}", armada_spec::go::quote(&url)))?;
        let mut r = BufReader::new(conn);
        let mut status = String::new();
        r.read_line(&mut status)
            .map_err(|e| format!("Get {}: {e}", armada_spec::go::quote(&url)))?;
        let status = status
            .trim_end()
            .split_once(' ')
            .map_or("", |x| x.1)
            .to_string();
        let code: u16 = status
            .split(' ')
            .next()
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let mut location = String::new();
        let mut chunked = false;
        let mut length: Option<u64> = None;
        loop {
            let mut line = String::new();
            let n = r.read_line(&mut line).map_err(|e| e.to_string())?;
            let line = line.trim_end();
            if n == 0 || line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                let v = v.trim();
                match k.trim().to_ascii_lowercase().as_str() {
                    "location" => location = v.to_string(),
                    "transfer-encoding" => chunked = v.eq_ignore_ascii_case("chunked"),
                    "content-length" => length = v.parse().ok(),
                    _ => {}
                }
            }
        }
        if matches!(code, 301 | 302 | 303 | 307 | 308) && !location.is_empty() {
            let next = resolve(&url, &location);
            if !next.starts_with("https://") {
                return Err(format!(
                    "Get {}: redirect away from https",
                    armada_spec::go::quote(&next)
                ));
            }
            url = next;
            continue;
        }
        if code != 200 {
            return Err(status);
        }
        let mut body: Box<dyn Read> = if chunked {
            Box::new(Chunked {
                r,
                left: 0,
                done: false,
            })
        } else if let Some(n) = length {
            Box::new(r.take(n))
        } else {
            Box::new(r)
        };
        return std::io::copy(&mut (&mut body).take(limit), w).map_err(|e| e.to_string());
    }
    Err(format!(
        "Get {}: stopped after 10 redirects",
        armada_spec::go::quote(&url)
    ))
}

fn split_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url.strip_prefix("https://").ok_or_else(|| {
        format!(
            "unsupported protocol scheme in {}",
            armada_spec::go::quote(url)
        )
    })?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || h.ends_with(']') => (
            h.to_string(),
            p.parse().map_err(|_| format!("invalid port in {url}"))?,
        ),
        _ => (hostport.to_string(), 443),
    };
    Ok((
        host.trim_matches(['[', ']']).to_string(),
        port,
        path.to_string(),
    ))
}

fn resolve(base: &str, loc: &str) -> String {
    if loc.contains("://") {
        return loc.to_string();
    }
    let Ok((host, port, _)) = split_url(base) else {
        return loc.to_string();
    };
    let hp = if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    };
    if loc.starts_with('/') {
        format!("https://{hp}{loc}")
    } else {
        format!("https://{hp}/{loc}")
    }
}

type Tls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

fn connect(host: &str, port: u16, deadline: Instant) -> Result<Tls, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(armada_client::release::roots())
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let conn = rustls::ClientConnection::new(Arc::new(cfg), name).map_err(|e| e.to_string())?;
    let addr = std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
        .map_err(|e| e.to_string())?
        .next()
        .ok_or("no address")?;
    let left = deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(1));
    let tcp = TcpStream::connect_timeout(&addr, left).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(left))
        .map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(left))
        .map_err(|e| e.to_string())?;
    Ok(rustls::StreamOwned::new(conn, tcp))
}

/// A chunked body.
struct Chunked<R: BufRead> {
    r: R,
    left: u64,
    done: bool,
}

impl<R: BufRead> Read for Chunked<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.done {
            return Ok(0);
        }
        if self.left == 0 {
            let mut line = String::new();
            self.r.read_line(&mut line)?;
            if line.trim().is_empty() {
                line.clear();
                self.r.read_line(&mut line)?;
            }
            let size = line.trim().split(';').next().unwrap_or("").trim();
            self.left = u64::from_str_radix(size, 16).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid chunk size")
            })?;
            if self.left == 0 {
                self.done = true;
                return Ok(0);
            }
        }
        let k = self.left.min(buf.len() as u64) as usize;
        let n = self.r.read(&mut buf[..k])?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF",
            ));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

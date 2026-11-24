//! volbackup.S3: the bucket of a target, path-style, signed with AWS
//! Signature Version 4 from the URL's static keys, as minio-go reaches it
//! for the Go agent: objects written whole with Content-MD5, read whole
//! up to a bound, listed with ListObjectsV2, deleted one at a time, and
//! the bucket's region asked once when the URL names none. The bucket is
//! dialled itself, never through a proxy from the environment, and every
//! address dialled is refused when it reaches the node itself (nodeOnly),
//! whatever name resolved to it. http:// is plain TCP (ParseTarget keeps
//! it to private IP addresses); https:// is TLS 1.2 or 1.3 with the
//! machine's roots, as Go reads them. Errors keep what the bucket answered
//! and never the request's URL or the keys.
//!
//! One connection per Conn, kept alive between its requests; a request
//! the bucket answers with a temporary failure (minio-go's retryable
//! codes and statuses) or that the network fails is tried three times.

use super::gotime::{Instant, parse_rfc3339};
use super::keys::hex;
use super::target::{Target, err_target, node_only, parse_addr};
use crate::runtime::image::http::{base64, read_head, system_roots};
use crate::volume::errno;
use ring::{digest, hmac};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
/// requestTimeout bounds one request; here each read and write.
const IO_TIMEOUT: Duration = Duration::from_secs(300);
const TRIES: usize = 3;
/// What is read of an answer that is not an object: a listing page or
/// an error.
const MAX_ANSWER: usize = 32 << 20;

/// ARMADA_NODE_TEST_BUCKET_ADDR=IP:PORT: tests' bucket, dialled in place
/// of the endpoint and without the nodeOnly refusal (Go's tests set
/// Target.loopback); read only by builds with test hooks.
const TEST_ADDR: &str = "ARMADA_NODE_TEST_BUCKET_ADDR";

#[derive(Debug)]
pub enum Error {
    /// ErrNotExist: a read of a missing object.
    NotExist,
    Other(String),
}

impl Error {
    pub fn text(&self) -> String {
        match self {
            Error::NotExist => "object does not exist".into(),
            Error::Other(s) => s.clone(),
        }
    }
}

/// One listed object.
pub struct Object {
    pub key: String,
    pub size: i64,
    pub modified: Instant,
}

/// The bucket of a target.
pub struct Bucket {
    t: Target,
    tls: Option<Arc<rustls::ClientConfig>>,
    test_addr: Option<SocketAddr>,
    region: Mutex<Option<String>>,
}

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

impl Bucket {
    /// S3. extra_ca: a PEM file trusted besides the machine's roots
    /// (tests only).
    pub fn new(t: Target, extra_ca: Option<&str>) -> Result<Arc<Bucket>, String> {
        let tls = if t.secure {
            let mut roots = rustls::RootCertStore::empty();
            system_roots(&mut roots);
            if let Some(f) = extra_ca {
                use rustls::pki_types::CertificateDer;
                use rustls::pki_types::pem::PemObject;
                let b = std::fs::read(f).map_err(|e| format!("extra CA {f}: {e}"))?;
                for c in CertificateDer::pem_slice_iter(&b) {
                    let c = c.map_err(|e| format!("extra CA {f}: {e}"))?;
                    roots.add(c).map_err(|e| format!("extra CA {f}: {e}"))?;
                }
            }
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let cfg = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| format!("TLS: {e}"))?
                .with_root_certificates(roots)
                .with_no_client_auth();
            Some(Arc::new(cfg))
        } else {
            None
        };
        let test_addr = match crate::hooks::var(TEST_ADDR) {
            Some(a) if !a.is_empty() => Some(
                a.parse::<SocketAddr>()
                    .map_err(|_| format!("{TEST_ADDR}: not IP:PORT"))?,
            ),
            _ => None,
        };
        let region = (!t.region.is_empty()).then(|| t.region.clone());
        Ok(Arc::new(Bucket {
            t,
            tls,
            test_addr,
            region: Mutex::new(region),
        }))
    }

    pub fn conn(self: &Arc<Bucket>) -> Conn {
        Conn {
            b: self.clone(),
            s: None,
        }
    }

    /// The endpoint's host without brackets, and its port.
    fn host_port(&self) -> (String, u16) {
        let e = &self.t.endpoint;
        let default = if self.t.secure { 443 } else { 80 };
        if let Some(r) = e.strip_prefix('[') {
            let (h, after) = r.split_once(']').unwrap_or((r, ""));
            let port = after
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default);
            return (h.to_string(), port);
        }
        match e.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default)),
            None => (e.clone(), default),
        }
    }
}

fn sys_text(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(n) => errno::text(n),
        None if e.kind() == io::ErrorKind::TimedOut => "i/o timeout".into(),
        None => e.to_string(),
    }
}

/// Dials the bucket: every address checked (refuseNodeOnly), the first
/// that connects used.
fn dial(b: &Bucket) -> Result<TcpStream, String> {
    let (host, port) = b.host_port();
    let addrs: Vec<SocketAddr> = match b.test_addr {
        Some(a) => vec![a],
        None => match parse_addr(host.as_bytes()) {
            Some(ip) => vec![SocketAddr::new(ip, port)],
            None => (host.as_str(), port)
                .to_socket_addrs()
                .map_err(|_| format!("dial tcp: lookup {host}: no such host"))?
                .collect(),
        },
    };
    let mut first: Option<String> = None;
    for a in &addrs {
        if b.test_addr.is_none() && node_only(a.ip()) {
            first.get_or_insert(format!(
                "dial tcp {a}: {}",
                err_target(
                    "the bucket's name resolves to a loopback, link-local, or multicast address"
                )
            ));
            continue;
        }
        match TcpStream::connect_timeout(a, DIAL_TIMEOUT) {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                let _ = s.set_read_timeout(Some(IO_TIMEOUT));
                let _ = s.set_write_timeout(Some(IO_TIMEOUT));
                return Ok(s);
            }
            Err(e) => {
                first.get_or_insert(format!("dial tcp {a}: connect: {}", sys_text(&e)));
            }
        }
    }
    Err(first.unwrap_or_else(|| format!("dial tcp: lookup {host}: no such host")))
}

/// An answer read whole.
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// The body went past the bound it was read with.
    over: bool,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A connection to the bucket.
pub struct Conn {
    b: Arc<Bucket>,
    s: Option<BufReader<Box<dyn Stream>>>,
}

/// S3's URI encoding: unreserved characters kept, '/' kept in paths.
fn uri_encode(s: &str, path: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.bytes() {
        if c.is_ascii_alphanumeric()
            || matches!(c, b'-' | b'_' | b'.' | b'~')
            || (path && c == b'/')
        {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

fn sha256_hex(b: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, b).as_ref())
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), msg)
        .as_ref()
        .to_vec()
}

/// A request before it is signed.
struct Req<'a> {
    method: &'a str,
    /// The object's key, "" for the bucket itself.
    key: &'a str,
    query: Vec<(String, String)>,
    body: &'a [u8],
    put: bool,
}

/// minio-go's retryable S3 codes and HTTP statuses.
fn retryable(status: u16, code: &str) -> bool {
    matches!(status, 408 | 429 | 499 | 500 | 502 | 503 | 504 | 520)
        || matches!(
            code,
            "RequestError"
                | "RequestTimeout"
                | "Throttling"
                | "ThrottlingException"
                | "RequestLimitExceeded"
                | "RequestThrottled"
                | "InternalError"
                | "ExpiredToken"
                | "ExpiredTokenException"
                | "SlowDown"
                | "SlowDownWrite"
                | "SlowDownRead"
        )
}

/// An XML text's entities replaced.
fn xml_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest.find(';') else {
            break;
        };
        let ent = &rest[1..end];
        let c = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            e if e.starts_with("#x") => u32::from_str_radix(&e[2..], 16)
                .ok()
                .and_then(char::from_u32),
            e if e.starts_with('#') => e[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match c {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The text of every <tag>...</tag> in s.
fn tags<'a>(s: &'a str, tag: &str) -> Vec<&'a str> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i + open.len()..];
        let Some(j) = after.find(&close) else {
            break;
        };
        out.push(&after[..j]);
        rest = &after[j + close.len()..];
    }
    out
}

fn tag(s: &str, name: &str) -> Option<String> {
    tags(s, name).first().map(|v| xml_text(v))
}

/// What an error answer says, as minio-go reads it
/// (httpRespToErrorResponse): the XML's code, else one made from the
/// status; x-minio-error-code wins.
fn error_code(a: &Answer, object: bool) -> (String, String) {
    let body = String::from_utf8_lossy(&a.body);
    let mut code = tag(&body, "Code").unwrap_or_default();
    let mut region = tag(&body, "Region").unwrap_or_default();
    if code.is_empty() {
        code = match a.status {
            404 if object => "NoSuchKey".into(),
            404 => "NoSuchBucket".into(),
            403 => "AccessDenied".into(),
            409 => "Conflict".into(),
            412 => "PreconditionFailed".into(),
            s => format!("{s} {}", reason(s)),
        };
    }
    if let Some(c) = a.header("x-minio-error-code").filter(|c| !c.is_empty()) {
        code = c.to_string();
    }
    region = region.trim().to_string();
    if region.is_empty() {
        region = a.header("x-amz-bucket-region").unwrap_or("").to_string();
    }
    (code, region)
}

/// http.StatusText for the statuses a bucket answers.
fn reason(s: u16) -> &'static str {
    match s {
        400 => "Bad Request",
        401 => "Unauthorized",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Request Entity Too Large",
        416 => "Requested Range Not Satisfiable",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

fn backoff(attempt: usize) {
    // minio-go: 200 ms doubling, at most a second, jittered.
    let ms = (200u64 << attempt).min(1000);
    let jitter = super::keys::random(1).map_or(0, |b| u64::from(b[0]) % (ms / 2 + 1));
    std::thread::sleep(Duration::from_millis(ms - jitter));
}

impl Conn {
    fn connect(&mut self) -> Result<(), String> {
        let tcp = dial(&self.b)?;
        let s: Box<dyn Stream> = match &self.b.tls {
            None => Box::new(tcp),
            Some(cfg) => {
                use rustls::pki_types::ServerName;
                let (host, _) = self.b.host_port();
                let name = match parse_addr(host.as_bytes()) {
                    Some(ip) => ServerName::IpAddress(ip.into()),
                    None => ServerName::try_from(host.clone())
                        .map_err(|e| format!("tls: server name {host}: {e}"))?,
                };
                let conn = rustls::ClientConnection::new(cfg.clone(), name)
                    .map_err(|e| format!("tls: {e}"))?;
                let mut s = rustls::StreamOwned::new(conn, tcp);
                while s.conn.is_handshaking() {
                    s.conn
                        .complete_io(&mut s.sock)
                        .map_err(|e| format!("tls: {e}"))?;
                }
                Box::new(s)
            }
        };
        self.s = Some(BufReader::with_capacity(64 << 10, s));
        Ok(())
    }

    /// Writes a request and reads its answer, on the kept connection or a
    /// new one; a kept connection the bucket closed meanwhile is dialled
    /// again once.
    fn exchange(&mut self, head: &str, body: &[u8], max: usize) -> Result<Answer, String> {
        for again in [true, false] {
            let fresh = self.s.is_none();
            if fresh {
                self.connect()?;
            }
            match self.try_exchange(head, body, max) {
                Ok(a) => return Ok(a),
                Err((e, sent)) => {
                    self.s = None;
                    if fresh || sent || !again {
                        return Err(e);
                    }
                }
            }
        }
        unreachable!("the loop returns")
    }

    /// The error, and whether the bucket answered anything first.
    fn try_exchange(
        &mut self,
        head: &str,
        body: &[u8],
        max: usize,
    ) -> Result<Answer, (String, bool)> {
        let s = self.s.as_mut().expect("connected");
        let w = s.get_mut();
        w.write_all(head.as_bytes())
            .and_then(|()| w.write_all(body))
            .and_then(|()| w.flush())
            .map_err(|e| (format!("write: {}", sys_text(&e)), false))?;
        if s.fill_buf_empty().map_err(|e| (e, false))? {
            return Err(("EOF".into(), false));
        }
        let (status, _, headers) = read_head(s).map_err(|e| (e.msg, true))?;
        let get = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };
        let no_body = head.starts_with("HEAD ")
            || status == 204
            || status == 304
            || (100..200).contains(&status);
        let close = get("connection").is_some_and(|v| v.eq_ignore_ascii_case("close"));
        let chunked =
            get("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        let length = get("content-length").and_then(|v| v.trim().parse::<u64>().ok());
        let mut out = Vec::new();
        let mut over = false;
        let mut keep = !close;
        if !no_body {
            let limit = max as u64 + 1;
            let r: Box<dyn Read + '_> = if chunked {
                Box::new(ChunkedBody {
                    r: &mut *s,
                    left: 0,
                    done: false,
                })
            } else if let Some(n) = length {
                Box::new((&mut *s).take(n))
            } else {
                keep = false;
                Box::new(&mut *s)
            };
            r.take(limit)
                .read_to_end(&mut out)
                .map_err(|e| (format!("read: {}", sys_text(&e)), true))?;
            if out.len() > max {
                over = true;
                keep = false;
                out.truncate(max);
            } else if let Some(n) = length
                && !chunked
                && (out.len() as u64) < n
            {
                return Err(("unexpected EOF".into(), true));
            }
        }
        if !keep {
            self.s = None;
        }
        Ok(Answer {
            status,
            headers,
            body: out,
            over,
        })
    }

    fn region(&mut self, op: &str) -> Result<String, Error> {
        if let Some(r) = self.b.region.lock().expect("region lock").clone() {
            return Ok(r);
        }
        let req = Req {
            method: "GET",
            key: "",
            query: vec![("location".into(), String::new())],
            body: b"",
            put: false,
        };
        let a = self.send(op, &req, "us-east-1", MAX_ANSWER)?;
        let region = if a.status == 200 {
            let body = String::from_utf8_lossy(&a.body);
            let loc = tag(&body, "LocationConstraint")
                .unwrap_or_default()
                .trim()
                .to_string();
            match loc.as_str() {
                "" => "us-east-1".to_string(),
                "EU" => "eu-west-1".to_string(),
                l => l.to_string(),
            }
        } else {
            let (code, region) = error_code(&a, false);
            let server = a.header("server").unwrap_or("");
            match code.as_str() {
                "NotImplemented" if server == "AmazonSnowball" => "snowball".into(),
                "NotImplemented" if server == "cloudflare" => "us-east-1".into(),
                "AuthorizationHeaderMalformed" | "InvalidRegion" | "AccessDenied" => {
                    if region.is_empty() {
                        "us-east-1".into()
                    } else {
                        region
                    }
                }
                _ => {
                    return Err(Error::Other(format!(
                        "bucket: {op}: {code} (HTTP {})",
                        a.status
                    )));
                }
            }
        };
        *self.b.region.lock().expect("region lock") = Some(region.clone());
        Ok(region)
    }

    /// One request, signed for region, tried up to three times while the
    /// network fails or the bucket answers with a temporary failure.
    fn send(&mut self, op: &str, req: &Req, region: &str, max: usize) -> Result<Answer, Error> {
        let mut attempt = 0;
        loop {
            let head = self.head(req, region);
            let res = self.exchange(&head, req.body, max);
            let last = attempt + 1 >= TRIES;
            match res {
                Err(e) if last => return Err(Error::Other(format!("bucket: {op}: {e}"))),
                Err(_) => {}
                Ok(a) if (200..300).contains(&a.status) => return Ok(a),
                Ok(a) => {
                    let (code, _) = error_code(&a, !req.key.is_empty());
                    if last || !retryable(a.status, &code) {
                        return Ok(a);
                    }
                }
            }
            backoff(attempt);
            attempt += 1;
        }
    }

    /// A request's head, signed.
    fn head(&self, req: &Req, region: &str) -> String {
        let t = &self.b.t;
        let path = if req.key.is_empty() {
            format!("/{}", t.bucket)
        } else {
            format!("/{}/{}", t.bucket, req.key)
        };
        let path = uri_encode(&path, true);
        let mut q: Vec<(String, String)> = req
            .query
            .iter()
            .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
            .collect();
        q.sort();
        let query = q
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        let now = Instant::now();
        let date = now.amz_date();
        let payload = sha256_hex(req.body);
        let mut headers: Vec<(&str, String)> = vec![
            ("host", t.endpoint.clone()),
            ("x-amz-content-sha256", payload.clone()),
            ("x-amz-date", date.clone()),
        ];
        if req.put {
            headers.push(("content-md5", base64(&md5(req.body))));
            headers.push(("content-type", "application/octet-stream".into()));
        }
        headers.sort();
        let signed = headers
            .iter()
            .map(|(k, _)| *k)
            .collect::<Vec<_>>()
            .join(";");
        let canonical = format!(
            "{}\n{path}\n{query}\n{}\n{signed}\n{payload}",
            req.method,
            headers
                .iter()
                .map(|(k, v)| format!("{k}:{}\n", v.trim()))
                .collect::<String>()
        );
        let scope = format!("{}/{region}/s3/aws4_request", &date[..8]);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{date}\n{scope}\n{}",
            sha256_hex(canonical.as_bytes())
        );
        let mut key = hmac_sha256(
            format!("AWS4{}", t.secret_key).as_bytes(),
            &date.as_bytes()[..8],
        );
        for part in [region, "s3", "aws4_request"] {
            key = hmac_sha256(&key, part.as_bytes());
        }
        let signature = hex(&hmac_sha256(&key, to_sign.as_bytes()));
        let target = if query.is_empty() {
            path
        } else {
            format!("{path}?{query}")
        };
        let mut head = format!("{} {target} HTTP/1.1\r\n", req.method);
        for (k, v) in &headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str(&format!(
            "authorization: AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}\r\n",
            t.access_key
        ));
        head.push_str("user-agent: armada-node\r\n");
        if req.put || !req.body.is_empty() {
            head.push_str(&format!("content-length: {}\r\n", req.body.len()));
        }
        head.push_str("\r\n");
        head
    }

    fn call(&mut self, op: &str, req: &Req, max: usize) -> Result<Answer, Error> {
        let region = self.region(op)?;
        let a = self.send(op, req, &region, max)?;
        if (200..300).contains(&a.status) {
            return Ok(a);
        }
        let (code, _) = error_code(&a, !req.key.is_empty());
        if code == "NoSuchKey" && op == "read" {
            return Err(Error::NotExist);
        }
        Err(Error::Other(format!(
            "bucket: {op}: {code} (HTTP {})",
            a.status
        )))
    }

    /// Put.
    pub fn put(&mut self, key: &str, data: &[u8]) -> Result<(), Error> {
        let req = Req {
            method: "PUT",
            key,
            query: Vec::new(),
            body: data,
            put: true,
        };
        self.call("write", &req, MAX_ANSWER).map(drop)
    }

    /// Get: NotExist for a missing object, an error for one larger than
    /// max.
    pub fn get(&mut self, key: &str, max: usize) -> Result<Vec<u8>, Error> {
        let req = Req {
            method: "GET",
            key,
            query: Vec::new(),
            body: b"",
            put: false,
        };
        let a = self.call("read", &req, max)?;
        if a.over {
            return Err(Error::Other(format!(
                "bucket: object larger than {max} bytes"
            )));
        }
        Ok(a.body)
    }

    /// Delete.
    pub fn delete(&mut self, key: &str) -> Result<(), Error> {
        let req = Req {
            method: "DELETE",
            key,
            query: Vec::new(),
            body: b"",
            put: false,
        };
        self.call("delete", &req, MAX_ANSWER).map(drop)
    }

    /// List: every object under prefix, in the bucket's order (by key).
    pub fn list(
        &mut self,
        prefix: &str,
        f: &mut dyn FnMut(Object) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut token: Option<String> = None;
        loop {
            let mut query = vec![
                ("list-type".to_string(), "2".to_string()),
                ("prefix".to_string(), prefix.to_string()),
            ];
            if let Some(t) = &token {
                query.push(("continuation-token".into(), t.clone()));
            }
            let req = Req {
                method: "GET",
                key: "",
                query,
                body: b"",
                put: false,
            };
            let a = self.call("list", &req, MAX_ANSWER).map_err(|e| e.text())?;
            if a.over {
                return Err("bucket: list: answer too large".into());
            }
            let body = String::from_utf8_lossy(&a.body).into_owned();
            for c in tags(&body, "Contents") {
                let key = tag(c, "Key").unwrap_or_default();
                let size = tag(c, "Size")
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0);
                let modified = tag(c, "LastModified")
                    .and_then(|m| parse_rfc3339(m.trim()))
                    .unwrap_or(Instant { sec: 0, nsec: 0 });
                f(Object {
                    key,
                    size,
                    modified,
                })?;
            }
            let truncated = tag(&body, "IsTruncated").is_some_and(|v| v.trim() == "true");
            if !truncated {
                return Ok(());
            }
            match tag(&body, "NextContinuationToken").filter(|t| !t.is_empty()) {
                Some(t) => token = Some(t),
                None => {
                    return Err(
                        "bucket: list: a truncated listing without a continuation token".into(),
                    );
                }
            }
        }
    }
}

/// fill_buf on the connection: whether the bucket closed it.
trait FillEmpty {
    fn fill_buf_empty(&mut self) -> Result<bool, String>;
}

impl FillEmpty for BufReader<Box<dyn Stream>> {
    fn fill_buf_empty(&mut self) -> Result<bool, String> {
        match self.fill_buf() {
            Ok(b) => Ok(b.is_empty()),
            Err(e) => Err(format!("read: {}", sys_text(&e))),
        }
    }
}

/// A chunked body.
struct ChunkedBody<R> {
    r: R,
    left: u64,
    done: bool,
}

impl<R: io::BufRead> Read for ChunkedBody<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            let mut line = String::new();
            (&mut self.r).take(4096).read_line(&mut line)?;
            let size = line.trim_end().split(';').next().unwrap_or("").trim();
            self.left = u64::from_str_radix(size, 16).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "malformed chunked encoding")
            })?;
            if self.left == 0 {
                loop {
                    line.clear();
                    if (&mut self.r).take(4096).read_line(&mut line)? == 0
                        || line.trim_end().is_empty()
                    {
                        break;
                    }
                }
                self.done = true;
                return Ok(0);
            }
        }
        let max = buf.len().min(self.left.min(usize::MAX as u64) as usize);
        let n = self.r.read(&mut buf[..max])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF",
            ));
        }
        self.left -= n as u64;
        if self.left == 0 {
            let mut crlf = [0u8; 2];
            self.r.read_exact(&mut crlf)?;
        }
        Ok(n)
    }
}

/// MD5 (RFC 1321), for Content-MD5 only.
pub fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32)
        .collect();
    let (mut a0, mut b0, mut c0, mut d0) = (
        0x6745_2301u32,
        0xefcd_ab89u32,
        0x98ba_dcfeu32,
        0x1032_5476u32,
    );
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_le_bytes());
    for block in msg.chunks(64) {
        let m: Vec<u32> = block
            .chunks(4)
            .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
            .collect();
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    for (i, v) in [a0, b0, c0, d0].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_as_rfc_1321() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            hex(&md5(b"The quick brown fox jumps over the lazy dog")),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
        assert_eq!(hex(&md5(&[b'a'; 1000])), "cabe45dcc9ae5b66ba86600cca6b8ba8");
    }

    #[test]
    fn reads_listings_and_errors() {
        let x = "<ListBucketResult><Contents><Key>a&amp;b</Key><Size>3</Size><LastModified>2023-11-14T22:13:20.000Z</LastModified></Contents><IsTruncated>false</IsTruncated></ListBucketResult>";
        let c = tags(x, "Contents");
        assert_eq!(tag(c[0], "Key").unwrap(), "a&b");
        let a = Answer {
            status: 404,
            headers: Vec::new(),
            body: Vec::new(),
            over: false,
        };
        assert_eq!(error_code(&a, true).0, "NoSuchKey");
        assert_eq!(uri_encode("a b/c~", true), "a%20b/c~");
    }
}

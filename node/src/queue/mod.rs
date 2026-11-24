//! Queue lengths for queue autoscaling rules and queue-triggered jobs
//! (ADR 0034, ADR 0040), as internal/queuelen reads them (ADR 0054 step
//! 5): from inside a replica's or a job sandbox's network namespace, so a
//! rule reaches nothing its app could not reach itself.
//!
//!   armada-node queue redis|rabbitmq
//!       stdin: {"url", "name", "addresses"?, "timeoutMs", and the
//!              namespace as `runtime dial` takes it: "dir", "shimDir",
//!              "id", "proc" for a container or "netns" for a sandbox}
//!       stdout: {"length": N}, {"error": TEXT} with queuelen's texts, or
//!              {"redo": WHY} when Go must read it (a broker named by a
//!              name with no addresses, a zone, a shim that is gone)
//!
//! The URL carries the broker's credentials, so it comes on stdin, never
//! as an argument, and no answer or error repeats it or anything the
//! broker sent back. A broker named by a name is resolved by Go from the
//! same namespace (through the container's nameserver, as queuelen's
//! callers do), and its addresses come in "addresses", tried in order.
//! Go's TestArmadaNodeQueue* (internal/runtime/supervisor) compare the
//! answers with queuelen's against fake brokers.

mod amqp;
mod redis;
pub mod url;

use crate::net::addr::Addr;
use crate::runtime::container::dial::{self, DialRequest, Outcome};
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::fd::FromRawFd;
use std::time::{Duration, Instant};

/// queuelen.MaxLength: the largest length a broker may report.
pub const MAX_LENGTH: i64 = 1 << 40;

pub const ERR_URL: &str = "the URL in the secret is not valid for this rule";
pub const ERR_DIAL: &str = "cannot reach the broker from the replica";
pub const ERR_AUTH: &str = "the broker refused the URL's credentials";
pub const ERR_REPLY: &str = "the broker answered something unexpected";
pub const ERR_MISSING: &str = "the queue does not exist";
pub const ERR_TIMEOUT: &str = "timed out";

#[derive(Deserialize, Default)]
#[serde(default)]
struct Request {
    url: String,
    name: String,
    /// The broker's addresses Go resolved, "IP:PORT" each.
    addresses: Vec<String>,
    #[serde(rename = "timeoutMs")]
    timeout_ms: u64,
    dir: String,
    #[serde(rename = "shimDir")]
    shim_dir: String,
    id: String,
    proc: String,
    netns: String,
}

/// How a reading ended.
#[derive(Debug, PartialEq)]
pub enum Answer {
    Length(i64),
    Error(&'static str),
    Redo(String),
}

/// Where a reading dials: the namespace (entered on first use) and the
/// broker's addresses.
pub struct Dialer<'a> {
    target: &'a DialRequest,
    addresses: &'a [String],
    deadline: Option<Instant>,
    entered: bool,
}

impl Dialer<'_> {
    /// Connects to host:port as queuelen's dialer does: an IP address
    /// directly, a name through the addresses Go resolved.
    pub fn dial(&mut self, host: &[u8], port: &[u8]) -> Result<Conn, Answer> {
        let host = String::from_utf8_lossy(host);
        let mut targets: Vec<(String, String)> = Vec::new();
        if let Some(ip) = Addr::parse(&host) {
            if !ip.zone().is_empty() {
                return Err(Answer::Redo("an address with a zone".into()));
            }
            targets.push((ip.unmap().to_string(), String::from_utf8_lossy(port).into()));
        } else if self.addresses.is_empty() {
            return Err(Answer::Redo("a broker named by a name".into()));
        } else {
            for a in self.addresses {
                let Some((ip, p)) = a.rsplit_once(':') else {
                    return Err(Answer::Error(ERR_DIAL));
                };
                targets.push((
                    ip.trim_start_matches('[').trim_end_matches(']').into(),
                    p.into(),
                ));
            }
        }
        if !self.entered {
            match dial::enter_target(self.target, self.deadline) {
                Ok(()) => self.entered = true,
                Err(Outcome::Redo(why)) => return Err(Answer::Redo(why)),
                Err(_) => return Err(Answer::Error(ERR_DIAL)),
            }
        }
        for (ip, port) in targets {
            // netip.ParseAddrPort: digits only, at most 65535.
            let port = if port.bytes().all(|c| c.is_ascii_digit()) {
                port.parse::<u16>()
            } else {
                "x".parse::<u16>()
            };
            let (Some(addr), Ok(port)) = (Addr::parse(&ip), port) else {
                continue;
            };
            let req = DialRequest {
                kind: "tcp".into(),
                ip: addr.to_string(),
                family: if addr.is4() { 4 } else { 6 },
                port,
                ..Default::default()
            };
            if let Outcome::Connected(fd) = dial::connect(&req, self.deadline) {
                // SAFETY: the connected socket connect returned, owned here.
                let stream = unsafe { TcpStream::from_raw_fd(fd) };
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                return Ok(Conn {
                    stream,
                    deadline: self.deadline,
                });
            }
        }
        Err(Answer::Error(ERR_DIAL))
    }

    pub fn timed_out(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }
}

/// A connection whose reads and writes end at the reading's deadline, as
/// queuelen sets the context's deadline on its connection.
pub struct Conn {
    stream: TcpStream,
    deadline: Option<Instant>,
}

impl Conn {
    fn left(&self) -> std::io::Result<Option<Duration>> {
        match self.deadline {
            None => Ok(None),
            Some(d) => {
                let left = d.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    Err(std::io::ErrorKind::TimedOut.into())
                } else {
                    Ok(Some(left))
                }
            }
        }
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.left()?;
        self.stream.set_read_timeout(left)?;
        self.stream.read(buf)
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let left = self.left()?;
        self.stream.set_write_timeout(left)?;
        self.stream.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A connection, plain or over TLS.
pub trait Stream: Read + Write {}
impl<T: Read + Write> Stream for T {}

/// TLS over conn with the machine's roots, TLS 1.2 or later, verifying
/// server_name as Go's crypto/tls does (an IP address against the
/// certificate's IP addresses). None when the handshake fails.
pub fn tls(conn: Conn, server_name: &[u8]) -> Option<Box<dyn Stream>> {
    use rustls::pki_types::ServerName;
    use std::sync::Arc;
    let mut roots = rustls::RootCertStore::empty();
    crate::runtime::image::http::system_roots(&mut roots);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .ok()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let host = std::str::from_utf8(server_name).ok()?;
    let name = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(host.to_string()).ok()?,
    };
    let c = rustls::ClientConnection::new(Arc::new(config), name).ok()?;
    let mut s = rustls::StreamOwned::new(c, conn);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock).ok()?;
    }
    Some(Box::new(s))
}

fn read(kind: &str, r: &Request) -> Answer {
    let deadline = (r.timeout_ms > 0).then(|| Instant::now() + Duration::from_millis(r.timeout_ms));
    let target = DialRequest {
        dir: r.dir.clone(),
        shim_dir: r.shim_dir.clone(),
        id: r.id.clone(),
        proc: r.proc.clone(),
        netns: r.netns.clone(),
        ..Default::default()
    };
    let mut d = Dialer {
        target: &target,
        addresses: &r.addresses,
        deadline,
        entered: false,
    };
    match kind {
        "redis" => redis::list_length(&mut d, &r.url, &r.name),
        _ => amqp::queue_length(&mut d, &r.url, &r.name),
    }
}

/// armada-node queue redis|rabbitmq.
pub fn command(kind: &str) -> Result<(), String> {
    if kind != "redis" && kind != "rabbitmq" {
        return Err(format!("unknown queue {kind:?}; try redis or rabbitmq"));
    }
    // The request holds the URL: its parse errors never say what it held.
    let r: Request = serde_json::from_slice(&crate::runtime::read_stdin()?)
        .map_err(|_| "read request: not a queue request".to_string())?;
    let out = match read(kind, &r) {
        Answer::Length(n) => serde_json::json!({ "length": n }),
        Answer::Error(e) => serde_json::json!({ "error": e }),
        Answer::Redo(why) => serde_json::json!({ "redo": why }),
    };
    crate::runtime::write_out(&crate::runtime::spec::to_go_json(&out))
}

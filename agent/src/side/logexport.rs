//! Sending app output to the cluster's log endpoint (ADR 0044; Go's
//! logexport.go and internal/logexport): a Loki push endpoint or an
//! OTLP/HTTP logs endpoint, as JSON, gzipped, at least once: what was read
//! is marked sent only after the endpoint took all of it.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use armada_proto::armada::v1 as pb;
use sha2::{Digest, Sha256};

use super::{LogEncoding, LogRecord};
use crate::agent::{Inner, lock};
use crate::runtime::Runtime;

/// How often new output is sent.
pub const LOG_EXPORT_EVERY: Duration = Duration::from_secs(2);
/// The output read per round; a round with more to send goes again at once.
pub const EXPORT_TAIL_BYTES: i64 = 8 << 20;
/// What one request carries at most.
pub const EXPORT_BATCH_RECORDS: usize = 2000;
pub const EXPORT_BATCH_BYTES: usize = 1 << 20;
/// The longest wait after failures.
pub const EXPORT_BACKOFF_MAX: Duration = Duration::from_secs(60);

const MAX_ENDPOINT: usize = 2048;
const MAX_NAME: usize = 256;
/// The longest token.
pub const MAX_TOKEN: usize = 4096;
/// One request's bound.
const PUSH_TIMEOUT: Duration = Duration::from_secs(30);
/// How much of an error reply is read and shown.
const MAX_REPLY: usize = 256;

/// Where logs go (logexport.Config). Debug leaves the token out.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ExportConfig {
    pub format: String,
    pub endpoint: String,
    pub user: String,
    pub tenant: String,
    pub token: Vec<u8>,
}

impl std::fmt::Debug for ExportConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.format, self.endpoint)
    }
}

fn check_format(f: &str) -> Result<(), String> {
    if !f.is_empty() && f != "loki" && f != "otlp" {
        return Err(format!(
            "unsupported log export {} (want loki, otlp, or none)",
            super::quote(f)
        ));
    }
    Ok(())
}

/// net/netip's IsPrivate.
fn private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private(),
        IpAddr::V6(v) => (v.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn check_endpoint(raw: &str) -> Result<(), String> {
    if raw.is_empty() {
        return Err("log export needs --log-endpoint, the push URL".into());
    }
    if raw.len() > MAX_ENDPOINT {
        return Err("log endpoint is too long".into());
    }
    let bad = || {
        "log endpoint must be a URL such as https://logs.example.com/loki/api/v1/push".to_string()
    };
    let fragment = raw.split_once('#').is_some_and(|(_, f)| !f.is_empty());
    let u = armada_node::queue::url::parse(raw).map_err(|_| bad())?;
    if u.host.is_empty() || !u.opaque.is_empty() || fragment {
        return Err(bad());
    }
    if u.user.is_some() || !u.raw_query.is_empty() {
        return Err(
            "log endpoint must not hold credentials or a query; use --log-export-user and --log-token"
                .into(),
        );
    }
    match u.scheme.as_str() {
        "https" => Ok(()),
        "http" => {
            let ip = std::str::from_utf8(u.hostname())
                .ok()
                .and_then(|h| h.parse::<IpAddr>().ok());
            match ip {
                Some(ip) if private_ip(ip) || ip.is_loopback() => Ok(()),
                _ => Err(
                    "http:// log endpoints are only allowed for a private IP address; use https://"
                        .into(),
                ),
            }
        }
        _ => Err("log endpoint must start with https://".into()),
    }
}

fn check_token(t: &[u8]) -> Result<(), String> {
    if t.len() > MAX_TOKEN {
        return Err(format!("log token is longer than {MAX_TOKEN} bytes"));
    }
    if t.iter().any(|&b| b < 0x20 || b == 0x7f) {
        return Err("log token must be one line of printable characters".into());
    }
    Ok(())
}

fn check_name(what: &str, v: &str) -> Result<(), String> {
    if v.len() > MAX_NAME {
        return Err(format!("log export {what} is longer than {MAX_NAME} bytes"));
    }
    if v.chars().any(|r| r < '\u{21}' || r == '\u{7f}' || r == ':') {
        return Err(format!(
            "log export {what} must be printable, with no spaces or colons"
        ));
    }
    Ok(())
}

impl ExportConfig {
    /// logexport.Config.Check.
    pub fn check(&self) -> Result<(), String> {
        check_format(&self.format)?;
        if self.format.is_empty() {
            return Ok(());
        }
        check_endpoint(&self.endpoint)?;
        check_name("user", &self.user)?;
        check_name("tenant", &self.tenant)?;
        if !self.tenant.is_empty() && self.format != "loki" {
            return Err("a log tenant is only for loki".into());
        }
        if !self.user.is_empty() && self.token.is_empty() {
            return Err("a log export user needs a token: --log-token - < FILE".into());
        }
        check_token(&self.token)
    }
}

/// Names where logs go: setting the export again starts over, a new token
/// does not (exportTarget).
pub fn export_target(c: &ExportConfig, set_at: i64) -> String {
    let h = Sha256::digest(
        format!(
            "{}\0{}\0{}\0{}\0{set_at}",
            c.format, c.endpoint, c.user, c.tenant
        )
        .as_bytes(),
    );
    h[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// One line of output with where it came from (logexport.Record).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub time: SystemTime,
    pub stderr: bool,
    pub line: Vec<u8>,
    pub app: String,
    pub space: String,
    pub revision: String,
    pub replica: String,
    pub container: String,
    pub node: String,
}

impl Record {
    fn stream(&self) -> &'static str {
        if self.stderr { "stderr" } else { "stdout" }
    }

    /// The line without its trailing newline, invalid UTF-8 replaced.
    fn text(&self) -> String {
        let l = self.line.strip_suffix(b"\n").unwrap_or(&self.line);
        let mut out = String::new();
        for chunk in l.utf8_chunks() {
            out.push_str(chunk.valid());
            if !chunk.invalid().is_empty() {
                out.push('\u{fffd}');
            }
        }
        out
    }
}

/// A string as Go's encoding/json writes it (HTML escaped).
pub(crate) fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn nanos(t: SystemTime) -> String {
    crate::clock::unix_nanos(t).to_string()
}

fn obj(pairs: &[(&str, String)]) -> String {
    let mut sorted: Vec<&(&str, String)> = pairs.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let body: Vec<String> = sorted
        .iter()
        .map(|(k, v)| format!("{}:{}", json_string(k), json_string(v)))
        .collect();
    format!("{{{}}}", body.join(","))
}

fn attr(k: &str, v: &str) -> String {
    format!(
        "{{\"key\":{},\"value\":{{\"stringValue\":{}}}}}",
        json_string(k),
        json_string(v)
    )
}

/// Renders records in format's JSON (logexport.Encode).
pub fn encode(format: &str, recs: &[Record], now: SystemTime) -> Result<Vec<u8>, String> {
    match format {
        "loki" => Ok(encode_loki(recs).into_bytes()),
        "otlp" => Ok(encode_otlp(recs, now).into_bytes()),
        f => Err(format!("unsupported log export {}", super::quote(f))),
    }
}

fn encode_loki(recs: &[Record]) -> String {
    let mut keys: Vec<String> = Vec::new();
    let mut streams: Vec<(String, Vec<String>)> = Vec::new();
    for r in recs {
        let key = [&r.app, &r.space, &r.container, r.stream(), &r.node]
            .map(|s| s.to_string())
            .join("\0");
        let i = match keys.iter().position(|k| *k == key) {
            Some(i) => i,
            None => {
                keys.push(key);
                let labels = obj(&[
                    ("app", r.app.clone()),
                    ("space", r.space.clone()),
                    ("container", r.container.clone()),
                    ("stream", r.stream().into()),
                    ("node", r.node.clone()),
                    ("source", "armada".into()),
                ]);
                streams.push((labels, Vec::new()));
                streams.len() - 1
            }
        };
        let mut meta = vec![("replica", r.replica.clone())];
        if !r.revision.is_empty() {
            meta.push(("revision", r.revision.clone()));
        }
        streams[i].1.push(format!(
            "[{},{},{}]",
            json_string(&nanos(r.time)),
            json_string(&r.text()),
            obj(&meta)
        ));
    }
    if streams.is_empty() {
        return "{\"streams\":null}".into();
    }
    let s: Vec<String> = streams
        .into_iter()
        .map(|(l, v)| format!("{{\"stream\":{l},\"values\":[{}]}}", v.join(",")))
        .collect();
    format!("{{\"streams\":[{}]}}", s.join(","))
}

fn encode_otlp(recs: &[Record], now: SystemTime) -> String {
    let now = nanos(now);
    let mut keys: Vec<String> = Vec::new();
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for r in recs {
        let key = [&r.space, &r.app, &r.replica, &r.container, &r.node]
            .map(|s| s.to_string())
            .join("\0");
        let i = match keys.iter().position(|k| *k == key) {
            Some(i) => i,
            None => {
                keys.push(key);
                let attrs = [
                    attr("service.name", &r.app),
                    attr("service.namespace", &r.space),
                    attr("service.instance.id", &r.replica),
                    attr("service.version", &r.revision),
                    attr("host.name", &r.node),
                    attr("container.name", &r.container),
                    attr("armada.app", &r.app),
                    attr("armada.space", &r.space),
                    attr("armada.replica", &r.replica),
                    attr("armada.revision", &r.revision),
                    attr("armada.node", &r.node),
                ];
                out.push((attrs.join(","), Vec::new()));
                out.len() - 1
            }
        };
        out[i].1.push(format!(
            "{{\"timeUnixNano\":{},\"observedTimeUnixNano\":{},\"body\":{{\"stringValue\":{}}},\"attributes\":[{}]}}",
            json_string(&nanos(r.time)),
            json_string(&now),
            json_string(&r.text()),
            attr("log.iostream", r.stream())
        ));
    }
    if out.is_empty() {
        return "{\"resourceLogs\":null}".into();
    }
    let res: Vec<String> = out
        .into_iter()
        .map(|(a, recs)| {
            format!(
                "{{\"resource\":{{\"attributes\":[{a}]}},\"scopeLogs\":[{{\"scope\":{{\"name\":\"armada\"}},\"logRecords\":[{}]}}]}}",
                recs.join(",")
            )
        })
        .collect();
    format!("{{\"resourceLogs\":[{}]}}", res.join(","))
}

/// Splits records into requests of at most max_records records and about
/// max_bytes of output each (logexport.Batches).
pub fn batches(recs: &[Record], max_records: usize, max_bytes: usize) -> Vec<&[Record]> {
    let mut out = Vec::new();
    let (mut start, mut size) = (0, 0);
    for (i, r) in recs.iter().enumerate() {
        if i > start && (i - start >= max_records || size + r.line.len() > max_bytes) {
            out.push(&recs[start..i]);
            start = i;
            size = 0;
        }
        size += r.line.len();
    }
    if start < recs.len() {
        out.push(&recs[start..]);
    }
    out
}

/// Makes text one printable line without the token (logexport's clean).
pub fn clean(s: &str, token: &[u8]) -> String {
    let mut s = s.to_string();
    if !token.is_empty() {
        s = s.replace(&*String::from_utf8_lossy(token), "[token]");
    }
    let mapped: String = s
        .chars()
        .map(|r| {
            if r < '\u{20}' || r == '\u{7f}' || r == '\u{fffd}' {
                ' '
            } else {
                r
            }
        })
        .collect();
    let mut s = mapped.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.len() > MAX_REPLY {
        let mut cut = MAX_REPLY;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

/// Pushes requests to one endpoint (logexport.Client).
pub struct Client {
    cfg: ExportConfig,
    tls: Arc<rustls::ClientConfig>,
}

/// The machine's roots, as Go's default HTTP client trusts them.
fn machine_tls() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    armada_node::http::system_roots(&mut roots);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(cfg)
}

impl Client {
    /// Checks cfg and returns a client for it (NewClient).
    pub fn new(
        cfg: ExportConfig,
        tls: Option<Arc<rustls::ClientConfig>>,
    ) -> Result<Client, String> {
        if cfg.format.is_empty() {
            return Err("log export is off".into());
        }
        cfg.check()?;
        Ok(Client {
            cfg,
            tls: tls.unwrap_or_else(machine_tls),
        })
    }

    pub fn format(&self) -> &str {
        &self.cfg.format
    }

    /// Sends records in one request.
    pub async fn push(&self, recs: &[Record]) -> Result<(), String> {
        if recs.is_empty() {
            return Ok(());
        }
        let body = encode(&self.cfg.format, recs, SystemTime::now())?;
        self.push_body(body).await
    }

    /// Sends a request already rendered in the client's format. Errors
    /// never carry the token.
    pub async fn push_body(&self, body: Vec<u8>) -> Result<(), String> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&body).map_err(|e| e.to_string())?;
        let gz = gz.finish().map_err(|e| e.to_string())?;
        let cfg = self.cfg.clone();
        let tls = self.tls.clone();
        let deadline = Instant::now() + PUSH_TIMEOUT;
        let task = tokio::task::spawn_blocking(move || post(&tls, &cfg, &gz, deadline));
        let (status, reply) = match tokio::time::timeout(PUSH_TIMEOUT, task).await {
            Ok(Ok(Ok(r))) => r,
            Ok(Ok(Err(e))) => {
                return Err(format!("log endpoint: {}", clean(&e, &self.cfg.token)));
            }
            Ok(Err(e)) => return Err(format!("log endpoint: {e}")),
            Err(_) => {
                return Err(
                    "log endpoint: context deadline exceeded (Client.Timeout exceeded while awaiting headers)"
                        .into(),
                );
            }
        };
        if status / 100 == 2 {
            return Ok(());
        }
        let mut msg = format!("log endpoint answered {status}");
        let r = clean(&String::from_utf8_lossy(&reply), &self.cfg.token);
        if !r.is_empty() {
            msg.push_str(": ");
            msg.push_str(&r);
        }
        Err(msg)
    }
}

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

fn left(deadline: Instant) -> Result<Duration, String> {
    let d = deadline.saturating_duration_since(Instant::now());
    if d.is_zero() {
        return Err("i/o timeout".into());
    }
    Ok(d)
}

/// An io error as Go's syscall texts word the common ones.
fn io_text(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::ConnectionRefused => "connection refused".into(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => "i/o timeout".into(),
        std::io::ErrorKind::ConnectionReset => "connection reset by peer".into(),
        std::io::ErrorKind::UnexpectedEof => "EOF".into(),
        _ => {
            let s = e.to_string();
            s.split(" (os error").next().unwrap_or(&s).to_lowercase()
        }
    }
}

/// One POST with the export's headers: the status and up to MAX_REPLY
/// bytes of the body. Redirects are not followed: one could carry the
/// token elsewhere.
fn post(
    tls: &Arc<rustls::ClientConfig>,
    cfg: &ExportConfig,
    body: &[u8],
    deadline: Instant,
) -> Result<(u16, Vec<u8>), String> {
    let u =
        armada_node::http::Url::parse(&cfg.endpoint).map_err(|_| "invalid request".to_string())?;
    let port = u.effective_port();
    let addrs: Vec<SocketAddr> = match u.host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => (u.host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| format!("dial tcp: lookup {}: {e}", u.host))?
            .collect(),
    };
    let mut last = format!("dial tcp: lookup {}: no such host", u.host);
    let mut tcp = None;
    for a in addrs {
        match TcpStream::connect_timeout(&a, left(deadline)?) {
            Ok(s) => {
                let t = Some(left(deadline)?);
                let _ = s.set_read_timeout(t);
                let _ = s.set_write_timeout(t);
                tcp = Some(s);
                break;
            }
            Err(e) => last = format!("dial tcp {a}: connect: {}", io_text(&e)),
        }
    }
    let tcp = tcp.ok_or(last)?;
    let mut s: Box<dyn Stream> = if u.scheme == "https" {
        use rustls::pki_types::ServerName;
        let name = match u.host.parse::<IpAddr>() {
            Ok(ip) => ServerName::IpAddress(ip.into()),
            Err(_) => ServerName::try_from(u.host.clone()).map_err(|e| format!("tls: {e}"))?,
        };
        let conn =
            rustls::ClientConnection::new(tls.clone(), name).map_err(|e| format!("tls: {e}"))?;
        let mut st = rustls::StreamOwned::new(conn, tcp);
        while st.conn.is_handshaking() {
            st.conn
                .complete_io(&mut st.sock)
                .map_err(|e| format!("tls: {}", io_text(&e)))?;
        }
        Box::new(st)
    } else {
        Box::new(tcp)
    };
    let mut head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: armada\r\nContent-Length: {}\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n",
        u.path,
        u.authority(),
        body.len()
    );
    if !cfg.user.is_empty() {
        let mut cred = cfg.user.as_bytes().to_vec();
        cred.push(b':');
        cred.extend_from_slice(&cfg.token);
        head.push_str(&format!(
            "Authorization: Basic {}\r\n",
            armada_node::http::base64(&cred)
        ));
    } else if !cfg.token.is_empty() {
        head.push_str(&format!(
            "Authorization: Bearer {}\r\n",
            String::from_utf8_lossy(&cfg.token)
        ));
    }
    if !cfg.tenant.is_empty() {
        head.push_str(&format!("X-Scope-OrgID: {}\r\n", cfg.tenant));
    }
    head.push_str("Connection: close\r\n\r\n");
    s.write_all(head.as_bytes())
        .and_then(|()| s.write_all(body))
        .and_then(|()| s.flush())
        .map_err(|e| io_text(&e))?;
    let mut r = BufReader::new(s);
    let (code, chunked, length) = loop {
        let mut line = String::new();
        r.read_line(&mut line).map_err(|e| io_text(&e))?;
        let mut parts = line.split_whitespace();
        let proto = parts.next().unwrap_or_default();
        let code: u16 = parts
            .next()
            .and_then(|c| c.parse().ok())
            .filter(|_| proto.starts_with("HTTP/"))
            .ok_or_else(|| format!("malformed HTTP response {}", super::quote(line.trim_end())))?;
        let mut chunked = false;
        let mut length: Option<usize> = None;
        loop {
            let mut h = String::new();
            r.read_line(&mut h).map_err(|e| io_text(&e))?;
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                let k = k.trim().to_ascii_lowercase();
                let v = v.trim();
                if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
                    chunked = true;
                } else if k == "content-length" {
                    length = v.parse().ok();
                }
            }
        }
        if (100..200).contains(&code) {
            continue;
        }
        break (code, chunked, length);
    };
    let mut reply = Vec::new();
    if chunked {
        while reply.len() < MAX_REPLY {
            let mut size = String::new();
            if r.read_line(&mut size).unwrap_or(0) == 0 {
                break;
            }
            let n = usize::from_str_radix(size.trim().split(';').next().unwrap_or("0"), 16)
                .unwrap_or(0);
            if n == 0 {
                break;
            }
            let mut chunk = vec![0; n];
            if r.read_exact(&mut chunk).is_err() {
                break;
            }
            reply.extend_from_slice(&chunk);
            let mut crlf = String::new();
            let _ = r.read_line(&mut crlf);
        }
    } else {
        let limit = length.unwrap_or(MAX_REPLY).min(MAX_REPLY);
        let _ = r.by_ref().take(limit as u64).read_to_end(&mut reply);
    }
    reply.truncate(MAX_REPLY);
    Ok((code, reply))
}

/// What the export loop keeps between rounds.
#[derive(Default)]
pub struct ExportState {
    client: Option<Client>,
    current: ExportConfig,
    fails: u32,
    last_err: String,
}

impl<R: Runtime> Inner<R> {
    /// The cluster's log export from the latest assignment, and its target
    /// (exportConfig).
    fn export_config(&self) -> Option<(ExportConfig, String)> {
        let e = lock(&self.side.logs).as_ref()?.export.clone()?;
        if e.format.is_empty() {
            return None;
        }
        let c = ExportConfig {
            format: e.format,
            endpoint: e.endpoint,
            user: e.user,
            tenant: e.tenant,
            token: e.token,
        };
        let t = export_target(&c, e.set_at);
        Some((c, t))
    }

    /// Sends the node's app output every interval (logExportLoop).
    pub(crate) async fn log_export_loop(self: Arc<Self>) {
        if !self.rt.tails_logs() {
            return;
        }
        let mut st = ExportState::default();
        let mut wait = self.cfg.side.log_export;
        loop {
            tokio::time::sleep(wait).await;
            wait = self.export_round(&mut st).await;
        }
    }

    /// One round of the loop; the wait before the next.
    pub(crate) async fn export_round(&self, st: &mut ExportState) -> Duration {
        let every = self.cfg.side.log_export;
        let Some((cfg, target)) = self.export_config() else {
            *st = ExportState::default();
            *lock(&self.side.export) = None;
            return every;
        };
        if st.client.is_none() || st.current != cfg {
            match Client::new(cfg.clone(), self.cfg.side.export_tls.clone()) {
                Ok(c) => {
                    st.client = Some(c);
                    st.current = cfg;
                    st.fails = 0;
                }
                Err(e) => {
                    self.export_failed(e, &mut st.last_err);
                    return every;
                }
            }
        }
        let res = match &st.client {
            Some(c) => self.export_once(c, &target).await,
            None => return every,
        };
        match res {
            Err(e) => {
                st.fails += 1;
                let wait = every
                    .checked_mul(1 << st.fails.min(6))
                    .unwrap_or(EXPORT_BACKOFF_MAX)
                    .min(EXPORT_BACKOFF_MAX);
                self.export_failed(e, &mut st.last_err);
                wait
            }
            Ok(more) => {
                if st.fails > 0 || !st.last_err.is_empty() {
                    self.log.info("log export: sending again", &[]);
                }
                st.fails = 0;
                st.last_err.clear();
                *lock(&self.side.export) = Some(pb::LogExportStatus::default());
                if more { Duration::ZERO } else { every }
            }
        }
    }

    fn export_failed(&self, msg: String, last: &mut String) {
        if msg != *last {
            self.log.warn("log export failed", &[("err", msg.clone())]);
            *last = msg.clone();
        }
        *lock(&self.side.export) = Some(pb::LogExportStatus {
            failing: true,
            error: msg,
        });
    }

    /// Sends one round of new output; whether more may be waiting.
    async fn export_once(&self, client: &Client, target: &str) -> Result<bool, String> {
        let enc = self.rt.encodes_logs().then(|| LogEncoding {
            format: client.format().to_string(),
            node: self.cfg.node_id.clone(),
            batch_records: EXPORT_BATCH_RECORDS as i64,
            batch_bytes: EXPORT_BATCH_BYTES as i64,
        });
        let tail = self
            .rt
            .tail_logs(target, EXPORT_TAIL_BYTES, enc.as_ref())
            .await
            .map_err(|e| e.to_string())?;
        let commit = |c: Option<super::CommitFn>| async move {
            match c {
                Some(c) => c().await.map_err(|e| e.to_string()),
                None => Ok(()),
            }
        };
        if let Some(bodies) = tail.bodies {
            // Read and rendered by the runtime (armada-log).
            for b in bodies {
                client.push_body(b).await?;
            }
            commit(tail.commit).await?;
            return Ok(tail.size >= EXPORT_TAIL_BYTES / 2);
        }
        let mut recs = Vec::with_capacity(tail.records.len());
        let mut size = 0;
        for r in tail.records {
            let LogRecord {
                time,
                stderr,
                data,
                replica,
                container,
                app,
                revision,
            } = r;
            let Some((space, name)) = armada_spec::validate::split_app_id(&app) else {
                continue;
            };
            size += data.len() as i64;
            recs.push(Record {
                time,
                stderr,
                line: data,
                app: name,
                space,
                revision,
                replica,
                container: if container.is_empty() {
                    "app".into()
                } else {
                    container
                },
                node: self.cfg.node_id.clone(),
            });
        }
        for b in batches(&recs, EXPORT_BATCH_RECORDS, EXPORT_BATCH_BYTES) {
            client.push(b).await?;
        }
        commit(tail.commit).await?;
        Ok(size >= EXPORT_TAIL_BYTES / 2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(line: &str, stderr: bool) -> Record {
        Record {
            time: crate::clock::from_unix_nanos(1_700_000_000_000_000_001),
            stderr,
            line: line.as_bytes().to_vec(),
            app: "web".into(),
            space: "default".into(),
            revision: "web-r1".into(),
            replica: "web-r1-a".into(),
            container: "app".into(),
            node: "n1".into(),
        }
    }

    #[test]
    fn loki() {
        let b = encode(
            "loki",
            &[rec("a<b\n", false), rec("c", true)],
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(b).unwrap(),
            r#"{"streams":[{"stream":{"app":"web","container":"app","node":"n1","source":"armada","space":"default","stream":"stdout"},"values":[["1700000000000000001","a\u003cb",{"replica":"web-r1-a","revision":"web-r1"}]]},{"stream":{"app":"web","container":"app","node":"n1","source":"armada","space":"default","stream":"stderr"},"values":[["1700000000000000001","c",{"replica":"web-r1-a","revision":"web-r1"}]]}]}"#
        );
    }

    #[test]
    fn checks() {
        let mut c = ExportConfig {
            format: "loki".into(),
            endpoint: "http://10.0.0.1/push".into(),
            ..Default::default()
        };
        assert!(c.check().is_ok());
        c.endpoint = "http://1.2.3.4/push".into();
        assert!(c.check().unwrap_err().starts_with("http:// log endpoints"));
        c.endpoint = "https://u:p@x/push".into();
        assert!(c.check().unwrap_err().contains("credentials"));
        c.endpoint = "https://x/push".into();
        c.tenant = "t".into();
        assert!(c.check().is_ok());
        c.format = "otlp".into();
        assert_eq!(c.check().unwrap_err(), "a log tenant is only for loki");
        assert_eq!(clean("a\nsecret  b", b"secret"), "a [token] b");
    }

    #[test]
    fn batching() {
        let recs: Vec<Record> = (0..5).map(|_| rec("xx", false)).collect();
        let b = batches(&recs, 2, 100);
        assert_eq!(b.iter().map(|b| b.len()).collect::<Vec<_>>(), vec![2, 2, 1]);
        let b = batches(&recs, 10, 3);
        assert_eq!(b.len(), 5);
    }
}

//! The HTTPS client image pulls use (newResolver, guardRegistryClient):
//! every request, redirect, and token request is HTTPS, at most 10
//! redirects are followed, no connection is made to a link-local,
//! unspecified, multicast, or broadcast address (checked for every
//! address dialled, the proxy's included), and an HTTPS proxy is used only
//! when the environment names one (HTTPS_PROXY, NO_PROXY), tunnelled with
//! CONNECT. Servers are checked against the machine's roots
//! (SSL_CERT_FILE, SSL_CERT_DIR, the distributions' bundles), plus,
//! only when the caller passes one, an extra CA file (tests).
//!
//! HTTP/1.1 with one connection per request; Authorization goes with a
//! redirect only to the same host or a subdomain.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

/// maxRegistryRedirects.
pub const MAX_REDIRECTS: usize = 10;
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// A read that waits this long fails (a separate process must not hang
/// for ever on a silent registry).
const READ_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_HEADER_BYTES: usize = 1 << 20;

pub const ERR_PLAIN: &str = "registry requests must use https";

/// An error and whether containerd retries it (isTransientTransportErr:
/// timeouts and unexpected ends of the connection).
#[derive(Debug)]
pub struct Error {
    pub msg: String,
    pub transient: bool,
}

impl Error {
    fn new(msg: impl Into<String>) -> Error {
        Error {
            msg: msg.into(),
            transient: false,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

fn io_error(context: &str, e: io::Error) -> Error {
    let transient = matches!(
        e.kind(),
        io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
    );
    Error {
        msg: format!("{context}: {e}"),
        transient,
    }
}

/// An absolute http(s) URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    pub userinfo: Option<String>,
    /// Without brackets for IPv6.
    pub host: String,
    pub port: Option<u16>,
    /// Path and query, starting with '/'.
    pub path: String,
}

impl Url {
    pub fn parse(s: &str) -> Result<Url, String> {
        let bad = || format!("invalid URL {:?}", redact(s));
        let (scheme, rest) = s.split_once("://").ok_or_else(bad)?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme.is_empty()
            || !scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
        {
            return Err(bad());
        }
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, mut path) = (&rest[..end], rest[end..].to_string());
        if let Some(i) = path.find('#') {
            path.truncate(i);
        }
        if path.is_empty() || path.starts_with('?') {
            path.insert(0, '/');
        }
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u.to_string()), h),
            None => (None, authority),
        };
        let (host, port) = if let Some(r) = hostport.strip_prefix('[') {
            let (h, after) = r.split_once(']').ok_or_else(bad)?;
            (h.to_string(), after.strip_prefix(':'))
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), Some(p)),
                None => (hostport.to_string(), None),
            }
        };
        if host.is_empty() || host.bytes().any(|b| b <= b' ' || b == b'/' || b == b'\\') {
            return Err(bad());
        }
        let port = match port {
            None | Some("") => None,
            Some(p) => Some(p.parse::<u16>().map_err(|_| bad())?),
        };
        if path.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err(bad());
        }
        Ok(Url {
            scheme,
            userinfo,
            host: host.to_ascii_lowercase(),
            port,
            path,
        })
    }

    pub fn effective_port(&self) -> u16 {
        self.port
            .unwrap_or(if self.scheme == "http" { 80 } else { 443 })
    }

    /// host[:port] as the Host header and CONNECT write it.
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match self.port {
            Some(p) => format!("{host}:{p}"),
            None => host,
        }
    }

    /// The URL's host and port with the scheme's default filled in.
    fn host_port(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!("{host}:{}", self.effective_port())
    }

    /// A reference (a redirect's Location) resolved against this URL.
    pub fn join(&self, location: &str) -> Result<Url, String> {
        if location.contains("://") {
            return Url::parse(location);
        }
        if let Some(rest) = location.strip_prefix("//") {
            return Url::parse(&format!("{}://{rest}", self.scheme));
        }
        let mut u = self.clone();
        u.userinfo = None;
        if location.starts_with('/') {
            u.path = location.to_string();
        } else if location.starts_with('?') {
            let base = self.path.split('?').next().unwrap_or("/");
            u.path = format!("{base}{location}");
        } else {
            let base = self.path.split('?').next().unwrap_or("/");
            let dir = &base[..base.rfind('/').map_or(0, |i| i + 1)];
            u.path = format!("{dir}{location}");
        }
        if let Some(i) = u.path.find('#') {
            u.path.truncate(i);
        }
        Ok(u)
    }
}

impl std::fmt::Display for Url {
    /// Without user information.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}{}", self.scheme, self.authority(), self.path)
    }
}

/// A URL for messages: the user information and the query (which may hold
/// tokens) left out.
fn redact(s: &str) -> String {
    let s = match s.split_once("://") {
        Some((scheme, rest)) => match rest.split_once('@') {
            Some((_, after)) if !after.contains('/') || rest.find('@') < rest.find('/') => {
                format!("{scheme}://{after}")
            }
            _ => s.to_string(),
        },
        None => s.to_string(),
    };
    match s.split_once('?') {
        Some((base, _)) => format!("{base}?REDACTED"),
        None => s,
    }
}

/// registryAddr: addresses no registry has, whatever name resolved to
/// them.
pub fn registry_addr(a: IpAddr) -> bool {
    let a = match a {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(a),
        v4 => v4,
    };
    match a {
        IpAddr::V4(v4) => {
            !v4.is_link_local()
                && !v4.is_multicast()
                && !v4.is_unspecified()
                && v4 != Ipv4Addr::BROADCAST
        }
        IpAddr::V6(v6) => {
            let link_local_unicast = (v6.segments()[0] & 0xffc0) == 0xfe80;
            !link_local_unicast && !v6.is_multicast() && !v6.is_unspecified()
        }
    }
}

/// registryDialControl's refusal of one address.
pub fn check_dial(addr: &SocketAddr) -> Result<(), Error> {
    let ip = match addr.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(addr.ip()),
        v4 => v4,
    };
    if registry_addr(ip) {
        Ok(())
    } else {
        Err(Error::new(format!("registry address {ip} refused")))
    }
}

/// Dials host:port, every address it resolves to checked before it is
/// dialled; the first that connects wins.
fn dial(host: &str, port: u16) -> Result<TcpStream, Error> {
    let addrs: Vec<SocketAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => (host, port)
            .to_socket_addrs()
            .map_err(|e| Error::new(format!("dial tcp: lookup {host}: {e}")))?
            .collect(),
    };
    let mut first: Option<Error> = None;
    for a in &addrs {
        if let Err(e) = check_dial(a) {
            first.get_or_insert(Error::new(format!("dial tcp {a}: {e}")));
            continue;
        }
        match TcpStream::connect_timeout(a, DIAL_TIMEOUT) {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                keepalive(&s);
                return Ok(s);
            }
            Err(e) => {
                first.get_or_insert(io_error(&format!("dial tcp {a}"), e));
            }
        }
    }
    Err(first.unwrap_or_else(|| Error::new(format!("dial tcp: lookup {host}: no addresses"))))
}

fn keepalive(s: &TcpStream) {
    use std::os::fd::AsRawFd;
    let on: libc::c_int = 1;
    let idle: libc::c_int = 30;
    // SAFETY: plain setsockopt calls on a socket this function borrows.
    unsafe {
        let fd = s.as_raw_fd();
        let size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            (&on as *const libc::c_int).cast(),
            size,
        );
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPIDLE,
            (&idle as *const libc::c_int).cast(),
            size,
        );
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPINTVL,
            (&idle as *const libc::c_int).cast(),
            size,
        );
    }
}

/// The environment's HTTPS proxy (HTTPS_PROXY and NO_PROXY, or their
/// lowercase names), read once.
#[derive(Clone, Debug, Default)]
pub struct Proxy {
    pub https_proxy: Option<Url>,
    pub no_proxy: String,
}

impl Proxy {
    pub fn from_env() -> Proxy {
        let get = |a: &str, b: &str| {
            std::env::var(a)
                .ok()
                .filter(|v| !v.is_empty())
                .or_else(|| std::env::var(b).ok())
                .unwrap_or_default()
        };
        Proxy {
            https_proxy: parse_proxy(&get("HTTPS_PROXY", "https_proxy")),
            no_proxy: get("NO_PROXY", "no_proxy"),
        }
    }

    /// The proxy a request to u goes through, if any.
    pub fn for_url(&self, u: &Url) -> Option<Url> {
        if u.scheme != "https" {
            return None;
        }
        let p = self.https_proxy.as_ref()?;
        use_proxy(&self.no_proxy, &u.host, u.effective_port()).then(|| p.clone())
    }
}

fn parse_proxy(s: &str) -> Option<Url> {
    if s.is_empty() {
        return None;
    }
    match Url::parse(s) {
        Ok(u) => Some(u),
        Err(_) => Url::parse(&format!("http://{s}")).ok(),
    }
}

/// httpproxy's useProxy: false for localhost, loopback addresses, and
/// what NO_PROXY names.
fn use_proxy(no_proxy: &str, host: &str, port: u16) -> bool {
    if host == "localhost" {
        return false;
    }
    let ip = host.parse::<IpAddr>().ok();
    if ip.is_some_and(|ip| ip.is_loopback()) {
        return false;
    }
    let host = host.trim().to_lowercase();
    let port = port.to_string();
    for entry in no_proxy.split(',') {
        let p = entry.trim().to_lowercase();
        if p.is_empty() {
            continue;
        }
        if p == "*" {
            return false;
        }
        if let Some((net, bits)) = p.split_once('/')
            && let (Ok(net), Ok(bits)) = (net.parse::<IpAddr>(), bits.parse::<u8>())
        {
            if ip.is_some_and(|ip| in_cidr(ip, net, bits)) {
                return false;
            }
            continue;
        }
        let (mut phost, pport) = match split_host_port(&p) {
            Some((h, pp)) => {
                if h.is_empty() {
                    continue;
                }
                (h.to_string(), pp.to_string())
            }
            None => (p.clone(), String::new()),
        };
        if let Ok(pip) = phost.parse::<IpAddr>() {
            if ip == Some(pip) && (pport.is_empty() || pport == port) {
                return false;
            }
            continue;
        }
        if phost.is_empty() {
            continue;
        }
        if let Some(rest) = phost.strip_prefix("*.") {
            phost = format!(".{rest}");
        }
        let mut match_host = false;
        if !phost.starts_with('.') {
            match_host = true;
            phost = format!(".{phost}");
        }
        if (host.ends_with(&phost) || (match_host && host == phost[1..]))
            && (pport.is_empty() || pport == port)
        {
            return false;
        }
    }
    true
}

/// net.SplitHostPort for NO_PROXY entries.
fn split_host_port(s: &str) -> Option<(&str, &str)> {
    if let Some(r) = s.strip_prefix('[') {
        let (h, after) = r.split_once(']')?;
        return Some((h, after.strip_prefix(':')?));
    }
    let (h, p) = s.rsplit_once(':')?;
    if h.contains(':') {
        return None;
    }
    Some((h, p))
}

fn in_cidr(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) if bits <= 32 => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) if bits <= 128 => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

/// The machine's root certificates: SSL_CERT_FILE and SSL_CERT_DIR when
/// set, else the distributions' bundle files and directories.
pub fn system_roots(store: &mut rustls::RootCertStore) {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let add_pem = |store: &mut rustls::RootCertStore, b: &[u8]| {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(b)
            .filter_map(Result::ok)
            .collect();
        store.add_parsable_certificates(certs);
    };
    let files: Vec<String> = match std::env::var("SSL_CERT_FILE") {
        Ok(f) if !f.is_empty() => vec![f],
        _ => [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
            "/etc/pki/tls/cacert.pem",
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
            "/etc/ssl/cert.pem",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
    };
    for f in files {
        if let Ok(b) = std::fs::read(&f) {
            add_pem(store, &b);
            break;
        }
    }
    let dirs: Vec<String> = match std::env::var("SSL_CERT_DIR") {
        Ok(d) if !d.is_empty() => d.split(':').map(str::to_string).collect(),
        _ => vec!["/etc/ssl/certs".into(), "/etc/pki/tls/certs".into()],
    };
    for d in dirs {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            // readUniqueDirectoryEntries: a link to a file in the same
            // directory is read once, by its own name.
            if let Ok(target) = std::fs::read_link(&path)
                && !target.to_string_lossy().contains('/')
            {
                continue;
            }
            if let Ok(b) = std::fs::read(&path) {
                add_pem(store, &b);
            }
        }
    }
}

/// The client: TLS settings and the environment's proxy.
pub struct Client {
    tls: Arc<rustls::ClientConfig>,
    proxy: Proxy,
}

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

impl Client {
    /// extra_ca: a PEM file whose certificates are trusted besides the
    /// machine's roots (tests only; nodes never pass one).
    pub fn new(extra_ca: Option<&str>, proxy: Proxy) -> Result<Client, String> {
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
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("TLS: {e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Client {
            tls: Arc::new(tls),
            proxy,
        })
    }

    fn tls_wrap(&self, inner: Box<dyn Stream>, host: &str) -> Result<Box<dyn Stream>, Error> {
        use rustls::pki_types::ServerName;
        let name = match host.parse::<IpAddr>() {
            Ok(ip) => ServerName::IpAddress(ip.into()),
            Err(_) => ServerName::try_from(host.to_string())
                .map_err(|e| Error::new(format!("tls: server name {host}: {e}")))?,
        };
        let conn = rustls::ClientConnection::new(self.tls.clone(), name)
            .map_err(|e| Error::new(format!("tls: {e}")))?;
        let mut s = rustls::StreamOwned::new(conn, inner);
        while s.conn.is_handshaking() {
            s.conn
                .complete_io(&mut s.sock)
                .map_err(|e| io_error("tls: handshake", e))?;
        }
        Ok(Box::new(s))
    }

    /// One connection to u, through the proxy when the environment names
    /// one for it.
    fn connect(&self, u: &Url) -> Result<Box<dyn Stream>, Error> {
        if u.scheme != "https" {
            return Err(Error::new(ERR_PLAIN));
        }
        let Some(proxy) = self.proxy.for_url(u) else {
            let tcp = dial(&u.host, u.effective_port())?;
            let _ = tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
            let _ = tcp.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
            let s = self.tls_wrap(
                Box::new(tcp.try_clone().map_err(|e| io_error("dial", e))?),
                &u.host,
            )?;
            let _ = tcp.set_read_timeout(Some(READ_TIMEOUT));
            let _ = tcp.set_write_timeout(Some(READ_TIMEOUT));
            return Ok(s);
        };
        if proxy.scheme != "http" && proxy.scheme != "https" {
            return Err(Error::new(format!(
                "proxy scheme {:?} is not supported",
                proxy.scheme
            )));
        }
        let tcp = dial(&proxy.host, proxy.effective_port())?;
        let _ = tcp.set_read_timeout(Some(READ_TIMEOUT));
        let _ = tcp.set_write_timeout(Some(READ_TIMEOUT));
        let mut s: Box<dyn Stream> = Box::new(tcp);
        if proxy.scheme == "https" {
            s = self.tls_wrap(s, &proxy.host)?;
        }
        let target = u.host_port();
        let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let Some(ui) = &proxy.userinfo {
            let (user, pass) = ui.split_once(':').unwrap_or((ui, ""));
            let cred = format!("{}:{}", percent_decode(user), percent_decode(pass));
            req.push_str(&format!(
                "Proxy-Authorization: Basic {}\r\n",
                base64(cred.as_bytes())
            ));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes())
            .map_err(|e| io_error("proxy: CONNECT", e))?;
        let mut r = BufReader::new(s);
        let (status, reason, _) = read_head(&mut r).map_err(|e| Error {
            msg: format!("proxy: {}", e.msg),
            transient: e.transient,
        })?;
        if status != 200 {
            return Err(Error::new(format!("proxy: {status} {reason}")));
        }
        if !r.buffer().is_empty() {
            return Err(Error::new("proxy: data after the CONNECT response"));
        }
        self.tls_wrap(Box::new(r.into_inner()), &u.host)
    }

    /// Sends one request and follows redirects: at most MAX_REDIRECTS,
    /// HTTPS only, every address checked.
    pub fn send(&self, req: &Request) -> Result<Response, Error> {
        let mut url = req.url.clone();
        let mut method = req.method.clone();
        let mut body = req.body.clone();
        let mut redirects = 0;
        loop {
            if url.scheme != "https" {
                return Err(Error::new(format!(
                    "{} {:?}: {ERR_PLAIN}",
                    op(&method),
                    redact(&url.to_string())
                )));
            }
            let same_host = url.host == req.url.host
                || (!url.host.contains([':', '%'])
                    && url.host.ends_with(&format!(".{}", req.url.host)));
            let headers: Vec<(String, String)> = req
                .headers
                .iter()
                .filter(|(k, _)| {
                    same_host
                        || !["authorization", "www-authenticate", "cookie", "cookie2"]
                            .contains(&k.to_ascii_lowercase().as_str())
                })
                .cloned()
                .collect();
            let resp = self
                .round_trip(&method, &url, &headers, body.as_deref())
                .map_err(|e| Error {
                    msg: format!("{} {:?}: {}", op(&method), redact(&url.to_string()), e.msg),
                    transient: e.transient,
                })?;
            let (keep_method, include_body) = match resp.status {
                301..=303 => (method == "GET" || method == "HEAD", false),
                307 | 308 => (true, true),
                _ => return Ok(resp),
            };
            let Some(loc) = resp.header("location").map(str::to_string) else {
                return Ok(resp);
            };
            let next = url.join(&loc).map_err(Error::new)?;
            if redirects >= MAX_REDIRECTS {
                return Err(Error::new(format!(
                    "{} {:?}: stopped after {MAX_REDIRECTS} redirects",
                    op(&method),
                    redact(&next.to_string())
                )));
            }
            redirects += 1;
            if !keep_method {
                method = "GET".into();
            }
            if !include_body {
                body = None;
            }
            url = next;
        }
    }

    fn round_trip(
        &self,
        method: &str,
        url: &Url,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<Response, Error> {
        let mut s = self.connect(url)?;
        let mut head = format!(
            "{method} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: armada-node\r\nConnection: close\r\n",
            url.path,
            url.authority()
        );
        for (k, v) in headers {
            if v.contains(['\r', '\n']) || k.contains(['\r', '\n', ':']) {
                return Err(Error::new("invalid header"));
            }
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        if let Some(b) = body {
            head.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        head.push_str("\r\n");
        s.write_all(head.as_bytes())
            .and_then(|()| s.write_all(body.unwrap_or_default()))
            .and_then(|()| s.flush())
            .map_err(|e| io_error("write", e))?;
        let mut r = BufReader::with_capacity(64 << 10, s);
        let (status, reason, headers) = read_head(&mut r)?;
        let get = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };
        let no_body =
            method == "HEAD" || status == 204 || status == 304 || (100..200).contains(&status);
        let content_length = get("content-length").and_then(|v| v.trim().parse::<u64>().ok());
        let chunked =
            get("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        let body: Box<dyn Read + Send> = if no_body {
            Box::new(io::empty())
        } else if chunked {
            Box::new(Chunked {
                r,
                left: 0,
                done: false,
            })
        } else if let Some(n) = content_length {
            Box::new(Exact {
                r: r.take(n),
                want: n,
            })
        } else {
            Box::new(r)
        };
        Ok(Response {
            status,
            reason,
            content_length: if chunked { None } else { content_length },
            headers,
            url: url.clone(),
            body,
        })
    }
}

/// The verb an error names for a method ("Get", "Head", ...).
fn op(method: &str) -> String {
    let lower = method.to_ascii_lowercase();
    let mut c = lower.chars();
    match c.next() {
        Some(f) => f.to_ascii_uppercase().to_string() + c.as_str(),
        None => "Get".into(),
    }
}

pub(crate) type Head = (u16, String, Vec<(String, String)>);

pub(crate) fn read_head<R: BufRead>(r: &mut R) -> Result<Head, Error> {
    let mut total = 0usize;
    let mut line = String::new();
    let mut read_line = |line: &mut String| -> Result<(), Error> {
        line.clear();
        let n = r
            .by_ref()
            .take((MAX_HEADER_BYTES - total.min(MAX_HEADER_BYTES)) as u64 + 1)
            .read_line(line)
            .map_err(|e| io_error("read response", e))?;
        if n == 0 {
            return Err(Error {
                msg: "read response: unexpected EOF".into(),
                transient: true,
            });
        }
        total += n;
        if total > MAX_HEADER_BYTES {
            return Err(Error::new("read response: headers too large"));
        }
        Ok(())
    };
    read_line(&mut line)?;
    let status_line = line.trim_end().to_string();
    let mut parts = status_line.splitn(3, ' ');
    let proto = parts.next().unwrap_or("");
    if !proto.starts_with("HTTP/1.") {
        return Err(Error::new(format!(
            "malformed HTTP response {status_line:?}"
        )));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .filter(|s| (100..1000).contains(s))
        .ok_or_else(|| Error::new(format!("malformed HTTP status {status_line:?}")))?;
    let reason = parts.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    loop {
        read_line(&mut line)?;
        let l = line.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((status, reason, headers))
}

/// A body of a known length: an early end is an error.
struct Exact<R> {
    r: io::Take<R>,
    want: u64,
}

impl<R: Read> Read for Exact<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.r.read(buf)?;
        if n == 0 && self.r.limit() > 0 && !buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("body ended {} bytes early of {}", self.r.limit(), self.want),
            ));
        }
        Ok(n)
    }
}

struct Chunked<R> {
    r: R,
    left: u64,
    done: bool,
}

impl<R: BufRead> Read for Chunked<R> {
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
                // Trailers up to the empty line.
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
                "chunked body ended early",
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

pub struct Request {
    pub method: String,
    pub url: Url,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

pub struct Response {
    pub status: u16,
    pub reason: String,
    pub content_length: Option<u64>,
    pub headers: Vec<(String, String)>,
    /// The URL that answered (after redirects).
    pub url: Url,
    pub body: Box<dyn Read + Send>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// The status line's code and reason, e.g. "404 Not Found".
    pub fn status_text(&self) -> String {
        format!("{} {}", self.status, self.reason)
    }
}

pub fn base64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// url.Values.Encode for a form or query: keys sorted, values escaped.
pub fn form_encode(pairs: &[(&str, &str)]) -> String {
    let mut sorted: Vec<&(&str, &str)> = pairs.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    sorted
        .iter()
        .map(|(k, v)| format!("{}={}", query_escape(k), query_escape(v)))
        .collect::<Vec<_>>()
        .join("&")
}

pub fn query_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dial_control_refuses_addresses() {
        for (addr, ok) in [
            ("169.254.169.254:80", false),
            ("[fe80::1]:443", false),
            ("0.0.0.0:443", false),
            ("[::]:443", false),
            ("224.0.0.1:443", false),
            ("255.255.255.255:443", false),
            ("[ff02::1]:443", false),
            ("[::ffff:169.254.169.254]:443", false),
            ("10.0.0.5:443", true),
            ("127.0.0.1:5000", true),
            ("[2001:db8::1]:443", true),
        ] {
            let a: SocketAddr = addr.parse().unwrap();
            assert_eq!(check_dial(&a).is_ok(), ok, "{addr}");
        }
    }

    #[test]
    fn no_proxy_matches() {
        let n = "example.org, .sub.test, *.wild.test, 10.0.0.0/8, 192.168.1.1, [::1]:443, host.test:8443";
        for (host, port, proxied) in [
            ("localhost", 443, false),
            ("127.0.0.1", 443, false),
            ("example.org", 443, false),
            ("a.example.org", 443, false),
            ("badexample.org", 443, true),
            ("sub.test", 443, true),
            ("a.sub.test", 443, false),
            ("a.wild.test", 443, false),
            ("10.1.2.3", 443, false),
            ("11.1.2.3", 443, true),
            ("192.168.1.1", 443, false),
            ("host.test", 8443, false),
            ("host.test", 443, true),
            ("registry.test", 443, true),
        ] {
            assert_eq!(use_proxy(n, host, port), proxied, "{host}:{port}");
        }
        assert!(!use_proxy("*", "registry.test", 443));
    }

    #[test]
    fn urls() {
        let u = Url::parse("https://user:pw@Registry.Test:5000/v2/x?y=1#f").unwrap();
        assert_eq!(u.host, "registry.test");
        assert_eq!(u.to_string(), "https://registry.test:5000/v2/x?y=1");
        assert_eq!(
            u.join("/a").unwrap().to_string(),
            "https://registry.test:5000/a"
        );
        assert_eq!(
            u.join("b").unwrap().to_string(),
            "https://registry.test:5000/v2/b"
        );
        assert_eq!(
            u.join("//cdn.test/c").unwrap().to_string(),
            "https://cdn.test/c"
        );
        assert_eq!(u.join("http://x.test/").unwrap().scheme, "http");
        let v6 = Url::parse("https://[fe80::1]:8443/").unwrap();
        assert_eq!(v6.host, "fe80::1");
        assert_eq!(v6.authority(), "[fe80::1]:8443");
        assert_eq!(
            redact("https://u:p@h.test/x?token=1"),
            "https://h.test/x?REDACTED"
        );
    }

    #[test]
    fn encodes() {
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64(b"a"), "YQ==");
        assert_eq!(
            form_encode(&[("scope", "repository:a/b:pull"), ("a", "x y")]),
            "a=x+y&scope=repository%3Aa%2Fb%3Apull"
        );
    }
}

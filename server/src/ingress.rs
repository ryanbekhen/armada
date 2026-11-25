//! Ingress (Go's ingress.go and the proxy parts of reconciler.go; ADR
//! 0055, pull request 14): the proxy configuration every node's HAProxy
//! renders, built by each pass from the apps and their replicas (backends,
//! internal and public rules, labelled revisions' backends and weights,
//! local-first, sticky sessions, CORS, client address rules, wake backends,
//! internal TCP routes), with the addresses two apps claim left out
//! (AddressConflict), public routes another app holds left out
//! (RouteConflict), the trusted proxies and PROXY protocol sources without
//! the container ranges, the certificates the manager holds, and the last
//! valid configuration kept when a pass's own is not (ProxyNotUpdated);
//! certificates by reference for agents that fetch them
//! (GetCertificates), custom domains with their TXT proof (ListDomains,
//! VerifyDomain), and the trusted proxies and PROXY protocol sources of
//! SetClusterConfig. Go's proxy.Config.Validate is ported here too: the
//! leader checks what it sends as the agents check what they render.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use armada_proto::armada::v1::{
    Domain as DomainProto, GetCertificatesRequest, GetCertificatesResponse, ListDomainsRequest,
    ListDomainsResponse, ProxyBackend, ProxyCertificate, ProxyConfig, ProxyCors, ProxyRule,
    ProxyServer, ProxyTcpRoute, VerifyDomainRequest,
};
use armada_spec::go::{Addr, Prefix, parse_addr, parse_prefix, quote};
use armada_spec::validate::{
    CORS_METHOD_NAMES, INTERNAL_SUFFIX, MAX_ALLOW, MAX_CORS_HEADERS, MAX_CORS_ORIGINS,
    MAX_IP_RANGES, app_id, check_tcp_port, internal_host, ip_ranges, label_host, parse_ip_range,
    split_app_id, valid_app_id, valid_cors_header, valid_cors_origin, valid_host_name,
    validate_domain, validate_probe_path, validate_route_path,
};
use armada_spec::{App as Spec, INGRESS_EXTERNAL, INGRESS_NONE, Ingress, MAX_REPLICAS};
use armada_store::{App, Domain, Kind, Replica};
use tonic::{Code, Status};

use crate::assign::Revisions;
use crate::certs::Dns;
use crate::events::{NODE, event};
use crate::grpc::Auth;
use crate::netutil::is_private;
use crate::reconcile::{APP, app_event, traffic_weight};
use crate::{Server, store_err};

/// Meta keys of the cluster settings ingress reads.
pub(crate) const META_TRUSTED_PROXIES: &str = "trusted_proxies";
pub(crate) const META_PROXY_PROTOCOL: &str = "proxy_protocol";

/// TXTPrefix: the label under which domain owners publish the
/// verification token.
pub const TXT_PREFIX: &str = "_armada-verify.";
/// defaultVerifyInterval.
pub const DEFAULT_VERIFY_INTERVAL: Duration = Duration::from_secs(60);

const EVENT_DOMAIN: &str = "domain";
const EVENT_CERTIFICATE: &str = "certificate";

// proxy's limits.
const MAX_TIMEOUT_SECONDS: i64 = 3600;
const MAX_BACKENDS: usize = 100_000;
const MAX_RULES: usize = 1_000_000;
const MAX_CERTIFICATES: usize = 100_000;
const MAX_SERVERS: usize = 2 * MAX_REPLICAS as usize;
const MAX_CERTIFICATE_PEM: usize = 64 << 10;
/// proxy.MaxTrustedProxies.
pub(crate) const MAX_TRUSTED_PROXIES: usize = 64;
const MAX_TCP_ROUTES: usize = 100_000;
const MAX_TCP_PORTS: usize = 4096;
const MAX_WEIGHT: i64 = 256;
const MAX_CORS_MAX_AGE_SECONDS: i64 = 86400;
/// maxCertificateNames bounds one GetCertificates call.
const MAX_CERTIFICATE_NAMES: usize = 256;

/// The bridge subnet of clusters without a cluster network.
const LEGACY_CONTAINER_SUBNET: &str = "10.121.0.0/24";

/// proxy.Config, as Go's server builds and validates it.
#[derive(Default)]
pub(crate) struct Px {
    backends: Vec<Backend>,
    rules: Vec<Rule>,
    certificates: Vec<(String, Vec<u8>)>,
    acme_address: String,
    trusted_proxies: Vec<String>,
    tcp: Vec<TcpRoute>,
    plain_http: bool,
    proxy_protocol: Vec<String>,
}

#[derive(Default, Clone)]
struct Backend {
    name: String,
    servers: Vec<Srv>,
    health_path: String,
    wake: bool,
    local_first: bool,
    timeout_seconds: i64,
    ip_allow: Vec<String>,
    ip_deny: Vec<String>,
    sticky: bool,
    cors: Option<Cors>,
}

#[derive(Clone)]
struct Cors {
    origins: Vec<String>,
    methods: Vec<String>,
    headers: Vec<String>,
    expose: Vec<String>,
    max_age_seconds: i64,
    credentials: bool,
}

#[derive(Clone)]
struct Srv {
    name: String,
    address: String,
    weight: i64,
}

#[derive(Clone)]
struct Rule {
    host: String,
    path_prefix: String,
    strip_prefix: bool,
    backend: String,
    internal: bool,
    allow: Vec<String>,
}

#[derive(Clone)]
struct TcpRoute {
    port: i64,
    backend: String,
    allow: Vec<String>,
}

/// proxy.BackendSpace: the space of the app a backend serves, or "".
fn backend_space(backend: &str) -> String {
    let id = backend.split_once("--").map_or(backend, |(_, id)| id);
    split_app_id(id).map(|(p, _)| p).unwrap_or_default()
}

/// netip.ParseAddrPort with its canonical text, or None.
pub(crate) fn parse_addr_port(s: &str) -> Option<(Addr, u16, String)> {
    let i = s.rfind(':')?;
    let (host, port) = (&s[..i], &s[i + 1..]);
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let p: u32 = port.parse().ok()?;
    let p = u16::try_from(p).ok()?;
    let (ip, v6) = match host.strip_prefix('[') {
        Some(h) => (parse_addr(h.strip_suffix(']')?)?, true),
        None => (parse_addr(host)?, false),
    };
    if v6 == ip.is4 {
        return None;
    }
    let text = if ip.is4 {
        format!("{}:{p}", ip.string())
    } else {
        format!("[{}]:{p}", ip.string())
    };
    Some((ip, p, text))
}

/// Prefix.Overlaps.
fn overlaps(a: &Prefix, b: &Prefix) -> bool {
    if a.addr.is4 != b.addr.is4 {
        return false;
    }
    let bits = a.bits.min(b.bits);
    if bits == 0 {
        return true;
    }
    Prefix::from(&a.addr, bits).masked().addr.bytes
        == Prefix::from(&b.addr, bits).masked().addr.bytes
}

/// around: the prefixes that make up p without e, which p holds.
fn around(p: &Prefix, e: &Prefix) -> Vec<Prefix> {
    let mut res = Vec::new();
    for bits in p.bits + 1..=e.bits {
        let mut a = e.addr.clone();
        let i = (bits - 1) as usize;
        a.bytes[i / 8] ^= 0x80 >> (i % 8);
        res.push(Prefix::from(&a, bits).masked());
    }
    res
}

/// proxy.ExcludePrefixes.
pub(crate) fn exclude_prefixes(trusted: &[String], out: &[Prefix]) -> Vec<String> {
    let mut cur: Vec<Prefix> = trusted
        .iter()
        .filter_map(|s| parse_prefix(s))
        .map(|p| p.masked())
        .collect();
    for e in out {
        let e = e.masked();
        let mut next = Vec::new();
        for p in cur {
            if !overlaps(&p, &e) {
                next.push(p);
            } else if e.bits <= p.bits {
                // p lies inside e.
            } else {
                next.extend(around(&p, &e));
            }
        }
        cur = next;
    }
    let mut res: Vec<String> = cur.iter().map(Prefix::string).collect();
    res.sort();
    res.dedup();
    res
}

/// parseProxyPrefixes: canonical, sorted, without duplicates; a prefix
/// matching every address is refused.
fn parse_proxy_prefixes(one: &str, many: &str, prefixes: &[String]) -> Result<Vec<String>, String> {
    if prefixes.len() > MAX_TRUSTED_PROXIES {
        return Err(format!("at most {MAX_TRUSTED_PROXIES} {many}"));
    }
    let mut out = Vec::with_capacity(prefixes.len());
    for s in prefixes {
        let Some(p) = parse_prefix(s) else {
            return Err(format!(
                "{one} {}: want an address prefix such as 192.0.2.0/24",
                quote(s)
            ));
        };
        if p.bits == 0 {
            return Err(format!("{one} {} matches every address", quote(s)));
        }
        out.push(p.masked().string());
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// proxy.ParseTrustedProxies.
pub(crate) fn parse_trusted_proxies(p: &[String]) -> Result<Vec<String>, String> {
    parse_proxy_prefixes("trusted proxy", "trusted proxies", p)
}

/// proxy.ParseProxyProtocol.
pub(crate) fn parse_proxy_protocol(p: &[String]) -> Result<Vec<String>, String> {
    parse_proxy_prefixes("PROXY protocol source", "PROXY protocol sources", p)
}

fn join_prefixes(ps: &[Prefix]) -> String {
    ps.iter().map(Prefix::string).collect::<Vec<_>>().join(", ")
}

/// validCORS.
fn valid_cors(c: &Option<Cors>) -> Result<(), String> {
    let Some(c) = c else { return Ok(()) };
    if c.origins.is_empty() || c.origins.len() > MAX_CORS_ORIGINS {
        return Err("cors: 1 to 32 origins".into());
    }
    for o in &c.origins {
        if (o != "*" || c.origins.len() > 1 || c.credentials) && !valid_cors_origin(o) {
            return Err(format!("cors: invalid origin {}", quote(o)));
        }
    }
    if c.methods.is_empty() {
        return Err("cors: no methods".into());
    }
    for m in &c.methods {
        if !CORS_METHOD_NAMES.contains(&m.as_str()) {
            return Err(format!("cors: invalid method {}", quote(m)));
        }
    }
    for list in [&c.headers, &c.expose] {
        if list.len() > MAX_CORS_HEADERS {
            return Err("cors: too many headers".into());
        }
        for h in list {
            if !valid_cors_header(h) {
                return Err(format!("cors: invalid header {}", quote(h)));
            }
        }
    }
    if c.max_age_seconds < 0 || c.max_age_seconds > MAX_CORS_MAX_AGE_SECONDS {
        return Err("cors: max age out of range".into());
    }
    Ok(())
}

/// validIPRules.
fn valid_ip_rules(b: &Backend) -> Result<(), String> {
    if !b.ip_allow.is_empty() && !b.ip_deny.is_empty() {
        return Err("both allowed and denied client addresses".into());
    }
    for list in [&b.ip_allow, &b.ip_deny] {
        if list.len() > MAX_IP_RANGES {
            return Err("too many client address rules".into());
        }
        for s in list {
            match parse_ip_range(s) {
                Ok(p) if p.string() == *s => {}
                _ => {
                    return Err(format!(
                        "client address rule {} is not a canonical prefix",
                        quote(s)
                    ));
                }
            }
        }
    }
    Ok(())
}

/// One PEM block as encoding/pem's Decode finds it: the type and the rest
/// after it, or None when no block is left.
fn pem_decode(data: &[u8]) -> Option<(String, &[u8])> {
    let begin = b"-----BEGIN ";
    let mut rest = data;
    loop {
        let start = if rest.starts_with(begin) {
            0
        } else {
            let i = find(rest, b"\n-----BEGIN ")?;
            i + 1
        };
        rest = &rest[start + begin.len()..];
        let line_end = rest
            .iter()
            .position(|&c| c == b'\n')
            .map_or(rest.len(), |i| i + 1);
        let line = trim_right_ws(&rest[..line_end]);
        let Some(typ) = line.strip_suffix(b"-----") else {
            continue;
        };
        let typ = String::from_utf8_lossy(typ).into_owned();
        let body = &rest[line_end..];
        let end_marker = format!("\n-----END {typ}-----");
        let (end_idx, end_len) = if body.starts_with(&end_marker.as_bytes()[1..]) {
            (0, end_marker.len() - 1)
        } else {
            match find(body, end_marker.as_bytes()) {
                Some(i) => (i, end_marker.len()),
                None => continue,
            }
        };
        let b64: Vec<u8> = body[..end_idx]
            .iter()
            .copied()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let mut after = &body[end_idx + end_len..];
        // The end line's own line break.
        let nl = after
            .iter()
            .position(|&c| c == b'\n')
            .map_or(after.len(), |i| i + 1);
        if trim_right_ws(&after[..nl]).is_empty() {
            after = &after[nl..];
        } else {
            continue;
        }
        if armada_pki::encoding::base64_decode(&b64).is_none() {
            continue;
        }
        return Some((typ, after));
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn trim_right_ws(b: &[u8]) -> &[u8] {
    let mut e = b.len();
    while e > 0 && matches!(b[e - 1], b' ' | b'\t' | b'\r' | b'\n') {
        e -= 1;
    }
    &b[..e]
}

/// checkPEM: a certificate chain followed by one private key.
fn check_pem(b: &[u8]) -> Result<(), String> {
    if b.len() > MAX_CERTIFICATE_PEM {
        return Err("bundle too large".into());
    }
    let (mut certs, mut keys) = (0, 0);
    let mut rest = b;
    while let Some((typ, r)) = pem_decode(rest) {
        rest = r;
        match typ.as_str() {
            "CERTIFICATE" => certs += 1,
            "PRIVATE KEY" | "EC PRIVATE KEY" | "RSA PRIVATE KEY" => keys += 1,
            _ => return Err(format!("unexpected PEM block {}", quote(&typ))),
        }
    }
    if !String::from_utf8_lossy(rest).trim().is_empty() {
        return Err("trailing data after PEM blocks".into());
    }
    if certs == 0 || keys != 1 {
        return Err("bundle must contain a certificate chain and one private key".into());
    }
    Ok(())
}

impl Px {
    fn tcp_ports(&self) -> Vec<i64> {
        let mut out: Vec<i64> = self.tcp.iter().map(|r| r.port).collect();
        out.sort();
        out.dedup();
        out
    }

    /// proxy.Config.Validate: errors joined by line breaks.
    fn validate(&self) -> Result<(), String> {
        let mut errs: Vec<String> = Vec::new();
        if !self.acme_address.is_empty() {
            match parse_addr_port(&self.acme_address) {
                Some((a, _, _)) if is_private(&a) => {}
                _ => errs.push(format!(
                    "acme address {} must be a private ip:port",
                    quote(&self.acme_address)
                )),
            }
        }
        if let Err(e) = parse_proxy_protocol(&self.proxy_protocol) {
            errs.push(e);
        }
        if let Err(e) = parse_trusted_proxies(&self.trusted_proxies) {
            errs.push(e);
        }
        if self.backends.len() > MAX_BACKENDS
            || self.rules.len() > MAX_RULES
            || self.certificates.len() > MAX_CERTIFICATES
        {
            errs.push("configuration exceeds size limits".into());
            return Err(errs.join("\n"));
        }
        let mut backends = BTreeSet::new();
        for b in &self.backends {
            if b.timeout_seconds < 0 || b.timeout_seconds > MAX_TIMEOUT_SECONDS {
                return Err(format!(
                    "backend {}: timeout {} out of range",
                    b.name, b.timeout_seconds
                ));
            }
            if !valid_host_name(&b.name) {
                errs.push(format!("backend {}: invalid name", quote(&b.name)));
                continue;
            }
            if !backends.insert(b.name.clone()) {
                errs.push(format!("duplicate backend {}", quote(&b.name)));
            }
            if let Err(e) = valid_ip_rules(b) {
                errs.push(format!("backend {}: {e}", b.name));
            }
            if let Err(e) = valid_cors(&b.cors) {
                errs.push(format!("backend {}: {e}", b.name));
            }
            if !b.health_path.is_empty()
                && let Err(e) = validate_probe_path(&b.health_path)
            {
                errs.push(format!("backend {}: health path: {e}", b.name));
            }
            if b.servers.len() > MAX_SERVERS {
                errs.push(format!("backend {}: too many servers", b.name));
            }
            let mut seen = BTreeSet::new();
            for s in &b.servers {
                if !server_address_ok(&s.address) {
                    errs.push(format!(
                        "backend {}: server address {} must be a private ip:port",
                        b.name,
                        quote(&s.address)
                    ));
                }
                if s.weight < 0 || s.weight > MAX_WEIGHT {
                    errs.push(format!(
                        "backend {}: server weight must be between 1 and {MAX_WEIGHT}",
                        b.name
                    ));
                }
                if s.name.is_empty() || !seen.insert(s.name.clone()) {
                    errs.push(format!(
                        "backend {}: missing or duplicate server name",
                        b.name
                    ));
                }
            }
        }
        let mut routes = BTreeSet::new();
        for r in &self.rules {
            if r.internal {
                let ok = r
                    .host
                    .strip_suffix(INTERNAL_SUFFIX)
                    .is_some_and(valid_host_name);
                if !ok {
                    errs.push(format!(
                        "internal rule host {} must be <app>{INTERNAL_SUFFIX} or <label>--<app>{INTERNAL_SUFFIX}",
                        quote(&r.host)
                    ));
                }
            } else if let Err(e) = validate_domain(&r.host) {
                errs.push(format!("rule host {}: {e}", quote(&r.host)));
            }
            if let Err(e) = validate_route_path(&r.path_prefix) {
                errs.push(format!("rule path {}: {e}", quote(&r.path_prefix)));
            }
            if !r.allow.is_empty() && !r.internal {
                errs.push(format!(
                    "rule {}{}: only internal rules have callers",
                    r.host, r.path_prefix
                ));
            }
            if r.allow.len() > MAX_ALLOW + 1 {
                errs.push(format!(
                    "rule {}{}: too many callers",
                    r.host, r.path_prefix
                ));
            }
            let space = backend_space(&r.backend);
            for a in &r.allow {
                if split_app_id(a).is_none_or(|(p, _)| p != space) {
                    errs.push(format!(
                        "rule {}{}: caller {} is not an app of space {space}",
                        r.host,
                        r.path_prefix,
                        quote(a)
                    ));
                }
            }
            if r.path_prefix == "/" && r.strip_prefix {
                errs.push(format!("rule {}/: cannot strip the root path", r.host));
            }
            if !backends.contains(&r.backend) {
                errs.push(format!(
                    "rule {}{}: unknown backend {}",
                    r.host,
                    r.path_prefix,
                    quote(&r.backend)
                ));
            }
            if !routes.insert(format!("{}{}", r.host, r.path_prefix)) {
                errs.push(format!("duplicate rule for {}{}", r.host, r.path_prefix));
            }
        }
        errs.extend(self.valid_tcp());
        let mut certs = BTreeSet::new();
        for (name, pem) in &self.certificates {
            if validate_domain(name.strip_prefix("*.").unwrap_or(name)).is_err() {
                errs.push(format!("certificate {}: invalid name", quote(name)));
            }
            if !certs.insert(name.clone()) {
                errs.push(format!("duplicate certificate {}", quote(name)));
            }
            if let Err(e) = check_pem(pem) {
                errs.push(format!("certificate {name}: {e}"));
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("\n"))
        }
    }

    /// validTCP.
    fn valid_tcp(&self) -> Vec<String> {
        let mut errs = Vec::new();
        if self.tcp.len() > MAX_TCP_ROUTES || self.tcp_ports().len() > MAX_TCP_PORTS {
            errs.push("too many TCP routes".to_string());
            return errs;
        }
        let backends: HashMap<&str, &Backend> =
            self.backends.iter().map(|b| (b.name.as_str(), b)).collect();
        let http: BTreeSet<&str> = self.rules.iter().map(|r| r.backend.as_str()).collect();
        let mut routed = BTreeSet::new();
        let mut taken = BTreeSet::new();
        for r in &self.tcp {
            if let Err(e) = check_tcp_port(r.port) {
                errs.push(format!("tcp port {}: {e}", r.port));
            }
            let b = match backends.get(r.backend.as_str()) {
                Some(b) if valid_app_id(&r.backend) => b,
                _ => {
                    errs.push(format!(
                        "tcp port {}: unknown backend {}",
                        r.port,
                        quote(&r.backend)
                    ));
                    continue;
                }
            };
            if http.contains(r.backend.as_str()) || routed.contains(&r.backend) {
                errs.push(format!("tcp backend {}: routed more than once", r.backend));
            }
            routed.insert(r.backend.clone());
            if !b.health_path.is_empty()
                || b.wake
                || b.sticky
                || b.cors.is_some()
                || b.timeout_seconds != 0
                || !b.ip_allow.is_empty()
                || !b.ip_deny.is_empty()
            {
                errs.push(format!("tcp backend {}: has HTTP settings", r.backend));
            }
            let space = backend_space(&r.backend);
            if !taken.insert(format!("{space}/{}", r.port)) {
                errs.push(format!(
                    "tcp port {}: more than one backend of space {space}",
                    r.port
                ));
            }
            if r.allow.len() > MAX_ALLOW + 1 {
                errs.push(format!("tcp backend {}: too many callers", r.backend));
            }
            for a in &r.allow {
                if split_app_id(a).is_none_or(|(p, _)| p != space) || !valid_app_id(a) {
                    errs.push(format!(
                        "tcp backend {}: caller {} is not an app of space {space}",
                        r.backend,
                        quote(a)
                    ));
                }
            }
        }
        errs
    }

    /// Config.ToProto, the certificates with their PEMs.
    fn to_proto(&self) -> ProxyConfig {
        let mut p = ProxyConfig {
            acme_challenge_address: self.acme_address.clone(),
            trusted_proxies: self.trusted_proxies.clone(),
            plain_http: self.plain_http,
            proxy_protocol: self.proxy_protocol.clone(),
            ..Default::default()
        };
        for b in &self.backends {
            p.backends.push(ProxyBackend {
                name: b.name.clone(),
                servers: b
                    .servers
                    .iter()
                    .map(|s| ProxyServer {
                        name: s.name.clone(),
                        address: s.address.clone(),
                        weight: s.weight.max(0) as u32,
                    })
                    .collect(),
                health_path: b.health_path.clone(),
                wake: b.wake,
                local_first: b.local_first,
                timeout_seconds: b.timeout_seconds.clamp(0, MAX_TIMEOUT_SECONDS) as u32,
                ip_allow: b.ip_allow.clone(),
                ip_deny: b.ip_deny.clone(),
                sticky: b.sticky,
                cors: b.cors.as_ref().map(|c| ProxyCors {
                    origins: c.origins.clone(),
                    methods: c.methods.clone(),
                    headers: c.headers.clone(),
                    expose: c.expose.clone(),
                    max_age_seconds: c.max_age_seconds.clamp(0, MAX_CORS_MAX_AGE_SECONDS) as u32,
                    credentials: c.credentials,
                }),
            });
        }
        for r in &self.rules {
            p.rules.push(ProxyRule {
                host: r.host.clone(),
                path_prefix: r.path_prefix.clone(),
                strip_prefix: r.strip_prefix,
                backend: r.backend.clone(),
                internal: r.internal,
                allow: r.allow.clone(),
            });
        }
        for (name, pem) in &self.certificates {
            p.certificates.push(ProxyCertificate {
                name: name.clone(),
                pem: pem.clone(),
                sha256: Vec::new(),
            });
        }
        for r in &self.tcp {
            p.tcp_routes.push(ProxyTcpRoute {
                port: r.port.clamp(0, 65535) as u32,
                backend: r.backend.clone(),
                allow: r.allow.clone(),
            });
        }
        p
    }
}

/// The server address check of Validate.
fn server_address_ok(addr: &str) -> bool {
    matches!(parse_addr_port(addr), Some((a, port, text)) if is_private(&a) && port != 0 && text == addr)
}

/// tcpPorts: the ports of a proxy configuration's TCP routes, sorted.
pub(crate) fn tcp_ports(px: Option<&ProxyConfig>) -> Vec<u32> {
    let mut out: Vec<u32> = px
        .map(|p| p.tcp_routes.iter().map(|r| r.port).collect())
        .unwrap_or_default();
    out.sort();
    out.dedup();
    out
}

fn spec_of(a: &App) -> &Spec {
    a.spec.as_deref().expect("a stored app has a spec")
}

/// rootHost: the host Armada gives a name under the root domain, or "".
fn root_host(name: &str, root: &str) -> String {
    if root.is_empty() {
        return String::new();
    }
    let h = format!("{name}.{root}");
    if validate_domain(&h).is_err() {
        return String::new();
    }
    h
}

/// appHosts: <app>.<root> and the app's verified custom domains, once.
fn app_hosts(app: &App, root: &str, verified: &BTreeSet<String>) -> Vec<String> {
    let mut hosts = Vec::new();
    let h = root_host(&app.name, root);
    if !h.is_empty() {
        hosts.push(h);
    }
    if let Some(ing) = &spec_of(app).ingress {
        for d in &ing.domains {
            if verified.contains(d) && !hosts.contains(d) {
                hosts.push(d.clone());
            }
        }
    }
    hosts
}

/// rootHosts: every host under the root domain an external app or one of
/// its labelled revisions is served at, with its backend.
fn root_hosts(apps: &[App], root: &str) -> HashMap<String, String> {
    let mut hosts = HashMap::new();
    for app in apps {
        let Some(ing) = &spec_of(app).ingress else {
            continue;
        };
        if ing.typ != INGRESS_EXTERNAL || Ingress::tcp(Some(ing)) {
            continue;
        }
        let h = root_host(&app.name, root);
        if !h.is_empty() {
            hosts.insert(h, app.name.clone());
        }
        if app.traffic.is_empty() || app.rolling() {
            continue;
        }
        for t in &app.traffic {
            if t.label.is_empty() {
                continue;
            }
            let name = label_host(&t.label, &app.name);
            let h = root_host(&name, root);
            if !h.is_empty() {
                hosts.insert(h, name);
            }
        }
    }
    hosts
}

/// appRoutes: (path, strip) of each route, "/" without any.
fn app_routes(sp: &Spec) -> Vec<(String, bool)> {
    match &sp.ingress {
        Some(i) if !i.routes.is_empty() => i
            .routes
            .iter()
            .map(|r| (r.path.clone(), r.strip_prefix))
            .collect(),
        _ => vec![("/".to_string(), false)],
    }
}

/// allowedCallers: the app IDs ingress.allow lets call, the app first;
/// empty when it allows its whole space.
fn allowed_callers(id: &str, names: &[String]) -> Vec<String> {
    if names.is_empty() {
        return Vec::new();
    }
    let space = split_app_id(id).map(|(p, _)| p).unwrap_or_default();
    let mut out = vec![id.to_string()];
    out.extend(names.iter().map(|n| app_id(&space, n)));
    out
}

/// underWildcard: host is exactly one label under root.
fn under_wildcard(host: &str, root: &str) -> bool {
    host.strip_suffix(&format!(".{root}"))
        .is_some_and(|l| !l.is_empty() && !l.contains('.'))
}

/// inProxy: r serves app's traffic.
fn in_proxy(app: &App, r: &Replica) -> bool {
    r.app == app.name
        && (r.revision == app.active_revision
            || r.revision == app.target_revision
            || traffic_weight(app, &r.revision) > 0)
        && r.state == armada_store::REPLICA_RUNNING
        && r.ready
        && !r.draining()
        && !r.address.is_empty()
}

/// claimedTwice: the addresses and container IPs replicas of more than one
/// app claim.
fn claimed_twice(replicas: &[Replica]) -> BTreeSet<String> {
    let mut owner: HashMap<String, &str> = HashMap::new();
    let mut out = BTreeSet::new();
    for r in replicas {
        if r.done {
            continue;
        }
        let mut keys = Vec::new();
        if !r.address.is_empty() {
            keys.push(format!("a/{}", r.address));
        }
        if !r.ip.is_empty() {
            keys.push(format!("i/{}", r.ip));
        }
        for key in keys {
            if let Some(a) = owner.get(&key)
                && *a != r.app
            {
                out.insert(key.clone());
            }
            owner.insert(key, &r.app);
        }
    }
    out
}

fn clashes(r: &Replica, clash: &BTreeSet<String>) -> bool {
    (!r.address.is_empty() && clash.contains(&format!("a/{}", r.address)))
        || (!r.ip.is_empty() && clash.contains(&format!("i/{}", r.ip)))
}

/// proxyServers: the servers of app's replicas that pass keep.
fn proxy_servers(
    app: &App,
    replicas: &[&Replica],
    clash: &BTreeSet<String>,
    keep: impl Fn(&Replica) -> bool,
) -> Vec<Srv> {
    let mut out = Vec::new();
    for r in replicas {
        if !keep(r) || clashes(r, clash) {
            continue;
        }
        // One bad address must not invalidate the whole configuration.
        if !valid_host_name(&app.name) || !server_address_ok(&r.address) || r.id.is_empty() {
            continue;
        }
        out.push(Srv {
            name: r.id.clone(),
            address: r.address.clone(),
            weight: 0,
        });
    }
    out
}

/// weighServers: each server's revision weight divided among the
/// revision's servers, scaled to the proxy's weight range.
fn weigh_servers(app: &App, replicas: &[&Replica], servers: &mut [Srv]) {
    let rev_of: HashMap<&str, &str> = replicas
        .iter()
        .map(|r| (r.id.as_str(), r.revision.as_str()))
        .collect();
    let mut count: HashMap<&str, i64> = HashMap::new();
    for s in servers.iter() {
        *count
            .entry(rev_of.get(s.name.as_str()).copied().unwrap_or(""))
            .or_default() += 1;
    }
    for s in servers.iter_mut() {
        let rev = rev_of.get(s.name.as_str()).copied().unwrap_or("");
        let w = traffic_weight(app, rev);
        let n = count[rev];
        s.weight = ((w * MAX_WEIGHT + 50 * n) / (100 * n)).max(1);
    }
}

/// What the leader keeps of the last proxy configurations (Go's
/// lastProxy, lastProxyRefs, servedCerts, lastCertNames).
#[derive(Default)]
pub struct ProxyMemory {
    last: Option<ProxyConfig>,
    last_refs: Option<ProxyConfig>,
}

impl Server {
    async fn meta_prefixes(
        &self,
        key: &str,
        parse: fn(&[String]) -> Result<Vec<String>, String>,
    ) -> Result<Vec<String>, String> {
        match self.store().get_meta(key).await {
            Err(e) if e.kind == Kind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.to_string()),
            Ok(v) if v.is_empty() => Ok(Vec::new()),
            Ok(v) => parse(&v.split(',').map(str::to_string).collect::<Vec<_>>()),
        }
    }

    /// trustedProxies: the prefixes set with SetClusterConfig.
    pub(crate) async fn trusted_proxies(&self) -> Result<Vec<String>, String> {
        self.meta_prefixes(META_TRUSTED_PROXIES, parse_trusted_proxies)
            .await
    }

    /// proxyProtocol: the load balancers that send the PROXY protocol.
    pub(crate) async fn proxy_protocol(&self) -> Result<Vec<String>, String> {
        self.meta_prefixes(META_PROXY_PROTOCOL, parse_proxy_protocol)
            .await
    }

    /// containerRanges: the cluster CIDR, or the default bridge subnet.
    async fn container_ranges(&self) -> Result<Vec<Prefix>, armada_store::Error> {
        match self.store().get_network().await {
            Err(e) if e.kind == Kind::NotFound => Ok(vec![
                parse_prefix(LEGACY_CONTAINER_SUBNET).expect("a valid prefix"),
            ]),
            Err(e) => Err(e),
            Ok(n) => Ok(n.cluster_cidr.into_iter().collect()),
        }
    }

    async fn without_containers(
        &self,
        prefixes: Vec<String>,
        what: &str,
    ) -> Result<Vec<String>, String> {
        if prefixes.is_empty() {
            return Ok(prefixes);
        }
        let ranges = self.container_ranges().await.map_err(|e| e.to_string())?;
        let out = exclude_prefixes(&prefixes, &ranges);
        if out.len() > MAX_TRUSTED_PROXIES {
            return Err(format!(
                "the {what} without the container addresses ({}) are more than {MAX_TRUSTED_PROXIES} prefixes; set narrower ones",
                join_prefixes(&ranges)
            ));
        }
        Ok(out)
    }

    /// checkProxyPrefixes: refuses prefixes of only container addresses,
    /// or too many once those are taken out.
    pub(crate) async fn check_proxy_prefixes(
        &self,
        prefixes: &[String],
        one: &str,
        many: &str,
    ) -> Result<(), Status> {
        let ranges = self.container_ranges().await.map_err(|e| store_err(&e))?;
        for t in prefixes {
            if exclude_prefixes(std::slice::from_ref(t), &ranges).is_empty() {
                return Err(Status::new(
                    Code::InvalidArgument,
                    format!(
                        "{one} {t} holds only the cluster's container addresses ({}); a workload is never a {one}",
                        join_prefixes(&ranges)
                    ),
                ));
            }
        }
        let n = exclude_prefixes(prefixes, &ranges).len();
        if n > MAX_TRUSTED_PROXIES {
            return Err(Status::new(
                Code::InvalidArgument,
                format!(
                    "the {many} without the container addresses ({}) make {n} prefixes, more than {MAX_TRUSTED_PROXIES}; set narrower ones",
                    join_prefixes(&ranges)
                ),
            ));
        }
        Ok(())
    }

    /// addressConflict: records, once until it clears, that an app's
    /// replicas are out of the proxy because another app's claims their
    /// address.
    async fn address_conflict(&self, app: &str, replicas: &[&Replica], clash: &BTreeSet<String>) {
        let hit = if clash.is_empty() {
            None
        } else {
            replicas.iter().find(|r| !r.done && clashes(r, clash))
        };
        let mut e = app_event(APP, app, app, "AddressConflict", "");
        if let Some(h) = hit {
            e.node = h.node_id.clone();
            e.message = format!(
                "replica {} claims an address another app's replica claims too (one of them is stale); both stay out of the proxy until one reports a new address",
                h.id
            );
        }
        self.condition(&format!("address-conflict/{app}"), hit.is_some(), e)
            .await;
    }

    /// appDNS: the DNS token an app's ingress.dns names, pinned by its
    /// active revision (ADR 0047); DNSTokenUnavailable otherwise.
    async fn app_dns(&self, revs: &mut Revisions<'_>, app: &App) -> Option<Dns> {
        let d = spec_of(app)
            .ingress
            .as_ref()
            .and_then(|i| i.dns.clone())
            .unwrap_or_default();
        let mut problem = String::new();
        let mut out = None;
        let res = async {
            let rev = revs.get(&app.active_revision).await?;
            revs.secrets(&rev).await
        }
        .await;
        match res {
            Ok(vals) => match vals.get(&d.token_secret_ref) {
                Some(v) if !v.bytes().is_empty() => {
                    out = Some(Dns {
                        provider: d.provider.clone(),
                        token: String::from_utf8_lossy(v.bytes()).trim().to_string(),
                    });
                }
                _ => {
                    problem = format!("secret {} of ingress.dns is not set", d.token_secret_ref);
                }
            },
            Err(e) => {
                self.0.log.warn(
                    "cannot open the DNS token of an app",
                    &[("app", app.name.clone()), ("err", e.to_string())],
                );
                problem = format!(
                    "secret {} of ingress.dns cannot be read",
                    d.token_secret_ref
                );
            }
        }
        self.condition(
            &format!("dns-token/{}", app.name),
            !problem.is_empty(),
            app_event(
                APP,
                &app.name,
                &app.name,
                "DNSTokenUnavailable",
                &format!("{problem}; certificates of its custom domains use HTTP-01"),
            ),
        )
        .await;
        out
    }

    /// buildProxy: the ingress configuration shared by every node.
    async fn build_proxy(&self, apps: &[App], replicas: &[Replica]) -> Result<Px, String> {
        let root = self.root_domain().await;
        let domains = self
            .store()
            .list_domains()
            .await
            .map_err(|e| e.to_string())?;
        let verified: BTreeSet<String> = domains
            .iter()
            .filter(|d| d.verified)
            .map(|d| d.name.clone())
            .collect();
        let sources = self.proxy_protocol().await?;
        let sources = self
            .without_containers(sources, "PROXY protocol sources")
            .await?;
        let trusted = self.trusted_proxies().await?;
        let trusted = self.without_containers(trusted, "trusted proxies").await?;
        let mut cfg = Px {
            trusted_proxies: trusted,
            plain_http: self.0.plain_http,
            proxy_protocol: sources,
            ..Default::default()
        };
        let certs = self.0.certs.clone();
        let mut cert_names: Vec<String> = Vec::new();
        let wildcard = certs.as_ref().is_some_and(|c| c.supports_wildcard()) && !root.is_empty();
        if wildcard {
            cert_names.push(format!("*.{root}"));
        }
        let mut per_app: HashMap<&str, Vec<&Replica>> = HashMap::new();
        for r in replicas {
            per_app.entry(r.app.as_str()).or_default().push(r);
        }
        let mut revs = Revisions::new(self);
        let mut dns_for: BTreeMap<String, Dns> = BTreeMap::new();
        let mut tcp_taken: HashMap<String, String> = HashMap::new();
        let clash = claimed_twice(replicas);
        let roots = root_hosts(apps, &root);
        let mut owner: HashMap<String, String> = HashMap::new();
        let mut conflicts: HashMap<String, String> = HashMap::new();
        // publicRoutes.add and the conflict it may record.
        let mut public = |app: &str, r: &Rule| -> bool {
            let taken = match roots.get(&r.host) {
                Some(b) if *b != r.backend => Some(b.clone()),
                _ => {
                    let key = format!("{}{}", r.host, r.path_prefix);
                    match owner.get(&key) {
                        Some(b) => Some(b.clone()),
                        None => {
                            owner.insert(key, r.backend.clone());
                            None
                        }
                    }
                }
            };
            match taken {
                None => true,
                Some(o) => {
                    if o != r.backend && !conflicts.contains_key(app) {
                        conflicts.insert(
                            app.to_string(),
                            format!(
                                "{}{} is routed to app {o}, so this app does not serve it; remove it from ingress.domains",
                                r.host, r.path_prefix
                            ),
                        );
                    }
                    false
                }
            }
        };
        let none: Vec<&Replica> = Vec::new();
        for app in apps {
            let reps = per_app.get(app.name.as_str()).unwrap_or(&none);
            self.address_conflict(&app.name, reps, &clash).await;
            let sp = spec_of(app);
            let Some(ing) = sp.ingress.as_ref().filter(|i| i.typ != INGRESS_NONE) else {
                continue;
            };
            if Ingress::tcp(Some(ing)) {
                let key = format!("{}/{}", backend_space(&app.name), ing.port);
                if let Some(o) = tcp_taken.get(&key) {
                    self.0.log.warn(
                        "TCP port taken by another app of the space",
                        &[
                            ("app", app.name.clone()),
                            ("port", ing.port.to_string()),
                            ("owner", o.clone()),
                        ],
                    );
                    continue;
                }
                tcp_taken.insert(key, app.name.clone());
                cfg.backends.push(Backend {
                    name: app.name.clone(),
                    local_first: true,
                    servers: proxy_servers(app, reps, &clash, |r| in_proxy(app, r)),
                    ..Default::default()
                });
                cfg.tcp.push(TcpRoute {
                    port: ing.port,
                    backend: app.name.clone(),
                    allow: allowed_callers(&app.name, &ing.allow),
                });
                continue;
            }
            let splits = !app.traffic.is_empty() && !app.rolling();
            let external = ing.typ == INGRESS_EXTERNAL;
            let mut be = Backend {
                name: app.name.clone(),
                wake: sp.scales_to_zero() && !app.removing,
                local_first: !splits && !ing.sticky,
                timeout_seconds: ing.timeout.0 / 1_000_000_000,
                sticky: ing.sticky,
                ..Default::default()
            };
            if let Some(r) = sp.probes.as_ref().and_then(|p| p.readiness.as_ref()) {
                be.health_path = r.path.clone();
            }
            if external {
                be.ip_allow = ip_ranges(&ing.ip_allow);
                be.ip_deny = ip_ranges(&ing.ip_deny);
            }
            if let Some(c) = &ing.cors {
                be.cors = Some(Cors {
                    origins: c.origins().to_vec(),
                    methods: c.cors_methods(),
                    headers: c.allow_headers.clone(),
                    expose: c.expose_headers.clone(),
                    max_age_seconds: c.max_age.0 / 1_000_000_000,
                    credentials: c.allow_credentials,
                });
            }
            be.servers = proxy_servers(app, reps, &clash, |r| in_proxy(app, r));
            if splits {
                weigh_servers(app, reps, &mut be.servers);
            }
            cfg.backends.push(be.clone());
            let allow = allowed_callers(&app.name, &ing.allow);
            let routes = app_routes(sp);
            for (path, strip) in &routes {
                cfg.rules.push(Rule {
                    host: internal_host(&app.name),
                    path_prefix: path.clone(),
                    strip_prefix: *strip,
                    backend: app.name.clone(),
                    internal: true,
                    allow: allow.clone(),
                });
            }
            if splits {
                for t in &app.traffic {
                    if t.label.is_empty() {
                        continue;
                    }
                    let name = label_host(&t.label, &app.name);
                    let mut lb = Backend {
                        name: name.clone(),
                        health_path: be.health_path.clone(),
                        timeout_seconds: be.timeout_seconds,
                        ip_allow: be.ip_allow.clone(),
                        ip_deny: be.ip_deny.clone(),
                        sticky: be.sticky,
                        cors: be.cors.clone(),
                        ..Default::default()
                    };
                    lb.servers = proxy_servers(app, reps, &clash, |r| {
                        r.app == app.name
                            && r.revision == t.revision
                            && r.state == armada_store::REPLICA_RUNNING
                            && r.ready
                            && !r.draining()
                            && !r.address.is_empty()
                    });
                    cfg.backends.push(lb);
                    for (path, strip) in &routes {
                        cfg.rules.push(Rule {
                            host: internal_host(&name),
                            path_prefix: path.clone(),
                            strip_prefix: *strip,
                            backend: name.clone(),
                            internal: true,
                            allow: allow.clone(),
                        });
                    }
                    // Labels serve under the root domain only.
                    let h = format!("{name}.{root}");
                    if !external || root.is_empty() || validate_domain(&h).is_err() {
                        continue;
                    }
                    for (path, strip) in &routes {
                        let r = Rule {
                            host: h.clone(),
                            path_prefix: path.clone(),
                            strip_prefix: *strip,
                            backend: name.clone(),
                            internal: false,
                            allow: Vec::new(),
                        };
                        if public(&app.name, &r) {
                            cfg.rules.push(r);
                        }
                    }
                    if !wildcard {
                        cert_names.push(h);
                    }
                }
            }
            if !external {
                continue;
            }
            // Custom domains with the app's own DNS token (ADR 0047).
            let own = if ing.dns.is_some() {
                self.app_dns(&mut revs, app).await
            } else {
                None
            };
            for h in app_hosts(app, &root, &verified) {
                let mut served = false;
                for (path, strip) in &routes {
                    let r = Rule {
                        host: h.clone(),
                        path_prefix: path.clone(),
                        strip_prefix: *strip,
                        backend: app.name.clone(),
                        internal: false,
                        allow: Vec::new(),
                    };
                    if public(&app.name, &r) {
                        cfg.rules.push(r);
                        served = true;
                    }
                }
                if served && (!wildcard || !under_wildcard(&h, &root)) {
                    cert_names.push(h.clone());
                    if let Some(own) = &own
                        && !dns_for.contains_key(&h)
                        && h != root_host(&app.name, &root)
                    {
                        dns_for.insert(h.clone(), own.clone());
                    }
                }
            }
        }
        for app in apps {
            let msg = conflicts.get(&app.name).cloned().unwrap_or_default();
            self.condition(
                &format!("route-conflict/{}", app.name),
                !msg.is_empty(),
                app_event(APP, &app.name, &app.name, "RouteConflict", &msg),
            )
            .await;
        }
        if let Some(certs) = certs {
            let mut last = self.0.cert_names.lock().await;
            cert_names.sort();
            cert_names.dedup();
            // The credentials count too: a new token starts its names over.
            let mut managed = cert_names.clone();
            for (n, d) in &dns_for {
                managed.push(format!("{n}={}", d.key()));
            }
            if managed != *last {
                match certs.manage(&cert_names, &root, &dns_for).await {
                    Err(e) => self
                        .0
                        .log
                        .error("certificate management failed", &[("err", e)]),
                    Ok(()) => *last = managed,
                }
            }
            for n in &cert_names {
                if let Some(pem) = self.certificate(n).await {
                    cfg.certificates.push((n.clone(), pem));
                }
            }
            cfg.acme_address = self.0.acme_addr.clone();
        }
        cfg.validate()
            .map_err(|e| format!("generated proxy config is invalid: {e}"))?;
        Ok(cfg)
    }

    /// proxyConfig: the pass's proxy configuration, in full and with
    /// certificates by reference; when it cannot be built the nodes keep
    /// the last one that could.
    pub(crate) async fn proxy_config(
        &self,
        apps: &[App],
        replicas: &[Replica],
    ) -> Result<(Option<ProxyConfig>, Option<ProxyConfig>), armada_store::Error> {
        let res = self.build_proxy(apps, replicas).await;
        let msg = match &res {
            Err(e) => format!("the proxy configuration was not updated: {e}"),
            Ok(_) => "the proxy configuration was not updated: <nil>".to_string(),
        };
        self.condition(
            "proxy-invalid",
            res.is_err(),
            event(NODE, "*", "", "ProxyNotUpdated", &msg),
        )
        .await;
        let mut mem = self.0.proxy.lock().unwrap_or_else(|p| p.into_inner());
        match res {
            Ok(px) => {
                let full = px.to_proto();
                let mut refs = full.clone();
                refs.certificates.clear();
                let mut served = BTreeSet::new();
                for (name, pem) in &px.certificates {
                    refs.certificates.push(ProxyCertificate {
                        name: name.clone(),
                        pem: Vec::new(),
                        sha256: ring::digest::digest(&ring::digest::SHA256, pem)
                            .as_ref()
                            .to_vec(),
                    });
                    served.insert(name.clone());
                }
                *self
                    .0
                    .served_certs
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = served;
                mem.last = Some(full);
                mem.last_refs = Some(refs);
                Ok((mem.last.clone(), mem.last_refs.clone()))
            }
            Err(e) => {
                self.0
                    .log
                    .error("proxy configuration not updated", &[("err", e.clone())]);
                if mem.last.is_none() {
                    return Err(armada_store::Error::other(e));
                }
                Ok((mem.last.clone(), mem.last_refs.clone()))
            }
        }
    }

    /// certificate: the certificate for name, read from the manager once
    /// and kept until it obtains it again ([`Server::certificate_event`]).
    pub(crate) async fn certificate(&self, name: &str) -> Option<Vec<u8>> {
        if let Some(p) = self
            .0
            .pems
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(name)
        {
            return Some(p.clone());
        }
        let certs = self.0.certs.as_ref()?;
        let pem = certs.certificate(name).await?;
        self.0
            .pems
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(name.to_string(), pem.clone());
        Some(pem)
    }

    /// CertificateEvent: a certificate was obtained (err None) or obtaining
    /// it failed; the next read takes the new one.
    pub async fn certificate_event(&self, name: &str, err: Option<String>) {
        self.0
            .pems
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(name);
        let e = match err {
            None => event(EVENT_CERTIFICATE, name, "", "Obtained", ""),
            Some(m) => event(EVENT_CERTIFICATE, name, "", "Failed", &m),
        };
        self.record(e).await;
    }

    /// GetCertificates: the certificates an agent's assignment names by
    /// reference, only those the last proxy configuration holds.
    pub(crate) async fn get_certificates(
        &self,
        _a: &Auth,
        req: GetCertificatesRequest,
    ) -> Result<GetCertificatesResponse, Status> {
        if req.names.len() > MAX_CERTIFICATE_NAMES {
            return Err(Status::new(
                Code::InvalidArgument,
                format!("at most {MAX_CERTIFICATE_NAMES} names per call"),
            ));
        }
        let mut resp = GetCertificatesResponse::default();
        if self.0.certs.is_none() {
            return Ok(resp);
        }
        let served = self
            .0
            .served_certs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mut seen = BTreeSet::new();
        for n in req.names {
            if seen.contains(&n) || !served.contains(&n) {
                continue;
            }
            seen.insert(n.clone());
            if let Some(pem) = self.certificate(&n).await {
                resp.certificates.push(ProxyCertificate {
                    name: n,
                    pem,
                    sha256: Vec::new(),
                });
            }
        }
        Ok(resp)
    }

    /// ListDomains: custom domains with what their owners must configure.
    pub(crate) async fn list_domains(
        &self,
        a: &Auth,
        req: ListDomainsRequest,
    ) -> Result<ListDomainsResponse, Status> {
        let apps = self.store().list_apps().await.map_err(|e| store_err(&e))?;
        // A rolling app uses the domains of its active and target spec.
        let mut users: HashMap<String, Vec<String>> = HashMap::new();
        for app in &apps {
            let mut specs = vec![app.spec.clone()];
            if app.target_revision != app.active_revision
                && let Ok(rev) = self.store().get_revision(&app.target_revision).await
            {
                specs.push(rev.spec.clone());
            }
            for sp in specs.iter().flatten() {
                let Some(ing) = &sp.ingress else { continue };
                for d in &ing.domains {
                    let u = users.entry(d.clone()).or_default();
                    if !u.contains(&app.name) {
                        u.push(app.name.clone());
                    }
                }
            }
        }
        let domains = self
            .store()
            .list_domains()
            .await
            .map_err(|e| store_err(&e))?;
        if !req.app.is_empty() {
            a.acc.app(&req.app)?;
        }
        let mut resp = ListDomainsResponse::default();
        let none = Vec::new();
        for d in &domains {
            let u = users.get(&d.name).unwrap_or(&none);
            if !req.app.is_empty() && !u.contains(&req.app) {
                continue;
            }
            // Others see a domain only through the apps of theirs that use it.
            let mut apps: Vec<String> = u.iter().filter(|x| a.acc.sees(x)).cloned().collect();
            if apps.is_empty() && !a.acc.admin() {
                continue;
            }
            if a.acc.admin() {
                apps = u.clone();
            }
            resp.domains.push(self.domain_proto(d, apps).await);
        }
        Ok(resp)
    }

    async fn domain_proto(&self, d: &Domain, apps: Vec<String>) -> DomainProto {
        let mut out = DomainProto {
            name: d.name.clone(),
            apps,
            verified: d.verified,
            txt_name: format!("{TXT_PREFIX}{}", d.name),
            txt_value: d.token.clone(),
            message: d.message.clone(),
            tls_ready: false,
        };
        if let Some(certs) = &self.0.certs
            && d.verified
        {
            let mut name = d.name.clone();
            // One label under the root domain: the wildcard certificate.
            let root = self.root_domain().await;
            if certs.supports_wildcard() && !root.is_empty() && under_wildcard(&name, &root) {
                name = format!("*.{root}");
            }
            out.tls_ready = certs.certificate(&name).await.is_some();
        }
        out
    }

    /// verifyDomain: checks the TXT record for d and records the result.
    async fn verify_domain_record(&self, d: Domain) -> Result<Domain, armada_store::Error> {
        if d.verified {
            return Ok(d);
        }
        let name = format!("{TXT_PREFIX}{}", d.name);
        let res = tokio::time::timeout(Duration::from_secs(10), self.0.resolver.lookup_txt(&name))
            .await
            .unwrap_or_else(|_| Err("context deadline exceeded".to_string()));
        let ok = res
            .as_ref()
            .is_ok_and(|rs| rs.iter().any(|r| r.trim() == d.token));
        let msg = match &res {
            _ if ok => String::new(),
            Err(_) => format!("TXT record {name} not found"),
            Ok(rs) if rs.is_empty() => format!("TXT record {name} not found"),
            Ok(_) => format!("TXT record {name} does not contain the expected token"),
        };
        self.store()
            .set_domain_verification(&d.name, ok, &msg)
            .await?;
        if ok {
            self.0
                .log
                .info("domain verified", &[("domain", d.name.clone())]);
            self.record(event(EVENT_DOMAIN, &d.name, "", "Verified", ""))
                .await;
            self.trigger();
        }
        self.condition(
            &format!("domain-unverified:{}", d.name),
            !ok,
            event(EVENT_DOMAIN, &d.name, "", "NotVerified", &msg),
        )
        .await;
        self.store().get_domain(&d.name).await
    }

    /// VerifyDomain: checks a domain's TXT record now.
    pub(crate) async fn verify_domain(
        &self,
        a: &Auth,
        req: VerifyDomainRequest,
    ) -> Result<DomainProto, Status> {
        if !a.acc.admin() {
            // Only a domain one of the caller's apps uses.
            let resp = self.list_domains(a, ListDomainsRequest::default()).await?;
            if !resp.domains.iter().any(|d| d.name == req.name) {
                return Err(Status::new(
                    Code::PermissionDenied,
                    format!("{} may not verify {}", a.acc.id, req.name),
                ));
            }
        }
        let d = self
            .store()
            .get_domain(&req.name)
            .await
            .map_err(|e| store_err(&e))?;
        let d = match self.verify_domain_record(d).await {
            Ok(d) => d,
            Err(e) if e.kind == Kind::NotFound => return Err(store_err(&e)),
            Err(_) => return Err(Status::new(Code::Internal, "verification failed")),
        };
        let resp = self.list_domains(a, ListDomainsRequest::default()).await?;
        if let Some(x) = resp.domains.into_iter().find(|x| x.name == d.name) {
            return Ok(x);
        }
        Ok(self.domain_proto(&d, Vec::new()).await)
    }

    /// verifyLoop: checks every unverified domain's TXT record each
    /// interval.
    pub(crate) async fn verify_loop(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        loop {
            if let Ok(domains) = self.store().list_domains().await {
                for d in domains {
                    if d.verified {
                        continue;
                    }
                    let name = d.name.clone();
                    if let Err(e) = self.verify_domain_record(d).await
                        && !*shutdown.borrow()
                    {
                        self.0.log.warn(
                            "domain verification failed",
                            &[("domain", name), ("err", e.to_string())],
                        );
                    }
                }
            }
            tokio::select! {
                _ = crate::stopped(&mut shutdown) => return,
                _ = tokio::time::sleep(self.0.verify_interval) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        parse_prefix(s).unwrap()
    }

    #[test]
    fn excludes_container_ranges() {
        let t = vec!["10.0.0.0/8".to_string(), "192.0.2.0/24".to_string()];
        let out = exclude_prefixes(&t, &[p("10.120.0.0/16")]);
        assert!(out.contains(&"192.0.2.0/24".to_string()));
        assert!(!out.iter().any(|x| x == "10.0.0.0/8"));
        assert_eq!(out.len(), 9);
        assert!(exclude_prefixes(&["10.120.1.0/24".to_string()], &[p("10.120.0.0/16")]).is_empty());
    }

    #[test]
    fn addresses_in_canonical_form() {
        assert!(server_address_ok("10.0.0.1:80"));
        assert!(!server_address_ok("10.0.0.1:0"));
        assert!(!server_address_ok("8.8.8.8:80"));
        assert!(!server_address_ok("10.0.0.01:80"));
        assert!(server_address_ok("[fd00::1]:80"));
        assert!(!server_address_ok("fd00::1:80"));
    }

    #[test]
    fn pem_bundles() {
        let cert = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let key = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert!(check_pem(format!("{cert}{key}").as_bytes()).is_ok());
        assert!(check_pem(cert.as_bytes()).is_err());
        assert!(check_pem(format!("{cert}{key}junk").as_bytes()).is_err());
        assert!(check_pem(format!("{cert}{key}{key}").as_bytes()).is_err());
    }

    #[test]
    fn prefixes_parsed_like_go() {
        assert_eq!(
            parse_trusted_proxies(&["192.0.2.7/24".into(), "192.0.2.0/24".into()]).unwrap(),
            vec!["192.0.2.0/24"]
        );
        assert!(parse_trusted_proxies(&["0.0.0.0/0".into()]).is_err());
    }
}

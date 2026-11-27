//! The node's ingress configuration: [`ProxyConfig::from_proto`]'s bounds
//! and [`ProxyConfig::validate`]'s checks and texts, over armada-node's
//! render types (certificates by name) with their PEMs beside them.

use armada_node::proxy::{Backend, Certificate, Config, Cors, Rule, Server, TcpRoute};
use armada_proto::armada::v1 as pb;
use armada_spec::go::{Addr, parse_addr, parse_prefix, quote};
use armada_spec::validate as v;

/// The longest backend timeout.
pub const MAX_TIMEOUT_SECONDS: i64 = 3600;
/// The longest CORS max age.
pub const MAX_CORS_MAX_AGE_SECONDS: i64 = 86400;
/// The highest server weight.
pub const MAX_WEIGHT: i64 = 256;
pub const MAX_BACKENDS: usize = 100_000;
pub const MAX_RULES: usize = 1_000_000;
pub const MAX_CERTIFICATES: usize = 100_000;
/// Servers per backend: 2 × the most replicas, for rollouts.
pub const MAX_SERVERS: usize = 2 * armada_spec::spec::MAX_REPLICAS as usize;
const MAX_CERTIFICATE_PEM: usize = 64 << 10;
pub const MAX_TRUSTED_PROXIES: usize = 64;
pub const MAX_TCP_ROUTES: usize = 100_000;
pub const MAX_TCP_PORTS: usize = 4096;

/// What armada-node renders, and every certificate's PEM in
/// the order of `cfg.certificates`.
#[derive(Default)]
pub struct ProxyConfig {
    pub cfg: Config,
    pub pems: Vec<Vec<u8>>,
}

/// A certificate's file name: `*` as `_wildcard`, then `.pem`.
pub fn file_name(name: &str) -> String {
    format!("{}.pem", name.replacen('*', "_wildcard", 1))
}

impl ProxyConfig {
    /// The configuration of a ProxyConfig message, within the bounds.
    pub fn from_proto(p: &pb::ProxyConfig) -> ProxyConfig {
        let mut c = Config {
            acme_address: p.acme_challenge_address.clone(),
            trusted_proxies: p.trusted_proxies.clone(),
            plain_http: p.plain_http,
            proxy_protocol: p.proxy_protocol.clone(),
            ..Config::default()
        };
        for b in &p.backends {
            c.backends.push(Backend {
                name: b.name.clone(),
                servers: b
                    .servers
                    .iter()
                    .map(|s| Server {
                        name: s.name.clone(),
                        address: s.address.clone(),
                        weight: i64::from(s.weight).min(MAX_WEIGHT + 1),
                    })
                    .collect(),
                health_path: b.health_path.clone(),
                wake: b.wake,
                local_first: b.local_first,
                timeout_seconds: i64::from(b.timeout_seconds).min(MAX_TIMEOUT_SECONDS + 1),
                ip_allow: b.ip_allow.clone(),
                ip_deny: b.ip_deny.clone(),
                sticky: b.sticky,
                cors: b.cors.as_ref().map(|c| Cors {
                    origins: c.origins.clone(),
                    methods: c.methods.clone(),
                    headers: c.headers.clone(),
                    expose: c.expose.clone(),
                    max_age_seconds: i64::from(c.max_age_seconds).min(MAX_CORS_MAX_AGE_SECONDS + 1),
                    credentials: c.credentials,
                }),
            });
        }
        for r in &p.rules {
            c.rules.push(Rule {
                host: r.host.clone(),
                path_prefix: r.path_prefix.clone(),
                strip_prefix: r.strip_prefix,
                backend: r.backend.clone(),
                internal: r.internal,
                allow: r.allow.clone(),
            });
        }
        let mut pems = Vec::new();
        for crt in &p.certificates {
            c.certificates.push(Certificate {
                name: crt.name.clone(),
            });
            pems.push(crt.pem.clone());
        }
        for r in &p.tcp_routes {
            c.tcp.push(TcpRoute {
                port: i64::from(r.port).min(65536),
                backend: r.backend.clone(),
                allow: r.allow.clone(),
            });
        }
        ProxyConfig { cfg: c, pems }
    }

    /// The ports of the TCP routes, sorted, once each.
    pub fn tcp_ports(&self) -> Vec<i64> {
        let mut out: Vec<i64> = self.cfg.tcp.iter().map(|r| r.port).collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Checks the configuration: every problem, one per line.
    pub fn validate(&self) -> Result<(), String> {
        validate(self)
    }
}

/// Whether an address is private: RFC 1918 or unique local, loopback, or
/// shared (100.64.0.0/10); never one with a zone.
pub fn is_private(a: &Addr) -> bool {
    if !a.zone.is_empty() {
        return false;
    }
    let u = a.unmap();
    let loopback = if u.is4 {
        u.bytes[0] == 127
    } else {
        u.bytes[..15].iter().all(|&b| b == 0) && u.bytes[15] == 1
    };
    let cgnat = parse_prefix("100.64.0.0/10").expect("a valid prefix");
    u.is_private() || loopback || cgnat.contains(&u)
}

/// An address and port.
pub struct AddrPort {
    pub addr: Addr,
    pub port: u16,
}

impl AddrPort {
    /// `ip:port`, or `[ip%zone]:port` for IPv6.
    pub fn string(&self) -> String {
        let mut ip = self.addr.string();
        if !self.addr.zone.is_empty() {
            ip = format!("{ip}%{}", self.addr.zone);
        }
        if self.addr.is4 {
            format!("{ip}:{}", self.port)
        } else {
            format!("[{ip}]:{}", self.port)
        }
    }
}

/// Parses `ip:port` or `[ipv6]:port`.
pub fn parse_addr_port(s: &str) -> Option<AddrPort> {
    let i = s.rfind(':')?;
    let (mut ip, port) = (&s[..i], &s[i + 1..]);
    if ip.is_empty() {
        return None;
    }
    let mut v6 = false;
    if ip.starts_with('[') {
        if ip.len() < 2 || !ip.ends_with(']') {
            return None;
        }
        ip = &ip[1..ip.len() - 1];
        v6 = true;
    }
    if port.is_empty() || !port.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    let addr = parse_addr(ip)?;
    if v6 == addr.is4 {
        return None;
    }
    Some(AddrPort { addr, port })
}

/// The space of a backend's app (`<label>--<app ID>` or `<app ID>`).
pub fn backend_space(backend: &str) -> String {
    let id = backend.split_once("--").map_or(backend, |(_, id)| id);
    v::split_app_id(id).map(|(s, _)| s).unwrap_or_default()
}

fn parse_proxy_prefixes(one: &str, many: &str, prefixes: &[String]) -> Result<(), String> {
    if prefixes.len() > MAX_TRUSTED_PROXIES {
        return Err(format!("at most {MAX_TRUSTED_PROXIES} {many}"));
    }
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
    }
    Ok(())
}

fn valid_cors(c: Option<&Cors>) -> Result<(), String> {
    let Some(c) = c else { return Ok(()) };
    if c.origins.is_empty() || c.origins.len() > v::MAX_CORS_ORIGINS {
        return Err("cors: 1 to 32 origins".into());
    }
    for o in &c.origins {
        if (o != "*" || c.origins.len() > 1 || c.credentials) && !v::valid_cors_origin(o) {
            return Err(format!("cors: invalid origin {}", quote(o)));
        }
    }
    if c.methods.is_empty() {
        return Err("cors: no methods".into());
    }
    for m in &c.methods {
        if !v::CORS_METHOD_NAMES.contains(&m.as_str()) {
            return Err(format!("cors: invalid method {}", quote(m)));
        }
    }
    for list in [&c.headers, &c.expose] {
        if list.len() > v::MAX_CORS_HEADERS {
            return Err("cors: too many headers".into());
        }
        for h in list {
            if !v::valid_cors_header(h) {
                return Err(format!("cors: invalid header {}", quote(h)));
            }
        }
    }
    if c.max_age_seconds < 0 || c.max_age_seconds > MAX_CORS_MAX_AGE_SECONDS {
        return Err("cors: max age out of range".into());
    }
    Ok(())
}

fn valid_ip_rules(b: &Backend) -> Result<(), String> {
    if !b.ip_allow.is_empty() && !b.ip_deny.is_empty() {
        return Err("both allowed and denied client addresses".into());
    }
    for list in [&b.ip_allow, &b.ip_deny] {
        if list.len() > v::MAX_IP_RANGES {
            return Err("too many client address rules".into());
        }
        for s in list {
            match v::parse_ip_range(s) {
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

fn validate(pc: &ProxyConfig) -> Result<(), String> {
    let c = &pc.cfg;
    let mut errs: Vec<String> = Vec::new();
    let join = |errs: Vec<String>| {
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("\n"))
        }
    };
    if !c.acme_address.is_empty() {
        match parse_addr_port(&c.acme_address) {
            Some(ap) if is_private(&ap.addr) => {}
            _ => errs.push(format!(
                "acme address {} must be a private ip:port",
                quote(&c.acme_address)
            )),
        }
    }
    if let Err(e) = parse_proxy_prefixes(
        "PROXY protocol source",
        "PROXY protocol sources",
        &c.proxy_protocol,
    ) {
        errs.push(e);
    }
    if let Err(e) = parse_proxy_prefixes("trusted proxy", "trusted proxies", &c.trusted_proxies) {
        errs.push(e);
    }
    if c.backends.len() > MAX_BACKENDS
        || c.rules.len() > MAX_RULES
        || c.certificates.len() > MAX_CERTIFICATES
    {
        errs.push("configuration exceeds size limits".into());
        return join(errs);
    }

    let mut backends = std::collections::HashSet::new();
    for b in &c.backends {
        if b.timeout_seconds < 0 || b.timeout_seconds > MAX_TIMEOUT_SECONDS {
            return Err(format!(
                "backend {}: timeout {} out of range",
                b.name, b.timeout_seconds
            ));
        }
        if !v::valid_host_name(&b.name) {
            errs.push(format!("backend {}: invalid name", quote(&b.name)));
            continue;
        }
        if !backends.insert(b.name.as_str()) {
            errs.push(format!("duplicate backend {}", quote(&b.name)));
        }
        if let Err(e) = valid_ip_rules(b) {
            errs.push(format!("backend {}: {e}", b.name));
        }
        if let Err(e) = valid_cors(b.cors.as_ref()) {
            errs.push(format!("backend {}: {e}", b.name));
        }
        if !b.health_path.is_empty()
            && let Err(e) = v::validate_probe_path(&b.health_path)
        {
            errs.push(format!("backend {}: health path: {e}", b.name));
        }
        if b.servers.len() > MAX_SERVERS {
            errs.push(format!("backend {}: too many servers", b.name));
        }
        let mut seen = std::collections::HashSet::new();
        for s in &b.servers {
            let ok = parse_addr_port(&s.address)
                .is_some_and(|ap| is_private(&ap.addr) && ap.port != 0 && ap.string() == s.address);
            if !ok {
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
            if s.name.is_empty() || seen.contains(s.name.as_str()) {
                errs.push(format!(
                    "backend {}: missing or duplicate server name",
                    b.name
                ));
            }
            seen.insert(s.name.as_str());
        }
    }

    let mut routes = std::collections::HashSet::new();
    for r in &c.rules {
        if r.internal {
            let ok = r
                .host
                .strip_suffix(v::INTERNAL_SUFFIX)
                .is_some_and(v::valid_host_name);
            if !ok {
                errs.push(format!(
                    "internal rule host {} must be <app>{s} or <label>--<app>{s}",
                    quote(&r.host),
                    s = v::INTERNAL_SUFFIX
                ));
            }
        } else if let Err(e) = v::validate_domain(&r.host) {
            errs.push(format!("rule host {}: {e}", quote(&r.host)));
        }
        if let Err(e) = v::validate_route_path(&r.path_prefix) {
            errs.push(format!("rule path {}: {e}", quote(&r.path_prefix)));
        }
        if !r.allow.is_empty() && !r.internal {
            errs.push(format!(
                "rule {}{}: only internal rules have callers",
                r.host, r.path_prefix
            ));
        }
        if r.allow.len() > v::MAX_ALLOW + 1 {
            errs.push(format!(
                "rule {}{}: too many callers",
                r.host, r.path_prefix
            ));
        }
        let space = backend_space(&r.backend);
        for a in &r.allow {
            if v::split_app_id(a).is_none_or(|(p, _)| p != space) {
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
        if !backends.contains(r.backend.as_str()) {
            errs.push(format!(
                "rule {}{}: unknown backend {}",
                r.host,
                r.path_prefix,
                quote(&r.backend)
            ));
        }
        let key = format!("{}{}", r.host, r.path_prefix);
        if routes.contains(&key) {
            errs.push(format!("duplicate rule for {key}"));
        }
        routes.insert(key);
    }
    errs.extend(valid_tcp(pc));

    let mut certs = std::collections::HashSet::new();
    for (i, crt) in c.certificates.iter().enumerate() {
        let name = crt.name.strip_prefix("*.").unwrap_or(&crt.name);
        if v::validate_domain(name).is_err() {
            errs.push(format!("certificate {}: invalid name", quote(&crt.name)));
        }
        if !certs.insert(crt.name.as_str()) {
            errs.push(format!("duplicate certificate {}", quote(&crt.name)));
        }
        let pem = pc.pems.get(i).map(Vec::as_slice).unwrap_or(&[]);
        if let Err(e) = check_pem(pem) {
            errs.push(format!("certificate {}: {e}", crt.name));
        }
    }
    join(errs)
}

fn valid_tcp(pc: &ProxyConfig) -> Vec<String> {
    let c = &pc.cfg;
    let mut errs = Vec::new();
    if c.tcp.len() > MAX_TCP_ROUTES || pc.tcp_ports().len() > MAX_TCP_PORTS {
        errs.push("too many TCP routes".to_string());
        return errs;
    }
    let backends: std::collections::HashMap<&str, &Backend> =
        c.backends.iter().map(|b| (b.name.as_str(), b)).collect();
    let http: std::collections::HashSet<&str> =
        c.rules.iter().map(|r| r.backend.as_str()).collect();
    let mut routed = std::collections::HashSet::new();
    let mut taken = std::collections::HashSet::new();
    for r in &c.tcp {
        if let Err(e) = v::check_tcp_port(r.port) {
            errs.push(format!("tcp port {}: {e}", r.port));
        }
        let b = match backends.get(r.backend.as_str()) {
            Some(b) if v::valid_app_id(&r.backend) => *b,
            _ => {
                errs.push(format!(
                    "tcp port {}: unknown backend {}",
                    r.port,
                    quote(&r.backend)
                ));
                continue;
            }
        };
        if http.contains(r.backend.as_str()) || routed.contains(r.backend.as_str()) {
            errs.push(format!("tcp backend {}: routed more than once", r.backend));
        }
        routed.insert(r.backend.as_str());
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
        let key = format!("{space}/{}", r.port);
        if !taken.insert(key) {
            errs.push(format!(
                "tcp port {}: more than one backend of space {space}",
                r.port
            ));
        }
        if r.allow.len() > v::MAX_ALLOW + 1 {
            errs.push(format!("tcp backend {}: too many callers", r.backend));
        }
        for a in &r.allow {
            let ok = v::split_app_id(a).is_some_and(|(p, _)| p == space) && v::valid_app_id(a);
            if !ok {
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

/// The next line of data, its line end and trailing spaces and tabs
/// dropped, and the rest after it.
fn get_line(data: &[u8]) -> (&[u8], &[u8]) {
    let (mut i, j) = match data.iter().position(|&b| b == b'\n') {
        None => (data.len(), data.len()),
        Some(i) => (i, i + 1),
    };
    if i > 0 && i < data.len() && data[i] == b'\n' && data[i - 1] == b'\r' {
        i -= 1;
    }
    let mut line = &data[..i];
    while let Some((&last, rest)) = line.split_last() {
        if last == b' ' || last == b'\t' {
            line = rest;
        } else {
            break;
        }
    }
    (line, &data[j..])
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The next PEM block: its type, and what follows it; None when no
/// block is left.
pub fn pem_decode(data: &[u8]) -> Option<(String, &[u8])> {
    const START: &[u8] = b"\n-----BEGIN ";
    const END: &[u8] = b"\n-----END ";
    const EOL: &[u8] = b"-----";
    let mut rest = data;
    loop {
        if rest.starts_with(&START[1..]) {
            rest = &rest[START.len() - 1..];
        } else {
            let i = find(rest, START)?;
            rest = &rest[i + START.len()..];
        }
        let (type_line, r) = get_line(rest);
        rest = r;
        let Some(type_line) = type_line.strip_suffix(EOL) else {
            continue;
        };
        let mut headers = 0;
        loop {
            if rest.is_empty() {
                return None;
            }
            let (line, next) = get_line(rest);
            if !line.contains(&b':') {
                break;
            }
            headers += 1;
            rest = next;
        }
        let (end_index, end_trailer_index) = if headers == 0 && rest.starts_with(&END[1..]) {
            (0usize, END.len() - 1)
        } else {
            match find(rest, END) {
                Some(i) => (i, i + END.len()),
                None => continue,
            }
        };
        let end_trailer = &rest[end_trailer_index..];
        let len = type_line.len() + EOL.len();
        if end_trailer.len() < len {
            continue;
        }
        let rest_of_end_line = &end_trailer[len..];
        let end_trailer = &end_trailer[..len];
        if !end_trailer.starts_with(type_line) || !end_trailer.ends_with(EOL) {
            continue;
        }
        if !get_line(rest_of_end_line).0.is_empty() {
            continue;
        }
        let body: String = rest[..end_index]
            .iter()
            .filter(|&&b| b != b' ' && b != b'\t')
            .map(|&b| b as char)
            .collect();
        if armada_node::net::key::b64_decode(&body).is_none() {
            continue;
        }
        let after = get_line(&rest[end_index + END.len() - 1..]).1;
        return Some((String::from_utf8_lossy(type_line).into_owned(), after));
    }
}

/// A chain and one private key, nothing else.
pub fn check_pem(b: &[u8]) -> Result<(), String> {
    if b.len() > MAX_CERTIFICATE_PEM {
        return Err("bundle too large".into());
    }
    let (mut certs, mut keys) = (0, 0);
    let mut rest = b;
    while let Some((kind, r)) = pem_decode(rest) {
        rest = r;
        match kind.as_str() {
            "CERTIFICATE" => certs += 1,
            "PRIVATE KEY" | "EC PRIVATE KEY" | "RSA PRIVATE KEY" => keys += 1,
            _ => return Err(format!("unexpected PEM block {}", quote(&kind))),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_ports_as_netip_reads_them() {
        for (s, ok) in [
            ("10.0.0.1:80", true),
            ("[fd00::1]:80", true),
            ("fd00::1:80", false),
            ("[10.0.0.1]:80", false),
            ("10.0.0.1:+80", false),
            ("10.0.0.1:", false),
            (":80", false),
            ("10.0.0.1:65536", false),
        ] {
            assert_eq!(parse_addr_port(s).is_some(), ok, "{s}");
        }
        assert_eq!(
            parse_addr_port("10.0.0.1:080").unwrap().string(),
            "10.0.0.1:80"
        );
        assert!(is_private(&parse_addr("100.64.1.1").unwrap()));
        assert!(is_private(&parse_addr("::1").unwrap()));
        assert!(!is_private(&parse_addr("8.8.8.8").unwrap()));
    }

    #[test]
    fn pem_blocks() {
        let pem = b"junk\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert_eq!(check_pem(pem), Ok(()));
        let mut extra = pem.to_vec();
        extra.extend_from_slice(b"tail");
        assert_eq!(
            check_pem(&extra).unwrap_err(),
            "trailing data after PEM blocks"
        );
        assert!(
            check_pem(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").is_err()
        );
        let other = b"-----BEGIN X-----\nAAAA\n-----END X-----\n";
        assert_eq!(check_pem(other).unwrap_err(), "unexpected PEM block \"X\"");
        // A bad body is not a block.
        let bad = b"-----BEGIN CERTIFICATE-----\nA!AA\n-----END CERTIFICATE-----\n";
        assert_eq!(
            check_pem(bad).unwrap_err(),
            "trailing data after PEM blocks"
        );
    }

    #[test]
    fn from_proto_bounds_values() {
        let p = pb::ProxyConfig {
            backends: vec![pb::ProxyBackend {
                name: "web".into(),
                timeout_seconds: 99999,
                servers: vec![pb::ProxyServer {
                    name: "a".into(),
                    address: "10.0.0.2:80".into(),
                    weight: 9999,
                }],
                cors: Some(pb::ProxyCors {
                    max_age_seconds: 999_999,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            tcp_routes: vec![pb::ProxyTcpRoute {
                port: 99999,
                backend: "web".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let c = ProxyConfig::from_proto(&p).cfg;
        assert_eq!(c.backends[0].timeout_seconds, 3601);
        assert_eq!(c.backends[0].servers[0].weight, 257);
        assert_eq!(c.backends[0].cors.as_ref().unwrap().max_age_seconds, 86401);
        assert_eq!(c.tcp[0].port, 65536);
    }
}

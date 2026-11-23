//! The port of internal/proxy/haproxy/render.go. Lines are written with
//! render.go's own format strings (`%s`, `%d`, `%%`) through `Out::line`, so
//! the two read side by side; keep them that way when either changes.

use super::{Backend, Config, Cors, Layout, Options, Rule, Server, TcpRoute, backend_space};
use crate::names::{DEFAULT_SPACE, INTERNAL_SUFFIX};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::{Display, Write as _};
use std::net::{IpAddr, SocketAddr};

const CONTAINER_CONF_DIR: &str = "/usr/local/etc/haproxy";
const CONTAINER_RUN_DIR: &str = "/var/run/haproxy";
const DEFAULT_CERT_FILE: &str = "default.pem";
const CERT_DIR: &str = "certs";
const SOCKET_FILE: &str = "admin.sock";
const CLIENTS_FILE: &str = "clients.map";
const LOCAL_FILE: &str = "local.map";
const ROUTE_FILE_PREFIX: &str = "routes-";
const METRICS_PORT: u16 = 8404;
const WAKE_SOCKET_FILE: &str = "wake.sock";
const INTERNAL_PORT: u16 = 80;
const LOCAL_WEIGHT: i64 = 11;
const REMOTE_WEIGHT: i64 = 10;
const LOCAL_CHOICES: usize = 4;
const TCP_TIMEOUT: &str = "1h";
const REMOTE_CHECK_INTERVAL: &str = "15s";
const MAX_PROXY_HOPS: usize = 4;
const FRONTEND_HTTP: &str = "http";
const FRONTEND_HTTPS: &str = "https";
const ROUTES_PUBLIC: &str = "r";
const ROUTES_INTERNAL: &str = "i";
/// proxy.WakeHeader.
const WAKE_HEADER: &str = "X-Armada-Wake";
/// proxy.WakeTimeout + 60s, in seconds.
const WAKE_SERVER_TIMEOUT: i64 = 120;
/// proxy.ClientAddressHeaders.
const CLIENT_ADDRESS_HEADERS: [&str; 4] = [
    "Forwarded",
    "X-Forwarded-For",
    "CF-Connecting-IP",
    "True-Client-IP",
];
/// proxy.ForwardedURLHeaders.
const FORWARDED_URL_HEADERS: [&str; 4] = [
    "X-Forwarded-Host",
    "X-Forwarded-Port",
    "X-Forwarded-Prefix",
    "X-Forwarded-Server",
];
/// proxy.ClientIPHeader.
const CLIENT_IP_HEADER: &str = "X-Real-IP";

/// A configuration being written, line by line, with Go's verbs.
#[derive(Default)]
struct Out(String);

impl Out {
    /// fmt.Fprintf(format + "\n") for the verbs render.go uses: %s and %d
    /// print an argument, %% a percent sign.
    fn line(&mut self, format: &str, args: &[&dyn Display]) {
        let mut args = args.iter();
        let mut chars = format.chars();
        while let Some(c) = chars.next() {
            if c != '%' {
                self.0.push(c);
                continue;
            }
            match chars.next() {
                Some('%') => self.0.push('%'),
                Some('s' | 'd') => {
                    let a = args.next().expect("a verb without its argument");
                    let _ = write!(self.0, "{a}");
                }
                v => panic!("unsupported verb %{v:?}"),
            }
        }
        assert!(args.next().is_none(), "arguments left over in {format:?}");
        self.0.push('\n');
    }
}

macro_rules! w {
    ($o:expr, $f:expr $(, $a:expr)* $(,)?) => {
        $o.line($f, &[$(&$a as &dyn Display),*])
    };
}

/// Where this node's replicas are: ports on its private IP, or addresses in
/// its container subnet.
#[derive(Clone, Copy)]
pub struct Node {
    ip: Option<IpAddr>,
    subnet: Option<(IpAddr, u8)>,
}

impl Options {
    pub fn node(&self) -> Node {
        Node {
            ip: self.private_ip.parse().ok(),
            subnet: parse_prefix(&self.subnet),
        }
    }

    fn checks_callers(&self) -> bool {
        !self.subnet.is_empty()
    }

    fn serves_tcp(&self) -> bool {
        !self.internal_ip.is_empty() && self.checks_callers()
    }
}

/// netip.ParsePrefix: an address and a length within its family.
fn parse_prefix(s: &str) -> Option<(IpAddr, u8)> {
    let (ip, bits) = s.split_once('/')?;
    let ip: IpAddr = ip.parse().ok()?;
    if bits.is_empty() || (bits.len() > 1 && bits.starts_with('0')) {
        return None;
    }
    let bits: u8 = bits.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    (bits <= max).then_some((ip, bits))
}

fn prefix_contains((net, bits): (IpAddr, u8), ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            u32::from(n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

impl Node {
    fn known(&self) -> bool {
        self.ip.is_some()
    }

    /// Whether a server's ip:port is on the node.
    fn has(&self, addr: &str) -> bool {
        let (Some(own), Ok(sa)) = (self.ip, addr.parse::<SocketAddr>()) else {
            return false;
        };
        let ip = sa.ip().to_canonical();
        ip == own.to_canonical() || self.subnet.is_some_and(|p| prefix_contains(p, ip))
    }
}

fn backend_name(app: &str) -> String {
    format!("be_{app}")
}

fn wake_backend_name(app: &str) -> String {
    format!("wk_{app}")
}

fn slot_name(i: usize) -> String {
    format!("s{}", i + 1)
}

fn strip_field(prefix: &str) -> usize {
    prefix.matches('/').count() + 2
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn sticky_value(replica: &str) -> String {
    format!("r{}", hex(&sha256(replica.as_bytes())[..6]))
}

fn sticky_cookie(backend: &str) -> String {
    format!("armada_{}", hex(&sha256(backend.as_bytes())[..4]))
}

fn host_for_bind(ip: &str) -> String {
    if ip.contains(':') {
        format!("[{ip}]")
    } else {
        ip.to_string()
    }
}

fn local_first(be: &Backend, n: &Node) -> bool {
    be.local_first && n.known()
}

/// One HAProxy backend with server slots.
struct Pool<'a> {
    name: String,
    servers: Vec<Server>,
    leastconn: bool,
    timeout: i64,
    ip_allow: &'a [String],
    ip_deny: &'a [String],
    remote: HashSet<String>,
    sticky: bool,
    plain_http: bool,
    cors: Option<&'a Cors>,
    tcp: bool,
}

fn backend_pool<'a>(be: &'a Backend, n: &Node) -> Pool<'a> {
    let mut p = Pool {
        name: backend_name(&be.name),
        servers: be.servers.clone(),
        leastconn: false,
        timeout: be.timeout_seconds,
        ip_allow: &be.ip_allow,
        ip_deny: &be.ip_deny,
        remote: HashSet::new(),
        sticky: be.sticky,
        plain_http: false,
        cors: be.cors.as_ref(),
        tcp: false,
    };
    if n.known() {
        for s in &be.servers {
            if !n.has(&s.address) {
                p.remote.insert(s.name.clone());
            }
        }
    }
    if !local_first(be, n) {
        return p;
    }
    p.leastconn = true;
    for s in &mut p.servers {
        s.weight = if n.has(&s.address) {
            LOCAL_WEIGHT
        } else {
            REMOTE_WEIGHT
        };
    }
    p
}

fn sorted_backends(cfg: &Config) -> Vec<&Backend> {
    let mut b: Vec<&Backend> = cfg.backends.iter().collect();
    b.sort_by(|a, b| a.name.cmp(&b.name));
    b
}

/// localMap.
pub fn local_map(cfg: &Config, layout: &Layout, n: &Node) -> Vec<u8> {
    let mut out = String::new();
    for be in sorted_backends(cfg) {
        if !local_first(be, n) {
            continue;
        }
        let addr: HashMap<&str, &str> = be
            .servers
            .iter()
            .map(|s| (s.name.as_str(), s.address.as_str()))
            .collect();
        let name = backend_name(&be.name);
        let slots: Vec<String> = layout
            .get(&name)
            .into_iter()
            .flatten()
            .enumerate()
            .filter(|(_, s)| !s.is_empty() && n.has(addr.get(s.as_str()).copied().unwrap_or("")))
            .map(|(i, _)| slot_name(i))
            .collect();
        if slots.is_empty() {
            continue;
        }
        for i in 0..LOCAL_CHOICES {
            let _ = writeln!(out, "{name}/{i} {}", slots[i % slots.len()]);
        }
    }
    out.into_bytes()
}

/// render: haproxy.cfg, or None when a value is not a single token.
pub fn render(cfg: &Config, layout: &Layout, opts: &Options) -> Option<String> {
    if !safe_config(cfg, opts) {
        return None;
    }
    let mut o = Out::default();
    w!(
        o,
        "# Generated by Armada. Do not edit: changes are overwritten."
    );
    w!(o, "global");
    w!(
        o,
        "    stats socket %s/%s mode 600 level admin",
        CONTAINER_RUN_DIR,
        SOCKET_FILE
    );
    w!(o, "    log stdout format raw local0");
    w!(o, "    maxconn 20000");
    w!(o, "    hard-stop-after 1h");
    w!(
        o,
        "    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets"
    );
    w!(
        o,
        "    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
    );
    w!(
        o,
        "    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
    );
    w!(o, "");
    w!(o, "defaults");
    w!(o, "    mode http");
    w!(o, "    log global");
    w!(o, "    option httplog");
    w!(o, "    option forwardfor");
    w!(o, "    retries 3");
    w!(o, "    option redispatch 1");
    w!(o, "    timeout connect 2s");
    w!(o, "    timeout client 60s");
    w!(o, "    timeout server 60s");
    w!(o, "    timeout http-request 10s");
    w!(o, "    timeout http-keep-alive 10s");
    w!(o, "    timeout queue 30s");
    w!(o, "    timeout tunnel 1h");
    w!(o, "");

    if !opts.private_ip.is_empty() {
        w!(o, "frontend metrics");
        w!(o, "    bind 127.0.0.1:%d", METRICS_PORT);
        w!(
            o,
            "    http-request use-service prometheus-exporter if { path /metrics }"
        );
        w!(o, "    http-request return status 404");
        w!(o, "");
    }

    let (public, internal) = split_rules(cfg);
    let by_name: HashMap<&str, &Backend> =
        cfg.backends.iter().map(|b| (b.name.as_str(), b)).collect();
    let mut rr = RuleRenderer {
        backends: &by_name,
        callers: false,
    };

    w!(o, "frontend %s", FRONTEND_HTTP);
    w!(o, "    bind :80");
    write_proxy_protocol(&mut o, &cfg.proxy_protocol);
    if !cfg.acme_address.is_empty() {
        w!(o, "    acl acme path_beg /.well-known/acme-challenge/");
        if !cfg.plain_http {
            w!(
                o,
                "    http-request redirect scheme https code 301 unless acme"
            );
        }
        w!(o, "    use_backend be_armada_acme if acme");
    } else if !cfg.plain_http {
        w!(o, "    http-request redirect scheme https code 301");
    }
    if cfg.plain_http {
        write_public_routes(&mut o, cfg, &rr, &public, "http");
    }
    w!(o, "");

    w!(o, "frontend %s", FRONTEND_HTTPS);
    w!(
        o,
        "    bind :443 ssl crt %s/%s crt %s/%s/ alpn h2,http/1.1",
        CONTAINER_CONF_DIR,
        DEFAULT_CERT_FILE,
        CONTAINER_CONF_DIR,
        CERT_DIR
    );
    write_proxy_protocol(&mut o, &cfg.proxy_protocol);
    write_public_routes(&mut o, cfg, &rr, &public, "https");
    w!(o, "");

    if !opts.internal_ip.is_empty() {
        w!(o, "frontend internal");
        w!(
            o,
            "    bind %s:%d",
            host_for_bind(&opts.internal_ip),
            INTERNAL_PORT
        );
        w!(o, "    http-request set-header X-Forwarded-Proto http");
        w!(
            o,
            "    http-request set-var(txn.host) req.hdr(host),field(1,:),lower"
        );
        w!(o, "    http-request set-var(txn.path) path");
        if opts.checks_callers() {
            w!(
                o,
                "    http-request set-var(txn.cspace) src,map_ip(%s/%s),field(1,:)",
                CONTAINER_CONF_DIR,
                CLIENTS_FILE
            );
            w!(
                o,
                "    http-request set-var(txn.capp) src,map_ip(%s/%s),field(2,:)",
                CONTAINER_CONF_DIR,
                CLIENTS_FILE
            );
            rr.callers = true;
            w!(
                o,
                "    http-request set-var(txn.host) var(txn.host),concat(%s) if !{ var(txn.host) -m sub . } { var(txn.cspace) -m str %s }",
                INTERNAL_SUFFIX,
                DEFAULT_SPACE
            );
            w!(
                o,
                "    http-request set-var(txn.host) var(txn.host),concat(.,txn.cspace,%s) if !{ var(txn.host) -m sub . } { var(txn.cspace) -m found }",
                INTERNAL_SUFFIX
            );
        } else {
            w!(
                o,
                "    http-request set-var(txn.host) var(txn.host),concat(%s) if !{ var(txn.host) -m sub . }",
                INTERNAL_SUFFIX
            );
        }
        rr.write(&mut o, ROUTES_INTERNAL, &internal);
        w!(o, "    default_backend be_armada_notfound");
        w!(o, "");
    }

    let backends = sorted_backends(cfg);
    let tcp: HashSet<&str> = cfg.tcp.iter().map(|r| r.backend.as_str()).collect();
    let node = opts.node();
    for be in &backends {
        if tcp.contains(be.name.as_str()) {
            continue;
        }
        let mut p = backend_pool(be, &node);
        p.plain_http = cfg.plain_http;
        write_backend(&mut o, &p, &be.health_path, layout);
        if be.wake {
            w!(o, "backend %s", wake_backend_name(&be.name));
            write_ip_rules(&mut o, &be.ip_allow, &be.ip_deny);
            write_cors(&mut o, be.cors.as_ref());
            w!(o, "    http-request set-header %s %s", WAKE_HEADER, be.name);
            w!(o, "    timeout server %ds", WAKE_SERVER_TIMEOUT);
            w!(
                o,
                "    server wake unix@%s/%s",
                CONTAINER_RUN_DIR,
                WAKE_SOCKET_FILE
            );
            w!(o, "");
        }
    }

    if !cfg.acme_address.is_empty() {
        w!(o, "backend be_armada_acme");
        w!(o, "    server acme %s", cfg.acme_address);
        w!(o, "");
    }
    w!(o, "backend be_armada_notfound");
    w!(
        o,
        "    http-request return status 404 content-type text/plain string \"no app is configured for this host\""
    );
    if !cfg.tcp.is_empty() {
        write_tcp(&mut o, cfg, &backends, &tcp, layout, opts);
    }
    Some(o.0)
}

/// Config.TCPPorts: the distinct ports, sorted.
fn tcp_ports(cfg: &Config) -> Vec<i64> {
    let mut p: Vec<i64> = cfg.tcp.iter().map(|r| r.port).collect();
    p.sort_unstable();
    p.dedup();
    p
}

fn write_tcp(
    o: &mut Out,
    cfg: &Config,
    backends: &[&Backend],
    tcp: &HashSet<&str>,
    layout: &Layout,
    opts: &Options,
) {
    w!(o, "");
    w!(o, "defaults tcp");
    w!(o, "    mode tcp");
    w!(o, "    log global");
    w!(o, "    option tcplog");
    w!(o, "    retries 3");
    w!(o, "    option redispatch 1");
    w!(o, "    timeout connect 2s");
    w!(o, "    timeout client %s", TCP_TIMEOUT);
    w!(o, "    timeout server %s", TCP_TIMEOUT);
    w!(o, "");
    if opts.serves_tcp() {
        let mut by_port: HashMap<i64, Vec<&TcpRoute>> = HashMap::new();
        for r in &cfg.tcp {
            by_port.entry(r.port).or_default().push(r);
        }
        let clients = format!("{CONTAINER_CONF_DIR}/{CLIENTS_FILE}");
        for port in tcp_ports(cfg) {
            if opts.busy_tcp.contains(&port) {
                continue;
            }
            let mut routes = by_port.remove(&port).unwrap_or_default();
            routes.sort_by(|a, b| a.backend.cmp(&b.backend));
            w!(o, "frontend %s", format!("tcp_{port}"));
            w!(o, "    bind %s:%d", host_for_bind(&opts.internal_ip), port);
            w!(
                o,
                "    tcp-request connection set-var(sess.cspace) src,map_ip(%s),field(1,:)",
                clients
            );
            w!(
                o,
                "    tcp-request connection set-var(sess.capp) src,map_ip(%s),field(2,:)",
                clients
            );
            for r in routes {
                let mut set = format!(
                    "    tcp-request connection set-var(sess.route) str({}) if {{ var(sess.cspace) -m str {} }}",
                    backend_name(&r.backend),
                    backend_space(&r.backend)
                );
                if !r.allow.is_empty() {
                    set += &format!(" {{ var(sess.capp) -m str {} }}", r.allow.join(" "));
                }
                w!(o, "%s", set);
            }
            w!(
                o,
                "    tcp-request connection reject unless { var(sess.route) -m found }"
            );
            w!(o, "    use_backend %%[var(sess.route)]");
            w!(o, "");
        }
    }
    let node = opts.node();
    for be in backends {
        if !tcp.contains(be.name.as_str()) {
            continue;
        }
        let mut p = backend_pool(be, &node);
        p.tcp = true;
        write_backend(o, &p, "", layout);
    }
}

fn write_cors(o: &mut Out, c: Option<&Cors>) {
    let Some(c) = c else { return };
    if c.origins.len() == 1 && c.origins[0] == "*" {
        w!(
            o,
            "    http-request set-var(txn.cors) str(*) if { req.hdr(Origin) -m found }"
        );
    } else {
        w!(
            o,
            "    http-request set-var(txn.cors) req.hdr(Origin) if { req.hdr(Origin) -m str %s }",
            c.origins.join(" ")
        );
    }
    let mut ret = format!(
        "    http-request return status 204 hdr Access-Control-Allow-Origin %[var(txn.cors)] hdr Access-Control-Allow-Methods \"{}\"",
        c.methods.join(", ")
    );
    if !c.headers.is_empty() {
        ret += &format!(
            " hdr Access-Control-Allow-Headers \"{}\"",
            c.headers.join(", ")
        );
    }
    if c.max_age_seconds > 0 {
        ret += &format!(" hdr Access-Control-Max-Age {}", c.max_age_seconds);
    }
    if c.credentials {
        ret += " hdr Access-Control-Allow-Credentials true";
    }
    ret += " if METH_OPTIONS { var(txn.cors) -m found } { req.hdr(Access-Control-Request-Method) -m found }";
    w!(o, "%s", ret);
    w!(
        o,
        "    http-after-response set-header Access-Control-Allow-Origin %%[var(txn.cors)] if { var(txn.cors) -m found }"
    );
    if c.credentials {
        w!(
            o,
            "    http-after-response set-header Access-Control-Allow-Credentials true if { var(txn.cors) -m found }"
        );
    }
    if !c.expose.is_empty() {
        w!(
            o,
            "    http-after-response set-header Access-Control-Expose-Headers \"%s\" if { var(txn.cors) -m found }",
            c.expose.join(", ")
        );
    }
    w!(o, "    http-after-response add-header Vary Origin");
}

fn write_client_address(o: &mut Out, trusted: &[String]) {
    w!(o, "    http-request set-var(txn.ext) bool(true)");
    w!(o, "    http-request set-var(txn.client) src");
    if trusted.is_empty() {
        return;
    }
    let t = trusted.join(" ");
    w!(o, "    http-request unset-var(txn.client) if trusted_proxy");
    w!(
        o,
        "    http-request set-var(txn.client) req.hdr_ip(X-Forwarded-For,-1) if trusted_proxy"
    );
    for hop in 2..=MAX_PROXY_HOPS {
        w!(
            o,
            "    http-request set-var(txn.client) req.hdr_ip(X-Forwarded-For,-%d) if trusted_proxy { var(txn.client) -m ip %s }",
            hop,
            t
        );
    }
    w!(
        o,
        "    http-request unset-var(txn.client) if trusted_proxy { var(txn.client) -m ip %s }",
        t
    );
}

fn write_ip_rules(o: &mut Out, allow: &[String], deny: &[String]) {
    if !allow.is_empty() {
        w!(
            o,
            "    http-request deny deny_status 403 if { var(txn.ext) -m bool } !{ var(txn.client) -m ip %s }",
            allow.join(" ")
        );
    } else if !deny.is_empty() {
        w!(
            o,
            "    http-request deny deny_status 403 if { var(txn.ext) -m bool } !{ var(txn.client) -m found }"
        );
        w!(
            o,
            "    http-request deny deny_status 403 if { var(txn.ext) -m bool } { var(txn.client) -m ip %s }",
            deny.join(" ")
        );
    }
}

fn write_backend(o: &mut Out, p: &Pool, health_path: &str, layout: &Layout) {
    let servers: HashMap<&str, &Server> = p.servers.iter().map(|s| (s.name.as_str(), s)).collect();
    w!(o, "backend %s", p.name);
    write_ip_rules(o, p.ip_allow, p.ip_deny);
    write_cors(o, p.cors);
    if p.timeout > 0 {
        w!(o, "    timeout server %ds", p.timeout);
    }
    let rules = if p.tcp {
        "tcp-request content"
    } else {
        "http-request"
    };
    if p.leastconn {
        w!(o, "    balance leastconn");
        w!(o, "    %s set-var(txn.lk) rand(%d)", rules, LOCAL_CHOICES);
        w!(
            o,
            "    use-server %%[str(%s),concat(/,txn.lk),map(%s/%s)] if { be_conn le 1 } !{ fe_name %s } !{ fe_name %s }",
            p.name,
            CONTAINER_CONF_DIR,
            LOCAL_FILE,
            FRONTEND_HTTP,
            FRONTEND_HTTPS
        );
    } else if p.tcp {
        w!(o, "    balance leastconn");
    } else {
        w!(o, "    balance roundrobin");
    }
    let mut cookie = "";
    if p.sticky {
        let secure = if p.plain_http { "" } else { " secure" };
        w!(
            o,
            "    cookie %s insert indirect nocache httponly%s attr \"SameSite=Lax\"",
            sticky_cookie(&p.name),
            secure
        );
        cookie = " cookie ";
    }
    if !health_path.is_empty() {
        w!(o, "    option httpchk GET %s", health_path);
        w!(o, "    http-check expect status 200-399");
    }
    w!(
        o,
        "    default-server check inter 2s fastinter 1s fall 2 rise 2 observe layer4 error-limit 2 on-error fastinter"
    );
    for (i, sname) in layout.get(&p.name).into_iter().flatten().enumerate() {
        let s = servers.get(sname.as_str()).filter(|_| !sname.is_empty());
        let mut c = String::new();
        if s.is_some() && !cookie.is_empty() {
            c = format!("{cookie}{}", sticky_value(sname));
        }
        if p.remote.contains(sname) {
            c += " inter ";
            c += REMOTE_CHECK_INTERVAL;
        }
        match s {
            Some(s) if s.effective_weight() != 1 => {
                w!(
                    o,
                    "    server %s %s weight %d%s",
                    slot_name(i),
                    s.address,
                    s.effective_weight(),
                    c
                )
            }
            Some(s) => w!(o, "    server %s %s%s", slot_name(i), s.address, c),
            None => w!(o, "    server %s 127.0.0.1:1 disabled%s", slot_name(i), c),
        }
    }
    w!(o, "");
}

struct RuleRenderer<'a> {
    backends: &'a HashMap<&'a str, &'a Backend>,
    callers: bool,
}

fn split_rules(cfg: &Config) -> (Vec<&Rule>, Vec<&Rule>) {
    cfg.rules.iter().partition(|r| !r.internal)
}

/// Longest path first, then by host and path. A stable sort: Go's is not,
/// but validated rules never tie on all three.
fn sort_rules<'a>(rules: &[&'a Rule]) -> Vec<&'a Rule> {
    let mut r = rules.to_vec();
    r.sort_by(|a, b| {
        b.path_prefix
            .len()
            .cmp(&a.path_prefix.len())
            .then_with(|| a.host.cmp(&b.host))
            .then_with(|| a.path_prefix.cmp(&b.path_prefix))
    });
    r
}

fn mapped(r: &Rule, be: Option<&&Backend>) -> bool {
    r.path_prefix == "/" && !r.strip_prefix && r.allow.is_empty() && !be.is_some_and(|b| b.wake)
}

/// routeMap: the file name and content, or None without mapped rules.
fn route_map(
    prefix: &str,
    rules: &[&Rule],
    backends: &HashMap<&str, &Backend>,
    callers: bool,
) -> Option<(String, Vec<u8>)> {
    let mut b = String::new();
    for r in sort_rules(rules) {
        if !mapped(r, backends.get(r.backend.as_str())) {
            continue;
        }
        if callers {
            let _ = write!(b, "{}/", backend_space(&r.backend));
        }
        let _ = writeln!(b, "{} {}", r.host, backend_name(&r.backend));
    }
    if b.is_empty() {
        return None;
    }
    let sum = sha256(b.as_bytes());
    Some((
        format!("{ROUTE_FILE_PREFIX}{prefix}-{}.map", hex(&sum[..8])),
        b.into_bytes(),
    ))
}

/// routeFiles, by file name.
pub fn route_files(cfg: &Config, opts: &Options) -> BTreeMap<String, Vec<u8>> {
    let (public, internal) = split_rules(cfg);
    let backends: HashMap<&str, &Backend> =
        cfg.backends.iter().map(|b| (b.name.as_str(), b)).collect();
    let mut out = BTreeMap::new();
    if let Some((n, c)) = route_map(ROUTES_PUBLIC, &public, &backends, false) {
        out.insert(n, c);
    }
    if !opts.internal_ip.is_empty()
        && let Some((n, c)) =
            route_map(ROUTES_INTERNAL, &internal, &backends, opts.checks_callers())
    {
        out.insert(n, c);
    }
    out
}

impl RuleRenderer<'_> {
    fn write(&self, o: &mut Out, prefix: &str, rules: &[&Rule]) {
        let rules = sort_rules(rules);
        let (own, via_map): (Vec<&Rule>, Vec<&Rule>) = rules
            .iter()
            .partition(|r| !mapped(r, self.backends.get(r.backend.as_str())));
        for (i, r) in own.iter().enumerate() {
            let mut set = format!(
                "    http-request set-var(txn.route) str({prefix}{i}) if !{{ var(txn.route) -m found }} {{ var(txn.host) -m str {} }}",
                r.host
            );
            if self.callers {
                set += &format!(
                    " {{ var(txn.cspace) -m str {} }}",
                    backend_space(&r.backend)
                );
                if !r.allow.is_empty() {
                    set += &format!(" {{ var(txn.capp) -m str {} }}", r.allow.join(" "));
                }
            }
            if r.path_prefix == "/" {
                w!(o, "%s", set);
                continue;
            }
            w!(o, "%s { var(txn.path) -m str %s }", set, r.path_prefix);
            w!(o, "%s { var(txn.path) -m beg %s/ }", set, r.path_prefix);
        }
        if let Some((name, _)) = route_map(prefix, &rules, self.backends, self.callers) {
            let path = format!("{CONTAINER_CONF_DIR}/{name}");
            if self.callers {
                w!(
                    o,
                    "    http-request set-var(txn.rkey) var(txn.cspace),concat(/,txn.host) if !{ var(txn.route) -m found }"
                );
                w!(
                    o,
                    "    http-request set-var(txn.route) var(txn.rkey),map(%s) if !{ var(txn.route) -m found }",
                    path
                );
            } else {
                w!(
                    o,
                    "    http-request set-var(txn.route) var(txn.host),map(%s) if !{ var(txn.route) -m found }",
                    path
                );
            }
        }
        let matcher = |i: usize| format!("{{ var(txn.route) -m str {prefix}{i} }}");
        for (i, r) in own.iter().enumerate() {
            if r.strip_prefix {
                w!(
                    o,
                    "    http-request set-path /%%[path,field(%d,/,0)] if %s",
                    strip_field(&r.path_prefix),
                    matcher(i)
                );
            }
        }
        for (i, r) in own.iter().enumerate() {
            if self
                .backends
                .get(r.backend.as_str())
                .is_some_and(|b| b.wake)
            {
                w!(
                    o,
                    "    use_backend %s if %s { nbsrv(%s) eq 0 }",
                    wake_backend_name(&r.backend),
                    matcher(i),
                    backend_name(&r.backend)
                );
            }
            w!(
                o,
                "    use_backend %s if %s",
                backend_name(&r.backend),
                matcher(i)
            );
        }
        if !via_map.is_empty() {
            w!(
                o,
                "    use_backend %%[var(txn.route)] if { var(txn.route) -m beg be_ }"
            );
        }
    }
}

fn write_proxy_protocol(o: &mut Out, sources: &[String]) {
    if sources.is_empty() {
        return;
    }
    w!(
        o,
        "    tcp-request connection expect-proxy layer4 if { src %s }",
        sources.join(" ")
    );
}

fn write_public_routes(
    o: &mut Out,
    cfg: &Config,
    rr: &RuleRenderer,
    public: &[&Rule],
    scheme: &str,
) {
    w!(
        o,
        "    http-request set-header X-Forwarded-Proto %s",
        scheme
    );
    let mut unless = "";
    if !cfg.trusted_proxies.is_empty() {
        w!(
            o,
            "    acl trusted_proxy src %s",
            cfg.trusted_proxies.join(" ")
        );
        unless = " unless trusted_proxy";
    }
    for h in CLIENT_ADDRESS_HEADERS {
        w!(o, "    http-request del-header %s%s", h, unless);
    }
    for h in FORWARDED_URL_HEADERS {
        w!(o, "    http-request del-header %s", h);
    }
    write_client_address(o, &cfg.trusted_proxies);
    w!(o, "    http-request del-header %s", CLIENT_IP_HEADER);
    w!(
        o,
        "    http-request set-header %s %%[var(txn.client)] if { var(txn.client) -m found }",
        CLIENT_IP_HEADER
    );
    w!(
        o,
        "    http-request set-var(txn.host) req.hdr(host),field(1,:),lower"
    );
    w!(o, "    http-request set-var(txn.path) path");
    rr.write(o, ROUTES_PUBLIC, public);
    w!(o, "    default_backend be_armada_notfound");
}

/// safeConfig: every value render interpolates is one token.
fn safe_config(cfg: &Config, opts: &Options) -> bool {
    let mut vals: Vec<&str> = vec![
        &cfg.acme_address,
        &opts.private_ip,
        &opts.internal_ip,
        &opts.subnet,
    ];
    vals.extend(cfg.trusted_proxies.iter().map(String::as_str));
    vals.extend(cfg.proxy_protocol.iter().map(String::as_str));
    for be in &cfg.backends {
        vals.push(&be.name);
        vals.push(&be.health_path);
        vals.extend(be.ip_allow.iter().map(String::as_str));
        vals.extend(be.ip_deny.iter().map(String::as_str));
        if let Some(c) = &be.cors {
            for l in [&c.origins, &c.methods, &c.headers, &c.expose] {
                vals.extend(l.iter().map(String::as_str));
            }
        }
        for s in &be.servers {
            vals.push(&s.name);
            vals.push(&s.address);
        }
    }
    for r in &cfg.rules {
        vals.push(&r.host);
        vals.push(&r.path_prefix);
        vals.push(&r.backend);
        vals.extend(r.allow.iter().map(String::as_str));
    }
    for r in &cfg.tcp {
        vals.push(&r.backend);
        vals.extend(r.allow.iter().map(String::as_str));
    }
    for c in &cfg.certificates {
        vals.push(&c.name);
    }
    vals.iter().all(|v| safe_token(v))
}

/// safeToken: no space or control character (unicode.IsSpace and
/// unicode.IsControl are White_Space and Cc, as in Rust).
fn safe_token(s: &str) -> bool {
    !s.chars()
        .any(|r| r <= ' ' || r == '\x7f' || r.is_whitespace() || r.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_verbs() {
        let mut o = Out::default();
        w!(o, "a %s b %d c %%[x] { y }", "s", 7);
        assert_eq!(o.0, "a s b 7 c %[x] { y }\n");
    }

    #[test]
    fn node_addresses() {
        let o = Options {
            private_ip: "10.0.0.5".into(),
            subnet: "10.120.3.0/24".into(),
            ..Default::default()
        };
        let n = o.node();
        assert!(n.has("10.0.0.5:8080"));
        assert!(n.has("10.120.3.9:80"));
        assert!(!n.has("10.120.4.9:80"));
        assert!(!n.has("10.0.0.6:80"));
        assert!(!Options::default().node().has("10.0.0.5:1"));
    }

    #[test]
    fn tokens() {
        assert!(safe_token("a.example.com"));
        assert!(!safe_token("a b"));
        assert!(!safe_token("a\u{a0}b"));
        assert!(!safe_token("a\u{2028}"));
        assert!(!safe_token("a\u{85}"));
    }
}

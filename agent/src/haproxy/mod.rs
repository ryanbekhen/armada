//! HAProxy behind the agent's [`Proxy`] seam (ADR 0055, item 16d): Go's
//! internal/proxy/haproxy driver with armada-node's renderer called in
//! process. Structural changes are rendered, checked with `haproxy -c`,
//! and reloaded (SIGUSR2, then the new process is waited for through `show
//! info`); servers, weights, the local and clients maps, and renewed
//! certificates change live through the Runtime API; a running HAProxy that
//! outlived its agent is taken over without a reload when its
//! configuration differs only in server lines. The files it writes (the
//! configuration, route maps, local.map, clients.map, certificates) are
//! Go's byte for byte, so either agent takes over from the other.

pub mod api;
pub mod config;
pub mod engine;
pub mod parse;

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use armada_node::proxy::render;
use armada_node::proxy::{Layout, Options};
use armada_proto::armada::v1 as pb;
use armada_spec::go::{parse_addr, parse_prefix, quote};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::log::Logger;
use crate::proxy::{BoxFut, Clients, Proxy, ServerLoad};
use api::Api;
use config::{ProxyConfig, file_name, is_private, parse_addr_port};

/// Where the configuration is inside HAProxy's container.
pub const CONTAINER_CONF_DIR: &str = "/usr/local/etc/haproxy";
pub const CONTAINER_RUN_DIR: &str = "/var/run/haproxy";
pub const CONFIG_FILE: &str = "haproxy.cfg";
pub const DEFAULT_CERT_FILE: &str = "default.pem";
pub const CERT_DIR: &str = "certs";
pub const SOCKET_FILE: &str = "admin.sock";
pub const CLIENTS_FILE: &str = "clients.map";
pub const LOCAL_FILE: &str = "local.map";
pub const ROUTE_FILE_PREFIX: &str = "routes-";
/// The clients map's bound: a node subnet holds at most 253 containers.
pub const MAX_CLIENTS: usize = 4096;
/// The lines sent in one command: HAProxy holds a payload in 16 KiB.
pub const MAP_CHUNK: usize = 8 << 10;

/// How long a reload waits for the new process to answer, and how often
/// it asks.
pub const RELOAD_WAIT: Duration = Duration::from_secs(10);
pub const RELOAD_POLL: Duration = Duration::from_millis(50);

/// The HAProxy process (Go's Engine).
pub trait Engine: Send + Sync + 'static {
    fn running(&self) -> BoxFut<'_, Result<bool, String>>;
    /// (Re)creates the HAProxy container from the current config file.
    fn start(&self) -> BoxFut<'_, Result<(), String>>;
    /// Runs `haproxy -c` against a config file (its path in the container).
    fn validate<'a>(&'a self, file: &'a str) -> BoxFut<'a, Result<(), String>>;
    /// Reloads the configuration (master-worker SIGUSR2).
    fn reload(&self) -> BoxFut<'_, Result<(), String>>;
}

/// The node's listening TCP sockets (ADR 0039).
pub type ListenersFn = Arc<dyn Fn() -> Result<Vec<SocketAddr>, String> + Send + Sync>;

/// What a Driver runs with (Go's haproxy.Config).
pub struct DriverConfig {
    /// Holds etc/ (configuration, certificates) and run/ (the Runtime API
    /// socket), 0700.
    pub dir: PathBuf,
    pub private_ip: String,
    /// The bridge's gateway for the internal frontend; "" for none.
    pub internal_ip: String,
    /// The node's container subnet in the cluster network; "" for none.
    pub subnet: String,
    pub engine: Arc<dyn Engine>,
    /// None: the socket under dir.
    pub api: Option<Arc<dyn Api>>,
    /// None: /proc/net.
    pub listeners: Option<ListenersFn>,
    pub logger: Logger,
    /// How long a reload waits (RELOAD_WAIT unless tests shorten it).
    pub reload_wait: Duration,
}

/// What a server slot serves: a replica's address and its weight.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Slot {
    pub addr: String,
    pub weight: i64,
}

#[derive(Default)]
struct St {
    sig: String,
    layout: Layout,
    /// "backend/slot" → what it serves; a default Slot is free.
    applied: HashMap<String, Slot>,
    /// File name → SHA-256 of its PEM.
    cert_hash: HashMap<String, String>,
    /// The clients and local maps HAProxy last loaded or was given.
    clients: Option<Vec<u8>>,
    local: Vec<u8>,
    worker_pid: String,
    totals: HashMap<String, i64>,
    carried: HashMap<String, i64>,
    /// The TCP ports the running HAProxy listens on, and those left out.
    held: Vec<i64>,
    busy: Vec<i64>,
}

/// The HAProxy driver.
pub struct Driver {
    dir: PathBuf,
    private_ip: String,
    internal_ip: String,
    subnet: String,
    engine: Arc<dyn Engine>,
    api: Arc<dyn Api>,
    listeners: ListenersFn,
    log: Logger,
    reload_wait: Duration,
    st: Mutex<St>,
}

fn etc_dir(dir: &Path) -> PathBuf {
    dir.join("etc")
}

fn run_dir(dir: &Path) -> PathBuf {
    dir.join("run")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    armada_fsutil::write_file_atomic(path, data, 0o600).map_err(|e| e.to_string())
}

fn slot_key(pool: &str, i: usize) -> String {
    format!("{pool}/{}", render::slot_name(i))
}

/// assignLayout: replicas keep their slot; new ones take the lowest free.
pub fn assign_layout(prev: &Layout, cfg: &armada_node::proxy::Config, n: &render::Node) -> Layout {
    let mut next = Layout::new();
    for (name, servers) in render::pools(cfg, n) {
        let count = render::slot_count(servers.len());
        let mut slots = vec![String::new(); count];
        let mut want: std::collections::BTreeSet<String> =
            servers.iter().map(|s| s.name.clone()).collect();
        if let Some(p) = prev.get(&name) {
            for (i, s) in p.iter().enumerate() {
                if i < count && want.remove(s) {
                    slots[i] = s.clone();
                }
            }
        }
        for s in want {
            if let Some(free) = slots.iter_mut().find(|x| x.is_empty()) {
                *free = s;
            }
        }
        next.insert(name, slots);
    }
    next
}

/// desiredServers: what every slot serves.
pub fn desired_servers(
    cfg: &armada_node::proxy::Config,
    layout: &Layout,
    n: &render::Node,
) -> HashMap<String, Slot> {
    let mut out = HashMap::new();
    for (name, servers) in render::pools(cfg, n) {
        let slots: HashMap<&str, Slot> = servers
            .iter()
            .map(|s| {
                (
                    s.name.as_str(),
                    Slot {
                        addr: s.address.clone(),
                        weight: s.effective_weight(),
                    },
                )
            })
            .collect();
        for (i, replica) in layout.get(&name).into_iter().flatten().enumerate() {
            // A free slot is rendered with the default weight.
            let want = slots.get(replica.as_str()).cloned().unwrap_or(Slot {
                addr: String::new(),
                weight: 1,
            });
            out.insert(slot_key(&name, i), want);
        }
    }
    out
}

/// signature: everything that needs a reload (backends and their slot
/// counts, checks, rules, the certificate set, the node's settings, and
/// which replica holds each slot of a sticky backend), never addresses.
fn signature(cfg: &armada_node::proxy::Config, layout: &Layout, opts: &Options) -> String {
    let mut backends: Vec<serde_json::Value> = cfg
        .backends
        .iter()
        .map(|b| {
            let name = render::backend_name(&b.name);
            let slots = layout.get(&name).cloned().unwrap_or_default();
            json!({
                "Name": b.name, "Health": b.health_path, "Slots": slots.len(),
                "Wake": b.wake, "LocalFirst": b.local_first, "Timeout": b.timeout_seconds,
                "IPAllow": b.ip_allow, "IPDeny": b.ip_deny, "Sticky": b.sticky,
                "CORS": b.cors.as_ref().map(|c| json!({
                    "Origins": c.origins, "Methods": c.methods, "Headers": c.headers,
                    "Expose": c.expose, "MaxAgeSeconds": c.max_age_seconds, "Credentials": c.credentials,
                })),
                "Replicas": if b.sticky { Some(slots) } else { None },
            })
        })
        .collect();
    backends.sort_by(|a, b| a["Name"].as_str().cmp(&b["Name"].as_str()));
    let mut rules: Vec<serde_json::Value> = cfg
        .rules
        .iter()
        .map(|r| {
            json!({"Host": r.host, "PathPrefix": r.path_prefix, "StripPrefix": r.strip_prefix,
                "Backend": r.backend, "Internal": r.internal, "Allow": r.allow})
        })
        .collect();
    rules.sort_by_key(|r| {
        format!(
            "{}{}",
            r["Host"].as_str().unwrap_or(""),
            r["PathPrefix"].as_str().unwrap_or("")
        )
    });
    let mut tcp: Vec<(i64, String, Vec<String>)> = cfg
        .tcp
        .iter()
        .map(|r| (r.port, r.backend.clone(), r.allow.clone()))
        .collect();
    tcp.sort();
    let mut certs: Vec<&str> = cfg.certificates.iter().map(|c| c.name.as_str()).collect();
    certs.sort_unstable();
    let s = json!({
        "Opts": {"PrivateIP": opts.private_ip, "InternalIP": opts.internal_ip,
            "Subnet": opts.subnet, "BusyTCP": opts.busy_tcp},
        "ACME": cfg.acme_address, "Plain": cfg.plain_http, "Trusted": cfg.trusted_proxies,
        "PROXY": cfg.proxy_protocol, "Backends": backends, "Rules": rules, "TCP": tcp, "Certs": certs,
    });
    hex(&Sha256::digest(s.to_string().as_bytes()))
}

/// clientsMap: one "<address> <space>:<app ID>" line per container of the
/// node subnet, sorted, each checked again.
pub fn clients_map(clients: &Clients, subnet: &str) -> Result<Vec<u8>, String> {
    if clients.len() > MAX_CLIENTS {
        return Err(format!("{} clients: at most {MAX_CLIENTS}", clients.len()));
    }
    let subnet = parse_prefix(subnet).ok_or("invalid subnet")?;
    let mut out = String::new();
    // BTreeMap<IpAddr, _> sorts IPv4 addresses as netip.Addr.Compare does.
    for (a, app) in clients {
        let ok = match a {
            IpAddr::V4(v4) => {
                parse_addr(&v4.to_string()).is_some_and(|x| subnet.contains(&x))
                    && armada_spec::validate::valid_app_id(app)
            }
            IpAddr::V6(_) => false,
        };
        if !ok {
            return Err(format!("invalid client {a} ({})", quote(app)));
        }
        let space = armada_spec::validate::split_app_id(app)
            .map(|(s, _)| s)
            .unwrap_or_default();
        out.push_str(&format!("{a} {space}:{app}\n"));
    }
    Ok(out.into_bytes())
}

/// mapChunks: content split at line ends into pieces of about limit bytes.
pub fn map_chunks(content: &[u8], limit: usize) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut content = content;
    while content.len() > limit {
        let mut cut = content[..limit]
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i + 1);
        if cut == 0 {
            match content.iter().position(|&b| b == b'\n') {
                Some(i) => cut = i + 1,
                None => break,
            }
        }
        out.push(&content[..cut]);
        content = &content[cut..];
    }
    if !content.is_empty() {
        out.push(content);
    }
    out
}

/// selfSignedPEM: the certificate served for unknown names, so HAProxy
/// starts before any real one exists.
pub fn self_signed_pem() -> Result<Vec<u8>, String> {
    let key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "armada-default");
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(3650);
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let mut serial = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut serial))
        .map_err(|e| e.to_string())?;
    serial[0] &= 0x7f;
    params.serial_number = Some(rcgen::SerialNumber::from(serial.to_vec()));
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
    let mut out = cert.pem().into_bytes();
    out.extend_from_slice(key.serialize_pem().as_bytes());
    Ok(out)
}

impl Driver {
    /// Prepares the directories, the empty maps, and the default
    /// certificate (Go's New).
    pub fn new(cfg: DriverConfig) -> Result<Driver, String> {
        if !cfg.private_ip.is_empty() && parse_addr(&cfg.private_ip).is_none() {
            return Err(format!(
                "haproxy: invalid private IP {}",
                quote(&cfg.private_ip)
            ));
        }
        if !cfg.subnet.is_empty() {
            let ok =
                parse_prefix(&cfg.subnet).is_some_and(|p| p.masked() == p && is_private(&p.addr));
            if !ok {
                return Err(format!(
                    "haproxy: subnet {} must be a private prefix",
                    quote(&cfg.subnet)
                ));
            }
        }
        if !cfg.internal_ip.is_empty()
            && !parse_addr(&cfg.internal_ip).is_some_and(|a| is_private(&a))
        {
            return Err(format!(
                "haproxy: internal IP {} must be a private address",
                quote(&cfg.internal_ip)
            ));
        }
        let etc = etc_dir(&cfg.dir);
        for d in [
            cfg.dir.clone(),
            etc.clone(),
            etc.join(CERT_DIR),
            run_dir(&cfg.dir),
        ] {
            armada_fsutil::mkdir_private(&d).map_err(|e| e.to_string())?;
        }
        let api = cfg.api.clone().unwrap_or_else(|| {
            Arc::new(api::Socket {
                path: run_dir(&cfg.dir).join(SOCKET_FILE),
                timeout: Duration::ZERO,
            })
        });
        let listeners = cfg
            .listeners
            .clone()
            .unwrap_or_else(|| Arc::new(parse::proc_listeners));
        // A HAProxy that outlives its agent holds the TCP ports of the
        // configuration it runs.
        let held = std::fs::read(etc.join(CONFIG_FILE))
            .map(|b| parse::held_tcp(&b))
            .unwrap_or_default();
        // HAProxy reads its maps at start: empty until the agent knows its
        // containers.
        for name in [CLIENTS_FILE, LOCAL_FILE] {
            let p = etc.join(name);
            if !p.exists() {
                write_private(&p, b"")?;
            }
        }
        let def = etc.join(DEFAULT_CERT_FILE);
        if !def.exists() {
            write_private(&def, &self_signed_pem()?)?;
        }
        Ok(Driver {
            dir: cfg.dir,
            private_ip: cfg.private_ip,
            internal_ip: cfg.internal_ip,
            subnet: cfg.subnet,
            engine: cfg.engine,
            api,
            listeners,
            log: cfg.logger.with("component", "haproxy"),
            reload_wait: if cfg.reload_wait.is_zero() {
                RELOAD_WAIT
            } else {
                cfg.reload_wait
            },
            st: Mutex::new(St {
                held,
                ..St::default()
            }),
        })
    }

    fn etc(&self) -> PathBuf {
        etc_dir(&self.dir)
    }

    /// The node's parts of the configuration.
    fn options(&self) -> Options {
        Options {
            private_ip: self.private_ip.clone(),
            internal_ip: self.internal_ip.clone(),
            subnet: self.subnet.clone(),
            busy_tcp: Vec::new(),
        }
    }

    /// busyPorts: the TCP ports of cfg another program holds; logs when
    /// that changes.
    fn busy_ports(&self, st: &mut St, pc: &ProxyConfig, opts: &Options) -> Vec<i64> {
        let mut busy = Vec::new();
        if opts.serves_tcp() && !pc.cfg.tcp.is_empty() {
            match (self.listeners)() {
                Err(e) => {
                    self.log.warn(
                        "cannot read the node's listening sockets; no internal TCP listeners",
                        &[("err", e)],
                    );
                    busy = pc.tcp_ports();
                }
                Ok(ls) => {
                    let gw: IpAddr = opts
                        .internal_ip
                        .parse()
                        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
                    busy = parse::busy_tcp(&pc.tcp_ports(), gw, &ls, &st.held);
                }
            }
        }
        if busy != st.busy {
            if !busy.is_empty() {
                let list: Vec<String> = busy.iter().map(ToString::to_string).collect();
                self.log.warn(
                    "another program listens on these TCP ports; apps using them are not reachable from this node",
                    &[("ports", format!("[{}]", list.join(" ")))],
                );
            }
            st.busy = busy.clone();
        }
        busy
    }

    /// liveConfig: takes over a running HAProxy whose certificates are the
    /// configuration's, from the slots it reports.
    async fn live_config(&self, st: &mut St, pc: &ProxyConfig, opts: &Options) -> Option<Vec<u8>> {
        if !st.sig.is_empty() {
            return None;
        }
        if !matches!(self.engine.running().await, Ok(true)) {
            return None;
        }
        let live = std::fs::read(self.etc().join(CONFIG_FILE)).ok()?;
        let mut have: Vec<String> = std::fs::read_dir(self.etc().join(CERT_DIR))
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        let mut want: Vec<String> = pc
            .cfg
            .certificates
            .iter()
            .map(|c| file_name(&c.name))
            .collect();
        have.sort();
        want.sort();
        if have != want {
            return None;
        }
        let out = match self.api.command("show servers state").await {
            Ok(o) => o,
            Err(e) => {
                self.log
                    .debug("read the running proxy's servers", &[("err", e)]);
                return None;
            }
        };
        let slots = parse::parse_servers_state(&out);
        if slots.is_empty() {
            return None;
        }
        let (layout, applied) = layout_from_slots(&slots, &pc.cfg, &opts.node());
        st.layout = layout;
        st.applied = applied;
        Some(live)
    }

    /// writeCerts: writes changed certificates, removes stale ones, and
    /// returns the names that existed and changed.
    fn write_certs(&self, st: &mut St, pc: &ProxyConfig) -> Result<Vec<String>, String> {
        let dir = self.etc().join(CERT_DIR);
        let mut want = std::collections::HashSet::new();
        let mut changed = Vec::new();
        for (i, c) in pc.cfg.certificates.iter().enumerate() {
            let name = file_name(&c.name);
            want.insert(name.clone());
            let pem = pc.pems.get(i).map(Vec::as_slice).unwrap_or(&[]);
            let h = hex(&Sha256::digest(pem));
            if st.cert_hash.get(&name) == Some(&h) {
                continue;
            }
            write_private(&dir.join(&name), pem)?;
            if st.cert_hash.get(&name).is_some_and(|x| !x.is_empty()) {
                changed.push(name.clone());
            }
            st.cert_hash.insert(name, h);
        }
        let entries = std::fs::read_dir(&dir).map_err(|e| e.to_string())?;
        for e in entries.filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().into_owned();
            if !want.contains(&name) {
                let _ = std::fs::remove_file(e.path());
                st.cert_hash.remove(&name);
            }
        }
        changed.sort();
        Ok(changed)
    }

    async fn update_cert(&self, file: &str, pc: &ProxyConfig) -> Result<(), String> {
        let mut data: &[u8] = &[];
        for (i, c) in pc.cfg.certificates.iter().enumerate() {
            if file_name(&c.name) == file {
                data = pc.pems.get(i).map(Vec::as_slice).unwrap_or(&[]);
            }
        }
        let path = format!("{CONTAINER_CONF_DIR}/{CERT_DIR}/{file}");
        self.api
            .payload(&format!("set ssl cert {path}"), &api::pem_payload(data))
            .await?;
        self.api
            .command(&format!("commit ssl cert {path}"))
            .await
            .map(|_| ())
    }

    /// reload: SIGUSR2, then waits until `show info` names a new process.
    async fn reload(&self, st: &mut St) -> Result<(), String> {
        let old = self
            .api
            .command("show info")
            .await
            .map(|i| parse::worker_pid(&i))
            .unwrap_or_default();
        self.engine
            .reload()
            .await
            .map_err(|e| format!("reload haproxy: {e}"))?;
        if old.is_empty() {
            return Ok(());
        }
        let deadline = tokio::time::Instant::now() + self.reload_wait;
        loop {
            if let Ok(info) = self.api.command("show info").await {
                let pid = parse::worker_pid(&info);
                if !pid.is_empty() && pid != old {
                    return Ok(());
                }
            }
            if tokio::time::Instant::now() > deadline {
                st.sig.clear(); // the next Apply reloads again
                return Err(format!(
                    "reload haproxy: the new process did not answer within {}",
                    crate::clock::duration_string(self.reload_wait.as_nanos() as i64)
                ));
            }
            tokio::time::sleep(RELOAD_POLL).await;
        }
    }

    /// removeOldRoutes: deletes route maps the configuration does not use.
    fn remove_old_routes(&self, keep: &BTreeMap<String, Vec<u8>>) {
        let Ok(entries) = std::fs::read_dir(self.etc()) else {
            return;
        };
        for e in entries.filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().into_owned();
            if !keep.contains_key(&name)
                && name.starts_with(ROUTE_FILE_PREFIX)
                && let Err(err) = std::fs::remove_file(e.path())
            {
                self.log
                    .debug("remove an old route map", &[("err", err.to_string())]);
            }
        }
    }

    /// writeValidated: the new configuration replaces the live one only
    /// once haproxy -c accepts it, unless only servers changed.
    async fn write_validated(&self, path: &Path, content: &[u8]) -> Result<(), String> {
        let cur = std::fs::read(path);
        if let Ok(cur) = &cur {
            if cur == content {
                return Ok(());
            }
            if parse::same_structure(cur, content) {
                return write_private(path, content);
            }
        }
        let next = path.with_file_name(format!("{CONFIG_FILE}.new"));
        write_private(&next, content)?;
        let file = format!("{CONTAINER_CONF_DIR}/{CONFIG_FILE}.new");
        if let Err(e) = self.engine.validate(&file).await {
            let _ = std::fs::remove_file(&next);
            return Err(format!(
                "generated haproxy config is invalid, keeping the current one: {e}"
            ));
        }
        std::fs::rename(&next, path).map_err(|e| e.to_string())
    }

    fn commit(&self, st: &mut St, sig: String, layout: Layout, cfg: &armada_node::proxy::Config) {
        st.applied = desired_servers(cfg, &layout, &self.options().node());
        st.sig = sig;
        st.layout = layout;
    }

    async fn set_server(&self, key: &str, cur: &Slot, want: &Slot) -> Result<(), String> {
        if want.addr.is_empty() {
            return self
                .api
                .command(&format!("set server {key} state maint"))
                .await
                .map(|_| ());
        }
        if want.weight != cur.weight {
            self.api
                .command(&format!("set server {key} weight {}", want.weight))
                .await?;
        }
        if want.addr == cur.addr {
            return Ok(());
        }
        let ap = parse_addr_port(&want.addr)
            .ok_or_else(|| format!("ParseAddrPort({}): invalid", quote(&want.addr)))?;
        let ip = ap.addr.string();
        self.api
            .command(&format!("set server {key} addr {ip} port {}", ap.port))
            .await?;
        self.api
            .command(&format!("set server {key} state ready"))
            .await
            .map(|_| ())
    }

    /// replaceMap: swaps a map of the running HAProxy in one step.
    async fn replace_map(&self, name: &str, content: &[u8]) -> Result<(), String> {
        let file = format!("{CONTAINER_CONF_DIR}/{name}");
        let out = self.api.command(&format!("prepare map {file}")).await?;
        let ver = out
            .trim()
            .strip_prefix("New version created:")
            .map(str::trim)
            .filter(|v| !v.is_empty() && v.bytes().all(|c| c.is_ascii_digit()));
        let Some(ver) = ver else {
            return Err(format!("unexpected answer to prepare map: {}", quote(&out)));
        };
        for chunk in map_chunks(content, MAP_CHUNK) {
            self.api
                .payload(
                    &format!("add map @{ver} {file}"),
                    &String::from_utf8_lossy(chunk),
                )
                .await?;
        }
        self.api
            .command(&format!("commit map @{ver} {file}"))
            .await
            .map(|_| ())
    }

    /// Apply of a proxy.Config.
    pub async fn apply_config(&self, pc: &ProxyConfig) -> Result<(), String> {
        pc.validate()
            .map_err(|e| format!("refusing invalid proxy config: {e}"))?;
        let mut guard = self.st.lock().await;
        let st = &mut *guard;
        let mut opts = self.options();
        opts.busy_tcp = self.busy_ports(st, pc, &opts);
        let node = opts.node();
        let live = self.live_config(st, pc, &opts).await;
        let layout = assign_layout(&st.layout, &pc.cfg, &node);
        let sig = signature(&pc.cfg, &layout, &opts);
        let Some(content) = render::render(&pc.cfg, &layout, &opts) else {
            return Err(
                "refusing proxy config: an interpolated value is not a single token".into(),
            );
        };
        let content = content.into_bytes();
        let routes = render::route_files(&pc.cfg, &opts);
        let local = render::local_map(&pc.cfg, &layout, &node);

        let adopted = live
            .as_deref()
            .is_some_and(|l| parse::same_structure(l, &content));
        let mut changed_certs = self.write_certs(st, pc)?;
        if adopted {
            // A certificate may have been renewed while no agent ran.
            changed_certs = pc
                .cfg
                .certificates
                .iter()
                .map(|c| file_name(&c.name))
                .collect();
            st.sig = sig.clone();
            st.held = parse::held_tcp(&content);
            self.log.info("kept the running haproxy", &[]);
        }
        let etc = self.etc();
        for (name, b) in &routes {
            write_private(&etc.join(name), b)?;
        }
        if local != st.local {
            write_private(&etc.join(LOCAL_FILE), &local)?;
        }

        let running = self.engine.running().await?;
        let cfg_path = etc.join(CONFIG_FILE);
        if !running {
            // Nothing serves traffic yet: there is no old config to keep.
            write_private(&cfg_path, &content)?;
            self.engine
                .start()
                .await
                .map_err(|e| format!("start haproxy: {e}"))?;
            self.commit(st, sig, layout, &pc.cfg);
            st.held = parse::held_tcp(&content);
            st.local = local;
            self.remove_old_routes(&routes);
            self.log.info("haproxy started", &[]);
            return Ok(());
        }

        self.write_validated(&cfg_path, &content).await?;

        if sig != st.sig {
            // What the outgoing process counted would otherwise be lost.
            if let Err(e) = self.load_locked(st).await {
                self.log
                    .debug("read proxy load before a reload", &[("err", e)]);
            }
            self.reload(st).await?;
            self.commit(st, sig, layout, &pc.cfg);
            st.held = parse::held_tcp(&content);
            st.local = local;
            self.remove_old_routes(&routes);
            self.log.info("haproxy reloaded", &[]);
            return Ok(());
        }

        // Same structure: servers and certificates change live, new
        // servers enabled before old ones leave.
        let desired = desired_servers(&pc.cfg, &layout, &node);
        let mut keys: Vec<&String> = desired.keys().collect();
        keys.sort();
        for enable in [true, false] {
            for key in &keys {
                let cur = st.applied.get(*key).cloned().unwrap_or_default();
                let mut want = desired[*key].clone();
                if cur == want
                    || (want.addr.is_empty() && cur.addr.is_empty())
                    || (!want.addr.is_empty()) != enable
                {
                    continue;
                }
                self.set_server(key, &cur, &want).await?;
                if want.addr.is_empty() {
                    want.weight = cur.weight; // maintenance keeps the weight
                }
                st.applied.insert((*key).clone(), want);
            }
        }
        if local != st.local {
            self.replace_map(LOCAL_FILE, &local)
                .await
                .map_err(|e| format!("update the local map: {e}"))?;
            st.local = local;
        }
        for name in &changed_certs {
            if let Err(e) = self.update_cert(name, pc).await {
                // The file on disk is the new certificate: a reload loads it.
                self.log.warn(
                    "live certificate update failed; reloading",
                    &[("cert", name.clone()), ("err", e)],
                );
                self.reload(st)
                    .await
                    .map_err(|e| format!("reload haproxy for certificate {name}: {e}"))?;
                break;
            }
        }
        st.layout = layout;
        Ok(())
    }

    /// SetClients: the clients map for the internal frontend's checks,
    /// written for the next start and swapped into a running HAProxy.
    pub async fn set_clients_map(&self, clients: &Clients) -> Result<(), String> {
        if self.subnet.is_empty() {
            return Ok(());
        }
        let content = clients_map(clients, &self.subnet)?;
        let mut st = self.st.lock().await;
        if st.clients.as_deref() == Some(content.as_slice()) {
            return Ok(());
        }
        write_private(&self.etc().join(CLIENTS_FILE), &content)?;
        if self.engine.running().await? {
            self.replace_map(CLIENTS_FILE, &content)
                .await
                .map_err(|e| format!("update the clients map: {e}"))?;
        }
        st.clients = Some(content);
        Ok(())
    }

    /// load with the lock held: totals carried over from one process to
    /// the next.
    async fn load_locked(&self, st: &mut St) -> Result<BTreeMap<String, ServerLoad>, String> {
        let info = self.api.command("show info").await?;
        let out = self.api.command("show stat -1 4 -1 no-maint").await?;
        let load = parse::parse_load(&out, &st.layout)?;
        let pid = parse::worker_pid(&info);
        if pid != st.worker_pid {
            if !st.worker_pid.is_empty() {
                st.carried = std::mem::take(&mut st.totals);
            }
            st.worker_pid = pid;
        }
        let mut out = BTreeMap::new();
        let mut totals = HashMap::with_capacity(load.len());
        for (id, mut l) in load {
            l.total += st.carried.get(&id).copied().unwrap_or(0);
            totals.insert(id.clone(), l.total);
            out.insert(id, l);
        }
        st.totals = totals;
        Ok(out)
    }

    /// The layout the driver keeps, for the tests.
    pub async fn layout(&self) -> Layout {
        self.st.lock().await.layout.clone()
    }
}

/// layoutFromSlots: the layout and slots of a running HAProxy, its servers
/// named by the configuration's replica at each address.
fn layout_from_slots(
    live: &HashMap<String, Vec<Slot>>,
    cfg: &armada_node::proxy::Config,
    n: &render::Node,
) -> (Layout, HashMap<String, Slot>) {
    let mut layout = Layout::new();
    let mut applied = HashMap::new();
    for (name, servers) in render::pools(cfg, n) {
        let by_addr: HashMap<&str, &str> = servers
            .iter()
            .map(|s| (s.address.as_str(), s.name.as_str()))
            .collect();
        let slots = live.get(&name).cloned().unwrap_or_default();
        let mut names = vec![String::new(); slots.len()];
        for (i, s) in slots.iter().enumerate() {
            if !s.addr.is_empty() {
                names[i] = by_addr
                    .get(s.addr.as_str())
                    .copied()
                    .unwrap_or("")
                    .to_string();
            }
            applied.insert(slot_key(&name, i), s.clone());
        }
        layout.insert(name, names);
    }
    (layout, applied)
}

impl Proxy for Driver {
    fn apply<'a>(&'a self, cfg: &'a pb::ProxyConfig) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async move { self.apply_config(&ProxyConfig::from_proto(cfg)).await })
    }

    fn health(&self) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async move {
            if !self.engine.running().await? {
                return Err("haproxy is not running".into());
            }
            self.api.command("show info").await.map(|_| ())
        })
    }

    fn sets_clients(&self) -> bool {
        true
    }

    fn set_clients<'a>(&'a self, clients: &'a Clients) -> BoxFut<'a, Result<(), String>> {
        Box::pin(self.set_clients_map(clients))
    }

    fn reads_load(&self) -> bool {
        true
    }

    fn load(&self) -> BoxFut<'_, Result<BTreeMap<String, ServerLoad>, String>> {
        Box::pin(async move {
            let mut st = self.st.lock().await;
            self.load_locked(&mut st).await
        })
    }
}

#[cfg(test)]
mod tests;

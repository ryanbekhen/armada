//! armadad doctor (Go's doctor.go and doctor_certs.go): the pre-flight
//! checks of this host with Go's names, order, levels, details, and exit
//! code. The cluster network's checks are armada-node's Diagnose, called
//! as a library, for an agent with no userspace WireGuard (ADR 0055).
//!
//! Where the Rust armadad does not do what Go's did, the check says what
//! it does (ADR 0055): a node on containerd fails the runtime check (this
//! armadad does not run containerd, so it has no containerd to ask), and
//! agent.json's "runtimeAgent": "go" is ignored, armada-node running the
//! containers.
//!
//! The parity tests' hooks (test-hooks builds only): HOST_ROOT prefixes
//! the host files read here (/proc, /sys, /etc, /lib), PACK_ID is the
//! runtime pack this armadad carries, and EUID, NEEDRESTART_DIR, and
//! VERSION stand for being root, needrestart's directory, and the version.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, UNIX_EPOCH};

use armada_agent::runtime::{
    AGENT_CONTAINERD, AGENT_SUPERVISOR_GO, AGENT_SUPERVISOR_RUST, AgentStatus, Runtime,
};
use armada_agent::supervisor::selinux::{Selinux, State as SelinuxState};
use armada_agent::supervisor::{self, Supervisor, host::LinuxHost};
use armada_client::cli::{Ctx, Error, Result};
use armada_client::release;
use armada_node::net::addr::Addr as NetAddr;
use armada_node::net::diagnose::{self, CHECK_FAIL, CHECK_OK, CHECK_WARN};
use armada_spec::go::Prefix;

use crate::agentconfig::{
    self, AgentConfig, DIR_ETCD, FILE_AGENT, FILE_CA_KEY, FILE_SERVER_CERT, RUNTIME_SUPERVISOR,
};
use crate::machine::{
    self, DEFAULT_CONTAINER_SUBNET, DEFAULT_RUNTIME, FILE_MASTER_KEY, FILE_MESH_CACHE,
    FILE_NODE_CERT, FILE_NODE_KEY, FILE_SERVER_KEY,
};
use crate::{hooks, netutil, systemd};

const OK: &str = "ok";
const WARN: &str = "warn";
const FAIL: &str = "FAIL";

/// The control plane's port, the join port, and HAProxy's statistics
/// (defaultPort, defaultPort+1, haproxy.MetricsPort).
const CLUSTER_PORTS: [u16; 3] = [7443, 7444, 8404];
const JOIN_PORT: u16 = 7444;
/// embedded.BridgeName.
const BRIDGE: &str = "armada0";
const FILE_ETCD_KEY: &str = "etcd/member.key";
/// Where needrestart reads extra settings, and Armada's file there.
const NEEDRESTART_DIR: &str = "/etc/needrestart/conf.d";
const NEEDRESTART_FILE: &str = "armada.conf";
const NEEDRESTART_SET: &str = "$nrconf{override_rc}{qr(^armada-)} = 0;";
/// Where the systemd unit reads armadad server's flags.
const SERVER_ENV_FILE: &str = "/etc/armada/server.env";
/// The server flags that are cluster settings (ADR 0031, clusterFlags).
const CLUSTER_FLAGS: [&str; 7] = [
    "tls",
    "acme-ca",
    "acme-email",
    "dns-provider",
    "dns-token-file",
    "metrics-listen",
    "node-lost-timeout",
];
/// conntrack.WarnPercent.
const CONNTRACK_WARN_PERCENT: i64 = 80;
/// How long before a user certificate expires doctor starts warning.
const USER_WARN_BEFORE: i128 = 30 * 24 * 3600 * 1_000_000_000;
const PING_TIMEOUT: Duration = Duration::from_secs(5);

/// One result (checkResult).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub status: &'static str,
    pub detail: String,
}

fn check(name: &str, status: &'static str, detail: impl Into<String>) -> Check {
    Check {
        name: name.to_string(),
        status,
        detail: detail.into(),
    }
}

/// A host file under the parity tests' root (the machine's own without).
fn host_file(p: &str) -> String {
    format!("{}{p}", hooks::get("HOST_ROOT").unwrap_or_default())
}

/// os.Open's and os.ReadFile's error text.
fn open_text(path: &str, e: &std::io::Error) -> String {
    format!("open {path}: {}", armada_fsutil::errno_text(e))
}

/// The Go agent's runtimeHint.
fn runtime_hint(rt: &str) -> &'static str {
    if rt == RUNTIME_SUPERVISOR {
        "the runtime pack is installed by armada-server or armada-agent; check sudo armadad doctor"
    } else {
        "systemctl start armada-runtime"
    }
}

/// What doctor reads of the machine (doctorEnv).
struct Env {
    euid: u32,
    data_dir: String,
    secrets_dir: String,
    private_ip: String,
    admin_config: String,
    ac: AgentConfig,
    /// The supervisor runtime, or why it cannot be opened; None on a node
    /// on containerd (this armadad has no containerd driver).
    driver: std::result::Result<Option<Supervisor>, String>,
    subnet: Option<Prefix>,
    endpoint: Option<IpAddr>,
    version: String,
    now_ns: i128,
}

pub fn run(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let data_dir = ctx.str("data-dir");
    let secrets_dir = ctx.str("secrets-dir");
    let mut private_ip = ctx.str("private-ip");
    let loaded = agentconfig::load(&data_dir).ok();
    // A node that has joined already knows its address.
    if private_ip.is_empty()
        && let Some(ac) = &loaded
    {
        private_ip = ac.private_ip.clone();
    }
    let mut ac = loaded.unwrap_or_default();
    if ac.container_subnet.is_empty() {
        ac.container_subnet = DEFAULT_CONTAINER_SUBNET.to_string();
    }
    let subnet = machine::parse_prefix_go(&ac.container_subnet).ok();
    let driver = open_driver(&data_dir, &ac);
    let endpoint = join_endpoint(&ac);
    let now_ns = crate::hooks::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0);
    let env = Env {
        euid: machine::euid(),
        admin_config: ctx.g.config_path.clone(),
        data_dir,
        secrets_dir,
        private_ip,
        ac,
        driver,
        subnet,
        endpoint,
        version: hooks::get("VERSION")
            .unwrap_or_else(|| armada_client::commands::version::get().version.to_string()),
        now_ns,
    };
    let results = ctx.block_on(run_doctor(&env));
    let mut out = String::new();
    let mut failed = 0;
    for r in &results {
        if r.status == FAIL {
            failed += 1;
        }
        out.push_str(&format!("[{:<4}] {:<14} {}\n", r.status, r.name, r.detail));
    }
    ctx.print(&out);
    if failed > 0 {
        return Err(Error::Msg(format!("{failed} check(s) failed")));
    }
    Ok(())
}

/// joinEndpoint: the endpoint the node announces (announcedEndpoint), where
/// the leader's join listener faces the public while a token for it is
/// open.
fn join_endpoint(ac: &AgentConfig) -> Option<IpAddr> {
    if ac.behind_nat {
        return None;
    }
    if !ac.endpoint.is_empty() || ac.network.is_empty() {
        return ac.endpoint.parse().ok();
    }
    netutil::detect_endpoint().ok().map(IpAddr::V4)
}

/// newDriver: the node's runtime as the agent opens it; the runtime pack
/// installed first on the supervisor runtime, as the agent does.
fn open_driver(
    data_dir: &str,
    ac: &AgentConfig,
) -> std::result::Result<Option<Supervisor>, String> {
    ac.check_runtime()?;
    let subnet = machine::parse_prefix_go(&ac.container_subnet)
        .map_err(|e| format!("{FILE_AGENT}: container subnet: {e}"))?;
    let mut mtu = 0;
    if !ac.network.is_empty() {
        // Containers reach other nodes through the tunnel, which takes its
        // overhead from each packet (ADR 0025).
        if ac.private_ip.parse::<IpAddr>().is_err() {
            return Err(format!(
                "{FILE_AGENT}: private IP: ParseAddr({}): unable to parse IP",
                armada_spec::go::quote(&ac.private_ip)
            ));
        }
        let ep = machine::uplink_endpoint(ac);
        mtu = armada_node::net::apply::container_mtu(&ac.network, &ac.private_ip, &ep, ac.mtu)
            .map_err(|e| format!("cluster network: {e}"))?;
    }
    if ac.runtime != RUNTIME_SUPERVISOR {
        machine::bridge_of(&subnet)?;
        return Ok(None);
    }
    crate::pack::install_pack(&crate::paths(data_dir))?;
    machine::bridge_of(&subnet)?;
    let mut cfg = supervisor::Config::new(
        PathBuf::from(data_dir),
        PathBuf::from(crate::run_dir()),
        armada_agent::log::Logger::discard(),
    );
    cfg.subnet = ac.container_subnet.clone();
    cfg.mtu = mtu as u32;
    Supervisor::new(cfg).map(Some)
}

async fn run_doctor(env: &Env) -> Vec<Check> {
    let mut out = Vec::new();
    if env.euid != 0 {
        out.push(check(
            "user",
            WARN,
            "not running as root; some checks may be incomplete",
        ));
    }
    out.extend(check_runtime(env).await);
    match doctor_private_ip(env) {
        Err(e) => out.push(check("private-ip", FAIL, e)),
        Ok(ip) => out.push(check("private-ip", OK, ip.to_string())),
    }
    out.push(check_listeners(env));
    out.push(check_data_dir(env));
    out.extend(check_certificates(env));
    if let Some(c) = check_etcd(env).await {
        out.push(c);
    }
    out.push(check_secrets_tmpfs(&env.secrets_dir));
    if let Some(c) = check_clock() {
        out.push(c);
    }
    if let Some(c) = check_firewall() {
        out.push(c);
    }
    let root = hooks::get("HOST_ROOT").unwrap_or_default();
    if armada_agent::side::nfs::nfs_supported_in(&root) {
        out.push(check(
            "nfs",
            OK,
            "the kernel has an NFSv4 client: apps with NFS volumes may run here",
        ));
    } else {
        out.push(check(
            "nfs",
            WARN,
            "the kernel has no NFSv4 client: apps with NFS volumes are not placed here",
        ));
    }
    if let Some(c) = check_needrestart() {
        out.push(c);
    }
    if let Some(c) = check_runtime_pack(env) {
        out.push(c);
    }
    if let Some(c) = check_server_env() {
        out.push(c);
    }
    if let Some(c) = check_release(env) {
        out.push(c);
    }
    out
}

/// checkRuntime: the host's kernel features, the cluster network, the
/// runtime, whose code runs containers, and the bridge.
async fn check_runtime(env: &Env) -> Vec<Check> {
    let mut out = host_checks(env.subnet.as_ref());
    if let Ok(ip) = env.ac.private_ip.parse::<IpAddr>()
        && !env.ac.network.is_empty()
    {
        out.extend(cluster_net_checks(env, ip));
    }
    let rt = match &env.driver {
        Err(e) => {
            out.push(check("runtime", FAIL, e.clone()));
            return out;
        }
        Ok(rt) => rt,
    };
    let Some(rt) = rt else {
        out.extend(containerd_check(env));
        return out;
    };
    let err = match tokio::time::timeout(PING_TIMEOUT, rt.ping()).await {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e.to_string()),
        Err(_) => Some("context deadline exceeded".to_string()),
    };
    // No daemon to reach: the agent runs containers through armada-shim
    // (ADR 0046).
    match err {
        Some(_) if env.euid != 0 => {
            out.push(check(
                "runtime",
                WARN,
                "cannot check the supervisor runtime without root: run sudo armadad doctor",
            ));
            return out;
        }
        Some(e) => {
            out.push(check(
                "runtime",
                FAIL,
                format!(
                    "supervisor runtime: {e} ({})",
                    runtime_hint(RUNTIME_SUPERVISOR)
                ),
            ));
            return out;
        }
        None => out.push(check(
            "runtime",
            OK,
            "supervisor runtime ready (armada-shim, no containerd)",
        )),
    }
    if let Some(st) = rt.runtime_agent().await {
        out.extend(runtime_agent_check(&st, &env.ac.runtime_agent));
    }
    out.push(bridge_check(
        rt.bridge().gateway,
        &rt.bridge().subnet.to_string(),
    ));
    out
}

/// The runtime check of a node on containerd, which this armadad does not
/// run (ADR 0055): Go's texts while it cannot tell, then what it does.
fn containerd_check(env: &Env) -> Vec<Check> {
    if env.euid != 0 {
        return vec![check(
            "runtime",
            WARN,
            "cannot reach the embedded runtime without root (its socket is root's only): run sudo armadad doctor",
        )];
    }
    if std::fs::metadata(Path::new(&env.data_dir).join(FILE_AGENT)).is_err() {
        return vec![check(
            "runtime",
            WARN,
            format!("no container runtime yet: init or join sets up the {DEFAULT_RUNTIME} runtime"),
        )];
    }
    vec![check(
        "runtime",
        FAIL,
        "this node runs containers on containerd, which this armadad does not run (ADR 0055): its agent starts and removes nothing; move the node to the supervisor runtime with v0.1.0-alpha.42 (armada node drain, armadad runtime migrate --to supervisor, armada node resume), or roll this machine back",
    )]
}

/// runtimeAgentCheck: whose code runs the node's containers and how its
/// move to armada-node went (ADR 0054); armada-node always runs them here.
pub fn runtime_agent_check(st: &AgentStatus, runtime_agent: &str) -> Vec<Check> {
    let mut out = Vec::new();
    let name = "runtime-agent";
    match st.agent.as_str() {
        "" => return out,
        AGENT_CONTAINERD => out.push(check(
            name,
            WARN,
            "containers run on containerd, which armada-node does not replace",
        )),
        AGENT_SUPERVISOR_GO => out.push(check(
            name,
            WARN,
            "the runtime pack has no armada-node, so Go's runtime code runs containers: install a release build of armadad (sudo armadad upgrade)",
        )),
        _ if !st.error.is_empty() => out.push(check(
            name,
            WARN,
            format!(
                "armada-node runs containers, but converting Go's image store failed ({}); images are pulled again when needed, and the next start of armada-server or armada-agent tries again",
                st.error
            ),
        )),
        _ if !st.converted => out.push(check(
            name,
            WARN,
            "armada-node runs containers, but Go's image store is not converted yet: the agent converts it when it starts (restart armada-server or armada-agent)",
        )),
        _ if st.go_images => out.push(check(
            name,
            OK,
            "armada-node runs containers; Go's image store stays until the last container made from it is replaced",
        )),
        _ => out.push(check(name, OK, "armada-node runs containers")),
    }
    if st.images_to_pull > 0 {
        out.push(check(
            name,
            WARN,
            format!(
                "{} images were left out of the conversion to armada-node's store and are not pulled again yet; each is pulled when a replica needs it (the agent's log names them and why)",
                st.images_to_pull
            ),
        ));
    }
    if st.runc_containers > 0 {
        out.push(check(
            "runc",
            WARN,
            format!(
                "{} containers still run on runc; the agent moves them to crun (ADR 0056): replicas one at a time, the proxy last, job attempts once they end and leave the history. The next release's runtime pack has no runc: upgrade to it once this check is gone",
                st.runc_containers
            ),
        ));
    }
    if st.agent == AGENT_SUPERVISOR_RUST && runtime_agent == "go" {
        out.push(check(
            name,
            WARN,
            "agent.json sets \"runtimeAgent\": \"go\", which this armadad ignores: armada-node runs containers (ADR 0055); remove the field",
        ));
    }
    out
}

/// bridgeCheck: the container bridge's gateway must be private.
fn bridge_check(gateway: Ipv4Addr, subnet: &str) -> Check {
    if !netutil::is_private(&IpAddr::V4(gateway)) {
        return check(
            "bridge",
            FAIL,
            format!("container bridge gateway {gateway} is not a private address"),
        );
    }
    check("bridge", OK, format!("gateway {gateway}, subnet {subnet}"))
}

/// clusterNetChecks: armada-node's Diagnose for an agent with no
/// userspace WireGuard.
fn cluster_net_checks(env: &Env, ip: IpAddr) -> Vec<Check> {
    let ep = machine::uplink_endpoint(&env.ac);
    let cache = Path::new(&env.data_dir)
        .join(FILE_MESH_CACHE)
        .to_string_lossy()
        .into_owned();
    diagnose::diagnose_kernel_only(
        armada_agent::clusternet::ERR_NO_KERNEL_WIREGUARD,
        &env.ac.network,
        &NetAddr::parse(&ip.to_string()),
        &NetAddr::parse(&ep),
        &cache,
        &env.ac.node_id,
    )
    .into_iter()
    .map(|c| Check {
        name: c.name,
        status: match c.level {
            CHECK_OK => OK,
            CHECK_WARN => WARN,
            CHECK_FAIL => FAIL,
            _ => "",
        },
        detail: c.detail,
    })
    .collect()
}

/// embeddedHostChecks: the kernel features the runtime uses, and a free
/// container subnet.
fn host_checks(subnet: Option<&Prefix>) -> Vec<Check> {
    let mut out = Vec::new();
    match std::fs::read_to_string(host_file("/sys/fs/cgroup/cgroup.controllers")) {
        Err(_) => out.push(check(
            "cgroup",
            FAIL,
            "cgroup v2 (unified hierarchy) is required",
        )),
        Ok(s) => {
            let have: Vec<&str> = s.split_whitespace().collect();
            let missing: Vec<&str> = ["cpu", "memory", "pids"]
                .into_iter()
                .filter(|w| !have.contains(w))
                .collect();
            if missing.is_empty() {
                out.push(check("cgroup", OK, "cgroup v2 with cpu, memory, pids"));
            } else {
                out.push(check(
                    "cgroup",
                    FAIL,
                    format!("cgroup v2 controllers missing: {}", missing.join(", ")),
                ));
            }
        }
    }
    if let Ok(b) = std::fs::read(host_file("/proc/filesystems")) {
        if contains(&b, b"\toverlay\n") {
            out.push(check("overlayfs", OK, "available"));
        } else {
            out.push(check(
                "overlayfs",
                WARN,
                "overlay filesystem not loaded yet (armada-runtime.service loads it; otherwise modprobe overlay)",
            ));
        }
    }
    match Selinux::new(std::sync::Arc::new(LinuxHost)).state() {
        SelinuxState::Confined => out.push(check(
            "selinux",
            OK,
            "containers run as container_t, each with its own categories",
        )),
        SelinuxState::NoPolicy => out.push(check(
            "selinux",
            WARN,
            "SELinux is enabled but its policy has no container types, so containers are not confined by it; install the container-selinux policy",
        )),
        SelinuxState::Disabled => {}
    }
    if look_path("iptables").is_some() {
        out.push(check("iptables", OK, "found"));
    } else {
        out.push(check(
            "iptables",
            FAIL,
            "iptables not found; container networking needs it",
        ));
    }
    let (entries, limit, ok) =
        armada_node::conntrack::read_table(&host_file("/proc/sys/net/netfilter"));
    out.push(conntrack_check(entries, limit, ok));
    if let Some(subnet) = subnet {
        let path = host_file("/proc/net/route");
        match std::fs::read(&path) {
            Err(e) => out.push(check(
                "subnet",
                WARN,
                format!("cannot read routes: {}", open_text(&path, &e)),
            )),
            Ok(b) => {
                let clash = parse_routes(&b)
                    .into_iter()
                    .find(|(iface, dst)| iface != BRIDGE && dst.bits > 0 && overlaps(dst, subnet));
                match clash {
                    Some((iface, dst)) => out.push(check(
                        "subnet",
                        FAIL,
                        format!(
                            "container subnet {} overlaps route {} via {iface}; pick another with --container-subnet",
                            subnet.string(),
                            dst.string()
                        ),
                    )),
                    None => out.push(check(
                        "subnet",
                        OK,
                        format!("container subnet {} is free", subnet.string()),
                    )),
                }
            }
        }
    }
    out
}

fn contains(b: &[u8], needle: &[u8]) -> bool {
    b.windows(needle.len()).any(|w| w == needle)
}

/// exec.LookPath for a name without a slash.
fn look_path(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let dir = if dir.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            dir
        };
        let p = dir.join(name);
        std::fs::metadata(&p)
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .then_some(p)
    })
}

/// conntrackCheck: past the table's limit the kernel drops new
/// connections (ADR 0025).
pub fn conntrack_check(entries: i64, limit: i64, ok: bool) -> Check {
    if !ok {
        return check("conntrack", OK, "no connections tracked yet");
    }
    if entries.saturating_mul(100) >= limit.saturating_mul(CONNTRACK_WARN_PERCENT) {
        return check(
            "conntrack",
            WARN,
            format!(
                "{entries} of {limit} tracked connections in use; past the limit new connections are dropped, so raise net.netfilter.nf_conntrack_max or keep connections open longer"
            ),
        );
    }
    check(
        "conntrack",
        OK,
        format!("{entries} of {limit} tracked connections in use"),
    )
}

/// Whether two prefixes share an address (netip.Prefix.Overlaps).
fn overlaps(a: &Prefix, b: &Prefix) -> bool {
    if a.addr.is4 != b.addr.is4 {
        return false;
    }
    let bits = a.bits.min(b.bits);
    let (x, y) = (
        Prefix {
            addr: a.addr.clone(),
            bits,
        }
        .masked(),
        Prefix {
            addr: b.addr.clone(),
            bits,
        }
        .masked(),
    );
    x.addr.bytes == y.addr.bytes
}

/// parseRoutes: the IPv4 routing table in /proc/net/route's format, as
/// (interface, destination) pairs.
pub fn parse_routes(b: &[u8]) -> Vec<(String, Prefix)> {
    let text = String::from_utf8_lossy(b);
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let (Some(dst), Some(mask)) = (proc_hex_addr(f[1]), proc_hex_addr(f[7])) else {
            continue;
        };
        let mut bits = 0u8;
        for mut b in mask {
            while b & 0x80 != 0 {
                bits += 1;
                b <<= 1;
            }
        }
        let Some(p) = armada_spec::go::parse_prefix(&format!("{}/{bits}", Ipv4Addr::from(dst)))
        else {
            continue;
        };
        out.push((f[0].to_string(), p.masked()));
    }
    out
}

/// procHexAddr: a little-endian hex IPv4 address from /proc.
fn proc_hex_addr(s: &str) -> Option<[u8; 4]> {
    let b = hex_decode(s)?;
    let b: [u8; 4] = b.try_into().ok()?;
    Some([b[3], b[2], b[1], b[0]])
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// doctorPrivateIP.
fn doctor_private_ip(env: &Env) -> std::result::Result<IpAddr, String> {
    if !env.private_ip.is_empty() {
        return netutil::check_node_ip(&env.private_ip);
    }
    let ip = netutil::detect_private_ip()?;
    netutil::check_node_ip(&ip.to_string())
}

/// checkListeners: Armada's ports listening on a wildcard or public
/// address.
fn check_listeners(env: &Env) -> Check {
    let ls = match proc_listeners() {
        Err(e) => {
            return check(
                "listeners",
                WARN,
                format!("cannot list listening sockets: {e}"),
            );
        }
        Ok(ls) => ls,
    };
    let mut bad = Vec::new();
    for l in &ls {
        for &p in &CLUSTER_PORTS {
            if p == JOIN_PORT && env.endpoint == Some(l.ip()) {
                // The leader's public join listener, open while a join
                // token for it is (a mesh, or other sites).
                continue;
            }
            if l.port() == p && (l.ip().is_unspecified() || !netutil::is_private(&l.ip())) {
                bad.push(l.to_string());
            }
        }
    }
    if !bad.is_empty() {
        return check(
            "listeners",
            FAIL,
            format!("cluster ports listening publicly: {}", bad.join(", ")),
        );
    }
    check(
        "listeners",
        OK,
        "no cluster port listens on a public or wildcard address",
    )
}

/// procListeners: listening TCP sockets from /proc/net/tcp{,6}.
fn proc_listeners() -> std::result::Result<Vec<SocketAddr>, String> {
    let mut out = Vec::new();
    for (f, v6) in [
        (host_file("/proc/net/tcp"), false),
        (host_file("/proc/net/tcp6"), true),
    ] {
        let b = match std::fs::read(&f) {
            Err(_) if v6 => continue, // IPv6 disabled
            Err(e) => return Err(open_text(&f, &e)),
            Ok(b) => b,
        };
        out.extend(parse_proc_net_tcp(&b).map_err(|e| format!("{f}: {e}"))?);
    }
    Ok(out)
}

/// parseProcNetTCP: the local addresses of listening sockets.
pub fn parse_proc_net_tcp(b: &[u8]) -> std::result::Result<Vec<SocketAddr>, String> {
    let text = String::from_utf8_lossy(b);
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || f[3] != "0A" {
            continue;
        }
        out.push(parse_proc_addr(f[1])?);
    }
    Ok(out)
}

/// parseProcAddr: "0100007F:1F90", the address in host byte order per
/// 32-bit word.
fn parse_proc_addr(s: &str) -> std::result::Result<SocketAddr, String> {
    let quoted = armada_spec::go::quote(s);
    let Some((host, port)) = s.split_once(':') else {
        return Err(format!("bad address {quoted}"));
    };
    let port = u16::from_str_radix(port, 16)
        .ok()
        .filter(|_| !port.is_empty() && !port.starts_with(['+', '-']))
        .ok_or_else(|| format!("bad port in {quoted}"))?;
    let mut raw = hex_decode(host)
        .filter(|r| r.len() == 4 || r.len() == 16)
        .ok_or_else(|| format!("bad address {quoted}"))?;
    for w in raw.chunks_mut(4) {
        w.reverse();
    }
    let ip = if raw.len() == 4 {
        IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))
    } else {
        let a: [u8; 16] = raw
            .try_into()
            .map_err(|_| format!("bad address {quoted}"))?;
        netutil::unmap(&IpAddr::V6(a.into()))
    };
    Ok(SocketAddr::new(ip, port))
}

/// checkDataDir: the permissions of the key material.
fn check_data_dir(env: &Env) -> Check {
    use std::os::unix::fs::PermissionsExt;
    let dir = &env.data_dir;
    let Ok(m) = std::fs::metadata(dir) else {
        return check("data-dir", OK, format!("{dir} does not exist yet"));
    };
    let perm = m.permissions().mode() & 0o777;
    if perm & 0o077 != 0 {
        return check(
            "data-dir",
            FAIL,
            format!("{dir} is mode {perm:o}; want 0700"),
        );
    }
    let mut bad = Vec::new();
    for name in [
        FILE_CA_KEY,
        FILE_SERVER_KEY,
        FILE_NODE_KEY,
        FILE_MASTER_KEY,
        FILE_ETCD_KEY,
        FILE_AGENT,
    ] {
        let Ok(m) = std::fs::metadata(Path::new(dir).join(name)) else {
            continue;
        };
        let perm = m.permissions().mode() & 0o777;
        if perm & 0o077 != 0 {
            bad.push(format!("{name} ({perm:o})"));
        }
    }
    if !bad.is_empty() {
        return check(
            "data-dir",
            FAIL,
            format!("readable by others, want 0600: {}", bad.join(", ")),
        );
    }
    check(
        "data-dir",
        OK,
        format!("{dir} and its key files are private"),
    )
}

/// A day as time.DateOnly writes it, in UTC.
fn day(unix: i64) -> String {
    let (y, m, d) = armada_node::volbackup::gotime::civil_from_days(unix.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// checkCertificates: the certificates Armada renews itself must not be
/// past their renewal point by much, and the user certificate in the
/// client config must not be close to expiring.
fn check_certificates(env: &Env) -> Vec<Check> {
    const NAME: &str = "certificates";
    let now = env.now_ns;
    let ns = |s: i64| i128::from(s) * 1_000_000_000;
    let mut problems = Vec::new();
    let mut good: Vec<&str> = Vec::new();
    let mut next: Option<i64> = None;
    let mut note = |after: i64| {
        if next.is_none_or(|n| after < n) {
            next = Some(after);
        }
    };
    let dd = Path::new(&env.data_dir);
    let read = |f: &str| armada_fsutil::read_private_file(&dd.join(f)).ok();
    let restart = "restart armada-server: it renews its certificates at start";
    let node_fix = if read(FILE_SERVER_CERT).is_some() {
        "restart armada-server: on a server it renews this node's certificate at start"
    } else {
        "remove the node with `armada node delete` and join it again"
    };
    let member = format!("{DIR_ETCD}/member.crt");
    let auto = [
        (FILE_SERVER_CERT, "server", restart),
        (member.as_str(), "etcd member", restart),
        (FILE_NODE_CERT, "node", node_fix),
    ];
    for (file, what, fix) in auto {
        let Some(b) = read(file) else { continue };
        let c = match armada_pki::parse_cert_pem(&b) {
            Err(e) => {
                problems.push(check(NAME, FAIL, format!("{what} certificate {file}: {e}")));
                continue;
            }
            Ok(c) => c,
        };
        let life = ns(c.not_after) - ns(c.not_before);
        let left = ns(c.not_after) - now;
        if left <= 0 {
            problems.push(check(
                NAME,
                FAIL,
                format!("{what} certificate expired on {}; {fix}", day(c.not_after)),
            ));
        } else if left < life / 6 {
            problems.push(check(
                NAME,
                WARN,
                format!(
                    "{what} certificate expires on {} and was not renewed; check the logs (journalctl -u armada-server -u armada-agent)",
                    day(c.not_after)
                ),
            ));
        } else {
            good.push(what);
            note(c.not_after);
        }
    }
    let path = &env.admin_config;
    if let Ok(cc) = armada_client::config::load(path)
        && let Ok(c) = armada_pki::parse_cert_pem(cc.cert.as_bytes())
        && let Ok(id) = c.identity()
        && (id.kind == armada_pki::KIND_USER || id.kind == armada_pki::KIND_ADMIN)
    {
        let left = ns(c.not_after) - now;
        if left <= 0 {
            problems.push(check(
                NAME,
                FAIL,
                format!(
                    "user certificate in {path} expired on {}; on a server, renew it with `armadad user renew --data-dir {}`",
                    day(c.not_after),
                    env.data_dir
                ),
            ));
        } else if left < USER_WARN_BEFORE {
            problems.push(check(
                NAME,
                WARN,
                format!(
                    "user certificate in {path} expires on {}; renew it with `armada user renew`",
                    day(c.not_after)
                ),
            ));
        } else {
            good.push("user");
            note(c.not_after);
        }
    }
    if let Some(next) = next {
        problems.push(check(
            NAME,
            OK,
            format!(
                "{} valid; the first expires on {}",
                good.join(", "),
                day(next)
            ),
        ));
    }
    problems
}

/// What the etcd check learned of the member.
pub struct MemberStatus {
    pub host: String,
    pub version: String,
    pub learner: bool,
    pub errors: Vec<String>,
}

/// The etcd check (ADR 0055, the Rust armadad's own): on a server whose
/// member armada-etcd.service runs (etcd/etcd.yaml, which `armadad etcd`
/// writes), the unit, the member's health, and its version against the
/// pack's. The member's certificate is the certificates check's.
async fn check_etcd(env: &Env) -> Option<Check> {
    let file = Path::new(&env.data_dir)
        .join(DIR_ETCD)
        .join(crate::etcdmember::FILE_CONFIG);
    std::fs::metadata(&file).ok()?;
    let active = systemd::unit_active("armada-etcd");
    let status = if active && env.euid == 0 {
        Some(
            crate::state::member_health(&env.data_dir)
                .await
                .map(|(host, st)| MemberStatus {
                    host,
                    version: st.version,
                    learner: st.is_learner,
                    errors: st.errors,
                }),
        )
    } else {
        None
    };
    Some(etcd_check(active, status, &pack_etcd_version()))
}

/// The etcd version the runtime pack this armadad carries pins; "" for a
/// build without one.
fn pack_etcd_version() -> String {
    let b = crate::pack::bundled();
    if b.is_empty() {
        return String::new();
    }
    crate::pack::read_manifest(b)
        .ok()
        .and_then(|m| m.versions.get("etcd").cloned())
        .unwrap_or_default()
}

/// What the etcd check says: the unit's state, then (as root) what the
/// member answered.
pub fn etcd_check(
    active: bool,
    status: Option<std::result::Result<MemberStatus, String>>,
    pack: &str,
) -> Check {
    const NAME: &str = "etcd";
    if !active {
        return check(
            NAME,
            FAIL,
            "armada-etcd is not active, so this server's control plane has no state: sudo systemctl start armada-etcd (journalctl -u armada-etcd says why it stopped)",
        );
    }
    match status {
        None => check(
            NAME,
            WARN,
            "armada-etcd is active; asking its member needs root (its certificate is root's only): run sudo armadad doctor",
        ),
        Some(Err(e)) => check(
            NAME,
            FAIL,
            format!(
                "armada-etcd is active, but its member does not answer: {e} (journalctl -u armada-etcd)"
            ),
        ),
        Some(Ok(m)) if !m.errors.is_empty() => check(
            NAME,
            WARN,
            format!("the member at {} reports: {}", m.host, m.errors.join("; ")),
        ),
        Some(Ok(m)) if m.learner => check(
            NAME,
            WARN,
            format!(
                "the member at {} is a learner: the leader promotes it once it has caught up (armada server list)",
                m.host
            ),
        ),
        Some(Ok(m)) if !pack.is_empty() && m.version != pack => check(
            NAME,
            WARN,
            format!(
                "the member at {} runs etcd {}, but this armadad carries {pack}: sudo systemctl restart armada-etcd",
                m.host, m.version
            ),
        ),
        Some(Ok(m)) => check(
            NAME,
            OK,
            format!(
                "armada-etcd is active; the member at {} answers (etcd {})",
                m.host, m.version
            ),
        ),
    }
}

/// existingAncestor: dir or its nearest parent that exists.
fn existing_ancestor(dir: &str) -> String {
    let mut dir = dir.to_string();
    loop {
        if std::fs::metadata(&dir).is_ok() {
            return dir;
        }
        let parent = crate::gopath::dir(&dir);
        if parent == dir {
            return dir;
        }
        dir = parent;
    }
}

/// The secrets directory must be on tmpfs: plaintext must not reach a
/// disk. Before the first start it does not exist yet (systemd creates
/// /run/armada), so the nearest directory that exists is checked.
fn check_secrets_tmpfs(secrets: &str) -> Check {
    let dir = existing_ancestor(secrets);
    match crate::commands::agent::check_tmpfs(&dir) {
        Err(e) => check(
            "secrets-tmpfs",
            WARN,
            format!(
                "secret files will be disabled: {e} (mount: mount -t tmpfs -o mode=0700,size=16m tmpfs {})",
                crate::gopath::dir(secrets)
            ),
        ),
        Ok(()) if dir != secrets => check(
            "secrets-tmpfs",
            OK,
            format!("{secrets} will be created on tmpfs ({dir})"),
        ),
        Ok(()) => check("secrets-tmpfs", OK, format!("{secrets} is on tmpfs")),
    }
}

/// A program's standard output as exec.Cmd.Output gives it, with Go's
/// error texts.
fn output(program: &str, args: &[&str]) -> std::result::Result<String, String> {
    let o = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| systemd::start_text(program, &e))?;
    if !o.status.success() {
        return Err(systemd::exit_text(o.status));
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// The clock: certificates and tokens depend on it.
fn check_clock() -> Option<Check> {
    Some(
        match output("timedatectl", &["show", "-p", "NTPSynchronized", "--value"]) {
            Err(e) => check(
                "clock",
                WARN,
                format!(
                    "cannot tell whether the clock is synchronized ({e}); certificates and tokens depend on it"
                ),
            ),
            Ok(s) if s.trim() != "yes" => check(
                "clock",
                WARN,
                "the clock is not NTP-synchronized; certificates and tokens depend on it",
            ),
            Ok(_) => check("clock", OK, "NTP-synchronized"),
        },
    )
}

/// The host firewall: ufw, when it is installed.
fn check_firewall() -> Option<Check> {
    // ufw not installed: nothing to say about it.
    let out = output("ufw", &["status"]).ok()?;
    if !out.trim().starts_with("Status: active") {
        return Some(check(
            "firewall",
            OK,
            "ufw inactive; restrict the cluster ports to the VPC in the provider firewall",
        ));
    }
    let (dns, web) = ufw_allows_bridge(&out, BRIDGE);
    if dns && web {
        return Some(check(
            "firewall",
            OK,
            format!(
                "ufw is active and allows {BRIDGE} → 53 and 80/tcp for internal names; published container ports bypass its rules"
            ),
        ));
    }
    Some(check(
        "firewall",
        WARN,
        format!(
            "ufw is active: published container ports bypass ufw rules, and containers need {BRIDGE} → 53/udp,tcp and 80/tcp allowed for internal names (ufw allow in on {BRIDGE} to any port 53; ufw allow in on {BRIDGE} to any port 80 proto tcp)"
        ),
    ))
}

/// ufwColumns: the columns of a line of `ufw status`, split at runs of
/// two or more white space characters (`\s{2,}`).
fn ufw_columns(line: &str) -> Vec<&str> {
    let ws = |c: char| matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0c');
    let mut out = Vec::new();
    let mut start = 0;
    let chars: Vec<(usize, char)> = line.char_indices().collect();
    let mut i = 0;
    while i < chars.len() {
        if ws(chars[i].1) {
            let mut j = i;
            while j < chars.len() && ws(chars[j].1) {
                j += 1;
            }
            if j - i >= 2 {
                out.push(&line[start..chars[i].0]);
                start = if j < chars.len() {
                    chars[j].0
                } else {
                    line.len()
                };
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out.push(&line[start..]);
    out
}

/// ufwAllowsBridge: whether `ufw status` has IPv4 rules allowing traffic
/// in on the bridge to DNS (port 53, both protocols) and to the internal
/// frontend (80/tcp). A rule for the whole interface allows both.
pub fn ufw_allows_bridge(out: &str, bridge: &str) -> (bool, bool) {
    let (mut dns_udp, mut dns_tcp, mut web) = (false, false, false);
    let suffix = format!(" on {bridge}");
    for line in out.split_inclusive('\n') {
        let cols = ufw_columns(line.trim());
        if cols.len() < 2 || !cols[1].starts_with("ALLOW") {
            continue;
        }
        let Some(ports) = cols[0].strip_suffix(&suffix) else {
            continue;
        };
        if ports.contains("(v6)") {
            continue;
        }
        if ports == "Anywhere" {
            return (true, true);
        }
        let (ports, proto) = ports.split_once('/').unwrap_or((ports, ""));
        for port in ports.split(',') {
            match port {
                "53" => {
                    dns_udp = dns_udp || proto != "tcp";
                    dns_tcp = dns_tcp || proto != "udp";
                }
                "80" => web = web || proto != "udp",
                _ => {}
            }
        }
    }
    (dns_udp && dns_tcp, web)
}

/// needrestart, when installed, must leave Armada's services alone.
fn check_needrestart() -> Option<Check> {
    let dir = hooks::get("NEEDRESTART_DIR").unwrap_or_else(|| NEEDRESTART_DIR.to_string());
    if std::fs::metadata(&dir).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return None;
    }
    let set = std::fs::read(Path::new(&dir).join(NEEDRESTART_FILE))
        .is_ok_and(|b| contains(&b, NEEDRESTART_SET.as_bytes()));
    if set {
        return Some(check(
            "needrestart",
            OK,
            "needrestart leaves Armada's services alone",
        ));
    }
    Some(check(
        "needrestart",
        WARN,
        format!(
            "needrestart may restart armada-runtime and the other Armada services after package upgrades; sudo armadad upgrade (or install.sh) writes {NEEDRESTART_DIR}/{NEEDRESTART_FILE} to stop it"
        ),
    ))
}

/// The runtime pack the runtime runs against the one this armadad
/// carries.
fn check_runtime_pack(env: &Env) -> Option<Check> {
    let bundled = hooks::get("PACK_ID").unwrap_or_else(|| {
        let b = crate::pack::bundled();
        if b.is_empty() {
            String::new()
        } else {
            crate::pack::pack_id(b)
        }
    });
    let installed = crate::pack::installed_pack(&crate::paths(&env.data_dir).bundle());
    if bundled.is_empty()
        || installed.is_empty()
        || installed == "dev"
        || env.ac.runtime != RUNTIME_SUPERVISOR
    {
        // A development build, a runtime that never started, or a node on
        // containerd, which this armadad does not run: the runtime check
        // covers that.
        return None;
    }
    Some(if installed != bundled {
        check(
            "runtime-pack",
            WARN,
            format!(
                "the installed runtime pack is {installed}, but this armadad carries {bundled} (crun, armada-shim, armada-log): restart armada-server or armada-agent, which installs it (containers keep running)"
            ),
        )
    } else {
        check(
            "runtime-pack",
            OK,
            format!("the installed runtime pack is the one this armadad carries ({bundled})"),
        )
    })
}

/// clusterFlagsIn: the cluster settings a server.env still sets.
fn cluster_flags_in(env: &str) -> Vec<String> {
    CLUSTER_FLAGS
        .iter()
        .filter(|f| {
            [" ", "=", "\""]
                .iter()
                .any(|end| env.contains(&format!("--{f}{end}")))
        })
        .map(|f| format!("--{f}"))
        .collect()
}

fn check_server_env() -> Option<Check> {
    let b = std::fs::read(host_file(SERVER_ENV_FILE)).ok()?;
    let flags = cluster_flags_in(&String::from_utf8_lossy(&b));
    if flags.is_empty() {
        return None;
    }
    Some(check(
        "server-env",
        WARN,
        format!(
            "{SERVER_ENV_FILE} sets {}: these are cluster settings now (ADR 0031), kept for every server; check `armada cluster show`, change them with `armada cluster update`, and remove them from the file",
            flags.join(", ")
        ),
    ))
}

/// The latest release, through the hour-long cache armada version uses;
/// nothing when looking is turned off.
fn check_release(env: &Env) -> Option<Check> {
    if std::env::var_os(release::DISABLE_ENV).is_some_and(|v| !v.is_empty()) {
        return None;
    }
    let now = crate::hooks::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let dir = release::user_cache_dir();
    let (found, err) = release::latest_cached(dir.as_deref(), now);
    let v = &env.version;
    Some(if found.tag.is_empty() {
        check(
            "release",
            OK,
            format!(
                "{v}; could not look for a newer release ({})",
                err.unwrap_or_default()
            ),
        )
    } else if release::newer(&found.tag, v) {
        check(
            "release",
            WARN,
            format!(
                "{} is available (this is {v}): sudo armadad upgrade, servers first, one at a time",
                found.tag
            ),
        )
    } else {
        check("release", OK, v.clone())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(agent: &str) -> AgentStatus {
        AgentStatus {
            agent: agent.into(),
            converted: true,
            ..Default::default()
        }
    }

    #[test]
    fn runtime_agent_says_what_runs_containers() {
        let one = |st: &AgentStatus, ra: &str| {
            runtime_agent_check(st, ra)
                .into_iter()
                .map(|c| format!("{} {}", c.status, c.detail))
                .collect::<Vec<_>>()
        };
        assert!(one(&status(""), "").is_empty());
        assert_eq!(
            one(&status(AGENT_SUPERVISOR_RUST), ""),
            ["ok armada-node runs containers"]
        );
        let mut st = status(AGENT_SUPERVISOR_RUST);
        st.go_images = true;
        st.images_to_pull = 2;
        assert_eq!(
            one(&st, ""),
            [
                "ok armada-node runs containers; Go's image store stays until the last container made from it is replaced",
                "warn 2 images were left out of the conversion to armada-node's store and are not pulled again yet; each is pulled when a replica needs it (the agent's log names them and why)",
            ]
        );
        st.converted = false;
        assert_eq!(
            one(&st, "")[0],
            "warn armada-node runs containers, but Go's image store is not converted yet: the agent converts it when it starts (restart armada-server or armada-agent)"
        );
        st.error = "boom".into();
        assert_eq!(
            one(&st, "")[0],
            "warn armada-node runs containers, but converting Go's image store failed (boom); images are pulled again when needed, and the next start of armada-server or armada-agent tries again"
        );
        let mut runc = status(AGENT_SUPERVISOR_RUST);
        runc.runc_containers = 3;
        let r = one(&runc, "");
        assert_eq!(r.len(), 2);
        assert!(
            r[1].starts_with("warn 3 containers still run on runc; the agent moves them to crun")
        );
        let go = one(&status(AGENT_SUPERVISOR_RUST), "go");
        assert_eq!(go.len(), 2);
        assert!(go[1].starts_with(
            "warn agent.json sets \"runtimeAgent\": \"go\", which this armadad ignores"
        ));
    }

    #[test]
    fn bridges_must_be_private() {
        assert_eq!(
            bridge_check(Ipv4Addr::new(10, 121, 0, 1), "10.121.0.0/24").detail,
            "gateway 10.121.0.1, subnet 10.121.0.0/24"
        );
        let c = bridge_check(Ipv4Addr::new(8, 8, 8, 1), "8.8.8.0/24");
        assert_eq!(c.status, FAIL);
        assert_eq!(
            c.detail,
            "container bridge gateway 8.8.8.1 is not a private address"
        );
    }

    #[test]
    fn ufw_rules_as_go_reads_them() {
        let status = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n53 on armada0              ALLOW IN    Anywhere\n80/tcp on armada0          ALLOW IN    Anywhere\n53 (v6) on armada0         ALLOW IN    Anywhere (v6)\n";
        assert_eq!(ufw_allows_bridge(status, BRIDGE), (true, true));
        let udp = "Status: active\n53/udp on armada0          ALLOW IN    Anywhere\n";
        assert_eq!(ufw_allows_bridge(udp, BRIDGE), (false, false));
        let all = "Status: active\nAnywhere on armada0        ALLOW IN    Anywhere\n";
        assert_eq!(ufw_allows_bridge(all, BRIDGE), (true, true));
        assert_eq!(ufw_columns("a b  c   d"), ["a b", "c", "d"]);
    }

    #[test]
    fn proc_files_as_go_parses_them() {
        let tcp = b"  sl  local_address rem_address   st\n   0: 00000000:1D13 00000000:0000 0A\n   1: 0100007F:1D14 00000000:0000 0A\n   2: 0500000A:1D13 00000000:0000 01\n";
        let ls = parse_proc_net_tcp(tcp).unwrap();
        assert_eq!(
            ls.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["0.0.0.0:7443", "127.0.0.1:7444"]
        );
        let tcp6 = b"h\n 0: 00000000000000000000000000000000:1D13 x 0A\n";
        assert_eq!(
            parse_proc_net_tcp(tcp6).unwrap()[0].to_string(),
            "[::]:7443"
        );
        assert_eq!(
            parse_proc_net_tcp(b"h\n 0: 0100007F:XYZ x 0A\n").unwrap_err(),
            "bad port in \"0100007F:XYZ\""
        );
        let routes = b"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\nenp5s0\t00000000\t0154770A\t0003\t0\t0\t0\t00000000\nenp5s0\t0054770A\t00000000\t0001\t0\t0\t0\t00FFFFFF\n";
        let r = parse_routes(routes);
        assert_eq!(r[1].0, "enp5s0");
        assert_eq!(r[1].1.string(), "10.119.84.0/24");
        assert_eq!(r[0].1.bits, 0);
    }

    #[test]
    fn cluster_flags_found_as_go_finds_them() {
        assert_eq!(
            cluster_flags_in(
                "ARMADA_SERVER_FLAGS=\"--tls=false --acme-email a@b.c --metrics-listen\""
            ),
            ["--tls", "--acme-email", "--metrics-listen"]
        );
        assert!(cluster_flags_in("ARMADA_SERVER_FLAGS=\"--port 7443\"").is_empty());
    }

    #[test]
    fn conntrack_warns_when_nearly_full() {
        assert_eq!(
            conntrack_check(0, 0, false).detail,
            "no connections tracked yet"
        );
        assert_eq!(conntrack_check(80, 100, true).status, WARN);
        assert_eq!(conntrack_check(79, 100, true).status, OK);
    }

    #[test]
    fn etcd_says_how_the_member_is() {
        let m = |version: &str, learner: bool, errors: &[&str]| {
            Some(Ok(MemberStatus {
                host: "10.0.0.5:2379".into(),
                version: version.into(),
                learner,
                errors: errors.iter().map(ToString::to_string).collect(),
            }))
        };
        let one = |c: Check| format!("{} {}", c.status, c.detail);
        assert!(one(etcd_check(false, None, "")).starts_with("FAIL armada-etcd is not active"));
        assert!(
            one(etcd_check(true, None, ""))
                .starts_with("warn armada-etcd is active; asking its member needs root")
        );
        assert_eq!(
            one(etcd_check(
                true,
                Some(Err(
                    "etcd at 10.0.0.5:2379: context deadline exceeded".into()
                )),
                ""
            )),
            "FAIL armada-etcd is active, but its member does not answer: etcd at 10.0.0.5:2379: context deadline exceeded (journalctl -u armada-etcd)"
        );
        assert_eq!(
            one(etcd_check(true, m("3.7.4", false, &["NOSPACE"]), "3.7.4")),
            "warn the member at 10.0.0.5:2379 reports: NOSPACE"
        );
        assert!(one(etcd_check(true, m("3.7.4", true, &[]), "3.7.4")).contains("is a learner"));
        assert_eq!(
            one(etcd_check(true, m("3.7.3", false, &[]), "3.7.4")),
            "warn the member at 10.0.0.5:2379 runs etcd 3.7.3, but this armadad carries 3.7.4: sudo systemctl restart armada-etcd"
        );
        assert_eq!(
            one(etcd_check(true, m("3.7.4", false, &[]), "")),
            "ok armada-etcd is active; the member at 10.0.0.5:2379 answers (etcd 3.7.4)"
        );
    }

    #[test]
    fn containerd_nodes_fail_as_root_once_set_up() {
        let dir = std::env::temp_dir().join(format!("doctor-containerd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut env = Env {
            euid: 1000,
            data_dir: dir.display().to_string(),
            secrets_dir: String::new(),
            private_ip: String::new(),
            admin_config: String::new(),
            ac: AgentConfig::default(),
            driver: Ok(None),
            subnet: None,
            endpoint: None,
            version: "dev".into(),
            now_ns: 0,
        };
        assert_eq!(containerd_check(&env)[0].status, WARN);
        env.euid = 0;
        assert!(
            containerd_check(&env)[0]
                .detail
                .starts_with("no container runtime yet")
        );
        std::fs::write(dir.join(FILE_AGENT), "{}").unwrap();
        let c = &containerd_check(&env)[0];
        assert_eq!(c.status, FAIL);
        assert!(
            c.detail
                .contains("which this armadad does not run (ADR 0055)")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

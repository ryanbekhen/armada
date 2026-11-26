//! armadad agent (Go's newAgentCommand and runAgent): this node's agent
//! (armada-agent's loop) on the supervisor runtime, with HAProxy as a
//! system container, the cluster network and the resolver over
//! armada-node's library, and the side seams through armada-node.
//!
//! A server machine runs it as a unit of its own too (ADR 0055): the same
//! armada-agent.service, wanted by armada-server.service, reading
//! /etc/armada/agent.env as on every node (never server.env, whose server
//! flags it does not know). It holds the data directory's lock; the server
//! takes none. With no --server, it starts with agent.json's control plane
//! list and every server the local etcd member records, as Go's
//! knownServers gives its embedded agent.
//!
//! The Rust agent has no containerd runtime (ADR 0055, "A node on
//! containerd"): on a node whose agent.json names it, it starts nothing
//! and removes nothing; it logs why and waits to be stopped, so systemd
//! does not restart it in a loop, and `armadad doctor` says the same.

use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use armada_agent::clusternet::ClusterNet;
use armada_agent::dnsprocess::{DnsProcess, ProcessConfig};
use armada_agent::haproxy::engine::ContainerEngine;
use armada_agent::haproxy::{Driver, DriverConfig};
use armada_agent::log::Logger;
use armada_agent::network::Network;
use armada_agent::proxy::{BoxFut, Clients, InternalDns, Proxy};
use armada_agent::runtime::Runtime as _;
use armada_agent::session::ServerConn;
use armada_agent::side::SideConfig;
use armada_agent::supervisor::{self, Supervisor};
use armada_client::cli::{Ctx, Error, Result};
use armada_client::config as clientconfig;
use armada_proto::armada::v1 as pb;
use tokio::sync::watch;

use crate::agentconfig::{self, AgentConfig, FILE_SERVER_CERT, NETWORK_MESH, RUNTIME_SUPERVISOR};
use crate::machine;
use crate::{netutil, signals};

fn msg(s: impl Into<String>) -> Error {
    Error::Msg(s.into())
}

/// The leader's plan for a containerd node's move (Go's fileRuntimeMove).
pub const FILE_RUNTIME_MOVE: &str = "runtime-move.json";
/// HAProxy's directory below the data directory.
const DIR_HAPROXY: &str = "haproxy";
/// How often the agent checks whether its certificate needs renewal.
const RENEW_CHECK: Duration = Duration::from_secs(3600);

/// lockDataDir: one agent per data directory; the lock goes with the
/// process.
pub fn lock_data_dir(dir: &str) -> std::result::Result<std::fs::File, String> {
    let f = std::fs::File::open(dir).map_err(|e| {
        format!(
            "open data directory: open {dir}: {}",
            armada_fsutil::errno_text(&e)
        )
    })?;
    // SAFETY: flock on a descriptor this process owns.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(format!(
                "another agent is using {dir}: armada-agent.service already runs this node's agent (on a server machine too), so do not also start `armadad agent` here"
            ));
        }
        return Err(format!(
            "lock data directory: {}",
            armada_fsutil::errno_text(&e)
        ));
    }
    Ok(f)
}

/// checkProxyKind.
fn check_proxy_kind(kind: &str) -> std::result::Result<(), String> {
    if kind != "none" && kind != "haproxy" {
        return Err(format!(
            "unsupported --proxy {} (want haproxy or none)",
            armada_spec::go::quote(kind)
        ));
    }
    Ok(())
}

/// CheckTmpfs: dir on tmpfs or ramfs.
pub fn check_tmpfs(dir: &str) -> std::result::Result<(), String> {
    let c = std::ffi::CString::new(dir).map_err(|e| e.to_string())?;
    // SAFETY: plain data filled by statfs.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: c is a valid path; st is written by the call.
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return Err(format!(
            "statfs {dir}: {}",
            armada_fsutil::errno_text(&std::io::Error::last_os_error())
        ));
    }
    const TMPFS: i64 = 0x0102_1994;
    const RAMFS: i64 = 0x8584_58f6;
    let t = st.f_type as i64;
    if t != TMPFS && t != RAMFS {
        return Err(format!("{dir} is not on tmpfs (file system type {t:#x})"));
    }
    Ok(())
}

/// prepareSecretsDir: the secret files' directory, or "" (secret files
/// disabled) when it is not on tmpfs.
fn prepare_secrets_dir(dir: &str, log: &Logger) -> String {
    if dir.is_empty() {
        return String::new();
    }
    if let Err(e) = armada_fsutil::mkdir_private(Path::new(dir)) {
        log.warn(
            "secret files disabled",
            &[("dir", dir.into()), ("err", e.to_string())],
        );
        return String::new();
    }
    if crate::hooks::get("SKIP_TMPFS").is_none()
        && let Err(e) = check_tmpfs(dir)
    {
        log.warn(
            "secret files disabled: plaintext must not reach a disk",
            &[("dir", dir.into()), ("err", e)],
        );
        return String::new();
    }
    dir.to_string()
}

/// nosuidNodev.
fn nosuid_nodev(dir: &str) -> std::result::Result<bool, String> {
    let c = std::ffi::CString::new(dir).map_err(|e| e.to_string())?;
    // SAFETY: plain data filled by statvfs.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: c is a valid path; st is written by the call.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(armada_fsutil::errno_text(&std::io::Error::last_os_error()));
    }
    Ok(st.f_flag & libc::ST_NOSUID != 0 && st.f_flag & libc::ST_NODEV != 0)
}

/// PrepareVolumesDir: the volumes' directory mounted onto itself nosuid,
/// nodev; on failure the node announces no volumes.
fn prepare_volumes_dir(dir: &str, log: &Logger) -> String {
    let prepare = || -> std::result::Result<(), String> {
        armada_fsutil::mkdir_private(Path::new(dir)).map_err(|e| e.to_string())?;
        if nosuid_nodev(dir)? {
            return Ok(());
        }
        let c = std::ffi::CString::new(dir).map_err(|e| e.to_string())?;
        let os = |e: std::io::Error| armada_fsutil::errno_text(&e);
        // SAFETY: c is a valid path; the other arguments are null.
        if unsafe {
            libc::mount(
                c.as_ptr(),
                c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(format!(
                "bind {dir}: {}",
                os(std::io::Error::last_os_error())
            ));
        }
        let flags = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV;
        // SAFETY: as above.
        if unsafe {
            libc::mount(
                std::ptr::null(),
                c.as_ptr(),
                std::ptr::null(),
                flags,
                std::ptr::null(),
            )
        } != 0
        {
            let e = std::io::Error::last_os_error();
            // SAFETY: c is a valid path.
            unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
            return Err(format!("remount {dir} nosuid,nodev: {}", os(e)));
        }
        if !nosuid_nodev(dir).unwrap_or(false) {
            return Err(format!("{dir} is not nosuid,nodev after remounting it"));
        }
        Ok(())
    };
    match prepare() {
        Ok(()) => dir.to_string(),
        Err(e) => {
            log.warn("volumes disabled", &[("dir", dir.into()), ("err", e)]);
            String::new()
        }
    }
}

/// saveRuntimeMovePlan with no plan: the note removed.
fn remove_runtime_move_plan(data_dir: &str) {
    let _ = std::fs::remove_file(Path::new(data_dir).join(FILE_RUNTIME_MOVE));
}

/// HostUpstreams: the machine's resolvers, for names outside the
/// cluster.
fn host_upstreams(path: &str) -> std::result::Result<Vec<String>, String> {
    let b = std::fs::read_to_string(path)
        .map_err(|e| format!("open {path}: {}", armada_fsutil::errno_text(&e)))?;
    let mut out = Vec::new();
    for line in b.lines() {
        let mut f = line.split_whitespace();
        if f.next() != Some("nameserver") {
            continue;
        }
        if let Some(ip) = f.next().and_then(|s| s.parse::<IpAddr>().ok()) {
            out.push(match ip {
                IpAddr::V4(v) => format!("{v}:53"),
                IpAddr::V6(v) => format!("[{v}]:53"),
            });
        }
    }
    if out.is_empty() {
        return Err(format!("no nameservers in {path}"));
    }
    Ok(out)
}

/// startInternalDNS: armada-dns from the runtime pack on the bridge's
/// gateway. Rust has no resolver inside armadad to fall back to (Go's
/// dnsserver.Server): without armada-dns, or when it does not start,
/// internal ingress and DNS are off on this node and containers keep the
/// runtime's default DNS.
async fn start_internal_dns(
    rt: &Supervisor,
    data_dir: &str,
    log: &Logger,
) -> Option<Arc<DnsProcess>> {
    let disabled = |reason: &str, err: String| {
        log.warn(
            "internal ingress and DNS disabled on this node",
            &[("reason", reason.into()), ("err", err)],
        );
        None
    };
    // Go's Bridge ensures the network first: armada-dns binds the bridge's
    // gateway, which the bridge has only once it is set up.
    match tokio::time::timeout(Duration::from_secs(10), rt.ping()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return disabled("no container bridge", e.to_string()),
        Err(_) => return disabled("no container bridge", "context deadline exceeded".into()),
    }
    let br = rt.bridge();
    let ups = match host_upstreams("/etc/resolv.conf") {
        Ok(u) => u,
        Err(e) => return disabled("no upstream resolvers for other names", e),
    };
    let bin = crate::paths(data_dir).bin().join("armada-dns");
    let Ok(bin) = std::fs::canonicalize(&bin) else {
        return disabled("the runtime pack has no armada-dns", String::new());
    };
    let cfg = ProcessConfig {
        bin,
        addr: br.gateway,
        port: 0,
        clients: br.subnet.to_string(),
        upstreams: ups,
        unknown_wait: Duration::ZERO,
        start_wait: Duration::ZERO,
        dir: PathBuf::from(crate::run_dir()).join("dns"),
        launcher: None,
        logger: log.clone(),
    };
    match tokio::time::timeout(Duration::from_secs(10), DnsProcess::start(cfg)).await {
        Ok(Ok(p)) => Some(p),
        Ok(Err(e)) => disabled("armada-dns did not start", e),
        Err(_) => disabled(
            "armada-dns did not start",
            "context deadline exceeded".into(),
        ),
    }
}

/// nodeNet: the cluster network, recording in agent.json the mode a
/// switch ends in (ADR 0050), so the node starts in it.
struct NodeNet {
    net: ClusterNet,
    data_dir: String,
    log: Logger,
    mode: Mutex<String>,
}

impl Network for NodeNet {
    fn apply<'a>(
        &'a self,
        cfg: &'a pb::NetworkConfig,
        local: Option<&'a Clients>,
    ) -> BoxFut<'a, std::result::Result<(), String>> {
        Box::pin(async move {
            self.net.apply(cfg, local).await?;
            let mut mode = self.mode.lock().unwrap_or_else(|p| p.into_inner());
            if !cfg.switch_to.is_empty()
                || cfg.mode == *mode
                || *mode == NETWORK_MESH
                || cfg.mode == NETWORK_MESH
            {
                return Ok(());
            }
            let to = cfg.mode.clone();
            match agentconfig::update(&self.data_dir, |c| {
                c.network = to;
                Ok(())
            }) {
                Err(e) => self
                    .log
                    .warn("record the cluster network's new mode", &[("err", e)]),
                Ok(ac) => {
                    self.log.info(
                        "the cluster network's mode changed; containers created after the agent's next start use its MTU",
                        &[("mode", ac.network.clone())],
                    );
                    *mode = ac.network;
                }
            }
            Ok(())
        })
    }
    fn switches(&self) -> bool {
        self.net.switches()
    }
    fn switch_status(&self) -> BoxFut<'_, Option<pb::NetworkSwitchStatus>> {
        self.net.switch_status()
    }
    fn checks_peers(&self) -> bool {
        self.net.checks_peers()
    }
    fn unreachable_peers(&self) -> BoxFut<'_, Vec<String>> {
        self.net.unreachable_peers()
    }
    fn reports_wireguard(&self) -> bool {
        self.net.reports_wireguard()
    }
    fn wireguard_userspace(&self) -> BoxFut<'_, bool> {
        self.net.wireguard_userspace()
    }
    fn rotates_keys(&self) -> bool {
        self.net.rotates_keys()
    }
    fn rotate_key(&self) -> BoxFut<'_, std::result::Result<String, String>> {
        self.net.rotate_key()
    }
}

/// knownServers: on a server machine, agent.json's list and every
/// server's API address the local etcd member records; None, and
/// agent.json's list alone, when either cannot be read.
async fn known_servers(data_dir: &str, ac: &AgentConfig, log: &Logger) -> Option<Vec<String>> {
    std::fs::metadata(Path::new(data_dir).join(FILE_SERVER_CERT)).ok()?;
    let read = async {
        let cfg = crate::etcdmember::etcd_config(data_dir)?;
        let addr = cfg.addr.ok_or("etcd: no listen address")?;
        let url = crate::etcdmember::member_url(&addr, cfg.client_port);
        let c = armada_store::Client::connect(&url, &cfg.dir).map_err(|e| e.to_string())?;
        let st = armada_store::Etcd::new(c, crate::backup::ETCD_PREFIX)
            .await
            .map_err(|e| e.to_string())?;
        st.list_servers().await.map_err(|e| e.to_string())
    };
    let servers = match tokio::time::timeout(Duration::from_secs(5), read).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            log.warn(
                "read the control plane's servers for this machine's agent; it starts with agent.json's list",
                &[("err", e)],
            );
            return None;
        }
        Err(_) => {
            log.warn(
                "read the control plane's servers for this machine's agent; it starts with agent.json's list",
                &[("err", "context deadline exceeded".into())],
            );
            return None;
        }
    };
    let mut list = ac.servers.clone().unwrap_or_default();
    for s in servers {
        if !s.api_addr.is_empty() && !list.contains(&s.api_addr) {
            list.push(s.api_addr);
        }
    }
    if !clientconfig::check_servers(&list) {
        log.warn(
            "the control plane's servers are not a valid list; the agent starts with agent.json's",
            &[("err", crate::commands::join::servers_error(&list))],
        );
        return None;
    }
    Some(list)
}

pub fn run(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let verbose = ctx.bool("verbose");
    let log = match ctx.str("log-format").as_str() {
        "text" => Logger::stderr(verbose),
        "json" => Logger::stderr_json(verbose),
        other => {
            return Err(msg(format!(
                "unsupported --log-format {} (want text or json)",
                armada_spec::go::quote(other)
            )));
        }
    };
    let opts = Opts {
        data_dir: ctx.str("data-dir"),
        servers: ctx.strs("server"),
        proxy: ctx.str("proxy"),
        secrets_dir: ctx.str("secrets-dir"),
        internal_dns: ctx.bool("internal-dns"),
    };
    let rt = crate::commands::server::runtime()?;
    let stop = signals::stop_on_signals();
    rt.block_on(run_agent(opts, log, stop)).map_err(msg)
}

struct Opts {
    data_dir: String,
    servers: Vec<String>,
    proxy: String,
    secrets_dir: String,
    internal_dns: bool,
}

/// runAgent.
async fn run_agent(
    o: Opts,
    log: Logger,
    mut stop: watch::Receiver<bool>,
) -> std::result::Result<(), String> {
    let data_dir = o.data_dir.clone();
    let _lock = lock_data_dir(&data_dir)?;
    let mut ac = agentconfig::load(&data_dir).map_err(|e| e.text)?;
    if !o.servers.is_empty() {
        if !clientconfig::check_servers(&o.servers) {
            return Err(crate::commands::join::servers_error(&o.servers));
        }
        ac.servers = Some(o.servers.clone());
    } else if let Some(list) = known_servers(&data_dir, &ac, &log).await {
        ac.servers = Some(list);
    }
    netutil::check_private_ip(&ac.private_ip)?;
    // A mesh node reaches the servers at mesh addresses (ADR 0049).
    machine::up_mesh(&data_dir, &ac, None, &log).await?;
    let servers = ac.servers.clone().unwrap_or_default();
    if let Some(w) = machine::write_machine_servers(&data_dir, &servers) {
        log.warn("write the control plane list for clients", &[("err", w)]);
    }
    let creds = Arc::new(armada_agent::creds::Credentials::load(
        Path::new(&data_dir),
        &ac.node_id,
    )?);
    let conn = Arc::new(ServerConn::new(creds, servers.clone())?);
    let on_servers = {
        let conn = conn.clone();
        let data_dir = data_dir.clone();
        let log = log.clone();
        Arc::new(move |list: Vec<String>| {
            if !clientconfig::check_servers(&list) {
                log.warn(
                    "ignoring invalid control plane list",
                    &[("err", crate::commands::join::servers_error(&list))],
                );
                return;
            }
            conn.set_servers(list.clone());
            // Only the list changes, in agent.json as it is now.
            let l = list.clone();
            if let Err(e) = agentconfig::update(&data_dir, |c| {
                c.servers = Some(l);
                Ok(())
            }) {
                log.warn("save control plane list", &[("err", e)]);
                return;
            }
            if let Some(w) = machine::write_machine_servers(&data_dir, &list) {
                log.warn("write the control plane list for clients", &[("err", w)]);
            }
            log.info("control plane updated", &[("servers", list.join(","))]);
        }) as Arc<dyn Fn(Vec<String>) + Send + Sync>
    };
    check_proxy_kind(&o.proxy)?;
    ac.check_runtime()?;
    if ac.runtime != RUNTIME_SUPERVISOR {
        // ADR 0055: no containerd runtime in the Rust agent.
        remove_runtime_move_plan(&data_dir);
        log.error(
            "this node runs containers on containerd, which this armadad does not run: it starts and removes nothing; move the node to the supervisor runtime with the release before (armada node drain, armadad runtime migrate --to supervisor, armada node resume), or roll this machine back",
            &[("runtime", if ac.runtime.is_empty() { crate::agentconfig::RUNTIME_EMBEDDED.into() } else { ac.runtime.clone() })],
        );
        crate::stopped(&mut stop).await;
        return Ok(());
    }
    // Only supervisor nodes run here: nothing moves them (ADR 0054).
    remove_runtime_move_plan(&data_dir);
    let mut mtu = 0;
    if !ac.network.is_empty() {
        // Containers reach other nodes through the tunnel, which takes its
        // overhead from each packet (ADR 0025).
        let ep = machine::uplink_endpoint(&ac);
        mtu = armada_node::net::apply::container_mtu(&ac.network, &ac.private_ip, &ep, ac.mtu)
            .map_err(|e| format!("cluster network: {e}"))?;
    }
    let paths = crate::paths(&data_dir);
    // No daemon to start: the agent installs the runtime pack itself, so
    // an upgrade brings the new armada-shim and runc with it.
    crate::pack::install_pack(&paths)?;
    let mut scfg = supervisor::Config::new(
        PathBuf::from(&data_dir),
        PathBuf::from(crate::run_dir()),
        log.clone(),
    );
    scfg.subnet = ac.container_subnet.clone();
    scfg.mtu = mtu as u32;
    // Only the agent's start moves Go's image store (Go's
    // containerd.Config.Agent); doctor, reset, and migrate never do.
    scfg.agent = true;
    let rt = Arc::new(Supervisor::new(scfg)?);
    let mut dns: Option<Arc<DnsProcess>> = None;
    let mut internal_ip = String::new();
    if o.proxy != "none" && o.internal_dns {
        dns = start_internal_dns(&rt, &data_dir, &log).await;
        if dns.is_some() {
            internal_ip = rt.bridge().gateway.to_string();
        }
    }
    let mut network: Option<Arc<dyn Network>> = None;
    let mut network_key = String::new();
    if !ac.network.is_empty() {
        let n = machine::cluster_net(&data_dir, &ac, log.clone())?;
        network_key = n.public_key();
        network = Some(Arc::new(NodeNet {
            net: n,
            data_dir: data_dir.clone(),
            log: log.clone(),
            mode: Mutex::new(ac.network.clone()),
        }));
    }
    // On the cluster network replicas live on the node subnet and publish
    // no port (ADR 0025).
    let unpublished = network.is_some() && !ac.container_subnet.is_empty();
    let subnet = if unpublished {
        ac.container_subnet.clone()
    } else {
        String::new()
    };
    let mut proxy: Option<Arc<dyn Proxy>> = None;
    let mut wake_socket = String::new();
    if o.proxy == "haproxy" {
        let dir = Path::new(&data_dir).join(DIR_HAPROXY);
        let engine = ContainerEngine {
            runtime: rt.clone(),
            dir: dir.clone(),
            image: String::new(),
            start_wait: Duration::ZERO,
        };
        let d = Driver::new(DriverConfig {
            dir: dir.clone(),
            private_ip: ac.private_ip.clone(),
            internal_ip: internal_ip.clone(),
            subnet,
            engine: Arc::new(engine),
            api: None,
            listeners: None,
            logger: log.clone(),
            reload_wait: Duration::ZERO,
        })?;
        proxy = Some(Arc::new(d));
        wake_socket = dir
            .join("run")
            .join("wake.sock")
            .to_string_lossy()
            .into_owned();
    }
    let bin = machine::pack_program(&data_dir).map(|p| p.to_string_lossy().into_owned());
    let mut side = SideConfig {
        nfs_dir: Path::new(&data_dir)
            .join("nfs")
            .to_string_lossy()
            .into_owned(),
        ..SideConfig::default()
    };
    if let Some(bin) = &bin {
        side.nfs = Some(Arc::new(armada_agent::side::nfs::NodeNfs {
            bin: bin.clone(),
            supported: None,
        }));
        side.volumes = Some(Arc::new(armada_agent::side::volume::NodeVolumes {
            bin: bin.clone(),
        }));
        side.conntrack = Some(Arc::new(armada_agent::side::conntrack::NodeConntrack {
            bin: bin.clone(),
            // conntrack.New: the kernel's table and this machine's memory.
            dir: "/proc/sys/net/netfilter".to_string(),
            memory: Some(armada_node::conntrack::machine_memory()),
        }));
    } else {
        log.warn(
            "the runtime pack has no armada-node: NFS volumes, volume sessions, and the connection tracking table are off",
            &[],
        );
    }
    let mut cfg = armada_agent::Config {
        node_id: ac.node_id.clone(),
        private_ip: ac.private_ip.clone(),
        logger: log.clone(),
        version: armada_client::commands::version::get().version.to_string(),
        ..Default::default()
    };
    cfg.unpublished = unpublished;
    cfg.secrets_dir = prepare_secrets_dir(&o.secrets_dir, &log);
    cfg.volumes_dir = prepare_volumes_dir(
        &Path::new(&data_dir).join("volumes").to_string_lossy(),
        &log,
    );
    cfg.dns = dns.clone().map(|d| d as Arc<dyn InternalDns>);
    cfg.proxy = proxy;
    cfg.network = network;
    cfg.wake_socket = wake_socket;
    cfg.servers = servers;
    cfg.on_servers = Some(on_servers);
    cfg.network_key = network_key;
    if cfg.network.is_some() {
        cfg.endpoint = crate::commands::endpoint::announced(&ac);
        cfg.behind_nat = ac.behind_nat;
    }
    cfg.side = side;
    let agent = armada_agent::Agent::new(cfg, (*rt).clone());
    if let Some(d) = dns {
        // The resolver outlives the agent: armada-dns runs in a unit of
        // its own and answers while armadad restarts (ADR 0053).
        tokio::spawn(d.run());
    }
    let renew = {
        let a = agent.clone();
        let c = conn.clone();
        tokio::spawn(async move { a.renew_loop(c, RENEW_CHECK).await })
    };
    let res = tokio::select! {
        r = agent.run(conn.clone()) => r,
        _ = crate::stopped(&mut stop) => Ok(()),
    };
    renew.abort();
    agent.shutdown();
    res
}

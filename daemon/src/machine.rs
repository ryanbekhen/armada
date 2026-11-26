//! What the commands that set a machine up and run it share (Go's
//! datadir.go, group.go, mesh.go, init.go's helpers, runtime.go's
//! runtimeFlags, and clientconfig's SaveShared and WriteMachineServers):
//! names, accounts, addresses, the container subnet, the machine's admin
//! config and server list, and the tunnels a mesh node brings up before
//! the control plane.

use std::ffi::{CStr, CString};
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use armada_client::config::{self as clientconfig, GROUP, SERVERS_PATH};
use armada_proto::armada::v1 as pb;
use armada_spec::go::{Addr, Prefix, parse_addr, parse_prefix, quote};

use crate::agentconfig::{
    AgentConfig, FILE_AGENT, NETWORK_MESH, RUNTIME_EMBEDDED, RUNTIME_SUPERVISOR,
};
use crate::netutil;

pub const DEFAULT_DATA_DIR: &str = "/var/lib/armada";
pub const DEFAULT_SECRETS_DIR: &str = "/run/armada/secrets";
pub const DEFAULT_PORT: i64 = 7443;
pub const FILE_SERVER_KEY: &str = "server.key";
pub const FILE_NODE_CERT: &str = "node.crt";
pub const FILE_NODE_KEY: &str = "node.key";
pub const FILE_MASTER_KEY: &str = "master.key";
/// The node's WireGuard key (ADR 0025).
pub const FILE_NETWORK_KEY: &str = "network.key";
/// The last peer list a node of a mesh or of several sites applied.
pub const FILE_MESH_CACHE: &str = "mesh.json";
pub const META_CLUSTER: &str = "cluster";
pub const META_MASTER_KEY: &str = "master_key_id";
pub const NETWORK_PLAIN: &str = "plain";
pub const NETWORK_WIREGUARD: &str = "wireguard";
/// The supervisor is the runtime of new nodes (ADR 0046).
pub const DEFAULT_RUNTIME: &str = RUNTIME_SUPERVISOR;
pub const DEFAULT_CONTAINER_SUBNET: &str = "10.121.0.0/24";
pub const DEFAULT_CLUSTER_CIDR: &str = "10.120.0.0/16";
pub const DEFAULT_MESH_CIDR: &str = "10.122.0.0/16";
pub const NODE_SUBNET_BITS: u8 = 24;
/// clusternet.WireGuardPort and MinUplinkMTU.
pub const WIREGUARD_PORT: u16 = 51820;
pub const MIN_UPLINK_MTU: i64 = 1280;
/// clusternet.InternetProbe: whose route finds the uplink of a machine
/// behind NAT.
pub const INTERNET_PROBE: &str = "1.1.1.1";
/// The --endpoint value of a machine behind NAT (ADR 0050).
pub const ENDPOINT_NONE: &str = "none";

/// The effective user ID (the parity tests' hook stands for being root).
pub fn euid() -> u32 {
    if let Some(v) = crate::hooks::get("EUID").and_then(|v| v.parse().ok()) {
        return v;
    }
    // SAFETY: geteuid cannot fail.
    unsafe { libc::geteuid() }
}

/// sanitizeName: a hostname or user name as an identity-safe label.
pub fn sanitize_name(s: &str, fallback: &str) -> String {
    let first = s.split('.').next().unwrap_or("").to_lowercase();
    let mut out = String::new();
    let mut run = false;
    for c in first.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' {
            out.push(c);
            run = false;
        } else if !run {
            out.push('-');
            run = true;
        }
    }
    let mut s = out.trim_matches('-').to_string();
    if s.len() > 63 {
        s = s[..63].trim_end_matches('-').to_string();
    }
    if s.is_empty() {
        fallback.to_string()
    } else {
        s
    }
}

/// The machine's hostname (os.Hostname), "" when it cannot be read.
pub fn hostname() -> String {
    if let Some(h) = crate::hooks::get("HOSTNAME") {
        return h;
    }
    fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// An account of the machine (os/user.User, the parts used).
#[derive(Clone, Debug)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
}

fn passwd(p: *const libc::passwd) -> Account {
    // SAFETY: p is a filled entry of getpwnam_r or getpwuid_r.
    unsafe {
        Account {
            name: CStr::from_ptr((*p).pw_name).to_string_lossy().into_owned(),
            uid: (*p).pw_uid,
            gid: (*p).pw_gid,
        }
    }
}

/// user.Lookup.
pub fn lookup_user(name: &str) -> Option<Account> {
    let c = CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; 16384];
    // SAFETY: plain data filled by getpwnam_r.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call.
    let rc =
        unsafe { libc::getpwnam_r(c.as_ptr(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut res) };
    (rc == 0 && !res.is_null()).then(|| passwd(res))
}

/// user.Current's name, "" when the account is unknown.
pub fn current_user_name() -> String {
    let mut buf = vec![0 as libc::c_char; 16384];
    // SAFETY: plain data filled by getpwuid_r.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call; getuid cannot fail.
    let rc = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut pw,
            buf.as_mut_ptr(),
            buf.len(),
            &mut res,
        )
    };
    if rc == 0 && !res.is_null() {
        passwd(res).name
    } else {
        String::new()
    }
}

/// The ID of group name (user.LookupGroup), None when unknown.
pub fn lookup_group(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; 65536];
    // SAFETY: plain data filled by getgrnam_r.
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::group = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call.
    let rc =
        unsafe { libc::getgrnam_r(c.as_ptr(), &mut gr, buf.as_mut_ptr(), buf.len(), &mut res) };
    // SAFETY: res points at gr when found.
    (rc == 0 && !res.is_null()).then(|| unsafe { (*res).gr_gid })
}

/// The groups an account is in (User.GroupIds).
pub fn group_ids(u: &Account) -> Result<Vec<u32>, String> {
    let c = CString::new(u.name.as_str()).map_err(|e| e.to_string())?;
    let mut n: libc::c_int = 64;
    loop {
        let mut groups = vec![0 as libc::gid_t; n as usize];
        // SAFETY: groups holds n entries.
        let rc = unsafe { libc::getgrouplist(c.as_ptr(), u.gid, groups.as_mut_ptr(), &mut n) };
        if rc >= 0 {
            groups.truncate(n as usize);
            return Ok(groups);
        }
        if n > 65536 {
            return Err(format!("user: list groups for {}: too many", u.name));
        }
        n *= 2;
    }
}

/// sudoUser: the account that ran armadad as root through sudo.
pub fn sudo_user() -> Option<Account> {
    let name = std::env::var("SUDO_USER").unwrap_or_default();
    if euid() != 0 || name.is_empty() {
        return None;
    }
    let u = lookup_user(&name)?;
    if u.uid == 0 || Some(u.uid.to_string()) != std::env::var("SUDO_UID").ok() {
        return None;
    }
    Some(u)
}

/// exec.LookPath, enough for system tools: a name with a slash is used as
/// it is when executable, else the first executable file of PATH.
fn look_path(tool: &str) -> Option<PathBuf> {
    let executable = |p: &Path| {
        fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if tool.contains('/') {
        let p = PathBuf::from(tool);
        return executable(&p).then_some(p);
    }
    let path = std::env::var("PATH").unwrap_or_default();
    path.split(':')
        .map(|d| Path::new(if d.is_empty() { "." } else { d }).join(tool))
        .find(|p| executable(p))
}

/// findTool.
fn find_tool(tool: &str) -> Option<PathBuf> {
    look_path(tool).or_else(|| {
        ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]
            .iter()
            .find_map(|d| look_path(&format!("{d}/{tool}")))
    })
}

/// groupCommand: usermod, gpasswd, or BusyBox's addgroup.
fn group_command(name: &str, group: &str) -> Result<Vec<String>, String> {
    for c in [
        vec!["usermod", "-a", "-G", group, name],
        vec!["gpasswd", "-a", name, group],
        vec!["addgroup", name, group],
    ] {
        if let Some(p) = find_tool(c[0]) {
            let mut argv = vec![p.to_string_lossy().into_owned()];
            argv.extend(c[1..].iter().map(|s| s.to_string()));
            return Ok(argv);
        }
    }
    Err("found none of usermod, gpasswd, or addgroup".to_string())
}

/// joinAdminGroup: the account added to the group that may read the
/// machine's admin config (ADR 0027); whether it joined now.
pub fn join_admin_group(u: &Account) -> Result<bool, String> {
    let gid =
        lookup_group(GROUP).ok_or_else(|| format!("group {GROUP}: user: unknown group {GROUP}"))?;
    if group_ids(u)?.contains(&gid) {
        return Ok(false);
    }
    let argv = group_command(&u.name, GROUP)?;
    let out = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| crate::systemd::start_text(&argv[0], &e))?;
    if !out.status.success() {
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        return Err(format!(
            "{}: {}: {}",
            crate::gopath::base(&argv[0]),
            crate::systemd::exit_text(out.status),
            text.trim()
        ));
    }
    Ok(true)
}

/// adminGroupNote.
pub fn admin_group_note(name: &str) -> String {
    format!(
        "{name} joined the {GROUP} group: log in again (or run `newgrp {GROUP}`) to use armada without sudo"
    )
}

/// The directory of path with search permission for everyone, set
/// explicitly: the units run armadad with UMask=0077.
fn searchable_dir(path: &str) -> Result<(), String> {
    let dir = crate::gopath::dir(path);
    crate::gofs::mkdir_all(Path::new(&dir), 0o711)?;
    let m =
        fs::metadata(&dir).map_err(|e| format!("stat {dir}: {}", armada_fsutil::errno_text(&e)))?;
    let perm = m.permissions().mode() & 0o777;
    if perm & 0o011 != 0o011 {
        fs::set_permissions(&dir, fs::Permissions::from_mode(perm | 0o011))
            .map_err(|e| format!("chmod {dir}: {}", armada_fsutil::errno_text(&e)))?;
    }
    Ok(())
}

/// Config.SaveShared: the config written root-owned, mode 0640, group
/// armada; whether it is shared (false when the group does not exist).
pub fn save_shared(cfg: &clientconfig::Config, path: &str) -> Result<bool, String> {
    searchable_dir(path)?;
    cfg.save_file(path)?;
    let Some(gid) = lookup_group(GROUP) else {
        return Ok(false);
    };
    std::os::unix::fs::chown(path, Some(0), Some(gid))
        .map_err(|e| format!("chown {path}: {}", armada_fsutil::errno_text(&e)))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o640))
        .map_err(|e| format!("chmod {path}: {}", armada_fsutil::errno_text(&e)))?;
    Ok(true)
}

/// writeMachineServers: /etc/armada/servers kept current for the client
/// configs of this machine, only by the agent of the machine's own data
/// directory run as root; a warning's text when it fails.
pub fn write_machine_servers(data_dir: &str, servers: &[String]) -> Option<String> {
    if euid() != 0 || crate::gopath::clean(data_dir) != DEFAULT_DATA_DIR || servers.is_empty() {
        return None;
    }
    let write = || -> Result<(), String> {
        if !clientconfig::check_servers(servers) {
            return Err("invalid control plane list".to_string());
        }
        searchable_dir(SERVERS_PATH)?;
        let mut b = servers.join("\n");
        b.push('\n');
        armada_fsutil::write_file_atomic(Path::new(SERVERS_PATH), b.as_bytes(), 0o644)
            .map_err(|e| format!("{SERVERS_PATH}: {e}"))
    };
    write().err()
}

/// nextStep: how to start role after init or join.
pub fn next_step(role: &str, data_dir: &str) -> String {
    if data_dir == DEFAULT_DATA_DIR {
        format!("Next: sudo systemctl enable --now armada-{role}\n")
    } else {
        format!("Next: armadad {role} --data-dir {data_dir}\n")
    }
}

/// netip.ParsePrefix with its errors (ParseAddr's own texts approximated
/// as the client's CheckPrivateListen approximates them).
pub fn parse_prefix_go(s: &str) -> Result<Prefix, String> {
    let fail = |msg: String| Err(format!("netip.ParsePrefix({}): {msg}", quote(s)));
    let Some(i) = s.rfind('/') else {
        return fail("no '/'".to_string());
    };
    let Some(ip) = parse_addr(&s[..i]) else {
        return fail(format!("ParseAddr({}): unable to parse IP", quote(&s[..i])));
    };
    if !ip.is4 && !ip.zone.is_empty() {
        return fail("IPv6 zones cannot be present in a prefix".to_string());
    }
    let bits = &s[i + 1..];
    let b = bits.as_bytes();
    let bad = || format!("bad bits after slash: {}", quote(bits));
    if b.len() > 1 && !(b'1'..=b'9').contains(&b[0]) {
        return fail(bad());
    }
    let Ok(n) = armada_spec::go::atoi(bits) else {
        return fail(bad());
    };
    let max = if ip.is4 { 32 } else { 128 };
    if !(0..=max).contains(&n) {
        return fail("prefix length out of range".to_string());
    }
    parse_prefix(s).ok_or_else(|| format!("netip.ParsePrefix({}): invalid", quote(s)))
}

/// The address after a (Addr.Next) for IPv4.
pub fn next4(a: &Addr) -> Addr {
    let v = u32::from_be_bytes([a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3]]).wrapping_add(1);
    parse_addr(&std::net::Ipv4Addr::from(v).to_string()).unwrap_or_else(|| a.clone())
}

/// containerd.BridgeOf: the bridge's subnet, masked.
pub fn bridge_of(subnet: &Prefix) -> Result<Prefix, String> {
    let s = subnet.masked();
    if !s.addr.is4 || s.bits > 28 || s.bits < 8 {
        return Err(format!(
            "container subnet {}: need an IPv4 prefix between /8 and /28",
            s.string()
        ));
    }
    let gw = next4(&s.addr);
    if !netutil::is_private(&netutil::to_std(&gw)) {
        return Err(format!("container subnet {} is not private", s.string()));
    }
    Ok(s)
}

fn std_addr(ip: &IpAddr) -> Option<Addr> {
    parse_addr(&ip.to_string())
}

/// runtimeFlags: --container-subnet and --runtime.
pub struct RuntimeFlags {
    pub subnet: String,
    pub runtime: String,
    /// Whether --container-subnet was given.
    pub subnet_changed: bool,
}

impl RuntimeFlags {
    pub fn from(ctx: &armada_client::cli::Ctx<'_>) -> RuntimeFlags {
        RuntimeFlags {
            subnet: ctx.str("container-subnet"),
            runtime: ctx.str("runtime"),
            subnet_changed: ctx.changed("container-subnet"),
        }
    }

    /// apply: the flags checked and recorded in c. private_ip None is Go's
    /// invalid address (a join over a public address that sends none).
    pub fn apply(&self, c: &mut AgentConfig, private_ip: Option<&IpAddr>) -> Result<(), String> {
        let p = parse_prefix_go(&self.subnet)
            .map_err(|e| format!("invalid --container-subnet: {e}"))?;
        let b = bridge_of(&p)?;
        if let Some(ip) = private_ip
            && std_addr(ip).is_some_and(|a| b.contains(&a))
        {
            return Err(format!(
                "--container-subnet {} contains the private IP {ip}; pick a subnet the network does not use",
                b.string()
            ));
        }
        c.runtime = match self.runtime.as_str() {
            "" | RUNTIME_SUPERVISOR => DEFAULT_RUNTIME.to_string(),
            // containerd left the runtime pack (ADR 0046, ADR 0055): a
            // node set up on it would start nothing.
            RUNTIME_EMBEDDED => {
                return Err(format!(
                    "invalid --runtime {RUNTIME_EMBEDDED}: containerd is no longer in the runtime pack; new nodes run on {RUNTIME_SUPERVISOR}, the only runtime (ADR 0046)"
                ));
            }
            other => {
                return Err(format!(
                    "invalid --runtime {}: use {RUNTIME_SUPERVISOR}",
                    quote(other)
                ));
            }
        };
        c.container_subnet = b.string();
        Ok(())
    }

    /// useNodeSubnet: the cluster network the node joined and the subnet
    /// it gave the node; a note when it overrides --container-subnet.
    pub fn use_node_subnet(
        &self,
        c: &mut AgentConfig,
        subnet: &str,
        mode: &str,
        private_ip: Option<&IpAddr>,
    ) -> Result<String, String> {
        if subnet.is_empty() {
            return Ok(String::new());
        }
        if mode != NETWORK_PLAIN && mode != NETWORK_WIREGUARD && mode != NETWORK_MESH {
            return Err(format!(
                "the control plane uses cluster network mode {}, which this Armada does not know; upgrade it",
                quote(mode)
            ));
        }
        c.network = mode.to_string();
        let Some(p) = parse_prefix(subnet) else {
            return Err(format!(
                "the control plane gave this node an invalid subnet {}",
                quote(subnet)
            ));
        };
        match bridge_of(&p) {
            Ok(b) if b == p && p.bits == NODE_SUBNET_BITS => {}
            _ => {
                return Err(format!(
                    "the control plane gave this node an unusable subnet {subnet}"
                ));
            }
        }
        if let Some(ip) = private_ip
            && std_addr(ip).is_some_and(|a| p.contains(&a))
        {
            return Err(format!(
                "the node subnet {} contains this machine's private IP {ip}",
                p.string()
            ));
        }
        let mut note = String::new();
        if self.subnet_changed && self.subnet != p.string() {
            note = format!(
                "--container-subnet {} is not used: the cluster network gives this node {}.\n",
                self.subnet,
                p.string()
            );
        }
        c.container_subnet = p.string();
        Ok(note)
    }
}

/// resolvePrivateIP.
pub fn resolve_private_ip(flag: &str) -> Result<IpAddr, String> {
    if flag.is_empty() {
        return netutil::detect_private_ip();
    }
    netutil::check_private_ip(flag)
}

/// resolveEndpoint: --endpoint, or the machine's only public IPv4 address.
pub fn resolve_endpoint(flag: &str) -> Result<std::net::Ipv4Addr, String> {
    if flag.is_empty() {
        return netutil::detect_endpoint();
    }
    netutil::check_endpoint(flag)
}

/// checkUplinkMTU.
pub fn check_uplink_mtu(mtu: i64) -> Result<(), String> {
    if mtu != 0 && !(MIN_UPLINK_MTU..=9000).contains(&mtu) {
        return Err(format!("--mtu {mtu}: want {MIN_UPLINK_MTU} to 9000"));
    }
    Ok(())
}

/// meshJoinAddr: whether a join address is public (a mesh cluster's, or
/// the leader's for another site).
pub fn mesh_join_addr(addr: &str) -> Result<bool, String> {
    let Some((a, port)) = clientconfig::parse_addr_port(addr).filter(|(_, p)| *p != 0) else {
        return Err(format!("join address {}: want IP:PORT", quote(addr)));
    };
    let _ = port;
    let ip = netutil::to_std(&a);
    if netutil::is_private(&ip) {
        return netutil::check_private_listen(addr).map(|_| false);
    }
    netutil::check_endpoint(&a.unmap().string()).map_err(|e| format!("join address: {e}"))?;
    Ok(true)
}

/// meshJoinListen: a join listener moved to the endpoint, same port.
pub fn mesh_join_listen(join_addr: &str, endpoint: Option<IpAddr>) -> Result<String, String> {
    let Some((_, port)) = clientconfig::parse_addr_port(join_addr) else {
        return Err(format!("join listener {}: invalid", quote(join_addr)));
    };
    let Some(ep) = endpoint else {
        return Err(format!("{FILE_AGENT}: a mesh node needs its endpoint"));
    };
    Ok(match ep {
        IpAddr::V4(v) => format!("{v}:{port}"),
        IpAddr::V6(v) => format!("[{v}]:{port}"),
    })
}

/// joinMesh: a machine's side of joining over a public address.
#[derive(Clone, Debug, Default)]
pub struct JoinMesh {
    pub on: bool,
    pub endpoint: Option<std::net::Ipv4Addr>,
    pub key: String,
    pub behind_nat: bool,
}

/// prepareJoin: the machine's private IP (None when a public join sends
/// none) and how it joins addr.
pub fn prepare_join(
    changed: &dyn Fn(&str) -> bool,
    addr: &str,
    private_ip: &str,
    endpoint: &str,
    no_private_ip: bool,
    server: bool,
) -> Result<(Option<IpAddr>, JoinMesh), String> {
    let public = mesh_join_addr(addr)?;
    let nat = endpoint == ENDPOINT_NONE;
    if nat && server {
        return Err("--endpoint none: a server needs an endpoint other sites reach it at; join it as a node instead".to_string());
    }
    if no_private_ip && changed("private-ip") {
        return Err("--private-ip and --no-private-ip exclude each other".to_string());
    }
    if !public {
        let other = "--no-private-ip is for joins over a public address: machines of another site than the leader's";
        if nat {
            if no_private_ip {
                return Err(other.to_string());
            }
            let ip = resolve_private_ip(private_ip)?;
            return Ok((
                Some(ip),
                JoinMesh {
                    behind_nat: true,
                    ..Default::default()
                },
            ));
        }
        if changed("endpoint") {
            return Err("--endpoint is for joins over a public address (mesh clusters, and machines of another site than the leader's)".to_string());
        }
        if no_private_ip {
            return Err(other.to_string());
        }
        return Ok((Some(resolve_private_ip(private_ip)?), JoinMesh::default()));
    }
    let ep = if nat {
        None
    } else {
        Some(resolve_endpoint(endpoint)?)
    };
    let ip = if no_private_ip {
        None
    } else if changed("private-ip") {
        Some(resolve_private_ip(private_ip)?)
    } else {
        resolve_private_ip("").ok()
    };
    Ok((
        ip,
        JoinMesh {
            on: true,
            endpoint: ep,
            behind_nat: nat,
            key: String::new(),
        },
    ))
}

impl JoinMesh {
    /// loadKey: the machine's WireGuard key for a public join.
    pub fn load_key(&mut self, data_dir: &str) -> Result<(), String> {
        if !self.on {
            return Ok(());
        }
        let k = armada_node::net::key::load_or_create(&Path::new(data_dir).join(FILE_NETWORK_KEY))
            .map_err(|e| format!("cluster network key: {e}"))?;
        self.key = k.public().to_string();
        Ok(())
    }

    /// address: the machine's address from the join answer.
    pub fn address(&self, ip: Option<IpAddr>, mode: &str, mesh_ip: &str) -> Result<IpAddr, String> {
        if mode == NETWORK_MESH && !self.on {
            return Err(format!(
                "the cluster's network mode is {}, which does not match a join at this address",
                quote(mode)
            ));
        }
        if mode != NETWORK_MESH && mesh_ip.is_empty() {
            return ip.ok_or_else(|| {
                "the cluster gave this machine, which sent no private IP, no mesh address"
                    .to_string()
            });
        }
        if let Some(ip) = ip
            && mode != NETWORK_MESH
        {
            return Err(format!(
                "the cluster gave this machine a mesh address although it joined with its private IP {ip}"
            ));
        }
        netutil::check_node_ip(mesh_ip).map_err(|e| format!("mesh address from the cluster: {e}"))
    }

    pub fn endpoint_text(&self) -> String {
        self.endpoint.map(|e| e.to_string()).unwrap_or_default()
    }
}

/// ipString.
pub fn ip_string(ip: Option<&IpAddr>) -> String {
    ip.map(|i| i.to_string()).unwrap_or_default()
}

/// uplinkEndpoint: the address whose route finds the uplink when the
/// node's own does not: its endpoint, or behind NAT an address on the
/// internet.
pub fn uplink_endpoint(ac: &AgentConfig) -> String {
    if ac.behind_nat {
        return INTERNET_PROBE.to_string();
    }
    ac.endpoint.clone()
}

/// The runtime pack's armada-node, when installed (packProgram).
pub fn pack_program(data_dir: &str) -> Option<PathBuf> {
    let p = crate::paths(data_dir).bin().join(crate::pack::BIN_NODE);
    fs::canonicalize(&p)
        .ok()
        .filter(|p| fs::metadata(p).is_ok_and(|m| m.is_file()))
}

/// meshConfig: the cluster network's configuration of a node.
pub fn net_config(
    data_dir: &str,
    ac: &AgentConfig,
) -> Result<armada_agent::clusternet::NetConfig, String> {
    netutil::check_private_ip(&ac.private_ip).or_else(|_| {
        ac.private_ip.parse::<IpAddr>().map_err(|_| {
            format!(
                "{FILE_AGENT}: private IP: ParseAddr({}): unable to parse IP",
                quote(&ac.private_ip)
            )
        })
    })?;
    let dd = Path::new(data_dir);
    Ok(armada_agent::clusternet::NetConfig {
        node: ac.node_id.clone(),
        private_ip: ac.private_ip.clone(),
        endpoint: uplink_endpoint(ac),
        mesh_cache: dd.join(FILE_MESH_CACHE).to_string_lossy().into_owned(),
        uplink_mtu: ac.mtu,
        key_path: dd.join(FILE_NETWORK_KEY),
    })
}

/// The node's cluster network over armada-node's library.
pub fn cluster_net(
    data_dir: &str,
    ac: &AgentConfig,
    log: armada_agent::log::Logger,
) -> Result<armada_agent::clusternet::ClusterNet, String> {
    let cfg = net_config(data_dir, ac)?;
    let kernel = Arc::new(armada_agent::clusternet::Kernel {
        program: pack_program(data_dir),
    });
    armada_agent::clusternet::ClusterNet::new(cfg, kernel, log)
        .map_err(|e| format!("cluster network key: {e}"))
}

/// alone: a mesh network with only this node in it.
pub fn alone(ac: &AgentConfig, key: &str) -> pb::NetworkConfig {
    pb::NetworkConfig {
        mode: NETWORK_MESH.to_string(),
        cluster_cidr: ac.cluster_cidr.clone(),
        mesh_cidr: ac.mesh_cidr.clone(),
        peers: vec![pb::NetworkPeer {
            node: ac.node_id.clone(),
            private_ip: ac.private_ip.clone(),
            subnet: ac.container_subnet.clone(),
            public_key: key.to_string(),
            endpoint: ac.endpoint.clone(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// upMesh: a mesh node's tunnel brought up before etcd or the agent reach
/// mesh addresses (ADR 0049), from cfg or the peer list the node last
/// applied; a node of another mode does so too while it keeps a list
/// (peers in other sites, ADR 0050). The parity tests' hook
/// ARMADA_DAEMON_TEST_NO_NET leaves the kernel alone.
pub async fn up_mesh(
    data_dir: &str,
    ac: &AgentConfig,
    cfg: Option<pb::NetworkConfig>,
    log: &armada_agent::log::Logger,
) -> Result<(), String> {
    if ac.network.is_empty() {
        return Ok(());
    }
    let cache = Path::new(data_dir).join(FILE_MESH_CACHE);
    if ac.network != NETWORK_MESH && cfg.is_none() && fs::metadata(&cache).is_err() {
        return Ok(());
    }
    let given = cfg.is_some();
    let n = cluster_net(data_dir, ac, log.clone())?;
    let mut cfg = cfg;
    if cfg.is_none() && ac.network == NETWORK_MESH && fs::metadata(&cache).is_err() {
        cfg = Some(alone(ac, &n.public_key()));
    }
    if crate::hooks::get("NO_NET").is_some() {
        return Ok(());
    }
    if let Err(e) = n.up(cfg.as_ref()).await {
        if ac.network != NETWORK_MESH && !given {
            log.warn("bring the tunnels to other sites up", &[("err", e)]);
            return Ok(());
        }
        return Err(format!("cluster network: {e}"));
    }
    Ok(())
}

/// The owner and mode of a file, for checks.
pub fn owner_mode(p: &Path) -> Option<(u32, u32)> {
    fs::metadata(p).ok().map(|m| (m.uid(), m.mode() & 0o7777))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(sanitize_name("Web-01.example.com", "x"), "web-01");
        assert_eq!(sanitize_name("a__b", "x"), "a-b");
        assert_eq!(sanitize_name("--", "node-1"), "node-1");
        assert_eq!(sanitize_name(&"a".repeat(70), "x").len(), 63);
    }

    #[test]
    fn prefixes() {
        assert_eq!(
            parse_prefix_go("10.0.0.0").unwrap_err(),
            "netip.ParsePrefix(\"10.0.0.0\"): no '/'"
        );
        assert_eq!(
            parse_prefix_go("10.0.0.0/33").unwrap_err(),
            "netip.ParsePrefix(\"10.0.0.0/33\"): prefix length out of range"
        );
        assert_eq!(
            parse_prefix_go("10.0.0.0/08").unwrap_err(),
            "netip.ParsePrefix(\"10.0.0.0/08\"): bad bits after slash: \"08\""
        );
        let p = parse_prefix_go("10.121.0.5/24").unwrap();
        assert_eq!(bridge_of(&p).unwrap().string(), "10.121.0.0/24");
        assert!(bridge_of(&parse_prefix_go("8.8.8.0/24").unwrap()).is_err());
        assert!(bridge_of(&parse_prefix_go("10.0.0.0/30").unwrap()).is_err());
    }

    #[test]
    fn node_subnets() {
        let rt = RuntimeFlags {
            subnet: "10.121.0.0/24".into(),
            runtime: String::new(),
            subnet_changed: true,
        };
        let mut c = AgentConfig::default();
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        rt.apply(&mut c, Some(&ip)).unwrap();
        assert_eq!(
            (c.runtime.as_str(), c.container_subnet.as_str()),
            ("supervisor", "10.121.0.0/24")
        );
        for (runtime, ok) in [("supervisor", true), ("embedded", false), ("podman", false)] {
            let flags = RuntimeFlags {
                subnet: "10.121.0.0/24".into(),
                runtime: runtime.into(),
                subnet_changed: false,
            };
            let mut c = AgentConfig::default();
            assert_eq!(flags.apply(&mut c, Some(&ip)).is_ok(), ok, "{runtime}");
        }
        let note = rt
            .use_node_subnet(&mut c, "10.120.3.0/24", "plain", Some(&ip))
            .unwrap();
        assert_eq!(c.container_subnet, "10.120.3.0/24");
        assert!(note.contains("is not used"));
        assert!(
            rt.use_node_subnet(&mut c, "10.120.3.0/25", "plain", Some(&ip))
                .is_err()
        );
        assert!(
            rt.use_node_subnet(&mut c, "10.120.3.0/24", "vxlan", Some(&ip))
                .is_err()
        );
    }

    #[test]
    fn joins() {
        let none = |_: &str| false;
        assert_eq!(
            prepare_join(&none, "nope", "", "", false, false).unwrap_err(),
            "join address \"nope\": want IP:PORT"
        );
        assert!(
            prepare_join(&none, "203.0.113.2:7444", "", "none", false, true)
                .unwrap_err()
                .starts_with("--endpoint none: a server")
        );
        let (ip, m) = prepare_join(&none, "10.0.0.2:7444", "10.0.0.6", "", false, false).unwrap();
        assert_eq!(ip, Some("10.0.0.6".parse().unwrap()));
        assert!(!m.on);
        let mesh = JoinMesh {
            on: true,
            ..Default::default()
        };
        assert_eq!(
            mesh.address(None, "mesh", "10.122.0.2").unwrap(),
            "10.122.0.2".parse::<IpAddr>().unwrap()
        );
        assert!(
            JoinMesh::default()
                .address(None, "mesh", "10.122.0.2")
                .is_err()
        );
    }
}

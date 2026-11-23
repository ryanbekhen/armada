//! What armadad doctor checks of the cluster network (clusternet_linux.go's
//! Diagnose, with wireguard_linux.go's diagnoseWireGuard): the uplink's MTU,
//! a switch under way, the tunnel and its peers, peers of other sites whose
//! address the machine's own networks hide, relays, and the isolation
//! tables. Names, levels, and details are Go's, for the same machine.
//!
//!   armada-node net diagnose   stdin: {Mode, PrivateIP, Endpoint, Cache, Node}
//!                              stdout: {checks: [{name, level, detail}],
//!                              needsUserspace}
//!
//! The userspace WireGuard device belongs to the Go agent: when the kernel
//! has no device of a name but that device's control socket exists, this
//! answers needsUserspace and Go diagnoses it.

use super::addr::{Addr, Prefix};
use super::apply::Net;
use super::kernel::Socket as NftSocket;
use super::plan::{
    self, INTERFACE, LocalPrefix, MODE_MESH, MODE_PLAIN, MODE_WIREGUARD, NEXT, SITE_INTERFACE,
    VXLAN_PORT, WIREGUARD_PORT, encrypted,
};
use super::rtnl::{self, AF_INET};
use super::rules::BRIDGE;
use super::wgnl::{self, WgError};
use super::wireguard::STALE_HANDSHAKE;
use super::{mesh, nft, read_stdin, write_stdout};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const CHECK_OK: i64 = 0;
pub const CHECK_WARN: i64 = 1;
pub const CHECK_FAIL: i64 = 2;

/// IF_OPER_DOWN.
const OPER_DOWN: u8 = 2;
const IFF_LOOPBACK: u32 = 0x8;
/// Where the userspace device of an interface serves its control socket.
const USER_SOCKETS: &str = "/var/run/wireguard";
/// Where the kernel keeps each interface's IPv6 settings.
const IPV6_CONF: &str = "/proc/sys/net/ipv6/conf";

/// One result (clusternet.Check).
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub level: i64,
    pub detail: String,
}

fn check(name: &str, level: i64, detail: String) -> Check {
    Check {
        name: name.to_string(),
        level,
        detail,
    }
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Request {
    mode: String,
    #[serde(rename = "PrivateIP")]
    private_ip: String,
    endpoint: String,
    cache: String,
    node: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Answer {
    checks: Vec<Check>,
    needs_userspace: bool,
}

/// The device belongs to the Go agent's userspace WireGuard.
pub struct Userspace;

/// kernelHas: whether the kernel has a module loaded, built in, or
/// available to load.
fn kernel_has(module: &str) -> bool {
    if Path::new(&format!("/sys/module/{module}")).exists() {
        return true;
    }
    std::process::Command::new("modprobe")
        .args(["-n", module])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Diagnose.
pub fn diagnose(
    mode: &str,
    ip: &Option<Addr>,
    endpoint: &Option<Addr>,
    cache: &str,
    node: &str,
) -> Result<Vec<Check>, Userspace> {
    let mut out = diagnose_tunnel(mode, ip, endpoint)?;
    if let Some(c) = diagnose_sites(cache, node, ip) {
        out.push(c);
    }
    if let Some(c) = diagnose_relay(cache, node, ip) {
        out.push(c);
    }
    out.push(diagnose_isolation());
    Ok(out)
}

/// The Go agent's address as netip.Addr prints it, for an invalid one too.
fn addr_text(ip: &Option<Addr>) -> String {
    ip.as_ref()
        .map_or_else(|| "invalid IP".to_string(), Addr::to_string)
}

fn diagnose_tunnel(
    mode: &str,
    ip: &Option<Addr>,
    endpoint: &Option<Addr>,
) -> Result<Vec<Check>, Userspace> {
    let mut out = Vec::new();
    let mut net = match Net::bare(ip.clone().unwrap_or(Addr::V4([0; 4])), endpoint.clone()) {
        Ok(n) => n,
        Err(e) => {
            out.push(check("network-mtu", CHECK_FAIL, e));
            return Ok(out);
        }
    };
    let (uplink, mtu, meshed) = match net.uplink_for(mode) {
        Ok(u) => u,
        Err(f) => {
            out.push(check("network-mtu", CHECK_FAIL, f.text()));
            return Ok(out);
        }
    };
    let tunnel_mode = if meshed { MODE_WIREGUARD } else { mode };
    out.push(check(
        "network-mtu",
        CHECK_OK,
        format!(
            "{} has MTU {mtu}; the tunnel and containers use {}",
            uplink.name,
            plan::tunnel_mtu(tunnel_mode, mtu)
        ),
    ));
    if let Ok(Some(_)) = net.rt.link_named(NEXT) {
        out.push(check(
            "network-switch",
            CHECK_WARN,
            format!(
                "{NEXT} is up: the cluster network is switching modes (armada cluster status shows how far)"
            ),
        ));
    }
    if encrypted(mode) || meshed {
        out.extend(diagnose_wireguard(mode, ip, meshed)?);
        return Ok(out);
    }
    let link = match net.rt.link_named(INTERFACE) {
        Err(e) => {
            out.push(check(
                "network",
                CHECK_FAIL,
                format!("inspect {INTERFACE}: {e}"),
            ));
            return Ok(out);
        }
        Ok(None) => {
            if !kernel_has("vxlan") {
                out.push(check(
                    "network",
                    CHECK_FAIL,
                    "the kernel has no VXLAN support (modprobe vxlan fails); the cluster network needs it".into(),
                ));
                return Ok(out);
            }
            out.push(check(
                "network",
                CHECK_WARN,
                format!("{INTERFACE} is not set up yet; the agent creates it once connected"),
            ));
            return Ok(out);
        }
        Ok(Some(l)) => l,
    };
    if link.kind != "vxlan" || link.oper == OPER_DOWN {
        out.push(check(
            "network",
            CHECK_FAIL,
            format!("{INTERFACE} is not an up VXLAN interface; restart the agent to recreate it"),
        ));
        return Ok(out);
    }
    let routes = match net.rt.routes(link.index, AF_INET) {
        Ok(r) => r,
        Err(e) => {
            out.push(check(
                "network",
                CHECK_WARN,
                format!("list routes of {INTERFACE}: {e}"),
            ));
            return Ok(out);
        }
    };
    let peers = routes
        .iter()
        .filter(|r| r.dst.is_some() && r.gw.is_some())
        .count();
    out.push(check(
        "network",
        CHECK_OK,
        format!(
            "{INTERFACE} routes {peers} other node subnet(s) over VXLAN (UDP {VXLAN_PORT} on {}, open it to the other nodes)",
            addr_text(ip)
        ),
    ));
    if let Ok(Some(_)) = net.rt.link_named(SITE_INTERFACE) {
        for mut c in diagnose_wireguard(mode, ip, true)? {
            if c.name == "network" {
                c.name = "network-sites".into();
            }
            out.push(c);
        }
    }
    Ok(out)
}

/// The address of a WireGuard endpoint ("IP:port") as net.IP prints it.
fn endpoint_ip(ep: &str) -> String {
    let host = ep.rsplit_once(':').map_or(ep, |(h, _)| h);
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

/// diagnoseWireGuard.
fn diagnose_wireguard(
    mode: &str,
    ip: &Option<Addr>,
    meshed: bool,
) -> Result<Vec<Check>, Userspace> {
    let dev = if meshed && mode == MODE_PLAIN {
        SITE_INTERFACE
    } else {
        INTERFACE
    };
    let mut out = Vec::new();
    if kernel_has("wireguard") {
        out.push(check(
            "wireguard",
            CHECK_OK,
            "the kernel has WireGuard".into(),
        ));
    } else if mode == MODE_MESH {
        out.push(check(
            "wireguard",
            CHECK_FAIL,
            super::apply::ERR_NO_KERNEL_WIREGUARD.into(),
        ));
        return Ok(out);
    } else if meshed {
        out.push(check(
            "wireguard",
            CHECK_FAIL,
            super::apply::ERR_SITES_NEED_KERNEL.into(),
        ));
        return Ok(out);
    } else {
        out.push(check("wireguard", CHECK_WARN, "the kernel has no WireGuard: the agent runs it in userspace, which is markedly slower; install a kernel with WireGuard".into()));
    }
    let not_set_up = || {
        check(
            "network",
            CHECK_WARN,
            format!("{dev} is not set up yet; the agent creates it once connected"),
        )
    };
    let device = match wgnl::Client::open() {
        Ok(mut c) => c.device(dev),
        Err(e @ WgError::Errno(_)) => {
            out.push(check(
                "network",
                CHECK_FAIL,
                format!("WireGuard control: {e}"),
            ));
            return Ok(out);
        }
        // The kernel has no WireGuard family: wgctrl reads only
        // userspace devices then.
        Err(e) => Err(e),
    };
    let d = match device {
        Ok(d) => d,
        Err(_) => {
            if Path::new(&format!("{USER_SOCKETS}/{dev}.sock")).exists() {
                return Err(Userspace);
            }
            out.push(not_set_up());
            return Ok(out);
        }
    };
    let now = now();
    let mut stale: Vec<String> = d
        .peers
        .iter()
        .filter(|pe| pe.last_handshake.is_none_or(|t| now - t > STALE_HANDSHAKE))
        .map(|pe| {
            pe.endpoint
                .as_deref()
                .map_or_else(|| "no endpoint".to_string(), endpoint_ip)
        })
        .collect();
    stale.sort();
    if !stale.is_empty() {
        out.push(check(
            "network",
            CHECK_FAIL,
            format!(
                "{} of {} peer(s) have no recent handshake: [{}]; allow UDP {WIREGUARD_PORT} between the nodes",
                stale.len(),
                d.peers.len(),
                stale.join(" ")
            ),
        ));
        return Ok(out);
    }
    // Devices read over netlink are the kernel's (wgtypes.LinuxKernel).
    let kind = "Linux kernel";
    if mode == MODE_MESH || meshed {
        out.push(check(
            "network",
            CHECK_OK,
            format!(
                "{dev} ({kind}) has a recent handshake with all {} peer(s) (UDP {WIREGUARD_PORT}, open it to every address)",
                d.peers.len()
            ),
        ));
        return Ok(out);
    }
    out.push(check(
        "network",
        CHECK_OK,
        format!(
            "{INTERFACE} ({kind}) has a recent handshake with all {} peer(s) (UDP {WIREGUARD_PORT} on {}, open it to the other nodes)",
            d.peers.len(),
            addr_text(ip)
        ),
    ));
    Ok(out)
}

/// The peer list kept in cache, parsed for node: None when there is none
/// (or no cache), Err with the check's detail when it cannot be read.
fn kept_plan(cache: &str, node: &str, ip: &Option<Addr>) -> Option<Result<plan::Plan, String>> {
    if cache.is_empty() {
        return None;
    }
    let cfg = match mesh::load(Path::new(cache)) {
        Err(e) => return Some(Err(format!("read the peer list: {e}"))),
        Ok(None) => return None,
        Ok(Some(c)) => c,
    };
    Some(plan::parse(&cfg, node, ip).map_err(|e| {
        format!(
            "the peer list in {cache} does not parse: {e}; the agent writes it again once connected"
        )
    }))
}

/// diagnoseSites.
fn diagnose_sites(cache: &str, node: &str, ip: &Option<Addr>) -> Option<Check> {
    let p = match kept_plan(cache, node, ip)? {
        Ok(p) => p,
        Err(detail) => return Some(check("sites", CHECK_WARN, detail)),
    };
    let remote = p.peers.iter().filter(|pe| pe.remote).count();
    if remote == 0 {
        return None;
    }
    let locals = match local_prefixes() {
        Ok(l) => l,
        Err(e) => {
            return Some(check(
                "sites",
                CHECK_WARN,
                format!("list this machine's addresses: {e}"),
            ));
        }
    };
    let bad = plan::shadowed(&p, &locals);
    if !bad.is_empty() {
        return Some(check(
            "sites",
            CHECK_WARN,
            format!(
                "{} node(s) of other sites have an address inside this machine's local networks: {}; this machine reaches those addresses through the tunnel, so a host on the local network at the same address is unreachable from it (join such a node again with --no-private-ip to give it a mesh address)",
                bad.len(),
                bad.join("; ")
            ),
        ));
    }
    Some(check(
        "sites",
        CHECK_OK,
        format!("{remote} node(s) in other sites, none inside this machine's local networks"),
    ))
}

/// diagnoseRelay.
fn diagnose_relay(cache: &str, node: &str, ip: &Option<Addr>) -> Option<Check> {
    let p = kept_plan(cache, node, ip)?.ok()?;
    plan::relay_check(&p).map(|(level, detail)| check("relay", level, detail))
}

/// localPrefixes: the IPv4 networks on the machine's interfaces, leaving
/// out loopback and Armada's own.
fn local_prefixes() -> Result<Vec<LocalPrefix>, String> {
    let mut rt = rtnl::Handle::open().map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for l in rt.links().map_err(|e| e.to_string())? {
        if [INTERFACE, NEXT, SITE_INTERFACE, BRIDGE].contains(&l.name.as_str())
            || l.flags & IFF_LOOPBACK != 0
        {
            continue;
        }
        let addrs = rt
            .addrs(l.index, AF_INET)
            .map_err(|e| format!("addresses of {}: {e}", l.name))?;
        for a in addrs {
            if let Some(ip) = rtnl::addr_of(&a.ip) {
                out.push(LocalPrefix {
                    dev: l.name.clone(),
                    prefix: Prefix::from(&ip, a.prefixlen),
                });
            }
        }
    }
    Ok(out)
}

/// hasIsolation: whether both isolation tables exist; the error as Go's
/// netlink library words it.
fn has_isolation() -> Result<bool, String> {
    let sock = NftSocket::open()?;
    for fam in nft::FAMILIES.iter() {
        match sock.table_errno(&nft::get_table(*fam)) {
            Ok(()) => {}
            Err(libc::ENOENT) => return Ok(false),
            Err(e) => {
                return Err(format!("netlink receive: {}", super::netlink::Errno(e)));
            }
        }
    }
    Ok(true)
}

/// embedded.IPv6Off.
fn ipv6_off(link: &str) -> Result<bool, String> {
    match std::fs::read_to_string(format!("{IPV6_CONF}/{link}/disable_ipv6")) {
        Ok(s) => Ok(s.trim() == "1"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !Path::new(IPV6_CONF).exists() {
                return Ok(true);
            }
            Err(format!("{link} has no IPv6 settings"))
        }
        Err(e) => Err(e.to_string()),
    }
}

/// diagnoseIsolation.
fn diagnose_isolation() -> Check {
    match has_isolation() {
        Err(e) => check(
            "isolation",
            CHECK_FAIL,
            format!("nftables is not usable ({e}); the kernel needs nf_tables to keep apps and spaces apart"),
        ),
        Ok(false) => check(
            "isolation",
            CHECK_WARN,
            "the nftables tables that keep apps and spaces apart are not set up yet; the agent creates them once connected".into(),
        ),
        Ok(true) => match ipv6_off(BRIDGE) {
            Ok(true) => check(
                "isolation",
                CHECK_OK,
                "the nftables tables that keep apps and spaces apart are in place".into(),
            ),
            _ => check(
                "isolation",
                CHECK_FAIL,
                format!("IPv6 is on for {BRIDGE}, so containers can reach this machine's IPv6 listeners past the firewall; restart the agent, which turns it off"),
            ),
        },
    }
}

/// armada-node net diagnose.
pub fn command() -> Result<(), String> {
    let req: Request = serde_json::from_slice(&read_stdin()?).map_err(|e| e.to_string())?;
    let ip = Addr::parse(&req.private_ip);
    let endpoint = Addr::parse(&req.endpoint);
    let answer = match diagnose(&req.mode, &ip, &endpoint, &req.cache, &req.node) {
        Ok(checks) => Answer {
            checks,
            needs_userspace: false,
        },
        Err(Userspace) => Answer {
            checks: Vec::new(),
            needs_userspace: true,
        },
    };
    write_stdout(&serde_json::to_vec(&answer).map_err(|e| e.to_string())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_print_as_go_prints_their_address() {
        assert_eq!(endpoint_ip("203.0.113.2:51820"), "203.0.113.2");
        assert_eq!(endpoint_ip("[2001:db8::1]:51820"), "2001:db8::1");
    }
}

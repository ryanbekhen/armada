//! The validated cluster network (clusternet.go, peers.go, policy.go's
//! parsers): what the control plane sent, checked again before anything of
//! it reaches routes or firewall rules, and the paths between nodes behind
//! NAT (ADR 0050).

use super::addr::{Addr, Prefix, addr_text, opt_contains, prefix_text, quote};
use super::config::{NetworkConfig, NetworkEndpoint};
use super::key::Key;
use crate::names;
use std::collections::{BTreeMap, HashMap, HashSet};

pub const INTERFACE: &str = "armada-net";
pub const SITE_INTERFACE: &str = "armada-wg";
pub const NEXT: &str = "armada-next";
pub const VXLAN_PORT: u16 = 4789;
pub const VXLAN_OVERHEAD: i64 = 50;
pub const WIREGUARD_PORT: u16 = 51820;
pub const WIREGUARD_OVERHEAD: i64 = 80;
const SUBNET_BITS: u8 = 24;
const MAX_PEERS: usize = 4096;
const MAX_ENDPOINTS: usize = 1 << 16;
const MAX_TCP_PORTS: usize = 4096;

pub const MODE_PLAIN: &str = "plain";
pub const MODE_WIREGUARD: &str = "wireguard";
pub const MODE_MESH: &str = "mesh";
pub const SWITCH_PREPARE: &str = "prepare";
pub const SWITCH_MOVE: &str = "move";

/// Whether a mode runs over WireGuard.
pub fn encrypted(mode: &str) -> bool {
    mode == MODE_WIREGUARD || mode == MODE_MESH
}

/// TunnelMTU: the MTU of the tunnel, bridge, and containers for an uplink.
pub fn tunnel_mtu(mode: &str, uplink: i64) -> i64 {
    if encrypted(mode) {
        uplink - WIREGUARD_OVERHEAD
    } else {
        uplink - VXLAN_OVERHEAD
    }
}

/// The tunnel's UDP port in a mode.
pub fn port(mode: &str) -> u16 {
    if encrypted(mode) {
        WIREGUARD_PORT
    } else {
        VXLAN_PORT
    }
}

/// One other node (peer).
#[derive(Clone, Debug, Default)]
pub struct Peer {
    pub node: String,
    pub ip: Option<Addr>,
    pub subnet: Option<Prefix>,
    pub key: Key,
    pub endpoint: Option<Addr>,
    pub site: String,
    pub remote: bool,
    pub nat: bool,
    pub relay: bool,
    pub carried: Vec<Prefix>,
}

impl Peer {
    pub fn ip(&self) -> &Addr {
        self.ip.as_ref().expect("a parsed peer has an address")
    }

    pub fn subnet(&self) -> &Prefix {
        self.subnet.as_ref().expect("a parsed peer has a subnet")
    }
}

/// A validated network configuration (plan).
#[derive(Clone, Debug, Default)]
pub struct Plan {
    pub mode: String,
    pub cidr: Option<Prefix>,
    pub mesh: Option<Prefix>,
    pub meshed: bool,
    pub switch_to: String,
    pub step: String,
    pub self_: Peer,
    pub peers: Vec<Peer>,
    pub relayed: Vec<Peer>,
    pub unreachable: Vec<String>,
    pub relaying: Vec<[Prefix; 2]>,
    pub endpoints: BTreeMap<Addr, String>,
    pub isolate_default: bool,
    pub tcp_ports: Vec<u16>,
}

impl Plan {
    pub fn cidr(&self) -> &Prefix {
        self.cidr
            .as_ref()
            .expect("a parsed plan has a cluster CIDR")
    }

    pub fn switching(&self) -> bool {
        !self.switch_to.is_empty()
    }

    pub fn local(&self) -> Vec<Peer> {
        self.peers.iter().filter(|p| !p.remote).cloned().collect()
    }

    pub fn remote(&self) -> Vec<Peer> {
        self.peers.iter().filter(|p| p.remote).cloned().collect()
    }

    pub fn has_remote(&self) -> bool {
        self.peers.iter().any(|p| p.remote)
    }

    /// p.only: the plan with only the given peers.
    pub fn only(&self, peers: Vec<Peer>) -> Plan {
        Plan {
            peers,
            ..self.clone()
        }
    }

    /// Whether a pair is reached over WireGuard between endpoints.
    fn public(&self, a: &Peer, b: &Peer) -> bool {
        self.mode == MODE_MESH
            || a.site != b.site
            || opt_contains(&self.mesh, a.ip())
            || opt_contains(&self.mesh, b.ip())
    }

    /// relayThrough (ADR 0050).
    fn relay_through(&mut self) {
        let mut relays: HashMap<String, Peer> = HashMap::new();
        for pe in std::iter::once(&self.self_).chain(self.peers.iter()) {
            if pe.relay && pe.endpoint.is_some() && !pe.key.is_zero() {
                relays.insert(pe.site.clone(), pe.clone());
            }
        }
        if self.self_.nat {
            let mut carried: HashMap<String, Vec<Prefix>> = HashMap::new();
            let mut kept = Vec::new();
            for pe in std::mem::take(&mut self.peers) {
                if !pe.nat || !self.public(&self.self_, &pe) {
                    kept.push(pe);
                    continue;
                }
                match pair_relay(&relays, &self.self_, &pe) {
                    Some(r) => {
                        carried
                            .entry(r.node.clone())
                            .or_default()
                            .push(pe.subnet().clone());
                        self.relayed.push(pe);
                    }
                    None => self.unreachable.push(pe.node.clone()),
                }
            }
            for pe in &mut kept {
                pe.carried = carried.get(&pe.node).cloned().unwrap_or_default();
            }
            self.peers = kept;
            return;
        }
        if !self.self_.relay {
            return;
        }
        for (i, a) in self.peers.iter().enumerate() {
            for b in &self.peers[i + 1..] {
                if !a.nat || !b.nat || !self.public(a, b) {
                    continue;
                }
                if let Some(r) = pair_relay(&relays, a, b)
                    && r.node == self.self_.node
                {
                    self.relaying.push([a.subnet().clone(), b.subnet().clone()]);
                }
            }
        }
    }
}

/// pairRelay: the relay of the site of a and b that sorts first, else of the
/// other, else of the first site of all with one.
fn pair_relay<'a>(relays: &'a HashMap<String, Peer>, a: &Peer, b: &Peer) -> Option<&'a Peer> {
    let (first, second) = if a.site <= b.site {
        (&a.site, &b.site)
    } else {
        (&b.site, &a.site)
    };
    relays
        .get(first)
        .or_else(|| relays.get(second))
        .or_else(|| relays.keys().min().and_then(|k| relays.get(k)))
}

/// CheckMeshCIDR.
pub fn check_mesh_cidr(s: &str) -> Result<Prefix, String> {
    let p = match Prefix::parse(s) {
        Some(p) if p.addr.is4() => p,
        _ => {
            return Err(format!(
                "invalid mesh CIDR {}: want an IPv4 prefix",
                quote(s)
            ));
        }
    };
    if p.masked() != p {
        return Err(format!(
            "mesh CIDR {p} is not in canonical form (want {})",
            p.masked()
        ));
    }
    if p.bits < 8 || p.bits > 24 {
        return Err(format!("mesh CIDR {p}: the prefix must be from /8 to /24"));
    }
    if !p.addr.is_private() {
        return Err(format!("mesh CIDR {p} is not a private range"));
    }
    Ok(p)
}

/// parseSwitch.
fn parse_switch(cfg: &NetworkConfig) -> Result<(String, String), String> {
    let (to, step) = (&cfg.switch_to, &cfg.switch_step);
    if to.is_empty() {
        if !step.is_empty() {
            return Err(format!("switch step {} without a target mode", quote(step)));
        }
        return Ok((String::new(), String::new()));
    }
    let mode = &cfg.mode;
    if (mode != MODE_PLAIN && mode != MODE_WIREGUARD)
        || (to != MODE_PLAIN && to != MODE_WIREGUARD)
        || to == mode
    {
        return Err(format!(
            "cannot switch the cluster network from {} to {}",
            quote(mode),
            quote(to)
        ));
    }
    if step != SWITCH_PREPARE && step != SWITCH_MOVE {
        return Err(format!("unknown switch step {}", quote(step)));
    }
    Ok((to.clone(), step.clone()))
}

/// containerAddr: an address the bridge of a node subnet may give a
/// container.
pub fn container_addr(a: &Addr, cidr: &Prefix) -> bool {
    match a {
        Addr::V4(b) => cidr.contains(a) && b[3] != 0 && b[3] != 1 && b[3] != 255,
        Addr::V6(..) => false,
    }
}

/// parseEndpoints: addresses claimed twice are left out.
fn parse_endpoints(
    eps: &[NetworkEndpoint],
    cidr: &Prefix,
) -> Result<BTreeMap<Addr, String>, String> {
    if eps.len() > MAX_ENDPOINTS {
        return Err(format!(
            "{} container addresses: at most {MAX_ENDPOINTS}",
            eps.len()
        ));
    }
    let mut out = BTreeMap::new();
    let mut clash = HashSet::new();
    for e in eps {
        let a = match Addr::parse(&e.address) {
            Some(a) if container_addr(&a, cidr) => a,
            _ => return Err(format!("invalid container address {}", quote(&e.address))),
        };
        if !names::valid_app_id(&e.app) {
            return Err(format!(
                "container address {a}: invalid app {}",
                quote(&e.app)
            ));
        }
        if out.insert(a.clone(), e.app.clone()).is_some() {
            clash.insert(a);
        }
    }
    for a in clash {
        out.remove(&a);
    }
    Ok(out)
}

/// parseTCPPorts: sorted and unique.
fn parse_tcp_ports(ports: &[super::config::U32]) -> Result<Vec<u16>, String> {
    if ports.len() > MAX_TCP_PORTS {
        return Err(format!(
            "{} TCP ports: at most {MAX_TCP_PORTS}",
            ports.len()
        ));
    }
    let mut out = Vec::with_capacity(ports.len());
    for p in ports {
        if !names::tcp_port_ok(u64::from(p.0)) {
            return Err(format!("invalid TCP port {}", p.0));
        }
        out.push(p.0 as u16);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// netutil.CheckNodeIP.
fn check_node_ip(s: &str) -> Result<Addr, String> {
    let addr = match Addr::parse(s) {
        Some(a) if a.zone().is_empty() => a,
        _ => return Err(format!("invalid IP address {}", quote(s))),
    };
    let unmapped = addr.unmap();
    if unmapped.to_string() != s {
        return Err(format!(
            "IP address {} is not in canonical form (want {unmapped})",
            quote(s)
        ));
    }
    let cgnat = Prefix::parse("100.64.0.0/10").expect("a valid prefix");
    if !(unmapped.is_private() || unmapped.is_loopback() || cgnat.contains(&unmapped)) {
        return Err(format!(
            "{s}: address is not private; internal services must bind to a private (VPC) or loopback address"
        ));
    }
    if unmapped.is_loopback() {
        return Err(format!("{s}: a node IP must not be a loopback address"));
    }
    Ok(unmapped)
}

/// netutil.CheckEndpoint.
fn check_endpoint(s: &str) -> Result<Addr, String> {
    let a = match Addr::parse(s) {
        Some(a) if a.is4() && a.to_string() == s => a,
        _ => {
            return Err(format!(
                "invalid endpoint {}: want an IPv4 address",
                quote(s)
            ));
        }
    };
    if !a.is_global_unicast() || a.is_loopback() || a == Addr::V4([255; 4]) {
        return Err(format!(
            "endpoint {a} is not a unicast address other machines can reach"
        ));
    }
    Ok(a)
}

/// parse: what the control plane sent, for the node `self_name` at
/// `self_ip`.
pub fn parse(cfg: &NetworkConfig, self_name: &str, self_ip: &Option<Addr>) -> Result<Plan, String> {
    let mode = cfg.mode.as_str();
    if mode != MODE_PLAIN && mode != MODE_WIREGUARD && mode != MODE_MESH {
        return Err(format!(
            "cluster network mode {} is not supported by this agent",
            quote(mode)
        ));
    }
    let cidr = match Prefix::parse(&cfg.cluster_cidr) {
        Some(c)
            if c.addr.is4()
                && c.masked() == c
                && c.addr.is_private()
                && c.bits >= 8
                && c.bits <= SUBNET_BITS =>
        {
            c
        }
        _ => return Err(format!("invalid cluster CIDR {}", quote(&cfg.cluster_cidr))),
    };
    let mut mesh = None;
    if mode == MODE_MESH || !cfg.mesh_cidr.is_empty() {
        let m = check_mesh_cidr(&cfg.mesh_cidr)?;
        if m.overlaps(&cidr) {
            return Err(format!("mesh CIDR {m} overlaps the cluster CIDR {cidr}"));
        }
        mesh = Some(m);
    }
    if cfg.peers.len() > MAX_PEERS {
        return Err(format!("{} peers: at most {MAX_PEERS}", cfg.peers.len()));
    }
    let (switch_to, step) = parse_switch(cfg)?;
    let endpoints = parse_endpoints(&cfg.endpoints, &cidr)?;
    let tcp_ports = parse_tcp_ports(&cfg.tcp_ports)?;
    let mut p = Plan {
        mode: mode.to_string(),
        cidr: Some(cidr.clone()),
        mesh: mesh.clone(),
        switch_to,
        step,
        endpoints,
        isolate_default: cfg.isolate_default,
        tcp_ports,
        ..Plan::default()
    };
    let (mut ips, mut subnets, mut nodes, mut keys) = (
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
    );
    let mut found = false;
    for pp in &cfg.peers {
        let node = &pp.node;
        if let Some(e) = names::validate_name(node) {
            return Err(format!("peer name {}: {e}", quote(node)));
        }
        let ip = check_node_ip(&pp.private_ip).map_err(|e| format!("peer {node}: {e}"))?;
        let sub = match Prefix::parse(&pp.subnet) {
            Some(s) if s.bits == SUBNET_BITS && s.masked() == s && cidr.contains(&s.addr) => s,
            _ => {
                return Err(format!(
                    "peer {node}: subnet {} is not a /{SUBNET_BITS} of {cidr}",
                    quote(&pp.subnet)
                ));
            }
        };
        if cidr.contains(&ip) {
            return Err(format!(
                "peer {node}: private IP {ip} is inside the cluster CIDR"
            ));
        }
        if mode == MODE_MESH && !opt_contains(&mesh, &ip) {
            return Err(format!(
                "peer {node}: mesh address {ip} is outside the mesh CIDR {}",
                prefix_text(&mesh)
            ));
        }
        if nodes.contains(node) || ips.contains(&ip) || subnets.contains(&sub) {
            return Err(format!("peer {node}: duplicate name, address, or subnet"));
        }
        nodes.insert(node.clone());
        ips.insert(ip.clone());
        subnets.insert(sub.clone());
        let mut pe = Peer {
            node: node.clone(),
            ip: Some(ip.clone()),
            subnet: Some(sub),
            site: pp.site.clone(),
            nat: pp.behind_nat,
            relay: pp.relay,
            ..Peer::default()
        };
        if pe.nat && pe.relay {
            return Err(format!("peer {node}: a node behind NAT cannot relay"));
        }
        if !pe.site.is_empty()
            && let Some(e) = names::check_label_value(&pe.site)
        {
            return Err(format!("peer {node}: site: {e}"));
        }
        if !pp.endpoint.is_empty() && !pe.nat {
            let ep = check_endpoint(&pp.endpoint).map_err(|e| format!("peer {node}: {e}"))?;
            if cidr.contains(&ep) || opt_contains(&mesh, &ep) {
                return Err(format!(
                    "peer {node}: endpoint {ep} is inside the cluster's own ranges"
                ));
            }
            pe.endpoint = Some(ep);
        }
        if !pp.public_key.is_empty() {
            let k = match Key::parse(&pp.public_key) {
                Some(k) if !k.is_zero() => k,
                _ => return Err(format!("peer {node}: invalid public key")),
            };
            if !keys.insert(k) {
                return Err(format!("peer {node}: duplicate public key"));
            }
            pe.key = k;
        }
        if node == self_name {
            if Some(&ip) != self_ip.as_ref() {
                return Err(format!(
                    "the control plane lists this node at {ip}, not {}",
                    addr_text(self_ip)
                ));
            }
            p.self_ = pe;
            found = true;
            continue;
        }
        p.peers.push(pe);
    }
    if !found {
        return Err("this node is not in the cluster network's peer list".into());
    }
    p.meshed = mode != MODE_MESH && opt_contains(&mesh, p.self_.ip());
    let mut kept = Vec::new();
    for mut pe in std::mem::take(&mut p.peers) {
        pe.remote = mode != MODE_MESH
            && (pe.site != p.self_.site || p.meshed || opt_contains(&mesh, pe.ip()));
        let wg = encrypted(mode) || pe.remote;
        if wg && pe.key.is_zero() {
            continue;
        }
        if (mode == MODE_MESH || pe.remote) && pe.endpoint.is_none() && !pe.nat {
            continue;
        }
        kept.push(pe);
    }
    p.peers = kept;
    p.relay_through();
    if p.switching() && p.has_remote() {
        return Err("a cluster with more than one site cannot switch its network mode".into());
    }
    Ok(p)
}

/// A network on one of the machine's interfaces (localPrefix).
pub struct LocalPrefix {
    pub dev: String,
    pub prefix: Prefix,
}

/// shadowed: the peers of other sites whose node address lies in one of the
/// machine's local networks.
pub fn shadowed(p: &Plan, locals: &[LocalPrefix]) -> Vec<String> {
    let mut out = Vec::new();
    for pe in p.peers.iter().filter(|pe| pe.remote) {
        if let Some(l) = locals
            .iter()
            .find(|l| l.prefix.bits < 32 && l.prefix.contains(pe.ip()))
        {
            let site = if pe.site.is_empty() {
                "the first site"
            } else {
                &pe.site
            };
            out.push(format!(
                "{} ({site}) at {} is inside {} on {}",
                pe.node,
                pe.ip(),
                l.prefix.masked(),
                l.dev
            ));
        }
    }
    out
}

/// Check levels of doctor's checks.
pub const CHECK_OK: i64 = 0;
pub const CHECK_FAIL: i64 = 2;

/// relayCheck: what doctor's relay check says of a plan, or None.
pub fn relay_check(p: &Plan) -> Option<(i64, String)> {
    if !p.unreachable.is_empty() {
        return Some((
            CHECK_FAIL,
            format!(
                "this node is behind NAT and cannot reach {} node(s) behind NAT: {}; their sites and this one have no relay (a ready node with an endpoint)",
                p.unreachable.len(),
                p.unreachable.join(", ")
            ),
        ));
    }
    if !p.relayed.is_empty() {
        let via: Vec<String> = p
            .peers
            .iter()
            .filter(|pe| !pe.carried.is_empty())
            .map(|pe| format!("{} through {}", pe.carried.len(), pe.node))
            .collect();
        return Some((
            CHECK_OK,
            format!(
                "this node is behind NAT and reaches {} node(s) behind NAT in other sites through relays: {}",
                p.relayed.len(),
                via.join(", ")
            ),
        ));
    }
    if p.self_.nat {
        return Some((
            CHECK_OK,
            "this node is behind NAT; it reaches every node of another site directly".into(),
        ));
    }
    if p.self_.relay {
        return Some((
            CHECK_OK,
            format!(
                "this node relays its site's traffic between nodes behind NAT: {} pair(s)",
                p.relaying.len()
            ),
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::config::NetworkPeer;

    fn np(node: &str, ip: &str, subnet: &str) -> NetworkPeer {
        NetworkPeer {
            node: node.into(),
            private_ip: ip.into(),
            subnet: subnet.into(),
            ..Default::default()
        }
    }

    fn config(peers: Vec<NetworkPeer>) -> NetworkConfig {
        NetworkConfig {
            mode: "plain".into(),
            cluster_cidr: "10.120.0.0/16".into(),
            peers,
            ..Default::default()
        }
    }

    #[test]
    fn parses_a_cluster() {
        let cfg = config(vec![
            np("a", "10.0.0.1", "10.120.0.0/24"),
            np("b", "10.0.0.2", "10.120.1.0/24"),
            np("c", "10.0.0.3", "10.120.2.0/24"),
        ]);
        let p = parse(&cfg, "a", &Addr::parse("10.0.0.1")).unwrap();
        assert_eq!(p.self_.subnet().to_string(), "10.120.0.0/24");
        assert_eq!(p.peers.len(), 2);
        assert_eq!(p.peers[1].node, "c");
    }

    #[test]
    fn refuses() {
        let a = np("a", "10.0.0.1", "10.120.0.0/24");
        let ip = Addr::parse("10.0.0.1");
        for (peer, want) in [
            (
                np("B;rm", "10.0.0.2", "10.120.1.0/24"),
                "peer name \"B;rm\": name: must be",
            ),
            (
                np("b", "1.1.1.1", "10.120.1.0/24"),
                "peer b: 1.1.1.1: address is not private",
            ),
            (
                np("b", "127.0.0.1", "10.120.1.0/24"),
                "peer b: 127.0.0.1: a node IP",
            ),
            (
                np("b", "10.0.0.2", "10.120.1.5/24"),
                "peer b: subnet \"10.120.1.5/24\" is not a /24 of 10.120.0.0/16",
            ),
            (np("a", "10.0.0.2", "10.120.1.0/24"), "peer a: duplicate"),
        ] {
            let err = parse(&config(vec![a.clone(), peer]), "a", &ip).unwrap_err();
            assert!(err.starts_with(want), "{err}");
        }
        let mut c = config(vec![a]);
        c.mode = "ipsec".into();
        assert_eq!(
            parse(&c, "a", &ip).unwrap_err(),
            "cluster network mode \"ipsec\" is not supported by this agent"
        );
    }
}

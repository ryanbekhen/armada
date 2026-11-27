//! The firewall rules of the cluster network, as
//! iptables argument lists written the way `iptables -S` prints them, and
//! the routes and tunnel addresses each transport carries.

use super::addr::{Addr, Prefix};
use super::plan::{
    INTERFACE, MODE_MESH, MODE_PLAIN, NEXT, Peer, Plan, SITE_INTERFACE, VXLAN_PORT, WIREGUARD_PORT,
    port,
};

/// The container bridge (embedded.BridgeName).
pub const BRIDGE: &str = "armada0";
pub const CHAIN_IN: &str = "ARMADA-NET-IN";
pub const CHAIN_MESH: &str = "ARMADA-NET-MESH";

pub type Rule = Vec<String>;

fn rule(parts: &[&str]) -> Rule {
    parts.iter().map(|s| s.to_string()).collect()
}

fn host(a: &Addr) -> String {
    format!("{a}/32")
}

/// tunnels: the interfaces packets between nodes come and go by.
pub fn tunnels(p: &Plan) -> Vec<&'static str> {
    if p.switching() {
        vec![INTERFACE, NEXT]
    } else if p.mode == MODE_PLAIN && p.has_remote() {
        vec![INTERFACE, SITE_INTERFACE]
    } else {
        vec![INTERFACE]
    }
}

/// Where WireGuard peers' traffic comes out.
pub fn wg_interface(p: &Plan) -> &'static str {
    if p.mode == MODE_PLAIN {
        SITE_INTERFACE
    } else {
        INTERFACE
    }
}

/// ARMADA-NET-IN's rules for a node at private_ip.
pub fn input_rules(p: &Plan, private_ip: &Addr) -> Vec<Rule> {
    if p.mode == MODE_MESH {
        return vec![rule(&["-j", "ACCEPT"])];
    }
    let mut rules: Vec<Rule> = p
        .local()
        .iter()
        .map(|pe| {
            rule(&[
                "-s",
                &host(pe.ip()),
                "-d",
                &host(private_ip),
                "-j",
                "ACCEPT",
            ])
        })
        .collect();
    if p.has_remote() {
        rules.push(rule(&[
            "-p",
            "udp",
            "-m",
            "udp",
            "--dport",
            &WIREGUARD_PORT.to_string(),
            "-j",
            "ACCEPT",
        ]));
    }
    rules.push(rule(&["-j", "DROP"]));
    rules
}

/// The INPUT rule that sends the tunnel's port to ARMADA-NET-IN.
pub fn input_jump(p: &Plan) -> Rule {
    if p.switching() || (p.mode == MODE_PLAIN && p.has_remote()) {
        return rule(&[
            "-p",
            "udp",
            "-m",
            "multiport",
            "--dports",
            &format!("{VXLAN_PORT},{WIREGUARD_PORT}"),
            "-j",
            CHAIN_IN,
        ]);
    }
    rule(&[
        "-p",
        "udp",
        "-m",
        "udp",
        "--dport",
        &port(&p.mode).to_string(),
        "-j",
        CHAIN_IN,
    ])
}

/// ARMADA-NET-MSS's rules.
pub fn mss_rules(tunnels: &[&str]) -> Vec<Rule> {
    tunnels
        .iter()
        .map(|name| {
            rule(&[
                "-o",
                name,
                "-p",
                "tcp",
                "-m",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-j",
                "TCPMSS",
                "--clamp-mss-to-pmtu",
            ])
        })
        .collect()
}

/// ARMADA-NET-FWD's rules, with a relay's pairs first.
pub fn forward_rules(tunnels: &[&str], relaying: &[[Prefix; 2]]) -> Vec<Rule> {
    let mut rules = Vec::new();
    for pair in relaying {
        for i in tunnels {
            for o in tunnels {
                for (s, d) in [(&pair[0], &pair[1]), (&pair[1], &pair[0])] {
                    rules.push(rule(&[
                        "-s",
                        &s.to_string(),
                        "-d",
                        &d.to_string(),
                        "-i",
                        i,
                        "-o",
                        o,
                        "-j",
                        "ACCEPT",
                    ]));
                }
            }
        }
    }
    for name in tunnels {
        rules.push(rule(&["-i", name, "-o", BRIDGE, "-j", "ACCEPT"]));
        rules.push(rule(&["-i", BRIDGE, "-o", name, "-j", "ACCEPT"]));
    }
    for name in tunnels {
        rules.push(rule(&["-i", name, "-j", "DROP"]));
    }
    rules.push(rule(&["-i", BRIDGE, "-o", BRIDGE, "-j", "RETURN"]));
    rules.push(rule(&[
        "-o",
        BRIDGE,
        "-m",
        "conntrack",
        "--ctstate",
        "NEW",
        "-m",
        "conntrack",
        "!",
        "--ctstate",
        "DNAT",
        "-j",
        "DROP",
    ]));
    rules
}

/// ARMADA-NET-MESH's rules.
pub fn mesh_rules(p: &Plan) -> Vec<Rule> {
    let me = host(p.self_.ip());
    let mut rules = Vec::new();
    if p.mode == MODE_MESH {
        let mesh = p.mesh.as_ref().map(|m| m.to_string()).unwrap_or_default();
        rules.push(rule(&["-s", &mesh, "-d", &me, "-j", "ACCEPT"]));
    } else {
        for pe in p.peers.iter().filter(|pe| pe.remote) {
            rules.push(rule(&["-s", &host(pe.ip()), "-d", &me, "-j", "ACCEPT"]));
        }
    }
    rules.push(rule(&["-j", "RETURN"]));
    rules
}

/// ARMADA-NET-PRE's rules.
pub fn spoof_rules(p: &Plan) -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut ports = vec![port(&p.mode)];
    if p.switching() {
        ports.push(port(&p.switch_to));
    }
    for pe in &p.peers {
        let (to, peer_ports) = if p.mode == MODE_MESH || pe.remote {
            (pe.endpoint.as_ref(), vec![WIREGUARD_PORT])
        } else {
            (pe.ip.as_ref(), ports.clone())
        };
        let Some(to) = to else { continue };
        for port in peer_ports {
            rules.push(rule(&[
                "-d",
                &host(to),
                "-i",
                BRIDGE,
                "-p",
                "udp",
                "-m",
                "udp",
                "--dport",
                &port.to_string(),
                "-j",
                "DROP",
            ]));
        }
    }
    if p.mode != MODE_MESH {
        let dev = wg_interface(p);
        for pe in p.peers.iter().filter(|pe| pe.remote) {
            let ip = host(pe.ip());
            rules.push(rule(&["-s", &ip, "!", "-i", dev, "-j", "DROP"]));
            rules.push(rule(&["-s", &ip, "-i", dev, "-j", "RETURN"]));
        }
        if let Some(mesh) = &p.mesh {
            let mesh = mesh.to_string();
            rules.push(rule(&["-d", &mesh, "-i", "lo", "-j", "RETURN"]));
            rules.push(rule(&["-d", &mesh, "!", "-i", dev, "-j", "DROP"]));
            rules.push(rule(&["-s", &mesh, "!", "-i", dev, "-j", "DROP"]));
        }
    }
    if p.mode == MODE_MESH {
        let mesh = p.mesh.as_ref().map(|m| m.to_string()).unwrap_or_default();
        rules.push(rule(&["-d", &mesh, "-i", "lo", "-j", "RETURN"]));
        rules.push(rule(&["-d", &mesh, "!", "-i", INTERFACE, "-j", "DROP"]));
        rules.push(rule(&["-s", &mesh, "!", "-i", INTERFACE, "-j", "DROP"]));
        rules.push(rule(&["-s", &mesh, "-i", INTERFACE, "-j", "RETURN"]));
    }
    let sub = p.self_.subnet().to_string();
    rules.push(rule(&["-s", &sub, "-i", "lo", "-j", "RETURN"]));
    rules.push(rule(&["-s", &sub, "!", "-i", BRIDGE, "-j", "DROP"]));
    let cidr = p.cidr().to_string();
    for name in tunnels(p) {
        rules.push(rule(&["!", "-s", &cidr, "-i", name, "-j", "DROP"]));
    }
    rules
}

/// The routes a transport carries (routeSet).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RouteSet {
    All,
    Probe,
    None,
}

impl RouteSet {
    pub fn name(self) -> &'static str {
        match self {
            RouteSet::All => "all",
            RouteSet::Probe => "probe",
            RouteSet::None => "none",
        }
    }
}

/// One route syncRoutes installs (wantedRoute).
pub struct Route {
    pub node: String,
    pub dst: Prefix,
    /// The peer's tunnel end, on link, over VXLAN.
    pub via: Option<Addr>,
    pub src: Option<Addr>,
}

/// a node's end of the tunnel, its subnet's network address.
pub fn vtep_addr(subnet: &Prefix) -> Addr {
    subnet.masked().addr
}

/// The fixed hardware address of a node's tunnel end.
pub fn vtep_mac(subnet: &Prefix) -> String {
    match vtep_addr(subnet) {
        Addr::V4(b) => format!("02:42:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3]),
        Addr::V6(..) => String::new(),
    }
}

/// The routes to the peers of p, via their tunnel ends when via
/// is set.
pub fn want_routes(p: &Plan, via: bool, set: RouteSet) -> Vec<Route> {
    let mut out = Vec::new();
    if set == RouteSet::None {
        return out;
    }
    for pe in &p.peers {
        if set == RouteSet::Probe {
            out.push(Route {
                node: pe.node.clone(),
                dst: Prefix::from(&vtep_addr(pe.subnet()), 32),
                via: None,
                src: None,
            });
            continue;
        }
        if p.mode == MODE_MESH || pe.remote {
            out.push(Route {
                node: pe.node.clone(),
                dst: Prefix::from(pe.ip(), 32),
                via: None,
                src: Some(p.self_.ip().clone()),
            });
        }
        for dst in std::iter::once(pe.subnet()).chain(pe.carried.iter()) {
            out.push(Route {
                node: pe.node.clone(),
                dst: dst.clone(),
                via: via.then(|| vtep_addr(pe.subnet())),
                src: None,
            });
        }
    }
    out
}

/// The addresses setUp gives a tunnel interface.
pub fn tunnel_addresses(p: &Plan) -> Vec<Prefix> {
    let mut out = vec![Prefix::from(&vtep_addr(p.self_.subnet()), 32)];
    if p.mode == MODE_MESH || p.meshed {
        out.push(Prefix::from(p.self_.ip(), 32));
    }
    out
}

/// The VXLAN entries vxlanPeers installs for a peer: its hardware address
/// on its private IP, and its tunnel address on that hardware address.
pub fn vxlan_entry(pe: &Peer) -> (String, Addr) {
    (vtep_mac(pe.subnet()), vtep_addr(pe.subnet()))
}

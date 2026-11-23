//! What the Go parity tests ask of the netlink code without root:
//!
//!   armada-node net netlink encode   stdin: a list of calls (below); stdout: for each,
//!                                    the hex of the messages it sends (seq and port 0)
//!   armada-node net netlink show     stdout: this machine's interfaces, IPv4 addresses,
//!                                    main-table IPv4 routes, and neighbour and
//!                                    forwarding entries, as rtnl.rs reads them
//!   armada-node net netlink wg-parse stdin: the hex of a WireGuard device dump's
//!                                    messages (after the netlink header); stdout: the
//!                                    device
//!
//! A call is {"Op": NAME, ...}, named after the Go call it stands for.

use super::addr::Addr;
use super::key::Key;
use super::netlink::Msg;
use super::rtnl::{self, IfAddr, Link, Neigh, Route};
use super::wgnl::{self, DeviceSet, PeerSet};
use super::{read_stdin, write_stdout};
use serde::{Deserialize, Serialize};

fn ip(s: &str) -> Vec<u8> {
    Addr::parse(s).map(|a| rtnl::v4(&a)).unwrap_or_default()
}

fn opt_ip(s: &str) -> Option<Vec<u8>> {
    (!s.is_empty()).then(|| ip(s))
}

fn text(b: &[u8]) -> String {
    rtnl::addr_of(b).map(|a| a.to_string()).unwrap_or_default()
}

fn opt_text(b: &Option<Vec<u8>>) -> String {
    b.as_deref().map(text).unwrap_or_default()
}

#[derive(Deserialize, Serialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct AddrJson {
    index: i32,
    family: u8,
    #[serde(rename = "IP")]
    ip: String,
    prefixlen: u8,
    peer: String,
    broadcast: String,
    label: String,
    flags: u32,
    scope: u8,
    valid: u32,
    preferred: u32,
}

impl AddrJson {
    fn of(a: &IfAddr) -> AddrJson {
        AddrJson {
            index: a.index,
            family: a.family,
            ip: text(&a.ip),
            prefixlen: a.prefixlen,
            peer: opt_text(&a.peer),
            broadcast: opt_text(&a.broadcast),
            label: a.label.clone(),
            flags: a.flags,
            scope: a.scope,
            valid: a.valid,
            preferred: a.preferred,
        }
    }

    fn addr(&self) -> IfAddr {
        IfAddr {
            index: self.index,
            family: self.family,
            ip: ip(&self.ip),
            prefixlen: self.prefixlen,
            peer: opt_ip(&self.peer),
            broadcast: opt_ip(&self.broadcast),
            label: self.label.clone(),
            flags: self.flags,
            scope: self.scope,
            valid: self.valid,
            preferred: self.preferred,
        }
    }
}

#[derive(Deserialize, Serialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct RouteJson {
    family: u8,
    /// "" for none, else "ip/bits".
    dst: String,
    src: String,
    gw: String,
    oif: i32,
    priority: u32,
    table: u32,
    protocol: u8,
    scope: u8,
    #[serde(rename = "Type")]
    kind: u8,
    flags: u32,
    tos: u8,
}

impl RouteJson {
    fn of(r: &Route) -> RouteJson {
        RouteJson {
            family: r.family,
            dst: r
                .dst
                .as_ref()
                .map(|(a, bits)| format!("{}/{bits}", text(a)))
                .unwrap_or_default(),
            src: opt_text(&r.src),
            gw: opt_text(&r.gw),
            oif: r.oif,
            priority: r.priority,
            table: r.table,
            protocol: r.protocol,
            scope: r.scope,
            kind: r.kind,
            flags: r.flags,
            tos: r.tos,
        }
    }

    fn route(&self) -> Route {
        Route {
            family: self.family,
            dst: self
                .dst
                .rsplit_once('/')
                .map(|(a, b)| (ip(a), b.parse().unwrap_or(0))),
            src: opt_ip(&self.src),
            gw: opt_ip(&self.gw),
            oif: self.oif,
            priority: self.priority,
            table: self.table,
            protocol: self.protocol,
            scope: self.scope,
            kind: self.kind,
            flags: self.flags,
            tos: self.tos,
        }
    }
}

#[derive(Deserialize, Serialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct NeighJson {
    index: i32,
    family: u8,
    state: u16,
    #[serde(rename = "Type")]
    kind: u8,
    flags: u8,
    #[serde(rename = "IP")]
    ip: String,
    #[serde(rename = "MAC")]
    mac: String,
    #[serde(rename = "LLIP")]
    ll_ip: String,
    flags_ext: u32,
    vlan: u16,
    #[serde(rename = "VNI")]
    vni: u32,
    master: u32,
}

impl NeighJson {
    fn of(n: &Neigh) -> NeighJson {
        NeighJson {
            index: n.index,
            family: n.family,
            state: n.state,
            kind: n.kind,
            flags: n.flags,
            ip: text(&n.ip),
            mac: n.mac.as_deref().map(rtnl::mac_text).unwrap_or_default(),
            ll_ip: opt_text(&n.ll_ip),
            flags_ext: n.flags_ext,
            vlan: n.vlan,
            vni: n.vni,
            master: n.master,
        }
    }

    fn neigh(&self) -> Neigh {
        Neigh {
            index: self.index,
            family: self.family,
            state: self.state,
            kind: self.kind,
            flags: self.flags,
            ip: ip(&self.ip),
            mac: (!self.mac.is_empty()).then(|| rtnl::parse_mac(&self.mac)),
            ll_ip: opt_ip(&self.ll_ip),
            flags_ext: self.flags_ext,
            vlan: self.vlan,
            vni: self.vni,
            master: self.master,
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct PeerJson {
    public_key: String,
    remove: bool,
    #[serde(rename = "ReplaceAllowedIPs")]
    replace_allowed_ips: bool,
    endpoint: String,
    keepalive: Option<u16>,
    #[serde(rename = "AllowedIPs")]
    allowed_ips: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct WgConfigJson {
    private_key: String,
    listen_port: Option<u16>,
    peers: Vec<PeerJson>,
}

impl WgConfigJson {
    fn set(&self) -> DeviceSet {
        let key = |s: &str| Key::parse(s).unwrap_or_default().0;
        DeviceSet {
            private_key: (!self.private_key.is_empty()).then(|| key(&self.private_key)),
            listen_port: self.listen_port,
            peers: self
                .peers
                .iter()
                .map(|p| PeerSet {
                    public_key: key(&p.public_key),
                    remove: p.remove,
                    replace_allowed_ips: p.replace_allowed_ips,
                    endpoint: p.endpoint.rsplit_once(':').and_then(|(h, port)| {
                        let h = h.trim_start_matches('[').trim_end_matches(']');
                        Some((Addr::parse(h)?, port.parse().ok()?))
                    }),
                    keepalive: p.keepalive,
                    allowed_ips: p
                        .allowed_ips
                        .iter()
                        .filter_map(|n| {
                            let (a, b) = n.rsplit_once('/')?;
                            Some((Addr::parse(a)?, b.parse().ok()?))
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "Op", rename_all_fields = "PascalCase")]
enum Call {
    LinkByName {
        name: String,
    },
    LinkByIndex {
        index: i32,
    },
    LinkList,
    AddVxlan {
        name: String,
        #[serde(rename = "MTU")]
        mtu: u32,
        #[serde(rename = "MAC", default)]
        mac: String,
        #[serde(rename = "VNI")]
        vni: u32,
        #[serde(default)]
        link: u32,
        #[serde(default)]
        local: String,
        port: u16,
        #[serde(default)]
        learning: bool,
    },
    AddWireguard {
        name: String,
        #[serde(rename = "MTU")]
        mtu: u32,
    },
    LinkDel {
        index: i32,
    },
    SetMTU {
        index: i32,
        #[serde(rename = "MTU")]
        mtu: u32,
    },
    SetUp {
        index: i32,
    },
    SetDown {
        index: i32,
    },
    SetName {
        index: i32,
        name: String,
    },
    SetMAC {
        index: i32,
        #[serde(rename = "MAC")]
        mac: String,
    },
    AddrList {
        family: u8,
    },
    AddrReplace {
        index: i32,
        addr: AddrJson,
    },
    AddrDel {
        index: i32,
        addr: AddrJson,
    },
    RouteReplace {
        route: RouteJson,
    },
    RouteDel {
        route: RouteJson,
    },
    RouteList {
        family: u8,
        index: i32,
    },
    RouteGet {
        dst: String,
    },
    NeighSet {
        neigh: NeighJson,
    },
    NeighDel {
        neigh: NeighJson,
    },
    NeighList {
        family: u8,
        index: i32,
    },
    WgFamily,
    WgGet {
        family: u16,
        name: String,
    },
    WgSet {
        family: u16,
        name: String,
        config: WgConfigJson,
    },
}

fn encode(c: &Call) -> Vec<Msg> {
    match c {
        Call::LinkByName { name } => vec![rtnl::get_link_by_name(name)],
        Call::LinkByIndex { index } => vec![rtnl::get_link_by_index(*index)],
        Call::LinkList => vec![rtnl::list_links()],
        Call::AddVxlan {
            name,
            mtu,
            mac,
            vni,
            link,
            local,
            port,
            learning,
        } => vec![rtnl::add_vxlan(
            name,
            *mtu,
            &rtnl::parse_mac(mac),
            &rtnl::Vxlan {
                id: *vni,
                link: *link,
                local: ip(local),
                port: *port,
                learning: *learning,
            },
        )],
        Call::AddWireguard { name, mtu } => vec![rtnl::add_wireguard(name, *mtu)],
        Call::LinkDel { index } => vec![rtnl::del_link(*index)],
        Call::SetMTU { index, mtu } => vec![rtnl::set_mtu(*index, *mtu)],
        Call::SetUp { index } => vec![rtnl::set_up(*index)],
        Call::SetDown { index } => vec![rtnl::set_down(*index)],
        Call::SetName { index, name } => vec![rtnl::set_name(*index, name)],
        Call::SetMAC { index, mac } => vec![rtnl::set_mac(*index, &rtnl::parse_mac(mac))],
        Call::AddrList { family } => vec![rtnl::list_addrs(*family)],
        Call::AddrReplace { index, addr } => vec![rtnl::addr(true, *index, &addr.addr())],
        Call::AddrDel { index, addr } => vec![rtnl::addr(false, *index, &addr.addr())],
        Call::RouteReplace { route } => vec![rtnl::replace_route(&route.route())],
        Call::RouteDel { route } => vec![rtnl::del_route(&route.route())],
        Call::RouteList { family, index } => vec![rtnl::list_routes(*family, *index)],
        Call::RouteGet { dst } => vec![rtnl::get_route(&ip(dst))],
        Call::NeighSet { neigh } => vec![rtnl::neigh(true, &neigh.neigh())],
        Call::NeighDel { neigh } => vec![rtnl::neigh(false, &neigh.neigh())],
        Call::NeighList { family, index } => vec![rtnl::list_neighs(*family, *index)],
        Call::WgFamily => vec![wgnl::get_family()],
        Call::WgGet { family, name } => vec![wgnl::get_device(*family, name)],
        Call::WgSet {
            family,
            name,
            config,
        } => wgnl::batches(&config.set())
            .iter()
            .map(|b| wgnl::set_device(*family, name, b))
            .collect(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct LinkJson {
    index: i32,
    name: String,
    #[serde(rename = "MTU")]
    mtu: u32,
    #[serde(rename = "MAC")]
    mac: String,
    kind: String,
    oper: u8,
    vxlan: Option<VxlanJson>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct VxlanJson {
    #[serde(rename = "ID")]
    id: u32,
    link: u32,
    local: String,
    port: u16,
    learning: bool,
}

impl LinkJson {
    fn of(l: &Link) -> LinkJson {
        LinkJson {
            index: l.index,
            name: l.name.clone(),
            mtu: l.mtu,
            mac: rtnl::mac_text(&l.mac),
            kind: l.kind.clone(),
            oper: l.oper,
            vxlan: l.vxlan.as_ref().map(|v| VxlanJson {
                id: v.id,
                link: v.link,
                local: text(&v.local),
                port: v.port,
                learning: v.learning,
            }),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Shown {
    links: Vec<LinkJson>,
    addrs: Vec<AddrJson>,
    routes: Vec<RouteJson>,
    neighs: Vec<NeighJson>,
}

fn show() -> Result<Shown, String> {
    let mut h = rtnl::Handle::open().map_err(|e| e.to_string())?;
    let e = |e: super::netlink::Errno| e.to_string();
    let mut neighs = h.neighs(0, rtnl::AF_INET).map_err(e)?;
    neighs.extend(h.neighs(0, rtnl::AF_BRIDGE).map_err(e)?);
    Ok(Shown {
        links: h.links().map_err(e)?.iter().map(LinkJson::of).collect(),
        addrs: h
            .addrs(0, rtnl::AF_INET)
            .map_err(e)?
            .iter()
            .map(AddrJson::of)
            .collect(),
        routes: h
            .routes(0, rtnl::AF_INET)
            .map_err(e)?
            .iter()
            .map(RouteJson::of)
            .collect(),
        neighs: neighs.iter().map(NeighJson::of).collect(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct DeviceJson {
    private_key: String,
    listen_port: i64,
    peers: Vec<DevicePeerJson>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct DevicePeerJson {
    public_key: String,
    endpoint: String,
    #[serde(rename = "AllowedIPs")]
    allowed_ips: Vec<String>,
    keepalive: i64,
    last_handshake: i64,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .filter_map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// armada-node net netlink OP.
pub fn command(op: &str) -> Result<(), String> {
    let out = match op {
        "encode" => {
            let calls: Vec<Call> =
                serde_json::from_slice(&read_stdin()?).map_err(|e| e.to_string())?;
            let hex: Vec<Vec<String>> = calls
                .iter()
                .map(|c| encode(c).iter().map(Msg::hex).collect())
                .collect();
            serde_json::to_vec(&hex)
        }
        "show" => serde_json::to_vec(&show()?),
        "wg-parse" => {
            let msgs: Vec<String> =
                serde_json::from_slice(&read_stdin()?).map_err(|e| e.to_string())?;
            let bodies: Vec<Vec<u8>> = msgs.iter().map(|m| unhex(m)).collect();
            let d = wgnl::parse_device(&bodies);
            let key = |k: &Key| {
                if k.is_zero() {
                    String::new()
                } else {
                    k.to_string()
                }
            };
            serde_json::to_vec(&DeviceJson {
                private_key: key(&d.private_key),
                listen_port: d.listen_port,
                peers: d
                    .peers
                    .iter()
                    .map(|p| DevicePeerJson {
                        public_key: key(&p.public_key),
                        endpoint: p.endpoint.clone().unwrap_or_default(),
                        allowed_ips: p.allowed_ips.clone(),
                        keepalive: p.keepalive,
                        last_handshake: p.last_handshake.unwrap_or(0),
                    })
                    .collect(),
            })
        }
        _ => {
            return Err(format!(
                "unknown netlink operation {op:?}; try: encode, show, wg-parse"
            ));
        }
    }
    .map_err(|e| e.to_string())?;
    write_stdout(&out)
}

//! Routing netlink (rtnetlink): the interfaces, addresses, routes,
//! neighbour entries, and forwarding entries the cluster network sets up,
//! read and changed (links looked up, added, and changed, addresses,
//! routes, and neighbour entries replaced, and the rest); tests compare
//! the messages with recorded bytes.
//!
//! Every message builder is a pure function; `Handle` sends them.

use super::netlink::{
    Attrs, Errno, Msg, NETLINK_ROUTE, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL,
    NLM_F_REPLACE, NLM_F_REQUEST, Socket, attrs, cstring, ne_u16, ne_u32,
};

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_SETLINK: u16 = 19;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_DELNEIGH: u16 = 29;
pub const RTM_GETNEIGH: u16 = 30;

pub const AF_UNSPEC: u8 = 0;
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;
pub const AF_BRIDGE: u8 = 7;

const IFF_UP: u32 = 0x1;
const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_TXQLEN: u16 = 13;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_LINKINFO: u16 = 18;
const IFLA_EXT_MASK: u16 = 29;
const IFLA_ALT_IFNAME: u16 = 53;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const RTEXT_FILTER_VF: u32 = 1;

const IFLA_VXLAN_ID: u16 = 1;
const IFLA_VXLAN_LINK: u16 = 3;
const IFLA_VXLAN_LOCAL: u16 = 4;
const IFLA_VXLAN_TTL: u16 = 5;
const IFLA_VXLAN_TOS: u16 = 6;
const IFLA_VXLAN_LEARNING: u16 = 7;
const IFLA_VXLAN_PROXY: u16 = 11;
const IFLA_VXLAN_RSC: u16 = 12;
const IFLA_VXLAN_L2MISS: u16 = 13;
const IFLA_VXLAN_L3MISS: u16 = 14;
const IFLA_VXLAN_PORT: u16 = 15;
const IFLA_VXLAN_UDP_ZERO_CSUM6_TX: u16 = 19;
const IFLA_VXLAN_UDP_ZERO_CSUM6_RX: u16 = 20;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_BROADCAST: u16 = 4;
const IFA_CACHEINFO: u16 = 6;
const IFA_FLAGS: u16 = 8;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_TABLE: u16 = 15;
pub const RT_TABLE_MAIN: u32 = 254;
const RTPROT_BOOT: u8 = 3;
pub const RTPROT_KERNEL: u8 = 2;
const RTN_UNICAST: u8 = 1;
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_LINK: u8 = 253;
pub const RTNH_F_ONLINK: u32 = 4;
const RTM_F_CLONED: u32 = 0x200;
const RTM_F_LOOKUP_TABLE: u32 = 0x1000;

const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const NDA_VLAN: u16 = 5;
const NDA_VNI: u16 = 7;
const NDA_MASTER: u16 = 9;
const NDA_FLAGS_EXT: u16 = 15;
pub const NUD_PERMANENT: u16 = 0x80;
pub const NTF_SELF: u8 = 0x2;

/// An interface as LinkDeserialize reads it, keeping what the cluster
/// network looks at.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Link {
    pub index: i32,
    pub name: String,
    pub mtu: u32,
    pub mac: Vec<u8>,
    /// IFLA_INFO_KIND: "vxlan", "wireguard", ... ("" for none).
    pub kind: String,
    pub flags: u32,
    pub oper: u8,
    pub vxlan: Option<Vxlan>,
}

/// A VXLAN interface's settings (netlink.Vxlan).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Vxlan {
    pub id: u32,
    /// The interface it sends by (VtepDevIndex).
    pub link: u32,
    /// Its source address (SrcAddr), as the kernel sends it.
    pub local: Vec<u8>,
    pub port: u16,
    pub learning: bool,
}

/// An address as parseAddr reads it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IfAddr {
    pub index: i32,
    pub family: u8,
    /// The address (IPNet.IP) and the prefix length its mask has.
    pub ip: Vec<u8>,
    pub prefixlen: u8,
    /// The peer of a point-to-point address.
    pub peer: Option<Vec<u8>>,
    pub broadcast: Option<Vec<u8>>,
    pub label: String,
    pub flags: u32,
    pub scope: u8,
    pub valid: u32,
    pub preferred: u32,
}

/// A route as deserializeRoute reads it, keeping what deleting it sends.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Route {
    pub family: u8,
    /// The destination and its length; a route with none has the family's
    /// zero address.
    pub dst: Option<(Vec<u8>, u8)>,
    pub src: Option<Vec<u8>>,
    pub gw: Option<Vec<u8>>,
    pub oif: i32,
    pub priority: u32,
    pub table: u32,
    pub protocol: u8,
    pub scope: u8,
    pub kind: u8,
    pub flags: u32,
    pub tos: u8,
}

/// A neighbour or forwarding entry as NeighDeserialize reads it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Neigh {
    pub index: i32,
    pub family: u8,
    pub state: u16,
    pub kind: u8,
    pub flags: u8,
    pub ip: Vec<u8>,
    pub mac: Option<Vec<u8>>,
    /// A 4-byte link-layer address (LLIPAddr).
    pub ll_ip: Option<Vec<u8>>,
    pub flags_ext: u32,
    pub vlan: u16,
    pub vni: u32,
    pub master: u32,
}

fn ifinfomsg(index: i32, flags: u32, change: u32) -> Vec<u8> {
    let mut b = vec![AF_UNSPEC, 0, 0, 0];
    b.extend(index.to_ne_bytes());
    b.extend(flags.to_ne_bytes());
    b.extend(change.to_ne_bytes());
    b
}

fn msg(ty: u16, flags: u16, head: Vec<u8>, a: Attrs) -> Msg {
    let mut body = head;
    body.extend(a.b);
    Msg {
        ty,
        flags: NLM_F_REQUEST | flags,
        body,
    }
}

/// LinkByName's lookup.
pub fn get_link_by_name(name: &str) -> Msg {
    let mut a = Attrs::new();
    a.u32(IFLA_EXT_MASK, RTEXT_FILTER_VF);
    if name.len() > 15 {
        a.cstr(IFLA_ALT_IFNAME, name);
    } else {
        a.cstr(IFLA_IFNAME, name);
    }
    msg(RTM_GETLINK, NLM_F_ACK, ifinfomsg(0, 0, 0), a)
}

/// LinkByIndex's lookup.
pub fn get_link_by_index(index: i32) -> Msg {
    let mut a = Attrs::new();
    a.u32(IFLA_EXT_MASK, RTEXT_FILTER_VF);
    msg(RTM_GETLINK, NLM_F_ACK, ifinfomsg(index, 0, 0), a)
}

/// LinkList's dump.
pub fn list_links() -> Msg {
    let mut a = Attrs::new();
    a.u32(IFLA_EXT_MASK, RTEXT_FILTER_VF);
    msg(RTM_GETLINK, NLM_F_DUMP, ifinfomsg(0, 0, 0), a)
}

/// The message adding a link of the agent's: name, MTU, a queue length
/// of 0, the hardware address when given, and the
/// kind with its data.
fn add_link(name: &str, mtu: u32, mac: &[u8], kind: &str, data: Option<Attrs>) -> Msg {
    let mut a = Attrs::new();
    a.cstr(IFLA_IFNAME, name);
    if mtu > 0 {
        a.u32(IFLA_MTU, mtu);
    }
    a.u32(IFLA_TXQLEN, 0);
    if !mac.is_empty() {
        a.put(IFLA_ADDRESS, mac);
    }
    // IFLA_LINKINFO without the nested flag.
    a.nested(IFLA_LINKINFO, |l| {
        l.put(IFLA_INFO_KIND, kind.as_bytes());
        if let Some(d) = data {
            l.nested(IFLA_INFO_DATA, |x| x.b.extend(d.b));
        }
    });
    msg(
        RTM_NEWLINK,
        NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
        ifinfomsg(0, 0, 0),
        a,
    )
}

/// LinkAdd(&netlink.Vxlan{...}) as vxlanDevice asks for it.
pub fn add_vxlan(name: &str, mtu: u32, mac: &[u8], v: &Vxlan) -> Msg {
    let mut d = Attrs::new();
    d.u32(IFLA_VXLAN_ID, v.id);
    if v.link != 0 {
        d.u32(IFLA_VXLAN_LINK, v.link);
    }
    if !v.local.is_empty() {
        d.put(IFLA_VXLAN_LOCAL, &v.local);
    }
    d.u8(IFLA_VXLAN_TTL, 0)
        .u8(IFLA_VXLAN_TOS, 0)
        .u8(IFLA_VXLAN_LEARNING, u8::from(v.learning))
        .u8(IFLA_VXLAN_PROXY, 0)
        .u8(IFLA_VXLAN_RSC, 0)
        .u8(IFLA_VXLAN_L2MISS, 0)
        .u8(IFLA_VXLAN_L3MISS, 0)
        .u8(IFLA_VXLAN_UDP_ZERO_CSUM6_TX, 0)
        .u8(IFLA_VXLAN_UDP_ZERO_CSUM6_RX, 0);
    if v.port > 0 {
        d.put(IFLA_VXLAN_PORT, &v.port.to_be_bytes());
    }
    add_link(name, mtu, mac, "vxlan", Some(d))
}

/// The message adding the container bridge: its name alone.
// The agent's, through the library; the program makes no bridge.
#[allow(dead_code)]
pub fn add_bridge(name: &str) -> Msg {
    add_link(name, 0, &[], "bridge", None)
}

/// LinkAdd(&netlink.Wireguard{...}).
pub fn add_wireguard(name: &str, mtu: u32) -> Msg {
    add_link(name, mtu, &[], "wireguard", None)
}

pub fn del_link(index: i32) -> Msg {
    msg(RTM_DELLINK, NLM_F_ACK, ifinfomsg(index, 0, 0), Attrs::new())
}

pub fn set_mtu(index: i32, mtu: u32) -> Msg {
    let mut a = Attrs::new();
    a.u32(IFLA_MTU, mtu);
    msg(RTM_SETLINK, NLM_F_ACK, ifinfomsg(index, 0, 0), a)
}

pub fn set_up(index: i32) -> Msg {
    msg(
        RTM_NEWLINK,
        NLM_F_ACK,
        ifinfomsg(index, IFF_UP, IFF_UP),
        Attrs::new(),
    )
}

pub fn set_down(index: i32) -> Msg {
    msg(
        RTM_NEWLINK,
        NLM_F_ACK,
        ifinfomsg(index, 0, IFF_UP),
        Attrs::new(),
    )
}

/// Renames a link: the name without its NUL.
pub fn set_name(index: i32, name: &str) -> Msg {
    let mut a = Attrs::new();
    a.put(IFLA_IFNAME, name.as_bytes());
    msg(RTM_SETLINK, NLM_F_ACK, ifinfomsg(index, 0, 0), a)
}

pub fn set_mac(index: i32, mac: &[u8]) -> Msg {
    let mut a = Attrs::new();
    a.put(IFLA_ADDRESS, mac);
    msg(RTM_SETLINK, NLM_F_ACK, ifinfomsg(index, 0, 0), a)
}

fn ifaddrmsg(family: u8, prefixlen: u8, flags: u8, scope: u8, index: i32) -> Vec<u8> {
    let mut b = vec![family, prefixlen, flags, scope];
    b.extend(index.to_ne_bytes());
    b
}

/// AddrList's dump.
pub fn list_addrs(family: u8) -> Msg {
    msg(
        RTM_GETADDR,
        NLM_F_DUMP,
        ifaddrmsg(family, 0, 0, 0, 0),
        Attrs::new(),
    )
}

fn family_of(ip: &[u8]) -> u8 {
    if ip.len() == 4 { AF_INET } else { AF_INET6 }
}

/// The message of AddrReplace (replace) or AddrDel for a on
/// interface index.
pub fn addr(replace: bool, index: i32, a: &IfAddr) -> Msg {
    let family = family_of(&a.ip);
    let mut flags = 0u8;
    let mut at = Attrs::new();
    at.put(IFA_LOCAL, &a.ip);
    at.put(IFA_ADDRESS, a.peer.as_deref().unwrap_or(&a.ip));
    if a.flags != 0 {
        if a.flags <= 0xff {
            flags = a.flags as u8;
        } else {
            at.u32(IFA_FLAGS, a.flags);
        }
    }
    if family == AF_INET {
        let mut broadcast = a.broadcast.clone();
        if broadcast.is_none() && a.prefixlen < 31 {
            let host = u32::MAX.checked_shr(u32::from(a.prefixlen)).unwrap_or(0);
            let mut b = [0u8; 4];
            for (i, byte) in b.iter_mut().enumerate() {
                *byte = a.ip.get(i).copied().unwrap_or(0) | host.to_be_bytes()[i];
            }
            broadcast = Some(b.to_vec());
        }
        if broadcast.as_deref() == Some(&[0, 0, 0, 0]) {
            broadcast = None;
        }
        if let Some(b) = broadcast {
            at.put(IFA_BROADCAST, &b);
        }
        if !a.label.is_empty() {
            at.cstr(IFA_LABEL, &a.label);
        }
    }
    if a.valid > 0 || a.preferred > 0 {
        let mut ci = Vec::new();
        ci.extend(a.preferred.to_ne_bytes());
        ci.extend(a.valid.to_ne_bytes());
        ci.extend([0u8; 8]);
        at.put(IFA_CACHEINFO, &ci);
    }
    let (ty, f) = if replace {
        (RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK)
    } else {
        (RTM_DELADDR, NLM_F_ACK)
    };
    msg(
        ty,
        f,
        ifaddrmsg(family, a.prefixlen, flags, a.scope, index),
        at,
    )
}

#[allow(clippy::too_many_arguments)]
fn rtmsg(
    family: u8,
    dst_len: u8,
    tos: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    kind: u8,
    flags: u32,
) -> Vec<u8> {
    let mut b = vec![family, dst_len, 0, tos, table, protocol, scope, kind];
    b.extend(flags.to_ne_bytes());
    b
}

/// prepareRouteReq for a route of the agent's (or one read back): the
/// destination, preferred source, gateway, table, priority, and output
/// interface. Metrics, multipath, and encapsulation are not written: the
/// agent's routes have none, and deleting a route does not need them.
fn route_msg(ty: u16, flags: u16, r: &Route, new: bool) -> Msg {
    // NewRtMsg or NewRtDelMsg, then what the route sets.
    let (mut table, mut protocol, mut kind) = if new {
        (RT_TABLE_MAIN as u8, RTPROT_BOOT, RTN_UNICAST)
    } else {
        (RT_TABLE_MAIN as u8, 0, 0)
    };
    let mut family = AF_INET;
    let mut dst_len = 0;
    let mut a = Attrs::new();
    if let Some((ip, len)) = &r.dst {
        dst_len = *len;
        family = family_of(ip);
        a.put(RTA_DST, ip);
    }
    if let Some(src) = &r.src {
        family = family_of(src);
        a.put(RTA_PREFSRC, src);
    }
    if let Some(gw) = &r.gw {
        family = family_of(gw);
        a.put(RTA_GATEWAY, gw);
    }
    if r.table > 0 {
        if r.table >= 256 {
            table = 0;
            a.u32(RTA_TABLE, r.table);
        } else {
            table = r.table as u8;
        }
    }
    if r.priority > 0 {
        a.u32(RTA_PRIORITY, r.priority);
    }
    if r.protocol > 0 {
        protocol = r.protocol;
    }
    if r.kind > 0 {
        kind = r.kind;
    }
    a.u32(RTA_OIF, r.oif as u32);
    msg(
        ty,
        flags,
        rtmsg(
            family, dst_len, r.tos, table, protocol, r.scope, kind, r.flags,
        ),
        a,
    )
}

/// RouteReplace.
pub fn replace_route(r: &Route) -> Msg {
    route_msg(
        RTM_NEWROUTE,
        NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK,
        r,
        true,
    )
}

/// RouteDel of a route read back.
pub fn del_route(r: &Route) -> Msg {
    route_msg(RTM_DELROUTE, NLM_F_ACK, r, false)
}

/// RouteList(link, family)'s dump: the output interface as a filter.
pub fn list_routes(family: u8, oif: i32) -> Msg {
    let mut a = Attrs::new();
    if oif > 0 {
        a.u32(RTA_OIF, oif as u32);
    }
    msg(
        RTM_GETROUTE,
        NLM_F_DUMP,
        rtmsg(family, 0, 0, 0, 0, 0, 0, 0),
        a,
    )
}

/// RouteGet(dst).
pub fn get_route(dst: &[u8]) -> Msg {
    let (family, bits) = if dst.len() == 4 {
        (AF_INET, 32)
    } else {
        (AF_INET6, 128)
    };
    let mut a = Attrs::new();
    a.put(RTA_DST, dst);
    msg(
        RTM_GETROUTE,
        NLM_F_REQUEST,
        rtmsg(family, bits, 0, 0, 0, 0, 0, RTM_F_LOOKUP_TABLE),
        a,
    )
}

fn ndmsg(family: u8, index: i32, state: u16, flags: u8, kind: u8) -> Vec<u8> {
    let mut b = vec![family, 0, 0, 0];
    b.extend(index.to_ne_bytes());
    b.extend(state.to_ne_bytes());
    b.push(flags);
    b.push(kind);
    b
}

/// NeighSet (set) or NeighDel of n.
pub fn neigh(set: bool, n: &Neigh) -> Msg {
    let mut a = Attrs::new();
    a.put(NDA_DST, &n.ip);
    if let Some(ll) = &n.ll_ip {
        a.put(NDA_LLADDR, ll);
    } else if let Some(mac) = &n.mac {
        a.put(NDA_LLADDR, mac);
    }
    if n.flags_ext != 0 {
        a.u32(NDA_FLAGS_EXT, n.flags_ext);
    }
    if n.vlan != 0 {
        a.u16(NDA_VLAN, n.vlan);
    }
    if n.vni != 0 {
        a.u32(NDA_VNI, n.vni);
    }
    if n.master != 0 {
        a.u32(NDA_MASTER, n.master);
    }
    let (ty, flags) = if set {
        (RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK)
    } else {
        (RTM_DELNEIGH, NLM_F_ACK)
    };
    let family = if n.family > 0 {
        n.family
    } else {
        family_of(&n.ip)
    };
    msg(
        ty,
        flags,
        ndmsg(family, n.index, n.state, n.flags, n.kind),
        a,
    )
}

/// NeighList(index, family)'s dump.
pub fn list_neighs(family: u8, index: i32) -> Msg {
    msg(
        RTM_GETNEIGH,
        NLM_F_DUMP,
        ndmsg(family, index, 0, 0, 0),
        Attrs::new(),
    )
}

fn i32_at(b: &[u8], at: usize) -> i32 {
    ne_u32(b.get(at..).unwrap_or_default()) as i32
}

/// LinkDeserialize, for what the agent reads.
pub fn parse_link(b: &[u8]) -> Option<Link> {
    if b.len() < 16 {
        return None;
    }
    let mut l = Link {
        index: i32_at(b, 4),
        flags: ne_u32(&b[8..]),
        ..Link::default()
    };
    for (ty, v) in attrs(&b[16..]) {
        match ty {
            IFLA_IFNAME => l.name = cstring(v),
            IFLA_MTU => l.mtu = ne_u32(v),
            // An all-zero address is none.
            IFLA_ADDRESS if v.iter().any(|c| *c != 0) => l.mac = v.to_vec(),
            IFLA_OPERSTATE => l.oper = v.first().copied().unwrap_or(0),
            IFLA_LINKINFO => {
                let info = attrs(v);
                for (t, d) in &info {
                    if *t == IFLA_INFO_KIND && !d.is_empty() {
                        // The last byte is the kernel's NUL.
                        l.kind = String::from_utf8_lossy(&d[..d.len() - 1]).into_owned();
                    }
                }
                if l.kind == "vxlan" {
                    let mut x = Vxlan::default();
                    for (t, d) in &info {
                        if *t != IFLA_INFO_DATA {
                            continue;
                        }
                        for (k, val) in attrs(d) {
                            match k {
                                IFLA_VXLAN_ID => x.id = ne_u32(val),
                                IFLA_VXLAN_LINK => x.link = ne_u32(val),
                                IFLA_VXLAN_LOCAL => x.local = val.to_vec(),
                                IFLA_VXLAN_PORT => {
                                    x.port = val
                                        .get(..2)
                                        .map(|p| u16::from_be_bytes([p[0], p[1]]))
                                        .unwrap_or(0);
                                }
                                IFLA_VXLAN_LEARNING => {
                                    x.learning = val.first().is_some_and(|c| *c != 0);
                                }
                                _ => {}
                            }
                        }
                    }
                    l.vxlan = Some(x);
                }
            }
            _ => {}
        }
    }
    Some(l)
}

/// parseAddr.
pub fn parse_addr(b: &[u8]) -> Option<IfAddr> {
    if b.len() < 8 {
        return None;
    }
    let mut a = IfAddr {
        family: b[0],
        scope: b[3],
        index: i32_at(b, 4),
        ..IfAddr::default()
    };
    let prefixlen = b[1];
    let (mut local, mut dst) = (None, None);
    for (ty, v) in attrs(&b[8..]) {
        match ty {
            IFA_ADDRESS => dst = Some(v.to_vec()),
            IFA_LOCAL => local = Some(v.to_vec()),
            IFA_BROADCAST => a.broadcast = Some(v.to_vec()),
            IFA_LABEL if !v.is_empty() => {
                a.label = String::from_utf8_lossy(&v[..v.len() - 1]).into_owned();
            }
            IFA_FLAGS => a.flags = ne_u32(v),
            IFA_CACHEINFO => {
                a.preferred = ne_u32(v);
                a.valid = ne_u32(v.get(4..).unwrap_or_default());
            }
            _ => {}
        }
    }
    match (local, dst) {
        (Some(l), Some(d)) if a.family == AF_INET && l == d => {
            a.ip = d;
            a.prefixlen = prefixlen;
        }
        (Some(l), d) => {
            a.prefixlen = (8 * l.len()) as u8;
            a.ip = l;
            if let Some(d) = d {
                a.peer = Some(d);
                a.prefixlen = prefixlen;
            }
        }
        (None, Some(d)) => {
            a.ip = d;
            a.prefixlen = prefixlen;
        }
        (None, None) => {}
    }
    Some(a)
}

/// deserializeRoute, for what the agent reads and deletes.
pub fn parse_route(b: &[u8]) -> Option<Route> {
    if b.len() < 12 {
        return None;
    }
    let mut r = Route {
        family: b[0],
        tos: b[3],
        table: u32::from(b[4]),
        protocol: b[5],
        scope: b[6],
        kind: b[7],
        flags: ne_u32(&b[8..]),
        ..Route::default()
    };
    let dst_len = b[1];
    for (ty, v) in attrs(&b[12..]) {
        match ty {
            RTA_DST => r.dst = Some((v.to_vec(), dst_len)),
            RTA_PREFSRC => r.src = Some(v.to_vec()),
            RTA_GATEWAY => r.gw = Some(v.to_vec()),
            RTA_OIF => r.oif = ne_u32(v) as i32,
            RTA_PRIORITY => r.priority = ne_u32(v),
            RTA_TABLE => r.table = ne_u32(v),
            _ => {}
        }
    }
    if r.dst.is_none() {
        match r.family {
            AF_INET => r.dst = Some((vec![0; 4], dst_len)),
            AF_INET6 => r.dst = Some((vec![0; 16], dst_len)),
            _ => {}
        }
    }
    Some(r)
}

/// NeighDeserialize.
pub fn parse_neigh(b: &[u8]) -> Option<Neigh> {
    if b.len() < 12 {
        return None;
    }
    let mut n = Neigh {
        family: b[0],
        index: i32_at(b, 4),
        state: ne_u16(&b[8..]),
        flags: b[10],
        kind: b[11],
        ..Neigh::default()
    };
    for (ty, v) in attrs(&b[12..]) {
        match ty {
            NDA_DST => n.ip = v.to_vec(),
            NDA_LLADDR if v.len() == 4 => n.ll_ip = Some(v.to_vec()),
            NDA_LLADDR => n.mac = Some(v.to_vec()),
            NDA_FLAGS_EXT => n.flags_ext = ne_u32(v),
            NDA_VLAN => n.vlan = ne_u16(v),
            NDA_VNI => n.vni = ne_u32(v),
            NDA_MASTER => n.master = ne_u32(v),
            _ => {}
        }
    }
    Some(n)
}

/// A routing netlink socket and the calls the agent makes on it.
pub struct Handle {
    sock: Socket,
}

impl Handle {
    pub fn open() -> Result<Handle, Errno> {
        Ok(Handle {
            sock: Socket::open(NETLINK_ROUTE)?,
        })
    }

    /// Sends m, answering only success or failure.
    pub fn exec(&mut self, m: &Msg) -> Result<(), Errno> {
        self.sock.request(m).map(|_| ())
    }

    fn answers(&mut self, m: &Msg, ty: u16) -> Result<Vec<Vec<u8>>, Errno> {
        Ok(self
            .sock
            .request(m)?
            .into_iter()
            .filter(|(t, _)| *t == ty)
            .map(|(_, d)| d)
            .collect())
    }

    /// The interface, None when there is none.
    pub fn link_named(&mut self, name: &str) -> Result<Option<Link>, Errno> {
        match self.sock.request(&get_link_by_name(name)) {
            Err(Errno(libc::ENODEV)) => Ok(None),
            Err(e) => Err(e),
            Ok(msgs) => match msgs.as_slice() {
                [] => Ok(None),
                [(_, b)] => Ok(parse_link(b)),
                _ => Err(Errno(libc::EINVAL)),
            },
        }
    }

    pub fn link_by_index(&mut self, index: i32) -> Result<Link, Errno> {
        let msgs = self.sock.request(&get_link_by_index(index))?;
        match msgs.as_slice() {
            [(_, b)] => parse_link(b).ok_or(Errno(libc::EINVAL)),
            _ => Err(Errno(libc::ENODEV)),
        }
    }

    pub fn links(&mut self) -> Result<Vec<Link>, Errno> {
        Ok(self
            .answers(&list_links(), RTM_NEWLINK)?
            .iter()
            .filter_map(|b| parse_link(b))
            .collect())
    }

    /// AddrList(link, family): every interface's when index is 0.
    pub fn addrs(&mut self, index: i32, family: u8) -> Result<Vec<IfAddr>, Errno> {
        Ok(self
            .answers(&list_addrs(family), RTM_NEWADDR)?
            .iter()
            .filter_map(|b| parse_addr(b))
            .filter(|a| (index == 0 || a.index == index) && a.family == family)
            .collect())
    }

    /// RouteList(link, family): the main table's routes, without cloned
    /// ones, through interface oif.
    pub fn routes(&mut self, oif: i32, family: u8) -> Result<Vec<Route>, Errno> {
        let mut out = Vec::new();
        for b in self.answers(&list_routes(family, oif), RTM_NEWROUTE)? {
            if b.len() < 12 || b[0] != family {
                continue;
            }
            if ne_u32(&b[8..]) & RTM_F_CLONED != 0 || u32::from(b[4]) != RT_TABLE_MAIN {
                continue;
            }
            if let Some(r) = parse_route(&b)
                && (oif == 0 || r.oif == oif)
            {
                out.push(r);
            }
        }
        Ok(out)
    }

    /// RouteGet(dst).
    pub fn route_get(&mut self, dst: &[u8]) -> Result<Vec<Route>, Errno> {
        Ok(self
            .answers(&get_route(dst), RTM_NEWROUTE)?
            .iter()
            .filter_map(|b| parse_route(b))
            .collect())
    }

    /// NeighList(index, family).
    pub fn neighs(&mut self, index: i32, family: u8) -> Result<Vec<Neigh>, Errno> {
        Ok(self
            .answers(&list_neighs(family, index), RTM_NEWNEIGH)?
            .iter()
            .filter_map(|b| parse_neigh(b))
            .filter(|n| (index == 0 || n.index == index) && (family == 0 || n.family == family))
            .collect())
    }
}

/// An IPv4 address as bytes.
pub fn v4(a: &super::addr::Addr) -> Vec<u8> {
    match a {
        super::addr::Addr::V4(b) => b.to_vec(),
        super::addr::Addr::V6(b, _) => b.to_vec(),
    }
}

/// The address in b (4 or 16 bytes), unmapped as netip.AddrFromSlice and
/// Unmap make it.
pub fn addr_of(b: &[u8]) -> Option<super::addr::Addr> {
    use super::addr::Addr;
    match b.len() {
        4 => Some(Addr::V4([b[0], b[1], b[2], b[3]])),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            Some(Addr::V6(a, String::new()).unmap())
        }
        _ => None,
    }
}

/// A MAC address as net.HardwareAddr.String prints it.
pub fn mac_text(b: &[u8]) -> String {
    b.iter()
        .map(|c| format!("{c:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Parses "02:42:0a:78:00:00".
pub fn parse_mac(s: &str) -> Vec<u8> {
    s.split(':')
        .filter_map(|p| u8::from_str_radix(p, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vxlan_creation_as_recorded() {
        // The recorded message adding a VXLAN link: name armada-net, MTU
        // 1450, VNI 7027, port 4789.
        let want = "ac000000100005060000000000000000000000000000000000000000000000000f00030061726d6164612d6e6574000008000400aa05000008000d00000000006c0012000900010076786c616e0000005c00020008000100731b000005000500000000000500060000000000050007000000000005000b000000000005000c000000000005000d000000000005000e00000000000500130000000000050014000000000006000f0012b50000";
        let m = add_vxlan(
            "armada-net",
            1450,
            &[],
            &Vxlan {
                id: 7027,
                port: 4789,
                ..Vxlan::default()
            },
        );
        assert_eq!(m.hex(), want);
    }

    #[test]
    fn links_read_back() {
        let m = add_vxlan(
            "armada-net",
            1450,
            &[2, 0x42, 10, 120, 1, 0],
            &Vxlan {
                id: 7027,
                link: 2,
                local: vec![10, 0, 0, 1],
                port: 4789,
                learning: false,
            },
        );
        let l = parse_link(&m.body).unwrap();
        assert_eq!(l.name, "armada-net");
        assert_eq!(l.mtu, 1450);
        assert_eq!(mac_text(&l.mac), "02:42:0a:78:01:00");
    }

    #[test]
    fn default_routes_have_a_zero_destination() {
        let b = rtmsg(AF_INET, 0, 0, 254, 3, 0, 1, 0);
        let r = parse_route(&b).unwrap();
        assert_eq!(r.dst, Some((vec![0, 0, 0, 0], 0)));
    }

    #[test]
    fn addresses_get_a_broadcast_below_31_bits() {
        let a = IfAddr {
            ip: vec![10, 0, 0, 1],
            prefixlen: 24,
            ..IfAddr::default()
        };
        let m = addr(true, 3, &a);
        let at = attrs(&m.body[8..]);
        assert_eq!(at[2], (IFA_BROADCAST, &[10u8, 0, 0, 255][..]));
        let host = addr(true, 3, &IfAddr { prefixlen: 32, ..a });
        assert_eq!(attrs(&host.body[8..]).len(), 2);
    }
}

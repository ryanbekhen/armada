//! Kernel WireGuard over generic netlink: the family looked up by name, a
//! device read with WG_CMD_GET_DEVICE (its peers merged across the dump's
//! messages), and changes sent with WG_CMD_SET_DEVICE, a large
//! configuration split into batches. Tests compare the messages and the
//! parsing with recorded ones.

use super::addr::Addr;
use super::key::Key;
use super::netlink::{
    Attrs, Errno, Msg, NETLINK_GENERIC, NLA_F_NESTED, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, Socket,
    attrs, ne_u16,
};
use super::wireguard::{self, Device, DevicePeer, udp_text};

const GENL_ID_CTRL: u16 = 16;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const WG_GENL_NAME: &str = "wireguard";
const WG_GENL_VERSION: u8 = 1;
const WG_CMD_GET_DEVICE: u8 = 0;
const WG_CMD_SET_DEVICE: u8 = 1;

const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
const WGDEVICE_A_PEERS: u16 = 8;
const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_FLAGS: u16 = 3;
const WGPEER_A_ENDPOINT: u16 = 4;
const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
const WGPEER_A_ALLOWEDIPS: u16 = 9;
const WGALLOWEDIP_A_FAMILY: u16 = 1;
const WGALLOWEDIP_A_IPADDR: u16 = 2;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;
const WGPEER_F_REMOVE_ME: u32 = 1;
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 2;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// The most allowed IPs and peers one batch carries.
const IP_BATCH: usize = 256;
const PEER_BATCH: usize = 32;

/// One peer's change as it goes to the kernel (wgtypes.PeerConfig).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerSet {
    pub public_key: [u8; 32],
    pub remove: bool,
    pub replace_allowed_ips: bool,
    pub endpoint: Option<(Addr, u16)>,
    pub keepalive: Option<u16>,
    pub allowed_ips: Vec<(Addr, u8)>,
}

/// A device's change as it goes to the kernel (wgtypes.Config).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceSet {
    pub private_key: Option<[u8; 32]>,
    pub listen_port: Option<u16>,
    pub peers: Vec<PeerSet>,
}

fn genl(family: u16, cmd: u8, flags: u16, a: Attrs) -> Msg {
    let mut body = vec![cmd, WG_GENL_VERSION, 0, 0];
    body.extend(a.b);
    Msg {
        ty: family,
        flags,
        body,
    }
}

/// GetFamily("wireguard").
pub fn get_family() -> Msg {
    let mut a = Attrs::new();
    a.cstr(CTRL_ATTR_FAMILY_NAME, WG_GENL_NAME);
    let mut body = vec![CTRL_CMD_GETFAMILY, 1, 0, 0];
    body.extend(a.b);
    Msg {
        ty: GENL_ID_CTRL,
        flags: NLM_F_REQUEST,
        body,
    }
}

/// Device(name)'s dump.
pub fn get_device(family: u16, name: &str) -> Msg {
    let mut a = Attrs::new();
    a.cstr(WGDEVICE_A_IFNAME, name);
    genl(family, WG_CMD_GET_DEVICE, NLM_F_REQUEST | NLM_F_DUMP, a)
}

fn sockaddr(a: &Addr, port: u16) -> Vec<u8> {
    let mut b = Vec::new();
    match a {
        Addr::V4(ip) => {
            b.extend(AF_INET.to_ne_bytes());
            b.extend(port.to_be_bytes());
            b.extend(ip);
            b.extend([0u8; 8]);
        }
        Addr::V6(ip, _) => {
            b.extend(AF_INET6.to_ne_bytes());
            b.extend(port.to_be_bytes());
            b.extend([0u8; 4]);
            b.extend(ip);
            b.extend([0u8; 4]);
        }
    }
    b
}

fn encode_peer(a: &mut Attrs, p: &PeerSet) {
    a.put(WGPEER_A_PUBLIC_KEY, &p.public_key);
    let mut flags = 0;
    if p.remove {
        flags |= WGPEER_F_REMOVE_ME;
    }
    if p.replace_allowed_ips {
        flags |= WGPEER_F_REPLACE_ALLOWEDIPS;
    }
    if flags != 0 {
        a.u32(WGPEER_A_FLAGS, flags);
    }
    if let Some((ip, port)) = &p.endpoint {
        a.put(WGPEER_A_ENDPOINT, &sockaddr(ip, *port));
    }
    if let Some(k) = p.keepalive {
        a.u16(WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, k);
    }
    if !p.allowed_ips.is_empty() {
        a.nested(NLA_F_NESTED | WGPEER_A_ALLOWEDIPS, |ips| {
            for (i, (ip, bits)) in p.allowed_ips.iter().enumerate() {
                ips.nested(NLA_F_NESTED | i as u16, |x| {
                    match ip {
                        Addr::V4(b) => x
                            .u16(WGALLOWEDIP_A_FAMILY, AF_INET)
                            .put(WGALLOWEDIP_A_IPADDR, b),
                        Addr::V6(b, _) => x
                            .u16(WGALLOWEDIP_A_FAMILY, AF_INET6)
                            .put(WGALLOWEDIP_A_IPADDR, b),
                    };
                    x.u8(WGALLOWEDIP_A_CIDR_MASK, *bits);
                });
            }
        });
    }
}

/// configAttrs as one WG_CMD_SET_DEVICE message.
pub fn set_device(family: u16, name: &str, cfg: &DeviceSet) -> Msg {
    let mut a = Attrs::new();
    a.cstr(WGDEVICE_A_IFNAME, name);
    if let Some(k) = &cfg.private_key {
        a.put(WGDEVICE_A_PRIVATE_KEY, k);
    }
    if let Some(p) = cfg.listen_port {
        a.u16(WGDEVICE_A_LISTEN_PORT, p);
    }
    if !cfg.peers.is_empty() {
        a.nested(NLA_F_NESTED | WGDEVICE_A_PEERS, |ps| {
            for (i, p) in cfg.peers.iter().enumerate() {
                ps.nested(NLA_F_NESTED | i as u16, |x| encode_peer(x, p));
            }
        });
    }
    genl(family, WG_CMD_SET_DEVICE, NLM_F_REQUEST | NLM_F_ACK, a)
}

/// A large configuration split into batches, every
/// batch with the device's settings and one peer's (part of its) allowed
/// IPs.
pub fn batches(cfg: &DeviceSet) -> Vec<DeviceSet> {
    let ips: usize = cfg.peers.iter().map(|p| p.allowed_ips.len()).sum();
    if cfg.peers.len() <= PEER_BATCH && ips <= IP_BATCH {
        return vec![cfg.clone()];
    }
    let mut out = Vec::new();
    let mut known = std::collections::HashSet::new();
    for p in &cfg.peers {
        let mut rest = p.allowed_ips.as_slice();
        loop {
            let (chunk, done) = if rest.len() < IP_BATCH {
                (rest.to_vec(), true)
            } else {
                let c = rest[..IP_BATCH].to_vec();
                rest = &rest[IP_BATCH..];
                (c, rest.is_empty())
            };
            let mut pc = PeerSet {
                public_key: p.public_key,
                remove: p.remove,
                allowed_ips: chunk,
                ..PeerSet::default()
            };
            if known.insert(p.public_key) {
                pc.endpoint = p.endpoint.clone();
                pc.keepalive = p.keepalive;
                pc.replace_allowed_ips = p.replace_allowed_ips;
            }
            out.push(DeviceSet {
                private_key: cfg.private_key,
                listen_port: cfg.listen_port,
                peers: vec![pc],
            });
            if done {
                break;
            }
        }
    }
    out
}

/// The kernel's form of what peerChanges decided, with the node's key.
pub fn device_set(c: &wireguard::Config, key: &Key) -> Result<DeviceSet, String> {
    let mut out = DeviceSet {
        private_key: c.private_key.then_some(key.0),
        listen_port: c.listen_port,
        peers: Vec::new(),
    };
    for p in &c.peers {
        let endpoint = match &p.endpoint {
            None => None,
            Some(text) => {
                Some(parse_udp(text).ok_or_else(|| format!("invalid endpoint {text:?}"))?)
            }
        };
        let mut allowed = Vec::new();
        for n in &p.allowed_ips {
            let (ip, bits) = n
                .rsplit_once('/')
                .and_then(|(a, b)| Some((Addr::parse(a)?, b.parse::<u8>().ok()?)))
                .ok_or_else(|| format!("invalid allowed IP {n:?}"))?;
            allowed.push((ip, bits));
        }
        out.peers.push(PeerSet {
            public_key: p.public_key.0,
            remove: p.remove,
            replace_allowed_ips: p.replace_allowed_ips,
            endpoint,
            keepalive: p.keepalive.map(|k| k as u16),
            allowed_ips: allowed,
        });
    }
    Ok(out)
}

/// "1.2.3.4:51820" or "[fd00::1]:51820".
fn parse_udp(s: &str) -> Option<(Addr, u16)> {
    let (host, port) = s.rsplit_once(':')?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    Some((Addr::parse(host)?, port.parse().ok()?))
}

fn key_of(b: &[u8]) -> Key {
    let mut k = [0u8; 32];
    if b.len() == 32 {
        k.copy_from_slice(b);
    }
    Key(k)
}

fn parse_endpoint(b: &[u8]) -> Option<String> {
    let family = ne_u16(b);
    let port = u16::from_be_bytes([*b.get(2)?, *b.get(3)?]);
    match family {
        AF_INET => {
            let ip = b.get(4..8)?;
            Some(udp_text(&Addr::V4([ip[0], ip[1], ip[2], ip[3]]), port))
        }
        AF_INET6 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(b.get(8..24)?);
            Some(udp_text(&Addr::V6(ip, String::new()), port))
        }
        _ => None,
    }
}

fn parse_allowed(b: &[u8]) -> Option<String> {
    let (mut ip, mut bits) = (None, 0u8);
    for (t, v) in attrs(b) {
        match t {
            WGALLOWEDIP_A_IPADDR => {
                ip = match v.len() {
                    4 => Some(Addr::V4([v[0], v[1], v[2], v[3]])),
                    16 => {
                        let mut a = [0u8; 16];
                        a.copy_from_slice(v);
                        Some(Addr::V6(a, String::new()))
                    }
                    _ => None,
                };
            }
            WGALLOWEDIP_A_CIDR_MASK => bits = v.first().copied().unwrap_or(0),
            _ => {}
        }
    }
    ip.map(|ip| format!("{ip}/{bits}"))
}

fn parse_peer(b: &[u8]) -> DevicePeer {
    let mut p = DevicePeer::default();
    for (t, v) in attrs(b) {
        match t {
            WGPEER_A_PUBLIC_KEY => p.public_key = key_of(v),
            WGPEER_A_ENDPOINT => p.endpoint = parse_endpoint(v),
            WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL => p.keepalive = i64::from(ne_u16(v)),
            WGPEER_A_LAST_HANDSHAKE_TIME if v.len() >= 16 => {
                let sec = i64::from_ne_bytes(v[0..8].try_into().unwrap_or_default());
                let nsec = i64::from_ne_bytes(v[8..16].try_into().unwrap_or_default());
                p.last_handshake = (sec != 0 || nsec != 0).then_some(sec);
            }
            WGPEER_A_ALLOWEDIPS => {
                p.allowed_ips
                    .extend(attrs(v).iter().filter_map(|(_, a)| parse_allowed(a)));
            }
            _ => {}
        }
    }
    p
}

/// The device of the dump's first message with the peers of
/// every message, a peer split across messages merged into one.
pub fn parse_device(msgs: &[Vec<u8>]) -> Device {
    let mut d = Device::default();
    for (i, m) in msgs.iter().enumerate() {
        let Some(body) = m.get(4..) else { continue };
        let mut peers = Vec::new();
        for (t, v) in attrs(body) {
            match t {
                WGDEVICE_A_PRIVATE_KEY if i == 0 => d.private_key = key_of(v),
                WGDEVICE_A_LISTEN_PORT if i == 0 => d.listen_port = i64::from(ne_u16(v)),
                WGDEVICE_A_PEERS => peers.extend(attrs(v).iter().map(|(_, p)| parse_peer(p))),
                _ => {}
            }
        }
        for p in peers {
            match d.peers.iter_mut().find(|q| q.public_key == p.public_key) {
                Some(q) if i > 0 => q.allowed_ips.extend(p.allowed_ips),
                _ => d.peers.push(p),
            }
        }
    }
    d
}

/// The family's ID from GetFamily's answer.
fn parse_family(msgs: &[(u16, Vec<u8>)]) -> Option<u16> {
    for (_, m) in msgs {
        for (t, v) in attrs(m.get(4..)?) {
            if t == CTRL_ATTR_FAMILY_ID {
                return Some(ne_u16(v));
            }
        }
    }
    None
}

/// Why WireGuard could not be read or set.
#[derive(Debug)]
pub enum WgError {
    /// No such device, not a WireGuard one, or no WireGuard in the kernel
    /// (not found).
    NotExist,
    Errno(Errno),
}

impl std::fmt::Display for WgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WgError::NotExist => write!(f, "file does not exist"),
            WgError::Errno(e) => write!(f, "{e}"),
        }
    }
}

fn wg_err(e: Errno) -> WgError {
    match e.0 {
        libc::ENODEV | libc::EOPNOTSUPP | libc::ENOENT => WgError::NotExist,
        _ => WgError::Errno(e),
    }
}

/// A generic netlink socket with WireGuard's family.
pub struct Client {
    sock: Socket,
    family: u16,
}

impl Client {
    pub fn open() -> Result<Client, WgError> {
        let mut sock = Socket::open(NETLINK_GENERIC).map_err(WgError::Errno)?;
        let answer = sock.request(&get_family()).map_err(wg_err)?;
        let family = parse_family(&answer).ok_or(WgError::NotExist)?;
        Ok(Client { sock, family })
    }

    pub fn device(&mut self, name: &str) -> Result<Device, WgError> {
        let msgs = self
            .sock
            .request(&get_device(self.family, name))
            .map_err(wg_err)?;
        let bodies: Vec<Vec<u8>> = msgs
            .into_iter()
            .filter(|(t, _)| *t == self.family)
            .map(|(_, b)| b)
            .collect();
        Ok(parse_device(&bodies))
    }

    pub fn configure(&mut self, name: &str, cfg: &DeviceSet) -> Result<(), WgError> {
        for b in batches(cfg) {
            self.sock
                .request(&set_device(self.family, name, &b))
                .map_err(wg_err)?;
        }
        Ok(())
    }
}

/// The device name as the kernel reports it, for tests of parse_device.
#[cfg(test)]
fn device_name(msgs: &[Vec<u8>]) -> String {
    msgs.first()
        .and_then(|m| m.get(4..))
        .map(|b| {
            attrs(b)
                .iter()
                .find(|(t, _)| *t == WGDEVICE_A_IFNAME)
                .map(|(_, v)| super::netlink::cstring(v))
                .unwrap_or_default()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(n: u8, ips: usize) -> PeerSet {
        PeerSet {
            public_key: [n; 32],
            replace_allowed_ips: true,
            endpoint: Some((Addr::V4([10, 0, 0, n]), 51820)),
            keepalive: Some(25),
            allowed_ips: (0..ips)
                .map(|i| (Addr::V4([10, 120, (i % 256) as u8, 0]), 24))
                .collect(),
            ..PeerSet::default()
        }
    }

    #[test]
    fn small_configurations_go_in_one_message() {
        let cfg = DeviceSet {
            private_key: Some([1; 32]),
            listen_port: Some(51820),
            peers: vec![peer(2, 1), peer(3, 2)],
        };
        assert_eq!(batches(&cfg), vec![cfg]);
    }

    #[test]
    fn large_configurations_split_as_wgctrl_splits_them() {
        let cfg = DeviceSet {
            private_key: None,
            listen_port: None,
            peers: vec![peer(2, 300), peer(3, 1)],
        };
        let b = batches(&cfg);
        assert_eq!(b.len(), 3);
        assert_eq!(b[0].peers[0].allowed_ips.len(), 256);
        assert!(b[0].peers[0].replace_allowed_ips);
        assert_eq!(b[1].peers[0].allowed_ips.len(), 44);
        assert!(!b[1].peers[0].replace_allowed_ips);
        assert_eq!(b[1].peers[0].endpoint, None);
        assert!(b[2].peers[0].replace_allowed_ips);
    }

    #[test]
    fn devices_read_back_what_was_set() {
        let cfg = DeviceSet {
            private_key: Some([1; 32]),
            listen_port: Some(51820),
            peers: vec![peer(2, 2)],
        };
        // A device answer has the set message's attributes, after the
        // generic netlink header.
        let m = set_device(30, "armada-net", &cfg);
        let d = parse_device(std::slice::from_ref(&m.body));
        assert_eq!(device_name(&[m.body]), "armada-net");
        assert_eq!(d.private_key.0, [1; 32]);
        assert_eq!(d.listen_port, 51820);
        assert_eq!(d.peers.len(), 1);
        assert_eq!(d.peers[0].endpoint.as_deref(), Some("10.0.0.2:51820"));
        assert_eq!(
            d.peers[0].allowed_ips,
            vec!["10.120.0.0/24", "10.120.1.0/24"]
        );
        assert_eq!(d.peers[0].keepalive, 25);
        assert_eq!(d.peers[0].last_handshake, None);
    }
}

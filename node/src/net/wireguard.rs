//! What a WireGuard device must change to carry a transport's peers
//! (peers.go's peerChanges), and which peers have gone quiet (stalePeers).
//! Devices are read and configured by the caller; times are Unix seconds.

use super::addr::Prefix;
use super::key::Key;
use super::plan::{MODE_MESH, Peer, WIREGUARD_PORT};
use std::collections::{HashMap, HashSet};

/// keepalive, in seconds.
pub const KEEPALIVE: i64 = 25;
/// staleHandshake, in seconds.
pub const STALE_HANDSHAKE: i64 = 180;

/// A device's peer as the kernel reports it (wgtypes.Peer).
#[derive(Clone, Default)]
pub struct DevicePeer {
    pub public_key: Key,
    /// net.UDPAddr.String, or None.
    pub endpoint: Option<String>,
    /// net.IPNet.String of each.
    pub allowed_ips: Vec<String>,
    pub keepalive: i64,
    /// Unix seconds, None when there was none.
    pub last_handshake: Option<i64>,
}

/// A device as the kernel reports it (wgtypes.Device).
#[derive(Clone, Default)]
pub struct Device {
    pub private_key: Key,
    pub listen_port: i64,
    pub peers: Vec<DevicePeer>,
}

/// One peer's change (wgtypes.PeerConfig).
pub struct PeerConfig {
    pub public_key: Key,
    pub remove: bool,
    pub endpoint: Option<String>,
    pub replace_allowed_ips: bool,
    pub allowed_ips: Vec<String>,
    pub keepalive: Option<i64>,
}

/// A device's changes (wgtypes.Config).
pub struct Config {
    pub private_key: bool,
    pub listen_port: Option<u16>,
    pub peers: Vec<PeerConfig>,
}

fn net_text(p: &Prefix) -> String {
    format!("{}/{}", p.addr, p.bits)
}

/// The text of a UDP address (net.UDPAddr.String).
pub fn udp_text(addr: &super::addr::Addr, port: u16) -> String {
    if addr.is4() {
        format!("{addr}:{port}")
    } else {
        format!("[{addr}]:{port}")
    }
}

fn same_nets(a: &[String], b: &[String]) -> bool {
    let (mut a, mut b) = (a.to_vec(), b.to_vec());
    a.sort();
    b.sort();
    a == b
}

/// peerChanges: the configuration that turns d into a device with key and
/// peers, or None when it already is one. Removed peers come last, by key.
pub fn peer_changes(d: &Device, key: &Key, mode: &str, peers: &[Peer], now: i64) -> Option<Config> {
    let mut cfg = Config {
        private_key: d.private_key != *key,
        listen_port: (d.listen_port != i64::from(WIREGUARD_PORT)).then_some(WIREGUARD_PORT),
        peers: Vec::new(),
    };
    let have: HashMap<Key, &DevicePeer> = d.peers.iter().map(|p| (p.public_key, p)).collect();
    let mut want = HashSet::new();
    for pe in peers {
        want.insert(pe.key);
        let public = mode == MODE_MESH || pe.remote;
        let (target, mut allowed) = if public {
            (
                pe.endpoint.clone(),
                vec![net_text(&Prefix::from(pe.ip(), 32)), net_text(pe.subnet())],
            )
        } else {
            (pe.ip.clone(), vec![net_text(pe.subnet())])
        };
        allowed.extend(pe.carried.iter().map(net_text));
        let h = have.get(&pe.key);
        let (ep, keep) = match (&target, public) {
            (None, true) => (None, h.is_some()),
            _ => {
                let ep = udp_text(target.as_ref().expect("an address"), WIREGUARD_PORT);
                let keep = h.is_some_and(|h| {
                    h.endpoint.as_ref().is_some_and(|e| {
                        *e == ep
                            || public
                                && h.last_handshake.is_some_and(|t| now - t <= STALE_HANDSHAKE)
                    })
                });
                (Some(ep), keep)
            }
        };
        if let Some(h) = h
            && keep
            && same_nets(&h.allowed_ips, &allowed)
            && h.keepalive == KEEPALIVE
        {
            continue;
        }
        cfg.peers.push(PeerConfig {
            public_key: pe.key,
            remove: false,
            endpoint: if keep { None } else { ep },
            replace_allowed_ips: true,
            allowed_ips: allowed,
            keepalive: Some(KEEPALIVE),
        });
    }
    let mut gone: Vec<Key> = have
        .keys()
        .filter(|k| !want.contains(*k))
        .copied()
        .collect();
    gone.sort_by_key(|k| k.to_string());
    for k in gone {
        cfg.peers.push(PeerConfig {
            public_key: k,
            remove: true,
            endpoint: None,
            replace_allowed_ips: false,
            allowed_ips: Vec::new(),
            keepalive: None,
        });
    }
    if !cfg.private_key && cfg.listen_port.is_none() && cfg.peers.is_empty() {
        return None;
    }
    Some(cfg)
}

/// When a WireGuard peer was first configured, and for which node.
pub struct Seen {
    pub node: String,
    pub since: i64,
}

/// stalePeers: the nodes of peers configured longer ago than
/// STALE_HANDSHAKE with no handshake since, sorted, at most 32.
pub fn stale_peers(
    devices: &[Vec<DevicePeer>],
    since: &HashMap<Key, Seen>,
    now: i64,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in devices {
        for pe in d {
            let Some(seen) = since.get(&pe.public_key) else {
                continue;
            };
            if now - seen.since <= STALE_HANDSHAKE {
                continue;
            }
            if pe.last_handshake.is_none_or(|t| now - t > STALE_HANDSHAKE) {
                out.push(seen.node.clone());
            }
        }
    }
    out.sort();
    out.dedup();
    out.truncate(32);
    out
}

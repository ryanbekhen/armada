//! The cluster network (network.go, ADR 0025, ADR 0049, ADR 0050).

use std::collections::HashSet;

use armada_spec::go::{Addr, Prefix, parse_addr, parse_prefix, quote};
use armada_spec::gotime::Time;
use serde::{Serialize, Serializer};

use crate::error::{Result, conflict, not_found, other, precondition};
use crate::gojson::time_text;
use crate::records::{NetworkRec, NetworkSwitchRec, NodeRec};
use crate::tx::*;

/// Network modes.
pub const NETWORK_PLAIN: &str = "plain";
pub const NETWORK_WIREGUARD: &str = "wireguard";
pub const NETWORK_MESH: &str = "mesh";

/// The default range of mesh addresses.
pub const DEFAULT_MESH_CIDR: &str = "10.122.0.0/16";

/// The prefix length of each node's container subnet.
pub const NODE_SUBNET_BITS: u8 = 24;

/// Steps of a network switch.
pub const SWITCH_PREPARE: &str = "prepare";
pub const SWITCH_MOVE: &str = "move";

pub(crate) const KEY_NETWORK: &str = "network";

fn prefix_text<S: Serializer>(p: &Option<Prefix>, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&p.as_ref().map(Prefix::string).unwrap_or_default())
}

/// The cluster network.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Network {
    pub mode: String,
    #[serde(rename = "ClusterCIDR", serialize_with = "prefix_text")]
    pub cluster_cidr: Option<Prefix>,
    pub isolate_default: bool,
    #[serde(rename = "MeshCIDR", serialize_with = "prefix_text")]
    pub mesh_cidr: Option<Prefix>,
    pub switch: Option<NetworkSwitch>,
}

/// A switch between the plain and wireguard modes under way.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkSwitch {
    pub to: String,
    pub step: String,
    #[serde(with = "time_text")]
    pub since: Time,
}

fn u32_of(a: &Addr) -> u32 {
    u32::from_be_bytes([a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3]])
}

fn addr4(v: u32) -> Addr {
    parse_addr(&std::net::Ipv4Addr::from(v).to_string()).expect("an IPv4 address")
}

/// Prefix.Overlaps.
pub fn overlaps(p: &Prefix, o: &Prefix) -> bool {
    if p == o {
        return true;
    }
    if p.addr.is4 != o.addr.is4 {
        return false;
    }
    let bits = p.bits.min(o.bits);
    if bits == 0 {
        return true;
    }
    Prefix::from(&p.addr, bits).masked().addr.bytes
        == Prefix::from(&o.addr, bits).masked().addr.bytes
}

fn p_str(p: &Option<Prefix>) -> String {
    p.as_ref()
        .map_or_else(|| "invalid Prefix".to_string(), Prefix::string)
}

/// CheckClusterCIDR: a private IPv4 prefix from /12 to /20, canonical.
pub fn check_cluster_cidr(p: &Option<Prefix>) -> std::result::Result<(), String> {
    check_cidr(p, "cluster CIDR", 12, 20)
}

/// CheckMeshCIDR: a private IPv4 prefix from /8 to /24, canonical.
pub fn check_mesh_cidr(p: &Option<Prefix>) -> std::result::Result<(), String> {
    check_cidr(p, "mesh CIDR", 8, 24)
}

fn check_cidr(p: &Option<Prefix>, what: &str, lo: u8, hi: u8) -> std::result::Result<(), String> {
    let Some(p) = p.as_ref().filter(|p| p.addr.is4) else {
        return Err(format!("{what} must be an IPv4 prefix"));
    };
    let s = p.string();
    if &p.masked() != p {
        return Err(format!(
            "{what} {s} is not in canonical form (want {})",
            p.masked().string()
        ));
    }
    if p.bits < lo || p.bits > hi {
        return Err(format!(
            "{what} {s}: the prefix must be from /{lo} to /{hi}"
        ));
    }
    if !p.addr.is_private() {
        return Err(format!("{what} {s} is not a private range"));
    }
    Ok(())
}

fn parse_net_prefix(s: &str, what: &str) -> Result<Prefix> {
    parse_prefix(s).ok_or_else(|| {
        other!(
            "decode {KEY_NETWORK}: {what}: netip.ParsePrefix({}): invalid",
            quote(s)
        )
    })
}

impl Network {
    /// meshRange: the recorded mesh range, else DefaultMeshCIDR.
    fn mesh_range(&self) -> Prefix {
        self.mesh_cidr
            .clone()
            .unwrap_or_else(|| parse_prefix(DEFAULT_MESH_CIDR).expect("a valid prefix"))
    }
}

/// freeMeshAddress: the lowest host address of mesh not in used.
fn free_mesh_address(mesh: &Prefix, used: &HashSet<u32>) -> Result<Addr> {
    let base = u32_of(&mesh.addr);
    let last = base | (((1u64 << (32 - u32::from(mesh.bits))) - 1) as u32);
    let mut a = base.wrapping_add(1);
    while a > base && a < last {
        if !used.contains(&a) {
            return Ok(addr4(a));
        }
        a += 1;
    }
    Err(precondition!(
        "the mesh CIDR {} has no free address",
        mesh.string()
    ))
}

/// freeSubnet: the first node subnet of cidr not in used.
fn free_subnet(cidr: &Prefix, used: &HashSet<String>) -> Result<Prefix> {
    let count = 1u32 << (NODE_SUBNET_BITS - cidr.bits);
    let start = u32_of(&cidr.addr);
    for i in 0..count {
        let p = Prefix::from(
            &addr4(start.wrapping_add(i << (32 - NODE_SUBNET_BITS))),
            NODE_SUBNET_BITS,
        );
        if !used.contains(&p.string()) {
            return Ok(p);
        }
    }
    Err(precondition!(
        "the cluster CIDR {} has no free node subnet ({count} nodes)",
        cidr.string()
    ))
}

impl Etx<'_> {
    pub(crate) async fn network(&self) -> Result<Option<Network>> {
        let Some(r) = self.get::<NetworkRec>(KEY_NETWORK).await? else {
            return Ok(None);
        };
        let p = parse_net_prefix(&r.cluster_cidr, "cluster CIDR")?;
        let mut n = Network {
            mode: r.mode,
            cluster_cidr: Some(p),
            isolate_default: r.isolate_default,
            mesh_cidr: None,
            switch: None,
        };
        if let Some(sw) = r.switch {
            n.switch = Some(NetworkSwitch {
                to: sw.to,
                step: sw.step,
                since: armada_spec::gotime::parse_rfc3339(&sw.since).unwrap_or_else(Time::zero),
            });
        }
        if !r.mesh_cidr.is_empty() {
            n.mesh_cidr = Some(parse_net_prefix(&r.mesh_cidr, "mesh CIDR")?);
        }
        Ok(Some(n))
    }

    /// claimMeshRange records p as r's mesh range once no node holds a mesh
    /// address, p is clear of the cluster CIDR, and no node's address or
    /// endpoint lies in it.
    pub(crate) async fn claim_mesh_range(&self, r: &NetworkRec, p: &Prefix) -> Result<()> {
        let cidr = parse_net_prefix(&r.cluster_cidr, "cluster CIDR")?;
        if overlaps(p, &cidr) {
            return Err(precondition!(
                "mesh CIDR {} overlaps the cluster CIDR {}",
                p.string(),
                cidr.string()
            ));
        }
        for (_, n) in self.list_into::<NodeRec>(PFX_NODES).await? {
            if n.mesh_address {
                return Err(precondition!(
                    "node {} already holds a mesh address of {}",
                    n.id,
                    r.mesh_cidr
                ));
            }
            for s in [&n.private_ip, &n.endpoint] {
                if let Some(a) = parse_addr(s)
                    && p.contains(&a)
                {
                    return Err(precondition!(
                        "node {}'s address {} is inside the mesh CIDR {}; pick another range with armada cluster update --mesh-cidr",
                        n.id,
                        a.string(),
                        p.string()
                    ));
                }
            }
        }
        Ok(())
    }

    /// newNodeNetwork checks a new node's private IP against the cluster
    /// network and returns the subnet to give it ("" without a network).
    pub(crate) async fn new_node_network(
        &mut self,
        private_ip: &str,
        mesh_address: bool,
    ) -> Result<String> {
        let Some(n) = self.network().await? else {
            if mesh_address {
                return Err(precondition!("a mesh address needs a cluster network"));
            }
            return Ok(String::new());
        };
        let cidr = n
            .cluster_cidr
            .clone()
            .expect("a recorded network has a cluster CIDR");
        let ip = match parse_addr(private_ip) {
            Some(ip) if ip.is4 => ip,
            _ => {
                return Err(precondition!(
                    "private IP {} is not an IPv4 address; the cluster network carries IPv4 only",
                    quote(private_ip)
                ));
            }
        };
        if cidr.contains(&ip) {
            return Err(precondition!(
                "private IP {private_ip} is inside the cluster CIDR {}",
                cidr.string()
            ));
        }
        if n.mode == NETWORK_MESH {
            if !n.mesh_cidr.as_ref().is_some_and(|m| m.contains(&ip)) {
                return Err(precondition!(
                    "a mesh node's address {private_ip} must be in the mesh CIDR {}",
                    p_str(&n.mesh_cidr)
                ));
            }
        } else if mesh_address {
            let mesh = n.mesh_range();
            if !mesh.contains(&ip) {
                return Err(precondition!(
                    "mesh address {private_ip} must be in the mesh CIDR {}",
                    mesh.string()
                ));
            }
            if n.mesh_cidr.is_none() {
                let mut r: NetworkRec = self.get(KEY_NETWORK).await?.unwrap_or_default();
                self.claim_mesh_range(&r, &mesh).await?;
                r.mesh_cidr = mesh.string();
                self.put(KEY_NETWORK, &r)?;
            }
        } else if let Some(m) = &n.mesh_cidr
            && m.contains(&ip)
        {
            return Err(precondition!(
                "private IP {private_ip} is inside the cluster's mesh CIDR {}, which machines with no private network take their addresses from; join with --no-private-ip",
                m.string()
            ));
        }
        let mut used = HashSet::new();
        for (_, r) in self.list_into::<NodeRec>(PFX_NODES).await? {
            if !r.subnet.is_empty() {
                used.insert(r.subnet);
            }
        }
        Ok(free_subnet(&cidr, &used)?.string())
    }
}

impl Etcd {
    /// GetNetwork returns the cluster network, ErrNotFound without one.
    pub async fn get_network(&self) -> Result<Network> {
        let mut out = None;
        view!(self, |t| {
            out = t.network().await?;
            if out.is_none() {
                return Err(not_found!("cluster network"));
            }
            Ok(())
        })?;
        Ok(out.expect("set by the view"))
    }

    /// InitNetwork records the cluster network, once and before any node.
    pub async fn init_network(&self, n: &Network) -> Result<()> {
        if n.mode != NETWORK_PLAIN && n.mode != NETWORK_WIREGUARD && n.mode != NETWORK_MESH {
            return Err(other!("unknown network mode {}", quote(&n.mode)));
        }
        check_cluster_cidr(&n.cluster_cidr).map_err(crate::Error::other)?;
        let cidr = n.cluster_cidr.clone().expect("checked");
        let mut rec = NetworkRec {
            mode: n.mode.clone(),
            cluster_cidr: cidr.string(),
            ..Default::default()
        };
        if n.mode != NETWORK_MESH && n.mesh_cidr.is_some() {
            return Err(other!("a mesh CIDR needs the mesh network mode"));
        }
        if n.mode == NETWORK_MESH {
            check_mesh_cidr(&n.mesh_cidr).map_err(crate::Error::other)?;
            let mesh = n.mesh_cidr.clone().expect("checked");
            if overlaps(&mesh, &cidr) {
                return Err(other!(
                    "mesh CIDR {} overlaps the cluster CIDR {}",
                    mesh.string(),
                    cidr.string()
                ));
            }
            rec.mesh_cidr = mesh.string();
        }
        let rec = &rec;
        tx!(self, |t| {
            if t.network().await?.is_some() {
                return Err(conflict!("the cluster network is already set"));
            }
            if !t.list(PFX_NODES).await?.is_empty() {
                return Err(precondition!("the cluster already has nodes"));
            }
            t.put(KEY_NETWORK, rec)
        })
    }

    /// SetDefaultIsolation turns isolation of the default space on or off.
    pub async fn set_default_isolation(&self, on: bool, actor: &str) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            let Some(mut r) = t.get::<NetworkRec>(KEY_NETWORK).await? else {
                return Err(precondition!(
                    "network isolation needs the cluster network (armadad init --cluster-cidr)"
                ));
            };
            if r.isolate_default == on {
                return Ok(());
            }
            r.isolate_default = on;
            t.put(KEY_NETWORK, &r)?;
            t.audit(
                &now,
                actor,
                "space.set",
                "default",
                &format!("network isolation {on}"),
            )
            .await
        })
    }

    /// StartNetworkSwitch begins switching a running cluster to mode to.
    pub async fn start_network_switch(&self, to: &str, actor: &str) -> Result<()> {
        if to != NETWORK_PLAIN && to != NETWORK_WIREGUARD {
            return Err(precondition!(
                "a running cluster switches only to {NETWORK_PLAIN} or {NETWORK_WIREGUARD}, not {}",
                quote(to)
            ));
        }
        let now = self.now();
        tx!(self, |t| {
            let Some(mut r) = t.get::<NetworkRec>(KEY_NETWORK).await? else {
                return Err(precondition!(
                    "the cluster has no cluster network to switch"
                ));
            };
            if r.mode == NETWORK_MESH {
                return Err(precondition!(
                    "a mesh cluster cannot switch its network mode: its nodes' addresses depend on it"
                ));
            }
            if let Some(sw) = r.switch.clone() {
                if to == r.mode && sw.step == SWITCH_PREPARE {
                    r.switch = None;
                    t.put(KEY_NETWORK, &r)?;
                    let detail = format!("gave up the switch to {to}; staying on {}", r.mode);
                    return t
                        .audit(&now, actor, "network.switch", "network", &detail)
                        .await;
                }
                return Err(conflict!(
                    "the network is switching to {} ({} step)",
                    sw.to,
                    sw.step
                ));
            }
            if to == r.mode {
                return Ok(());
            }
            let away: Vec<String> = t
                .list_into::<NodeRec>(PFX_NODES)
                .await?
                .into_iter()
                .filter(|(_, n)| !n.site.is_empty())
                .map(|(_, n)| n.id)
                .collect();
            if !away.is_empty() {
                return Err(precondition!(
                    "nodes in another site reach the others over WireGuard whatever the mode, and a switch moves only one site's: move them back first (armada node site NODE --clear): {}",
                    away.join(", ")
                ));
            }
            r.switch = Some(NetworkSwitchRec {
                to: to.to_string(),
                step: SWITCH_PREPARE.to_string(),
                since: now.rfc3339_nano(),
            });
            t.put(KEY_NETWORK, &r)?;
            let detail = format!("switching from {} to {to}", r.mode);
            t.audit(&now, actor, "network.switch", "network", &detail)
                .await
        })
    }

    /// AdvanceNetworkSwitch takes a switch to to from step from to the next.
    pub async fn advance_network_switch(&self, to: &str, from: &str) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            let r = t.get::<NetworkRec>(KEY_NETWORK).await?;
            let Some(mut r) = r.filter(|r| {
                r.switch
                    .as_ref()
                    .is_some_and(|s| s.to == to && s.step == from)
            }) else {
                return Err(conflict!("the network switch is not at {to} {from}"));
            };
            match from {
                SWITCH_PREPARE => {
                    r.switch = Some(NetworkSwitchRec {
                        to: to.to_string(),
                        step: SWITCH_MOVE.to_string(),
                        since: now.rfc3339_nano(),
                    })
                }
                SWITCH_MOVE => {
                    r.mode = to.to_string();
                    r.switch = None;
                }
                _ => return Err(other!("unknown switch step {}", quote(from))),
            }
            t.put(KEY_NETWORK, &r)
        })
    }

    /// FreeMeshAddress returns the lowest free mesh address.
    pub async fn free_mesh_address(&self) -> Result<String> {
        let mut out = String::new();
        view!(self, |t| {
            let Some(n) = t.network().await? else {
                return Err(precondition!("the cluster has no cluster network"));
            };
            let mesh = n.mesh_range();
            let mut used = HashSet::new();
            for (_, r) in t.list_into::<NodeRec>(PFX_NODES).await? {
                if let Some(a) = parse_addr(&r.private_ip)
                    && a.is4
                {
                    used.insert(u32_of(&a));
                }
            }
            match free_mesh_address(&mesh, &used) {
                Ok(a) => out = a.string(),
                Err(e) => {
                    out = "invalid IP".to_string();
                    return Err(e);
                }
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// SetMeshCIDR records a plain or wireguard cluster's mesh range.
    pub async fn set_mesh_cidr(&self, p: &Option<Prefix>, actor: &str) -> Result<()> {
        check_mesh_cidr(p).map_err(|e| precondition!("{e}"))?;
        let p = p.clone().expect("checked");
        let now = self.now();
        tx!(self, |t| {
            let Some(mut r) = t.get::<NetworkRec>(KEY_NETWORK).await? else {
                return Err(precondition!("the cluster has no cluster network"));
            };
            if r.mode == NETWORK_MESH {
                return Err(precondition!("a mesh cluster's range is set once, at init"));
            }
            if r.mesh_cidr == p.string() {
                return Ok(());
            }
            t.claim_mesh_range(&r, &p).await?;
            r.mesh_cidr = p.string();
            t.put(KEY_NETWORK, &r)?;
            t.audit(&now, actor, "cluster.mesh-cidr", &p.string(), "")
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnets_and_addresses() {
        let p = parse_prefix("10.120.0.0/16").unwrap();
        let mut used = HashSet::new();
        assert_eq!(free_subnet(&p, &used).unwrap().string(), "10.120.0.0/24");
        used.insert("10.120.0.0/24".to_string());
        assert_eq!(free_subnet(&p, &used).unwrap().string(), "10.120.1.0/24");
        let m = parse_prefix("10.122.0.0/30").unwrap();
        let mut u = HashSet::new();
        assert_eq!(free_mesh_address(&m, &u).unwrap().string(), "10.122.0.1");
        u.insert(u32_of(&parse_addr("10.122.0.1").unwrap()));
        assert_eq!(free_mesh_address(&m, &u).unwrap().string(), "10.122.0.2");
        u.insert(u32_of(&parse_addr("10.122.0.2").unwrap()));
        assert!(free_mesh_address(&m, &u).is_err());
        assert!(overlaps(&p, &parse_prefix("10.0.0.0/8").unwrap()));
        assert!(!overlaps(&p, &parse_prefix("10.121.0.0/16").unwrap()));
        assert_eq!(
            check_cluster_cidr(&parse_prefix("10.120.0.1/16")).unwrap_err(),
            "cluster CIDR 10.120.0.1/16 is not in canonical form (want 10.120.0.0/16)"
        );
    }
}

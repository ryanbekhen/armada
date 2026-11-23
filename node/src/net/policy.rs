//! The isolation policy (policy.go's buildPolicy, ADR 0026): what the
//! nftables tables that keep apps and spaces apart are built from.

use super::addr::{Addr, Prefix};
use super::plan::{Plan, container_addr};
use crate::names;
use std::collections::{BTreeMap, HashMap};

pub struct Policy {
    pub cidr: Prefix,
    pub subnet: Prefix,
    pub gateway: Option<Addr>,
    /// App IDs with a known address, sorted, each with its addresses,
    /// sorted.
    pub members: BTreeMap<String, Vec<Addr>>,
    pub open: Vec<Addr>,
    pub nodes: Vec<Addr>,
    pub tcp_ports: Vec<u16>,
}

/// buildPolicy: the cluster's container addresses merged with this node's
/// own (`local`), which win in the node subnet; with none, the control
/// plane's list is used as is.
pub fn build_policy(p: &Plan, local: Option<&HashMap<Addr, String>>) -> Policy {
    let subnet = p.self_.subnet().clone();
    let mut eps: BTreeMap<Addr, String> = BTreeMap::new();
    for (a, app) in &p.endpoints {
        if local.is_none() || !subnet.contains(a) {
            eps.insert(a.clone(), app.clone());
        }
    }
    for (a, app) in local.into_iter().flatten() {
        if subnet.contains(a) && container_addr(a, p.cidr()) && names::valid_app_id(app) {
            eps.insert(a.clone(), app.clone());
        }
    }
    let mut members: BTreeMap<String, Vec<Addr>> = BTreeMap::new();
    let mut open = Vec::new();
    for (a, app) in eps {
        members.entry(app.clone()).or_default().push(a.clone());
        if subnet.contains(&a)
            && names::space_of(&app) == Some(names::DEFAULT_SPACE)
            && !p.isolate_default
        {
            open.push(a);
        }
    }
    let mut nodes: Vec<Addr> = std::iter::once(&p.self_)
        .chain(p.peers.iter())
        .chain(p.relayed.iter())
        .map(|pe| pe.ip().clone())
        .collect();
    nodes.sort();
    Policy {
        cidr: p.cidr().clone(),
        gateway: subnet.masked().addr.next4(),
        subnet,
        members,
        open,
        nodes,
        tcp_ports: p.tcp_ports.clone(),
    }
}

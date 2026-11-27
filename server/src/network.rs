//! The cluster network (ADR 0025, 0026, 0049, 0050): the configuration
//! every agent applies with its peers, their keys, endpoints, sites, and
//! relays, and the container addresses the firewalls keep apart; and
//! switches of a running cluster's mode between plain and wireguard, step
//! by step as the nodes report them.
//!
//! The ports of internal TCP apps (`NetworkConfig.tcp_ports`) come from
//! the pass's proxy configuration (`ingress`).

use std::collections::{BTreeMap, HashMap};

use armada_proto::armada::v1::{
    NetworkConfig, NetworkEndpoint, NetworkPeer, NetworkSwitchProgress, NetworkSwitchStatus,
    NodeSwitchWait,
};
use armada_spec::gotime::Time;
use armada_spec::validate::validate_name;
use armada_store::network::{NETWORK_PLAIN, NETWORK_WIREGUARD, SWITCH_MOVE, SWITCH_PREPARE};
use armada_store::{Kind, Network, Node, Replica};
use tonic::{Code, Status};

use crate::agents::valid_replica_ip;
use crate::events::{NODE, clean_message, event};
use crate::grpc::Auth;
use crate::reconcile::{nanos, node_lost};
use crate::{Server, store_err};

/// Bounds the peers a node's switch status names.
const MAX_SWITCH_UNREACHED: usize = 32;
/// Bounds the nodes a switch's progress lists.
const MAX_SWITCH_WAITING: usize = 50;
/// How often the leader looks at a switch again without
/// news from the nodes.
const SWITCH_RECHECK: i64 = 10 * 1_000_000_000;

/// A prefix as text, "invalid Prefix" for none.
fn prefix_text(p: &Option<armada_spec::go::Prefix>) -> String {
    p.as_ref()
        .map(armada_spec::go::Prefix::string)
        .unwrap_or_else(|| "invalid Prefix".to_string())
}

/// The container address of every replica whose node
/// has a subnet, with its app ID, sorted by address; an address two apps
/// claim is left out.
pub(crate) fn network_endpoints(
    replicas: &[&Replica],
    subnets: &HashMap<String, String>,
) -> Vec<NetworkEndpoint> {
    let mut apps: BTreeMap<String, String> = BTreeMap::new();
    let mut clash = std::collections::HashSet::new();
    for r in replicas {
        let subnet = subnets.get(&r.node_id).map(String::as_str).unwrap_or("");
        if r.ip.is_empty() || r.done || !valid_replica_ip(&r.ip, subnet) {
            continue;
        }
        if let Some(a) = apps.get(&r.ip)
            && *a != r.app
        {
            clash.insert(r.ip.clone());
        }
        apps.insert(r.ip.clone(), r.app.clone());
    }
    apps.into_iter()
        .filter(|(ip, _)| !clash.contains(ip))
        .map(|(address, app)| NetworkEndpoint { address, app })
        .collect()
}

/// What a node reports about its side of a switch,
/// bounded: known modes and steps, peer names that are node names, and a
/// printable error. Anything else is none.
pub(crate) fn clean_switch_status(st: Option<&NetworkSwitchStatus>) -> Option<NetworkSwitchStatus> {
    let st = st?;
    if (st.to != NETWORK_PLAIN && st.to != NETWORK_WIREGUARD)
        || (st.step != SWITCH_PREPARE && st.step != SWITCH_MOVE)
    {
        return None;
    }
    let mut out = NetworkSwitchStatus {
        to: st.to.clone(),
        step: st.step.clone(),
        ready: st.ready,
        ..Default::default()
    };
    for name in &st.unreached {
        if out.unreached.len() == MAX_SWITCH_UNREACHED {
            break;
        }
        if validate_name(name).is_ok() {
            out.unreached.push(name.clone());
        }
    }
    if !st.error.is_empty() {
        out.error = clean_message(&st.error);
        out.ready = false;
    }
    Some(out)
}

impl Server {
    /// The cluster network, none for a cluster without one.
    async fn network(&self) -> Result<Option<Network>, armada_store::Error> {
        match self.store().get_network().await {
            Err(e) if e.kind == Kind::NotFound => Ok(None),
            Err(e) => Err(e),
            Ok(n) => Ok(Some(n)),
        }
    }

    /// The cluster network every agent applies (ADR 0025):
    /// the mode, the cluster CIDR, every node that has a subnet, and the
    /// container addresses of replicas; none for a cluster without one.
    pub(crate) async fn build_network(
        &self,
        nodes: &[Node],
        replicas: &[&Replica],
    ) -> Result<Option<NetworkConfig>, armada_store::Error> {
        let Some(n) = self.network().await? else {
            return Ok(None);
        };
        let mut cfg = NetworkConfig {
            mode: n.mode.clone(),
            cluster_cidr: prefix_text(&n.cluster_cidr),
            isolate_default: n.isolate_default,
            ..Default::default()
        };
        if let Some(p) = &n.mesh_cidr {
            cfg.mesh_cidr = p.string();
        }
        if let Some(sw) = &n.switch {
            cfg.switch_to = sw.to.clone();
            cfg.switch_step = sw.step.clone();
        }
        // Each site's relay (apps.rs, which Status shares).
        let relays = self.site_relays(nodes);
        let mut subnets = HashMap::new();
        for node in nodes {
            if node.subnet.is_empty() {
                continue;
            }
            subnets.insert(node.id.clone(), node.subnet.clone());
            cfg.peers.push(NetworkPeer {
                node: node.id.clone(),
                private_ip: node.private_ip.clone(),
                subnet: node.subnet.clone(),
                public_key: node.network_key.clone(),
                endpoint: node.endpoint.clone(),
                site: node.site.clone(),
                behind_nat: node.behind_nat,
                relay: relays.get(&node.site) == Some(&node.id),
            });
        }
        cfg.endpoints = network_endpoints(replicas, &subnets);
        Ok(Some(cfg))
    }

    /// The cluster network a machine joining a mesh, or from
    /// another site, brings its tunnels up with: every node, the new one
    /// included.
    pub(crate) async fn mesh_network(&self) -> Result<Option<NetworkConfig>, armada_store::Error> {
        let nodes = self.store().list_nodes().await?;
        self.build_network(&nodes, &[]).await
    }

    /// Which nodes the step of n's switch waits for: every
    /// node with a subnet that has connected and is not lost, until it
    /// reports the step done.
    pub(crate) fn switch_progress(
        &self,
        n: &Network,
        nodes: &[Node],
        now: &Time,
    ) -> NetworkSwitchProgress {
        let sw = n.switch.as_ref().expect("a switch");
        let mut p = NetworkSwitchProgress {
            from: n.mode.clone(),
            to: sw.to.clone(),
            step: sw.step.clone(),
            since_unix: sw.since.unix,
            ..Default::default()
        };
        let timeout = nanos(self.0.node_lost_timeout);
        let mut waiting = Vec::new();
        for node in nodes {
            if node.subnet.is_empty() || node.last_seen.is_zero() || node_lost(node, now, timeout) {
                continue;
            }
            let mut w = NodeSwitchWait {
                node: node.id.clone(),
                ..Default::default()
            };
            match self.session(&node.id) {
                None => w.disconnected = true,
                Some(sess) if !sess.caps.net_switch => w.unsupported = true,
                Some(_) => {
                    let st = self.0.usage.switch_status(&node.id).unwrap_or_default();
                    if st.to == sw.to && st.step == sw.step && st.ready {
                        continue;
                    }
                    if st.to == sw.to && st.step == sw.step {
                        w.unreached = st.unreached;
                        w.error = st.error;
                    }
                }
            }
            waiting.push(w);
        }
        waiting.sort_by(|a, b| a.node.cmp(&b.node));
        p.waiting_total = waiting.len() as i32;
        waiting.truncate(MAX_SWITCH_WAITING);
        p.waiting = waiting;
        p
    }

    /// Takes a network switch (ADR 0050) to its next step
    /// once no node holds the current one up.
    pub(crate) async fn advance_switch(
        &self,
        now: &Time,
        nodes: &[Node],
    ) -> Result<(), armada_store::Error> {
        let Some(n) = self.network().await? else {
            return Ok(());
        };
        let Some(sw) = n.switch.clone() else {
            return Ok(());
        };
        self.wake_after(SWITCH_RECHECK);
        if self.switch_progress(&n, nodes, now).waiting_total > 0 {
            return Ok(());
        }
        match self.store().advance_network_switch(&sw.to, &sw.step).await {
            // Changed since it was read; the next pass sees it.
            Err(e) if e.kind == Kind::Conflict => return Ok(()),
            Err(e) => return Err(e),
            Ok(()) => {}
        }
        if sw.step == SWITCH_PREPARE {
            self.0.log.info(
                "every node reaches its peers over the target transport; moving the routes",
                &[("from", n.mode.clone()), ("to", sw.to.clone())],
            );
            self.record(event(
                NODE,
                "*",
                "",
                "NetworkSwitchMoving",
                &format!(
                    "every node reaches its peers over {}; routing over it",
                    sw.to
                ),
            ))
            .await;
            return Ok(());
        }
        self.0.log.info(
            "the cluster network switched",
            &[("from", n.mode.clone()), ("to", sw.to.clone())],
        );
        self.record(event(
            NODE,
            "*",
            "",
            "NetworkSwitched",
            &format!("the cluster network switched from {} to {}", n.mode, sw.to),
        ))
        .await;
        Ok(())
    }

    /// Starts a switch of the cluster network's mode (ADR
    /// 0050), or gives one up during its prepare step.
    pub(crate) async fn set_network(&self, a: &Auth, to: &str) -> Result<(), Status> {
        if to != NETWORK_PLAIN && to != NETWORK_WIREGUARD {
            return Err(Status::new(
                Code::InvalidArgument,
                format!(
                    "a running cluster switches its network to {NETWORK_PLAIN} or {NETWORK_WIREGUARD}, not {}",
                    armada_spec::go::quote(to)
                ),
            ));
        }
        let n = match self.store().get_network().await {
            Err(e) if e.kind == Kind::NotFound => {
                return Err(Status::new(
                    Code::FailedPrecondition,
                    "this cluster has no cluster network (it was created before ADR 0025); its mode cannot be switched",
                ));
            }
            Err(e) => return Err(store_err(&e)),
            Ok(n) => n,
        };
        let starting = n.switch.is_none() && to != n.mode;
        if starting {
            let mut old: Vec<String> = self
                .sessions()
                .iter()
                .filter(|s| !s.caps.net_switch)
                .map(|s| s.node_id.clone())
                .collect();
            if !old.is_empty() {
                old.sort();
                return Err(Status::new(
                    Code::FailedPrecondition,
                    format!(
                        "these nodes run a version that cannot switch the network's mode; upgrade them first: {}",
                        old.join(", ")
                    ),
                ));
            }
        }
        if let Err(e) = self.store().start_network_switch(to, &a.actor()).await {
            if e.kind == Kind::Conflict || e.kind == Kind::Precondition {
                return Err(Status::new(Code::FailedPrecondition, e.msg));
            }
            return Err(store_err(&e));
        }
        if starting {
            self.0.log.info(
                "switching the cluster network",
                &[
                    ("from", n.mode.clone()),
                    ("to", to.to_string()),
                    ("by", a.actor()),
                ],
            );
            self.record(event(
                NODE,
                "*",
                "",
                "NetworkSwitchStarted",
                &format!("switching the cluster network from {} to {to}", n.mode),
            ))
            .await;
        } else if let Some(sw) = &n.switch
            && to == n.mode
        {
            self.0.log.info(
                "gave up switching the cluster network",
                &[("to", sw.to.clone()), ("by", a.actor())],
            );
            self.record(event(
                NODE,
                "*",
                "",
                "NetworkSwitchGivenUp",
                &format!(
                    "gave up switching the cluster network to {}; staying on {}",
                    sw.to, n.mode
                ),
            ))
            .await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_switch_status_bounds() {
        assert!(
            clean_switch_status(Some(&NetworkSwitchStatus {
                to: "mesh".into(),
                step: SWITCH_PREPARE.into(),
                ..Default::default()
            }))
            .is_none()
        );
        let st = clean_switch_status(Some(&NetworkSwitchStatus {
            to: NETWORK_WIREGUARD.into(),
            step: SWITCH_MOVE.into(),
            ready: true,
            unreached: vec!["n1".into(), "Bad;Name".into()],
            error: "boom\x1b".into(),
        }))
        .unwrap();
        assert_eq!(st.unreached, vec!["n1".to_string()]);
        assert!(!st.ready);
        assert_eq!(st.error, "boom ");
    }

    #[test]
    fn endpoints_leave_out_clashes() {
        let subnets = HashMap::from([("n1".to_string(), "10.120.0.0/24".to_string())]);
        let r = |id: &str, app: &str, ip: &str, done: bool| Replica {
            id: id.into(),
            app: app.into(),
            node_id: "n1".into(),
            ip: ip.into(),
            done,
            ..Default::default()
        };
        let rs = [
            r("a", "web", "10.120.0.5", false),
            r("b", "api", "10.120.0.5", false),
            r("c", "web", "10.120.0.10", false),
            r("d", "web", "10.120.0.11", true),
            r("e", "web", "10.120.0.1", false),
        ];
        let refs: Vec<&Replica> = rs.iter().collect();
        let eps = network_endpoints(&refs, &subnets);
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].address, "10.120.0.10");
    }
}

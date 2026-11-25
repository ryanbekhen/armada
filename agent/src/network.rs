//! The network pass as the agent sees it (Go's applyNetwork,
//! applyNetworkNow, listLocal, rotateNetworkKey, and reportPeers): the
//! cluster network applied before the proxy, the node's containers handed
//! to the proxy, the firewall, and the resolver in that order, the
//! WireGuard key replaced on request, and what the network tells the
//! leader. armada-node's network code behind [`Network`] comes with the
//! supervisor runtime (ADR 0055, item 16c); the parity tests use a fake.

use std::net::IpAddr;
use std::sync::Arc;

use armada_proto::armada::v1 as pb;

use crate::agent::{Agent, Inner, lock, managed};
use crate::proxy::{BoxFut, Clients};
use crate::runtime::{self, LABEL_APP, Runtime, stopped};

/// The cluster network on the node (ADR 0025), with the optional parts of
/// Go's NetworkSwitcher, PeerChecker, WireGuardReporter, and KeyRotator.
pub trait Network: Send + Sync + 'static {
    /// Makes the node's tunnel, routes, and firewall match cfg; called
    /// again on every pass, so it repairs what drifted. local maps this
    /// node's containers to their apps (None on nodes whose containers are
    /// not in the node subnet).
    fn apply<'a>(
        &'a self,
        cfg: &'a pb::NetworkConfig,
        local: Option<&'a Clients>,
    ) -> BoxFut<'a, Result<(), String>>;

    /// Whether it switches modes while the cluster runs (ADR 0050).
    fn switches(&self) -> bool {
        false
    }
    /// Its side of a switch; None while none runs.
    fn switch_status(&self) -> BoxFut<'_, Option<pb::NetworkSwitchStatus>> {
        Box::pin(async { None })
    }
    /// Whether it tells which WireGuard peers are unreachable.
    fn checks_peers(&self) -> bool {
        false
    }
    /// Their node names, sorted, at most 32.
    fn unreachable_peers(&self) -> BoxFut<'_, Vec<String>> {
        Box::pin(async { Vec::new() })
    }
    /// Whether it tells if its WireGuard runs in userspace.
    fn reports_wireguard(&self) -> bool {
        false
    }
    fn wireguard_userspace(&self) -> BoxFut<'_, bool> {
        Box::pin(async { false })
    }
    /// Whether its key can be replaced while it runs.
    fn rotates_keys(&self) -> bool {
        false
    }
    /// Writes a new key and returns its public half.
    fn rotate_key(&self) -> BoxFut<'_, Result<String, String>> {
        Box::pin(async { Err("this network rotates no keys".to_string()) })
    }
}

/// Go's netip.ParseAddr for the addresses runtimes report.
pub(crate) fn parse_addr(s: &str) -> Option<IpAddr> {
    s.parse().ok()
}

impl<R: Runtime> Agent<R> {
    /// Replaces the node's WireGuard key and announces its public half.
    pub async fn rotate_network_key(&self) {
        self.inner.rotate_network_key().await
    }
}

impl<R: Runtime> Inner<R> {
    pub(crate) fn set_network(&self, cfg: Option<&pb::NetworkConfig>) {
        if let Some(c) = cfg {
            lock(&self.st).network_desired = Some(c.clone());
        }
    }

    /// Applies the cluster network before the proxy and the containers
    /// that use it; a failure leaves the node on the network it has and is
    /// retried on the next pass.
    pub(crate) async fn apply_network(&self) {
        if self.cfg.network.is_none() {
            return;
        }
        if self.cfg.unpublished
            && let Ok(local) = self.list_local().await
        {
            lock(&self.st).local = Some(local);
        }
        self.apply_network_now().await;
    }

    /// Applies the last cluster network received with the containers known
    /// on this node, and tells the resolver who asks.
    pub(crate) async fn apply_network_now(&self) {
        let Some(net) = self.cfg.network.clone() else {
            return;
        };
        let (want, local) = {
            let st = lock(&self.st);
            let local = self
                .cfg
                .unpublished
                .then(|| st.local.clone().unwrap_or_default());
            (st.network_desired.clone(), local)
        };
        let Some(want) = want else { return };
        if let (Some(px), Some(l)) = (&self.cfg.proxy, &local)
            && px.sets_clients()
            && let Err(e) = px.set_clients(l).await
        {
            self.log
                .warn("updating the proxy's callers failed", &[("err", e)]);
        }
        let res = net.apply(&want, local.as_ref()).await;
        // The resolver last: it holds a new container's first lookups until
        // it learns the container, and by then the proxy and the firewall
        // know it too.
        if let (Some(l), Some(dns)) = (&local, &self.cfg.dns) {
            dns.set_clients(l).await;
        }
        let msg = res.as_ref().err().cloned().unwrap_or_default();
        let changed = {
            let mut st = lock(&self.st);
            let changed = msg != st.network_failed;
            st.network_failed = msg;
            changed
        };
        match res {
            Err(e) if changed => self
                .log
                .error("applying the cluster network failed", &[("err", e)]),
            Ok(()) if changed => self.log.info("cluster network applied again", &[]),
            _ => {}
        }
    }

    /// Maps the addresses of this node's running containers to their apps.
    pub(crate) async fn list_local(&self) -> runtime::Result<Clients> {
        let cs = self.rt.list(&managed()).await?;
        let mut local = Clients::new();
        for c in cs {
            let app = c.label(LABEL_APP);
            let Some(ip) = parse_addr(&c.ip) else {
                continue;
            };
            if app.is_empty() || stopped(&c.state) {
                continue;
            }
            local.insert(ip, app.to_string());
        }
        Ok(local)
    }

    /// Notes a started container's address before the control plane
    /// hears of it: until then it is an unknown address and reaches little.
    pub(crate) fn note_local(&self, ip: &str, app: &str) {
        if !(self.cfg.unpublished && self.cfg.network.is_some()) {
            return;
        }
        if let Some(ip) = parse_addr(ip) {
            lock(&self.st)
                .local
                .get_or_insert_with(Clients::new)
                .insert(ip, app.to_string());
        }
    }

    /// Replaces the node's WireGuard key and announces the new public half
    /// on the stream; the next Hello carries it too.
    pub(crate) async fn rotate_network_key(&self) {
        let Some(net) = self.cfg.network.clone().filter(|n| n.rotates_keys()) else {
            return;
        };
        let _g = self.key_mu.lock().await;
        let public = match net.rotate_key().await {
            Ok(p) => p,
            Err(e) => {
                self.log.error("rotate the network key", &[("err", e)]);
                return;
            }
        };
        lock(&self.st).network_key = public.clone();
        let Some(tx) = lock(&self.stream).tx.clone() else {
            return; // the next Hello announces it
        };
        let msg = pb::AgentMessage {
            msg: Some(pb::agent_message::Msg::NetworkKey(pb::NetworkKeyChanged {
                public_key: public,
            })),
        };
        if let Err(e) = tx.try_send(msg) {
            self.log
                .warn("announce the new network key", &[("err", e.to_string())]);
        }
    }

    /// The node's network when it switches modes.
    pub(crate) fn switcher(&self) -> Option<Arc<dyn Network>> {
        self.cfg.network.clone().filter(|n| n.switches())
    }

    /// Adds what the network knows about its WireGuard to report.
    pub(crate) async fn report_peers(&self, report: &mut pb::UsageReport) {
        let Some(net) = self.cfg.network.clone().filter(|n| n.checks_peers()) else {
            return;
        };
        report.peers_checked = true;
        report.unreachable_peers = net.unreachable_peers().await;
        if net.reports_wireguard() {
            report.wireguard_userspace = net.wireguard_userspace().await;
        }
    }
}

//! The proxy pass as the agent sees it (Go's applyProxy, certs.go, and the
//! load part of usage.go): the node's ingress configuration handed to a
//! [`Proxy`], its certificates fetched by reference, the names the node's
//! resolver answers, and the requests in progress per replica. The HAProxy
//! driver behind the trait is [`crate::haproxy::Driver`] and the resolver
//! [`crate::dnsprocess::DnsProcess`] (ADR 0055, item 16d); the parity
//! tests implement them with fakes.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use armada_proto::armada::v1 as pb;
use sha2::{Digest, Sha256};

use crate::agent::{Inner, lock};
use crate::runtime::Runtime;

/// A boxed future: the seams are trait objects.
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The addresses of this node's containers and their app IDs.
pub type Clients = BTreeMap<IpAddr, String>;

/// How many certificates one GetCertificates call asks for.
pub const CERT_BATCH: usize = 256;

/// The busy replicas one usage report carries at most (Go's
/// proxy.MaxLoadEntries).
pub const MAX_LOAD_ENTRIES: usize = 20_000;

/// Requests in progress at a server and sent to it so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerLoad {
    pub in_flight: i64,
    /// Keeps growing across reloads; may start over after a crash.
    pub total: i64,
}

/// The node's proxy (Go's proxy.Driver with its optional ClientSetter and
/// LoadReader). The configuration it gets carries every certificate's PEM.
pub trait Proxy: Send + Sync + 'static {
    /// Makes the proxy serve cfg; on failure the previous one stays.
    fn apply<'a>(&'a self, cfg: &'a pb::ProxyConfig) -> BoxFut<'a, Result<(), String>>;
    /// Whether the proxy runs and answers.
    fn health(&self) -> BoxFut<'_, Result<(), String>>;
    /// Whether its internal frontend checks who calls (ClientSetter).
    fn sets_clients(&self) -> bool {
        false
    }
    fn set_clients<'a>(&'a self, _clients: &'a Clients) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    /// Whether it counts requests per server (LoadReader).
    fn reads_load(&self) -> bool {
        false
    }
    fn load(&self) -> BoxFut<'_, Result<BTreeMap<String, ServerLoad>, String>> {
        Box::pin(async { Err("this proxy counts no requests".to_string()) })
    }
    /// Whether it runs in a container the agent may move to crun (ADR
    /// 0056).
    fn moves_to_crun(&self) -> bool {
        false
    }
    /// Whether its container is one runc created.
    fn on_runc(&self) -> BoxFut<'_, Result<bool, String>> {
        Box::pin(async { Ok(false) })
    }
    /// Replaces its container with one crun creates, keeping the
    /// configuration it serves.
    fn move_to_crun(&self) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
}

/// Where certificates named by reference come from (AgentService's
/// GetCertificates).
pub trait CertificateSource: Send + Sync + 'static {
    fn get_certificates(
        &self,
        names: Vec<String>,
    ) -> BoxFut<'_, Result<Vec<pb::ProxyCertificate>, String>>;
}

/// The node's resolver for `<app>.internal` (Go's InternalDNS).
pub trait InternalDns: Send + Sync + 'static {
    /// The nameserver containers are given.
    fn address(&self) -> String;
    /// Replaces the apps that resolve under .internal.
    fn set_names(&self, apps: Vec<String>) -> BoxFut<'_, ()>;
    /// Maps this node's containers to their apps, so each resolves only
    /// its own space's names.
    fn set_clients<'a>(&'a self, clients: &'a Clients) -> BoxFut<'a, ()>;
}

/// A certificate fetched by reference.
#[derive(Clone)]
pub(crate) struct CachedCert {
    sum: [u8; 32],
    pem: Vec<u8>,
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// The apps the resolver answers for a configuration: the internal rules'
/// hosts and the internal TCP apps, in order, once each.
pub fn internal_names(cfg: &pb::ProxyConfig) -> Vec<String> {
    let mut apps: Vec<String> = Vec::new();
    for r in &cfg.rules {
        let name = r
            .host
            .strip_suffix(armada_spec::validate::INTERNAL_SUFFIX)
            .unwrap_or(&r.host);
        if r.internal && !apps.iter().any(|a| a == name) {
            apps.push(name.to_string());
        }
    }
    for r in &cfg.tcp_routes {
        if !apps.contains(&r.backend) {
            apps.push(r.backend.clone());
        }
    }
    apps
}

impl<R: Runtime> Inner<R> {
    /// The source of certificates: the configured one, else the session's.
    fn certificate_source(&self) -> Option<Arc<dyn CertificateSource>> {
        self.cfg
            .certificates
            .clone()
            .or_else(|| lock(&self.cert_source).clone())
    }

    /// Turns want into the configuration the proxy gets, fetching the
    /// certificates it names by reference that the agent does not have, or
    /// whose content changed; each is checked against the assignment's
    /// digest, and certificates no longer named are forgotten.
    pub(crate) async fn with_certificates(
        &self,
        want: &pb::ProxyConfig,
    ) -> Result<pb::ProxyConfig, String> {
        let have = lock(&self.st).certs.clone();
        let mut next: HashMap<String, CachedCert> = HashMap::new();
        let mut missing = Vec::new();
        let mut want_sum: HashMap<String, Vec<u8>> = HashMap::new();
        for c in &want.certificates {
            if !c.pem.is_empty() {
                continue;
            }
            want_sum.insert(c.name.clone(), c.sha256.clone());
            if let Some(h) = have.get(&c.name)
                && h.sum[..] == c.sha256[..]
            {
                next.insert(c.name.clone(), h.clone());
                continue;
            }
            missing.push(c.name.clone());
        }
        for names in missing.chunks(CERT_BATCH) {
            let Some(src) = self.certificate_source() else {
                return Err("no connection to the control plane".to_string());
            };
            for c in src.get_certificates(names.to_vec()).await? {
                let sum = sha256(&c.pem);
                match want_sum.get(&c.name) {
                    // Renewed since this assignment: the next one names it.
                    Some(w) if w[..] == sum[..] => {}
                    _ => continue,
                }
                next.insert(c.name.clone(), CachedCert { sum, pem: c.pem });
            }
        }
        let mut cfg = want.clone();
        for c in &mut cfg.certificates {
            if !c.pem.is_empty() {
                continue;
            }
            let Some(got) = next.get(&c.name) else {
                return Err(format!("certificate {} is not available", c.name));
            };
            c.pem = got.pem.clone();
        }
        lock(&self.st).certs = next;
        Ok(cfg)
    }

    /// Hands the latest ingress configuration to the proxy. A failure is
    /// logged and retried on the next pass while the proxy keeps its last
    /// configuration; an unchanged one is applied again when the proxy is
    /// unhealthy, which starts it if it stopped. The configuration holds
    /// TLS keys and is never logged.
    pub(crate) async fn apply_proxy(&self) {
        let Some(px) = self.cfg.proxy.clone() else {
            return;
        };
        let (want, have) = {
            let st = lock(&self.st);
            (st.proxy_desired.clone(), st.proxy_applied.clone())
        };
        let Some(want) = want else { return };
        if have.as_ref() == Some(&want) {
            match px.health().await {
                Ok(()) => return,
                Err(e) => self.log.warn(
                    "proxy unhealthy, applying its configuration again",
                    &[("err", e)],
                ),
            }
        }
        let cfg = match self.with_certificates(&want).await {
            Ok(c) => c,
            Err(e) => {
                self.log
                    .error("fetching proxy certificates failed", &[("err", e)]);
                return;
            }
        };
        if let Err(e) = px.apply(&cfg).await {
            self.log
                .error("applying proxy config failed", &[("err", e)]);
            return;
        }
        if let Some(dns) = &self.cfg.dns {
            // Resolve exactly the names the proxy now routes.
            dns.set_names(internal_names(&cfg)).await;
        }
        lock(&self.st).proxy_applied = Some(want);
        self.proxy_changed.send_modify(|n| *n += 1);
    }

    /// Adds the requests in progress per replica at the node's proxy, and
    /// those sent since the previous sample (a counter that went back, after
    /// a reload, starts over), to report; an unreadable proxy leaves it
    /// unmeasured. Returns the totals for the next sample.
    pub(crate) async fn sample_load(
        &self,
        px: &dyn Proxy,
        report: &mut pb::UsageReport,
        prev: HashMap<String, i64>,
    ) -> HashMap<String, i64> {
        let load = match px.load().await {
            Ok(l) => l,
            Err(e) => {
                self.log.debug("read proxy load", &[("err", e)]);
                return prev;
            }
        };
        report.load_measured = true;
        let mut next = HashMap::with_capacity(load.len());
        for (id, l) in load {
            next.insert(id.clone(), l.total);
            let mut requests = 0;
            if let Some(p) = prev.get(&id) {
                requests = l.total - p;
                if requests < 0 {
                    requests = l.total;
                }
            }
            // Idle replicas count as zero: only busy ones are sent.
            if l.in_flight > 0 || requests > 0 {
                report.load.push(pb::ReplicaLoad {
                    id,
                    in_flight: l.in_flight,
                    requests,
                });
            }
        }
        if report.load.len() > MAX_LOAD_ENTRIES {
            // Unmeasured holds autoscaling instead of misleading it.
            self.log.warn(
                "proxy load not reported: too many busy replicas",
                &[("replicas", report.load.len().to_string())],
            );
            report.load.clear();
            report.load_measured = false;
        }
        next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_of_internal_routes() {
        let cfg = pb::ProxyConfig {
            rules: vec![
                pb::ProxyRule {
                    host: "api.internal".into(),
                    internal: true,
                    ..Default::default()
                },
                pb::ProxyRule {
                    host: "api.internal".into(),
                    internal: true,
                    path_prefix: "/x".into(),
                    ..Default::default()
                },
                pb::ProxyRule {
                    host: "www.example.com".into(),
                    ..Default::default()
                },
                pb::ProxyRule {
                    host: "web.s1.internal".into(),
                    internal: true,
                    ..Default::default()
                },
            ],
            tcp_routes: vec![
                pb::ProxyTcpRoute {
                    backend: "db".into(),
                    ..Default::default()
                },
                pb::ProxyTcpRoute {
                    backend: "api".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert_eq!(internal_names(&cfg), ["api", "web.s1", "db"]);
    }
}

//! Usage reports (ADR 0016, Go's usage.go): what the node's replicas use,
//! sampled every interval, a container whose network interface stayed
//! gone over two samples recreated, how the node runs containers, the
//! proxy's load, the network switch, and WireGuard peers. Volumes,
//! connection tracking, queues, sandboxes, and log export come with a later
//! part.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use armada_proto::armada::v1 as pb;

use crate::agent::{Agent, Inner, lock, managed};
use crate::clock;
use crate::runtime::{
    self, AgentStatus, Container, LABEL_REPLICA, LABEL_SYSTEM, Runtime, STATE_RUNNING,
};

/// How often the agent samples what its replicas use.
pub const DEFAULT_USAGE_INTERVAL: Duration = Duration::from_secs(10);

/// A container's cumulative use when it was sampled.
#[derive(Clone, Debug)]
pub struct UsageSample {
    container: String,
    cpu: Duration,
    egress: i64,
    oom_kills: i64,
    at: SystemTime,
    no_network: bool,
}

/// The samples of the last round, by replica.
pub type Samples = HashMap<String, UsageSample>;

/// What the usage loop keeps between rounds: the replicas' samples and the
/// proxy's request totals.
#[derive(Default)]
pub struct UsageState {
    pub samples: Samples,
    pub totals: HashMap<String, i64>,
}

/// How the node runs containers, as the leader reads it.
pub fn runtime_status(s: &AgentStatus) -> pb::RuntimeStatus {
    pb::RuntimeStatus {
        runc_containers: s.runc_containers.clamp(0, 1 << 20) as i32,
    }
}

impl<R: Runtime> Agent<R> {
    /// One round of sampling (sampleUsage): the report, None when the
    /// containers could not be listed, and the samples for the next round.
    pub async fn sample_usage(&self, prev: Samples) -> (Option<pb::UsageReport>, Samples) {
        self.inner.sample_usage(prev).await
    }

    /// One usage report as the loop sends it, None when it has nothing to
    /// say.
    pub async fn usage_report(&self, state: &mut UsageState) -> Option<pb::UsageReport> {
        self.inner.usage_report(state).await
    }
}

impl<R: Runtime> Inner<R> {
    /// Asks for a container whose network interface is gone to be
    /// recreated: no probe can succeed, and nothing else brings it back.
    fn restart_lost_network(&self, replica: &str, container: &str) {
        let reason = "its network interface is gone";
        lock(&self.st)
            .restarts
            .insert(container.to_string(), reason.to_string());
        self.log.warn(
            "restarting replica",
            &[
                ("replica", replica.to_string()),
                ("reason", reason.to_string()),
            ],
        );
        self.trigger.notify_one();
    }

    /// Samples every container of cs: in one round when the runtime
    /// samples many at once, else one by one.
    async fn sample_all(&self, cs: &[Container]) -> Vec<runtime::Result<runtime::Stats>> {
        let ids: Vec<String> = cs.iter().map(|c| c.id.clone()).collect();
        if !ids.is_empty()
            && let Some(r) = self.rt.stats_batch(&ids).await
            && r.len() == ids.len()
        {
            return r;
        }
        let mut out = Vec::with_capacity(ids.len());
        for id in &ids {
            out.push(self.rt.stats(id).await);
        }
        out
    }

    pub(crate) async fn sample_usage(&self, prev: Samples) -> (Option<pb::UsageReport>, Samples) {
        let cs = match self.rt.list(&managed()).await {
            Ok(cs) => cs,
            Err(_) => return (None, prev),
        };
        let sampled: Vec<Container> = cs
            .into_iter()
            .filter(|c| {
                !c.label(LABEL_REPLICA).is_empty()
                    && c.label(LABEL_SYSTEM).is_empty()
                    && c.state == STATE_RUNNING
            })
            .collect();
        let stats = self.sample_all(&sampled).await;
        let mut next = Samples::with_capacity(sampled.len());
        let mut report = pb::UsageReport::default();
        for (c, st) in sampled.iter().zip(stats) {
            let id = c.label(LABEL_REPLICA).to_string();
            let Ok(st) = st else { continue };
            let now = self.now();
            next.insert(
                id.clone(),
                UsageSample {
                    container: c.id.clone(),
                    cpu: st.cpu,
                    egress: st.egress_bytes,
                    oom_kills: st.oom_kills,
                    at: now,
                    no_network: st.network_lost,
                },
            );
            let p = prev.get(&id);
            if let Some(p) = p
                && p.container == c.id
                && p.no_network
                && st.network_lost
            {
                self.restart_lost_network(&id, &c.id);
            }
            let Some(p) = p else { continue };
            let elapsed = clock::sub(now, p.at);
            if p.container != c.id || st.cpu < p.cpu || elapsed <= 0 {
                continue;
            }
            let used = (st.cpu - p.cpu).as_nanos() as f64;
            report.replicas.push(pb::ReplicaUsage {
                id,
                cpu_millis: (used / elapsed as f64 * 1000.0) as i64,
                memory_bytes: st.memory_bytes,
                egress_bytes: (st.egress_bytes - p.egress).max(0),
                oom_kills: (st.oom_kills - p.oom_kills).max(0),
            });
        }
        (Some(report), next)
    }

    pub(crate) async fn usage_report(&self, state: &mut UsageState) -> Option<pb::UsageReport> {
        let mut report = pb::UsageReport::default();
        let mut sampled = false;
        if self.rt.can_stats() {
            let (r, next) = self.sample_usage(std::mem::take(&mut state.samples)).await;
            state.samples = next;
            if let Some(r) = r {
                report.replicas = r.replicas;
                sampled = true;
            }
        }
        if let Some(px) = self.cfg.proxy.clone().filter(|p| p.reads_load()) {
            let prev = std::mem::take(&mut state.totals);
            state.totals = self.sample_load(px.as_ref(), &mut report, prev).await;
        }
        self.side_usage(&mut report).await;
        if let Some(sw) = self.switcher() {
            report.network_switch = sw.switch_status().await;
        }
        self.report_peers(&mut report).await;
        if let Some(s) = self.rt.runtime_agent().await {
            report.runtime = Some(runtime_status(&s));
        }
        (sampled
            || report.runtime.is_some()
            || report.peers_checked
            || report.load_measured
            || report.volumes_measured
            || report.conntrack_max > 0
            || !report.queues.is_empty()
            || !report.sandboxes.is_empty()
            || !report.dropped_sandboxes.is_empty()
            || report.log_export.is_some()
            || report.network_switch.is_some())
        .then_some(report)
    }

    /// Sends a usage report on the session, if one is open.
    pub(crate) fn send_usage(&self, r: pb::UsageReport) {
        let Some(tx) = lock(&self.stream).tx.clone() else {
            return;
        };
        let msg = pb::AgentMessage {
            msg: Some(pb::agent_message::Msg::Usage(r)),
        };
        if let Err(e) = tx.try_send(msg) {
            self.log
                .warn("send usage failed", &[("err", e.to_string())]);
        }
    }

    /// Samples and reports every usage interval.
    pub(crate) async fn usage_loop(self: Arc<Self>) {
        if !self.rt.can_stats() {
            self.log.info(
                "the container runtime cannot sample containers; armada app top shows no usage for this node",
                &[],
            );
        }
        self.sample_conntrack(&mut pb::UsageReport::default()).await;
        let every = self.cfg.usage_interval;
        let mut t = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        let mut state = UsageState::default();
        loop {
            t.tick().await;
            if let Some(r) = self.usage_report(&mut state).await {
                self.send_usage(r);
            }
        }
    }
}

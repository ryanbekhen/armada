//! The cluster's status (Go's ClusterStatus in apps.go and runtimeProgress
//! in runtimeagent.go): counts, and the apps and nodes that need
//! attention, bounded however large the cluster is.

use armada_proto::armada::v1::{
    ClusterStatusRequest, ClusterStatusResponse, NodeRuntime, RuntimeProgress, RuntimeStatus,
};
use armada_spec::gotime::Time;
use armada_store::{Kind, NODE_READY, Node};
use tonic::{Code, Status};

use crate::grpc::Auth;
use crate::reconcile::{nanos, node_lost};
use crate::runtimemove::AGENT_SUPERVISOR_RUST;
use crate::{Server, store_err};

/// maxAttention bounds the apps ClusterStatus names.
const MAX_ATTENTION: usize = 20;
/// maxRuntimeOthers bounds the nodes ClusterStatus names that are not on
/// armada-node yet (ADR 0054).
const MAX_RUNTIME_OTHERS: usize = 20;

/// runtimeMoved: a node runs containers through armada-node with nothing
/// left of Go's image store or images to pull again.
fn runtime_moved(st: Option<&RuntimeStatus>) -> bool {
    st.is_some_and(|s| s.agent == AGENT_SUPERVISOR_RUST && !s.converting && s.images_to_pull == 0)
}

impl Server {
    /// ClusterStatus (cluster-admin only).
    pub(crate) async fn cluster_status(
        &self,
        a: &Auth,
        _req: ClusterStatusRequest,
    ) -> Result<ClusterStatusResponse, Status> {
        if !a.acc.admin() {
            return Err(Status::new(
                Code::PermissionDenied,
                "the cluster's status needs cluster-admin",
            ));
        }
        let apps = self.app_summaries(a, |_| true).await?;
        let mut resp = ClusterStatusResponse {
            apps: apps.len() as i32,
            ..Default::default()
        };
        for s in apps {
            match s.state.as_str() {
                crate::apps::APP_READY | crate::apps::APP_IDLE => {
                    resp.apps_ready += 1;
                    continue;
                }
                crate::apps::APP_PROGRESS => resp.apps_progressing += 1,
                crate::apps::APP_FAILING => resp.apps_failing += 1,
                _ => {}
            }
            resp.attention_total += 1;
            if resp.attention.len() < MAX_ATTENTION {
                resp.attention.push(s);
            }
        }
        let all = self.store().list_apps().await.map_err(|e| store_err(&e))?;
        resp.jobs = all
            .iter()
            .filter(|x| x.spec.as_deref().is_some_and(|sp| sp.is_job()))
            .count() as i32;
        let nodes = self.store().list_nodes().await.map_err(|e| store_err(&e))?;
        let lost = nanos(self.0.node_lost_timeout);
        for n in &nodes {
            resp.nodes += 1;
            if n.state == NODE_READY && !node_lost(n, &self.now(), lost) {
                resp.nodes_ready += 1;
            } else {
                resp.nodes_not_ready.push(n.id.clone());
            }
        }
        if !nodes.is_empty() {
            resp.runtime = Some(self.runtime_progress(&nodes, &self.now()));
        }
        resp.runtime_move = self.0.moves.lock().await.seen.clone();
        match self.store().get_network().await {
            Err(e) if e.kind == Kind::NotFound => {}
            Err(e) => return Err(store_err(&e)),
            Ok(n) if n.switch.is_some() => {
                resp.network_switch = Some(self.switch_progress(&n, &nodes, &self.now()));
            }
            Ok(_) => {}
        }
        resp.control_plane_backup = self
            .control_plane_backup_status()
            .await
            .map_err(|e| store_err(&e))?;
        Ok(resp)
    }

    /// runtimeProgress: where the nodes' move to armada-node stands (ADR
    /// 0054), from their latest reports.
    pub(crate) fn runtime_progress(&self, nodes: &[Node], now: &Time) -> RuntimeProgress {
        let mut p = RuntimeProgress {
            nodes: nodes.len() as i32,
            ..Default::default()
        };
        let mut others = Vec::new();
        for n in nodes {
            let st = self.0.usage.runtime_of(&n.id, now);
            if runtime_moved(st.as_ref()) {
                p.moved += 1;
                continue;
            }
            others.push(NodeRuntime {
                node: n.id.clone(),
                status: st,
            });
        }
        others.sort_by(|a, b| a.node.cmp(&b.node));
        p.others_total = others.len() as i32;
        others.truncate(MAX_RUNTIME_OTHERS);
        p.others = others;
        p
    }
}

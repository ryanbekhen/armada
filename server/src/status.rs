//! The cluster's status: counts, and the apps and nodes that need
//! attention, bounded however large the cluster is.

use armada_proto::armada::v1::{ClusterStatusRequest, ClusterStatusResponse};
use armada_store::{Kind, NODE_READY};
use tonic::{Code, Status};

use crate::grpc::Auth;
use crate::reconcile::{nanos, node_lost};
use crate::{Server, store_err};

/// The most apps ClusterStatus names.
const MAX_ATTENTION: usize = 20;

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
        resp.state_move = self.state_move_status().await.map_err(|e| store_err(&e))?;
        Ok(resp)
    }
}

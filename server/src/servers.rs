//! Control plane nodes: the recorded servers joined
//! with the etcd membership, the API addresses agents and clients are
//! given, learners promoted by the leader, and a term's start.

use std::collections::HashMap;

use armada_proto::armada::v1::{
    ListServersRequest, ListServersResponse, RemoveServerRequest, RemoveServerResponse, ServerInfo,
};
use armada_store::{NODE_READY, NODE_UNKNOWN, NodeStatus};
use tonic::{Code, Status};

use crate::cluster::MemberInfo;
use crate::grpc::Auth;
use crate::{Server, store_err};

/// A control plane node as the leader sees it.
pub(crate) struct ServerView {
    pub rec: armada_store::Server,
    pub member: bool,
    pub voting: bool,
    pub info: MemberInfo,
}

impl Server {
    /// The recorded control plane nodes joined with the etcd membership;
    /// without a Cluster every record counts as a voting member.
    pub(crate) async fn servers(&self) -> Result<Vec<ServerView>, armada_store::Error> {
        let recs = self.store().list_servers().await?;
        let Some(cluster) = &self.0.cluster else {
            return Ok(recs
                .into_iter()
                .map(|rec| ServerView {
                    rec,
                    member: true,
                    voting: true,
                    info: MemberInfo::default(),
                })
                .collect());
        };
        let members = cluster
            .members()
            .await
            .map_err(armada_store::Error::other)?;
        let by_id: HashMap<u64, MemberInfo> = members.into_iter().map(|m| (m.id, m)).collect();
        Ok(recs
            .into_iter()
            .map(|rec| {
                let m = by_id.get(&rec.member_id).cloned();
                ServerView {
                    member: m.is_some(),
                    voting: m.as_ref().is_some_and(|m| !m.learner),
                    info: m.unwrap_or_default(),
                    rec,
                }
            })
            .collect())
    }

    /// The API addresses agents may connect to: every control plane node
    /// that is an etcd member, in name order.
    pub(crate) async fn endpoints(&self) -> Result<Vec<String>, armada_store::Error> {
        let mut out: Vec<String> = self
            .servers()
            .await?
            .into_iter()
            .filter(|v| v.member && !v.rec.api_addr.is_empty())
            .map(|v| v.rec.api_addr)
            .collect();
        if out.is_empty() && !self.0.api_addr.is_empty() {
            out = vec![self.0.api_addr.clone()];
        }
        Ok(out)
    }

    /// Promotes servers that joined and caught up.
    pub(crate) async fn promote_learners(&self) {
        let Some(cluster) = &self.0.cluster else {
            return;
        };
        let promoted = match cluster.promote().await {
            Ok(p) => p,
            Err(e) => {
                self.0.log.warn("promote joining servers", &[("err", e)]);
                Vec::new()
            }
        };
        for name in promoted {
            self.0
                .log
                .info("server promoted to a voting member", &[("server", name)]);
            self.trigger();
        }
    }

    /// Prepares the state for a new leadership term: nodes recorded as
    /// ready start over as unknown, last seen now.
    pub(crate) async fn start_term(&self) -> Result<(), armada_store::Error> {
        let nodes = self.store().list_nodes().await?;
        let now = self.now();
        for n in nodes {
            if n.state != NODE_READY || self.session(&n.id).is_some() {
                continue;
            }
            self.store()
                .set_node_status(
                    &n.id,
                    &NodeStatus {
                        state: NODE_UNKNOWN.to_string(),
                        last_seen: now.clone(),
                        cpu_millis: n.cpu_millis,
                        memory_bytes: n.memory_bytes,
                        jobs: n.jobs,
                        volumes: n.volumes,
                        containers: n.containers,
                        nfs: n.nfs,
                        ..Default::default()
                    },
                )
                .await?;
        }
        Ok(())
    }

    /// ListServers.
    pub(crate) async fn list_servers(
        &self,
        _a: &Auth,
        _req: ListServersRequest,
    ) -> Result<ListServersResponse, Status> {
        let views = self
            .servers()
            .await
            .map_err(|_| Status::new(Code::Unavailable, "list servers"))?;
        let schema = self
            .store()
            .stored_schema()
            .await
            .map_err(|_| Status::new(Code::Unavailable, "read state schema"))?;
        let mut out = ListServersResponse {
            servers: Vec::with_capacity(views.len()),
            state_schema: schema as i32,
        };
        for v in views {
            let mut info = ServerInfo {
                name: v.rec.name.clone(),
                private_ip: v.rec.private_ip.clone(),
                api_addr: v.rec.api_addr.clone(),
                leader: v.rec.name == self.0.name,
                voting: v.voting,
                member: v.member,
                reachable: v.member && self.0.cluster.is_none(),
                schema: v.rec.schema as i32,
                version: v.rec.version.clone(),
            };
            if v.member
                && let Some(c) = &self.0.cluster
            {
                info.reachable = c.reachable(&v.info).await;
            }
            out.servers.push(info);
        }
        Ok(out)
    }

    /// RemoveServer removes a control plane node from the etcd cluster and
    /// forgets it.
    pub(crate) async fn remove_server(
        &self,
        a: &Auth,
        req: RemoveServerRequest,
    ) -> Result<RemoveServerResponse, Status> {
        let Some(cluster) = self.0.cluster.clone() else {
            return Err(Status::new(
                Code::FailedPrecondition,
                "server membership is not managed by this server",
            ));
        };
        let name = req.name;
        if name == self.0.name {
            return Err(Status::new(
                Code::FailedPrecondition,
                format!(
                    "{name} is the leader serving this request; stop it first, and remove it once another server leads"
                ),
            ));
        }
        let views = self
            .servers()
            .await
            .map_err(|_| Status::new(Code::Unavailable, "list servers"))?;
        let Some(v) = views.iter().find(|v| v.rec.name == name) else {
            return Err(Status::new(
                Code::NotFound,
                format!("server {name} not found"),
            ));
        };
        if v.member {
            cluster
                .remove_member(v.rec.member_id)
                .await
                .map_err(|e| Status::new(Code::FailedPrecondition, e))?;
        }
        self.store()
            .remove_server(&name, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        self.0
            .log
            .info("server removed", &[("server", name), ("by", a.actor())]);
        self.trigger();
        Ok(RemoveServerResponse {})
    }
}

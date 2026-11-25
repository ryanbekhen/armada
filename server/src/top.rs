//! What replicas, nodes, and spaces use (ADR 0016, ADR 0026; Go's Top and
//! topSpaces in top.go), from the latest samples of the nodes' agents.

use std::collections::HashMap;

use armada_proto::armada::v1::{NodeTop, ReplicaTop, SpaceTop, TopRequest, TopResponse};
use armada_spec::gotime::Time;
use armada_spec::validate::split_app_id;
use armada_store::ReplicaFilter;
use tonic::Status;

use crate::assign::Revisions;
use crate::events::timestamp;
use crate::grpc::Auth;
use crate::schedule::{allocatable, reservation, reserved_of};
use crate::{Server, store_err};

impl Server {
    /// Top reports what replicas use from the latest samples of their
    /// nodes. A replica's usage only counts when it comes from the node the
    /// replica is assigned to.
    pub(crate) async fn top(&self, a: &Auth, req: TopRequest) -> Result<TopResponse, Status> {
        let mut filter = ReplicaFilter::default();
        if !req.app.is_empty() {
            a.acc.app(&req.app)?;
            self.store()
                .get_app(&req.app)
                .await
                .map_err(|e| store_err(&e))?;
            filter.app = req.app.clone();
        }
        let mut reps = self
            .store()
            .list_replicas(&filter)
            .await
            .map_err(|e| store_err(&e))?;
        // Finished job attempts keep a stopped container for their logs only.
        reps.retain(|r| !r.done && a.acc.sees(&r.app));
        let now = self.now();
        let mut revs = Revisions::new(self);
        revs.preload(&[], &reps).await;
        let reserved = revs.reserved(&reps).await;

        let mut resp = TopResponse::default();
        for r in &reps {
            let mut rt = ReplicaTop {
                id: r.id.clone(),
                app: r.app.clone(),
                node_id: r.node_id.clone(),
                state: r.state.clone(),
                ..Default::default()
            };
            if let Ok(rev) = revs.get(&r.revision).await {
                let res = reservation(&rev);
                rt.cpu_reserved_millis = res.cpu;
                rt.memory_limit_bytes = res.mem;
                if rev.spec().nano_cpus() > 0 {
                    rt.cpu_limit_millis = res.cpu;
                }
            }
            if let Some(n) = self.0.usage.node(&r.node_id, &now)
                && let Some(ru) = n.replicas.get(&r.id)
            {
                rt.measured = true;
                rt.cpu_millis = ru.cpu;
                rt.memory_bytes = ru.mem;
                rt.sampled_at = Some(timestamp(&n.at));
            }
            resp.replicas.push(rt);
        }
        if !req.app.is_empty() {
            return Ok(resp);
        }
        self.top_spaces(a, &mut resp, &now)
            .await
            .map_err(|e| store_err(&e))?;

        let nodes = self.store().list_nodes().await.map_err(|e| store_err(&e))?;
        let servers = self
            .store()
            .list_servers()
            .await
            .map_err(|e| store_err(&e))?;
        for n in allocatable(&nodes, &servers) {
            let sample = self.0.usage.node(&n.id, &now);
            let mut nt = NodeTop {
                id: n.id.clone(),
                cpu_allocatable_millis: n.cpu_millis,
                memory_allocatable_bytes: n.memory_bytes,
                measured: sample.is_some(),
                ..Default::default()
            };
            if let Some(s) = &sample {
                nt.conntrack_entries = s.conntrack_entries;
                nt.conntrack_max = s.conntrack_max;
            }
            for r in reps.iter().filter(|r| r.node_id == n.id) {
                nt.replicas += 1;
                let res = reserved_of(r, &reserved);
                nt.cpu_reserved_millis += res.cpu;
                nt.memory_reserved_bytes += res.mem;
                if let Some(ru) = sample.as_ref().and_then(|s| s.replicas.get(&r.id)) {
                    nt.cpu_millis += ru.cpu;
                    nt.memory_bytes += ru.mem;
                }
            }
            resp.nodes.push(nt);
        }
        if !a.acc.admin() {
            resp.nodes.clear();
        }
        Ok(resp)
    }

    /// topSpaces adds up what the replicas in resp use per space, for the
    /// spaces the caller may manage (ADR 0026).
    async fn top_spaces(
        &self,
        a: &Auth,
        resp: &mut TopResponse,
        now: &Time,
    ) -> Result<(), armada_store::Error> {
        let spaces = self.store().list_spaces().await?;
        let vols = self.store().list_volumes("").await?;
        let mut by_name: HashMap<String, usize> = HashMap::new();
        for p in &spaces {
            if a.acc.space(&p.name).is_err() {
                continue;
            }
            let (totals, since) = self.0.usage.space_totals(&p.name);
            by_name.insert(p.name.clone(), resp.spaces.len());
            resp.spaces.push(SpaceTop {
                name: p.name.clone(),
                requests: totals.requests,
                egress_bytes: totals.egress,
                ..Default::default()
            });
            if let Some(since) = since {
                resp.counted_since = Some(timestamp(&since));
            }
        }
        for r in &resp.replicas {
            let space = split_app_id(&r.app).map(|(p, _)| p).unwrap_or_default();
            let Some(&i) = by_name.get(space.as_str()) else {
                continue;
            };
            let pt = &mut resp.spaces[i];
            pt.replicas += 1;
            pt.cpu_reserved_millis += r.cpu_reserved_millis;
            pt.memory_reserved_bytes += r.memory_limit_bytes;
            if r.measured {
                pt.measured += 1;
                pt.cpu_millis += r.cpu_millis;
                pt.memory_bytes += r.memory_bytes;
            }
        }
        for v in &vols {
            let space = split_app_id(&v.app).map(|(p, _)| p).unwrap_or_default();
            if let Some(&i) = by_name.get(space.as_str())
                && let Some(b) = self.0.usage.volume(&v.node, &v.app, &v.name, now)
            {
                resp.spaces[i].volume_bytes += b;
            }
        }
        Ok(())
    }
}

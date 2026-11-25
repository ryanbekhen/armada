//! Where each replica was created (placements.go, ADR 0043).

use std::collections::BTreeMap;

use armada_proto::etcd::etcdserverpb as pb;
use armada_spec::gotime::Time;

use crate::apps::replica_prefix;
use crate::client::op;
use crate::error::Result;
use crate::gojson::unix_milli;
use crate::records::PlacementRec;
use crate::tx::*;
use crate::types::Replica;

pub(crate) const PFX_PLACEMENTS: &str = "placements/";

/// placementBatch bounds the deletes of one PrunePlacements transaction.
const PLACEMENT_BATCH: usize = 1000;

impl Etx<'_> {
    pub(crate) fn put_placement(&mut self, r: &Replica, now: &Time) -> Result<()> {
        self.put(
            &format!("{PFX_PLACEMENTS}{}", r.id),
            &PlacementRec {
                app: r.app.clone(),
                node: r.node_id.clone(),
                at: unix_milli(now),
            },
        )
    }
}

impl Etcd {
    /// ReplicaPlacements returns the node of every recorded replica of app,
    /// gone ones included, by replica ID.
    pub async fn replica_placements(&self, app: &str) -> Result<BTreeMap<String, String>> {
        let mut out = BTreeMap::new();
        view!(self, |t| {
            out.clear();
            let pfx = format!("{PFX_PLACEMENTS}{}", replica_prefix(app));
            for (k, r) in t.list_into::<PlacementRec>(&pfx).await? {
                if r.app == app {
                    out.insert(k[PFX_PLACEMENTS.len()..].to_string(), r.node);
                }
            }
            for (_, r) in t.app_replicas(app).await? {
                out.insert(r.id, r.node_id);
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// PrunePlacements deletes the placement records written before
    /// before and returns how many it deleted.
    pub async fn prune_placements(&self, before: &Time) -> Result<i64> {
        let r = self
            .c
            .range(op::get_prefix(
                &format!("{}{PFX_PLACEMENTS}", self.prefix),
                0,
            ))
            .await?;
        let cut = unix_milli(before);
        let mut ops = Vec::new();
        let mut n = 0i64;
        for kv in r.kvs {
            if let Ok(p) = serde_json::from_slice::<PlacementRec>(&kv.value)
                && p.at >= cut
            {
                continue;
            }
            ops.push(op::delete(&String::from_utf8_lossy(&kv.key)));
            if ops.len() == PLACEMENT_BATCH {
                self.flush_deletes(&mut ops, &mut n).await?;
            }
        }
        self.flush_deletes(&mut ops, &mut n).await?;
        Ok(n)
    }

    async fn flush_deletes(&self, ops: &mut Vec<pb::RequestOp>, n: &mut i64) -> Result<()> {
        if ops.is_empty() {
            return Ok(());
        }
        let k = ops.len() as i64;
        self.c
            .txn(pb::TxnRequest {
                compare: Vec::new(),
                success: std::mem::take(ops),
                failure: Vec::new(),
            })
            .await?;
        *n += k;
        Ok(())
    }
}

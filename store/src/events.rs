//! Events (events.go, ADR 0018): expiring records outside the state
//! transaction, written only while a fenced store still leads.

use armada_proto::etcd::etcdserverpb as pb;
use armada_spec::gotime::Time;

use crate::client::op;
use crate::error::{Error, Kind, Result};
use crate::gojson::{decode, from_ms, marshal, unix_milli, unix_nano};
use crate::records::EventRec;
use crate::tx::Etcd;
use crate::types::Event;

pub(crate) const PFX_EVENTS: &str = "events/";

/// EventTTL: how long events are kept.
pub const EVENT_TTL_SECONDS: i64 = 24 * 3600;

/// eventLeaseSpan: one etcd lease per hour.
const EVENT_LEASE_SPAN: i64 = 3600;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Etcd {
    /// The lease of the hour at falls in, granted once per hour.
    async fn event_lease(&self, at: &Time) -> Result<i64> {
        let bucket = at.truncate_seconds(EVENT_LEASE_SPAN).unix;
        let mut l = self.leases.lock().await;
        if l.1 != 0 && l.0 == bucket {
            return Ok(l.1);
        }
        let id = self.c.grant(EVENT_TTL_SECONDS + EVENT_LEASE_SPAN).await?;
        *l = (bucket, id);
        Ok(id)
    }

    /// PutEvent stores e under a new key ordered by e.last and deletes the
    /// key replace, if set; it returns the new key.
    pub async fn put_event(&self, e: &Event, replace: &str) -> Result<String> {
        let lease = self.event_lease(&e.last).await?;
        let b = marshal(&EventRec {
            kind: e.kind.clone(),
            object: e.object.clone(),
            app: e.app.clone(),
            node: e.node.clone(),
            reason: e.reason.clone(),
            message: e.message.clone(),
            count: e.count,
            first: unix_milli(&e.first),
            last: unix_milli(&e.last),
        });
        let mut suffix = [0u8; 4];
        self.random(&mut suffix);
        let key = format!("{PFX_EVENTS}{:020}-{}", unix_nano(&e.last), hex(&suffix));
        let mut ops = vec![op::put(&format!("{}{key}", self.prefix), &b, lease)];
        if !replace.is_empty() && replace != key {
            ops.push(op::delete(&format!("{}{replace}", self.prefix)));
        }
        let mut cmps = Vec::new();
        if let Some((k, rev)) = self.fence() {
            cmps.push(op::created_at(k, *rev));
        }
        cmps.push(op::created_at(&self.moving_key(), 0));
        let r = self
            .c
            .txn(pb::TxnRequest {
                compare: cmps,
                success: ops,
                failure: Vec::new(),
            })
            .await?;
        if !r.succeeded {
            return Err(self.refused(Error::bare(Kind::NotLeader)).await);
        }
        Ok(key)
    }

    /// ListEvents returns the events that last happened at or after since,
    /// oldest first.
    pub async fn list_events(&self, since: &Time) -> Result<Vec<Event>> {
        let from = format!("{}{PFX_EVENTS}{:020}", self.prefix, unix_nano(since).max(0));
        let r = self
            .c
            .range(pb::RangeRequest {
                key: from.into_bytes(),
                range_end: op::prefix_end(&format!("{}{PFX_EVENTS}", self.prefix)),
                ..Default::default()
            })
            .await?;
        let mut out = Vec::with_capacity(r.kvs.len());
        for kv in r.kvs {
            let k = String::from_utf8_lossy(&kv.key).into_owned();
            let e: EventRec = decode(&k, &kv.value)?;
            out.push(Event {
                key: k.get(self.prefix.len()..).unwrap_or_default().to_string(),
                kind: e.kind,
                object: e.object,
                app: e.app,
                node: e.node,
                reason: e.reason,
                message: e.message,
                count: e.count,
                first: from_ms(e.first),
                last: from_ms(e.last),
            });
        }
        Ok(out)
    }

    /// TrimEvents deletes the oldest events beyond keep.
    pub async fn trim_events(&self, keep: i64) -> Result<()> {
        let pfx = format!("{}{PFX_EVENTS}", self.prefix);
        let mut req = op::get_prefix(&pfx, 0);
        req.keys_only = true;
        let r = self.c.range(req).await?;
        let drop = r.kvs.len() as i64 - keep;
        if drop <= 0 {
            return Ok(());
        }
        // With keep at 0 or less, every event goes.
        let end = match r.kvs.get(drop as usize) {
            Some(kv) => String::from_utf8_lossy(&kv.key).into_owned(),
            None => String::from_utf8(op::prefix_end(&pfx)).expect("prefixes are ASCII"),
        };
        // Not while the state moves (ADR 0057).
        let r = self
            .c
            .txn(pb::TxnRequest {
                compare: vec![op::created_at(&self.moving_key(), 0)],
                success: vec![op::delete_range(&pfx, &end)],
                failure: Vec::new(),
            })
            .await?;
        if !r.succeeded {
            return Err(Error::bare(Kind::Moving));
        }
        Ok(())
    }
}

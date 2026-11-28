//! The move of the control plane's state from etcd to armada-kv (ADR 0057)
//! as the store keeps it:
//!
//! - `meta/state-move`: the move's record (its ID, its step `copying` or
//!   `moved`, the leader moving it, the servers taking part, the peer URLs
//!   of the new store's first member, the revision copied).
//! - `moving` (beside the commit key): exists, holding the move's ID, from
//!   the moment the move starts until it is given up. Every write of the
//!   store compares that it does not exist (transactions, events, the
//!   placements' pruning, the ACME storage), so nothing but the move's own
//!   writes reaches etcd while the key space is copied, and nothing at all
//!   once it moved. Reads keep working.
//! - `meta/state-move-mode` (`auto`, `off`, `now`) and
//!   `meta/state-move-retry` (the failures so far and when to try again):
//!   ordinary meta records.
//!
//! The move's own writes compare the record's whole value, so starting,
//! stepping, and giving up never cross: once `moved` is written, nothing
//! gives the move up, and once it is given up, nothing writes `moved`.
//!
//! A copy leaves out what is the old store's alone: the election's keys,
//! the ACME locks, the moving key, and the move's record (written into the
//! new store as `moved` afterwards).

use armada_proto::etcd::etcdserverpb as pb;
use armada_proto::etcd::mvccpb::KeyValue;
use serde::{Deserialize, Serialize};

use crate::client::{Client, op};
use crate::error::{Error, Kind, Result, other};
use crate::gojson::marshal;
use crate::tx::{Etcd, KEY_COMMIT, PFX_META};

/// The key that exists while the state moves (below the store's prefix).
pub const KEY_MOVING: &str = "moving";
/// The move's record, a meta record.
pub const META_STATE_MOVE: &str = "state-move";
/// Whether the leader moves the state by itself: auto (the default), off,
/// or now.
pub const META_STATE_MOVE_MODE: &str = "state-move-mode";
/// The failures of earlier moves and when the next may start.
pub const META_STATE_MOVE_RETRY: &str = "state-move-retry";

pub const STEP_COPYING: &str = "copying";
pub const STEP_MOVED: &str = "moved";

pub const MODE_AUTO: &str = "auto";
pub const MODE_OFF: &str = "off";
pub const MODE_NOW: &str = "now";

/// Where the ACME locks live: left out of a copy, as the election is.
pub const ACME_LOCKS_PREFIX: &str = "/armada-acme/locks/";

/// How many keys one read of a copy asks for.
const PAGE: i64 = 1000;

fn is_zero(n: &i64) -> bool {
    *n == 0
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// The move's record.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StateMove {
    pub id: String,
    pub step: String,
    /// The server that moves it.
    pub leader: String,
    /// The servers whose members make up the new store.
    pub servers: Vec<String>,
    /// The peer URLs of the new store's first member, which the other
    /// servers' members join through; empty until it runs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<String>,
    /// When the move started, in Unix milliseconds.
    #[serde(rename = "startedAt")]
    pub started_at: i64,
    /// The revision of etcd's key space the new store holds.
    #[serde(skip_serializing_if = "is_zero")]
    pub revision: i64,
    /// When it moved, in Unix milliseconds.
    #[serde(rename = "movedAt", skip_serializing_if = "is_zero")]
    pub moved_at: i64,
    /// Whether the new store's leader recorded the StateMoved event.
    #[serde(skip_serializing_if = "is_false")]
    pub told: bool,
}

impl StateMove {
    /// The record's value: a JSON string holding its JSON, as every meta
    /// record (get_meta reads it).
    pub fn encode(&self) -> Vec<u8> {
        marshal(&String::from_utf8(marshal(self)).expect("JSON is UTF-8"))
    }

    /// A record's value read back.
    pub fn decode(b: &[u8]) -> Result<StateMove> {
        let s: String =
            serde_json::from_slice(b).map_err(|e| other!("meta/{META_STATE_MOVE}: {e}"))?;
        serde_json::from_str(&s).map_err(|e| other!("meta/{META_STATE_MOVE}: {e}"))
    }
}

/// The full key of a meta record.
pub fn meta_key(prefix: &str, name: &str) -> String {
    format!("{prefix}{PFX_META}{name}")
}

/// The move's record and its value as stored, read from the member c
/// reaches (serializable: what that member applied, without asking the
/// leader, so a member that lost its quorum still answers).
pub async fn read_state_move(
    c: &Client,
    prefix: &str,
    serializable: bool,
) -> Result<Option<(StateMove, Vec<u8>)>> {
    let mut r = op::get(&meta_key(prefix, META_STATE_MOVE), 0);
    r.serializable = serializable;
    let resp = c.range(r).await?;
    match resp.kvs.into_iter().next() {
        None => Ok(None),
        Some(kv) => Ok(Some((StateMove::decode(&kv.value)?, kv.value))),
    }
}

/// Whether a copy leaves key out: the election's keys, the ACME locks, and
/// the move's own keys below prefix.
pub fn left_out(key: &[u8], prefix: &str) -> bool {
    key.starts_with(crate::election::ELECTION_PREFIX.as_bytes())
        || key.starts_with(ACME_LOCKS_PREFIX.as_bytes())
        || key == format!("{prefix}{KEY_MOVING}").as_bytes()
        || key == meta_key(prefix, META_STATE_MOVE).as_bytes()
}

/// Every key c's store holds at rev (0: the current revision) that a copy
/// keeps, in key order, read a page at a time at one revision. The
/// revision read is returned with them.
pub async fn read_key_space(c: &Client, rev: i64, prefix: &str) -> Result<(i64, Vec<KeyValue>)> {
    read_key_space_on(c, rev, prefix, false).await
}

/// read_key_space, serializable: the key space of the member c reaches as
/// that member applied it, without asking the leader (a member that has
/// not applied rev yet answers an error).
pub async fn read_key_space_on(
    c: &Client,
    rev: i64,
    prefix: &str,
    serializable: bool,
) -> Result<(i64, Vec<KeyValue>)> {
    let mut out = Vec::new();
    let mut from = vec![0u8];
    let mut at = rev;
    loop {
        let resp = c
            .range(pb::RangeRequest {
                key: from.clone(),
                range_end: vec![0],
                limit: PAGE,
                revision: at,
                serializable,
                ..Default::default()
            })
            .await?;
        if at == 0 {
            at = resp.header.as_ref().map_or(0, |h| h.revision);
        }
        let more = resp.more;
        let last = resp.kvs.last().map(|kv| kv.key.clone());
        out.extend(resp.kvs.into_iter().filter(|kv| !left_out(&kv.key, prefix)));
        match last {
            Some(mut k) if more => {
                k.push(0);
                from = k;
            }
            _ => break,
        }
    }
    Ok((at, out))
}

/// The leases the keys name, each with what is left of its TTL on c's
/// store (at least a second: a lease that expired while the copy was
/// read expires in the new store too).
pub async fn lease_ttls(c: &Client, kvs: &[KeyValue]) -> Result<Vec<(i64, i64)>> {
    let mut ids: Vec<i64> = kvs.iter().map(|kv| kv.lease).filter(|l| *l != 0).collect();
    ids.sort_unstable();
    ids.dedup();
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let ttl = c.lease_ttl(id).await?;
        out.push((id, ttl.max(1)));
    }
    Ok(out)
}

/// The SHA-256 of a key space: every key with its value, version, creation
/// and modification revisions, and lease, in key order.
pub fn key_space_hash(kvs: &[KeyValue]) -> [u8; 32] {
    let mut h = ring::digest::Context::new(&ring::digest::SHA256);
    for kv in kvs {
        for part in [&kv.key, &kv.value] {
            h.update(&(part.len() as u64).to_be_bytes());
            h.update(part);
        }
        for n in [kv.version, kv.create_revision, kv.mod_revision, kv.lease] {
            h.update(&n.to_be_bytes());
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finish().as_ref());
    out
}

/// What differs between two key spaces, or None when they hold the same
/// keys with the same values, versions, revisions, and leases.
pub fn key_space_difference(want: &[KeyValue], got: &[KeyValue]) -> Option<String> {
    let name = |k: &[u8]| String::from_utf8_lossy(k).into_owned();
    let (mut i, mut j) = (0, 0);
    while i < want.len() || j < got.len() {
        match (want.get(i), got.get(j)) {
            (Some(w), Some(g)) if w.key == g.key => {
                if w != g {
                    return Some(format!("key {} differs", name(&w.key)));
                }
                i += 1;
                j += 1;
            }
            (Some(w), Some(g)) if w.key < g.key => {
                return Some(format!("key {} is missing", name(&w.key)));
            }
            (Some(w), None) => return Some(format!("key {} is missing", name(&w.key))),
            (_, Some(g)) => return Some(format!("key {} was not copied", name(&g.key))),
            (None, None) => break,
        }
    }
    if key_space_hash(want) != key_space_hash(got) {
        return Some("the key spaces' hashes differ".to_string());
    }
    None
}

fn value_is(key: &str, value: &[u8]) -> pb::Compare {
    pb::Compare {
        result: pb::compare::CompareResult::Equal as i32,
        target: pb::compare::CompareTarget::Value as i32,
        key: key.as_bytes().to_vec(),
        range_end: Vec::new(),
        target_union: Some(pb::compare::TargetUnion::Value(value.to_vec())),
    }
}

impl Etcd {
    /// The move's record and its stored value.
    pub async fn state_move(&self) -> Result<Option<(StateMove, Vec<u8>)>> {
        read_state_move(&self.c, &self.prefix, false).await
    }

    fn fence_cmps(&self) -> Vec<pb::Compare> {
        self.fence()
            .map(|(k, rev)| vec![op::created_at(k, *rev)])
            .unwrap_or_default()
    }

    /// Why one of the move's writes was refused: this server no longer
    /// leads, or the record is not what the write expected.
    async fn move_refused(&self, what: &str) -> Error {
        match self.fence_holds().await {
            Ok(false) => Error::bare(Kind::NotLeader),
            Err(e) => e,
            Ok(true) => Error::wrap(Kind::Precondition, what),
        }
    }

    /// Starts a move: the record (step copying) and the moving key written
    /// together, unless a move is under way. Returns the revision the
    /// write made, which is the one the key space is copied at, and the
    /// record's stored value.
    pub async fn begin_state_move(&self, m: &StateMove) -> Result<(i64, Vec<u8>)> {
        let value = m.encode();
        let mut cmps = self.fence_cmps();
        cmps.push(op::created_at(&self.moving_key(), 0));
        let r = self
            .c
            .txn(pb::TxnRequest {
                compare: cmps,
                success: vec![
                    op::put(&self.moving_key(), m.id.as_bytes(), 0),
                    op::put(&meta_key(&self.prefix, META_STATE_MOVE), &value, 0),
                    // Transactions that read before the move fail on the
                    // commit key, and then see the moving key.
                    op::put(&format!("{}{KEY_COMMIT}", self.prefix), b"", 0),
                ],
                failure: Vec::new(),
            })
            .await?;
        if !r.succeeded {
            return Err(self.move_refused("the state is moving already").await);
        }
        Ok((r.header.map_or(0, |h| h.revision), value))
    }

    /// Replaces the move's record, while it still holds prev (the value
    /// last written or read) and the moving key names the move: the next
    /// step. Returns the new stored value.
    pub async fn step_state_move(&self, prev: &[u8], m: &StateMove) -> Result<Vec<u8>> {
        let value = m.encode();
        let key = meta_key(&self.prefix, META_STATE_MOVE);
        let mut cmps = self.fence_cmps();
        cmps.push(value_is(&key, prev));
        cmps.push(value_is(&self.moving_key(), m.id.as_bytes()));
        let r = self
            .c
            .txn(pb::TxnRequest {
                compare: cmps,
                success: vec![op::put(&key, &value, 0)],
                failure: Vec::new(),
            })
            .await?;
        if !r.succeeded {
            return Err(self
                .move_refused("the state move changed (another leader gave it up)")
                .await);
        }
        Ok(value)
    }

    /// Gives a move up: the record and the moving key removed, while the
    /// record still holds prev (a move that reached `moved` is never given
    /// up). Writes work again afterwards.
    pub async fn end_state_move(&self, prev: &[u8]) -> Result<()> {
        let key = meta_key(&self.prefix, META_STATE_MOVE);
        let mut cmps = self.fence_cmps();
        cmps.push(value_is(&key, prev));
        let r = self
            .c
            .txn(pb::TxnRequest {
                compare: cmps,
                success: vec![
                    op::delete(&self.moving_key()),
                    op::delete(&key),
                    op::put(&format!("{}{KEY_COMMIT}", self.prefix), b"", 0),
                ],
                failure: Vec::new(),
            })
            .await?;
        if !r.succeeded {
            return Err(self.move_refused("the state move changed").await);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kv(k: &str, v: &str, rev: i64) -> KeyValue {
        KeyValue {
            key: k.as_bytes().to_vec(),
            value: v.as_bytes().to_vec(),
            create_revision: rev,
            mod_revision: rev,
            version: 1,
            lease: 0,
        }
    }

    #[test]
    fn records_round_trip_as_meta_values() {
        let m = StateMove {
            id: "ab12".into(),
            step: STEP_COPYING.into(),
            leader: "cp-1".into(),
            servers: vec!["cp-1".into(), "cp-2".into()],
            started_at: 1700000000000,
            ..Default::default()
        };
        let b = m.encode();
        // A JSON string, as get_meta reads every meta record.
        let s: String = serde_json::from_slice(&b).unwrap();
        assert!(s.starts_with("{\"id\":\"ab12\""), "{s}");
        assert!(!s.contains("revision"));
        assert_eq!(StateMove::decode(&b).unwrap(), m);
        assert!(StateMove::decode(b"{}").is_err());
    }

    #[test]
    fn a_copy_leaves_out_the_old_stores_own_keys() {
        for k in [
            "/armada-leader/694d8a",
            "/armada-acme/locks/issue_cert_a/694d8b",
            "/armada/moving",
            "/armada/meta/state-move",
        ] {
            assert!(left_out(k.as_bytes(), "/armada/"), "{k}");
        }
        for k in [
            "/armada/meta/state-move-mode",
            "/armada/commit",
            "/armada-acme/data/certificates/x",
            "/armada/events/1",
        ] {
            assert!(!left_out(k.as_bytes(), "/armada/"), "{k}");
        }
    }

    #[test]
    fn key_spaces_compare_key_by_key() {
        let a = vec![kv("a", "1", 2), kv("b", "2", 3)];
        assert_eq!(key_space_difference(&a, &a.clone()), None);
        let mut b = a.clone();
        b[1].version = 2;
        assert_eq!(
            key_space_difference(&a, &b).as_deref(),
            Some("key b differs")
        );
        assert_eq!(
            key_space_difference(&a, &a[..1]).as_deref(),
            Some("key b is missing")
        );
        let mut c = a.clone();
        c.push(kv("c", "3", 4));
        assert_eq!(
            key_space_difference(&a, &c).as_deref(),
            Some("key c was not copied")
        );
        assert_ne!(key_space_hash(&a), key_space_hash(&b));
    }
}

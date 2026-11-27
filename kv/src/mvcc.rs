//! The multi-version key space (ADR 0057) in one redb database: a
//! cluster-wide revision raised by every change, each key's creation and
//! modification revision, version, and lease, reads at a past revision
//! until it is compacted, and leases whose revocation deletes their keys.
//!
//! The tables:
//!
//! - `latest`: key → its current version (absent once deleted), for reads
//!   at the current revision.
//! - `history`: (key, revision) → the version written at that revision, or
//!   a tombstone (version 0) where the key was deleted; reads at a past
//!   revision take each key's newest entry at or below it.
//! - `events`: (revision, n) → the n-th change of a revision (its type and
//!   key), which watches read and compaction walks.
//! - `leases`: ID → granted TTL; `lease_keys`: (ID, key) → ().
//! - `meta`: the format, the revision, the compacted revision, the count of
//!   applied commands, and the member's and cluster's IDs.
//!
//! Every change is a [`Command`] applied by [`Store::apply`] in one write
//! transaction per batch, durable (fsync) when it returns. The values
//! stored are etcd's `KeyValue` messages without their key.

use std::collections::{BTreeSet, HashSet};
use std::ops::Bound;
use std::path::{Path, PathBuf};

use armada_proto::etcd::etcdserverpb as pb;
use armada_proto::etcd::mvccpb::{self, KeyValue};
use pb::compare::{CompareResult, CompareTarget, TargetUnion};
use pb::range_request::{SortOrder, SortTarget};
use pb::request_op::Request;
use pb::response_op::Response as OpResponse;
use prost::Message;
use redb::{Database, ReadableDatabase, ReadableTable, Table, TableDefinition, WriteTransaction};

use crate::command::{Command, Op};
use crate::error::{Error, Result, storage};

type Bytes = &'static [u8];

const LATEST: TableDefinition<&[u8], &[u8]> = TableDefinition::new("latest");
const HISTORY: TableDefinition<(&[u8], i64), &[u8]> = TableDefinition::new("history");
const EVENTS: TableDefinition<(i64, u32), &[u8]> = TableDefinition::new("events");
const LEASES: TableDefinition<i64, i64> = TableDefinition::new("leases");
const LEASE_KEYS: TableDefinition<(i64, &[u8]), ()> = TableDefinition::new("lease_keys");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");

/// The database's format; another one is refused.
pub const FORMAT: u64 = 1;

const M_FORMAT: &str = "format";
const M_REVISION: &str = "revision";
const M_COMPACTED: &str = "compacted";
const M_APPLIED: &str = "applied";
const M_MEMBER: &str = "member";
const M_CLUSTER: &str = "cluster";

/// etcd's MaxLeaseTTL.
pub const MAX_LEASE_TTL: i64 = 9_000_000_000;

/// The Raft term of a single member, which never elects (step 2 replaces
/// it with the log's term).
pub const RAFT_TERM: u64 = 1;

const EVENT_PUT: u8 = 0;
const EVENT_DELETE: u8 = 1;

/// The store's limits.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Operations of a transaction (and its compares), as etcd's
    /// `--max-txn-ops`.
    pub max_txn_ops: usize,
    /// The shortest lease granted: shorter TTLs are raised to it.
    pub min_lease_ttl: i64,
    /// The database's size past which commands that only add are refused.
    pub quota_bytes: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_txn_ops: 4096,
            min_lease_ttl: 2,
            quota_bytes: 8 << 30,
        }
    }
}

/// The member's and its cluster's IDs, made when the database is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ids {
    pub cluster: u64,
    pub member: u64,
}

impl Ids {
    /// A response header at revision rev.
    pub fn header(&self, rev: i64) -> pb::ResponseHeader {
        pb::ResponseHeader {
            cluster_id: self.cluster,
            member_id: self.member,
            revision: rev,
            raft_term: RAFT_TERM,
        }
    }
}

/// The answer to an applied command.
#[derive(Clone, Debug, PartialEq)]
pub enum Response {
    Put(pb::PutResponse),
    DeleteRange(pb::DeleteRangeResponse),
    Txn(pb::TxnResponse),
    LeaseGrant(pb::LeaseGrantResponse),
    LeaseRevoke(pb::LeaseRevokeResponse),
    Compact(pb::CompactionResponse),
}

/// A command applied: its answer and what the member's lease clock has to
/// follow.
#[derive(Clone, Debug, PartialEq)]
pub struct Applied {
    /// The revision after the command.
    pub revision: i64,
    pub response: Response,
    /// A lease granted: its ID and TTL.
    pub granted: Option<(i64, i64)>,
    /// A lease revoked or expired.
    pub revoked: Option<i64>,
}

/// The database's numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub revision: i64,
    pub compacted: i64,
    /// Commands applied, failed ones included (a log's applied index).
    pub applied: u64,
}

/// Changes read for a watch.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EventsRead {
    /// Each event with its revision, in order.
    pub events: Vec<mvccpb::Event>,
    /// The revision read up to (the store's revision when read).
    pub revision: i64,
    pub compacted: i64,
}

/// The key space on disk.
pub struct Store {
    db: Database,
    path: PathBuf,
    ids: Ids,
    limits: Limits,
}

fn random_id() -> u64 {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 8];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .expect("the system's random source works");
    // Positive as an int64 and never 0, as etcd's IDs.
    (u64::from_be_bytes(b) >> 1).max(1)
}

/// A new lease ID (etcd's are positive int64s).
pub fn new_lease_id() -> i64 {
    random_id() as i64
}

fn open_db(path: &Path) -> Result<Database> {
    Database::create(path).map_err(|e| match e {
        redb::DatabaseError::DatabaseAlreadyOpen => Error::Storage(format!(
            "{}: another process holds the database",
            path.display()
        )),
        e => storage(format!("{}: {e}", path.display())),
    })
}

impl Store {
    /// Opens the database at path, creating it (revision 1, new IDs) when
    /// it does not exist. Another process holding it is refused.
    pub fn open(path: &Path, limits: Limits) -> Result<Store> {
        let db = open_db(path)?;
        let txn = db.begin_write().map_err(storage)?;
        let ids = {
            let w = Tables::open(&txn)?;
            let mut meta = w.meta;
            let format = meta.get(M_FORMAT).map_err(storage)?.map(|g| g.value());
            match format {
                None => {
                    let ids = Ids {
                        cluster: random_id(),
                        member: random_id(),
                    };
                    for (k, v) in [
                        (M_FORMAT, FORMAT),
                        (M_REVISION, 1),
                        (M_COMPACTED, 0),
                        (M_APPLIED, 0),
                        (M_MEMBER, ids.member),
                        (M_CLUSTER, ids.cluster),
                    ] {
                        meta.insert(k, v).map_err(storage)?;
                    }
                    ids
                }
                Some(FORMAT) => Ids {
                    cluster: get_meta(&meta, M_CLUSTER)?,
                    member: get_meta(&meta, M_MEMBER)?,
                },
                Some(f) => {
                    return Err(Error::Storage(format!(
                        "{}: database format {f}, this binary reads {FORMAT}",
                        path.display()
                    )));
                }
            }
        };
        txn.commit().map_err(storage)?;
        Ok(Store {
            db,
            path: path.to_path_buf(),
            ids,
            limits,
        })
    }

    pub fn ids(&self) -> Ids {
        self.ids
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The database file's size.
    pub fn size(&self) -> u64 {
        std::fs::metadata(&self.path).map_or(0, |m| m.len())
    }

    /// The revision, the compacted revision, and the applied count.
    pub fn state(&self) -> Result<State> {
        let txn = self.db.begin_read().map_err(storage)?;
        let meta = txn.open_table(META).map_err(storage)?;
        Ok(State {
            revision: get_meta(&meta, M_REVISION)? as i64,
            compacted: get_meta(&meta, M_COMPACTED)? as i64,
            applied: get_meta(&meta, M_APPLIED)?,
        })
    }

    /// Every lease with its granted TTL.
    pub fn leases(&self) -> Result<Vec<(i64, i64)>> {
        let txn = self.db.begin_read().map_err(storage)?;
        let t = txn.open_table(LEASES).map_err(storage)?;
        let mut out = Vec::new();
        for e in t.range(..).map_err(storage)? {
            let (k, v) = e.map_err(storage)?;
            out.push((k.value(), v.value()));
        }
        Ok(out)
    }

    /// KV.Range at the store's current revision or a past one.
    pub fn range(&self, r: &pb::RangeRequest) -> Result<pb::RangeResponse> {
        if r.key.is_empty() {
            return Err(Error::EmptyKey);
        }
        let txn = self.db.begin_read().map_err(storage)?;
        let meta = txn.open_table(META).map_err(storage)?;
        let rev = get_meta(&meta, M_REVISION)? as i64;
        let compacted = get_meta(&meta, M_COMPACTED)? as i64;
        check_rev(r.revision, rev, compacted)?;
        let latest = txn.open_table(LATEST).map_err(storage)?;
        let history = txn.open_table(HISTORY).map_err(storage)?;
        range(&latest, &history, r, rev, self.ids)
    }

    /// A transaction with only ranges, read without a commit: its
    /// compares and ranges at one revision.
    pub fn read_txn(&self, t: &pb::TxnRequest, max_ops: usize) -> Result<pb::TxnResponse> {
        check_txn(t, max_ops)?;
        let txn = self.db.begin_read().map_err(storage)?;
        let meta = txn.open_table(META).map_err(storage)?;
        let rev = get_meta(&meta, M_REVISION)? as i64;
        let compacted = get_meta(&meta, M_COMPACTED)? as i64;
        let latest = txn.open_table(LATEST).map_err(storage)?;
        let history = txn.open_table(HISTORY).map_err(storage)?;
        let mut succeeded = true;
        for c in &t.compare {
            if !compare(&latest, c)? {
                succeeded = false;
                break;
            }
        }
        let ops = if succeeded { &t.success } else { &t.failure };
        let mut responses = Vec::with_capacity(ops.len());
        for o in ops {
            match &o.request {
                None => {}
                Some(Request::RequestRange(r)) => {
                    check_rev(r.revision, rev, compacted)?;
                    responses.push(pb::ResponseOp {
                        response: Some(OpResponse::ResponseRange(range(
                            &latest, &history, r, rev, self.ids,
                        )?)),
                    });
                }
                Some(_) => {
                    return Err(Error::Unimplemented("a write in a read".into()));
                }
            }
        }
        Ok(pb::TxnResponse {
            header: Some(self.ids.header(rev)),
            succeeded,
            responses,
        })
    }

    /// The changes from revision `from` to the current one in [key, end)
    /// (etcd's range forms), for a watch.
    pub fn events(&self, from: i64, key: &[u8], end: &[u8], prev_kv: bool) -> Result<EventsRead> {
        let txn = self.db.begin_read().map_err(storage)?;
        let meta = txn.open_table(META).map_err(storage)?;
        let rev = get_meta(&meta, M_REVISION)? as i64;
        let compacted = get_meta(&meta, M_COMPACTED)? as i64;
        let mut out = EventsRead {
            events: Vec::new(),
            revision: rev,
            compacted,
        };
        if from < compacted || from > rev {
            return Ok(out);
        }
        let events = txn.open_table(EVENTS).map_err(storage)?;
        let history = txn.open_table(HISTORY).map_err(storage)?;
        let kr = KeyRange::of(key, end);
        for e in events.range((from, 0u32)..).map_err(storage)? {
            let (k, v) = e.map_err(storage)?;
            let (at, _) = k.value();
            let v = v.value();
            let Some((&kind, ekey)) = v.split_first() else {
                continue;
            };
            if !kr.contains(ekey) {
                continue;
            }
            let (ty, kv) = if kind == EVENT_PUT {
                let Some(kv) = entry_at(&history, ekey, at)? else {
                    continue;
                };
                (mvccpb::event::EventType::Put, kv)
            } else {
                (
                    mvccpb::event::EventType::Delete,
                    KeyValue {
                        key: ekey.to_vec(),
                        mod_revision: at,
                        ..Default::default()
                    },
                )
            };
            let prev = if prev_kv {
                version_at(&history, ekey, at - 1)?
            } else {
                None
            };
            out.events.push(mvccpb::Event {
                r#type: ty as i32,
                kv: Some(kv),
                prev_kv: prev,
            });
        }
        Ok(out)
    }

    /// Applies commands in order in one durable commit: each command's
    /// answer or error. An error of the database fails them all, and
    /// nothing of the batch is kept.
    pub fn apply(&self, cmds: &[Command]) -> Result<Vec<Result<Applied>>> {
        let full = self.size() > self.limits.quota_bytes;
        let txn = self.db.begin_write().map_err(storage)?;
        let results = {
            let mut w = Writer::open(&txn, self.ids, &self.limits)?;
            let mut results = Vec::with_capacity(cmds.len());
            for c in cmds {
                let r = if full && c.grows() {
                    Err(Error::NoSpace)
                } else {
                    w.apply(c)
                };
                if let Err(Error::Storage(e)) = &r {
                    return Err(Error::Storage(e.clone()));
                }
                w.applied += 1;
                results.push(r);
            }
            w.save()?;
            results
        };
        txn.commit().map_err(storage)?;
        Ok(results)
    }

    /// The store's snapshot (crate::snapshot): the current key space and
    /// leases at one revision.
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        let txn = self.db.begin_read().map_err(storage)?;
        let meta = txn.open_table(META).map_err(storage)?;
        let rev = get_meta(&meta, M_REVISION)? as i64;
        let latest = txn.open_table(LATEST).map_err(storage)?;
        let leases = txn.open_table(LEASES).map_err(storage)?;
        let mut w = crate::snapshot::Writer::new(rev);
        for e in leases.range(..).map_err(storage)? {
            let (k, v) = e.map_err(storage)?;
            w.lease(k.value(), v.value());
        }
        for e in latest.range(..).map_err(storage)? {
            let (k, v) = e.map_err(storage)?;
            w.kv(&decode_kv(k.value(), v.value())?);
        }
        Ok(w.finish())
    }

    /// A new database at path from a snapshot (checked first): its keys
    /// and leases at the snapshot's revision, which is also the compacted
    /// one; new member and cluster IDs. An existing file is refused.
    pub fn restore(snapshot: &[u8], path: &Path, limits: Limits) -> Result<Store> {
        let snap = crate::snapshot::read(snapshot)?;
        if path.exists() {
            return Err(Error::Snapshot(format!("{} exists", path.display())));
        }
        let store = Store::open(path, limits)?;
        let txn = store.db.begin_write().map_err(storage)?;
        {
            let mut t = Tables::open(&txn)?;
            for (id, ttl) in &snap.leases {
                t.leases.insert(*id, *ttl).map_err(storage)?;
            }
            for kv in &snap.kvs {
                let v = encode_kv(kv);
                t.latest
                    .insert(kv.key.as_slice(), v.as_slice())
                    .map_err(storage)?;
                t.history
                    .insert((kv.key.as_slice(), kv.mod_revision), v.as_slice())
                    .map_err(storage)?;
                if kv.lease != 0 {
                    t.lease_keys
                        .insert((kv.lease, kv.key.as_slice()), ())
                        .map_err(storage)?;
                }
            }
            t.meta
                .insert(M_REVISION, snap.revision as u64)
                .map_err(storage)?;
            t.meta
                .insert(M_COMPACTED, snap.revision as u64)
                .map_err(storage)?;
        }
        txn.commit().map_err(storage)?;
        Ok(store)
    }
}

fn get_meta(t: &impl ReadableTable<&'static str, u64>, k: &str) -> Result<u64> {
    t.get(k)
        .map_err(storage)?
        .map(|g| g.value())
        .ok_or_else(|| Error::Storage(format!("no {k} in the database")))
}

/// A read at revision `want` (0 or less: the current one) against the
/// store at `rev` compacted at `compacted`.
fn check_rev(want: i64, rev: i64, compacted: i64) -> Result<()> {
    if want > rev {
        return Err(Error::FutureRev);
    }
    if want > 0 && want < compacted {
        return Err(Error::Compacted);
    }
    Ok(())
}

fn encode_kv(kv: &KeyValue) -> Vec<u8> {
    KeyValue {
        key: Vec::new(),
        create_revision: kv.create_revision,
        mod_revision: kv.mod_revision,
        version: kv.version,
        value: kv.value.clone(),
        lease: kv.lease,
    }
    .encode_to_vec()
}

fn decode_kv(key: &[u8], v: &[u8]) -> Result<KeyValue> {
    let mut kv = KeyValue::decode(v).map_err(storage)?;
    kv.key = key.to_vec();
    Ok(kv)
}

/// The keys of a request: etcd's forms of key and range_end.
#[derive(Clone, Copy, Debug)]
enum KeyRange<'a> {
    One(&'a [u8]),
    /// From a key up to an end, or every key after it.
    Span(&'a [u8], Option<&'a [u8]>),
    Empty,
}

impl<'a> KeyRange<'a> {
    fn of(key: &'a [u8], end: &'a [u8]) -> KeyRange<'a> {
        if end.is_empty() {
            KeyRange::One(key)
        } else if end == [0] {
            KeyRange::Span(key, None)
        } else if key >= end {
            KeyRange::Empty
        } else {
            KeyRange::Span(key, Some(end))
        }
    }

    fn contains(&self, k: &[u8]) -> bool {
        match *self {
            KeyRange::One(o) => k == o,
            KeyRange::Span(from, end) => k >= from && end.is_none_or(|e| k < e),
            KeyRange::Empty => false,
        }
    }
}

/// The current versions of the keys in kr, in key order.
fn kvs_latest(latest: &impl ReadableTable<Bytes, Bytes>, kr: KeyRange) -> Result<Vec<KeyValue>> {
    let mut out = Vec::new();
    match kr {
        KeyRange::Empty => {}
        KeyRange::One(k) => {
            if let Some(v) = latest.get(k).map_err(storage)? {
                out.push(decode_kv(k, v.value())?);
            }
        }
        KeyRange::Span(from, end) => {
            let hi = match end {
                Some(e) => Bound::Excluded(e),
                None => Bound::Unbounded,
            };
            for e in latest.range((Bound::Included(from), hi)).map_err(storage)? {
                let (k, v) = e.map_err(storage)?;
                out.push(decode_kv(k.value(), v.value())?);
            }
        }
    }
    Ok(out)
}

/// The history entry of key written at exactly rev.
fn entry_at(
    history: &impl ReadableTable<(Bytes, i64), Bytes>,
    key: &[u8],
    rev: i64,
) -> Result<Option<KeyValue>> {
    match history.get((key, rev)).map_err(storage)? {
        Some(v) => decode_kv(key, v.value()).map(Some),
        None => Ok(None),
    }
}

/// The version of key at rev: its newest entry at or below rev, unless
/// that is a tombstone.
fn version_at(
    history: &impl ReadableTable<(Bytes, i64), Bytes>,
    key: &[u8],
    rev: i64,
) -> Result<Option<KeyValue>> {
    let mut it = history
        .range((key, i64::MIN)..=(key, rev))
        .map_err(storage)?;
    match it.next_back() {
        None => Ok(None),
        Some(e) => {
            let (_, v) = e.map_err(storage)?;
            let kv = decode_kv(key, v.value())?;
            Ok((kv.version != 0).then_some(kv))
        }
    }
}

/// The versions of the keys in kr at a past revision, in key order.
fn kvs_at(
    history: &impl ReadableTable<(Bytes, i64), Bytes>,
    kr: KeyRange,
    rev: i64,
) -> Result<Vec<KeyValue>> {
    let mut out = Vec::new();
    let (from, end) = match kr {
        KeyRange::Empty => return Ok(out),
        KeyRange::One(k) => {
            out.extend(version_at(history, k, rev)?);
            return Ok(out);
        }
        KeyRange::Span(from, end) => (from, end),
    };
    let hi = match end {
        Some(e) => Bound::Excluded((e, i64::MIN)),
        None => Bound::Unbounded,
    };
    let mut last: Option<Vec<u8>> = None;
    loop {
        let lo = match &last {
            None => Bound::Included((from, i64::MIN)),
            Some(p) => Bound::Excluded((p.as_slice(), i64::MAX)),
        };
        let next = {
            let mut it = history.range((lo, hi)).map_err(storage)?;
            match it.next() {
                None => None,
                Some(e) => Some(e.map_err(storage)?.0.value().0.to_vec()),
            }
        };
        let Some(key) = next else { break };
        out.extend(version_at(history, &key, rev)?);
        last = Some(key);
    }
    Ok(out)
}

/// KV.Range against the tables at revision `cur` (the revision a
/// transaction reads at, its own writes included).
fn range(
    latest: &impl ReadableTable<Bytes, Bytes>,
    history: &impl ReadableTable<(Bytes, i64), Bytes>,
    r: &pb::RangeRequest,
    cur: i64,
    ids: Ids,
) -> Result<pb::RangeResponse> {
    let kr = KeyRange::of(&r.key, &r.range_end);
    let mut kvs = if r.revision <= 0 || r.revision >= cur {
        kvs_latest(latest, kr)?
    } else {
        kvs_at(history, kr, r.revision)?
    };
    let count = kvs.len() as i64;
    kvs.retain(|kv| {
        !(r.max_mod_revision != 0 && kv.mod_revision > r.max_mod_revision
            || r.min_mod_revision != 0 && kv.mod_revision < r.min_mod_revision
            || r.max_create_revision != 0 && kv.create_revision > r.max_create_revision
            || r.min_create_revision != 0 && kv.create_revision < r.min_create_revision)
    });
    let target = SortTarget::try_from(r.sort_target).unwrap_or(SortTarget::Key);
    let mut order = SortOrder::try_from(r.sort_order).unwrap_or(SortOrder::None);
    if target != SortTarget::Key && order == SortOrder::None {
        order = SortOrder::Ascend;
    } else if target == SortTarget::Key && order == SortOrder::Ascend {
        order = SortOrder::None;
    }
    if order != SortOrder::None {
        kvs.sort_by(|a, b| match target {
            SortTarget::Key => a.key.cmp(&b.key),
            SortTarget::Version => a.version.cmp(&b.version),
            SortTarget::Create => a.create_revision.cmp(&b.create_revision),
            SortTarget::Mod => a.mod_revision.cmp(&b.mod_revision),
            SortTarget::Value => a.value.cmp(&b.value),
        });
        if order == SortOrder::Descend {
            kvs.reverse();
        }
    }
    let mut more = false;
    if r.limit > 0 && kvs.len() > r.limit as usize {
        kvs.truncate(r.limit as usize);
        more = true;
    }
    if r.count_only {
        kvs.clear();
    } else if r.keys_only {
        for kv in &mut kvs {
            kv.value.clear();
        }
    }
    Ok(pb::RangeResponse {
        header: Some(ids.header(cur)),
        kvs,
        more,
        count,
    })
}

/// Whether the keys of [key, end) satisfy a compare (etcd's applyCompare:
/// every key must; with none, the zero key does, except for its value).
fn compare(latest: &impl ReadableTable<Bytes, Bytes>, c: &pb::Compare) -> Result<bool> {
    let target = CompareTarget::try_from(c.target).unwrap_or(CompareTarget::Version);
    let kvs = kvs_latest(latest, KeyRange::of(&c.key, &c.range_end))?;
    if kvs.is_empty() {
        if target == CompareTarget::Value {
            return Ok(false);
        }
        return Ok(compare_kv(&KeyValue::default(), target, c));
    }
    Ok(kvs.iter().all(|kv| compare_kv(kv, target, c)))
}

fn compare_kv(kv: &KeyValue, target: CompareTarget, c: &pb::Compare) -> bool {
    let num = |want: Option<i64>| want.unwrap_or(0);
    let ord = match target {
        CompareTarget::Version => kv.version.cmp(&num(match c.target_union {
            Some(TargetUnion::Version(v)) => Some(v),
            _ => None,
        })),
        CompareTarget::Create => kv.create_revision.cmp(&num(match c.target_union {
            Some(TargetUnion::CreateRevision(v)) => Some(v),
            _ => None,
        })),
        CompareTarget::Mod => kv.mod_revision.cmp(&num(match c.target_union {
            Some(TargetUnion::ModRevision(v)) => Some(v),
            _ => None,
        })),
        CompareTarget::Lease => kv.lease.cmp(&num(match c.target_union {
            Some(TargetUnion::Lease(v)) => Some(v),
            _ => None,
        })),
        CompareTarget::Value => {
            let want: &[u8] = match &c.target_union {
                Some(TargetUnion::Value(v)) => v,
                _ => &[],
            };
            kv.value.as_slice().cmp(want)
        }
    };
    use std::cmp::Ordering::*;
    match CompareResult::try_from(c.result).unwrap_or(CompareResult::Equal) {
        CompareResult::Equal => ord == Equal,
        CompareResult::Greater => ord == Greater,
        CompareResult::Less => ord == Less,
        CompareResult::NotEqual => ord != Equal,
    }
}

/// The checks of a transaction etcd makes before it is applied: sizes,
/// keys given, and no key changed twice in either branch.
fn check_txn(t: &pb::TxnRequest, max_ops: usize) -> Result<()> {
    if t.compare.len() > max_ops || t.success.len() > max_ops || t.failure.len() > max_ops {
        return Err(Error::TooManyOps);
    }
    for ops in [&t.success, &t.failure] {
        for o in ops.iter() {
            match &o.request {
                Some(Request::RequestRange(r)) if r.key.is_empty() => return Err(Error::EmptyKey),
                Some(Request::RequestDeleteRange(d)) if d.key.is_empty() => {
                    return Err(Error::EmptyKey);
                }
                Some(Request::RequestPut(p)) => check_put(p)?,
                Some(Request::RequestTxn(_)) => {
                    return Err(Error::Unimplemented(
                        "a transaction inside a transaction".into(),
                    ));
                }
                _ => {}
            }
        }
        check_intervals(ops)?;
    }
    Ok(())
}

/// The checks of a command that need no key space, made before it is
/// proposed (they are made again where it is applied).
pub fn validate(c: &Command, limits: &Limits) -> Result<()> {
    match &c.op {
        None => Err(Error::Unimplemented("an empty command".into())),
        Some(Op::Put(p)) => check_put(p),
        Some(Op::DeleteRange(d)) if d.key.is_empty() => Err(Error::EmptyKey),
        Some(Op::Txn(t)) => check_txn(t, limits.max_txn_ops),
        Some(Op::LeaseGrant(g)) if g.ttl > MAX_LEASE_TTL => Err(Error::LeaseTtlTooLarge),
        _ => Ok(()),
    }
}

fn check_put(p: &pb::PutRequest) -> Result<()> {
    if p.key.is_empty() {
        return Err(Error::EmptyKey);
    }
    if p.ignore_value && !p.value.is_empty() {
        return Err(Error::ValueProvided);
    }
    if p.ignore_lease && p.lease != 0 {
        return Err(Error::LeaseProvided);
    }
    Ok(())
}

/// etcd's checkIntervals: a key put twice, or put inside a range the same
/// branch deletes, is refused.
fn check_intervals(ops: &[pb::RequestOp]) -> Result<()> {
    let mut puts: HashSet<&[u8]> = HashSet::new();
    let mut dels: Vec<KeyRange> = Vec::new();
    for o in ops {
        match &o.request {
            Some(Request::RequestPut(p)) => {
                if !puts.insert(&p.key) {
                    return Err(Error::DuplicateKey);
                }
            }
            Some(Request::RequestDeleteRange(d)) => dels.push(KeyRange::of(&d.key, &d.range_end)),
            _ => {}
        }
    }
    if dels.iter().any(|d| puts.iter().any(|k| d.contains(k))) {
        return Err(Error::DuplicateKey);
    }
    Ok(())
}

/// The tables of a write transaction.
struct Tables<'t> {
    latest: Table<'t, Bytes, Bytes>,
    history: Table<'t, (Bytes, i64), Bytes>,
    events: Table<'t, (i64, u32), Bytes>,
    leases: Table<'t, i64, i64>,
    lease_keys: Table<'t, (i64, Bytes), ()>,
    meta: Table<'t, &'static str, u64>,
}

impl<'t> Tables<'t> {
    fn open(txn: &'t WriteTransaction) -> Result<Tables<'t>> {
        Ok(Tables {
            latest: txn.open_table(LATEST).map_err(storage)?,
            history: txn.open_table(HISTORY).map_err(storage)?,
            events: txn.open_table(EVENTS).map_err(storage)?,
            leases: txn.open_table(LEASES).map_err(storage)?,
            lease_keys: txn.open_table(LEASE_KEYS).map_err(storage)?,
            meta: txn.open_table(META).map_err(storage)?,
        })
    }
}

/// Applies commands within one write transaction.
struct Writer<'t, 'l> {
    t: Tables<'t>,
    ids: Ids,
    limits: &'l Limits,
    /// The revision of the last applied command.
    rev: i64,
    compacted: i64,
    applied: u64,
    /// Changes made at rev + 1 by the command being applied.
    changes: u32,
}

impl<'t, 'l> Writer<'t, 'l> {
    fn open(txn: &'t WriteTransaction, ids: Ids, limits: &'l Limits) -> Result<Writer<'t, 'l>> {
        let t = Tables::open(txn)?;
        let rev = get_meta(&t.meta, M_REVISION)? as i64;
        let compacted = get_meta(&t.meta, M_COMPACTED)? as i64;
        let applied = get_meta(&t.meta, M_APPLIED)?;
        Ok(Writer {
            t,
            ids,
            limits,
            rev,
            compacted,
            applied,
            changes: 0,
        })
    }

    fn save(&mut self) -> Result<()> {
        self.t
            .meta
            .insert(M_REVISION, self.rev as u64)
            .map_err(storage)?;
        self.t
            .meta
            .insert(M_APPLIED, self.applied)
            .map_err(storage)?;
        self.t
            .meta
            .insert(M_COMPACTED, self.compacted as u64)
            .map_err(storage)?;
        Ok(())
    }

    /// The revision a read in the command sees: rev + 1 once it changed
    /// something.
    fn read_rev(&self) -> i64 {
        if self.changes > 0 {
            self.rev + 1
        } else {
            self.rev
        }
    }

    /// Ends a command: its changes, if any, become revision rev + 1.
    fn finish(&mut self) -> i64 {
        if self.changes > 0 {
            self.rev += 1;
            self.changes = 0;
        }
        self.rev
    }

    fn event(&mut self, kind: u8, key: &[u8]) -> Result<()> {
        let mut v = Vec::with_capacity(key.len() + 1);
        v.push(kind);
        v.extend_from_slice(key);
        self.t
            .events
            .insert((self.rev + 1, self.changes), v.as_slice())
            .map_err(storage)?;
        self.changes += 1;
        Ok(())
    }

    fn current(&self, key: &[u8]) -> Result<Option<KeyValue>> {
        match self.t.latest.get(key).map_err(storage)? {
            Some(v) => decode_kv(key, v.value()).map(Some),
            None => Ok(None),
        }
    }

    fn lease_exists(&self, id: i64) -> Result<bool> {
        Ok(self.t.leases.get(id).map_err(storage)?.is_some())
    }

    /// The checks of a put that need the key space.
    fn check_put_state(&self, p: &pb::PutRequest) -> Result<()> {
        if (p.ignore_value || p.ignore_lease) && self.current(&p.key)?.is_none() {
            return Err(Error::KeyNotFound);
        }
        if !p.ignore_lease && p.lease != 0 && !self.lease_exists(p.lease)? {
            return Err(Error::LeaseNotFound);
        }
        Ok(())
    }

    /// Writes a put (checked) at rev + 1: the previous version.
    fn put(&mut self, p: &pb::PutRequest) -> Result<Option<KeyValue>> {
        let prev = self.current(&p.key)?;
        let at = self.rev + 1;
        let value = match (&prev, p.ignore_value) {
            (Some(pr), true) => pr.value.clone(),
            _ => p.value.clone(),
        };
        let lease = match (&prev, p.ignore_lease) {
            (Some(pr), true) => pr.lease,
            _ => p.lease,
        };
        let kv = KeyValue {
            key: Vec::new(),
            create_revision: prev.as_ref().map_or(at, |pr| pr.create_revision),
            mod_revision: at,
            version: prev.as_ref().map_or(0, |pr| pr.version) + 1,
            value,
            lease,
        };
        let v = kv.encode_to_vec();
        let key = p.key.as_slice();
        self.t.latest.insert(key, v.as_slice()).map_err(storage)?;
        self.t
            .history
            .insert((key, at), v.as_slice())
            .map_err(storage)?;
        if let Some(pr) = &prev
            && pr.lease != 0
            && pr.lease != lease
        {
            self.t.lease_keys.remove((pr.lease, key)).map_err(storage)?;
        }
        if lease != 0 {
            self.t
                .lease_keys
                .insert((lease, key), ())
                .map_err(storage)?;
        }
        self.event(EVENT_PUT, key)?;
        Ok(prev)
    }

    /// Deletes one existing key at rev + 1: its last version.
    fn delete_key(&mut self, key: &[u8]) -> Result<Option<KeyValue>> {
        let Some(prev) = self.current(key)? else {
            return Ok(None);
        };
        let at = self.rev + 1;
        self.t.latest.remove(key).map_err(storage)?;
        let tomb = KeyValue {
            mod_revision: at,
            ..Default::default()
        }
        .encode_to_vec();
        self.t
            .history
            .insert((key, at), tomb.as_slice())
            .map_err(storage)?;
        if prev.lease != 0 {
            self.t
                .lease_keys
                .remove((prev.lease, key))
                .map_err(storage)?;
        }
        self.event(EVENT_DELETE, key)?;
        Ok(Some(prev))
    }

    fn delete_range(&mut self, key: &[u8], end: &[u8]) -> Result<Vec<KeyValue>> {
        let kvs = kvs_latest(&self.t.latest, KeyRange::of(key, end))?;
        for kv in &kvs {
            self.delete_key(&kv.key)?;
        }
        Ok(kvs)
    }

    /// Revokes a lease that exists: its keys are deleted at rev + 1.
    fn revoke(&mut self, id: i64) -> Result<()> {
        let mut keys = Vec::new();
        for e in self.t.lease_keys.range((id, &b""[..])..).map_err(storage)? {
            let (k, _) = e.map_err(storage)?;
            let (lid, key) = k.value();
            if lid != id {
                break;
            }
            keys.push(key.to_vec());
        }
        for k in &keys {
            self.delete_key(k)?;
        }
        for k in &keys {
            self.t
                .lease_keys
                .remove((id, k.as_slice()))
                .map_err(storage)?;
        }
        self.t.leases.remove(id).map_err(storage)?;
        Ok(())
    }

    /// Drops the history below revision at: each key keeps its newest
    /// version at or below it (a tombstone only when written at it).
    fn compact(&mut self, at: i64) -> Result<()> {
        let mut keys: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut gone = Vec::new();
        for e in self.t.events.range(..(at, 0u32)).map_err(storage)? {
            let (k, v) = e.map_err(storage)?;
            gone.push(k.value());
            if let Some((_, key)) = v.value().split_first() {
                keys.insert(key.to_vec());
            }
        }
        for k in gone {
            self.t.events.remove(k).map_err(storage)?;
        }
        for key in keys {
            let mut entries = Vec::new();
            for e in self
                .t
                .history
                .range((key.as_slice(), i64::MIN)..=(key.as_slice(), at))
                .map_err(storage)?
            {
                let (k, v) = e.map_err(storage)?;
                let tomb = KeyValue::decode(v.value()).map_err(storage)?.version == 0;
                entries.push((k.value().1, tomb));
            }
            let keep = match entries.last() {
                Some(&(r, tomb)) if !tomb || r == at => Some(r),
                _ => None,
            };
            for (r, _) in entries {
                if Some(r) != keep {
                    self.t
                        .history
                        .remove((key.as_slice(), r))
                        .map_err(storage)?;
                }
            }
        }
        self.compacted = at;
        Ok(())
    }

    fn apply(&mut self, c: &Command) -> Result<Applied> {
        let mut granted = None;
        let mut revoked = None;
        let response = match &c.op {
            None => return Err(Error::Unimplemented("an empty command".into())),
            Some(Op::Put(p)) => {
                check_put(p)?;
                self.check_put_state(p)?;
                let prev = self.put(p)?;
                let rev = self.finish();
                Response::Put(pb::PutResponse {
                    header: Some(self.ids.header(rev)),
                    prev_kv: if p.prev_kv { prev } else { None },
                })
            }
            Some(Op::DeleteRange(d)) => {
                if d.key.is_empty() {
                    return Err(Error::EmptyKey);
                }
                let prev = self.delete_range(&d.key, &d.range_end)?;
                let rev = self.finish();
                Response::DeleteRange(pb::DeleteRangeResponse {
                    header: Some(self.ids.header(rev)),
                    deleted: prev.len() as i64,
                    prev_kvs: if d.prev_kv { prev } else { Vec::new() },
                })
            }
            Some(Op::Txn(t)) => Response::Txn(self.txn(t)?),
            Some(Op::LeaseGrant(g)) => {
                if g.ttl > MAX_LEASE_TTL {
                    return Err(Error::LeaseTtlTooLarge);
                }
                if g.id == 0 {
                    return Err(Error::Unimplemented("a lease without an ID".into()));
                }
                if self.lease_exists(g.id)? {
                    return Err(Error::LeaseExists);
                }
                let ttl = g.ttl.max(self.limits.min_lease_ttl);
                self.t.leases.insert(g.id, ttl).map_err(storage)?;
                granted = Some((g.id, ttl));
                Response::LeaseGrant(pb::LeaseGrantResponse {
                    header: Some(self.ids.header(self.rev)),
                    id: g.id,
                    ttl,
                    error: String::new(),
                })
            }
            Some(Op::LeaseRevoke(r)) => {
                if !self.lease_exists(r.id)? {
                    return Err(Error::LeaseNotFound);
                }
                self.revoke(r.id)?;
                let rev = self.finish();
                revoked = Some(r.id);
                Response::LeaseRevoke(pb::LeaseRevokeResponse {
                    header: Some(self.ids.header(rev)),
                })
            }
            Some(Op::LeaseExpire(r)) => {
                if self.lease_exists(r.id)? {
                    self.revoke(r.id)?;
                }
                let rev = self.finish();
                revoked = Some(r.id);
                Response::LeaseRevoke(pb::LeaseRevokeResponse {
                    header: Some(self.ids.header(rev)),
                })
            }
            Some(Op::Compact(c)) => {
                if c.revision > self.rev {
                    return Err(Error::FutureRev);
                }
                if c.revision <= self.compacted {
                    return Err(Error::Compacted);
                }
                self.compact(c.revision)?;
                Response::Compact(pb::CompactionResponse {
                    header: Some(self.ids.header(self.rev)),
                })
            }
        };
        Ok(Applied {
            revision: self.rev,
            response,
            granted,
            revoked,
        })
    }

    fn txn(&mut self, t: &pb::TxnRequest) -> Result<pb::TxnResponse> {
        check_txn(t, self.limits.max_txn_ops)?;
        let mut succeeded = true;
        for c in &t.compare {
            if !compare(&self.t.latest, c)? {
                succeeded = false;
                break;
            }
        }
        let ops = if succeeded { &t.success } else { &t.failure };
        // Everything that can refuse the branch, before any change.
        for o in ops {
            match &o.request {
                Some(Request::RequestRange(r)) => check_rev(r.revision, self.rev, self.compacted)?,
                Some(Request::RequestPut(p)) => self.check_put_state(p)?,
                _ => {}
            }
        }
        let mut responses = Vec::with_capacity(ops.len());
        for o in ops {
            let r = match &o.request {
                None => continue,
                Some(Request::RequestRange(r)) => {
                    let cur = self.read_rev();
                    OpResponse::ResponseRange(range(
                        &self.t.latest,
                        &self.t.history,
                        r,
                        cur,
                        self.ids,
                    )?)
                }
                Some(Request::RequestPut(p)) => {
                    let prev = self.put(p)?;
                    OpResponse::ResponsePut(pb::PutResponse {
                        header: Some(self.ids.header(self.rev + 1)),
                        prev_kv: if p.prev_kv { prev } else { None },
                    })
                }
                Some(Request::RequestDeleteRange(d)) => {
                    let prev = self.delete_range(&d.key, &d.range_end)?;
                    OpResponse::ResponseDeleteRange(pb::DeleteRangeResponse {
                        header: Some(self.ids.header(self.read_rev())),
                        deleted: prev.len() as i64,
                        prev_kvs: if d.prev_kv { prev } else { Vec::new() },
                    })
                }
                Some(Request::RequestTxn(_)) => {
                    return Err(Error::Unimplemented(
                        "a transaction inside a transaction".into(),
                    ));
                }
            };
            responses.push(pb::ResponseOp { response: Some(r) });
        }
        let rev = self.finish();
        Ok(pb::TxnResponse {
            header: Some(self.ids.header(rev)),
            succeeded,
            responses,
        })
    }
}

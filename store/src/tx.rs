//! The store and its optimistic transactions (Go's Etcd and etx).
//!
//! A transaction reads a consistent snapshot at one etcd revision, buffers
//! its writes, and commits them atomically only if no other transaction
//! committed in between, which it detects through a single commit key that
//! every write updates. On a conflict it runs again, so its body may run
//! more than once and must have no side effects outside the transaction.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use armada_proto::etcd::etcdserverpb as pb;
use armada_spec::gotime::Time;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::client::{Client, op};
use crate::error::{Error, Kind, Result, other};
use crate::gojson::{decode, marshal};

/// Key layout below the prefix.
pub(crate) const KEY_COMMIT: &str = "commit";
pub(crate) const KEY_AUDIT_SEQ: &str = "auditseq";
pub(crate) const KEY_SCHEMA: &str = "schema";
pub(crate) const PFX_META: &str = "meta/";
pub(crate) const PFX_NODES: &str = "nodes/";
pub(crate) const PFX_CERTS: &str = "nodecerts/";
pub(crate) const PFX_TOKENS: &str = "tokens/";
pub(crate) const PFX_APPS: &str = "apps/";
pub(crate) const PFX_REVS: &str = "revs/";
pub(crate) const PFX_REPLICAS: &str = "replicas/";
pub(crate) const PFX_SECRETS: &str = "secrets/";
pub(crate) const PFX_SECRET_SEQ: &str = "secretseq/";
pub(crate) const PFX_SECRET_USERS: &str = "secretusers/";
pub(crate) const PFX_DOMAINS: &str = "domains/";
pub(crate) const PFX_AUDIT: &str = "audit/";
pub(crate) const PFX_SERVERS: &str = "servers/";
pub(crate) const PFX_RUNS: &str = "runs/";
pub(crate) const PFX_VOLUMES: &str = "volumes/";

/// The version of the key layout (etcdSchema): the schema of the last Go
/// release. A newer stored schema is refused.
pub const SCHEMA: i64 = 15;

const MAX_TXN_RETRIES: u32 = 100;

/// readBatch: how many keys one read asks for.
pub(crate) const READ_BATCH: usize = 128;

/// The clock timestamps come from.
pub type Clock = Arc<dyn Fn() -> Time + Send + Sync>;
/// The source of random bytes (domain tokens and event keys).
pub type Random = Arc<dyn Fn(&mut [u8]) + Send + Sync>;
type CommitHook = Arc<dyn Fn(usize) + Send + Sync>;
type ListHook = Arc<dyn Fn(&str, usize) + Send + Sync>;

/// The cluster state in etcd: every record a JSON value under the prefix.
#[derive(Clone)]
pub struct Etcd {
    pub(crate) c: Client,
    pub(crate) prefix: String,
    now: Clock,
    rand: Random,
    fence: Option<(String, i64)>,
    /// The lease of the current hour's events, shared by fenced copies.
    pub(crate) leases: Arc<tokio::sync::Mutex<(i64, i64)>>,
    on_commit: Option<CommitHook>,
    on_list: Option<ListHook>,
}

fn system_random(b: &mut [u8]) {
    use ring::rand::SecureRandom;
    ring::rand::SystemRandom::new()
        .fill(b)
        .expect("the system's random source works");
}

/// Times one transaction body runs in (see `tx!`).
pub(crate) struct Etx<'a> {
    pub s: &'a Etcd,
    pub rev: i64,
    mod_rev: i64,
    ops: BTreeMap<String, Vec<u8>>,
    del: BTreeSet<String>,
    ranges: Vec<(String, String)>,
}

/// Runs a transaction body, retrying it on conflicts: `tx!(store, |t| {
/// ...; Ok(()) })?`. The body is an async block over `t: &mut Etx`; it may
/// run more than once.
macro_rules! tx {
    ($s:expr, |$t:ident| $body:block) => {{
        let __s: &$crate::tx::Etcd = $s;
        let mut __attempt = 0u32;
        loop {
            let mut __etx = __s.begin().await?;
            {
                let $t = &mut __etx;
                let __r: $crate::error::Result<()> = async {
                    let __v: $crate::error::Result<()> = $body;
                    __v
                }
                .await;
                __r?;
            }
            if __s.commit(__etx, &mut __attempt).await? {
                break;
            }
        }
        $crate::error::Result::<()>::Ok(())
    }};
}

/// Runs a body on a consistent snapshot without writing (Go's view).
macro_rules! view {
    ($s:expr, |$t:ident| $body:block) => {{
        let __s: &$crate::tx::Etcd = $s;
        let mut __etx = __s.begin().await?;
        {
            let $t = &mut __etx;
            let __r: $crate::error::Result<()> = async {
                let __v: $crate::error::Result<()> = $body;
                __v
            }
            .await;
            __r?;
        }
        if __etx.dirty() {
            return Err($crate::error::other!("store: write in a read-only view"));
        }
        $crate::error::Result::<()>::Ok(())
    }};
}

pub(crate) use {tx, view};

impl Etcd {
    /// NewEtcd: a store using c under prefix (e.g. "/armada/"), after
    /// checking the stored schema: an empty keyspace gets this schema, a
    /// newer one is refused.
    pub async fn new(c: Client, prefix: &str) -> Result<Etcd> {
        if !prefix.ends_with('/') {
            return Err(other!("store: etcd prefix must end with /"));
        }
        let s = Etcd {
            c,
            prefix: prefix.to_string(),
            now: Arc::new(crate::gojson::now),
            rand: Arc::new(system_random),
            fence: None,
            leases: Arc::new(tokio::sync::Mutex::new((0, 0))),
            on_commit: None,
            on_list: None,
        };
        tx!(&s, |t| {
            match t.get::<i64>(KEY_SCHEMA).await? {
                None => t.put(KEY_SCHEMA, &SCHEMA)?,
                Some(v) if v > SCHEMA => {
                    return Err(other!(
                        "the state was written by a newer Armada (schema {v}, this binary knows {SCHEMA}); run the newer version (downgrades are not supported)"
                    ));
                }
                Some(_) => {}
            }
            Ok(())
        })?;
        Ok(s)
    }

    /// The client the store uses.
    pub fn client(&self) -> &Client {
        &self.c
    }

    /// The prefix the store keeps its records under.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// SetNow replaces the clock (tests drive time by hand).
    pub fn set_now(&mut self, now: Clock) {
        self.now = now;
    }

    /// Replaces the random source (the parity tests make it predictable).
    pub fn set_random(&mut self, rand: Random) {
        self.rand = rand;
    }

    /// Sees the operation count of each transaction's commit (tests).
    pub fn on_commit(&mut self, f: impl Fn(usize) + Send + Sync + 'static) {
        self.on_commit = Some(Arc::new(f));
    }

    /// Sees the prefix and stored key count of each list (tests).
    pub fn on_list(&mut self, f: impl Fn(&str, usize) + Send + Sync + 'static) {
        self.on_list = Some(Arc::new(f));
    }

    pub(crate) fn now(&self) -> Time {
        (self.now)()
    }

    pub(crate) fn random(&self, b: &mut [u8]) {
        (self.rand)(b)
    }

    /// Fenced returns a store whose writes commit only while the etcd key
    /// exists with the given creation revision: the leader election key of
    /// one leadership term. Its writes fail with ErrNotLeader after that.
    pub fn fenced(&self, key: &str, rev: i64) -> Etcd {
        let mut f = self.clone();
        f.fence = Some((key.to_string(), rev));
        f
    }

    pub(crate) fn fence(&self) -> Option<&(String, i64)> {
        self.fence.as_ref()
    }

    /// fenceHolds: whether the fence key still has its revision.
    pub(crate) async fn fence_holds(&self) -> Result<bool> {
        let Some((key, rev)) = &self.fence else {
            return Ok(true);
        };
        let r = self.c.range(op::get(key, 0)).await?;
        Ok(r.kvs.len() == 1 && r.kvs[0].create_revision == *rev)
    }

    pub(crate) async fn begin(&self) -> Result<Etx<'_>> {
        let commit = format!("{}{KEY_COMMIT}", self.prefix);
        let r = self.c.range(op::get(&commit, 0)).await?;
        let mod_rev = r.kvs.first().map_or(0, |kv| kv.mod_revision);
        Ok(Etx {
            s: self,
            rev: r.header.map_or(0, |h| h.revision),
            mod_rev,
            ops: BTreeMap::new(),
            del: BTreeSet::new(),
            ranges: Vec::new(),
        })
    }

    /// Commits t, reporting whether it is done; false means it collided
    /// and must run again.
    pub(crate) async fn commit(&self, t: Etx<'_>, attempt: &mut u32) -> Result<bool> {
        if !t.dirty() {
            return Ok(true);
        }
        let commit = format!("{}{KEY_COMMIT}", self.prefix);
        let mut ops = Vec::with_capacity(t.ops.len() + t.del.len() + t.ranges.len() + 1);
        for (k, v) in &t.ops {
            ops.push(op::put(&t.full(k), v, 0));
        }
        for k in &t.del {
            ops.push(op::delete(&t.full(k)));
        }
        for (from, to) in &t.ranges {
            ops.push(op::delete_range(&t.full(from), &t.full(to)));
        }
        ops.push(op::put(&commit, b"", 0));
        if let Some(f) = &self.on_commit {
            f(ops.len());
        }
        let mut cmps = vec![op::mod_is(&commit, t.mod_rev)];
        if let Some((key, rev)) = &self.fence {
            cmps.push(op::created_at(key, *rev));
        }
        let r = self
            .c
            .txn(pb::TxnRequest {
                compare: cmps,
                success: ops,
                failure: Vec::new(),
            })
            .await?;
        if r.succeeded {
            return Ok(true);
        }
        if self.fence.is_some() && !self.fence_holds().await? {
            return Err(Error::bare(Kind::NotLeader));
        }
        *attempt += 1;
        if *attempt >= MAX_TXN_RETRIES {
            return Err(other!("store: too many concurrent changes; try again"));
        }
        tokio::time::sleep(Duration::from_millis(u64::from(*attempt))).await;
        Ok(false)
    }
}

impl Etx<'_> {
    pub(crate) fn full(&self, k: &str) -> String {
        format!("{}{k}", self.s.prefix)
    }

    /// deleted reports whether k is deleted in this transaction.
    pub(crate) fn deleted(&self, k: &str) -> bool {
        self.del.contains(k)
            || self
                .ranges
                .iter()
                .any(|(f, to)| k >= f.as_str() && k < to.as_str())
    }

    /// deleteRange: every key in [from, to) with one operation. Nothing
    /// may be written into the range afterwards in the same transaction.
    pub(crate) fn delete_range(&mut self, from: &str, to: &str) {
        self.ops
            .retain(|k, _| !(k.as_str() >= from && k.as_str() < to));
        self.del
            .retain(|k| !(k.as_str() >= from && k.as_str() < to));
        self.ranges.push((from.to_string(), to.to_string()));
    }

    /// deletePrefix: every key under prefix with one operation.
    pub(crate) fn delete_prefix(&mut self, prefix: &str) {
        let end = String::from_utf8(op::prefix_end(prefix)).expect("prefixes are ASCII");
        self.delete_range(prefix, &end);
    }

    pub(crate) async fn get_raw(&self, k: &str) -> Result<Option<Vec<u8>>> {
        if self.deleted(k) {
            return Ok(None);
        }
        if let Some(v) = self.ops.get(k) {
            return Ok(Some(v.clone()));
        }
        let r = self.s.c.range(op::get(&self.full(k), self.rev)).await?;
        Ok(r.kvs.into_iter().next().map(|kv| kv.value))
    }

    /// getMany: the records at keys that exist, by key, in as few round
    /// trips as the batch size allows, writes of this transaction included.
    pub(crate) async fn get_many(&self, keys: &[String]) -> Result<HashMap<String, Vec<u8>>> {
        let mut out = HashMap::with_capacity(keys.len());
        let mut remote = Vec::new();
        for k in keys {
            if self.deleted(k) {
                continue;
            }
            if let Some(v) = self.ops.get(k) {
                out.insert(k.clone(), v.clone());
                continue;
            }
            remote.push(k.clone());
        }
        for batch in remote.chunks(READ_BATCH) {
            let ops = batch
                .iter()
                .map(|k| op::range(op::get(&self.full(k), self.rev)))
                .collect();
            let r = self
                .s
                .c
                .txn(pb::TxnRequest {
                    compare: Vec::new(),
                    success: ops,
                    failure: Vec::new(),
                })
                .await?;
            for (i, k) in batch.iter().enumerate() {
                if let Some(kv) = op::range_of(&r, i).and_then(|rr| rr.kvs.first()) {
                    out.insert(k.clone(), kv.value.clone());
                }
            }
        }
        Ok(out)
    }

    /// get decodes the record at k, None when it does not exist.
    pub(crate) async fn get<T: DeserializeOwned>(&self, k: &str) -> Result<Option<T>> {
        match self.get_raw(k).await? {
            None => Ok(None),
            Some(b) => decode(k, &b).map(Some),
        }
    }

    /// list: the records under prefix in key order, writes of this
    /// transaction included.
    pub(crate) async fn list(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let r = self
            .s
            .c
            .range(op::get_prefix(&self.full(prefix), self.rev))
            .await?;
        if let Some(f) = &self.s.on_list {
            f(prefix, r.kvs.len());
        }
        let mut m: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for kv in r.kvs {
            let k = String::from_utf8_lossy(&kv.key);
            let k = k
                .strip_prefix(self.s.prefix.as_str())
                .unwrap_or(&k)
                .to_string();
            m.insert(k, kv.value);
        }
        for (k, v) in &self.ops {
            if k.starts_with(prefix) {
                m.insert(k.clone(), v.clone());
            }
        }
        Ok(m.into_iter().filter(|(k, _)| !self.deleted(k)).collect())
    }

    /// list with every record decoded, in key order, failing at the first
    /// record that does not decode (listInto).
    pub(crate) async fn list_into<T: DeserializeOwned>(
        &self,
        prefix: &str,
    ) -> Result<Vec<(String, T)>> {
        let kvs = self.list(prefix).await?;
        let mut out = Vec::with_capacity(kvs.len());
        for (k, v) in kvs {
            let rec = decode(&k, &v)?;
            out.push((k, rec));
        }
        Ok(out)
    }

    pub(crate) fn put<T: Serialize + ?Sized>(&mut self, k: &str, v: &T) -> Result<()> {
        self.put_raw(k, marshal(v))
    }

    pub(crate) fn put_raw(&mut self, k: &str, b: Vec<u8>) -> Result<()> {
        if self
            .ranges
            .iter()
            .any(|(f, to)| k >= f.as_str() && k < to.as_str())
        {
            // etcd refuses a write inside a deleted range in one transaction.
            return Err(other!("store: write to {k} after deleting its range"));
        }
        self.del.remove(k);
        self.ops.insert(k.to_string(), b);
        Ok(())
    }

    pub(crate) fn delete(&mut self, k: &str) {
        self.ops.remove(k);
        if !self.deleted(k) {
            self.del.insert(k.to_string());
        }
    }

    pub(crate) fn dirty(&self) -> bool {
        !self.ops.is_empty() || !self.del.is_empty() || !self.ranges.is_empty()
    }
}

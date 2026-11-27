//! The state machine Raft applies committed entries to: the key space
//! (crate::mvcc). Each batch of entries is one durable commit holding
//! their changes and the last applied log ID (and membership), so the
//! member restarts exactly where it left off.
//!
//! A snapshot is the key space in the store's snapshot format
//! (crate::snapshot) with its last applied log ID and membership as
//! openraft's metadata; installing one replaces the key space and keeps
//! the member's and cluster's IDs.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use openraft::storage::{EntryResponder, RaftSnapshotBuilder, RaftStateMachine};
use tokio::sync::watch;

use crate::command::Command;
use crate::log::{blocking, io_err};
use crate::mvcc::{Applied, Store};
use crate::raft::{
    self, LogId, Payload, Reply, Snapshot, SnapshotMeta, StoredMembership, Tc, WLogId,
    WStoredMembership,
};

pub(crate) const K_APPLIED: &str = "applied";
pub(crate) const K_MEMBERSHIP: &str = "membership";

/// Entries applied in one commit at most.
const MAX_BATCH: usize = 256;

/// A lease as the member's clock follows it.
pub(crate) struct Lease {
    pub ttl: i64,
    pub deadline: Instant,
    /// An expiry was proposed.
    pub expiring: bool,
}

pub(crate) fn ttl_duration(ttl: i64) -> Duration {
    Duration::from_secs(ttl.max(0) as u64)
}

/// What the state machine and the services share.
pub(crate) struct Shared {
    /// The revision after the last commit.
    pub rev: watch::Sender<i64>,
    /// The index of the last applied log entry.
    pub applied: watch::Sender<u64>,
    pub leases: Mutex<HashMap<i64, Lease>>,
}

impl Shared {
    pub fn new(store: &Store) -> crate::Result<Shared> {
        let state = store.state()?;
        let applied = match store.raft_get(K_APPLIED)? {
            Some(b) => raft::decode::<WLogId>(&b, K_APPLIED)?.index,
            None => 0,
        };
        let shared = Shared {
            rev: watch::channel(state.revision).0,
            applied: watch::channel(applied).0,
            leases: Mutex::new(HashMap::new()),
        };
        shared.reload_leases(store)?;
        Ok(shared)
    }

    /// Every lease of the store with its whole TTL again (as etcd's lessor
    /// when a leader starts).
    pub fn reload_leases(&self, store: &Store) -> crate::Result<()> {
        let now = Instant::now();
        let leases = store
            .leases()?
            .into_iter()
            .map(|(id, ttl)| {
                (
                    id,
                    Lease {
                        ttl,
                        deadline: now + ttl_duration(ttl),
                        expiring: false,
                    },
                )
            })
            .collect();
        *self.leases.lock().expect("not poisoned") = leases;
        Ok(())
    }

    /// Gives every lease its whole TTL again: a member that becomes the
    /// leader does not know when the last one last heard of them.
    pub fn renew_all(&self) {
        let now = Instant::now();
        for l in self.leases.lock().expect("not poisoned").values_mut() {
            l.deadline = now + ttl_duration(l.ttl);
            l.expiring = false;
        }
    }

    fn follow(&self, results: &[Option<crate::Result<Applied>>], applied: u64) {
        let now = Instant::now();
        let mut rev = None;
        {
            let mut leases = self.leases.lock().expect("not poisoned");
            for r in results.iter().flatten().flatten() {
                if let Some((id, ttl)) = r.granted {
                    leases.insert(
                        id,
                        Lease {
                            ttl,
                            deadline: now + ttl_duration(ttl),
                            expiring: false,
                        },
                    );
                }
                if let Some(id) = r.revoked {
                    leases.remove(&id);
                }
                rev = Some(r.revision);
            }
        }
        if let Some(rev) = rev {
            self.set_rev(rev);
        }
        self.applied.send_if_modified(|a| {
            let changed = *a != applied;
            *a = applied;
            changed
        });
    }

    fn set_rev(&self, rev: i64) {
        self.rev.send_if_modified(|r| {
            let changed = *r != rev;
            *r = rev;
            changed
        });
    }
}

/// The state machine of a member.
pub struct StateMachine {
    store: Arc<Store>,
    shared: Arc<Shared>,
}

impl StateMachine {
    pub(crate) fn new(store: Arc<Store>, shared: Arc<Shared>) -> StateMachine {
        StateMachine { store, shared }
    }
}

fn kv_err(e: crate::Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// The snapshot of the store with its Raft metadata, or None before
/// anything was applied.
fn build(store: &Store) -> io::Result<Option<Snapshot>> {
    let (data, vals) = store
        .snapshot_with(&[K_APPLIED, K_MEMBERSHIP])
        .map_err(kv_err)?;
    let Some(applied) = &vals[0] else {
        return Ok(None);
    };
    let last: LogId = raft::decode::<WLogId>(applied, K_APPLIED)
        .map_err(kv_err)?
        .into();
    let membership: StoredMembership = match &vals[1] {
        Some(b) => raft::decode::<WStoredMembership>(b, K_MEMBERSHIP)
            .map_err(kv_err)?
            .try_into()
            .map_err(kv_err)?,
        None => StoredMembership::default(),
    };
    Ok(Some(openraft::Snapshot {
        meta: SnapshotMeta {
            last_log_id: Some(last),
            last_membership: membership,
        },
        snapshot: data,
    }))
}

/// Builds snapshots of the state machine.
pub struct Builder {
    store: Arc<Store>,
}

impl RaftSnapshotBuilder<Tc> for Builder {
    type SnapshotData = Vec<u8>;

    async fn build_snapshot(&mut self) -> io::Result<Snapshot> {
        let store = self.store.clone();
        blocking(move || build(&store)?.ok_or_else(|| io_err("nothing applied yet"))).await
    }
}

impl RaftStateMachine<Tc> for StateMachine {
    type SnapshotData = Vec<u8>;
    type SnapshotBuilder = Builder;

    async fn applied_state(&mut self) -> io::Result<(Option<LogId>, StoredMembership)> {
        let applied = match self.store.raft_get(K_APPLIED).map_err(kv_err)? {
            Some(b) => Some(
                raft::decode::<WLogId>(&b, K_APPLIED)
                    .map_err(kv_err)?
                    .into(),
            ),
            None => None,
        };
        let membership = match self.store.raft_get(K_MEMBERSHIP).map_err(kv_err)? {
            Some(b) => raft::decode::<WStoredMembership>(&b, K_MEMBERSHIP)
                .map_err(kv_err)?
                .try_into()
                .map_err(kv_err)?,
            None => StoredMembership::default(),
        };
        Ok((applied, membership))
    }

    async fn apply<S>(&mut self, mut entries: S) -> io::Result<()>
    where
        S: futures_util::Stream<Item = io::Result<EntryResponder<Tc>>> + Unpin + Send,
    {
        let mut all = Vec::new();
        while let Some(e) = entries.next().await {
            all.push(e?);
        }
        while !all.is_empty() {
            let rest = all.split_off(all.len().min(MAX_BATCH));
            let batch = std::mem::replace(&mut all, rest);
            let mut cmds: Vec<Option<Command>> = Vec::with_capacity(batch.len());
            let mut responders = Vec::with_capacity(batch.len());
            let mut last = None;
            let mut membership = None;
            for (e, r) in batch {
                match e.payload {
                    Payload::Normal(c) => cmds.push(Some(c)),
                    Payload::Blank => cmds.push(None),
                    Payload::Membership(m) => {
                        cmds.push(None);
                        membership = Some(openraft::StoredMembership::new(Some(e.log_id), m));
                    }
                }
                last = Some(e.log_id);
                responders.push(r);
            }
            let Some(last) = last else { break };
            let mut meta = vec![(K_APPLIED, raft::encode(&WLogId::from(&last)))];
            if let Some(m) = &membership {
                meta.push((K_MEMBERSHIP, raft::encode(&WStoredMembership::from(m))));
            }
            let store = self.store.clone();
            let results = blocking(move || {
                let refs: Vec<Option<&Command>> = cmds.iter().map(Option::as_ref).collect();
                store.apply_logged(&refs, &meta).map_err(kv_err)
            })
            .await?;
            self.shared.follow(&results, last.index);
            for (r, res) in responders.into_iter().zip(results) {
                if let Some(r) = r {
                    r.send(Reply(res));
                }
            }
        }
        Ok(())
    }

    async fn get_snapshot_builder(&mut self) -> Builder {
        Builder {
            store: self.store.clone(),
        }
    }

    async fn try_create_snapshot_builder(&mut self, _force: bool) -> Option<Builder> {
        Some(Builder {
            store: self.store.clone(),
        })
    }

    async fn install_snapshot(&mut self, meta: &SnapshotMeta, data: Vec<u8>) -> io::Result<()> {
        let mut raft_meta = vec![(
            K_MEMBERSHIP,
            raft::encode(&WStoredMembership::from(&meta.last_membership)),
        )];
        if let Some(l) = &meta.last_log_id {
            raft_meta.push((K_APPLIED, raft::encode(&WLogId::from(l))));
        }
        let applied = meta.last_log_id.map_or(0, |l| l.index);
        let store = self.store.clone();
        let rev = blocking(move || {
            store.install(&data, &raft_meta).map_err(kv_err)?;
            Ok(store.state().map_err(kv_err)?.revision)
        })
        .await?;
        self.shared.reload_leases(&self.store).map_err(kv_err)?;
        self.shared.set_rev(rev);
        self.shared.applied.send_replace(applied);
        Ok(())
    }

    async fn get_current_snapshot(&mut self) -> io::Result<Option<Snapshot>> {
        let store = self.store.clone();
        blocking(move || build(&store)).await
    }
}

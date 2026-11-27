//! The Raft log and vote, in the member's database beside the key space
//! (ADR 0057): `raft_log` holds the entries by index, `raft` the vote and
//! the purged and committed log IDs. Every change is one durable commit,
//! made before openraft is told it is done.

use std::fmt::Debug;
use std::io;
use std::ops::{Bound, RangeBounds};
use std::sync::Arc;

use openraft::storage::{IOFlushed, LogState, RaftLogReader, RaftLogStorage};
use redb::{ReadableDatabase, ReadableTable};

use crate::error::Error;
use crate::mvcc::{RAFT, RAFT_LOG, Store};
use crate::raft::{self, Entry, LogId, Tc, Vote, WLogId, WVote};

pub(crate) const K_VOTE: &str = "vote";
pub(crate) const K_PURGED: &str = "purged";
pub(crate) const K_COMMITTED: &str = "committed";

/// The log of a member. Clones share it.
#[derive(Clone)]
pub struct LogStore {
    store: Arc<Store>,
}

pub(crate) fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

fn kv_err(e: Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// Runs f off the async runtime's threads: redb commits wait for the disk.
pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    tokio::task::spawn_blocking(f).await.map_err(io_err)?
}

impl LogStore {
    pub fn new(store: Arc<Store>) -> LogStore {
        LogStore { store }
    }

    fn get_log_id(&self, key: &str) -> io::Result<Option<LogId>> {
        match self.store.raft_get(key).map_err(kv_err)? {
            Some(b) => Ok(Some(
                raft::decode::<WLogId>(&b, key).map_err(kv_err)?.into(),
            )),
            None => Ok(None),
        }
    }

    fn put_raft(&self, key: &'static str, val: Vec<u8>) -> io::Result<()> {
        let txn = self.store.db().begin_write().map_err(io_err)?;
        {
            let mut t = txn.open_table(RAFT).map_err(io_err)?;
            t.insert(key, val.as_slice()).map_err(io_err)?;
        }
        txn.commit().map_err(io_err)
    }

    /// The last log ID, if the log holds an entry.
    fn last_entry(&self) -> io::Result<Option<LogId>> {
        let txn = self.store.db().begin_read().map_err(io_err)?;
        let t = txn.open_table(RAFT_LOG).map_err(io_err)?;
        match t.last().map_err(io_err)? {
            Some((_, v)) => Ok(Some(raft::decode_entry(v.value()).map_err(kv_err)?.log_id)),
            None => Ok(None),
        }
    }

    /// Whether the member has any Raft state: a vote, a log, or anything
    /// applied (a member that never started has none).
    pub fn is_pristine(&self) -> io::Result<bool> {
        Ok(self.store.raft_get(K_VOTE).map_err(kv_err)?.is_none()
            && self.last_entry()?.is_none()
            && self.get_log_id(K_PURGED)?.is_none()
            && self
                .store
                .raft_get(crate::sm::K_APPLIED)
                .map_err(kv_err)?
                .is_none())
    }
}

fn bounds(range: &impl RangeBounds<u64>) -> (u64, Option<u64>) {
    let start = match range.start_bound() {
        Bound::Included(&s) => s,
        Bound::Excluded(&s) => s.saturating_add(1),
        Bound::Unbounded => 0,
    };
    let end = match range.end_bound() {
        Bound::Included(&e) => Some(e.saturating_add(1)),
        Bound::Excluded(&e) => Some(e),
        Bound::Unbounded => None,
    };
    (start, end)
}

impl RaftLogReader<Tc> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + Send>(
        &mut self,
        range: RB,
    ) -> io::Result<Vec<Entry>> {
        let (start, end) = bounds(&range);
        let store = self.store.clone();
        blocking(move || {
            let txn = store.db().begin_read().map_err(io_err)?;
            let t = txn.open_table(RAFT_LOG).map_err(io_err)?;
            let iter = match end {
                Some(e) if e <= start => return Ok(Vec::new()),
                Some(e) => t.range(start..e),
                None => t.range(start..),
            }
            .map_err(io_err)?;
            let mut out = Vec::new();
            for e in iter {
                let (_, v) = e.map_err(io_err)?;
                out.push(raft::decode_entry(v.value()).map_err(kv_err)?);
            }
            Ok(out)
        })
        .await
    }

    async fn read_vote(&mut self) -> io::Result<Option<Vote>> {
        match self.store.raft_get(K_VOTE).map_err(kv_err)? {
            Some(b) => Ok(Some(
                raft::decode::<WVote>(&b, K_VOTE).map_err(kv_err)?.into(),
            )),
            None => Ok(None),
        }
    }
}

impl RaftLogStorage<Tc> for LogStore {
    type LogReader = LogStore;

    async fn get_log_state(&mut self) -> io::Result<LogState<Tc>> {
        let purged = self.get_log_id(K_PURGED)?;
        let last = self.last_entry()?.or(purged);
        Ok(LogState {
            last_purged_log_id: purged,
            last_log_id: last,
        })
    }

    async fn get_log_reader(&mut self) -> LogStore {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote) -> io::Result<()> {
        let b = raft::encode(&WVote::from(vote));
        let me = self.clone();
        blocking(move || me.put_raft(K_VOTE, b)).await
    }

    async fn save_committed(&mut self, committed: Option<LogId>) -> io::Result<()> {
        let Some(c) = committed else { return Ok(()) };
        let b = raft::encode(&WLogId::from(&c));
        let me = self.clone();
        blocking(move || me.put_raft(K_COMMITTED, b)).await
    }

    async fn read_committed(&mut self) -> io::Result<Option<LogId>> {
        self.get_log_id(K_COMMITTED)
    }

    async fn append<I>(&mut self, entries: I, callback: IOFlushed<Tc>) -> io::Result<()>
    where
        I: IntoIterator<Item = Entry> + Send,
        I::IntoIter: Send,
    {
        let encoded: Vec<(u64, Vec<u8>)> = entries
            .into_iter()
            .map(|e| (e.log_id.index, raft::encode_entry(&e)))
            .collect();
        let store = self.store.clone();
        let r = blocking(move || {
            let txn = store.db().begin_write().map_err(io_err)?;
            {
                let mut t = txn.open_table(RAFT_LOG).map_err(io_err)?;
                for (i, b) in &encoded {
                    t.insert(*i, b.as_slice()).map_err(io_err)?;
                }
            }
            txn.commit().map_err(io_err)
        })
        .await;
        match r {
            Ok(()) => {
                callback.io_completed(Ok(()));
                Ok(())
            }
            Err(e) => {
                callback.io_completed(Err(io::Error::other(e.to_string())));
                Err(e)
            }
        }
    }

    async fn truncate_after(&mut self, last: Option<LogId>) -> io::Result<()> {
        let from = last.map_or(0, |l| l.index + 1);
        let store = self.store.clone();
        blocking(move || {
            let txn = store.db().begin_write().map_err(io_err)?;
            {
                let mut t = txn.open_table(RAFT_LOG).map_err(io_err)?;
                t.retain_in(from.., |_, _| false).map_err(io_err)?;
            }
            txn.commit().map_err(io_err)
        })
        .await
    }

    async fn purge(&mut self, upto: LogId) -> io::Result<()> {
        let b = raft::encode(&WLogId::from(&upto));
        let store = self.store.clone();
        blocking(move || {
            let txn = store.db().begin_write().map_err(io_err)?;
            {
                let mut r = txn.open_table(RAFT).map_err(io_err)?;
                r.insert(K_PURGED, b.as_slice()).map_err(io_err)?;
                let mut t = txn.open_table(RAFT_LOG).map_err(io_err)?;
                t.retain_in(..=upto.index, |_, _| false).map_err(io_err)?;
            }
            txn.commit().map_err(io_err)
        })
        .await
    }
}

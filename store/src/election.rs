//! Leader election and locks, the recipes of etcd's `concurrency` package
//! (v3.7.4) as `internal/etcd` (Campaign, Leader) and the ACME storage
//! (Mutex) use them: a key `<prefix>/<lease ID in hex>` under the session's
//! lease, the holder being the key with the lowest creation revision, each
//! waiter watching the deletion of the key created just before its own. Go
//! and Rust servers campaign in one election.

use std::sync::Arc;
use std::time::Duration;

use armada_proto::etcd::etcdserverpb as pb;
use pb::range_request::{SortOrder, SortTarget};

use crate::client::{Client, KeepAlive, op};
use crate::error::{Error, Result, other};

/// electionPrefix holds the leader election, outside the store's prefix.
pub const ELECTION_PREFIX: &str = "/armada-leader/";

/// A lease kept alive while the session lives (concurrency.Session).
pub struct Session {
    c: Client,
    lease: i64,
    ttl: i64,
    keep: KeepAlive,
}

impl Session {
    /// NewSession: a lease of ttl seconds, kept alive.
    pub async fn new(c: &Client, ttl: i64) -> Result<Session> {
        let ttl = if ttl > 0 { ttl } else { 60 };
        let lease = c.grant(ttl).await?;
        let keep = c.keep_alive(lease, ttl);
        Ok(Session {
            c: c.clone(),
            lease,
            ttl,
            keep,
        })
    }

    pub fn lease(&self) -> i64 {
        self.lease
    }

    pub fn client(&self) -> &Client {
        &self.c
    }

    /// Resolves once the lease is no longer kept alive (Done).
    pub async fn done(&self) {
        self.keep.done().await
    }

    pub fn is_done(&self) -> bool {
        self.keep.is_done()
    }

    /// Orphan stops keeping the lease alive without revoking it.
    pub fn orphan(&self) {
        self.keep.stop();
    }

    /// Close stops keeping the lease alive and revokes it, which deletes
    /// its keys, within the TTL.
    pub async fn close(&self) -> Result<()> {
        self.orphan();
        match tokio::time::timeout(
            Duration::from_secs(self.ttl as u64),
            self.c.revoke(self.lease),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => Err(other!("context deadline exceeded")),
        }
    }
}

/// waitDeletes: waits until every key under pfx created at or before
/// max_create_rev is deleted.
async fn wait_deletes(c: &Client, pfx: &str, max_create_rev: i64) -> Result<()> {
    loop {
        let mut r = op::get_prefix(pfx, 0);
        r.sort_target = SortTarget::Create as i32;
        r.sort_order = SortOrder::Descend as i32;
        r.limit = 1;
        r.max_create_revision = max_create_rev;
        let resp = c.range(r).await?;
        let Some(kv) = resp.kvs.first() else {
            return Ok(());
        };
        let key = String::from_utf8_lossy(&kv.key).into_owned();
        let rev = resp.header.map_or(0, |h| h.revision);
        c.wait_delete(&key, rev).await?;
    }
}

/// The key with the lowest creation revision under pfx (WithFirstCreate).
async fn first_created(
    c: &Client,
    pfx: &str,
) -> Result<Option<armada_proto::etcd::mvccpb::KeyValue>> {
    let mut r = op::get_prefix(pfx, 0);
    r.sort_target = SortTarget::Create as i32;
    r.sort_order = SortOrder::Ascend as i32;
    r.limit = 1;
    Ok(c.range(r).await?.kvs.into_iter().next())
}

/// An election (concurrency.Election).
pub struct Election {
    s: Arc<Session>,
    prefix: String,
    key: String,
    rev: i64,
    leading: bool,
}

impl Election {
    /// NewElection on prefix pfx: keys go under pfx + "/".
    pub fn new(s: Arc<Session>, pfx: &str) -> Election {
        Election {
            s,
            prefix: format!("{pfx}/"),
            key: String::new(),
            rev: 0,
            leading: false,
        }
    }

    /// Campaign puts val under the session's key and returns once it is
    /// the oldest key: this session leads. Dropping the future stops
    /// waiting; the key stays until Resign or the session ends.
    pub async fn campaign(&mut self, val: &str) -> Result<()> {
        let c = self.s.client().clone();
        let k = format!("{}{:x}", self.prefix, self.s.lease());
        let r = c
            .txn(pb::TxnRequest {
                compare: vec![op::created_at(&k, 0)],
                success: vec![op::put(&k, val.as_bytes(), self.s.lease())],
                failure: vec![op::range(op::get(&k, 0))],
            })
            .await?;
        self.key = k;
        self.rev = r.header.map_or(0, |h| h.revision);
        self.leading = true;
        if !r.succeeded {
            let kv = op::range_of(&r, 0)
                .and_then(|rr| rr.kvs.first())
                .ok_or_else(|| other!("election: no key"))?;
            self.rev = kv.create_revision;
            if kv.value != val.as_bytes()
                && let Err(e) = self.proclaim(val).await
            {
                let _ = self.resign().await;
                return Err(e);
            }
        }
        if let Err(e) = wait_deletes(&c, &self.prefix, self.rev - 1).await {
            self.leading = false;
            return Err(e);
        }
        Ok(())
    }

    /// Proclaim changes the leader's value without another election.
    pub async fn proclaim(&mut self, val: &str) -> Result<()> {
        if !self.leading {
            return Err(other!("election: not leader"));
        }
        let r = self
            .s
            .client()
            .txn(pb::TxnRequest {
                compare: vec![op::created_at(&self.key, self.rev)],
                success: vec![op::put(&self.key, val.as_bytes(), self.s.lease())],
                failure: Vec::new(),
            })
            .await?;
        if !r.succeeded {
            self.key.clear();
            return Err(other!("election: not leader"));
        }
        Ok(())
    }

    /// Resign gives leadership up so another node can take over at once.
    pub async fn resign(&mut self) -> Result<()> {
        if !self.leading {
            return Ok(());
        }
        let r = self
            .s
            .client()
            .txn(pb::TxnRequest {
                compare: vec![op::created_at(&self.key, self.rev)],
                success: vec![op::delete(&self.key)],
                failure: Vec::new(),
            })
            .await;
        self.key.clear();
        self.leading = false;
        r.map(|_| ())
    }

    /// The election key of this term (Election.Key).
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Its creation revision (Election.Rev).
    pub fn rev(&self) -> i64 {
        self.rev
    }

    /// The current leader's key and value, ErrElectionNoLeader without one.
    pub async fn leader(&self) -> Result<(String, Vec<u8>)> {
        match first_created(self.s.client(), &self.prefix).await? {
            None => Err(other!("election: no leader")),
            Some(kv) => Ok((String::from_utf8_lossy(&kv.key).into_owned(), kv.value)),
        }
    }
}

/// Leadership of the control plane (internal/etcd's Campaign).
pub struct Leadership {
    session: Arc<Session>,
    key: String,
    rev: i64,
}

impl Leadership {
    /// Campaign blocks until this node leads (internal/etcd.Campaign),
    /// with a session of ttl seconds.
    pub async fn campaign(c: &Client, ttl: Duration, name: &str) -> Result<Leadership> {
        let session = Arc::new(
            Session::new(c, ttl.as_secs() as i64)
                .await
                .map_err(|e| e.context("etcd session"))?,
        );
        let (key, rev) = {
            let mut e = Election::new(session.clone(), ELECTION_PREFIX);
            if let Err(err) = e.campaign(name).await {
                let _ = session.close().await;
                return Err(err);
            }
            (e.key.clone(), e.rev)
        };
        Ok(Leadership { session, key, rev })
    }

    /// Resolves once leadership is lost (Done).
    pub async fn done(&self) {
        self.session.done().await
    }

    pub fn is_done(&self) -> bool {
        self.session.is_done()
    }

    /// Fence: the key and creation revision of this term.
    pub fn fence(&self) -> (String, i64) {
        (self.key.clone(), self.rev)
    }

    /// Resign gives up leadership so another node can take over at once.
    pub async fn resign(self) -> Result<()> {
        let r = self
            .session
            .client()
            .txn(pb::TxnRequest {
                compare: vec![op::created_at(&self.key, self.rev)],
                success: vec![op::delete(&self.key)],
                failure: Vec::new(),
            })
            .await;
        let c = self.session.close().await;
        r.map(|_| ())?;
        c
    }
}

/// Leader returns the name of the current leader, "" without one
/// (internal/etcd.Leader, which reads ELECTION_PREFIX itself).
pub async fn leader(c: &Client) -> Result<String> {
    Ok(first_created(c, ELECTION_PREFIX)
        .await?
        .map(|kv| String::from_utf8_lossy(&kv.value).into_owned())
        .unwrap_or_default())
}

/// A lock (concurrency.Mutex).
pub struct Mutex {
    s: Arc<Session>,
    pfx: String,
    my_key: String,
    my_rev: i64,
}

impl Mutex {
    /// NewMutex on prefix pfx: keys go under pfx + "/".
    pub fn new(s: Arc<Session>, pfx: &str) -> Mutex {
        Mutex {
            s,
            pfx: format!("{pfx}/"),
            my_key: String::new(),
            my_rev: -1,
        }
    }

    async fn try_acquire(&mut self) -> Result<pb::TxnResponse> {
        self.my_key = format!("{}{:x}", self.pfx, self.s.lease());
        let mut owner = op::get_prefix(&self.pfx, 0);
        owner.sort_target = SortTarget::Create as i32;
        owner.sort_order = SortOrder::Ascend as i32;
        owner.limit = 1;
        let r = self
            .s
            .client()
            .txn(pb::TxnRequest {
                compare: vec![op::created_at(&self.my_key, 0)],
                success: vec![
                    op::put(&self.my_key, b"", self.s.lease()),
                    op::range(owner.clone()),
                ],
                failure: vec![op::range(op::get(&self.my_key, 0)), op::range(owner)],
            })
            .await?;
        self.my_rev = r.header.map_or(0, |h| h.revision);
        if !r.succeeded {
            self.my_rev = op::range_of(&r, 0)
                .and_then(|rr| rr.kvs.first())
                .map_or(0, |kv| kv.create_revision);
        }
        Ok(r)
    }

    fn owns(&self, r: &pb::TxnResponse) -> bool {
        match op::range_of(r, 1).and_then(|rr| rr.kvs.first()) {
            None => true,
            Some(kv) => kv.create_revision == self.my_rev,
        }
    }

    /// TryLock takes the lock or fails at once with "mutex: Locked by
    /// another session".
    pub async fn try_lock(&mut self) -> Result<()> {
        let r = self.try_acquire().await?;
        if self.owns(&r) {
            return Ok(());
        }
        self.s.client().delete(&self.my_key, None).await?;
        self.my_key = "\0".to_string();
        self.my_rev = -1;
        Err(other!("mutex: Locked by another session"))
    }

    /// Lock waits for the lock.
    pub async fn lock(&mut self) -> Result<()> {
        let r = self.try_acquire().await?;
        if self.owns(&r) {
            return Ok(());
        }
        let c = self.s.client().clone();
        if let Err(e) = wait_deletes(&c, &self.pfx, self.my_rev - 1).await {
            let _ = self.unlock().await;
            return Err(e);
        }
        let g = c.range(op::get(&self.my_key, 0)).await;
        match g {
            Err(e) => {
                let _ = self.unlock().await;
                Err(e)
            }
            Ok(g) if g.kvs.is_empty() => Err(other!("mutex: session is expired")),
            Ok(_) => Ok(()),
        }
    }

    /// Unlock releases the lock.
    pub async fn unlock(&mut self) -> Result<()> {
        if self.my_key.is_empty() || self.my_rev <= 0 || self.my_key == "\0" {
            return Err(other!("mutex: lock has already been released"));
        }
        if !self.my_key.starts_with(&self.pfx) {
            return Err(Error::other(format!(
                "invalid key {:?}, it should have prefix {:?}",
                self.my_key, self.pfx
            )));
        }
        self.s.client().delete(&self.my_key, None).await?;
        self.my_key = "\0".to_string();
        self.my_rev = -1;
        Ok(())
    }

    /// The lock's key (Mutex.Key).
    pub fn key(&self) -> &str {
        &self.my_key
    }
}

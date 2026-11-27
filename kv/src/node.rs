//! A member of the store: the key space on disk, one writer that applies
//! proposed commands in batches (one durable commit each), the lease clock,
//! and the periodic compaction.
//!
//! A single member decides alone: a proposal is applied as soon as the
//! writer takes it. With Raft (ADR 0057, step 2) `propose` appends to the
//! log instead and the writer applies committed entries; the lease clock
//! and the compaction run on the leader only, and propose what they decide
//! (`LeaseExpire`, `Compact`) like any other change.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use armada_proto::etcd::etcdserverpb as pb;
use tokio::sync::{oneshot, watch};

use crate::command::{Command, Op};
use crate::error::{Error, Result};
use crate::mvcc::{self, Applied, Limits, Store};

/// The database file in the member's directory.
pub const DB_FILE: &str = "kv.db";

/// Commands applied in one commit at most.
const MAX_BATCH: usize = 256;

/// How often the lease clock looks for expired leases.
const LEASE_TICK: Duration = Duration::from_millis(250);

/// A member's settings.
#[derive(Clone, Debug)]
pub struct Options {
    /// The member's name, peer and client URLs, as the member list shows
    /// them.
    pub name: String,
    pub peer_urls: Vec<String>,
    pub client_urls: Vec<String>,
    pub limits: Limits,
    /// History kept before it is compacted (as `armadad etcd` sets etcd's
    /// periodic compaction: an hour).
    pub retention: Duration,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            name: "default".to_string(),
            peer_urls: Vec::new(),
            client_urls: Vec::new(),
            limits: Limits::default(),
            retention: Duration::from_secs(3600),
        }
    }
}

struct Lease {
    ttl: i64,
    deadline: Instant,
    /// An expiry was proposed.
    expiring: bool,
}

/// What the writer and the services share.
struct Shared {
    /// The revision after the last commit.
    rev: watch::Sender<i64>,
    leases: Mutex<HashMap<i64, Lease>>,
}

type Proposal = (Command, oneshot::Sender<Result<Applied>>);

struct Inner {
    store: Arc<Store>,
    shared: Arc<Shared>,
    opts: Options,
    dir: PathBuf,
    proposals: Mutex<Option<std::sync::mpsc::Sender<Proposal>>>,
    writer: Mutex<Option<std::thread::JoinHandle<()>>>,
    stop: watch::Sender<bool>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.proposals.lock().expect("not poisoned").take();
    }
}

/// A member. Clones share it.
#[derive(Clone)]
pub struct Node(Arc<Inner>);

impl Node {
    /// Opens the member in dir (created 0700), its database in
    /// [`DB_FILE`]. Runs within a tokio runtime: the lease clock and the
    /// compaction are its tasks.
    pub fn open(dir: &Path, opts: Options) -> Result<Node> {
        create_private_dir(dir)?;
        let store = Arc::new(Store::open(&dir.join(DB_FILE), opts.limits.clone())?);
        let state = store.state()?;
        let now = Instant::now();
        let leases = store
            .leases()?
            .into_iter()
            .map(|(id, ttl)| {
                (
                    id,
                    Lease {
                        ttl,
                        // As etcd's lessor when a leader starts: every
                        // lease gets its whole TTL again.
                        deadline: now + ttl_duration(ttl),
                        expiring: false,
                    },
                )
            })
            .collect();
        let (rev, _) = watch::channel(state.revision);
        let shared = Arc::new(Shared {
            rev,
            leases: Mutex::new(leases),
        });
        let (tx, rx) = std::sync::mpsc::channel::<Proposal>();
        let writer = {
            let store = store.clone();
            let shared = shared.clone();
            std::thread::Builder::new()
                .name("armada-kv-writer".to_string())
                .spawn(move || write_loop(&store, &shared, rx))
                .map_err(|e| Error::Storage(e.to_string()))?
        };
        let (stop, _) = watch::channel(false);
        let node = Node(Arc::new(Inner {
            store,
            shared,
            opts,
            dir: dir.to_path_buf(),
            proposals: Mutex::new(Some(tx)),
            writer: Mutex::new(Some(writer)),
            stop,
        }));
        tokio::spawn(lease_clock(
            Arc::downgrade(&node.0),
            node.0.stop.subscribe(),
        ));
        tokio::spawn(compaction(Arc::downgrade(&node.0), node.0.stop.subscribe()));
        Ok(node)
    }

    /// Stops taking proposals and waits for the writer to finish the ones
    /// it holds. The database closes once every clone is dropped.
    pub fn close(&self) {
        let _ = self.0.stop.send(true);
        self.0.proposals.lock().expect("not poisoned").take();
        let w = self.0.writer.lock().expect("not poisoned").take();
        if let Some(w) = w {
            let _ = w.join();
        }
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.0.store
    }

    pub fn options(&self) -> &Options {
        &self.0.opts
    }

    pub fn dir(&self) -> &Path {
        &self.0.dir
    }

    /// The revision after the last commit, as it changes.
    pub fn revisions(&self) -> watch::Receiver<i64> {
        self.0.shared.rev.subscribe()
    }

    /// A response header at rev.
    pub fn header(&self, rev: i64) -> pb::ResponseHeader {
        self.0.store.ids().header(rev)
    }

    /// The member as the member list shows it.
    pub fn member(&self) -> pb::Member {
        pb::Member {
            id: self.0.store.ids().member,
            name: self.0.opts.name.clone(),
            peer_ur_ls: self.0.opts.peer_urls.clone(),
            client_ur_ls: self.0.opts.client_urls.clone(),
            is_learner: false,
        }
    }

    /// Applies a command once it is durable: its answer, or why it was
    /// refused.
    pub async fn propose(&self, cmd: Command) -> Result<Applied> {
        mvcc::validate(&cmd, &self.0.opts.limits)?;
        let (tx, rx) = oneshot::channel();
        {
            let p = self.0.proposals.lock().expect("not poisoned");
            let Some(p) = p.as_ref() else {
                return Err(Error::Stopped);
            };
            p.send((cmd, tx)).map_err(|_| Error::Stopped)?;
        }
        rx.await.map_err(|_| Error::Stopped)?
    }

    /// Lease.LeaseGrant: a new ID unless one is asked for.
    pub async fn grant(&self, mut r: pb::LeaseGrantRequest) -> Result<pb::LeaseGrantResponse> {
        if r.id == 0 {
            r.id = mvcc::new_lease_id();
        }
        match self
            .propose(Command::new(Op::LeaseGrant(r)))
            .await?
            .response
        {
            mvcc::Response::LeaseGrant(g) => Ok(g),
            _ => Err(Error::Storage("a lease grant answered otherwise".into())),
        }
    }

    /// A keep-alive of lease id: its TTL, or 0 when it is gone (as etcd
    /// answers).
    pub fn keep_alive(&self, id: i64) -> i64 {
        let mut leases = self.0.shared.leases.lock().expect("not poisoned");
        match leases.get_mut(&id) {
            Some(l) if !l.expiring => {
                l.deadline = Instant::now() + ttl_duration(l.ttl);
                l.ttl
            }
            _ => 0,
        }
    }
}

fn ttl_duration(ttl: i64) -> Duration {
    Duration::from_secs(ttl.max(0) as u64)
}

fn create_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| Error::Storage(format!("{}: {e}", dir.display())))?;
    let mode = std::fs::metadata(dir)
        .map_err(|e| Error::Storage(format!("{}: {e}", dir.display())))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(Error::Storage(format!(
            "{} is open to other users (mode {:o}); it must be 0700",
            dir.display(),
            mode & 0o777
        )));
    }
    Ok(())
}

/// The writer: takes every proposal waiting, applies them in one durable
/// commit, then follows the leases and the revision and answers.
fn write_loop(store: &Store, shared: &Shared, rx: std::sync::mpsc::Receiver<Proposal>) {
    while let Ok(first) = rx.recv() {
        let mut batch = vec![first];
        while batch.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(p) => batch.push(p),
                Err(_) => break,
            }
        }
        let cmds: Vec<Command> = batch.iter().map(|(c, _)| c.clone()).collect();
        match store.apply(&cmds) {
            Err(e) => {
                for (_, tx) in batch {
                    let _ = tx.send(Err(e.clone()));
                }
            }
            Ok(results) => {
                let now = Instant::now();
                let mut rev = None;
                {
                    let mut leases = shared.leases.lock().expect("not poisoned");
                    for r in results.iter().flatten() {
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
                    shared.rev.send_if_modified(|r| {
                        let changed = *r != rev;
                        *r = rev;
                        changed
                    });
                }
                for ((_, tx), r) in batch.into_iter().zip(results) {
                    let _ = tx.send(r);
                }
            }
        }
    }
}

/// Proposes the expiry of every lease not kept alive within its TTL.
async fn lease_clock(node: Weak<Inner>, mut stop: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(LEASE_TICK);
    loop {
        tokio::select! {
            _ = stop.wait_for(|s| *s) => return,
            _ = tick.tick() => {}
        }
        let Some(inner) = node.upgrade() else { return };
        let n = Node(inner);
        let now = Instant::now();
        let due: Vec<i64> = {
            let mut leases = n.0.shared.leases.lock().expect("not poisoned");
            leases
                .iter_mut()
                .filter(|(_, l)| !l.expiring && l.deadline <= now)
                .map(|(id, l)| {
                    l.expiring = true;
                    *id
                })
                .collect()
        };
        for id in due {
            let n = n.clone();
            tokio::spawn(async move {
                let cmd = Command::new(Op::LeaseExpire(pb::LeaseRevokeRequest { id }));
                if n.propose(cmd).await.is_err()
                    && let Some(l) = n.0.shared.leases.lock().expect("not poisoned").get_mut(&id)
                {
                    l.expiring = false;
                }
            });
        }
    }
}

/// Compacts the history older than the retention: the revision of a
/// sample taken at least that long ago.
async fn compaction(node: Weak<Inner>, mut stop: watch::Receiver<bool>) {
    let Some(retention) = node.upgrade().map(|n| n.opts.retention) else {
        return;
    };
    let every = (retention / 12).clamp(Duration::from_millis(100), Duration::from_secs(300));
    let mut samples: VecDeque<(Instant, i64)> = VecDeque::new();
    let mut tick = tokio::time::interval(every);
    loop {
        tokio::select! {
            _ = stop.wait_for(|s| *s) => return,
            _ = tick.tick() => {}
        }
        let Some(inner) = node.upgrade() else { return };
        let n = Node(inner);
        let Ok(state) = n.0.store.state() else {
            continue;
        };
        let now = Instant::now();
        samples.push_back((now, state.revision));
        let mut target = None;
        while let Some(&(at, rev)) = samples.front() {
            if now.duration_since(at) < retention {
                break;
            }
            target = Some(rev);
            samples.pop_front();
        }
        if let Some(rev) = target
            && rev > state.compacted
        {
            let _ = n
                .propose(Command::new(Op::Compact(pb::CompactionRequest {
                    revision: rev,
                    physical: false,
                })))
                .await;
        }
    }
}

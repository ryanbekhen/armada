//! A member of the store (ADR 0057): the key space on disk, Raft in front
//! of it, the lease clock, and the periodic compaction.
//!
//! - Every change is a command proposed to Raft and applied by every member
//!   in log order (crate::sm). A member that is not the leader forwards
//!   what a client asked of it to the leader over the peer service
//!   (crate::peer) and answers the client itself, so a client may call any
//!   member, as with etcd: commands, ReadIndex, lease keep-alives, and the
//!   membership changes of etcd's Cluster service.
//! - Reads are linearizable unless they ask to be serializable: the member
//!   gets the leader's ReadIndex (the leader confirms it still leads with a
//!   majority) and waits until it has applied that far before reading its
//!   own key space. Watches read the member's own key space.
//! - The lease clock and the compaction run on the leader only and propose
//!   what they decide (`LeaseExpire`, `Compact`) like any other change.
//!   Deadlines live in memory: a member that becomes the leader gives every
//!   lease its whole TTL again, and keep-alives go to the leader.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use armada_proto::etcd::etcdserverpb as pb;
use openraft::async_runtime::WatchReceiver;
use openraft::errors::{ChangeMembershipError, ClientWriteError, LinearizableReadError, RaftError};
use openraft::{ChangeMembers, ReadPolicy, ServerState};
use tokio::sync::watch;

use crate::command::{Command, Op};
use crate::error::{Error, Result};
use crate::log::LogStore;
use crate::mvcc::{self, Applied, Limits, Store};
use crate::peer::{
    Connector, NetFactory, PeerCtx, PeerOp, PeerReply, PeerRequest, PeerResult, Peers,
    SnapshotChunk, WMembers,
};
use crate::raft::{self, Peer, Raft, WApplied};
use crate::sm::{Shared, StateMachine, ttl_duration};

/// The database file in the member's directory.
pub const DB_FILE: &str = "kv.db";

/// Entries in one AppendEntries at most (each at most a request).
pub const MAX_PAYLOAD_ENTRIES: u64 = 64;

/// How often the lease clock looks for expired leases.
const LEASE_TICK: Duration = Duration::from_millis(250);

/// How long a member waits between tries while the leader is unknown or
/// moves.
const SETTLE: Duration = Duration::from_millis(20);

/// How a member starts the first time (a member with Raft state of its own
/// restarts from it and ignores this).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Start {
    /// A new cluster with this member as its only voter.
    #[default]
    New,
    /// A member of an existing cluster that added it (MemberAdd): it asks
    /// the members at these peer URLs for the member list and takes the ID
    /// of the member with its own peer URL, and the cluster's ID.
    Join(Vec<String>),
}

/// Raft's timing and log compaction.
#[derive(Clone, Debug)]
pub struct Timing {
    pub heartbeat: Duration,
    pub election_min: Duration,
    pub election_max: Duration,
    /// Entries applied since the last snapshot before another is built
    /// (and the log before it purged).
    pub snapshot_every: u64,
    /// Entries kept in the log behind a snapshot, for members a little
    /// behind.
    pub keep_behind: u64,
}

impl Default for Timing {
    /// etcd's defaults: a heartbeat every 100 ms, elections after a second
    /// without one.
    fn default() -> Timing {
        Timing {
            heartbeat: Duration::from_millis(100),
            election_min: Duration::from_millis(1000),
            election_max: Duration::from_millis(2000),
            snapshot_every: 10_000,
            keep_behind: 1_000,
        }
    }
}

/// A member's settings.
#[derive(Clone)]
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
    pub start: Start,
    pub timing: Timing,
    /// How the member reaches the others (none: a member alone).
    pub connector: Option<Arc<dyn Connector>>,
    /// How long a proposal or a linearizable read may take (etcd's request
    /// timeout).
    pub request_timeout: Duration,
}

impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("name", &self.name)
            .field("peer_urls", &self.peer_urls)
            .field("client_urls", &self.client_urls)
            .field("limits", &self.limits)
            .field("retention", &self.retention)
            .field("start", &self.start)
            .field("timing", &self.timing)
            .field("connector", &self.connector.is_some())
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

impl Default for Options {
    fn default() -> Options {
        Options {
            name: "default".to_string(),
            peer_urls: Vec::new(),
            client_urls: Vec::new(),
            limits: Limits::default(),
            retention: Duration::from_secs(3600),
            start: Start::New,
            timing: Timing::default(),
            connector: None,
            request_timeout: Duration::from_secs(7),
        }
    }
}

struct Inner {
    store: Arc<Store>,
    shared: Arc<Shared>,
    opts: Options,
    dir: PathBuf,
    raft: Raft,
    ctx: Arc<PeerCtx>,
    stop: watch::Sender<bool>,
    /// The term in which this member, as the leader, last gave every lease
    /// its whole TTL again; None while it does not lead.
    leading: Mutex<Option<u64>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

/// A member. Clones share it.
#[derive(Clone)]
pub struct Node(Arc<Inner>);

/// Where the leader is.
enum Leader {
    Me,
    Other(u64, String),
}

fn raft_config(t: &Timing) -> Result<openraft::Config> {
    let c = openraft::Config {
        cluster_name: "armada-kv".to_string(),
        heartbeat_interval: t.heartbeat.as_millis() as u64,
        election_timeout_min: t.election_min.as_millis() as u64,
        election_timeout_max: t.election_max.as_millis() as u64,
        install_snapshot_timeout: 60_000,
        max_payload_entries: MAX_PAYLOAD_ENTRIES,
        snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(t.snapshot_every),
        max_in_snapshot_log_to_keep: t.keep_behind,
        purge_batch_size: (t.snapshot_every / 4).clamp(1, 256),
        enable_pre_vote: Some(true),
        ..Default::default()
    };
    c.validate()
        .map_err(|e| Error::Storage(format!("Raft's settings: {e}")))
}

fn stopped<E>(_: E) -> Error {
    Error::Stopped
}

impl Node {
    /// Opens the member in dir (created 0700), its database in
    /// [`DB_FILE`], and starts its Raft: a new member bootstraps a cluster
    /// or joins one as `opts.start` says. Runs within a tokio runtime: Raft,
    /// the lease clock, and the compaction are its tasks.
    pub async fn open(dir: &Path, opts: Options) -> Result<Node> {
        create_private_dir(dir)?;
        let store = Arc::new(Store::open(&dir.join(DB_FILE), opts.limits.clone())?);
        let logs = LogStore::new(store.clone());
        let pristine = logs
            .is_pristine()
            .map_err(|e| Error::Storage(e.to_string()))?;
        let peers = Peers::new(opts.connector.clone());
        if pristine && let Start::Join(urls) = &opts.start {
            let (cluster, member) = join(&peers, urls, &opts).await?;
            store.set_ids(cluster, member)?;
        }
        let ids = store.ids();
        let ctx = Arc::new(PeerCtx {
            peers,
            me: ids.member,
            cluster: ids.cluster,
        });
        let shared = Arc::new(Shared::new(&store)?);
        let sm = StateMachine::new(store.clone(), shared.clone());
        let config = Arc::new(raft_config(&opts.timing)?);
        let raft = Raft::new(ids.member, config, NetFactory(ctx.clone()), logs, sm)
            .await
            .map_err(|e| Error::Storage(format!("Raft: {e}")))?;
        if pristine && opts.start == Start::New {
            let me = Peer {
                name: opts.name.clone(),
                peer_urls: opts.peer_urls.clone(),
                client_urls: opts.client_urls.clone(),
            };
            raft.initialize(BTreeMap::from([(ids.member, me)]))
                .await
                .map_err(|e| Error::Storage(format!("Raft: {e}")))?;
        }
        let (stop, _) = watch::channel(false);
        let node = Node(Arc::new(Inner {
            store,
            shared,
            opts,
            dir: dir.to_path_buf(),
            raft,
            ctx,
            stop,
            leading: Mutex::new(None),
        }));
        let weak = Arc::downgrade(&node.0);
        tokio::spawn(follow_raft(weak.clone(), node.0.stop.subscribe()));
        tokio::spawn(lease_clock(weak.clone(), node.0.stop.subscribe()));
        tokio::spawn(compaction(weak.clone(), node.0.stop.subscribe()));
        tokio::spawn(publish(weak, node.0.stop.subscribe()));
        Ok(node)
    }

    /// Stops the member's tasks and Raft. The database closes once every
    /// clone is dropped.
    pub async fn close(&self) {
        let _ = self.0.stop.send(true);
        let _ = self.0.raft.shutdown().await;
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

    /// The member's ID (its Raft node ID).
    pub fn id(&self) -> u64 {
        self.0.ctx.me
    }

    /// The member's Raft, for its metrics.
    pub fn raft(&self) -> &Raft {
        &self.0.raft
    }

    /// The revision after the last applied commit, as it changes.
    pub fn revisions(&self) -> watch::Receiver<i64> {
        self.0.shared.rev.subscribe()
    }

    /// The index of the last applied log entry, as it changes.
    pub fn applied(&self) -> watch::Receiver<u64> {
        self.0.shared.applied.subscribe()
    }

    /// A response header at rev.
    pub fn header(&self, rev: i64) -> pb::ResponseHeader {
        self.0.store.ids().header(rev)
    }

    /// The member list as this member knows it: every member of the
    /// latest membership, learners marked.
    pub fn members(&self) -> Vec<pb::Member> {
        let m = self
            .0
            .raft
            .metrics()
            .borrow_watched()
            .membership_config
            .clone();
        members_of(m.membership())
    }

    /// What Maintenance.Status shows of Raft: the leader (0 when none is
    /// known), the last log index, the term, the last applied index, and
    /// whether this member is a learner.
    pub fn raft_status(&self) -> (u64, u64, u64, u64, bool) {
        let m = self.0.raft.metrics().borrow_watched().clone();
        let me = self.id();
        let learner = m.membership_config.membership().get_node(&me).is_some()
            && !m
                .membership_config
                .membership()
                .voter_ids()
                .any(|v| v == me);
        (
            m.current_leader.unwrap_or(0),
            m.last_log_index.unwrap_or(0),
            m.current_term,
            m.last_applied.map_or(0, |l| l.index),
            learner,
        )
    }

    async fn with_timeout<T>(&self, f: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::time::timeout(self.0.opts.request_timeout, f)
            .await
            .map_err(|_| Error::Timeout)?
    }

    /// The leader, once one is known.
    async fn leader(&self) -> Result<Leader> {
        let mut m = self.0.raft.metrics();
        loop {
            {
                let mm = m.borrow_watched();
                if let Some(l) = mm.current_leader {
                    if l == self.id() {
                        return Ok(Leader::Me);
                    }
                    if let Some(u) = mm
                        .membership_config
                        .membership()
                        .get_node(&l)
                        .and_then(|n| n.peer_urls.first())
                    {
                        return Ok(Leader::Other(l, u.clone()));
                    }
                }
            }
            if *self.0.stop.borrow() {
                return Err(Error::Stopped);
            }
            m.changed().await.map_err(stopped)?;
        }
    }

    /// Runs op on the leader: here, or forwarded to it. A transport error
    /// of a forwarded op is returned, never retried: the leader may have
    /// done it.
    async fn route(&self, op: PeerOp) -> Result<PeerResult> {
        self.with_timeout(async {
            loop {
                let r = match self.leader().await? {
                    Leader::Me => self.local(op.clone()).await,
                    Leader::Other(id, url) => {
                        let req = PeerRequest {
                            cluster: self.0.ctx.cluster,
                            to: id,
                            from: self.id(),
                            op: Some(op.clone()),
                        };
                        let reply = self
                            .0
                            .ctx
                            .peers
                            .call(&url, req, self.0.opts.request_timeout)
                            .await?;
                        match reply.result {
                            Some(PeerResult::Error(e)) => Err(e.into()),
                            Some(r) => Ok(r),
                            None => Err(Error::Unavailable("an empty answer".into())),
                        }
                    }
                };
                match r {
                    Err(Error::NotLeader) => tokio::time::sleep(SETTLE).await,
                    r => return r,
                }
            }
        })
        .await
    }

    /// Applies a command once a majority holds it: its answer, or why it
    /// was refused.
    pub async fn propose(&self, cmd: Command) -> Result<Applied> {
        mvcc::validate(&cmd, &self.0.opts.limits)?;
        match self.route(PeerOp::Propose(cmd)).await? {
            PeerResult::Applied(a) => {
                let mut a: Applied = a.try_into()?;
                self.restamp(&mut a.response);
                Ok(a)
            }
            _ => Err(unexpected()),
        }
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

    /// A keep-alive of lease id, on the leader: its TTL, or 0 when it is
    /// gone (as etcd answers).
    pub async fn keep_alive(&self, id: i64) -> Result<i64> {
        match self
            .route(PeerOp::KeepAlive(pb::LeaseKeepAliveRequest { id }))
            .await?
        {
            PeerResult::Ttl(t) => Ok(t),
            _ => Err(unexpected()),
        }
    }

    /// Waits until a read on this member sees every write acknowledged
    /// before it was called (Raft's ReadIndex through the leader).
    pub async fn linearize(&self) -> Result<()> {
        let index = match self.route(PeerOp::ReadIndex(true)).await? {
            PeerResult::ReadIndex(i) => i,
            _ => return Err(unexpected()),
        };
        self.with_timeout(async {
            let mut a = self.applied();
            a.wait_for(|a| *a >= index).await.map_err(stopped)?;
            Ok(())
        })
        .await
    }

    /// Cluster.MemberAdd (learners only, as armada-store adds members).
    pub async fn member_add(&self, r: pb::MemberAddRequest) -> Result<pb::MemberAddResponse> {
        match self.route(PeerOp::MemberAdd(r)).await? {
            PeerResult::MemberAdd(r) => Ok(r),
            _ => Err(unexpected()),
        }
    }

    pub async fn member_remove(
        &self,
        r: pb::MemberRemoveRequest,
    ) -> Result<pb::MemberRemoveResponse> {
        match self.route(PeerOp::MemberRemove(r)).await? {
            PeerResult::MemberRemove(r) => Ok(r),
            _ => Err(unexpected()),
        }
    }

    pub async fn member_update(
        &self,
        r: pb::MemberUpdateRequest,
    ) -> Result<pb::MemberUpdateResponse> {
        match self.route(PeerOp::MemberUpdate(r)).await? {
            PeerResult::MemberUpdate(r) => Ok(r),
            _ => Err(unexpected()),
        }
    }

    pub async fn member_promote(
        &self,
        r: pb::MemberPromoteRequest,
    ) -> Result<pb::MemberPromoteResponse> {
        match self.route(PeerOp::MemberPromote(r)).await? {
            PeerResult::MemberPromote(r) => Ok(r),
            _ => Err(unexpected()),
        }
    }

    /// Headers of an answer the leader made, as this member's.
    fn restamp(&self, r: &mut mvcc::Response) {
        let ids = self.0.store.ids();
        let fix = |h: &mut Option<pb::ResponseHeader>| {
            if let Some(h) = h {
                h.member_id = ids.member;
                h.raft_term = ids.raft_term;
            }
        };
        match r {
            mvcc::Response::Put(p) => fix(&mut p.header),
            mvcc::Response::DeleteRange(d) => fix(&mut d.header),
            mvcc::Response::LeaseGrant(g) => fix(&mut g.header),
            mvcc::Response::LeaseRevoke(g) => fix(&mut g.header),
            mvcc::Response::Compact(c) => fix(&mut c.header),
            mvcc::Response::Txn(t) => {
                fix(&mut t.header);
                use pb::response_op::Response as R;
                for o in &mut t.responses {
                    match &mut o.response {
                        Some(R::ResponseRange(x)) => fix(&mut x.header),
                        Some(R::ResponsePut(x)) => fix(&mut x.header),
                        Some(R::ResponseDeleteRange(x)) => fix(&mut x.header),
                        Some(R::ResponseTxn(x)) => fix(&mut x.header),
                        None => {}
                    }
                }
            }
        }
    }

    // What the leader does for itself and for the members that forward to
    // it.

    /// Runs op here, as the leader; Error::NotLeader when this member does
    /// not lead.
    async fn local(&self, op: PeerOp) -> Result<PeerResult> {
        match op {
            PeerOp::Propose(cmd) => {
                if prost::Message::encoded_len(&cmd) > crate::service::MAX_REQUEST_BYTES {
                    return Err(Error::RequestTooLarge);
                }
                mvcc::validate(&cmd, &self.0.opts.limits)?;
                Ok(PeerResult::Applied(WApplied::from(&self.write(cmd).await?)))
            }
            PeerOp::ReadIndex(_) => Ok(PeerResult::ReadIndex(self.read_index().await?)),
            PeerOp::KeepAlive(k) => {
                self.read_index().await?;
                let mut leases = self.0.shared.leases.lock().expect("not poisoned");
                let ttl = match leases.get_mut(&k.id) {
                    Some(l) if !l.expiring => {
                        l.deadline = Instant::now() + ttl_duration(l.ttl);
                        l.ttl
                    }
                    _ => 0,
                };
                Ok(PeerResult::Ttl(ttl))
            }
            PeerOp::MemberAdd(r) => self.add_member(r).await,
            PeerOp::MemberRemove(r) => self.remove_member(r.id).await,
            PeerOp::MemberUpdate(r) => self.update_member(r.id, r.peer_ur_ls).await,
            PeerOp::MemberPromote(r) => self.promote_member(r.id).await,
            PeerOp::Publish(m) => self.publish_member(m).await,
            PeerOp::Members(_) => Ok(PeerResult::Members(WMembers {
                cluster: self.0.ctx.cluster,
                members: self.members(),
            })),
            PeerOp::Append(_) | PeerOp::Vote(_) | PeerOp::PreVote(_) => Err(Error::Unimplemented(
                "a Raft message to the leader's own".into(),
            )),
        }
    }

    /// Proposes a command as the leader.
    async fn write(&self, cmd: Command) -> Result<Applied> {
        if cmd.grows() && self.0.store.full() {
            return Err(Error::NoSpace);
        }
        match self.0.raft.client_write(cmd).await {
            Ok(r) => r
                .data
                .0
                .unwrap_or_else(|| Err(Error::Storage("a command without an answer".into()))),
            Err(e) => Err(write_error(e)),
        }
    }

    /// The leader's ReadIndex: the log index a read must have applied.
    async fn read_index(&self) -> Result<u64> {
        match self.0.raft.ensure_linearizable(ReadPolicy::ReadIndex).await {
            Ok(r) => Ok(r.index()),
            Err(RaftError::APIError(LinearizableReadError::ForwardToLeader(_))) => {
                Err(Error::NotLeader)
            }
            Err(RaftError::APIError(LinearizableReadError::QuorumNotEnough(_))) => {
                Err(Error::NoLeader)
            }
            Err(RaftError::Fatal(_)) => Err(Error::Stopped),
        }
    }

    fn membership(&self) -> Arc<raft::StoredMembership> {
        self.0
            .raft
            .metrics()
            .borrow_watched()
            .membership_config
            .clone()
    }

    fn cluster_header(&self) -> Option<pb::ResponseHeader> {
        Some(self.header(*self.0.shared.rev.borrow()))
    }

    /// A membership change as the leader, tried again while another is in
    /// progress.
    async fn change(&self, c: ChangeMembers<u64, Peer>) -> Result<()> {
        let deadline = Instant::now() + self.0.opts.request_timeout;
        loop {
            match self.0.raft.change_membership(c.clone(), false).await {
                Ok(_) => return Ok(()),
                Err(RaftError::APIError(ClientWriteError::ChangeMembershipError(
                    ChangeMembershipError::InProgress(_),
                ))) if Instant::now() < deadline => tokio::time::sleep(SETTLE * 5).await,
                Err(e) => return Err(write_error(e)),
            }
        }
    }

    async fn add_member(&self, r: pb::MemberAddRequest) -> Result<PeerResult> {
        if !r.is_learner {
            return Err(Error::Unimplemented(
                "adding a voting member (add it as a learner, then promote it)".into(),
            ));
        }
        if r.peer_ur_ls.is_empty() {
            return Err(Error::Unimplemented("a member without peer URLs".into()));
        }
        let m = self.membership();
        if m.membership()
            .nodes()
            .any(|(_, p)| p.peer_urls.iter().any(|u| r.peer_ur_ls.contains(u)))
        {
            return Err(Error::PeerUrlExists);
        }
        let id = loop {
            let id = mvcc::new_lease_id() as u64;
            if m.membership().get_node(&id).is_none() {
                break id;
            }
        };
        let peer = Peer {
            name: String::new(),
            peer_urls: r.peer_ur_ls.clone(),
            client_urls: Vec::new(),
        };
        self.change(ChangeMembers::AddNodes(BTreeMap::from([(id, peer)])))
            .await?;
        let member = pb::Member {
            id,
            name: String::new(),
            peer_ur_ls: r.peer_ur_ls,
            client_ur_ls: Vec::new(),
            is_learner: true,
        };
        Ok(PeerResult::MemberAdd(pb::MemberAddResponse {
            header: self.cluster_header(),
            member: Some(member),
            members: self.members(),
        }))
    }

    async fn remove_member(&self, id: u64) -> Result<PeerResult> {
        let m = self.membership();
        if m.membership().get_node(&id).is_none() {
            return Err(Error::MemberNotFound);
        }
        let set = BTreeSet::from([id]);
        if m.membership().voter_ids().any(|v| v == id) {
            self.change(ChangeMembers::RemoveVoters(set)).await?;
        } else {
            self.change(ChangeMembers::RemoveNodes(set)).await?;
        }
        Ok(PeerResult::MemberRemove(pb::MemberRemoveResponse {
            header: self.cluster_header(),
            members: self.members(),
        }))
    }

    async fn update_member(&self, id: u64, peer_urls: Vec<String>) -> Result<PeerResult> {
        let m = self.membership();
        let Some(old) = m.membership().get_node(&id).cloned() else {
            return Err(Error::MemberNotFound);
        };
        if m.membership()
            .nodes()
            .any(|(o, p)| *o != id && p.peer_urls.iter().any(|u| peer_urls.contains(u)))
        {
            return Err(Error::PeerUrlExists);
        }
        if old.peer_urls != peer_urls {
            let p = Peer { peer_urls, ..old };
            self.change(ChangeMembers::SetNodes(BTreeMap::from([(id, p)])))
                .await?;
        }
        Ok(PeerResult::MemberUpdate(pb::MemberUpdateResponse {
            header: self.cluster_header(),
            members: self.members(),
        }))
    }

    async fn promote_member(&self, id: u64) -> Result<PeerResult> {
        let m = self.membership();
        if m.membership().get_node(&id).is_none() {
            return Err(Error::MemberNotFound);
        }
        if m.membership().voter_ids().any(|v| v == id) {
            return Err(Error::NotLearner);
        }
        // As etcd: the learner's log is at least 90% of the leader's.
        let (matched, last) = {
            let mm = self.0.raft.metrics().borrow_watched().clone();
            let matched = mm
                .replication
                .as_ref()
                .and_then(|r| r.get(&id).cloned().flatten())
                .map_or(0, |l| l.index);
            (matched, mm.last_log_index.unwrap_or(0))
        };
        if (matched as f64) < (last as f64) * 0.9 {
            return Err(Error::LearnerNotReady);
        }
        self.change(ChangeMembers::AddVoterIds(BTreeSet::from([id])))
            .await?;
        Ok(PeerResult::MemberPromote(pb::MemberPromoteResponse {
            header: self.cluster_header(),
            members: self.members(),
        }))
    }

    async fn publish_member(&self, m: pb::Member) -> Result<PeerResult> {
        let ms = self.membership();
        let Some(old) = ms.membership().get_node(&m.id).cloned() else {
            return Err(Error::MemberNotFound);
        };
        if old.name != m.name || old.client_urls != m.client_ur_ls {
            let p = Peer {
                name: m.name,
                client_urls: m.client_ur_ls,
                ..old
            };
            self.change(ChangeMembers::SetNodes(BTreeMap::from([(m.id, p)])))
                .await?;
        }
        Ok(PeerResult::Done(true))
    }

    // The peer service's server side (crate::peer::PeerDispatch).

    /// Answers a request of another member.
    pub(crate) async fn handle_peer(&self, req: PeerRequest) -> PeerReply {
        let ids = self.0.store.ids();
        if let Some(PeerOp::Members(_)) = req.op {
            return PeerReply::of(PeerResult::Members(WMembers {
                cluster: ids.cluster,
                members: self.members(),
            }));
        }
        if req.cluster != ids.cluster || req.to != ids.member {
            return PeerReply::error(&wrong_member(req.cluster, req.to, ids));
        }
        let Some(op) = req.op else {
            return PeerReply::error(&Error::Unimplemented("an empty request".into()));
        };
        let raft = &self.0.raft;
        let r = match op {
            PeerOp::Append(w) => match w.try_into() {
                Ok(rpc) => match raft.append_entries(rpc).await {
                    Ok(r) => Ok(PeerResult::Append((&r).into())),
                    Err(_) => Err(Error::Stopped),
                },
                Err(e) => Err(e),
            },
            PeerOp::Vote(w) => match raft.vote(w.into()).await {
                Ok(r) => Ok(PeerResult::Vote((&r).into())),
                Err(_) => Err(Error::Stopped),
            },
            PeerOp::PreVote(w) => match raft.pre_vote(w.into()).await {
                Ok(r) => Ok(PeerResult::Vote((&r).into())),
                Err(_) => Err(Error::Stopped),
            },
            op => self.local(op).await,
        };
        match r {
            Ok(r) => PeerReply::of(r),
            Err(e) => PeerReply::error(&e),
        }
    }

    /// Installs a snapshot another member sent.
    pub(crate) async fn handle_snapshot(&self, s: tonic::Streaming<SnapshotChunk>) -> PeerReply {
        let ids = self.0.store.ids();
        let r = async {
            let (first, data) = crate::peer::read_chunks(s).await?;
            if first.cluster != ids.cluster || first.to != ids.member {
                return Err(wrong_member(first.cluster, first.to, ids));
            }
            let meta: raft::SnapshotMeta = first.meta.unwrap_or_default().try_into()?;
            let vote: raft::Vote = first.vote.unwrap_or_default().into();
            // Checked before Raft takes it: a damaged snapshot is refused
            // here, not when it is installed.
            crate::snapshot::read(&data)?;
            let snap = openraft::Snapshot {
                meta,
                snapshot: data,
            };
            match self.0.raft.install_full_snapshot(vote, snap).await {
                Ok(r) => Ok(PeerResult::Snapshot((&r.vote).into())),
                Err(_) => Err(Error::Stopped),
            }
        }
        .await;
        match r {
            Ok(r) => PeerReply::of(r),
            Err(e) => PeerReply::error(&e),
        }
    }

    /// Whether this member leads, and has given every lease its whole TTL
    /// again in this term.
    fn leads(&self) -> bool {
        let term = self.0.raft.metrics().borrow_watched().current_term;
        self.0.raft.is_leader() && *self.0.leading.lock().expect("not poisoned") == Some(term)
    }
}

fn unexpected() -> Error {
    Error::Unavailable("the leader answered another request".into())
}

fn wrong_member(cluster: u64, to: u64, ids: mvcc::Ids) -> Error {
    Error::Unavailable(format!(
        "a request for member {to:x} of cluster {cluster:x} reached member {:x} of cluster {:x}",
        ids.member, ids.cluster
    ))
}

fn write_error(e: RaftError<raft::Tc, ClientWriteError<raft::Tc>>) -> Error {
    match e {
        RaftError::APIError(ClientWriteError::ForwardToLeader(_)) => Error::NotLeader,
        RaftError::APIError(ClientWriteError::LogEntryDiscarded(_)) => Error::LeaderChanged,
        RaftError::APIError(e) => Error::Unavailable(e.to_string()),
        RaftError::Fatal(_) => Error::Stopped,
    }
}

fn members_of(m: &raft::Membership) -> Vec<pb::Member> {
    let voters: BTreeSet<u64> = m.voter_ids().collect();
    m.nodes()
        .map(|(id, p)| pb::Member {
            id: *id,
            name: p.name.clone(),
            peer_ur_ls: p.peer_urls.clone(),
            client_ur_ls: p.client_urls.clone(),
            is_learner: !voters.contains(id),
        })
        .collect()
}

/// A new member's IDs: the cluster's, and the one MemberAdd gave the member
/// with this member's peer URL, read from the members at urls.
async fn join(peers: &Peers, urls: &[String], opts: &Options) -> Result<(u64, u64)> {
    let Some(mine) = opts.peer_urls.first() else {
        return Err(Error::Unimplemented(
            "joining a cluster without a peer URL".into(),
        ));
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last = Error::Unavailable("no member to ask".into());
    loop {
        for u in urls {
            let req = PeerRequest {
                op: Some(PeerOp::Members(true)),
                ..Default::default()
            };
            match peers.call(u, req, Duration::from_secs(3)).await {
                Ok(PeerReply {
                    result: Some(PeerResult::Members(m)),
                }) => {
                    if let Some(me) = m.members.iter().find(|m| m.peer_ur_ls.contains(mine)) {
                        return Ok((m.cluster, me.id));
                    }
                    last = Error::Unavailable(format!(
                        "{u} has no member with the peer URL {mine}: add it first (MemberAdd)"
                    ));
                }
                Ok(r) => last = Error::Unavailable(format!("{u}: answered {r:?}")),
                Err(e) => last = e,
            }
        }
        if Instant::now() > deadline {
            return Err(last);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
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

/// Follows Raft's metrics: the term the headers name, and the leases'
/// deadlines renewed when this member becomes the leader.
async fn follow_raft(node: Weak<Inner>, mut stop: watch::Receiver<bool>) {
    let Some(mut m) = node.upgrade().map(|n| n.raft.metrics()) else {
        return;
    };
    loop {
        {
            let Some(inner) = node.upgrade() else { return };
            let mm = m.borrow_watched();
            inner.store.set_term(mm.current_term);
            let mut leading = inner.leading.lock().expect("not poisoned");
            if mm.state == ServerState::Leader && mm.current_leader == Some(inner.ctx.me) {
                if *leading != Some(mm.current_term) {
                    inner.shared.renew_all();
                    *leading = Some(mm.current_term);
                }
            } else {
                *leading = None;
            }
        }
        tokio::select! {
            _ = stop.wait_for(|s| *s) => return,
            r = m.changed() => if r.is_err() { return },
        }
    }
}

/// Proposes, on the leader, the expiry of every lease not kept alive
/// within its TTL.
async fn lease_clock(node: Weak<Inner>, mut stop: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(LEASE_TICK);
    loop {
        tokio::select! {
            _ = stop.wait_for(|s| *s) => return,
            _ = tick.tick() => {}
        }
        let Some(inner) = node.upgrade() else { return };
        let n = Node(inner);
        if !n.leads() {
            continue;
        }
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
                // Only as the leader: an expiry decided by a member that
                // no longer leads must not reach the one that does.
                if n.write(cmd).await.is_err()
                    && let Some(l) = n.0.shared.leases.lock().expect("not poisoned").get_mut(&id)
                {
                    l.expiring = false;
                }
            });
        }
    }
}

/// Compacts, on the leader, the history older than the retention: the
/// revision of a sample taken at least that long ago.
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
            && n.0.raft.is_leader()
        {
            let _ = n
                .write(Command::new(Op::Compact(pb::CompactionRequest {
                    revision: rev,
                    physical: false,
                })))
                .await;
        }
    }
}

/// Tells the cluster this member's name and client URLs once it is in
/// the membership without them (a member MemberAdd added, now started), as
/// etcd's members publish their attributes.
async fn publish(node: Weak<Inner>, mut stop: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    loop {
        tokio::select! {
            _ = stop.wait_for(|s| *s) => return,
            _ = tick.tick() => {}
        }
        let Some(inner) = node.upgrade() else { return };
        let n = Node(inner);
        let me = n.id();
        let current = n.membership().membership().get_node(&me).cloned();
        let Some(current) = current else { continue };
        let o = &n.0.opts;
        if current.name == o.name && current.client_urls == o.client_urls {
            return;
        }
        let m = pb::Member {
            id: me,
            name: o.name.clone(),
            peer_ur_ls: Vec::new(),
            client_ur_ls: o.client_urls.clone(),
            is_learner: false,
        };
        if n.route(PeerOp::Publish(m)).await.is_ok() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raft_settings_are_valid() {
        raft_config(&Timing::default()).unwrap();
    }
}

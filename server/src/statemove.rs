//! The move of the control plane's state from etcd to armada-kv (ADR 0057).
//!
//! The leader moves the state once every server of the cluster runs a
//! release with armada-kv (its server record names the peer URL its member
//! takes, `KvPeerURL`), is a voting etcd member that answers, and has been
//! so for [`Timing::stable`] (ten minutes) as this leader saw it, unless
//! `armada cluster update --state-move off` holds it; `--state-move now`
//! starts it at the next pass without the wait and the backoff. A move:
//!
//! 1. `StateMoveStarted`, then the record (step `copying`) and the moving
//!    key written together (armada-store's statemove): from then on every
//!    write but the move's own is refused with "the control plane's state
//!    is moving".
//! 2. The key space read at that revision (keys with their versions and
//!    revisions; leases with what is left of their TTLs, at least
//!    [`MIN_LEASE_TTL`]; the election's keys and the ACME locks left out)
//!    and handed to this server's machine ([`MoveHost::start_new`]), which
//!    starts a new armada-kv store of its member alone from it.
//! 3. Every other server's member added as a learner at its `KvPeerURL`,
//!    and the record given the first member's peer URL: each server's
//!    daemon, watching the record ([`follow`]), starts its member joining
//!    through it; the leader promotes each once it caught up, until every
//!    server's member votes.
//! 4. The new store's key space read back and compared with the copy (every
//!    key, value, version, revision, and lease, and a SHA-256 over each).
//! 5. The record's step `moved` written into etcd (the point of no return:
//!    the record's value is compared, so a move given up never moves), then
//!    into armada-kv. Every server, seeing `moved`, ends its term, switches
//!    its store to armada-kv, and campaigns there; the new leader records
//!    `StateMoved`.
//!
//! A move that fails before `moved` stops this server's member, removes
//! the record and the moving key (every other server's daemon then removes
//! its member's data), records `StateMoveFailed` with the reason, and waits
//! 10 minutes before the next try, doubling up to 2 hours. A new leader
//! that finds a move `copying` gives it up the same way before anything
//! else ([`clean_up`], from the term's start).

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use armada_proto::armada::v1::{SetClusterConfigRequest, StateMoveStatus};
use armada_proto::etcd::mvccpb::KeyValue;
use armada_spec::gotime::Time;
use armada_store::gojson::{from_ms, unix_milli};
use armada_store::statemove::{
    self as sm, META_STATE_MOVE, META_STATE_MOVE_MODE, META_STATE_MOVE_RETRY, MODE_AUTO, MODE_NOW,
    MODE_OFF, STEP_COPYING, STEP_MOVED, StateMove,
};
use armada_store::{Client, Etcd, Event, Kind};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, watch};
use tonic::codegen::async_trait;
use tonic::{Code, Status};

use crate::cluster::STATE_KV;
use crate::events::event;
use crate::grpc::Auth;
use crate::log::Logger;
use crate::settings::read_meta;
use crate::{Server, store_err};

/// Events.
pub const EVENT_STARTED: &str = "StateMoveStarted";
pub const EVENT_MOVED: &str = "StateMoved";
pub const EVENT_FAILED: &str = "StateMoveFailed";
const EVENT_KIND: &str = "cluster";
const EVENT_OBJECT: &str = "state";

/// The least TTL a lease gets in the new store: a lease about to expire in
/// etcd outlives the move, so its keys are compared, and expires soon
/// after.
pub const MIN_LEASE_TTL: i64 = 600;

/// The first wait after a failed move, doubling up to [`RETRY_MAX`].
pub const RETRY_BASE: Duration = Duration::from_secs(10 * 60);
pub const RETRY_MAX: Duration = Duration::from_secs(2 * 3600);

/// The move's timing; tests shorten it.
#[derive(Clone, Debug)]
pub struct Timing {
    /// How long every server must be ready, as this leader saw it, before
    /// an automatic move.
    pub stable: Duration,
    /// How often the leader looks.
    pub every: Duration,
    /// How long the other servers' members may take to join and catch up.
    pub join_wait: Duration,
    /// How long a whole move may take before it is given up.
    pub limit: Duration,
}

impl Default for Timing {
    fn default() -> Timing {
        Timing {
            stable: Duration::from_secs(10 * 60),
            every: Duration::from_secs(30),
            join_wait: Duration::from_secs(5 * 60),
            limit: Duration::from_secs(15 * 60),
        }
    }
}

/// What a server's machine does in a move: the daemon's, which starts and
/// stops its armada-kv member in its own process until the switch.
#[async_trait]
pub trait MoveHost: Send + Sync {
    /// Starts this server's member of move id as a new store of this
    /// member alone holding the key space (at revision, with its leases),
    /// and returns a client of it once it leads.
    async fn start_new(
        &self,
        id: &str,
        revision: i64,
        kvs: Vec<KeyValue>,
        leases: Vec<(i64, i64)>,
    ) -> Result<Client, String>;
    /// Starts this server's member of move id, joining the new store
    /// through the members at peers (which added it as a learner).
    async fn join(&self, id: &str, peers: &[String]) -> Result<(), String>;
    /// The move whose member this server has, running or on disk.
    fn current(&self) -> Option<String>;
    /// A client of this server's member of move id while it runs.
    fn member(&self, id: &str) -> Option<Client>;
    /// A client of the new store's member at client_url (any server's),
    /// with this server's member certificate.
    fn member_client(&self, client_url: &str) -> Result<Client, String>;
    /// Stops this server's member and removes its data.
    async fn discard(&self);
    /// Whether this server's leader is in the middle of a move: its
    /// member is never discarded, and the switch waits, until it is done.
    fn set_leading(&self, on: bool);
    fn leading(&self) -> bool;
}

/// What the leader remembers of the move between passes (memory only).
#[derive(Default)]
pub struct MoveRuns {
    /// Since when every server was ready, as this leader saw it.
    ready_since: Mutex<Option<Time>>,
    /// A move of this server's runs.
    running: AtomicBool,
    pub(crate) wake: Notify,
}

/// The failures of earlier moves.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct RetryRec {
    failures: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(rename = "failedAt")]
    failed_at: i64,
    #[serde(rename = "retryAt")]
    retry_at: i64,
}

async fn read_retry(st: &Etcd) -> Result<RetryRec, armada_store::Error> {
    match read_meta(st, META_STATE_MOVE_RETRY).await? {
        None => Ok(RetryRec::default()),
        Some(v) => Ok(serde_json::from_value(v).unwrap_or_default()),
    }
}

/// The wait after the n-th failure in a row.
pub fn retry_wait(failures: i64) -> Duration {
    let mut d = RETRY_BASE;
    for _ in 1..failures.max(1) {
        d = (d * 2).min(RETRY_MAX);
    }
    d
}

fn add(t: &Time, d: Duration) -> Time {
    from_ms(unix_milli(t).saturating_add(d.as_millis() as i64))
}

/// Records a failure: the event, and when the next move may start.
async fn note_failure(st: &Etcd, now: &Time, reason: &str, log: &Logger) {
    let mut r = read_retry(st).await.unwrap_or_default();
    r.failures += 1;
    r.error = crate::events::clean_message(reason);
    r.failed_at = unix_milli(now);
    r.retry_at = unix_milli(&add(now, retry_wait(r.failures)));
    let b = serde_json::to_string(&r).unwrap_or_default();
    if let Err(e) = st.set_meta(META_STATE_MOVE_RETRY, &b).await {
        log.warn("state move: record the failure", &[("err", e.to_string())]);
    }
}

/// An event with its times, for a writer that is no term's server.
fn plain_event(reason: &str, message: &str, now: &Time) -> Event {
    let mut e = event(EVENT_KIND, EVENT_OBJECT, "", reason, message);
    e.message = crate::events::clean_message(message);
    e.count = 1;
    e.first = now.clone();
    e.last = now.clone();
    e
}

/// Gives up a move another term left `copying` (the leader that ran it
/// stopped, or this server's term ran again): the record and the moving
/// key go, the failure is recorded, and writes work again. Runs at every
/// term's start, before anything writes.
pub async fn clean_up(st: &Etcd, log: &Logger, now: &Time) -> Result<(), armada_store::Error> {
    let Some((m, raw)) = st.state_move().await? else {
        return Ok(());
    };
    if m.step != STEP_COPYING {
        return Ok(());
    }
    st.end_state_move(&raw).await?;
    let reason = "the leader moving it stopped before the state moved; the state stays in etcd";
    log.warn(
        "state move given up",
        &[("move", m.id.clone()), ("reason", reason.to_string())],
    );
    if let Err(e) = st
        .put_event(&plain_event(EVENT_FAILED, reason, now), "")
        .await
    {
        log.warn("record event", &[("err", e.to_string())]);
    }
    note_failure(st, now, reason, log).await;
    Ok(())
}

/// How a server's [`follow`] ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Followed {
    /// The state moved (move ID): switch to armada-kv.
    Moved(String),
    Stopped,
}

/// A daemon's part in moves, on every server, leader or not: it watches the
/// move's record on its own etcd member (serializable reads, so a member
/// that lost its quorum when the others left etcd still answers), starts
/// its member when a move asks it to join, removes it when the move is
/// given up, and returns once the state moved. A member whose etcd lags
/// learns it moved from its armada-kv member, which has the record only
/// once etcd has it.
pub async fn follow(
    c: Client,
    prefix: String,
    name: String,
    host: Arc<dyn MoveHost>,
    log: Logger,
    every: Duration,
    mut stop: watch::Receiver<bool>,
) -> Followed {
    let log = log.with("component", "state-move");
    let mut said = String::new();
    let mut held = 0u32;
    loop {
        let rec = sm::read_state_move(&c, &prefix, true).await;
        let current = host.current();
        let mut moved = None;
        match &rec {
            Ok(Some((m, _))) if m.step == STEP_MOVED => {
                if current.as_deref() == Some(m.id.as_str()) {
                    moved = Some(m.id.clone());
                } else if said != m.id {
                    log.error(
                        "the state moved to armada-kv without this server's member; restore this server from a backup, or remove it and join it again",
                        &[("move", m.id.clone())],
                    );
                    said = m.id.clone();
                }
            }
            Ok(Some((m, _))) => {
                if let Some(cur) = &current
                    && *cur != m.id
                    && !host.leading()
                {
                    log.info("removing the member of an earlier state move", &[]);
                    host.discard().await;
                } else if m.leader != name
                    && m.servers.contains(&name)
                    && !m.peers.is_empty()
                    && host.member(&m.id).is_none()
                {
                    log.info(
                        "starting this server's armada-kv member for the state move",
                        &[("move", m.id.clone())],
                    );
                    if let Err(e) = host.join(&m.id, &m.peers).await {
                        log.warn("start the armada-kv member", &[("err", e)]);
                    }
                }
                if moved.is_none() {
                    moved = moved_in_kv(host.as_ref(), &current, &prefix).await;
                }
            }
            Ok(None) => {
                if current.is_some() && !host.leading() {
                    log.info(
                        "the state move was given up; removing this server's armada-kv member",
                        &[],
                    );
                    host.discard().await;
                }
            }
            Err(_) => moved = moved_in_kv(host.as_ref(), &current, &prefix).await,
        }
        if let Some(id) = moved {
            // This server's leader writes the record into armada-kv after
            // etcd; the switch waits for it, at most a minute.
            if !host.leading() || held * every.as_millis().max(1) as u32 >= 60_000 {
                return Followed::Moved(id);
            }
            held += 1;
        }
        tokio::select! {
            _ = crate::stopped(&mut stop) => return Followed::Stopped,
            _ = tokio::time::sleep(every) => {}
        }
    }
}

/// The move this server's member belongs to, when its armada-kv member says
/// the state moved.
async fn moved_in_kv(
    host: &dyn MoveHost,
    current: &Option<String>,
    prefix: &str,
) -> Option<String> {
    let id = current.clone()?;
    let kc = host.member(&id)?;
    match sm::read_state_move(&kc, prefix, true).await {
        Ok(Some((m, _))) if m.step == STEP_MOVED && m.id == id => Some(id),
        _ => None,
    }
}

/// Each server record names its server's member of the store kc reaches
/// (matched by name).
async fn rename_members(kc: &Client, prefix: &str) -> Result<(), String> {
    let members = kc.member_list().await.map_err(|e| e.to_string())?;
    let st = Etcd::new(kc.clone(), prefix)
        .await
        .map_err(|e| e.to_string())?;
    for mut srv in st.list_servers().await.map_err(|e| e.to_string())? {
        if let Some(m) = members.iter().find(|m| m.name == srv.name)
            && m.id != srv.member_id
        {
            srv.member_id = m.id;
            st.upsert_server(&srv).await.map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Resets a host's leading flag when a move of this server ends, also when
/// its term ends in the middle.
struct Leading(Arc<dyn MoveHost>);

impl Drop for Leading {
    fn drop(&mut self) {
        self.0.set_leading(false);
    }
}

fn hex_id() -> String {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 8];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .expect("the system's random source");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Server {
    fn on_kv(&self) -> bool {
        self.0
            .cluster
            .as_ref()
            .is_some_and(|c| c.state() == STATE_KV)
    }

    /// The mode: auto, off, or now.
    async fn state_move_mode(&self) -> Result<String, armada_store::Error> {
        match self.store().get_meta(META_STATE_MOVE_MODE).await {
            Err(e) if e.kind == Kind::NotFound => Ok(MODE_AUTO.to_string()),
            Err(e) => Err(e),
            Ok(m) if m.is_empty() => Ok(MODE_AUTO.to_string()),
            Ok(m) => Ok(m),
        }
    }

    /// What keeps the state from moving now: empty when every server runs
    /// a release with armada-kv and is a voting etcd member that answers.
    async fn state_move_blockers(&self) -> Result<Vec<String>, armada_store::Error> {
        let mut out = Vec::new();
        let Some(cluster) = &self.0.cluster else {
            return Ok(vec!["this server manages no etcd membership".to_string()]);
        };
        let views = self.servers().await?;
        for v in &views {
            let n = &v.rec.name;
            if v.rec.kv_peer_url.is_empty() {
                out.push(format!("{n} runs a release without armada-kv: upgrade it"));
            } else if !v.member {
                out.push(format!("{n} is not an etcd member"));
            } else if !v.voting {
                out.push(format!("{n} is still joining"));
            } else if !cluster.reachable(&v.info).await {
                out.push(format!("{n}'s etcd member does not answer"));
            }
        }
        let members = cluster
            .members()
            .await
            .map_err(armada_store::Error::other)?;
        for m in members {
            if !views.iter().any(|v| v.rec.member_id == m.id) {
                out.push(format!(
                    "etcd member {} belongs to no server",
                    if m.name.is_empty() {
                        "(unstarted)"
                    } else {
                        &m.name
                    }
                ));
            }
        }
        if !views.iter().any(|v| v.rec.name == self.0.name) {
            out.push(format!("{} has no server record", self.0.name));
        }
        Ok(out)
    }

    /// The leader's loop: a pass every [`Timing::every`], and when the
    /// settings change.
    pub(crate) async fn state_move_loop(&self, mut shutdown: watch::Receiver<bool>) {
        if self.0.state_mover.is_none() {
            return;
        }
        let every = self.0.state_move_timing.every;
        loop {
            let res = tokio::select! {
                r = self.state_move_pass() => r,
                _ = crate::stopped(&mut shutdown) => return,
            };
            if let Err(e) = res
                && !*shutdown.borrow()
            {
                self.0.log.warn("state move", &[("err", e)]);
            }
            tokio::select! {
                _ = crate::stopped(&mut shutdown) => return,
                _ = tokio::time::sleep(every) => {}
                _ = self.0.state_moves.wake.notified() => {}
            }
        }
    }

    /// Moves the state when it is time to; on armada-kv, records that it
    /// moved.
    pub async fn state_move_pass(&self) -> Result<(), String> {
        let Some(host) = self.0.state_mover.clone() else {
            return Ok(());
        };
        let e = |e: armada_store::Error| e.to_string();
        if self.on_kv() {
            return self.tell_moved().await.map_err(e);
        }
        if let Some((m, _)) = self.store().state_move().await.map_err(e)? {
            if m.step == STEP_COPYING && !self.0.state_moves.running.load(Ordering::SeqCst) {
                clean_up(self.store(), &self.0.log, &self.now())
                    .await
                    .map_err(e)?;
            }
            return Ok(());
        }
        let mode = self.state_move_mode().await.map_err(e)?;
        if mode == MODE_OFF {
            *self.0.state_moves.ready_since.lock().expect("ready") = None;
            return Ok(());
        }
        let now = self.now();
        let blockers = self.state_move_blockers().await.map_err(e)?;
        let since = {
            let mut s = self.0.state_moves.ready_since.lock().expect("ready");
            if blockers.is_empty() {
                s.get_or_insert_with(|| now.clone()).clone()
            } else {
                *s = None;
                return Ok(());
            }
        };
        if mode != MODE_NOW {
            let stable = self.0.state_move_timing.stable;
            if unix_milli(&now) - unix_milli(&since) < stable.as_millis() as i64 {
                return Ok(());
            }
            let r = read_retry(self.store()).await.map_err(e)?;
            if r.retry_at > unix_milli(&now) {
                return Ok(());
            }
        }
        self.move_state(host, &mode).await
    }

    /// One move, from the record to `moved`, or given up.
    async fn move_state(&self, host: Arc<dyn MoveHost>, mode: &str) -> Result<(), String> {
        let st = self.store();
        let e = |e: armada_store::Error| e.to_string();
        if mode == MODE_NOW {
            st.set_meta(META_STATE_MOVE_MODE, MODE_AUTO)
                .await
                .map_err(e)?;
        }
        let servers = st.list_servers().await.map_err(e)?;
        let now = self.now();
        let mut m = StateMove {
            id: hex_id(),
            step: STEP_COPYING.to_string(),
            leader: self.0.name.clone(),
            servers: servers.iter().map(|s| s.name.clone()).collect(),
            started_at: unix_milli(&now),
            ..Default::default()
        };
        self.record(event(
            EVENT_KIND,
            EVENT_OBJECT,
            "",
            EVENT_STARTED,
            &format!(
                "moving the control plane's state from etcd to armada-kv on {} (writes wait until it moved)",
                m.servers.join(", ")
            ),
        ))
        .await;
        self.0.log.info(
            "moving the control plane's state to armada-kv",
            &[("move", m.id.clone()), ("servers", m.servers.join(","))],
        );
        self.0.state_moves.running.store(true, Ordering::SeqCst);
        host.set_leading(true);
        let _leading = Leading(host.clone());
        struct Running<'a>(&'a AtomicBool);
        impl Drop for Running<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _running = Running(&self.0.state_moves.running);
        let (rev, mut raw) = match st.begin_state_move(&m).await {
            Ok(v) => v,
            Err(err) => {
                let reason = format!("start: {err}");
                self.moved_not(&m, None, &host, &reason).await;
                return Err(reason);
            }
        };
        let res = tokio::time::timeout(
            self.0.state_move_timing.limit,
            self.copy_state(&host, &mut m, &mut raw, rev, &servers),
        )
        .await;
        let res = match res {
            Ok(r) => r,
            Err(_) => Err(format!(
                "the move took longer than {}",
                armada_spec::go::format_duration(self.0.state_move_timing.limit.as_nanos() as i64)
            )),
        };
        match res {
            Ok(()) => {
                self.0.log.info(
                    "the control plane's state moved to armada-kv; every server switches to it",
                    &[("move", m.id.clone()), ("revision", rev.to_string())],
                );
                Ok(())
            }
            Err(reason) if m.step == STEP_MOVED => {
                // Past the point of no return: the servers switch.
                self.0.log.warn(
                    "the state moved, but its record did not reach armada-kv",
                    &[("err", reason)],
                );
                Ok(())
            }
            Err(reason) => {
                self.moved_not(&m, Some(&raw), &host, &reason).await;
                Err(reason)
            }
        }
    }

    /// Gives a move of this server's up: its member stopped and removed,
    /// the record and the moving key removed (the other servers remove
    /// theirs on seeing it), the failure recorded.
    async fn moved_not(
        &self,
        m: &StateMove,
        raw: Option<&[u8]>,
        host: &Arc<dyn MoveHost>,
        reason: &str,
    ) {
        host.discard().await;
        if let Some(raw) = raw
            && let Err(err) = self.store().end_state_move(raw).await
        {
            // Another leader gave it up already, or this one lost its
            // term: the next leader cleans up.
            self.0.log.warn(
                "state move: give it up",
                &[("move", m.id.clone()), ("err", err.to_string())],
            );
            if err.kind == Kind::NotLeader {
                return;
            }
        }
        self.0.log.warn(
            "state move failed; the state stays in etcd",
            &[("move", m.id.clone()), ("reason", reason.to_string())],
        );
        let now = self.now();
        self.record(event(
            EVENT_KIND,
            EVENT_OBJECT,
            "",
            EVENT_FAILED,
            &format!("{reason}; the state stays in etcd and the move is tried again later"),
        ))
        .await;
        note_failure(self.store(), &now, reason, &self.0.log).await;
    }

    /// Steps 2 to 5 of a move.
    async fn copy_state(
        &self,
        host: &Arc<dyn MoveHost>,
        m: &mut StateMove,
        raw: &mut Vec<u8>,
        rev: i64,
        servers: &[armada_store::Server],
    ) -> Result<(), String> {
        let st = self.store();
        let prefix = st.prefix().to_string();
        let etcd = st.client().clone();
        let (_, kvs) = sm::read_key_space(&etcd, rev, &prefix)
            .await
            .map_err(|e| format!("read etcd's key space: {e}"))?;
        let leases = sm::lease_ttls(&etcd, &kvs)
            .await
            .map_err(|e| format!("read etcd's leases: {e}"))?
            .into_iter()
            .map(|(id, ttl)| (id, ttl.max(MIN_LEASE_TTL)))
            .collect();
        let kc = host
            .start_new(&m.id, rev, kvs.clone(), leases)
            .await
            .map_err(|e| format!("start this server's armada-kv member: {e}"))?;
        let mine = servers
            .iter()
            .find(|s| s.name == self.0.name)
            .map(|s| s.kv_peer_url.clone())
            .unwrap_or_default();
        let others: Vec<&armada_store::Server> =
            servers.iter().filter(|s| s.name != self.0.name).collect();
        for s in &others {
            kc.member_add_learner(vec![s.kv_peer_url.clone()])
                .await
                .map_err(|e| format!("add {}'s armada-kv member: {e}", s.name))?;
        }
        m.peers = vec![mine];
        *raw = st
            .step_state_move(raw, m)
            .await
            .map_err(|e| format!("record the new store's peers: {e}"))?;
        if !others.is_empty() {
            self.wait_members(&kc, servers.len()).await?;
        }
        let (at, got) = sm::read_key_space(&kc, 0, &prefix)
            .await
            .map_err(|e| format!("read armada-kv's key space: {e}"))?;
        if let Some(d) = sm::key_space_difference(&kvs, &got) {
            return Err(format!("the copy differs from etcd: {d}"));
        }
        self.check_members(host, &kc, at, &prefix, &kvs).await?;
        m.step = STEP_MOVED.to_string();
        m.revision = rev;
        m.moved_at = unix_milli(&self.now());
        match st.step_state_move(raw, m).await {
            Ok(v) => *raw = v,
            Err(err) => {
                m.step = STEP_COPYING.to_string();
                return Err(format!("record that the state moved: {err}"));
            }
        }
        let key = sm::meta_key(&prefix, META_STATE_MOVE);
        let mut last = String::new();
        for _ in 0..10 {
            match kc.put(&key, &m.encode()).await {
                Ok(_) => {
                    last.clear();
                    break;
                }
                Err(e) => last = e.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        if !last.is_empty() {
            return Err(format!("write the record into armada-kv: {last}"));
        }
        // The server records name their etcd member IDs: from now on they
        // name the new store's (each server writes its own again when it
        // starts on armada-kv).
        if let Err(e) = rename_members(&kc, &prefix).await {
            self.0.log.warn(
                "state move: record the servers' armada-kv member IDs",
                &[("err", e)],
            );
        }
        Ok(())
    }

    /// Every member of the new store holds the copy: each one's own key
    /// space at the revision the leader's member reached, read without
    /// asking the leader once the member applied that far (at most the
    /// join wait). A member that lacks it, or differs, fails the move.
    async fn check_members(
        &self,
        host: &Arc<dyn MoveHost>,
        kc: &Client,
        at: i64,
        prefix: &str,
        kvs: &[KeyValue],
    ) -> Result<(), String> {
        let members = kc
            .member_list()
            .await
            .map_err(|e| format!("armada-kv member list: {e}"))?;
        for mem in &members {
            let name = if mem.name.is_empty() {
                mem.peer_ur_ls.join(",")
            } else {
                mem.name.clone()
            };
            let Some(url) = mem.client_ur_ls.first() else {
                return Err(format!("armada-kv member {name} names no client URL"));
            };
            let c = host
                .member_client(url)
                .map_err(|e| format!("reach armada-kv member {name}: {e}"))?;
            let deadline = tokio::time::Instant::now() + self.0.state_move_timing.join_wait;
            let got = loop {
                match sm::read_key_space_on(&c, at, prefix, true).await {
                    Ok((_, got)) => break got,
                    Err(e) if tokio::time::Instant::now() > deadline => {
                        return Err(format!(
                            "armada-kv member {name} did not apply revision {at}: {e}"
                        ));
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
                }
            };
            if let Some(d) = sm::key_space_difference(kvs, &got) {
                return Err(format!(
                    "armada-kv member {name} does not hold the copy: {d}"
                ));
            }
        }
        Ok(())
    }

    /// Promotes the joining members as they catch up, until every server's
    /// member votes.
    async fn wait_members(&self, kc: &Client, want: usize) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + self.0.state_move_timing.join_wait;
        loop {
            let members = kc
                .member_list()
                .await
                .map_err(|e| format!("armada-kv member list: {e}"))?;
            let mut waiting = Vec::new();
            for mem in &members {
                if !mem.is_learner {
                    continue;
                }
                if mem.name.is_empty() {
                    waiting.push(mem.peer_ur_ls.join(","));
                    continue;
                }
                if kc.member_promote(mem.id).await.is_err() {
                    // Not caught up yet.
                    waiting.push(mem.name.clone());
                }
            }
            if waiting.is_empty() && members.len() >= want {
                return Ok(());
            }
            if tokio::time::Instant::now() > deadline {
                return Err(format!(
                    "the armada-kv members at {} did not join within {}",
                    waiting.join(", "),
                    armada_spec::go::format_duration(
                        self.0.state_move_timing.join_wait.as_nanos() as i64
                    )
                ));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// On armada-kv: the StateMoved event, once, and the failures of
    /// earlier tries forgotten.
    async fn tell_moved(&self) -> Result<(), armada_store::Error> {
        let Some((mut m, _)) = self.store().state_move().await? else {
            return Ok(());
        };
        if m.step != STEP_MOVED || m.told {
            return Ok(());
        }
        self.record(event(
            EVENT_KIND,
            EVENT_OBJECT,
            "",
            EVENT_MOVED,
            &format!(
                "the control plane's state moved from etcd to armada-kv (etcd's revision {})",
                m.revision
            ),
        ))
        .await;
        m.told = true;
        let json =
            String::from_utf8(serde_json::to_vec(&m).unwrap_or_default()).unwrap_or_default();
        self.store().set_meta(META_STATE_MOVE, &json).await?;
        self.store().set_meta(META_STATE_MOVE_RETRY, "").await
    }

    /// What ClusterStatus shows of the state and its move; None on a
    /// server that cannot move it.
    pub(crate) async fn state_move_status(
        &self,
    ) -> Result<Option<StateMoveStatus>, armada_store::Error> {
        if self.0.state_mover.is_none() {
            return Ok(None);
        }
        let mut out = StateMoveStatus {
            store: if self.on_kv() { "kv" } else { "etcd" }.to_string(),
            mode: self.state_move_mode().await?,
            ..Default::default()
        };
        if let Some((m, _)) = self.store().state_move().await? {
            out.step = m.step.clone();
            out.since_unix = m.started_at / 1000;
            out.moved_unix = m.moved_at / 1000;
            out.revision = m.revision;
        }
        if self.on_kv() {
            return Ok(Some(out));
        }
        let r = read_retry(self.store()).await?;
        if r.failures > 0 {
            out.failures = r.failures as i32;
            out.error = r.error.clone();
            out.failed_unix = r.failed_at / 1000;
            out.retry_unix = r.retry_at / 1000;
        }
        if out.step.is_empty() && out.mode != MODE_OFF {
            out.waiting = self.state_move_blockers().await?;
            let since = self
                .0
                .state_moves
                .ready_since
                .lock()
                .expect("ready")
                .clone();
            if out.waiting.is_empty() && out.mode == MODE_AUTO {
                let stable = self.0.state_move_timing.stable;
                let at = add(&since.unwrap_or_else(|| self.now()), stable);
                if at.after(&self.now()) {
                    out.waiting.push(format!(
                        "every server ready for {} (until {})",
                        armada_spec::go::format_duration(stable.as_nanos() as i64),
                        at.rfc3339_nano()
                    ));
                }
            }
        }
        Ok(Some(out))
    }

    /// The metrics: the store, and the moves that failed in a row; None
    /// on a server that cannot move the state.
    pub(crate) async fn state_move_gauges(
        &self,
    ) -> Result<Option<(&'static str, i64)>, armada_store::Error> {
        if self.0.state_mover.is_none() {
            return Ok(None);
        }
        if self.on_kv() {
            return Ok(Some(("kv", 0)));
        }
        Ok(Some(("etcd", read_retry(self.store()).await?.failures)))
    }

    /// The mode GetClusterConfig shows: empty for auto.
    pub(crate) async fn state_move_setting(&self) -> Result<String, armada_store::Error> {
        let m = self.state_move_mode().await?;
        Ok(if m == MODE_AUTO { String::new() } else { m })
    }

    /// SetClusterConfig's --state-move.
    pub(crate) async fn set_state_move(
        &self,
        a: &Auth,
        req: &SetClusterConfigRequest,
    ) -> Result<(), Status> {
        if !req.set_state_move {
            return Ok(());
        }
        let mode = req
            .config
            .as_ref()
            .map(|c| c.state_move.trim().to_string())
            .unwrap_or_default();
        let mode = if mode.is_empty() {
            MODE_AUTO.to_string()
        } else {
            mode
        };
        if ![MODE_AUTO, MODE_OFF, MODE_NOW].contains(&mode.as_str()) {
            return Err(Status::new(
                Code::InvalidArgument,
                format!(
                    "--state-move {}: want auto, off, or now",
                    armada_spec::go::quote(&mode)
                ),
            ));
        }
        if self.0.state_mover.is_none() {
            return Err(Status::new(
                Code::FailedPrecondition,
                "this server cannot move the control plane's state",
            ));
        }
        if mode == MODE_NOW && self.on_kv() {
            return Err(Status::new(
                Code::FailedPrecondition,
                "the control plane's state is in armada-kv already",
            ));
        }
        self.store()
            .set_meta(META_STATE_MOVE_MODE, &mode)
            .await
            .map_err(|e| store_err(&e))?;
        self.store()
            .record_audit(&a.actor(), "cluster.state_move", "cluster", &mode)
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "state move setting changed",
            &[("state_move", mode), ("by", a.actor())],
        );
        self.0.state_moves.wake.notify_one();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_wait_longer_up_to_two_hours() {
        assert_eq!(retry_wait(1), Duration::from_secs(600));
        assert_eq!(retry_wait(2), Duration::from_secs(1200));
        assert_eq!(retry_wait(4), Duration::from_secs(4800));
        assert_eq!(retry_wait(5), Duration::from_secs(7200));
        assert_eq!(retry_wait(50), Duration::from_secs(7200));
        assert_eq!(retry_wait(0), Duration::from_secs(600));
    }
}

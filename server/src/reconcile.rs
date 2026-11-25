//! The reconcile pass (Go's Reconcile and reconciler.go, remove.go):
//! scheduling, rollouts (ADR 0005), drains, evacuation of cordoned and
//! lost nodes and self-healing (ADR 0008), rebalancing (ADR 0013),
//! placement (ADR 0014), traffic splitting (ADR 0022), and the removal of
//! apps, then every connected node's assignment.
//!
//! Jobs and their queue triggers (pull request 10 of ADR 0055) run after
//! the apps (`jobs`, `triggers`); the autoscaler (11) runs on its own
//! loop (`autoscale`), and a pass tells the usage store whose replicas
//! are whose. Apps with local volumes (12) are reconciled by `volumes`.
//! The proxy configuration (14), and the cluster network and the runtime
//! move (13) are left out until their pull requests. Go's server runs the
//! same parts in the scenario parity tests (`coreParts`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicI64, Ordering as AtomicOrdering};
use std::time::Duration;

use armada_proto::armada::v1::QueueSandbox;
use armada_spec::go::format_duration;
use armada_spec::gotime::Time;
use armada_spec::{App as Spec, INGRESS_NONE, Placement, TrafficTarget};
use armada_store::{
    App, Event, Kind, NODE_READY, Node, REPLICA_FAILED, REPLICA_PENDING, REPLICA_RUNNING,
    ROLLOUT_FAILED, ROLLOUT_NONE, Replica, Revision,
};

use crate::Server;
use crate::assign::Revisions;
use crate::events::{NODE, REPLICA, event};
use crate::schedule::{
    Use, allocatable, eligible, pick_node, pick_victim, placement_allows, rebalance_victim,
    reservation, spread_groups, usage_of,
};

type Result<T> = std::result::Result<T, armada_store::Error>;

pub(crate) const APP: &str = "app";
pub(crate) const ROLLOUT: &str = "rollout";

const SECOND: i64 = 1_000_000_000;
const MILLISECOND: i64 = 1_000_000;
/// maxSurge: at most one replica above the desired count during a rollout.
const MAX_SURGE: i64 = 1;
pub(crate) const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const DEFAULT_WARMUP: Duration = Duration::from_secs(3);
pub(crate) const DEFAULT_PROGRESS_DEADLINE: Duration = Duration::from_secs(3 * 60);
/// rebalanceBackoff: how long an app is left alone after a move whose
/// replacement never served.
const REBALANCE_BACKOFF: i64 = 10 * 60 * SECOND;
/// failedMoveAfter: how long a replica keeps failing to start on its node
/// before it is tried on another one.
const FAILED_MOVE_AFTER: i64 = 60 * SECOND;
/// awayHold bounds how long a drained replica waits for nodes that are
/// away (finishDrain).
const AWAY_HOLD: i64 = 60 * SECOND;

/// Go's Time.Sub in nanoseconds.
pub(crate) fn sub(a: &Time, b: &Time) -> i64 {
    (a.unix - b.unix)
        .saturating_mul(SECOND)
        .saturating_add(a.nsec - b.nsec)
}

pub(crate) fn nanos(d: Duration) -> i64 {
    i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)
}

/// An event about an app.
pub(crate) fn app_event(kind: &str, object: &str, app: &str, reason: &str, msg: &str) -> Event {
    let mut e = event(kind, object, "", reason, msg);
    e.app = app.to_string();
    e
}

fn replica_event(r: &Replica, reason: &str, msg: &str) -> Event {
    let mut e = event(REPLICA, &r.id, &r.node_id, reason, msg);
    e.app = r.app.clone();
    e
}

/// The rollout progress, moves, and failures the server remembers between
/// passes (Go's progress, rebalanceAfter, and failedSince).
#[derive(Default)]
pub(crate) struct Memory {
    progress: HashMap<String, (String, usize)>,
    rebalance_after: HashMap<String, Time>,
    failed_since: HashMap<String, Time>,
}

/// One change to the pass's replicas, undone when an app fails.
enum Undo {
    Replaced(usize, Replica),
    Removed(usize, Replica),
    Pushed,
}

/// What each app of a pass needs to know about all the replicas (Go's
/// replicaView).
pub(crate) struct View {
    pub by_app: HashMap<String, Vec<Replica>>,
    pub use_: Use,
    pub moving: bool,
}

/// The state of one pass (Go's reconcileRun).
pub(crate) struct Run<'a> {
    pub now: Time,
    /// The earliest time something becomes due, relative to now (0: none).
    wake: AtomicI64,
    /// The nodes whose replicas are being rescheduled.
    pub lost: HashSet<String>,
    /// A node is disconnected but not lost yet.
    pub away: bool,
    pub revs: Revisions<'a>,
    /// The pass's current replicas.
    pub all: Vec<Replica>,
    generation: u64,
    view: Option<(u64, View)>,
    undo: Vec<Undo>,

    /// Queue triggers (ADR 0040): the connected nodes that keep network
    /// sandboxes, the node that reads each queue-triggered job's queue (""
    /// for none), what each node is asked to read, and the jobs with a
    /// queue trigger.
    pub sandbox_nodes: HashSet<String>,
    pub queue_nodes: HashMap<String, String>,
    pub sandboxes: HashMap<String, Vec<QueueSandbox>>,
    pub triggered: HashSet<String>,
    /// The sandboxes' addresses, as replicas of their jobs, for the
    /// cluster network's endpoints (pull request 13).
    #[allow(dead_code)]
    pub sandbox_addrs: Vec<Replica>,
}

impl<'a> Run<'a> {
    pub(crate) fn new(now: Time, revs: Revisions<'a>, all: Vec<Replica>) -> Run<'a> {
        Run {
            now,
            wake: AtomicI64::new(0),
            lost: HashSet::new(),
            away: false,
            revs,
            all,
            generation: 0,
            view: None,
            undo: Vec::new(),
            sandbox_nodes: HashSet::new(),
            queue_nodes: HashMap::new(),
            sandboxes: HashMap::new(),
            triggered: HashSet::new(),
            sandbox_addrs: Vec::new(),
        }
    }

    pub(crate) fn wake_at(&self, t: &Time) {
        let mut d = sub(t, &self.now);
        if d <= 0 {
            d = MILLISECOND;
        }
        let w = self.wake.load(AtomicOrdering::Relaxed);
        if w == 0 || d < w {
            self.wake.store(d, AtomicOrdering::Relaxed);
        }
    }

    pub(crate) fn replace(&mut self, r: &Replica) {
        if let Some(i) = self.all.iter().position(|x| x.id == r.id) {
            let old = std::mem::replace(&mut self.all[i], r.clone());
            self.undo.push(Undo::Replaced(i, old));
        }
        self.generation += 1;
    }

    pub(crate) fn without(&mut self, id: &str) {
        while let Some(i) = self.all.iter().position(|x| x.id == id) {
            let old = self.all.remove(i);
            self.undo.push(Undo::Removed(i, old));
        }
        self.generation += 1;
    }

    pub(crate) fn push(&mut self, r: Replica) {
        self.all.push(r);
        self.undo.push(Undo::Pushed);
        self.generation += 1;
    }

    /// Takes back every change since the last commit: an app that cannot
    /// be reconciled leaves the pass's replicas as they were.
    fn rollback(&mut self) {
        while let Some(u) = self.undo.pop() {
            match u {
                Undo::Replaced(i, r) => self.all[i] = r,
                Undo::Removed(i, r) => self.all.insert(i, r),
                Undo::Pushed => {
                    self.all.pop();
                }
            }
        }
        self.generation += 1;
    }

    fn commit(&mut self) {
        self.undo.clear();
    }

    /// The view of the pass's current replicas, worked out again only
    /// after a change.
    pub(crate) async fn view(&mut self) -> &View {
        if self
            .view
            .as_ref()
            .is_none_or(|(g, _)| *g != self.generation)
        {
            let res = self.revs.reserved(&self.all).await;
            let mut by_app: HashMap<String, Vec<Replica>> = HashMap::new();
            for r in &self.all {
                by_app.entry(r.app.clone()).or_default().push(r.clone());
            }
            let v = View {
                by_app,
                use_: usage_of(&self.all, &res),
                moving: self.all.iter().any(|r| r.moving() && !r.draining()),
            };
            self.view = Some((self.generation, v));
        }
        &self.view.as_ref().expect("view").1
    }
}

/// nodeLost: n has been disconnected for at least timeout.
pub(crate) fn node_lost(n: &Node, now: &Time, timeout: i64) -> bool {
    n.state != NODE_READY && !n.last_seen.is_zero() && sub(now, &n.last_seen) >= timeout
}

/// publishesPort.
pub(crate) fn publishes_port(sp: &Spec) -> bool {
    sp.ingress.as_ref().is_some_and(|i| i.typ != INGRESS_NONE)
}

/// working: r runs and is ready (and has an address when it publishes a
/// port), warmed up or not.
fn working(r: &Replica, publishes: bool) -> bool {
    r.state == REPLICA_RUNNING && r.ready && !r.draining() && (!publishes || !r.address.is_empty())
}

/// trafficWeight: rev's weight in app's traffic, or -1.
pub(crate) fn traffic_weight(app: &App, rev: &str) -> i64 {
    app.traffic
        .iter()
        .find(|t| t.revision == rev)
        .map_or(-1, |t| t.weight)
}

/// trafficShares: replicas per traffic target, at least one each.
pub(crate) fn traffic_shares(total: i64, traffic: &[TrafficTarget]) -> Vec<i64> {
    traffic
        .iter()
        .map(|t| ((total * t.weight + 50) / 100).max(1))
        .collect()
}

/// probeBudget: how long a healthy replica may need to pass its startup
/// and readiness probes.
fn probe_budget(sp: &Spec) -> i64 {
    let Some(p) = &sp.probes else { return 0 };
    let mut d = 0;
    for p in [&p.startup, &p.readiness].into_iter().flatten() {
        d += p.initial_delay.0 + p.failure_threshold * p.period.0;
    }
    d
}

fn later(a: &Time, b: &Time) -> Time {
    if b.after(a) { b.clone() } else { a.clone() }
}

fn without(rs: &mut Vec<Replica>, id: &str) {
    rs.retain(|r| r.id != id);
}

/// Whether each revision of a reconcile publishes a port (unknown: it
/// does, so an address is required).
pub(crate) struct Publishes(HashMap<String, bool>);

impl Publishes {
    /// What reconcileVolumeApp's serving reads: every replica as the
    /// target revision publishes (its current replicas are all of it).
    pub(crate) fn of_all(rev: String, publishes: bool) -> Publishes {
        Publishes(HashMap::from([(rev, publishes)]))
    }

    pub(crate) fn of(&self, r: &Replica) -> bool {
        self.0.get(&r.revision).copied().unwrap_or(true)
    }
}

impl Server {
    fn memory(&self) -> std::sync::MutexGuard<'_, Memory> {
        self.0.memory.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// serving: r takes traffic and has done so long enough for every
    /// proxy to have picked it up.
    pub(crate) fn serving(&self, rc: &Run<'_>, r: &Replica, publishes: bool) -> bool {
        if r.state != REPLICA_RUNNING
            || !r.ready
            || r.draining()
            || (publishes && r.address.is_empty())
        {
            return false;
        }
        let due = r.ready_since.add(nanos(self.0.warmup));
        if due.after(&rc.now) {
            rc.wake_at(&due);
            return false;
        }
        true
    }

    /// A reconcile pass (Go's Reconcile, the parts ported so far).
    pub async fn reconcile(&self) -> Result<()> {
        let _pass = self.0.pass.lock().await;
        let res = self.pass().await;
        self.0.opened.sweep();
        res
    }

    async fn pass(&self) -> Result<()> {
        let mut apps = self.store().list_apps().await?;
        let nodes = self.store().list_nodes().await?;
        let replicas = self.store().list_replicas(&Default::default()).await?;
        self.0.usage.set_owners(&replicas);
        let mut revs = Revisions::new(self);
        revs.preload(&apps, &replicas).await;
        let servers = self.store().list_servers().await?;
        let nodes = allocatable(&nodes, &servers);
        self.0.cluster_size.store(
            (apps.len() + nodes.len()) as i64,
            std::sync::atomic::Ordering::Relaxed,
        );
        let mut rc = Run::new(self.now(), revs, replicas);
        rc.sandbox_nodes = self.sandbox_nodes();
        rc.lost = self.lost_nodes(&mut rc, &nodes).await;
        let mut jobs = Vec::new();
        for app in &mut apps {
            if app.spec.as_ref().is_some_and(|s| s.is_job()) {
                jobs.push(app.clone());
                continue;
            }
            let res = if app.removing {
                self.reconcile_removal(&mut rc, app).await.map(|_| ())
            } else {
                self.reconcile_app(&mut rc, app, &nodes).await
            };
            if let Err(e) = &res
                && e.kind == Kind::NotLeader
            {
                return Err(e.clone().context(format!("app {}", app.name)));
            }
            let msg = match &res {
                Err(e) => e.to_string(),
                Ok(()) => "<nil>".to_string(),
            };
            self.condition(
                &format!("reconcile/{}", app.name),
                res.is_err(),
                app_event(APP, &app.name, &app.name, "ReconcileFailed", &msg),
            )
            .await;
            match res {
                Err(e) => {
                    self.0.log.error(
                        "reconcile app",
                        &[("app", app.name.clone()), ("err", e.to_string())],
                    );
                    rc.rollback();
                }
                Ok(()) => rc.commit(),
            }
        }
        self.reconcile_jobs(&mut rc, &jobs, &nodes).await?;
        let wake = rc.wake.load(AtomicOrdering::Relaxed);
        if wake > 0 {
            self.wake_after(wake);
        }
        let eps = self.endpoints().await?;
        *self
            .0
            .endpoints_seen
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some((eps.clone(), tokio::time::Instant::now()));
        let all = std::mem::take(&mut rc.all);
        let sandboxes = std::mem::take(&mut rc.sandboxes);
        self.push_assignments(&all, &mut rc.revs, &eps, &sandboxes)
            .await
    }

    /// wakeAfter: a reconcile after d nanoseconds unless one is due sooner.
    pub(crate) fn wake_after(&self, d: i64) {
        let d = Duration::from_nanos(d.max(0) as u64);
        let at = tokio::time::Instant::now() + d;
        let mut w = self.0.wake.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((due, _)) = &*w
            && *due < at
            && *due > tokio::time::Instant::now()
        {
            return;
        }
        if let Some((_, h)) = w.take() {
            h.abort();
        }
        let s = self.clone();
        let h = tokio::spawn(async move {
            tokio::time::sleep(d).await;
            s.trigger();
        });
        *w = Some((at, h.abort_handle()));
    }

    /// lostNodes: the nodes disconnected for longer than the lost timeout,
    /// none when more are lost than ready.
    async fn lost_nodes(&self, rc: &mut Run<'_>, nodes: &[Node]) -> HashSet<String> {
        let timeout = nanos(self.0.node_lost_timeout);
        let mut lost = HashSet::new();
        let mut ready = 0;
        for n in nodes {
            if n.state == NODE_READY {
                ready += 1;
            } else if node_lost(n, &rc.now, timeout) {
                lost.insert(n.id.clone());
            } else if !n.last_seen.is_zero() {
                rc.away = true;
                rc.wake_at(&n.last_seen.add(timeout));
            }
        }
        let cut_off = lost.len() > ready;
        self.condition(
            "cut-off",
            cut_off,
            event(
                NODE,
                "*",
                "",
                "MostUnreachable",
                &format!(
                    "{} nodes lost and {ready} ready: not moving their replicas (is the control plane cut off?)",
                    lost.len()
                ),
            ),
        )
        .await;
        if cut_off {
            self.0.log.warn(
                "most nodes are unreachable; not rescheduling their replicas (is the control plane cut off?)",
                &[("lost", lost.len().to_string()), ("ready", ready.to_string())],
            );
            return HashSet::new();
        }
        let msg = format!(
            "no contact for {}; moving its replicas",
            format_duration(timeout)
        );
        for n in nodes {
            self.condition(
                &format!("lost:{}", n.id),
                lost.contains(&n.id),
                event(NODE, &n.id, &n.id, "Lost", &msg),
            )
            .await;
        }
        lost
    }

    async fn reconcile_app(&self, rc: &mut Run<'_>, app: &mut App, nodes: &[Node]) -> Result<()> {
        let target = rc.revs.get(&app.target_revision).await?;
        if target.spec().has_local_volumes() {
            return self.reconcile_volume_app(rc, app, &target, nodes).await;
        }
        if app.traffic.is_empty() || app.rolling() {
            return self.reconcile_revision(rc, app, nodes, None).await;
        }
        // Traffic splitting (ADR 0022): each revision in the traffic is
        // reconciled like an app of its own with its share of the
        // replicas, leaving the replicas of the others alone.
        let shares = traffic_shares(app.replicas, &app.traffic);
        let traffic = app.traffic.clone();
        for (i, t) in traffic.iter().enumerate() {
            let others: BTreeMap<String, bool> = traffic
                .iter()
                .map(|o| (o.revision.clone(), o.revision != t.revision))
                .collect();
            let mut sub = app.clone();
            sub.active_revision = t.revision.clone();
            sub.target_revision = t.revision.clone();
            sub.replicas = shares[i];
            sub.traffic = Vec::new();
            self.reconcile_revision(rc, &mut sub, nodes, Some(&others))
                .await?;
        }
        Ok(())
    }

    /// reconcileRevision: converges app's replicas toward its target
    /// revision, leaving those of the revisions in others alone.
    async fn reconcile_revision(
        &self,
        rc: &mut Run<'_>,
        app: &mut App,
        nodes: &[Node],
        others: Option<&BTreeMap<String, bool>>,
    ) -> Result<()> {
        let mine: Vec<Replica> = rc
            .view()
            .await
            .by_app
            .get(&app.name)
            .cloned()
            .unwrap_or_default();
        let mut pubs = HashMap::new();
        let names: Vec<String> = mine
            .iter()
            .map(|r| r.revision.clone())
            .chain(std::iter::once(app.target_revision.clone()))
            .collect();
        for n in names {
            if let std::collections::hash_map::Entry::Vacant(e) = pubs.entry(n) {
                // Unknown: require an address.
                let p = match rc.revs.get(e.key()).await {
                    Ok(rev) => publishes_port(rev.spec()),
                    Err(_) => true,
                };
                e.insert(p);
            }
        }
        let pubs = Publishes(pubs);
        let other = |rev: &str| others.is_some_and(|o| o.get(rev).copied().unwrap_or(false));

        let mut current = Vec::new();
        let mut old = Vec::new();
        for r in mine {
            if other(&r.revision) {
                continue;
            }
            if r.draining() {
                self.finish_drain(rc, &r, true).await?;
            } else if r.revision == app.target_revision {
                current.push(r);
            } else if app.rolling()
                && (r.revision == app.active_revision || traffic_weight(app, &r.revision) >= 0)
            {
                // Leaving multiple revision mode: every revision in the
                // traffic serves until the new one does.
                old.push(r);
            } else {
                // Leftovers of an aborted or superseded rollout.
                self.retire(rc, &r).await?;
            }
        }

        // Replicas on cordoned nodes, and on nodes the app's placement no
        // longer allows, are replaced elsewhere, then retired.
        let target = rc.revs.get(&app.target_revision).await?;
        let fit = eligible(nodes, &target);
        let cordoned: HashSet<String> = nodes
            .iter()
            .filter(|n| n.cordoned || (n.state == NODE_READY && !placement_allows(n, &target)))
            .map(|n| n.id.clone())
            .collect();
        let mut moving = Vec::new();
        let mut lost = Vec::new();
        current.retain(|r: &Replica| {
            if rc.lost.contains(&r.node_id) {
                lost.push(r.clone());
                false
            } else if cordoned.contains(&r.node_id) || r.moving() {
                moving.push(r.clone());
                false
            } else {
                true
            }
        });
        self.abort_stuck_moves(rc, app, &mut current, &mut moving, &cordoned, &pubs)
            .await?;

        if app.rolling() {
            let aborted = self
                .check_rollout(rc, app, &target, &current, &pubs)
                .await?;
            if aborted {
                // Aborted: everything of the target goes, the old replicas
                // stay and become current again.
                for r in &current {
                    self.retire(rc, r).await?;
                }
                return Ok(());
            }
        }

        let spread_key = Placement::spread_key(target.spec().placement.as_ref());
        if !app.rolling() {
            self.move_failed(rc, app, &target, &fit, &mut current)
                .await?;
        }

        // Scale down: drop unhealthy replicas first, then from the most
        // loaded node.
        while current.len() as i64 > app.replicas {
            let victim = pick_victim(&current, &spread_groups(&fit, &spread_key));
            self.retire(rc, &victim).await?;
            without(&mut current, &victim.id);
        }

        // Scale up, with one replica of surge while old replicas still run.
        let mut unplaced = false;
        while (current.len() as i64) < app.replicas
            && ((current.len() + old.len() + moving.len()) as i64) < app.replicas + MAX_SURGE
        {
            let res = rc.revs.reserved(&rc.all).await;
            let Some(node) = pick_node(
                &fit,
                &rc.all,
                &current,
                &spread_key,
                reservation(&target),
                &res,
            ) else {
                self.0.log.warn(
                    "no node can fit replica",
                    &[
                        ("app", app.name.clone()),
                        ("want", app.replicas.to_string()),
                        ("have", current.len().to_string()),
                    ],
                );
                unplaced = true;
                break;
            };
            let r = self.place_replica(app, &target, &node.id).await?;
            current.push(r.clone());
            rc.push(r);
        }
        let mut key = format!("unplaced:{}", app.name);
        if others.is_some() {
            key += &format!("/{}", target.name);
        }
        self.condition(
            &key,
            unplaced,
            app_event(
                APP,
                &app.name,
                &app.name,
                "Unschedulable",
                &format!(
                    "no node can fit another replica ({} of {} placed); see armada node top",
                    current.len(),
                    app.replicas
                ),
            ),
        )
        .await;
        let mut leaving = lost.clone();
        leaving.extend(moving.iter().cloned());
        self.evacuate(rc, app, &current, &old, leaving, &pubs)
            .await?;
        if !app.rolling() {
            if lost.is_empty() && moving.is_empty() {
                return self.rebalance(rc, app, &fit, &current, &pubs).await;
            }
            return Ok(());
        }

        // Retire old replicas while enough others serve. Unhealthy ones go
        // first: they serve nothing anyway. An old replica serves once it
        // is in the proxies (working), warmed up or not.
        let new_serving = current
            .iter()
            .filter(|r| self.serving(rc, r, pubs.of(r)))
            .count() as i64;
        let mut old_serving = old.iter().filter(|r| working(r, pubs.of(r))).count() as i64;
        old.sort_by(|a, b| {
            let (sa, sb) = (working(a, pubs.of(a)), working(b, pubs.of(b)));
            sa.cmp(&sb).then(a.id.cmp(&b.id))
        });
        let mut left = old.clone();
        for r in &old {
            let lose = i64::from(working(r, pubs.of(r)));
            // One that serves nothing goes at once, whatever the new
            // replicas do: it only holds capacity they may need.
            if lose == 1 && old_serving - lose + new_serving < app.replicas {
                break;
            }
            self.retire(rc, r).await?;
            without(&mut left, &r.id);
            old_serving -= lose;
        }

        if left.is_empty() && new_serving >= app.replicas && current.len() as i64 == app.replicas {
            self.complete(rc, app).await?;
        }
        Ok(())
    }

    /// Completes app's rollout: its target serves.
    pub(crate) async fn complete(&self, rc: &mut Run<'_>, app: &mut App) -> Result<()> {
        self.store()
            .complete_rollout(&app.name, &app.target_revision)
            .await?;
        self.0.log.info(
            "rollout complete",
            &[
                ("app", app.name.clone()),
                ("revision", app.target_revision.clone()),
            ],
        );
        self.record(app_event(
            ROLLOUT,
            &app.target_revision,
            &app.name,
            "Completed",
            &format!("{} serves", app.target_revision),
        ))
        .await;
        app.active_revision = app.target_revision.clone();
        app.rollout_state = ROLLOUT_NONE.to_string();
        if let Ok(r) = rc.revs.get(&app.target_revision).await {
            app.spec = r.spec;
        }
        self.forget_progress(&app.name);
        Ok(())
    }

    /// rebalance: starts moving one replica of a stable app whose replicas
    /// are spread unevenly (ADR 0013).
    async fn rebalance(
        &self,
        rc: &mut Run<'_>,
        app: &App,
        nodes: &[Node],
        current: &[Replica],
        pubs: &Publishes,
    ) -> Result<()> {
        if current.len() as i64 != app.replicas || !rc.lost.is_empty() {
            return Ok(());
        }
        for r in current {
            if !self.serving(rc, r, pubs.of(r)) {
                return Ok(());
            }
        }
        if rc.view().await.moving {
            return Ok(());
        }
        let after = self.memory().rebalance_after.get(&app.name).cloned();
        if after.is_some_and(|a| rc.now.before(&a)) {
            return Ok(());
        }
        let target = rc.revs.get(&app.target_revision).await?;
        let spread_key = Placement::spread_key(target.spec().placement.as_ref());
        let picked = {
            let view = rc.view().await;
            rebalance_victim(
                nodes,
                &view.use_,
                current,
                &spread_key,
                reservation(&target),
            )
        };
        let Some((mut victim, to)) = picked else {
            return Ok(());
        };
        self.store().set_replica_moving(&victim.id, true).await?;
        self.0.log.info(
            "moving replica to spread app",
            &[
                ("replica", victim.id.clone()),
                ("from", victim.node_id.clone()),
                ("to", to.clone()),
            ],
        );
        self.record(replica_event(
            &victim,
            "Rebalancing",
            &format!("moving from {} to {to}", victim.node_id),
        ))
        .await;
        victim.moving_since = rc.now.clone();
        rc.wake_at(&rc.now.clone());
        rc.replace(&victim);
        Ok(())
    }

    /// abortStuckMoves: gives up moves whose replacement has not served
    /// within the progress deadline.
    async fn abort_stuck_moves(
        &self,
        rc: &mut Run<'_>,
        app: &App,
        current: &mut Vec<Replica>,
        moving: &mut Vec<Replica>,
        cordoned: &HashSet<String>,
        pubs: &Publishes,
    ) -> Result<()> {
        let mut stuck = Vec::new();
        for r in moving.iter() {
            if !r.moving() || cordoned.contains(&r.node_id) {
                continue;
            }
            let rev = rc.revs.get(&r.revision).await?;
            let deadline = r
                .moving_since
                .add(nanos(self.0.progress_deadline) + probe_budget(rev.spec()));
            if rc.now.before(&deadline) {
                rc.wake_at(&deadline);
                continue;
            }
            stuck.push(r.clone());
        }
        if stuck.is_empty() {
            return Ok(());
        }
        for mut r in stuck {
            self.store().set_replica_moving(&r.id, false).await?;
            self.0.log.warn(
                "replacement of moving replica never served; keeping it",
                &[("replica", r.id.clone()), ("node", r.node_id.clone())],
            );
            r.moving_since = Time::zero();
            rc.replace(&r);
            without(moving, &r.id);
            current.push(r);
        }
        self.memory()
            .rebalance_after
            .insert(app.name.clone(), rc.now.add(REBALANCE_BACKOFF));
        // Back to the desired count by retiring what does not serve.
        for r in current.clone() {
            if current.len() as i64 <= app.replicas {
                break;
            }
            if self.serving(rc, &r, pubs.of(&r)) {
                continue;
            }
            self.retire(rc, &r).await?;
            without(current, &r.id);
        }
        Ok(())
    }

    /// evacuate: retires replicas on cordoned or lost nodes while enough
    /// other replicas serve, unhealthy ones first.
    async fn evacuate(
        &self,
        rc: &mut Run<'_>,
        app: &App,
        current: &[Replica],
        old: &[Replica],
        mut moving: Vec<Replica>,
        pubs: &Publishes,
    ) -> Result<()> {
        if moving.is_empty() {
            return Ok(());
        }
        let count = |rs: &[Replica]| {
            rs.iter()
                .filter(|r| self.serving(rc, r, pubs.of(r)))
                .count() as i64
        };
        let others = count(current) + count(old);
        let mut left = count(&moving);
        moving.sort_by(|a, b| {
            let (sa, sb) = (
                self.serving(rc, a, pubs.of(a)),
                self.serving(rc, b, pubs.of(b)),
            );
            sa.cmp(&sb).then(a.id.cmp(&b.id))
        });
        for r in &moving {
            let lose = i64::from(self.serving(rc, r, pubs.of(r)));
            // A replica that does no work goes at once; one that works
            // stays until enough others serve.
            if working(r, pubs.of(r)) && others + left - lose < app.replicas {
                continue;
            }
            let reason = if rc.lost.contains(&r.node_id) {
                "lost"
            } else if r.moving() {
                "moving"
            } else {
                "cordoned"
            };
            self.0.log.info(
                "evacuating replica",
                &[
                    ("replica", r.id.clone()),
                    ("node", r.node_id.clone()),
                    ("node_state", reason.to_string()),
                ],
            );
            self.record(replica_event(
                r,
                "Evacuating",
                &format!("node {} is {reason}", r.node_id),
            ))
            .await;
            self.retire(rc, r).await?;
            left -= lose;
        }
        Ok(())
    }

    /// checkRollout: records a rollout's progress and aborts it once no new
    /// replica became serving within the progress deadline.
    pub(crate) async fn check_rollout(
        &self,
        rc: &mut Run<'_>,
        app: &mut App,
        target: &Revision,
        current: &[Replica],
        pubs: &Publishes,
    ) -> Result<bool> {
        let serving = current
            .iter()
            .filter(|r| self.serving(rc, r, pubs.of(r)))
            .count();
        let prev = {
            let mut m = self.memory();
            let prev = m.progress.get(&app.name).cloned();
            match &prev {
                Some((rev, n)) if *rev == target.name && serving <= *n => {}
                _ => {
                    m.progress
                        .insert(app.name.clone(), (target.name.clone(), serving));
                }
            }
            prev
        };
        if let Some((rev, n)) = prev
            && rev == target.name
            && serving > n
        {
            self.store().mark_rollout_progress(&app.name).await?;
            app.rollout_progress_at = rc.now.clone();
        }
        let deadline = nanos(self.0.progress_deadline) + probe_budget(target.spec());
        let due = app.rollout_progress_at.add(deadline);
        if rc.now.before(&due) {
            rc.wake_at(&due);
            return Ok(false);
        }
        let mut msg = format!(
            "{} made no progress within {}",
            target.name,
            format_duration(deadline)
        );
        for r in current {
            if !r.message.is_empty() && !self.serving(rc, r, pubs.of(r)) {
                msg += &format!("; {}: {}", r.id, r.message);
                break;
            }
        }
        self.store()
            .fail_rollout(&app.name, &target.name, &msg)
            .await?;
        self.0.log.warn(
            "rollout failed, keeping the active revision",
            &[
                ("app", app.name.clone()),
                ("revision", target.name.clone()),
                ("active", app.active_revision.clone()),
                ("reason", msg.clone()),
            ],
        );
        self.record(app_event(
            ROLLOUT,
            &target.name,
            &app.name,
            "Failed",
            &format!("{msg}; {} stays active", app.active_revision),
        ))
        .await;
        app.target_revision = app.active_revision.clone();
        app.rollout_state = ROLLOUT_FAILED.to_string();
        app.rollout_message = msg;
        self.forget_progress(&app.name);
        Ok(true)
    }

    pub(crate) fn forget_progress(&self, app: &str) {
        self.memory().progress.remove(app);
    }

    /// retire: takes r out of service, draining it first when it may be
    /// receiving traffic.
    pub(crate) async fn retire(&self, rc: &mut Run<'_>, r: &Replica) -> Result<()> {
        if !r.ready || r.address.is_empty() || r.state != REPLICA_RUNNING {
            rc.without(&r.id);
            return self.delete_replica(r).await;
        }
        self.store().drain_replica(&r.id).await?;
        self.0.log.info(
            "draining replica",
            &[("replica", r.id.clone()), ("node", r.node_id.clone())],
        );
        let mut r = r.clone();
        r.draining_since = rc.now.clone();
        let d = self.drain_for(rc, &r).await;
        rc.wake_at(&rc.now.add(d));
        rc.replace(&r);
        Ok(())
    }

    /// finishDrain: removes a draining replica once its drain timeout
    /// passed, counted from this leader's start for drains a previous one
    /// began; with hold, it also waits up to awayHold while a node is away.
    pub(crate) async fn finish_drain(
        &self,
        rc: &mut Run<'_>,
        r: &Replica,
        hold: bool,
    ) -> Result<()> {
        let due = later(&r.draining_since, &self.0.term_start).add(self.drain_for(rc, r).await);
        if rc.now.before(&due) {
            rc.wake_at(&due);
            return Ok(());
        }
        let held = due.add(AWAY_HOLD);
        if hold && rc.away && rc.now.before(&held) {
            rc.wake_at(&held);
            return Ok(());
        }
        rc.without(&r.id);
        self.delete_replica(r).await
    }

    /// drainFor: how long r drains.
    async fn drain_for(&self, rc: &mut Run<'_>, r: &Replica) -> i64 {
        if let Ok(rev) = rc.revs.get(&r.revision).await
            && rev.spec().drain.0 != 0
        {
            return rev.spec().drain.0;
        }
        nanos(self.0.drain_timeout)
    }

    async fn delete_replica(&self, r: &Replica) -> Result<()> {
        self.0.log.info(
            "removing replica",
            &[("replica", r.id.clone()), ("node", r.node_id.clone())],
        );
        self.store().delete_replica(&r.id).await?;
        self.record(replica_event(r, "Removed", "")).await;
        Ok(())
    }

    /// placeReplica: records a new replica of target on node.
    async fn place_replica(&self, app: &App, target: &Revision, node: &str) -> Result<Replica> {
        let r = Replica {
            id: format!("{}-r{}-{}", app.name, target.seq, (self.0.new_id)(5)),
            app: app.name.clone(),
            revision: target.name.clone(),
            node_id: node.to_string(),
            state: REPLICA_PENDING.to_string(),
            ..Replica::default()
        };
        self.store().create_replica(&r).await?;
        self.0.log.info(
            "scheduled replica",
            &[
                ("replica", r.id.clone()),
                ("revision", r.revision.clone()),
                ("node", node.to_string()),
            ],
        );
        self.record(replica_event(
            &r,
            "Scheduled",
            &format!("revision {} on {node}", r.revision),
        ))
        .await;
        Ok(r)
    }

    /// moveFailed: replaces, on another node, a replica that has kept
    /// failing to start for failedMoveAfter; the first of an app moves at a
    /// time.
    async fn move_failed(
        &self,
        rc: &mut Run<'_>,
        app: &App,
        target: &Revision,
        fit: &[Node],
        current: &mut Vec<Replica>,
    ) -> Result<()> {
        let spread_key = Placement::spread_key(target.spec().placement.as_ref());
        let mut moved = false;
        for r in current.clone() {
            if r.state != REPLICA_FAILED {
                self.memory().failed_since.remove(&r.id);
                continue;
            }
            let since = self
                .memory()
                .failed_since
                .entry(r.id.clone())
                .or_insert_with(|| rc.now.clone())
                .clone();
            let due = since.add(FAILED_MOVE_AFTER);
            if rc.now.before(&due) {
                rc.wake_at(&due);
                continue;
            }
            if moved {
                rc.wake_at(&rc.now.add(SECOND));
                continue;
            }
            let others: Vec<Node> = fit.iter().filter(|n| n.id != r.node_id).cloned().collect();
            let res = rc.revs.reserved(&rc.all).await;
            let Some(to) = pick_node(
                &others,
                &rc.all,
                current,
                &spread_key,
                reservation(target),
                &res,
            ) else {
                continue;
            };
            let fresh = self.place_replica(app, target, &to.id).await?;
            self.0.log.warn(
                "replica keeps failing to start; trying another node",
                &[
                    ("replica", r.id.clone()),
                    ("node", r.node_id.clone()),
                    ("to", to.id.clone()),
                ],
            );
            self.delete_replica(&r).await?;
            self.memory().failed_since.remove(&r.id);
            without(current, &r.id);
            current.push(fresh.clone());
            rc.without(&r.id);
            rc.push(fresh);
            moved = true;
        }
        Ok(())
    }

    /// reconcileRemoval: drains the replicas of an app being removed and,
    /// when none is left, removes the app; true once it is gone.
    async fn reconcile_removal(&self, rc: &mut Run<'_>, app: &App) -> Result<bool> {
        for r in rc.all.clone() {
            if r.app != app.name {
                continue;
            }
            if r.draining() {
                self.finish_drain(rc, &r, true).await?;
            } else {
                self.retire(rc, &r).await?;
            }
        }
        if rc.all.iter().any(|r| r.app == app.name) {
            return Ok(false);
        }
        self.store().delete_app(&app.name).await?;
        self.end_app_conditions(&app.name).await;
        self.0.log.info("removed app", &[("app", app.name.clone())]);
        self.record(app_event(APP, &app.name, &app.name, "Removed", ""))
            .await;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shares() {
        let t = |w| TrafficTarget {
            revision: String::new(),
            weight: w,
            label: String::new(),
        };
        assert_eq!(traffic_shares(4, &[t(90), t(10)]), vec![4, 1]);
        assert_eq!(traffic_shares(3, &[t(50), t(50)]), vec![2, 2]);
        assert_eq!(traffic_shares(0, &[t(100)]), vec![1]);
    }

    #[test]
    fn subtracting() {
        let a = Time::zero().add(5 * SECOND);
        assert_eq!(sub(&a, &Time::zero()), 5 * SECOND);
    }
}

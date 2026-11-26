//! The move of containerd nodes to the supervisor runtime (Go's
//! runtimemove.go and runtimeagent.go; ADR 0054, "The runtime's move",
//! step 4): the leader drains one containerd node at a time like a cordon,
//! asks its agent to move once no replica is left, waits for the node to
//! report the supervisor, and lets it take replicas again. The record in
//! meta `runtime-move` keeps the move's node and step, so a new leader
//! carries on.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Weak};

use armada_proto::armada::v1::server_message::Msg;
use armada_proto::armada::v1::{
    MoveRuntime, RuntimeMovePlan, RuntimeMoveStatus, RuntimeMoveWait, RuntimeStatus, ServerMessage,
};
use armada_spec::go::format_duration;
use armada_spec::gotime::{Location, Time};
use armada_store::gojson::{from_ms, unix_milli};
use armada_store::{Kind, NODE_READY, Node, Replica};
use serde::{Deserialize, Serialize};
use tonic::Status;

use crate::agents::Session;
use crate::assign::Revisions;
use crate::events::{NODE, clean_message, event};
use crate::grpc::Auth;
use crate::jobs::round;
use crate::reconcile::{Run, nanos, node_lost, sub};
use crate::schedule::{eligible, pick_node_by, reservation, usage_of};
use crate::{Server, store_err};

/// metaRuntimeMove holds the move's setting and state.
pub(crate) const META_RUNTIME_MOVE: &str = "runtime-move";

const MOVE_DRAINING: &str = "draining";
const MOVE_MIGRATING: &str = "migrating";

const PLAN_QUEUED: &str = "queued";
const PLAN_MOVING: &str = "moving";
const PLAN_WAITING: &str = "waiting";
const PLAN_OFF: &str = "off";

const SECOND: i64 = 1_000_000_000;
/// The defaults of Config's runtime move limits (runtimeDrainLimit,
/// runtimeMigrateLimit, runtimeMoveBackoff).
pub(crate) const DEFAULT_DRAIN_LIMIT: std::time::Duration = std::time::Duration::from_secs(15 * 60);
pub(crate) const DEFAULT_MIGRATE_LIMIT: std::time::Duration =
    std::time::Duration::from_secs(10 * 60);
pub(crate) const DEFAULT_MOVE_BACKOFF: std::time::Duration = std::time::Duration::from_secs(3600);
/// runtimeMoveAsk: how often the leader asks the node again while it has
/// not moved.
const MOVE_ASK: i64 = 30 * SECOND;
/// runtimeMoveRecheck: how often the leader looks at a move again without
/// other news.
const MOVE_RECHECK: i64 = 10 * SECOND;
/// maxRuntimeMoveWaiting bounds the waiting nodes the status names.
const MAX_WAITING: usize = 20;
/// maxImagesToPull bounds a node's count of images to pull again.
const MAX_IMAGES_TO_PULL: i32 = 1 << 20;
/// Bounds the runc containers a node reports (ADR 0056).
const MAX_RUNC_CONTAINERS: i32 = 1 << 20;

/// The runtimes a node reports (runtime.AgentContainerd and the others).
pub(crate) const AGENT_CONTAINERD: &str = "containerd";
pub(crate) const AGENT_SUPERVISOR_GO: &str = "supervisor-go";
pub(crate) const AGENT_SUPERVISOR_RUST: &str = "supervisor-rust";

/// cleanRuntimeStatus: what a node says about how it runs containers,
/// bounded; a runtime the leader does not know is dropped.
pub(crate) fn clean_runtime_status(st: Option<&RuntimeStatus>) -> Option<RuntimeStatus> {
    let st = st?;
    match st.agent.as_str() {
        AGENT_CONTAINERD => {
            let mut out = RuntimeStatus {
                agent: st.agent.clone(),
                ..Default::default()
            };
            if !st.move_error.is_empty() {
                out.move_error = clean_message(&st.move_error);
            }
            Some(out)
        }
        AGENT_SUPERVISOR_GO => Some(RuntimeStatus {
            agent: st.agent.clone(),
            ..Default::default()
        }),
        AGENT_SUPERVISOR_RUST => {
            let mut out = RuntimeStatus {
                agent: st.agent.clone(),
                converting: st.converting,
                images_to_pull: st.images_to_pull.clamp(0, MAX_IMAGES_TO_PULL),
                runc_containers: st.runc_containers.clamp(0, MAX_RUNC_CONTAINERS),
                ..Default::default()
            };
            if !st.error.is_empty() {
                out.error = clean_message(&st.error);
                out.converting = true;
            }
            Some(out)
        }
        _ => None,
    }
}

/// The move's record (Go's runtimeMoveRec), as encoding/json writes it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct MoveRec {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub off: bool,
    #[serde(rename = "move", default, skip_serializing_if = "Option::is_none")]
    pub mv: Option<Move>,
    #[serde(
        rename = "givenUp",
        default,
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub given_up: BTreeMap<String, GivenUp>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct Move {
    pub node: String,
    pub step: String,
    /// Unix milliseconds.
    pub since: i64,
    #[serde(rename = "stepSince")]
    pub step_since: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct GivenUp {
    pub at: i64,
    pub reason: String,
}

/// What the move keeps in memory: when the leader last asked a node, on
/// which session, and the last pass's view for ClusterStatus.
#[derive(Default)]
pub(crate) struct MoveState {
    asked: Option<(Weak<Session>, Time)>,
    pub seen: Option<RuntimeMoveStatus>,
}

/// encoding/json's escaping of what serde_json leaves as it is.
fn go_json<T: Serialize>(v: &T) -> String {
    let s = serde_json::to_string(v).unwrap_or_default();
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out
}

/// moved: the node's runtime is the supervisor's.
fn moved(agent: &str) -> bool {
    agent == AGENT_SUPERVISOR_GO || agent == AGENT_SUPERVISOR_RUST
}

/// remaining: the replicas that keep node from moving, by ID: every one
/// placed there but finished job attempts.
fn remaining<'a>(replicas: &'a [Replica], node: &str) -> Vec<&'a Replica> {
    let mut out: Vec<&Replica> = replicas
        .iter()
        .filter(|r| r.node_id == node && !r.done)
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// cordonMoving: marks the node being moved cordoned in the pass's copy
/// of the nodes, never in its record.
pub(crate) fn cordon_moving(rec: &MoveRec, nodes: &mut [Node]) {
    let Some(m) = &rec.mv else { return };
    for n in nodes.iter_mut() {
        if n.id == m.node {
            n.cordoned = true;
        }
    }
}

/// The UTC RFC 3339 text of a time, to the second.
fn rfc3339_utc(t: &Time) -> String {
    Time {
        unix: t.unix,
        nsec: 0,
        loc: Location::utc(),
    }
    .rfc3339_nano()
}

/// planRuntimeMove's answer: the status, every containerd node's plan, and
/// the node to start moving now, if any.
struct Plan {
    status: RuntimeMoveStatus,
    plans: HashMap<String, RuntimeMovePlan>,
    start: String,
}

impl Server {
    pub(crate) async fn load_runtime_move(&self) -> Result<MoveRec, armada_store::Error> {
        let raw = match self.store().get_meta(META_RUNTIME_MOVE).await {
            Err(e) if e.kind == Kind::NotFound => return Ok(MoveRec::default()),
            Err(e) => return Err(e),
            Ok(v) => v,
        };
        if raw.is_empty() {
            return Ok(MoveRec::default());
        }
        serde_json::from_str(&raw)
            .map_err(|e| armada_store::Error::other(format!("runtime move: {e}")))
    }

    async fn save_runtime_move(&self, rec: &MoveRec) -> Result<(), armada_store::Error> {
        self.store()
            .set_meta(META_RUNTIME_MOVE, &go_json(rec))
            .await
    }

    /// setRuntimeMove turns the automatic move on or off (cluster update
    /// --runtime-move).
    pub(crate) async fn set_runtime_move(&self, a: &Auth, on: bool) -> Result<(), Status> {
        let _g = self.0.moves.lock().await;
        let mut rec = self.load_runtime_move().await.map_err(|e| store_err(&e))?;
        rec.off = !on;
        self.save_runtime_move(&rec)
            .await
            .map_err(|e| store_err(&e))?;
        let detail = if on { "on" } else { "off" };
        self.store()
            .record_audit(&a.actor(), "cluster.runtime_move", "cluster", detail)
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "automatic move of containerd nodes changed",
            &[("move", detail.to_string()), ("by", a.actor())],
        );
        Ok(())
    }

    /// advanceRuntimeMove takes the move one step further when its step is
    /// done, gives it up when a step takes too long, or starts the next
    /// one; it returns the plan of each containerd node for its assignment
    /// and the node to ask to move after the assignments went out. nodes
    /// are the pass's (allocatable, the moving node cordoned), replicas
    /// its latest.
    pub(crate) async fn advance_runtime_move(
        &self,
        rc: &mut Run<'_>,
        nodes: &[Node],
        replicas: &[Replica],
    ) -> Result<(HashMap<String, RuntimeMovePlan>, String), armada_store::Error> {
        let mut state = self.0.moves.lock().await;
        let mut rec = self.load_runtime_move().await?;
        let now = rc.now.clone();
        let mut changed = false;
        let mut by_id: HashMap<&str, &Node> = HashMap::new();
        let mut runtime_of: HashMap<String, String> = HashMap::new();
        let mut on_containerd = Vec::new();
        for n in nodes {
            by_id.insert(&n.id, n);
            let agent = self
                .0
                .usage
                .runtime_of(&n.id, &now)
                .map(|s| s.agent)
                .unwrap_or_default();
            if agent == AGENT_CONTAINERD {
                on_containerd.push(n.clone());
            }
            runtime_of.insert(n.id.clone(), agent);
        }
        // A node that moved, by the leader or by hand, or is gone, keeps
        // no given-up move.
        let before = rec.given_up.len();
        rec.given_up.retain(|id, _| {
            by_id.contains_key(id.as_str())
                && !moved(runtime_of.get(id).map(String::as_str).unwrap_or(""))
        });
        if rec.given_up.len() != before {
            changed = true;
        }

        let mut ended = false;
        if rec.mv.is_some() {
            if self
                .step_runtime_move(
                    &mut state,
                    &mut rec,
                    &by_id,
                    &runtime_of,
                    replicas,
                    rc,
                    &now,
                )
                .await
            {
                changed = true;
            }
            // The pass's nodes still have the moved node cordoned: the next
            // move starts in the next pass.
            ended = rec.mv.is_none();
        }

        let mut view = self
            .plan_runtime_move(rc, &rec, nodes, &on_containerd, replicas, &now)
            .await;
        if ended && !view.start.is_empty() {
            view.plans.insert(
                std::mem::take(&mut view.start),
                RuntimeMovePlan {
                    state: PLAN_QUEUED.to_string(),
                    reason: "one node moves at a time".to_string(),
                    operator: false,
                },
            );
            self.wake_after(100_000_000);
        }
        if !view.start.is_empty() {
            let n = view.start.clone();
            let left = remaining(replicas, &n).len();
            rec.given_up.remove(&n);
            rec.mv = Some(Move {
                node: n.clone(),
                step: MOVE_DRAINING.to_string(),
                since: unix_milli(&now),
                step_since: unix_milli(&now),
            });
            changed = true;
            self.0.log.info(
                "moving a node from containerd to the supervisor runtime",
                &[("node", n.clone()), ("replicas", left.to_string())],
            );
            self.record(event(
                NODE,
                &n,
                &n,
                "RuntimeMoveStarted",
                &format!(
                    "moving {n} from containerd to the supervisor runtime, one node at a time"
                ),
            ))
            .await;
            if left > 0 {
                self.record(event(
                    NODE,
                    &n,
                    &n,
                    "RuntimeMoveDraining",
                    &format!("{left} replicas of {n} start on other nodes first"),
                ))
                .await;
            }
            view.plans.insert(
                n,
                RuntimeMovePlan {
                    state: PLAN_MOVING.to_string(),
                    ..Default::default()
                },
            );
            self.wake_after(100_000_000);
        }
        if changed {
            self.save_runtime_move(&rec).await?;
        }
        // The node is asked only once the record says so, so a new leader
        // carries on, and after its assignment without the replicas went
        // out (the pass).
        let mut ask = String::new();
        if let Some(m) = &rec.mv
            && m.step == MOVE_MIGRATING
            && by_id
                .get(m.node.as_str())
                .is_some_and(|n| n.state == NODE_READY)
        {
            ask = m.node.clone();
        }
        let backoff = format_duration(nanos(self.0.runtime_move_backoff));
        for n in nodes {
            let g = rec.given_up.get(&n.id);
            let reason = g.map(|g| g.reason.as_str()).unwrap_or("");
            self.condition(
                &format!("runtime-move:{}", n.id),
                g.is_some(),
                event(
                    NODE,
                    &n.id,
                    &n.id,
                    "RuntimeMoveGivenUp",
                    &format!(
                        "gave up moving {} to the supervisor runtime: {reason}; it stays on containerd and is tried again after {backoff}",
                        n.id
                    ),
                ),
            )
            .await;
        }
        if rec.mv.is_some() || !on_containerd.is_empty() {
            self.wake_after(MOVE_RECHECK);
        }
        let mut st = Some(view.status);
        if let (Some(m), Some(st)) = (&rec.mv, st.as_mut()) {
            st.node = m.node.clone();
            st.step = m.step.clone();
            st.since_unix = m.since / 1000;
            st.step_since_unix = m.step_since / 1000;
            st.error = self
                .0
                .usage
                .runtime_of(&m.node, &now)
                .map(|s| s.move_error)
                .unwrap_or_default();
        }
        if rec.mv.is_none() && on_containerd.is_empty() {
            st = None;
        }
        state.seen = st;
        Ok((view.plans, ask))
    }

    /// stepRuntimeMove looks at the move under way: done once the node
    /// reports the supervisor, migrating once no replica is left, given up
    /// when a step takes too long or the node is gone. It reports whether
    /// rec changed.
    #[allow(clippy::too_many_arguments)]
    async fn step_runtime_move(
        &self,
        state: &mut MoveState,
        rec: &mut MoveRec,
        by_id: &HashMap<&str, &Node>,
        runtime_of: &HashMap<String, String>,
        replicas: &[Replica],
        rc: &mut Run<'_>,
        now: &Time,
    ) -> bool {
        let m = rec.mv.clone().expect("a move");
        let agent = runtime_of.get(&m.node).cloned().unwrap_or_default();
        if !by_id.contains_key(m.node.as_str()) {
            self.record(event(
                NODE,
                &m.node,
                &m.node,
                "RuntimeMoveGivenUp",
                &format!(
                    "gave up moving {} to the supervisor runtime: the node was removed",
                    m.node
                ),
            ))
            .await;
            rec.mv = None;
            return true;
        }
        if moved(&agent) {
            let took = format_duration(round(sub(now, &from_ms(m.since)), SECOND));
            self.0.log.info(
                "node moved to the supervisor runtime",
                &[("node", m.node.clone()), ("took", took.clone())],
            );
            self.record(event(
                NODE,
                &m.node,
                &m.node,
                "RuntimeMoveDone",
                &format!(
                    "{} runs containers on the supervisor runtime ({agent}, took {took}); it takes replicas again",
                    m.node
                ),
            ))
            .await;
            rec.given_up.remove(&m.node);
            rec.mv = None;
            state.asked = None;
            return true;
        }
        let step_for = sub(now, &from_ms(m.step_since));
        match m.step.as_str() {
            MOVE_DRAINING => {
                if rec.off {
                    self.0.log.info(
                        "the automatic runtime move was turned off; the node takes replicas again",
                        &[("node", m.node.clone())],
                    );
                    self.record(event(
                        NODE,
                        &m.node,
                        &m.node,
                        "RuntimeMoveGivenUp",
                        &format!(
                            "stopped moving {} to the supervisor runtime: the automatic move was turned off; it takes replicas again",
                            m.node
                        ),
                    ))
                    .await;
                    rec.mv = None;
                    return true;
                }
                let left = remaining(replicas, &m.node);
                let apps = volume_apps(&left, &mut rc.revs).await;
                if !apps.is_empty() {
                    self.give_up_move(
                        state,
                        rec,
                        now,
                        &format!(
                            "it holds volumes of {}, whose app runs only there: move it by hand",
                            apps.join(", ")
                        ),
                    );
                    return true;
                }
                if left.is_empty() {
                    if let Some(mv) = rec.mv.as_mut() {
                        mv.step = MOVE_MIGRATING.to_string();
                        mv.step_since = unix_milli(now);
                    }
                    self.0.log.info(
                        "node drained; asking it to move to the supervisor runtime",
                        &[("node", m.node.clone())],
                    );
                    self.record(event(
                        NODE,
                        &m.node,
                        &m.node,
                        "RuntimeMoveMigrating",
                        &format!(
                            "no replica left on {}; it removes its containers (its proxy too) and restarts its service on the supervisor runtime",
                            m.node
                        ),
                    ))
                    .await;
                    return true;
                }
                let drain = nanos(self.0.runtime_drain_limit);
                if step_for >= drain {
                    let mut apps: Vec<&str> = Vec::new();
                    for r in &left {
                        if !apps.contains(&r.app.as_str()) {
                            apps.push(&r.app);
                        }
                    }
                    apps.truncate(5);
                    let why = format!(
                        "{} replicas did not leave it within {} ({})",
                        left.len(),
                        format_duration(drain),
                        apps.join(", ")
                    );
                    self.give_up_move(state, rec, now, &why);
                    return true;
                }
            }
            MOVE_MIGRATING => {
                let migrate = nanos(self.0.runtime_migrate_limit);
                if step_for >= migrate {
                    let mut why = self
                        .0
                        .usage
                        .runtime_of(&m.node, now)
                        .map(|s| s.move_error)
                        .unwrap_or_default();
                    if why.is_empty() {
                        why = format!(
                            "it did not report the supervisor runtime within {} of being asked (see its service's log)",
                            format_duration(migrate)
                        );
                    }
                    self.give_up_move(state, rec, now, &why);
                    return true;
                }
            }
            other => {
                let why = format!("unknown step {}", armada_spec::go::quote(other));
                self.give_up_move(state, rec, now, &why);
                return true;
            }
        }
        false
    }

    /// giveUpMove ends the move under way: the node takes replicas again,
    /// stays on containerd, and is tried again after the backoff.
    fn give_up_move(&self, state: &mut MoveState, rec: &mut MoveRec, now: &Time, why: &str) {
        let Some(m) = rec.mv.take() else { return };
        // Bounded like an event's message.
        let why = clean_message(why);
        self.0.log.warn(
            "gave up moving a node to the supervisor runtime",
            &[
                ("node", m.node.clone()),
                ("step", m.step.clone()),
                ("reason", why.clone()),
            ],
        );
        rec.given_up.insert(
            m.node,
            GivenUp {
                at: unix_milli(now),
                reason: why,
            },
        );
        state.asked = None;
    }

    /// askToMove sends the node's agent MoveRuntime, again every 30
    /// seconds and on every new session, until it moves.
    pub(crate) async fn ask_to_move(&self, node: &str, now: &Time) {
        let mut state = self.0.moves.lock().await;
        let Some(sess) = self.session(node) else {
            return;
        };
        if !sess.caps.runtime_move {
            return;
        }
        if let Some((s, at)) = &state.asked
            && s.upgrade().is_some_and(|s| Arc::ptr_eq(&s, &sess))
            && sub(now, at) < MOVE_ASK
        {
            return;
        }
        let m = ServerMessage {
            msg: Some(Msg::MoveRuntime(MoveRuntime {
                to: "supervisor".to_string(),
            })),
        };
        // With the session's queue full the next pass asks again.
        if sess.try_offer(m) {
            state.asked = Some((Arc::downgrade(&sess), now.clone()));
        }
    }

    /// planRuntimeMove works out which containerd node moves next and why
    /// the others wait.
    async fn plan_runtime_move(
        &self,
        rc: &mut Run<'_>,
        rec: &MoveRec,
        nodes: &[Node],
        on_containerd: &[Node],
        replicas: &[Replica],
        now: &Time,
    ) -> Plan {
        let mut out = Plan {
            status: RuntimeMoveStatus {
                off: rec.off,
                ..Default::default()
            },
            plans: HashMap::new(),
            start: String::new(),
        };
        if let Some(m) = &rec.mv {
            out.plans.insert(
                m.node.clone(),
                RuntimeMovePlan {
                    state: PLAN_MOVING.to_string(),
                    ..Default::default()
                },
            );
        }
        let mut held = String::new();
        if rec.off {
            held = "the automatic move is turned off (armada cluster update --runtime-move=true turns it on)".to_string();
        } else if rec.mv.is_some() {
        } else if !rc.lost.is_empty() || rc.away {
            held = "a node is not connected".to_string();
        } else if let Ok(n) = self.store().get_network().await
            && n.switch.is_some()
        {
            held = "the cluster network is switching its mode".to_string();
        }
        if rec.mv.is_none() && !on_containerd.is_empty() {
            out.status.held = held.clone();
        }
        let order = self.move_order(on_containerd).await;
        let mut waiting = Vec::new();
        for n in &order {
            if rec.mv.as_ref().is_some_and(|m| m.node == n.id) {
                continue;
            }
            let (reason, operator) = self.move_wait(rec, n, nodes, replicas, rc, now).await;
            if rec.off {
                let mut p = RuntimeMovePlan {
                    state: PLAN_OFF.to_string(),
                    ..Default::default()
                };
                if !reason.is_empty() {
                    p.reason = reason.clone();
                    p.operator = operator;
                }
                out.plans.insert(n.id.clone(), p);
            } else if !reason.is_empty() {
                out.plans.insert(
                    n.id.clone(),
                    RuntimeMovePlan {
                        state: PLAN_WAITING.to_string(),
                        reason: reason.clone(),
                        operator,
                    },
                );
            } else if held.is_empty() && rec.mv.is_none() && out.start.is_empty() {
                out.start = n.id.clone();
                continue;
            } else {
                let why = if held.is_empty() {
                    "one node moves at a time".to_string()
                } else {
                    held.clone()
                };
                out.plans.insert(
                    n.id.clone(),
                    RuntimeMovePlan {
                        state: PLAN_QUEUED.to_string(),
                        reason: why,
                        operator: false,
                    },
                );
            }
            if !reason.is_empty() {
                waiting.push(RuntimeMoveWait {
                    node: n.id.clone(),
                    reason,
                    operator,
                });
            }
        }
        waiting.sort_by(|a, b| a.node.cmp(&b.node));
        out.status.waiting_total = waiting.len() as i32;
        waiting.truncate(MAX_WAITING);
        out.status.waiting = waiting;
        out
    }

    /// moveOrder: machines that run no control plane first, then servers,
    /// the leader's own last; by name within each.
    async fn move_order(&self, nodes: &[Node]) -> Vec<Node> {
        let mut rank: HashMap<String, i32> = HashMap::new();
        if let Ok(servers) = self.store().list_servers().await {
            for sv in servers {
                let r = if sv.name == self.0.name { 2 } else { 1 };
                rank.insert(sv.private_ip, r);
            }
        }
        let mut out = nodes.to_vec();
        out.sort_by(|a, b| {
            let ra = rank.get(&a.private_ip).copied().unwrap_or(0);
            let rb = rank.get(&b.private_ip).copied().unwrap_or(0);
            ra.cmp(&rb).then(a.id.cmp(&b.id))
        });
        out
    }

    /// moveWait says why node is not moved now, "" when it can be, and
    /// whether it waits for its operator.
    async fn move_wait(
        &self,
        rec: &MoveRec,
        node: &Node,
        nodes: &[Node],
        replicas: &[Replica],
        rc: &mut Run<'_>,
        now: &Time,
    ) -> (String, bool) {
        let Some(sess) = self.session(&node.id) else {
            return ("not connected".to_string(), false);
        };
        if !sess.caps.runtime_move {
            return (
                "its agent cannot move itself: upgrade it (sudo armadad upgrade), or move it by hand"
                    .to_string(),
                true,
            );
        }
        let left = remaining(replicas, &node.id);
        let apps = volume_apps(&left, &mut rc.revs).await;
        if !apps.is_empty() {
            return (
                format!(
                    "holds volumes of {}, whose app runs only there and would stop: move it by hand (armadad runtime migrate)",
                    apps.join(", ")
                ),
                true,
            );
        }
        if rec.mv.is_some() {
            // Room and the other nodes change with the move under way:
            // this node is looked at again once it ends.
            return (String::new(), false);
        }
        let timeout = nanos(self.0.node_lost_timeout);
        let others = nodes
            .iter()
            .filter(|n| {
                n.id != node.id
                    && n.state == NODE_READY
                    && !n.cordoned
                    && !node_lost(n, now, timeout)
            })
            .count();
        if others == 0 {
            return ("no other node takes its replicas (a cluster of one node waits for its operator): move it by hand (armadad runtime migrate)".to_string(), true);
        }
        if let Some(g) = rec.given_up.get(&node.id) {
            let again = from_ms(g.at).add(nanos(self.0.runtime_move_backoff));
            if now.before(&again) {
                return (
                    format!(
                        "the last move was given up ({}); tried again at {}",
                        g.reason,
                        rfc3339_utc(&again)
                    ),
                    false,
                );
            }
        }
        if node.state != NODE_READY {
            return ("not ready".to_string(), false);
        }
        if let Err(app) = room_for(&node.id, nodes, replicas, &left, &mut rc.revs).await {
            return (
                format!("the other nodes have no room for a replica of {app}"),
                false,
            );
        }
        (String::new(), false)
    }
}

/// roomFor: whether the other nodes can take every replica on node that
/// would be replaced (job attempts aside), placing them one by one as the
/// scheduler would; the error names the first app that does not fit.
async fn room_for(
    node: &str,
    nodes: &[Node],
    all: &[Replica],
    left: &[&Replica],
    revs: &mut Revisions<'_>,
) -> Result<(), String> {
    let others: Vec<Node> = nodes.iter().filter(|n| n.id != node).cloned().collect();
    let rest: Vec<Replica> = all.iter().filter(|r| r.node_id != node).cloned().collect();
    let res = revs.reserved(&rest).await;
    let mut use_ = usage_of(&rest, &res);
    for r in left {
        if r.run != 0 {
            continue;
        }
        let Ok(rev) = revs.get(&r.revision).await else {
            return Err(r.app.clone());
        };
        let want = reservation(&rev);
        let Some(to) = pick_node_by(&eligible(&others, &rev), &use_, &[], "", want) else {
            return Err(r.app.clone());
        };
        let u = use_.entry(to.id.clone()).or_default();
        u.total += 1;
        u.holding += 1;
        u.reserved.cpu += want.cpu;
        u.reserved.mem += want.mem;
    }
    Ok(())
}

/// volumeApps: the apps (at most 5) of replicas whose revision has local
/// volumes (ADR 0023).
async fn volume_apps(replicas: &[&Replica], revs: &mut Revisions<'_>) -> Vec<String> {
    let mut apps: Vec<String> = Vec::new();
    for r in replicas {
        if let Ok(rev) = revs.get(&r.revision).await
            && rev.spec().has_local_volumes()
            && !apps.contains(&r.app)
        {
            apps.push(r.app.clone());
        }
    }
    apps.truncate(5);
    apps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_as_go_writes_it() {
        let mut rec = MoveRec::default();
        assert_eq!(go_json(&rec), "{}");
        rec.off = true;
        rec.mv = Some(Move {
            node: "n1".into(),
            step: MOVE_DRAINING.into(),
            since: 1,
            step_since: 2,
        });
        rec.given_up.insert(
            "n2".into(),
            GivenUp {
                at: 3,
                reason: "a<b".into(),
            },
        );
        assert_eq!(
            go_json(&rec),
            r#"{"off":true,"move":{"node":"n1","step":"draining","since":1,"stepSince":2},"givenUp":{"n2":{"at":3,"reason":"a\u003cb"}}}"#
        );
    }

    #[test]
    fn clean_runtime_status_bounds() {
        assert!(
            clean_runtime_status(Some(&RuntimeStatus {
                agent: "docker".into(),
                ..Default::default()
            }))
            .is_none()
        );
        let st = clean_runtime_status(Some(&RuntimeStatus {
            agent: AGENT_SUPERVISOR_RUST.into(),
            move_error: "x".into(),
            images_to_pull: -3,
            error: "bad".into(),
            ..Default::default()
        }))
        .unwrap();
        assert!(st.move_error.is_empty() && st.converting && st.images_to_pull == 0);
        // Containers left on runc (ADR 0056), bounded.
        for (n, want) in [(-1, 0), (7, 7), (i32::MAX, 1 << 20)] {
            let st = clean_runtime_status(Some(&RuntimeStatus {
                agent: AGENT_SUPERVISOR_RUST.into(),
                runc_containers: n,
                ..Default::default()
            }))
            .unwrap();
            assert_eq!(st.runc_containers, want);
        }
    }
}

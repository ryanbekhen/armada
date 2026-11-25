//! Event history (ADR 0018; Go's events.go): the leader records what it
//! sees happen, folding repeats, and streams it to `armada cluster events`.
//! Alerts (ADR 0045) and the event counter of the metrics endpoint come
//! with watching (pull request 15 of ADR 0055).

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::Ordering;
use std::time::Duration;

use armada_proto::armada::v1::{EventInfo, EventsRequest};
use armada_proto::google::protobuf::Timestamp;
use armada_spec::gotime::Time;
use armada_spec::validate::{DEFAULT_SPACE, split_app_id};
use armada_store::{EVENT_TTL_SECONDS, Event, Replica, ReplicaStatus};
use tokio::sync::mpsc;
use tonic::{Code, Request, Response, Status};

use crate::admin::Out;
use crate::grpc::auth;
use crate::guard::Guard;
use crate::{Server, store_err};

/// eventDedup: an event that happens again for the same object within
/// this window is folded into the stored one.
const DEDUP_NANOS: i64 = 10 * 60 * 1_000_000_000;
const KEEP: i64 = 2000;
const PER_OBJECT: i64 = 20;
const MAX_KEEP: i64 = 50_000;
const TRIM_EVERY: u64 = 100;
const MAX_MESSAGE: usize = 512;
const WRITE: Duration = Duration::from_secs(5);
const DEFAULT_SINCE_SECONDS: i64 = 3600;
const SUB_BUFFER: usize = 1024;

/// A check a guarded stream runs again on every recheck.
type Check = Box<dyn Fn(&crate::access::Access) -> Result<(), Status> + Send + Sync>;

pub const REPLICA: &str = "replica";
pub const NODE: &str = "node";

#[derive(Default)]
struct State {
    recent: HashMap<(String, String, String), (String, Event)>,
    /// Conditions reported once until they clear.
    active: HashMap<String, Event>,
    subs: Vec<mpsc::Sender<Event>>,
    writes: u64,
}

/// Writes events, folds repeats, and feeds followers.
#[derive(Default)]
pub struct Recorder {
    st: tokio::sync::Mutex<State>,
}

/// Go's Time.Sub in nanoseconds.
fn sub(a: &Time, b: &Time) -> i64 {
    (a.unix - b.unix)
        .saturating_mul(1_000_000_000)
        .saturating_add(a.nsec - b.nsec)
}

/// An event's common fields.
pub fn event(kind: &str, object: &str, node: &str, reason: &str, message: &str) -> Event {
    Event {
        key: String::new(),
        kind: kind.to_string(),
        object: object.to_string(),
        app: String::new(),
        node: node.to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        count: 0,
        first: Time::zero(),
        last: Time::zero(),
    }
}

/// cleanMessage: bounded, with control characters replaced, so text from
/// an agent cannot forge lines or terminal sequences.
pub fn clean_message(m: &str) -> String {
    let mut m = m;
    if m.len() > MAX_MESSAGE {
        let mut end = MAX_MESSAGE;
        while !m.is_char_boundary(end) {
            end -= 1;
        }
        m = &m[..end];
    }
    m.chars()
        .map(|c| {
            if armada_spec::go::is_control(c) || c == char::REPLACEMENT_CHARACTER {
                ' '
            } else {
                c
            }
        })
        .collect()
}

impl Server {
    /// Stores e (Go's record). A failure is logged: events never hold up
    /// the work they describe.
    pub(crate) async fn record(&self, mut e: Event) {
        e.message = clean_message(&e.message);
        let now = self.now();
        let k = (e.kind.clone(), e.object.clone(), e.reason.clone());
        // The lock is held across the write, as Go's is, so repeats fold
        // in the order they happen.
        let mut s = self.0.events.st.lock().await;
        let mut replace = String::new();
        match s.recent.get(&k) {
            Some((key, p)) if sub(&now, &p.last) < DEDUP_NANOS => {
                e.count = p.count + 1;
                e.first = p.first.clone();
                replace = key.clone();
            }
            _ => {
                e.count = 1;
                e.first = now.clone();
            }
        }
        e.last = now.clone();
        let put = tokio::time::timeout(WRITE, self.store().put_event(&e, &replace)).await;
        let key = match put {
            Ok(Ok(k)) => k,
            res => {
                let err = match res {
                    Ok(Err(err)) => err.to_string(),
                    _ => "context deadline exceeded".to_string(),
                };
                drop(s);
                self.0.log.warn(
                    "record event",
                    &[
                        ("kind", e.kind.clone()),
                        ("reason", e.reason.clone()),
                        ("err", err),
                    ],
                );
                return;
            }
        };
        e.key = key.clone();
        s.recent.insert(k, (key, e.clone()));
        s.writes += 1;
        let trim = s.writes % TRIM_EVERY == 0;
        if trim {
            s.recent.retain(|_, v| sub(&now, &v.1.last) < DEDUP_NANOS);
        }
        // A follower that cannot keep up is dropped rather than slowing the
        // reconciler.
        s.subs.retain(|ch| ch.try_send(e.clone()).is_ok());
        drop(s);
        if trim && let Err(err) = self.store().trim_events(self.event_keep()).await {
            self.0.log.warn("trim events", &[("err", err.to_string())]);
        }
    }

    /// Records e when the condition named key starts, and nothing while it
    /// lasts; on false ends it.
    pub(crate) async fn condition(&self, key: &str, on: bool, e: Event) {
        let start = {
            let mut s = self.0.events.st.lock().await;
            let was = s.active.contains_key(key);
            if on && !was {
                s.active.insert(key.to_string(), e.clone());
            } else if !on {
                s.active.remove(key);
            }
            on && !was
        };
        if start {
            self.record(e).await;
        }
    }

    /// Ends every condition an app or job started, once it is deleted
    /// (Go's endAppConditions).
    pub(crate) async fn end_app_conditions(&self, app: &str) {
        let ended: Vec<(String, Event)> = {
            let s = self.0.events.st.lock().await;
            s.active
                .iter()
                .filter(|(_, e)| e.app == app)
                .map(|(k, e)| (k.clone(), e.clone()))
                .collect()
        };
        for (key, e) in ended {
            self.condition(&key, false, e).await;
        }
    }

    fn event_keep(&self) -> i64 {
        (PER_OBJECT * self.0.cluster_size.load(Ordering::Relaxed)).clamp(KEEP, MAX_KEEP)
    }

    /// Records what an agent's report changed about a replica.
    pub(crate) async fn replica_event(&self, prev: &Replica, next: &ReplicaStatus) {
        let mut e = event(REPLICA, &prev.id, &prev.node_id, "", &next.message);
        e.app = prev.app.clone();
        let running = next.state == armada_store::REPLICA_RUNNING;
        e.reason = if !prev.container_id.is_empty()
            && !next.container_id.is_empty()
            && next.container_id != prev.container_id
        {
            "Restarted".to_string()
        } else if next.state != prev.state
            && (next.state == armada_store::REPLICA_EXITED
                || next.state == armada_store::REPLICA_FAILED)
        {
            if next.state == armada_store::REPLICA_FAILED {
                "Failed".to_string()
            } else {
                "Crashed".to_string()
            }
        } else if running && prev.state != armada_store::REPLICA_RUNNING {
            "Started".to_string()
        } else if running && next.ready && !prev.ready {
            e.message = String::new();
            "Ready".to_string()
        } else if running && !next.ready && prev.ready {
            "NotReady".to_string()
        } else {
            return;
        };
        self.record(e).await;
    }

    /// When each space other than default was created.
    async fn spaces_created(&self) -> Result<BTreeMap<String, Time>, Status> {
        let sps = self
            .store()
            .list_spaces()
            .await
            .map_err(|e| store_err(&e))?;
        Ok(sps
            .into_iter()
            .filter(|sp| sp.name != DEFAULT_SPACE && !sp.created_at.is_zero())
            .map(|sp| (sp.name, sp.created_at))
            .collect())
    }

    /// Streams events, newest last (ADR 0018).
    pub(crate) async fn events(
        &self,
        request: Request<EventsRequest>,
    ) -> Result<Response<Out<EventInfo>>, Status> {
        let a = auth(&request)?;
        let req = request.into_inner();
        let mut since = DEFAULT_SINCE_SECONDS;
        if req.since_seconds != 0 {
            since = req.since_seconds;
        }
        if since <= 0 || since > EVENT_TTL_SECONDS {
            return Err(Status::new(
                Code::InvalidArgument,
                format!(
                    "since must be between 1s and {}",
                    armada_spec::go::format_duration(EVENT_TTL_SECONDS * 1_000_000_000)
                ),
            ));
        }
        // A follow keeps to what the caller may see now: its access is
        // checked again while the stream is open.
        let guard = a.acc.p.is_some().then(|| {
            Guard::start(
                self,
                a.acc.clone(),
                a.cert.clone(),
                "/armada.v1.AdminService/Events",
            )
        });
        let require = |check: Check| -> Result<(), Status> {
            match &guard {
                Some(g) => g.require(check),
                None => check(&a.acc),
            }
        };
        let fail = |e: Status| {
            if let Some(g) = &guard {
                g.stop();
            }
            e
        };
        if !req.app.is_empty() {
            let app = req.app.clone();
            require(Box::new(move |acc| acc.app(&app))).map_err(fail)?;
        }
        if !req.node.is_empty() {
            require(Box::new(|acc| {
                if acc.admin() {
                    Ok(())
                } else {
                    Err(Status::new(
                        Code::PermissionDenied,
                        "listing a node's events needs cluster-admin",
                    ))
                }
            }))
            .map_err(fail)?;
        }
        let created = if !a.acc.admin() || req.follow {
            self.spaces_created().await.map_err(fail)?
        } else {
            BTreeMap::new()
        };
        let current = {
            let guard = guard.clone();
            let acc = a.acc.clone();
            move || {
                guard
                    .as_ref()
                    .map(|g| g.current())
                    .unwrap_or_else(|| acc.clone())
            }
        };
        let matches = {
            let (app, node) = (req.app.clone(), req.node.clone());
            move |e: &Event, acc: &crate::access::Access| {
                (app.is_empty() || e.app == app)
                    && (node.is_empty() || e.node == node)
                    && (acc.admin()
                        || (!e.app.is_empty()
                            && acc.sees(&e.app)
                            && !before_space(&created, &e.app, &e.last)))
            }
        };
        let sub = if req.follow {
            let (tx, rx) = mpsc::channel(SUB_BUFFER);
            self.0.events.st.lock().await.subs.push(tx);
            Some(rx)
        } else {
            None
        };
        let from = self.now().add(-since * 1_000_000_000);
        let evs = self
            .store()
            .list_events(&from)
            .await
            .map_err(|e| fail(store_err(&e)))?;
        let (out, rx) = mpsc::channel::<Result<EventInfo, Status>>(16);
        tokio::spawn(async move {
            let mut sent = std::collections::HashSet::new();
            let acc = current();
            for e in evs {
                if !matches(&e, &acc) {
                    continue;
                }
                sent.insert(e.key.clone());
                if out.send(Ok(event_info(&e))).await.is_err() {
                    if let Some(g) = &guard {
                        g.stop();
                    }
                    return;
                }
            }
            let Some(mut sub) = sub else {
                if let Some(g) = &guard {
                    g.stop();
                }
                return;
            };
            loop {
                let cancelled = async {
                    match &guard {
                        Some(g) => g.cancelled().await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    e = sub.recv() => {
                        let Some(e) = e else {
                            let _ = out.send(Err(Status::new(Code::ResourceExhausted, "fell behind the event stream; run the command again"))).await;
                            break;
                        };
                        if !matches(&e, &current()) || sent.contains(&e.key) {
                            continue;
                        }
                        if out.send(Ok(event_info(&e))).await.is_err() {
                            break;
                        }
                    }
                    _ = cancelled => {
                        if let Some(err) = guard.as_ref().and_then(|g| g.ended()) {
                            let _ = out.send(Err(err)).await;
                        }
                        break;
                    }
                    _ = out.closed() => break,
                }
            }
            if let Some(g) = &guard {
                g.stop();
            }
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
}

/// Whether t, a time in app's history, is from before its space was
/// created.
fn before_space(created: &BTreeMap<String, Time>, app: &str, t: &Time) -> bool {
    let Some((space, _)) = split_app_id(app) else {
        return false;
    };
    created.get(&space).is_some_and(|c| t.before(c))
}

pub(crate) fn timestamp(t: &Time) -> Timestamp {
    Timestamp {
        seconds: t.unix,
        nanos: t.nsec as i32,
    }
}

fn event_info(e: &Event) -> EventInfo {
    EventInfo {
        kind: e.kind.clone(),
        object: e.object.clone(),
        app: e.app.clone(),
        node: e.node.clone(),
        reason: e.reason.clone(),
        message: e.message.clone(),
        count: e.count.min(i64::from(i32::MAX)) as i32,
        first: Some(timestamp(&e.first)),
        last: Some(timestamp(&e.last)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean() {
        assert_eq!(clean_message("a\nb\x1b[0m"), "a b [0m");
        let long = "é".repeat(400);
        assert!(clean_message(&long).len() <= MAX_MESSAGE);
    }
}

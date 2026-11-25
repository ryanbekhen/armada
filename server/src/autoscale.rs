//! The autoscaler (Go's autoscale.go, ADR 0020, 0021, 0034): every 15
//! seconds the leader evaluates each autoscaled app from the usage store
//! (requests in progress at the proxies, CPU and memory of a replica's
//! reservation sampled on its own node, queue lengths read from its
//! replicas) and its schedule windows, and changes its replica count
//! through the store (`autoscale_replicas`); a quiet app that scales to
//! zero goes to zero, and a request waiting at a node's proxy wakes it
//! (`wake_app`). What it remembers between evaluations (when it started
//! watching an app, the recent recommendations, the last status, the last
//! request) is memory only: a new leader starts over and waits a full
//! window before scaling anything down.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use armada_proto::armada::v1::{Autoscale, AutoscaleRule};
use armada_spec::go::format_duration;
use armada_spec::gotime::Time;
use armada_spec::validate::valid_app_id;
use armada_spec::{App as Spec, SCALE_CPU, SCALE_HTTP, SCALE_MEMORY, SCALE_SCHEDULE};
use armada_store::{App, Kind, REPLICA_RUNNING, Replica};
use tokio::sync::watch;

use crate::Server;
use crate::assign::Revisions;
use crate::events::{event, timestamp};
use crate::reconcile::{APP, app_event, sub, traffic_weight};
use crate::schedule::{Res, reservation};
use crate::usage::Usage;

type Result<T> = std::result::Result<T, armada_store::Error>;

const SECOND: i64 = 1_000_000_000;
/// defaultAutoscaleInterval: how often the leader evaluates autoscaled
/// apps.
pub(crate) const DEFAULT_AUTOSCALE_INTERVAL: Duration = Duration::from_secs(15);
/// scaleDownWindow: how long the highest recommendation holds before an
/// app scales down, so it does not flap.
const SCALE_DOWN_WINDOW: i64 = 5 * 60 * SECOND;
/// scaleTolerance ignores changes smaller than 10% of the target.
const SCALE_TOLERANCE: f64 = 0.1;
pub(crate) const AUTOSCALE_ACTOR: &str = "armada:autoscaler";
/// The wake limit per node: 20 at once, one more a second.
pub(crate) const WAKE_BURST: u32 = 20;
pub(crate) const WAKE_REFILL: Duration = Duration::from_secs(1);

/// What the leader remembers of one app between evaluations (Go's
/// appScaling).
#[derive(Clone, Debug)]
pub(crate) struct AppScaling {
    /// The first evaluation in this term.
    since: Time,
    recs: Vec<(Time, i64)>,
    status: Option<Autoscale>,
    /// When the app last had a request or was woken.
    last_active: Time,
}

impl AppScaling {
    fn new(now: &Time) -> AppScaling {
        AppScaling {
            since: now.clone(),
            recs: Vec::new(),
            status: None,
            last_active: Time::zero(),
        }
    }
}

/// The autoscaler's memory (Go's autoscaler).
#[derive(Default)]
pub(crate) struct Autoscaler {
    apps: Mutex<HashMap<String, AppScaling>>,
}

impl Autoscaler {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, AppScaling>> {
        self.apps.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// touch records activity of app at now.
    fn touch(&self, app: &str, now: &Time) {
        let mut m = self.lock();
        let st = m
            .entry(app.to_string())
            .or_insert_with(|| AppScaling::new(now));
        if now.after(&st.last_active) {
            st.last_active = now.clone();
        }
    }

    /// note replaces the message of app's last evaluation until the next
    /// one, for a change made outside an evaluation (a wake).
    fn note(&self, app: &str, msg: &str) {
        if let Some(s) = self.lock().get_mut(app).and_then(|st| st.status.as_mut()) {
            s.message = msg.to_string();
        }
    }

    /// status: the last evaluation of app.
    pub(crate) fn status(&self, app: &str) -> Option<Autoscale> {
        self.lock().get(app).and_then(|st| st.status.clone())
    }
}

/// The samples one evaluation reads (Go's scaleInputs).
pub(crate) struct Inputs<'a> {
    pub now: Time,
    pub usage: &'a Usage,
    pub load: HashMap<String, i64>,
    pub load_measured: bool,
}

/// scheduleWake: the most replicas an open schedule window asks for and
/// when that window closes; 0 while none is open.
fn schedule_wake(sp: &Spec, now: &Time) -> (i64, Time) {
    let mut n = 0;
    let mut until = Time::zero();
    let Some(scale) = &sp.scale else {
        return (0, until);
    };
    for r in &scale.rules {
        if r.typ != SCALE_SCHEDULE {
            continue;
        }
        let (open, end) = r.window(now);
        if open && r.replicas > n {
            n = r.replicas;
            until = end;
        }
    }
    (n, until)
}

/// scheduleOpen: one of the app's schedule rules has its window open.
fn schedule_open(sp: &Spec, now: &Time) -> bool {
    sp.scale
        .as_ref()
        .is_some_and(|s| s.rules.iter().any(|r| r.window(now).0))
}

/// queueLength: the latest length of the app's queue for the rule of type
/// typ: the largest read from its replicas, each only from the node it is
/// assigned to. None while no replica's node reported one.
fn queue_length(reps: &[Replica], typ: &str, inp: &Inputs<'_>) -> Option<i64> {
    let mut length = None;
    for r in reps {
        if r.done {
            continue;
        }
        let Some(n) = inp.usage.node(&r.node_id, &inp.now) else {
            continue;
        };
        if let Some(l) = n.queues.get(&(r.id.clone(), typ.to_string())) {
            length = Some(length.map_or(*l, |x: i64| x.max(*l)));
        }
    }
    length
}

/// ruleValue: the current average per ready replica for one rule:
/// requests in progress for http, percent of the reservation for cpu and
/// memory. None without enough samples: no proxy was read, or fewer than
/// half the ready replicas were sampled on their own node.
fn rule_value(typ: &str, res: Res, ready: &[&Replica], inp: &Inputs<'_>) -> Option<f64> {
    if typ == SCALE_HTTP {
        if !inp.load_measured {
            return None;
        }
        let sum: i64 = ready
            .iter()
            .map(|r| inp.load.get(&r.id).copied().unwrap_or(0))
            .sum();
        return Some(sum as f64 / ready.len() as f64);
    }
    let mut sum = 0.0;
    let mut measured = 0usize;
    for r in ready {
        let Some(n) = inp.usage.node(&r.node_id, &inp.now) else {
            continue;
        };
        let Some(u) = n.replicas.get(&r.id) else {
            continue;
        };
        if typ == SCALE_CPU && res.cpu > 0 {
            sum += u.cpu as f64 * 100.0 / res.cpu as f64;
        } else if typ == SCALE_MEMORY && res.mem > 0 {
            sum += u.mem as f64 * 100.0 / res.mem as f64;
        } else {
            continue;
        }
        measured += 1;
    }
    if measured == 0 || measured * 2 < ready.len() {
        return None;
    }
    Some(sum / measured as f64)
}

/// decide: the replica count app a should have, why, and its status; a's
/// own count to hold. st holds the recent recommendations and is updated.
pub(crate) fn decide(
    a: &App,
    sp: &Spec,
    res: Res,
    reps: &[Replica],
    inp: &Inputs<'_>,
    st: &mut AppScaling,
) -> (i64, String, Autoscale) {
    let (lo, hi) = sp.scale_bounds();
    let mut status = Autoscale {
        min: lo as i32,
        max: hi as i32,
        ..Default::default()
    };
    let window = format_duration(SCALE_DOWN_WINDOW);
    macro_rules! hold {
        ($msg:expr) => {{
            status.message = $msg.to_string();
            return (a.replicas, String::new(), status);
        }};
    }
    if a.rolling() {
        hold!("holding while a rollout is in progress");
    }
    if a.replicas == 0 {
        // An open schedule window wakes it (ADR 0034); otherwise the next
        // request does.
        let (n, until) = schedule_wake(sp, &inp.now);
        if n > 0 {
            let n = n.min(hi);
            let when = until.day_clock_zone();
            status.message = format!("schedule {n} until {when}");
            return (n, format!("schedule {n} until {when}"), status);
        }
        hold!("scaled to zero; the next request wakes it");
    }
    if sp.scales_to_zero() && inp.load_measured && !schedule_open(sp, &inp.now) {
        let idle = sp.idle_after();
        let mut quiet = sub(&inp.now, &st.since);
        if !st.last_active.is_zero() {
            quiet = quiet.min(sub(&inp.now, &st.last_active));
        }
        if quiet >= idle {
            let d = format_duration(idle);
            status.message = format!("scaling to zero: no requests for {d}");
            return (0, format!("no requests for {d}"), status);
        }
    }
    // With split traffic, the replicas of every revision with a weight
    // share the load (ADR 0022).
    let ready: Vec<&Replica> = reps
        .iter()
        .filter(|r| {
            let serves = if a.traffic.is_empty() {
                r.revision == a.active_revision
            } else {
                traffic_weight(a, &r.revision) > 0
            };
            serves && r.state == REPLICA_RUNNING && r.ready && !r.draining() && !r.done
        })
        .collect();
    if ready.is_empty() {
        hold!("holding: no ready replicas");
    }

    let mut rec: i64 = -1;
    let mut has_metric = false;
    // The most replicas an open schedule window asks for.
    let mut sched: i64 = -1;
    let mut reasons: Vec<String> = Vec::new();
    let rules = sp.scale.as_ref().map(|s| s.rules.as_slice()).unwrap_or(&[]);
    for rule in rules {
        if rule.typ == SCALE_SCHEDULE {
            let mut rs = AutoscaleRule {
                r#type: rule.typ.clone(),
                target: rule.replicas,
                measured: true,
                ..Default::default()
            };
            let (open, until) = rule.window(&inp.now);
            if open {
                rs.current = rule.replicas;
                rs.until = Some(timestamp(&until));
                sched = sched.max(rule.replicas);
                reasons.push(format!(
                    "schedule {} until {}",
                    rule.replicas,
                    until.day_clock_zone()
                ));
            }
            status.rules.push(rs);
            continue;
        }
        if rule.is_queue() {
            has_metric = true;
            let length = queue_length(reps, &rule.typ, inp);
            status.rules.push(AutoscaleRule {
                r#type: rule.typ.clone(),
                target: rule.length,
                measured: length.is_some(),
                current: length.unwrap_or(0),
                ..Default::default()
            });
            let Some(length) = length else {
                continue;
            };
            // The queue is shared: it needs ⌈length ÷ items per replica⌉.
            let mut n = a.replicas;
            let ratio = length as f64 / (ready.len() as i64 * rule.length) as f64;
            if (ratio - 1.0).abs() > SCALE_TOLERANCE {
                n = (length as f64 / rule.length as f64).ceil() as i64;
            }
            rec = rec.max(n);
            reasons.push(format!(
                "{} {} for {} per replica",
                rule.typ, length, rule.length
            ));
            continue;
        }
        has_metric = true;
        let target = if rule.typ == SCALE_HTTP {
            rule.concurrent as f64
        } else {
            rule.utilization as f64
        };
        let cur = rule_value(&rule.typ, res, &ready, inp);
        let rs = AutoscaleRule {
            r#type: rule.typ.clone(),
            target: target as i64,
            measured: cur.is_some(),
            current: cur.unwrap_or(0.0).round() as i64,
            ..Default::default()
        };
        let (current, tgt) = (rs.current, rs.target);
        status.rules.push(rs);
        let Some(cur) = cur else {
            continue;
        };
        let mut n = a.replicas;
        let ratio = cur / target;
        if (ratio - 1.0).abs() > SCALE_TOLERANCE {
            n = (ready.len() as f64 * ratio).ceil() as i64;
        }
        rec = rec.max(n);
        let unit = if rule.typ == SCALE_HTTP {
            " per replica"
        } else {
            "%"
        };
        reasons.push(format!("{} {current} of {tgt}{unit}", rule.typ));
    }
    if rec < 0 && sched < 0 {
        if has_metric {
            hold!("holding: not enough samples yet");
        }
        // Only schedules, all closed: back to scale.min.
        rec = lo;
        reasons.push("no schedule window open".to_string());
    }
    // A metric rule without samples never pulls below an open window, and
    // an open window only raises.
    rec = rec.max(sched);
    // At most double the ready replicas per step (replicas that cannot be
    // placed do not compound), never below the current count on that
    // account, and within the bounds. Rules never go below one replica:
    // only idleness scales to zero.
    let ready_n = ready.len() as i64;
    rec = rec
        .min((2 * ready_n).max(a.replicas))
        .max(lo)
        .max(1)
        .min(hi);
    st.recs.push((inp.now.clone(), rec));
    st.recs
        .retain(|(at, _)| sub(&inp.now, at) <= SCALE_DOWN_WINDOW);
    let why = reasons.join(", ");
    if a.replicas < lo.max(1) || a.replicas > hi {
        let n = a.replicas.max(lo).max(1).min(hi);
        status.message = format!("moving to {n} (bounds {lo}..{hi})");
        return (n, "within scale.min and scale.max".to_string(), status);
    }
    if rec > a.replicas {
        status.message = format!("scaling up to {rec}: {why}");
        return (rec, why, status);
    }
    let highest = st.recs.iter().map(|(_, n)| *n).fold(rec, i64::max);
    if highest >= a.replicas {
        status.message = format!("steady: {why}");
        if rec < a.replicas {
            status.message =
                format!("would scale down to {rec} once the load stays lower for {window}: {why}");
        }
        return (a.replicas, String::new(), status);
    }
    if sub(&inp.now, &st.since) < SCALE_DOWN_WINDOW {
        status.message = format!("would scale down to {highest}; watching load for {window} first");
        return (a.replicas, String::new(), status);
    }
    status.message = format!("scaling down to {highest}: {why}");
    (
        highest,
        format!("{why} (highest in the last {window})"),
        status,
    )
}

impl Server {
    /// The status of app's last evaluation, if any (Status).
    pub(crate) fn autoscale_status(&self, app: &str) -> Option<Autoscale> {
        self.0.scaler.status(app)
    }

    /// autoscaleLoop: an evaluation every interval for the term.
    pub(crate) async fn autoscale_loop(&self, mut shutdown: watch::Receiver<bool>) {
        let every = self.0.autoscale_interval;
        loop {
            tokio::select! {
                _ = crate::stopped(&mut shutdown) => return,
                _ = tokio::time::sleep(every) => {}
            }
            if let Err(e) = self.autoscale().await
                && !*shutdown.borrow()
            {
                self.0
                    .log
                    .error("autoscale failed", &[("err", e.to_string())]);
            }
        }
    }

    /// autoscale: evaluates every autoscaled app once and applies its
    /// decision (the scenario parity tests call it as they run passes).
    pub async fn autoscale(&self) -> Result<()> {
        let apps = self.store().list_apps().await?;
        let reps = self.store().list_replicas(&Default::default()).await?;
        let now = self.now();
        let mut revs = Revisions::new(self);
        revs.preload(&apps, &reps).await;
        let (load, load_measured) = self.0.usage.load(&now);
        let inp = Inputs {
            now: now.clone(),
            usage: &self.0.usage,
            load,
            load_measured,
        };
        let mut seen = HashSet::new();
        for a in &apps {
            let Some(sp) = a.spec.as_deref() else {
                continue;
            };
            if !sp.autoscaled() {
                continue;
            }
            seen.insert(a.name.clone());
            let mine: Vec<Replica> = reps.iter().filter(|r| r.app == a.name).cloned().collect();
            let active = self.0.usage.last_active(mine.iter().map(|r| r.id.as_str()));
            let Ok(rev) = revs.get(&a.active_revision).await else {
                continue;
            };
            let (n, why) = {
                let mut m = self.0.scaler.lock();
                let st = m
                    .entry(a.name.clone())
                    .or_insert_with(|| AppScaling::new(&now));
                if active.after(&st.last_active) {
                    st.last_active = active;
                }
                let (n, why, status) = decide(a, sp, reservation(&rev), &mine, &inp, st);
                st.status = Some(status);
                (n, why)
            };
            if n == a.replicas {
                continue;
            }
            self.apply_scale(a, n, &why).await;
        }
        self.0.scaler.lock().retain(|name, _| seen.contains(name));
        Ok(())
    }

    async fn apply_scale(&self, a: &App, n: i64, why: &str) {
        match self
            .store()
            .autoscale_replicas(&a.name, a.replicas, n, AUTOSCALE_ACTOR)
            .await
        {
            Ok(()) => {}
            // Changed meanwhile; the next evaluation sees the new state.
            Err(e) if e.kind == Kind::Conflict => return,
            Err(e) => {
                self.0.log.error(
                    "autoscale",
                    &[("app", a.name.clone()), ("err", e.to_string())],
                );
                return;
            }
        }
        let (reason, verb) = if n == 0 {
            ("ScaledToZero", "down")
        } else if n < a.replicas {
            ("ScaledDown", "down")
        } else {
            ("ScaledUp", "up")
        };
        self.0.log.info(
            "autoscaled",
            &[
                ("app", a.name.clone()),
                ("from", a.replicas.to_string()),
                ("to", n.to_string()),
                ("why", why.to_string()),
            ],
        );
        self.record(app_event(
            APP,
            &a.name,
            &a.name,
            reason,
            &format!("scaled {verb} from {} to {n}: {why}", a.replicas),
        ))
        .await;
        self.trigger();
    }

    /// wakeApp: starts an app scaled to zero for which a request waits at
    /// node's proxy (ADR 0021). Wakes are untrusted: they are rate limited
    /// per node, and only raise an app that scales to zero from 0 to 1.
    pub(crate) async fn wake_app(&self, node: &str, app: &str) {
        let now = self.now();
        if !valid_app_id(app) || !self.0.wake_limit.allow(node, &now) {
            return;
        }
        let Ok(a) = self.store().get_app(app).await else {
            return;
        };
        if !a.spec.as_deref().is_some_and(Spec::scales_to_zero) {
            return;
        }
        self.0.scaler.touch(app, &now);
        if a.replicas != 0 {
            return;
        }
        match self
            .store()
            .autoscale_replicas(app, 0, 1, AUTOSCALE_ACTOR)
            .await
        {
            Ok(()) => {}
            Err(e) if e.kind == Kind::Conflict => return,
            Err(e) => {
                self.0
                    .log
                    .error("wake", &[("app", app.to_string()), ("err", e.to_string())]);
                return;
            }
        }
        self.0.log.info(
            "woke app",
            &[("app", app.to_string()), ("node", node.to_string())],
        );
        // Until the next evaluation, app show would still say it scales
        // to zero.
        self.0
            .scaler
            .note(app, &format!("woken by a request at {node}; starting"));
        let mut e = event(
            APP,
            app,
            node,
            "Woken",
            &format!("a request at {node} started it from zero"),
        );
        e.app = app.to_string();
        self.record(e).await;
        self.trigger();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use armada_proto::armada::v1::{QueueLength, ReplicaLoad, ReplicaUsage, UsageReport};
    use armada_spec::gotime::Location;
    use std::sync::Arc;

    const SCALED: &str = "name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\nresources:\n  cpu: 500m\n  memory: 256Mi\nscale:\n  min: 2\n  max: 10\n  rules:\n";
    const ZERO: &str = "name: web\nimage: nginx:1\ningress:\n  type: internal\n  port: 80\nscale:\n  min: 0\n  max: 4\n  idleAfter: 10m\n  rules:\n    - type: http\n      concurrent: 10\n";
    const RES: Res = Res {
        cpu: 500,
        mem: 256 << 20,
    };

    fn app(y: &str, replicas: i64) -> App {
        let sp = armada_spec::parse(y.as_bytes()).expect("a valid spec");
        App {
            name: "web".into(),
            active_revision: "web--r1".into(),
            target_revision: "web--r1".into(),
            replicas,
            spec: Some(Arc::new(sp)),
            rollout_state: String::new(),
            rollout_message: String::new(),
            rollout_progress_at: Time::zero(),
            created_at: Time::zero(),
            updated_at: Time::zero(),
            last_scheduled: Time::zero(),
            traffic: Vec::new(),
            removing: false,
            scaled_at: Time::zero(),
        }
    }

    fn ready(n: usize) -> Vec<Replica> {
        (0..n)
            .map(|i| Replica {
                id: format!("web-{i}"),
                app: "web".into(),
                revision: "web--r1".into(),
                node_id: format!("n{}", i % 2),
                state: REPLICA_RUNNING.into(),
                ready: true,
                ..Replica::default()
            })
            .collect()
    }

    fn at(s: i64) -> Time {
        Time::date(2026, 11, 11, 0, 0, 0, 0, &Location::utc()).add(s * SECOND)
    }

    fn load_of<'a>(u: &'a Usage, now: Time, reps: &[Replica], per: i64) -> Inputs<'a> {
        let r = UsageReport {
            load_measured: true,
            load: reps
                .iter()
                .map(|x| ReplicaLoad {
                    id: x.id.clone(),
                    in_flight: per,
                    requests: 0,
                })
                .collect(),
            ..Default::default()
        };
        u.set("n0", &r, now.clone());
        let (load, load_measured) = u.load(&now);
        Inputs {
            now,
            usage: u,
            load,
            load_measured,
        }
    }

    fn run(
        a: &App,
        reps: &[Replica],
        inp: &Inputs<'_>,
        st: &mut AppScaling,
    ) -> (i64, String, Autoscale) {
        let sp = a.spec.clone().expect("spec");
        decide(a, &sp, RES, reps, inp, st)
    }

    // Go's TestDecideHTTP.
    #[test]
    fn http() {
        let a = app(
            &format!("{SCALED}    - type: http\n      concurrent: 10\n"),
            3,
        );
        let reps = ready(3);
        let now = at(0);
        let mut st = AppScaling::new(&now);
        let u = Usage::default();
        let (n, why, status) = run(&a, &reps, &load_of(&u, now.clone(), &reps, 25), &mut st);
        assert_eq!(n, 6, "{why}");
        assert!(why.contains("http 25 of 10 per replica"));
        assert_eq!(status.rules[0].current, 25);
        assert_eq!((status.min, status.max), (2, 10));
        let u = Usage::default();
        assert_eq!(
            run(&a, &reps, &load_of(&u, now.clone(), &reps, 10), &mut st).0,
            3
        );
        let u = Usage::default();
        assert_eq!(run(&a, &reps, &load_of(&u, at(60), &reps, 0), &mut st).0, 3);
        let u = Usage::default();
        let (n, _, s) = run(
            &a,
            &reps,
            &load_of(&u, now.clone(), &reps, 0),
            &mut AppScaling::new(&now),
        );
        assert_eq!(n, 3);
        assert!(s.message.contains("would scale down"), "{}", s.message);
        let u = Usage::default();
        assert_eq!(
            run(&a, &reps, &load_of(&u, at(330), &reps, 0), &mut st).0,
            2
        );
    }

    // Go's TestDecideScaleToZero.
    #[test]
    fn scale_to_zero() {
        let a = app(ZERO, 1);
        let reps = ready(1);
        let now = at(0);
        let mut st = AppScaling::new(&now);
        let u = Usage::default();
        assert_eq!(
            run(&a, &reps, &load_of(&u, now.clone(), &reps, 0), &mut st).0,
            1
        );
        st.last_active = at(9 * 60);
        assert_eq!(
            run(&a, &reps, &load_of(&u, at(10 * 60), &reps, 0), &mut st).0,
            1
        );
        let (n, why, status) = run(&a, &reps, &load_of(&u, at(19 * 60 + 1), &reps, 0), &mut st);
        assert_eq!(n, 0);
        assert!(why.contains("no requests for 10m0s"), "{why}");
        assert!(status.message.contains("zero"));
        let mut zero = a.clone();
        zero.replicas = 0;
        let (n, _, s) = run(&zero, &[], &load_of(&u, now.clone(), &[], 0), &mut st);
        assert_eq!(n, 0);
        assert!(s.message.contains("wakes"));
    }

    // Go's TestDecideQueue.
    #[test]
    fn queue() {
        let a = app(
            &format!(
                "{SCALED}    - type: queue\n      command: [queue-length]\n      length: 100\n"
            ),
            2,
        );
        let reps = ready(2);
        let now = at(0);
        let queue_of = |u: &Usage, length: i64| {
            u.set(
                "n0",
                &UsageReport {
                    queues: vec![QueueLength {
                        id: "web-0".into(),
                        length,
                        r#type: String::new(),
                    }],
                    ..Default::default()
                },
                now.clone(),
            );
        };
        let inp = |u| Inputs {
            now: now.clone(),
            usage: u,
            load: HashMap::new(),
            load_measured: false,
        };
        let u = Usage::default();
        queue_of(&u, 700);
        let (n, why, status) = run(&a, &reps, &inp(&u), &mut AppScaling::new(&now));
        assert_eq!(n, 4);
        assert!(why.contains("queue 700 for 100 per replica"), "{why}");
        assert_eq!(
            (status.rules[0].current, status.rules[0].target),
            (700, 100)
        );
        queue_of(&u, 210);
        assert_eq!(run(&a, &reps, &inp(&u), &mut AppScaling::new(&now)).0, 2);
        let empty = Usage::default();
        let (n, _, s) = run(&a, &reps, &inp(&empty), &mut AppScaling::new(&now));
        assert_eq!(n, 2);
        assert!(s.message.contains("not enough samples"));
        queue_of(&u, 1 << 62);
        assert_eq!(run(&a, &reps, &inp(&u), &mut AppScaling::new(&now)).0, 4);
    }

    // Go's TestDecideHolds (CPU from the replica's own node).
    #[test]
    fn cpu_from_own_node() {
        let a = app(
            &format!("{SCALED}    - type: cpu\n      utilization: 50\n"),
            2,
        );
        let reps = ready(2);
        let now = at(0);
        let u = Usage::default();
        let sample = |id: &str| UsageReport {
            replicas: vec![ReplicaUsage {
                id: id.into(),
                cpu_millis: 500,
                ..Default::default()
            }],
            ..Default::default()
        };
        u.set("n9", &sample("web-0"), now.clone());
        let inp = Inputs {
            now: now.clone(),
            usage: &u,
            load: HashMap::new(),
            load_measured: false,
        };
        assert_eq!(run(&a, &reps, &inp, &mut AppScaling::new(&now)).0, 2);
        u.set("n0", &sample("web-0"), now.clone());
        u.set("n1", &sample("web-1"), now.clone());
        let (n, why, _) = run(&a, &reps, &inp, &mut AppScaling::new(&now));
        assert_eq!(n, 4);
        assert!(why.contains("cpu 100 of 50%"), "{why}");
        let mut rolling = a.clone();
        rolling.target_revision = "web--r2".into();
        rolling.rollout_state = armada_store::ROLLOUT_PROGRESSING.into();
        let (n, _, s) = run(&rolling, &reps, &inp, &mut AppScaling::new(&now));
        assert_eq!(n, 2);
        assert!(s.message.contains("rollout"));
    }

    // Go's TestDecideSchedule and TestDecideScheduleWakesZero.
    #[test]
    fn schedules() {
        let only = app(
            &format!(
                "{SCALED}    - type: schedule\n      schedule: \"0 8 * * *\"\n      duration: 10h\n      replicas: 6\n"
            ),
            2,
        );
        let reps = ready(2);
        let day = Time::date(2026, 11, 11, 9, 0, 0, 0, &Location::utc());
        let u = Usage::default();
        let inp = |now: &Time| Inputs {
            now: now.clone(),
            usage: &u,
            load: HashMap::new(),
            load_measured: false,
        };
        let (n, why, status) = run(&only, &reps, &inp(&day), &mut AppScaling::new(&day));
        assert_eq!(n, 4);
        assert_eq!(why, "schedule 6 until Wed 18:00 UTC");
        assert_eq!(status.rules[0].current, 6);
        let night = Time::date(2026, 11, 11, 22, 0, 0, 0, &Location::utc());
        let mut big = only.clone();
        big.replicas = 6;
        let (n, _, _) = run(
            &big,
            &ready(6),
            &inp(&night),
            &mut AppScaling::new(&night.add(-3600 * SECOND)),
        );
        assert_eq!(n, 2);
        let zero = app(
            &format!(
                "{ZERO}    - type: schedule\n      schedule: \"0 8 * * *\"\n      duration: 10h\n      replicas: 2\n"
            ),
            0,
        );
        let morning = Time::date(2026, 11, 11, 8, 1, 0, 0, &Location::utc());
        let (n, why, _) = run(&zero, &[], &inp(&morning), &mut AppScaling::new(&morning));
        assert_eq!((n, why.as_str()), (2, "schedule 2 until Wed 18:00 UTC"));
    }
}

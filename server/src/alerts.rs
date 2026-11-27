//! Alerts (ADR 0045): channels kept in meta `alerts` with
//! their secrets sealed, one worker and queue per channel so a slow
//! channel holds up no other, notices queued by source (a space, or the
//! cluster) with a rate per source, and the AdminService methods.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use armada_proto::armada::v1::{
    AlertChannel, AlertChannelRequest, DeleteAlertChannelRequest, DeleteAlertChannelResponse,
    ListAlertChannelsRequest, ListAlertChannelsResponse, TestAlertChannelRequest,
    TestAlertChannelResponse,
};
use armada_secrets::Value;
use armada_spec::gotime::Time;
use armada_spec::validate::split_app_id;
use armada_store::{Event, Kind};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tonic::{Code, Status};

use crate::alert::{self, Channel, Endpoints, Notice, Sender};
use crate::events::timestamp;
use crate::grpc::Auth;
use crate::settings::{SealedJson, TOKEN_SCOPE};
use crate::{Server, store_err};

const META_ALERTS: &str = "alerts";
/// The notices waiting per channel, and those of one source; more are
/// dropped and counted.
pub(crate) const ALERT_QUEUE: usize = 256;
pub(crate) const ALERT_SOURCE_QUEUE: usize = 64;
/// How many notices of one source may go at once per channel, and then
/// per minute; the rest are summed up in one notice.
pub(crate) const ALERT_BURST: f64 = 20.0;
const ALERT_TRIES: usize = 3;
const ALERT_RETRY: Duration = Duration::from_secs(2);

/// A stored channel: the channel without the secret, which is sealed.
#[derive(Clone, Default, Serialize, Deserialize)]
struct AlertRec {
    #[serde(flatten)]
    ch: Channel,
    #[serde(default, rename = "secret", skip_serializing_if = "Option::is_none")]
    sealed: Option<SealedJson>,
    #[serde(default, skip_serializing_if = "is_zero")]
    version: i64,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

#[derive(Default, Serialize, Deserialize)]
struct AlertConfig {
    #[serde(default, deserialize_with = "null_vec")]
    channels: Vec<AlertRec>,
}

fn null_vec<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<AlertRec>, D::Error> {
    Ok(Option::<Vec<AlertRec>>::deserialize(d)?.unwrap_or_default())
}

fn alert_secret_name(channel: &str) -> String {
    format!("alert-{channel}")
}

/// A channel's waiting notices of one source, with its rate.
struct Source {
    waiting: std::collections::VecDeque<Notice>,
    tokens: f64,
    refilled: Instant,
    held: usize,
}

/// A channel's waiting notices by source: each source has its own place
/// and rate, and sources take turns.
pub(crate) struct NoticeQueue {
    sources: HashMap<String, Source>,
    order: std::collections::VecDeque<String>,
    pub(crate) waiting: usize,
}

fn minutes(d: Duration) -> f64 {
    d.as_secs_f64() / 60.0
}

impl NoticeQueue {
    pub(crate) fn new() -> NoticeQueue {
        NoticeQueue {
            sources: HashMap::new(),
            order: Default::default(),
            waiting: 0,
        }
    }

    /// put queues n, never blocking. When its source is full, or the queue
    /// is full and n's source holds no more than the largest, a notice is
    /// dropped (put answers false): n itself, or the oldest of the largest
    /// source.
    pub(crate) fn put(&mut self, n: Notice, now: Instant) -> bool {
        self.source(&n.space, now);
        if self.sources[&n.space].waiting.len() >= ALERT_SOURCE_QUEUE {
            return false;
        }
        let mut kept = true;
        if self.waiting >= ALERT_QUEUE {
            let mut big: Option<&String> = None;
            for name in &self.order {
                let len = self.sources[name].waiting.len();
                if big.is_none_or(|b| len > self.sources[b].waiting.len()) {
                    big = Some(name);
                }
            }
            let mine = self.sources[&n.space].waiting.len();
            let Some(big) = big.cloned() else {
                return false;
            };
            if self.sources[&big].waiting.len() <= mine + 1 {
                return false;
            }
            if let Some(s) = self.sources.get_mut(&big) {
                s.waiting.pop_front();
            }
            self.waiting -= 1;
            kept = false;
        }
        let src = self.sources.get_mut(&n.space).expect("made above");
        if src.waiting.is_empty() {
            self.order.push_back(n.space.clone());
        }
        src.waiting.push_back(n);
        self.waiting += 1;
        kept
    }

    /// source makes a source's record; records of sources with nothing
    /// waiting or held and a full rate are forgotten first.
    fn source(&mut self, name: &str, now: Instant) {
        if self.sources.contains_key(name) {
            return;
        }
        self.sources.retain(|_, s| {
            !(s.waiting.is_empty()
                && s.held == 0
                && s.tokens + minutes(now.saturating_duration_since(s.refilled)) * ALERT_BURST
                    >= ALERT_BURST)
        });
        self.sources.insert(
            name.to_string(),
            Source {
                waiting: Default::default(),
                tokens: ALERT_BURST,
                refilled: now,
                held: 0,
            },
        );
    }

    /// next takes the next notice that may go now, sources taking turns;
    /// notices over their source's rate are counted as held. held is how
    /// many of that source's notices were held since one last went.
    pub(crate) fn next(&mut self, now: Instant) -> Option<(Notice, usize)> {
        while let Some(name) = self.order.pop_front() {
            let s = self.sources.get_mut(&name).expect("a queued source");
            let n = s.waiting.pop_front().expect("a waiting notice");
            self.waiting -= 1;
            if !s.waiting.is_empty() {
                self.order.push_back(name.clone());
            }
            // take: spend a token, or count the notice as held back.
            s.tokens = ALERT_BURST
                .min(s.tokens + minutes(now.saturating_duration_since(s.refilled)) * ALERT_BURST);
            s.refilled = now;
            if s.tokens < 1.0 {
                s.held += 1;
                continue;
            }
            s.tokens -= 1.0;
            let held = std::mem::take(&mut s.held);
            return Some((n, held));
        }
        None
    }

    #[cfg(test)]
    fn has_source(&self, name: &str) -> bool {
        self.sources.contains_key(name)
    }

    #[cfg(test)]
    fn source_len(&self, name: &str) -> usize {
        self.sources.get(name).map_or(0, |s| s.waiting.len())
    }
}

/// Sums up the notices of n's source that were held back.
pub(crate) fn held_notice(n: &Notice, held: usize) -> Notice {
    let about = if n.space.is_empty() {
        "the cluster".to_string()
    } else {
        format!("space {}", n.space)
    };
    let mut out = Notice::new(alert::KIND_SUMMARY, armada_store::gojson::now());
    out.cluster = n.cluster.clone();
    out.space = n.space.clone();
    out.message = format!(
        "{held} more notices about {about} were held back (more than {} a minute)",
        ALERT_BURST as i64
    );
    out
}

/// How delivery went for one channel since the leader started.
#[derive(Clone, Default)]
struct Stats {
    last_sent: Option<Time>,
    last_error_at: Option<Time>,
    last_error: String,
    sent: i64,
    failed: i64,
    dropped: i64,
}

struct Worker {
    ch: Channel,
    send: Sender,
    queue: Arc<(Mutex<NoticeQueue>, Notify)>,
    stats: Arc<Mutex<Stats>>,
    task: Option<tokio::task::AbortHandle>,
}

#[derive(Default)]
struct AlertState {
    workers: HashMap<String, Worker>,
    cluster: String,
    started: bool,
}

/// Delivers notices.
pub(crate) struct Alerter {
    st: Mutex<AlertState>,
    ends: Endpoints,
    tls: Arc<rustls::ClientConfig>,
    /// One channel change at a time.
    pub(crate) change: tokio::sync::Mutex<()>,
}

fn same_channel(a: &Channel, b: &Channel) -> bool {
    a.kind == b.kind
        && a.chat_id == b.chat_id
        && a.smtp_host == b.smtp_host
        && a.smtp_user == b.smtp_user
        && a.from == b.from
        && a.to == b.to
        && a.spaces == b.spaces
        && a.reasons == b.reasons
        && a.secret == b.secret
}

/// The machine's roots, for HTTPS and SMTP alike.
fn client_tls() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    armada_node::http::system_roots(&mut roots);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(cfg)
}

impl Alerter {
    pub(crate) fn new(ends: Endpoints) -> Alerter {
        Alerter {
            st: Mutex::default(),
            ends,
            tls: client_tls(),
            change: tokio::sync::Mutex::new(()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, AlertState> {
        self.st.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// start begins delivering for the term.
    pub(crate) fn start(&self) {
        self.lock().started = true;
    }

    /// stop ends every worker (the term ended).
    pub(crate) fn stop(&self) {
        let mut st = self.lock();
        st.started = false;
        for w in st.workers.values_mut() {
            if let Some(t) = w.task.take() {
                t.abort();
            }
        }
        st.workers.clear();
    }

    /// set replaces the channels; workers of unchanged channels keep their
    /// queue and counts.
    fn set(&self, srv: &Server, chs: Vec<Channel>, cluster: String) {
        let mut st = self.lock();
        st.cluster = cluster;
        if !st.started {
            return;
        }
        let mut keep = std::collections::HashSet::new();
        for c in chs {
            keep.insert(c.name.clone());
            if st
                .workers
                .get(&c.name)
                .is_some_and(|w| same_channel(&w.ch, &c))
            {
                continue;
            }
            let mut w = Worker {
                send: Sender::new(c.clone(), self.ends.clone(), self.tls.clone()),
                ch: c.clone(),
                queue: Arc::new((Mutex::new(NoticeQueue::new()), Notify::new())),
                stats: Arc::default(),
                task: None,
            };
            if let Some(mut old) = st.workers.remove(&c.name) {
                // A changed channel keeps its counts, rates, and waiting
                // notices.
                if let Some(t) = old.task.take() {
                    t.abort();
                }
                let s = old.stats.lock().unwrap_or_else(|p| p.into_inner()).clone();
                *w.stats.lock().unwrap_or_else(|p| p.into_inner()) = s;
                w.queue = old.queue.clone();
                w.queue.1.notify_one();
            }
            let task = tokio::spawn(run(
                srv.clone(),
                c.name.clone(),
                w.send.clone(),
                w.queue.clone(),
                w.stats.clone(),
            ));
            w.task = Some(task.abort_handle());
            st.workers.insert(c.name.clone(), w);
        }
        st.workers.retain(|name, w| {
            if keep.contains(name) {
                return true;
            }
            if let Some(t) = w.task.take() {
                t.abort();
            }
            false
        });
    }

    /// notify queues n for every channel that wants it; it never blocks.
    pub(crate) fn notify(&self, srv: &Server, mut n: Notice) {
        let st = self.lock();
        n.cluster = st.cluster.clone();
        for (name, w) in &st.workers {
            if !w.ch.wants(&n.reason, &n.space) {
                continue;
            }
            let kept = {
                let mut q = w.queue.0.lock().unwrap_or_else(|p| p.into_inner());
                q.put(n.clone(), Instant::now())
            };
            w.queue.1.notify_one();
            if !kept {
                w.stats.lock().unwrap_or_else(|p| p.into_inner()).dropped += 1;
                srv.0.metrics.alert_dropped(name);
            }
        }
    }

    /// stats fills a channel's delivery fields.
    fn stats(&self, name: &str, out: &mut AlertChannel) {
        let st = self.lock();
        let Some(w) = st.workers.get(name) else {
            return;
        };
        let s = w.stats.lock().unwrap_or_else(|p| p.into_inner());
        out.last_sent = s.last_sent.as_ref().map(timestamp);
        out.last_error = s.last_error.clone();
        out.last_error_at = s.last_error_at.as_ref().map(timestamp);
        out.sent = s.sent;
        out.failed = s.failed;
        out.dropped = s.dropped;
    }

    fn sender(&self, name: &str) -> Option<Sender> {
        self.lock().workers.get(name).map(|w| w.send.clone())
    }
}

/// A channel's worker: delivers what its queue lets go, in turn.
async fn run(
    srv: Server,
    name: String,
    send: Sender,
    queue: Arc<(Mutex<NoticeQueue>, Notify)>,
    stats: Arc<Mutex<Stats>>,
) {
    loop {
        queue.1.notified().await;
        loop {
            let next = queue
                .0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .next(Instant::now());
            let Some((n, held)) = next else { break };
            if held > 0 {
                deliver(&srv, &name, &send, &stats, &held_notice(&n, held)).await;
            }
            deliver(&srv, &name, &send, &stats, &n).await;
        }
    }
}

/// deliver tries n a few times with backoff and records how it went.
async fn deliver(srv: &Server, name: &str, send: &Sender, stats: &Mutex<Stats>, n: &Notice) {
    let mut wait = ALERT_RETRY;
    let mut res = Ok(());
    for t in 0..ALERT_TRIES {
        if t > 0 {
            tokio::time::sleep(wait).await;
            wait *= 5;
        }
        res = send.send(n).await;
        if res.is_ok() {
            break;
        }
    }
    let mut s = stats.lock().unwrap_or_else(|p| p.into_inner());
    match res {
        Err(e) => {
            s.failed += 1;
            s.last_error = e;
            s.last_error_at = Some(armada_store::gojson::now());
            srv.0.metrics.alert_failed(name);
        }
        Ok(()) => {
            s.sent += 1;
            s.last_sent = Some(armada_store::gojson::now());
            srv.0.metrics.alert_sent(name);
        }
    }
}

/// Turns an event into a notice.
pub(crate) fn notice_of(e: &Event, kind: &str) -> Notice {
    let time = if e.last.is_zero() {
        armada_store::gojson::now()
    } else {
        e.last.clone()
    };
    let mut n = Notice::new(kind, time);
    n.reason = e.reason.clone();
    n.object = format!("{} {}", e.kind, e.object);
    n.app = e.app.clone();
    n.node = e.node.clone();
    n.message = e.message.clone();
    n.count = e.count;
    if !e.app.is_empty()
        && let Some((space, name)) = split_app_id(&e.app)
    {
        n.space = space;
        n.app = name;
    }
    if kind == alert::KIND_RESOLVED {
        n.message.clear();
        n.count = 0;
    }
    n
}

fn channel_proto(r: &AlertRec) -> AlertChannel {
    let c = &r.ch;
    AlertChannel {
        name: c.name.clone(),
        r#type: c.kind.clone(),
        chat_id: c.chat_id.clone(),
        smtp_host: c.smtp_host.clone(),
        smtp_user: c.smtp_user.clone(),
        from: c.from.clone(),
        to: c.to.clone(),
        spaces: c.spaces.clone(),
        reasons: c.reasons.clone(),
        secret_set: r.sealed.is_some(),
        ..Default::default()
    }
}

fn trim(s: &str) -> String {
    String::from_utf8_lossy(armada_node::gostr::trim_space(s.as_bytes())).to_string()
}

fn trim_all(v: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for x in v {
        let x = trim(x);
        if !x.is_empty() && !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

/// Copies the fields req names onto c.
fn apply_channel(c: &mut Channel, req: &AlertChannelRequest, create: bool) {
    let p = req.channel.clone().unwrap_or_default();
    if create || req.set_chat_id {
        c.chat_id = trim(&p.chat_id);
    }
    if create || req.set_smtp {
        c.smtp_host = trim(&p.smtp_host);
        c.smtp_user = trim(&p.smtp_user);
    }
    if create || req.set_from {
        c.from = trim(&p.from);
    }
    if create || req.set_to {
        c.to = trim_all(&p.to);
    }
    if create || req.set_spaces {
        c.spaces = trim_all(&p.spaces);
    }
    if create || req.set_reasons {
        c.reasons = trim_all(&p.reasons);
    }
}

impl Server {
    async fn alert_config(&self) -> Result<AlertConfig, armada_store::Error> {
        let v = match self.store().get_meta(META_ALERTS).await {
            Err(e) if e.kind == Kind::NotFound => return Ok(AlertConfig::default()),
            Err(e) => return Err(e),
            Ok(v) if v.is_empty() => return Ok(AlertConfig::default()),
            Ok(v) => v,
        };
        serde_json::from_str(&v)
            .map_err(|e| armada_store::Error::other(format!("alert channels: {e}")))
    }

    async fn save_alert_config(&self, ac: &AlertConfig) -> Result<(), armada_store::Error> {
        let s = String::from_utf8(go_json(ac)).unwrap_or_default();
        self.store().set_meta(META_ALERTS, &s).await
    }

    /// Opens every channel's secret and hands the channels to
    /// the alerter.
    pub(crate) async fn load_alerts(&self) -> Result<(), armada_store::Error> {
        let ac = self.alert_config().await?;
        let mut chs = Vec::new();
        for r in &ac.channels {
            let mut c = r.ch.clone();
            if let Some(sealed) = &r.sealed {
                let Some(keys) = &self.0.keys else {
                    self.0.log.warn(
                        "alert channel: no master key to open its secret",
                        &[("channel", c.name.clone())],
                    );
                    continue;
                };
                match keys.open(
                    &sealed.sealed(),
                    TOKEN_SCOPE,
                    &alert_secret_name(&c.name),
                    r.version,
                ) {
                    Ok(v) => c.secret = v.bytes().to_vec(),
                    Err(e) => {
                        self.0.log.warn(
                            "alert channel: open its secret",
                            &[("channel", c.name.clone()), ("err", e.to_string())],
                        );
                        continue;
                    }
                }
            }
            chs.push(c);
        }
        let root = self.root_domain().await;
        let cluster = if root.is_empty() {
            self.0.name.clone()
        } else {
            root
        };
        self.0.alerts.set(self, chs, cluster);
        Ok(())
    }

    /// Tells the channels that want it about an event (a new one, or a
    /// condition that ended).
    pub(crate) fn alert(&self, e: &Event, kind: &str) {
        self.0.alerts.notify(self, notice_of(e, kind));
    }

    pub(crate) async fn create_alert_channel(
        &self,
        a: &Auth,
        req: AlertChannelRequest,
    ) -> Result<AlertChannel, Status> {
        self.change_alert_channel(a, req, true).await
    }

    pub(crate) async fn update_alert_channel(
        &self,
        a: &Auth,
        req: AlertChannelRequest,
    ) -> Result<AlertChannel, Status> {
        self.change_alert_channel(a, req, false).await
    }

    async fn change_alert_channel(
        &self,
        a: &Auth,
        req: AlertChannelRequest,
        create: bool,
    ) -> Result<AlertChannel, Status> {
        let p = req.channel.clone().unwrap_or_default();
        let name = p.name.clone();
        alert::check_name(&name).map_err(|e| Status::new(Code::InvalidArgument, e))?;
        let _guard = self.0.alerts.change.lock().await;
        let mut ac = self.alert_config().await.map_err(|e| store_err(&e))?;
        let i = ac.channels.iter().position(|r| r.ch.name == name);
        if create && i.is_some() {
            return Err(Status::new(
                Code::AlreadyExists,
                format!("alert channel {name} exists; change it with armada alert update"),
            ));
        }
        if create && ac.channels.len() >= alert::MAX_CHANNELS {
            return Err(Status::new(
                Code::ResourceExhausted,
                format!("at most {} alert channels", alert::MAX_CHANNELS),
            ));
        }
        if !create && i.is_none() {
            return Err(Status::new(
                Code::NotFound,
                format!("alert channel {name} not found"),
            ));
        }
        let mut r = AlertRec::default();
        if create {
            r.ch.name = name.clone();
            r.ch.kind = trim(&p.r#type);
        } else {
            r = ac.channels[i.unwrap_or_default()].clone();
            if !p.r#type.is_empty() && p.r#type != r.ch.kind {
                return Err(Status::new(
                    Code::InvalidArgument,
                    "the type of a channel cannot change; delete it and create it again",
                ));
            }
        }
        apply_channel(&mut r.ch, &req, create);
        r.ch.check()
            .map_err(|e| Status::new(Code::InvalidArgument, e))?;
        if req.set_secret || create {
            let secret = armada_node::gostr::trim_space(&req.secret).to_vec();
            r.ch.check_secret(&secret)
                .map_err(|e| Status::new(Code::InvalidArgument, e))?;
            r.sealed = None;
            if !secret.is_empty() {
                let Some(keys) = &self.0.keys else {
                    return Err(Status::new(
                        Code::FailedPrecondition,
                        "this server has no master key to encrypt the secret with",
                    ));
                };
                let sealed = keys
                    .seal(
                        TOKEN_SCOPE,
                        &alert_secret_name(&name),
                        r.version + 1,
                        &Value::new(&secret),
                    )
                    .map_err(|_| Status::new(Code::Internal, "seal the channel's secret"))?;
                r.version += 1;
                r.sealed = Some(SealedJson::of(&sealed));
            }
        } else if r.sealed.is_none() && r.ch.needs_secret() {
            return Err(Status::new(
                Code::FailedPrecondition,
                format!(
                    "{} needs its secret: --{} -",
                    r.ch.kind,
                    alert::secret_flag(&r.ch.kind)
                ),
            ));
        }
        match i {
            Some(i) if !create => ac.channels[i] = r.clone(),
            _ => ac.channels.push(r.clone()),
        }
        self.save_alert_config(&ac)
            .await
            .map_err(|e| store_err(&e))?;
        let verb = if create {
            "alert.create"
        } else {
            "alert.update"
        };
        let mut what = format!(
            "{} spaces={} reasons={}",
            r.ch.kind,
            r.ch.spaces.join(","),
            r.ch.reasons.join(",")
        );
        if req.set_secret {
            what.push_str(" secret");
        }
        self.store()
            .record_audit(&a.actor(), verb, &format!("alert/{name}"), &what)
            .await
            .map_err(|e| store_err(&e))?;
        if let Err(e) = self.load_alerts().await {
            self.0
                .log
                .warn("alert channels: reload", &[("err", e.to_string())]);
        }
        let mut out = channel_proto(&r);
        self.0.alerts.stats(&name, &mut out);
        Ok(out)
    }

    /// ListAlertChannels lists the channels with how delivery went since
    /// the leader started.
    pub(crate) async fn list_alert_channels(
        &self,
        _a: &Auth,
        _req: ListAlertChannelsRequest,
    ) -> Result<ListAlertChannelsResponse, Status> {
        let ac = self.alert_config().await.map_err(|e| store_err(&e))?;
        let mut resp = ListAlertChannelsResponse::default();
        for r in &ac.channels {
            let mut c = channel_proto(r);
            self.0.alerts.stats(&r.ch.name, &mut c);
            resp.channels.push(c);
        }
        resp.channels.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(resp)
    }

    /// DeleteAlertChannel removes a channel.
    pub(crate) async fn delete_alert_channel(
        &self,
        a: &Auth,
        req: DeleteAlertChannelRequest,
    ) -> Result<DeleteAlertChannelResponse, Status> {
        let _guard = self.0.alerts.change.lock().await;
        let mut ac = self.alert_config().await.map_err(|e| store_err(&e))?;
        let Some(i) = ac.channels.iter().position(|r| r.ch.name == req.name) else {
            return Err(Status::new(
                Code::NotFound,
                format!("alert channel {} not found", req.name),
            ));
        };
        ac.channels.remove(i);
        self.save_alert_config(&ac)
            .await
            .map_err(|e| store_err(&e))?;
        self.store()
            .record_audit(
                &a.actor(),
                "alert.delete",
                &format!("alert/{}", req.name),
                "",
            )
            .await
            .map_err(|e| store_err(&e))?;
        if let Err(e) = self.load_alerts().await {
            self.0
                .log
                .warn("alert channels: reload", &[("err", e.to_string())]);
        }
        Ok(DeleteAlertChannelResponse {})
    }

    /// TestAlertChannel sends a test notice now and says how it went.
    pub(crate) async fn test_alert_channel(
        &self,
        _a: &Auth,
        req: TestAlertChannelRequest,
    ) -> Result<TestAlertChannelResponse, Status> {
        let Some(snd) = self.0.alerts.sender(&req.name) else {
            return Err(Status::new(
                Code::NotFound,
                format!("alert channel {} not found", req.name),
            ));
        };
        let root = self.root_domain().await;
        let mut n = Notice::new(alert::KIND_TEST, armada_store::gojson::now());
        n.cluster = if root.is_empty() {
            self.0.name.clone()
        } else {
            root
        };
        n.message = "Armada can reach this channel. Notices about events that need a person will come here.".into();
        snd.send(&n).await.map_err(|e| {
            Status::new(
                Code::FailedPrecondition,
                format!("the test notice was not sent: {e}"),
            )
        })?;
        Ok(TestAlertChannelResponse {})
    }
}

/// Compact JSON with <, >, &, U+2028, and U+2029 escaped.
fn go_json<T: Serialize>(v: &T) -> Vec<u8> {
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
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notice(space: &str, reason: &str) -> Notice {
        let mut n = Notice::new(alert::KIND_EVENT, Time::zero());
        n.space = space.into();
        n.reason = reason.into();
        n
    }

    #[test]
    fn rate_limit() {
        let mut q = NoticeQueue::new();
        let now = Instant::now();
        for _ in 0..ALERT_BURST as usize + 2 {
            assert!(q.put(notice("noisy", ""), now));
        }
        q.put(notice("", "Lost"), now);
        q.put(notice("quiet", ""), now);
        let mut got = Vec::new();
        while let Some((n, _)) = q.next(now) {
            got.push(format!("{}/{}", n.space, n.reason));
        }
        assert_eq!(got.len(), ALERT_BURST as usize + 2);
        assert_eq!(got[1], "/Lost");
        assert_eq!(got[2], "quiet/");
        let later = now + Duration::from_secs(4);
        q.put(notice("noisy", ""), later);
        let (n, held) = q.next(later).expect("one token");
        assert_eq!((n.space.as_str(), held), ("noisy", 2));
        let s = held_notice(&n, held);
        assert!(s.message.contains("space noisy") && s.space == "noisy");
    }

    #[test]
    fn queue_fair() {
        let mut q = NoticeQueue::new();
        let now = Instant::now();
        let mut dropped = 0;
        for i in 0..ALERT_QUEUE {
            if !q.put(notice(&format!("s{}", i % 4), ""), now) {
                dropped += 1;
            }
        }
        assert_eq!((dropped, q.waiting), (0, ALERT_QUEUE));
        assert!(!q.put(notice("s0", ""), now), "a full source took a place");
        assert!(
            !q.put(notice("", "Lost"), now),
            "no notice was dropped for it"
        );
        assert_eq!((q.waiting, q.source_len("")), (ALERT_QUEUE, 1));
        while q.next(now).is_some() {}
        q.put(notice("new", ""), now + Duration::from_secs(3600));
        assert!(!q.has_source("") && q.has_source("s0") && q.has_source("new"));
    }

    #[test]
    fn records_written() {
        let ac = AlertConfig {
            channels: vec![AlertRec {
                ch: Channel {
                    name: "ops".into(),
                    kind: "webhook".into(),
                    spaces: vec!["shop".into()],
                    ..Default::default()
                },
                sealed: None,
                version: 0,
            }],
        };
        assert_eq!(
            String::from_utf8(go_json(&ac)).unwrap(),
            r#"{"channels":[{"name":"ops","type":"webhook","spaces":["shop"]}]}"#
        );
    }
}

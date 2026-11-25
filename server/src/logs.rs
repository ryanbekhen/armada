//! Logs (Go's Logs and relayLogs in admin.go, PushLogs and logRouter in
//! agents.go, and loghistory.go): live output relayed from each replica's
//! node, a search of every node's log history (ADR 0043) merged by time,
//! the pruning of the records of where replicas ran, and the cluster's log
//! settings (history, ADR 0043, and export, ADR 0044) of SetClusterConfig.
//! A node is asked through a LogRequest on its Connect stream and answers
//! on a PushLogs stream the router pairs with the request, once and only
//! for the node it went to.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use armada_proto::armada::v1::server_message::Msg;
use armada_proto::armada::v1::*;
use armada_proto::google::protobuf::Timestamp;
use armada_spec::gotime::Time;
use armada_store::{REPLICA_RUNNING, Replica, ReplicaFilter};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch};
use tonic::{Code, Request, Response, Status, Streaming};

use crate::Server;
use crate::admin::Out;
use crate::agents::Session;
use crate::events::{before_space, timestamp};
use crate::exec::{ATTACH_TIMEOUT, OFFER_TIMEOUT, check_container_name, find_replica};
use crate::grpc::{Auth, auth};
use crate::guard::Guard;
use crate::settings::{LOG_TOKEN_NAME, META_LOGS, SealedJson, TOKEN_SCOPE};
use crate::store_err;

const DEFAULT_LOG_TAIL: i32 = 100;
const MAX_LOG_TAIL: i32 = 10000;
const DEFAULT_SEARCH_LIMIT: i32 = 500;
const MAX_SEARCH_LIMIT: i32 = 5000;
/// searchWait: how long the leader waits for the nodes' answers.
const SEARCH_WAIT: Duration = Duration::from_secs(45);
const MAX_SEARCHES: usize = 4;
const MAX_SEARCHES_PER_CALLER: usize = 2;
const MAX_SEARCH_NODE_BYTES: usize = 32 << 20;
const MAX_LIVE_LOGS: usize = 128;
const MAX_LIVE_LOGS_PER_CALLER: usize = 8;
/// searchSkew: how far in the future a node's entry may be stamped.
const SEARCH_SKEW: i64 = 60 * 1_000_000_000;
/// followScan: how often a followed app is checked for new replicas.
const FOLLOW_SCAN: Duration = Duration::from_secs(2);
const MIN_LOG_RETENTION: i64 = 3600;
const MAX_LOG_RETENTION: i64 = 90 * 24 * 3600;
/// defaultLogRetention: what nodes keep when the cluster sets none.
const DEFAULT_LOG_RETENTION: i64 = 7 * 24 * 3600;
const MIN_LOG_MAX_BYTES: i64 = 64 << 20;
const MAX_LOG_MAX_BYTES: i64 = 1 << 40;
/// placementPrune and placementMargin: how often placement records older
/// than the log retention are dropped, and how much longer they are kept.
const PLACEMENT_PRUNE: Duration = Duration::from_secs(3600);
const PLACEMENT_MARGIN: i64 = 24 * 3600;
/// logexport's bounds.
const MAX_ENDPOINT: usize = 2048;
const MAX_NAME: usize = 256;
const MAX_TOKEN: usize = 4096;

const BUSY_SEARCHES: &str = "too many log searches are running; try again shortly";
const BUSY_LIVE: &str = "too many log streams are open; close one or try again shortly";

/// callerSlots: bounds the calls of one kind served at once, in total and
/// per caller.
pub struct CallerSlots {
    st: Arc<Mutex<(usize, HashMap<String, usize>)>>,
    limit: usize,
    per_caller: usize,
    busy: &'static str,
}

/// A slot taken; dropping it gives it back.
pub struct Slot {
    st: Arc<Mutex<(usize, HashMap<String, usize>)>>,
    who: String,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        st.0 -= 1;
        if let Some(n) = st.1.get_mut(&self.who) {
            *n -= 1;
            if *n == 0 {
                st.1.remove(&self.who);
            }
        }
    }
}

impl CallerSlots {
    fn new(limit: usize, per_caller: usize, busy: &'static str) -> CallerSlots {
        CallerSlots {
            st: Arc::default(),
            limit,
            per_caller,
            busy,
        }
    }

    pub fn searches() -> CallerSlots {
        CallerSlots::new(MAX_SEARCHES, MAX_SEARCHES_PER_CALLER, BUSY_SEARCHES)
    }

    pub fn live() -> CallerSlots {
        CallerSlots::new(MAX_LIVE_LOGS, MAX_LIVE_LOGS_PER_CALLER, BUSY_LIVE)
    }

    fn take(&self, who: &str) -> Result<Slot, Status> {
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        if st.0 >= self.limit || st.1.get(who).copied().unwrap_or(0) >= self.per_caller {
            return Err(Status::new(Code::ResourceExhausted, self.busy));
        }
        st.0 += 1;
        *st.1.entry(who.to_string()).or_default() += 1;
        Ok(Slot {
            st: self.st.clone(),
            who: who.to_string(),
        })
    }
}

struct Pending {
    node: String,
    push: mpsc::Sender<LogPush>,
    attached: oneshot::Sender<()>,
}

/// logRouter: pairs log requests with the agent streams that serve them.
#[derive(Default)]
pub struct LogRouter {
    pending: Mutex<HashMap<String, Pending>>,
}

impl LogRouter {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pending>> {
        self.pending.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn register(&self, node: &str) -> (String, mpsc::Receiver<LogPush>, oneshot::Receiver<()>) {
        let id = crate::random_id(20);
        let (push, rx) = mpsc::channel(16);
        let (attached, att) = oneshot::channel();
        self.lock().insert(
            id.clone(),
            Pending {
                node: node.to_string(),
                push,
                attached,
            },
        );
        (id, rx, att)
    }

    /// attach: claims a pending request for node, once and only by the
    /// node it was sent to.
    fn attach(&self, id: &str, node: &str) -> Option<mpsc::Sender<LogPush>> {
        let mut m = self.lock();
        match m.get(id) {
            Some(p) if p.node == node => {}
            _ => return None,
        }
        let p = m.remove(id)?;
        let _ = p.attached.send(());
        Some(p.push)
    }

    fn cancel(&self, id: &str) {
        self.lock().remove(id);
    }
}

/// The lower case Go's strings.ToLower makes, rune by rune.
fn lower(s: &str) -> String {
    s.chars()
        .map(|c| c.to_lowercase().next().unwrap_or(c))
        .collect()
}

/// runtime.ContainsFold: whether line holds needle (lower case), ignoring
/// case.
fn contains_fold(line: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.iter().any(|c| *c >= 0x80) {
        // bytes.ToLower: invalid bytes become U+FFFD one by one.
        let mut s = String::new();
        for chunk in line.utf8_chunks() {
            s.push_str(&lower(chunk.valid()));
            for _ in chunk.invalid() {
                s.push('\u{FFFD}');
            }
        }
        return s.as_bytes().windows(needle.len()).any(|w| w == needle);
    }
    line.windows(needle.len()).any(|w| {
        w.iter()
            .zip(needle)
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
    })
}

/// replicaOf: whether id has the form of a replica ID of app:
/// <app>-r<seq>-... or <app>-j<run>-....
fn replica_of(id: &str, app: &str) -> bool {
    let Some(rest) = id.strip_prefix(app).and_then(|r| r.strip_prefix('-')) else {
        return false;
    };
    let b = rest.as_bytes();
    b.len() >= 2 && (b[0] == b'r' || b[0] == b'j') && b[1].is_ascii_digit()
}

fn time_of(t: &Timestamp) -> Time {
    Time {
        unix: t.seconds,
        nsec: i64::from(t.nanos),
        loc: armada_spec::gotime::Location::utc(),
    }
}

fn cmp_ts(a: &Option<Timestamp>, b: &Option<Timestamp>) -> std::cmp::Ordering {
    let k = |t: &Option<Timestamp>| t.as_ref().map_or((0, 0), |t| (t.seconds, t.nanos));
    k(a).cmp(&k(b))
}

/// The wall clock, as Go's time.Now in searchMatch.
fn wall_now() -> Time {
    armada_store::gojson::now()
}

/// searchMatch: whether a node's entry answers q.
fn search_match(q: &LogQuery, m: &LogPush, now: &Time) -> bool {
    let r = &m.replica;
    if !replica_of(r, &q.app) || (!q.replica.is_empty() && *r != q.replica) {
        return false;
    }
    let t = m.time.as_ref().map(time_of).unwrap_or_else(Time::zero);
    let since = q.since.as_ref().map(time_of).unwrap_or_else(Time::zero);
    if t.before(&since) || t.after(&now.add(SEARCH_SKEW)) {
        return false;
    }
    q.until.as_ref().is_none_or(|u| !t.after(&time_of(u)))
}

fn notice(replica: &str, msg: &str) -> LogEntry {
    LogEntry {
        replica: replica.to_string(),
        stream: Stream::Stderr as i32,
        data: format!("[armada] {msg}\n").into_bytes(),
        time: None,
    }
}

fn not_zero(n: &i64) -> bool {
    *n == 0
}

/// The meta record of the cluster's log settings (Go's logSettings).
#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct LogSettingsRec {
    #[serde(rename = "retentionSeconds", default, skip_serializing_if = "not_zero")]
    pub retention_seconds: i64,
    #[serde(rename = "maxBytes", default, skip_serializing_if = "not_zero")]
    pub max_bytes: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub export: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tenant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<SealedJson>,
    #[serde(rename = "tokenVersion", default, skip_serializing_if = "not_zero")]
    pub token_version: i64,
    #[serde(rename = "setAt", default, skip_serializing_if = "not_zero")]
    pub set_at: i64,
}

fn invalid(e: impl Into<String>) -> Status {
    Status::new(Code::InvalidArgument, e.into())
}

/// CheckLogRetention (seconds); 0 means the default.
fn check_log_retention(secs: i64) -> Result<(), String> {
    if secs != 0 && !(MIN_LOG_RETENTION..=MAX_LOG_RETENTION).contains(&secs) {
        return Err(
            "log retention must be between 1h0m0s and 90 days (0 for the default, 7 days)".into(),
        );
    }
    Ok(())
}

/// CheckLogMaxBytes; 0 means the default.
fn check_log_max_bytes(n: i64) -> Result<(), String> {
    if n != 0 && !(MIN_LOG_MAX_BYTES..=MAX_LOG_MAX_BYTES).contains(&n) {
        return Err(
            "log history size must be between 64Mi and 1Ti per node (0 for the default)".into(),
        );
    }
    Ok(())
}

/// logexport.CheckToken.
fn check_token(t: &[u8]) -> Result<(), String> {
    if t.len() > MAX_TOKEN {
        return Err(format!("log token is longer than {MAX_TOKEN} bytes"));
    }
    if t.iter().any(|b| *b < 0x20 || *b == 0x7f) {
        return Err("log token must be one line of printable characters".into());
    }
    Ok(())
}

fn check_name(what: &str, v: &str) -> Result<(), String> {
    if v.len() > MAX_NAME {
        return Err(format!("log export {what} is longer than {MAX_NAME} bytes"));
    }
    if v.chars().any(|r| r < '\u{21}' || r == '\u{7f}' || r == ':') {
        return Err(format!(
            "log export {what} must be printable, with no spaces or colons"
        ));
    }
    Ok(())
}

/// logexport.CheckEndpoint.
fn check_endpoint(raw: &str) -> Result<(), String> {
    if raw.is_empty() {
        return Err("log export needs --log-endpoint, the push URL".into());
    }
    if raw.len() > MAX_ENDPOINT {
        return Err("log endpoint is too long".into());
    }
    let fragment = raw.split_once('#').is_some_and(|(_, f)| !f.is_empty());
    let u = match armada_node::queue::url::parse(raw) {
        Ok(u) if !u.host.is_empty() && u.opaque.is_empty() && !fragment => u,
        _ => {
            return Err(
                "log endpoint must be a URL such as https://logs.example.com/loki/api/v1/push"
                    .into(),
            );
        }
    };
    if u.user.is_some() || !u.raw_query.is_empty() {
        return Err(
            "log endpoint must not hold credentials or a query; use --log-export-user and --log-token"
                .into(),
        );
    }
    match u.scheme.as_str() {
        "https" => Ok(()),
        "http" => {
            let ok = std::str::from_utf8(u.hostname())
                .ok()
                .and_then(armada_spec::go::parse_addr)
                .is_some_and(|ip| {
                    let ip = ip.unmap();
                    let loopback = if ip.is4 {
                        ip.bytes[0] == 127
                    } else {
                        ip.bytes[..15].iter().all(|b| *b == 0) && ip.bytes[15] == 1
                    };
                    ip.is_private() || loopback
                });
            if ok {
                Ok(())
            } else {
                Err(
                    "http:// log endpoints are only allowed for a private IP address; use https://"
                        .into(),
                )
            }
        }
        _ => Err("log endpoint must start with https://".into()),
    }
}

/// logexport.Config.Check.
fn check_export(ls: &LogSettingsRec, token: bool) -> Result<(), String> {
    let f = &ls.export;
    if !f.is_empty() && f != "loki" && f != "otlp" {
        return Err(format!(
            "unsupported log export {} (want loki, otlp, or none)",
            armada_spec::go::quote(f)
        ));
    }
    if f.is_empty() {
        return Ok(());
    }
    check_endpoint(&ls.endpoint)?;
    check_name("user", &ls.user)?;
    check_name("tenant", &ls.tenant)?;
    if !ls.tenant.is_empty() && f != "loki" {
        return Err("a log tenant is only for loki".into());
    }
    if !ls.user.is_empty() && !token {
        return Err("a log export user needs a token: --log-token - < FILE".into());
    }
    Ok(())
}

fn trim(s: &str) -> String {
    armada_spec::go::trim_space(s).to_string()
}

impl Server {
    pub(crate) async fn log_settings(&self) -> Result<LogSettingsRec, armada_store::Error> {
        match crate::settings::read_meta(self.store(), META_LOGS).await? {
            None => Ok(LogSettingsRec::default()),
            Some(v) => serde_json::from_value(v)
                .map_err(|e| armada_store::Error::other(format!("log settings: {e}"))),
        }
    }

    /// setLogSettings: stores the log settings the request names; they
    /// reach the agents with the next assignments.
    pub(crate) async fn set_log_settings(
        &self,
        a: &Auth,
        req: &SetClusterConfigRequest,
    ) -> Result<(), Status> {
        if !req.set_log_retention
            && !req.set_log_max_bytes
            && !req.set_log_export
            && !req.set_log_token
        {
            return Ok(());
        }
        let mut ls = self.log_settings().await.map_err(|e| store_err(&e))?;
        let c = req.config.clone().unwrap_or_default();
        if req.set_log_retention {
            check_log_retention(c.log_retention_seconds).map_err(invalid)?;
            ls.retention_seconds = c.log_retention_seconds;
        }
        if req.set_log_max_bytes {
            check_log_max_bytes(c.log_max_bytes).map_err(invalid)?;
            ls.max_bytes = c.log_max_bytes;
        }
        self.set_log_export(req, &c, &mut ls)?;
        let b =
            serde_json::to_string(&ls).map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        self.store()
            .set_meta(META_LOGS, &b)
            .await
            .map_err(|e| store_err(&e))?;
        let export = if ls.export.is_empty() {
            "none"
        } else {
            ls.export.as_str()
        };
        let mut what = format!(
            "retention={}s max_bytes={} export={export}",
            ls.retention_seconds, ls.max_bytes
        );
        if !ls.export.is_empty() {
            what.push_str(&format!(" endpoint={}", ls.endpoint));
        }
        if req.set_log_token {
            what.push_str(" token");
        }
        self.store()
            .record_audit(&a.actor(), "cluster.logs", "cluster", &what)
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "log settings changed",
            &[
                ("retention_seconds", ls.retention_seconds.to_string()),
                ("max_bytes", ls.max_bytes.to_string()),
                ("export", export.to_string()),
                ("by", a.actor()),
            ],
        );
        Ok(())
    }

    /// setLogExport: the request's log export and token (ADR 0044).
    fn set_log_export(
        &self,
        req: &SetClusterConfigRequest,
        c: &ClusterConfig,
        ls: &mut LogSettingsRec,
    ) -> Result<(), Status> {
        if req.set_log_export {
            let mut format = trim(&c.log_export);
            if format == "none" {
                format.clear();
            }
            ls.export = format.clone();
            ls.endpoint = trim(&c.log_endpoint);
            ls.user = trim(&c.log_export_user);
            ls.tenant = trim(&c.log_export_tenant);
            let now = self.now();
            ls.set_at = now.unix * 1_000_000_000 + now.nsec;
            if format.is_empty() {
                *ls = LogSettingsRec {
                    retention_seconds: ls.retention_seconds,
                    max_bytes: ls.max_bytes,
                    ..Default::default()
                };
            }
        }
        if req.set_log_token {
            let token = armada_node::gostr::trim_space(&req.log_token).to_vec();
            check_token(&token).map_err(invalid)?;
            if token.is_empty() {
                ls.token = None;
            } else {
                let Some(keys) = &self.0.keys else {
                    return Err(Status::new(
                        Code::FailedPrecondition,
                        "this server has no master key to encrypt the token with",
                    ));
                };
                let sealed = keys
                    .seal(
                        TOKEN_SCOPE,
                        LOG_TOKEN_NAME,
                        ls.token_version + 1,
                        &armada_secrets::Value::new(&token),
                    )
                    .map_err(|_| Status::new(Code::Internal, "seal the log token"))?;
                ls.token_version += 1;
                ls.token = Some(SealedJson::of(&sealed));
            }
        }
        if ls.export.is_empty() {
            if ls.token.is_some() {
                return Err(Status::new(
                    Code::FailedPrecondition,
                    "a log token needs a log export: --log-export loki|otlp --log-endpoint URL",
                ));
            }
            return Ok(());
        }
        check_export(ls, ls.token.is_some()).map_err(invalid)
    }

    /// One prune of the placement records (Go's placementLoop body).
    pub async fn prune_placements(&self) -> Result<i64, armada_store::Error> {
        let ls = self.log_settings().await?;
        let keep = if ls.retention_seconds > 0 {
            ls.retention_seconds
        } else {
            DEFAULT_LOG_RETENTION
        };
        let before = self.now().add(-(keep + PLACEMENT_MARGIN) * 1_000_000_000);
        self.store().prune_placements(&before).await
    }

    /// placementLoop: prunes the records of where replicas ran (ADR 0043)
    /// once they are older than any history a node keeps.
    pub(crate) async fn placement_loop(&self, mut shutdown: watch::Receiver<bool>) {
        loop {
            tokio::select! {
                _ = crate::stopped(&mut shutdown) => return,
                _ = tokio::time::sleep(PLACEMENT_PRUNE) => {}
            }
            if let Err(e) = self.prune_placements().await
                && !*shutdown.borrow()
            {
                self.0
                    .log
                    .warn("prune placements", &[("err", e.to_string())]);
            }
        }
    }

    /// PushLogs: the log stream for a pending request, from the agent it
    /// was asked of.
    pub(crate) async fn push_logs(
        &self,
        request: Request<Streaming<LogPush>>,
    ) -> Result<Response<PushLogsResponse>, Status> {
        let a = auth(&request)?;
        let mut inbound = request.into_inner();
        let Some(first) = inbound.message().await? else {
            return Err(Status::new(Code::Unknown, "EOF"));
        };
        let Some(tx) = self.0.logs.attach(&first.request_id, &a.id.name) else {
            return Err(Status::new(Code::PermissionDenied, "unknown log request"));
        };
        let rid = first.request_id.clone();
        let mut msg = first;
        loop {
            if tx.send(msg).await.is_err() {
                // The requester is done.
                return Ok(Response::new(PushLogsResponse {}));
            }
            msg = match inbound.message().await? {
                None => return Ok(Response::new(PushLogsResponse {})),
                Some(m) => m,
            };
            if !msg.request_id.is_empty() && msg.request_id != rid {
                return Err(Status::new(
                    Code::InvalidArgument,
                    "request_id changed mid-stream",
                ));
            }
        }
    }

    /// runReplica: the replica of a job's run (the newest, or seq) to read
    /// logs from, or of one of its tasks.
    async fn run_replica(&self, job: &str, seq: i64, task: Option<i32>) -> Result<String, Status> {
        let runs = self
            .store()
            .list_job_runs(job)
            .await
            .map_err(|e| store_err(&e))?;
        let kept = crate::jobs::JOB_LOGS_KEPT;
        for r in runs.iter().rev() {
            if seq != 0 && r.seq != seq {
                continue;
            }
            if r.replica.is_empty() {
                return Err(Status::new(
                    Code::FailedPrecondition,
                    format!("run {} of {job} has not started", r.seq),
                ));
            }
            if !r.active() && !self.now().before(&r.finished_at.add(kept)) {
                return Err(Status::new(
                    Code::NotFound,
                    format!(
                        "the logs of run {} of {job} were removed {} after it finished",
                        r.seq,
                        armada_spec::go::format_duration(kept)
                    ),
                ));
            }
            let Some(i) = task else {
                return Ok(r.replica.clone());
            };
            if i < 0 || i as usize >= r.tasks.len() {
                return Err(Status::new(
                    Code::InvalidArgument,
                    format!(
                        "run {} of {job} has no task {i} (it has {})",
                        r.seq,
                        r.tasks.len()
                    ),
                ));
            }
            let t = &r.tasks[i as usize];
            if t.replica.is_empty() {
                return Err(Status::new(
                    Code::FailedPrecondition,
                    format!("task {i} of run {} of {job} has not started", r.seq),
                ));
            }
            return Ok(t.replica.clone());
        }
        if seq != 0 {
            return Err(Status::new(
                Code::NotFound,
                format!(
                    "run {seq} of {job} not found (finished runs beyond the job's history are removed)"
                ),
            ));
        }
        Err(Status::new(
            Code::FailedPrecondition,
            format!("{job} has no runs yet; start one with `armada job start {job}`"),
        ))
    }

    /// Logs: an app's output, live from each replica's node, or searched in
    /// every node's log history.
    pub(crate) async fn logs(
        &self,
        request: Request<LogsRequest>,
    ) -> Result<Response<Out<LogEntry>>, Status> {
        let a = auth(&request)?;
        let req = request.into_inner();
        let app = req.app.clone();
        let guard = self.stream_guard(
            &a,
            "/armada.v1.AdminService/Logs",
            Box::new(move |acc| acc.app(&app)),
        )?;
        let (tx, rx) = mpsc::channel::<Result<LogEntry, Status>>(64);
        // Ends what the call waits for: the caller gone, or the guard.
        let (stop_tx, stop) = watch::channel(false);
        {
            let (tx, guard, stop_tx) = (tx.clone(), guard.clone(), stop_tx.clone());
            tokio::spawn(async move {
                let cancelled = async {
                    match &guard {
                        Some(g) => g.cancelled().await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    _ = tx.closed() => {}
                    _ = cancelled => {}
                    _ = stop_tx.closed() => {}
                }
                stop_tx.send_replace(true);
            });
        }
        let srv = self.clone();
        tokio::spawn(async move {
            let res = srv.serve_logs(&a, req, guard.clone(), &tx, stop).await;
            stop_tx.send_replace(true);
            let err = guard.as_ref().and_then(|g| g.ended()).or(res.err());
            if let Some(e) = err {
                let _ = tx.send(Err(e)).await;
            }
            if let Some(g) = &guard {
                g.stop();
            }
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }

    async fn serve_logs(
        &self,
        a: &Auth,
        mut req: LogsRequest,
        guard: Option<Arc<Guard>>,
        tx: &mpsc::Sender<Result<LogEntry, Status>>,
        mut stop: watch::Receiver<bool>,
    ) -> Result<(), Status> {
        let app = self
            .store()
            .get_app(&req.app)
            .await
            .map_err(|e| store_err(&e))?;
        let mut reps = self
            .store()
            .list_replicas(&ReplicaFilter {
                app: req.app.clone(),
                ..Default::default()
            })
            .await
            .map_err(|e| store_err(&e))?;
        check_container_name(&req.container)?;
        let search = req.since.is_some();
        if !search && (req.until.is_some() || req.limit != 0) {
            return Err(invalid(
                "--until and --limit search the log history: give --since too",
            ));
        }
        if !req.replica.is_empty() {
            // A replica's short name, or its ID; the log history also
            // holds replicas that are gone, by ID.
            match find_replica(&app.name, &reps, &req.replica) {
                Ok(r) => req.replica = r.id,
                Err(e) if !search => return Err(e),
                Err(_) => {}
            }
        }
        let is_job = app.spec.as_ref().is_some_and(|s| s.is_job());
        if req.run != 0 && !is_job {
            return Err(invalid(format!(
                "{} is an app; --run is for jobs",
                app.name
            )));
        }
        if is_job && req.replica.is_empty() && (!search || req.run != 0 || req.task.is_some()) {
            req.replica = self.run_replica(&app.name, req.run, req.task).await?;
        }
        if search {
            self.search_logs(a, &app.name, &req, tx, stop.clone())
                .await?;
            if !req.follow {
                return Ok(());
            }
            // Live output follows, from now.
            req.tail = -1;
        }
        if !req.replica.is_empty() {
            let only: Vec<Replica> = reps
                .iter()
                .filter(|r| r.id == req.replica)
                .cloned()
                .collect();
            if only.is_empty() {
                find_replica(&app.name, &reps, &req.replica)?;
            }
            reps = only;
        }
        if !search && !is_job {
            // Containers of the replicas being read; a job's are its spec's.
            let mut revs: Vec<String> = Vec::new();
            for r in &reps {
                if !revs.contains(&r.revision) {
                    revs.push(r.revision.clone());
                }
            }
            if revs.is_empty() {
                revs.push(app.target_revision.clone());
            }
            self.check_container(&app.name, &req.container, &revs, false)
                .await?;
        }
        // Each call holds a relay per replica and a stream on every node.
        let _slot = self.0.live_logs.take(&a.actor())?;
        let tail = match req.tail {
            t if t > 0 => t.min(MAX_LOG_TAIL),
            t if t < 0 => -1,
            _ => DEFAULT_LOG_TAIL,
        };
        let grep = lower(&req.grep);
        let (out_tx, mut out) = mpsc::channel::<LogEntry>(64);
        let (relays_stop, relays) = watch::channel(false);
        let mut following: HashSet<String> = HashSet::new();
        let relay = |r: Replica,
                     tail: i32,
                     following: &mut HashSet<String>,
                     out: &mpsc::Sender<LogEntry>| {
            following.insert(r.id.clone());
            let (srv, out, stop) = (self.clone(), out.clone(), relays.clone());
            let (container, grep, follow) = (req.container.clone(), grep.clone(), req.follow);
            tokio::spawn(async move {
                srv.relay_logs(r, container, follow, tail, grep, out, stop)
                    .await;
            });
        };
        for r in reps {
            relay(r, tail, &mut following, &out_tx);
        }
        // Following a whole app also follows the replicas it gets later;
        // otherwise the stream ends once every relay did.
        let scanning = req.follow && req.replica.is_empty();
        let keep = scanning.then_some(out_tx);
        let mut scan =
            tokio::time::interval_at(tokio::time::Instant::now() + FOLLOW_SCAN, FOLLOW_SCAN);
        let res = async {
            loop {
                tokio::select! {
                    e = out.recv() => {
                        let Some(e) = e else { return Ok(()) };
                        if tx.send(Ok(e)).await.is_err() {
                            return Ok(());
                        }
                    }
                    _ = scan.tick(), if scanning => {
                        let Ok(now) = self.store().list_replicas(&ReplicaFilter { app: req.app.clone(), ..Default::default() }).await else {
                            continue;
                        };
                        let mut rechecked = false;
                        for r in now {
                            // Only once its container runs.
                            if !following.contains(&r.id) && r.state == REPLICA_RUNNING {
                                // The caller's access, as of now, before a
                                // new replica's output reaches it.
                                if !rechecked {
                                    if let Some(g) = &guard {
                                        g.recheck().await?;
                                    }
                                    rechecked = true;
                                }
                                if let Some(k) = &keep {
                                    relay(r, DEFAULT_LOG_TAIL, &mut following, k);
                                }
                            }
                        }
                    }
                    _ = crate::stopped(&mut stop) => return Ok(()),
                }
            }
        }
        .await;
        relays_stop.send_replace(true);
        res
    }

    /// relayLogs: a replica's output to out, lines holding grep (lower
    /// case; empty for all), stamped with when they were written.
    #[allow(clippy::too_many_arguments)]
    async fn relay_logs(
        &self,
        r: Replica,
        container: String,
        follow: bool,
        tail: i32,
        grep: String,
        out: mpsc::Sender<LogEntry>,
        mut stop: watch::Receiver<bool>,
    ) {
        let stop_note = stop.clone();
        let note = |msg: String| {
            let (out, id) = (out.clone(), r.id.clone());
            let mut stop = stop_note.clone();
            async move {
                tokio::select! {
                    _ = out.send(notice(&id, &msg)) => {}
                    _ = crate::stopped(&mut stop) => {}
                }
            }
        };
        let Some(sess) = self.session(&r.node_id) else {
            note(format!("node {} is not connected", r.node_id)).await;
            return;
        };
        let (id, mut rx, attached) = self.0.logs.register(&r.node_id);
        let req = LogRequest {
            request_id: id.clone(),
            replica_id: r.id.clone(),
            follow,
            tail,
            container,
            query: None,
            grep: grep.clone(),
        };
        if !sess
            .offer(
                ServerMessage {
                    msg: Some(Msg::LogRequest(req)),
                },
                OFFER_TIMEOUT,
            )
            .await
        {
            self.0.logs.cancel(&id);
            note(format!("node {} did not accept the log request", r.node_id)).await;
            return;
        }
        let ok = tokio::select! {
            a = tokio::time::timeout(ATTACH_TIMEOUT, attached) => {
                if !matches!(a, Ok(Ok(()))) {
                    note(format!("node {} did not send logs", r.node_id)).await;
                }
                matches!(a, Ok(Ok(())))
            }
            _ = crate::stopped(&mut stop) => false,
        };
        if ok {
            loop {
                let m = tokio::select! {
                    m = rx.recv() => m,
                    _ = crate::stopped(&mut stop) => break,
                };
                let Some(m) = m else { break };
                if !m.error.is_empty() {
                    note(m.error.clone()).await;
                    continue;
                }
                // Older agents do not filter.
                if m.data.is_empty() || !contains_fold(&m.data, grep.as_bytes()) {
                    continue;
                }
                let at = m.time.unwrap_or_else(|| timestamp(&self.now()));
                let e = LogEntry {
                    replica: r.id.clone(),
                    stream: m.stream,
                    data: m.data,
                    time: Some(at),
                };
                tokio::select! {
                    res = out.send(e) => if res.is_err() { break },
                    _ = crate::stopped(&mut stop) => break,
                }
            }
        }
        self.0.logs.cancel(&id);
        drop(rx);
        sess.offer(
            ServerMessage {
                msg: Some(Msg::LogCancel(LogCancel { request_id: id })),
            },
            OFFER_TIMEOUT,
        )
        .await;
    }

    /// searchSessions: the connected agents that keep a log history.
    fn search_sessions(&self) -> Vec<Arc<Session>> {
        let mut out: Vec<Arc<Session>> = self
            .sessions()
            .into_iter()
            .filter(|s| s.caps.log_history)
            .collect();
        out.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        out
    }

    /// searchLogs: asks every node that keeps a log history for app's
    /// entries in the request's window and sends the newest limit of
    /// them, oldest first, then the nodes' notices.
    async fn search_logs(
        &self,
        a: &Auth,
        app: &str,
        req: &LogsRequest,
        tx: &mpsc::Sender<Result<LogEntry, Status>>,
        stop: watch::Receiver<bool>,
    ) -> Result<(), Status> {
        let limit = if req.limit > 0 {
            req.limit.min(MAX_SEARCH_LIMIT)
        } else {
            DEFAULT_SEARCH_LIMIT
        };
        let since_t = req.since.as_ref().map(time_of).unwrap_or_else(Time::zero);
        if let Some(u) = &req.until
            && time_of(u).before(&since_t)
        {
            return Err(invalid("--until is before --since"));
        }
        let _slot = self.0.searches.take(&a.actor())?;
        let mut since = req.since;
        if !a.acc.admin() {
            // History from before the app's space was created belongs to
            // an earlier space of the same name.
            let created = self.spaces_created().await?;
            if before_space(&created, app, &since_t)
                && let Some((sp, _)) = armada_spec::validate::split_app_id(app)
                && let Some(c) = created.get(&sp)
            {
                since = Some(timestamp(c));
            }
        }
        let q = LogQuery {
            app: app.to_string(),
            replica: req.replica.clone(),
            container: req.container.clone(),
            since,
            until: req.until,
            grep: req.grep.clone(),
            limit,
        };
        let deadline = tokio::time::Instant::now() + SEARCH_WAIT;
        let sessions = self.search_sessions();
        if sessions.is_empty() {
            return Err(Status::new(
                Code::FailedPrecondition,
                "no connected node keeps a log history (upgrade the nodes)",
            ));
        }
        // A node answers only for the app's replicas placed on it.
        let placed = Arc::new(
            self.store()
                .replica_placements(app)
                .await
                .map_err(|e| store_err(&e))?,
        );
        let mut tasks = Vec::new();
        for sess in sessions {
            let (srv, q, placed, stop) = (self.clone(), q.clone(), placed.clone(), stop.clone());
            tasks.push(tokio::spawn(async move {
                let node = sess.node_id.clone();
                let (got, msg) = srv.search_node(sess, q, placed, deadline, stop).await;
                (node, got, msg)
            }));
        }
        let mut entries: Vec<LogEntry> = Vec::new();
        let mut notices: Vec<String> = Vec::new();
        for t in tasks {
            if let Ok((node, got, msg)) = t.await {
                if !msg.is_empty() {
                    notices.push(format!("node {node}: {msg}"));
                }
                entries.extend(got);
            }
        }
        entries.sort_by(|a, b| cmp_ts(&a.time, &b.time));
        let limit = limit as usize;
        if entries.len() > limit {
            entries.drain(..entries.len() - limit);
        }
        for e in entries {
            if tx.send(Ok(e)).await.is_err() {
                return Ok(());
            }
        }
        notices.sort();
        for n in notices {
            if tx.send(Ok(notice("", &n))).await.is_err() {
                return Ok(());
            }
        }
        Ok(())
    }

    /// searchNode: one node's part of a search, and a notice, if any.
    async fn search_node(
        &self,
        sess: Arc<Session>,
        q: LogQuery,
        placed: Arc<BTreeMap<String, String>>,
        deadline: tokio::time::Instant,
        mut stop: watch::Receiver<bool>,
    ) -> (Vec<LogEntry>, String) {
        let node = sess.node_id.clone();
        let (id, mut rx, attached) = self.0.logs.register(&node);
        let msg = ServerMessage {
            msg: Some(Msg::LogRequest(LogRequest {
                request_id: id.clone(),
                query: Some(q.clone()),
                ..Default::default()
            })),
        };
        if !sess.offer(msg, OFFER_TIMEOUT).await {
            self.0.logs.cancel(&id);
            return (Vec::new(), "did not accept the search".into());
        }
        let mut out: Vec<LogEntry> = Vec::new();
        let mut bytes = 0usize;
        let mut full = String::new();
        let res: Result<(), String> = async {
            tokio::select! {
                a = attached => if a.is_err() { return Err("did not answer".into()) },
                _ = tokio::time::sleep(ATTACH_TIMEOUT) => return Err("did not answer".into()),
                _ = tokio::time::sleep_until(deadline) => return Err("did not answer in time".into()),
                _ = crate::stopped(&mut stop) => return Err("did not answer in time".into()),
            }
            loop {
                let m = tokio::select! {
                    m = rx.recv() => m,
                    _ = tokio::time::sleep_until(deadline) => return Err("did not finish in time".into()),
                    _ = crate::stopped(&mut stop) => return Err("did not finish in time".into()),
                };
                let Some(m) = m else { return Ok(()) };
                if !m.error.is_empty() {
                    return Err(m.error);
                }
                // A node's answer is trusted only for the query it was
                // asked: the app's replicas that ran on this node, inside
                // the window.
                if m.data.is_empty()
                    || m.time.is_none()
                    || out.len() >= MAX_SEARCH_LIMIT as usize
                    || placed.get(&m.replica) != Some(&node)
                    || !search_match(&q, &m, &wall_now())
                {
                    continue;
                }
                if bytes + m.data.len() > MAX_SEARCH_NODE_BYTES {
                    full = format!(
                        "stopped at {} MiB of output; narrow the search",
                        MAX_SEARCH_NODE_BYTES >> 20
                    );
                    continue;
                }
                bytes += m.data.len();
                out.push(LogEntry {
                    replica: m.replica,
                    stream: m.stream,
                    data: m.data,
                    time: m.time,
                });
            }
        }
        .await;
        self.0.logs.cancel(&id);
        drop(rx);
        sess.offer(
            ServerMessage {
                msg: Some(Msg::LogCancel(LogCancel { request_id: id })),
            },
            OFFER_TIMEOUT,
        )
        .await;
        match res {
            Ok(()) => (out, full),
            Err(e) => (out, e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replica_ids() {
        assert!(replica_of("web-r1-abc", "web"));
        assert!(replica_of("web-j12-t0-abc", "web"));
        assert!(!replica_of("web-api-r1-abc", "web"));
        assert!(!replica_of("web-rx", "web"));
        assert!(!replica_of("web", "web"));
    }

    #[test]
    fn fold() {
        assert!(contains_fold(b"An ERROR here", b"error"));
        assert!(!contains_fold(b"fine", b"error"));
        assert!(contains_fold(b"x", b""));
        assert!(contains_fold("ÄBC".as_bytes(), "äb".as_bytes()));
    }

    #[test]
    fn matches_the_window() {
        let ts = |s: i64| {
            Some(Timestamp {
                seconds: s,
                nanos: 0,
            })
        };
        let q = LogQuery {
            app: "web".into(),
            since: ts(100),
            until: ts(200),
            ..Default::default()
        };
        let m = |r: &str, t: i64| LogPush {
            replica: r.into(),
            time: ts(t),
            ..Default::default()
        };
        let now = time_of(&Timestamp {
            seconds: 1000,
            nanos: 0,
        });
        assert!(search_match(&q, &m("web-r1-a", 150), &now));
        assert!(search_match(&q, &m("web-r1-a", 200), &now));
        assert!(!search_match(&q, &m("web-r1-a", 99), &now));
        assert!(!search_match(&q, &m("web-r1-a", 201), &now));
        assert!(!search_match(&q, &m("api-r1-a", 150), &now));
        let open = LogQuery { until: None, ..q };
        assert!(!search_match(&open, &m("web-r1-a", 1061), &now));
        assert!(search_match(&open, &m("web-r1-a", 1060), &now));
    }

    #[test]
    fn slots() {
        let s = CallerSlots::searches();
        let a = s.take("a").unwrap();
        let _b = s.take("a").unwrap();
        assert_eq!(s.take("a").err().unwrap().code(), Code::ResourceExhausted);
        let _c = s.take("b").unwrap();
        let _d = s.take("c").unwrap();
        assert!(s.take("d").is_err());
        drop(a);
        assert!(s.take("d").is_ok());
    }

    #[test]
    fn export_checks() {
        let ls = |e: &str, ep: &str| LogSettingsRec {
            export: e.into(),
            endpoint: ep.into(),
            ..Default::default()
        };
        assert!(check_export(&ls("loki", "https://l.example/x"), false).is_ok());
        assert!(check_export(&ls("loki", "http://10.0.0.5:3100/x"), false).is_ok());
        assert!(check_export(&ls("loki", "http://127.0.0.1/x"), false).is_ok());
        assert!(check_export(&ls("loki", "http://203.0.113.1/x"), false).is_err());
        assert!(check_export(&ls("loki", "https://u:p@l.example/x"), false).is_err());
        assert!(check_export(&ls("loki", "https://l.example/x?a=b"), false).is_err());
        assert!(check_export(&ls("loki", "https://l.example/x#f"), false).is_err());
        assert!(check_export(&ls("syslog", "https://l.example"), false).is_err());
        assert!(check_export(&ls("loki", ""), false).is_err());
        assert!(check_log_retention(60).is_err());
        assert!(check_log_retention(0).is_ok());
        assert!(check_log_max_bytes(1).is_err());
    }
}

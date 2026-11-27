//! The metrics endpoint (ADR 0017): `GET /metrics` on
//! the metrics listener, TLS 1.3 with the API's server certificate, only
//! to metrics certificates on record and to users or services with
//! cluster-admin; the leader's counters, and the cluster's metrics read
//! from the same sources as `armada app show` and `armada app top`, at
//! most once per `metrics_cache`. The text is Prometheus' text format
//! (families by name, samples by label values, labels by name, floats in
//! their shortest form).

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use armada_pki::{Identity, KIND_METRICS, KIND_SERVICE, parse_identity};
use armada_proto::armada::v1::{
    AppStatus, IssueMetricsCertificateRequest, IssueMetricsCertificateResponse,
    ListMetricsCredentialsRequest, ListMetricsCredentialsResponse, ListVolumesRequest,
    MetricsCertificate, MetricsCredential, RevokeMetricsCredentialsRequest,
    RevokeMetricsCredentialsResponse, StatusRequest, TopRequest,
};
use armada_spec::gotime::Time;
use armada_store::jobs::RUN_SUCCEEDED;
use armada_store::{
    Grant, NODE_READY, REPLICA_EXITED, REPLICA_FAILED, REPLICA_PENDING, REPLICA_PULLED,
    REPLICA_PULLING, REPLICA_RUNNING, REPLICA_STARTING, ROLE_CLUSTER_ADMIN, ROLLOUT_FAILED,
    ROLLOUT_PROGRESSING,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tonic::{Code, Status};

use crate::access::Access;
use crate::events::timestamp;
use crate::grpc::{Auth, cert_time};
use crate::reconcile::sub;
use crate::{Server, store_err};

/// How long gathered metrics answer further scrapes.
pub const METRICS_CACHE_FOR: Duration = Duration::from_secs(10);
/// Bounds the store reads of one scrape.
const METRICS_TIMEOUT: Duration = Duration::from_secs(10);
const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HEADER_BYTES: usize = 16 << 10;

/// The reconcile histogram's buckets: ExponentialBuckets(0.005, 2, 12).
fn buckets() -> Vec<f64> {
    (0..12).map(|i| 0.005 * f64::powi(2.0, i)).collect()
}

/// A histogram's counts.
struct Hist {
    counts: Vec<u64>,
    sum: f64,
    count: u64,
}

/// The leader's counters: reconcile durations and errors, events, job
/// runs, alerts, and control plane backup failures.
pub(crate) struct Metrics {
    reconcile: Mutex<Hist>,
    reconcile_errors: AtomicU64,
    events: Mutex<BTreeMap<(String, String), u64>>,
    job_runs: Mutex<BTreeMap<(String, String), u64>>,
    alerts_sent: Mutex<BTreeMap<String, u64>>,
    alerts_failed: Mutex<BTreeMap<String, u64>>,
    alerts_dropped: Mutex<BTreeMap<String, u64>>,
    cp_failures: AtomicU64,
    /// The last gathering and when (the server's clock); one gathering at
    /// a time, scrapes that arrive meanwhile wait for it.
    cache: tokio::sync::Mutex<Option<(Vec<Sample>, Time)>>,
    pub(crate) every: Duration,
}

fn bump<K: Ord>(m: &Mutex<BTreeMap<K, u64>>, k: K) {
    *m.lock()
        .unwrap_or_else(|p| p.into_inner())
        .entry(k)
        .or_default() += 1;
}

impl Metrics {
    pub(crate) fn new(every: Duration) -> Metrics {
        Metrics {
            reconcile: Mutex::new(Hist {
                counts: vec![0; 12],
                sum: 0.0,
                count: 0,
            }),
            reconcile_errors: AtomicU64::new(0),
            events: Mutex::default(),
            job_runs: Mutex::default(),
            alerts_sent: Mutex::default(),
            alerts_failed: Mutex::default(),
            alerts_dropped: Mutex::default(),
            cp_failures: AtomicU64::new(0),
            cache: tokio::sync::Mutex::new(None),
            every: if every.is_zero() {
                METRICS_CACHE_FOR
            } else {
                every
            },
        }
    }

    pub(crate) fn reconciled(&self, d: Duration, failed: bool) {
        let v = d.as_secs_f64();
        let mut h = self.reconcile.lock().unwrap_or_else(|p| p.into_inner());
        for (i, b) in buckets().iter().enumerate() {
            if v <= *b {
                h.counts[i] += 1;
            }
        }
        h.sum += v;
        h.count += 1;
        drop(h);
        if failed {
            self.reconcile_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn event(&self, kind: &str, reason: &str) {
        bump(&self.events, (kind.to_string(), reason.to_string()));
    }

    pub(crate) fn job_run(&self, job: &str, result: &str) {
        bump(&self.job_runs, (job.to_string(), result.to_string()));
    }

    pub(crate) fn alert_sent(&self, channel: &str) {
        bump(&self.alerts_sent, channel.to_string());
    }

    pub(crate) fn alert_failed(&self, channel: &str) {
        bump(&self.alerts_failed, channel.to_string());
    }

    pub(crate) fn alert_dropped(&self, channel: &str) {
        bump(&self.alerts_dropped, channel.to_string());
    }

    #[allow(dead_code)]
    pub(crate) fn control_plane_backup_failed(&self) {
        self.cp_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// The counters as samples.
    fn samples(&self, out: &mut Vec<Sample>) {
        let h = self.reconcile.lock().unwrap_or_else(|p| p.into_inner());
        for (i, b) in buckets().iter().enumerate() {
            out.push(Sample::new(
                "armada_reconcile_duration_seconds_bucket",
                vec![("le", fmt_float(*b))],
                h.counts[i] as f64,
            ));
        }
        out.push(Sample::new(
            "armada_reconcile_duration_seconds_bucket",
            vec![("le", "+Inf".into())],
            h.count as f64,
        ));
        out.push(Sample::new(
            "armada_reconcile_duration_seconds_sum",
            vec![],
            h.sum,
        ));
        out.push(Sample::new(
            "armada_reconcile_duration_seconds_count",
            vec![],
            h.count as f64,
        ));
        drop(h);
        out.push(Sample::new(
            "armada_reconcile_errors_total",
            vec![],
            self.reconcile_errors.load(Ordering::Relaxed) as f64,
        ));
        out.push(Sample::new(
            "armada_control_plane_backup_failures_total",
            vec![],
            self.cp_failures.load(Ordering::Relaxed) as f64,
        ));
        for ((kind, reason), n) in self.events.lock().unwrap_or_else(|p| p.into_inner()).iter() {
            out.push(Sample::new(
                "armada_events_total",
                vec![("kind", kind.clone()), ("reason", reason.clone())],
                *n as f64,
            ));
        }
        for ((job, result), n) in self
            .job_runs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
        {
            out.push(Sample::new(
                "armada_job_runs_total",
                vec![("job", job.clone()), ("result", result.clone())],
                *n as f64,
            ));
        }
        for (name, m) in [
            ("armada_alerts_sent_total", &self.alerts_sent),
            ("armada_alerts_failed_total", &self.alerts_failed),
            ("armada_alerts_dropped_total", &self.alerts_dropped),
        ] {
            for (ch, n) in m.lock().unwrap_or_else(|p| p.into_inner()).iter() {
                out.push(Sample::new(name, vec![("channel", ch.clone())], *n as f64));
            }
        }
    }
}

/// One sample: a series' name (with a histogram's suffix), its labels,
/// and its value.
#[derive(Clone, Debug)]
pub(crate) struct Sample {
    name: &'static str,
    labels: Vec<(&'static str, String)>,
    value: f64,
}

impl Sample {
    fn new(name: &'static str, labels: Vec<(&'static str, String)>, value: f64) -> Sample {
        Sample {
            name,
            labels,
            value,
        }
    }
}

/// The families: name, type, and help.
const FAMILIES: &[(&str, &str, &str)] = &[
    (
        "armada_server_leader",
        "gauge",
        "1 on the control plane server that leads and serves this endpoint.",
    ),
    (
        "armada_agents_connected",
        "gauge",
        "Agents connected to the leader.",
    ),
    (
        "armada_app_replicas_desired",
        "gauge",
        "Replicas an app should run.",
    ),
    (
        "armada_app_replicas_ready",
        "gauge",
        "Replicas of an app that are running, ready, and not draining.",
    ),
    (
        "armada_app_rollout",
        "gauge",
        "1 for an app's current rollout state (idle, progressing, failed).",
    ),
    (
        "armada_replica_ready",
        "gauge",
        "1 when a replica is running, ready, and not draining.",
    ),
    (
        "armada_replica_restarts_total",
        "counter",
        "How often the agent recreated a replica's container.",
    ),
    (
        "armada_replica_last_restart_timestamp_seconds",
        "gauge",
        "When the agent last recreated a replica's container, and why (exited, out_of_memory, liveness, startup, network, volume, machine_restart, other, unknown).",
    ),
    (
        "armada_replica_start_time_seconds",
        "gauge",
        "When a replica was scheduled.",
    ),
    (
        "armada_app_replicas_min",
        "gauge",
        "The fewest replicas an autoscaled app may run.",
    ),
    (
        "armada_app_replicas_max",
        "gauge",
        "The most replicas an autoscaled app may run.",
    ),
    (
        "armada_replica_cpu_usage_cores",
        "gauge",
        "CPU a replica used over its node's last sampling interval.",
    ),
    (
        "armada_replica_memory_usage_bytes",
        "gauge",
        "Memory a replica uses, without reclaimable page cache.",
    ),
    (
        "armada_replica_cpu_reserved_cores",
        "gauge",
        "CPU a replica reserves on its node.",
    ),
    (
        "armada_replica_cpu_limit_cores",
        "gauge",
        "A replica's CPU limit, for apps that set one.",
    ),
    (
        "armada_replica_memory_limit_bytes",
        "gauge",
        "A replica's memory limit, which is also its reservation.",
    ),
    (
        "armada_node_ready",
        "gauge",
        "1 when a node's agent is connected and the node is ready.",
    ),
    (
        "armada_node_cordoned",
        "gauge",
        "1 when a node is cordoned.",
    ),
    (
        "armada_node_replicas",
        "gauge",
        "Replicas assigned to a node.",
    ),
    (
        "armada_node_cpu_allocatable_cores",
        "gauge",
        "CPU a node can give replicas, after what Armada keeps.",
    ),
    (
        "armada_node_memory_allocatable_bytes",
        "gauge",
        "Memory a node can give replicas, after what Armada keeps.",
    ),
    (
        "armada_node_cpu_reserved_cores",
        "gauge",
        "CPU the replicas on a node reserve.",
    ),
    (
        "armada_node_memory_reserved_bytes",
        "gauge",
        "Memory the replicas on a node reserve.",
    ),
    (
        "armada_node_cpu_usage_cores",
        "gauge",
        "CPU the replicas on a node use, from its latest sample.",
    ),
    (
        "armada_node_memory_usage_bytes",
        "gauge",
        "Memory the replicas on a node use, from its latest sample.",
    ),
    (
        "armada_node_conntrack_entries",
        "gauge",
        "Connections a node's kernel tracks, from its latest sample.",
    ),
    (
        "armada_node_conntrack_max",
        "gauge",
        "How many connections a node's kernel can track; new ones are dropped past it.",
    ),
    (
        "armada_job_last_success_timestamp_seconds",
        "gauge",
        "When the newest kept successful run of a job finished.",
    ),
    (
        "armada_app_autoscale_current",
        "gauge",
        "An autoscaling rule's current value: the average per ready replica (requests in progress, or percent of the reservation), a queue's length, or the replicas an open schedule window asks for (0 when closed); absent while unmeasured.",
    ),
    (
        "armada_app_autoscale_target",
        "gauge",
        "An autoscaling rule's target: per replica, or a schedule's replicas.",
    ),
    (
        "armada_job_runs_active",
        "gauge",
        "Runs of a job that are pending or running.",
    ),
    (
        "armada_job_queue_length",
        "gauge",
        "The length of the queue that starts a job's runs, as last read; absent while unread.",
    ),
    (
        "armada_app_traffic_weight",
        "gauge",
        "A revision's percent of an app's requests in multiple revision mode.",
    ),
    (
        "armada_space_replicas",
        "gauge",
        "Replicas of a space's apps.",
    ),
    (
        "armada_space_cpu_usage_cores",
        "gauge",
        "CPU a space's replicas used over the last sampling interval.",
    ),
    (
        "armada_space_memory_usage_bytes",
        "gauge",
        "Memory a space's replicas use, without reclaimable page cache.",
    ),
    (
        "armada_space_cpu_reserved_cores",
        "gauge",
        "CPU a space's replicas reserve.",
    ),
    (
        "armada_space_memory_reserved_bytes",
        "gauge",
        "Memory a space's replicas reserve.",
    ),
    (
        "armada_space_volume_used_bytes",
        "gauge",
        "Bytes in a space's volumes, from their latest measurements.",
    ),
    (
        "armada_space_requests_total",
        "counter",
        "Requests the proxies sent to a space's replicas; resets when the leader changes.",
    ),
    (
        "armada_space_egress_bytes_total",
        "counter",
        "Bytes a space's containers sent; resets when the leader changes.",
    ),
    (
        "armada_volume_used_bytes",
        "gauge",
        "Bytes in a volume's files, from its node's latest measurement; absent while unmeasured.",
    ),
    (
        "armada_volume_backup_last_success_timestamp_seconds",
        "gauge",
        "When a volume's last backup to its bucket worked (ADR 0041); absent before the first.",
    ),
    (
        "armada_volume_backup_stored_bytes",
        "gauge",
        "Bytes a volume's backup repository held after its last backup.",
    ),
    (
        "armada_volume_backup_snapshots",
        "gauge",
        "Backups a volume's repository held after its last backup.",
    ),
    (
        "armada_volume_backup_failing",
        "gauge",
        "1 while a volume's last backup failed, 0 otherwise.",
    ),
    (
        "armada_revision_info",
        "gauge",
        "1 for each revision of an app that serves, rolls out, or still has replicas, with the image its spec names.",
    ),
    (
        "armada_replica_state",
        "gauge",
        "1 for a replica's current state (pending, pulling, starting, running, exited, failed, unknown).",
    ),
    (
        "armada_replica_info",
        "gauge",
        "1 for each replica, with its revision and the IP address it is reached at (empty until it has one).",
    ),
    (
        "armada_replica_draining",
        "gauge",
        "1 while a replica is out of the proxy and being stopped (an older revision after a rollout, a scale down, or a move to another node), 0 otherwise.",
    ),
    (
        "armada_control_plane_backup_last_success_timestamp_seconds",
        "gauge",
        "When the control plane's last backup to its bucket worked (ADR 0051); absent before the first.",
    ),
    (
        "armada_control_plane_backup_last_size_bytes",
        "gauge",
        "Bytes of the files in the control plane's last backup.",
    ),
    (
        "armada_state_store",
        "gauge",
        "1 for the store the control plane keeps its state in: etcd or kv (armada-kv, ADR 0057).",
    ),
    (
        "armada_state_move_failures",
        "gauge",
        "Moves of the control plane's state to armada-kv that failed in a row (ADR 0057); 0 once one works.",
    ),
    (
        "armada_app_autoscale_last_scale_timestamp_seconds",
        "gauge",
        "When the autoscaler last changed an app's replica count; absent until it does.",
    ),
    (
        "armada_reconcile_duration_seconds",
        "histogram",
        "How long a reconcile of the whole cluster takes.",
    ),
    (
        "armada_reconcile_errors_total",
        "counter",
        "Reconciles that failed.",
    ),
    (
        "armada_events_total",
        "counter",
        "Events the leader recorded, by kind and reason.",
    ),
    (
        "armada_job_runs_total",
        "counter",
        "Job runs that ended, by job and result (succeeded, failed, cancelled).",
    ),
    (
        "armada_alerts_sent_total",
        "counter",
        "Notices sent to alert channels, by channel.",
    ),
    (
        "armada_alerts_failed_total",
        "counter",
        "Notices that could not be sent after every try, by channel.",
    ),
    (
        "armada_alerts_dropped_total",
        "counter",
        "Notices dropped because a channel's queue was full, by channel.",
    ),
    (
        "armada_control_plane_backup_failures_total",
        "counter",
        "Backups of the control plane to its bucket that failed since this server became the leader (ADR 0051).",
    ),
];

/// A float in Prometheus' text format: the shortest digits that read back
/// as f, in exponent form (`1.5e+06`) for exponents below -4 or from 6,
/// and NaN, +Inf, -Inf.
pub(crate) fn fmt_float(f: f64) -> String {
    if f == 1.0 {
        return "1".into();
    }
    if f == 0.0 {
        return "0".into();
    }
    if f == -1.0 {
        return "-1".into();
    }
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "+Inf" } else { "-Inf" }.into();
    }
    // The shortest digits and the exponent, then the exponent form or the
    // plain one.
    let e = format!("{f:e}");
    let (mant, exp) = e.split_once('e').unwrap_or((&e, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let neg = mant.starts_with('-');
    let digits: String = mant.chars().filter(char::is_ascii_digit).collect();
    let sign = if neg { "-" } else { "" };
    if !(-4..6).contains(&exp) {
        let mut s = format!("{sign}{}", &digits[..1]);
        if digits.len() > 1 {
            s.push('.');
            s.push_str(&digits[1..]);
        }
        let (es, ea) = if exp < 0 { ('-', -exp) } else { ('+', exp) };
        s.push('e');
        s.push(es);
        s.push_str(&format!("{ea:02}"));
        return s;
    }
    if exp < 0 {
        let zeros = "0".repeat((-exp - 1) as usize);
        return format!("{sign}0.{zeros}{digits}");
    }
    let point = exp as usize + 1;
    if digits.len() <= point {
        format!("{sign}{digits}{}", "0".repeat(point - digits.len()))
    } else {
        format!("{sign}{}.{}", &digits[..point], &digits[point..])
    }
}

fn escape_help(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\n', "\\n")
}

fn escape_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

/// The family a sample belongs to: its name without a histogram's suffix.
fn family_of(name: &str) -> &str {
    for suffix in ["_bucket", "_sum", "_count"] {
        if let Some(base) = name.strip_suffix(suffix)
            && FAMILIES.iter().any(|f| f.0 == base && f.1 == "histogram")
        {
            return base;
        }
    }
    name
}

/// The text format of samples.
pub(crate) fn exposition(samples: Vec<Sample>) -> String {
    let mut by: BTreeMap<&str, Vec<Sample>> = BTreeMap::new();
    for mut s in samples {
        s.labels.sort_by(|a, b| a.0.cmp(b.0));
        by.entry(family_of(s.name)).or_default().push(s);
    }
    let mut out = String::new();
    for (fam, mut list) in by {
        let Some((_, typ, help)) = FAMILIES.iter().find(|f| f.0 == fam) else {
            continue;
        };
        out.push_str(&format!(
            "# HELP {fam} {}\n# TYPE {fam} {typ}\n",
            escape_help(help)
        ));
        if *typ == "histogram" {
            // One metric: buckets in order, then sum and count.
            for s in &list {
                write_sample(&mut out, s);
            }
            continue;
        }
        list.sort_by(|a, b| {
            let av = a.labels.iter().map(|l| l.1.as_str());
            let bv = b.labels.iter().map(|l| l.1.as_str());
            av.cmp(bv)
        });
        for s in &list {
            write_sample(&mut out, s);
        }
    }
    out
}

fn write_sample(out: &mut String, s: &Sample) {
    out.push_str(s.name);
    if !s.labels.is_empty() {
        out.push('{');
        for (i, (k, v)) in s.labels.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!("{k}=\"{}\"", escape_value(v)));
        }
        out.push('}');
    }
    out.push(' ');
    out.push_str(&fmt_float(s.value));
    out.push('\n');
}

/// Keeps the state label to the states the store knows.
fn replica_state_label(state: &str) -> String {
    match state {
        REPLICA_PENDING | REPLICA_PULLING | REPLICA_PULLED | REPLICA_STARTING | REPLICA_RUNNING
        | REPLICA_EXITED | REPLICA_FAILED => state.to_string(),
        _ => "unknown".into(),
    }
}

/// The IP of a replica's host:port address, or "".
fn address_ip(addr: &str) -> String {
    addr.parse::<std::net::SocketAddr>()
        .map(|a| a.ip().to_string())
        .unwrap_or_default()
}

/// Names why a container was recreated from the agent's
/// words, so that the label takes only a few values.
pub(crate) fn restart_reason(msg: &str) -> &'static str {
    match msg {
        "" => "unknown",
        "the machine restarted" => "machine_restart",
        m if m.contains("out of memory") => "out_of_memory",
        m if m.contains("liveness probe") => "liveness",
        m if m.contains("startup probe") => "startup",
        m if m.contains("network interface") => "network",
        m if m.contains("volume backup") => "volume",
        m if m.starts_with("exited with code") || m.starts_with("container ") => "exited",
        _ => "other",
    }
}

fn cores(millis: i64) -> f64 {
    millis as f64 / 1000.0
}

fn bool_value(b: bool) -> f64 {
    if b { 1.0 } else { 0.0 }
}

fn secs(t: &Option<armada_proto::google::protobuf::Timestamp>) -> Option<f64> {
    t.as_ref().map(|t| t.seconds as f64)
}

impl Server {
    /// The server's own access.
    pub(crate) fn internal_auth(&self) -> Auth {
        let id = Identity::new(armada_pki::KIND_SERVER, &self.0.name);
        Auth {
            acc: Access::of(id.clone()),
            id,
            cert: self.0.cert.leaf(),
        }
    }

    /// The metrics of one scrape: the counters, and the cluster's metrics
    /// gathered at most once per the cache's time.
    pub(crate) async fn scrape(&self) -> String {
        let mut cache = self.0.metrics.cache.lock().await;
        let now = self.now();
        let fresh = cache
            .as_ref()
            .is_some_and(|(_, at)| sub(&now, at) < self.0.metrics.every.as_nanos() as i64);
        if !fresh {
            *cache = None;
            let gathered = tokio::time::timeout(METRICS_TIMEOUT, self.gather_metrics()).await;
            if let Ok((m, true)) = gathered {
                *cache = Some((m, self.now()));
            } else if let Ok((m, false)) = gathered {
                drop(cache);
                return self.exposition_with(m);
            } else {
                drop(cache);
                return self.exposition_with(Vec::new());
            }
        }
        let m = cache.as_ref().map(|(m, _)| m.clone()).unwrap_or_default();
        drop(cache);
        self.exposition_with(m)
    }

    fn exposition_with(&self, mut m: Vec<Sample>) -> String {
        self.0.metrics.samples(&mut m);
        exposition(m)
    }

    /// gather reads the cluster's metrics; false when a read failed and the
    /// metrics end there.
    async fn gather_metrics(&self) -> (Vec<Sample>, bool) {
        let mut out = Vec::new();
        let g =
            |out: &mut Vec<Sample>, name: &'static str, v: f64, labels: &[(&'static str, &str)]| {
                out.push(Sample::new(
                    name,
                    labels.iter().map(|(k, v)| (*k, v.to_string())).collect(),
                    v,
                ));
            };
        g(
            &mut out,
            "armada_server_leader",
            1.0,
            &[("server", &self.0.name)],
        );
        let agents = self
            .0
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len();
        g(&mut out, "armada_agents_connected", agents as f64, &[]);
        let a = self.internal_auth();
        let Ok(st) = self.status(&a, StatusRequest::default()).await else {
            return (out, false);
        };
        for app in &st.apps {
            let name = app.name.as_str();
            g(
                &mut out,
                "armada_app_replicas_desired",
                f64::from(app.desired_replicas),
                &[("app", name)],
            );
            let mut ready = 0;
            for r in &app.replicas {
                let up = r.ready && r.state == REPLICA_RUNNING && !r.draining;
                if up {
                    ready += 1;
                }
                g(
                    &mut out,
                    "armada_replica_ready",
                    bool_value(up),
                    &[
                        ("app", name),
                        ("replica", &r.id),
                        ("revision", &r.revision),
                        ("node", &r.node_id),
                    ],
                );
                g(
                    &mut out,
                    "armada_replica_state",
                    1.0,
                    &[
                        ("app", name),
                        ("replica", &r.id),
                        ("node", &r.node_id),
                        ("state", &replica_state_label(&r.state)),
                    ],
                );
                g(
                    &mut out,
                    "armada_replica_info",
                    1.0,
                    &[
                        ("app", name),
                        ("replica", &r.id),
                        ("revision", &r.revision),
                        ("node", &r.node_id),
                        ("ip", &address_ip(&r.address)),
                    ],
                );
                g(
                    &mut out,
                    "armada_replica_draining",
                    bool_value(r.draining),
                    &[("app", name), ("replica", &r.id), ("node", &r.node_id)],
                );
                g(
                    &mut out,
                    "armada_replica_restarts_total",
                    f64::from(r.restarts),
                    &[("app", name), ("replica", &r.id), ("node", &r.node_id)],
                );
                if let Some(t) = secs(&r.last_restart_at) {
                    g(
                        &mut out,
                        "armada_replica_last_restart_timestamp_seconds",
                        t,
                        &[
                            ("app", name),
                            ("replica", &r.id),
                            ("node", &r.node_id),
                            ("reason", restart_reason(&r.last_restart)),
                        ],
                    );
                }
                if let Some(t) = secs(&r.created_at) {
                    g(
                        &mut out,
                        "armada_replica_start_time_seconds",
                        t,
                        &[("app", name), ("replica", &r.id), ("node", &r.node_id)],
                    );
                }
            }
            g(
                &mut out,
                "armada_app_replicas_ready",
                f64::from(ready),
                &[("app", name)],
            );
            let state = if app.rollout_state.is_empty() {
                "idle"
            } else {
                app.rollout_state.as_str()
            };
            for v in ["idle", ROLLOUT_PROGRESSING, ROLLOUT_FAILED] {
                g(
                    &mut out,
                    "armada_app_rollout",
                    bool_value(v == state),
                    &[("app", name), ("state", v)],
                );
            }
            if let Some(au) = &app.autoscale {
                g(
                    &mut out,
                    "armada_app_replicas_min",
                    f64::from(au.min),
                    &[("app", name)],
                );
                g(
                    &mut out,
                    "armada_app_replicas_max",
                    f64::from(au.max),
                    &[("app", name)],
                );
                if let Some(t) = secs(&au.last_scaled_at) {
                    g(
                        &mut out,
                        "armada_app_autoscale_last_scale_timestamp_seconds",
                        t,
                        &[("app", name)],
                    );
                }
                for r in &au.rules {
                    g(
                        &mut out,
                        "armada_app_autoscale_target",
                        r.target as f64,
                        &[("app", name), ("rule", &r.r#type)],
                    );
                    if r.measured {
                        g(
                            &mut out,
                            "armada_app_autoscale_current",
                            r.current as f64,
                            &[("app", name), ("rule", &r.r#type)],
                        );
                    }
                }
            }
            for t in &app.traffic {
                g(
                    &mut out,
                    "armada_app_traffic_weight",
                    f64::from(t.weight),
                    &[("app", name), ("revision", &t.revision)],
                );
            }
        }
        self.revision_info(&st.apps, &mut out).await;
        for n in &st.nodes {
            g(
                &mut out,
                "armada_node_ready",
                bool_value(n.state == NODE_READY),
                &[("node", &n.id)],
            );
            g(
                &mut out,
                "armada_node_cordoned",
                bool_value(n.cordoned),
                &[("node", &n.id)],
            );
        }
        let Ok(top) = self.top(&a, TopRequest::default()).await else {
            return (out, false);
        };
        for r in &top.replicas {
            let l = [
                ("app", r.app.as_str()),
                ("replica", &r.id),
                ("node", &r.node_id),
            ];
            if r.measured {
                g(
                    &mut out,
                    "armada_replica_cpu_usage_cores",
                    cores(r.cpu_millis),
                    &l,
                );
                g(
                    &mut out,
                    "armada_replica_memory_usage_bytes",
                    r.memory_bytes as f64,
                    &l,
                );
            }
            g(
                &mut out,
                "armada_replica_cpu_reserved_cores",
                cores(r.cpu_reserved_millis),
                &l,
            );
            if r.cpu_limit_millis > 0 {
                g(
                    &mut out,
                    "armada_replica_cpu_limit_cores",
                    cores(r.cpu_limit_millis),
                    &l,
                );
            }
            g(
                &mut out,
                "armada_replica_memory_limit_bytes",
                r.memory_limit_bytes as f64,
                &l,
            );
        }
        if let Ok((jobs, runs)) = self.jobs_and_runs(&a).await {
            for j in &jobs.jobs {
                g(
                    &mut out,
                    "armada_job_runs_active",
                    f64::from(j.active),
                    &[("job", &j.name)],
                );
                if let Some(tr) = &j.trigger
                    && tr.measured
                {
                    g(
                        &mut out,
                        "armada_job_queue_length",
                        tr.length as f64,
                        &[("job", &j.name)],
                    );
                }
                let mut last: Option<&Time> = None;
                for r in runs.get(&j.name).into_iter().flatten() {
                    if r.state == RUN_SUCCEEDED
                        && last.is_none_or(|l| r.finished_at.after(l))
                        && !r.finished_at.is_zero()
                    {
                        last = Some(&r.finished_at);
                    }
                }
                if let Some(l) = last {
                    g(
                        &mut out,
                        "armada_job_last_success_timestamp_seconds",
                        l.unix as f64,
                        &[("job", &j.name)],
                    );
                }
            }
        }
        if let Ok(vols) = self.list_volumes(&a, ListVolumesRequest::default()).await {
            for v in &vols.volumes {
                if v.used_bytes >= 0 {
                    g(
                        &mut out,
                        "armada_volume_used_bytes",
                        v.used_bytes as f64,
                        &[("app", &v.app), ("volume", &v.name), ("node", &v.node)],
                    );
                }
                if !v.backup {
                    continue;
                }
                let l = [("app", v.app.as_str()), ("volume", &v.name)];
                if let Some(t) = &v.last_backup_at {
                    g(
                        &mut out,
                        "armada_volume_backup_last_success_timestamp_seconds",
                        t.seconds as f64,
                        &l,
                    );
                    g(
                        &mut out,
                        "armada_volume_backup_stored_bytes",
                        v.backup_stored_bytes as f64,
                        &l,
                    );
                    g(
                        &mut out,
                        "armada_volume_backup_snapshots",
                        f64::from(v.backup_snapshots),
                        &l,
                    );
                }
                g(
                    &mut out,
                    "armada_volume_backup_failing",
                    bool_value(v.backup_failed_at.is_some()),
                    &l,
                );
            }
        }
        if let Ok(Some(b)) = self.control_plane_backup_status().await
            && let Some(t) = &b.last_at
        {
            g(
                &mut out,
                "armada_control_plane_backup_last_success_timestamp_seconds",
                t.seconds as f64,
                &[],
            );
            g(
                &mut out,
                "armada_control_plane_backup_last_size_bytes",
                b.last_size_bytes as f64,
                &[],
            );
        }
        if let Ok(Some((store, failures))) = self.state_move_gauges().await {
            g(&mut out, "armada_state_store", 1.0, &[("store", store)]);
            g(&mut out, "armada_state_move_failures", failures as f64, &[]);
        }
        for p in &top.spaces {
            let l = [("space", p.name.as_str())];
            g(&mut out, "armada_space_replicas", f64::from(p.replicas), &l);
            if p.measured > 0 {
                g(
                    &mut out,
                    "armada_space_cpu_usage_cores",
                    cores(p.cpu_millis),
                    &l,
                );
                g(
                    &mut out,
                    "armada_space_memory_usage_bytes",
                    p.memory_bytes as f64,
                    &l,
                );
            }
            g(
                &mut out,
                "armada_space_cpu_reserved_cores",
                cores(p.cpu_reserved_millis),
                &l,
            );
            g(
                &mut out,
                "armada_space_memory_reserved_bytes",
                p.memory_reserved_bytes as f64,
                &l,
            );
            g(
                &mut out,
                "armada_space_volume_used_bytes",
                p.volume_bytes as f64,
                &l,
            );
            g(
                &mut out,
                "armada_space_requests_total",
                p.requests as f64,
                &l,
            );
            g(
                &mut out,
                "armada_space_egress_bytes_total",
                p.egress_bytes as f64,
                &l,
            );
        }
        for n in &top.nodes {
            let l = [("node", n.id.as_str())];
            g(&mut out, "armada_node_replicas", f64::from(n.replicas), &l);
            g(
                &mut out,
                "armada_node_cpu_allocatable_cores",
                cores(n.cpu_allocatable_millis),
                &l,
            );
            g(
                &mut out,
                "armada_node_memory_allocatable_bytes",
                n.memory_allocatable_bytes as f64,
                &l,
            );
            g(
                &mut out,
                "armada_node_cpu_reserved_cores",
                cores(n.cpu_reserved_millis),
                &l,
            );
            g(
                &mut out,
                "armada_node_memory_reserved_bytes",
                n.memory_reserved_bytes as f64,
                &l,
            );
            if n.measured {
                g(
                    &mut out,
                    "armada_node_cpu_usage_cores",
                    cores(n.cpu_millis),
                    &l,
                );
                g(
                    &mut out,
                    "armada_node_memory_usage_bytes",
                    n.memory_bytes as f64,
                    &l,
                );
            }
            if n.conntrack_max > 0 {
                g(
                    &mut out,
                    "armada_node_conntrack_entries",
                    n.conntrack_entries as f64,
                    &l,
                );
                g(
                    &mut out,
                    "armada_node_conntrack_max",
                    n.conntrack_max as f64,
                    &l,
                );
            }
        }
        (out, true)
    }

    /// Exports the image of every revision an app serves,
    /// rolls out, or still runs replicas of, read in one batch.
    async fn revision_info(&self, apps: &[AppStatus], out: &mut Vec<Sample>) {
        let mut owner: HashMap<String, String> = HashMap::new();
        for a in apps {
            let mut names = vec![a.active_revision.clone(), a.target_revision.clone()];
            names.extend(a.traffic.iter().map(|t| t.revision.clone()));
            names.extend(a.replicas.iter().map(|r| r.revision.clone()));
            for n in names {
                if !n.is_empty() {
                    owner.insert(n, a.name.clone());
                }
            }
        }
        if owner.is_empty() {
            return;
        }
        let names: Vec<String> = owner.keys().cloned().collect();
        let revs = match self.store().get_revisions(&names).await {
            Ok(r) => r,
            Err(e) => {
                self.0
                    .log
                    .warn("metrics: read revisions", &[("err", e.to_string())]);
                return;
            }
        };
        for (name, app) in &owner {
            if let Some(r) = revs.get(name)
                && let Some(sp) = r.spec.as_deref()
            {
                out.push(Sample::new(
                    "armada_revision_info",
                    vec![
                        ("app", app.clone()),
                        ("revision", name.clone()),
                        ("image", sp.image.clone()),
                    ],
                    1.0,
                ));
            }
        }
    }

    /// Metrics certificates on record, and users or
    /// services with cluster-admin. The TLS config verified the chain.
    async fn metrics_allowed(&self, cert: &armada_pki::Certificate) -> bool {
        let Ok(id) = cert.identity() else {
            return false;
        };
        if id.kind == KIND_METRICS {
            return self
                .store()
                .metrics_access(&id.name, &cert_time(cert.not_before), &cert.serial_string())
                .await
                .unwrap_or(false);
        }
        let Some(pid) = id.principal() else {
            return false;
        };
        let serial = cert.serial_string();
        let res = if pid.kind == KIND_SERVICE {
            self.store().service_access(&pid.name, &serial).await
        } else {
            self.store()
                .user_access(&pid.name, &cert_time(cert.not_before), &serial)
                .await
        };
        match res {
            Ok((p, true)) => p.has(&Grant {
                role: ROLE_CLUSTER_ADMIN.to_string(),
                space: String::new(),
            }),
            _ => false,
        }
    }

    /// Serves /metrics on the metrics listener until shutdown.
    pub(crate) async fn serve_metrics(
        &self,
        shutdown: watch::Receiver<bool>,
    ) -> Result<(), String> {
        let addr = self.0.metrics_addr.clone();
        let lis = TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("metrics listener: listen tcp {addr}: {e}"))?;
        let mut cfg = self.0.cert.api_config()?;
        cfg.alpn_protocols.clear();
        let tls = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg));
        let srv = self.clone();
        tokio::spawn(async move {
            let mut shutdown = shutdown;
            loop {
                let (tcp, _) = tokio::select! {
                    r = lis.accept() => match r {
                        Ok(v) => v,
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                            continue;
                        }
                    },
                    _ = crate::stopped(&mut shutdown) => return,
                };
                let tls = tls.clone();
                let srv = srv.clone();
                let mut sd = shutdown.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = srv.serve_metrics_conn(tls, tcp) => {}
                        _ = crate::stopped(&mut sd) => {}
                    }
                });
            }
        });
        self.0.log.info(
            "metrics listening",
            &[("addr", self.0.metrics_addr.clone())],
        );
        Ok(())
    }

    async fn serve_metrics_conn(&self, tls: tokio_rustls::TlsAcceptor, tcp: tokio::net::TcpStream) {
        let Ok(Ok(mut s)) =
            tokio::time::timeout(crate::conn::HANDSHAKE_TIMEOUT, tls.accept(tcp)).await
        else {
            return;
        };
        let cert = s
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .and_then(|c| armada_pki::Certificate::from_der(c.as_ref()).ok());
        // The request's head, within its limits.
        let mut head = Vec::new();
        let read = tokio::time::timeout(READ_HEADER_TIMEOUT, async {
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                if head.len() > MAX_HEADER_BYTES {
                    return false;
                }
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => return false,
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                }
            }
            true
        })
        .await;
        if !matches!(read, Ok(true)) {
            return;
        }
        let line = String::from_utf8_lossy(&head);
        let mut parts = line.lines().next().unwrap_or_default().split(' ');
        let method = parts.next().unwrap_or_default().to_string();
        let target = parts.next().unwrap_or_default().to_string();
        let path = target.split('?').next().unwrap_or_default();
        let allowed = match &cert {
            Some(c) => self.metrics_allowed(c).await,
            None => false,
        };
        let (status, ctype, body, extra) = if !allowed {
            (
                "403 Forbidden",
                "text/plain; charset=utf-8",
                "a metrics certificate, or a user or service with cluster-admin, is required\n"
                    .to_string(),
                "X-Content-Type-Options: nosniff\r\n",
            )
        } else if path != "/metrics" {
            (
                "404 Not Found",
                "text/plain; charset=utf-8",
                "404 page not found\n".to_string(),
                "X-Content-Type-Options: nosniff\r\n",
            )
        } else if method != "GET" && method != "HEAD" {
            (
                "405 Method Not Allowed",
                "text/plain; charset=utf-8",
                "Method Not Allowed\n".to_string(),
                "Allow: GET, HEAD\r\nX-Content-Type-Options: nosniff\r\n",
            )
        } else {
            (
                "200 OK",
                "text/plain; version=0.0.4; charset=utf-8; escaping=underscores",
                self.scrape().await,
                "",
            )
        };
        let mut resp = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        if method != "HEAD" {
            resp.extend_from_slice(body.as_bytes());
        }
        let _ = tokio::time::timeout(WRITE_TIMEOUT, async {
            let _ = s.write_all(&resp).await;
            let _ = s.shutdown().await;
        })
        .await;
    }

    /// IssueMetricsCertificate signs a metrics client certificate from the
    /// caller's CSR (ADR 0017) and records it, so it can be revoked.
    pub(crate) async fn issue_metrics_certificate(
        &self,
        a: &Auth,
        req: IssueMetricsCertificateRequest,
    ) -> Result<IssueMetricsCertificateResponse, Status> {
        let Some(ca) = &self.0.ca else {
            return Err(Status::new(
                Code::FailedPrecondition,
                "this server cannot issue certificates",
            ));
        };
        check_metrics_name(&req.name)?;
        let cert = ca
            .sign_metrics_csr(&req.csr, &req.name)
            .map_err(|e| Status::new(Code::InvalidArgument, format!("sign certificate: {e}")))?;
        let not_after = armada_store::gojson::from_unix(cert.not_after);
        self.store()
            .record_metrics_cert(
                &req.name,
                &armada_store::NodeCert {
                    serial: cert.serial.clone(),
                    not_after: not_after.clone(),
                },
                &a.actor(),
            )
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "issued metrics certificate",
            &[
                ("name", req.name.clone()),
                ("serial", cert.serial.clone()),
                ("by", a.actor()),
            ],
        );
        Ok(IssueMetricsCertificateResponse {
            cert: cert.pem,
            ca_cert: ca.cert_pem.clone(),
            expires_at: Some(timestamp(&not_after)),
        })
    }

    /// ListMetricsCredentials lists the metrics scrapers with an unexpired
    /// certificate on record.
    pub(crate) async fn list_metrics_credentials(
        &self,
        _a: &Auth,
        _req: ListMetricsCredentialsRequest,
    ) -> Result<ListMetricsCredentialsResponse, Status> {
        let creds = self
            .store()
            .list_metrics_certs()
            .await
            .map_err(|e| store_err(&e))?;
        Ok(ListMetricsCredentialsResponse {
            credentials: creds
                .iter()
                .map(|c| MetricsCredential {
                    name: c.name.clone(),
                    certificates: c
                        .certs
                        .iter()
                        .map(|x| MetricsCertificate {
                            serial: x.serial.clone(),
                            expires_at: Some(timestamp(&x.not_after)),
                        })
                        .collect(),
                })
                .collect(),
        })
    }

    /// RevokeMetricsCredentials refuses every certificate of a metrics
    /// scraper from now on.
    pub(crate) async fn revoke_metrics_credentials(
        &self,
        a: &Auth,
        req: RevokeMetricsCredentialsRequest,
    ) -> Result<RevokeMetricsCredentialsResponse, Status> {
        check_metrics_name(&req.name)?;
        self.store()
            .revoke_metrics_certs(&req.name, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "revoked metrics certificates",
            &[("name", req.name.clone()), ("by", a.actor())],
        );
        Ok(RevokeMetricsCredentialsResponse {})
    }
}

fn check_metrics_name(name: &str) -> Result<(), Status> {
    parse_identity(&format!("{KIND_METRICS}:{name}"))
        .map(|_| ())
        .map_err(|_| {
            Status::new(
                Code::InvalidArgument,
                "invalid name: use letters, digits, '.', '_', and '-' (at most 63)",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats() {
        for (f, want) in [
            (1.0, "1"),
            (0.0, "0"),
            (0.5, "0.5"),
            (0.005, "0.005"),
            (10.24, "10.24"),
            (262144.0, "262144"),
            (104857600.0, "1.048576e+08"),
            (1048576.0, "1.048576e+06"),
            (0.25, "0.25"),
            (1e-05, "1e-05"),
            (0.0001, "0.0001"),
            (123456.0, "123456"),
            (1.7642e9, "1.7642e+09"),
            (-2.5, "-2.5"),
            (100.0, "100"),
            (f64::INFINITY, "+Inf"),
        ] {
            assert_eq!(fmt_float(f), want, "{f}");
        }
    }

    #[test]
    fn restart_reasons() {
        for (msg, want) in [
            ("", "unknown"),
            ("the machine restarted", "machine_restart"),
            ("crashed: out of memory", "out_of_memory"),
            ("failed its liveness probe", "liveness"),
            ("exited with code 1", "exited"),
            ("container gone", "exited"),
            ("something", "other"),
        ] {
            assert_eq!(restart_reason(msg), want);
        }
    }

    #[test]
    fn text_format() {
        let out = exposition(vec![
            Sample::new("armada_node_ready", vec![("node", "n2".into())], 1.0),
            Sample::new("armada_node_ready", vec![("node", "n1".into())], 0.0),
            Sample::new(
                "armada_revision_info",
                vec![
                    ("revision", "web--r1".into()),
                    ("app", "web".into()),
                    ("image", "nginx:\"1\"".into()),
                ],
                1.0,
            ),
        ]);
        assert_eq!(
            out,
            "# HELP armada_node_ready 1 when a node's agent is connected and the node is ready.\n\
             # TYPE armada_node_ready gauge\n\
             armada_node_ready{node=\"n1\"} 0\n\
             armada_node_ready{node=\"n2\"} 1\n\
             # HELP armada_revision_info 1 for each revision of an app that serves, rolls out, or still has replicas, with the image its spec names.\n\
             # TYPE armada_revision_info gauge\n\
             armada_revision_info{app=\"web\",image=\"nginx:\\\"1\\\"\",revision=\"web--r1\"} 1\n"
        );
    }
}

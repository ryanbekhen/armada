//! The spec's types, their defaults, and the methods that read them.

use std::collections::BTreeMap;

use crate::cron::Schedule as CronSchedule;
use crate::go;
use crate::gotime::{Location, Time, load_location};

/// The only accepted value for the optional apiVersion field.
pub const API_VERSION: &str = "armada.dev/v1alpha1";
/// The largest spec document.
pub const MAX_SPEC_BYTES: usize = 1 << 20;

pub const KIND_APP: &str = "app";
pub const KIND_JOB: &str = "job";

pub const INGRESS_EXTERNAL: &str = "external";
pub const INGRESS_INTERNAL: &str = "internal";
pub const INGRESS_NONE: &str = "none";

pub const PROTOCOL_HTTP: &str = "http";
pub const PROTOCOL_TCP: &str = "tcp";

pub const REVISIONS_SINGLE: &str = "single";
pub const REVISIONS_MULTIPLE: &str = "multiple";

pub const DNS_PROVIDER_CLOUDFLARE: &str = "cloudflare";

/// A duration written as a duration string ("10s", "1m30s"), in
/// nanoseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration(pub i64);

impl Duration {
    /// Duration.String.
    pub fn string(self) -> String {
        go::format_duration(self.0)
    }
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// An app or job spec.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct App {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub image: String,
    pub command: Vec<String>,
    pub args: Vec<String>,
    pub env: Vec<EnvVar>,
    pub env_from: EnvFrom,
    /// The variables envFrom added when the app was deployed (JSON only).
    pub env_from_added: Vec<String>,
    pub secret_files: Vec<SecretFile>,
    pub registry: Option<Registry>,
    pub ingress: Option<Ingress>,
    pub revisions: Option<Revisions>,
    pub probes: Option<Probes>,
    pub scale: Option<Scale>,
    pub resources: Option<Resources>,
    pub placement: Option<Placement>,
    pub volumes: Vec<Volume>,
    pub init_containers: Vec<Container>,
    pub sidecars: Vec<Container>,
    pub drain: Duration,
    /// The space, set by the API, never by the file.
    pub space: String,
    pub schedule: String,
    pub time_zone: String,
    pub timeout: Duration,
    pub retries: i64,
    pub concurrency: String,
    pub history: Option<i64>,
    pub tasks: i64,
    pub parallelism: i64,
    pub trigger: Option<Trigger>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
    pub secret_ref: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ingress {
    pub typ: String,
    pub protocol: String,
    pub port: i64,
    pub domains: Vec<String>,
    pub routes: Vec<Route>,
    pub allow: Vec<String>,
    pub ip_allow: Vec<IPRule>,
    pub ip_deny: Vec<IPRule>,
    pub sticky: bool,
    pub cors: Option<Cors>,
    pub timeout: Duration,
    pub dns: Option<IngressDns>,
}

impl Ingress {
    /// Ingress.TCP on a possibly nil ingress.
    pub fn tcp(i: Option<&Ingress>) -> bool {
        i.is_some_and(|i| i.protocol == PROTOCOL_TCP)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IngressDns {
    pub provider: String,
    pub token_secret_ref: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Route {
    pub path: String,
    pub strip_prefix: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Revisions {
    pub mode: String,
    pub traffic: Vec<TrafficTarget>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrafficTarget {
    pub revision: String,
    pub weight: i64,
    pub label: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Probes {
    pub startup: Option<Probe>,
    pub readiness: Option<Probe>,
    pub liveness: Option<Probe>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Probe {
    pub path: String,
    pub command: Vec<String>,
    pub port: i64,
    pub initial_delay: Duration,
    pub period: Duration,
    pub timeout: Duration,
    pub failure_threshold: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cors {
    /// None is a nil slice (JSON null), Some(empty) an empty one.
    pub allow_origins: Option<Vec<String>>,
    pub allow_methods: Vec<String>,
    pub allow_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    pub max_age: Duration,
    pub allow_credentials: bool,
}

impl Cors {
    pub fn origins(&self) -> &[String] {
        self.allow_origins.as_deref().unwrap_or(&[])
    }
    /// CORS.CORSMethods.
    pub fn cors_methods(&self) -> Vec<String> {
        if self.allow_methods.is_empty() {
            return vec!["GET".into(), "HEAD".into(), "POST".into()];
        }
        self.allow_methods.clone()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IPRule {
    pub range: String,
    pub name: String,
    pub description: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scale {
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub rules: Vec<ScaleRule>,
    pub idle_after: Duration,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScaleRule {
    pub typ: String,
    pub concurrent: i64,
    pub utilization: i64,
    pub command: Vec<String>,
    pub url_secret_ref: String,
    pub list: String,
    pub queue: String,
    pub length: i64,
    pub schedule: String,
    pub time_zone: String,
    pub duration: Duration,
    pub replicas: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resources {
    pub cpu: String,
    pub memory: String,
}

/// Placement; Require's keys sort as they are listed in JSON.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Placement {
    pub require: BTreeMap<String, LabelValues>,
    pub spread_by: String,
}

/// One or more label values; None is a nil slice.
pub type LabelValues = Option<Vec<String>>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Volume {
    pub name: String,
    pub path: String,
    pub owner: String,
    pub backup: Option<VolumeBackup>,
    pub failover: String,
    pub nfs: Option<NfsSource>,
}

impl Volume {
    /// Volume.Local.
    pub fn local(&self) -> bool {
        self.nfs.is_none()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NfsSource {
    pub server: String,
    pub path: String,
    pub read_only: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VolumeBackup {
    pub every: Duration,
    pub schedule: String,
    pub time_zone: String,
    pub keep: BackupKeep,
    pub url_secret_ref: String,
    pub key_secret_ref: String,
    pub stop: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackupKeep {
    pub last: i64,
    pub hourly: i64,
    pub daily: i64,
    pub weekly: i64,
    pub monthly: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Container {
    pub name: String,
    pub image: String,
    pub command: Vec<String>,
    pub args: Vec<String>,
    pub env: Vec<EnvVar>,
    pub resources: Option<Resources>,
    pub volumes: Vec<String>,
    pub secret_files: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretFile {
    pub secret_ref: String,
    pub path: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registry {
    pub server: String,
    pub username: String,
    pub password_secret_ref: String,
}

/// envFrom: the word "secrets" (own) or a list of the space's secrets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnvFrom {
    pub own: bool,
    /// None is a nil slice.
    pub secrets: Option<Vec<EnvFromSecret>>,
}

impl EnvFrom {
    pub fn list(&self) -> &[EnvFromSecret] {
        self.secrets.as_deref().unwrap_or(&[])
    }
    /// EnvFrom.IsZero.
    pub fn is_zero(&self) -> bool {
        !self.own && self.list().is_empty()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnvFromSecret {
    pub secret: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trigger {
    pub queue: Option<QueueTrigger>,
    pub polling_interval: Duration,
    pub parallelism: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueueTrigger {
    pub typ: String,
    pub url_secret_ref: String,
    pub list: String,
    pub queue: String,
    pub per_run: i64,
}

// Limits and defaults (validate.go).
pub const MAX_REPLICAS: i64 = 100;
pub const MIN_MEMORY_BYTES: i64 = 16 << 20;
pub const MAX_MEMORY_BYTES: i64 = 64 << 30;
pub const MIN_NANO_CPUS: i64 = 10_000_000;
pub const MAX_NANO_CPUS: i64 = 64_000_000_000;
pub const DEFAULT_MEMORY: &str = "256Mi";
pub const DEFAULT_CPU_MILLIS: i64 = 100;
pub const DEFAULT_PIDS: i64 = 1024;
const DEFAULT_PERIOD: i64 = 10 * go::SECOND;
const DEFAULT_TIMEOUT: i64 = go::SECOND;
const DEFAULT_FAILURES: i64 = 3;
const STARTUP_FAILURES: i64 = 30;

pub const MAX_DRAIN: i64 = go::HOUR;
pub const MAX_INGRESS_TIMEOUT: i64 = go::HOUR;

// Scale (validate.go, ADR 0020, 0021, 0034).
pub const SCALE_HTTP: &str = "http";
pub const SCALE_CPU: &str = "cpu";
pub const SCALE_MEMORY: &str = "memory";
pub const SCALE_QUEUE: &str = "queue";
pub const SCALE_REDIS: &str = "redis";
pub const SCALE_RABBITMQ: &str = "rabbitmq";
pub const SCALE_SCHEDULE: &str = "schedule";
pub const MAX_CONCURRENT: i64 = 10000;
pub const MAX_QUEUE_LENGTH: i64 = 1_000_000_000;
pub const MAX_SCHEDULE_RULES: i64 = 8;
pub const MAX_REDIS_LIST_LEN: usize = 1024;
pub const MAX_RABBITMQ_QUEUE_LEN: usize = 255;
pub const MIN_SCHEDULE_DURATION: i64 = go::MINUTE;
pub const MAX_SCHEDULE_DURATION: i64 = 7 * 24 * go::HOUR;
pub const DEFAULT_IDLE_AFTER: i64 = 15 * go::MINUTE;
pub const MIN_IDLE_AFTER: i64 = go::MINUTE;
pub const MAX_IDLE_AFTER: i64 = 24 * go::HOUR;

// Jobs (job.go).
pub const DEFAULT_JOB_TIMEOUT: i64 = go::HOUR;
pub const MAX_JOB_TIMEOUT: i64 = 24 * go::HOUR;
pub const MIN_JOB_TIMEOUT: i64 = go::SECOND;
pub const MAX_JOB_RETRIES: i64 = 10;
pub const DEFAULT_JOB_HISTORY: i64 = 5;
pub const MAX_JOB_HISTORY: i64 = 50;
pub const MAX_JOB_TASKS: i64 = 100;
pub const CONCURRENCY_FORBID: &str = "forbid";
pub const CONCURRENCY_REPLACE: &str = "replace";

// Triggers (trigger.go).
pub const DEFAULT_POLLING_INTERVAL: i64 = 30 * go::SECOND;
pub const MIN_POLLING_INTERVAL: i64 = 10 * go::SECOND;
pub const MAX_POLLING_INTERVAL: i64 = 10 * go::MINUTE;
pub const MAX_JOB_PARALLELISM: i64 = 50;
pub const MAX_NODE_QUEUE_SANDBOXES: i64 = 64;

// Containers (containers.go).
pub const MAX_INIT_CONTAINERS: usize = 4;
pub const MAX_SIDECARS: usize = 4;
pub const MAIN_CONTAINER: &str = "app";
pub const DEFAULT_CONTAINER_MEMORY: &str = "64Mi";
pub const DEFAULT_CONTAINER_CPU_MILLIS: i64 = 10;

// Volumes and backups (volume.go, backup.go).
pub const FAILOVER_RESTORE: &str = "restore";
pub const MAX_VOLUMES: usize = 8;
pub const MIN_BACKUP_EVERY: i64 = 5 * go::MINUTE;
pub const MAX_BACKUP_EVERY: i64 = 7 * 24 * go::HOUR;
pub const MAX_BACKUP_KEEP: i64 = 1000;
pub const MIN_BACKUP_KEY_LEN: usize = 32;

/// maxWindowChain bounds how many back-to-back fires extend one schedule
/// window.
const MAX_WINDOW_CHAIN: usize = 64;

impl App {
    /// SetDefaults fills optional fields; parse calls it before validate.
    pub fn set_defaults(&mut self) {
        if self.kind.is_empty() {
            self.kind = KIND_APP.to_string();
        }
        if self.ingress.is_none() {
            self.ingress = Some(Ingress {
                typ: INGRESS_NONE.to_string(),
                ..Ingress::default()
            });
        }
        let rev = self.revisions.get_or_insert_with(Revisions::default);
        if rev.mode.is_empty() {
            rev.mode = REVISIONS_SINGLE.to_string();
        }
        let port = self.ingress.as_ref().map_or(0, |i| i.port);
        if let Some(p) = &mut self.probes {
            for (probe, failures) in [
                (&mut p.startup, STARTUP_FAILURES),
                (&mut p.readiness, DEFAULT_FAILURES),
                (&mut p.liveness, DEFAULT_FAILURES),
            ] {
                let Some(probe) = probe else { continue };
                if probe.port == 0 && probe.command.is_empty() {
                    probe.port = port;
                }
                if probe.period.0 == 0 {
                    probe.period = Duration(DEFAULT_PERIOD);
                }
                if probe.timeout.0 == 0 {
                    probe.timeout = Duration(DEFAULT_TIMEOUT);
                }
                if probe.failure_threshold == 0 {
                    probe.failure_threshold = failures;
                }
            }
        }
        if self.scale.is_none() && !self.is_job() {
            self.scale = Some(Scale::default());
        }
        if let Some(s) = &mut self.scale {
            if s.min.is_none() {
                s.min = Some(1);
            }
            if s.max.is_none() {
                s.max = s.min;
            }
        }
        let r = self.resources.get_or_insert_with(Resources::default);
        if r.memory.is_empty() {
            r.memory = DEFAULT_MEMORY.to_string();
        }
    }

    /// The app's ID (spec.AppID).
    pub fn id(&self) -> String {
        crate::validate::app_id(&self.space, &self.name)
    }

    pub fn is_job(&self) -> bool {
        self.kind == KIND_JOB
    }

    /// Autoscaled: the autoscaler sets the replica count.
    pub fn autoscaled(&self) -> bool {
        !self.is_job() && self.scale.as_ref().is_some_and(|s| !s.rules.is_empty())
    }

    /// ScaleBounds returns scale.min and scale.max.
    pub fn scale_bounds(&self) -> (i64, i64) {
        if self.is_job() {
            return (0, 0);
        }
        let mut lo = 1;
        if let Some(m) = self.scale.as_ref().and_then(|s| s.min) {
            lo = m;
        }
        let mut hi = lo;
        if let Some(m) = self.scale.as_ref().and_then(|s| s.max) {
            hi = m;
        }
        (lo, hi)
    }

    pub fn scales_to_zero(&self) -> bool {
        self.autoscaled() && self.scale_bounds().0 == 0
    }

    /// IdleAfter, in nanoseconds.
    pub fn idle_after(&self) -> i64 {
        match &self.scale {
            Some(s) if s.idle_after.0 != 0 => s.idle_after.0,
            _ => DEFAULT_IDLE_AFTER,
        }
    }

    pub fn replicas(&self) -> i64 {
        if self.is_job() {
            return 0;
        }
        self.scale_bounds().0.max(1)
    }

    pub fn memory_bytes(&self) -> i64 {
        match &self.resources {
            None => crate::validate::parse_memory(DEFAULT_MEMORY).unwrap_or(0),
            Some(r) => crate::validate::parse_memory(&r.memory).unwrap_or(0),
        }
    }

    pub fn nano_cpus(&self) -> i64 {
        match &self.resources {
            Some(r) if !r.cpu.is_empty() => crate::validate::parse_cpu(&r.cpu).unwrap_or(0),
            _ => 0,
        }
    }

    pub fn cpu_millis(&self) -> i64 {
        let n = self.nano_cpus();
        if n > 0 {
            return (n / 1_000_000).max(1);
        }
        DEFAULT_CPU_MILLIS
    }

    pub fn multiple_revisions(&self) -> bool {
        !self.is_job()
            && self
                .revisions
                .as_ref()
                .is_some_and(|r| r.mode == REVISIONS_MULTIPLE)
    }

    /// QueueRules: the rules that read a queue's length.
    pub fn queue_rules(&self) -> Vec<ScaleRule> {
        if !self.autoscaled() {
            return Vec::new();
        }
        self.scale.as_ref().map_or_else(Vec::new, |s| {
            s.rules.iter().filter(|r| r.is_queue()).cloned().collect()
        })
    }

    pub fn has_containers(&self) -> bool {
        !self.init_containers.is_empty() || !self.sidecars.is_empty()
    }

    pub fn container_names(&self) -> Vec<String> {
        self.init_containers
            .iter()
            .chain(&self.sidecars)
            .map(|c| c.name.clone())
            .collect()
    }

    pub fn reserved_cpu_millis(&self) -> i64 {
        let run = self.cpu_millis() + self.sidecars.iter().map(Container::cpu_millis).sum::<i64>();
        let init = self
            .init_containers
            .iter()
            .map(Container::cpu_millis)
            .max()
            .unwrap_or(0);
        run.max(init)
    }

    pub fn reserved_memory_bytes(&self) -> i64 {
        let run = self.memory_bytes()
            + self
                .sidecars
                .iter()
                .map(Container::memory_bytes)
                .sum::<i64>();
        let init = self
            .init_containers
            .iter()
            .map(Container::memory_bytes)
            .max()
            .unwrap_or(0);
        run.max(init)
    }

    pub fn fails_over(&self) -> bool {
        self.has_local_volumes()
            && !self
                .volumes
                .iter()
                .any(|v| v.local() && v.failover != FAILOVER_RESTORE)
    }

    pub fn has_volumes(&self) -> bool {
        !self.volumes.is_empty()
    }

    pub fn has_local_volumes(&self) -> bool {
        self.volumes.iter().any(Volume::local)
    }

    pub fn has_nfs_volumes(&self) -> bool {
        self.volumes.iter().any(|v| !v.local())
    }

    /// JobSchedule: the job's schedule, None for jobs without one.
    pub fn job_schedule(&self) -> Option<Schedule> {
        if self.schedule.is_empty() {
            return None;
        }
        let (s, loc) = parse_schedule(&self.schedule, &self.time_zone).ok()?;
        Some(Schedule { s, loc })
    }

    pub fn job_timeout(&self) -> i64 {
        if self.timeout.0 == 0 {
            DEFAULT_JOB_TIMEOUT
        } else {
            self.timeout.0
        }
    }

    pub fn job_history(&self) -> i64 {
        self.history.unwrap_or(DEFAULT_JOB_HISTORY)
    }

    pub fn job_tasks(&self) -> i64 {
        self.tasks.max(1)
    }

    pub fn job_parallelism(&self) -> i64 {
        if self.parallelism == 0 {
            return self.job_tasks();
        }
        self.parallelism.min(self.job_tasks())
    }

    pub fn job_concurrency(&self) -> String {
        if self.concurrency.is_empty() {
            CONCURRENCY_FORBID.to_string()
        } else {
            self.concurrency.clone()
        }
    }

    pub fn queue_trigger(&self) -> Option<&QueueTrigger> {
        self.trigger.as_ref().and_then(|t| t.queue.as_ref())
    }
}

impl ScaleRule {
    pub fn is_queue(&self) -> bool {
        self.typ == SCALE_QUEUE || self.typ == SCALE_REDIS || self.typ == SCALE_RABBITMQ
    }

    /// Window reports whether a schedule rule's window is open at now, and
    /// when it closes.
    pub fn window(&self, now: &Time) -> (bool, Time) {
        if self.typ != SCALE_SCHEDULE {
            return (false, Time::zero());
        }
        let Ok((s, loc)) = parse_schedule(&self.schedule, &self.time_zone) else {
            return (false, Time::zero());
        };
        let d = self.duration.0;
        let mut start = s.next(&now.add(-d).in_loc(&loc));
        if start.after(now) {
            return (false, Time::zero());
        }
        let mut until = start.add(d);
        for _ in 0..MAX_WINDOW_CHAIN {
            let next = s.next(&start);
            if !next.before(&until) {
                break;
            }
            until = next.add(d);
            start = next;
        }
        (true, until)
    }
}

impl Container {
    pub fn memory_bytes(&self) -> i64 {
        let m = match &self.resources {
            Some(r) if !r.memory.is_empty() => r.memory.as_str(),
            _ => DEFAULT_CONTAINER_MEMORY,
        };
        crate::validate::parse_memory(m).unwrap_or(0)
    }

    pub fn nano_cpus(&self) -> i64 {
        match &self.resources {
            Some(r) if !r.cpu.is_empty() => crate::validate::parse_cpu(&r.cpu).unwrap_or(0),
            _ => 0,
        }
    }

    pub fn cpu_millis(&self) -> i64 {
        let n = self.nano_cpus();
        if n > 0 {
            return (n / 1_000_000).max(1);
        }
        DEFAULT_CONTAINER_CPU_MILLIS
    }
}

impl QueueTrigger {
    /// The Redis list or the RabbitMQ queue the trigger reads.
    pub fn name(&self) -> &str {
        if self.typ == SCALE_RABBITMQ {
            &self.queue
        } else {
            &self.list
        }
    }
}

impl Trigger {
    /// PollEvery on a possibly nil trigger, in nanoseconds.
    pub fn poll_every(t: Option<&Trigger>) -> i64 {
        match t {
            Some(t) if t.polling_interval.0 != 0 => t.polling_interval.0,
            _ => DEFAULT_POLLING_INTERVAL,
        }
    }

    /// MaxRuns on a possibly nil trigger.
    pub fn max_runs(t: Option<&Trigger>) -> i64 {
        match t {
            Some(t) if t.parallelism != 0 => t.parallelism,
            _ => 1,
        }
    }

    /// RunsWanted: ⌈length ÷ perRun⌉, at most the trigger's parallelism.
    pub fn runs_wanted(&self, length: i64) -> i64 {
        let Some(q) = &self.queue else { return 0 };
        if length <= 0 || q.per_run <= 0 {
            return 0;
        }
        // length + perRun - 1 wraps on overflow.
        let n = length.wrapping_add(q.per_run - 1) / q.per_run;
        n.min(Trigger::max_runs(Some(self)))
    }
}

impl VolumeBackup {
    /// Next returns when the backup after one at last is due.
    pub fn next(&self, last: &Time) -> Time {
        if self.every.0 != 0 {
            return last.add(self.every.0);
        }
        match parse_schedule(&self.schedule, &self.time_zone) {
            Ok((s, loc)) => s.next(&last.in_loc(&loc)),
            Err(_) => Time::zero(),
        }
    }

    /// Location: the zone Keep counts backups in.
    pub fn location(&self) -> Location {
        if !self.time_zone.is_empty()
            && let Some(l) = load_location(&self.time_zone)
        {
            return l;
        }
        Location::utc()
    }
}

/// A parsed job schedule in its time zone.
#[derive(Clone, Debug)]
pub struct Schedule {
    s: CronSchedule,
    loc: Location,
}

impl Schedule {
    /// Next returns the first time after t that the schedule fires.
    pub fn next(&self, t: &Time) -> Time {
        self.s.next(&t.in_loc(&self.loc))
    }
}

/// parseSchedule: the zone first, then the five fields.
pub fn parse_schedule(expr: &str, zone: &str) -> Result<(CronSchedule, Location), String> {
    let mut loc = Location::utc();
    if !zone.is_empty() {
        loc =
            load_location(zone).ok_or_else(|| format!("unknown time zone {}", go::quote(zone)))?;
    }
    if expr.starts_with('@') || expr.contains("TZ=") {
        return Err("use five fields (minute hour day-of-month month day-of-week), and timeZone for the zone".to_string());
    }
    let s = CronSchedule::parse(expr).map_err(|e| format!("invalid schedule: {e}"))?;
    Ok((s, loc))
}

/// FairOrder orders app IDs one space at a time.
pub fn fair_order(ids: &[String]) -> Vec<String> {
    let mut by_space: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for id in ids {
        let sp = crate::validate::split_app_id(id).map_or(String::new(), |(s, _)| s);
        by_space.entry(sp).or_default().push(id.clone());
    }
    let mut out = Vec::with_capacity(ids.len());
    let mut round = 0;
    while out.len() < ids.len() {
        for list in by_space.values() {
            if let Some(id) = list.get(round) {
                out.push(id.clone());
            }
        }
        round += 1;
    }
    out
}

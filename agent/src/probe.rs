//! Startup, readiness, and liveness probes: HTTP, TCP, or a
//! command run in the container like `armada app exec`.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use armada_proto::armada::v1 as pb;

use crate::agent::{Inner, join_host_port, lock};
use crate::runtime::{Container, Runtime};

/// Without a readiness probe, an app with a port is ready once the port
/// accepts connections.
pub(crate) fn implicit_readiness() -> pb::Probe {
    pb::Probe {
        period_ms: 1000,
        timeout_ms: 1000,
        failure_threshold: 3,
        ..Default::default()
    }
}

/// How often the implicit check runs while the port answers.
pub const IMPLICIT_STEADY_EVERY: Duration = Duration::from_secs(10);

#[derive(Default)]
struct ProbeStatus {
    ready: bool,
    /// The probes have reached a verdict.
    checked: bool,
    message: String,
    /// Why the container was restarted: prefixes every message until it
    /// has been reported while ready.
    note: String,
}

/// The probes of one container.
pub(crate) struct ProbeWorker {
    pub container_id: String,
    task: Mutex<Option<tokio::task::AbortHandle>>,
    s: Mutex<ProbeStatus>,
}

impl ProbeWorker {
    pub fn status(&self) -> (bool, String) {
        let s = lock(&self.s);
        (s.ready, s.message.clone())
    }

    pub fn has_verdict(&self) -> bool {
        lock(&self.s).checked
    }

    /// Records a verdict; whether readiness changed.
    pub fn set(&self, ready: bool, msg: &str) -> bool {
        let mut s = lock(&self.s);
        let changed = s.ready != ready;
        s.checked = true;
        let msg = match (s.note.is_empty(), msg.is_empty()) {
            (false, false) => format!("{}; {msg}", s.note),
            (false, true) => s.note.clone(),
            _ => msg.to_string(),
        };
        s.ready = ready;
        s.message = msg;
        changed
    }

    /// Drops the restart note once reported for a ready container.
    pub fn clear_note(&self) {
        let mut s = lock(&self.s);
        if s.ready && !s.note.is_empty() {
            s.note.clear();
            s.message.clear();
        }
    }

    pub fn cancel(&self) {
        if let Some(t) = lock(&self.task).take() {
            t.abort();
        }
    }
}

/// v milliseconds, or def when not positive.
fn millis(v: i64, def: Duration) -> Duration {
    if v <= 0 {
        def
    } else {
        Duration::from_millis(v as u64)
    }
}

fn threshold(p: &pb::Probe) -> u32 {
    if p.failure_threshold > 0 {
        p.failure_threshold as u32
    } else {
        3
    }
}

/// How long the implicit check waits; the steady period varies a little
/// to spread the checks of containers that started together.
fn implicit_period(ready: bool, failures: u32) -> Duration {
    if !ready || failures > 0 {
        return millis(implicit_readiness().period_ms, Duration::from_secs(1));
    }
    let spread = IMPLICIT_STEADY_EVERY.as_nanos() as u64 / 5;
    IMPLICIT_STEADY_EVERY - IMPLICIT_STEADY_EVERY / 10 + Duration::from_nanos(random() % spread)
}

/// A number for spreading checks (not security sensitive).
fn random() -> u64 {
    use std::hash::{BuildHasher, RandomState};
    RandomState::new().hash_one(std::time::SystemTime::now())
}

/// Runs check every period after the initial delay and passes each result
/// with the count of consecutive failures to f until f returns true.
async fn watch_every<C, CF, E, F>(check: C, p: &pb::Probe, every: E, mut f: F)
where
    C: Fn() -> CF,
    CF: Future<Output = Result<(), String>>,
    E: Fn(u32) -> Duration,
    F: FnMut(Option<String>, u32) -> bool,
{
    let d = millis(p.initial_delay_ms, Duration::ZERO);
    if !d.is_zero() {
        tokio::time::sleep(d).await;
    }
    let mut failures = 0u32;
    loop {
        let err = check().await.err();
        if err.is_some() {
            failures += 1;
        } else {
            failures = 0;
        }
        if f(err, failures) {
            return;
        }
        let d = every(failures);
        if !d.is_zero() {
            tokio::time::sleep(d).await;
        }
    }
}

/// Where probe p of container c goes: only the container itself, with a
/// validated path.
pub(crate) fn probe_addr(
    s: &pb::ReplicaSpec,
    c: &Container,
    p: &pb::Probe,
) -> Result<String, String> {
    if !p.path.is_empty() {
        armada_spec::validate::validate_probe_path(&p.path)
            .map_err(|e| format!("invalid probe path: {e}"))?;
    }
    let port = if p.port == 0 { s.port } else { p.port };
    if !(1..=65535).contains(&port) {
        return Err(format!("invalid probe port {port}"));
    }
    if !c.ip.is_empty() {
        return Ok(join_host_port(&c.ip, i64::from(port)));
    }
    // Without a bridge IP only the published app port is reachable.
    if port == s.port && c.host_port != 0 {
        return Ok(join_host_port(&c.host_ip, c.host_port));
    }
    Err(format!("container has no address for port {port}"))
}

impl<R: Runtime> Inner<R> {
    /// Starts the worker for container c of replica s. message shows until
    /// the replica first becomes ready.
    pub(crate) fn start_probes(
        self: &Arc<Self>,
        s: &pb::ReplicaSpec,
        c: &Container,
        message: String,
    ) -> Arc<ProbeWorker> {
        let w = Arc::new(ProbeWorker {
            container_id: c.id.clone(),
            task: Mutex::new(None),
            s: Mutex::new(ProbeStatus {
                message: message.clone(),
                note: message,
                ..ProbeStatus::default()
            }),
        });
        let t = tokio::spawn(self.clone().run_probes(w.clone(), s.clone(), c.clone()));
        *lock(&w.task) = Some(t.abort_handle());
        w
    }

    /// One check of probe p.
    async fn check_probe(
        &self,
        s: &pb::ReplicaSpec,
        c: &Container,
        p: &pb::Probe,
    ) -> Result<(), String> {
        let timeout = millis(p.timeout_ms, Duration::from_secs(1));
        if !p.command.is_empty() {
            return self.check_command(&c.id, &p.command, timeout).await;
        }
        let addr = probe_addr(s, c, p)?;
        // The check words its own timeout; the agent's bound is a little
        // later, for a check that ignores it.
        match tokio::time::timeout(
            timeout + Duration::from_millis(100),
            (self.check)(addr, p.path.clone(), timeout),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => Err("context deadline exceeded".to_string()),
        }
    }

    /// Runs a probe's command in the container with the container's own
    /// security settings; its output is dropped and its arguments stay out
    /// of the result.
    async fn check_command(
        &self,
        id: &str,
        cmd: &[String],
        timeout: Duration,
    ) -> Result<(), String> {
        if !self.rt.can_exec() {
            return Err("this node's runtime cannot run commands in containers".to_string());
        }
        match tokio::time::timeout(timeout, self.rt.exec_app(id, cmd)).await {
            Err(_) => Err("command timed out".to_string()),
            Ok(Err(_)) => {
                Err("could not run the command; is the program in the image?".to_string())
            }
            Ok(Ok(code)) if code != 0 => Err(format!("command exited with code {code}")),
            Ok(Ok(_)) => Ok(()),
        }
    }

    fn restart(&self, w: &ProbeWorker, replica: &str, reason: String) {
        lock(&self.st)
            .restarts
            .insert(w.container_id.clone(), reason.clone());
        self.log.warn(
            "restarting replica",
            &[("replica", replica.to_string()), ("reason", reason)],
        );
        self.trigger.notify_one();
    }

    async fn run_probes(self: Arc<Self>, w: Arc<ProbeWorker>, s: pb::ReplicaSpec, c: Container) {
        if let Some(p) = &s.startup {
            let mut started = false;
            let every = |_| millis(p.period_ms, Duration::from_secs(10));
            watch_every(
                || self.check_probe(&s, &c, p),
                p,
                every,
                |err, failures| match err {
                    None => {
                        started = true;
                        true
                    }
                    Some(e) if failures >= threshold(p) => {
                        self.restart(&w, &s.id, format!("startup probe failed: {e}"));
                        true
                    }
                    Some(_) => false,
                },
            )
            .await;
            if !started {
                return;
            }
        }

        let readiness = s
            .readiness
            .clone()
            .or_else(|| (s.port > 0).then(implicit_readiness));
        if readiness.is_none() && w.set(true, "") {
            self.trigger.notify_one();
        }
        let live = async {
            if let Some(p) = &s.liveness {
                let every = |_| millis(p.period_ms, Duration::from_secs(10));
                watch_every(
                    || self.check_probe(&s, &c, p),
                    p,
                    every,
                    |err, failures| {
                        if let Some(e) = err
                            && failures >= threshold(p)
                        {
                            self.restart(&w, &s.id, format!("liveness probe failed: {e}"));
                            return true;
                        }
                        false
                    },
                )
                .await;
            }
        };
        let ready = async {
            let Some(r) = &readiness else { return };
            let explicit = s.readiness.is_some();
            let every = |failures: u32| {
                if explicit {
                    millis(r.period_ms, Duration::from_secs(10))
                } else {
                    implicit_period(w.status().0, failures)
                }
            };
            watch_every(
                || self.check_probe(&s, &c, r),
                r,
                every,
                |err, failures| {
                    let (was, _) = w.status();
                    let changed = match err {
                        None => w.set(true, ""),
                        // The threshold guards against flapping out of
                        // service; a replica not ready yet shows why at once.
                        Some(e) if !was || failures >= threshold(r) => {
                            w.set(false, &format!("readiness probe failed: {e}"))
                        }
                        Some(_) => false,
                    };
                    if changed {
                        self.trigger.notify_one();
                    }
                    false
                },
            )
            .await;
        };
        tokio::join!(live, ready);
    }
}

//! The node's resolver behind the agent's [`InternalDns`] seam (ADR 0055,
//! item 16d): armada-dns (ADR 0053) in a systemd unit of its own, told the
//! names and clients over its control socket, as Go's
//! internal/dnsserver/process.go does. The unit's name comes from the
//! program and its settings exactly as Go makes it, so an agent of either
//! language finds the unit the other started and keeps it; a unit of
//! another program or other settings hands what it knows to the new one
//! (`--take-over`), which shares the port until the old one drained.
//!
//! The control protocol: one request line per connection (`names APP...`,
//! `clients IP=APP...`, `epoch`, `state`, `drain`), answered with `ok
//! EPOCH` or `err TEXT`. A process with a new epoch (it restarted) is told
//! everything again.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::log::Logger;
use crate::proxy::{BoxFut, Clients, InternalDns};

/// The systemd units armada-dns runs in.
pub const UNIT_PREFIX: &str = "armada-dns-";

/// Bounds one request to armada-dns.
pub const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a new armada-dns has to open its control socket.
pub const READY_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the agent checks armada-dns still runs.
pub const KEEP_EVERY: Duration = Duration::from_secs(5);
/// The largest answer read.
const MAX_ANSWER: u64 = 64 << 20;

/// Starts and stops the units armada-dns runs in; tests use plain
/// processes.
pub trait Launcher: Send + Sync + 'static {
    /// Runs argv as unit, restarted by its manager when it exits.
    fn start<'a>(&'a self, unit: &'a str, argv: &'a [String]) -> BoxFut<'a, Result<(), String>>;
    /// Stops unit; a unit that does not run is no error.
    fn stop<'a>(&'a self, unit: &'a str) -> BoxFut<'a, Result<(), String>>;
    /// The units whose name starts with UNIT_PREFIX and run.
    fn units(&self) -> BoxFut<'_, Result<Vec<String>, String>>;
}

/// What a DnsProcess runs with (Go's ProcessConfig).
#[derive(Clone)]
pub struct ProcessConfig {
    /// The armada-dns program.
    pub bin: PathBuf,
    /// Where it listens: the bridge's gateway.
    pub addr: Ipv4Addr,
    /// 0 for 53.
    pub port: u16,
    /// The containers' range (an IPv4 prefix).
    pub clients: String,
    pub upstreams: Vec<String>,
    pub unknown_wait: Duration,
    pub start_wait: Duration,
    /// Holds the control sockets (root-only).
    pub dir: PathBuf,
    /// None: systemd.
    pub launcher: Option<Arc<dyn Launcher>>,
    pub logger: Logger,
}

/// What the agent said last (None: not yet), and the process that heard
/// it.
#[derive(Default)]
struct Said {
    names: Option<Vec<String>>,
    clients: Option<Clients>,
    epoch: String,
}

/// The node-local resolver run by armada-dns (Go's dnsserver.Process).
pub struct DnsProcess {
    addr: Ipv4Addr,
    unit: String,
    sock: PathBuf,
    argv: Vec<String>,
    dir: PathBuf,
    launcher: Arc<dyn Launcher>,
    log: Logger,
    upstreams: Vec<String>,
    said: Mutex<Said>,
}

/// netutil.IsPrivate for an IPv4 address.
fn private4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_private() || a.is_loopback() || (o[0] == 100 && (o[1] & 0xc0) == 64)
}

/// netip.ParsePrefix of an IPv4 prefix, masked: its text.
fn masked4(s: &str) -> Option<String> {
    let (ip, bits) = s.split_once('/')?;
    let ip: Ipv4Addr = ip.parse().ok()?;
    if bits.is_empty() || (bits.len() > 1 && bits.starts_with('0')) {
        return None;
    }
    let bits: u32 = bits.parse().ok()?;
    if bits > 32 {
        return None;
    }
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    Some(format!("{}/{bits}", Ipv4Addr::from(u32::from(ip) & mask)))
}

/// The unit's ID and its arguments, as Go makes them from the program's
/// bytes and the settings.
pub fn unit_id(bin: &[u8], args: &[String]) -> String {
    let mut h = Sha256::new();
    h.update(bin);
    for a in args {
        h.update([0u8]);
        h.update(a.as_bytes());
    }
    let sum = h.finalize();
    sum.iter().map(|b| format!("{b:02x}")).collect::<String>()[..16].to_string()
}

/// The settings' arguments (before --control).
fn settings(cfg: &ProcessConfig, clients: &str) -> Vec<String> {
    let mut args = vec![
        "--listen".to_string(),
        format!("{}:{}", cfg.addr, if cfg.port == 0 { 53 } else { cfg.port }),
        "--clients".to_string(),
        clients.to_string(),
    ];
    for u in &cfg.upstreams {
        args.push("--upstream".into());
        args.push(u.clone());
    }
    if !cfg.unknown_wait.is_zero() {
        args.push("--unknown-wait-ms".into());
        args.push(cfg.unknown_wait.as_millis().to_string());
    }
    if !cfg.start_wait.is_zero() {
        args.push("--start-wait-ms".into());
        args.push(cfg.start_wait.as_millis().to_string());
    }
    args
}

fn names_line(names: &[String]) -> String {
    std::iter::once("names")
        .chain(names.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

fn clients_line(clients: &Clients) -> String {
    let mut words: Vec<String> = clients
        .iter()
        .filter(|(a, _)| a.is_ipv4())
        .map(|(a, app)| format!("{a}={app}"))
        .collect();
    words.sort();
    std::iter::once("clients".to_string())
        .chain(words)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Sends one request line to the armada-dns at sock and returns its answer
/// without the trailing line break.
pub async fn control(sock: &Path, line: &str) -> Result<String, String> {
    let call = async {
        let mut c = tokio::net::UnixStream::connect(sock)
            .await
            .map_err(|e| e.to_string())?;
        c.write_all(format!("{line}\n").as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut b = Vec::new();
        (&mut c)
            .take(MAX_ANSWER)
            .read_to_end(&mut b)
            .await
            .map_err(|e| e.to_string())?;
        Ok::<_, String>(b)
    };
    let b = tokio::time::timeout(CONTROL_TIMEOUT, call)
        .await
        .map_err(|_| "i/o timeout".to_string())??;
    let text = String::from_utf8_lossy(&b);
    let reply = text.strip_suffix('\n').unwrap_or(&text);
    if let Some(rest) = reply.strip_prefix("err ") {
        return Err(format!("armada-dns: {rest}"));
    }
    if reply.is_empty() {
        return Err("armada-dns: no answer".into());
    }
    Ok(reply.to_string())
}

impl DnsProcess {
    /// Runs armada-dns, or finds it running from an earlier agent; a unit
    /// of another program or other settings hands over to the new one,
    /// then is stopped.
    pub async fn start(cfg: ProcessConfig) -> Result<Arc<DnsProcess>, String> {
        if !private4(cfg.addr) {
            return Err(format!(
                "dns: listen address {} must be a private IPv4 address",
                cfg.addr
            ));
        }
        let clients = masked4(&cfg.clients).ok_or("dns: an IPv4 client range is required")?;
        let bin = std::fs::read(&cfg.bin).map_err(|e| format!("dns: {e}"))?;
        std::fs::create_dir_all(&cfg.dir).map_err(|e| format!("dns: {e}"))?;
        let args = settings(&cfg, &clients);
        let id = unit_id(&bin, &args);
        let sock = cfg.dir.join(format!("{id}.sock"));
        let mut argv = vec![cfg.bin.to_string_lossy().into_owned()];
        argv.extend(args);
        argv.push("--control".into());
        argv.push(sock.to_string_lossy().into_owned());
        let p = Arc::new(DnsProcess {
            addr: cfg.addr,
            unit: format!("{UNIT_PREFIX}{id}"),
            sock,
            argv,
            dir: cfg.dir.clone(),
            launcher: cfg.launcher.clone().unwrap_or_else(|| Arc::new(Systemd)),
            log: cfg.logger.with("component", "dns"),
            upstreams: cfg.upstreams.clone(),
            said: Mutex::new(Said::default()),
        });
        p.ensure().await?;
        p.hand_over().await;
        Ok(p)
    }

    /// The systemd unit armada-dns runs in.
    pub fn unit(&self) -> &str {
        &self.unit
    }

    async fn call(&self, line: &str) -> Result<String, String> {
        control(&self.sock, line).await
    }

    /// The control socket of another armada-dns unit.
    fn old_socket(&self, unit: &str) -> PathBuf {
        self.dir.join(format!(
            "{}.sock",
            unit.strip_prefix(UNIT_PREFIX).unwrap_or(unit)
        ))
    }

    async fn wait_ready(&self) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
        loop {
            let res = self.call("epoch").await;
            if res.is_ok() || tokio::time::Instant::now() > deadline {
                return res.map(|_| ());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Makes the unit answer: as it is, or started (again).
    async fn ensure(&self) -> Result<(), String> {
        if self.call("epoch").await.is_ok() {
            return Ok(());
        }
        let units = self
            .launcher
            .units()
            .await
            .map_err(|e| format!("dns: {e}"))?;
        if units.contains(&self.unit) {
            // Starting, or stuck: give it the time a start has.
            if self.wait_ready().await.is_ok() {
                return Ok(());
            }
            self.launcher
                .stop(&self.unit)
                .await
                .map_err(|e| format!("dns: {e}"))?;
        }
        let mut argv = self.argv.clone();
        for u in &units {
            if u != &self.unit && u.starts_with(UNIT_PREFIX) {
                argv.push("--take-over".into());
                argv.push(self.old_socket(u).to_string_lossy().into_owned());
            }
        }
        self.launcher
            .start(&self.unit, &argv)
            .await
            .map_err(|e| format!("dns: start {}: {e}", self.unit))?;
        if let Err(e) = self.wait_ready().await {
            let _ = self.launcher.stop(&self.unit).await;
            return Err(format!("dns: {} did not answer: {e}", self.unit));
        }
        self.log.info(
            "internal DNS started",
            &[
                ("unit", self.unit.clone()),
                ("addr", self.addr.to_string()),
                ("upstreams", format!("[{}]", self.upstreams.join(" "))),
            ],
        );
        Ok(())
    }

    /// Stops every other armada-dns unit, whose names and clients the new
    /// process took over.
    async fn hand_over(&self) {
        let units = match self.launcher.units().await {
            Ok(u) => u,
            Err(e) => {
                self.log
                    .warn("cannot list internal DNS units", &[("err", e)]);
                return;
            }
        };
        for u in units {
            if u == self.unit || !u.starts_with(UNIT_PREFIX) {
                continue;
            }
            let old = self.old_socket(&u);
            if let Err(e) = control(&old, "drain").await {
                self.log.warn(
                    "old internal DNS did not drain",
                    &[("unit", u.clone()), ("err", e)],
                );
            }
            if let Err(e) = self.launcher.stop(&u).await {
                self.log.warn(
                    "cannot stop the old internal DNS",
                    &[("unit", u.clone()), ("err", e)],
                );
                continue;
            }
            let _ = std::fs::remove_file(&old);
            let _ = std::fs::remove_file(old.with_extension("state"));
            self.log.info(
                "internal DNS handed over",
                &[("from", u), ("to", self.unit.clone())],
            );
        }
    }

    /// Everything the agent said, as requests.
    fn lines(s: &Said) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(c) = &s.clients {
            out.push(clients_line(c));
        }
        if let Some(n) = &s.names {
            out.push(names_line(n));
        }
        out
    }

    /// Sends one request with the lock held. A process that has not heard
    /// everything yet is told all of it; a failure is retried by run.
    async fn push(&self, s: &mut Said, line: String) {
        let reply = match self.call(&line).await {
            Ok(r) => r,
            Err(e) => {
                self.log.warn(
                    "internal DNS did not take the update; retrying",
                    &[("err", e)],
                );
                s.epoch.clear();
                return;
            }
        };
        let epoch = reply.strip_prefix("ok ").unwrap_or(&reply).to_string();
        if epoch != s.epoch {
            s.epoch.clear();
            for l in Self::lines(s) {
                if let Err(e) = self.call(&l).await {
                    self.log.warn(
                        "internal DNS did not take the update; retrying",
                        &[("err", e)],
                    );
                    return;
                }
            }
            s.epoch = epoch;
        }
    }

    /// Keeps armada-dns running and up to date until the task is dropped:
    /// a process that restarted, or one that missed an update, hears
    /// everything again.
    pub async fn run(self: Arc<Self>) {
        let mut t = tokio::time::interval(KEEP_EVERY);
        t.tick().await;
        loop {
            t.tick().await;
            self.keep().await;
        }
    }

    /// One check of run.
    pub async fn keep(&self) {
        let ensure = tokio::time::timeout(READY_TIMEOUT + 2 * CONTROL_TIMEOUT, self.ensure());
        match ensure.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                self.log.warn("internal DNS is not running", &[("err", e)]);
                return;
            }
            Err(_) => {
                self.log.warn(
                    "internal DNS is not running",
                    &[("err", "context deadline exceeded".into())],
                );
                return;
            }
        }
        let mut s = self.said.lock().await;
        let Ok(reply) = self.call("epoch").await else {
            return;
        };
        let epoch = reply.strip_prefix("ok ").unwrap_or(&reply).to_string();
        if epoch == s.epoch {
            return;
        }
        for line in Self::lines(&s) {
            if let Err(e) = self.call(&line).await {
                self.log.warn(
                    "internal DNS did not take the update; retrying",
                    &[("err", e)],
                );
                return;
            }
        }
        s.epoch = epoch;
    }
}

impl InternalDns for DnsProcess {
    fn address(&self) -> String {
        self.addr.to_string()
    }

    fn set_names(&self, apps: Vec<String>) -> BoxFut<'_, ()> {
        Box::pin(async move {
            let mut s = self.said.lock().await;
            let line = names_line(&apps);
            s.names = Some(apps);
            self.push(&mut s, line).await;
        })
    }

    fn set_clients<'a>(&'a self, clients: &'a Clients) -> BoxFut<'a, ()> {
        Box::pin(async move {
            let mut s = self.said.lock().await;
            s.clients = Some(clients.clone());
            let line = clients_line(clients);
            self.push(&mut s, line).await;
        })
    }
}

/// armada-dns as a transient systemd service that restarts when it exits,
/// outside the agent's cgroup so it outlives it.
pub struct Systemd;

/// Runs a program on a blocking thread and returns its output.
async fn output(program: &'static str, args: Vec<String>) -> Result<std::process::Output, String> {
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(program)
            .args(&args)
            .stdin(std::process::Stdio::null())
            .output()
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

impl Launcher for Systemd {
    fn start<'a>(&'a self, unit: &'a str, argv: &'a [String]) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async move {
            let mut args = vec![
                format!("--unit={unit}"),
                "--collect".into(),
                "--quiet".into(),
                "--property=Restart=always".into(),
                "--property=RestartSec=100ms".into(),
                "--property=OOMScoreAdjust=-900".into(),
                "--property=LimitNOFILE=65536".into(),
                "--".into(),
            ];
            args.extend(argv.iter().cloned());
            let out = output("systemd-run", args).await?;
            if !out.status.success() {
                let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
                text.push_str(&String::from_utf8_lossy(&out.stderr));
                return Err(format!("systemd-run: {}: {}", out.status, text.trim()));
            }
            Ok(())
        })
    }

    fn stop<'a>(&'a self, unit: &'a str) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async move {
            let args = vec!["stop".into(), "--".into(), unit.to_string()];
            let out = output("systemctl", args).await?;
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            if !out.status.success() && !text.contains("not loaded") {
                return Err(format!(
                    "systemctl stop {unit}: {}: {}",
                    out.status,
                    text.trim()
                ));
            }
            Ok(())
        })
    }

    fn units(&self) -> BoxFut<'_, Result<Vec<String>, String>> {
        Box::pin(async move {
            let pattern = format!("{UNIT_PREFIX}*");
            let args = [
                "list-units",
                "--plain",
                "--no-legend",
                "--state=active,activating,reloading,deactivating",
                "--",
                &pattern,
            ];
            let out = output("systemctl", args.iter().map(|s| s.to_string()).collect()).await?;
            if !out.status.success() {
                return Err(format!("systemctl list-units: {}", out.status));
            }
            Ok(parse_units(&String::from_utf8_lossy(&out.stdout)))
        })
    }
}

/// The unit names of `systemctl list-units --plain --no-legend`.
pub fn parse_units(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(|u| u.strip_suffix(".service").unwrap_or(u).to_string())
        .collect()
}

/// Stops every armada-dns unit (armadad runtime reset).
pub async fn stop_units() -> Result<(), String> {
    let s = Systemd;
    let mut errs = Vec::new();
    for u in s.units().await? {
        if let Err(e) = s.stop(&u).await {
            errs.push(e);
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;
    use tokio::net::UnixListener;

    fn v4(a: [u8; 4]) -> std::net::IpAddr {
        std::net::IpAddr::V4(Ipv4Addr::from(a))
    }

    /// A stand-in armada-dns: its control socket answers with its epoch
    /// and records each request.
    struct Stand {
        lines: Arc<StdMutex<Vec<String>>>,
        task: tokio::task::JoinHandle<()>,
    }

    fn serve(sock: PathBuf, epoch: &'static str) -> Stand {
        let _ = std::fs::remove_file(&sock);
        let l = UnixListener::bind(&sock).unwrap();
        let lines = Arc::new(StdMutex::new(Vec::new()));
        let rec = lines.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut c, _)) = l.accept().await else {
                    return;
                };
                let mut b = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = c.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    b.extend_from_slice(&buf[..n]);
                    if b.ends_with(b"\n") {
                        break;
                    }
                }
                let line = String::from_utf8_lossy(&b).trim_end().to_string();
                rec.lock().unwrap().push(line);
                let _ = c.write_all(format!("ok {epoch}\n").as_bytes()).await;
            }
        });
        Stand { lines, task }
    }

    /// Units as a map; start serves the unit's socket from the argv.
    #[derive(Default)]
    struct Fake {
        units: StdMutex<HashMap<String, Vec<String>>>,
        stands: StdMutex<HashMap<String, Stand>>,
        stopped: StdMutex<Vec<String>>,
        epoch: StdMutex<&'static str>,
    }

    impl Launcher for Fake {
        fn start<'a>(
            &'a self,
            unit: &'a str,
            argv: &'a [String],
        ) -> BoxFut<'a, Result<(), String>> {
            Box::pin(async move {
                let i = argv.iter().position(|a| a == "--control").unwrap();
                let stand = serve(PathBuf::from(&argv[i + 1]), *self.epoch.lock().unwrap());
                self.stands.lock().unwrap().insert(unit.to_string(), stand);
                self.units
                    .lock()
                    .unwrap()
                    .insert(unit.to_string(), argv.to_vec());
                Ok(())
            })
        }
        fn stop<'a>(&'a self, unit: &'a str) -> BoxFut<'a, Result<(), String>> {
            Box::pin(async move {
                if let Some(s) = self.stands.lock().unwrap().remove(unit) {
                    s.task.abort();
                }
                self.units.lock().unwrap().remove(unit);
                self.stopped.lock().unwrap().push(unit.to_string());
                Ok(())
            })
        }
        fn units(&self) -> BoxFut<'_, Result<Vec<String>, String>> {
            Box::pin(async move {
                let mut u: Vec<String> = self.units.lock().unwrap().keys().cloned().collect();
                u.sort();
                Ok(u)
            })
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("armada-dnsp-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn config(dir: &Path, launcher: Arc<Fake>, upstream: &str) -> ProcessConfig {
        let bin = dir.join("armada-dns");
        std::fs::write(&bin, b"program").unwrap();
        ProcessConfig {
            bin,
            addr: Ipv4Addr::new(10, 120, 0, 1),
            port: 0,
            clients: "10.120.0.9/24".into(),
            upstreams: vec![upstream.into()],
            unknown_wait: Duration::from_secs(3),
            start_wait: Duration::ZERO,
            dir: dir.join("dns"),
            launcher: Some(launcher),
            logger: Logger::discard(),
        }
    }

    #[test]
    fn unit_names_as_go_makes_them() {
        let args: Vec<String> = [
            "--listen",
            "10.120.0.1:53",
            "--clients",
            "10.120.0.0/24",
            "--upstream",
            "1.1.1.1:53",
            "--unknown-wait-ms",
            "3000",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        // Go: StartProcess with Bin holding "program" and these settings
        // (TestUnitNameMatchesRust in internal/dnsserver).
        assert_eq!(unit_id(b"program", &args), "77580d36485337b0");
        assert_eq!(masked4("10.120.0.9/24").unwrap(), "10.120.0.0/24");
        assert!(masked4("10.120.0.0/024").is_none());
        assert!(masked4("fd00::/8").is_none());
    }

    #[test]
    fn lines_as_armada_dns_reads_them() {
        let mut c = Clients::new();
        c.insert(v4([10, 120, 0, 12]), "web.shop".into());
        c.insert(v4([10, 120, 0, 3]), "api".into());
        c.insert("fd00::1".parse().unwrap(), "x".into());
        assert_eq!(
            clients_line(&c),
            "clients 10.120.0.12=web.shop 10.120.0.3=api"
        );
        assert_eq!(names_line(&[]), "names");
        assert_eq!(names_line(&["a".into(), "b.s".into()]), "names a b.s");
        assert_eq!(
            parse_units("armada-dns-ab.service loaded active running x\n\n"),
            vec!["armada-dns-ab"]
        );
    }

    #[tokio::test]
    async fn starts_tells_and_hands_over() {
        let dir = tmp("start");
        let fake = Arc::new(Fake::default());
        *fake.epoch.lock().unwrap() = "e1";
        let p = DnsProcess::start(config(&dir, fake.clone(), "1.1.1.1:53"))
            .await
            .unwrap();
        let argv = fake.units.lock().unwrap()[p.unit()].clone();
        assert_eq!(
            argv[1..5],
            ["--listen", "10.120.0.1:53", "--clients", "10.120.0.0/24"]
        );
        assert!(argv.contains(&"--unknown-wait-ms".to_string()));
        assert!(!argv.contains(&"--start-wait-ms".to_string()));
        assert_eq!(p.address(), "10.120.0.1");

        let mut c = Clients::new();
        c.insert(v4([10, 120, 0, 5]), "web".into());
        p.set_clients(&c).await;
        p.set_names(vec!["web".into()]).await;
        let lines = fake.stands.lock().unwrap()[p.unit()].lines.clone();
        // The first update finds a new epoch: everything is told again.
        assert_eq!(
            lines.lock().unwrap().clone(),
            vec![
                "epoch",
                "clients 10.120.0.5=web",
                "clients 10.120.0.5=web",
                "names web",
            ]
        );

        // Other settings: a new unit takes over from the running one, which
        // drains and stops.
        let old_unit = p.unit().to_string();
        drop(p);
        *fake.epoch.lock().unwrap() = "e2";
        let q = DnsProcess::start(config(&dir, fake.clone(), "9.9.9.9:53"))
            .await
            .unwrap();
        assert_ne!(q.unit(), old_unit);
        let argv = fake.units.lock().unwrap()[q.unit()].clone();
        let i = argv.iter().position(|a| a == "--take-over").unwrap();
        assert!(argv[i + 1].ends_with(&format!(
            "{}.sock",
            old_unit.strip_prefix(UNIT_PREFIX).unwrap()
        )));
        assert_eq!(fake.stopped.lock().unwrap().clone(), vec![old_unit.clone()]);
        assert!(fake.units.lock().unwrap().get(&old_unit).is_none());

        // A process that restarted hears everything again.
        q.set_names(vec!["a".into()]).await;
        let unit = q.unit().to_string();
        fake.stop(&unit).await.unwrap();
        *fake.epoch.lock().unwrap() = "e3";
        q.keep().await;
        let lines = fake.stands.lock().unwrap()[&unit].lines.clone();
        assert_eq!(
            lines.lock().unwrap().clone(),
            vec!["epoch", "epoch", "names a"]
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Units as plain processes (Go's procs in process_test.go).
    #[derive(Default)]
    struct Procs {
        units: StdMutex<HashMap<String, std::process::Child>>,
    }

    impl Launcher for Procs {
        fn start<'a>(
            &'a self,
            unit: &'a str,
            argv: &'a [String],
        ) -> BoxFut<'a, Result<(), String>> {
            Box::pin(async move {
                let child = std::process::Command::new(&argv[0])
                    .args(&argv[1..])
                    .spawn()
                    .map_err(|e| e.to_string())?;
                self.units.lock().unwrap().insert(unit.to_string(), child);
                Ok(())
            })
        }
        fn stop<'a>(&'a self, unit: &'a str) -> BoxFut<'a, Result<(), String>> {
            Box::pin(async move {
                if let Some(mut c) = self.units.lock().unwrap().remove(unit) {
                    let _ = c.kill();
                    let _ = c.wait();
                }
                Ok(())
            })
        }
        fn units(&self) -> BoxFut<'_, Result<Vec<String>, String>> {
            Box::pin(async move {
                let mut u: Vec<String> = self.units.lock().unwrap().keys().cloned().collect();
                u.sort();
                Ok(u)
            })
        }
    }

    impl Drop for Procs {
        fn drop(&mut self) {
            for (_, mut c) in self.units.lock().unwrap().drain() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    /// An A query for name, answered by the resolver at addr: the
    /// addresses of its answers.
    fn lookup(addr: &str, name: &str) -> (u8, Vec<Ipv4Addr>) {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        sock.send_to(&q, addr).unwrap();
        let mut b = [0u8; 512];
        let n = sock.recv(&mut b).unwrap();
        let b = &b[..n];
        let rcode = b[3] & 0x0f;
        let answers = u16::from_be_bytes([b[6], b[7]]);
        // The answers follow the question; each names it by a pointer.
        let mut i = q.len();
        let mut out = Vec::new();
        for _ in 0..answers {
            i += 2 + 2 + 2 + 4;
            let len = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
            i += 2;
            if len == 4 {
                out.push(Ipv4Addr::new(b[i], b[i + 1], b[i + 2], b[i + 3]));
            }
            i += len;
        }
        (rcode, out)
    }

    /// The real armada-dns (ARMADA_DNS_BIN, `make dns`) as plain processes:
    /// names and clients reach it over the control socket, and a unit with
    /// other settings takes over from it.
    #[tokio::test]
    async fn real_armada_dns() {
        let Ok(bin) = std::env::var("ARMADA_DNS_BIN") else {
            eprintln!("ARMADA_DNS_BIN is not set (make dns): skipped");
            return;
        };
        let dir = tmp("real");
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let procs = Arc::new(Procs::default());
        let cfg = |upstream: &str| ProcessConfig {
            bin: PathBuf::from(&bin),
            addr: Ipv4Addr::LOCALHOST,
            port,
            clients: "127.0.0.0/8".into(),
            upstreams: vec![upstream.into()],
            unknown_wait: Duration::from_millis(100),
            start_wait: Duration::from_millis(100),
            dir: dir.join("dns"),
            launcher: Some(procs.clone()),
            logger: Logger::discard(),
        };
        let p = DnsProcess::start(cfg("127.0.0.1:9")).await.unwrap();
        let mut c = Clients::new();
        c.insert(v4([127, 0, 0, 1]), "web".into());
        p.set_clients(&c).await;
        p.set_names(vec!["web".into(), "api".into()]).await;
        let at = format!("127.0.0.1:{port}");
        let ask = |name: &'static str| {
            let at = at.clone();
            tokio::task::spawn_blocking(move || lookup(&at, name))
        };
        assert_eq!(
            ask("api.internal").await.unwrap(),
            (0, vec![Ipv4Addr::LOCALHOST])
        );
        assert_eq!(ask("nope.internal").await.unwrap().0, 3);
        let first = p.unit().to_string();
        drop(p);
        let q = DnsProcess::start(cfg("127.0.0.1:19")).await.unwrap();
        assert_ne!(q.unit(), first);
        assert_eq!(procs.units().await.unwrap(), vec![q.unit().to_string()]);
        // The new process took the names over from the old one.
        assert_eq!(
            ask("web.internal").await.unwrap(),
            (0, vec![Ipv4Addr::LOCALHOST])
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn refuses_public_addresses() {
        let dir = tmp("refuse");
        let mut cfg = config(&dir, Arc::new(Fake::default()), "1.1.1.1:53");
        cfg.addr = Ipv4Addr::new(8, 8, 8, 8);
        assert!(DnsProcess::start(cfg).await.is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}

//! armada-shim processes as internal/runtime/supervisor's Shims reaches
//! them (shim.go): one per group as the transient systemd unit
//! armada-shim-<name>, socket DIR/<name>.sock, runc's state under
//! DIR/<name>/runc, one request line per connection.
//!
//! A shim that runs but does not answer is never replaced, and its
//! containers are ended only once it is really gone: nothing listens on
//! its socket, or its unit is not active. A timeout or a closed connection
//! says nothing about them. Starting and abandoning one group's shim are
//! serialized by an flock on DIR/<name>.lock (Go's agent also holds its
//! own lock around each call).

use super::errno_text;
use crate::net::addr::quote;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// What reaches a group's shim: Shims' fields, the group, and the time
/// left to the caller (0 for none).
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct Request {
    pub dir: String,
    pub bin: String,
    pub runc: String,
    pub logger: String,
    pub group: String,
    /// The programs systemd is reached through; tests name stand-ins.
    #[serde(rename = "systemdRun")]
    pub systemd_run: String,
    pub systemctl: String,
    #[serde(rename = "timeoutMs")]
    pub timeout_ms: u64,
    #[serde(default, deserialize_with = "crate::runtime::nullable")]
    pub words: Vec<String>,
    /// When the caller's time is up (from timeout_ms when read).
    #[serde(skip)]
    pub deadline: Option<Instant>,
}

/// shimName: a short name safe in paths and unit names.
pub fn shim_name(group: &str) -> String {
    let sum = Sha256::digest(group.as_bytes());
    let mut s = String::from("s");
    for b in &sum[..8] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn unit_name(group: &str) -> String {
    format!("armada-shim-{}", shim_name(group))
}

/// How a call to a shim failed.
#[derive(Debug, PartialEq)]
pub enum CallError {
    /// The shim answered "err TEXT" (errShim).
    Shim(String),
    /// The shim could not be reached or did not answer, with the errno of
    /// a failed connection.
    Conn(String, Option<i32>),
}

impl CallError {
    pub fn text(&self) -> &str {
        match self {
            CallError::Shim(t) | CallError::Conn(t, _) => t,
        }
    }
}

const CALL_LIMIT: Duration = Duration::from_secs(120);
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a probe goes on past the caller's time.
const PROBE_PAST_DEADLINE: Duration = Duration::from_secs(1);

fn io_text(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(n) => errno_text(n),
        None => e.to_string(),
    }
}

/// Shim.call: one request line, one answer line; "ok" and "ok WORDS" give
/// the words. A wait lasts as long as the container (bounded only by the
/// caller's time); anything else answers within two minutes.
pub fn call(
    socket: &Path,
    words: &[String],
    timeout: Option<Duration>,
) -> Result<String, CallError> {
    for w in words {
        if w.is_empty() || w.contains([' ', '\t', '\r', '\n']) {
            return Err(CallError::Conn(
                format!("invalid shim argument {}", quote(w)),
                None,
            ));
        }
    }
    let Some(first) = words.first() else {
        return Err(CallError::Conn("invalid shim argument \"\"".into(), None));
    };
    let sock = socket.display().to_string();
    let c = UnixStream::connect(socket).map_err(|e| {
        CallError::Conn(
            format!("dial unix {sock}: connect: {}", io_text(&e)),
            e.raw_os_error(),
        )
    })?;
    let limit = if first == "wait" {
        timeout
    } else {
        Some(timeout.map_or(CALL_LIMIT, |t| t.min(CALL_LIMIT)))
    };
    if let Some(l) = limit {
        let l = l.max(Duration::from_millis(1));
        let _ = c.set_read_timeout(Some(l));
        let _ = c.set_write_timeout(Some(l));
    }
    let net_err = |op: &str, e: &io::Error| -> String {
        if matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ) {
            format!("{op} unix @->{sock}: i/o timeout")
        } else {
            format!("{op} unix @->{sock}: {}", io_text(e))
        }
    };
    let mut w = &c;
    w.write_all(format!("{}\n", words.join(" ")).as_bytes())
        .map_err(|e| CallError::Conn(net_err("write", &e), None))?;
    let mut line = Vec::new();
    let n = BufReader::new(&c)
        .read_until(b'\n', &mut line)
        .map_err(|e| CallError::Conn(format!("shim: {}", net_err("read", &e)), None))?;
    if n == 0 || line.last() != Some(&b'\n') {
        return Err(CallError::Conn("shim: EOF".into(), None));
    }
    line.pop();
    let line = String::from_utf8_lossy(&line).into_owned();
    if line == "ok" {
        return Ok(String::new());
    }
    if let Some(r) = line.strip_prefix("ok ") {
        return Ok(r.to_string());
    }
    if let Some(r) = line.strip_prefix("err ") {
        return Err(CallError::Shim(r.to_string()));
    }
    Err(CallError::Conn(
        format!("shim: unexpected answer {}", quote(&line)),
        None,
    ))
}

/// An flock held until dropped.
struct Lock(fs::File);

impl Drop for Lock {
    fn drop(&mut self) {
        // SAFETY: unlocking a descriptor this value owns.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// exec.Cmd's error texts: a program not found on PATH, one that could
/// not start, an exit status, a signal.
fn spawn_text(prog: &str, e: &io::Error) -> String {
    if !prog.contains('/') && e.kind() == io::ErrorKind::NotFound {
        return format!("exec: {}: executable file not found in $PATH", quote(prog));
    }
    format!("fork/exec {prog}: {}", io_text(e))
}

fn status_text(o: &Output) -> Option<String> {
    use std::os::unix::process::ExitStatusExt;
    if o.status.success() {
        return None;
    }
    Some(match (o.status.code(), o.status.signal()) {
        (Some(c), _) => format!("exit status {c}"),
        (None, Some(libc::SIGKILL)) => "signal: killed".into(),
        (None, Some(libc::SIGTERM)) => "signal: terminated".into(),
        (None, Some(s)) => format!("signal: signal {s}"),
        (None, None) => "exit status -1".into(),
    })
}

/// What exec.CommandContext's error says once the caller's time is up.
const DEADLINE: &str = "context deadline exceeded";

/// Runs prog with args; stdout alone (Output) or stdout and stderr
/// together (CombinedOutput), and the error as Go words it. A program
/// still running at the deadline is killed, as CommandContext kills it.
fn run(
    prog: &str,
    args: &[&str],
    combined: bool,
    deadline: Option<Instant>,
) -> (Vec<u8>, Option<String>) {
    if deadline.is_some_and(|d| Instant::now() >= d) {
        return (Vec::new(), Some(DEADLINE.into()));
    }
    let (r, w) = match pipe() {
        Ok(p) => p,
        Err(e) => return (Vec::new(), Some(io_text(&e))),
    };
    let mut cmd = Command::new(prog);
    cmd.args(args).stdin(Stdio::null());
    if combined {
        // One pipe for both, as CombinedOutput writes them to one buffer.
        match w.try_clone() {
            Ok(w2) => cmd.stderr(Stdio::from(w2)),
            Err(e) => return (Vec::new(), Some(io_text(&e))),
        };
    } else {
        cmd.stderr(Stdio::null());
    }
    cmd.stdout(Stdio::from(w));
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return (Vec::new(), Some(spawn_text(prog, &e))),
    };
    drop(cmd);
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = io::Read::read_to_end(&mut fs::File::from(r), &mut out);
        out
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Ok(s),
            Ok(None) => {}
            Err(e) => break Err(io_text(&e)),
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            let _ = child.kill();
            let _ = child.wait();
            break Err(DEADLINE.into());
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    let out = reader.join().unwrap_or_default();
    match status {
        Ok(s) => {
            let o = Output {
                status: s,
                stdout: Vec::new(),
                stderr: Vec::new(),
            };
            let err = status_text(&o);
            (out, err)
        }
        Err(e) => (out, Some(e)),
    }
}

fn pipe() -> io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::FromRawFd;
    let mut fds = [0; 2];
    // SAFETY: pipe2 fills two descriptors this function then owns.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors were just made and are owned once.
    Ok(unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(fds[0]),
            std::os::fd::OwnedFd::from_raw_fd(fds[1]),
        )
    })
}

impl Request {
    fn name(&self) -> String {
        shim_name(&self.group)
    }

    pub fn socket(&self) -> PathBuf {
        Path::new(&self.dir).join(format!("{}.sock", self.name()))
    }

    fn runc_root(&self) -> PathBuf {
        Path::new(&self.dir).join(self.name()).join("runc")
    }

    /// The time left to the caller, none when it set no deadline.
    fn left(&self) -> Option<Duration> {
        self.deadline
            .map(|d| d.saturating_duration_since(Instant::now()))
    }

    fn expired(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }

    fn systemd_run(&self) -> &str {
        if self.systemd_run.is_empty() {
            "systemd-run"
        } else {
            &self.systemd_run
        }
    }

    fn systemctl(&self) -> &str {
        if self.systemctl.is_empty() {
            "systemctl"
        } else {
            &self.systemctl
        }
    }

    fn mkdir(&self) -> Result<(), String> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .map_err(|e| format!("mkdir {}: {}", self.dir, io_text(&e)))
    }

    fn lock(&self) -> Result<Lock, String> {
        self.mkdir()?;
        let p = Path::new(&self.dir).join(format!("{}.lock", self.name()));
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(&p)
            .map_err(|e| format!("open {}: {}", p.display(), io_text(&e)))?;
        loop {
            // SAFETY: flock on a descriptor this function owns.
            if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } == 0 {
                return Ok(Lock(f));
            }
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EINTR) {
                return Err(format!("flock {}: {}", p.display(), io_text(&e)));
            }
        }
    }

    /// Whether the shim answers, within the probe's own ten seconds: a
    /// caller short of time must never make a live shim look silent
    /// (Go's probe takes the caller's deadline). It gives up at most a
    /// second past the caller's time (within the grace Go gives this
    /// program), and a caller whose time ran out meanwhile gets that,
    /// not the probe's outcome.
    fn probe(&self) -> Result<(), CallError> {
        let t = self.left().map_or(PROBE_TIMEOUT, |l| {
            (l + PROBE_PAST_DEADLINE).min(PROBE_TIMEOUT)
        });
        call(&self.socket(), &["list".to_string()], Some(t)).map(|_| ())
    }

    /// systemdActive: only a unit that is inactive, failed, or unknown has
    /// no shim.
    fn active(&self) -> Result<bool, String> {
        let unit = unit_name(&self.group);
        let (out, err) = run(
            self.systemctl(),
            &["show", "--property=ActiveState", "--value", "--", &unit],
            false,
            self.deadline,
        );
        if let Some(e) = err {
            return Err(format!("systemctl show {unit}: {e}"));
        }
        let s = String::from_utf8_lossy(&out);
        Ok(!matches!(s.trim(), "" | "inactive" | "failed"))
    }

    /// gone: nothing listens on the socket, or the unit is not active.
    fn gone(&self, e: &CallError) -> Result<bool, String> {
        match e {
            CallError::Shim(_) => Ok(false),
            CallError::Conn(_, Some(n)) if *n == libc::ENOENT || *n == libc::ECONNREFUSED => {
                Ok(true)
            }
            CallError::Conn(..) => self
                .active()
                .map(|a| !a)
                .map_err(|err| format!("state of shim for {}: {err}", self.group)),
        }
    }

    /// abandon: every container in runc's state killed and deleted.
    fn abandon_root(&self) -> Result<(), String> {
        let root = self.runc_root();
        if fs::symlink_metadata(&root).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
            return Ok(());
        }
        let root = root.display().to_string();
        let (out, err) = run(
            &self.runc,
            &["--root", &root, "list", "-q"],
            false,
            self.deadline,
        );
        if let Some(e) = err {
            return Err(format!("runc list: {e}"));
        }
        let ids = String::from_utf8_lossy(&out).into_owned();
        for id in ids.split_whitespace() {
            let _ = run(
                &self.runc,
                &["--root", &root, "kill", "--all", id, "KILL"],
                false,
                self.deadline,
            );
            let (out, err) = run(
                &self.runc,
                &["--root", &root, "delete", "--force", id],
                true,
                self.deadline,
            );
            if let Some(e) = err {
                return Err(format!(
                    "runc delete {id}: {e}: {}",
                    String::from_utf8_lossy(&out).trim()
                ));
            }
        }
        Ok(())
    }

    /// The systemd-run arguments that start the group's shim.
    pub fn launch_args(&self) -> Vec<String> {
        let name = self.name();
        let mut a: Vec<String> = [
            format!("--unit={}", unit_name(&self.group)),
            "--collect".into(),
            "--quiet".into(),
            "--property=OOMScoreAdjust=-999".into(),
            "--property=LimitNOFILE=infinity".into(),
            "--property=LimitNPROC=infinity".into(),
            "--property=LimitCORE=infinity".into(),
            "--property=TasksMax=infinity".into(),
            "--".into(),
        ]
        .into();
        a.extend([
            self.bin.clone(),
            "serve".into(),
            self.socket().display().to_string(),
            Path::new(&self.dir).join(&name).display().to_string(),
            self.runc.clone(),
            self.logger.clone(),
        ]);
        a
    }

    /// Shims.For: the group's shim, started when none runs.
    pub fn start(&self) -> Result<(), String> {
        let g = &self.group;
        let _l = self.lock()?;
        let err = match self.probe() {
            Ok(()) => return Ok(()),
            Err(_) if self.expired() => return Err(DEADLINE.into()),
            Err(e) => e,
        };
        let gone = self
            .gone(&err)
            .map_err(|ge| format!("shim for {g} does not answer: {}; {ge}", err.text()))?;
        if !gone {
            return Err(format!(
                "shim for {g} runs but does not answer: {}",
                err.text()
            ));
        }
        self.mkdir()?;
        self.abandon_root()
            .map_err(|e| format!("containers of a stopped shim for {g}: {e}"))?;
        let args = self.launch_args();
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let (out, err) = run(self.systemd_run(), &refs, true, self.deadline);
        if let Some(e) = err {
            return Err(format!(
                "start shim for {g}: systemd-run: {e}: {}",
                String::from_utf8_lossy(&out).trim()
            ));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match call(&self.socket(), &["list".to_string()], self.left()) {
                Ok(_) => return Ok(()),
                Err(e) if Instant::now() > deadline => {
                    return Err(format!("shim for {g} does not answer: {}", e.text()));
                }
                Err(_) if self.expired() => return Err(DEADLINE.into()),
                Err(_) => {
                    std::thread::sleep(self.left().map_or(Duration::from_millis(20), |l| {
                        l.min(Duration::from_millis(20))
                    }));
                    if self.expired() {
                        return Err(DEADLINE.into());
                    }
                }
            }
        }
    }

    /// Shims.Abandon: whether the shim was gone, its containers ended.
    /// A shim found gone whose containers could not all be ended is
    /// gone with an error, as Go reports it.
    pub fn abandon(&self) -> (bool, Option<String>) {
        let _l = match self.lock() {
            Ok(l) => l,
            Err(e) => return (false, Some(e)),
        };
        let err = match self.probe() {
            Ok(()) => return (false, None),
            Err(_) if self.expired() => return (false, Some(DEADLINE.into())),
            Err(e) => e,
        };
        match self.gone(&err) {
            Ok(true) => (true, self.abandon_root().err()),
            Ok(false) => (false, None),
            Err(e) => (false, Some(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_as_go() {
        // shimName("web") in Go.
        assert_eq!(shim_name("web").len(), 17);
        assert!(shim_name("web").starts_with('s'));
        assert_eq!(
            unit_name("web"),
            format!("armada-shim-{}", shim_name("web"))
        );
    }

    #[test]
    fn probes_on_its_own_time() {
        use std::io::{BufRead, BufReader};
        let dir = std::env::temp_dir().join(format!("armada-shim-probe-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let r = Request {
            dir: dir.display().to_string(),
            group: "web".into(),
            // A caller with almost no time left.
            deadline: Some(Instant::now() + Duration::from_millis(1)),
            ..Default::default()
        };
        // A shim that answers after 100 ms.
        let l = std::os::unix::net::UnixListener::bind(r.socket()).unwrap();
        let t = std::thread::spawn(move || {
            let (c, _) = l.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&c).read_line(&mut line).unwrap();
            std::thread::sleep(Duration::from_millis(100));
            (&c).write_all(b"ok\n").unwrap();
        });
        assert_eq!(r.probe(), Ok(()));
        t.join().unwrap();
        // Its time ran out meanwhile: the caller hears that, and nothing
        // is abandoned.
        let _ = fs::remove_file(r.socket());
        assert_eq!(r.abandon(), (false, Some(DEADLINE.to_string())));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_words() {
        let e = call(
            Path::new("/nonexistent.sock"),
            &["create".into(), "a b".into()],
            None,
        );
        assert_eq!(
            e,
            Err(CallError::Conn(
                "invalid shim argument \"a b\"".into(),
                None
            ))
        );
        let e = call(Path::new("/nonexistent/x.sock"), &["list".into()], None);
        assert!(matches!(e, Err(CallError::Conn(_, Some(libc::ENOENT)))));
    }
}

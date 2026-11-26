//! armada-shim supervises one app's containers on a node (ADR 0046).
//!
//! It is the parent of the app's containers: it creates and starts them
//! with their OCI runtime, hands their output to armada-log, reaps them as
//! the child subreaper, and keeps their exit codes until they are deleted.
//! Requests arrive one per connection on a root-only Unix socket, as one
//! line of space-separated words; the answer is one line, `ok ...` or
//! `err ...`.
//!
//! The OCI runtime is crun for new containers and runc for those created
//! before ADR 0056 (crun cannot manage runc's containers, nor runc
//! crun's): each container keeps the runtime that created it for every
//! later call, and each runtime keeps its state in a directory of its own,
//! STATE-DIR/crun and STATE-DIR/runc.
//!
//!   create ID BUNDLE LOGDIR [RUNTIME]
//!                             create the container (not started) with
//!                             RUNTIME, `crun` or `runc` (the default, as
//!                             an agent before ADR 0056 asks)
//!   start ID                  start it
//!   state ID                  `ok created PID`, `ok running PID`, or `ok exited CODE`
//!   kill ID SIGNAL [all]      send a signal (number) to its process, or with
//!                             `all` to every process in it (kill --all)
//!   wait ID                   wait until it exits: `ok CODE`
//!   delete ID                 remove it (stopped first with SIGKILL)
//!   list                      `ok ID STATE ...` for every container
//!
//! Prototype: standard library only, Linux only.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn dup2(old: i32, new: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
}

const PR_SET_CHILD_SUBREAPER: i32 = 36;
const F_DUPFD_CLOEXEC: i32 = 1030;
const SIGKILL: i32 = 9;
const ECHILD: i32 = 10;

/// How many exit statuses the shim keeps before it drops the oldest that
/// nobody asked for. Containers' own are never dropped (they are pinned
/// until the container is deleted), and the runtimes and armada-log are taken as
/// soon as they exit, so what piles up are processes that were reparented
/// to the shim and that nobody waits for. A few thousand covers far more
/// than one app's containers at once in a few hundred KiB at most.
const MAX_EXITS: usize = 4096;

/// How long an exit status is kept at least, so a caller that spawned a
/// process and is about to wait for it never finds its status dropped.
const EXIT_GRACE: Duration = Duration::from_secs(60);

/// Exit statuses by PID, bounded by MAX_EXITS (see there).
#[derive(Default)]
struct Exits {
    codes: HashMap<i32, (i32, Instant)>,
    /// PIDs in the order they were reaped; entries whose status was taken
    /// stay until they reach the front or the queue is compacted.
    order: VecDeque<(i32, Instant)>,
    /// Containers' PIDs, whose statuses are kept until they are forgotten.
    pinned: HashSet<i32>,
}

impl Exits {
    fn insert(&mut self, pid: i32, code: i32, now: Instant) {
        self.codes.insert(pid, (code, now));
        self.order.push_back((pid, now));
        self.trim(now);
    }

    fn get(&self, pid: i32) -> Option<i32> {
        self.codes.get(&pid).map(|(code, _)| *code)
    }

    fn remove(&mut self, pid: i32) -> Option<i32> {
        self.codes.remove(&pid).map(|(code, _)| code)
    }

    /// Whether the order entry (pid, at) still stands for a kept status.
    fn current(&self, pid: i32, at: Instant) -> bool {
        self.codes.get(&pid).is_some_and(|(_, t)| *t == at)
    }

    /// Drops the oldest unpinned statuses past MAX_EXITS once they are
    /// older than EXIT_GRACE.
    fn trim(&mut self, now: Instant) {
        if self.order.len() > 2 * MAX_EXITS {
            let codes = &self.codes;
            self.order
                .retain(|(pid, at)| codes.get(pid).is_some_and(|(_, t)| t == at));
        }
        let mut kept = Vec::new();
        while self.codes.len() > MAX_EXITS {
            let Some(&(pid, at)) = self.order.front() else {
                break;
            };
            if now.saturating_duration_since(at) < EXIT_GRACE {
                break;
            }
            self.order.pop_front();
            if !self.current(pid, at) {
                continue;
            }
            if self.pinned.contains(&pid) {
                kept.push((pid, at));
            } else {
                self.codes.remove(&pid);
            }
        }
        for e in kept.into_iter().rev() {
            self.order.push_front(e);
        }
    }
}

/// Exit statuses of reaped children, by PID, until someone takes them.
#[derive(Default)]
struct Reaped {
    exits: Mutex<Exits>,
    cond: Condvar,
}

impl Reaped {
    /// Reaps every child that exits, forever.
    fn run(&self) {
        loop {
            let mut status = 0;
            let pid = unsafe { waitpid(-1, &mut status, 0) };
            if pid > 0 {
                self.exits
                    .lock()
                    .unwrap()
                    .insert(pid, exit_code(status), Instant::now());
                self.cond.notify_all();
                continue;
            }
            if io::Error::last_os_error().raw_os_error() == Some(ECHILD) {
                thread::sleep(Duration::from_millis(50));
            }
        }
    }

    /// Waits for pid to be reaped and takes its exit code.
    fn wait(&self, pid: i32) -> i32 {
        let mut exits = self.exits.lock().unwrap();
        loop {
            if let Some(code) = exits.remove(pid) {
                return code;
            }
            exits = self.cond.wait(exits).unwrap();
        }
    }

    /// The exit code of pid if it was reaped, without taking it.
    fn peek(&self, pid: i32) -> Option<i32> {
        self.exits.lock().unwrap().get(pid)
    }

    /// Keeps pid's exit status until it is forgotten (a container's).
    fn pin(&self, pid: i32) {
        self.exits.lock().unwrap().pinned.insert(pid);
    }

    fn forget(&self, pid: i32) {
        let mut exits = self.exits.lock().unwrap();
        exits.pinned.remove(&pid);
        exits.remove(pid);
    }
}

/// The container's PID from its runtime's pid file. 0, 1, and negative numbers
/// are refused: a signal to them would reach the shim's process group,
/// every process, or the host's init.
fn parse_pid(s: &str) -> Result<i32, String> {
    let pid: i32 = s
        .trim()
        .parse()
        .map_err(|_| "pid file: not a number".to_string())?;
    if pid <= 1 {
        return Err(format!("pid file: invalid pid {pid}"));
    }
    Ok(pid)
}

/// The exit code the way a shell reports it: 128 + signal when killed.
fn exit_code(status: i32) -> i32 {
    let sig = status & 0x7f;
    if sig == 0 {
        (status >> 8) & 0xff
    } else {
        128 + sig
    }
}

struct Container {
    pid: i32,
    logger: i32,
    started: bool,
    /// The OCI runtime that created it, which every later call uses.
    runtime: Runtime,
}

/// The OCI runtimes a shim runs containers with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Runtime {
    Runc,
    Crun,
}

impl Runtime {
    /// A create's RUNTIME word; none is runc.
    fn parse(word: Option<&str>) -> Result<Runtime, String> {
        match word {
            None | Some("runc") => Ok(Runtime::Runc),
            Some("crun") => Ok(Runtime::Crun),
            Some(_) => Err("unknown runtime".into()),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Runtime::Runc => "runc",
            Runtime::Crun => "crun",
        }
    }
}

/// An OCI runtime's program and its state directory (--root).
struct Program {
    path: PathBuf,
    root: PathBuf,
}

struct Shim {
    runc: Program,
    /// None for a shim started without crun (by a release before ADR 0056).
    crun: Option<Program>,
    logger: PathBuf,
    reaped: Arc<Reaped>,
    containers: Mutex<HashMap<String, Container>>,
    /// Requests in flight and when the last one began or ended.
    busy: Mutex<(usize, Instant)>,
}

/// A container ID: what the runtimes and the log directory accept, nothing else.
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && !id.starts_with('.')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

fn valid_path(p: &str) -> bool {
    p.starts_with('/') && !p.split('/').any(|c| c == "..") && !p.contains('\0')
}

impl Shim {
    fn program(&self, rt: Runtime) -> Result<&Program, String> {
        match rt {
            Runtime::Runc => Ok(&self.runc),
            Runtime::Crun => self
                .crun
                .as_ref()
                .ok_or_else(|| "crun: not available to this shim".to_string()),
        }
    }

    /// Runs the OCI runtime rt with args on its own state directory.
    fn oci(&self, rt: Runtime, args: &[&str], stdout: Stdio, stderr: Stdio) -> Result<(), String> {
        let name = rt.name();
        let prog = self.program(rt)?;
        let child = Command::new(&prog.path)
            .arg("--root")
            .arg(&prog.root)
            .args(args)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .map_err(|e| format!("{name}: {e}"))?;
        let code = self.reaped.wait(child.id() as i32);
        if code != 0 {
            return Err(format!("{name} {} exited with {code}", args[0]));
        }
        Ok(())
    }

    /// Like oci, but keeps what the runtime wrote to stderr for the error.
    fn oci_quiet(&self, rt: Runtime, args: &[&str]) -> Result<(), String> {
        let (mut r, w) = io::pipe().map_err(|e| e.to_string())?;
        let res = self.oci(rt, args, Stdio::null(), Stdio::from(OwnedFd::from(w)));
        let mut msg = String::new();
        let _ = r.read_to_string(&mut msg);
        res.map_err(|e| {
            let msg = msg.trim();
            if msg.is_empty() {
                e
            } else {
                format!("{e}: {}", last_line(msg))
            }
        })
    }

    /// Starts armada-log on the container's output the way containerd's
    /// shim does: output on fds 3 and 4, fd 5 closed once it is ready.
    fn start_logger(
        &self,
        id: &str,
        dir: &str,
    ) -> Result<(i32, io::PipeWriter, io::PipeWriter), String> {
        let (out_r, out_w) = io::pipe().map_err(|e| e.to_string())?;
        let (err_r, err_w) = io::pipe().map_err(|e| e.to_string())?;
        let (mut ready_r, ready_w) = io::pipe().map_err(|e| e.to_string())?;
        let fds = [out_r.as_raw_fd(), err_r.as_raw_fd(), ready_w.as_raw_fd()];
        let mut cmd = Command::new(&self.logger);
        cmd.args(["runtime-log", dir])
            .env_clear()
            .env("CONTAINER_ID", id)
            .env("CONTAINER_NAMESPACE", "armada")
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        unsafe {
            cmd.pre_exec(move || {
                // Copy first, so no source is overwritten before it moves.
                let mut tmp = [0; 3];
                for (i, fd) in fds.iter().enumerate() {
                    tmp[i] = fcntl(*fd, F_DUPFD_CLOEXEC, 10);
                    if tmp[i] < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                for (i, fd) in tmp.iter().enumerate() {
                    if dup2(*fd, 3 + i as i32) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let child = cmd.spawn().map_err(|e| format!("armada-log: {e}"))?;
        drop((out_r, err_r, ready_w));
        let mut buf = [0u8; 1];
        while ready_r.read(&mut buf).map_err(|e| e.to_string())? > 0 {}
        Ok((child.id() as i32, out_w, err_w))
    }

    fn create(
        &self,
        id: &str,
        bundle: &str,
        logdir: &str,
        runtime: Option<&str>,
    ) -> Result<String, String> {
        if !valid_id(id) || !valid_path(bundle) || !valid_path(logdir) {
            return Err("invalid arguments".into());
        }
        let rt = Runtime::parse(runtime)?;
        let prog = self.program(rt)?;
        if self.containers.lock().unwrap().contains_key(id) {
            return Err(format!("{id} exists"));
        }
        let (logger, out_w, err_w) = self.start_logger(id, logdir)?;
        // In the runtime's own state directory, as before ADR 0056 for
        // runc.
        let pidfile = prog.root.join(format!("{id}.pid"));
        let pidfile_s = pidfile.to_string_lossy().into_owned();
        // create without a terminal passes the runtime's own stdout and
        // stderr to the container's process: the log pipes (crun and runc
        // alike).
        let res = self.oci(
            rt,
            &["create", "--bundle", bundle, "--pid-file", &pidfile_s, id],
            Stdio::from(OwnedFd::from(out_w)),
            Stdio::from(OwnedFd::from(err_w)),
        );
        if let Err(e) = res {
            // The pipes are closed, so armada-log ends; reap it.
            self.reaped.wait(logger);
            return Err(e);
        }
        let pid = fs::read_to_string(&pidfile)
            .map_err(|e| format!("pid file: {e}"))
            .and_then(|s| parse_pid(&s));
        let _ = fs::remove_file(&pidfile);
        let pid = match pid {
            Ok(pid) => pid,
            Err(e) => {
                // The runtime made the container: remove it, or it is left
                // behind with no one to report it.
                if self.oci_quiet(rt, &["delete", "--force", id]).is_err() {
                    // Its process may still hold the log pipes.
                    unsafe { kill(logger, SIGKILL) };
                }
                self.reaped.wait(logger);
                return Err(e);
            }
        };
        self.reaped.pin(pid);
        self.containers.lock().unwrap().insert(
            id.to_string(),
            Container {
                pid,
                logger,
                started: false,
                runtime: rt,
            },
        );
        Ok(pid.to_string())
    }

    fn start(&self, id: &str) -> Result<String, String> {
        let rt = self.runtime_of(id)?;
        self.oci_quiet(rt, &["start", id])?;
        if let Some(c) = self.containers.lock().unwrap().get_mut(id) {
            c.started = true;
        }
        Ok(String::new())
    }

    /// The OCI runtime that created the container.
    fn runtime_of(&self, id: &str) -> Result<Runtime, String> {
        self.containers
            .lock()
            .unwrap()
            .get(id)
            .map(|c| c.runtime)
            .ok_or_else(|| format!("{id} not found"))
    }

    fn known(&self, id: &str) -> Result<i32, String> {
        self.containers
            .lock()
            .unwrap()
            .get(id)
            .map(|c| c.pid)
            .ok_or_else(|| format!("{id} not found"))
    }

    fn state(&self, id: &str) -> Result<String, String> {
        let containers = self.containers.lock().unwrap();
        let c = containers
            .get(id)
            .ok_or_else(|| format!("{id} not found"))?;
        Ok(self.describe(c))
    }

    fn describe(&self, c: &Container) -> String {
        match self.reaped.peek(c.pid) {
            Some(code) => format!("exited {code}"),
            None if c.started => format!("running {}", c.pid),
            None => format!("created {}", c.pid),
        }
    }

    fn signal(&self, id: &str, sig: &str) -> Result<String, String> {
        let sig: i32 = sig.parse().map_err(|_| "invalid signal".to_string())?;
        if !(1..=64).contains(&sig) {
            return Err("invalid signal".into());
        }
        let pid = self.known(id)?;
        if self.reaped.peek(pid).is_some() {
            return Err(format!("{id} is not running"));
        }
        if unsafe { kill(pid, sig) } != 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        Ok(String::new())
    }

    fn signal_all(&self, id: &str, sig: &str) -> Result<String, String> {
        let n: i32 = sig.parse().map_err(|_| "invalid signal".to_string())?;
        if !(1..=64).contains(&n) {
            return Err("invalid signal".into());
        }
        let rt = self.runtime_of(id)?;
        self.oci_quiet(rt, &["kill", "--all", id, sig])?;
        Ok(String::new())
    }

    /// Blocks until the container's process was reaped, or the container
    /// was deleted meanwhile.
    fn wait(&self, id: &str) -> Result<String, String> {
        loop {
            let pid = self.known(id)?;
            if let Some(code) = self.reaped.peek(pid) {
                return Ok(code.to_string());
            }
            self.reaped.wait_a_while();
        }
    }

    fn delete(&self, id: &str) -> Result<String, String> {
        let pid = self.known(id)?;
        let rt = self.runtime_of(id)?;
        if self.reaped.peek(pid).is_none() {
            unsafe { kill(pid, SIGKILL) };
            self.reaped.wait_keep(pid);
        }
        self.oci_quiet(rt, &["delete", "--force", id])?;
        if let Some(c) = self.containers.lock().unwrap().remove(id) {
            self.reaped.forget(c.pid);
            self.reaped.wait(c.logger);
        }
        Ok(String::new())
    }

    fn list(&self) -> String {
        let containers = self.containers.lock().unwrap();
        let mut ids: Vec<&String> = containers.keys().collect();
        ids.sort();
        ids.iter()
            .map(|id| format!("{id} {}", self.describe(&containers[*id]).replace(' ', ":")))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn handle(&self, line: &str) -> String {
        let w: Vec<&str> = line.split_whitespace().collect();
        let res = match w.as_slice() {
            ["create", id, bundle, logdir] => self.create(id, bundle, logdir, None),
            ["create", id, bundle, logdir, rt] => self.create(id, bundle, logdir, Some(rt)),
            ["start", id] => self.start(id),
            ["state", id] => self.state(id),
            ["kill", id, sig] => self.signal(id, sig),
            ["kill", id, sig, "all"] => self.signal_all(id, sig),
            ["wait", id] => self.wait(id),
            ["delete", id] => self.delete(id),
            ["list"] => Ok(self.list()),
            _ => Err("unknown request".into()),
        };
        match res {
            Ok(s) if s.is_empty() => "ok".into(),
            Ok(s) => format!("ok {s}"),
            Err(e) => format!("err {}", e.replace('\n', " ")),
        }
    }
}

impl Reaped {
    /// Waits for the next reaped child, or a second.
    fn wait_a_while(&self) {
        let exits = self.exits.lock().unwrap();
        let _ = self
            .cond
            .wait_timeout(exits, Duration::from_secs(1))
            .unwrap();
    }

    /// Waits for pid to be reaped and leaves its exit code in place.
    fn wait_keep(&self, pid: i32) {
        let mut exits = self.exits.lock().unwrap();
        while exits.get(pid).is_none() {
            exits = self.cond.wait(exits).unwrap();
        }
    }
}

fn last_line(s: &str) -> &str {
    s.lines().last().unwrap_or(s)
}

/// How long a shim with no containers and no requests waits before it
/// exits, as containerd's shim does once its last container is gone.
const IDLE_EXIT: Duration = Duration::from_secs(10);

/// Exits once the shim has had no containers and no requests for
/// IDLE_EXIT, removing its socket and its state. The socket goes first, so the agent starts a new shim for
/// the next container instead of reaching this one.
fn exit_when_idle(shim: &Shim, socket: &Path, state: &Path) {
    loop {
        thread::sleep(Duration::from_secs(2));
        let busy = shim.busy.lock().unwrap();
        if busy.0 == 0
            && busy.1.elapsed() >= IDLE_EXIT
            && shim.containers.lock().unwrap().is_empty()
        {
            let _ = fs::remove_file(socket);
            // The runtimes keep nothing for containers that were deleted.
            let _ = fs::remove_dir_all(state);
            std::process::exit(0);
        }
    }
}

impl Shim {
    fn begin(&self) {
        let mut b = self.busy.lock().unwrap();
        b.0 += 1;
        b.1 = Instant::now();
    }

    fn end(&self) {
        let mut b = self.busy.lock().unwrap();
        b.0 = b.0.saturating_sub(1);
        b.1 = Instant::now();
    }
}

fn serve_conn(shim: &Shim, stream: UnixStream) {
    let mut line = String::new();
    let mut r = BufReader::new(stream.take(4096));
    if r.read_line(&mut line).is_err() {
        return;
    }
    let answer = shim.handle(line.trim_end());
    let mut stream = r.into_inner().into_inner();
    let _ = writeln!(stream, "{answer}");
}

fn run(args: &[String]) -> Result<(), String> {
    // CRUN last and optional: the agent of a release before ADR 0056
    // starts shims with runc alone.
    let (cmd, socket, state, runc, logger, crun) = match args {
        [cmd, socket, state, runc, logger] => (cmd, socket, state, runc, logger, None),
        [cmd, socket, state, runc, logger, crun] => (cmd, socket, state, runc, logger, Some(crun)),
        _ => {
            return Err("usage: armada-shim serve SOCKET STATE-DIR RUNC ARMADA-LOG [CRUN]".into());
        }
    };
    if cmd != "serve" {
        return Err(format!("unknown command {cmd}"));
    }
    if unsafe { prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(format!("subreaper: {}", io::Error::last_os_error()));
    }
    let runc = Program {
        path: runc.into(),
        root: Path::new(state).join("runc"),
    };
    let crun = crun.map(|p| Program {
        path: p.into(),
        root: Path::new(state).join("crun"),
    });
    for p in std::iter::once(&runc).chain(crun.as_ref()) {
        fs::create_dir_all(&p.root).map_err(|e| e.to_string())?;
    }
    fs::set_permissions(state, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let _ = fs::remove_file(socket);
    let listener = UnixListener::bind(socket).map_err(|e| format!("{socket}: {e}"))?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    let reaped = Arc::new(Reaped::default());
    let r = reaped.clone();
    thread::Builder::new()
        .stack_size(64 << 10)
        .spawn(move || r.run())
        .map_err(|e| e.to_string())?;
    let shim = Arc::new(Shim {
        runc,
        crun,
        logger: logger.into(),
        reaped,
        containers: Mutex::new(HashMap::new()),
        busy: Mutex::new((0, Instant::now())),
    });
    let idle = shim.clone();
    let sock = PathBuf::from(socket);
    let state_dir = PathBuf::from(state);
    thread::Builder::new()
        .stack_size(64 << 10)
        .spawn(move || exit_when_idle(&idle, &sock, &state_dir))
        .map_err(|e| e.to_string())?;
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        shim.begin();
        let spawned = thread::Builder::new().stack_size(256 << 10).spawn({
            let shim = shim.clone();
            move || {
                serve_conn(&shim, stream);
                shim.end();
            }
        });
        if spawned.is_err() {
            shim.end();
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("armada-shim: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        assert!(valid_id("web-r1-0a1b2c3d"));
        assert!(valid_id("web.space-r1-0a"));
        for bad in ["", ".x", "a/b", "a b", "..", &"x".repeat(129)] {
            assert!(!valid_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn paths() {
        assert!(valid_path("/var/lib/armada/logs"));
        for bad in ["relative", "/a/../b", "/a/\0"] {
            assert!(!valid_path(bad), "{bad:?}");
        }
    }

    #[test]
    fn exit_codes() {
        assert_eq!(exit_code(0), 0);
        assert_eq!(exit_code(3 << 8), 3);
        assert_eq!(exit_code(9), 137);
        assert_eq!(exit_code(15), 143);
    }

    #[test]
    fn pids() {
        assert_eq!(parse_pid("4242\n"), Ok(4242));
        assert_eq!(parse_pid("2"), Ok(2));
        for bad in ["", "x", "1", "0", "-1", "-4242", "99999999999"] {
            assert!(parse_pid(bad).is_err(), "{bad:?}");
        }
    }

    /// A stand-in OCI runtime: logs its arguments, and for create starts
    /// a process on its own stdout and writes its pid.
    fn stand_in(dir: &Path, name: &str, log: &Path) -> PathBuf {
        let p = dir.join(name);
        fs::write(
            &p,
            format!(
                "#!/bin/sh\necho \"{name} $*\" >> {}\nif [ \"$3\" = create ]; then sleep 30 & echo $! > \"$7\"; fi\n",
                log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// Each container keeps the runtime that created it: crun when asked,
    /// runc when the create names none (an agent before ADR 0056), each
    /// with its own state directory.
    #[test]
    fn containers_keep_their_runtime() {
        // Orphaned processes come to this test process, which reaps them
        // as the shim does (no other test here starts any).
        assert_eq!(unsafe { prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }, 0);
        let dir = std::env::temp_dir().join(format!("armada-shim-rt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let state = dir.join("state");
        fs::create_dir_all(state.join("runc")).unwrap();
        fs::create_dir_all(state.join("crun")).unwrap();
        fs::create_dir_all(dir.join("logs")).unwrap();
        let log = dir.join("calls.log");
        let logger = dir.join("armada-log");
        fs::write(&logger, "#!/bin/sh\nexec 5>&-\nexec cat <&3 >/dev/null\n").unwrap();
        fs::set_permissions(&logger, fs::Permissions::from_mode(0o755)).unwrap();
        let reaped = Arc::new(Reaped::default());
        let r = reaped.clone();
        thread::spawn(move || r.run());
        let shim = Shim {
            runc: Program {
                path: stand_in(&dir, "runc", &log),
                root: state.join("runc"),
            },
            crun: Some(Program {
                path: stand_in(&dir, "crun", &log),
                root: state.join("crun"),
            }),
            logger,
            reaped,
            containers: Mutex::new(HashMap::new()),
            busy: Mutex::new((0, Instant::now())),
        };
        let (b, l) = (dir.join("b"), dir.join("logs"));
        let (b, l) = (b.to_str().unwrap(), l.to_str().unwrap());
        assert!(
            shim.handle(&format!("create old {b} {l}"))
                .starts_with("ok ")
        );
        assert!(
            shim.handle(&format!("create new {b} {l} crun"))
                .starts_with("ok ")
        );
        assert_eq!(
            shim.handle(&format!("create odd {b} {l} youki")),
            "err unknown runtime"
        );
        for line in [
            "start old",
            "start new",
            "kill new 9 all",
            "delete old",
            "delete new",
        ] {
            assert_eq!(shim.handle(line), "ok", "{line}");
        }
        let (rr, cr) = (state.join("runc"), state.join("crun"));
        let want = format!(
            "runc --root {r} create --bundle {b} --pid-file {r}/old.pid old\n\
             crun --root {c} create --bundle {b} --pid-file {c}/new.pid new\n\
             runc --root {r} start old\n\
             crun --root {c} start new\n\
             crun --root {c} kill --all new 9\n\
             runc --root {r} delete --force old\n\
             crun --root {c} delete --force new\n",
            r = rr.display(),
            c = cr.display()
        );
        assert_eq!(fs::read_to_string(&log).unwrap(), want);

        // A shim started without crun (by a release before ADR 0056).
        let old = Shim { crun: None, ..shim };
        assert_eq!(
            old.handle(&format!("create x {b} {l} crun")),
            "err crun: not available to this shim"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn exits_bounded() {
        let start = Instant::now();
        let mut e = Exits::default();
        e.pinned.insert(2);
        let n = MAX_EXITS as i32 + 100;
        for pid in 2..2 + n {
            e.insert(pid, 0, start);
        }
        // Young statuses are all kept, even past the bound.
        assert_eq!(e.codes.len(), n as usize);
        // Once old, the oldest unpinned go first.
        let later = start + EXIT_GRACE + Duration::from_secs(1);
        e.insert(1_000_000, 7, later);
        assert_eq!(e.codes.len(), MAX_EXITS);
        assert_eq!(e.get(2), Some(0), "a pinned status was dropped");
        assert_eq!(e.get(3), None);
        assert_eq!(e.get(1_000_000), Some(7));
        assert_eq!(e.get(1 + n), Some(0));
        // Taken statuses do not keep the queue growing.
        for pid in 0..10 * MAX_EXITS as i32 {
            e.insert(2_000_000 + pid, 0, later);
            e.remove(2_000_000 + pid);
        }
        assert!(e.order.len() <= 2 * MAX_EXITS + 1, "{}", e.order.len());
        assert_eq!(e.get(2), Some(0));
    }

    #[test]
    fn exits_forget_unpins() {
        let start = Instant::now();
        let r = Reaped::default();
        r.pin(5);
        r.exits.lock().unwrap().insert(5, 1, start);
        assert_eq!(r.peek(5), Some(1));
        r.forget(5);
        assert_eq!(r.peek(5), None);
        assert!(r.exits.lock().unwrap().pinned.is_empty());
    }
}

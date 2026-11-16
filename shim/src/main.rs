//! armada-shim supervises one app's containers on a node (ADR 0046).
//!
//! It is the parent of the app's containers: it creates and starts them
//! with runc, hands their output to armada-log, reaps them as the child
//! subreaper, and keeps their exit codes until they are deleted. Requests
//! arrive one per connection on a root-only Unix socket, as one line of
//! space-separated words; the answer is one line, `ok ...` or `err ...`.
//!
//!   create ID BUNDLE LOGDIR   create the container (not started)
//!   start ID                  start it
//!   state ID                  `ok created PID`, `ok running PID`, or `ok exited CODE`
//!   kill ID SIGNAL [all]      send a signal (number) to its process, or with
//!                             `all` to every process in it (runc kill --all)
//!   wait ID                   wait until it exits: `ok CODE`
//!   delete ID                 remove it (stopped first with SIGKILL)
//!   list                      `ok ID STATE ...` for every container
//!
//! Prototype: standard library only, Linux only.

use std::collections::HashMap;
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

/// Exit statuses of reaped children, by PID, until someone takes them.
#[derive(Default)]
struct Reaped {
    exits: Mutex<HashMap<i32, i32>>,
    cond: Condvar,
}

impl Reaped {
    /// Reaps every child that exits, forever.
    fn run(&self) {
        loop {
            let mut status = 0;
            let pid = unsafe { waitpid(-1, &mut status, 0) };
            if pid > 0 {
                self.exits.lock().unwrap().insert(pid, exit_code(status));
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
            if let Some(code) = exits.remove(&pid) {
                return code;
            }
            exits = self.cond.wait(exits).unwrap();
        }
    }

    /// The exit code of pid if it was reaped, without taking it.
    fn peek(&self, pid: i32) -> Option<i32> {
        self.exits.lock().unwrap().get(&pid).copied()
    }

    fn forget(&self, pid: i32) {
        self.exits.lock().unwrap().remove(&pid);
    }
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
}

struct Shim {
    runc: PathBuf,
    logger: PathBuf,
    root: PathBuf,
    reaped: Arc<Reaped>,
    containers: Mutex<HashMap<String, Container>>,
    /// Requests in flight and when the last one began or ended.
    busy: Mutex<(usize, Instant)>,
}

/// A container ID: what runc and the log directory accept, nothing else.
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
    fn runc(&self, args: &[&str], stdout: Stdio, stderr: Stdio) -> Result<(), String> {
        let child = Command::new(&self.runc)
            .arg("--root")
            .arg(&self.root)
            .args(args)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .map_err(|e| format!("runc: {e}"))?;
        let code = self.reaped.wait(child.id() as i32);
        if code != 0 {
            return Err(format!("runc {} exited with {code}", args[0]));
        }
        Ok(())
    }

    /// Like runc, but keeps what runc wrote to stderr for the error.
    fn runc_quiet(&self, args: &[&str]) -> Result<(), String> {
        let (mut r, w) = io::pipe().map_err(|e| e.to_string())?;
        let res = self.runc(args, Stdio::null(), Stdio::from(OwnedFd::from(w)));
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

    fn create(&self, id: &str, bundle: &str, logdir: &str) -> Result<String, String> {
        if !valid_id(id) || !valid_path(bundle) || !valid_path(logdir) {
            return Err("invalid arguments".into());
        }
        if self.containers.lock().unwrap().contains_key(id) {
            return Err(format!("{id} exists"));
        }
        let (logger, out_w, err_w) = self.start_logger(id, logdir)?;
        let pidfile = self.root.join(format!("{id}.pid"));
        let pidfile_s = pidfile.to_string_lossy().into_owned();
        // runc create without a terminal passes its own stdout and stderr
        // to the container's process: the log pipes.
        let res = self.runc(
            &["create", "--bundle", bundle, "--pid-file", &pidfile_s, id],
            Stdio::from(OwnedFd::from(out_w)),
            Stdio::from(OwnedFd::from(err_w)),
        );
        if let Err(e) = res {
            // The pipes are closed, so armada-log ends; reap it.
            self.reaped.wait(logger);
            return Err(e);
        }
        let pid: i32 = fs::read_to_string(&pidfile)
            .map_err(|e| format!("pid file: {e}"))?
            .trim()
            .parse()
            .map_err(|_| "pid file: not a number".to_string())?;
        let _ = fs::remove_file(&pidfile);
        self.containers.lock().unwrap().insert(
            id.to_string(),
            Container {
                pid,
                logger,
                started: false,
            },
        );
        Ok(pid.to_string())
    }

    fn start(&self, id: &str) -> Result<String, String> {
        self.known(id)?;
        self.runc_quiet(&["start", id])?;
        if let Some(c) = self.containers.lock().unwrap().get_mut(id) {
            c.started = true;
        }
        Ok(String::new())
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
        self.known(id)?;
        self.runc_quiet(&["kill", "--all", id, sig])?;
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
        if self.reaped.peek(pid).is_none() {
            unsafe { kill(pid, SIGKILL) };
            self.reaped.wait_keep(pid);
        }
        self.runc_quiet(&["delete", "--force", id])?;
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
            ["create", id, bundle, logdir] => self.create(id, bundle, logdir),
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
        while !exits.contains_key(&pid) {
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
            // runc keeps nothing for containers that were deleted.
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
    let [cmd, socket, state, runc, logger] = args else {
        return Err("usage: armada-shim serve SOCKET STATE-DIR RUNC ARMADA-LOG".into());
    };
    if cmd != "serve" {
        return Err(format!("unknown command {cmd}"));
    }
    if unsafe { prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(format!("subreaper: {}", io::Error::last_os_error()));
    }
    let root = Path::new(state).join("runc");
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
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
        runc: runc.into(),
        logger: logger.into(),
        root,
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
}

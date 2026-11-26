//! An exec's session in a container (ADR 0054 step 5, last part): what
//! the supervisor runtime's execProcess (internal/runtime/supervisor/
//! exec.go) and the driver's drain (ExecApp's drainIO, internal/runtime/
//! containerd/exec.go) do in Go. The process spec is the container's own
//! (its config.json) with the arguments, terminal, and console size the
//! exec sets, written 0600 as process.json in a directory of its own;
//! the container's OCI runtime's exec (crun's, or runc's for a container
//! runc created: oci.rs; called runc below) runs with Go's arguments on a
//! pseudo-terminal (its controlling terminal, in a session of its own) or
//! on pipes, and this process copies between them and the agent's
//! streams, waits for runc,
//! keeps copying the output after it ended while the output moves (the
//! terminal's grace, then the drain's), and removes the directory.
//!
//! Descriptors from the agent: 3 the request (it holds the command's
//! arguments, so it is never on the command line), 4 the control socket,
//! 5 the caller's input, 6 its output, 7 its error output (each only when
//! the caller has one). The control socket carries one JSON object per
//! line. From here: {"spawned"} once runc runs (every failure after it is
//! the call's), {"execErrno"} for a runc that could not be run (Go's
//! start error), {"redo"} for a failure Go words itself by doing the
//! session, {"error"} for armada-node failing; then {"started"} or
//! {"notStarted"} (execProcess.Start's nil or its ten-second error),
//! {"exit"} once done, and {"drained"} at the output's end. From the
//! agent: {"resize": {"width", "height"}}, {"kill": true} (the cleanup's
//! SIGKILL), and {"abandon": true}, which the socket's end also means.
//! Nothing but the exec's output reaches the caller's streams, and
//! neither arguments nor the environment appear in any answer.

use super::super::spec::to_go_json;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// What `runtime exec` reads on descriptor 3.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ExecRequest {
    pub bundle: String,
    pub dir: String,
    pub root: String,
    /// The container's OCI runtime (oci.rs): crun, or runc for a container
    /// it created. Both take the same arguments (`oci_args`).
    #[serde(alias = "runc")]
    pub runtime: String,
    pub id: String,
    #[serde(deserialize_with = "crate::runtime::nullable")]
    pub args: Vec<String>,
    pub terminal: bool,
    #[serde(rename = "consoleSize")]
    pub console_size: Option<ConsoleBox>,
    /// Which of the caller's streams the agent passed (5, 6, 7).
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
    /// The drain's grace (ExecApp's ioDrainGrace); 0 copies the output
    /// to its end (the driver's Exec of system containers).
    #[serde(rename = "drainGraceMs")]
    pub drain_grace_ms: u64,
    /// execProcess's terminalDrainGrace.
    #[serde(rename = "terminalDrainGraceMs")]
    pub terminal_drain_grace_ms: u64,
    /// With a terminal, the runtime hands the container's own terminal
    /// over a console socket instead of copying through one of its own
    /// (crun, ADR 0056: its own copy leaves the container's terminal
    /// without output translation and this side in raw mode, so "\n"
    /// would reach the caller without "\r"). runc keeps its own copy.
    #[serde(rename = "consoleSocket")]
    pub console_socket: bool,
}

/// The console socket's name in the exec's directory.
const CONSOLE_SOCKET: &str = "console.sock";

/// specs.Box.
#[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq)]
pub struct ConsoleBox {
    pub height: u64,
    pub width: u64,
}

type Raw = Option<Box<RawValue>>;

/// The bundle's config.json: only its process is read.
#[derive(Deserialize)]
struct Config {
    #[serde(default)]
    process: Option<ProcessIn>,
}

/// specs.Process (runtime-spec v1.3.0) as config.json holds it: every
/// field ExecApp keeps is kept as its bytes, which json.Marshal wrote
/// (Bundles.Create, or armada-node's bundle create, which writes the same
/// bytes), so writing them back gives what Go's json.Marshal of the
/// decoded process gives.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProcessIn {
    #[serde(default)]
    console_size: Option<ConsoleBox>,
    #[serde(default)]
    user: Raw,
    #[serde(default)]
    command_line: Raw,
    #[serde(default)]
    env: Raw,
    #[serde(default)]
    cwd: Raw,
    #[serde(default)]
    capabilities: Raw,
    #[serde(default)]
    rlimits: Raw,
    #[serde(default)]
    no_new_privileges: Raw,
    #[serde(default)]
    apparmor_profile: Raw,
    #[serde(default, rename = "oomScoreAdj")]
    oom_score_adj: Raw,
    #[serde(default)]
    scheduler: Raw,
    #[serde(default)]
    selinux_label: Raw,
    #[serde(default, rename = "ioPriority")]
    io_priority: Raw,
    #[serde(default, rename = "execCPUAffinity")]
    exec_cpu_affinity: Raw,
}

/// specs.Process in its field order with its omitempty rules.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessOut {
    #[serde(skip_serializing_if = "is_false")]
    terminal: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    console_size: Option<ConsoleBox>,
    user: Box<RawValue>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command_line: Raw,
    #[serde(skip_serializing_if = "Option::is_none")]
    env: Raw,
    cwd: Box<RawValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capabilities: Raw,
    #[serde(skip_serializing_if = "Option::is_none")]
    rlimits: Raw,
    #[serde(skip_serializing_if = "Option::is_none")]
    no_new_privileges: Raw,
    #[serde(skip_serializing_if = "Option::is_none")]
    apparmor_profile: Raw,
    #[serde(rename = "oomScoreAdj", skip_serializing_if = "Option::is_none")]
    oom_score_adj: Raw,
    #[serde(skip_serializing_if = "Option::is_none")]
    scheduler: Raw,
    #[serde(skip_serializing_if = "Option::is_none")]
    selinux_label: Raw,
    #[serde(rename = "ioPriority", skip_serializing_if = "Option::is_none")]
    io_priority: Raw,
    #[serde(rename = "execCPUAffinity", skip_serializing_if = "Option::is_none")]
    exec_cpu_affinity: Raw,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn raw(s: &str) -> Box<RawValue> {
    RawValue::from_string(s.to_string()).expect("valid JSON")
}

/// An omitempty field Go leaves out: missing, null, or its zero value
/// (empty), else its bytes.
fn unless(v: Raw, empty: &str) -> Raw {
    v.filter(|r| r.get() != empty)
}

/// The process spec execProcess.Start writes: the container's process
/// with args, terminal, and consoleSize as the request sets them.
pub fn process_json(config: &[u8], r: &ExecRequest) -> Result<Vec<u8>, String> {
    let c: Config =
        serde_json::from_slice(config).map_err(|_| "unreadable config.json".to_string())?;
    let p = c
        .process
        .ok_or_else(|| "config.json has no process".to_string())?;
    // The console size is the request's; the container's own is only read
    // so an unreadable one fails as Go's decoding does.
    let _ = p.console_size;
    let out = ProcessOut {
        terminal: r.terminal,
        console_size: r.console_size,
        user: p.user.unwrap_or_else(|| raw(r#"{"uid":0,"gid":0}"#)),
        args: r.args.clone(),
        command_line: unless(p.command_line, r#""""#),
        env: unless(p.env, "[]"),
        cwd: p.cwd.unwrap_or_else(|| raw(r#""""#)),
        capabilities: p.capabilities,
        rlimits: unless(p.rlimits, "[]"),
        no_new_privileges: unless(p.no_new_privileges, "false"),
        apparmor_profile: unless(p.apparmor_profile, r#""""#),
        oom_score_adj: p.oom_score_adj,
        scheduler: p.scheduler,
        selinux_label: unless(p.selinux_label, r#""""#),
        io_priority: p.io_priority,
        exec_cpu_affinity: p.exec_cpu_affinity,
    };
    Ok(to_go_json(&out))
}

/// The OCI runtime's arguments, as execProcess.Start gives them. crun
/// and runc read them alike: the process from process.json (its terminal
/// and console size included; `--tty` changes nothing then), the pid
/// written to the pid file once the process runs, and, with a terminal
/// and no console socket, a terminal of the runtime's own whose output
/// it copies to its stdout and whose size it takes from its stdin on
/// SIGWINCH.
pub fn oci_args(r: &ExecRequest) -> Vec<String> {
    let dir = Path::new(&r.dir);
    let mut a: Vec<String> = vec![
        "--root".into(),
        r.root.clone(),
        "exec".into(),
        "--process".into(),
        dir.join("process.json").to_string_lossy().into_owned(),
        "--pid-file".into(),
        dir.join("pid").to_string_lossy().into_owned(),
    ];
    if r.terminal {
        a.push("--tty".into());
        if r.console_socket {
            a.push("--console-socket".into());
            a.push(dir.join(CONSOLE_SOCKET).to_string_lossy().into_owned());
        }
    }
    a.push(r.id.clone());
    a
}

/// The console socket in the exec's directory, listening, non-blocking.
/// Bound through the directory's descriptor, so a directory path longer
/// than a socket address holds still works (the runtime connects the same
/// way, through /proc/self/fd, when the path is too long).
fn console_listener(dir: &str) -> std::io::Result<std::os::unix::net::UnixListener> {
    let d = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
        .open(dir)?;
    let l = std::os::unix::net::UnixListener::bind(format!(
        "/proc/self/fd/{}/{CONSOLE_SOCKET}",
        d.as_raw_fd()
    ))?;
    l.set_nonblocking(true)?;
    Ok(l)
}

/// The terminal a connection on the console socket carries (SCM_RIGHTS):
/// the master of the container's own pseudo-terminal. Anything that is
/// not a terminal is refused; descriptors past the first are closed.
fn recv_terminal(s: &UnixStream) -> std::io::Result<File> {
    let mut buf = [0u8; 4096];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // Room for a few descriptors, aligned for cmsghdr.
    let mut control = [0u64; 16];
    // SAFETY: a zeroed msghdr is a valid empty one.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control) as _;
    let n = loop {
        // SAFETY: recvmsg on a socket this process owns, into msg.
        let n = unsafe { libc::recvmsg(s.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n >= 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            break n;
        }
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut fds = Vec::new();
    // SAFETY: walking the control messages recvmsg filled in.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(c).cast::<i32>();
                let len = (*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                for i in 0..len / std::mem::size_of::<i32>() {
                    fds.push(File::from_raw_fd(std::ptr::read_unaligned(data.add(i))));
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    let mut fds = fds.into_iter();
    let f = fds
        .next()
        .ok_or_else(|| std::io::Error::other("no terminal on the console socket"))?;
    // SAFETY: isatty on a descriptor this process owns.
    if unsafe { libc::isatty(f.as_raw_fd()) } != 1 {
        return Err(std::io::Error::other("the console socket sent no terminal"));
    }
    Ok(f)
}

/// Whether child pid ended (not reaped: Runc reaps it).
fn ended(pid: libc::pid_t) -> bool {
    // SAFETY: waitid with WNOWAIT|WNOHANG on this process's child, into a
    // zeroed local.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
        )
    };
    // SAFETY: si_pid of the siginfo waitid filled (0 when nothing ended).
    r != 0 || unsafe { info.si_pid() } != 0
}

/// The container's terminal from the console socket: the runtime sends it
/// once the process is made, before it writes the pid. None when the
/// runtime ended without sending one, or by the start's limit.
fn await_terminal(
    l: &std::os::unix::net::UnixListener,
    pid: libc::pid_t,
    limit: Instant,
) -> Option<File> {
    loop {
        let gone = ended(pid);
        match l.accept() {
            Ok((c, _)) => {
                let _ = c.set_nonblocking(false);
                let _ = c.set_read_timeout(Some(Duration::from_secs(1)));
                return recv_terminal(&c).ok();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return None,
        }
        // What a runtime sent before it ended is queued: accepted above.
        if gone || Instant::now() >= limit {
            return None;
        }
        let mut p = libc::pollfd {
            fd: l.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll of the listener this function holds.
        unsafe { libc::poll(&mut p, 1, 10) };
    }
}

/// What happened before runc was to run.
#[derive(Debug, PartialEq)]
pub enum Prepared {
    Ready,
    /// A failure Go words itself by doing the start.
    Redo(String),
    /// armada-node failing.
    Error(String),
}

/// Writes process.json under the request's directory as Go writes it
/// (MkdirAll 0700, WriteFile 0600).
pub fn prepare(r: &ExecRequest) -> Prepared {
    let config = match std::fs::read(Path::new(&r.bundle).join("config.json")) {
        Ok(b) => b,
        Err(e) => return Prepared::Redo(format!("read config.json: {e}")),
    };
    let body = match process_json(&config, r) {
        Ok(b) => b,
        Err(e) => return Prepared::Error(e),
    };
    if let Err(e) = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&r.dir)
    {
        return Prepared::Redo(format!("make the exec directory: {e}"));
    }
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(Path::new(&r.dir).join("process.json"))
        .and_then(|mut f| f.write_all(&body));
    if let Err(e) = written {
        return Prepared::Redo(format!("write process.json: {e}"));
    }
    Prepared::Ready
}

/// What the agent asks for on the control socket, one JSON object per
/// line: a size change of the terminal, the kill of the exec's cleanup
/// (execProcess.Kill with SIGKILL), or the end of the session
/// (execProcess.abandon; also the socket's end).
#[derive(Deserialize, Default)]
#[serde(default)]
struct Control {
    resize: Option<Size>,
    kill: bool,
    abandon: bool,
}

#[derive(Deserialize, Default, Clone, Copy)]
#[serde(default)]
struct Size {
    width: u32,
    height: u32,
}

/// What the main loop waits for.
enum Event {
    /// runc ended, with its exit code (128 plus a signal's number).
    Exited(i32),
    /// One of the output copies ended (its source's end, or a write
    /// that failed or was refused).
    CopyDone,
    Control(Control),
    /// The agent closed the control socket.
    ControlEnd,
}

/// The exec's output: writes to the agent's pipes count as activity, as
/// runtime.OutputActivity counts writes to the caller's writers, and once
/// stopped nothing more is written (the caller's cio cancelled, or the
/// terminal closed).
struct Output {
    state: Mutex<OutputState>,
    changed: Condvar,
}

struct OutputState {
    writing: usize,
    last: Option<Instant>,
    stopped: bool,
}

impl Output {
    fn new() -> Self {
        Output {
            state: Mutex::new(OutputState {
                writing: 0,
                last: None,
                stopped: false,
            }),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, OutputState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A read and its write begin, unless the output stopped: what is
    /// read from here on is written before stop returns.
    fn begin(&self) -> bool {
        let mut s = self.lock();
        if s.stopped {
            return false;
        }
        s.writing += 1;
        true
    }

    /// The read and write begun last ended (n bytes moved).
    fn end(&self, n: usize) {
        let mut s = self.lock();
        s.writing -= 1;
        if n > 0 {
            s.last = Some(Instant::now());
        }
        self.changed.notify_all();
    }

    /// Writes b whole to dst unless the output stopped; false ends the
    /// copy.
    #[cfg(test)]
    fn write(&self, dst: &mut File, b: &[u8]) -> bool {
        if !self.begin() {
            return false;
        }
        let ok = dst.write_all(b).is_ok();
        self.end(b.len());
        ok
    }

    /// OutputActivity.quietFor.
    fn quiet_for(&self, start: Instant) -> Duration {
        let s = self.lock();
        if s.writing > 0 {
            return Duration::ZERO;
        }
        let last = match s.last {
            Some(l) if l > start => l,
            _ => start,
        };
        last.elapsed()
    }

    /// Stops the output and waits for a read and write in progress to
    /// end, so what was read is delivered (the write a copy Go cancels
    /// still finishes).
    fn stop(&self) {
        let mut s = self.lock();
        s.stopped = true;
        while s.writing > 0 {
            s = self.changed.wait(s).unwrap_or_else(|e| e.into_inner());
        }
    }
}

/// OutputActivity.WaitQuiet's timer: due once no output has moved for
/// grace, counted from the start at the earliest, checking at least
/// every grace/4 while output moves.
struct Quiet {
    start: Instant,
    grace: Duration,
    check: Instant,
}

impl Quiet {
    fn new(grace: Duration) -> Self {
        let start = Instant::now();
        Quiet {
            start,
            grace,
            check: start + grace,
        }
    }

    /// At its check time: true when quiet for the grace, else the next
    /// check is set.
    fn due(&mut self, out: &Output) -> bool {
        let quiet = out.quiet_for(self.start);
        if quiet >= self.grace {
            return true;
        }
        self.check = Instant::now() + (self.grace - quiet).max(self.grace / 4);
        false
    }
}

/// How long the process may take to start (execProcess.Start).
const START_LIMIT: Duration = Duration::from_secs(10);
/// How often the pid file is read while it starts.
const START_POLL: Duration = Duration::from_millis(10);

/// The pid runc wrote, else 0 (execProcess.Pid).
fn exec_pid(dir: &str) -> u32 {
    let Ok(b) = std::fs::read(Path::new(dir).join("pid")) else {
        return 0;
    };
    let t = crate::gostr::trim_space(&b);
    std::str::from_utf8(t)
        .ok()
        .and_then(|s| crate::gostr::parse_uint(s, 32).ok())
        .map_or(0, |n| n as u32)
}

/// A pid kill may signal: a process's own (above 1 and within pid_t),
/// never 0 or a negative value (a process group, or every process) nor
/// init.
fn signallable(pid: u32) -> Option<libc::pid_t> {
    libc::pid_t::try_from(pid).ok().filter(|p| *p > 1)
}

/// runc, reaped once: a kill after that reaches no other process.
struct Runc {
    pid: libc::pid_t,
    reaped: Mutex<bool>,
}

impl Runc {
    fn kill(&self) {
        let reaped = self.reaped.lock().unwrap_or_else(|e| e.into_inner());
        if !*reaped {
            // SAFETY: a child not reaped yet, so the pid is still runc's.
            unsafe { libc::kill(self.pid, libc::SIGKILL) };
        }
    }

    /// Waits for runc to end without reaping it, then reaps it under the
    /// lock kill takes. The code is exitCode's: 128 plus a signal's
    /// number, else the exit status.
    fn wait(&self) -> i32 {
        loop {
            // SAFETY: waitid with WNOWAIT on this process's child, into a
            // zeroed local.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let r = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            if r == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }
        let mut reaped = self.reaped.lock().unwrap_or_else(|e| e.into_inner());
        let mut status = 0;
        loop {
            // SAFETY: waitpid on this process's child.
            let r = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if r >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }
        *reaped = true;
        if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            libc::WEXITSTATUS(status)
        }
    }
}

/// Reads src (descriptor fd) to its end (or an error) and writes it out,
/// counting. It waits for input before beginning a read, so a read never
/// blocks once begun and the output's stop waits for what it read to be
/// written: bytes read as the grace runs out are still delivered.
fn copy_out(
    mut src: impl Read,
    fd: std::os::fd::RawFd,
    mut dst: File,
    out: Arc<Output>,
    tx: Sender<Event>,
) {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll of one descriptor this copy reads.
        let r = unsafe { libc::poll(&mut p, 1, -1) };
        if r < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if p.revents & libc::POLLNVAL != 0 || !out.begin() {
            break;
        }
        let (n, ok) = loop {
            match src.read(&mut buf) {
                Ok(0) => break (0, false),
                Ok(n) => break (n, dst.write_all(&buf[..n]).is_ok()),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break (0, false),
            }
        };
        out.end(n);
        if !ok {
            break;
        }
    }
    drop(dst);
    let _ = tx.send(Event::CopyDone);
}

/// Copies the caller's input to runc's, then ends it: the pipe closed, or
/// on a terminal an end-of-transmission character, as a terminal sends
/// for Ctrl-D (written even after a failed copy, as Go writes it).
fn copy_in(mut src: File, mut dst: impl Write, eot: bool) {
    let _ = std::io::copy(&mut src, &mut dst);
    if eot {
        let _ = dst.write_all(&[4]);
    }
}

/// A pseudo-terminal as console.NewPty makes it: /dev/ptmx opened
/// without becoming the controlling terminal, unlocked, and its other end
/// opened the same way.
fn open_pty() -> std::io::Result<(File, File)> {
    // SAFETY: open of a constant path; the descriptor is owned below.
    let fd = unsafe {
        libc::open(
            c"/dev/ptmx".as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a descriptor just opened.
    let master = unsafe { File::from_raw_fd(fd) };
    let mut unlock: libc::c_int = 0;
    let mut n: libc::c_uint = 0;
    // SAFETY: ioctls on the master with pointers to locals.
    if unsafe { libc::ioctl(fd, libc::TIOCSPTLCK, &mut unlock) } != 0
        || unsafe { libc::ioctl(fd, libc::TIOCGPTN, &mut n) } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open(format!("/dev/pts/{n}"))?;
    Ok((master, slave))
}

/// console's Resize: each side at most 65535.
fn resize(pty: &File, s: Size) {
    let ws = libc::winsize {
        ws_row: s.height.min(65535) as u16,
        ws_col: s.width.min(65535) as u16,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCSWINSZ on the master with a pointer to a local.
    unsafe { libc::ioctl(pty.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
}

/// The session's answers to the agent, one JSON object per line.
struct Answers(UnixStream);

impl Answers {
    fn send(&mut self, v: serde_json::Value) {
        let mut b = to_go_json(&v);
        b.push(b'\n');
        let _ = self.0.write_all(&b);
    }
}

/// Takes descriptor fd when the agent passed it, closed on exec.
fn take_fd(fd: i32) -> Option<File> {
    // SAFETY: F_SETFD on a descriptor number; EBADF when it is not open.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return None;
    }
    // SAFETY: an open descriptor the agent passed, owned from here.
    Some(unsafe { File::from_raw_fd(fd) })
}

/// armada-node runtime exec: runs the exec's session (execProcess and
/// ExecApp's drain in Go) and exits.
pub fn exec_command() -> ! {
    // A panic's message could carry what it was handling: a fixed text
    // goes to the agent, nothing to the caller's streams.
    std::panic::set_hook(Box::new(|_| {
        // SAFETY: descriptor 4 is the control socket; written, never
        // closed here.
        let mut f = std::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(4) });
        let _ = f.write_all(b"{\"error\":\"armada-node panicked\"}\n");
    }));
    let mut buf = Vec::new();
    if let Some(mut req) = take_fd(3) {
        let _ = req.read_to_end(&mut buf);
    }
    let Some(ctl) = take_fd(4) else {
        std::process::exit(1);
    };
    let ctl = UnixStream::from(std::os::fd::OwnedFd::from(ctl));
    let streams = [take_fd(5), take_fd(6), take_fd(7)];
    let Ok(answers) = ctl.try_clone() else {
        std::process::exit(1);
    };
    let mut ans = Answers(answers);
    let r: ExecRequest = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(_) => {
            ans.send(serde_json::json!({ "error": "unreadable request" }));
            std::process::exit(1);
        }
    };
    drop(buf);
    match prepare(&r) {
        Prepared::Ready => {}
        Prepared::Redo(e) => {
            ans.send(serde_json::json!({ "redo": e }));
            std::process::exit(1);
        }
        Prepared::Error(e) => {
            ans.send(serde_json::json!({ "error": e }));
            std::process::exit(1);
        }
    }
    start(r, ctl, ans, streams)
}

/// Starts runc on its streams and the copies between them and the
/// agent's, then runs the session.
fn start(r: ExecRequest, ctl: UnixStream, mut ans: Answers, fds: [Option<File>; 3]) -> ! {
    let [stdin, stdout, stderr] = fds;
    let stdin = stdin.filter(|_| r.stdin);
    let stdout = stdout.filter(|_| r.stdout);
    let stderr = stderr.filter(|_| r.stderr && !r.terminal);
    let mut cmd = std::process::Command::new(&r.runtime);
    cmd.args(oci_args(&r));
    let mut pty = None;
    let console = r.terminal && r.console_socket;
    let mut listener = None;
    // The runtime's own output (its errors) with a console socket: the
    // container's output arrives on its terminal instead.
    let mut runtime_out = None;
    if console {
        match console_listener(&r.dir) {
            Ok(l) => listener = Some(l),
            Err(e) => {
                ans.send(serde_json::json!({ "redo": format!("open the console socket: {e}") }));
                std::process::exit(1);
            }
        }
        let (rd, wr) = match std::io::pipe() {
            Ok(p) => p,
            Err(e) => {
                ans.send(serde_json::json!({ "redo": format!("open a pipe: {e}") }));
                std::process::exit(1);
            }
        };
        let Ok(wr2) = wr.try_clone() else {
            ans.send(serde_json::json!({ "redo": "duplicate a pipe" }));
            std::process::exit(1);
        };
        cmd.stdin(Stdio::null()).stdout(wr).stderr(wr2);
        runtime_out = Some(rd);
    } else if r.terminal {
        let (master, slave) = match open_pty() {
            Ok(p) => p,
            Err(e) => {
                ans.send(serde_json::json!({ "redo": format!("open a terminal: {e}") }));
                std::process::exit(1);
            }
        };
        if let Some(s) = r.console_size {
            resize(
                &master,
                Size {
                    width: s.width.min(u64::from(u32::MAX)) as u32,
                    height: s.height.min(u64::from(u32::MAX)) as u32,
                },
            );
        }
        let (Ok(a), Ok(b)) = (slave.try_clone(), slave.try_clone()) else {
            ans.send(serde_json::json!({ "redo": "duplicate the terminal" }));
            std::process::exit(1);
        };
        cmd.stdin(a).stdout(b).stderr(slave);
        // runc's own session with the terminal as its controlling
        // terminal, as Go's Setsid and Setctty give it.
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 1) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        pty = Some(Arc::new(master));
    } else {
        let piped = |on: bool| if on { Stdio::piped() } else { Stdio::null() };
        cmd.stdin(piped(stdin.is_some()))
            .stdout(piped(stdout.is_some()))
            .stderr(piped(stderr.is_some()));
    }
    // runc dies with this process: an armada-node killed or crashed
    // leaves no runc running with nothing to copy its output or reap it.
    // (The main thread forks it and lives until the process exits, which
    // is what the signal is tied to.) std starts it with no signal
    // blocked.
    // SAFETY: getpid cannot fail.
    let parent = unsafe { libc::getpid() };
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let errno = e.raw_os_error().unwrap_or(libc::EINVAL);
            ans.send(serde_json::json!({ "execErrno": errno }));
            std::process::exit(1);
        }
    };
    // Only runc holds the terminal's other end now.
    drop(cmd);
    ans.send(serde_json::json!({ "spawned": true }));
    if let Some(l) = &listener {
        // The container's own terminal, which the copies below and the
        // resizes use as the terminal of runc's own copy is used.
        let t = await_terminal(l, child.id() as libc::pid_t, Instant::now() + START_LIMIT);
        if let (Some(t), Some(s)) = (&t, r.console_size) {
            resize(
                t,
                Size {
                    width: s.width.min(u64::from(u32::MAX)) as u32,
                    height: s.height.min(u64::from(u32::MAX)) as u32,
                },
            );
        }
        pty = t.map(Arc::new);
    }
    drop(listener);

    let (tx, rx) = mpsc::channel();
    let out = Arc::new(Output::new());
    let mut copies = 0;
    // The runtime's own errors go where its terminal's output would.
    let runtime_dst = match (&runtime_out, &stdout) {
        (Some(_), Some(d)) => d.try_clone().ok(),
        _ => None,
    };
    if let (Some(src), Some(dst)) = (runtime_out, runtime_dst) {
        let (o, t) = (Arc::clone(&out), tx.clone());
        copies += 1;
        let fd = src.as_raw_fd();
        std::thread::spawn(move || copy_out(src, fd, dst, o, t));
    }
    if let Some(master) = &pty {
        if let Some(src) = stdin {
            let m = Arc::clone(master);
            std::thread::spawn(move || copy_in(src, &*m, true));
        }
        if let Some(dst) = stdout {
            let (m, o, t) = (Arc::clone(master), Arc::clone(&out), tx.clone());
            copies += 1;
            let fd = m.as_raw_fd();
            std::thread::spawn(move || copy_out(&*m, fd, dst, o, t));
        }
    } else {
        if let (Some(src), Some(dst)) = (stdin, child.stdin.take()) {
            std::thread::spawn(move || copy_in(src, dst, false));
        }
        let sources: [Option<(std::os::fd::RawFd, Box<dyn Read + Send>)>; 2] = [
            child
                .stdout
                .take()
                .map(|s| (s.as_raw_fd(), Box::new(s) as _)),
            child
                .stderr
                .take()
                .map(|s| (s.as_raw_fd(), Box::new(s) as _)),
        ];
        for (dst, src) in [stdout, stderr].into_iter().zip(sources) {
            if let (Some(dst), Some((fd, src))) = (dst, src) {
                let (o, t) = (Arc::clone(&out), tx.clone());
                copies += 1;
                std::thread::spawn(move || copy_out(src, fd, dst, o, t));
            }
        }
    }
    let runc = Arc::new(Runc {
        pid: child.id() as libc::pid_t,
        reaped: Mutex::new(false),
    });
    drop(child);
    {
        let (runc, tx) = (Arc::clone(&runc), tx.clone());
        std::thread::spawn(move || {
            let code = runc.wait();
            let _ = tx.send(Event::Exited(code));
        });
    }
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut lines = BufReader::new(ctl);
            let mut line = Vec::new();
            loop {
                line.clear();
                match lines.read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if let Ok(c) = serde_json::from_slice::<Control>(&line) {
                            let _ = tx.send(Event::Control(c));
                        }
                    }
                }
            }
            let _ = tx.send(Event::ControlEnd);
        });
    }
    drop(tx);
    let now = Instant::now();
    Session {
        r,
        ans,
        out,
        runc,
        pty,
        copies,
        started: false,
        start_deadline: now + START_LIMIT,
        next_poll: now,
        code: 0,
        done: false,
        end_copy: false,
        pty_closed: false,
        terminal_drain: None,
        drain: None,
        abandoned: false,
    }
    .run(rx)
}

/// The session's state: execProcess's (started, done, the terminal and
/// its drain, killRunc's end of the copy) and ExecApp's drain.
struct Session {
    r: ExecRequest,
    ans: Answers,
    out: Arc<Output>,
    runc: Arc<Runc>,
    pty: Option<Arc<File>>,
    /// Output copies still running.
    copies: usize,
    started: bool,
    start_deadline: Instant,
    next_poll: Instant,
    code: i32,
    done: bool,
    end_copy: bool,
    pty_closed: bool,
    terminal_drain: Option<Quiet>,
    /// ExecApp's drain once done; None with no grace (to the end).
    drain: Option<Quiet>,
    abandoned: bool,
}

impl Session {
    fn run(mut self, rx: Receiver<Event>) -> ! {
        if exec_pid(&self.r.dir) != 0 {
            self.start_answer("started");
        } else {
            self.next_poll = Instant::now() + START_POLL;
        }
        loop {
            let wake = [
                (!self.started).then_some(self.next_poll),
                self.terminal_drain.as_ref().map(|q| q.check),
                self.drain.as_ref().map(|q| q.check),
            ]
            .into_iter()
            .flatten()
            .min();
            let ev = match wake {
                Some(at) => match rx.recv_timeout(at.saturating_duration_since(Instant::now())) {
                    Ok(ev) => Some(ev),
                    Err(RecvTimeoutError::Timeout) => None,
                    Err(RecvTimeoutError::Disconnected) => std::process::exit(1),
                },
                None => match rx.recv() {
                    Ok(ev) => Some(ev),
                    Err(_) => std::process::exit(1),
                },
            };
            match ev {
                Some(Event::Exited(code)) => self.exited(code),
                Some(Event::CopyDone) => {
                    self.copies = self.copies.saturating_sub(1);
                    if self.copies == 0 {
                        if self.terminal_drain.take().is_some() {
                            self.close_pty();
                            self.finish();
                        } else if self.done {
                            self.drained();
                        }
                    }
                }
                Some(Event::Control(c)) => {
                    if let (Some(s), Some(p), false) = (c.resize, &self.pty, self.pty_closed) {
                        resize(p, s);
                    }
                    if c.kill {
                        self.kill();
                    }
                    if c.abandon {
                        self.abandon();
                    }
                }
                Some(Event::ControlEnd) => self.abandon(),
                None => {}
            }
            let now = Instant::now();
            if !self.started && now >= self.next_poll {
                // Start's loop: after each wait the deadline, then the
                // pid file.
                if now > self.start_deadline {
                    // Start's error: runc, which never started the
                    // process, is ended too, so the session ends now
                    // rather than when the caller's cleanup gives up.
                    self.start_answer("notStarted");
                    self.kill_runc();
                } else if exec_pid(&self.r.dir) != 0 {
                    self.start_answer("started");
                } else {
                    self.next_poll = now + START_POLL;
                }
            }
            if self.terminal_drain.as_ref().is_some_and(|q| now >= q.check) {
                let mut q = self.terminal_drain.take().expect("checked");
                if q.due(&self.out) {
                    self.close_pty();
                    self.finish();
                } else {
                    self.terminal_drain = Some(q);
                }
            }
            if let Some(q) = self.drain.as_mut().filter(|q| now >= q.check)
                && q.due(&self.out)
            {
                self.drained();
            }
        }
    }

    /// What Start returned: nil ("started") or its timeout ("notStarted").
    fn start_answer(&mut self, what: &str) {
        self.started = true;
        self.ans.send(serde_json::json!({ what: true }));
    }

    fn exited(&mut self, code: i32) {
        self.code = code;
        if self.pty.is_some() && self.copies > 0 && !self.end_copy {
            // What runc wrote to the terminal before it exited may still
            // be on its way: copied until its end, until no output has
            // moved for the grace (something runc left holds the
            // terminal), or until a kill ends the copy.
            self.terminal_drain = Some(Quiet::new(Duration::from_millis(
                self.r.terminal_drain_grace_ms,
            )));
        } else {
            self.close_pty();
            self.finish();
        }
    }

    /// Closing the terminal: no more of its output is copied, and its
    /// size no longer changes. It closes when this process exits.
    fn close_pty(&mut self) {
        if self.pty.is_some() && !self.pty_closed {
            self.pty_closed = true;
            self.out.stop();
            self.copies = 0;
        }
    }

    /// execProcess's done: the directory removed and the exit code sent,
    /// then ExecApp's drain.
    fn finish(&mut self) {
        if self.done {
            return;
        }
        self.done = true;
        let _ = std::fs::remove_dir_all(&self.r.dir);
        if !self.started {
            self.start_answer("started");
        }
        self.ans.send(serde_json::json!({ "exit": self.code }));
        if self.abandoned {
            std::process::exit(0);
        }
        if self.copies == 0 {
            self.drained();
        }
        if self.r.drain_grace_ms > 0 {
            self.drain = Some(Quiet::new(Duration::from_millis(self.r.drain_grace_ms)));
        }
    }

    /// The output's end: nothing more is written, and the session ends.
    fn drained(&mut self) -> ! {
        self.out.stop();
        self.ans.send(serde_json::json!({ "drained": true }));
        std::process::exit(0);
    }

    /// execProcess.Kill with SIGKILL: the process runc started, then runc
    /// and the copy of the terminal's output. Nothing once done. Before
    /// runc wrote the pid, runc alone is ended, so a start that never
    /// comes does not hold the caller's cleanup (Go's code answers
    /// NotFound and waits).
    fn kill(&mut self) {
        if self.done {
            return;
        }
        if let Some(p) = signallable(exec_pid(&self.r.dir)) {
            // SAFETY: kill of a process's own pid (not a group, init, or
            // every process).
            unsafe { libc::kill(p, libc::SIGKILL) };
        }
        self.kill_runc();
    }

    /// killRunc: runc killed, and the terminal's copy ended.
    fn kill_runc(&mut self) {
        self.end_copy = true;
        self.runc.kill();
        if self.terminal_drain.take().is_some() {
            self.close_pty();
            self.finish();
        }
    }

    /// execProcess.abandon: runc killed and nothing more copied; the
    /// session ends once runc is reaped and its directory removed.
    fn abandon(&mut self) {
        self.abandoned = true;
        self.out.stop();
        if self.done {
            std::process::exit(0);
        }
        self.kill_runc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(args: &[&str], terminal: bool, size: Option<(u64, u64)>) -> ExecRequest {
        ExecRequest {
            bundle: "/b".into(),
            dir: "/run/x/exec-c1-e".into(),
            root: "/run/x/root".into(),
            runtime: "/bin/crun".into(),
            id: "c1".into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            terminal,
            console_size: size.map(|(h, w)| ConsoleBox {
                height: h,
                width: w,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn keeps_the_container_process() {
        let config = br#"{"ociVersion":"1.3.0","process":{"user":{"uid":1000,"gid":1000,"additionalGids":[1000]},"args":["/app","--x"],"env":["PATH=/bin","A=\u003cb\u003e"],"cwd":"/srv","capabilities":{"bounding":["CAP_CHOWN"]},"rlimits":[{"type":"RLIMIT_NOFILE","hard":1024,"soft":1024}],"noNewPrivileges":true,"apparmorProfile":"armada","oomScoreAdj":0,"selinuxLabel":"x"},"root":{"path":"rootfs"}}"#;
        let got = process_json(config, &req(&["sh", "-c", "a<b"], true, Some((33, 101)))).unwrap();
        assert_eq!(
            String::from_utf8(got).unwrap(),
            r#"{"terminal":true,"consoleSize":{"height":33,"width":101},"user":{"uid":1000,"gid":1000,"additionalGids":[1000]},"args":["sh","-c","a\u003cb"],"env":["PATH=/bin","A=\u003cb\u003e"],"cwd":"/srv","capabilities":{"bounding":["CAP_CHOWN"]},"rlimits":[{"type":"RLIMIT_NOFILE","hard":1024,"soft":1024}],"noNewPrivileges":true,"apparmorProfile":"armada","oomScoreAdj":0,"selinuxLabel":"x"}"#
        );
    }

    #[test]
    fn zero_values_as_go_writes_them() {
        let config = br#"{"process":{"terminal":true,"consoleSize":{"height":1,"width":2},"env":[],"cwd":null,"user":null,"noNewPrivileges":false,"rlimits":null}}"#;
        let got = process_json(config, &req(&[], false, None)).unwrap();
        assert_eq!(
            String::from_utf8(got).unwrap(),
            r#"{"user":{"uid":0,"gid":0},"cwd":""}"#
        );
        assert!(process_json(b"{}", &req(&[], false, None)).is_err());
        assert!(process_json(b"{", &req(&[], false, None)).is_err());
    }

    #[test]
    fn oci_arguments() {
        assert_eq!(
            oci_args(&req(&["x"], true, None)),
            [
                "--root",
                "/run/x/root",
                "exec",
                "--process",
                "/run/x/exec-c1-e/process.json",
                "--pid-file",
                "/run/x/exec-c1-e/pid",
                "--tty",
                "c1"
            ]
        );
        assert_eq!(oci_args(&req(&["x"], false, None)).len(), 8);
        // crun's terminal comes over a console socket in the exec's
        // directory (ADR 0056); without a terminal there is none.
        let mut console = req(&["x"], true, None);
        console.console_socket = true;
        assert_eq!(
            oci_args(&console)[7..],
            [
                "--tty",
                "--console-socket",
                "/run/x/exec-c1-e/console.sock",
                "c1"
            ]
        );
        console.terminal = false;
        assert_eq!(oci_args(&console).len(), 8);
        // A request of the agent before ADR 0056 names runc by its key.
        let r: ExecRequest = serde_json::from_str(r#"{"runc": "/bin/runc", "id": "c1"}"#).unwrap();
        assert_eq!(r.runtime, "/bin/runc");
    }

    #[test]
    fn pid_file_as_go_reads_it() {
        let dir = std::env::temp_dir().join(format!("armada-exec-pid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let d = dir.to_str().unwrap();
        assert_eq!(exec_pid(d), 0);
        for (text, want) in [
            (" 42\n", 42),
            ("+42", 0),
            ("4294967295", 4294967295),
            ("4294967296", 0),
            ("x", 0),
            ("", 0),
        ] {
            std::fs::write(dir.join("pid"), text).unwrap();
            assert_eq!(exec_pid(d), want, "{text:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn quiet_waits_for_the_grace_after_the_last_write() {
        let out = Output::new();
        let grace = Duration::from_millis(40);
        let mut q = Quiet::new(grace);
        assert!(!q.due(&out), "not quiet before the grace");
        std::thread::sleep(grace);
        assert!(q.due(&out));
        // A write in progress is never quiet; one that ended counts from
        // its end, checked again at least every grace/4.
        let mut q = Quiet::new(grace);
        out.lock().writing = 1;
        std::thread::sleep(grace);
        assert!(!q.due(&out));
        assert!(q.check >= Instant::now() + grace / 4 - Duration::from_millis(5));
        {
            let mut s = out.lock();
            s.writing = 0;
            s.last = Some(Instant::now());
        }
        assert!(!q.due(&out));
        std::thread::sleep(grace);
        assert!(q.due(&out));
    }

    #[test]
    fn signals_only_a_process_s_own_pid() {
        for (pid, want) in [
            (0, None),
            (1, None),
            (2, Some(2)),
            (2_147_483_647, Some(2_147_483_647)),
            (2_147_483_648, None),
            (u32::MAX, None),
        ] {
            assert_eq!(signallable(pid), want, "{pid}");
        }
    }

    #[test]
    fn delivers_what_it_read_before_the_stop() {
        // A copy that read bytes as the output stops still writes them:
        // stop waits for it.
        let (r, mut w) = std::io::pipe().unwrap();
        let (dr, dw) = std::io::pipe().unwrap();
        let out = Arc::new(Output::new());
        let (tx, rx) = mpsc::channel();
        let fd = r.as_raw_fd();
        let o = Arc::clone(&out);
        let dst = File::from(std::os::fd::OwnedFd::from(dw));
        let t = std::thread::spawn(move || copy_out(r, fd, dst, o, tx));
        w.write_all(b"last words").unwrap();
        // Wait until the copy took them, then stop at once.
        let start = Instant::now();
        while out.lock().last.is_none() && out.lock().writing == 0 {
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::yield_now();
        }
        out.stop();
        drop(w);
        t.join().unwrap();
        assert!(matches!(rx.recv().unwrap(), Event::CopyDone));
        let mut got = Vec::new();
        let mut dr = dr;
        dr.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"last words");
        // Stopped: nothing more is read.
        assert!(!out.begin());
    }

    #[test]
    fn stopped_output_takes_no_writes() {
        let out = Output::new();
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        assert!(out.write(&mut f, b"x"));
        out.stop();
        assert!(!out.write(&mut f, b"x"));
    }

    #[test]
    fn control_lines() {
        let c: Control =
            serde_json::from_str(r#"{"resize":{"width":80,"height":24},"other":1}"#).unwrap();
        let s = c.resize.unwrap();
        assert_eq!(
            (s.width, s.height, c.kill, c.abandon),
            (80, 24, false, false)
        );
        let c: Control = serde_json::from_str(r#"{"kill":true}"#).unwrap();
        assert!(c.kill && c.resize.is_none());
    }
}

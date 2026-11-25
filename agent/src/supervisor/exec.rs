//! Commands in a running container through `armada-node runtime exec`
//! (ADR 0054 step 5, last part; internal/runtime/supervisor
//! nativeexec.go), which becomes runc's parent and copies its output: a
//! probe's command (output dropped, the drain's grace of ExecApp) and a
//! system container's command (its whole output, as Driver.Exec). The
//! request goes on descriptor 3, the control socket is descriptor 4, and
//! the output both descriptors 6 and 7, so it arrives as one stream.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

/// The exec's request (nativeExec).
pub struct ExecRequest<'a> {
    pub bundle: &'a str,
    pub dir: &'a str,
    pub root: &'a str,
    pub runc: &'a str,
    pub id: &'a str,
    pub args: &'a [String],
    /// Whether the output is wanted (descriptors 6 and 7).
    pub output: bool,
    /// ExecApp's ioDrainGrace; 0 copies the output to its end.
    pub drain_grace: Duration,
}

/// ExecApp's and execProcess's graces.
pub const DRAIN_GRACE: Duration = Duration::from_secs(2);
pub const TERMINAL_DRAIN_GRACE: Duration = Duration::from_secs(2);

#[derive(Deserialize, Default)]
struct Answer {
    #[serde(default)]
    spawned: bool,
    #[serde(rename = "execErrno", default)]
    exec_errno: Option<i32>,
    #[serde(default)]
    redo: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(rename = "notStarted", default)]
    not_started: bool,
    #[serde(default)]
    exit: Option<i64>,
    #[serde(default)]
    drained: bool,
}

fn pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: fds has room for two descriptors.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both were just made and are owned by nobody else.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Places each (source, target) on its target in the child, sources moved
/// above every target first so none is overwritten.
fn place(fds: &[(RawFd, RawFd)]) -> std::io::Result<()> {
    // No allocation between fork and exec.
    let mut moved = [0 as RawFd; 8];
    for (i, (src, _)) in fds.iter().enumerate().take(moved.len()) {
        // SAFETY: duplicating an open descriptor in the child.
        let n = unsafe { libc::fcntl(*src, libc::F_DUPFD_CLOEXEC, 64) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        moved[i] = n;
    }
    for (n, (_, target)) in moved.iter().zip(fds) {
        // SAFETY: dup2 onto a descriptor this child owns; it is kept open
        // across exec (no CLOEXEC on a dup2 target).
        if unsafe { libc::dup2(*n, *target) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Closes the control socket on drop: armada-node reads that as abandon,
/// after the cleanup's kill.
struct KillOnDrop(Option<UnixStream>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(mut s) = self.0.take() {
            let _ = s.set_nonblocking(true);
            let _ = s.write_all(b"{\"kill\":true}\n");
        }
    }
}

/// Runs the exec and returns its exit code and output. Blocking: the
/// caller runs it off its async tasks; a caller that gives up drops the
/// returned future's thread result, and the control socket's end stops
/// armada-node.
pub fn run(node: &Path, r: &ExecRequest<'_>) -> Result<(i64, Vec<u8>), String> {
    let mut grace = r.drain_grace.as_millis() as u64;
    if !r.drain_grace.is_zero() && grace == 0 {
        grace = 1;
    }
    let req = serde_json::json!({
        "bundle": r.bundle, "dir": r.dir, "root": r.root, "runc": r.runc, "id": r.id,
        "args": r.args, "terminal": false, "consoleSize": Value::Null,
        "stdin": false, "stdout": r.output, "stderr": r.output,
        "drainGraceMs": grace,
        "terminalDrainGraceMs": TERMINAL_DRAIN_GRACE.as_millis() as u64,
    });
    let (req_r, req_w) = pipe().map_err(|e| e.to_string())?;
    let (ctl, ctl_child) = UnixStream::pair().map_err(|e| e.to_string())?;
    let (out_r, out_w) = pipe().map_err(|e| e.to_string())?;
    let mut targets = vec![(req_r.as_raw_fd(), 3), (ctl_child.as_raw_fd(), 4)];
    if r.output {
        targets.push((out_w.as_raw_fd(), 6));
        targets.push((out_w.as_raw_fd(), 7));
    }
    let mut cmd = std::process::Command::new(node);
    cmd.args(["runtime", "exec"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: place only duplicates descriptors (async-signal-safe).
    unsafe {
        cmd.pre_exec(move || place(&targets));
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("armada-node: {}", super::errno(&e)))?;
    drop((req_r, ctl_child, out_w));
    // The request may be larger than a pipe holds: written beside.
    let body = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
    let writer = std::thread::spawn(move || {
        let mut f = std::fs::File::from(req_w);
        let _ = f.write_all(&body);
    });
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = std::fs::File::from(out_r).read_to_end(&mut out);
        out
    });
    let mut control = KillOnDrop(Some(ctl.try_clone().map_err(|e| e.to_string())?));
    let res = answers(BufReader::new(ctl), r.runc);
    if res.is_ok() {
        // Done: nothing to kill.
        control.0 = None;
    }
    drop(control);
    let _ = writer.join();
    let output = reader.join().unwrap_or_default();
    let _ = child.wait();
    res.map(|code| (code, output))
}

/// The agent's side of the control socket until the session ends.
fn answers(mut ctl: BufReader<UnixStream>, runc: &str) -> Result<i64, String> {
    let mut code = None;
    let mut first = true;
    let mut line = String::new();
    loop {
        line.clear();
        match ctl.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let a: Answer = serde_json::from_str(line.trim_end())
            .map_err(|_| "exec: armada-node: unreadable answer".to_string())?;
        if first {
            first = false;
            match (a.spawned, a.exec_errno, a.redo, a.error) {
                (true, ..) => {}
                (_, Some(n), ..) => {
                    return Err(format!(
                        "exec: runc exec: fork/exec {runc}: {}",
                        armada_node::runtime::container::errno_text(n)
                    ));
                }
                (_, _, Some(r), _) => return Err(format!("exec: {r}")),
                (_, _, _, Some(e)) => return Err(format!("exec: armada-node: {e}")),
                _ => return Err("exec: armada-node: unreadable answer".into()),
            }
            continue;
        }
        if a.not_started {
            return Err("exec: runc exec did not start the process".into());
        }
        if let Some(c) = a.exit {
            code = Some(c);
        }
        if a.drained {
            break;
        }
    }
    if first {
        return Err("exec: armada-node: ended the exec session".into());
    }
    code.ok_or_else(|| "exec: armada-node: ended the exec session".to_string())
}

/// ExecApp's bound on killing a process the call left running
/// (execCleanupTimeout).
pub const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

/// An exec session's request (nativeExec) with a terminal and streams.
pub struct SessionRequest {
    pub bundle: String,
    pub dir: String,
    pub root: String,
    pub runc: String,
    pub id: String,
    pub args: Vec<String>,
    pub tty: bool,
    /// The terminal's first size; rows and cols 0 when unknown.
    pub size: crate::side::TermSize,
}

/// A line armada-node writes on the control socket.
#[derive(Deserialize, Default)]
struct Line {
    #[serde(default)]
    spawned: bool,
    #[serde(rename = "execErrno", default)]
    exec_errno: Option<i32>,
    #[serde(default)]
    redo: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    started: bool,
    #[serde(rename = "notStarted", default)]
    not_started: bool,
    #[serde(default)]
    exit: Option<i64>,
    #[serde(default)]
    drained: bool,
}

/// The agent's side of the control socket: lines to send, answers
/// received. Dropped before the exit, the session is cleaned up beside
/// the caller as ExecApp's deferred Delete does: the kill, the exit
/// awaited within CLEANUP_TIMEOUT, then the socket's end (abandon).
struct Control {
    tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
    answers: tokio::sync::mpsc::Receiver<Option<Line>>,
    exited: bool,
}

impl Control {
    fn send(&self, v: &Value) {
        if let Some(tx) = &self.tx {
            let mut b = serde_json::to_vec(v).unwrap_or_default();
            b.push(b'\n');
            let _ = tx.send(b);
        }
    }

    /// The next answer; None once the socket ended. An unreadable line is
    /// Some(None).
    async fn next(&mut self) -> Option<Option<Line>> {
        self.answers.recv().await
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        if self.exited {
            return;
        }
        let Some(tx) = self.tx.take() else { return };
        let mut answers = std::mem::replace(&mut self.answers, tokio::sync::mpsc::channel(1).1);
        let Ok(h) = tokio::runtime::Handle::try_current() else {
            return;
        };
        h.spawn(async move {
            let _ = tx.send(b"{\"kill\":true}\n".to_vec());
            let _ = tokio::time::timeout(CLEANUP_TIMEOUT, async {
                while let Some(a) = answers.recv().await {
                    if a.is_some_and(|a| a.exit.is_some()) {
                        break;
                    }
                }
            })
            .await;
            // The writer's end closes the socket: abandon.
            drop(tx);
        });
    }
}

fn nonblocking(fd: OwnedFd) -> std::io::Result<OwnedFd> {
    // SAFETY: fcntl on a descriptor this process owns.
    unsafe {
        let fl = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        if fl < 0 || libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(fd)
}

/// An exec session armada-node runs whole (Store.NativeExec and
/// ExecApp's flow): the caller's input until its channel ends, the
/// output in the order each stream is written (stdout true), the
/// terminal's sizes, the exit code once the output was drained. A failure
/// before runc ran answers with ExecApp's texts; dropping the future
/// kills the command (within CLEANUP_TIMEOUT) and abandons the session.
pub async fn session(
    node: &Path,
    r: SessionRequest,
    mut opts: crate::side::ExecOptions,
) -> Result<i64, String> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

    let console = if r.tty && r.size.rows > 0 && r.size.cols > 0 {
        serde_json::json!({"height": r.size.rows, "width": r.size.cols})
    } else {
        Value::Null
    };
    let want_out = opts.output.is_some();
    let req = serde_json::json!({
        "bundle": r.bundle, "dir": r.dir, "root": r.root, "runc": r.runc, "id": r.id,
        "args": r.args, "terminal": r.tty, "consoleSize": console,
        "stdin": opts.stdin.is_some(), "stdout": want_out, "stderr": want_out && !r.tty,
        "drainGraceMs": DRAIN_GRACE.as_millis() as u64,
        "terminalDrainGraceMs": TERMINAL_DRAIN_GRACE.as_millis() as u64,
    });
    let io = |e: std::io::Error| format!("exec: armada-node: {e}");
    let (req_r, req_w) = pipe().map_err(io)?;
    let (ctl, ctl_child) = UnixStream::pair().map_err(io)?;
    let mut targets = vec![(req_r.as_raw_fd(), 3), (ctl_child.as_raw_fd(), 4)];
    let mut keep_child = vec![req_r, OwnedFd::from(ctl_child)];
    let mut input = None;
    if opts.stdin.is_some() {
        let (r, w) = pipe().map_err(io)?;
        targets.push((r.as_raw_fd(), 5));
        keep_child.push(r);
        input = Some(w);
    }
    let mut outs = Vec::new();
    if want_out {
        for (stdout, slot) in [(true, 6), (false, 7)] {
            if !stdout && r.tty {
                continue;
            }
            let (rd, w) = pipe().map_err(io)?;
            targets.push((w.as_raw_fd(), slot));
            keep_child.push(w);
            outs.push((stdout, rd));
        }
    }
    let mut cmd = std::process::Command::new(node);
    cmd.args(["runtime", "exec"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: place only duplicates descriptors (async-signal-safe).
    unsafe {
        cmd.pre_exec(move || place(&targets));
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("exec: armada-node: {}", super::errno(&e)))?;
    drop(keep_child);
    tokio::task::spawn_blocking(move || {
        let _ = child.wait();
    });
    // The request carries the command's arguments: never logged.
    let body = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        let _ = std::fs::File::from(req_w).write_all(&body);
    });

    ctl.set_nonblocking(true).map_err(io)?;
    let ctl = tokio::net::UnixStream::from_std(ctl).map_err(io)?;
    let (rd, mut wr) = ctl.into_split();
    let (atx, arx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(rd).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            if atx
                .send(serde_json::from_str::<Line>(&l).ok())
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let (stx, mut srx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(b) = srx.recv().await {
            if wr.write_all(&b).await.is_err() {
                break;
            }
        }
        // The socket's end: armada-node abandons what is left.
        let _ = wr.shutdown().await;
    });
    let mut c = Control {
        tx: Some(stx),
        answers: arx,
        exited: false,
    };

    match c.next().await {
        Some(Some(a)) if a.spawned => {}
        Some(Some(a)) if a.exec_errno.is_some() => {
            c.exited = true;
            return Err(format!(
                "exec: runc exec: fork/exec {}: {}",
                r.runc,
                armada_node::runtime::container::errno_text(a.exec_errno.unwrap_or_default())
            ));
        }
        Some(Some(a)) if a.redo.is_some() => {
            c.exited = true;
            return Err(format!("exec: {}", a.redo.unwrap_or_default()));
        }
        Some(Some(a)) if a.error.is_some() => {
            c.exited = true;
            return Err(format!(
                "exec: armada-node: {}",
                a.error.unwrap_or_default()
            ));
        }
        _ => {
            c.exited = true;
            return Err("exec: armada-node: unreadable answer".into());
        }
    }

    // The caller's streams.
    if let (Some(w), Some(mut stdin)) = (input, opts.stdin.take()) {
        let w = nonblocking(w).map_err(io)?;
        let mut w = tokio::net::unix::pipe::Sender::from_owned_fd(w).map_err(io)?;
        tokio::spawn(async move {
            while let Some(b) = stdin.recv().await {
                if w.write_all(&b).await.is_err() {
                    return;
                }
            }
            // The input's end, as the caller's cio closes its FIFO.
        });
    }
    let mut copies = Vec::new();
    if let Some(out) = opts.output.take() {
        for (stdout, rd) in outs {
            let rd = nonblocking(rd).map_err(io)?;
            let mut rd = tokio::net::unix::pipe::Receiver::from_owned_fd(rd).map_err(io)?;
            let out = out.clone();
            copies.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 32 << 10];
                loop {
                    match rd.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if out.send((stdout, buf[..n].to_vec())).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }));
        }
    }

    // execProcess.Start.
    loop {
        match c.next().await {
            None => return Err("exec: armada-node: ended the exec session".into()),
            Some(Some(a)) if a.not_started => {
                return Err("exec: runc exec did not start the process".into());
            }
            Some(Some(a)) if a.started => break,
            Some(_) => {}
        }
    }
    let resize = |c: &Control, s: crate::side::TermSize| {
        if s.rows > 0 && s.cols > 0 {
            c.send(&serde_json::json!({"resize": {"width": s.cols, "height": s.rows}}));
        }
    };
    if r.tty {
        resize(&c, r.size);
    }
    let mut sizes = if r.tty { opts.resize.take() } else { None };
    // The exit, with resizes while it runs.
    let code = loop {
        tokio::select! {
            a = c.next() => match a {
                None => return Err("exec: armada-node: ended the exec session".into()),
                Some(Some(a)) => if let Some(code) = a.exit { break code },
                Some(None) => {}
            },
            s = async { sizes.as_mut()?.recv().await }, if sizes.is_some() => match s {
                Some(s) => resize(&c, s),
                None => sizes = None,
            },
        }
    };
    c.exited = true;
    // The drain, done by armada-node; then the copies reach the end it
    // closes.
    loop {
        match c.next().await {
            None => break,
            Some(Some(a)) if a.drained => break,
            Some(_) => {}
        }
    }
    for h in copies {
        let _ = h.await;
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in armada-node: reads the request on 3, answers on 4, and
    /// writes output on 6 and 7.
    fn stand_in(dir: &Path, script: &str) -> std::path::PathBuf {
        let p = dir.join("armada-node");
        std::fs::write(&p, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn runs_and_answers() {
        let dir = std::env::temp_dir().join(format!("armada-exec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let rec = dir.join("req.json");
        let bin = stand_in(
            &dir,
            &format!(
                "cat <&3 >{}\necho '{{\"spawned\":true}}' >&4\necho out >&6\necho err >&7\necho '{{\"started\":true}}' >&4\necho '{{\"exit\":3}}' >&4\necho '{{\"drained\":true}}' >&4",
                rec.display()
            ),
        );
        let args = vec!["haproxy".to_string(), "-c".to_string()];
        let r = ExecRequest {
            bundle: "/b",
            dir: "/d",
            root: "/r",
            runc: "/runc",
            id: "hap",
            args: &args,
            output: true,
            drain_grace: Duration::ZERO,
        };
        let (code, out) = run(&bin, &r).unwrap();
        assert_eq!(code, 3);
        assert_eq!(String::from_utf8(out).unwrap(), "out\nerr\n");
        let req: Value = serde_json::from_slice(&std::fs::read(&rec).unwrap()).unwrap();
        assert_eq!(req["args"], serde_json::json!(["haproxy", "-c"]));
        assert_eq!(req["drainGraceMs"], 0);
        assert_eq!(req["stdout"], true);
        let bin = stand_in(&dir, "echo '{\"execErrno\":2}' >&4");
        assert_eq!(
            run(&bin, &r).unwrap_err(),
            "exec: runc exec: fork/exec /runc: no such file or directory"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

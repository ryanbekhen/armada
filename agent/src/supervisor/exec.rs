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
    let mut moved = [0 as RawFd; 4];
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
struct Control(Option<UnixStream>);

impl Drop for Control {
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
    let mut control = Control(Some(ctl.try_clone().map_err(|e| e.to_string())?));
    let res = session(BufReader::new(ctl), r.runc);
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
fn session(mut ctl: BufReader<UnixStream>, runc: &str) -> Result<i64, String> {
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

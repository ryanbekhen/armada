//! Running the runtime pack's armada-node for one call (Go's
//! internal/nodeprog): JSON on stdin, one answer on stdout, `{"error":
//! TEXT}` for an error it answered with. A call that does not start, ends
//! badly, or cannot be read fails with "armada-node: ..." and its stderr.
//! The environment's test hooks (ARMADA_NODE_TEST_*) are never passed on.
//! Programs run on blocking threads; a call whose future is dropped kills
//! its program.

use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::Value;

/// Bounds a call that has no deadline of its own.
pub const LIMIT: Duration = Duration::from_secs(60);
/// How long armada-node may run past the caller's deadline: the deadline
/// travels in the request, and the program answers with its own texts.
pub const GRACE: Duration = Duration::from_secs(2);
/// The prefix of the variables only tests set.
pub const TEST_HOOK_PREFIX: &str = "ARMADA_NODE_TEST_";

/// A command for armada-node with the environment it may see.
pub fn command(bin: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with(TEST_HOOK_PREFIX) {
            cmd.env_remove(&k);
        }
    }
    cmd
}

/// Kills a program when dropped, unless it ended.
pub struct KillGuard {
    pid: i32,
    done: Arc<AtomicBool>,
}

impl KillGuard {
    pub fn new(c: &Child) -> KillGuard {
        KillGuard {
            pid: c.id() as i32,
            done: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A flag the waiting thread sets once the program was reaped.
    pub fn done(&self) -> Arc<AtomicBool> {
        self.done.clone()
    }

    pub fn kill(&self) {
        if !self.done.load(Ordering::SeqCst) {
            // SAFETY: kill only sends a signal to the program started here.
            unsafe { libc::kill(self.pid, libc::SIGKILL) };
        }
    }
}

impl Drop for KillGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

/// The text of a failed call: armada-node failing, not an answer.
pub fn failed(what: &str) -> String {
    format!("armada-node: {what}")
}

/// Runs bin with args and stdin, returning its output; timeout is the
/// caller's deadline (None: LIMIT).
pub async fn run(
    bin: &str,
    args: &[&str],
    stdin: &Value,
    timeout: Option<Duration>,
) -> Result<Vec<u8>, String> {
    run_files(bin, args, stdin, timeout, Vec::new()).await
}

/// run, with files given to the program as descriptors 3 and up.
pub async fn run_files(
    bin: &str,
    args: &[&str],
    stdin: &Value,
    timeout: Option<Duration>,
    files: Vec<std::os::fd::OwnedFd>,
) -> Result<Vec<u8>, String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let mut cmd = command(bin, args);
    if !files.is_empty() {
        let fds: Vec<i32> = files.iter().map(|f| f.as_raw_fd()).collect();
        // SAFETY: only fcntl and dup2 between fork and exec, no
        // allocation.
        unsafe {
            cmd.pre_exec(move || {
                let mut moved = [0i32; 8];
                for (i, fd) in fds.iter().enumerate().take(moved.len()) {
                    let n = libc::fcntl(*fd, libc::F_DUPFD_CLOEXEC, 64);
                    if n < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    moved[i] = n;
                }
                for (i, n) in moved.iter().take(fds.len()).enumerate() {
                    if libc::dup2(*n, 3 + i as i32) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| failed(&e.to_string()))?;
    drop(files);
    let guard = KillGuard::new(&child);
    let done = guard.done();
    let input = format!("{stdin}");
    let task = tokio::task::spawn_blocking(move || {
        if let Some(mut w) = child.stdin.take() {
            let _ = w.write_all(input.as_bytes());
        }
        let r = child.wait_with_output();
        done.store(true, Ordering::SeqCst);
        r
    });
    let limit = timeout.map(|t| t + GRACE).unwrap_or(LIMIT).min(LIMIT);
    let out = match tokio::time::timeout(limit, task).await {
        Ok(Ok(Ok(o))) => o,
        Ok(Ok(Err(e))) => return Err(failed(&e.to_string())),
        Ok(Err(e)) => return Err(failed(&e.to_string())),
        Err(_) => {
            guard.kill();
            if timeout.is_some() {
                return Err("context deadline exceeded".into());
            }
            return Err(failed("context deadline exceeded"));
        }
    };
    if !out.status.success() {
        let mut msg = exit_text(&out.status);
        let e = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if !e.is_empty() {
            msg = format!("{msg}: {e}");
        }
        return Err(failed(&msg));
    }
    Ok(out.stdout)
}

/// exec.ExitError's text.
pub fn exit_text(s: &std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (s.code(), s.signal()) {
        (Some(c), _) => format!("exit status {c}"),
        (None, Some(sig)) => format!("signal: {}", signal_name(sig)),
        _ => "exit status unknown".into(),
    }
}

fn signal_name(sig: i32) -> String {
    match sig {
        libc::SIGKILL => "killed".into(),
        libc::SIGTERM => "terminated".into(),
        libc::SIGINT => "interrupt".into(),
        libc::SIGSEGV => "segmentation fault".into(),
        libc::SIGABRT => "aborted".into(),
        n => format!("signal {n}"),
    }
}

/// Reads an answer: its error as a plain text, or the value.
pub fn answer(b: &[u8]) -> Result<Value, String> {
    let v: Value =
        serde_json::from_slice(b).map_err(|e| failed(&format!("unreadable answer: {e}")))?;
    if let Some(e) = v.get("error").and_then(Value::as_str) {
        return Err(e.to_string());
    }
    Ok(v)
}

/// Runs a call and reads its answer (Program.Call).
pub async fn call(
    bin: &str,
    args: &[&str],
    stdin: &Value,
    timeout: Option<Duration>,
) -> Result<Value, String> {
    answer(&run(bin, args, stdin, timeout).await?)
}

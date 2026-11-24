//! Starting `runc exec` for a process in a container, as the supervisor
//! runtime's execProcess.Start does (internal/runtime/supervisor/exec.go):
//! the process spec is the container's own (its config.json) with the
//! arguments, terminal, and console size ExecApp sets, written 0600 as
//! process.json in a directory of its own, and runc runs with the same
//! arguments. This process then becomes runc (execve), so the Go agent
//! that started it, with the standard streams and controlling terminal
//! runc gets, waits for, signals, and reads runc itself as it does when it
//! starts runc: exit codes, kills, the terminal and its size changes, and
//! draining stay Go's code on the same process.
//!
//! The request comes on descriptor 3 (it holds the command's arguments,
//! so it is never on the command line), the answer goes to descriptor 4,
//! which closes on exec: `exec\n` alone is a start, `exec\n` followed by
//! `{"execErrno"}` an exec of runc that failed (Go's start error),
//! `{"redo"}` a failure Go words itself by doing the start, and
//! `{"error"}` armada-node failing. Nothing is written to the standard
//! streams, which are the caller's, and neither arguments nor the
//! environment appear in any answer.

use super::super::spec::to_go_json;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;

/// What `runtime exec` reads on descriptor 3.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ExecRequest {
    pub bundle: String,
    pub dir: String,
    pub root: String,
    pub runc: String,
    pub id: String,
    #[serde(deserialize_with = "crate::runtime::nullable")]
    pub args: Vec<String>,
    pub terminal: bool,
    #[serde(rename = "consoleSize")]
    pub console_size: Option<ConsoleBox>,
}

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

/// runc's arguments, as execProcess.Start gives them.
pub fn runc_args(r: &ExecRequest) -> Vec<String> {
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
    }
    a.push(r.id.clone());
    a
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

fn answer(to: &mut File, v: serde_json::Value) {
    let _ = to.write_all(&to_go_json(&v));
}

/// armada-node runtime exec: becomes runc, or answers why not and exits.
pub fn exec_command() -> ! {
    // A panic's message could carry what it was handling: a fixed text
    // goes to the answer, nothing to the caller's streams.
    std::panic::set_hook(Box::new(|_| {
        // SAFETY: descriptor 4 is the answer pipe; written, never closed.
        let mut f = std::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(4) });
        let _ = f.write_all(br#"{"error":"armada-node panicked"}"#);
    }));
    let mut buf = Vec::new();
    {
        // SAFETY: descriptor 3 is the request pipe the agent passed, owned
        // and closed here.
        let mut req = unsafe { File::from_raw_fd(3) };
        let _ = req.read_to_end(&mut buf);
    }
    // SAFETY: descriptor 4 is the answer pipe the agent passed.
    let mut ans = unsafe { File::from_raw_fd(4) };
    // Closed when this process becomes runc, so the agent reads the end.
    // SAFETY: F_SETFD on a descriptor this process holds.
    if unsafe { libc::fcntl(4, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        answer(
            &mut ans,
            serde_json::json!({ "error": "set close-on-exec on the answer" }),
        );
        std::process::exit(1);
    }
    let r: ExecRequest = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(_) => {
            answer(
                &mut ans,
                serde_json::json!({ "error": "unreadable request" }),
            );
            std::process::exit(1);
        }
    };
    drop(buf);
    match prepare(&r) {
        Prepared::Ready => {}
        Prepared::Redo(e) => {
            answer(&mut ans, serde_json::json!({ "redo": e }));
            std::process::exit(1);
        }
        Prepared::Error(e) => {
            answer(&mut ans, serde_json::json!({ "error": e }));
            std::process::exit(1);
        }
    }
    let _ = ans.write_all(b"exec\n");
    // The streams, the controlling terminal, the environment, and the
    // working directory are this process's, which the agent set up as for
    // runc.
    let err = std::process::Command::new(&r.runc)
        .args(runc_args(&r))
        .exec();
    let errno = err.raw_os_error().unwrap_or(libc::EINVAL);
    answer(&mut ans, serde_json::json!({ "execErrno": errno }));
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(args: &[&str], terminal: bool, size: Option<(u64, u64)>) -> ExecRequest {
        ExecRequest {
            bundle: "/b".into(),
            dir: "/run/x/exec-c1-e".into(),
            root: "/run/x/root".into(),
            runc: "/bin/runc".into(),
            id: "c1".into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            terminal,
            console_size: size.map(|(h, w)| ConsoleBox {
                height: h,
                width: w,
            }),
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
    fn runc_arguments() {
        assert_eq!(
            runc_args(&req(&["x"], true, None)),
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
        assert_eq!(runc_args(&req(&["x"], false, None)).len(), 8);
    }
}

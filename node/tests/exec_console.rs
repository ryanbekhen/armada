//! `armada-node runtime exec` with a terminal over a console socket (ADR
//! 0056): crun hands the container's own pseudo-terminal over
//! `--console-socket` (a stand-in here, in python3, which sends a
//! terminal's master over SCM_RIGHTS as crun does), and armada-node copies
//! and resizes through it. The container's terminal keeps its output
//! translation, so "\n" reaches the caller as "\r\n" (crun's own copy
//! would leave it out). Skipped without python3.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

/// A stand-in crun: logs its arguments, makes a terminal (cooked, with
/// output translation, echo off), sends its master to the console socket
/// (through /proc/self/fd for a long path, as crun does), writes its pid,
/// reads a line of input, writes lines, and exits 3. Its own stderr gets
/// a line too, as crun's errors would.
const STAND_IN: &str = r#"#!/usr/bin/python3 -I
import os, socket, sys, termios
args = sys.argv[1:]
open(os.environ["STAND_IN_LOG"], "w").write(" ".join(args))
sock = args[args.index("--console-socket") + 1]
pidfile = args[args.index("--pid-file") + 1]
master, slave = os.openpty()
attrs = termios.tcgetattr(slave)
attrs[3] &= ~termios.ECHO
termios.tcsetattr(slave, termios.TCSANOW, attrs)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
if len(sock) >= 100:
    d = os.open(os.path.dirname(sock), os.O_PATH)
    sock = "/proc/self/fd/%d/%s" % (d, os.path.basename(sock))
s.connect(sock)
socket.send_fds(s, [b"\0"], [master])
os.close(master)
s.close()
open(pidfile, "w").write(str(os.getpid()))
sys.stderr.write("runtime says hello\n")
sys.stderr.flush()
line = b""
while not line.endswith(b"\n"):
    b = os.read(slave, 100)
    if not b:
        break
    line += b
os.write(slave, b"a\nb\ngot:" + line)
os.close(slave)
sys.exit(3)
"#;

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [0; 2];
    // SAFETY: pipe2 into a local array.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: both descriptors were just made.
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

#[test]
fn a_terminal_over_the_console_socket_keeps_its_line_endings() {
    if Command::new("python3").arg("-V").output().is_err() {
        eprintln!("no python3: skipped");
        return;
    }
    let base = std::env::temp_dir().join(format!("armada-console-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    // A directory path too long for a socket address.
    let deep = base.join("x".repeat(60)).join("y".repeat(60));
    let bundle = base.join("bundle");
    fs::create_dir_all(&bundle).unwrap();
    fs::create_dir_all(&deep).unwrap();
    fs::write(
        bundle.join("config.json"),
        r#"{"process":{"user":{"uid":0,"gid":0},"cwd":"/","env":["PATH=/bin"]}}"#,
    )
    .unwrap();
    let crun = base.join("crun");
    fs::write(&crun, STAND_IN).unwrap();
    fs::set_permissions(&crun, fs::Permissions::from_mode(0o755)).unwrap();
    let log = base.join("args.log");
    let dir = deep.join("exec-c1-exec-0123456789ab");
    let req = serde_json::json!({
        "bundle": bundle, "dir": dir, "root": base.join("state/crun"),
        "runtime": crun, "id": "c1", "args": ["sh"], "terminal": true,
        "consoleSize": {"height": 24, "width": 80},
        "stdin": true, "stdout": true, "stderr": false,
        "drainGraceMs": 2000, "terminalDrainGraceMs": 2000,
        "consoleSocket": true,
    });

    let (req_r, req_w) = pipe();
    let (in_r, in_w) = pipe();
    let (out_r, out_w) = pipe();
    let (ctl, ctl_child) = UnixStream::pair().unwrap();
    let targets = [
        (req_r.as_raw_fd(), 3),
        (ctl_child.as_raw_fd(), 4),
        (in_r.as_raw_fd(), 5),
        (out_w.as_raw_fd(), 6),
    ];
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_armada-node"));
    cmd.args(["runtime", "exec"])
        .env("STAND_IN_LOG", &log)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    // SAFETY: only dup and dup2 between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            let mut moved = [0; 4];
            for (i, (src, _)) in targets.iter().enumerate() {
                moved[i] = libc::fcntl(*src, libc::F_DUPFD_CLOEXEC, 64);
            }
            for (n, (_, to)) in moved.iter().zip(targets) {
                if libc::dup2(*n, to) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    drop((req_r, in_r, out_w, ctl_child));
    fs::File::from(req_w)
        .write_all(&serde_json::to_vec(&req).unwrap())
        .unwrap();
    let mut input = fs::File::from(in_w);
    input.write_all(b"hi\n").unwrap();
    drop(input);
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = fs::File::from(out_r).read_to_end(&mut out);
        out
    });
    let mut answers = Vec::new();
    for line in BufReader::new(&ctl).lines() {
        let line = line.unwrap();
        let done = line.contains("drained");
        answers.push(line);
        if done {
            break;
        }
    }
    assert!(child.wait().unwrap().success());
    let out = String::from_utf8_lossy(&reader.join().unwrap()).into_owned();
    assert_eq!(
        answers.first().map(String::as_str),
        Some(r#"{"spawned":true}"#),
        "{answers:?}"
    );
    assert!(
        answers.iter().any(|a| a == r#"{"started":true}"#),
        "{answers:?}"
    );
    assert!(answers.iter().any(|a| a == r#"{"exit":3}"#), "{answers:?}");
    // The container's terminal translates its output: "\r\n", not "\n".
    assert!(out.contains("a\r\nb\r\ngot:hi\r\n"), "{out:?}");
    // The runtime's own output reaches the caller too.
    assert!(out.contains("runtime says hello\n"), "{out:?}");
    let args = fs::read_to_string(&log).unwrap();
    assert!(
        args.ends_with(&format!(
            "--tty --console-socket {} c1",
            dir.join("console.sock").display()
        )),
        "{args}"
    );
    // The exec's directory, the socket with it, is gone.
    assert!(!Path::new(&dir).exists());
    let _ = fs::remove_dir_all(&base);
}

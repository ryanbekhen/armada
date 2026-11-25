//! systemctl as Go's machine commands run it: from PATH, with Go's texts
//! for a failure (`systemctl ARGS: exit status N: OUTPUT`).

use std::process::{Command, Stdio};

/// What exec.Cmd's error says about a program that ended badly.
pub fn exit_text(status: std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    if let Some(code) = status.code() {
        return format!("exit status {code}");
    }
    match status.signal() {
        Some(sig) => format!("signal: {}", signal_name(sig)),
        None => "exit status -1".to_string(),
    }
}

/// syscall.Signal.String for the signals a program is killed by.
fn signal_name(sig: i32) -> String {
    match sig {
        1 => "hangup",
        2 => "interrupt",
        3 => "quit",
        6 => "aborted",
        9 => "killed",
        11 => "segmentation fault",
        13 => "broken pipe",
        15 => "terminated",
        _ => return format!("signal {sig}"),
    }
    .to_string()
}

/// exec.Command's error when the program cannot start.
pub fn start_text(program: &str, e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::NotFound && !program.contains('/') {
        return format!(
            "exec: {}: executable file not found in $PATH",
            armada_spec::go::quote(program)
        );
    }
    format!("fork/exec {program}: {}", armada_fsutil::errno_text(e))
}

/// systemctl.
pub fn systemctl(args: &[&str]) -> Result<(), String> {
    let out = Command::new("systemctl")
        .args(args)
        .stdin(Stdio::null())
        .output();
    let joined = args.join(" ");
    match out {
        Err(e) => Err(format!(
            "systemctl {joined}: {}: ",
            start_text("systemctl", &e)
        )),
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let mut text = o.stdout;
            text.extend_from_slice(&o.stderr);
            Err(format!(
                "systemctl {joined}: {}: {}",
                exit_text(o.status),
                String::from_utf8_lossy(&text).trim()
            ))
        }
    }
}

/// unitActive.
pub fn unit_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

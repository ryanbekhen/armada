//! The logger cases recorded from Go (ADR 0055, item 20): before the Go
//! code was removed, Go's TestRecordLoggerCases ran every case of compareLoggers through Go's WriteLogs and wrote
//! testdata/logwriter.json.gz (each output, its limits, the history meta
//! file it starts with, and the files WriteLogs left, times blanked).
//! `armadad runtime-log` must store the same files (TestRuntimeLogMatchesGo
//! compared them with Go's), and so must armada-log (logger/,
//! TestArmadaLogMatchesGo) when ARMADA_LOG_BIN names a build of it.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/testdata/logwriter.json.gz"
);

fn cases() -> Vec<Value> {
    let mut text = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(FIXTURE).unwrap())
        .read_to_string(&mut text)
        .unwrap();
    serde_json::from_str::<Value>(&text)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

/// A pipe's ends, both close-on-exec and numbered above 9, so the child's
/// dup2 onto 3, 4, and 5 never meets one of them.
fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [0; 2];
    // SAFETY: pipe2 fills fds with two new descriptors.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let high = |fd: i32| {
        // SAFETY: fd is open; the duplicate is owned by the caller and
        // the original closed here.
        unsafe {
            let d = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10);
            assert!(d >= 10);
            libc::close(fd);
            OwnedFd::from_raw_fd(d)
        }
    };
    (high(fds[0]), high(fds[1]))
}

/// runLogger: output on fds 3 and 4, fd 5 closed once ready.
fn run_logger(bin: &str, args: &[String], env: &[(&str, String)], stdout: &[u8], stderr: &[u8]) {
    let (out_r, out_w) = pipe();
    let (err_r, err_w) = pipe();
    let (ready_r, ready_w) = pipe();
    let fds = [out_r.as_raw_fd(), err_r.as_raw_fd(), ready_w.as_raw_fd()];
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: only dup2, which is async-signal-safe, between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            for (i, fd) in fds.iter().enumerate() {
                if libc::dup2(*fd, 3 + i as i32) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    drop((out_r, err_r, ready_w));
    let mut ready = std::fs::File::from(ready_r);
    let mut sink = Vec::new();
    ready.read_to_end(&mut sink).unwrap();
    let feed = |fd: OwnedFd, b: Vec<u8>| {
        std::thread::spawn(move || {
            let mut f = std::fs::File::from(fd);
            f.write_all(&b).unwrap();
        })
    };
    let a = feed(out_w, stdout.to_vec());
    let b = feed(err_w, stderr.to_vec());
    a.join().unwrap();
    b.join().unwrap();
    let mut logged = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut logged)
        .unwrap();
    let st = child.wait().unwrap();
    assert!(st.success(), "{bin}: {st}: {logged}");
}

/// Unix nanoseconds of an RFC 3339 time in UTC ("Z"), or None.
fn utc_nanos(s: &str) -> Option<i128> {
    let b = s.as_bytes();
    if b.len() < 20 || !s.ends_with('Z') || b[4] != b'-' || b[10] != b'T' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (
        n(0..4)?,
        n(5..7)?,
        n(8..10)?,
        n(11..13)?,
        n(14..16)?,
        n(17..19)?,
    );
    let frac = &s[19..s.len() - 1];
    let nanos: i128 = match frac.strip_prefix('.') {
        Some(f) if !f.is_empty() && f.len() <= 9 => {
            f.parse::<i128>().ok()? * 10i128.pow(9 - f.len() as u32)
        }
        None if frac.is_empty() => 0,
        _ => return None,
    };
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * ((mo + 9) % 12) + 2) / 5 + d - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    Some(i128::from(days * 86_400 + h * 3600 + mi * 60 + se) * 1_000_000_000 + nanos)
}

fn now() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i128)
}

/// logFiles: history files by their sequence (named by their position),
/// then the live files; every time recent and in UTC, then blanked.
fn log_files(dir: &Path, start: i128) -> Vec<(String, String)> {
    let list = |d: &Path, keep: &dyn Fn(&str) -> bool| -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(d)
            .map(|r| {
                r.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| keep(n))
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    };
    let mut hist = list(&dir.join("history"), &|n| n.ends_with(".log"));
    let seq = |n: &str| -> i64 {
        let base = n.strip_suffix(".log").unwrap_or(n);
        base.rsplit_once('.')
            .and_then(|(_, s)| s.parse().ok())
            .unwrap_or(0)
    };
    hist.sort_by_key(|n| seq(n));
    let live = list(dir, &|n| n.contains(".log"));
    let mut out = Vec::new();
    let paths = hist
        .iter()
        .map(|n| dir.join("history").join(n))
        .chain(live.iter().map(|n| dir.join(n)));
    for (i, p) in paths.enumerate() {
        let body = String::from_utf8(std::fs::read(&p).unwrap()).unwrap();
        let mut blanked = String::new();
        let mut rest = body.as_str();
        const T: &str = "\"time\":\"";
        while let Some(at) = rest.find(T) {
            let v = &rest[at + T.len()..];
            let end = v.find('"').unwrap();
            let t = utc_nanos(&v[..end]);
            assert!(
                t.is_some_and(|t| t >= start - 1_000_000_000 && t <= now() + 1_000_000_000),
                "{}: time {:?}",
                p.display(),
                &v[..end]
            );
            blanked.push_str(&rest[..at + T.len()]);
            rest = &v[end..];
        }
        blanked.push_str(rest);
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{}", p.display());
        let name = if i < hist.len() {
            format!("history/{i}")
        } else {
            p.file_name().unwrap().to_string_lossy().into_owned()
        };
        out.push((name, blanked));
    }
    out
}

/// A []byte field (standard base64).
fn bytes(v: &Value, k: &str) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s(v, k).trim_end_matches('=').bytes() {
        acc = (acc << 6) | T.iter().position(|&t| t == c).unwrap() as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn num(v: &Value, k: &str) -> f64 {
    v.get(k).and_then(Value::as_f64).unwrap_or(0.0)
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

/// Every case through run, compared with what WriteLogs stored.
fn replay(run: &dyn Fn(&Path, &Value)) {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("logwriter-{}", now()));
    let mut failed = Vec::new();
    for (i, c) in cases().iter().enumerate() {
        let dir = base.join(i.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(m) = c.get("meta").and_then(Value::as_object) {
            for (rel, body) in m {
                let p = dir.join(rel);
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(&p, body.as_str().unwrap()).unwrap();
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        let start = now();
        run(&dir, c);
        let got = log_files(&dir, start);
        let want: Vec<(String, String)> = c["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| (s(f, "name"), s(f, "body")))
            .collect();
        if got != want {
            eprintln!(
                "{}: files differ:\n--- Go\n{want:?}\n--- Rust\n{got:?}",
                s(c, "name")
            );
            failed.push(s(c, "name"));
        }
    }
    let _ = std::fs::remove_dir_all(&base);
    assert!(failed.is_empty(), "cases that differ: {failed:?}");
}

#[test]
fn runtime_log_stores_what_go_stored() {
    let bin = env!("CARGO_BIN_EXE_armadad");
    replay(&|dir, c| {
        let limits = format!(
            "{},{},{:.0},{:.0}",
            num(c, "maxSize") as i64,
            num(c, "maxFiles") as i64,
            num(c, "rate"),
            num(c, "burst")
        );
        run_logger(
            bin,
            &["runtime-log".to_string(), dir.display().to_string()],
            &[
                ("CONTAINER_ID", s(c, "id")),
                ("ARMADA_DAEMON_TEST_LOG_LIMITS", limits),
            ],
            &bytes(c, "stdout"),
            &bytes(c, "stderr"),
        );
    });
}

#[test]
fn armada_log_stores_what_go_stored() {
    let Ok(bin) = std::env::var("ARMADA_LOG_BIN") else {
        eprintln!("ARMADA_LOG_BIN is not set (make logger builds armada-log): skipped");
        return;
    };
    replay(&|dir, c| {
        let args: Vec<String> = [
            "runtime-log".to_string(),
            dir.display().to_string(),
            "max-size".into(),
            (num(c, "maxSize") as i64).to_string(),
            "max-files".into(),
            (num(c, "maxFiles") as i64).to_string(),
            "rate".into(),
            format!("{:.0}", num(c, "rate")),
            "burst".into(),
            format!("{:.0}", num(c, "burst")),
        ]
        .into();
        run_logger(
            &bin,
            &args,
            &[
                ("CONTAINER_ID", s(c, "id")),
                ("CONTAINER_NAMESPACE", "armada".to_string()),
            ],
            &bytes(c, "stdout"),
            &bytes(c, "stderr"),
        );
    });
}

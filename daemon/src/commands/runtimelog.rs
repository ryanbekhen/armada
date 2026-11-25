//! armadad runtime-log DIR (hidden): the logging process the shim runs for
//! a container on nodes whose pack has no armada-log (Go's
//! embedded.WriteLogs, which stays the reference): the output on fds 3
//! (stdout) and 4 (stderr) stored as JSON lines `{"log","stream","time"}`
//! as Go's encoding/json writes them, lines cut at 16 KiB, at most 1 MiB a
//! second with a burst of 4 MiB (the excess dropped and counted in one
//! line), rotated at 10 MiB over 3 files, the oldest moved into history
//! when the container has a meta file (ADR 0043). Closing fd 5 says it is
//! ready. Unlike armada-log, and as Go, a stream stops at its first write
//! error, which the command then reports.

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use armada_client::cli::{Ctx, Error, Result};

/// runtime.LogMaxSize, LogMaxFiles, LogRate, LogBurst.
const MAX_SIZE: u64 = 10 << 20;
const MAX_FILES: u32 = 3;
const RATE: f64 = (1 << 20) as f64;
const BURST: f64 = (4 << 20) as f64;
/// maxLogChunk.
const CHUNK: usize = 16 << 10;
const HISTORY_DIR: &str = "history";
const META_SUFFIX: &str = ".meta";

struct Limits {
    max_size: u64,
    max_files: u32,
    rate: f64,
    burst: f64,
}

/// The limits, or the parity tests' (ARMADA_DAEMON_TEST_LOG_LIMITS=
/// SIZE,FILES,RATE,BURST, as Go's tests call writeLogs).
fn limits() -> Limits {
    let mut l = Limits {
        max_size: MAX_SIZE,
        max_files: MAX_FILES,
        rate: RATE,
        burst: BURST,
    };
    if let Some(v) = crate::hooks::get("LOG_LIMITS") {
        let p: Vec<&str> = v.split(',').collect();
        if let [s, f, r, b] = p[..] {
            l.max_size = s.parse().unwrap_or(MAX_SIZE);
            l.max_files = f.parse().unwrap_or(MAX_FILES);
            l.rate = r.parse().unwrap_or(RATE);
            l.burst = b.parse().unwrap_or(BURST);
        }
    }
    l
}

fn path_err(op: &str, p: &Path, e: &io::Error) -> String {
    format!("{op} {}: {}", p.display(), armada_fsutil::errno_text(e))
}

/// logFile: a size-rotated file shared by a container's two streams.
struct LogFile {
    dir: PathBuf,
    id: String,
    path: PathBuf,
    file: Option<File>,
    size: u64,
    limits: Limits,
    tokens: f64,
    last: Option<Instant>,
    dropped: u64,
}

impl LogFile {
    /// openLogFile.
    fn open(dir: &Path, id: &str, limits: Limits) -> std::result::Result<LogFile, String> {
        let path = dir.join(format!("{id}.log"));
        crate::gofs::mkdir_all(dir, 0o700)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| path_err("open", &path, &e))?;
        let size = file
            .metadata()
            .map_err(|e| path_err("stat", &path, &e))?
            .len();
        Ok(LogFile {
            dir: dir.to_path_buf(),
            id: id.to_string(),
            path,
            file: Some(file),
            size,
            limits,
            tokens: 0.0,
            last: None,
            dropped: 0,
        })
    }

    fn write(&mut self, stream: &str, data: &[u8]) -> std::result::Result<(), String> {
        let now = Instant::now();
        if !self.allow(now, data.len()) {
            self.dropped += data.len() as u64;
            return Ok(());
        }
        self.flush_dropped()?;
        self.append(stream, data)
    }

    fn allow(&mut self, now: Instant, n: usize) -> bool {
        if self.limits.rate <= 0.0 {
            return true;
        }
        match self.last {
            None => self.tokens = self.limits.burst,
            Some(last) => {
                let d = now.saturating_duration_since(last).as_secs_f64();
                if d > 0.0 {
                    self.tokens = self.limits.burst.min(self.tokens + d * self.limits.rate);
                }
            }
        }
        self.last = Some(now);
        if n as f64 > self.tokens {
            return false;
        }
        self.tokens -= n as f64;
        true
    }

    fn flush_dropped(&mut self) -> std::result::Result<(), String> {
        if self.dropped == 0 {
            return Ok(());
        }
        let msg = format!(
            "[armada: dropped {} bytes of output over the log rate limit of {} bytes per second]\n",
            self.dropped, self.limits.rate as i64
        );
        self.dropped = 0;
        self.append("stderr", msg.as_bytes())
    }

    fn append(&mut self, stream: &str, data: &[u8]) -> std::result::Result<(), String> {
        let mut line = Vec::with_capacity(data.len() + 96);
        line.extend_from_slice(b"{\"log\":");
        json_string(&mut line, data);
        line.extend_from_slice(b",\"stream\":");
        json_string(&mut line, stream.as_bytes());
        line.extend_from_slice(b",\"time\":\"");
        line.extend_from_slice(rfc3339_nano(SystemTime::now()).as_bytes());
        line.extend_from_slice(b"\"}\n");
        if self.size > 0 && self.size + line.len() as u64 > self.limits.max_size {
            self.rotate()?;
        }
        let path = self.path.clone();
        let Some(f) = self.file.as_mut() else {
            return Err(format!("write {}: file already closed", path.display()));
        };
        match f.write(&line) {
            Ok(n) => {
                self.size += n as u64;
                if n < line.len() {
                    return Err(format!("write {}: short write", path.display()));
                }
                Ok(())
            }
            Err(e) => Err(path_err("write", &path, &e)),
        }
    }

    fn numbered(&self, i: u32) -> PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(format!(".{i}"));
        PathBuf::from(p)
    }

    fn rotate(&mut self) -> std::result::Result<(), String> {
        drop(self.file.take());
        if !self.id.is_empty() && self.limits.max_files > 1 {
            keep(
                &self.dir,
                &self.id,
                &self.numbered(self.limits.max_files - 1),
                0,
            )?;
        }
        for i in (1..self.limits.max_files).rev() {
            let src = if i > 1 {
                self.numbered(i - 1)
            } else {
                self.path.clone()
            };
            let dst = self.numbered(i);
            if let Err(e) = fs::rename(&src, &dst)
                && e.kind() != ErrorKind::NotFound
            {
                return Err(format!(
                    "rename {} {}: {}",
                    src.display(),
                    dst.display(),
                    armada_fsutil::errno_text(&e)
                ));
            }
        }
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.path)
            .map_err(|e| path_err("open", &self.path, &e))?;
        self.file = Some(f);
        self.size = 0;
        Ok(())
    }

    /// Close: the dropped output's line, then the file (its errors are
    /// not reported, as Go's deferred Close).
    fn close(&mut self) {
        let _ = self.flush_dropped();
        drop(self.file.take());
    }
}

/// keep: a log file moved into history, or removed when the container has
/// no meta file.
fn keep(dir: &Path, id: &str, path: &Path, seq: i64) -> std::result::Result<(), String> {
    let history = dir.join(HISTORY_DIR);
    if fs::metadata(history.join(format!("{id}{META_SUFFIX}"))).is_err() {
        return match fs::remove_file(path) {
            Err(e) if e.kind() != ErrorKind::NotFound => Err(path_err("remove", path, &e)),
            _ => Ok(()),
        };
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i64);
    let dst = history.join(format!("{id}.{}.log", nanos + seq));
    match fs::rename(path, &dst) {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(format!(
            "rename {} {}: {}",
            path.display(),
            dst.display(),
            armada_fsutil::errno_text(&e)
        )),
        _ => Ok(()),
    }
}

/// encoding/json's string: HTML characters escaped, each invalid UTF-8
/// byte replaced by U+FFFD.
fn json_string(out: &mut Vec<u8>, s: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        if b < 0x80 {
            match b {
                b'"' | b'\\' => out.extend_from_slice(&[b'\\', b]),
                0x08 => out.extend_from_slice(b"\\b"),
                0x0c => out.extend_from_slice(b"\\f"),
                b'\n' => out.extend_from_slice(b"\\n"),
                b'\r' => out.extend_from_slice(b"\\r"),
                b'\t' => out.extend_from_slice(b"\\t"),
                b'<' | b'>' | b'&' | 0x00..=0x1f => {
                    out.extend_from_slice(b"\\u00");
                    out.push(HEX[(b >> 4) as usize]);
                    out.push(HEX[(b & 0xf) as usize]);
                }
                _ => out.push(b),
            }
            i += 1;
            continue;
        }
        let n = match b {
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => 0,
        };
        let valid = n > 0 && i + n <= s.len() && std::str::from_utf8(&s[i..i + n]).is_ok();
        if !valid {
            out.extend_from_slice("\u{fffd}".as_bytes());
            i += 1;
            continue;
        }
        match &s[i..i + n] {
            [0xe2, 0x80, 0xa8] => out.extend_from_slice(b"\\u2028"),
            [0xe2, 0x80, 0xa9] => out.extend_from_slice(b"\\u2029"),
            c => out.extend_from_slice(c),
        }
        i += n;
    }
    out.push(b'"');
}

/// time.RFC3339Nano of a UTC time.
fn rfc3339_nano(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let (y, m, day) = armada_node::volbackup::gotime::civil_from_days(days);
    let mut s = format!(
        "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    );
    let nanos = d.subsec_nanos();
    if nanos != 0 {
        let frac = format!("{nanos:09}");
        s.push('.');
        s.push_str(frac.trim_end_matches('0'));
    }
    s.push('Z');
    s
}

fn lock(l: &Mutex<LogFile>) -> MutexGuard<'_, LogFile> {
    l.lock().unwrap_or_else(|p| p.into_inner())
}

/// copyStream: r written to l line by line until EOF, as
/// bufio.Reader.ReadSlice over a 16 KiB buffer; a write or read error
/// ends the stream.
fn copy_stream(
    l: &Mutex<LogFile>,
    stream: &str,
    mut r: Option<File>,
) -> std::result::Result<(), String> {
    let mut buf = vec![0u8; CHUNK];
    let (mut start, mut end) = (0, 0);
    loop {
        if let Some(p) = buf[start..end].iter().position(|&b| b == b'\n') {
            lock(l).write(stream, &buf[start..start + p + 1])?;
            start += p + 1;
            continue;
        }
        if end - start == CHUNK {
            lock(l).write(stream, &buf[start..end])?;
            (start, end) = (0, 0);
            continue;
        }
        if start > 0 {
            buf.copy_within(start..end, 0);
            (end, start) = (end - start, 0);
        }
        let read = match r.as_mut() {
            Some(f) => f.read(&mut buf[end..]),
            None => Err(io::Error::from_raw_os_error(libc::EBADF)),
        };
        match read {
            Ok(0) => {
                if end > start {
                    lock(l).write(stream, &buf[start..end])?;
                }
                return Ok(());
            }
            Ok(n) => end += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => {
                if end > start {
                    lock(l).write(stream, &buf[start..end])?;
                }
                return Err(format!("read {stream}: {}", armada_fsutil::errno_text(&e)));
            }
        }
    }
}

/// validID: ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$.
fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

/// The descriptor as a file when it is open (os.NewFile wraps any number;
/// reading a closed one fails with EBADF).
fn fd_file(fd: i32) -> Option<File> {
    // SAFETY: F_GETFD only asks whether the descriptor is open.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return None;
    }
    // SAFETY: the shim hands these descriptors to this process; nothing
    // else in it owns them.
    Some(unsafe { File::from_raw_fd(fd) })
}

pub fn run(_ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let dir = &args[0];
    if !dir.starts_with('/') || crate::gopath::clean(dir) != *dir {
        return Err(Error::Msg(format!(
            "log directory {} must be absolute and clean",
            armada_spec::go::quote(dir)
        )));
    }
    let (stdout, stderr) = (fd_file(3), fd_file(4));
    drop(fd_file(5));
    write_logs(
        Path::new(dir),
        &std::env::var("CONTAINER_ID").unwrap_or_default(),
        stdout,
        stderr,
    )
    .map_err(Error::Msg)
}

/// WriteLogs: both streams stored until they end.
fn write_logs(
    dir: &Path,
    id: &str,
    stdout: Option<File>,
    stderr: Option<File>,
) -> std::result::Result<(), String> {
    if !valid_id(id) {
        return Err(format!(
            "invalid container id {}",
            armada_spec::go::quote(id)
        ));
    }
    let l = Arc::new(Mutex::new(LogFile::open(dir, id, limits())?));
    let l2 = Arc::clone(&l);
    let errs = std::thread::spawn(move || copy_stream(&l2, "stderr", stderr));
    let out = copy_stream(&l, "stdout", stdout);
    let err = errs
        .join()
        .unwrap_or_else(|_| Err("stderr reader stopped".to_string()));
    lock(&l).close();
    let msgs: Vec<String> = [out, err].into_iter().filter_map(|r| r.err()).collect();
    if msgs.is_empty() {
        Ok(())
    } else {
        Err(msgs.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        assert!(valid_id("web-r1-0a1b2c3d"));
        assert!(!valid_id("") && !valid_id("-x") && !valid_id("a/b"));
    }

    #[test]
    fn json_like_go() {
        let j = |s: &[u8]| {
            let mut v = Vec::new();
            json_string(&mut v, s);
            String::from_utf8(v).unwrap()
        };
        assert_eq!(
            j(b"<a&b>\n\x01\xff"),
            "\"\\u003ca\\u0026b\\u003e\\n\\u0001\u{fffd}\""
        );
    }
}

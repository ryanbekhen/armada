//! `armada-log` is the logging binary armada-shim runs for every
//! Armada container (ADR 0011, ADR 0046). The shim passes the container's output on
//! fds 3 (stdout) and 4 (stderr); closing fd 5 tells it the logger is ready.
//!
//! It stores the output exactly as `armadad runtime-log`
//! (`internal/runtime/embedded/logs.go`) does, which stays the reference:
//! JSON lines `{"log","stream","time"}` encoded like Go's encoding/json,
//! lines cut at 16 KiB, a token bucket of 1 MiB/s with a 4 MiB burst whose
//! excess is dropped (never blocked) and counted in one stderr line, and
//! rotation at 10 MiB with 3 files, the oldest moved into history when the
//! container has a meta file (ADR 0043). It differs in one way: after a
//! write error it keeps reading and dropping the output, so a full disk
//! never blocks the container. A Go test compares both byte for byte.
//!
//! `armada-log search` reads the log history for a search instead
//! (src/search.rs), and `armada-log export` renders new output as the
//! requests armadad sends to the cluster's log store (src/export.rs).
//!
//! It exists because a Go process costs about 5 MiB of private memory per
//! container; this one costs well under 1 MiB.

mod export;
mod search;

use std::fmt::Write as _;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Defaults, equal to runtime.LogMaxSize, LogMaxFiles, LogRate, LogBurst.
const MAX_SIZE: u64 = 10 << 20;
const MAX_FILES: u32 = 3;
const RATE: f64 = (1 << 20) as f64;
const BURST: f64 = (4 << 20) as f64;
/// maxLogChunk: longer lines are split.
const CHUNK: usize = 16 << 10;

const HISTORY_DIR: &str = "history";
const META_SUFFIX: &str = ".meta";

struct Limits {
    max_size: u64,
    max_files: u32,
    rate: f64,
    burst: f64,
}

/// A size-rotated log file shared by a container's two streams.
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
    /// The first write error; output after it is read and dropped.
    failed: Option<io::Error>,
}

impl LogFile {
    fn open(dir: &Path, id: &str, limits: Limits) -> io::Result<LogFile> {
        DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        let path = dir.join(format!("{id}.log"));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)?;
        let size = file.metadata()?.len();
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
            failed: None,
        })
    }

    fn write(&mut self, stream: &str, data: &[u8]) {
        if self.failed.is_some() {
            return;
        }
        let now = Instant::now();
        if !self.allow(now, data.len()) {
            self.dropped += data.len() as u64;
            return;
        }
        let r = self
            .flush_dropped()
            .and_then(|()| self.append(stream, data));
        if let Err(e) = r {
            self.failed = Some(e);
        }
    }

    /// Takes n bytes from the bucket, refilled at the rate since the last call.
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

    /// Records dropped output as one line on stderr.
    fn flush_dropped(&mut self) -> io::Result<()> {
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

    /// Writes one entry, rotating first when it would not fit.
    fn append(&mut self, stream: &str, data: &[u8]) -> io::Result<()> {
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
        let f = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("log file closed"))?;
        f.write_all(&line)?;
        self.size += line.len() as u64;
        Ok(())
    }

    /// Shifts path -> path.1 -> ... and moves the oldest file into history,
    /// or drops it when the container keeps none.
    fn rotate(&mut self) -> io::Result<()> {
        drop(self.file.take());
        let numbered = |i: u32| {
            let mut p = self.path.clone().into_os_string();
            p.push(format!(".{i}"));
            PathBuf::from(p)
        };
        if self.limits.max_files > 1 {
            keep(&self.dir, &self.id, &numbered(self.limits.max_files - 1), 0)?;
        }
        for i in (1..self.limits.max_files).rev() {
            let src = if i > 1 {
                numbered(i - 1)
            } else {
                self.path.clone()
            };
            ignore_missing(fs::rename(&src, numbered(i)))?;
        }
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.path)?;
        self.file = Some(f);
        self.size = 0;
        Ok(())
    }

    fn close(&mut self) -> io::Result<()> {
        if self.failed.is_none()
            && let Err(e) = self.flush_dropped()
        {
            self.failed = Some(e);
        }
        drop(self.file.take());
        match self.failed.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// Moves a log file of container id into history, or removes it when the
/// container has no meta file (embedded.keep).
fn keep(dir: &Path, id: &str, path: &Path, seq: i64) -> io::Result<()> {
    let history = dir.join(HISTORY_DIR);
    if !history.join(format!("{id}{META_SUFFIX}")).exists() {
        return ignore_missing(fs::remove_file(path));
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i64);
    ignore_missing(fs::rename(
        path,
        history.join(format!("{id}.{}.log", nanos + seq)),
    ))
}

fn ignore_missing(r: io::Result<()>) -> io::Result<()> {
    match r {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        r => r,
    }
}

/// Appends s as a JSON string the way Go's encoding/json does (HTML
/// characters escaped, each invalid UTF-8 byte replaced by U+FFFD).
fn json_string(out: &mut Vec<u8>, s: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    let mut i = 0;
    while i < s.len() {
        // The run that needs no escape, copied at once.
        let run = json_safe(&s[i..]);
        out.extend_from_slice(&s[i..i + run]);
        i += run;
        if i == s.len() {
            break;
        }
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

/// How many bytes at the start of s json_string copies as they are: ASCII
/// from 0x20 that is not `"`, `\`, `<`, `>`, or `&`; eight bytes at a time.
fn json_safe(s: &[u8]) -> usize {
    const LO: u64 = 0x0101_0101_0101_0101;
    const HI: u64 = 0x8080_8080_8080_8080;
    let zero = |w: u64| w.wrapping_sub(LO) & !w & HI;
    let mut i = 0;
    while i + 8 <= s.len() {
        let w = u64::from_le_bytes(s[i..i + 8].try_into().unwrap());
        // The first flagged byte is exact; later ones may be false.
        let found = (w & HI)
            | (w.wrapping_sub(LO * 0x20) & !w & HI)
            | zero(w ^ (LO * b'"' as u64))
            | zero(w ^ (LO * b'\\' as u64))
            | zero(w ^ (LO * b'<' as u64))
            | zero(w ^ (LO * b'>' as u64))
            | zero(w ^ (LO * b'&' as u64));
        if found != 0 {
            return i + (found.trailing_zeros() / 8) as usize;
        }
        i += 8;
    }
    i + s[i..]
        .iter()
        .position(|&c| !(0x20..0x80).contains(&c) || matches!(c, b'"' | b'\\' | b'<' | b'>' | b'&'))
        .unwrap_or(s.len() - i)
}

/// Formats t in UTC like Go's time.RFC3339Nano (trailing zeros of the
/// fraction dropped).
fn rfc3339_nano(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let (y, m, day) = civil_from_days(days);
    let mut s = format!(
        "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    );
    let nanos = d.subsec_nanos();
    if nanos != 0 {
        let mut frac = format!("{nanos:09}");
        while frac.ends_with('0') {
            frac.pop();
        }
        let _ = write!(s, ".{frac}");
    }
    s.push('Z');
    s
}

/// Converts days since 1970-01-01 into a proleptic Gregorian date.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn lock(l: &Mutex<LogFile>) -> MutexGuard<'_, LogFile> {
    l.lock().unwrap_or_else(|p| p.into_inner())
}

/// Writes r to l line by line until EOF, like bufio.Reader.ReadSlice over a
/// 16 KiB buffer: a line longer than the buffer is written in pieces.
fn copy_stream(l: &Mutex<LogFile>, stream: &str, mut r: File) -> io::Result<()> {
    let mut buf = vec![0u8; CHUNK];
    let (mut start, mut end) = (0, 0);
    loop {
        if let Some(p) = buf[start..end].iter().position(|&b| b == b'\n') {
            lock(l).write(stream, &buf[start..start + p + 1]);
            start += p + 1;
            continue;
        }
        if end - start == CHUNK {
            lock(l).write(stream, &buf[start..end]);
            (start, end) = (0, 0);
            continue;
        }
        if start > 0 {
            buf.copy_within(start..end, 0);
            (end, start) = (end - start, 0);
        }
        match r.read(&mut buf[end..]) {
            Ok(0) => {
                if end > start {
                    lock(l).write(stream, &buf[start..end]);
                }
                return Ok(());
            }
            Ok(n) => end += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// Accepts IDs like embedded.validID: ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$.
fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

/// Accepts absolute paths that filepath.Clean leaves unchanged.
fn clean_abs(p: &str) -> bool {
    if p == "/" {
        return true;
    }
    p.starts_with('/')
        && p[1..]
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

fn parse_args(args: &[String]) -> Result<(String, Limits), String> {
    let mut dir = None;
    let mut limits = Limits {
        max_size: MAX_SIZE,
        max_files: MAX_FILES,
        rate: RATE,
        burst: BURST,
    };
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let v = it.next().ok_or_else(|| format!("{k} needs a value"))?;
        let num = || {
            v.parse::<u64>()
                .map_err(|_| format!("{k}: invalid number {v:?}"))
        };
        match k.as_str() {
            "runtime-log" => dir = Some(v.clone()),
            "max-size" => limits.max_size = num()?,
            "max-files" => {
                limits.max_files = u32::try_from(num()?).map_err(|_| "max-files too large")?
            }
            "rate" => limits.rate = num()? as f64,
            "burst" => limits.burst = num()? as f64,
            _ => return Err(format!("unknown argument {k:?}")),
        }
    }
    let dir = dir.ok_or("usage: armada-log runtime-log DIR")?;
    if !clean_abs(&dir) {
        return Err(format!("log directory {dir:?} must be absolute and clean"));
    }
    if limits.max_files == 0 {
        return Err("max-files must be at least 1".into());
    }
    Ok((dir, limits))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("search") => return search::run(&args[1..]),
        Some("export") => return export::run(&args[1..]),
        _ => {}
    }
    let (dir, limits) = parse_args(&args)?;
    let id = std::env::var("CONTAINER_ID").unwrap_or_default();
    if !valid_id(&id) {
        return Err(format!("invalid container id {id:?}"));
    }
    // SAFETY: the shim starts the logger with these three descriptors open
    // and nothing else in this process owns them.
    let (stdout, stderr, ready) = unsafe {
        (
            File::from_raw_fd(3),
            File::from_raw_fd(4),
            File::from_raw_fd(5),
        )
    };
    drop(ready);
    let l = Arc::new(Mutex::new(
        LogFile::open(Path::new(&dir), &id, limits).map_err(|e| e.to_string())?,
    ));
    let l2 = Arc::clone(&l);
    let errs = thread::Builder::new()
        .name("stderr".into())
        .stack_size(64 << 10)
        .spawn(move || copy_stream(&l2, "stderr", stderr))
        .map_err(|e| e.to_string())?;
    let out = copy_stream(&l, "stdout", stdout);
    let err = errs
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("stderr reader stopped")));
    let closed = lock(&l).close();
    let msgs: Vec<String> = [out, err, closed]
        .into_iter()
        .filter_map(Result::err)
        .map(|e| e.to_string())
        .collect();
    if msgs.is_empty() {
        Ok(())
    } else {
        Err(msgs.join("; "))
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("armada-log: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_safe_finds_every_byte() {
        for at in 0..20 {
            for b in 0..=255u8 {
                let mut v = vec![b'a'; 20];
                v[at] = b;
                let want = if !(0x20..0x80).contains(&b) || b"\"\\<>&".contains(&b) {
                    at
                } else {
                    20
                };
                assert_eq!(json_safe(&v), want, "byte {b:#x} at {at}");
            }
        }
    }
    use std::time::Duration;

    fn json(s: &[u8]) -> String {
        let mut v = Vec::new();
        json_string(&mut v, s);
        String::from_utf8(v).unwrap()
    }

    #[test]
    fn json_like_go() {
        assert_eq!(json(b"a\"b\\c"), r#""a\"b\\c""#);
        assert_eq!(
            json(b"<a&b>\n\t\r\x08\x0c\x01\x7f"),
            "\"\\u003ca\\u0026b\\u003e\\n\\t\\r\\b\\f\\u0001\x7f\""
        );
        assert_eq!(json("é€😀".as_bytes()), "\"é€😀\"");
        assert_eq!(json(b"\xe2\x82"), "\"\u{fffd}\u{fffd}\"");
        assert_eq!(json(b"\xff\xc0\x80"), "\"\u{fffd}\u{fffd}\u{fffd}\"");
        assert_eq!(json(b"\xed\xa0\x80"), "\"\u{fffd}\u{fffd}\u{fffd}\"");
        assert_eq!(
            json("\u{2028}\u{2029}\u{fffd}".as_bytes()),
            "\"\\u2028\\u2029\u{fffd}\""
        );
    }

    #[test]
    fn time_like_go() {
        let t = |s: u64, n: u32| rfc3339_nano(UNIX_EPOCH + Duration::new(s, n));
        assert_eq!(t(0, 0), "1970-01-01T00:00:00Z");
        assert_eq!(
            t(1_794_734_316, 859_693_268),
            "2026-11-15T09:18:36.859693268Z"
        );
        assert_eq!(t(951_782_400, 500_000_000), "2000-02-29T00:00:00.5Z");
        assert_eq!(t(4_102_444_799, 10), "2099-12-31T23:59:59.00000001Z");
    }

    #[test]
    fn ids_and_dirs() {
        assert!(valid_id("web-r1-0a1b2c3d") && valid_id("api.shop-r2-ff"));
        assert!(
            !valid_id("") && !valid_id("-x") && !valid_id("a/b") && !valid_id(&"a".repeat(129))
        );
        assert!(clean_abs("/") && clean_abs("/var/lib/armada/logs"));
        assert!(
            !clean_abs("logs")
                && !clean_abs("/a/")
                && !clean_abs("/a//b")
                && !clean_abs("/a/../b")
                && !clean_abs("/a/./b")
        );
    }
}

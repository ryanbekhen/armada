//! What the agent's sessions read of containers' output: a container's stored
//! output with its tail and follow, searches of the log history (ADR 0043)
//! through the pack's armada-log (`search`) or read here, the history bounded,
//! and output read for an export (ADR 0044) through armada-log (`export`) with
//! the cursors in <logs>/history/export.json, or read here as records. Files
//! and formats stay the same across releases, so an upgraded agent carries on
//! from the history and cursors of the one before.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use super::logs::{LOG_MAX_FILES, LogMeta, log_path, valid_id};
use crate::runtime::{Error, Result};
use crate::side::{LogEncoding, LogFrame, LogFrames, LogOptions, LogQuery, LogRecord, LogTail};

const HISTORY: &str = "history";
const META_SUFFIX: &str = ".meta";
/// What a tail keeps of the newest entries, whatever their number.
const MAX_TAIL_BYTES: usize = 4 << 20;
/// How often a followed log is read again.
pub const FOLLOW_INTERVAL: Duration = Duration::from_millis(200);
/// DefaultLogRetention and DefaultHistoryBytes' bounds.
pub const DEFAULT_RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);
const MAX_DEFAULT_HISTORY: i64 = 5 << 30;
const MIN_DEFAULT_HISTORY: i64 = 64 << 20;
/// What armada-log search may print.
const MAX_SEARCH_OUTPUT: u64 = 256 << 20;
const EXPORT_STATE: &str = "export.json";
/// The least a container's share of a tail is.
const MIN_TAIL_SHARE: i64 = 64 << 10;
const MAX_EXPORT_BODY: usize = 64 << 20;
const MAX_EXPORT_OUTPUT: usize = 512 << 20;

fn other(e: impl Into<String>) -> Error {
    Error::Other(e.into())
}

/// The zero time, 0001-01-01T00:00:00Z.
pub fn zero_time() -> SystemTime {
    UNIX_EPOCH - Duration::from_secs(62_135_596_800)
}

/// One line of a log file; a time that is missing is the zero time, one that
/// does not parse makes the line unreadable.
#[derive(Clone, Debug)]
pub struct Entry {
    pub log: String,
    pub stderr: bool,
    pub time: SystemTime,
}

#[derive(Deserialize)]
struct RawEntry {
    #[serde(default)]
    log: String,
    #[serde(default)]
    stream: String,
    #[serde(default)]
    time: Option<String>,
}

fn parse_entry(line: &[u8]) -> Option<Entry> {
    let r: RawEntry = serde_json::from_slice(line).ok()?;
    let time = match r.time {
        None => zero_time(),
        Some(t) => super::parse_time(&t)?,
    };
    Some(Entry {
        log: r.log,
        stderr: r.stream == "stderr",
        time,
    })
}

/// Every whole line of r, read; the bytes of the whole lines
/// (a line cut short at the end is left for later).
fn scan_entries(r: impl Read, mut f: impl FnMut(Entry)) -> std::io::Result<u64> {
    let mut br = BufReader::with_capacity(64 << 10, r);
    let mut n = 0u64;
    let mut line = Vec::new();
    loop {
        line.clear();
        let got = br.read_until(b'\n', &mut line)?;
        if got == 0 || line.last() != Some(&b'\n') {
            return Ok(n);
        }
        n += got as u64;
        if let Some(e) = parse_entry(&line) {
            f(e);
        }
    }
}

fn frame(e: Entry) -> LogFrame {
    LogFrame {
        stderr: e.stderr,
        data: e.log.into_bytes(),
        time: (e.time != zero_time()).then_some(e.time),
    }
}

fn numbered(path: &Path, i: usize) -> PathBuf {
    if i == 0 {
        path.to_path_buf()
    } else {
        PathBuf::from(format!("{}.{i}", path.display()))
    }
}

/// The container's stored output, its tail first, then (with
/// follow) what it writes from then on, until the receiver is dropped.
pub fn read_logs(dir: &Path, id: &str, opts: &LogOptions) -> Result<LogFrames> {
    let path = log_path(dir, id).map_err(other)?;
    if fs::metadata(&path).is_err() {
        return Err(Error::NotFound);
    }
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let opts = opts.clone();
    std::thread::spawn(move || {
        if let Err(e) = read_logs_into(&path, &opts, &tx) {
            let _ = tx.blocking_send(Err(other(e)));
        }
    });
    Ok(rx)
}

type FrameTx = tokio::sync::mpsc::Sender<Result<LogFrame>>;

fn read_logs_into(path: &Path, opts: &LogOptions, tx: &FrameTx) -> std::result::Result<(), String> {
    let grep = opts.grep.as_bytes();
    let matches = |e: &Entry| crate::side::logs::contains_fold(e.log.as_bytes(), grep);
    let mut entries: std::collections::VecDeque<Entry> = Default::default();
    let mut kept = 0usize;
    let mut keep = |e: Entry| {
        if opts.tail < 0 || !matches(&e) {
            return;
        }
        kept += e.log.len();
        entries.push_back(e);
        while entries.len() > 1
            && ((opts.tail > 0 && entries.len() as i64 > opts.tail) || kept > MAX_TAIL_BYTES)
        {
            if let Some(old) = entries.pop_front() {
                kept -= old.log.len();
            }
        }
    };
    for i in (1..LOG_MAX_FILES).rev() {
        let p = numbered(path, i);
        if let Ok(f) = fs::File::open(&p) {
            scan_entries(f, &mut keep).map_err(|e| super::os_err("read", &p, &e))?;
        }
    }
    let mut f = fs::File::open(path).map_err(|e| super::os_err("open", path, &e))?;
    let mut off = scan_entries(&f, &mut keep).map_err(|e| super::os_err("read", path, &e))?;
    for e in entries {
        if tx.blocking_send(Ok(frame(e))).is_err() {
            return Ok(());
        }
    }
    if !opts.follow {
        return Ok(());
    }
    loop {
        std::thread::sleep(FOLLOW_INTERVAL);
        if tx.is_closed() {
            return Ok(());
        }
        if let (Ok(cur), Ok(old)) = (fs::metadata(path), f.metadata())
            && (cur.dev(), cur.ino()) != (old.dev(), old.ino())
        {
            f = fs::File::open(path).map_err(|e| super::os_err("open", path, &e))?;
            off = 0;
        }
        f.seek(SeekFrom::Start(off))
            .map_err(|e| super::os_err("seek", path, &e))?;
        let mut gone = false;
        let n = scan_entries(&f, |e| {
            if gone || !matches(&e) {
                return;
            }
            gone = tx.blocking_send(Ok(frame(e))).is_err();
        })
        .map_err(|e| super::os_err("read", path, &e))?;
        if gone {
            return Ok(());
        }
        off += n;
    }
}

fn history(dir: &Path) -> PathBuf {
    dir.join(HISTORY)
}

/// A container's file moved into history.
#[derive(Clone, Debug)]
struct HistoryFile {
    id: String,
    seq: i64,
    path: PathBuf,
    size: i64,
    modified: SystemTime,
}

/// "<id>.<seq>.log".
fn parse_history_name(name: &str) -> Option<(String, i64)> {
    let base = name.strip_suffix(".log")?;
    let i = base.rfind('.')?;
    if i == 0 {
        return None;
    }
    let seq: i64 = armada_node::gostr::parse_int(&base.as_bytes()[i + 1..], 64).ok()?;
    valid_id(&base[..i]).then(|| (base[..i].to_string(), seq))
}

/// A history meta file with its creation time.
#[derive(Clone, Debug)]
struct Meta {
    m: LogMeta,
    created: SystemTime,
}

/// The history files, oldest first, and the meta files by
/// container.
fn read_history(
    dir: &Path,
) -> std::result::Result<(Vec<HistoryFile>, BTreeMap<String, Meta>), String> {
    let h = history(dir);
    let rd = match fs::read_dir(&h) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Vec::new(), BTreeMap::new()));
        }
        Err(e) => return Err(super::os_err("open", &h, &e)),
        Ok(r) => r,
    };
    let mut ents: Vec<_> = rd.filter_map(|e| e.ok()).collect();
    ents.sort_by_key(|e| e.file_name());
    let mut files = Vec::new();
    let mut metas = BTreeMap::new();
    for e in ents {
        if !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if let Some(id) = name.strip_suffix(META_SUFFIX)
            && valid_id(id)
        {
            if let Ok(b) = fs::read(e.path())
                && let Ok(m) = serde_json::from_slice::<LogMeta>(&b)
                && let Some(created) = super::parse_time(&m.created)
            {
                metas.insert(id.to_string(), Meta { m, created });
            }
            continue;
        }
        let Some((id, seq)) = parse_history_name(&name) else {
            continue;
        };
        let Ok(md) = e.metadata() else { continue };
        files.push(HistoryFile {
            id,
            seq,
            path: e.path(),
            size: md.len() as i64,
            modified: md.modified().unwrap_or(UNIX_EPOCH),
        });
    }
    files.sort_by_key(|f| f.seq);
    Ok((files, metas))
}

/// A tenth of the file system, within its bounds.
pub fn default_history_bytes(dir: &Path) -> i64 {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        return MIN_DEFAULT_HISTORY;
    };
    // SAFETY: an all-zero statfs is valid and statfs fills it.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path and a statfs.
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return MIN_DEFAULT_HISTORY;
    }
    let total = (st.f_blocks as i64).saturating_mul(st.f_bsize as i64);
    (total / 10).clamp(MIN_DEFAULT_HISTORY, MAX_DEFAULT_HISTORY)
}

/// History past retention goes, then the oldest past
/// max_bytes, then the meta files of removed containers with no history
/// left.
pub fn prune_logs(
    dir: &Path,
    retention: Duration,
    max_bytes: i64,
    now: SystemTime,
) -> std::result::Result<(), String> {
    let retention = if retention.is_zero() {
        DEFAULT_RETENTION
    } else {
        retention
    };
    let max_bytes = if max_bytes <= 0 {
        default_history_bytes(dir)
    } else {
        max_bytes
    };
    let (files, metas) = read_history(dir)?;
    let mut errs = Vec::new();
    let mut total: i64 = files.iter().map(|f| f.size).sum();
    let cutoff = now.checked_sub(retention).unwrap_or(UNIX_EPOCH);
    let mut left = std::collections::HashSet::new();
    for f in &files {
        if f.modified < cutoff || total > max_bytes {
            match fs::remove_file(&f.path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    errs.push(super::os_err("remove", &f.path, &e));
                    left.insert(f.id.clone());
                }
                _ => total -= f.size,
            }
            continue;
        }
        left.insert(f.id.clone());
    }
    for id in metas.keys() {
        if left.contains(id) || dir.join(format!("{id}.log")).exists() {
            continue;
        }
        let p = history(dir).join(format!("{id}{META_SUFFIX}"));
        if let Err(e) = fs::remove_file(&p)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            errs.push(super::os_err("remove", &p, &e));
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("\n"))
    }
}

fn notice_timeout() -> String {
    "the search took too long; narrow it with --since, --until, or --replica".into()
}

fn notice_budget(max_bytes: i64) -> String {
    format!(
        "searched the newest {} MiB of output on this node; narrow it with --since, --until, or --replica",
        max_bytes >> 20
    )
}

fn unix_nanos(t: SystemTime) -> i128 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    }
}

fn record(e: Entry, m: &LogMeta) -> LogRecord {
    LogRecord {
        time: e.time,
        stderr: e.stderr,
        data: e.log.into_bytes(),
        replica: m.replica.clone(),
        container: m.container.clone(),
        app: String::new(),
        revision: String::new(),
    }
}

/// A file a search reads, with whose output it is.
struct Source {
    path: PathBuf,
    meta: LogMeta,
}

/// The files a search reads: the live files of the app's containers in
/// the order of their IDs, then history, newest first.
fn sources(dir: &Path, q: &LogQuery) -> std::result::Result<Vec<Source>, String> {
    let (files, metas) = read_history(dir)?;
    let want = |id: &str| -> Option<LogMeta> {
        let m = &metas.get(id)?.m;
        if m.app != q.app || (!q.replica.is_empty() && m.replica != q.replica) {
            return None;
        }
        let ok = (q.container.is_empty() && (m.container.is_empty() || m.container == "app"))
            || m.container == q.container;
        ok.then(|| m.clone())
    };
    let mut out = Vec::new();
    for id in metas.keys() {
        let Some(m) = want(id) else { continue };
        let path = dir.join(format!("{id}.log"));
        for i in 0..LOG_MAX_FILES {
            out.push(Source {
                path: numbered(&path, i),
                meta: m.clone(),
            });
        }
    }
    for f in files.iter().rev() {
        if let Some(m) = want(&f.id) {
            out.push(Source {
                path: f.path.clone(),
                meta: m,
            });
        }
    }
    Ok(out)
}

/// The newest matching entries within the window, oldest
/// first, and a notice when the search stopped early. armada-log scans
/// the files when the pack has it and the text is ASCII; else, or when it
/// fails, they are read here.
pub async fn search_logs(
    dir: &Path,
    bin: Option<PathBuf>,
    q: &LogQuery,
    deadline: Duration,
) -> Result<(Vec<LogRecord>, String)> {
    if q.limit <= 0 {
        return Ok((Vec::new(), String::new()));
    }
    let (dir, q) = (dir.to_path_buf(), q.clone());
    let until = std::time::Instant::now() + deadline;
    tokio::task::spawn_blocking(move || {
        let srcs = sources(&dir, &q).map_err(other)?;
        if let Some(bin) = bin
            && q.grep.is_ascii()
            && let Ok(r) = search_with(&bin, &srcs, &q, deadline)
        {
            return Ok(r);
        }
        Ok(scan_search(&srcs, &q, until))
    })
    .await
    .map_err(|e| other(e.to_string()))?
}

/// Runs bin with args, input on its standard input, and returns its
/// output (at most limit bytes) once it ended.
fn run_program(
    bin: &Path,
    args: &[String],
    input: String,
    limit: u64,
) -> std::result::Result<(std::process::ExitStatus, std::io::Result<Vec<u8>>), String> {
    use std::io::Write;
    let mut child = std::process::Command::new(bin)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(input.as_bytes());
    });
    let mut b = Vec::new();
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let read = stdout.take(limit).read_to_end(&mut b).map(|_| b);
    if read.is_err() {
        let _ = child.kill();
    }
    let st = child.wait().map_err(|e| e.to_string())?;
    let _ = writer.join();
    Ok((st, read))
}

/// A search's scan of every source, without armada-log.
fn scan_search(
    srcs: &[Source],
    q: &LogQuery,
    until: std::time::Instant,
) -> (Vec<LogRecord>, String) {
    let grep = q.grep.to_lowercase();
    let limit = q.limit as usize;
    let mut out: Vec<LogRecord> = Vec::new();
    let mut read = 0i64;
    let mut notice = String::new();
    let trim = |out: &mut Vec<LogRecord>| {
        out.sort_by_key(|r| r.time);
        if out.len() > limit {
            out.drain(..out.len() - limit);
        }
    };
    for s in srcs {
        if std::time::Instant::now() >= until {
            notice = notice_timeout();
            break;
        }
        let Ok(md) = fs::metadata(&s.path) else {
            continue;
        };
        if md.modified().unwrap_or(UNIX_EPOCH) < q.since {
            continue;
        }
        if read + md.len() as i64 > q.max_bytes {
            notice = notice_budget(q.max_bytes);
            break;
        }
        let Ok(f) = fs::File::open(&s.path) else {
            continue;
        };
        let n = scan_entries(f, |e| {
            if e.time < q.since || q.until.is_some_and(|u| e.time > u) {
                return;
            }
            if !crate::side::logs::contains_fold(e.log.as_bytes(), grep.as_bytes()) {
                return;
            }
            out.push(record(e, &s.meta));
            if out.len() > 2 * limit {
                trim(&mut out);
            }
        })
        .unwrap_or(0);
        read += n as i64;
    }
    trim(&mut out);
    (out, notice)
}

/// armada-log search over the sources' paths.
fn search_with(
    bin: &Path,
    srcs: &[Source],
    q: &LogQuery,
    deadline: Duration,
) -> std::result::Result<(Vec<LogRecord>, String), String> {
    let mut args: Vec<String> = vec![
        "search".into(),
        "--limit".into(),
        q.limit.to_string(),
        "--max-bytes".into(),
        q.max_bytes.to_string(),
    ];
    if q.since > zero_time() {
        args.extend(["--since".into(), unix_nanos(q.since).to_string()]);
    }
    if let Some(u) = q.until {
        args.extend(["--until".into(), unix_nanos(u).to_string()]);
    }
    if !q.grep.is_empty() {
        args.extend(["--grep".into(), q.grep.clone()]);
    }
    args.extend(["--deadline-ms".into(), deadline.as_millis().to_string()]);
    let mut input = String::new();
    for s in srcs {
        input.push_str(&s.path.display().to_string());
        input.push('\n');
    }
    let (st, read) = run_program(bin, &args, input, MAX_SEARCH_OUTPUT)?;
    if !st.success() {
        return Err(format!("armada-log search: {}", super::exit_text(&st)));
    }
    let b = read.map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&b);
    let text = text.strip_suffix('\n').unwrap_or(&text);
    let lines: Vec<&str> = text.split('\n').collect();
    let end: Vec<&str> = lines[lines.len() - 1].split_whitespace().collect();
    if end.len() != 3 || end[0] != "end" {
        return Err("armada-log search: no end line".into());
    }
    let mut out = Vec::new();
    for line in &lines[..lines.len() - 1] {
        let bad = || format!("armada-log search: bad line {line:.40?}");
        let (idx, raw) = line.split_once(' ').ok_or_else(bad)?;
        let i: usize = idx.parse().map_err(|_| bad())?;
        let s = srcs.get(i).ok_or_else(bad)?;
        if let Some(e) = parse_entry(raw.as_bytes()) {
            out.push(record(e, &s.meta));
        }
    }
    let notice = match end[1] {
        "budget" => notice_budget(q.max_bytes),
        "timeout" => notice_timeout(),
        _ => String::new(),
    };
    Ok((out, notice))
}

/// Where a container's export stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
struct Cursor {
    ino: u64,
    off: i64,
    /// None: the zero time.
    time: Option<SystemTime>,
}

/// export.json.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ExportState {
    target: String,
    since: SystemTime,
    files: Option<BTreeMap<String, Cursor>>,
}

#[derive(Deserialize)]
struct RawCursor {
    #[serde(default)]
    ino: u64,
    #[serde(default)]
    off: i64,
    #[serde(default)]
    time: Option<String>,
}

#[derive(Deserialize)]
struct RawState {
    #[serde(default)]
    target: String,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    files: Option<BTreeMap<String, RawCursor>>,
}

fn state_path(dir: &Path) -> PathBuf {
    history(dir).join(EXPORT_STATE)
}

fn time_of(s: Option<String>) -> Option<Option<SystemTime>> {
    match s {
        None => Some(None),
        Some(t) => {
            let t = super::parse_time(&t)?;
            Some((t != zero_time()).then_some(t))
        }
    }
}

fn load_state(dir: &Path) -> Option<ExportState> {
    let b = fs::read(state_path(dir)).ok()?;
    let r: RawState = serde_json::from_slice(&b).ok()?;
    let mut files = None;
    if let Some(fs) = r.files {
        let mut m = BTreeMap::new();
        for (k, c) in fs {
            m.insert(
                k,
                Cursor {
                    ino: c.ino,
                    off: c.off,
                    time: time_of(c.time)?,
                },
            );
        }
        files = Some(m);
    }
    Some(ExportState {
        target: r.target,
        since: time_of(r.since)?.unwrap_or_else(zero_time),
        files,
    })
}

fn go_time(t: SystemTime) -> String {
    crate::clock::rfc3339_nano(t)
}

/// export.json's bytes: target, since, then files, with each cursor's
/// zero fields left out.
fn state_json(st: &ExportState) -> Vec<u8> {
    let mut files = serde_json::Map::new();
    for (k, c) in st.files.iter().flatten() {
        let mut o = serde_json::Map::new();
        if c.ino != 0 {
            o.insert("ino".into(), c.ino.into());
        }
        if c.off != 0 {
            o.insert("off".into(), c.off.into());
        }
        if let Some(t) = c.time {
            o.insert("time".into(), go_time(t).into());
        }
        files.insert(k.clone(), serde_json::Value::Object(o));
    }
    let files = if st.files.is_some() {
        serde_json::Value::Object(files)
    } else {
        serde_json::Value::Null
    };
    // Map keys sorted; a cursor's fields as ino, off, time; the outer
    // object as target, since, files.
    format!(
        "{{\"target\":{},\"since\":{},\"files\":{}}}",
        serde_json::to_string(&st.target).unwrap_or_default(),
        serde_json::to_string(&go_time(st.since)).unwrap_or_default(),
        serde_json::to_string(&files).unwrap_or_default()
    )
    .into_bytes()
}

fn save_state(dir: &Path, st: &ExportState) -> std::result::Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let h = history(dir);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&h)
        .map_err(|e| super::os_err("mkdir", &h, &e))?;
    let p = state_path(dir);
    let tmp = PathBuf::from(format!("{}.tmp", p.display()));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| super::os_err("open", &tmp, &e))?;
    std::io::Write::write_all(&mut f, &state_json(st))
        .map_err(|e| super::os_err("write", &tmp, &e))?;
    fs::rename(&tmp, &p).map_err(|e| {
        format!(
            "rename {} {}: {}",
            tmp.display(),
            p.display(),
            super::errno(&e)
        )
    })
}

/// A file of a container's output.
#[derive(Clone, Debug)]
struct TailFile {
    path: PathBuf,
    ino: u64,
    size: i64,
}

fn stat_tail(p: &Path) -> Option<TailFile> {
    let md = fs::metadata(p).ok()?;
    md.is_file().then(|| TailFile {
        path: p.to_path_buf(),
        ino: md.ino(),
        size: md.len() as i64,
    })
}

/// Its history files, oldest first, then its rotated
/// files and its current one.
fn container_files(dir: &Path, id: &str, hist: &[HistoryFile]) -> Vec<TailFile> {
    let mut out: Vec<TailFile> = hist.iter().filter_map(|h| stat_tail(&h.path)).collect();
    let path = dir.join(format!("{id}.log"));
    for i in (0..LOG_MAX_FILES).rev() {
        if let Some(f) = stat_tail(&numbered(&path, i)) {
            out.push(f);
        }
    }
    out
}

/// A container's part of a tail.
#[derive(Clone, Debug)]
struct Job {
    id: String,
    meta: LogMeta,
    cursor: Cursor,
    files: Vec<TailFile>,
    start: usize,
    off: i64,
    by_time: bool,
}

/// Output written since the last committed tail for target,
/// at most about max_bytes, shared between containers; rendered by
/// armada-log as enc's requests when both are given, else records. The
/// commit writes the cursors (only when they moved).
pub async fn tail_logs(
    dir: &Path,
    bin: Option<PathBuf>,
    target: &str,
    max_bytes: i64,
    now: SystemTime,
    enc: Option<&LogEncoding>,
) -> Result<LogTail> {
    let (dir2, target2, enc) = (dir.to_path_buf(), target.to_string(), enc.cloned());
    let (mut tail, prev, next) = tokio::task::spawn_blocking(
        move || -> std::result::Result<(LogTail, ExportState, ExportState), String> {
            let (prev, mut next, jobs, share) = plan_tail(&dir2, &target2, max_bytes, now)?;
            let mut tail = LogTail::default();
            let moved = match (bin, enc) {
                (Some(bin), Some(enc)) => export_with(&bin, &jobs, share, max_bytes, now, &enc)
                    .ok()
                    .map(|(bodies, size, moved)| {
                        tail.bodies = Some(bodies);
                        tail.size = size;
                        moved
                    }),
                _ => None,
            };
            let moved = moved.unwrap_or_else(|| {
                let (recs, moved) = read_tails(&jobs, share, max_bytes);
                tail.records = recs;
                moved
            });
            if let Some(f) = next.files.as_mut() {
                f.extend(moved);
            }
            Ok((tail, prev, next))
        },
    )
    .await
    .map_err(|e| other(e.to_string()))?
    .map_err(other)?;
    let dir = dir.to_path_buf();
    tail.commit = Some(Box::new(move || {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                if prev == next && state_path(&dir).exists() {
                    return Ok(()); // nothing moved: no write every round
                }
                save_state(&dir, &next).map_err(other)
            })
            .await
            .map_err(|e| other(e.to_string()))?
        })
    }));
    Ok(tail)
}

type Plan = (ExportState, ExportState, Vec<Job>, i64);

fn plan_tail(
    dir: &Path,
    target: &str,
    max_bytes: i64,
    now: SystemTime,
) -> std::result::Result<Plan, String> {
    let prev = match load_state(dir) {
        Some(p) if p.target == target && p.files.is_some() => p,
        _ => ExportState {
            target: target.into(),
            since: now,
            files: Some(BTreeMap::new()),
        },
    };
    let (files, metas) = read_history(dir)?;
    let mut hist: HashMap<String, Vec<HistoryFile>> = HashMap::new();
    for f in files {
        hist.entry(f.id.clone()).or_default().push(f);
    }
    let mut next = ExportState {
        target: target.into(),
        since: prev.since,
        files: Some(BTreeMap::new()),
    };
    let mut jobs = Vec::new();
    let prev_files = prev.files.clone().unwrap_or_default();
    let next_files = next.files.as_mut().expect("set above");
    for (id, m) in &metas {
        let known = prev_files.get(id).copied();
        let tf = container_files(dir, id, hist.get(id).map_or(&[][..], |v| v));
        if known.is_none() && m.created < prev.since {
            let mut c = Cursor {
                time: Some(now),
                ..Default::default()
            };
            if let Some(last) = tf.last() {
                c.ino = last.ino;
                c.off = last.size;
            }
            next_files.insert(id.clone(), c);
            continue;
        }
        let c = known.unwrap_or_default();
        next_files.insert(id.clone(), c);
        let mut j = Job {
            id: id.clone(),
            meta: m.m.clone(),
            cursor: c,
            files: tf,
            start: 0,
            off: c.off,
            by_time: false,
        };
        if c.ino != 0 {
            match j.files.iter().position(|f| f.ino == c.ino) {
                Some(i) => j.start = i,
                None => {
                    j.start = 0;
                    j.off = 0;
                    j.by_time = true;
                }
            }
        } else {
            j.off = 0;
            j.by_time = c.time.is_some();
        }
        jobs.push(j);
    }
    let share = (max_bytes / metas.len().max(1) as i64).max(MIN_TAIL_SHARE);
    Ok((prev, next, jobs, share))
}

/// Each job's output from its cursor, within its share and
/// the budget, as records; the cursors moved.
fn read_tails(
    jobs: &[Job],
    share: i64,
    mut budget: i64,
) -> (Vec<LogRecord>, BTreeMap<String, Cursor>) {
    let mut recs = Vec::new();
    let mut moved = BTreeMap::new();
    for job in jobs {
        if budget <= 0 {
            break;
        }
        let (mut c, m, tf) = (job.cursor, &job.meta, &job.files);
        let mut take = share.min(budget);
        let mut j = job.start;
        while j < tf.len() && take > 0 {
            let mut o = if j == job.start { job.off } else { 0 };
            if o > tf[j].size {
                o = 0; // the file was replaced
            }
            let limit = take;
            let res = tail_read(&tf[j].path, o, limit, |e| {
                if job.by_time && c.time.is_some_and(|t| e.time <= t) {
                    return;
                }
                c.time = (e.time != zero_time()).then_some(e.time);
                recs.push(LogRecord {
                    time: e.time,
                    stderr: e.stderr,
                    data: e.log.into_bytes(),
                    app: m.app.clone(),
                    revision: m.revision.clone(),
                    replica: m.replica.clone(),
                    container: m.container.clone(),
                });
            });
            let Ok(n) = res else { break };
            c.ino = tf[j].ino;
            c.off = o + n;
            take -= n;
            budget -= n;
            if tf[j].size - o > limit {
                break; // the budget ended within this file
            }
            j += 1;
        }
        moved.insert(job.id.clone(), c);
    }
    (recs, moved)
}

fn tail_read(p: &Path, off: i64, limit: i64, f: impl FnMut(Entry)) -> std::io::Result<i64> {
    let mut file = fs::File::open(p)?;
    file.seek(SeekFrom::Start(off.max(0) as u64))?;
    Ok(scan_entries(file.take(limit.max(0) as u64), f)? as i64)
}

/// Fields joined by tabs; None when one holds a tab or a line
/// break.
fn plan_line(b: &mut String, fields: &[&str]) -> bool {
    if fields.iter().any(|f| f.contains(['\t', '\n'])) {
        return false;
    }
    b.push_str(&fields.join("\t"));
    b.push('\n');
    true
}

fn unix_text(t: SystemTime) -> String {
    let n = unix_nanos(t);
    format!(
        "{}.{}",
        n.div_euclid(1_000_000_000),
        n.rem_euclid(1_000_000_000)
    )
}

type Exported = (Vec<Vec<u8>>, i64, BTreeMap<String, Cursor>);

/// armada-log export renders the jobs' output as requests.
fn export_with(
    bin: &Path,
    jobs: &[Job],
    share: i64,
    budget: i64,
    now: SystemTime,
    enc: &LogEncoding,
) -> std::result::Result<Exported, String> {
    let mut input = String::new();
    for j in jobs {
        let (space, name, send) = match armada_spec::validate::split_app_id(&j.meta.app) {
            Some((s, n)) => (s, n, "1"),
            None => (String::new(), String::new(), "0"),
        };
        let container = if j.meta.container.is_empty() {
            "app"
        } else {
            &j.meta.container
        };
        let after = if j.by_time {
            unix_text(j.cursor.time.unwrap_or_else(zero_time))
        } else {
            "-".into()
        };
        if !plan_line(
            &mut input,
            &[
                "c",
                send,
                &space,
                &name,
                &j.meta.replica,
                &j.meta.revision,
                container,
                &after,
            ],
        ) {
            return Err("armada-log export: a name holds a tab or line break".into());
        }
        for (k, f) in j.files[j.start..].iter().enumerate() {
            let off = if k == 0 { j.off } else { 0 };
            if !plan_line(
                &mut input,
                &[
                    "f",
                    &off.to_string(),
                    &f.size.to_string(),
                    &f.path.display().to_string(),
                ],
            ) {
                return Err("armada-log export: a path holds a tab or line break".into());
            }
        }
    }
    let args: Vec<String> = [
        "export",
        "--format",
        &enc.format,
        "--node",
        &enc.node,
        "--now",
        &unix_nanos(now).to_string(),
        "--batch-records",
        &enc.batch_records.to_string(),
        "--batch-bytes",
        &enc.batch_bytes.to_string(),
        "--budget",
        &budget.to_string(),
        "--share",
        &share.to_string(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let (st, read) = run_program(bin, &args, input, (MAX_EXPORT_OUTPUT + (16 << 20)) as u64)?;
    let res = read
        .map_err(|e| format!("armada-log export: {e}"))
        .and_then(|b| read_export(&mut std::io::Cursor::new(b), jobs));
    if !st.success() {
        return Err(format!("armada-log export: {}", super::exit_text(&st)));
    }
    res
}

fn read_export(r: &mut impl BufRead, jobs: &[Job]) -> std::result::Result<Exported, String> {
    let mut bodies = Vec::new();
    let mut total = 0usize;
    let mut moved: BTreeMap<String, Cursor> = BTreeMap::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = r
            .read_until(b'\n', &mut line)
            .map_err(|e| format!("armada-log export: {e}"))?;
        if n == 0 || line.last() != Some(&b'\n') {
            return Err("armada-log export: EOF".into());
        }
        let text = String::from_utf8_lossy(&line).into_owned();
        let f: Vec<&str> = text.split_whitespace().collect();
        let bad = || format!("armada-log export: bad line {text:.40?}");
        match f.as_slice() {
            ["body", n] => {
                let n: usize = n.parse().map_err(|_| bad())?;
                if n == 0 || n > MAX_EXPORT_BODY || total + n > MAX_EXPORT_OUTPUT {
                    return Err(bad());
                }
                let mut b = vec![0u8; n];
                r.read_exact(&mut b)
                    .map_err(|e| format!("armada-log export: {e}"))?;
                bodies.push(b);
                total += n;
            }
            ["cursor", i, k, off, t] => {
                let i: usize = i.parse().map_err(|_| bad())?;
                let j = jobs.get(i).ok_or_else(bad)?;
                let mut c = moved.get(&j.id).copied().unwrap_or(j.cursor);
                if *k != "-" {
                    let k: usize = k.parse().map_err(|_| bad())?;
                    let off: i64 = off.parse().map_err(|_| bad())?;
                    if j.start + k >= j.files.len() || off < 0 {
                        return Err(bad());
                    }
                    c.ino = j.files[j.start + k].ino;
                    c.off = off;
                }
                if *t != "-" {
                    let (s, ns) = t.split_once('.').ok_or_else(bad)?;
                    let s: i64 = s.parse().map_err(|_| bad())?;
                    let ns: i64 = ns.parse().map_err(|_| bad())?;
                    if !(0..1_000_000_000).contains(&ns) {
                        return Err(bad());
                    }
                    let t = if s >= 0 {
                        UNIX_EPOCH + Duration::new(s as u64, ns as u32)
                    } else {
                        UNIX_EPOCH - Duration::from_secs((-s) as u64)
                            + Duration::from_nanos(ns as u64)
                    };
                    c.time = (t != zero_time()).then_some(t);
                }
                moved.insert(j.id.clone(), c);
            }
            ["end", size] => {
                let size: i64 = size.parse().map_err(|_| bad())?;
                if size < 0 {
                    return Err(bad());
                }
                return Ok((bodies, size, moved));
            }
            _ => return Err(bad()),
        }
    }
}

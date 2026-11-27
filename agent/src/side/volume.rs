//! Volume sessions (ADR 0023, ADR 0041): the control plane offers a
//! VolumeRequest on the Connect stream, and the agent opens AgentService's
//! VolumeSession to back a volume up as a gzipped tar, restore one, remove
//! it, or back it up to, list, and restore it from its bucket, with the
//! app paused under the reconcile lock. Volumes are measured for usage
//! reports.
//!
//! The work on the volume's files is [`Volumes`]; [`NodeVolumes`] runs the
//! runtime pack's armada-node `volume archive|restore|size|snapshot|prune|
//! snapshots|restore-snapshot` (the archive on standard streams, answers on
//! descriptors 3 and 4, backup requests on stdin).

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use armada_proto::armada::v1 as pb;
use pb::volume_request::Op;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::nodeprog::{self, KillGuard};
use super::{Inbound, ts};
use crate::agent::{Inner, lock};
use crate::proxy::BoxFut;
use crate::runtime::{LABEL_APP, LABEL_MANAGED, Runtime, stopped};

/// The most archive data one VolumeData message carries.
pub const VOLUME_CHUNK: usize = 64 << 10;
/// The backups, restores, and removals an agent runs at once.
pub const MAX_VOLUME_SESSIONS: i32 = 2;
/// How often the agent measures its volumes.
pub const VOLUME_MEASURE_EVERY: Duration = Duration::from_secs(60);
/// How much of an answer is read: an error quoting a long entry name.
const VOLUME_ANSWER_LIMIT: u64 = 4 << 20;
/// Why a container stopped for a volume operation is started again.
const RESUMED: &str = "stopped for a volume backup or restore";

/// A snapshot in a volume's bucket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub id: String,
    pub time: SystemTime,
    pub files: i64,
    pub bytes: i64,
    pub node: String,
}

/// What a backup uploaded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackupStats {
    pub new_bytes: i64,
    pub uploaded: i64,
}

/// What a prune left.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub snapshots: i64,
    pub stored: i64,
    pub deleted_snapshots: i64,
    pub deleted_chunks: i64,
}

/// The keep policy of a prune.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Keep {
    pub last: i64,
    pub hourly: i64,
    pub daily: i64,
    pub weekly: i64,
    pub monthly: i64,
}

/// What a backup call reads. Its Debug leaves the
/// URL and the key out.
#[derive(Clone, Default, serde::Serialize)]
pub struct SnapshotRequest {
    pub url: String,
    /// Base64 in JSON, null when empty.
    #[serde(serialize_with = "b64")]
    pub key: Vec<u8>,
    pub app: String,
    pub volume: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub dir: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub node: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub now: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep: Option<Keep>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub zone: Vec<[i64; 2]>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub snapshot: String,
}

impl std::fmt::Debug for SnapshotRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "volume {} of {}", self.volume, self.app)
    }
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

fn b64<S: serde::Serializer>(k: &[u8], s: S) -> Result<S::Ok, S::Error> {
    if k.is_empty() {
        // An empty key is written as null.
        return s.serialize_none();
    }
    s.serialize_str(&armada_node::http::base64(k))
}

/// Pauses the app; the caller resumes it.
pub type PauseFn = Box<dyn FnOnce() -> BoxFut<'static, Result<(), String>> + Send>;

/// The work on a volume's files and its bucket.
pub trait Volumes: Send + Sync {
    /// Writes dir as a gzipped tar to out.
    fn archive<'a>(
        &'a self,
        dir: &'a str,
        out: mpsc::Sender<Vec<u8>>,
    ) -> BoxFut<'a, Result<(), String>>;
    /// Replaces dir's contents with the gzipped tar read from input; an
    /// Err item is the session's failure, which the restore fails with.
    fn restore<'a>(
        &'a self,
        dir: &'a str,
        input: mpsc::Receiver<Result<Vec<u8>, String>>,
    ) -> BoxFut<'a, Result<(), String>>;
    /// The regular files of each dir added up.
    fn sizes(&self, dirs: Vec<String>) -> BoxFut<'_, Result<Vec<i64>, String>>;
    /// Backs dir up to its bucket.
    fn snapshot(&self, req: SnapshotRequest)
    -> BoxFut<'_, Result<(Snapshot, BackupStats), String>>;
    /// Removes the snapshots the keep policy drops; the usage even when it
    /// failed.
    fn prune(&self, req: SnapshotRequest) -> BoxFut<'_, (Usage, Result<(), String>)>;
    /// The bucket's snapshots.
    fn snapshots(&self, req: SnapshotRequest) -> BoxFut<'_, Result<Vec<Snapshot>, String>>;
    /// Restores snapshot req.snapshot ("latest" resolved) into dir, calling
    /// pause once the snapshot was found and before the volume is touched.
    fn restore_snapshot(
        &self,
        req: SnapshotRequest,
        pause: PauseFn,
    ) -> BoxFut<'_, Result<Snapshot, String>>;
}

/// Volumes through armada-node.
pub struct NodeVolumes {
    pub bin: String,
}

/// Moves fd above the standard descriptors, close-on-exec; the original
/// is closed.
fn high(fd: OwnedFd) -> std::io::Result<OwnedFd> {
    // SAFETY: duplicating a descriptor this process owns.
    let n = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: n is a new descriptor owned from here on.
    Ok(unsafe { OwnedFd::from_raw_fd(n) })
}

/// A close-on-exec pipe: (read, write).
fn pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 fills two descriptors.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both are new descriptors owned from here on.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Hands fds to the program as descriptors 3, 4, ...
fn extra_files(cmd: &mut std::process::Command, fds: Vec<RawFd>) {
    // SAFETY: only dup2 runs between fork and exec.
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
}

/// "armada-node: WHAT: exit: stderr", valid UTF-8.
fn program_failed(what: &str, status: Option<std::process::ExitStatus>, stderr: &[u8]) -> String {
    let mut msg = what.to_string();
    if let Some(s) = status.filter(|s| !s.success()) {
        msg.push_str(": ");
        msg.push_str(&nodeprog::exit_text(&s));
    }
    let e = String::from_utf8_lossy(stderr).trim().to_string();
    if !e.is_empty() {
        msg.push_str(": ");
        msg.push_str(&e);
    }
    nodeprog::failed(&msg)
}

fn read_all(mut r: impl Read) -> Vec<u8> {
    let mut b = Vec::new();
    let _ = r.by_ref().take(VOLUME_ANSWER_LIMIT).read_to_end(&mut b);
    let _ = std::io::copy(&mut r, &mut std::io::sink());
    b
}

fn stderr_thread(c: &mut Child) -> std::thread::JoinHandle<Vec<u8>> {
    let e = c.stderr.take();
    std::thread::spawn(move || e.map(read_all).unwrap_or_default())
}

/// An answer's error, if it has one.
fn answered(b: &[u8]) -> Option<Result<Value, String>> {
    let v: Value = serde_json::from_slice(b).ok()?;
    if let Some(e) = v.get("error").and_then(Value::as_str) {
        return Some(Err(e.to_string()));
    }
    Some(Ok(v))
}

fn snapshot_of(v: &Value) -> Result<Snapshot, String> {
    let t = v["time"].as_str().unwrap_or("");
    let t = armada_proto::google::protobuf::Timestamp::parse_rfc3339(t)
        .map_err(|_| nodeprog::failed("unreadable time in the answer"))?;
    Ok(Snapshot {
        id: v["id"].as_str().unwrap_or("").to_string(),
        time: super::from_ts(Some(&t)),
        files: v["files"].as_i64().unwrap_or(0),
        bytes: v["bytes"].as_i64().unwrap_or(0),
        node: v["node"].as_str().unwrap_or("").to_string(),
    })
}

fn archive_blocking(bin: &str, dir: &str, out: &mpsc::Sender<Vec<u8>>) -> Result<(), String> {
    let (ar, aw) = pipe().map_err(|e| nodeprog::failed(&e.to_string()))?;
    let aw = high(aw).map_err(|e| nodeprog::failed(&e.to_string()))?;
    let mut cmd = nodeprog::command(bin, &["volume", "archive", dir]);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    extra_files(&mut cmd, vec![aw.as_raw_fd()]);
    let mut c = cmd.spawn().map_err(|e| nodeprog::failed(&e.to_string()))?;
    drop(aw);
    let guard = KillGuard::new(&c);
    let errs = stderr_thread(&mut c);
    let answer = std::thread::spawn(move || read_all(std::fs::File::from(ar)));
    let mut stdout = c.stdout.take().expect("piped");
    let mut buf = vec![0u8; VOLUME_CHUNK];
    let mut write_err = None;
    loop {
        let n = match stdout.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if write_err.is_none() && out.blocking_send(buf[..n].to_vec()).is_err() {
            write_err = Some("the session ended".to_string());
            guard.kill();
        }
    }
    let status = c.wait().ok();
    guard.done().store(true, Ordering::SeqCst);
    let b = answer.join().unwrap_or_default();
    let stderr = errs.join().unwrap_or_default();
    if let Some(e) = write_err {
        return Err(format!("archive volume: {e}"));
    }
    match answered(&b) {
        None => Err(format!(
            "archive volume: {}",
            program_failed("no answer", status, &stderr)
        )),
        Some(Err(e)) => Err(e),
        Some(Ok(_)) => Ok(()),
    }
}

fn restore_blocking(
    bin: &str,
    dir: &str,
    mut input: mpsc::Receiver<Result<Vec<u8>, String>>,
) -> Result<(), String> {
    let p = |e: std::io::Error| nodeprog::failed(&e.to_string());
    let (ar, aw) = pipe().map_err(p)?;
    let (br, bw) = pipe().map_err(p)?;
    let (aw, br) = (high(aw).map_err(p)?, high(br).map_err(p)?);
    // Not killed with the caller: the restore ends when its input does,
    // removing what it wrote, and the session's end is such an error.
    let mut cmd = nodeprog::command(bin, &["volume", "restore", dir]);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    extra_files(&mut cmd, vec![aw.as_raw_fd(), br.as_raw_fd()]);
    let mut c = cmd.spawn().map_err(|e| nodeprog::failed(&e.to_string()))?;
    drop((aw, br));
    let errs = stderr_thread(&mut c);
    let mut stdin = c.stdin.take().expect("piped");
    let mut ans = BufReader::new(std::fs::File::from(ar));
    let mut line = String::new();
    let _ = ans.read_line(&mut line);
    if line != "ready\n" {
        let _ = c.kill();
        drop(stdin);
        let status = c.wait().ok();
        let stderr = errs.join().unwrap_or_default();
        return Err(program_failed("not ready", status, &stderr));
    }
    let answer = std::thread::spawn(move || read_all(ans));
    let mut read_err = None;
    while let Some(m) = input.blocking_recv() {
        match m {
            Ok(b) => {
                if stdin.write_all(&b).is_err() {
                    break; // it stopped reading: its answer says why
                }
            }
            Err(e) => {
                read_err = Some(e);
                break;
            }
        }
    }
    let mut bw = std::fs::File::from(bw);
    if let Some(e) = read_err {
        let _ = bw.write_all(super::logexport::json_string(&e).as_bytes());
    }
    // Descriptor 4 first: armada-node reads it once stdin ends.
    drop(bw);
    drop(stdin);
    let status = c.wait().ok();
    let b = answer.join().unwrap_or_default();
    let stderr = errs.join().unwrap_or_default();
    match answered(&b) {
        None => Err(program_failed("no answer", status, &stderr)),
        Some(Err(e)) => Err(e),
        Some(Ok(_)) => Ok(()),
    }
}

/// One armada-node volume backup call.
struct Call {
    child: Child,
    guard: KillGuard,
    stdin: Option<ChildStdin>,
    out: BufReader<ChildStdout>,
    errs: Option<std::thread::JoinHandle<Vec<u8>>>,
    done: bool,
}

enum Line {
    Ready,
    Answer(Vec<u8>),
}

impl Call {
    fn start(bin: &str, op: &str, req: &SnapshotRequest) -> Result<Call, String> {
        let mut cmd = nodeprog::command(bin, &["volume", op]);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| nodeprog::failed(&e.to_string()))?;
        let guard = KillGuard::new(&child);
        let errs = stderr_thread(&mut child);
        let stdin = child.stdin.take();
        let out = BufReader::with_capacity(64 << 10, child.stdout.take().expect("piped"));
        let mut c = Call {
            child,
            guard,
            stdin,
            out,
            errs: Some(errs),
            done: false,
        };
        let line = serde_json::to_string(req).map_err(|e| nodeprog::failed(&e.to_string()))?;
        let w = c
            .stdin
            .as_mut()
            .map(|s| s.write_all(format!("{line}\n").as_bytes()));
        if !matches!(w, Some(Ok(()))) {
            let _ = c.finish();
            return Err(nodeprog::failed("broken pipe"));
        }
        Ok(c)
    }

    /// The next line up to an answer or "ready ID"; "touched" lines
    /// skipped.
    fn next(&mut self) -> Result<Line, String> {
        loop {
            let mut line = String::new();
            let n = self.out.read_line(&mut line).unwrap_or(0);
            let full = line.ends_with('\n');
            let l = line.trim_end_matches('\n');
            if n > 0 && l == "touched" {
                continue;
            }
            if full && l.starts_with("ready ") {
                return Ok(Line::Ready);
            }
            if full && l.starts_with('{') {
                return Ok(Line::Answer(l.as_bytes().to_vec()));
            }
            let (status, stderr) = self.finish();
            return Err(program_failed("no answer", status, &stderr));
        }
    }

    fn finish(&mut self) -> (Option<std::process::ExitStatus>, Vec<u8>) {
        if self.done {
            return (None, Vec::new());
        }
        self.done = true;
        self.stdin = None;
        let _ = std::io::copy(&mut self.out, &mut std::io::sink());
        let status = self.child.wait().ok();
        self.guard.done().store(true, Ordering::SeqCst);
        let stderr = self
            .errs
            .take()
            .and_then(|h| h.join().ok())
            .unwrap_or_default();
        (status, stderr)
    }

    /// A call with no handshake: its answer.
    fn answer(mut self) -> Result<Value, String> {
        let r = self.next();
        self.finish();
        match r? {
            Line::Answer(b) => match answered(&b) {
                Some(r) => r,
                None => Err(nodeprog::failed("unreadable answer")),
            },
            Line::Ready => Err(nodeprog::failed("an answer before ready")),
        }
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| nodeprog::failed(&e.to_string()))
}

impl Volumes for NodeVolumes {
    fn archive<'a>(
        &'a self,
        dir: &'a str,
        out: mpsc::Sender<Vec<u8>>,
    ) -> BoxFut<'a, Result<(), String>> {
        let (bin, dir) = (self.bin.clone(), dir.to_string());
        Box::pin(async move { blocking(move || archive_blocking(&bin, &dir, &out)).await? })
    }

    fn restore<'a>(
        &'a self,
        dir: &'a str,
        input: mpsc::Receiver<Result<Vec<u8>, String>>,
    ) -> BoxFut<'a, Result<(), String>> {
        let (bin, dir) = (self.bin.clone(), dir.to_string());
        Box::pin(async move { blocking(move || restore_blocking(&bin, &dir, input)).await? })
    }

    fn sizes(&self, dirs: Vec<String>) -> BoxFut<'_, Result<Vec<i64>, String>> {
        Box::pin(async move {
            let mut args = vec!["volume", "size"];
            args.extend(dirs.iter().map(String::as_str));
            let out = nodeprog::run(&self.bin, &args, &Value::Null, None)
                .await
                .map_err(|e| e.replacen("armada-node: ", "armada-node: size: ", 1))?;
            let v: Value =
                serde_json::from_slice(&out).map_err(|_| nodeprog::failed("unreadable answer"))?;
            let sizes: Vec<i64> = v["sizes"]
                .as_array()
                .map(|a| a.iter().map(|n| n.as_i64().unwrap_or(0)).collect())
                .unwrap_or_default();
            if sizes.len() != dirs.len() {
                return Err(nodeprog::failed("unreadable answer"));
            }
            Ok(sizes)
        })
    }

    fn snapshot(
        &self,
        req: SnapshotRequest,
    ) -> BoxFut<'_, Result<(Snapshot, BackupStats), String>> {
        let bin = self.bin.clone();
        Box::pin(async move {
            let v = blocking(move || Call::start(&bin, "snapshot", &req)?.answer()).await??;
            let snap = snapshot_of(&v["snapshot"])?;
            Ok((
                snap,
                BackupStats {
                    new_bytes: v["newBytes"].as_i64().unwrap_or(0),
                    uploaded: v["uploaded"].as_i64().unwrap_or(0),
                },
            ))
        })
    }

    fn prune(&self, req: SnapshotRequest) -> BoxFut<'_, (Usage, Result<(), String>)> {
        let bin = self.bin.clone();
        Box::pin(async move {
            let r = blocking(move || -> Result<Vec<u8>, String> {
                let mut c = Call::start(&bin, "prune", &req)?;
                let l = c.next();
                c.finish();
                match l? {
                    Line::Answer(b) => Ok(b),
                    Line::Ready => Err(nodeprog::failed("unreadable answer")),
                }
            })
            .await
            .and_then(|r| r);
            let b = match r {
                Ok(b) => b,
                Err(e) => return (Usage::default(), Err(e)),
            };
            let Ok(v) = serde_json::from_slice::<Value>(&b) else {
                return (Usage::default(), Err(nodeprog::failed("unreadable answer")));
            };
            let u = Usage {
                snapshots: v["snapshots"].as_i64().unwrap_or(0),
                stored: v["stored"].as_i64().unwrap_or(0),
                deleted_snapshots: v["deletedSnapshots"].as_i64().unwrap_or(0),
                deleted_chunks: v["deletedChunks"].as_i64().unwrap_or(0),
            };
            match v.get("error").and_then(Value::as_str) {
                Some(e) => (u, Err(e.to_string())),
                None => (u, Ok(())),
            }
        })
    }

    fn snapshots(&self, req: SnapshotRequest) -> BoxFut<'_, Result<Vec<Snapshot>, String>> {
        let bin = self.bin.clone();
        Box::pin(async move {
            let v = blocking(move || Call::start(&bin, "snapshots", &req)?.answer()).await??;
            let mut out = Vec::new();
            for s in v["snapshots"].as_array().cloned().unwrap_or_default() {
                out.push(snapshot_of(&s)?);
            }
            Ok(out)
        })
    }

    fn restore_snapshot(
        &self,
        req: SnapshotRequest,
        pause: PauseFn,
    ) -> BoxFut<'_, Result<Snapshot, String>> {
        let bin = self.bin.clone();
        Box::pin(async move {
            let (mut c, ready) = blocking(move || -> Result<(Call, Line), String> {
                let mut c = Call::start(&bin, "restore-snapshot", &req)?;
                let l = c.next()?;
                Ok((c, l))
            })
            .await??;
            if let Line::Answer(b) = ready {
                // An error before the snapshot was found.
                c.finish();
                return match answered(&b) {
                    Some(Err(e)) => Err(e),
                    _ => Err(nodeprog::failed("an answer before ready")),
                };
            }
            if let Err(e) = pause().await {
                blocking(move || c.finish()).await?;
                return Err(e);
            }
            let v = blocking(move || -> Result<Value, String> {
                let w = c.stdin.as_mut().map(|s| s.write_all(b"go\n"));
                if !matches!(w, Some(Ok(()))) {
                    let (status, stderr) = c.finish();
                    return Err(program_failed("go: broken pipe", status, &stderr));
                }
                c.answer()
            })
            .await??;
            snapshot_of(&v["snapshot"])
        })
    }
}

/// Volumes through armada-node's code in process:
/// the archives, restores, sizes, and the snapshot repository the
/// program runs, called as a library on blocking threads.
pub struct LibVolumes;

/// Writes an archive to the session in VOLUME_CHUNK pieces.
struct ChunkWriter<'a> {
    out: &'a mpsc::Sender<Vec<u8>>,
    buf: Vec<u8>,
    ended: bool,
}

impl ChunkWriter<'_> {
    fn send(&mut self) -> std::io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let b = std::mem::replace(&mut self.buf, Vec::with_capacity(VOLUME_CHUNK));
        if self.out.blocking_send(b).is_err() {
            self.ended = true;
            return Err(std::io::Error::other("the session ended"));
        }
        Ok(())
    }
}

impl Write for ChunkWriter<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = b.len().min(VOLUME_CHUNK - self.buf.len());
        self.buf.extend_from_slice(&b[..n]);
        if self.buf.len() == VOLUME_CHUNK {
            self.send()?;
        }
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.send()
    }
}

/// The session's data as a reader: an Err item is the session's
/// failure, returned on this and every later read (Feed).
struct SessionReader {
    input: mpsc::Receiver<Result<Vec<u8>, String>>,
    cur: Vec<u8>,
    pos: usize,
    failed: Option<String>,
}

impl Read for SessionReader {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if let Some(t) = &self.failed {
                return Err(std::io::Error::other(t.clone()));
            }
            if self.pos < self.cur.len() {
                let n = b.len().min(self.cur.len() - self.pos);
                b[..n].copy_from_slice(&self.cur[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            match self.input.blocking_recv() {
                None => return Ok(0),
                Some(Ok(d)) => {
                    self.cur = d;
                    self.pos = 0;
                }
                Some(Err(e)) => self.failed = Some(e),
            }
        }
    }
}

fn lib_snapshot(s: &armada_node::volbackup::repo::Snapshot) -> Snapshot {
    Snapshot {
        id: s.id.clone(),
        time: nanos_time(s.time.nanos()),
        files: s.files,
        bytes: s.bytes,
        node: s.node.clone(),
    }
}

fn nanos_time(n: i128) -> SystemTime {
    if n >= 0 {
        SystemTime::UNIX_EPOCH + Duration::from_nanos(n as u64)
    } else {
        SystemTime::UNIX_EPOCH - Duration::from_nanos((-n) as u64)
    }
}

/// The volume's repository in its bucket, as the program opens it.
fn open_repo(req: &SnapshotRequest) -> Result<armada_node::volbackup::repo::Repo, String> {
    use armada_node::volbackup::{repo, s3, target};
    let t = target::parse(&req.url)?;
    let bucket = s3::Bucket::new(t.clone(), None)?;
    repo::Repo::open(
        &bucket,
        &repo::root(&t.prefix, &req.app, &req.volume),
        &req.key,
    )
}

/// A kernel without openat2 cannot walk a volume safely.
fn probe(dir: &str) -> Result<(), String> {
    match armada_node::volume::walk::Root::open(dir.as_bytes()) {
        Ok(root) => root.probe(),
        Err(_) => Ok(()),
    }
}

/// Sets a restore's stop when the call is dropped.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl Volumes for LibVolumes {
    fn archive<'a>(
        &'a self,
        dir: &'a str,
        out: mpsc::Sender<Vec<u8>>,
    ) -> BoxFut<'a, Result<(), String>> {
        let dir = dir.to_string();
        Box::pin(async move {
            blocking(move || {
                let mut w = ChunkWriter {
                    out: &out,
                    buf: Vec::with_capacity(VOLUME_CHUNK),
                    ended: false,
                };
                let res = armada_node::volume::archive::write_to(&dir, &mut w);
                if w.ended {
                    return Err("archive volume: the session ended".to_string());
                }
                match res {
                    Ok(()) => Ok(()),
                    Err(armada_node::volume::archive::WriteError::Entry { text, .. }) => Err(text),
                    Err(armada_node::volume::archive::WriteError::Out(e)) => {
                        Err(format!("write archive: {e}"))
                    }
                }
            })
            .await?
        })
    }

    fn restore<'a>(
        &'a self,
        dir: &'a str,
        input: mpsc::Receiver<Result<Vec<u8>, String>>,
    ) -> BoxFut<'a, Result<(), String>> {
        let dir = dir.to_string();
        Box::pin(async move {
            blocking(move || {
                let r = BufReader::with_capacity(
                    64 << 10,
                    SessionReader {
                        input,
                        cur: Vec::new(),
                        pos: 0,
                        failed: None,
                    },
                );
                armada_node::volume::restore::restore(
                    dir.as_bytes(),
                    r,
                    armada_node::volume::restore::restore_space(),
                )
            })
            .await?
        })
    }

    fn sizes(&self, dirs: Vec<String>) -> BoxFut<'_, Result<Vec<i64>, String>> {
        Box::pin(async move {
            blocking(move || {
                dirs.iter()
                    .map(|d| armada_node::volume::walk::size(d.as_bytes()))
                    .collect()
            })
            .await?
        })
    }

    fn snapshot(
        &self,
        req: SnapshotRequest,
    ) -> BoxFut<'_, Result<(Snapshot, BackupStats), String>> {
        Box::pin(async move {
            blocking(move || {
                probe(&req.dir)?;
                let mut repo = open_repo(&req)?;
                let now = armada_node::volbackup::gotime::Instant::from_nanos(i128::from(req.now));
                match repo.backup(req.dir.as_bytes(), &req.node, now) {
                    Ok((s, st)) => Ok((
                        lib_snapshot(&s),
                        BackupStats {
                            new_bytes: st.new_bytes,
                            uploaded: st.uploaded,
                        },
                    )),
                    Err(f) => Err(f.text),
                }
            })
            .await?
        })
    }

    fn prune(&self, req: SnapshotRequest) -> BoxFut<'_, (Usage, Result<(), String>)> {
        Box::pin(async move {
            let r = blocking(move || {
                let mut repo = match open_repo(&req) {
                    Ok(r) => r,
                    Err(e) => return (Usage::default(), Err(e)),
                };
                let k = req.keep.unwrap_or_default();
                let keep = armada_node::volbackup::gotime::Keep {
                    last: k.last,
                    hourly: k.hourly,
                    daily: k.daily,
                    weekly: k.weekly,
                    monthly: k.monthly,
                };
                let zone: Vec<(i64, i64)> = if req.zone.is_empty() {
                    vec![(i64::MIN, 0)]
                } else {
                    req.zone.iter().map(|z| (z[0], z[1])).collect()
                };
                let now = armada_node::volbackup::gotime::Instant::from_nanos(i128::from(req.now));
                let (u, err) = repo.prune(&keep, &zone, now);
                let u = Usage {
                    snapshots: u.snapshots,
                    stored: u.stored,
                    deleted_snapshots: u.deleted_snapshots,
                    deleted_chunks: u.deleted_chunks,
                };
                (u, err.map_or(Ok(()), Err))
            })
            .await;
            r.unwrap_or_else(|e| (Usage::default(), Err(e)))
        })
    }

    fn snapshots(&self, req: SnapshotRequest) -> BoxFut<'_, Result<Vec<Snapshot>, String>> {
        Box::pin(async move {
            blocking(move || {
                let s = open_repo(&req)?.snapshots()?;
                Ok(s.iter()
                    .map(|(id, t)| Snapshot {
                        id: id.clone(),
                        time: nanos_time(t.nanos()),
                        files: 0,
                        bytes: 0,
                        node: String::new(),
                    })
                    .collect())
            })
            .await?
        })
    }

    fn restore_snapshot(
        &self,
        req: SnapshotRequest,
        pause: PauseFn,
    ) -> BoxFut<'_, Result<Snapshot, String>> {
        Box::pin(async move {
            let (repo, id, dir) = blocking(move || -> Result<_, String> {
                probe(&req.dir)?;
                let mut repo = open_repo(&req)?;
                let id = if req.snapshot == "latest" {
                    repo.latest()?
                } else {
                    req.snapshot.clone()
                };
                Ok((repo, id, req.dir))
            })
            .await??;
            pause().await?;
            let stop = Arc::new(AtomicBool::new(false));
            let _guard = StopOnDrop(stop.clone());
            blocking(move || {
                armada_node::volbackup::with_stop(stop, || {
                    let mut repo = repo;
                    armada_node::volbackup::repo::restore_into(&mut repo, dir.as_bytes(), &id)
                        .map(|s| lib_snapshot(&s))
                })
            })
            .await?
        })
    }
}

/// The zone as armada-node counts days in it: each offset from UTC and
/// when it starts (Unix seconds), the first also before. The table covers
/// 1900 towards 2300; for a zone whose file has a last transition it stops
/// at the end of the 365th day of the first leap year from that
/// transition, where the table has always stopped, so every release sends
/// armada-node the same table.
pub fn zone_table(loc: &armada_spec::gotime::Location) -> Vec<[i64; 2]> {
    const DAY: i64 = 86_400;
    // Steps of six hours: no zone changes its offset twice within one.
    const STEP: i64 = 6 * 3600;
    let start = -2_208_988_800; // 1900-01-01T00:00:00Z
    let mut end = year_start(2301);
    if let Some(last) = last_transition(loc.name()) {
        // The first leap year from the last transition's on: the table
        // stops at its 366th day.
        let mut y = civil_year(last);
        while !(y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) {
            y += 1;
        }
        end = end.min(year_start(y) + 365 * DAY);
    }
    let mut out = vec![[i64::MIN, loc.offset(start)]];
    let mut t = start;
    while t < end && out.len() < 4096 {
        let next = (t + STEP).min(end);
        if loc.offset(next) != loc.offset(t) {
            // The second the offset changes.
            let (mut lo, mut hi) = (t, next);
            while hi - lo > 1 {
                let mid = lo + (hi - lo) / 2;
                if loc.offset(mid) == loc.offset(t) {
                    lo = mid;
                } else {
                    hi = mid;
                }
            }
            let off = loc.offset(hi);
            if off != out[out.len() - 1][1] {
                out.push([hi, off]);
            }
        }
        t = next;
    }
    out
}

/// The UTC year of a Unix time.
fn civil_year(t: i64) -> i64 {
    let mut y = 1970 + t.div_euclid(31_556_952);
    while year_start(y + 1) <= t {
        y += 1;
    }
    while year_start(y) > t {
        y -= 1;
    }
    y
}

/// The Unix time of January 1 of year y, UTC.
fn year_start(y: i64) -> i64 {
    let leaps = |y: i64| y.div_euclid(4) - y.div_euclid(100) + y.div_euclid(400);
    (365 * (y - 1970) + leaps(y - 1) - leaps(1969)) * 86_400
}

/// The last transition of the zone file for name (ZONEINFO, then the
/// system's directories); None for UTC, Local, or a zone with no file.
fn last_transition(name: &str) -> Option<i64> {
    if name.is_empty() || name == "UTC" || name == "Local" {
        return None;
    }
    let mut paths = Vec::new();
    if let Ok(z) = std::env::var("ZONEINFO")
        && !z.is_empty()
    {
        paths.push(format!("{z}/{name}"));
    }
    for dir in [
        "/usr/share/zoneinfo/",
        "/usr/share/lib/zoneinfo/",
        "/usr/lib/locale/TZ/",
        "/etc/zoneinfo/",
    ] {
        paths.push(format!("{dir}{name}"));
    }
    let data = paths.iter().find_map(|p| std::fs::read(p).ok())?;
    tzif_last(&data)
}

/// The last transition time in TZif data, from its 64-bit part when it
/// has one.
fn tzif_last(d: &[u8]) -> Option<i64> {
    let u32_at = |o: usize| -> Option<usize> {
        Some(u32::from_be_bytes(d.get(o..o + 4)?.try_into().ok()?) as usize)
    };
    // isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt.
    let header = |o: usize| -> Option<[usize; 6]> {
        if d.get(o..o + 4)? != b"TZif" {
            return None;
        }
        let mut c = [0; 6];
        for (i, x) in c.iter_mut().enumerate() {
            *x = u32_at(o + 20 + 4 * i)?;
        }
        Some(c)
    };
    let c = header(0)?;
    if d.get(4).copied().unwrap_or(0) < b'2' {
        let n = c[3].checked_sub(1)?;
        let o = 44 + 4 * n;
        return Some(i64::from(i32::from_be_bytes(
            d.get(o..o + 4)?.try_into().ok()?,
        )));
    }
    let o = 44 + c[3] * 5 + c[4] * 6 + c[5] + c[2] * 8 + c[1] + c[0];
    let n = header(o)?[3].checked_sub(1)?;
    let at = o + 44 + 8 * n;
    Some(i64::from_be_bytes(d.get(at..at + 8)?.try_into().ok()?))
}

impl<R: Runtime> Inner<R> {
    /// Stops app's containers on this node and keeps the reconcile pass
    /// from starting them again until resume (pause).
    pub(crate) async fn pause(&self, app: &str) -> Result<(), String> {
        let _g = self.reconcile_mu.lock().await;
        *lock(&self.st).paused.entry(app.to_string()).or_insert(0) += 1;
        let labels = BTreeMap::from([
            (LABEL_MANAGED.to_string(), "true".to_string()),
            (LABEL_APP.to_string(), app.to_string()),
        ]);
        let cs = match self.rt.list(&labels).await {
            Ok(cs) => cs,
            Err(e) => {
                self.resume(app).await;
                return Err(e.to_string());
            }
        };
        for c in cs {
            if stopped(&c.state) {
                continue;
            }
            if let Err(e) = self.rt.stop(&c.id, crate::agent::VOLUME_STOP_GRACE).await {
                self.resume(app).await;
                return Err(format!("stop {}: {e}", c.name));
            }
        }
        Ok(())
    }

    /// Lets the reconcile pass start app's containers again; those stopped
    /// for the operation are recreated at once (resume).
    pub(crate) async fn resume(&self, app: &str) {
        let labels = BTreeMap::from([
            (LABEL_MANAGED.to_string(), "true".to_string()),
            (LABEL_APP.to_string(), app.to_string()),
        ]);
        let cs = tokio::time::timeout(Duration::from_secs(10), self.rt.list(&labels))
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default();
        {
            let mut st = lock(&self.st);
            let n = st.paused.entry(app.to_string()).or_insert(0);
            *n -= 1;
            if *n <= 0 {
                st.paused.remove(app);
                for c in cs {
                    if stopped(&c.state) {
                        st.restarts.insert(c.id.clone(), RESUMED.to_string());
                    }
                }
            }
        }
        self.trigger.notify_one();
    }

    /// Whether a replica assigned to this node mounts the volume.
    fn volume_used(&self, app: &str, name: &str) -> bool {
        lock(&self.st).desired.as_ref().is_some_and(|d| {
            d.values()
                .any(|s| s.app == app && s.volumes.iter().any(|v| v.name == name))
        })
    }

    fn volumes_seam(&self) -> Result<Arc<dyn Volumes>, String> {
        self.cfg
            .side
            .volumes
            .clone()
            .ok_or_else(|| "this node cannot back up or restore volumes".to_string())
    }

    /// One volume request.
    pub(crate) async fn serve_volume(self: Arc<Self>, req: pb::VolumeRequest) {
        let Some(conn) = lock(&self.side.conn).clone() else {
            return;
        };
        let (tx, rx) = mpsc::channel::<pb::VolumeData>(16);
        let mut client = conn.client();
        let mut inbound =
            Inbound::new(async move { client.volume_session(ReceiverStream::new(rx)).await });
        let s = Sender {
            tx,
            rid: req.request_id.clone(),
            first: Arc::new(AtomicBool::new(true)),
        };
        let n = self.side_volume_ops_add();
        let _g = OpsGuard(self.clone());
        if n > MAX_VOLUME_SESSIONS {
            return s
                .finish(
                    Some("this node is already busy with other volume backups or restores".into()),
                    &mut inbound,
                )
                .await;
        }
        let dir = match self.volume_dir(&req.app, &req.volume) {
            Ok(d) => d,
            Err(e) => return s.finish(Some(e), &mut inbound).await,
        };
        let dir_s = dir.to_string_lossy().into_owned();
        let op = Op::try_from(req.op).unwrap_or(Op::Unspecified);
        self.log.info(
            "volume operation",
            &[
                ("op", op.as_str_name().to_string()),
                ("app", req.app.clone()),
                ("volume", req.volume.clone()),
            ],
        );
        let is_dir = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir());
        let missing = || {
            format!(
                "volume {} of {} does not exist on this node",
                req.volume, req.app
            )
        };
        match op {
            Op::Backup => {
                if !is_dir(&dir) {
                    return s.finish(Some(missing()), &mut inbound).await;
                }
                if req.stop
                    && let Err(e) = self.pause(&req.app).await
                {
                    return s.finish(Some(e), &mut inbound).await;
                }
                let r = self.backup_archive(&s, &dir_s).await;
                if req.stop {
                    self.resume(&req.app).await;
                }
                if let Some(r) = r {
                    s.finish(r.err(), &mut inbound).await;
                }
            }
            Op::Restore => {
                if let Err(e) = self.pause(&req.app).await {
                    return s.finish(Some(e), &mut inbound).await;
                }
                let r = if s.send(pb::VolumeData::default()).await {
                    Some(self.restore_archive(&dir_s, &mut inbound).await)
                } else {
                    None
                };
                self.resume(&req.app).await;
                if let Some(r) = r {
                    s.finish(r.err(), &mut inbound).await;
                }
            }
            Op::Snapshot | Op::Snapshots | Op::RestoreSnapshot => {
                if !s.send(pb::VolumeData::default()).await {
                    return;
                }
                let (m, err) = self.clone().snapshot_op(&req, &dir_s).await;
                let Some(mut m) = m else {
                    return s.finish(err, &mut inbound).await;
                };
                m.done = err.is_none();
                m.error = err.unwrap_or_default();
                s.send(m).await;
                s.finish(None, &mut inbound).await;
            }
            Op::Remove => {
                if self.volume_used(&req.app, &req.volume) {
                    let e = format!(
                        "a replica on this node still uses volume {} of {}",
                        req.volume, req.app
                    );
                    return s.finish(Some(e), &mut inbound).await;
                }
                let r = match std::fs::remove_dir_all(&dir) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                        Some(armada_fsutil::Error::path("unlinkat", &dir, &e).to_string())
                    }
                    _ => None,
                };
                s.finish(r, &mut inbound).await;
            }
            Op::Unspecified => {
                s.finish(Some("unknown volume operation".into()), &mut inbound)
                    .await
            }
        }
    }

    fn side_volume_ops_add(&self) -> i32 {
        self.volume_ops.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Attaches the session and sends dir's archive in chunks; None when
    /// the session went away before.
    async fn backup_archive(&self, s: &Sender, dir: &str) -> Option<Result<(), String>> {
        if !s.send(pb::VolumeData::default()).await {
            return None;
        }
        let vols = match self.volumes_seam() {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(4);
        let fwd = {
            let s = s.clone();
            tokio::spawn(async move {
                while let Some(b) = out_rx.recv().await {
                    for c in b.chunks(VOLUME_CHUNK) {
                        if !s
                            .send(pb::VolumeData {
                                data: c.to_vec(),
                                ..Default::default()
                            })
                            .await
                        {
                            return;
                        }
                    }
                }
            })
        };
        let r = vols.archive(dir, out_tx).await;
        let _ = fwd.await;
        Some(r)
    }

    /// Restores dir from the session's VolumeData.
    async fn restore_archive(
        &self,
        dir: &str,
        inbound: &mut Inbound<pb::VolumeData>,
    ) -> Result<(), String> {
        let vols = self.volumes_seam()?;
        let (in_tx, in_rx) = mpsc::channel::<Result<Vec<u8>, String>>(4);
        let restore = vols.restore(dir, in_rx);
        let feed = async move {
            loop {
                let m = match inbound.next().await {
                    Ok(Some(m)) => m,
                    Ok(None) => {
                        let _ = in_tx.send(Err("receive archive: EOF".into())).await;
                        return;
                    }
                    Err(e) => {
                        let _ = in_tx.send(Err(format!("receive archive: {e}"))).await;
                        return;
                    }
                };
                if !m.error.is_empty() {
                    let _ = in_tx.send(Err(m.error)).await;
                    return;
                }
                if m.data.len() > VOLUME_CHUNK {
                    let _ = in_tx.send(Err("archive chunk too large".into())).await;
                    return;
                }
                if !m.data.is_empty() && in_tx.send(Ok(m.data)).await.is_err() {
                    return;
                }
                if m.done {
                    return;
                }
            }
        };
        let (r, ()) = tokio::join!(restore, feed);
        r
    }

    /// The backup request armada-node reads.
    fn snapshot_request(&self, req: &pb::VolumeRequest) -> SnapshotRequest {
        let b = req.backup.clone().unwrap_or_default();
        SnapshotRequest {
            url: b.url,
            key: b.key,
            app: req.app.clone(),
            volume: req.volume.clone(),
            ..Default::default()
        }
    }

    /// A backup, a listing, or a restore against the volume's bucket: a
    /// message, an error, or both (a backup whose cleanup
    /// failed).
    async fn snapshot_op(
        self: Arc<Self>,
        req: &pb::VolumeRequest,
        dir: &str,
    ) -> (Option<pb::VolumeData>, Option<String>) {
        let _g = self
            .side
            .repos
            .lock(&format!("{}/{}", req.app, req.volume))
            .await;
        let Some(b) = req.backup.clone() else {
            return (None, Some("the volume has no backup bucket".into()));
        };
        let vols = match self.volumes_seam() {
            Ok(v) => v,
            Err(e) => return (None, Some(e)),
        };
        let snap_pb = |s: &Snapshot| pb::VolumeSnapshot {
            id: s.id.clone(),
            time: Some(ts(s.time)),
            files: s.files,
            bytes: s.bytes,
        };
        match Op::try_from(req.op).unwrap_or(Op::Unspecified) {
            Op::Snapshots => match vols.snapshots(self.snapshot_request(req)).await {
                Err(e) => (None, Some(e)),
                Ok(snaps) => (
                    Some(pb::VolumeData {
                        snapshots: snaps
                            .iter()
                            .map(|s| pb::VolumeSnapshot {
                                id: s.id.clone(),
                                time: Some(ts(s.time)),
                                ..Default::default()
                            })
                            .collect(),
                        ..Default::default()
                    }),
                    None,
                ),
            },
            Op::Snapshot => {
                if !std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir()) {
                    return (
                        None,
                        Some(format!(
                            "volume {} of {} does not exist on this node",
                            req.volume, req.app
                        )),
                    );
                }
                if req.stop
                    && let Err(e) = self.pause(&req.app).await
                {
                    return (None, Some(e));
                }
                let mut r = self.snapshot_request(req);
                r.dir = dir.to_string();
                r.node = self.cfg.node_id.clone();
                r.now = crate::clock::unix_nanos(SystemTime::now()) as i64;
                let res = vols.snapshot(r).await;
                if req.stop {
                    self.resume(&req.app).await;
                }
                let (snap, st) = match res {
                    Ok(x) => x,
                    Err(e) => return (None, Some(e)),
                };
                self.log.info(
                    "backed up volume",
                    &[
                        ("app", req.app.clone()),
                        ("volume", req.volume.clone()),
                        ("backup", snap.id.clone()),
                        ("new_bytes", st.new_bytes.to_string()),
                    ],
                );
                let mut res = pb::CreateVolumeSnapshotResponse {
                    snapshot: Some(snap_pb(&snap)),
                    new_bytes: st.new_bytes,
                    ..Default::default()
                };
                let (keep, loc) = backup_keep(&b);
                let mut pr = self.snapshot_request(req);
                pr.now = crate::clock::unix_nanos(SystemTime::now()) as i64;
                pr.keep = Some(keep);
                pr.zone = zone_table(&loc);
                let (u, err) = vols.prune(pr).await;
                res.stored_bytes = u.stored;
                res.snapshots = u.snapshots.min(1 << 30) as i32;
                let m = pb::VolumeData {
                    snapshot: Some(res),
                    ..Default::default()
                };
                match err {
                    Err(e) => (
                        Some(m),
                        Some(format!(
                            "backed up as {}, but removing old backups failed: {e}",
                            snap.id
                        )),
                    ),
                    Ok(()) => (Some(m), None),
                }
            }
            Op::RestoreSnapshot => {
                let mut r = self.snapshot_request(req);
                r.dir = dir.to_string();
                r.snapshot = req.snapshot.clone();
                let paused = Arc::new(AtomicBool::new(false));
                let pause: PauseFn = {
                    let me = self.clone();
                    let app = req.app.clone();
                    let paused = paused.clone();
                    Box::new(move || {
                        Box::pin(async move {
                            me.pause(&app).await?;
                            paused.store(true, Ordering::SeqCst);
                            Ok(())
                        })
                    })
                };
                let res = vols.restore_snapshot(r, pause).await;
                if paused.load(Ordering::SeqCst) {
                    self.resume(&req.app).await;
                }
                match res {
                    Err(e) => (None, Some(e)),
                    Ok(snap) => {
                        self.log.info(
                            "restored volume from backup",
                            &[
                                ("app", req.app.clone()),
                                ("volume", req.volume.clone()),
                                ("backup", snap.id.clone()),
                            ],
                        );
                        (
                            Some(pb::VolumeData {
                                snapshot: Some(pb::CreateVolumeSnapshotResponse {
                                    snapshot: Some(snap_pb(&snap)),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }),
                            None,
                        )
                    }
                }
            }
            _ => (None, Some("unknown volume operation".into())),
        }
    }

    /// Adds up the size of every volume on this node;
    /// None when it cannot measure them.
    pub(crate) async fn measure_volumes(&self) -> Option<Vec<pb::VolumeUsage>> {
        let vols = self.cfg.side.volumes.clone()?;
        let root = Path::new(&self.cfg.volumes_dir);
        let Ok(apps) = read_dir_entries(root) else {
            return Some(Vec::new());
        };
        let mut out = Vec::new();
        let mut dirs = Vec::new();
        for (app, is_dir) in apps {
            if !is_dir || !armada_spec::validate::valid_app_id(&app) {
                continue;
            }
            let Ok(vs) = read_dir_entries(&root.join(&app)) else {
                continue;
            };
            for (v, is_dir) in vs {
                if !is_dir || !armada_spec::validate::valid_name(&v) {
                    continue; // leftovers of a restore, among others
                }
                dirs.push(root.join(&app).join(&v).to_string_lossy().into_owned());
                out.push(pb::VolumeUsage {
                    app: app.clone(),
                    volume: v,
                    bytes: 0,
                });
            }
        }
        if !dirs.is_empty() {
            match vols.sizes(dirs).await {
                Ok(sizes) => {
                    for (u, n) in out.iter_mut().zip(sizes) {
                        u.bytes = n;
                    }
                }
                Err(e) => self.log.warn(
                    "armada-node failed",
                    &[("op", "volume size".into()), ("err", e)],
                ),
            }
        }
        Some(out)
    }
}

/// A directory's names sorted, and whether each is a directory (not
/// following links).
fn read_dir_entries(p: &Path) -> std::io::Result<Vec<(String, bool)>> {
    let mut out: Vec<(String, bool)> = std::fs::read_dir(p)?
        .filter_map(|e| e.ok())
        .map(|e| {
            let d = e.file_type().is_ok_and(|t| t.is_dir());
            (e.file_name().to_string_lossy().into_owned(), d)
        })
        .collect();
    out.sort();
    Ok(out)
}

/// The request's keep policy and the zone it counts in.
fn backup_keep(b: &pb::BackupTarget) -> (Keep, armada_spec::gotime::Location) {
    let k = b.keep.unwrap_or_default();
    let keep = Keep {
        last: i64::from(k.last),
        hourly: i64::from(k.hourly),
        daily: i64::from(k.daily),
        weekly: i64::from(k.weekly),
        monthly: i64::from(k.monthly),
    };
    let loc = if b.time_zone.is_empty() {
        armada_spec::gotime::Location::utc()
    } else {
        armada_spec::gotime::load_location(&b.time_zone)
            .unwrap_or_else(armada_spec::gotime::Location::utc)
    };
    (keep, loc)
}

/// The session's stream: the request's ID on the first message.
#[derive(Clone)]
struct Sender {
    tx: mpsc::Sender<pb::VolumeData>,
    rid: String,
    first: Arc<AtomicBool>,
}

impl Sender {
    async fn send(&self, mut m: pb::VolumeData) -> bool {
        if self.first.swap(false, Ordering::SeqCst) {
            m.request_id = self.rid.clone();
        }
        self.tx.send(m).await.is_ok()
    }

    /// Sends the last message and waits for the server to end the session.
    async fn finish(&self, err: Option<String>, inbound: &mut Inbound<pb::VolumeData>) {
        let m = pb::VolumeData {
            done: err.is_none(),
            error: err.unwrap_or_default(),
            ..Default::default()
        };
        self.send(m).await;
        inbound.drain().await;
    }
}

/// Counts a volume session until dropped.
struct OpsGuard<R: Runtime>(Arc<Inner<R>>);

impl<R: Runtime> Drop for OpsGuard<R> {
    fn drop(&mut self) {
        self.0.volume_ops.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zones() {
        let utc = armada_spec::gotime::Location::utc();
        assert_eq!(zone_table(&utc), vec![[i64::MIN, 0]]);
        if let Some(l) = armada_spec::gotime::load_location("Europe/Amsterdam") {
            let t = zone_table(&l);
            assert!(t.len() > 100);
            // 2026-03-29T01:00:00Z: summer time starts.
            assert!(t.contains(&[1_774_746_000, 7200]));
            // The table stops in a leap year past the file's transitions.
            assert!(t.last().unwrap()[0] < year_start(2301));
        }
        assert_eq!(year_start(2040), 2_208_988_800);
        assert_eq!(year_start(1900), -2_208_988_800);
        assert_eq!(civil_year(2_208_988_799), 2039);
        assert_eq!(civil_year(2_208_988_800), 2040);
    }

    #[test]
    fn requests() {
        let r = SnapshotRequest {
            url: "https://k:s@h/b".into(),
            key: b"0123".to_vec(),
            app: "web".into(),
            volume: "data".into(),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"url":"https://k:s@h/b","key":"MDEyMw==","app":"web","volume":"data"}"#
        );
        assert_eq!(format!("{r:?}"), "volume data of web");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn archives_restores_and_measures_in_process() {
        let root = std::env::temp_dir().join(format!("armada-libvol-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (src, dst) = (root.join("src"), root.join("dst"));
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        for p in [&root, &dst] {
            std::fs::set_permissions(p, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .unwrap();
        }
        std::fs::write(src.join("a"), vec![7u8; 200_000]).unwrap();
        std::fs::write(src.join("sub/b"), b"bee").unwrap();
        let v = LibVolumes;
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4);
        let s = src.display().to_string();
        let collect = tokio::spawn(async move {
            let mut all = Vec::new();
            while let Some(b) = rx.recv().await {
                assert!(b.len() <= VOLUME_CHUNK);
                all.extend(b);
            }
            all
        });
        v.archive(&s, tx).await.unwrap();
        let data = collect.await.unwrap();
        assert_eq!(&data[..2], &[0x1f, 0x8b]);

        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            for c in data.chunks(1000) {
                tx.send(Ok(c.to_vec())).await.unwrap();
            }
        });
        let d = dst.display().to_string();
        v.restore(&d, rx).await.unwrap();
        assert_eq!(std::fs::read(dst.join("sub/b")).unwrap(), b"bee");
        assert_eq!(std::fs::read(dst.join("a")).unwrap().len(), 200_000);
        assert_eq!(
            v.sizes(vec![s.clone(), d.clone()]).await.unwrap(),
            vec![200_003, 200_003]
        );

        // A session that fails makes the restore fail with its error and
        // leaves the volume as it was.
        let (tx, rx) = mpsc::channel(4);
        tx.send(Ok(vec![0x1f, 0x8b])).await.unwrap();
        tx.send(Err("the session ended".into())).await.unwrap();
        drop(tx);
        let e = v.restore(&d, rx).await.unwrap_err();
        assert!(e.contains("the session ended"), "{e}");
        assert_eq!(std::fs::read(dst.join("sub/b")).unwrap(), b"bee");

        // A missing directory, and a bucket URL refused as ParseTarget
        // refuses it.
        let e = v
            .archive(&root.join("nope").display().to_string(), mpsc::channel(1).0)
            .await
            .unwrap_err();
        assert!(e.starts_with("archive volume: open "), "{e}");
        let req = SnapshotRequest {
            url: "ftp://k:s@h/b".into(),
            key: b"0123".to_vec(),
            app: "web".into(),
            volume: "data".into(),
            ..Default::default()
        };
        let want = armada_node::volbackup::target::parse("ftp://k:s@h/b").unwrap_err();
        assert_eq!(v.snapshots(req.clone()).await.unwrap_err(), want);
        assert_eq!(v.prune(req).await.1.unwrap_err(), want);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn connection_tracking_in_process() {
        use super::super::conntrack::{Conntrack, LibConntrack};
        let dir = std::env::temp_dir().join(format!("armada-libct-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t = LibConntrack {
            dir: dir.display().to_string(),
            memory: Some(64 << 30),
        };
        assert_eq!(t.read().await, None);
        assert_eq!(t.raise().await.unwrap(), 0);
        std::fs::write(dir.join("nf_conntrack_max"), "65536\n").unwrap();
        std::fs::write(dir.join("nf_conntrack_count"), "12\n").unwrap();
        assert_eq!(t.raise().await.unwrap(), 65536);
        assert_eq!(t.read().await, Some((12, 262_144)));
        assert_eq!(t.raise().await.unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

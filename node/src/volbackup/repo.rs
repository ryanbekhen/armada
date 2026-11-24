//! volbackup.Repo: one volume's repository in its bucket, in Go's format
//! byte for byte where it is not random (nonces, the repository's ID,
//! snapshot IDs' suffix): `config` ({"version":1,"id","check"}),
//! `chunks/<2>/<64 hex>` (zstd, then sealed with the key named by the
//! object), and `snapshots/<UTC ms time>-<8 hex>` (a sealed, compressed
//! JSON manifest of every entry). A backup lists the chunks once, uploads
//! the missing ones many at a time, and writes the manifest last; a
//! restore reads chunks ahead in order, each checked against its name,
//! and hands entries to the volume's restore; a prune deletes the
//! snapshots the policy does not keep, then the chunks no kept snapshot
//! names that are older than an hour.
//!
//! A manifest entry holds more than Go's where Go's loses something, in
//! fields Go's reader ignores (encoding/json skips unknown fields), so Go
//! still restores every snapshot: `pb` and `lb` the path's and link's
//! bytes (standard base64) when they are not UTF-8 (`p` and `l` then hold
//! them with U+FFFD, as Go writes them); `ms` and `mn` the time's seconds
//! and nanoseconds when it is past what `mt`'s 64-bit nanoseconds hold
//! (2262; `mt` then wraps as Go's UnixNano does); and setuid and setgid
//! in `m` as fs.FileMode's bits (ModeSetuid 1<<23, ModeSetgid 1<<22),
//! restored when the agent runs as root. Chunks and manifests are
//! compressed at ruzstd's Fastest level, the only one it implements
//! (Go writes SpeedDefault; either reads both).

use super::chunker::{Chunker, MAX_CHUNK};
use super::gotime::{self, Instant, Keep, Zone};
use super::keys::{ERR_SEALED, Keys, hex, random, unhex};
use super::s3::{Bucket, Conn, Error as S3Error};
use super::touch;
use crate::runtime::image::http::base64;
use crate::volume::restore::{self, Entry as RestoreEntry, Writer};
use crate::volume::walk::{self, EntryError, Root};
use crate::volume::{errno, quote, show};
use std::collections::HashSet;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex};

const CONFIG_KEY: &str = "config";
const CHUNKS_DIR: &str = "chunks/";
const SNAPSHOTS_DIR: &str = "snapshots/";
const REPO_VERSION: i64 = 1;
const MAX_CONFIG: usize = 4 << 10;
const MAX_MANIFEST: usize = 512 << 20;
const MAX_SEALED_CHUNK: usize = MAX_CHUNK + MAX_CHUNK / 8 + 1024;
/// chunkGrace, in seconds.
const CHUNK_GRACE: i64 = 3600;
/// uploads, uploadBytes: objects written at once and what they hold.
const UPLOADS: usize = 32;
const UPLOAD_BYTES: usize = 64 << 20;
const MAX_PACKERS: usize = 4;
/// fetches, fetchBytes: chunks a restore reads at once and ahead.
const FETCHES: usize = 32;
const FETCH_BYTES: usize = 64 << 20;
/// fs.FileMode's setuid, setgid, and sticky bits.
const MODE_SETUID: u32 = 1 << 23;
const MODE_SETGID: u32 = 1 << 22;
const MODE_STICKY: u32 = 1 << 20;

/// ^[0-9a-f]{64}$
fn chunk_name(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// ^[0-9]{8}T[0-9]{6}\.[0-9]{3}Z-[0-9a-f]{8}$
fn snapshot_name(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 29
        && b[..8].iter().all(u8::is_ascii_digit)
        && b[8] == b'T'
        && b[9..15].iter().all(u8::is_ascii_digit)
        && b[15] == b'.'
        && b[16..19].iter().all(u8::is_ascii_digit)
        && b[19] == b'Z'
        && b[20] == b'-'
        && b[21..]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}

/// path.Base.
fn base(p: &str) -> &str {
    let p = p.trim_end_matches('/');
    if p.is_empty() {
        return "/";
    }
    match p.rfind('/') {
        Some(i) => &p[i + 1..],
        None => p,
    }
}

/// An error, and whether it is volbackup.ErrChanged.
#[derive(Debug)]
pub struct Failure {
    pub text: String,
    pub changed: bool,
}

impl From<String> for Failure {
    fn from(text: String) -> Failure {
        Failure {
            text,
            changed: false,
        }
    }
}

/// Snapshot.
pub struct Snapshot {
    pub id: String,
    pub time: Instant,
    pub files: i64,
    pub bytes: i64,
    pub node: String,
}

/// Stats.
#[derive(Default)]
pub struct Stats {
    pub new_bytes: i64,
    pub uploaded: i64,
}

/// Usage.
#[derive(Default)]
pub struct Usage {
    pub snapshots: i64,
    pub stored: i64,
    pub deleted_snapshots: i64,
    pub deleted_chunks: i64,
}

pub struct Repo {
    b: Arc<Bucket>,
    conn: Conn,
    root: String,
    k: Arc<Keys>,
}

#[derive(serde::Deserialize)]
struct RepoConfig {
    #[serde(default)]
    version: Option<i64>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    check: Option<String>,
}

/// Root: where a volume's repository lives in the bucket.
pub fn root(prefix: &str, app: &str, volume: &str) -> String {
    format!("{prefix}{app}/{volume}/")
}

fn put(conn: &mut Conn, key: &str, data: &[u8]) -> Result<(), String> {
    touch();
    conn.put(key, data).map_err(|e| e.text())
}

fn delete(conn: &mut Conn, key: &str) -> Result<(), String> {
    touch();
    conn.delete(key).map_err(|e| e.text())
}

/// zstd's DecodeAll within max bytes of output and window.
fn unzstd(z: &[u8], max: usize) -> Result<Vec<u8>, ()> {
    use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};
    let mut out = Vec::new();
    let mut r = z;
    while !r.is_empty() {
        if let Some(w) = crate::runtime::image::check::window_size(r)
            && w > max as u64
        {
            return Err(());
        }
        match ruzstd::decoding::StreamingDecoder::new(&mut r) {
            Ok(mut d) => {
                let left = (max - out.len()) as u64 + 1;
                (&mut d).take(left).read_to_end(&mut out).map_err(|_| ())?;
                if out.len() > max {
                    return Err(());
                }
                let f = &d.decoder;
                if !f.is_finished() {
                    return Err(());
                }
                if let (Some(want), Some(got)) =
                    (f.get_checksum_from_data(), f.get_calculated_checksum())
                    && want != got
                {
                    return Err(());
                }
            }
            Err(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::SkipFrame {
                length,
                ..
            })) => {
                let n = length as usize;
                if r.len() < n {
                    return Err(());
                }
                r = &r[n..];
            }
            Err(_) => return Err(()),
        }
    }
    Ok(out)
}

fn zstd(b: &[u8]) -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(b, ruzstd::encoding::CompressionLevel::Fastest)
}

/// A manifest's entry.
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct ManifestEntry {
    p: Option<String>,
    /// The path's bytes when they are not UTF-8.
    pb: Option<String>,
    t: Option<String>,
    m: Option<u32>,
    u: Option<i64>,
    g: Option<i64>,
    mt: Option<i64>,
    /// The time's seconds and nanoseconds when mt cannot hold it.
    ms: Option<i64>,
    mn: Option<i64>,
    s: Option<i64>,
    l: Option<String>,
    /// The link's bytes when they are not UTF-8.
    lb: Option<String>,
    c: Option<Vec<String>>,
}

impl ManifestEntry {
    /// The path's bytes: pb's when it has them, else p's.
    fn path(&self) -> Result<Vec<u8>, String> {
        raw_or(&self.pb, &self.p)
    }

    fn link(&self) -> Result<Vec<u8>, String> {
        raw_or(&self.lb, &self.l)
    }

    /// The time in nanoseconds since the epoch, whole past 2262.
    fn time(&self) -> i128 {
        match self.ms {
            Some(s) => {
                i128::from(s) * 1_000_000_000
                    + i128::from(self.mn.unwrap_or(0).rem_euclid(1_000_000_000))
            }
            None => i128::from(self.mt.unwrap_or(0)),
        }
    }
}

fn raw_or(raw: &Option<String>, text: &Option<String>) -> Result<Vec<u8>, String> {
    match raw {
        Some(b) => super::unbase64(b).ok_or_else(|| ERR_SEALED.to_string()),
        None => Ok(text.clone().unwrap_or_default().into_bytes()),
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct Manifest {
    time: Option<String>,
    node: Option<String>,
    files: Option<i64>,
    bytes: Option<i64>,
    entries: Option<Vec<ManifestEntry>>,
}

/// The zero time.Time, which a manifest without a time holds.
const ZERO_TIME: Instant = Instant {
    sec: -62_135_596_800,
    nsec: 0,
};

impl Manifest {
    fn snapshot(&self, id: &str) -> Result<Snapshot, String> {
        let time = match &self.time {
            None => ZERO_TIME,
            Some(t) => gotime::parse_rfc3339(t).ok_or_else(|| ERR_SEALED.to_string())?,
        };
        Ok(Snapshot {
            id: id.to_string(),
            time,
            files: self.files.unwrap_or(0),
            bytes: self.bytes.unwrap_or(0),
            node: self.node.clone().unwrap_or_default(),
        })
    }
}

/// An entry the backup writes.
struct Entry {
    p: Vec<u8>,
    t: u8,
    m: u32,
    u: u32,
    g: u32,
    /// Nanoseconds since the epoch.
    mt: i128,
    s: i64,
    l: Vec<u8>,
    c: Vec<String>,
}

/// The manifest as Go's json.Marshal writes it.
fn manifest_json(time: Instant, node: &str, files: i64, bytes: i64, entries: &[Entry]) -> String {
    let mut o = String::with_capacity(256 + entries.len() * 128);
    o.push_str(&format!(
        "{{\"version\":{REPO_VERSION},\"time\":\"{}\",\"node\":",
        time.rfc3339_nano()
    ));
    gotime::json_string(&mut o, node.as_bytes());
    o.push_str(&format!(
        ",\"files\":{files},\"bytes\":{bytes},\"entries\":"
    ));
    if entries.is_empty() {
        o.push_str("null");
    }
    for (i, e) in entries.iter().enumerate() {
        o.push(if i == 0 { '[' } else { ',' });
        o.push_str("{\"p\":");
        gotime::json_string(&mut o, &e.p);
        if std::str::from_utf8(&e.p).is_err() {
            o.push_str(&format!(",\"pb\":\"{}\"", base64(&e.p)));
        }
        // time.UnixNano wraps past 2262; ms and mn then hold the time.
        o.push_str(&format!(
            ",\"t\":\"{}\",\"m\":{},\"u\":{},\"g\":{},\"mt\":{}",
            e.t as char, e.m, e.u, e.g, e.mt as i64
        ));
        if i64::try_from(e.mt).is_err() {
            o.push_str(&format!(
                ",\"ms\":{},\"mn\":{}",
                e.mt.div_euclid(1_000_000_000),
                e.mt.rem_euclid(1_000_000_000)
            ));
        }
        if e.s != 0 {
            o.push_str(&format!(",\"s\":{}", e.s));
        }
        if !e.l.is_empty() {
            o.push_str(",\"l\":");
            gotime::json_string(&mut o, &e.l);
            if std::str::from_utf8(&e.l).is_err() {
                o.push_str(&format!(",\"lb\":\"{}\"", base64(&e.l)));
            }
        }
        if !e.c.is_empty() {
            o.push_str(",\"c\":[");
            for (j, c) in e.c.iter().enumerate() {
                if j > 0 {
                    o.push(',');
                }
                o.push('"');
                o.push_str(c);
                o.push('"');
            }
            o.push(']');
        }
        o.push('}');
    }
    if !entries.is_empty() {
        o.push(']');
    }
    o.push('}');
    o
}

/// The first error of a backup's uploads, and the bytes they may hold.
struct Shared {
    err: Mutex<Option<String>>,
    budget: Mutex<usize>,
    freed: Condvar,
}

impl Shared {
    fn failed(&self) -> Option<String> {
        self.err.lock().expect("error lock").clone()
    }
    fn fail(&self, e: String) {
        self.err.lock().expect("error lock").get_or_insert(e);
        self.freed.notify_all();
    }
    /// Takes n bytes of the budget, or gives up once a write failed.
    fn take(&self, n: usize) -> bool {
        let mut left = self.budget.lock().expect("budget lock");
        while *left < n {
            if self.failed().is_some() {
                return false;
            }
            left = self.freed.wait(left).expect("budget lock");
        }
        *left -= n;
        true
    }
    fn give(&self, n: usize) {
        *self.budget.lock().expect("budget lock") += n;
        self.freed.notify_all();
    }
}

/// packers: up to MAX_PACKERS, leaving a CPU to the node's apps.
fn packers() -> usize {
    let n = std::thread::available_parallelism().map_or(1, |n| n.get());
    n.saturating_sub(1).clamp(1, MAX_PACKERS)
}

impl Repo {
    /// Open: the repository at root, made when the bucket has none there.
    pub fn open(b: &Arc<Bucket>, root: &str, secret: &[u8]) -> Result<Repo, String> {
        let mut conn = b.conn();
        let key = format!("{root}{CONFIG_KEY}");
        let k = match conn.get(&key, MAX_CONFIG) {
            Err(S3Error::NotExist) => {
                let id = random(16)?;
                let k = Keys::derive(secret, &id)?;
                let data = format!(
                    "{{\"version\":{REPO_VERSION},\"id\":\"{}\",\"check\":\"{}\"}}",
                    hex(&id),
                    k.check
                );
                put(&mut conn, &key, data.as_bytes())?;
                k
            }
            Err(e) => return Err(e.text()),
            Ok(b) => {
                let damaged = || "the backup repository's config is damaged".to_string();
                let cfg: RepoConfig = serde_json::from_slice(&b).map_err(|_| damaged())?;
                let version = cfg.version.unwrap_or(0);
                if version != REPO_VERSION {
                    return Err(format!(
                        "the backup repository has version {version}; this Armada reads version {REPO_VERSION}"
                    ));
                }
                let id = unhex(cfg.id.as_deref().unwrap_or(""))
                    .filter(|id| id.len() == 16)
                    .ok_or_else(damaged)?;
                let k = Keys::derive(secret, &id)?;
                if k.check != cfg.check.unwrap_or_default() {
                    return Err(
                        "the backup key does not match the one this repository's backups were made with"
                            .into(),
                    );
                }
                k
            }
        };
        Ok(Repo {
            b: b.clone(),
            conn,
            root: root.to_string(),
            k: Arc::new(k),
        })
    }

    fn chunk_key(&self, id: &str) -> String {
        format!("{}{CHUNKS_DIR}{}/{id}", self.root, &id[..2])
    }

    /// Backup: a snapshot of dir.
    pub fn backup(
        &mut self,
        dir: &[u8],
        node: &str,
        now: Instant,
    ) -> Result<(Snapshot, Stats), Failure> {
        let mut have: HashSet<String> = HashSet::new();
        self.conn
            .list(&format!("{}{CHUNKS_DIR}", self.root), &mut |o| {
                let id = base(&o.key);
                if chunk_name(id) {
                    have.insert(id.to_string());
                }
                Ok(())
            })?;
        let shared = Arc::new(Shared {
            err: Mutex::new(None),
            budget: Mutex::new(UPLOAD_BYTES),
            freed: Condvar::new(),
        });
        // Uploaders, each with its own connection.
        let (up_tx, up_rx) = sync_channel::<(String, Vec<u8>, usize)>(UPLOADS);
        let up_rx = Arc::new(Mutex::new(up_rx));
        let mut uploaders = Vec::new();
        for _ in 0..UPLOADS {
            let (rx, sh, mut conn) = (up_rx.clone(), shared.clone(), self.b.conn());
            uploaders.push(std::thread::spawn(move || {
                loop {
                    let job = rx.lock().expect("upload queue").recv();
                    let Ok((key, data, size)) = job else {
                        return;
                    };
                    if sh.failed().is_none()
                        && let Err(e) = put(&mut conn, &key, &data)
                    {
                        sh.fail(e);
                    }
                    sh.give(size);
                }
            }));
        }
        // Packers: compress and seal.
        let (pk_tx, pk_rx) = sync_channel::<(String, Vec<u8>)>(0);
        let pk_rx = Arc::new(Mutex::new(pk_rx));
        let uploaded = Arc::new(Mutex::new(0i64));
        let mut packs = Vec::new();
        for _ in 0..packers() {
            let (rx, sh, k, tx, up) = (
                pk_rx.clone(),
                shared.clone(),
                self.k.clone(),
                up_tx.clone(),
                uploaded.clone(),
            );
            packs.push(std::thread::spawn(move || {
                loop {
                    let job = rx.lock().expect("pack queue").recv();
                    let Ok((key, chunk)) = job else {
                        return;
                    };
                    if sh.failed().is_some() {
                        continue;
                    }
                    let sealed = match k.seal(&key, &zstd(&chunk)) {
                        Ok(s) => s,
                        Err(e) => {
                            sh.fail(e);
                            continue;
                        }
                    };
                    *up.lock().expect("uploaded") += sealed.len() as i64;
                    let size = sealed.len().min(UPLOAD_BYTES);
                    if !sh.take(size) {
                        continue;
                    }
                    if tx.send((key, sealed, size)).is_err() {
                        sh.give(size);
                    }
                }
            }));
        }
        drop(up_tx);

        let mut st = Stats::default();
        let mut files = 0i64;
        let mut bytes = 0i64;
        let mut entries: Vec<Entry> = Vec::new();
        let walked = self.walk(
            dir,
            &shared,
            &pk_tx,
            &mut have,
            &mut st,
            &mut files,
            &mut bytes,
            &mut entries,
        );
        drop(pk_tx);
        for p in packs {
            let _ = p.join();
        }
        for u in uploaders {
            let _ = u.join();
        }
        st.uploaded = *uploaded.lock().expect("uploaded");
        let walked = match (walked, shared.failed()) {
            (Err(e), _) => Err(e),
            (Ok(()), Some(e)) => Err(Failure::from(e)),
            (Ok(()), None) => Ok(()),
        };
        if let Err(e) = walked {
            return Err(Failure {
                text: format!("back up the volume: {}", e.text),
                changed: e.changed,
            });
        }
        let raw = manifest_json(now, node, files, bytes, &entries);
        let id = format!("{}-{}", now.snapshot_time(), hex(&random(4)?));
        let key = format!("{}{SNAPSHOTS_DIR}{id}", self.root);
        let sealed = self.k.seal(&key, &zstd(raw.as_bytes()))?;
        put(&mut self.conn, &key, &sealed)?;
        st.uploaded += sealed.len() as i64;
        Ok((
            Snapshot {
                id,
                time: now,
                files,
                bytes,
                node: node.to_string(),
            },
            st,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn walk(
        &self,
        dir: &[u8],
        shared: &Shared,
        pk_tx: &SyncSender<(String, Vec<u8>)>,
        have: &mut HashSet<String>,
        st: &mut Stats,
        files: &mut i64,
        bytes: &mut i64,
        entries: &mut Vec<Entry>,
    ) -> Result<(), Failure> {
        let root =
            Root::open(dir).map_err(|e| Failure::from(crate::volume::path_err("open", dir, e)))?;
        root.probe()?;
        let mut buf = Vec::new();
        walk::walk(&root, &mut |p, v| -> Result<(), Failure> {
            let st_ = v.map_err(entry_failure)?;
            if let Some(e) = shared.failed() {
                return Err(Failure::from(e));
            }
            let bit = |unix: u32, go: u32| if st_.mode & unix != 0 { go } else { 0 };
            let mut e = Entry {
                p: p.to_vec(),
                t: b'd',
                m: (st_.mode & 0o777)
                    | bit(0o1000, MODE_STICKY)
                    | bit(0o2000, MODE_SETGID)
                    | bit(0o4000, MODE_SETUID),
                u: st_.uid,
                g: st_.gid,
                mt: i128::from(st_.mtime) * 1_000_000_000 + i128::from(st_.mtime_nsec),
                s: 0,
                l: Vec::new(),
                c: Vec::new(),
            };
            if st_.is_dir() {
            } else if st_.is_link() {
                e.t = b'l';
                e.l = root
                    .readlink(p)
                    .map_err(|f| entry_failure(EntryError::new(p, f)))?;
            } else if st_.is_reg() {
                e.t = b'f';
                let fd = root
                    .open_same(p, st_, false)
                    .map_err(|f| entry_failure(EntryError::new(p, f)))?;
                let mut c = Chunker::new(FdReader(&fd), &self.k.gear, std::mem::take(&mut buf));
                loop {
                    let chunk = match c.next_chunk() {
                        Ok(Some(ch)) => ch,
                        Ok(None) => break,
                        Err(err) => {
                            let n = err.raw_os_error().unwrap_or(libc::EIO);
                            let name = [dir, b"/", p].concat();
                            return Err(Failure::from(format!(
                                "read {}: read {}: {}",
                                quote(p),
                                show(&name),
                                errno::text(n)
                            )));
                        }
                    };
                    let id = self.k.chunk_id(&chunk);
                    e.s += chunk.len() as i64;
                    let fresh = have.insert(id.clone());
                    e.c.push(id.clone());
                    if !fresh {
                        continue;
                    }
                    st.new_bytes += chunk.len() as i64;
                    if pk_tx.send((self.chunk_key(&id), chunk)).is_err() {
                        return Err(Failure::from(
                            shared.failed().unwrap_or_else(|| "backup stopped".into()),
                        ));
                    }
                }
                buf = c.into_buf();
                *files += 1;
                *bytes += e.s;
            } else {
                return Ok(()); // sockets, devices, and pipes
            }
            entries.push(e);
            Ok(())
        })
    }

    /// Snapshots: oldest first, IDs and times only.
    pub fn snapshots(&mut self) -> Result<Vec<(String, Instant)>, String> {
        let dir = format!("{}{SNAPSHOTS_DIR}", self.root);
        let mut out = Vec::new();
        let res = self.conn.list(&dir, &mut |o| {
            let id = base(&o.key);
            if o.key != format!("{dir}{id}") || !snapshot_name(id) {
                return Ok(());
            }
            if let Some(t) = gotime::parse_snapshot_time(&id[..20]) {
                out.push((id.to_string(), t));
            }
            Ok(())
        });
        out.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        res.map(|()| out)
    }

    /// Latest.
    pub fn latest(&mut self) -> Result<String, String> {
        let s = self.snapshots()?;
        match s.last() {
            Some((id, _)) => Ok(id.clone()),
            None => Err("there are no backups yet: object does not exist".into()),
        }
    }

    fn manifest(&mut self, id: &str) -> Result<Manifest, String> {
        if !snapshot_name(id) {
            return Err(format!("invalid backup ID {}", quote(id.as_bytes())));
        }
        let key = format!("{}{SNAPSHOTS_DIR}{id}", self.root);
        let sealed = match self.conn.get(&key, MAX_MANIFEST) {
            Err(S3Error::NotExist) => {
                return Err(format!(
                    "backup {}: object does not exist",
                    quote(id.as_bytes())
                ));
            }
            Err(e) => return Err(e.text()),
            Ok(b) => b,
        };
        let z = self.k.open(&key, sealed)?;
        let raw = unzstd(&z, MAX_MANIFEST).map_err(|()| ERR_SEALED.to_string())?;
        serde_json::from_slice(&raw).map_err(|_| ERR_SEALED.to_string())
    }

    /// Restore of snapshot id into the restore's writer.
    pub fn restore(&mut self, id: &str, w: &mut Writer) -> Result<Snapshot, String> {
        let m = self.manifest(id)?;
        let snap = m.snapshot(id)?;
        let entries = m.entries.unwrap_or_default();
        let mut refs = Vec::new();
        for e in &entries {
            if e.t.as_deref() == Some("f") {
                let size = e.s.unwrap_or(0).clamp(0, MAX_CHUNK as i64) as usize + (1 << 10);
                for c in e.c.iter().flatten() {
                    refs.push((c.clone(), size));
                }
            }
        }
        let f = Fetcher::start(self, refs);
        let res = (|| {
            for e in &entries {
                if super::stopped() {
                    return Err("context canceled".to_string());
                }
                let p = e.path()?;
                clean_path(&p)?;
                let typ = match e.t.as_deref() {
                    Some(t) if t.len() == 1 => t.as_bytes()[0],
                    _ => 0,
                };
                let mode = e.m.unwrap_or(0);
                let bit = |go: u32, unix: u32| if mode & go != 0 { unix } else { 0 };
                let re = RestoreEntry {
                    name: p,
                    typ,
                    // The writer keeps setuid and setgid only as root.
                    mode: (mode & 0o777)
                        | bit(MODE_STICKY, 0o1000)
                        | bit(MODE_SETGID, 0o2000)
                        | bit(MODE_SETUID, 0o4000),
                    uid: e.u.unwrap_or(0),
                    gid: e.g.unwrap_or(0),
                    mtime: Some(e.time()),
                    link: e.link()?,
                    size: e.s.unwrap_or(0),
                };
                let n = if typ == b'f' {
                    e.c.as_ref().map_or(0, Vec::len)
                } else {
                    0
                };
                let mut cs = ChunkStream {
                    f: &f,
                    left: n,
                    buf: Vec::new(),
                    at: 0,
                };
                let r = w.write(&re, &mut cs);
                cs.skip();
                r?;
            }
            Ok(())
        })();
        f.stop();
        res.map(|()| snap)
    }

    /// Prune.
    pub fn prune(&mut self, keep: &Keep, zone: &Zone, now: Instant) -> (Usage, Option<String>) {
        let mut u = Usage::default();
        let snaps = match self.snapshots() {
            Ok(s) => s,
            Err(e) => return (u, Some(e)),
        };
        let times: Vec<Instant> = snaps.iter().map(|s| s.1).collect();
        let kept = gotime::select_kept(&times, keep, zone);
        let mut used: HashSet<String> = HashSet::new();
        let mut kept_ids: HashSet<String> = HashSet::new();
        for (i, (id, _)) in snaps.iter().enumerate() {
            if !kept[i] {
                let key = format!("{}{SNAPSHOTS_DIR}{id}", self.root);
                if let Err(e) = delete(&mut self.conn, &key) {
                    return (u, Some(e));
                }
                u.deleted_snapshots += 1;
                continue;
            }
            let m = match self.manifest(id) {
                Ok(m) => m,
                Err(e) => return (u, Some(format!("read backup {id}: {e}"))),
            };
            for e in m.entries.iter().flatten() {
                for c in e.c.iter().flatten() {
                    used.insert(c.clone());
                }
            }
            kept_ids.insert(id.clone());
            u.snapshots += 1;
        }
        let root = self.root.clone();
        let mut deleter = self.b.conn();
        let res = self.conn.list(&root, &mut |o| {
            let rel = o.key.strip_prefix(&root).unwrap_or(&o.key);
            if rel.starts_with(CHUNKS_DIR) {
                let id = base(rel);
                let older =
                    (now.nanos() - o.modified.nanos()) > i128::from(CHUNK_GRACE) * 1_000_000_000;
                if chunk_name(id) && !used.contains(id) && older {
                    delete(&mut deleter, &o.key)?;
                    u.deleted_chunks += 1;
                    return Ok(());
                }
            } else if rel.starts_with(SNAPSHOTS_DIR) && !kept_ids.contains(base(rel)) {
                return Ok(());
            }
            u.stored += o.size;
            Ok(())
        });
        (u, res.err())
    }
}

fn entry_failure(e: EntryError) -> Failure {
    Failure {
        text: e.text(),
        changed: e.changed(),
    }
}

/// CleanPath, of the path's bytes.
fn clean_path(p: &[u8]) -> Result<(), String> {
    if p == b"." {
        return Ok(());
    }
    let clean = crate::runtime::image::unpack::clean(p);
    if p.is_empty()
        || p.len() > 4096
        || p.contains(&0)
        || p.starts_with(b"/")
        || clean != p
        || p == b".."
        || p.starts_with(b"../")
    {
        return Err(format!("backup entry {} is outside the volume", quote(p)));
    }
    Ok(())
}

/// A descriptor read as a file.
struct FdReader<'a>(&'a OwnedFd);

impl Read for FdReader<'_> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        loop {
            // SAFETY: read into the buffer given, of its length.
            let n = unsafe { libc::read(self.0.as_raw_fd(), b.as_mut_ptr().cast(), b.len()) };
            if n >= 0 {
                return Ok(n as usize);
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
}

type Fetched = Arc<(Mutex<Option<Result<Vec<u8>, String>>>, Condvar)>;

/// fetcher: a restore's chunks read ahead, many at a time within
/// FETCH_BYTES, handed over in order.
struct Fetcher {
    order: Mutex<Receiver<(Fetched, usize)>>,
    budget: Arc<(Mutex<(usize, bool)>, Condvar)>,
    threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
}

impl Fetcher {
    fn start(repo: &Repo, refs: Vec<(String, usize)>) -> Fetcher {
        let (order_tx, order_rx) = sync_channel::<(Fetched, usize)>(FETCHES);
        let (job_tx, job_rx) = sync_channel::<(String, Fetched)>(FETCHES);
        let job_rx = Arc::new(Mutex::new(job_rx));
        let budget = Arc::new((Mutex::new((FETCH_BYTES, false)), Condvar::new()));
        let mut threads = Vec::new();
        for _ in 0..FETCHES {
            let (rx, mut conn, k, root, budget) = (
                job_rx.clone(),
                repo.b.conn(),
                repo.k.clone(),
                repo.root.clone(),
                budget.clone(),
            );
            threads.push(std::thread::spawn(move || {
                loop {
                    let job = rx.lock().expect("fetch queue").recv();
                    let Ok((id, slot)) = job else {
                        return;
                    };
                    let got = if budget.0.lock().expect("budget").1 {
                        Err("restore stopped".to_string())
                    } else {
                        fetch_chunk(&mut conn, &k, &root, &id)
                    };
                    let (m, cv) = &*slot;
                    *m.lock().expect("slot") = Some(got);
                    cv.notify_all();
                }
            }));
        }
        let b2 = budget.clone();
        threads.push(std::thread::spawn(move || {
            for (id, size) in refs {
                let size = size.min(FETCH_BYTES);
                {
                    let (m, cv) = &*b2;
                    let mut g = m.lock().expect("budget");
                    while g.0 < size && !g.1 {
                        g = cv.wait(g).expect("budget");
                    }
                    if g.1 {
                        return;
                    }
                    g.0 -= size;
                }
                let slot: Fetched = Arc::new((Mutex::new(None), Condvar::new()));
                if order_tx.send((slot.clone(), size)).is_err() {
                    return;
                }
                if job_tx.send((id, slot)).is_err() {
                    return;
                }
            }
        }));
        Fetcher {
            order: Mutex::new(order_rx),
            budget,
            threads: Mutex::new(threads),
        }
    }

    fn next(&self) -> Result<Vec<u8>, String> {
        let Ok((slot, size)) = self.order.lock().expect("order").recv() else {
            return Err("restore stopped".into());
        };
        let (m, cv) = &*slot;
        let mut g = m.lock().expect("slot");
        while g.is_none() {
            g = cv.wait(g).expect("slot");
        }
        let got = g.take().expect("filled");
        let (bm, bcv) = &*self.budget;
        bm.lock().expect("budget").0 += size;
        bcv.notify_all();
        got
    }

    fn stop(self) {
        {
            let (bm, bcv) = &*self.budget;
            bm.lock().expect("budget").1 = true;
            bcv.notify_all();
        }
        // Dropping the order queue ends the producer; the workers end with
        // their queue.
        drop(self.order);
        for t in self.threads.into_inner().expect("threads") {
            let _ = t.join();
        }
    }
}

/// fetchChunk: read, opened, and checked against its name.
fn fetch_chunk(conn: &mut Conn, k: &Keys, root: &str, id: &str) -> Result<Vec<u8>, String> {
    if !chunk_name(id) {
        return Err(ERR_SEALED.into());
    }
    let key = format!("{root}{CHUNKS_DIR}{}/{id}", &id[..2]);
    let sealed = match conn.get(&key, MAX_SEALED_CHUNK) {
        Err(S3Error::NotExist) => {
            return Err("a chunk of the backup is missing from the bucket".into());
        }
        Err(e) => return Err(e.text()),
        Ok(b) => b,
    };
    let z = k.open(&key, sealed)?;
    let plain = unzstd(&z, MAX_CHUNK).map_err(|()| ERR_SEALED.to_string())?;
    if k.chunk_id(&plain) != id {
        return Err(ERR_SEALED.into());
    }
    Ok(plain)
}

/// chunkStream: a file's chunks in order.
struct ChunkStream<'a> {
    f: &'a Fetcher,
    left: usize,
    buf: Vec<u8>,
    at: usize,
}

impl Read for ChunkStream<'_> {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        while self.at == self.buf.len() {
            if self.left == 0 {
                return Ok(0);
            }
            self.left -= 1;
            match self.f.next() {
                Ok(b) => {
                    self.buf = b;
                    self.at = 0;
                }
                Err(e) => {
                    self.left = 0;
                    return Err(io::Error::other(e));
                }
            }
        }
        let n = p.len().min(self.buf.len() - self.at);
        p[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

impl ChunkStream<'_> {
    /// skip: the chunks write left unread.
    fn skip(&mut self) {
        while self.left > 0 {
            self.left -= 1;
            let _ = self.f.next();
        }
    }
}

/// replaceDir with a snapshot's entries.
pub fn restore_into(repo: &mut Repo, dir: &[u8], id: &str) -> Result<Snapshot, String> {
    let mut snap = None;
    restore::replace_dir(dir, restore::restore_space(), |w| {
        snap = Some(repo.restore(id, w)?);
        Ok(())
    })?;
    snap.ok_or_else(|| "restore: no snapshot".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_as_go() {
        assert!(snapshot_name("20231114T221320.123Z-0a1b2c3d"));
        assert!(!snapshot_name("20231114T221320.123Z-0A1b2c3d"));
        assert!(chunk_name(&"a".repeat(64)));
        assert_eq!(base("a/b/"), "b");
        assert!(clean_path(b"a/b").is_ok());
        assert!(clean_path(b"a\xff/b").is_ok());
        assert_eq!(
            clean_path(b"a/../b").unwrap_err(),
            "backup entry \"a/../b\" is outside the volume"
        );
        assert!(clean_path(b"/a").is_err());
    }

    #[test]
    fn keeps_what_go_loses() {
        // 2300-01-01: past what 64 bits of nanoseconds hold.
        let future = 10_413_792_000i128 * 1_000_000_000 + 7;
        let e = Entry {
            p: b"bad\xff".to_vec(),
            t: b'l',
            m: 0o755 | MODE_SETUID | MODE_SETGID,
            u: 1,
            g: 2,
            mt: future,
            s: 0,
            l: b"to\xfe".to_vec(),
            c: Vec::new(),
        };
        let json = manifest_json(Instant { sec: 0, nsec: 0 }, "n1", 0, 0, &[e]);
        assert!(
            json.contains(&format!(
                "{{\"p\":\"bad\\ufffd\",\"pb\":\"YmFk/w==\",\"t\":\"l\",\"m\":{},\"u\":1,\"g\":2,\"mt\":{},\"ms\":10413792000,\"mn\":7,\"l\":\"to\\ufffd\",\"lb\":\"dG/+\"}}",
                0o755 | MODE_SETUID | MODE_SETGID,
                future as i64
            )),
            "{json}"
        );
        let m: Manifest = serde_json::from_str(&json).unwrap();
        let e = &m.entries.unwrap()[0];
        assert_eq!(e.path().unwrap(), b"bad\xff");
        assert_eq!(e.link().unwrap(), b"to\xfe");
        assert_eq!(e.time(), future);
        // What Go writes: no extra fields.
        let m: Manifest =
            serde_json::from_str(r#"{"entries":[{"p":"a�","t":"f","m":420,"mt":-5}]}"#).unwrap();
        let e = &m.entries.unwrap()[0];
        assert_eq!(e.path().unwrap(), "a\u{fffd}".as_bytes());
        assert_eq!(e.time(), -5);
        let m: Manifest = serde_json::from_str(r#"{"entries":[{"pb":"%%"}]}"#).unwrap();
        assert!(m.entries.unwrap()[0].path().is_err());
    }

    #[test]
    fn writes_manifests_go_reads() {
        let e = Entry {
            p: b"a<b".to_vec(),
            t: b'f',
            m: 0o644 | 1 << 20,
            u: 1,
            g: 2,
            mt: 5,
            s: 3,
            l: Vec::new(),
            c: vec!["ab".into()],
        };
        let t = Instant { sec: 0, nsec: 5 };
        assert_eq!(
            manifest_json(t, "n1", 1, 3, &[e]),
            "{\"version\":1,\"time\":\"1970-01-01T00:00:00.000000005Z\",\"node\":\"n1\",\"files\":1,\"bytes\":3,\"entries\":[{\"p\":\"a\\u003cb\",\"t\":\"f\",\"m\":1048996,\"u\":1,\"g\":2,\"mt\":5,\"s\":3,\"c\":[\"ab\"]}]}"
        );
        // Go's decoder refuses a window past its memory bound, as this does.
        let z = zstd(b"hello hello hello hello");
        assert_eq!(unzstd(&z, 1 << 20).unwrap(), b"hello hello hello hello");
        assert!(unzstd(&z, 100).is_err());
        let big = vec![7u8; 200 << 10];
        assert!(unzstd(&zstd(&big), 150 << 10).is_err());
        assert_eq!(unzstd(&zstd(&big), 200 << 10).unwrap(), big);
    }
}

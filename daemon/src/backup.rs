//! Archives of a control plane: a snapshot of its
//! etcd keyspace, the secrets master key, the cluster CA, the server
//! certificate, and the embedded agent's identity, with a manifest of
//! their SHA-256s first. The layout, the manifest, the file modes, the
//! limits, and every check of a restore are fixed, so an archive any
//! release wrote restores on another.
//!
//! A restore treats the archive as untrusted input: only known file names
//! are extracted, sizes are capped, every file is checked against the
//! manifest, and the result is verified (in a scratch member of the
//! pack's etcd, state.rs) before it replaces anything.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use armada_pki::{Ca, ExtKeyUsage, parse_cert_pem};
use armada_store::client::Client;
use sha2::{Digest, Sha256};

use crate::manifest::{Created, Manifest};
use crate::state::{self, Programs};
use crate::{netutil, pack};

/// The data directory's files a backup covers.
pub const FILE_STATE: &str = "etcd.snapshot";
/// The state of a server whose store is armada-kv (ADR 0057), in place of
/// FILE_STATE.
pub const FILE_KV_STATE: &str = "kv.snapshot";
/// What a manifest of an armada-kv backup names as its state.
pub const STATE_KV: &str = "kv";
pub const FILE_MASTER_KEY: &str = "master.key";
pub const FILE_CA_CERT: &str = "ca.crt";
pub const FILE_CA_KEY: &str = "ca.key";
pub const FILE_SERVER_CERT: &str = "server.crt";
pub const FILE_SERVER_KEY: &str = "server.key";
pub const FILE_NODE_CERT: &str = "node.crt";
pub const FILE_NODE_KEY: &str = "node.key";
pub const FILE_AGENT: &str = "agent.json";
pub const DIR_ETCD: &str = "etcd";

/// Where the control plane's records live in etcd.
pub const ETCD_PREFIX: &str = "/armada/";
pub const META_MASTER_KEY: &str = "master_key_id";
const MANIFEST_NAME: &str = "manifest.json";
/// format 3: ACME certificates live in etcd, so in FILE_STATE.
const FORMAT: i64 = 3;
/// format 4: the state is armada-kv's snapshot (FILE_KV_STATE), and the
/// manifest says so (state "kv"); a release that knows format 3 only
/// refuses it.
const FORMAT_KV: i64 = 4;

/// Required files are in every backup; Optional ones when they exist.
pub const REQUIRED: [&str; 6] = [
    FILE_STATE,
    FILE_MASTER_KEY,
    FILE_CA_CERT,
    FILE_CA_KEY,
    FILE_SERVER_CERT,
    FILE_SERVER_KEY,
];
pub const OPTIONAL: [&str; 3] = [FILE_NODE_CERT, FILE_NODE_KEY, FILE_AGENT];

/// What a restore accepts.
const MAX_STATE_SIZE: i64 = 2 << 30;
const MAX_FILE_SIZE: i64 = 1 << 20;
const MAX_ENTRIES: usize = 10_000;
const MAX_TOTAL_SIZE: i64 = 4 << 30;

fn errno(op: &str, p: &Path, e: &io::Error) -> String {
    format!("{op} {}: {}", p.display(), armada_fsutil::errno_text(e))
}

/// A directory and a plain name joined, cleaned.
fn join(dir: &Path, name: &str) -> PathBuf {
    PathBuf::from(crate::gopath::join(&dir.to_string_lossy(), name))
}

fn check_private(p: &Path) -> Result<(), String> {
    armada_fsutil::check_private(p).map_err(|e| e.to_string())
}

fn read_private(p: &Path) -> Result<Vec<u8>, String> {
    armada_fsutil::read_private_file(p).map_err(|e| e.to_string())
}

/// A backup before it is written out: its manifest, where each file is
/// read from, and the temporary directory holding the snapshot.
pub struct Staged {
    pub m: Manifest,
    files: Vec<(String, PathBuf)>,
    tmp: PathBuf,
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.tmp);
    }
}

/// The control plane node a server certificate is for.
fn server_name(cert_pem: &[u8]) -> Result<String, String> {
    let leaf = parse_cert_pem(cert_pem).map_err(|e| format!("server certificate: {e}"))?;
    match leaf.identity() {
        Ok(id) if id.kind == armada_pki::KIND_SERVER => Ok(id.name),
        _ => Err("server certificate has no server identity".to_string()),
    }
}

/// prepare: a snapshot of the state taken through c into a temporary
/// directory inside data_dir, checked the way a restore checks it, and
/// every file hashed.
pub async fn prepare(data_dir: &str, c: &Client) -> Result<Staged, String> {
    let dd = Path::new(data_dir);
    // A server whose state is in armada-kv (ADR 0057) backs up its
    // snapshot, checked in a scratch member in this process.
    let kv = crate::kvmember::is_kv(data_dir);
    check_private(dd)?;
    for name in &REQUIRED[1..] {
        let p = join(dd, name);
        if let Err(e) = fs::metadata(&p) {
            return Err(format!(
                "{data_dir} is not a control plane data directory: {}",
                errno("stat", &p, &e)
            ));
        }
    }
    let tmp = pack::temp_dir(dd, ".backup-")?;
    let mut st = Staged {
        m: Manifest::default(),
        files: Vec::new(),
        tmp: tmp.clone(),
    };
    let state_file = if kv { FILE_KV_STATE } else { FILE_STATE };
    let snap = join(&tmp, state_file);
    write_snapshot(c, &snap).await?;
    let ca_pem = read_private(&join(dd, FILE_CA_CERT))?;
    let ca_key = read_private(&join(dd, FILE_CA_KEY))?;
    let srv = read_private(&join(dd, FILE_SERVER_CERT))?;
    let ca = Ca::load(&ca_pem, &ca_key).map_err(|e| e.to_string())?;
    let name = server_name(&srv)?;
    // The snapshot is checked the way a restore checks it, so a backup
    // that cannot be restored fails now rather than when it is needed.
    let info = if kv {
        state::inspect_kv(&snap, &tmp, &name).await
    } else {
        let programs = Programs::find(&tmp).map_err(|e| format!("verify snapshot: {e}"))?;
        state::inspect(&programs, &snap, &tmp, &name).await
    }
    .map_err(|e| format!("verify snapshot: {e}"))?;

    st.files.push((state_file.to_string(), snap));
    for name in REQUIRED[1..].iter().chain(OPTIONAL.iter()) {
        let src = join(dd, name);
        if let Err(e) = fs::symlink_metadata(&src)
            && e.kind() == io::ErrorKind::NotFound
        {
            continue;
        }
        st.files.push((name.to_string(), src));
    }
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let mut files = BTreeMap::new();
    for (name, src) in &st.files {
        files.insert(name.clone(), hash_file(src)?);
    }
    st.m = Manifest {
        format: if kv { FORMAT_KV } else { FORMAT },
        state: if kv {
            STATE_KV.to_string()
        } else {
            String::new()
        },
        armada_version: armada_client::commands::version::get().version.to_string(),
        created: Created::utc(now),
        schema: info.schema,
        listen: info.listen,
        master_key_id: info.master_key_id,
        ca_fingerprint: ca.cert.fingerprint(),
        files: Some(files),
    };
    Ok(st)
}

/// Stage: a backup's files written into a directory of their own (the
/// manifest and every file, each 0600), for the control plane's scheduled
/// backups to a bucket (ADR 0051). The directory goes when the returned
/// Staged is dropped.
pub async fn stage(data_dir: &str, c: &Client) -> Result<(PathBuf, Staged), String> {
    let st = prepare(data_dir, c).await?;
    let dir = join(&st.tmp, "files");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| errno("mkdir", &dir, &e))?;
    let mp = join(&dir, MANIFEST_NAME);
    write_new(&mp, &mut st.m.to_json().as_bytes(), None)?;
    let sums = st.m.files.clone().unwrap_or_default();
    for (name, src) in &st.files {
        let mut f = fs::File::open(src).map_err(|e| errno("open", src, &e))?;
        let mut h = Sha256::new();
        write_new(&join(&dir, name), &mut f, Some(&mut h))?;
        if pack::hex(&h.finalize()) != sums.get(name).cloned().unwrap_or_default() {
            return Err(format!(
                "{name} changed while the backup was written; run it again"
            ));
        }
    }
    Ok((dir, st))
}

/// A new file (0600) with what r holds, hashed into h.
fn write_new(dst: &Path, r: &mut dyn Read, mut h: Option<&mut Sha256>) -> Result<(), String> {
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dst)
        .map_err(|e| errno("open", dst, &e))?;
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = r.read(&mut buf).map_err(|e| errno("read", dst, &e))?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])
            .map_err(|e| errno("write", dst, &e))?;
        if let Some(h) = h.as_deref_mut() {
            h.update(&buf[..n]);
        }
    }
    Ok(())
}

/// The member's snapshot of the keyspace (etcd's, or armada-kv's in its
/// own format; each ending with its SHA-256, which a restore verifies)
/// into a new file.
async fn write_snapshot(c: &Client, dst: &Path) -> Result<(), String> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dst)
        .map_err(|e| errno("open", dst, &e))?;
    let mut stream = c
        .snapshot()
        .await
        .map_err(|e| format!("etcd snapshot: {e}"))?;
    loop {
        match stream.message().await {
            Ok(Some(r)) => f
                .write_all(&r.blob)
                .map_err(|e| format!("etcd snapshot: {}", errno("write", dst, &e)))?,
            Ok(None) => break,
            Err(e) => return Err(format!("etcd snapshot: {}", e.message())),
        }
    }
    f.sync_all().map_err(|e| errno("sync", dst, &e))
}

fn hash_file(p: &Path) -> Result<String, String> {
    check_private(p)?;
    let mut f = fs::File::open(p).map_err(|e| errno("open", p, &e))?;
    pack::sha256_reader(&mut f).map_err(|e| errno("read", p, &e))
}

/// Create: the staged backup written to w as a gzipped tar, the manifest
/// first.
pub fn create(st: &Staged, w: &mut dyn Write) -> Result<(), String> {
    let mut gz = flate2::write::GzEncoder::new(w, flate2::Compression::default());
    let mb = st.m.to_json();
    write_entry(
        &mut gz,
        MANIFEST_NAME,
        mb.len() as i64,
        &mut mb.as_bytes(),
        None,
    )?;
    let sums = st.m.files.clone().unwrap_or_default();
    for (name, src) in &st.files {
        let mut f = fs::File::open(src).map_err(|e| errno("open", src, &e))?;
        let size = f.metadata().map_err(|e| errno("stat", src, &e))?.len() as i64;
        let mut h = Sha256::new();
        write_entry(&mut gz, name, size, &mut f, Some(&mut h))?;
        if pack::hex(&h.finalize()) != sums.get(name).cloned().unwrap_or_default() {
            return Err(format!(
                "{name} changed while the backup was written; run it again"
            ));
        }
    }
    gz.write_all(&[0u8; 1024]).map_err(|e| e.to_string())?;
    gz.finish().map_err(|e| e.to_string())?;
    Ok(())
}

/// The octal field of a USTAR header: digits, then NUL.
fn octal(b: &mut [u8], v: i64) {
    let s = format!("{v:o}");
    let n = b.len() - 1;
    let s = format!("{}{s}", "0".repeat(n.saturating_sub(s.len())));
    b[..n].copy_from_slice(&s.as_bytes()[s.len() - n..]);
    b[n] = 0;
}

/// One regular file (mode 0600, the current second) with a plain USTAR
/// header (no PAX records needed), and its size bytes read from r.
fn write_entry(
    w: &mut dyn Write,
    name: &str,
    size: i64,
    r: &mut dyn Read,
    mut h: Option<&mut Sha256>,
) -> Result<(), String> {
    let mut b = [0u8; 512];
    b[..name.len()].copy_from_slice(name.as_bytes());
    octal(&mut b[100..108], 0o600);
    octal(&mut b[108..116], 0);
    octal(&mut b[116..124], 0);
    octal(&mut b[124..136], size);
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    octal(&mut b[136..148], now);
    b[156] = b'0';
    b[257..263].copy_from_slice(b"ustar\0");
    b[263..265].copy_from_slice(b"00");
    octal(&mut b[329..337], 0);
    octal(&mut b[337..345], 0);
    b[148..156].fill(b' ');
    let sum: i64 = b.iter().map(|&c| i64::from(c)).sum();
    octal(&mut b[148..155], sum);
    b[155] = b' ';
    w.write_all(&b).map_err(|e| e.to_string())?;
    let mut left = size;
    let mut buf = vec![0u8; 64 << 10];
    while left > 0 {
        let k = (left as usize).min(buf.len());
        let n = r.read(&mut buf[..k]).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("EOF".to_string());
        }
        if let Some(h) = h.as_deref_mut() {
            h.update(&buf[..n]);
        }
        w.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        left -= n as i64;
    }
    let pad = (512 - size % 512) % 512;
    w.write_all(&vec![0u8; pad as usize])
        .map_err(|e| e.to_string())
}

/// A restore handed the backup file by file: Add each,
/// then Finish. Nothing reaches the data directory unless all of it
/// verifies; what Finish did not use is removed when it is dropped.
pub struct Restorer {
    data_dir: PathBuf,
    tmp: Option<PathBuf>,
    m: Manifest,
    sums: BTreeMap<String, String>,
    total: i64,
    n: usize,
}

impl Drop for Restorer {
    fn drop(&mut self) {
        if let Some(t) = self.tmp.take() {
            let _ = fs::remove_dir_all(t);
        }
    }
}

/// The member a restore turns the snapshot into: its address (None: the
/// server certificate's) and peer port.
pub struct Member {
    pub addr: Option<IpAddr>,
    pub peer_port: u16,
}

const ENDED: &str = "the restore has ended";

impl Restorer {
    /// NewRestorer: a restore into data_dir, which must not exist or be
    /// empty.
    pub fn new(data_dir: &str) -> Result<Restorer, String> {
        let dd = PathBuf::from(crate::gopath::clean(data_dir));
        match fs::read_dir(&dd) {
            Ok(mut rd) => {
                if rd.next().is_some() {
                    return Err(format!(
                        "{} is not empty; move it aside first (restore never overwrites a data directory)",
                        dd.display()
                    ));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(errno("open", &dd, &e)),
        }
        let parent = PathBuf::from(crate::gopath::dir(&dd.to_string_lossy()));
        crate::gofs::mkdir_all(&parent, 0o755)?;
        let base = crate::gopath::base(&dd.to_string_lossy());
        let tmp = pack::temp_dir(&parent, &format!(".{base}.restore-"))?;
        if let Err(e) = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o700)) {
            let _ = fs::remove_dir_all(&tmp);
            return Err(errno("chmod", &tmp, &e));
        }
        Ok(Restorer {
            data_dir: dd,
            tmp: Some(tmp),
            m: Manifest::default(),
            sums: BTreeMap::new(),
            total: 0,
            n: 0,
        })
    }

    /// The parent of the data directory, where the programs go.
    fn parent(&self) -> PathBuf {
        PathBuf::from(crate::gopath::dir(&self.data_dir.to_string_lossy()))
    }

    /// Add: one file of the backup, size bytes read from r.
    pub fn add(&mut self, name: &str, size: i64, r: &mut dyn Read) -> Result<(), String> {
        let Some(tmp) = self.tmp.clone() else {
            return Err(ENDED.to_string());
        };
        self.n += 1;
        if self.n > MAX_ENTRIES {
            return Err("archive has too many entries".to_string());
        }
        if name == MANIFEST_NAME {
            if self.m.format != 0 {
                return Err(format!("duplicate entry {}", armada_spec::go::quote(name)));
            }
            if !(0..=MAX_FILE_SIZE).contains(&size) {
                return Err("not an Armada backup: the manifest is too large".to_string());
            }
            let mut b = Vec::new();
            r.take(size as u64)
                .read_to_end(&mut b)
                .map_err(|e| format!("manifest: {}", io_text(&e)))?;
            let m = Manifest::decode(&b).map_err(|e| format!("manifest: {e}"))?;
            if m.format != FORMAT && m.format != FORMAT_KV {
                return Err(format!(
                    "backup format {} is not supported (want {FORMAT} or {FORMAT_KV})",
                    m.format
                ));
            }
            let want = if m.format == FORMAT_KV { STATE_KV } else { "" };
            if m.state != want {
                return Err(format!(
                    "manifest: backup format {} cannot hold state {}",
                    m.format,
                    armada_spec::go::quote(&m.state)
                ));
            }
            self.m = m;
            return Ok(());
        }
        if !REQUIRED.contains(&name) && !OPTIONAL.contains(&name) && name != FILE_KV_STATE {
            return Err(format!(
                "unexpected entry {} in backup",
                armada_spec::go::quote(name)
            ));
        }
        if self.sums.contains_key(name) {
            return Err(format!("duplicate entry {}", armada_spec::go::quote(name)));
        }
        let limit = if name == FILE_STATE || name == FILE_KV_STATE {
            MAX_STATE_SIZE
        } else {
            MAX_FILE_SIZE
        };
        if !(0..=limit).contains(&size) {
            return Err(format!("{name} is too large ({size} bytes)"));
        }
        self.total += size;
        if self.total > MAX_TOTAL_SIZE {
            return Err("archive is too large".to_string());
        }
        let sum = write_file(&tmp, name, r, size)?;
        self.sums.insert(name.to_string(), sum);
        Ok(())
    }

    /// Finish: the files verified, the snapshot turned into the data of the
    /// member, and everything moved into the data directory.
    pub async fn finish(mut self, member: Member) -> Result<Manifest, String> {
        let Some(tmp) = self.tmp.clone() else {
            return Err(ENDED.to_string());
        };
        if self.m.format == 0 {
            return Err("not an Armada backup: no manifest".to_string());
        }
        let m = self.m.clone();
        let programs = verify(&self.parent(), &tmp, &m, &self.sums).await?;
        if m.state == STATE_KV {
            // A new single-member armada-kv store, laid out as a kv
            // server's member directory (ADR 0057).
            let snap = join(&tmp, FILE_KV_STATE);
            state::restore_kv(&snap, &join(&tmp, crate::agentconfig::DIR_KV))?;
            fs::remove_file(&snap).map_err(|e| errno("remove", &snap, &e))?;
            return self.place(tmp, m);
        }
        let Some(programs) = programs else {
            return Err("no etcd program to restore the snapshot with".to_string());
        };
        let srv = read_private(&join(&tmp, FILE_SERVER_CERT))?;
        let leaf = parse_cert_pem(&srv).map_err(|e| e.to_string())?;
        let name = match leaf.identity() {
            Ok(id) if id.kind == armada_pki::KIND_SERVER => id.name,
            _ => return Err("server certificate has no server identity".to_string()),
        };
        // The member listens on the server's private IP.
        let addr = member
            .addr
            .or_else(|| leaf.ip_addresses.first().map(netutil::unmap));
        state::restore(
            &programs,
            &join(&tmp, FILE_STATE),
            &join(&tmp, DIR_ETCD),
            &name,
            addr,
            member.peer_port,
        )?;
        let snap = join(&tmp, FILE_STATE);
        fs::remove_file(&snap).map_err(|e| errno("remove", &snap, &e))?;
        self.place(tmp, m)
    }

    /// The restored directory moved into place.
    fn place(&mut self, tmp: PathBuf, m: Manifest) -> Result<Manifest, String> {
        if let Err(e) = fs::remove_dir(&self.data_dir)
            && e.kind() != io::ErrorKind::NotFound
        {
            return Err(errno("remove", &self.data_dir, &e));
        }
        fs::rename(&tmp, &self.data_dir).map_err(|e| {
            format!(
                "rename {} {}: {}",
                tmp.display(),
                self.data_dir.display(),
                armada_fsutil::errno_text(&e)
            )
        })?;
        self.tmp = None;
        Ok(m)
    }
}

fn io_text(e: &io::Error) -> String {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        return "unexpected EOF".to_string();
    }
    match e.get_ref() {
        Some(inner) => inner.to_string(),
        None => armada_fsutil::errno_text(e),
    }
}

/// size bytes of r into a new file name below dir; its SHA-256.
fn write_file(dir: &Path, name: &str, r: &mut dyn Read, size: i64) -> Result<String, String> {
    let dst = join(dir, name);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&dst)
        .map_err(|e| errno("open", &dst, &e))?;
    let mut h = Sha256::new();
    let mut left = size;
    let mut buf = vec![0u8; 64 << 10];
    while left > 0 {
        let k = (left as usize).min(buf.len());
        let n = match r.read(&mut buf[..k]) {
            Ok(0) => return Err(format!("extract {name}: EOF")),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("extract {name}: {}", io_text(&e))),
        };
        h.update(&buf[..n]);
        f.write_all(&buf[..n])
            .map_err(|e| format!("extract {name}: {}", errno("write", &dst, &e)))?;
        left -= n as i64;
    }
    f.sync_all().ok();
    Ok(pack::hex(&h.finalize()))
}

/// verify: the extracted files against the manifest and each other; the
/// programs the snapshot was checked with (found below base), for the
/// restore.
async fn verify(
    base: &Path,
    dir: &Path,
    m: &Manifest,
    sums: &BTreeMap<String, String>,
) -> Result<Option<Programs>, String> {
    let files = m.files.clone().unwrap_or_default();
    for (name, want) in &files {
        match sums.get(name) {
            None => return Err(format!("{name} is listed in the manifest but missing")),
            Some(got) if got != want => {
                return Err(format!(
                    "{name} does not match its checksum; the archive is corrupt or was modified"
                ));
            }
            _ => {}
        }
    }
    for name in sums.keys() {
        if !files.contains_key(name) {
            return Err(format!("{name} is not listed in the manifest"));
        }
    }
    let kv = m.state == STATE_KV;
    let state_file = if kv { FILE_KV_STATE } else { FILE_STATE };
    for name in std::iter::once(state_file).chain(REQUIRED[1..].iter().copied()) {
        if !sums.contains_key(name) {
            return Err(format!("backup has no {name}"));
        }
    }
    let other = if kv { FILE_STATE } else { FILE_KV_STATE };
    if sums.contains_key(other) {
        return Err(format!("unexpected entry {other} in backup"));
    }
    if m.schema > armada_store::SCHEMA {
        return Err(format!(
            "the backup was made by a newer Armada (schema {}, this binary knows {}); restore it with that version",
            m.schema,
            armada_store::SCHEMA
        ));
    }
    let ca_pem = read_private(&join(dir, FILE_CA_CERT))?;
    let ca_key = read_private(&join(dir, FILE_CA_KEY))?;
    let ca = Ca::load(&ca_pem, &ca_key).map_err(|e| format!("cluster CA: {e}"))?;
    if !m.ca_fingerprint.is_empty() && ca.cert.fingerprint() != m.ca_fingerprint {
        return Err("cluster CA does not match the manifest".to_string());
    }
    let srv_cert = read_private(&join(dir, FILE_SERVER_CERT))?;
    let srv_key = read_private(&join(dir, FILE_SERVER_KEY))?;
    armada_client::dial::client_tls(&ca_pem, &srv_cert, &srv_key)
        .map_err(|e| format!("server certificate: {e}"))?;
    let leaf = parse_cert_pem(&srv_cert).map_err(|e| format!("server certificate: {e}"))?;
    leaf.verify(&ca.cert, None, ExtKeyUsage::Any, SystemTime::now())
        .map_err(|e| format!("server certificate is not signed by the cluster CA: {e}"))?;
    let name = server_name(&srv_cert)?;
    let (programs, info) = if kv {
        let info = state::inspect_kv(&join(dir, FILE_KV_STATE), dir, &name).await;
        (None, info)
    } else {
        let programs = Programs::find(base).map_err(|e| format!("state snapshot: {e}"))?;
        let info = state::inspect(&programs, &join(dir, FILE_STATE), dir, &name).await;
        (Some(programs), info)
    };
    let info = info.map_err(|e| format!("state snapshot: {e}"))?;
    if info.listen.is_empty() {
        return Err(format!(
            "the state has no control plane node {name}; not a backup of this server"
        ));
    }
    let keys = armada_secrets::load_key_file(&join(dir, FILE_MASTER_KEY))
        .map_err(|e| format!("master key: {e}"))?;
    if !info.master_key_id.is_empty() && info.master_key_id != keys.id() {
        return Err(format!(
            "master key (id {}) does not belong to this state (id {})",
            keys.id(),
            info.master_key_id
        ));
    }
    Ok(programs)
}

/// Restore: a gzipped tar archive read from r into data_dir.
pub async fn restore_archive(
    r: &mut dyn Read,
    data_dir: &str,
    member: Member,
) -> Result<Manifest, String> {
    let mut rs = Restorer::new(data_dir)?;
    let gz = armada_node::volume::gzip::Reader::new(io::BufReader::new(r))
        .map_err(|e| format!("not a backup archive: {}", gzip_text(&e)))?;
    let mut tr = armada_node::runtime::image::tar::Reader::new(gz);
    let mut n = 0;
    loop {
        let hdr = match tr.next() {
            Ok(None) => break,
            Ok(Some(h)) => h,
            Err(e) => return Err(format!("read archive: {e}")),
        };
        let name = String::from_utf8_lossy(&hdr.name).into_owned();
        // TypeRegA ('\0') reads as a regular file, or as a directory when
        // its name ends with a slash.
        let regular = hdr.typeflag == b'0' || (hdr.typeflag == 0 && !name.ends_with('/'));
        if n == 0 && (name != MANIFEST_NAME || !regular || hdr.size > MAX_FILE_SIZE) {
            return Err("not an Armada backup: the manifest must come first".to_string());
        }
        n += 1;
        if !regular {
            return Err(format!(
                "unexpected entry {}: only regular files are allowed",
                armada_spec::go::quote(&name)
            ));
        }
        rs.add(&name, hdr.size, &mut tr)?;
    }
    rs.finish(member).await
}

fn gzip_text(e: &io::Error) -> String {
    armada_node::volume::gzip::text(e)
}

#[cfg(test)]
mod kv_tests {
    //! Backups of a server whose state is in armada-kv (ADR 0057): taken
    //! from a member in this process, restored into a new single-member
    //! store laid out as a kv server's, and a damaged snapshot refused.

    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use armada_pki::{Ca, Identity, IssueRequest};

    use super::*;

    fn base(name: &str) -> PathBuf {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/tmp")
            .join(name);
        let _ = fs::remove_dir_all(&p);
        p
    }

    fn private_dir(p: &Path) {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(p)
            .unwrap();
    }

    /// A kv server's data directory (its keys and certificates, and kv/),
    /// and the master key's ID.
    fn data_dir(dd: &Path) -> String {
        private_dir(&dd.join("kv"));
        let ca = Ca::new("test").unwrap();
        let (cert, key) = ca
            .issue(&IssueRequest {
                identity: Identity::new("server", "s1"),
                dns_names: vec![armada_pki::SERVER_NAME.to_string()],
                ips: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))],
                server: true,
                client: true,
                validity: Duration::ZERO,
            })
            .unwrap();
        let write = |n: &str, b: &[u8]| {
            armada_fsutil::write_file_exclusive(&dd.join(n), b, 0o600).unwrap();
        };
        write(FILE_CA_CERT, &ca.cert_pem);
        write(FILE_CA_KEY, ca.key_pem().expose());
        write(FILE_SERVER_CERT, &cert);
        write(FILE_SERVER_KEY, key.expose());
        armada_secrets::generate_key_file(&dd.join(FILE_MASTER_KEY)).unwrap();
        armada_secrets::load_key_file(&dd.join(FILE_MASTER_KEY))
            .unwrap()
            .id()
            .to_string()
    }

    /// The server's member on a Unix socket, its state written.
    async fn member(dir: &Path, key_id: &str) -> (armada_kv::Node, Client) {
        let node = armada_kv::Node::open(dir, armada_kv::Options::default())
            .await
            .unwrap();
        let sock = dir.join("client.sock");
        {
            let (n, s) = (node.clone(), sock.clone());
            tokio::spawn(async move {
                let _ = armada_kv::serve_unix(n, &s, std::future::pending()).await;
            });
        }
        while !sock.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let c = Client::connect_unix(&sock).unwrap();
        loop {
            if c.status().await.is_ok_and(|s| s.leader != 0) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let st = armada_store::Etcd::new(c.clone(), ETCD_PREFIX)
            .await
            .unwrap();
        st.set_meta(META_MASTER_KEY, key_id).await.unwrap();
        st.set_meta("root_domain", "apps.example.com")
            .await
            .unwrap();
        st.upsert_server(&armada_store::Server {
            name: "s1".into(),
            private_ip: "10.0.0.5".into(),
            api_addr: "10.0.0.5:7443".into(),
            join_addr: String::new(),
            member_id: 0,
            schema: armada_store::SCHEMA,
            version: "test".into(),
            created_at: armada_spec::gotime::Time::zero(),
            kv_peer_url: String::new(),
        })
        .await
        .unwrap();
        (node, c)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn kv_backups_restore_into_a_kv_server() {
        let b = base("kv-backup");
        let dd = b.join("data");
        let key_id = data_dir(&dd);
        let (node, c) = member(&b.join("member"), &key_id).await;
        let dds = dd.to_string_lossy().into_owned();
        let staged = prepare(&dds, &c).await.unwrap();
        assert_eq!(staged.m.format, FORMAT_KV);
        assert_eq!(staged.m.state, STATE_KV);
        assert_eq!(staged.m.listen, "10.0.0.5:7443");
        assert_eq!(staged.m.master_key_id, key_id);
        let files = staged.m.files.clone().unwrap();
        assert!(files.contains_key(FILE_KV_STATE) && !files.contains_key(FILE_STATE));
        let mut archive = Vec::new();
        create(&staged, &mut archive).unwrap();
        drop(staged);
        node.close().await;

        let restored = b.join("restored");
        let m = restore_archive(
            &mut archive.as_slice(),
            &restored.to_string_lossy(),
            Member {
                addr: None,
                peer_port: 7446,
            },
        )
        .await
        .unwrap();
        assert_eq!(m.state, STATE_KV);
        let kv = restored.join(crate::agentconfig::DIR_KV);
        assert!(kv.join(armada_kv::node::DB_FILE).is_file());
        assert!(!restored.join(DIR_ETCD).exists());
        assert!(!restored.join(FILE_KV_STATE).exists());
        assert!(crate::kvmember::is_kv(&restored.to_string_lossy()));
        // The restored store holds the state, its member alone.
        let (node, c) = {
            let node = armada_kv::Node::open(&kv, armada_kv::Options::default())
                .await
                .unwrap();
            let sock = b.join("restored.sock");
            let (n, s) = (node.clone(), sock.clone());
            tokio::spawn(async move {
                let _ = armada_kv::serve_unix(n, &s, std::future::pending()).await;
            });
            while !sock.exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            (node, Client::connect_unix(&sock).unwrap())
        };
        let st = armada_store::Etcd::new(c, ETCD_PREFIX).await.unwrap();
        assert_eq!(
            st.get_meta("root_domain").await.unwrap(),
            "apps.example.com"
        );
        node.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_damaged_kv_snapshot_is_refused() {
        let b = base("kv-backup-damaged");
        let dd = b.join("data");
        let key_id = data_dir(&dd);
        let (node, c) = member(&b.join("member"), &key_id).await;
        let staged = prepare(&dd.to_string_lossy(), &c).await.unwrap();
        node.close().await;
        // The snapshot with one byte changed, and a manifest whose sums
        // match it: only the snapshot's own SHA-256 tells.
        let mut m = staged.m.clone();
        let mut sums = m.files.clone().unwrap();
        let mut rs = Restorer::new(&b.join("restored").to_string_lossy()).unwrap();
        for (name, src) in &staged.files {
            let mut body = fs::read(src).unwrap();
            if name == FILE_KV_STATE {
                let mid = body.len() / 2;
                body[mid] ^= 1;
                sums.insert(name.clone(), pack::hex(&Sha256::digest(&body)));
            }
            rs.add(name, body.len() as i64, &mut body.as_slice())
                .unwrap();
        }
        m.files = Some(sums);
        let mj = m.to_json();
        rs.add(MANIFEST_NAME, mj.len() as i64, &mut mj.as_bytes())
            .unwrap();
        let err = rs
            .finish(Member {
                addr: None,
                peer_port: 7446,
            })
            .await
            .err()
            .unwrap();
        assert!(err.contains("SHA-256"), "{err}");
        assert!(!b.join("restored").join("kv").exists());
        // A kv archive's manifest must say so, and the other way round.
        let mut wrong = staged.m.clone();
        wrong.state = String::new();
        let mut rs = Restorer::new(&b.join("restored2").to_string_lossy()).unwrap();
        let wj = wrong.to_json();
        let err = rs
            .add(MANIFEST_NAME, wj.len() as i64, &mut wj.as_bytes())
            .err()
            .unwrap();
        assert!(err.contains("cannot hold state"), "{err}");
    }
}

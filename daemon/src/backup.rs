//! Archives of a control plane (Go's internal/backup): a snapshot of its
//! etcd keyspace, the secrets master key, the cluster CA, the server
//! certificate, and the embedded agent's identity, with a manifest of
//! their SHA-256s first. The layout, the manifest, the file modes, the
//! limits, and every check of a restore are Go's, so an archive either
//! side wrote restores on the other.
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

/// The data directory's files a backup covers (Go's constants).
pub const FILE_STATE: &str = "etcd.snapshot";
pub const FILE_MASTER_KEY: &str = "master.key";
pub const FILE_CA_CERT: &str = "ca.crt";
pub const FILE_CA_KEY: &str = "ca.key";
pub const FILE_SERVER_CERT: &str = "server.crt";
pub const FILE_SERVER_KEY: &str = "server.key";
pub const FILE_NODE_CERT: &str = "node.crt";
pub const FILE_NODE_KEY: &str = "node.key";
pub const FILE_AGENT: &str = "agent.json";
pub const DIR_ETCD: &str = "etcd";

/// etcdPrefix: where the control plane's records live in etcd.
pub const ETCD_PREFIX: &str = "/armada/";
pub const META_MASTER_KEY: &str = "master_key_id";
const MANIFEST_NAME: &str = "manifest.json";
/// format 3: ACME certificates live in etcd, so in FILE_STATE.
const FORMAT: i64 = 3;

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

/// filepath.Join of a directory and a plain name.
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

/// serverName: the control plane node a server certificate is for.
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
    let snap = join(&tmp, FILE_STATE);
    write_snapshot(c, &snap).await?;
    let ca_pem = read_private(&join(dd, FILE_CA_CERT))?;
    let ca_key = read_private(&join(dd, FILE_CA_KEY))?;
    let srv = read_private(&join(dd, FILE_SERVER_CERT))?;
    let ca = Ca::load(&ca_pem, &ca_key).map_err(|e| e.to_string())?;
    let name = server_name(&srv)?;
    // The snapshot is checked the way a restore checks it, so a backup
    // that cannot be restored fails now rather than when it is needed.
    let programs = Programs::find(&tmp).map_err(|e| format!("verify snapshot: {e}"))?;
    let info = state::inspect(&programs, &snap, &tmp, &name)
        .await
        .map_err(|e| format!("verify snapshot: {e}"))?;

    st.files.push((FILE_STATE.to_string(), snap));
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
        format: FORMAT,
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

/// writeSnapshot: etcd's snapshot of the keyspace (ending with its
/// SHA-256, which a restore verifies) into a new file.
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
    let mut h = Sha256::new();
    io::copy(&mut f, &mut h).map_err(|e| errno("read", p, &e))?;
    Ok(pack::hex(&h.finalize()))
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

/// writeEntry: one regular file (mode 0600, the current second) with a
/// USTAR header, as Go's tar.Writer writes a FormatPAX header that needs
/// no records, and its size bytes read from r.
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

/// A restore handed the backup file by file (Go's Restorer): Add each,
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
            if m.format != FORMAT {
                return Err(format!(
                    "backup format {} is not supported (want {FORMAT})",
                    m.format
                ));
            }
            self.m = m;
            return Ok(());
        }
        if !REQUIRED.contains(&name) && !OPTIONAL.contains(&name) {
            return Err(format!(
                "unexpected entry {} in backup",
                armada_spec::go::quote(name)
            ));
        }
        if self.sums.contains_key(name) {
            return Err(format!("duplicate entry {}", armada_spec::go::quote(name)));
        }
        let limit = if name == FILE_STATE {
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

/// writeFile: size bytes of r into a new file name below dir; its SHA-256.
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
) -> Result<Programs, String> {
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
    for name in REQUIRED {
        if !sums.contains_key(name) {
            return Err(format!("backup has no {name}"));
        }
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
    let programs = Programs::find(base).map_err(|e| format!("state snapshot: {e}"))?;
    let info = state::inspect(&programs, &join(dir, FILE_STATE), dir, &name)
        .await
        .map_err(|e| format!("state snapshot: {e}"))?;
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

//! The runtime pack (Go's internal/runtime/embedded bundle.go): the pinned
//! runtime programs armadad carries, built by `make runtime-bundle` and
//! compiled in with `include_bytes!` when the build names one (the
//! `bundle` feature, or ARMADA_RUNTIME_PACK; build.rs), as Go's build tag
//! `bundle` embeds it. Without one, bundled() is empty and the programs
//! come from `--bin-dir`.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// The pack's programs (lock.go).
pub const BIN_CONTAINERD: &str = "containerd";
pub const BIN_SHIM: &str = "containerd-shim-runc-v2";
pub const BIN_RUNC: &str = "runc";
pub const BIN_TINI: &str = "tini";
pub const BIN_NODE: &str = "armada-node";
pub const BIN_ETCD: &str = "etcd";
pub const DIR_CNI: &str = "cni";

const MANIFEST_NAME: &str = "MANIFEST.json";
const INSTALL_LOCK: &str = ".install.lock";
const MAX_PACK_FILES: usize = 32;
const MAX_FILE_SIZE: u64 = 256 << 20;

#[cfg(armada_bundle)]
static BUNDLED: &[u8] = include_bytes!(env!("ARMADA_PACK_PATH"));
#[cfg(not(armada_bundle))]
static BUNDLED: &[u8] = &[];

/// Bundled: the pack compiled into this binary, or empty.
pub fn bundled() -> &'static [u8] {
    BUNDLED
}

/// Paths: where the runtime keeps its files.
#[derive(Clone, Debug)]
pub struct Paths {
    pub data_dir: PathBuf,
    pub run_dir: PathBuf,
}

impl Paths {
    pub fn bundle(&self) -> PathBuf {
        self.data_dir.join("runtime")
    }
    pub fn bin(&self) -> PathBuf {
        self.bundle().join("current").join("bin")
    }
    pub fn root(&self) -> PathBuf {
        self.data_dir.join("containerd")
    }
    pub fn state(&self) -> PathBuf {
        self.run_dir.join("containerd")
    }
    pub fn socket(&self) -> PathBuf {
        self.state().join("containerd.sock")
    }
    pub fn config(&self) -> PathBuf {
        self.bundle().join("containerd.toml")
    }
    pub fn logs(&self) -> PathBuf {
        self.data_dir.join("logs")
    }
    pub fn containers(&self) -> PathBuf {
        self.data_dir.join("containers")
    }
    pub fn cni(&self) -> PathBuf {
        self.run_dir.join("cni")
    }
}

/// A pack's manifest.
#[derive(Debug, Clone, Default)]
pub struct Manifest {
    pub arch: String,
    pub versions: BTreeMap<String, String>,
    pub files: BTreeMap<String, String>,
}

/// PackID: the first 8 bytes of the pack's SHA-256, in hex.
pub fn pack_id(pack: &[u8]) -> String {
    let sum = Sha256::digest(pack);
    hex(&sum[..8])
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// InstalledPack.
pub fn installed_pack(root: &Path) -> String {
    fs::read_link(root.join("current"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// checkName: plain relative names only.
fn check_name(n: &str) -> Result<(), String> {
    let clean = crate::gopath::clean(n);
    if n.is_empty()
        || n == MANIFEST_NAME
        || clean != n
        || n.starts_with('/')
        || n.starts_with("../")
        || n == ".."
        || n.contains(['\\', '\0'])
    {
        return Err(format!(
            "bundle: invalid file name {}",
            armada_spec::go::quote(n)
        ));
    }
    Ok(())
}

fn open_pack(
    pack: &[u8],
) -> Result<crate::tar::Reader<flate2::read::MultiGzDecoder<&[u8]>>, String> {
    if let Some(e) = crate::commands::upgrade::gzip_header_error(&pack[..pack.len().min(10)]) {
        return Err(format!("bundle: {e}"));
    }
    Ok(crate::tar::Reader::new(flate2::read::MultiGzDecoder::new(
        pack,
    )))
}

fn io_text(e: &std::io::Error) -> String {
    armada_fsutil::errno_text(e)
}

fn path_err(op: &str, p: &Path, e: &std::io::Error) -> String {
    format!("{op} {}: {}", p.display(), io_text(e))
}

/// readManifest.
fn read_manifest(pack: &[u8]) -> Result<Manifest, String> {
    let mut tr = open_pack(pack)?;
    let h = tr.next_entry();
    let h = match h {
        Ok(Some(h)) if h.name == MANIFEST_NAME && h.size <= 1 << 20 => h,
        _ => return Err("bundle: pack does not start with a manifest".to_string()),
    };
    let _ = h;
    let mut b = Vec::new();
    tr.data()
        .take(1 << 20)
        .read_to_end(&mut b)
        .map_err(|e| format!("bundle: manifest: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_slice(&b).map_err(|e| format!("bundle: manifest: {e}"))?;
    let mut m = Manifest::default();
    let str_map = |v: Option<&serde_json::Value>| -> BTreeMap<String, String> {
        v.and_then(|v| v.as_object())
            .map(|o| {
                o.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default()
    };
    m.arch = v
        .get("arch")
        .and_then(|a| a.as_str())
        .unwrap_or_default()
        .to_string();
    m.versions = str_map(v.get("versions"));
    m.files = str_map(v.get("files"));
    if m.files.is_empty() || m.files.len() > MAX_PACK_FILES {
        return Err("bundle: manifest lists no files or too many".to_string());
    }
    for (n, s) in &m.files {
        check_name(n)?;
        if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("bundle: bad checksum for {n}"));
        }
    }
    Ok(m)
}

/// extract.
fn extract(pack: &[u8], dir: &Path, m: &Manifest) -> Result<(), String> {
    let mut tr = open_pack(pack)?;
    let mut seen = std::collections::BTreeSet::new();
    while let Some(h) = tr.next_entry().map_err(|e| format!("bundle: {e}"))? {
        if h.name == MANIFEST_NAME {
            continue;
        }
        if !m.files.contains_key(&h.name) || seen.contains(&h.name) {
            return Err(format!(
                "bundle: unexpected entry {}",
                armada_spec::go::quote(&h.name)
            ));
        }
        if !h.is_regular() || h.size > MAX_FILE_SIZE {
            return Err(format!(
                "bundle: {} is not a regular file within limits",
                h.name
            ));
        }
        seen.insert(h.name.clone());
        let dst = dir.join(&h.name);
        if let Some(p) = dst.parent() {
            crate::gofs::mkdir_all(p, 0o700)?;
        }
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(&dst)
            .map_err(|e| path_err("open", &dst, &e))?;
        std::io::copy(&mut tr.data().take(MAX_FILE_SIZE), &mut f).map_err(|e| e.to_string())?;
    }
    if seen.len() != m.files.len() {
        return Err("bundle: pack is missing files from its manifest".to_string());
    }
    Ok(())
}

/// verify: dir holds the manifest's files with their checksums.
fn verify(dir: &Path, m: &Manifest) -> Result<(), String> {
    for (n, want) in &m.files {
        let p = dir.join(n);
        let fi = fs::symlink_metadata(&p).map_err(|e| path_err("lstat", &p, &e))?;
        if !fi.file_type().is_file() {
            return Err(format!("bundle: {n} is not a regular file"));
        }
        let mut f = fs::File::open(&p).map_err(|e| path_err("open", &p, &e))?;
        let mut h = Sha256::new();
        std::io::copy(&mut f, &mut h).map_err(|e| e.to_string())?;
        if hex(&h.finalize()) != *want {
            return Err(format!("bundle: {n} does not match its checksum"));
        }
    }
    Ok(())
}

/// The install lock, held until dropped.
struct Lock(fs::File);

impl Drop for Lock {
    fn drop(&mut self) {
        // Closing the file releases the flock.
        let _ = &self.0;
    }
}

/// Install: extracts pack under root unless an intact copy is there,
/// points root/current at it, and returns root/current/bin.
pub fn install(root: &Path, pack: &[u8]) -> Result<(PathBuf, Manifest), String> {
    let id = pack_id(pack);
    crate::gofs::mkdir_all(root, 0o700)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))
        .map_err(|e| path_err("chmod", root, &e))?;
    let lock_path = root.join(INSTALL_LOCK);
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|e| path_err("open", &lock_path, &e))?;
    // SAFETY: flock on a descriptor this function owns.
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) } != 0 {
        let e = std::io::Error::last_os_error();
        return Err(format!("lock {}: {}", lock_path.display(), io_text(&e)));
    }
    let _held = Lock(lock);
    let m = read_manifest(pack)?;
    let dir = root.join(&id);
    if verify(&dir.join("bin"), &m).is_err() {
        let tmp = temp_dir(root, ".extract-")?;
        let result = (|| {
            extract(pack, &tmp.join("bin"), &m)?;
            verify(&tmp.join("bin"), &m)?;
            if let Err(e) = fs::remove_dir_all(&dir)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                return Err(path_err("unlinkat", &dir, &e));
            }
            fs::rename(&tmp, &dir).map_err(|e| {
                format!(
                    "rename {} {}: {}",
                    tmp.display(),
                    dir.display(),
                    io_text(&e)
                )
            })
        })();
        let _ = fs::remove_dir_all(&tmp);
        result?;
    }
    let link = root.join("current");
    let tmp_link = root.join("current.new");
    let _ = fs::remove_file(&tmp_link);
    std::os::unix::fs::symlink(&id, &tmp_link)
        .map_err(|e| format!("symlink {id} {}: {}", tmp_link.display(), io_text(&e)))?;
    fs::rename(&tmp_link, &link).map_err(|e| {
        format!(
            "rename {} {}: {}",
            tmp_link.display(),
            link.display(),
            io_text(&e)
        )
    })?;
    let entries = fs::read_dir(root).map_err(|e| path_err("open", root, &e))?;
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if e.file_type().is_ok_and(|t| t.is_dir()) && name != id && !name.starts_with('.') {
            let _ = fs::remove_dir_all(e.path());
        }
    }
    Ok((link.join("bin"), m))
}

/// os.MkdirTemp(dir, pattern).
pub fn temp_dir(dir: &Path, prefix: &str) -> Result<PathBuf, String> {
    for _ in 0..10000 {
        let mut b = [0u8; 4];
        let _ = getrandom(&mut b);
        let n = u32::from_le_bytes(b);
        let p = dir.join(format!("{prefix}{n}"));
        match fs::DirBuilder::new().mode(0o700).create(&p) {
            Ok(()) => return Ok(p),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(path_err("mkdir", &p, &e)),
        }
    }
    Err(format!("mkdirtemp {}: too many tries", dir.display()))
}

fn getrandom(b: &mut [u8]) -> std::io::Result<()> {
    let mut f = fs::File::open("/dev/urandom")?;
    f.read_exact(b)
}

/// UseBinDir: root/current pointed at the programs in dir.
pub fn use_bin_dir(root: &Path, dir: &str) -> Result<(), String> {
    let abs = std::path::absolute(dir).map_err(|e| e.to_string())?;
    let abs = PathBuf::from(crate::gopath::clean(&abs.to_string_lossy()));
    for n in [BIN_CONTAINERD, BIN_SHIM, BIN_RUNC, BIN_TINI, DIR_CNI] {
        let p = abs.join(n);
        if let Err(e) = fs::metadata(&p) {
            return Err(format!("runtime binaries: {}", path_err("stat", &p, &e)));
        }
    }
    let dev = root.join("dev");
    crate::gofs::mkdir_all(&dev, 0o700)?;
    let _ = fs::remove_file(dev.join("bin"));
    std::os::unix::fs::symlink(&abs, dev.join("bin")).map_err(|e| {
        format!(
            "symlink {} {}: {}",
            abs.display(),
            dev.join("bin").display(),
            io_text(&e)
        )
    })?;
    let link = root.join("current");
    let new = root.join("current.new");
    let _ = fs::remove_file(&new);
    std::os::unix::fs::symlink("dev", &new)
        .map_err(|e| format!("symlink dev {}: {}", new.display(), io_text(&e)))?;
    fs::rename(&new, &link).map_err(|e| {
        format!(
            "rename {} {}: {}",
            new.display(),
            link.display(),
            io_text(&e)
        )
    })
}

/// CheckHost: what the embedded runtime needs from the kernel.
pub fn check_host() -> Result<(), String> {
    if fs::metadata("/sys/fs/cgroup/cgroup.controllers").is_err() {
        return Err("cgroup v2 is required (unified hierarchy at /sys/fs/cgroup)".to_string());
    }
    Ok(())
}

/// installPack: the pack extracted and verified, and the directories the
/// runtime writes to made.
pub fn install_pack(p: &Paths) -> Result<(), String> {
    check_host()?;
    let pack = bundled();
    if !pack.is_empty() {
        install(&p.bundle(), pack).map_err(|e| format!("runtime pack: {e}"))?;
    }
    for d in [p.logs(), p.containers(), p.cni()] {
        crate::gofs::mkdir_all(&d, 0o700)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn pack(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut m = String::from("{\n  \"arch\": \"amd64\",\n  \"versions\": {},\n  \"files\": {");
        let entries: Vec<String> = files
            .iter()
            .map(|(n, b)| format!("\"{n}\": \"{}\"", hex(&Sha256::digest(b))))
            .collect();
        m.push_str(&entries.join(", "));
        m.push_str("}\n}");
        let mut all: Vec<(&str, u32, &[u8])> = vec![(MANIFEST_NAME, 0o644, m.as_bytes())];
        for (n, b) in files {
            all.push((n, 0o755, b));
        }
        let t = crate::tar::write_test_archive(&all);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&t).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn installs_and_verifies() {
        let dir = std::env::temp_dir().join(format!("armadad-pack-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let p = pack(&[("runc", b"r"), ("cni/bridge", b"b")]);
        let (bin, m) = install(&dir, &p).unwrap();
        assert_eq!(m.files.len(), 2);
        assert_eq!(fs::read(bin.join("cni/bridge")).unwrap(), b"b");
        assert_eq!(installed_pack(&dir), pack_id(&p));
        // A damaged copy is extracted again.
        fs::write(dir.join(pack_id(&p)).join("bin/runc"), b"x").unwrap();
        install(&dir, &p).unwrap();
        assert_eq!(fs::read(bin.join("runc")).unwrap(), b"r");
        assert!(check_name("../x").is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}

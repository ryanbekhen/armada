//! The Rust runtime's image store (ADR 0054, "The runtime's move"):
//!
//!   <root>/content/blobs/<alg>/<hex>   every blob, read-only, by digest
//!   <root>/content/ingest/             downloads until their digest matches
//!   <root>/index.json                  image records and verified layers
//!   <root>/layers/<chain ID hex>/      unpacked layers (layers.rs)
//!   <root>/active/<key>/               containers' root filesystems
//!                                      (snapshot.rs)
//!   <root>/pull.lock, index.lock       see Store::pulls and Store::update
//!
//! The content layout is the one the supervisor runtime's content store
//! keeps, so converting a node moves blobs by hard link or rename.

use super::digest::Digest;
use super::registry::Descriptor;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const INDEX_FILE: &str = "index.json";
const INDEX_VERSION: u32 = 1;

/// What the store records about an image name.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ImageRecord {
    pub name: String,
    /// What the name resolved to (an index or a manifest).
    pub target: Descriptor,
    /// The manifest chosen for this node's platform.
    pub manifest: Descriptor,
    pub config: Descriptor,
    #[serde(default, deserialize_with = "crate::runtime::nullable")]
    pub layers: Vec<Descriptor>,
    #[serde(
        rename = "diffIDs",
        default,
        deserialize_with = "crate::runtime::nullable"
    )]
    pub diff_ids: Vec<Digest>,
    /// The image's chain ID; empty for an image with no layers.
    #[serde(rename = "chainID", default)]
    pub chain_id: String,
    /// The platforms the image offers, as "os/arch".
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "crate::runtime::nullable"
    )]
    pub platforms: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "crate::runtime::nullable"
    )]
    pub labels: BTreeMap<String, String>,
    pub created: String,
    pub updated: String,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Index {
    #[serde(default)]
    pub version: u32,
    #[serde(default, deserialize_with = "crate::runtime::nullable")]
    pub images: BTreeMap<String, ImageRecord>,
    /// Layer blobs shown to decompress to a diff ID.
    #[serde(default, deserialize_with = "crate::runtime::nullable")]
    pub verified: BTreeMap<String, Digest>,
    /// A record was removed and its blobs not collected yet.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub uncollected: bool,
}

pub struct Store {
    root: PathBuf,
}

/// An flock held until dropped.
pub struct Lock(File);

impl Drop for Lock {
    fn drop(&mut self) {
        // SAFETY: unlocking a descriptor this value owns.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn mkdir(p: &Path) -> io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(p)
}

static TEMP: AtomicU64 = AtomicU64::new(0);

impl Store {
    /// Opens (creating) the store under root.
    pub fn open(root: &Path) -> Result<Store, String> {
        for d in [
            root.to_path_buf(),
            root.join("content/blobs"),
            root.join("content/ingest"),
            root.join("layers"),
        ] {
            mkdir(&d).map_err(|e| format!("image store {}: {e}", d.display()))?;
        }
        Ok(Store {
            root: root.to_path_buf(),
        })
    }

    /// The store under root as it is, creating nothing: for reading a
    /// store of the same layout (Go's content store while converting it).
    pub fn at(root: &Path) -> Store {
        Store {
            root: root.to_path_buf(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn layers_root(&self) -> PathBuf {
        self.root.join("layers")
    }

    /// The directory of a chain's unpacked layer.
    pub fn layer_dir(&self, chain: &Digest) -> PathBuf {
        self.layers_root().join(chain.hex())
    }

    pub fn blob_path(&self, d: &Digest) -> PathBuf {
        self.root
            .join("content/blobs")
            .join(d.algorithm().name())
            .join(d.hex())
    }

    pub fn has(&self, d: &Digest) -> bool {
        self.blob_path(d).is_file()
    }

    pub fn open_blob(&self, d: &Digest) -> Result<File, String> {
        File::open(self.blob_path(d)).map_err(|e| format!("blob {d}: {e}"))
    }

    /// Reads a blob of at most max bytes whole.
    pub fn read_blob(&self, desc: &Descriptor, max: u64) -> Result<Vec<u8>, String> {
        let f = self.open_blob(&desc.digest)?;
        let size = f.metadata().map_err(|e| e.to_string())?.len();
        if size > max {
            return Err(format!("{} is larger than {max} bytes", desc.digest));
        }
        let mut b = Vec::with_capacity(size as usize);
        f.take(max + 1)
            .read_to_end(&mut b)
            .map_err(|e| format!("blob {}: {e}", desc.digest))?;
        Ok(b)
    }

    /// Writes desc's content from r: to a file of its own in ingest, then,
    /// once its size and digest match, renamed into place read-only.
    pub fn write(&self, desc: &Descriptor, r: &mut dyn Read) -> Result<(), String> {
        let tmp = self.root.join("content/ingest").join(format!(
            "{}-{}-{}",
            desc.digest.hex(),
            std::process::id(),
            TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| format!("ingest {}: {e}", desc.digest))?;
            let mut h = desc.digest.algorithm().hasher();
            let want = desc.size as u64;
            let mut limited = r.take(want + 1);
            let mut buf = vec![0u8; 64 << 10];
            let mut n: u64 = 0;
            loop {
                let k = match limited.read(&mut buf) {
                    Ok(0) => break,
                    Ok(k) => k,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(format!("read {}: {e}", desc.digest)),
                };
                h.update(&buf[..k]);
                f.write_all(&buf[..k])
                    .map_err(|e| format!("write {}: {e}", desc.digest))?;
                n += k as u64;
            }
            if n != want {
                return Err(format!(
                    "failed commit on ref {}: unexpected commit size {n}, expected {want}",
                    desc.digest
                ));
            }
            let got = h.finish();
            if got != desc.digest {
                return Err(format!(
                    "failed commit on ref {}: unexpected commit digest {got}, expected {}",
                    desc.digest, desc.digest
                ));
            }
            f.sync_all().map_err(|e| e.to_string())?;
            f.set_permissions(fs::Permissions::from_mode(0o400))
                .map_err(|e| e.to_string())?;
            let dst = self.blob_path(&desc.digest);
            if let Some(dir) = dst.parent() {
                mkdir(dir).map_err(|e| e.to_string())?;
            }
            fs::rename(&tmp, &dst).map_err(|e| format!("commit {}: {e}", desc.digest))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }

    fn lock(&self, name: &str, op: libc::c_int) -> Result<Option<Lock>, String> {
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(self.root.join(name))
            .map_err(|e| format!("{name}: {e}"))?;
        loop {
            // SAFETY: flock on a descriptor this function owns.
            if unsafe { libc::flock(f.as_raw_fd(), op) } == 0 {
                return Ok(Some(Lock(f)));
            }
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EWOULDBLOCK) if op & libc::LOCK_NB != 0 => return Ok(None),
                _ => return Err(format!("{name}: {e}")),
            }
        }
    }

    /// Held shared by a pull from its first fetch to its record, and
    /// exclusively while unused blobs are collected.
    pub fn pulls_shared(&self) -> Result<Lock, String> {
        Ok(self
            .lock("pull.lock", libc::LOCK_SH)?
            .expect("blocking lock"))
    }

    pub fn try_pulls_exclusive(&self) -> Result<Option<Lock>, String> {
        self.lock("pull.lock", libc::LOCK_EX | libc::LOCK_NB)
    }

    /// Takes the store's lock name (pull.lock, index.lock) exclusively,
    /// waiting for it: no pull, collection, or index change runs while it
    /// is held. Index changes under it go through write_index.
    pub fn lock_exclusive(&self, name: &str) -> Result<Lock, String> {
        Ok(self.lock(name, libc::LOCK_EX)?.expect("blocking lock"))
    }

    /// The index as it is now.
    pub fn index(&self) -> Result<Index, String> {
        let _l = self.lock("index.lock", libc::LOCK_SH)?;
        self.read_index()
    }

    /// The index without its lock: for a caller holding index.lock.
    pub fn read_index(&self) -> Result<Index, String> {
        match fs::read(self.root.join(INDEX_FILE)) {
            Ok(b) => {
                let idx: Index =
                    serde_json::from_slice(&b).map_err(|e| format!("{INDEX_FILE}: {e}"))?;
                if idx.version > INDEX_VERSION {
                    return Err(format!(
                        "{INDEX_FILE}: version {} is newer than this program's {INDEX_VERSION}",
                        idx.version
                    ));
                }
                Ok(idx)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Index {
                version: INDEX_VERSION,
                ..Default::default()
            }),
            Err(e) => Err(format!("{INDEX_FILE}: {e}")),
        }
    }

    /// Changes the index under its lock and writes it atomically.
    pub fn update<T>(&self, f: impl FnOnce(&mut Index) -> Result<T, String>) -> Result<T, String> {
        let _l = self.lock("index.lock", libc::LOCK_EX)?;
        let mut idx = self.read_index()?;
        let out = f(&mut idx)?;
        self.write_index(&mut idx)?;
        Ok(out)
    }

    /// Writes idx atomically (synced, then renamed) without taking
    /// index.lock: for a caller holding it.
    pub fn write_index(&self, idx: &mut Index) -> Result<(), String> {
        idx.version = INDEX_VERSION;
        let b = serde_json::to_vec(&idx).map_err(|e| e.to_string())?;
        let tmp = self.root.join(format!("{INDEX_FILE}.tmp"));
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("{INDEX_FILE}: {e}"))?;
        file.write_all(&b)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("{INDEX_FILE}: {e}"))?;
        fs::rename(&tmp, self.root.join(INDEX_FILE)).map_err(|e| format!("{INDEX_FILE}: {e}"))
    }

    /// The digests of every blob under the store.
    fn blobs(&self) -> Vec<(PathBuf, String)> {
        let mut out = Vec::new();
        let Ok(algs) = fs::read_dir(self.root.join("content/blobs")) else {
            return out;
        };
        for a in algs.flatten() {
            let alg = a.file_name().to_string_lossy().into_owned();
            let Ok(files) = fs::read_dir(a.path()) else {
                continue;
            };
            for f in files.flatten() {
                out.push((
                    f.path(),
                    format!("{alg}:{}", f.file_name().to_string_lossy()),
                ));
            }
        }
        out
    }

    /// The children of a descriptor whose content is here: an index's
    /// manifests, a manifest's config and layers (images.Children for
    /// walking what a record keeps).
    pub fn stored_children(&self, desc: &Descriptor) -> Option<Vec<Descriptor>> {
        use super::registry::{is_index, is_manifest};
        if !is_index(&desc.media_type) && !is_manifest(&desc.media_type) {
            return Some(Vec::new());
        }
        let b = self
            .read_blob(desc, super::registry::MAX_MANIFEST_SIZE)
            .ok()?;
        let doc: super::pull::Document = serde_json::from_slice(&b).ok()?;
        Some(if is_index(&desc.media_type) {
            doc.manifests
        } else {
            let mut c = Vec::with_capacity(doc.layers.len() + 1);
            c.extend(doc.config);
            c.extend(doc.layers);
            c
        })
    }

    /// Removes blobs and unpacked layers no record keeps, and downloads
    /// left behind; only while no pull runs (the pull lock held
    /// exclusively).
    pub fn collect(&self, _held: &Lock) -> Result<(), String> {
        self.update(|idx| {
            let mut keep = std::collections::BTreeSet::new();
            let mut chains = std::collections::BTreeSet::new();
            for r in idx.images.values() {
                for c in super::digest::chain_ids(&r.diff_ids) {
                    chains.insert(c.hex().to_string());
                }
                let mut stack = vec![r.target.clone()];
                while let Some(d) = stack.pop() {
                    if !keep.insert(d.digest.to_string()) || !self.has(&d.digest) {
                        continue;
                    }
                    stack.extend(self.stored_children(&d).unwrap_or_default());
                }
            }
            for (path, digest) in self.blobs() {
                if !keep.contains(&digest) {
                    match fs::remove_file(&path) {
                        Ok(()) => {}
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                        Err(e) => return Err(format!("remove {digest}: {e}")),
                    }
                }
            }
            if let Ok(ingest) = fs::read_dir(self.root.join("content/ingest")) {
                for e in ingest.flatten() {
                    let _ = fs::remove_file(e.path());
                }
            }
            // Layers under a container's root filesystem stay, as the
            // snapshotter refuses to remove a parent.
            let active = super::snapshot::in_use(self);
            // Layers held for containers moved from Go's store stay while
            // an active snapshot names their chain (their overlays may
            // still mount them); the store stays marked until they go.
            let held = super::layers::collect_held(self, &active);
            if !active.contains("*") {
                chains.extend(active);
                super::layers::collect(self, &chains);
            }
            idx.verified.retain(|blob, _| keep.contains(blob));
            idx.uncollected = held;
            Ok(())
        })
    }

    /// collectIdle: collects when a removal left blobs behind and no pull
    /// runs; otherwise the last running pull does.
    pub fn collect_idle(&self) -> Result<(), String> {
        let Some(l) = self.try_pulls_exclusive()? else {
            return Ok(());
        };
        if !self.index()?.uncollected {
            return Ok(());
        }
        self.collect(&l)
    }
}

/// Now as Go's time.Time marshals it in UTC (RFC 3339 with nanoseconds,
/// trailing zeros dropped).
pub fn now_rfc3339() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format_rfc3339(d.as_secs() as i64, d.subsec_nanos())
}

pub fn format_rfc3339(secs: i64, nanos: u32) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    // Civil from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let mut s = format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    );
    if nanos > 0 {
        let frac = format!("{nanos:09}");
        s.push('.');
        s.push_str(frac.trim_end_matches('0'));
    }
    s.push('Z');
    s
}

/// Seconds since the epoch of a time format_rfc3339 wrote (or any
/// RFC 3339 time in UTC); None when it does not parse.
pub fn parse_rfc3339(s: &str) -> Option<f64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-');
    let (y, m, day): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    let (hms, frac) = match time.split_once('.') {
        Some((a, b)) => (a, format!("0.{b}").parse::<f64>().ok()?),
        None => (time, 0.0),
    };
    let mut t = hms.split(':');
    let (h, mi, se): (i64, i64, i64) = (
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    );
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some((days * 86400 + h * 3600 + mi * 60 + se) as f64 + frac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_round_trip() {
        assert_eq!(format_rfc3339(0, 0), "1970-01-01T00:00:00Z");
        assert_eq!(
            format_rfc3339(1_795_420_800, 120_000_000),
            "2026-11-23T08:00:00.12Z"
        );
        assert_eq!(
            parse_rfc3339("2026-11-23T08:00:00.12Z"),
            Some(1_795_420_800.12)
        );
        assert_eq!(parse_rfc3339("2000-02-29T23:59:59Z"), Some(951_868_799.0));
    }

    #[test]
    fn writes_only_matching_content() {
        let dir = std::env::temp_dir().join(format!("armada-node-store-{}", std::process::id()));
        let s = Store::open(&dir).unwrap();
        let b = b"blob".to_vec();
        let desc: Descriptor = serde_json::from_str(&format!(
            r#"{{"mediaType":"x","digest":"{}","size":4}}"#,
            Digest::sha256(&b)
        ))
        .unwrap();
        assert!(s.write(&desc, &mut &b"blub"[..]).is_err());
        assert!(s.write(&desc, &mut &b"blob and more"[..]).is_err());
        assert!(!s.has(&desc.digest));
        s.write(&desc, &mut &b[..]).unwrap();
        assert!(s.has(&desc.digest));
        assert_eq!(fs::read_dir(dir.join("content/ingest")).unwrap().count(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A layer held for a container moved from Go's store stays while an
    /// active snapshot names its chain, keeping the store marked for a
    /// collection, and goes with the next collection after.
    #[test]
    fn collect_keeps_held_layers_while_named() {
        let dir = std::env::temp_dir().join(format!("armada-node-held-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let s = Store::open(&dir).unwrap();
        let (a, b) = ("a".repeat(64), "b".repeat(64));
        let active = dir.join("active/c1");
        fs::create_dir_all(&active).unwrap();
        fs::write(
            active.join("snapshot.json"),
            format!(r#"{{"image":"x","parents":["{a}"]}}"#),
        )
        .unwrap();
        for h in [format!("{a}.0"), format!("{a}.1"), format!("{b}.0")] {
            fs::create_dir_all(dir.join("held").join(h).join("usr")).unwrap();
        }
        let collect = || {
            let l = s.try_pulls_exclusive().unwrap().unwrap();
            s.collect(&l).unwrap();
        };
        collect();
        assert!(dir.join("held").join(format!("{a}.0/usr")).exists());
        assert!(dir.join("held").join(format!("{a}.1")).exists());
        assert!(!dir.join("held").join(format!("{b}.0")).exists());
        assert!(s.index().unwrap().uncollected);

        fs::remove_dir_all(&active).unwrap();
        collect();
        assert_eq!(fs::read_dir(dir.join("held")).unwrap().count(), 0);
        assert!(!s.index().unwrap().uncollected);
        let _ = fs::remove_dir_all(&dir);
    }
}

//! Containers' root filesystems in the store (ADR 0054 step 4, fourth
//! part): what the overlay snapshotter's Prepare and Remove do for a
//! container's active snapshot, on the store's unpacked layers.
//!
//!   <root>/active/<key>/fs/          the writable upper directory
//!   <root>/active/<key>/work/        overlay's work directory
//!   <root>/active/<key>/snapshot.json  {"image", "parents"}: the image
//!                                    and the chain ID hexes of its
//!                                    layers, the top first
//!
//! The directories are made as createSnapshot makes them (fs 0755 owned
//! like the top layer, work 0711, the snapshot's own directory 0700, all
//! in a staging directory renamed into place), and the mounts are the
//! ones its mounts() returns: a bind mount of fs for an image with no
//! layers, else overlay with workdir, upperdir, lowerdir (the top layer
//! first), userxattr when the kernel needs it, and index=off where the
//! overlay module has the parameter. A collection keeps every layer an
//! active snapshot names.

use super::digest::chain_ids;
use super::reference;
use super::store::Store;
use crate::runtime::container::errno_text;
use crate::runtime::container::mount::Mount;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP: AtomicU64 = AtomicU64::new(0);

const RECORD: &str = "snapshot.json";

#[derive(Serialize, Deserialize)]
struct Record {
    image: String,
    /// Chain ID hexes of the image's layers, the top first.
    parents: Vec<String>,
}

/// A snapshot key names a directory: no separator, not "." or "..",
/// not hidden (staging directories are), at most 255 bytes.
fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 255
        && !key.starts_with('.')
        && !key.contains('/')
        && !key.contains('\0')
}

fn active_root(store: &Store) -> PathBuf {
    store.root().join("active")
}

/// The overlay options every active mount ends with: userxattr when the
/// snapshotter would add it, then index=off when the kernel has the
/// parameter (NewSnapshotter).
fn overlay_options(root: &Path) -> Vec<String> {
    let mut o = Vec::new();
    if needs_userxattr(root) {
        o.push("userxattr".to_string());
    }
    if fs::metadata("/sys/module/overlay/parameters/index").is_ok() {
        o.push("index=off".to_string());
    }
    o
}

/// userns.RunningInUserNS: /proc/self/uid_map's first line is anything but
/// the whole range mapped to itself.
fn running_in_userns() -> bool {
    let Ok(s) = fs::read_to_string("/proc/self/uid_map") else {
        return false;
    };
    let Some(line) = s.lines().next() else {
        return false;
    };
    let f: Vec<&str> = line.split_whitespace().collect();
    let n: Vec<Option<i64>> = f.iter().take(3).map(|x| x.parse().ok()).collect();
    match n.as_slice() {
        [Some(a), Some(b), Some(c)] => !(*a == 0 && *b == 0 && *c == 4_294_967_295),
        _ => true,
    }
}

/// overlayutils.NeedsUserXAttr: only inside a user namespace, not on
/// tmpfs, on kernels from 5.11 (older kernels are not supported here and
/// get none).
fn needs_userxattr(root: &Path) -> bool {
    if !running_in_userns() {
        return false;
    }
    let Ok(c) = std::ffi::CString::new(root.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    // SAFETY: statfs into a zeroed struct with a NUL-terminated path.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::statfs(c.as_ptr(), &mut st) } == 0;
    // f_type's type differs between C libraries.
    #[allow(clippy::unnecessary_cast)]
    let tmpfs = st.f_type as u64 == libc::TMPFS_MAGIC as u64;
    if ok && tmpfs {
        return false;
    }
    kernel_at_least(5, 11)
}

fn kernel_at_least(major: u32, minor: u32) -> bool {
    // SAFETY: uname into a zeroed struct.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return false;
    }
    // SAFETY: release is NUL-terminated by uname.
    let rel = unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) }.to_string_lossy();
    let mut parts = rel.split(|c: char| !c.is_ascii_digit());
    let a: u32 = parts.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    let b: u32 = parts.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    (a, b) >= (major, minor)
}

/// The mounts of an active snapshot (mounts()).
fn mounts(store: &Store, dir: &Path, rec: &Record) -> Vec<Mount> {
    let fs_dir = dir.join("fs").display().to_string();
    if rec.parents.is_empty() {
        return vec![Mount {
            kind: "bind".into(),
            source: fs_dir,
            target: String::new(),
            options: vec!["rw".into(), "rbind".into()],
        }];
    }
    let lowers: Vec<String> = rec
        .parents
        .iter()
        .map(|h| store.layers_root().join(h).display().to_string())
        .collect();
    let mut options = vec![
        format!("workdir={}", dir.join("work").display()),
        format!("upperdir={fs_dir}"),
        format!("lowerdir={}", lowers.join(":")),
    ];
    options.extend(overlay_options(store.root()));
    vec![Mount {
        kind: "overlay".into(),
        source: "overlay".into(),
        target: String::new(),
        options,
    }]
}

fn read_record(dir: &Path) -> Result<Record, String> {
    let b = fs::read(dir.join(RECORD)).map_err(|e| {
        format!(
            "open {}: {}",
            dir.join(RECORD).display(),
            errno_text(e.raw_os_error().unwrap_or(libc::EIO))
        )
    })?;
    serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", dir.join(RECORD).display()))
}

/// Prepare: a writable root filesystem for container key on top of
/// image's layers, or the one key already has; returns its mounts.
pub fn prepare(store: &Store, key: &str, image: &str) -> Result<Vec<Mount>, String> {
    if !valid_key(key) {
        return Err(format!(
            "invalid snapshot key {}",
            crate::net::addr::quote(key)
        ));
    }
    // Held until the snapshot names its layers, so no collection takes
    // them meanwhile.
    let _pulls = store.pulls_shared()?;
    let root = active_root(store);
    let dir = root.join(key);
    if dir.is_dir() {
        return Ok(mounts(store, &dir, &read_record(&dir)?));
    }
    let idx = store.index()?;
    let rec = idx
        .images
        .get(image)
        .or_else(|| {
            reference::parse_docker_ref(image)
                .ok()
                .and_then(|r| idx.images.get(&r.to_string()))
        })
        .ok_or_else(|| format!("image {image}: not found"))?;
    let chains = chain_ids(&rec.diff_ids);
    let parents: Vec<String> = chains.iter().rev().map(|c| c.hex().to_string()).collect();
    for p in &parents {
        if !store.layers_root().join(p).is_dir() {
            return Err(format!(
                "image {image}: layer {} is not unpacked",
                store.layers_root().join(p).display()
            ));
        }
    }
    fs::DirBuilder::new()
        .recursive(true)
        .create(&root)
        .and_then(|()| fs::set_permissions(&root, fs::Permissions::from_mode(0o700)))
        .map_err(|e| {
            format!(
                "mkdir {}: {}",
                root.display(),
                errno_text(e.raw_os_error().unwrap_or(libc::EIO))
            )
        })?;
    let staging = root.join(format!(
        ".new-{key}-{}-{}",
        std::process::id(),
        TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    let record = Record {
        image: rec.name.clone(),
        parents,
    };
    let made = (|| {
        let mk = |p: &Path, mode: u32| -> Result<(), String> {
            fs::create_dir(p)
                .and_then(|()| fs::set_permissions(p, fs::Permissions::from_mode(mode)))
                .map_err(|e| {
                    format!(
                        "mkdir {}: {}",
                        p.display(),
                        errno_text(e.raw_os_error().unwrap_or(libc::EIO))
                    )
                })
        };
        mk(&staging, 0o700).map_err(|e| {
            format!("failed to create prepare snapshot dir: failed to create temp dir: {e}")
        })?;
        mk(&staging.join("fs"), 0o755)
            .map_err(|e| format!("failed to create prepare snapshot dir: {e}"))?;
        mk(&staging.join("work"), 0o711)
            .map_err(|e| format!("failed to create prepare snapshot dir: {e}"))?;
        if let Some(top) = record.parents.first() {
            let m = fs::metadata(store.layers_root().join(top)).map_err(|e| {
                format!(
                    "failed to stat parent: {}",
                    errno_text(e.raw_os_error().unwrap_or(libc::EIO))
                )
            })?;
            std::os::unix::fs::lchown(staging.join("fs"), Some(m.uid()), Some(m.gid())).map_err(
                |e| {
                    format!(
                        "failed to chown: lchown {}: {}",
                        staging.join("fs").display(),
                        errno_text(e.raw_os_error().unwrap_or(libc::EIO))
                    )
                },
            )?;
        }
        let b = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
        fs::write(staging.join(RECORD), b)
            .and_then(|()| {
                fs::set_permissions(staging.join(RECORD), fs::Permissions::from_mode(0o600))
            })
            .map_err(|e| format!("write {RECORD}: {e}"))?;
        match fs::rename(&staging, &dir) {
            Ok(()) => Ok(false),
            // Prepared meanwhile by another call: that one is kept.
            Err(_) if dir.is_dir() => Ok(true),
            Err(e) => Err(format!(
                "failed to rename: rename {} {}: {}",
                staging.display(),
                dir.display(),
                errno_text(e.raw_os_error().unwrap_or(libc::EIO))
            )),
        }
    })();
    match made {
        Ok(false) => Ok(mounts(store, &dir, &record)),
        Ok(true) => {
            super::layers::remove_tree(&staging);
            Ok(mounts(store, &dir, &read_record(&dir)?))
        }
        Err(e) => {
            super::layers::remove_tree(&staging);
            Err(e)
        }
    }
}

/// Remove: container key's root filesystem goes; none is not an error.
pub fn release(store: &Store, key: &str) -> Result<(), String> {
    if !valid_key(key) {
        return Err(format!(
            "invalid snapshot key {}",
            crate::net::addr::quote(key)
        ));
    }
    let dir = active_root(store).join(key);
    match fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        _ => {}
    }
    super::layers::remove_tree(&dir);
    if fs::symlink_metadata(&dir).is_ok() {
        return Err(format!(
            "remove {}: the directory is still there",
            dir.display()
        ));
    }
    Ok(())
}

/// The chain ID hexes active snapshots stand on, which a collection
/// keeps; staging directories a crashed prepare left are removed (only
/// while no prepare runs: the pull lock is held exclusively).
pub fn in_use(store: &Store) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(rd) = fs::read_dir(active_root(store)) else {
        return out;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with(".new-") {
            super::layers::remove_tree(&e.path());
            continue;
        }
        match read_record(&e.path()) {
            Ok(r) => out.extend(r.parents),
            // A snapshot whose record cannot be read keeps every layer:
            // nothing is collected rather than its layers taken.
            Err(_) => {
                out.insert("*".into());
            }
        }
    }
    out
}

/// The keys of every active snapshot, sorted.
pub fn keys(store: &Store) -> Vec<String> {
    let mut out: Vec<String> = fs::read_dir(active_root(store))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.'))
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_names() {
        assert!(valid_key("web-r1-3f2a"));
        assert!(!valid_key(""));
        assert!(!valid_key("."));
        assert!(!valid_key(".."));
        assert!(!valid_key(".new-x"));
        assert!(!valid_key("a/b"));
        assert!(!valid_key(&"x".repeat(256)));
    }
}

//! Unpacked layers in the store: layers/<chain ID hex>/ for each chain ID
//! of a recorded image, what the overlay snapshotter keeps as a
//! committed snapshot's fs/ directory. A layer is unpacked into a
//! directory of its own under layers/ and renamed into place once it is
//! complete, its parent chain first; a chain already there is kept.

use super::check;
use super::digest::{Algorithm, Digest, chain_ids};
use super::registry::Descriptor;
use super::store::Store;
use super::unpack;
use std::fs;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP: AtomicU64 = AtomicU64::new(0);

/// A reader hashing what passes through it.
struct Tee<R> {
    r: R,
    h: super::digest::Hasher,
}

impl<R: Read> Read for Tee<R> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let n = self.r.read(b)?;
        self.h.update(&b[..n]);
        Ok(n)
    }
}

/// The directories overlay mounts as lower directories for an image whose
/// diff IDs these are, the top layer first (the overlay snapshotter's
/// lowerdir order).
pub fn lower_dirs(store: &Store, diffs: &[Digest]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = chain_ids(diffs)
        .iter()
        .map(|c| store.layer_dir(c))
        .collect();
    out.reverse();
    out
}

/// ApplyLayers: every layer of the chain unpacked, from the first missing
/// one up; a layer whose chain is already there is checked against its
/// diff ID instead (unless verified holds it), since chains are named by
/// diff IDs alone. Returns the blobs shown to be their layers.
pub fn unpack_chain(
    store: &Store,
    layers: &[Descriptor],
    diffs: &[Digest],
    verified: &std::collections::BTreeMap<String, Digest>,
) -> Result<Vec<(String, Digest)>, String> {
    let chains = chain_ids(diffs);
    let mut shown = Vec::new();
    for (i, (blob, diff)) in layers.iter().zip(diffs).enumerate() {
        if !store.layer_dir(&chains[i]).is_dir() {
            continue;
        }
        if verified.get(&blob.digest.to_string()) == Some(diff) {
            continue;
        }
        let f = store
            .open_blob(&blob.digest)
            .map_err(|e| format!("layer {}: {e}", blob.digest))?;
        check::layer(f, &blob.digest, diff)?;
        shown.push((blob.digest.to_string(), diff.clone()));
    }
    let Some(top) = chains.last() else {
        return Ok(shown);
    };
    if store.layer_dir(top).is_dir() {
        return Ok(shown);
    }
    // The first chain missing from the top down: every one above it is
    // missing too (a parent goes only with its children).
    let mut first = chains.len() - 1;
    while first > 0 && !store.layer_dir(&chains[first - 1]).is_dir() {
        first -= 1;
    }
    for i in first..chains.len() {
        if store.layer_dir(&chains[i]).is_dir() {
            continue;
        }
        let parents: Vec<PathBuf> = chains[..i]
            .iter()
            .rev()
            .map(|c| store.layer_dir(c))
            .collect();
        unpack_layer(store, &layers[i], &diffs[i], &chains[i], &parents)
            .map_err(|e| format!("unpack: {e}"))?;
        shown.push((layers[i].digest.to_string(), diffs[i].clone()));
    }
    Ok(shown)
}

/// One layer applied over its parents (the closest first) into a
/// directory of its own, renamed to the chain's once complete.
fn unpack_layer(
    store: &Store,
    blob: &Descriptor,
    diff: &Digest,
    chain: &Digest,
    parents: &[PathBuf],
) -> Result<(), String> {
    let staging = store.layers_root().join(format!(
        ".new-{}-{}-{}",
        chain.hex(),
        std::process::id(),
        TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        // prepareDirectory and createSnapshot: 0755, owned like the
        // parent's directory.
        fs::create_dir(&staging).map_err(|e| format!("mkdir {}: {e}", staging.display()))?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
        if let Some(p) = parents.first() {
            let m = fs::metadata(p).map_err(|e| format!("failed to stat parent: {e}"))?;
            std::os::unix::fs::lchown(&staging, Some(m.uid()), Some(m.gid()))
                .map_err(|e| format!("failed to chown: {e}"))?;
        }
        let f = store.open_blob(&blob.digest)?;
        let r = check::layer_reader(f, &blob.media_type)
            .map_err(|e| format!("failed to extract layer {diff}: {e}"))?;
        // The applier's digest is the canonical algorithm's.
        let mut tee = Tee {
            r,
            h: Algorithm::Sha256.hasher(),
        };
        let ps: Vec<Vec<u8>> = parents
            .iter()
            .map(|p| p.as_os_str().as_bytes().to_vec())
            .collect();
        unpack::apply(staging.as_os_str().as_bytes(), &mut tee, &ps)
            .map_err(|e| format!("failed to extract layer {diff}: {e}"))?;
        io::copy(&mut tee, &mut io::sink())
            .map_err(|e| format!("failed to extract layer {diff}: {e}"))?;
        let got = tee.h.finish();
        if got != *diff {
            return Err(format!(
                "wrong diff id calculated on extraction {:?}",
                got.to_string()
            ));
        }
        match fs::rename(&staging, store.layer_dir(chain)) {
            Ok(()) => Ok(()),
            // Another pull unpacked it first.
            Err(_) if store.layer_dir(chain).is_dir() => {
                remove_tree(&staging);
                Ok(())
            }
            Err(e) => Err(format!("commit {chain}: {e}")),
        }
    })();
    if result.is_err() {
        remove_tree(&staging);
    }
    result
}

/// Removes a directory tree, making directories writable where the
/// tree's own modes would refuse it.
pub fn remove_tree(p: &Path) {
    if fs::remove_dir_all(p).is_ok() || fs::symlink_metadata(p).is_err() {
        return;
    }
    fn open_up(p: &Path) {
        let Ok(m) = fs::symlink_metadata(p) else {
            return;
        };
        if !m.is_dir() {
            return;
        }
        let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
        if let Ok(rd) = fs::read_dir(p) {
            for e in rd.flatten() {
                open_up(&e.path());
            }
        }
    }
    open_up(p);
    let _ = fs::remove_dir_all(p);
}

/// Removes every entry under held/ (`<chain ID hex>.<n>`: a layer of an
/// earlier store a container moved into this store may still mount)
/// whose chain no active snapshot names (active is
/// snapshot::in_use; "*" keeps them all). Returns whether any is left.
pub fn collect_held(store: &Store, active: &std::collections::BTreeSet<String>) -> bool {
    let Ok(rd) = fs::read_dir(store.root().join("held")) else {
        return false;
    };
    let mut left = false;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let chain = name.split('.').next().unwrap_or_default();
        if active.contains("*") || active.contains(chain) {
            left = true;
            continue;
        }
        remove_tree(&e.path());
        if fs::symlink_metadata(e.path()).is_ok() {
            left = true;
        }
    }
    left
}

/// Removes every entry under layers/ that is not one of keep (chain ID
/// hexes): unused layers, and unpacks a crashed pull left behind. Only
/// while no pull runs.
pub fn collect(store: &Store, keep: &std::collections::BTreeSet<String>) {
    let Ok(rd) = fs::read_dir(store.layers_root()) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !keep.contains(&name) {
            remove_tree(&e.path());
        }
    }
}

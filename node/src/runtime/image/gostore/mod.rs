//! The move of a node from Go's image store (<data dir>/supervisor/images:
//! containerd's content store, the overlay snapshotter, images.json) to
//! this store (<data dir>/node/images), ADR 0054 "The runtime's move", for
//! the Rust agent: internal/runtime/supervisor's convert.go (convert.rs),
//! move.go (this file), and hold.go (hold.rs), RevertImages aside (the
//! Rust agent runs only on this store). The snapshotter's metadata.db is
//! read with bolt.rs, never written: a container's root filesystem left in
//! Go's store is not removed from it on release, but goes with the whole
//! store once no container stands on it (collect_go).
//!
//! Go's TestRustMove (internal/runtime/supervisor rustmove_test.go) keeps
//! what Go's code does to stores it built in testdata/rust/move.json; the
//! tests here replay it.

pub mod bolt;
pub mod convert;
pub mod hold;

use super::digest::Digest;
use crate::runtime::container::bundle::{self, Record};
use crate::runtime::container::errno_text;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use convert::{ConvertSummary, convert_images};
pub use hold::{MOUNTINFO, remove_go_store};

/// The record, in armada-node's directory (<data dir>/node), that Go's
/// image store was converted into this one (supervisor.MovedFile).
pub const MOVED_FILE: &str = "converted.json";
const MOVE_STATE_VERSION: i64 = 1;

/// MoveState: MOVED_FILE as Go writes and reads it.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MoveState {
    #[serde(default)]
    pub version: i64,
    /// When the conversion ran, as Go's time.Time marshals it.
    #[serde(default)]
    pub at: String,
    /// The images in this store after the conversion: converted, or
    /// recorded here before.
    #[serde(default)]
    pub converted: i64,
    /// Each image the conversion left out, and why.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "crate::runtime::nullable"
    )]
    pub skipped: BTreeMap<String, String>,
    /// The unpacked layers moved.
    #[serde(default)]
    pub layers: i64,
    /// The containers' root filesystems moved into this store, and each
    /// container whose root filesystem stayed in Go's with why.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub containers: i64,
    #[serde(
        rename = "containersLeft",
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "crate::runtime::nullable"
    )]
    pub containers_left: BTreeMap<String, String>,
    /// Go's image store is gone.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub collected: bool,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// "op path: errno", as Go's *PathError prints.
pub(crate) fn os_err(op: &str, p: &Path, e: &io::Error) -> String {
    format!("{op} {}: {}", p.display(), errno(e))
}

pub(crate) fn errno(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(n) => errno_text(n),
        None => e.to_string(),
    }
}

/// *LinkError's text for a rename.
pub(crate) fn rename_err(from: &Path, to: &Path, e: &io::Error) -> String {
    format!("rename {} {}: {}", from.display(), to.display(), errno(e))
}

fn not_found(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound
}

pub(crate) fn exists(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok()
}

pub(crate) fn mkdir_all(p: &Path) -> Result<(), String> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(p)
        .map_err(|e| os_err("mkdir", p, &e))
}

/// writeSynced: path written whole (0600) and synced.
pub(crate) fn write_synced(path: &Path, b: &[u8]) -> Result<(), String> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| os_err("open", path, &e))?;
    f.write_all(b)
        .and_then(|()| f.sync_all())
        .map_err(|e| os_err("write", path, &e))
}

/// ReadMoveState: None when there is no record.
pub fn read_move_state(path: &Path) -> Result<Option<MoveState>, String> {
    let b = match fs::read(path) {
        Err(e) if not_found(&e) => return Ok(None),
        Err(e) => return Err(os_err("open", path, &e)),
        Ok(b) => b,
    };
    let st: MoveState =
        serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))?;
    if st.version > MOVE_STATE_VERSION {
        return Err(format!(
            "{}: version {} is newer than {MOVE_STATE_VERSION}",
            path.display(),
            st.version
        ));
    }
    Ok(Some(st))
}

/// writeMoveState: the record at path, atomically.
pub fn write_move_state(path: &Path, st: &MoveState) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        mkdir_all(dir)?;
    }
    let mut st = st.clone();
    st.version = MOVE_STATE_VERSION;
    let b = serde_json::to_vec(&st).map_err(|e| e.to_string())?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    write_synced(&tmp, &b)?;
    fs::rename(&tmp, path).map_err(|e| rename_err(&tmp, path, &e))
}

/// The kinds of the snapshotter's snapshots (snapshots.Kind).
pub const KIND_VIEW: u8 = 1;
pub const KIND_ACTIVE: u8 = 2;
pub const KIND_COMMITTED: u8 = 3;

/// One snapshot of Go's overlay snapshotter: its directory
/// (<root>/snapshots/<id>, holding fs and, when active, work), kind, and
/// parent's name.
#[derive(Clone, Debug, PartialEq)]
pub struct GoSnapshot {
    pub dir: PathBuf,
    pub kind: u8,
    pub parent: String,
}

/// readSnapshots: every snapshot of the overlay snapshotter under root
/// (<Go's store>/snapshots) from its metadata.db, read-only; none when it
/// has no metadata.
pub fn read_snapshots(root: &Path) -> Result<BTreeMap<String, GoSnapshot>, String> {
    let db = root.join("metadata.db");
    if let Err(e) = fs::metadata(&db)
        && not_found(&e)
    {
        return Ok(BTreeMap::new());
    }
    let db = bolt::Db::open(&db, Duration::from_secs(5))?;
    let read = || -> Result<BTreeMap<String, GoSnapshot>, String> {
        let mut out = BTreeMap::new();
        let Some(v1) = db.root().bucket(b"v1")? else {
            return Err("bucket does not exist: not found".into());
        };
        let Some(snaps) = v1.bucket(b"snapshots")? else {
            return Ok(out);
        };
        snaps.for_each(&mut |name, e| {
            // WalkInfo skips what is not a bucket.
            let bolt::Entry::Bucket(b) = e else {
                return Ok(());
            };
            let kind = match b.get(b"kind")? {
                Some([k]) => *k,
                _ => 0,
            };
            let id = uvarint(b.get(b"id")?.unwrap_or_default());
            let parent = String::from_utf8_lossy(b.get(b"parent")?.unwrap_or_default());
            out.insert(
                String::from_utf8_lossy(name).into_owned(),
                GoSnapshot {
                    dir: root.join("snapshots").join(id.to_string()),
                    kind,
                    parent: parent.into_owned(),
                },
            );
            Ok(())
        })?;
        Ok(out)
    };
    read().map_err(|e| format!("snapshots: {e}"))
}

/// binary.Uvarint, 0 for what does not decode.
fn uvarint(b: &[u8]) -> u64 {
    let mut x: u64 = 0;
    let mut s = 0u32;
    for (i, &c) in b.iter().enumerate() {
        if i == 10 {
            return 0;
        }
        if c < 0x80 {
            if i == 9 && c > 1 {
                return 0;
            }
            return x | (u64::from(c) << s);
        }
        x |= u64::from(c & 0x7f) << s;
        s += 7;
    }
    0
}

/// committedSnapshots: each committed snapshot's name (a chain ID) and
/// the directory of its files.
pub fn committed_snapshots(root: &Path) -> Result<BTreeMap<String, PathBuf>, String> {
    Ok(read_snapshots(root)?
        .into_iter()
        .filter(|(_, s)| s.kind == KIND_COMMITTED)
        .map(|(n, s)| (n, s.dir.join("fs")))
        .collect())
}

/// validKey: armada-node's rule for a snapshot key.
fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 255 && !key.starts_with('.') && !key.contains(['/', '\0'])
}

/// A container's root filesystem in this store (snapshot.rs's record).
#[derive(Serialize, Deserialize)]
pub(crate) struct NodeSnapshot {
    pub image: String,
    pub parents: Vec<String>,
}

/// MoveImages: moves a node from Go's image store under src to this one
/// under dst before the runtime starts, with neither store in use:
///
///  1. Unless the record at state_path exists, convert_images converts
///     the images (the summary; None when it did not run).
///  2. The root filesystem of every container whose bundle (under
///     bundles) stands on an active snapshot of Go's store moves into this
///     store's layout (move_active), running or not.
///  3. The record is written; once no container's root filesystem is left
///     in Go's store, the store is removed (remove_go_store, which holds
///     the layers moved containers' overlays still mount) and the record
///     says so.
///
/// Every step can run again after a crash and finds what it did. A node
/// with no Go store gets a record at once. mountinfo is /proc/self/mountinfo
/// (another file in tests).
pub fn move_images(
    src: &Path,
    dst: &Path,
    bundles: &Path,
    state_path: &Path,
    mountinfo: &Path,
) -> (MoveState, Option<ConvertSummary>, Result<(), String>) {
    let mut sum = None;
    let mut st = match read_move_state(state_path) {
        Err(e) => return (MoveState::default(), None, Err(e)),
        Ok(Some(st)) if st.collected => return (st, None, Ok(())),
        Ok(Some(st)) => st,
        Ok(None) => {
            let mut st = MoveState {
                at: super::now_rfc3339(),
                ..Default::default()
            };
            match fs::metadata(src) {
                Err(e) if not_found(&e) => {
                    st.collected = true;
                    let r = write_move_state(state_path, &st);
                    return (st, None, r);
                }
                Err(e) => return (st, None, Err(os_err("stat", src, &e))),
                Ok(_) => {}
            }
            let (s, r) = convert_images(src, dst);
            if let Err(e) = r {
                return (st, Some(s), Err(e));
            }
            st.converted = (s.converted.len() + s.kept.len()) as i64;
            st.layers = s.layers as i64;
            st.skipped = s.skipped.clone();
            sum = Some(s);
            st
        }
    };
    let (moved, layers, left, r) = move_active(src, dst, bundles);
    st.layers += layers as i64;
    if let Err(e) = r {
        return (st, sum, Err(e));
    }
    st.containers = moved as i64;
    st.containers_left = left;
    // The record first: a crash while removing Go's store repeats the
    // removal at the next start.
    if let Err(e) = write_move_state(state_path, &st) {
        return (st, sum, Err(e));
    }
    if !st.containers_left.is_empty() {
        return (st, sum, Ok(()));
    }
    if let Err(e) = remove_go_store(src, dst, mountinfo) {
        return (st, sum, Err(e));
    }
    st.collected = true;
    let r = write_move_state(state_path, &st);
    (st, sum, r)
}

/// moveActive: the root filesystem of every container whose bundle under
/// bundles stands on an active snapshot of Go's store under src moves into
/// dst as armada-node's prepare would have made it for that container ID
/// (active/<ID>/ with fs/, work/, and snapshot.json naming the image and
/// its layers, the top first), with one rename of the snapshot's
/// directory; its layers not in dst yet move to layers/<chain ID hex>
/// first. Returns the root filesystems in dst's layout (moved now or
/// before), the layers moved, and the containers left in Go's store with
/// why. Bundle records that cannot be read are left out, as armada-node's
/// listing leaves them out (Go's Bundles.Records fails the move).
pub fn move_active(
    src: &Path,
    dst: &Path,
    bundles: &Path,
) -> (usize, usize, BTreeMap<String, String>, Result<(), String>) {
    let mut left = BTreeMap::new();
    let (mut moved, mut layers) = (0, 0);
    let snaps = match read_snapshots(&src.join("snapshots")) {
        Ok(s) => s,
        Err(e) => return (0, 0, left, Err(e)),
    };
    let recs = match bundle::records(&bundles.display().to_string()) {
        Ok((r, _)) => r,
        Err(e) => return (0, 0, left, Err(e)),
    };
    for rec in &recs {
        let Some(sn) = snaps.get(&rec.id).filter(|s| s.kind == KIND_ACTIVE) else {
            continue; // armada-node's own, or none
        };
        let target = dst.join("active").join(&rec.id);
        if !exists(&sn.dir) {
            if exists(&target.join("snapshot.json")) {
                moved += 1; // by an earlier run
            }
            continue;
        }
        if !valid_key(&rec.id) {
            left.insert(
                rec.id.clone(),
                "not a snapshot key armada-node takes".into(),
            );
            continue;
        }
        if exists(&target) {
            left.insert(
                rec.id.clone(),
                "armada-node's store already has a root filesystem for it".into(),
            );
            continue;
        }
        let mut parents = Vec::new();
        let mut why = String::new();
        let mut p = sn.parent.clone();
        while !p.is_empty() {
            let ps = snaps.get(&p);
            let d = Digest::parse(&p);
            let (Some(ps), Ok(d)) = (ps.filter(|s| s.kind == KIND_COMMITTED), d) else {
                why = format!("layer {p} is not a layer of Go's store");
                break;
            };
            let layer = dst.join("layers").join(d.hex());
            if !exists(&layer) {
                if let Err(e) = mkdir_all(&dst.join("layers")) {
                    return (moved, layers, left, Err(e));
                }
                let from = ps.dir.join("fs");
                if let Err(e) = fs::rename(&from, &layer) {
                    why = format!("layer {p}: {}", rename_err(&from, &layer, &e));
                    break;
                }
                layers += 1;
            }
            parents.push(d.hex().to_string());
            p = ps.parent.clone();
        }
        if !why.is_empty() {
            left.insert(rec.id.clone(), why);
            continue;
        }
        let b = match serde_json::to_vec(&NodeSnapshot {
            image: rec.image.clone(),
            parents,
        }) {
            Ok(b) => b,
            Err(e) => return (moved, layers, left, Err(e.to_string())),
        };
        if let Err(e) = write_synced(&sn.dir.join("snapshot.json"), &b) {
            return (moved, layers, left, Err(e));
        }
        if let Err(e) = mkdir_all(&dst.join("active")) {
            return (moved, layers, left, Err(e));
        }
        if let Err(e) = fs::rename(&sn.dir, &target) {
            left.insert(rec.id.clone(), rename_err(&sn.dir, &target, &e));
            continue;
        }
        moved += 1;
    }
    (moved, layers, left, Ok(()))
}

/// What collect_go did.
#[derive(Debug, PartialEq)]
pub enum Collected {
    /// Nothing to do: no Go store, no record, or a container still on it.
    No,
    /// Go's store is gone and the record says so.
    Yes,
}

/// Store.CollectGo: removes Go's image store under src once the record at
/// state_path says it was converted and no container's root filesystem is
/// on it (no bundle record, among records, names a snapshot of Go's store
/// that did not move into dst); the record then says so.
pub fn collect_go(
    src: &Path,
    dst: &Path,
    state_path: &Path,
    records: &[Record],
    mountinfo: &Path,
) -> Result<Collected, String> {
    if !exists(src) {
        return Ok(Collected::No);
    }
    let mut st = match read_move_state(state_path) {
        Ok(Some(st)) => st,
        _ => return Ok(Collected::No),
    };
    // hasSnapshot: a metadata.db that cannot be read counts as naming
    // every container.
    let Ok(snaps) = read_snapshots(&src.join("snapshots")) else {
        return Ok(Collected::No);
    };
    for r in records {
        let moved_out = valid_key(&r.id) && exists(&dst.join("active").join(&r.id));
        if snaps.contains_key(&r.id) && !moved_out {
            return Ok(Collected::No);
        }
    }
    remove_go_store(src, dst, mountinfo)?;
    st.collected = true;
    write_move_state(state_path, &st)?;
    Ok(Collected::Yes)
}

#[cfg(test)]
mod tests;

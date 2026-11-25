//! hold.go: a container whose root filesystem moved from Go's image store
//! keeps its overlay mount, and with it every lower directory the mount
//! was made with. Where this store already had a layer, the move leaves
//! Go's directory of it in Go's store and names this store's own in
//! snapshot.json; before Go's store goes, hold_layers renames every such
//! directory to held/<chain ID hex>.<n> here, which a collection removes
//! once no active snapshot names that chain (layers::collect_held).

use super::super::digest::Digest;
use super::super::store::{INDEX_FILE, Store};
use super::{KIND_COMMITTED, NodeSnapshot, exists, mkdir_all, os_err, read_snapshots, rename_err};
use std::collections::BTreeSet;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

/// Where held layers live in this store.
const HELD_DIR: &str = "held";

/// The mounts read for directories of Go's store still in use.
pub const MOUNTINFO: &str = "/proc/self/mountinfo";

/// activeParents: the chain ID hexes this store's active snapshots under
/// dst stand on; all is true when a record cannot be read.
fn active_parents(dst: &Path) -> Result<(BTreeSet<String>, bool), String> {
    let mut named = BTreeSet::new();
    let mut all = false;
    let dir = dst.join("active");
    let rd = match fs::read_dir(&dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((named, false)),
        Err(e) => return Err(os_err("open", &dir, &e)),
        Ok(rd) => rd,
    };
    for e in rd {
        let e = e.map_err(|e| os_err("readdirent", &dir, &e))?;
        if e.file_name().to_string_lossy().starts_with('.') {
            continue; // a staging directory: a prepare in progress
        }
        let rec = fs::read(e.path().join("snapshot.json"))
            .map_err(|e| e.to_string())
            .and_then(|b| serde_json::from_slice::<NodeSnapshot>(&b).map_err(|e| e.to_string()));
        match rec {
            Ok(r) => named.extend(r.parents),
            Err(_) => all = true,
        }
    }
    Ok((named, all))
}

/// updateNodeIndex marking the store for a collection: under this store's
/// locks, and only when it has an index.
fn mark_uncollected(dst: &Path) -> Result<(), String> {
    let store = Store::at(dst);
    let _pulls = store.lock_exclusive("pull.lock")?;
    let _index = store.lock_exclusive("index.lock")?;
    if !exists(&dst.join(INDEX_FILE)) {
        return Ok(());
    }
    let mut idx = store.read_index()?;
    idx.uncollected = true;
    store.write_index(&mut idx)
}

/// holdLayers: each committed snapshot directory of Go's store under src
/// whose chain an active snapshot of this store under dst names (every
/// one when a record cannot be read) moves to <dst>/held/<hex>.<n>, and
/// the index is marked for a collection. Returns how many moved.
pub fn hold_layers(src: &Path, dst: &Path) -> Result<usize, String> {
    let snaps = read_snapshots(&src.join("snapshots"))?;
    let (named, all) = active_parents(dst)?;
    let mut held = 0;
    for (name, sn) in &snaps {
        if sn.kind != KIND_COMMITTED {
            continue;
        }
        let Ok(d) = Digest::parse(name) else {
            continue;
        };
        if !all && !named.contains(d.hex()) {
            continue;
        }
        let from = sn.dir.join("fs");
        if !exists(&from) {
            continue; // moved to layers/ by the conversion, or held before
        }
        mkdir_all(&dst.join(HELD_DIR))?;
        let to = free_held_name(dst, d.hex())?;
        fs::rename(&from, &to)
            .map_err(|e| format!("hold layer {name}: {}", rename_err(&from, &to, &e)))?;
        held += 1;
    }
    if held > 0 {
        mark_uncollected(dst)?;
    }
    Ok(held)
}

/// freeHeldName: the first <dst>/held/<hex>.<n> not taken.
fn free_held_name(dst: &Path, hex: &str) -> Result<PathBuf, String> {
    for n in 0..1 << 16 {
        let p = dst.join(HELD_DIR).join(format!("{hex}.{n}"));
        match fs::symlink_metadata(&p) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(p),
            Err(e) => return Err(os_err("lstat", &p, &e)),
            Ok(_) => {}
        }
    }
    Err(format!("no free name to hold layer {hex}"))
}

/// mountedUnder: a directory under root that a mounted overlay still
/// names (lowerdir, upperdir, workdir) and that is still there, or None.
/// Overlay options keep the paths the mount was made with, so a directory
/// renamed away since no longer shows. Relative lower directories are not
/// seen.
pub fn mounted_under(root: &Path, mountinfo: &Path) -> Result<Option<String>, String> {
    let f = fs::File::open(mountinfo).map_err(|e| os_err("open", mountinfo, &e))?;
    let mut prefix = root.display().to_string();
    while prefix.len() > 1 && prefix.ends_with('/') {
        prefix.pop();
    }
    prefix.push('/');
    for line in BufReader::new(f).split(b'\n') {
        let line = line.map_err(|e| e.to_string())?;
        if line.len() > 1 << 20 {
            return Err("bufio.Scanner: token too long".into());
        }
        let line = String::from_utf8_lossy(&line);
        let Some((_, after)) = line.split_once(" - ") else {
            continue;
        };
        let fields: Vec<&str> = after.split_ascii_whitespace().collect();
        if fields.len() < 3 || fields[0] != "overlay" {
            continue;
        }
        for opt in fields[2].split(',') {
            let Some((key, val)) = opt.split_once('=') else {
                continue;
            };
            if !matches!(
                key,
                "lowerdir" | "upperdir" | "workdir" | "lowerdir+" | "datadir+"
            ) {
                continue;
            }
            for p in split_unescaped(val) {
                let p = unescape_mount_info(&p);
                if p.starts_with(&prefix) && exists(Path::new(&p)) {
                    return Ok(Some(p));
                }
            }
        }
    }
    Ok(None)
}

/// splitUnescaped: an overlay directory list split on colons not escaped
/// with a backslash.
fn split_unescaped(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() && b[i + 1] == b':' {
            cur.push(b':');
            i += 1;
        } else if b[i] == b':' {
            out.push(String::from_utf8_lossy(&cur).into_owned());
            cur.clear();
        } else {
            cur.push(b[i]);
        }
        i += 1;
    }
    out.push(String::from_utf8_lossy(&cur).into_owned());
    out
}

/// unescapeMountInfo: mountinfo's octal escapes undone (three octal
/// digits whose value fits a byte).
fn unescape_mount_info(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 4 <= b.len()
            && let Ok(n) =
                u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 4]).unwrap_or("x"), 8)
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            out.push(n);
            i += 4;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// removeGoStore: Go's image store under src goes once no mount needs it:
/// the layers this store's active snapshots name are held first, and a
/// directory a mounted overlay still names refuses the removal.
pub fn remove_go_store(src: &Path, dst: &Path, mountinfo: &Path) -> Result<(), String> {
    if !exists(src) {
        return Ok(());
    }
    hold_layers(src, dst).map_err(|e| format!("hold the layers of moved containers: {e}"))?;
    match mounted_under(src, mountinfo) {
        Err(e) => return Err(format!("read the mounts: {e}")),
        Ok(Some(p)) => return Err(format!("a mounted overlay still uses {p}")),
        Ok(None) => {}
    }
    super::super::layers::remove_tree(src);
    if exists(src) {
        return Err(format!(
            "remove Go's image store: unlinkat {}: directory not empty",
            src.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mountinfo_lists_and_escapes() {
        assert_eq!(split_unescaped(r"/a:/b\:c:/d"), ["/a", "/b:c", "/d"]);
        assert_eq!(unescape_mount_info(r"/a\040b\134c\9zz"), "/a b\\c\\9zz");
    }

    #[test]
    fn finds_overlays_naming_the_store() {
        let dir = std::env::temp_dir().join(format!("armada-mounted-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = dir.join("go store");
        fs::create_dir_all(store.join("snapshots/1/fs")).unwrap();
        let mi = dir.join("mountinfo");
        let line = |opts: &str| {
            format!("36 35 0:31 / /run/x rw,relatime shared:1 - overlay overlay rw,{opts}\n")
        };
        let esc = store.display().to_string().replace(' ', "\\040");
        fs::write(
            &mi,
            line(&format!(
                "lowerdir={esc}/snapshots/9/fs:{esc}/snapshots/1/fs,upperdir=/u,workdir=/w"
            )),
        )
        .unwrap();
        assert_eq!(
            mounted_under(&store, &mi).unwrap(),
            Some(format!("{}/snapshots/1/fs", store.display()))
        );
        // Renamed away since: not in use.
        fs::rename(store.join("snapshots/1"), dir.join("elsewhere")).unwrap();
        assert_eq!(mounted_under(&store, &mi).unwrap(), None);
        // Not an overlay.
        fs::write(&mi, "36 35 0:31 / /run/x rw - ext4 /dev/sda rw\n").unwrap();
        assert_eq!(mounted_under(&store, &mi).unwrap(), None);
        let _ = fs::remove_dir_all(&dir);
    }
}

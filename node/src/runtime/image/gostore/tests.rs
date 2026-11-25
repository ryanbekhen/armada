//! The move against Go's: what Go's TestRustMove
//! (internal/runtime/supervisor/rustmove_test.go) kept in
//! testdata/rust/move.json, replayed. Each case's data directory is
//! written as it was before Go's MoveImages or CollectGo ran, the same is
//! done here, and the tree after, the summary, and what metadata.db reads
//! as must be Go's.

use super::*;
use crate::runtime::container::bundle;
use serde_json::{Map, Value};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

const DATA: &str = "DATA";

fn b64_decode(s: &str) -> Vec<u8> {
    crate::net::key::b64_decode(s).expect("base64")
}

fn b64_encode(b: &[u8]) -> String {
    crate::net::key::b64_encode(b)
}

fn fixture() -> Vec<Value> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../internal/runtime/supervisor/testdata/rust/move.json");
    let v: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
    v["cases"].as_array().unwrap().clone()
}

fn mode(e: &Value) -> u32 {
    e["mode"].as_u64().unwrap() as u32
}

/// Writes a tree rmTree read; directories' modes are set last, deepest
/// first.
fn write_tree(root: &Path, tree: &Map<String, Value>) {
    let mut paths: Vec<&String> = tree.keys().collect();
    paths.sort();
    for p in &paths {
        let e = &tree[*p];
        let at = root.join(p);
        match e["type"].as_str().unwrap() {
            "dir" => fs::create_dir_all(&at).unwrap(),
            "link" => {
                fs::create_dir_all(at.parent().unwrap()).unwrap();
                symlink(e["target"].as_str().unwrap(), &at).unwrap();
            }
            _ if e["same"].is_string() => {
                fs::create_dir_all(at.parent().unwrap()).unwrap();
                fs::hard_link(root.join(e["same"].as_str().unwrap()), &at).unwrap();
            }
            _ => {
                fs::create_dir_all(at.parent().unwrap()).unwrap();
                let mut b = vec![0u8; e["size"].as_u64().unwrap_or(0) as usize];
                if let Some(chunks) = e["chunks"].as_object() {
                    for (off, c) in chunks {
                        let off: usize = off.parse().unwrap();
                        let c = b64_decode(c.as_str().unwrap());
                        b[off..off + c.len()].copy_from_slice(&c);
                    }
                }
                fs::write(&at, &b).unwrap();
                fs::set_permissions(&at, fs::Permissions::from_mode(mode(e))).unwrap();
            }
        }
    }
    for p in paths.iter().rev() {
        let e = &tree[*p];
        if e["type"] == "dir" {
            fs::set_permissions(root.join(p), fs::Permissions::from_mode(mode(e))).unwrap();
        }
    }
}

/// rmTree after a run: .json files as values with root replaced, and for
/// each file how many of the tree's files are the same file.
fn read_tree(root: &Path) -> Map<String, Value> {
    let mut out = Map::new();
    let mut inodes = BTreeMap::new();
    let r = root.display().to_string();
    fn walk(
        root: &Path,
        dir: &Path,
        r: &str,
        out: &mut Map<String, Value>,
        inodes: &mut BTreeMap<String, u64>,
    ) {
        let mut ents: Vec<_> = fs::read_dir(dir).unwrap().flatten().collect();
        ents.sort_by_key(|e| e.file_name());
        for e in ents {
            let p = e.path();
            let rel = p.strip_prefix(root).unwrap().display().to_string();
            let m = fs::symlink_metadata(&p).unwrap();
            let mut v = Map::new();
            v.insert("mode".into(), (m.mode() & 0o777).into());
            if m.file_type().is_symlink() {
                v.insert("type".into(), "link".into());
                v.insert(
                    "target".into(),
                    fs::read_link(&p).unwrap().display().to_string().into(),
                );
            } else if m.is_dir() {
                v.insert("type".into(), "dir".into());
                walk(root, &p, r, out, inodes);
            } else {
                v.insert("type".into(), "file".into());
                inodes.insert(rel.clone(), m.ino());
                let b = fs::read(&p).unwrap();
                if rel.ends_with(".json") {
                    let s = String::from_utf8(b).unwrap().replace(r, DATA);
                    v.insert("json".into(), serde_json::from_str(&s).unwrap());
                } else {
                    if !b.is_empty() {
                        v.insert("size".into(), b.len().into());
                    }
                    let mut chunks = Map::new();
                    for (i, c) in b.chunks(4096).enumerate() {
                        let end = c.iter().rposition(|&x| x != 0).map_or(0, |n| n + 1);
                        if end > 0 {
                            chunks.insert((i * 4096).to_string(), b64_encode(&c[..end]).into());
                        }
                    }
                    if !chunks.is_empty() {
                        v.insert("chunks".into(), chunks.into());
                    }
                }
            }
            out.insert(rel, v.into());
        }
    }
    walk(root, root, &r, &mut out, &mut inodes);
    for (rel, ino) in &inodes {
        let n = inodes.values().filter(|i| *i == ino).count();
        out[rel]["nlink"] = n.into();
    }
    out
}

/// Go's times in records and the record of the move: the conversion's
/// own (converted.json "at") is the run's.
fn without_run_times(mut tree: Map<String, Value>) -> Map<String, Value> {
    if let Some(v) = tree.get_mut("node/converted.json") {
        v["json"]["at"] = "AT".into();
    }
    tree
}

fn data_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("armada-gostore-{name}-{}", std::process::id()));
    if d.exists() {
        super::super::layers::remove_tree(&d);
    }
    fs::create_dir_all(&d).unwrap();
    d
}

fn diff(want: &Map<String, Value>, got: &Map<String, Value>) -> Vec<String> {
    let mut out = Vec::new();
    for (k, w) in want {
        match got.get(k) {
            None => out.push(format!("missing {k}: {w}")),
            Some(g) if g != w => out.push(format!("{k}:\n  go:   {w}\n  rust: {g}")),
            _ => {}
        }
    }
    for k in got.keys() {
        if !want.contains_key(k) {
            out.push(format!("extra {k}: {}", got[k]));
        }
    }
    out
}

#[test]
fn moves_as_go() {
    let mountinfo = Path::new(MOUNTINFO);
    for c in fixture() {
        let name = c["name"].as_str().unwrap();
        let data = data_dir(name);
        write_tree(&data, c["before"].as_object().unwrap());
        let src = data.join("supervisor/images");
        let dst = data.join("node/images");
        let bundles = data.join("supervisor/containers");
        let state = data.join("node").join(MOVED_FILE);

        // What metadata.db holds, as Go's readSnapshots read it.
        let snaps = read_snapshots(&src.join("snapshots")).unwrap();
        let mut got = Map::new();
        for (n, s) in &snaps {
            let mut v = Map::new();
            v.insert(
                "dir".into(),
                s.dir
                    .strip_prefix(&data)
                    .unwrap()
                    .display()
                    .to_string()
                    .into(),
            );
            v.insert("kind".into(), s.kind.into());
            if !s.parent.is_empty() {
                v.insert("parent".into(), s.parent.clone().into());
            }
            got.insert(n.clone(), v.into());
        }
        assert_eq!(Value::Object(got), c["snapshots"], "{name}: snapshots");

        let mut err = String::new();
        let mut summary = Value::Null;
        match c["op"].as_str().unwrap() {
            "move" => {
                let (_, sum, r) = move_images(&src, &dst, &bundles, &state, mountinfo);
                if let Err(e) = r {
                    err = e.replace(&data.display().to_string(), DATA);
                }
                if let Some(s) = sum {
                    let s = serde_json::to_string(&s)
                        .unwrap()
                        .replace(&data.display().to_string(), DATA);
                    summary = serde_json::from_str(&s).unwrap();
                }
            }
            "collect" => {
                let (recs, _) = bundle::records(&bundles.display().to_string()).unwrap();
                if let Err(e) = collect_go(&src, &dst, &state, &recs, mountinfo) {
                    err = e;
                }
            }
            op => panic!("op {op}"),
        }
        assert_eq!(err, c["error"].as_str().unwrap_or(""), "{name}: error");
        assert_eq!(summary, c["summary"], "{name}: summary");
        let want = without_run_times(c["after"].as_object().unwrap().clone());
        let got = without_run_times(read_tree(&data));
        let d = diff(&want, &got);
        assert!(d.is_empty(), "{name}: trees differ:\n{}", d.join("\n"));
        super::super::layers::remove_tree(&data);
    }
}

/// The record reads as Go writes it, and a newer version is refused.
#[test]
fn reads_and_writes_the_record() {
    let d = data_dir("record");
    let p = d.join("node").join(MOVED_FILE);
    assert_eq!(read_move_state(&p).unwrap(), None);
    let st = MoveState {
        at: "2026-11-25T20:00:00Z".into(),
        converted: 2,
        skipped: [("x".to_string(), "why".to_string())].into(),
        ..Default::default()
    };
    write_move_state(&p, &st).unwrap();
    assert_eq!(
        fs::read_to_string(&p).unwrap(),
        r#"{"version":1,"at":"2026-11-25T20:00:00Z","converted":2,"skipped":{"x":"why"},"layers":0}"#
    );
    assert_eq!(fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
    fs::write(&p, r#"{"version":2}"#).unwrap();
    assert!(read_move_state(&p).unwrap_err().contains("is newer than 1"));
    super::super::layers::remove_tree(&d);
}

#[test]
fn reads_varints() {
    assert_eq!(uvarint(&[]), 0);
    assert_eq!(uvarint(&[7]), 7);
    assert_eq!(uvarint(&[0x96, 0x01]), 150);
    assert_eq!(uvarint(&[0x80]), 0);
}

fn mount_overlay(lower: &Path, upper: &Path, work: &Path, at: &Path) {
    use std::ffi::CString;
    let opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display()
    );
    let (src, tgt, ty, o) = (
        CString::new("overlay").unwrap(),
        CString::new(at.display().to_string()).unwrap(),
        CString::new("overlay").unwrap(),
        CString::new(opts).unwrap(),
    );
    // SAFETY: valid C strings for the call's duration.
    let r = unsafe {
        libc::mount(
            src.as_ptr(),
            tgt.as_ptr(),
            ty.as_ptr(),
            0,
            o.as_ptr().cast(),
        )
    };
    assert_eq!(r, 0, "mount: {}", io::Error::last_os_error());
}

fn unmount(at: &Path) {
    let t = std::ffi::CString::new(at.display().to_string()).unwrap();
    // SAFETY: a valid C string.
    unsafe { libc::umount2(t.as_ptr(), libc::MNT_DETACH) };
}

/// Root only (see CLAUDE.md's Commands): a container's overlay mounted on
/// Go's store, as on a node upgraded with its containers running, keeps
/// reading and writing through the move; Go's directory of a layer this
/// store already had is held, not removed; and Go's store is refused
/// while a mounted overlay names a directory left in it.
#[test]
#[ignore = "root: mounts overlays"]
fn moves_mounted_overlays() {
    for name in ["moved", "held"] {
        let c = fixture().into_iter().find(|c| c["name"] == name).unwrap();
        let data = data_dir(&format!("mounted-{name}"));
        write_tree(&data, c["before"].as_object().unwrap());
        let snaps = &c["snapshots"];
        let active = data.join(snaps["container-1"]["dir"].as_str().unwrap());
        let parent = snaps["container-1"]["parent"].as_str().unwrap();
        let lower = data.join(snaps[parent]["dir"].as_str().unwrap()).join("fs");
        let rootfs = data.join("supervisor/containers/container-1/rootfs");
        mount_overlay(&lower, &active.join("fs"), &active.join("work"), &rootfs);
        fs::write(rootfs.join("before"), "x").unwrap();

        let src = data.join("supervisor/images");
        let dst = data.join("node/images");
        // A mount naming a directory of Go's store that stays refuses its
        // removal.
        if name == "held" {
            let extra = data.join("extra");
            for d in ["u", "w", "m"] {
                fs::create_dir_all(extra.join(d)).unwrap();
            }
            mount_overlay(
                &src.join("content"),
                &extra.join("u"),
                &extra.join("w"),
                &extra.join("m"),
            );
            let e = remove_go_store(&src, &dst, Path::new(MOUNTINFO)).unwrap_err();
            assert!(e.contains("a mounted overlay still uses"), "{e}");
            unmount(&extra.join("m"));
        }
        let (st, _, r) = move_images(
            &src,
            &dst,
            &data.join("supervisor/containers"),
            &data.join("node").join(MOVED_FILE),
            Path::new(MOUNTINFO),
        );
        r.unwrap();
        assert!(st.collected && st.containers == 1, "{st:?}");
        assert!(!src.exists());
        assert_eq!(fs::read_to_string(rootfs.join("before")).unwrap(), "x");
        assert_eq!(
            fs::read_to_string(rootfs.join("layer")).unwrap(),
            "layer one"
        );
        fs::write(rootfs.join("after"), "y").unwrap();
        assert_eq!(
            fs::read_to_string(dst.join("active/container-1/fs/after")).unwrap(),
            "y"
        );
        if name == "held" {
            assert_eq!(fs::read_dir(dst.join("held")).unwrap().count(), 1);
        }
        unmount(&rootfs);
        super::super::layers::remove_tree(&data);
    }
}

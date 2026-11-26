//! The pins and the notices agree (THIRD_PARTY_NOTICES.md): every pinned
//! program is named at the version pack/lock.json pins, armada-log,
//! armada-shim, and armada-dns use the Rust standard library only, and
//! every crate in the workspace's Cargo.lock is named. A crate or an
//! upgrade cannot leave the notices behind.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use armada_pack::lock::{ARCHES, LOCK_PATH, Lock};
use armada_pack::pack::{MAX_PACK_FILES, check_name};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn read(path: &str) -> String {
    std::fs::read_to_string(root().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn lock() -> Lock {
    Lock::load(&root().join(LOCK_PATH)).expect("lock")
}

#[test]
fn lock_pins_every_program() {
    let lock = lock();
    let mut names = BTreeSet::new();
    let mut files = BTreeSet::new();
    for a in &lock.artifacts {
        assert!(names.insert(a.name.clone()), "{} pinned twice", a.name);
        for arch in ARCHES {
            let sum = a.sha256.get(arch).map(String::as_str).unwrap_or("");
            assert!(
                sum.len() == 64 && sum.bytes().all(|c| c.is_ascii_hexdigit()),
                "{}: no SHA-256 for {arch}",
                a.name
            );
            let u = a.url_for(arch);
            assert!(
                u.starts_with("https://") && !u.contains("{arch}"),
                "{}: URL {u}",
                a.name
            );
        }
        assert_eq!(a.sha256.len(), ARCHES.len(), "{}: checksums", a.name);
        for f in a.pack_names() {
            check_name(&f).unwrap_or_else(|e| panic!("{}: {e}", a.name));
            assert!(files.insert(f.clone()), "{f} in the pack twice");
        }
    }
    for f in ["runc", "tini", "etcd", "etcdutl"] {
        assert!(files.contains(f), "{f} is not in the pack");
    }
    for f in ["containerd", "containerd-shim-runc-v2"] {
        assert!(!files.contains(f), "{f} left the pack (ADR 0046)");
    }
    // Armada's own four programs join them.
    assert!(
        files.len() + 4 <= MAX_PACK_FILES,
        "{} files, the pack allows {MAX_PACK_FILES}",
        files.len() + 4
    );
    let etcd = lock.artifact("etcd").expect("etcd");
    assert!(etcd.module_licenses, "etcd's modules' licenses ship");
    let api = etcd.api_module.as_ref().expect("etcd's API module");
    assert!(api.h1.starts_with("h1:"), "{}", api.h1);
}

#[test]
fn notices_match_lock() {
    let notices = read("THIRD_PARTY_NOTICES.md");
    for a in &lock().artifacts {
        let row = format!("| {} | {} |", a.name, a.version);
        assert!(
            notices.contains(&row),
            "THIRD_PARTY_NOTICES.md has no row {row:?}; update it with {LOCK_PATH}"
        );
    }
}

#[test]
fn programs_outside_the_workspace_use_std_only() {
    for (lockfile, program) in [
        ("logger/Cargo.lock", "armada-log"),
        ("shim/Cargo.lock", "armada-shim"),
        ("dns/Cargo.lock", "armada-dns"),
    ] {
        let n = read(lockfile).matches("[[package]]").count();
        assert_eq!(
            n, 1,
            "{lockfile} lists {n} packages; {program} uses the Rust standard library only"
        );
    }
}

#[test]
fn notices_name_every_crate() {
    let notices = read("THIRD_PARTY_NOTICES.md");
    for line in read("Cargo.lock").lines() {
        let Some(name) = line.strip_prefix("name = ") else {
            continue;
        };
        let name = name.trim_matches('"');
        if name == "armada-node" || name == "armada-proto" {
            continue;
        }
        assert!(
            notices.contains(name),
            "THIRD_PARTY_NOTICES.md does not name the crate {name} (Cargo.lock)"
        );
    }
    for want in [
        "armada-log",
        "armada-shim",
        "armada-dns",
        "armada-node",
        "armada-proto",
        "armada-pack",
        "musl",
        "Rust standard library",
    ] {
        assert!(
            notices.contains(want),
            "THIRD_PARTY_NOTICES.md does not mention {want:?}"
        );
    }
}

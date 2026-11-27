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
    // crun runs new containers, runc those it created before ADR 0056
    // until they are recreated: both stay in the pack until a later
    // release removes runc.
    for f in ["crun", "runc", "tini", "etcd", "etcdutl"] {
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

/// A program under the GPL ships its complete corresponding source and
/// its license texts (ADR 0056); every source file is pinned like a
/// program. Licenses that limit commercial use or reach a network
/// service's users are never pinned.
#[test]
fn gpl_programs_ship_their_source() {
    let notices = read("THIRD_PARTY_NOTICES.md");
    for a in &lock().artifacts {
        for bad in ["AGPL", "SSPL", "BUSL", "Commons-Clause"] {
            assert!(!a.license.contains(bad), "{}: {}", a.name, a.license);
        }
        let gpl = a.license.starts_with("GPL") || a.license.contains(" GPL");
        assert!(
            !gpl || !a.sources.is_empty(),
            "{} is under {} and ships no source",
            a.name,
            a.license
        );
        assert!(
            a.sources.is_empty() || !a.license.is_empty(),
            "{}: sources need a license",
            a.name
        );
        let mut seen = BTreeSet::new();
        let mut licenses = 0;
        for s in &a.sources {
            assert!(s.url.starts_with("https://"), "{}: {}", a.name, s.url);
            assert!(
                s.sha256.len() == 64 && s.sha256.bytes().all(|c| c.is_ascii_hexdigit()),
                "{}: no SHA-256 for {}",
                a.name,
                s.file
            );
            check_name(&s.file).unwrap_or_else(|e| panic!("{}: {e}", a.name));
            assert!(seen.insert(s.file.clone()), "{}: {} twice", a.name, s.file);
            for to in s.licenses.values() {
                check_name(to).unwrap_or_else(|e| panic!("{}: {e}", a.name));
                licenses += 1;
            }
        }
        if gpl {
            assert!(
                a.sources
                    .iter()
                    .any(|s| s.file.ends_with(".tar.gz") && !s.licenses.is_empty()),
                "{}: no source tarball with its license texts",
                a.name
            );
            assert!(licenses > 0);
            let row = format!("| {} | {} | {} |", a.name, a.version, a.license);
            assert!(
                notices.contains(&row),
                "THIRD_PARTY_NOTICES.md has no row {row:?}"
            );
        }
    }
    let crun = lock().artifact("crun").cloned().expect("crun");
    assert_eq!(crun.license, "GPL-2.0-or-later");
    assert!(
        crun.url.ends_with("-disable-systemd"),
        "crun without systemd support (ADR 0056): {}",
        crun.url
    );
}

/// The pack's static programs that link libraries ship each library's
/// source (the tarball, the patches, the build files) in the release's
/// sources asset, or name the license exception that waives it; the
/// notices name every library, its license, and where its source is.
#[test]
fn linked_libraries_ship_their_source() {
    let notices = read("THIRD_PARTY_NOTICES.md");
    let lock = lock();
    lock.check_libraries().unwrap_or_else(|e| panic!("{e}"));
    for l in &lock.libraries {
        for bad in ["AGPL", "SSPL", "BUSL", "Commons-Clause"] {
            assert!(!l.license.contains(bad), "{}: {}", l.name, l.license);
        }
        let row = format!("| {} | {} | {} |", l.name, l.version, l.license);
        assert!(
            notices.contains(&row),
            "THIRD_PARTY_NOTICES.md has no row {row:?}"
        );
        if l.no_source.is_none() {
            let dir = format!("source/runtime/{}/", l.source_dir());
            assert!(
                notices.contains(&dir),
                "THIRD_PARTY_NOTICES.md does not say {} {} is in {dir}",
                l.name,
                l.version
            );
        }
        let mut seen = BTreeSet::new();
        for s in &l.sources {
            assert!(s.url.starts_with("https://"), "{}: {}", l.name, s.url);
            assert!(
                s.sha256.len() == 64 && s.sha256.bytes().all(|c| c.is_ascii_hexdigit()),
                "{} {}: no SHA-256 for {}",
                l.name,
                l.version,
                s.file
            );
            check_name(&s.file).unwrap_or_else(|e| panic!("{}: {e}", l.name));
            assert!(seen.insert(&s.file), "{}: {} twice", l.name, s.file);
            assert!(
                s.licenses.is_empty(),
                "{}: license texts are in third_party/licenses",
                l.name
            );
        }
    }
    // What each static program of the pack links (crun: its
    // nix/derivation.nix and flake.nix at its tag; runc: its Dockerfile
    // and script/build-seccomp.sh; tini: its Dockerfile and
    // ci/install_deps.sh; each checked with strings on the programs).
    for (program, want) in [
        (
            "crun",
            &[
                "glibc",
                "libgcc",
                "libseccomp",
                "libcap",
                "json-c",
                "criu",
                "protobuf-c",
            ][..],
        ),
        ("runc", &["glibc", "libgcc", "libseccomp"][..]),
        ("tini", &["glibc", "libgcc"][..]),
    ] {
        let a = lock.artifact(program).expect(program);
        for arch in ARCHES {
            for w in want {
                let on = a
                    .linked
                    .iter()
                    .any(|l| &l.name == w && l.arches.iter().any(|x| x == arch));
                let amd64_only = program == "crun" && ["criu", "protobuf-c"].contains(w);
                assert!(
                    on || (amd64_only && arch == "arm64"),
                    "{program} ({arch}) links {w}"
                );
            }
        }
    }
    // The pure Go programs link no C library (CGO_ENABLED=0 in their
    // build information).
    for program in ["etcd", "cni-plugins"] {
        assert!(lock.artifact(program).expect(program).linked.is_empty());
    }
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

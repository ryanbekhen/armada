//! The pins (`pack/lock.json`): every upstream artifact that contributes
//! files to the runtime pack.
//!
//! When bumping a version: verify the upstream signature first (crun
//! and tini publish GPG signatures; crun and the CNI plugins publish
//! checksums with the release, etcd SHA256SUMS), then record the SHA-256
//! of both architectures. The hash, not the URL, is what the pack trusts.
//!
//! A program under the GPL (crun, ADR 0056) runs only as a process of its
//! own, never linked into Armada's programs, and names its complete
//! corresponding source in `sources`. A static program names the
//! libraries linked into it in `linked`; each is pinned once in
//! `libraries`, with its source as the program's build used it (the
//! source tarball, the patches applied, and the build files), or with
//! `noSource` naming the exception that makes its source unnecessary. A
//! release carries all of these sources in one asset of its own
//! (`armada-pack sources`), and crun's license texts in its archives.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

/// The architectures a pack is built for.
pub const ARCHES: [&str; 2] = ["amd64", "arm64"];

/// The lock file, relative to the repository's root.
pub const LOCK_PATH: &str = "pack/lock.json";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lock {
    pub artifacts: Vec<Artifact>,
    /// The libraries linked into the static programs of artifacts.
    #[serde(default)]
    pub libraries: Vec<Library>,
}

/// Artifact: one upstream download that contributes files to the pack.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub name: String,
    pub version: String,
    /// `{arch}` is replaced by amd64 or arm64.
    pub url: String,
    /// By architecture.
    pub sha256: BTreeMap<String, String>,
    /// A path inside the downloaded gzipped tar to its name in the pack;
    /// `{arch}` in a path is replaced as in url. None: the download is the
    /// file itself, named after the artifact.
    #[serde(default)]
    pub files: BTreeMap<String, String>,
    /// Release archives carry the license files of the Go modules this
    /// artifact's programs link (`armada-pack licenses`).
    #[serde(default, rename = "moduleLicenses")]
    pub module_licenses: bool,
    /// etcd's API module at the artifact's version, whose protos
    /// armada-proto is generated from (`armada-pack etcd-api`).
    #[serde(default, rename = "apiModule")]
    pub api_module: Option<Module>,
    /// The artifact's license, an SPDX expression; required with sources.
    #[serde(default)]
    pub license: String,
    /// The source release archives carry beside the program (ADR 0056):
    /// every file of its complete corresponding source, each pinned by
    /// SHA-256 (`armada-pack sources`).
    #[serde(default)]
    pub sources: Vec<Source>,
    /// The libraries linked into a static program, each pinned in the
    /// lock's `libraries`.
    #[serde(default)]
    pub linked: Vec<Linked>,
}

/// A library a static program links, by name and version.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Linked {
    pub name: String,
    pub version: String,
    /// The architectures whose program links it.
    pub arches: Vec<String>,
}

/// A library linked into the static programs of artifacts.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Library {
    pub name: String,
    /// As the build that linked it names it (a distribution's version
    /// when a distribution built it).
    pub version: String,
    /// An SPDX expression.
    pub license: String,
    /// Why no source is carried: only a license exception that waives it
    /// (the license names it with WITH). Then sources is empty.
    #[serde(default, rename = "noSource")]
    pub no_source: Option<String>,
    /// Its source: a source tarball, the patches applied, and the build
    /// files, each under `libs/<name>-<version>/`.
    #[serde(default)]
    pub sources: Vec<Source>,
}

impl Library {
    /// The directory its source is kept in: `libs/<name>-<version>`.
    pub fn source_dir(&self) -> String {
        format!("libs/{}-{}", self.name, self.version)
    }

    /// check: a library carries a source tarball, or names in noSource
    /// the license exception that waives it and carries none.
    pub fn check(&self) -> Result<(), String> {
        let id = format!("{} {}", self.name, self.version);
        if self.license.is_empty() {
            return Err(format!("{id}: no license"));
        }
        if let Some(why) = &self.no_source {
            if !self.sources.is_empty() {
                return Err(format!("{id}: noSource with sources"));
            }
            let exception = self.license.split_once(" WITH ").map(|(_, e)| e.trim());
            match exception {
                Some(e) if !e.is_empty() && why.contains(e) => return Ok(()),
                _ => {
                    return Err(format!(
                        "{id}: noSource needs a license exception that waives the source, named in its reason ({:?} under {})",
                        why, self.license
                    ));
                }
            }
        }
        let tarball = self.sources.iter().any(|s| {
            [".tar.gz", ".tar.xz", ".tar.bz2"]
                .iter()
                .any(|x| s.file.ends_with(x))
        });
        if !tarball {
            return Err(format!("{id}: no source tarball"));
        }
        Ok(())
    }
}

/// One file of an artifact's source.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub url: String,
    pub sha256: String,
    /// Its name under the artifact's source directory
    /// (`<name>-<version>/<file>`), or a library's (`libs/<name>-<version>/<file>`).
    pub file: String,
    /// Paths inside this file (a gzipped tar) of license texts, to their
    /// names in the artifact's license directory (`<name>@<version>/`).
    #[serde(default)]
    pub licenses: BTreeMap<String, String>,
}

/// A Go module pinned by its go.sum hash (h1).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Module {
    pub path: String,
    pub h1: String,
}

impl Lock {
    pub fn load(path: &Path) -> Result<Lock, String> {
        let b = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn artifact(&self, name: &str) -> Option<&Artifact> {
        self.artifacts.iter().find(|a| a.name == name)
    }

    /// The pinned library a program links.
    pub fn library(&self, l: &Linked) -> Option<&Library> {
        self.libraries
            .iter()
            .find(|x| x.name == l.name && x.version == l.version)
    }

    /// check_libraries: every library is pinned once, checked, and linked
    /// by a program, and every library a program links is pinned, for
    /// architectures the pack is built for.
    pub fn check_libraries(&self) -> Result<(), String> {
        let mut seen = std::collections::BTreeSet::new();
        for l in &self.libraries {
            if !seen.insert((l.name.as_str(), l.version.as_str())) {
                return Err(format!("{} {} pinned twice", l.name, l.version));
            }
            l.check()?;
            let used = self.artifacts.iter().any(|a| {
                a.linked
                    .iter()
                    .any(|k| k.name == l.name && k.version == l.version)
            });
            if !used {
                return Err(format!("{} {}: no program links it", l.name, l.version));
            }
        }
        for a in &self.artifacts {
            for k in &a.linked {
                if self.library(k).is_none() {
                    return Err(format!(
                        "{} links {} {}, which is not pinned in libraries",
                        a.name, k.name, k.version
                    ));
                }
                if k.arches.is_empty() || !k.arches.iter().all(|x| ARCHES.contains(&x.as_str())) {
                    return Err(format!("{}: {} arches {:?}", a.name, k.name, k.arches));
                }
            }
        }
        Ok(())
    }
}

impl Artifact {
    /// URLFor: the download URL for arch.
    pub fn url_for(&self, arch: &str) -> String {
        self.url.replace("{arch}", arch)
    }

    /// FilesFor: files with `{arch}` replaced in each path.
    pub fn files_for(&self, arch: &str) -> BTreeMap<String, String> {
        self.files
            .iter()
            .map(|(from, to)| (from.replace("{arch}", arch), to.clone()))
            .collect()
    }

    /// The directory its source is kept in: `<name>-<version>`.
    pub fn source_dir(&self) -> String {
        format!("{}-{}", self.name, self.version)
    }

    /// The directory its license files are kept in, beside the Go
    /// modules' (`armada-pack licenses`): `<name>@<version>`.
    pub fn license_dir(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }

    /// The names this artifact gives the pack.
    pub fn pack_names(&self) -> Vec<String> {
        if self.files.is_empty() {
            vec![self.name.clone()]
        } else {
            self.files.values().cloned().collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(libraries: &str, linked: &str) -> Lock {
        serde_json::from_str(&format!(
            r#"{{"artifacts": [{{"name": "p", "version": "1", "url": "https://x/p", "sha256": {{}},
                "linked": [{linked}]}}], "libraries": [{libraries}]}}"#
        ))
        .expect("lock")
    }

    fn src(file: &str) -> String {
        format!(r#"{{"url": "https://x/{file}", "sha256": "00", "file": "{file}"}}"#)
    }

    const LINKED: &str = r#"{"name": "l", "version": "2", "arches": ["amd64"]}"#;

    #[test]
    fn libraries_carry_their_source() {
        let ok = lock(
            &format!(
                r#"{{"name": "l", "version": "2", "license": "MIT", "sources": [{}, {}]}}"#,
                src("l-2.tar.xz"),
                src("debian.dsc")
            ),
            LINKED,
        );
        ok.check_libraries().expect("valid");
        assert_eq!(ok.libraries[0].source_dir(), "libs/l-2");

        let none = lock(
            &format!(
                r#"{{"name": "l", "version": "2", "license": "MIT", "sources": [{}]}}"#,
                src("x.patch")
            ),
            LINKED,
        );
        assert_eq!(
            none.check_libraries().unwrap_err(),
            "l 2: no source tarball"
        );

        let missing = lock("", LINKED);
        assert_eq!(
            missing.check_libraries().unwrap_err(),
            "p links l 2, which is not pinned in libraries"
        );

        let unused = lock(
            &format!(
                r#"{{"name": "m", "version": "1", "license": "MIT", "sources": [{}]}}"#,
                src("m.tar.gz")
            ),
            "",
        );
        assert_eq!(
            unused.check_libraries().unwrap_err(),
            "m 1: no program links it"
        );

        let arch = lock(
            &format!(
                r#"{{"name": "l", "version": "2", "license": "MIT", "sources": [{}]}}"#,
                src("l.tar.gz")
            ),
            r#"{"name": "l", "version": "2", "arches": ["riscv64"]}"#,
        );
        assert!(arch.check_libraries().is_err());
    }

    /// noSource is explicit and holds only for a license exception that
    /// waives the source, named in the reason: never a silent skip.
    #[test]
    fn no_source_needs_an_exception() {
        let gcc = r#""license": "GPL-3.0-or-later WITH GCC-exception-3.1""#;
        let ok = lock(
            &format!(
                r#"{{"name": "l", "version": "2", {gcc}, "noSource": "GCC-exception-3.1 covers it"}}"#
            ),
            LINKED,
        );
        ok.check_libraries().expect("valid");

        let plain = lock(
            r#"{"name": "l", "version": "2", "license": "LGPL-2.1-or-later", "noSource": "small"}"#,
            LINKED,
        );
        assert!(
            plain
                .check_libraries()
                .unwrap_err()
                .contains("noSource needs a license exception")
        );

        let unnamed = lock(
            &format!(r#"{{"name": "l", "version": "2", {gcc}, "noSource": "an exception"}}"#),
            LINKED,
        );
        assert!(unnamed.check_libraries().is_err());

        let both = lock(
            &format!(
                r#"{{"name": "l", "version": "2", {gcc}, "noSource": "GCC-exception-3.1", "sources": [{}]}}"#,
                src("l.tar.gz")
            ),
            LINKED,
        );
        assert_eq!(
            both.check_libraries().unwrap_err(),
            "l 2: noSource with sources"
        );

        let silent = lock(r#"{"name": "l", "version": "2", "license": "MIT"}"#, LINKED);
        assert_eq!(
            silent.check_libraries().unwrap_err(),
            "l 2: no source tarball"
        );
    }
}

//! The pins (`pack/lock.json`): every upstream artifact that contributes
//! files to the runtime pack.
//!
//! When bumping a version: verify the upstream signature first (crun,
//! runc, and tini publish GPG signatures; crun and the CNI plugins publish
//! checksums with the release, etcd SHA256SUMS), then record the SHA-256
//! of both architectures. The hash, not the URL, is what the pack trusts.
//!
//! A program under the GPL (crun, ADR 0056) runs only as a process of its
//! own, never linked into Armada's programs, and names its complete
//! corresponding source in `sources`: release archives carry it
//! (`armada-pack sources`) with the license files it names.

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
}

/// One file of an artifact's source.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub url: String,
    pub sha256: String,
    /// Its name under the artifact's source directory
    /// (`<name>-<version>/<file>`).
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

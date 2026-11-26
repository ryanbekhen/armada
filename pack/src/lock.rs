//! The pins (`pack/lock.json`): every upstream artifact that contributes
//! files to the runtime pack.
//!
//! When bumping a version: verify the upstream signature first (runc and
//! tini publish GPG signatures; containerd and the CNI plugins publish
//! checksums with the release, etcd SHA256SUMS), then record the SHA-256
//! of both architectures. The hash, not the URL, is what the pack trusts.

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

    /// The names this artifact gives the pack.
    pub fn pack_names(&self) -> Vec<String> {
        if self.files.is_empty() {
            vec![self.name.clone()]
        } else {
            self.files.values().cloned().collect()
        }
    }
}

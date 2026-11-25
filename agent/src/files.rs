//! Secret files on the node's tmpfs and the directories of persistent
//! volumes (Go's secretfiles.go and volume.go's prepareVolumes).

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use armada_proto::armada::v1 as pb;
use armada_spec::go::{clean_path, quote};

use crate::agent::Inner;
use crate::runtime::{FileMount, Runtime, VolumeMount};

/// Why a replica with secret files cannot start on a node without a tmpfs
/// secrets directory.
pub const NO_SECRETS_DIR: &str = "this node cannot mount secret files: the agent has no tmpfs secrets directory (see --secrets-dir)";

/// Go's replicaIDRe, `^[a-z0-9]([a-z0-9.-]{0,126}[a-z0-9])?$`: replica IDs
/// before they name directories.
pub(crate) fn valid_replica_id(id: &str) -> bool {
    let b = id.as_bytes();
    let end = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    match b.len() {
        0 => false,
        1 => end(b[0]),
        n if n <= 128 => {
            end(b[0])
                && end(b[n - 1])
                && b[1..n - 1]
                    .iter()
                    .all(|&c| end(c) || c == b'.' || c == b'-')
        }
        _ => false,
    }
}

impl<R: Runtime> Inner<R> {
    /// Writes a replica's secret files to its directory under the secrets
    /// directory (tmpfs, so plaintext stays in memory) and returns the
    /// mounts for its container.
    pub(crate) fn write_secret_files(&self, s: &pb::ReplicaSpec) -> Result<Vec<FileMount>, String> {
        if s.secret_files.is_empty() {
            return Ok(Vec::new());
        }
        if self.cfg.secrets_dir.is_empty() {
            return Err(NO_SECRETS_DIR.to_string());
        }
        if !valid_replica_id(&s.id) {
            return Err(format!("invalid replica id {}", quote(&s.id)));
        }
        let dir = Path::new(&self.cfg.secrets_dir).join(&s.id);
        armada_fsutil::mkdir_private(&dir).map_err(|e| format!("secrets dir: {e}"))?;
        let mut mounts = Vec::with_capacity(s.secret_files.len());
        for (i, f) in s.secret_files.iter().enumerate() {
            let target = &f.path;
            if !target.starts_with('/') || clean_path(target) != *target {
                return Err(format!("invalid secret file path {}", quote(target)));
            }
            let src = dir.join(i.to_string());
            // World-readable so any container user can read it; the
            // private parent directories keep other users out.
            armada_fsutil::write_file_atomic(&src, &f.data, 0o444)
                .map_err(|e| format!("write secret file: {e}"))?;
            mounts.push(FileMount {
                source: src.to_string_lossy().into_owned(),
                target: target.clone(),
            });
        }
        Ok(mounts)
    }

    /// Removes the secret directories of replicas the node no longer runs.
    pub(crate) fn clean_secret_files(&self, desired: &BTreeMap<String, pb::ReplicaSpec>) {
        if self.cfg.secrets_dir.is_empty() {
            return;
        }
        let entries = match fs::read_dir(&self.cfg.secrets_dir) {
            Ok(e) => e,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    self.log
                        .warn("read secrets dir failed", &[("err", e.to_string())]);
                }
                return;
            }
        };
        let mut names: Vec<(String, bool)> = entries
            .flatten()
            .map(|e| {
                let dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                (e.file_name().to_string_lossy().into_owned(), dir)
            })
            .collect();
        names.sort();
        for (name, dir) in names {
            // Only what this agent could have created.
            if !dir || !valid_replica_id(&name) {
                continue;
            }
            if desired
                .get(&name)
                .is_some_and(|s| !s.secret_files.is_empty())
            {
                continue;
            }
            if let Err(e) = fs::remove_dir_all(Path::new(&self.cfg.secrets_dir).join(&name)) {
                self.log.warn(
                    "remove secret files failed",
                    &[("replica", name.clone()), ("err", e.to_string())],
                );
            }
        }
    }

    /// Whether the node can hold volumes.
    pub(crate) fn mounts_volumes(&self) -> bool {
        !self.cfg.volumes_dir.is_empty() && self.rt.can_mount_volumes()
    }

    /// Where volume `name` of `app` lives; both names are checked so a path
    /// from the server never leaves the volumes directory.
    fn volume_dir(&self, app: &str, name: &str) -> Result<PathBuf, String> {
        if self.cfg.volumes_dir.is_empty() {
            return Err("this node has no volume directory".to_string());
        }
        if !armada_spec::validate::valid_app_id(app) || !armada_spec::validate::valid_name(name) {
            return Err(format!(
                "invalid volume name {} of app {}",
                quote(name),
                quote(app)
            ));
        }
        Ok(Path::new(&self.cfg.volumes_dir).join(app).join(name))
    }

    /// Creates a replica's volume directories on first use and returns
    /// their mounts. NFS exports (ADR 0042) come with a later part: this
    /// agent mounts none, as a Go agent without an NFS directory.
    pub(crate) fn prepare_volumes(&self, s: &pb::ReplicaSpec) -> Result<Vec<VolumeMount>, String> {
        if s.volumes.is_empty() {
            return Ok(Vec::new());
        }
        if !self.mounts_volumes() {
            return Err("this node cannot mount volumes".to_string());
        }
        let mut out = Vec::with_capacity(s.volumes.len());
        for v in &s.volumes {
            if v.nfs.is_some() {
                return Err(format!(
                    "volume {}: this node does not mount NFS volumes",
                    v.name
                ));
            }
            let dir = self.volume_dir(&s.app, &v.name)?;
            armada_spec::validate::validate_volume_path(&v.path)
                .map_err(|e| format!("volume {}: path: {e}", v.name))?;
            ensure_volume(&dir, &v.owner).map_err(|e| format!("volume {}: {e}", v.name))?;
            out.push(VolumeMount {
                source: dir.to_string_lossy().into_owned(),
                target: v.path.clone(),
                ..VolumeMount::default()
            });
        }
        Ok(out)
    }
}

/// Creates dir (0700) unless it exists and gives it to owner when one is
/// set; an existing dir must be a directory, not a link.
fn ensure_volume(dir: &Path, owner: &str) -> Result<(), String> {
    if let Some(parent) = dir.parent() {
        armada_fsutil::mkdir_private(parent).map_err(|e| e.to_string())?;
    }
    match fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() => return chown_volume(dir, owner),
        Ok(_) => return Err(format!("{} is not a directory", dir.display())),
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(armada_fsutil::Error::path("lstat", dir, &e).to_string());
        }
        Err(_) => {}
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .map_err(|e| armada_fsutil::Error::path("mkdir", dir, &e).to_string())?;
    chown_volume(dir, owner)
}

/// Gives dir to owner when the agent runs as root, as on every node.
fn chown_volume(dir: &Path, owner: &str) -> Result<(), String> {
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if owner.is_empty() || euid != 0 {
        return Ok(());
    }
    let (uid, gid) = armada_spec::validate::parse_owner(owner)?;
    std::os::unix::fs::lchown(dir, Some(uid as u32), Some(gid as u32))
        .map_err(|e| armada_fsutil::Error::path("lchown", dir, &e).to_string())
}

#[cfg(test)]
mod tests {
    use super::valid_replica_id;

    #[test]
    fn replica_ids() {
        for (id, ok) in [
            ("web-r1-abc", true),
            ("a", true),
            ("web.space-r1", true),
            ("", false),
            ("-a", false),
            ("a-", false),
            ("A", false),
            ("a/b", false),
            ("..", false),
        ] {
            assert_eq!(valid_replica_id(id), ok, "{id}");
        }
        assert!(valid_replica_id(&"a".repeat(128)));
        assert!(!valid_replica_id(&"a".repeat(129)));
    }
}

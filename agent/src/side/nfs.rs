//! NFS volumes (ADR 0042): the agent mounts an export once per node and
//! volume under the NFS directory, with nosuid and nodev, and
//! bind-mounts it into each replica that names it. [`NodeNfs`] mounts,
//! reads, and unmounts through armada-node's `nfs mount|source|unmount`,
//! a process of its own, so a mount that never returns does not hold the
//! agent.

use std::path::{Path, PathBuf};
use std::time::Duration;

use armada_proto::armada::v1 as pb;
use serde_json::json;

use super::nodeprog;
use crate::agent::Inner;
use crate::proxy::BoxFut;
use crate::runtime::{Runtime, VolumeMount};

/// Bounds one mount: an unreachable server must not hold a start forever.
pub const NFS_MOUNT_TIMEOUT: Duration = Duration::from_secs(120);

/// What is mounted on a target.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mounted {
    pub source: String,
    pub mounted: bool,
    /// Whether the mount is read-only, asked only when the source is the
    /// export wanted.
    pub read_only: bool,
}

/// Mounts and unmounts NFS exports.
pub trait Nfs: Send + Sync {
    /// Whether the kernel has an NFSv4 client.
    fn supported(&self) -> bool;
    /// The source mounted on target and, when it is export, whether the
    /// mount is read-only.
    fn mounted<'a>(
        &'a self,
        target: &'a str,
        export: &'a str,
    ) -> BoxFut<'a, Result<Mounted, String>>;
    /// Detaches target.
    fn unmount<'a>(&'a self, target: &'a str) -> BoxFut<'a, Result<(), String>>;
    /// Mounts server:export on target within timeout.
    fn mount<'a>(
        &'a self,
        server: &'a str,
        export: &'a str,
        target: &'a str,
        read_only: bool,
        timeout: Duration,
    ) -> BoxFut<'a, Result<(), String>>;
}

/// NFS through armada-node.
pub struct NodeNfs {
    pub bin: String,
    /// Whether the kernel has an NFSv4 client; None: asked of the
    /// machine (tests say yes).
    pub supported: Option<bool>,
}

/// Whether the node mounts NFS: nfs4 in /proc/filesystems, or its module in the
/// running kernel's modules.dep.
pub fn nfs_supported() -> bool {
    nfs_supported_in("")
}

/// nfs_supported with the host's files under root ("" for the machine's;
/// armadad doctor's parity tests give one of their own).
pub fn nfs_supported_in(root: &str) -> bool {
    let at = |p: &str| format!("{root}{p}");
    if std::fs::read_to_string(at("/proc/filesystems")).is_ok_and(|s| s.contains("\tnfs4\n")) {
        return true;
    }
    let Ok(release) = std::fs::read_to_string(at("/proc/sys/kernel/osrelease")) else {
        return false;
    };
    let release = release.trim();
    let base = release.rsplit('/').next().unwrap_or(release);
    std::fs::read_to_string(
        Path::new(&at("/lib/modules"))
            .join(base)
            .join("modules.dep"),
    )
    .is_ok_and(|s| s.contains("/nfsv4.ko"))
}

impl Nfs for NodeNfs {
    fn supported(&self) -> bool {
        self.supported.unwrap_or_else(nfs_supported)
    }

    fn mounted<'a>(
        &'a self,
        target: &'a str,
        export: &'a str,
    ) -> BoxFut<'a, Result<Mounted, String>> {
        Box::pin(async move {
            let mut req = json!({"target": target});
            if !export.is_empty() {
                req["export"] = json!(export);
            }
            let v = nodeprog::call(&self.bin, &["nfs", "source"], &req, None).await?;
            Ok(Mounted {
                source: v["source"].as_str().unwrap_or("").to_string(),
                mounted: v["mounted"].as_bool().unwrap_or(false),
                read_only: v["readOnly"].as_bool().unwrap_or(false),
            })
        })
    }

    fn unmount<'a>(&'a self, target: &'a str) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async move {
            nodeprog::call(
                &self.bin,
                &["nfs", "unmount"],
                &json!({"target": target}),
                None,
            )
            .await
            .map(|_| ())
        })
    }

    fn mount<'a>(
        &'a self,
        server: &'a str,
        export: &'a str,
        target: &'a str,
        read_only: bool,
        timeout: Duration,
    ) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async move {
            let mut req = json!({
                "server": server, "path": export, "target": target,
                "timeoutMs": (timeout.as_millis() as i64).max(1),
            });
            if read_only {
                req["readOnly"] = json!(true);
            }
            match nodeprog::call(&self.bin, &["nfs", "mount"], &req, Some(timeout)).await {
                Err(e) if e == "context deadline exceeded" => {
                    Err("the server did not answer: context deadline exceeded".into())
                }
                r => r.map(|_| ()),
            }
        })
    }
}

/// The export as the kernel names it.
pub fn nfs_source(server: &str, path: &str) -> String {
    match server.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(_)) => format!("[{server}]:{path}"),
        _ => format!("{server}:{path}"),
    }
}

impl<R: Runtime> Inner<R> {
    /// Whether this node mounts NFS volumes.
    pub(crate) fn mounts_nfs(&self) -> bool {
        !self.cfg.side.nfs_dir.is_empty()
            && self.rt.can_mount_volumes()
            && self.cfg.side.nfs.as_ref().is_some_and(|n| n.supported())
    }

    /// Where volume name of app is mounted on this node.
    fn nfs_target(&self, app: &str, name: &str) -> Result<PathBuf, String> {
        if self.cfg.side.nfs_dir.is_empty() {
            return Err("this node does not mount NFS volumes".into());
        }
        if !armada_spec::validate::valid_app_id(app) || !armada_spec::validate::valid_name(name) {
            return Err(format!(
                "invalid volume name {} of app {}",
                super::quote(name),
                super::quote(app)
            ));
        }
        Ok(Path::new(&self.cfg.side.nfs_dir).join(app).join(name))
    }

    /// Mounts v's export unless it is mounted and returns the replica's
    /// mount of it.
    pub(crate) async fn prepare_nfs(
        &self,
        app: &str,
        v: &pb::VolumeSpec,
    ) -> Result<VolumeMount, String> {
        let n = v.nfs.clone().unwrap_or_default();
        let Some(nfs) = self.cfg.side.nfs.clone().filter(|_| self.mounts_nfs()) else {
            return Err("this node does not mount NFS volumes".into());
        };
        // The server checked these; a node checks again before calling the
        // kernel with them.
        armada_spec::validate::check_nfs_server(&n.server)
            .map_err(|e| format!("NFS server: {e}"))?;
        armada_spec::validate::check_nfs_path(&n.path).map_err(|e| format!("NFS path: {e}"))?;
        armada_spec::validate::validate_volume_path(&v.path).map_err(|e| format!("path: {e}"))?;
        let target = self.nfs_target(app, &v.name)?;
        let t = target.to_string_lossy().into_owned();
        let _g = self.side.nfs_mounts.lock(&t).await;
        if let Some(parent) = target.parent() {
            armada_fsutil::mkdir_private(parent).map_err(|e| e.to_string())?;
        }
        if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&target)
            && e.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(armada_fsutil::Error::path("mkdir", &target, &e).to_string());
        }
        let want = nfs_source(&n.server, &n.path);
        let mut m = nfs.mounted(&t, &want).await?;
        if m.mounted && (m.source != want || m.read_only != n.read_only) {
            // The spec moved to another export: replicas still on the old
            // one keep it through their own bind mounts.
            nfs.unmount(&t).await?;
            m.mounted = false;
        }
        if !m.mounted {
            nfs.mount(&n.server, &n.path, &t, n.read_only, NFS_MOUNT_TIMEOUT)
                .await
                .map_err(|e| format!("mount NFS export {want}: {e}"))?;
            self.log.info(
                "mounted NFS volume",
                &[
                    ("app", app.to_string()),
                    ("volume", v.name.clone()),
                    ("export", want),
                ],
            );
        }
        Ok(VolumeMount {
            source: t,
            target: v.path.clone(),
            shared: true,
            read_only: n.read_only,
        })
    }

    /// Unmounts the NFS volumes no desired replica names any more.
    pub(crate) async fn clean_nfs(
        &self,
        desired: &std::collections::BTreeMap<String, pb::ReplicaSpec>,
    ) {
        if self.cfg.side.nfs_dir.is_empty() {
            return;
        }
        let mut used = std::collections::HashSet::new();
        for s in desired.values() {
            for v in &s.volumes {
                if v.nfs.is_some()
                    && let Ok(t) = self.nfs_target(&s.app, &v.name)
                {
                    used.insert(t);
                }
            }
        }
        let Ok(apps) = read_dir_sorted(Path::new(&self.cfg.side.nfs_dir)) else {
            return;
        };
        for app in apps {
            let dir = Path::new(&self.cfg.side.nfs_dir).join(&app);
            let Ok(vols) = read_dir_sorted(&dir) else {
                continue;
            };
            for v in vols {
                let target = dir.join(&v);
                if used.contains(&target) {
                    continue;
                }
                let t = target.to_string_lossy().into_owned();
                let _g = self.side.nfs_mounts.lock(&t).await;
                if let Some(nfs) = &self.cfg.side.nfs
                    && let Ok(m) = nfs.mounted(&t, "").await
                    && m.mounted
                {
                    if let Err(e) = nfs.unmount(&t).await {
                        self.log
                            .warn("unmount NFS volume", &[("dir", t.clone()), ("err", e)]);
                        continue;
                    }
                    self.log.info("unmounted NFS volume", &[("dir", t.clone())]);
                }
                let _ = std::fs::remove_dir(&target); // only an empty mount point
            }
            let _ = std::fs::remove_dir(&dir);
        }
    }
}

use std::os::unix::fs::DirBuilderExt;

/// A directory's names, sorted.
fn read_dir_sorted(p: &Path) -> std::io::Result<Vec<String>> {
    let mut names: Vec<String> = std::fs::read_dir(p)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    Ok(names)
}

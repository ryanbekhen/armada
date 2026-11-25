//! Volumes (volumes.go, ADR 0023, ADR 0041).

use armada_spec::gotime::Time;
use armada_spec::validate::{valid_app_id, valid_name};

use crate::error::{Result, not_found, precondition};
use crate::gojson::{from_ms, ms};
use crate::records::VolumeRec;
use crate::tx::*;
use crate::types::*;

/// maxBackupError bounds the error kept on a volume's record.
const MAX_BACKUP_ERROR: usize = 512;

fn volume_key(app: &str, name: &str) -> String {
    format!("{PFX_VOLUMES}{app}/{name}")
}

fn volume_of(r: VolumeRec) -> Volume {
    Volume {
        app: r.app,
        name: r.name,
        node: r.node,
        created_at: from_ms(r.created_at),
        backup: VolumeBackupState {
            last_at: from_ms(r.backup_at),
            last_id: r.backup_id,
            failed_at: from_ms(r.backup_failed_at),
            error: r.backup_error,
            stored: r.backup_stored,
            snapshots: r.backup_snapshots,
        },
    }
}

/// The first n bytes of s as Go slices a string. A cut inside a character
/// leaves bytes that are not UTF-8, which encoding/json writes as one
/// "�" escape each; here each becomes U+FFFD, which reads back the
/// same but is written as the character itself.
fn cut(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    let mut end = n;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = s[..end].to_string();
    for _ in end..n {
        out.push('\u{fffd}');
    }
    out
}

impl Etx<'_> {
    /// bindVolumes binds the volumes a replica of rev mounts to node.
    pub(crate) async fn bind_volumes(
        &mut self,
        rev: &Revision,
        node: &str,
        now: &Time,
    ) -> Result<()> {
        for v in &rev.spec().volumes {
            if !v.local() {
                continue; // NFS volumes are not bound to a node (ADR 0042)
            }
            let k = volume_key(&rev.app, &v.name);
            if let Some(rec) = self.get::<VolumeRec>(&k).await? {
                if rec.node != node {
                    return Err(precondition!(
                        "volume {} of {} is on node {}, not {node}",
                        v.name,
                        rev.app,
                        rec.node
                    ));
                }
                continue;
            }
            self.put(
                &k,
                &VolumeRec {
                    app: rev.app.clone(),
                    name: v.name.clone(),
                    node: node.to_string(),
                    created_at: ms(now),
                    ..Default::default()
                },
            )?;
        }
        Ok(())
    }

    /// volumeInUse: whether app's serving or target revision mounts name.
    async fn volume_in_use(&self, app: &str, name: &str) -> Result<bool> {
        let Some(a) = self.app(app).await? else {
            return Ok(false);
        };
        for rn in [&a.active_revision, &a.target_revision] {
            if rn.is_empty() {
                continue;
            }
            let rev = self.revision(rn).await?;
            if rev.spec().volumes.iter().any(|v| v.name == name) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Etcd {
    /// RecordVolumeBackup keeps the outcome of a backup.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_volume_backup(
        &self,
        app: &str,
        name: &str,
        id: &str,
        stored: i64,
        snapshots: i64,
        err_msg: &str,
    ) -> Result<()> {
        let now = ms(&self.now());
        let err_msg = cut(err_msg, MAX_BACKUP_ERROR);
        tx!(self, |t| {
            let k = volume_key(app, name);
            let Some(mut r) = t.get::<VolumeRec>(&k).await? else {
                return Err(not_found!("volume {name} of app {app}"));
            };
            if !id.is_empty() {
                r.backup_at = now;
                r.backup_id = id.to_string();
                r.backup_stored = stored;
                r.backup_snapshots = snapshots;
                r.backup_failed_at = 0;
                r.backup_error.clear();
            }
            if !err_msg.is_empty() {
                r.backup_failed_at = now;
                r.backup_error = err_msg.clone();
            }
            t.put(&k, &r)
        })
    }

    /// ListVolumes returns the volumes of app, or of every app.
    pub async fn list_volumes(&self, app: &str) -> Result<Vec<Volume>> {
        let prefix = if app.is_empty() {
            PFX_VOLUMES.to_string()
        } else {
            format!("{PFX_VOLUMES}{app}/")
        };
        let mut out = Vec::new();
        view!(self, |t| {
            out = t
                .list_into::<VolumeRec>(&prefix)
                .await?
                .into_iter()
                .map(|(_, r)| volume_of(r))
                .collect();
            Ok(())
        })?;
        Ok(out)
    }

    /// GetVolume returns one volume.
    pub async fn get_volume(&self, app: &str, name: &str) -> Result<Volume> {
        let mut out = None;
        view!(self, |t| {
            let Some(r) = t.get::<VolumeRec>(&volume_key(app, name)).await? else {
                return Err(not_found!("volume {name} of app {app}"));
            };
            out = Some(volume_of(r));
            Ok(())
        })?;
        Ok(out.expect("set by the view"))
    }

    /// DeleteVolume removes a volume's record, refusing one the app's spec
    /// still mounts.
    pub async fn delete_volume(&self, app: &str, name: &str, actor: &str) -> Result<()> {
        tx!(self, |t| {
            let k = volume_key(app, name);
            if t.get_raw(&k).await?.is_none() {
                return Err(not_found!("volume {name} of app {app}"));
            }
            if t.volume_in_use(app, name).await? {
                return Err(precondition!(
                    "app {app} still mounts volume {name}; deploy it without the volume first"
                ));
            }
            t.delete(&k);
            t.audit(&self.now(), actor, "volume.delete", app, name)
                .await
        })
    }

    /// BindVolume binds a volume to node, creating its record if there is
    /// none, for a restore onto another node.
    pub async fn bind_volume(&self, app: &str, name: &str, node: &str, actor: &str) -> Result<()> {
        if !valid_app_id(app) || !valid_name(name) {
            return Err(precondition!("invalid volume name"));
        }
        let now = self.now();
        tx!(self, |t| {
            if t.node(node).await?.is_none() {
                return Err(not_found!("node {node}"));
            }
            let k = volume_key(app, name);
            let mut rec = VolumeRec {
                app: app.to_string(),
                name: name.to_string(),
                node: node.to_string(),
                created_at: ms(&now),
                ..Default::default()
            };
            if let Some(old) = t.get::<VolumeRec>(&k).await? {
                if old.node == node {
                    return Ok(());
                }
                // The backups stay the volume's.
                rec = old;
                rec.node = node.to_string();
            }
            t.put(&k, &rec)?;
            t.audit(
                &now,
                actor,
                "volume.bind",
                app,
                &format!("{name} node={node}"),
            )
            .await
        })
    }
}

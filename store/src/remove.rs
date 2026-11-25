//! Removing apps (remove.go).

use crate::error::{Result, not_found, precondition};
use crate::tx::*;

impl Etcd {
    /// MarkAppRemoving starts removing an app; marking it again changes
    /// nothing.
    pub async fn mark_app_removing(&self, app: &str, actor: &str) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            let Some(mut a) = t.app(app).await? else {
                return Err(not_found!("app {app}"));
            };
            if a.removing {
                return Ok(());
            }
            let rev = t.revision(&a.target_revision).await?;
            if rev.spec().is_job() {
                return Err(precondition!(
                    "{app} is a job; delete it with `armada job delete`"
                ));
            }
            a.removing = true;
            t.put(&format!("{PFX_APPS}{app}"), &a)?;
            t.audit(&now, actor, "app.remove", app, "").await
        })
    }

    /// DeleteApp removes an app marked for removal with its revisions and
    /// secrets, and the domains no other app names, once it has no
    /// replicas. Its volumes stay.
    pub async fn delete_app(&self, app: &str) -> Result<()> {
        tx!(self, |t| {
            let Some(a) = t.app(app).await? else {
                return Ok(());
            };
            if !a.removing {
                return Err(precondition!("app {app} is not being removed"));
            }
            if !t.app_replicas(app).await?.is_empty() {
                return Err(precondition!("app {app} still has replicas"));
            }
            let pins = t.secret_pins(app, true).await?;
            let shared = pins.iter().any(|p| p.app != app);
            t.delete(&format!("{PFX_APPS}{app}"));
            t.delete_prefix(&format!("{PFX_REVS}{app}/"));
            if !shared {
                t.delete_prefix(&format!("{PFX_SECRETS}{app}/"));
                t.delete_prefix(&format!("{PFX_SECRET_SEQ}{app}/"));
                t.delete_prefix(&format!("{PFX_SECRET_USERS}{app}/"));
            }
            t.prune_domains().await
        })
    }
}

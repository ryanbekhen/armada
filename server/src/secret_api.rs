//! Secrets through the API (Go's secrets.go, ADR 0006 and 0052). The
//! handlers never log, return, or audit a secret's value.

use armada_proto::armada::v1::*;
use armada_secrets::{MAX_SIZE, Value};
use armada_spec::validate::{
    DEFAULT_SPACE, secret_source, valid_app_id, valid_space, validate_secret_key,
};
use armada_store::Kind;
use tonic::{Code, Status};

use crate::apps::backups_later;
use crate::events::timestamp;
use crate::grpc::Auth;
use crate::reconcile::{ROLLOUT, app_event};
use crate::{Server, store_err};

/// checkSecretTarget: a secret's ID and, unless listing, a key name.
fn check_secret_target(secret: &str, key: &str, listing: bool) -> Result<(), Status> {
    if !valid_app_id(secret) {
        return Err(Status::new(
            Code::InvalidArgument,
            format!(
                "invalid secret {}: want NAME, or NAME.SPACE for a secret of another space",
                armada_spec::go::quote(secret)
            ),
        ));
    }
    if listing {
        return Ok(());
    }
    validate_secret_key(key).map_err(|e| Status::new(Code::InvalidArgument, e))
}

impl Server {
    /// checkSecretBackups: a change to a key that sets the bucket URL of
    /// the revision an app is heading to. The bucket's check itself comes
    /// with volumes (pull request 12 of ADR 0055).
    async fn check_secret_backups(&self, a: &Auth, secret: &str, key: &str) -> Result<(), Status> {
        if a.acc.admin() {
            return Ok(());
        }
        let mut apps = vec![secret.to_string()];
        let infos = match self.store().list_secrets(secret).await {
            Err(e) if e.kind == Kind::NotFound => Vec::new(),
            Err(e) => return Err(store_err(&e)),
            Ok(v) => v,
        };
        for info in infos.iter().filter(|i| i.name == key) {
            for rn in &info.used_by {
                if let Some(i) = rn.rfind("--r")
                    && i > 0
                    && !apps.iter().any(|x| x == &rn[..i])
                {
                    apps.push(rn[..i].to_string());
                }
            }
        }
        for app in apps {
            let x = match self.store().get_app(&app).await {
                Err(e) if e.kind == Kind::NotFound => continue,
                Err(e) => return Err(store_err(&e)),
                Ok(x) => x,
            };
            let rn = if x.target_revision.is_empty() {
                x.active_revision.clone()
            } else {
                x.target_revision.clone()
            };
            if rn.is_empty() {
                continue;
            }
            let rev = self
                .store()
                .get_revision(&rn)
                .await
                .map_err(|e| store_err(&e))?;
            let Some(sp) = &rev.spec else { continue };
            let uses = sp.volumes.iter().any(|v| {
                v.backup.as_ref().is_some_and(|b| {
                    let (sid, k) = secret_source(&app, &b.url_secret_ref);
                    sid == secret && k == key
                })
            });
            if uses {
                return Err(backups_later());
            }
        }
        Ok(())
    }

    /// SetSecret stores a new version of a secret's key, encrypted with
    /// the master key, and optionally rolls out every app using the key.
    pub(crate) async fn set_secret(
        &self,
        a: &Auth,
        req: SetSecretRequest,
    ) -> Result<SetSecretResponse, Status> {
        a.acc.app(&req.app)?;
        let (secret, key) = (req.app.clone(), req.name.clone());
        check_secret_target(&secret, &key, false)?;
        if req.value.len() > MAX_SIZE {
            return Err(Status::new(
                Code::InvalidArgument,
                format!(
                    "secret is {} bytes; the limit is {MAX_SIZE}",
                    req.value.len()
                ),
            ));
        }
        let Some(keys) = self.0.keys.clone() else {
            return Err(Status::new(
                Code::FailedPrecondition,
                "secrets are disabled: the server has no master key",
            ));
        };
        self.check_secret_backups(a, &secret, &key).await?;
        let val = Value::new(&req.value);
        let seal = |v: i64| {
            keys.seal(&secret, &key, v, &val)
                .map_err(|e| armada_store::Error::other(e.to_string()))
        };
        let (version, revs) = match self
            .store()
            .set_secret(&secret, &key, &seal, req.rollout, &a.actor())
            .await
        {
            Ok(x) => x,
            Err(e) => {
                self.0.log.error(
                    "set secret failed",
                    &[
                        ("secret", secret.clone()),
                        ("key", key.clone()),
                        ("err", e.to_string()),
                    ],
                );
                return Err(store_err(&e));
            }
        };
        self.0.log.info(
            "secret set",
            &[
                ("secret", secret.clone()),
                ("key", key.clone()),
                ("version", version.to_string()),
                ("rollouts", format!("{revs:?}")),
                ("by", a.actor()),
            ],
        );
        for rev in &revs {
            let app = &rev[..rev.rfind("--r").unwrap_or(rev.len())];
            self.record(app_event(
                ROLLOUT,
                rev,
                app,
                "Started",
                &format!("rolling out {rev} for secret {secret} key {key} version {version}"),
            ))
            .await;
        }
        let mut resp = SetSecretResponse {
            version: version as i32,
            revisions: revs.clone(),
            ..Default::default()
        };
        if let Some(first) = revs.first() {
            resp.revision = first.clone();
            self.trigger();
        }
        Ok(resp)
    }

    /// ListSecrets lists a secret's keys without their values.
    pub(crate) async fn list_secrets(
        &self,
        a: &Auth,
        req: ListSecretsRequest,
    ) -> Result<ListSecretsResponse, Status> {
        a.acc.app(&req.app)?;
        check_secret_target(&req.app, "", true)?;
        let list = self
            .store()
            .list_secrets(&req.app)
            .await
            .map_err(|e| store_err(&e))?;
        Ok(ListSecretsResponse {
            secrets: list
                .iter()
                .map(|s| SecretInfo {
                    name: s.name.clone(),
                    version: s.version as i32,
                    updated_at: Some(timestamp(&s.updated_at)),
                    updated_by: s.updated_by.clone(),
                    used_by: s.used_by.clone(),
                })
                .collect(),
        })
    }

    /// ListSpaceSecrets lists the secrets of a space without their values.
    pub(crate) async fn list_space_secrets(
        &self,
        a: &Auth,
        req: ListSpaceSecretsRequest,
    ) -> Result<ListSpaceSecretsResponse, Status> {
        let space = if req.space.is_empty() {
            DEFAULT_SPACE.to_string()
        } else {
            req.space.clone()
        };
        a.acc.space(&space)?;
        if !valid_space(&space) {
            return Err(Status::new(
                Code::InvalidArgument,
                format!("invalid space {}", armada_spec::go::quote(&space)),
            ));
        }
        let list = self
            .store()
            .list_space_secrets(&space)
            .await
            .map_err(|e| store_err(&e))?;
        Ok(ListSpaceSecretsResponse {
            secrets: list
                .iter()
                .map(|s| SpaceSecretInfo {
                    name: s.name.clone(),
                    keys: s.keys as i32,
                    updated_at: Some(timestamp(&s.updated_at)),
                    updated_by: s.updated_by.clone(),
                    used_by: s.used_by.clone(),
                })
                .collect(),
        })
    }

    /// DeleteSecret removes every version of a key no app uses, or with
    /// whole every key of the secret.
    pub(crate) async fn delete_secret(
        &self,
        a: &Auth,
        req: DeleteSecretRequest,
    ) -> Result<DeleteSecretResponse, Status> {
        a.acc.app(&req.app)?;
        let (secret, key) = (req.app.clone(), req.name.clone());
        check_secret_target(&secret, &key, req.whole)?;
        if req.whole && !key.is_empty() {
            return Err(Status::new(
                Code::InvalidArgument,
                "deleting a whole secret names no key",
            ));
        }
        self.store()
            .delete_secret(&secret, &key, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        self.0.opened.forget(&secret, &key);
        self.0.log.info(
            "secret deleted",
            &[("secret", secret), ("key", key), ("by", a.actor())],
        );
        Ok(DeleteSecretResponse {})
    }
}

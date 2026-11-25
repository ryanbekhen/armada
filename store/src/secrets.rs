//! Secrets (etcd.go, ADR 0006, ADR 0052).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use armada_secrets::Sealed;
use armada_spec::App as Spec;
use armada_spec::validate::{secret_source, split_app_id};

use crate::apps::seq_key;
use crate::error::{Result, not_found, other, precondition};
use crate::gojson::{decode, from_ms, unix_milli};
use crate::records::{AppRec, RevRec, SecretRec};
use crate::tx::*;
use crate::types::*;

pub(crate) fn secret_key(app: &str, name: &str, version: i64) -> String {
    format!("{PFX_SECRETS}{app}/{name}/{}", seq_key(version))
}

/// splitSecretKey: the key name and version of a secret record's key.
fn split_secret_key(key: &str, app: &str) -> Option<(String, i64)> {
    let pfx = format!("{PFX_SECRETS}{app}/");
    let rest = key.strip_prefix(pfx.as_str()).unwrap_or(key);
    let (name, ver) = rest.split_once('/')?;
    armada_spec::go::atoi(ver)
        .ok()
        .map(|v| (name.to_string(), v))
}

/// One pin of a kept revision on a key of a secret.
#[derive(Clone)]
pub(crate) struct SecretPin {
    pub app: String,
    pub rev: RevRec,
    pub key: String,
    pub version: i64,
}

impl Etx<'_> {
    /// latestVersions: the newest version of every key of a secret.
    pub(crate) async fn latest_versions(&self, app: &str) -> Result<BTreeMap<String, i64>> {
        let mut out: BTreeMap<String, i64> = BTreeMap::new();
        for (k, _) in self.list(&format!("{PFX_SECRETS}{app}/")).await? {
            if let Some((name, v)) = split_secret_key(&k, app)
                && v > out.get(&name).copied().unwrap_or(0)
            {
                out.insert(name, v);
            }
        }
        Ok(out)
    }

    /// secretEnv resolves envFrom against the keys the secrets have now.
    pub(crate) async fn secret_env(&self, sp: &Spec) -> Result<Spec> {
        if sp.env_from.is_zero() {
            return Ok(sp.clone());
        }
        let mut keys: HashMap<String, Vec<String>> = HashMap::new();
        if sp.env_from.own {
            let latest = self.latest_versions(&sp.id()).await?;
            keys.insert(String::new(), latest.into_keys().collect());
        }
        for e in sp.env_from.list() {
            let latest = self
                .latest_versions(&armada_spec::validate::app_id(&sp.space, &e.secret))
                .await?;
            if latest.is_empty() {
                return Err(precondition!(
                    "envFrom names the secret {}, which has no keys (create it with `armada secret create {}`)",
                    e.secret,
                    e.secret
                ));
            }
            keys.insert(e.secret.clone(), latest.into_keys().collect());
        }
        sp.with_secret_env(&keys)
            .map_err(|e| precondition!("envFrom: {}", armada_spec::validate::join(&e)))
    }

    /// pinSecrets resolves the latest version of every key sp references.
    pub(crate) async fn pin_secrets(&self, sp: &Spec) -> Result<BTreeMap<String, i64>> {
        let id = sp.id();
        let mut latest: HashMap<String, BTreeMap<String, i64>> = HashMap::new();
        let mut pins = BTreeMap::new();
        let mut missing = Vec::new();
        let mut own = true;
        for r in sp.secret_refs() {
            let (sid, key) = secret_source(&id, &r);
            if !latest.contains_key(&sid) {
                let l = self.latest_versions(&sid).await?;
                latest.insert(sid.clone(), l);
            }
            match latest[&sid].get(&key) {
                None => {
                    own = own && sid == id;
                    missing.push(r);
                }
                Some(v) => {
                    pins.insert(r, *v);
                }
            }
        }
        if !missing.is_empty() {
            let mut cmd = format!("armada secret set {} NAME", sp.name);
            if !own {
                cmd = "armada secret set SECRET KEY".to_string();
            }
            if id != sp.name {
                cmd += &format!(" --space {}", sp.space);
            }
            return Err(precondition!(
                "app {id} references secrets that are not set: {} (set them with `{cmd}`)",
                missing.join(", ")
            ));
        }
        Ok(pins)
    }

    /// noteSecretUsers records app as a user of every other secret pins
    /// name.
    pub(crate) async fn note_secret_users(
        &mut self,
        app: &str,
        pins: &BTreeMap<String, i64>,
    ) -> Result<()> {
        for r in pins.keys() {
            let (sid, _) = secret_source(app, r);
            if sid == app {
                continue;
            }
            let k = format!("{PFX_SECRET_USERS}{sid}/{app}");
            if self.get_raw(&k).await?.is_some() {
                continue;
            }
            self.put(&k, &true)?;
        }
        Ok(())
    }

    /// checkPins verifies every secret version rev pins still exists.
    pub(crate) async fn check_pins(&self, rev: &Revision) -> Result<()> {
        for (r, v) in &rev.secrets {
            let (sid, key) = secret_source(&rev.app, r);
            if self.get_raw(&secret_key(&sid, &key, *v)).await?.is_none() {
                return Err(precondition!(
                    "revision {} uses secret {r} version {v}, which was deleted",
                    rev.name
                ));
            }
        }
        Ok(())
    }

    /// secretPins: every pin of a kept revision on a key of the secret.
    /// With clean, index entries of apps that pin none of its keys any more
    /// are deleted.
    pub(crate) async fn secret_pins(
        &mut self,
        secret: &str,
        clean: bool,
    ) -> Result<Vec<SecretPin>> {
        let mut apps = vec![secret.to_string()];
        let upfx = format!("{PFX_SECRET_USERS}{secret}/");
        for (k, _) in self.list(&upfx).await? {
            apps.push(k.strip_prefix(upfx.as_str()).unwrap_or(&k).to_string());
        }
        let mut out = Vec::new();
        for (i, app) in apps.iter().enumerate() {
            let mut found = false;
            for (_, r) in self
                .list_into::<RevRec>(&format!("{PFX_REVS}{app}/"))
                .await?
            {
                if let Some(s) = &r.secrets {
                    for (rf, v) in s {
                        let (sid, key) = secret_source(app, rf);
                        if sid == secret {
                            out.push(SecretPin {
                                app: app.clone(),
                                rev: r.clone(),
                                key,
                                version: *v,
                            });
                            found = true;
                        }
                    }
                }
            }
            if i > 0 && !found && clean {
                self.delete(&format!("{upfx}{app}"));
            }
        }
        Ok(out)
    }

    /// servingPins: the pins held by an app's active or target revision.
    pub(crate) async fn serving_pins(&mut self, secret: &str) -> Result<Vec<SecretPin>> {
        let pins = self.secret_pins(secret, false).await?;
        let mut apps: HashMap<String, Option<AppRec>> = HashMap::new();
        let mut out = Vec::new();
        for p in pins {
            if !apps.contains_key(&p.app) {
                let a = self.app(&p.app).await?;
                apps.insert(p.app.clone(), a);
            }
            let Some(a) = &apps[&p.app] else {
                continue;
            };
            if p.rev.name == a.active_revision || p.rev.name == a.target_revision {
                out.push(p);
            }
        }
        Ok(out)
    }

    /// pruneSecrets deletes versions that are neither the latest of their
    /// key nor pinned by a kept revision of any app.
    pub(crate) async fn prune_secrets(&mut self, secret: &str) -> Result<()> {
        let pins = self.secret_pins(secret, true).await?;
        let pinned: BTreeSet<String> = pins
            .iter()
            .map(|p| secret_key(secret, &p.key, p.version))
            .collect();
        let latest = self.latest_versions(secret).await?;
        for (k, _) in self.list(&format!("{PFX_SECRETS}{secret}/")).await? {
            if let Some((name, v)) = split_secret_key(&k, secret)
                && v < latest.get(&name).copied().unwrap_or(0)
                && !pinned.contains(&k)
            {
                self.delete(&k);
            }
        }
        Ok(())
    }

    /// needSchema refuses what only servers at schema v or later may run.
    pub(crate) async fn need_schema(&self, v: i64, what: &str) -> Result<()> {
        let cur = self.get::<i64>(KEY_SCHEMA).await?.unwrap_or(0);
        if cur < v {
            return Err(precondition!(
                "{what} need every control plane server on this version first (armada server list shows them)"
            ));
        }
        Ok(())
    }
}

impl Etcd {
    /// SetSecret stores a new version of a secret's key; seal encrypts the
    /// value for the version the store allocates. With rollout, every app
    /// whose target revision uses the key gets a new revision.
    pub async fn set_secret(
        &self,
        secret: &str,
        key: &str,
        seal: &(dyn Fn(i64) -> Result<Sealed> + Sync),
        rollout: bool,
        actor: &str,
    ) -> Result<(i64, Vec<String>)> {
        let now = self.now();
        let Some((space, _)) = split_app_id(secret) else {
            return Err(other!("invalid secret {}", armada_spec::go::quote(secret)));
        };
        let mut version = 0;
        let mut revisions = Vec::new();
        tx!(self, |t| {
            revisions.clear();
            t.space_exists(&space).await?;
            let latest = t.latest_versions(secret).await?;
            let floor = t
                .get::<i64>(&format!("{PFX_SECRET_SEQ}{secret}/{key}"))
                .await?
                .unwrap_or(0);
            version = latest.get(key).copied().unwrap_or(0).max(floor) + 1;
            let sealed = seal(version)?;
            t.put(
                &secret_key(secret, key, version),
                &SecretRec {
                    key_id: sealed.key_id,
                    wrapped_key: Some(sealed.wrapped_key),
                    ciphertext: Some(sealed.ciphertext),
                    created_at: unix_milli(&now),
                    created_by: actor.to_string(),
                },
            )?;
            t.audit(
                &now,
                actor,
                "secret.set",
                secret,
                &format!("{key} v{version}"),
            )
            .await?;
            if rollout {
                revisions = self.rollout_secret(t, secret, key, actor).await?;
            }
            t.prune_secrets(secret).await
        })?;
        Ok((version, revisions))
    }

    /// rolloutSecret deploys again every app whose target revision uses key
    /// of secret.
    async fn rollout_secret(
        &self,
        t: &mut Etx<'_>,
        secret: &str,
        key: &str,
        actor: &str,
    ) -> Result<Vec<String>> {
        let pins = t.secret_pins(secret, false).await?;
        let mut out = Vec::new();
        let mut done = BTreeSet::new();
        for p in pins {
            if p.key != key || done.contains(&p.app) {
                continue;
            }
            let Some(a) = t.app(&p.app).await? else {
                continue;
            };
            if a.removing || p.rev.name != a.target_revision {
                continue;
            }
            done.insert(p.app.clone());
            let rev = t.revision(&a.target_revision).await?;
            let (next, created) = self
                .deploy_revision(t, rev.spec(), a.replicas, actor, "secret.rollout", false)
                .await?;
            if created {
                out.push(next.name);
            }
        }
        out.sort();
        Ok(out)
    }

    /// GetSecret returns one encrypted version of a key.
    pub async fn get_secret(&self, secret: &str, key: &str, version: i64) -> Result<Sealed> {
        let mut out = None;
        view!(self, |t| {
            let Some(r) = t
                .get::<SecretRec>(&secret_key(secret, key, version))
                .await?
            else {
                return Err(not_found!("secret {secret}/{key} v{version}"));
            };
            out = Some(Sealed {
                key_id: r.key_id,
                wrapped_key: r.wrapped_key.unwrap_or_default(),
                ciphertext: r.ciphertext.unwrap_or_default(),
            });
            Ok(())
        })?;
        Ok(out.expect("set by the view"))
    }

    /// ListSecrets describes the keys of a secret, sorted by name.
    pub async fn list_secrets(&self, secret: &str) -> Result<Vec<SecretInfo>> {
        let mut out: Vec<SecretInfo> = Vec::new();
        view!(self, |t| {
            out.clear();
            let latest = t.latest_versions(secret).await?;
            for (key, v) in &latest {
                let r: SecretRec = t
                    .get(&secret_key(secret, key, *v))
                    .await?
                    .unwrap_or_default();
                out.push(SecretInfo {
                    app: secret.to_string(),
                    name: key.clone(),
                    version: *v,
                    updated_at: from_ms(r.created_at),
                    updated_by: r.created_by,
                    used_by: Vec::new(),
                });
            }
            let mut pins = t.secret_pins(secret, false).await?;
            // Newest revision first, the secret's own app before others.
            pins.sort_by(|a, b| {
                if a.app != b.app {
                    if a.app == secret {
                        return std::cmp::Ordering::Less;
                    }
                    if b.app == secret {
                        return std::cmp::Ordering::Greater;
                    }
                    return a.app.cmp(&b.app);
                }
                b.rev.seq.cmp(&a.rev.seq)
            });
            for p in &pins {
                for o in out.iter_mut() {
                    if o.name == p.key && !o.used_by.contains(&p.rev.name) {
                        o.used_by.push(p.rev.name.clone());
                    }
                }
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// ListSpaceSecrets describes the secrets of a space, sorted by name.
    pub async fn list_space_secrets(&self, space: &str) -> Result<Vec<SpaceSecret>> {
        let mut out = Vec::new();
        view!(self, |t| {
            out.clear();
            t.space_exists(space).await?;
            let mut by_id: BTreeMap<String, SpaceSecret> = BTreeMap::new();
            let mut keys: HashMap<String, BTreeSet<String>> = HashMap::new();
            for (k, v) in t.list(PFX_SECRETS).await? {
                let rest_all = k.strip_prefix(PFX_SECRETS).unwrap_or(&k);
                let (id, rest) = rest_all.split_once('/').unwrap_or((rest_all, ""));
                let Some((sp, name)) = split_app_id(id) else {
                    continue;
                };
                if sp != space || !rest.contains('/') {
                    continue;
                }
                by_id.entry(id.to_string()).or_insert_with(|| SpaceSecret {
                    id: id.to_string(),
                    name,
                    keys: 0,
                    updated_at: armada_spec::gotime::Time::zero(),
                    updated_by: String::new(),
                    used_by: Vec::new(),
                });
                let key = rest.split_once('/').map_or(rest, |(k, _)| k);
                keys.entry(id.to_string())
                    .or_default()
                    .insert(key.to_string());
                let r: SecretRec = decode(&k, &v)?;
                let at = from_ms(r.created_at);
                let s = by_id.get_mut(id).expect("inserted");
                if at.after(&s.updated_at) {
                    s.updated_at = at;
                    s.updated_by = r.created_by;
                }
            }
            for (id, mut sec) in by_id {
                sec.keys = keys.get(&id).map_or(0, |k| k.len() as i64);
                for p in t.serving_pins(&id).await? {
                    if !sec.used_by.contains(&p.app) {
                        sec.used_by.push(p.app);
                    }
                }
                sec.used_by.sort();
                out.push(sec);
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// DeleteSecret removes every version of a key, or with key "" of
    /// every key of the secret.
    pub async fn delete_secret(&self, secret: &str, key: &str, actor: &str) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            for p in t.serving_pins(secret).await? {
                if key.is_empty() || p.key == key {
                    let what = if key.is_empty() {
                        format!("key {} of secret {secret}", p.key)
                    } else {
                        format!("secret {key}")
                    };
                    return Err(precondition!(
                        "{what} is used by revision {}; deploy a spec without it first",
                        p.rev.name
                    ));
                }
            }
            let mut prefix = format!("{PFX_SECRETS}{secret}/");
            if !key.is_empty() {
                prefix += &format!("{key}/");
            }
            let kvs = t.list(&prefix).await?;
            if kvs.is_empty() {
                if key.is_empty() {
                    return Err(not_found!("secret {secret}"));
                }
                return Err(not_found!("secret {secret}/{key}"));
            }
            let mut last: BTreeMap<String, i64> = BTreeMap::new();
            for (k, _) in &kvs {
                if let Some((name, v)) = split_secret_key(k, secret) {
                    let e = last.entry(name).or_insert(0);
                    *e = (*e).max(v);
                }
            }
            t.delete_prefix(&prefix);
            for (k, v) in &last {
                t.put(&format!("{PFX_SECRET_SEQ}{secret}/{k}"), v)?;
            }
            if key.is_empty() {
                t.delete_prefix(&format!("{PFX_SECRET_USERS}{secret}/"));
                return t.audit(&now, actor, "secret.delete", secret, "").await;
            }
            t.audit(&now, actor, "secret.delete", secret, key).await
        })
    }
}

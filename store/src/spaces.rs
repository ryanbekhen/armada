//! Spaces (spaces.go, ADR 0026).

use std::collections::BTreeSet;

use armada_spec::go::quote;
use armada_spec::validate::{DEFAULT_SPACE, split_app_id, valid_space};
use serde_json::{Map, Value};

use crate::access::{PFX_SERVICES, PFX_USERS, ROLE_SPACE_CREATOR};
use crate::error::{Result, conflict, not_found, other, precondition};
use crate::gojson::{compact, decode, escape_html, from_ms, truncate_ms, unix_milli};
use crate::records::{DomainRec, ReplicaRec, SpaceRec};
use crate::tx::*;
use crate::types::*;

pub(crate) const PFX_SPACES: &str = "spaces/";

fn space_of_rec(r: SpaceRec) -> Space {
    Space {
        name: r.name,
        created_at: from_ms(r.created_at),
        created_by: r.created_by,
    }
}

fn default_space() -> Space {
    Space {
        name: DEFAULT_SPACE.to_string(),
        created_at: armada_spec::gotime::Time::zero(),
        created_by: String::new(),
    }
}

impl Etx<'_> {
    /// spaceExists: ErrPrecondition unless space is the default one or has
    /// a record.
    pub(crate) async fn space_exists(&self, space: &str) -> Result<()> {
        if space.is_empty() || space == DEFAULT_SPACE {
            return Ok(());
        }
        if self
            .get::<SpaceRec>(&format!("{PFX_SPACES}{space}"))
            .await?
            .is_none()
        {
            return Err(precondition!(
                "space {space} does not exist (create it with `armada space create {space}`)"
            ));
        }
        Ok(())
    }

    /// spaceObjects: what is still stored under space.
    async fn space_objects(&self, space: &str) -> Result<Vec<String>> {
        let mut left = Vec::new();
        for (prefix, what) in [
            (PFX_APPS, "apps"),
            (PFX_SECRETS, "secrets"),
            (PFX_VOLUMES, "volumes"),
            (PFX_RUNS, "job runs"),
            (PFX_REPLICAS, "replicas"),
        ] {
            let mut apps = BTreeSet::new();
            for (k, v) in self.list(prefix).await? {
                let rest = k.strip_prefix(prefix).unwrap_or(&k);
                let mut id = rest.split_once('/').map_or(rest, |(a, _)| a).to_string();
                if prefix == PFX_REPLICAS {
                    let r: ReplicaRec = decode(&k, &v)?;
                    id = r.app;
                }
                if let Some((p, _)) = split_app_id(&id)
                    && p == space
                {
                    apps.insert(id);
                }
            }
            if !apps.is_empty() {
                left.push(format!(
                    "{what} ({})",
                    apps.into_iter().collect::<Vec<_>>().join(", ")
                ));
            }
        }
        Ok(left)
    }
}

impl Etcd {
    /// CreateSpace records a new space; by, a principal with
    /// space-creator, becomes its admin in the same transaction.
    pub async fn create_space(
        &self,
        name: &str,
        actor: &str,
        by: Option<&Principal>,
    ) -> Result<Space> {
        if name == DEFAULT_SPACE {
            return Err(conflict!("space {name} always exists"));
        }
        if !valid_space(name) {
            return Err(other!(
                "invalid space name {}: use lowercase letters, digits, and single hyphens, at most 30 characters",
                quote(name)
            ));
        }
        let now = self.now();
        let p = Space {
            name: name.to_string(),
            created_at: truncate_ms(&now),
            created_by: actor.to_string(),
        };
        tx!(self, |t| {
            let k = format!("{PFX_SPACES}{name}");
            if t.get::<SpaceRec>(&k).await?.is_some() {
                return Err(conflict!("space {name} already exists"));
            }
            if let Some(by) = by {
                t.grant_space(&by.kind, &by.name, name).await?;
            }
            t.put(
                &k,
                &SpaceRec {
                    name: name.to_string(),
                    created_at: unix_milli(&now),
                    created_by: actor.to_string(),
                },
            )?;
            t.audit(&now, actor, "space.create", name, "").await
        })?;
        Ok(p)
    }

    /// GetSpace returns one space; the default one always exists.
    pub async fn get_space(&self, name: &str) -> Result<Space> {
        let mut out = None;
        view!(self, |t| {
            if name == DEFAULT_SPACE {
                out = Some(default_space());
                return Ok(());
            }
            let Some(r) = t.get::<SpaceRec>(&format!("{PFX_SPACES}{name}")).await? else {
                return Err(not_found!("space {name}"));
            };
            out = Some(space_of_rec(r));
            Ok(())
        })?;
        Ok(out.expect("set by the view"))
    }

    /// ListSpaces lists every space, the default one first.
    pub async fn list_spaces(&self) -> Result<Vec<Space>> {
        let mut out = Vec::new();
        view!(self, |t| {
            out = vec![default_space()];
            for (_, r) in t.list_into::<SpaceRec>(PFX_SPACES).await? {
                out.push(space_of_rec(r));
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// DeleteSpace removes an empty space, taking back every role in it
    /// and its domains.
    pub async fn delete_space(&self, name: &str, actor: &str) -> Result<()> {
        if name == DEFAULT_SPACE {
            return Err(precondition!("space {name} cannot be removed"));
        }
        let now = self.now();
        tx!(self, |t| {
            let k = format!("{PFX_SPACES}{name}");
            if t.get::<SpaceRec>(&k).await?.is_none() {
                return Err(not_found!("space {name}"));
            }
            let left = t.space_objects(name).await?;
            if !left.is_empty() {
                return Err(precondition!(
                    "space {name} still holds {}; remove them first",
                    left.join(", ")
                ));
            }
            t.delete(&k);
            t.forget_space(name).await?;
            for (k, d) in t.list_into::<DomainRec>(PFX_DOMAINS).await? {
                if d.space == name {
                    t.delete(&k);
                }
            }
            t.audit(&now, actor, "space.delete", name, "").await
        })
    }
}

/// json.Marshal of a map[string]json.RawMessage: keys sorted, values
/// compacted (they are compact already) and HTML-escaped.
fn marshal_map(m: &Map<String, Value>) -> Vec<u8> {
    let mut out = String::from("{");
    let mut keys: Vec<&String> = m.keys().collect();
    keys.sort();
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&serde_json::to_string(k).expect("a string"));
        out.push(':');
        out.push_str(&String::from_utf8_lossy(&compact(
            m[*k]
                .as_str()
                .expect("raw values are kept as text")
                .as_bytes(),
        )));
    }
    out.push('}');
    escape_html(out).into_bytes()
}

/// Decodes a JSON object into its members, each kept as its raw text (Go's
/// map[string]json.RawMessage).
fn raw_members(b: &[u8]) -> std::result::Result<Map<String, Value>, String> {
    let m: std::collections::BTreeMap<String, Box<serde_json::value::RawValue>> =
        serde_json::from_slice(b).map_err(|e| e.to_string())?;
    Ok(m.into_iter()
        .map(|(k, v)| (k, Value::String(v.get().to_string())))
        .collect())
}

/// renameSpaceField renames a record's project field space; in_spec
/// renames it in the record's spec (revisions) instead.
fn rename_space_field(b: &[u8], in_spec: bool) -> std::result::Result<Option<Vec<u8>>, String> {
    let mut m = raw_members(b)?;
    if in_spec {
        let Some(sp) = m.get("spec").and_then(Value::as_str).map(str::to_string) else {
            // Go reads a missing spec as empty JSON, which fails to decode.
            return Err("unexpected end of JSON input".to_string());
        };
        let Some(changed) = rename_space_field(sp.as_bytes(), false)? else {
            return Ok(None);
        };
        m.insert(
            "spec".to_string(),
            Value::String(String::from_utf8(changed).expect("JSON is UTF-8")),
        );
        return Ok(Some(marshal_map(&m)));
    }
    let Some(v) = m.remove("project") else {
        return Ok(None);
    };
    m.insert("space".to_string(), v);
    Ok(Some(marshal_map(&m)))
}

/// renameGrants renames the project of a principal's grants space, and the
/// project-creator role space-creator.
fn rename_grants(b: &[u8]) -> std::result::Result<Option<Vec<u8>>, String> {
    let mut m = raw_members(b)?;
    let Some(roles) = m.get("roles").and_then(Value::as_str).map(str::to_string) else {
        return Ok(None);
    };
    if roles.is_empty() {
        return Ok(None);
    }
    let list: Option<Vec<std::collections::BTreeMap<String, Box<serde_json::value::RawValue>>>> =
        serde_json::from_str(&roles).map_err(|e| e.to_string())?;
    let mut list: Vec<Map<String, Value>> = list
        .unwrap_or_default()
        .into_iter()
        .map(|g| {
            g.into_iter()
                .map(|(k, v)| (k, Value::String(v.get().to_string())))
                .collect()
        })
        .collect();
    let mut changed = false;
    for g in &mut list {
        if let Some(v) = g.remove("project") {
            g.insert("space".to_string(), v);
            changed = true;
        }
        if g.get("role").and_then(Value::as_str) == Some("\"project-creator\"") {
            g.insert(
                "role".to_string(),
                Value::String(format!("\"{ROLE_SPACE_CREATOR}\"")),
            );
            changed = true;
        }
    }
    if !changed {
        return Ok(None);
    }
    let mut r = String::from("[");
    for (i, g) in list.iter().enumerate() {
        if i > 0 {
            r.push(',');
        }
        r.push_str(&String::from_utf8(marshal_map(g)).expect("JSON is UTF-8"));
    }
    r.push(']');
    m.insert("roles".to_string(), Value::String(r));
    Ok(Some(marshal_map(&m)))
}

/// migrateSpaces moves records written while spaces were called projects
/// to their current names (schema 10 to 11).
pub(crate) async fn migrate_spaces(t: &mut Etx<'_>) -> Result<()> {
    for (k, v) in t.list("projects/").await? {
        let name = k.strip_prefix("projects/").unwrap_or(&k).to_string();
        // json.Marshal of a json.RawMessage compacts it.
        serde_json::from_slice::<serde::de::IgnoredAny>(&v)
            .map_err(|e| other!("json: error calling MarshalJSON for type json.RawMessage: {e}"))?;
        t.put_raw(&format!("{PFX_SPACES}{name}"), compact(&v))?;
    }
    t.delete_prefix("projects/");
    for pfx in [PFX_DOMAINS, PFX_REVS] {
        for (k, v) in t.list(pfx).await? {
            match rename_space_field(&v, pfx == PFX_REVS) {
                Err(e) => return Err(other!("decode {k}: {e}")),
                Ok(Some(b)) => t.put_raw(&k, b)?,
                Ok(None) => {}
            }
        }
    }
    for pfx in [PFX_USERS, PFX_SERVICES] {
        for (k, v) in t.list(pfx).await? {
            match rename_grants(&v) {
                Err(e) => return Err(other!("decode {k}: {e}")),
                Ok(Some(b)) => t.put_raw(&k, b)?,
                Ok(None) => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renames() {
        let b = br#"{"name":"d","project":"p","token":"x"}"#;
        assert_eq!(
            String::from_utf8(rename_space_field(b, false).unwrap().unwrap()).unwrap(),
            r#"{"name":"d","space":"p","token":"x"}"#
        );
        assert!(
            rename_space_field(br#"{"name":"d"}"#, false)
                .unwrap()
                .is_none()
        );
        let r =
            br#"{"name":"u","roles":[{"role":"project-creator"},{"role":"admin","project":"p"}]}"#;
        assert_eq!(
            String::from_utf8(rename_grants(r).unwrap().unwrap()).unwrap(),
            r#"{"name":"u","roles":[{"role":"space-creator"},{"role":"admin","space":"p"}]}"#
        );
    }
}

//! Users, services, and roles (access.go, ADR 0033).

use std::collections::BTreeMap;

use armada_spec::go::quote;
use armada_spec::gotime::Time;
use armada_spec::validate::{
    DEFAULT_SPACE, MAX_NODE_LABELS, check_label_key, check_label_value, valid_space,
};

use crate::error::{Result, conflict, not_found, other, precondition};
use crate::gojson::{decode, from_ms, from_unix, unix_milli};
use crate::records::{AdminRec, AutomationRec, CertRec, GrantRec, PrincipalRec};
use crate::tx::*;
use crate::types::*;

pub const KIND_USER: &str = "user";
pub const KIND_SERVICE: &str = "service";

pub const ROLE_VIEWER: &str = "viewer";
pub const ROLE_DEPLOYER: &str = "deployer";
pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_SPACE_CREATOR: &str = "space-creator";
pub const ROLE_CLUSTER_ADMIN: &str = "cluster-admin";

/// Every role, from the least to the most.
pub const ROLES: [&str; 5] = [
    ROLE_VIEWER,
    ROLE_DEPLOYER,
    ROLE_ADMIN,
    ROLE_SPACE_CREATOR,
    ROLE_CLUSTER_ADMIN,
];

/// MaxServiceCerts bounds the certificates recorded per service.
pub const MAX_SERVICE_CERTS: usize = 8;
/// MaxGrants bounds the assignments of one principal.
pub const MAX_GRANTS: usize = 1000;

pub(crate) const PFX_USERS: &str = "users/";
pub(crate) const PFX_SERVICES: &str = "services/";

/// keyUserCutoff: when the keyspace moved to schema 14 (unix ms).
pub(crate) const KEY_USER_CUTOFF: &str = "meta/user-cutoff";

/// certBackdate: pki.ClockSkew, in seconds.
fn cert_backdate() -> i64 {
    armada_pki::CLOCK_SKEW.as_secs() as i64
}

/// CheckGrant validates a role and where it is given.
pub fn check_grant(g: &Grant) -> Result<()> {
    match g.role.as_str() {
        ROLE_CLUSTER_ADMIN | ROLE_SPACE_CREATOR => {
            if !g.space.is_empty() {
                return Err(other!(
                    "role {} applies to the whole cluster: give it without a space",
                    g.role
                ));
            }
        }
        ROLE_VIEWER => {
            if !g.space.is_empty() && g.space != DEFAULT_SPACE && !valid_space(&g.space) {
                return Err(other!("invalid space {}", quote(&g.space)));
            }
        }
        ROLE_DEPLOYER | ROLE_ADMIN => {
            if g.space.is_empty() {
                return Err(other!("role {} is given in one space: name it", g.role));
            }
            if g.space == DEFAULT_SPACE {
                return Err(precondition!(
                    "role {} cannot be given in the default space, whose containers may reach the platform; give viewer there, or cluster-admin",
                    g.role
                ));
            }
            if !valid_space(&g.space) {
                return Err(other!("invalid space {}", quote(&g.space)));
            }
        }
        _ => {
            return Err(other!(
                "unknown role {} (one of {})",
                quote(&g.role),
                ROLES.join(", ")
            ));
        }
    }
    Ok(())
}

/// CheckLabels validates the node label values a principal's apps may
/// require. With several invalid labels the one named is the first in key
/// order.
pub fn check_labels(labels: &BTreeMap<String, Vec<String>>) -> Result<()> {
    if labels.len() > MAX_NODE_LABELS {
        return Err(other!("at most {MAX_NODE_LABELS} label keys"));
    }
    for (k, vs) in labels {
        check_label_key(k).map_err(|e| other!("label {}: {e}", quote(k)))?;
        if vs.is_empty() || vs.len() > MAX_NODE_LABELS {
            return Err(other!("label {k}: give 1 to {MAX_NODE_LABELS} values"));
        }
        for v in vs {
            check_label_value(v).map_err(|e| other!("label {k}={}: {e}", quote(v)))?;
        }
    }
    Ok(())
}

fn role_index(r: &str) -> i64 {
    ROLES.iter().position(|x| *x == r).map_or(-1, |i| i as i64)
}

fn grant_of(g: &GrantRec) -> Grant {
    Grant {
        role: g.role.clone(),
        space: g.space.clone(),
    }
}

impl PrincipalRec {
    /// userAllowed: whether the record accepts a user certificate.
    fn user_allowed(&self, not_before: &Time, serial: &str) -> bool {
        if self.removed {
            return false;
        }
        if self.cutoff != 0 {
            return (!self.since_serial.is_empty() && serial == self.since_serial)
                || not_before.unix + cert_backdate() > self.cutoff;
        }
        not_before.unix >= self.since
    }

    fn principal(&self, kind: &str, now: &Time) -> Principal {
        Principal {
            kind: kind.to_string(),
            name: self.name.clone(),
            roles: self.roles.iter().map(grant_of).collect(),
            labels: self.labels.clone(),
            created_at: from_ms(self.created_at),
            created_by: self.created_by.clone(),
            since: if self.since != 0 {
                from_unix(self.since)
            } else {
                Time::zero()
            },
            since_serial: self.since_serial.clone(),
            removed: self.removed,
            certs: self
                .certs
                .iter()
                .filter(|c| c.not_after > unix_milli(now))
                .map(|c| NodeCert {
                    serial: c.serial.clone(),
                    not_after: from_ms(c.not_after),
                })
                .collect(),
        }
    }

    fn roles(&self) -> Vec<Grant> {
        self.roles.iter().map(grant_of).collect()
    }

    /// setRoles stores roles sorted and without repeats.
    fn set_roles(&mut self, roles: &[Grant]) {
        let mut out: Vec<GrantRec> = Vec::new();
        for g in roles {
            let gr = GrantRec {
                role: g.role.clone(),
                space: g.space.clone(),
            };
            if !out.contains(&gr) {
                out.push(gr);
            }
        }
        out.sort_by(|a, b| {
            a.space
                .cmp(&b.space)
                .then_with(|| role_index(&a.role).cmp(&role_index(&b.role)))
        });
        self.roles = out;
    }
}

fn principal_key(kind: &str, name: &str) -> Result<String> {
    match kind {
        KIND_USER => Ok(format!("{PFX_USERS}{name}")),
        KIND_SERVICE => Ok(format!("{PFX_SERVICES}{name}")),
        _ => Err(other!(
            "unknown principal kind {} (user or service)",
            quote(kind)
        )),
    }
}

fn roles_detail(roles: &[Grant]) -> String {
    format!(
        "roles={}",
        roles
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn cluster_admin() -> Grant {
    Grant {
        role: ROLE_CLUSTER_ADMIN.to_string(),
        space: String::new(),
    }
}

impl Etx<'_> {
    /// checkGrants validates roles: each space must exist.
    async fn check_grants(&self, roles: &[Grant]) -> Result<()> {
        if roles.len() > MAX_GRANTS {
            return Err(other!("at most {MAX_GRANTS} assignments"));
        }
        for g in roles {
            check_grant(g)?;
            if !g.space.is_empty() {
                self.space_exists(&g.space).await?;
            }
        }
        Ok(())
    }

    /// unrecordedUserAllowed: whether a user certificate that starts at
    /// not_before is accepted while its name has no record.
    async fn unrecorded_user_allowed(&self, not_before: &Time) -> Result<bool> {
        if let Some(cutoff) = self.get::<i64>(KEY_USER_CUTOFF).await? {
            return Ok(unix_milli(&not_before.add(cert_backdate() * 1_000_000_000)) <= cutoff);
        }
        Ok(self.get::<i64>(KEY_SCHEMA).await?.unwrap_or(0) < 14)
    }

    /// grantSpace makes the principal that creates space its admin.
    pub(crate) async fn grant_space(&mut self, kind: &str, name: &str, space: &str) -> Result<()> {
        let key = principal_key(kind, name)?;
        let r = self.get::<PrincipalRec>(&key).await?;
        let ok = r.is_some();
        let mut r = r.unwrap_or_default();
        let roles = r.roles();
        let creator = Grant {
            role: ROLE_SPACE_CREATOR.to_string(),
            space: String::new(),
        };
        if !ok || r.removed || !roles.contains(&creator) {
            return Err(precondition!("{kind} {name} may not create spaces"));
        }
        let mut next = roles;
        next.push(Grant {
            role: ROLE_ADMIN.to_string(),
            space: space.to_string(),
        });
        r.set_roles(&next);
        self.put(&key, &r)
    }

    /// forgetSpace takes every role in a deleted space back.
    pub(crate) async fn forget_space(&mut self, space: &str) -> Result<()> {
        for pfx in [PFX_USERS, PFX_SERVICES] {
            for (k, v) in self.list(pfx).await? {
                let mut r: PrincipalRec = decode(&k, &v)?;
                let keep: Vec<GrantRec> = r
                    .roles
                    .iter()
                    .filter(|g| g.space != space)
                    .cloned()
                    .collect();
                if keep.len() != r.roles.len() {
                    r.roles = keep;
                    self.put(&k, &r)?;
                }
            }
        }
        Ok(())
    }
}

/// migrateUsers (schema 13 -> 14) records when unrecorded user names
/// stopped being cluster-admins for new certificates.
pub(crate) async fn migrate_users(t: &mut Etx<'_>) -> Result<()> {
    if t.get::<i64>(KEY_USER_CUTOFF).await?.is_some() {
        return Ok(());
    }
    let now = unix_milli(&t.s.now());
    t.put(KEY_USER_CUTOFF, &now)
}

/// migrateAccess moves administrators and automation identities to users
/// and services (schema 8 to 9).
pub(crate) async fn migrate_access(t: &mut Etx<'_>) -> Result<()> {
    for (_, a) in t.list_into::<AdminRec>("admins/").await? {
        let mut r = PrincipalRec {
            name: a.name.clone(),
            created_at: a.added_at,
            created_by: a.added_by,
            since: a.since,
            removed: a.removed,
            ..Default::default()
        };
        if !a.removed {
            r.set_roles(&[cluster_admin()]);
        }
        t.put(&format!("{PFX_USERS}{}", a.name), &r)?;
    }
    for (_, a) in t.list_into::<AutomationRec>("automation/").await? {
        let mut r = PrincipalRec {
            name: a.name.clone(),
            labels: a.labels,
            created_at: a.created_at,
            created_by: a.created_by,
            certs: a.certs,
            ..Default::default()
        };
        let mut roles: Vec<Grant> = a
            .spaces
            .iter()
            .map(|p| Grant {
                role: ROLE_ADMIN.to_string(),
                space: p.clone(),
            })
            .collect();
        if a.create_spaces {
            roles.push(Grant {
                role: ROLE_SPACE_CREATOR.to_string(),
                space: String::new(),
            });
        }
        r.set_roles(&roles);
        t.put(&format!("{PFX_SERVICES}{}", a.name), &r)?;
    }
    t.delete_prefix("admins/");
    t.delete_prefix("automation/");
    Ok(())
}

impl Etcd {
    /// CreateUser records a user whose certificates issued before p.since
    /// are refused.
    pub async fn create_user(&self, p: &Principal, actor: &str) -> Result<Principal> {
        check_labels(&p.labels)?;
        let now = self.now();
        let mut out = None;
        tx!(self, |t| {
            t.check_grants(&p.roles).await?;
            let k = format!("{PFX_USERS}{}", p.name);
            if let Some(r) = t.get::<PrincipalRec>(&k).await?
                && !r.removed
            {
                return Err(conflict!(
                    "user {} exists; give them a new certificate with `armada user credentials`",
                    p.name
                ));
            }
            let mut r = PrincipalRec {
                name: p.name.clone(),
                labels: p.labels.clone(),
                created_at: unix_milli(&now),
                created_by: actor.to_string(),
                since: p.since.unix,
                since_serial: p.since_serial.clone(),
                ..Default::default()
            };
            if !p.since_serial.is_empty() {
                r.cutoff = self.now().unix;
            }
            r.set_roles(&p.roles);
            t.put(&k, &r)?;
            let pr = r.principal(KIND_USER, &now);
            t.audit(
                &now,
                actor,
                "user.create",
                &p.name,
                &roles_detail(&pr.roles),
            )
            .await?;
            out = Some(pr);
            Ok(())
        })?;
        Ok(out.expect("set by the transaction"))
    }

    /// KnowUser records a user with cluster-admin unless the name is on
    /// record.
    pub async fn know_user(&self, name: &str) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            let k = format!("{PFX_USERS}{name}");
            if t.get::<PrincipalRec>(&k).await?.is_some() {
                return Ok(());
            }
            let mut r = PrincipalRec {
                name: name.to_string(),
                created_at: unix_milli(&now),
                ..Default::default()
            };
            r.set_roles(&[cluster_admin()]);
            t.put(&k, &r)
        })
    }

    /// SetUserSince refuses a user's certificates issued before since,
    /// after a new one (serial) was issued to them.
    pub async fn set_user_since(
        &self,
        name: &str,
        since: &Time,
        serial: &str,
        actor: &str,
    ) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            let k = format!("{PFX_USERS}{name}");
            let Some(mut r) = t.get::<PrincipalRec>(&k).await?.filter(|r| !r.removed) else {
                return Err(not_found!("user {name}"));
            };
            r.since = since.unix;
            r.since_serial = serial.to_string();
            r.cutoff = self.now().unix;
            t.put(&k, &r)?;
            t.audit(&now, actor, "user.certificate", name, "").await
        })
    }

    /// CreateService records a service; ErrConflict if it exists.
    pub async fn create_service(&self, p: &Principal, actor: &str) -> Result<Principal> {
        check_labels(&p.labels)?;
        let now = self.now();
        let mut out = None;
        tx!(self, |t| {
            t.check_grants(&p.roles).await?;
            let k = format!("{PFX_SERVICES}{}", p.name);
            if t.get::<PrincipalRec>(&k).await?.is_some() {
                return Err(conflict!("service {} exists", p.name));
            }
            let mut r = PrincipalRec {
                name: p.name.clone(),
                labels: p.labels.clone(),
                created_at: unix_milli(&now),
                created_by: actor.to_string(),
                ..Default::default()
            };
            r.set_roles(&p.roles);
            t.put(&k, &r)?;
            let pr = r.principal(KIND_SERVICE, &now);
            t.audit(
                &now,
                actor,
                "service.create",
                &p.name,
                &roles_detail(&pr.roles),
            )
            .await?;
            out = Some(pr);
            Ok(())
        })?;
        Ok(out.expect("set by the transaction"))
    }

    /// GetPrincipal returns a user or service on record.
    pub async fn get_principal(&self, kind: &str, name: &str) -> Result<Principal> {
        let key = principal_key(kind, name)?;
        let mut out = None;
        view!(self, |t| {
            let Some(r) = t.get::<PrincipalRec>(&key).await? else {
                return Err(not_found!("{kind} {name}"));
            };
            out = Some(r.principal(kind, &self.now()));
            Ok(())
        })?;
        Ok(out.expect("set by the view"))
    }

    /// ListPrincipals lists users, then services, by name; kind "" both.
    pub async fn list_principals(&self, kind: &str) -> Result<Vec<Principal>> {
        let mut out = Vec::new();
        view!(self, |t| {
            out.clear();
            let now = self.now();
            for k in [KIND_USER, KIND_SERVICE] {
                if !kind.is_empty() && kind != k {
                    continue;
                }
                let pfx = principal_key(k, "")?;
                for (_, r) in t.list_into::<PrincipalRec>(&pfx).await? {
                    out.push(r.principal(k, &now));
                }
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// update applies a change to a principal on record (not a deleted
    /// user) and audits action.
    async fn update_principal(
        &self,
        kind: &str,
        name: &str,
        actor: &str,
        action: &str,
        change: Change<'_>,
    ) -> Result<Principal> {
        let key = principal_key(kind, name)?;
        let now = self.now();
        let mut out = None;
        tx!(self, |t| {
            let Some(mut r) = t.get::<PrincipalRec>(&key).await?.filter(|r| !r.removed) else {
                return Err(not_found!("{kind} {name}"));
            };
            let detail = match &change {
                Change::Labels(l) => {
                    r.labels = (*l).clone();
                    String::new()
                }
                Change::Assign(g) => {
                    t.check_grants(std::slice::from_ref(*g)).await?;
                    let mut roles = r.roles();
                    if roles.len() >= MAX_GRANTS {
                        return Err(other!("at most {MAX_GRANTS} assignments"));
                    }
                    roles.push((*g).clone());
                    r.set_roles(&roles);
                    g.to_string()
                }
                Change::Unassign(g) => {
                    let mut roles = r.roles();
                    let Some(i) = roles.iter().position(|x| x == *g) else {
                        return Err(not_found!("{kind} {name} has no role {g}"));
                    };
                    roles.remove(i);
                    r.set_roles(&roles);
                    g.to_string()
                }
            };
            t.put(&key, &r)?;
            out = Some(r.principal(kind, &now));
            t.audit(&now, actor, action, &format!("{kind}:{name}"), &detail)
                .await
        })?;
        Ok(out.expect("set by the transaction"))
    }

    /// SetPrincipalLabels replaces the node labels a principal's apps may
    /// require.
    pub async fn set_principal_labels(
        &self,
        kind: &str,
        name: &str,
        labels: &BTreeMap<String, Vec<String>>,
        actor: &str,
    ) -> Result<Principal> {
        check_labels(labels)?;
        self.update_principal(
            kind,
            name,
            actor,
            "principal.update",
            Change::Labels(labels),
        )
        .await
    }

    /// Assign gives a principal a role.
    pub async fn assign(
        &self,
        kind: &str,
        name: &str,
        g: &Grant,
        actor: &str,
    ) -> Result<Principal> {
        self.update_principal(kind, name, actor, "assignment.create", Change::Assign(g))
            .await
    }

    /// Unassign takes a role back; ErrNotFound unless the principal holds it.
    pub async fn unassign(
        &self,
        kind: &str,
        name: &str,
        g: &Grant,
        actor: &str,
    ) -> Result<Principal> {
        self.update_principal(kind, name, actor, "assignment.delete", Change::Unassign(g))
            .await
    }

    /// DeletePrincipal deletes a service, or marks a user deleted.
    pub async fn delete_principal(&self, kind: &str, name: &str, actor: &str) -> Result<()> {
        let key = principal_key(kind, name)?;
        let now = self.now();
        tx!(self, |t| {
            let r = t.get::<PrincipalRec>(&key).await?;
            if kind == KIND_SERVICE {
                if r.is_none() {
                    return Err(not_found!("service {name}"));
                }
                t.delete(&key);
            } else {
                let mut r = r.unwrap_or_else(|| PrincipalRec {
                    name: name.to_string(),
                    ..Default::default()
                });
                r.removed = true;
                r.roles.clear();
                r.labels.clear();
                t.put(&key, &r)?;
            }
            t.audit(&now, actor, &format!("{kind}.delete"), name, "")
                .await
        })
    }

    /// RecordServiceCert records a certificate issued to a service.
    pub async fn record_service_cert(
        &self,
        name: &str,
        c: &NodeCert,
        keep: &str,
        actor: &str,
    ) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            let k = format!("{PFX_SERVICES}{name}");
            let Some(mut r) = t.get::<PrincipalRec>(&k).await? else {
                return Err(not_found!("service {name}"));
            };
            let mut certs: Vec<CertRec> = r
                .certs
                .iter()
                .filter(|o| o.not_after > unix_milli(&now) && (keep.is_empty() || o.serial == keep))
                .cloned()
                .collect();
            certs.push(CertRec {
                serial: c.serial.clone(),
                not_after: unix_milli(&c.not_after),
                ..Default::default()
            });
            if certs.len() > MAX_SERVICE_CERTS {
                certs.drain(..certs.len() - MAX_SERVICE_CERTS);
            }
            r.certs = certs;
            t.put(&k, &r)?;
            t.audit(
                &now,
                actor,
                "service.certificate",
                name,
                &format!("serial={}", c.serial),
            )
            .await
        })
    }

    /// UserAccess returns what the user may do and whether a certificate
    /// of theirs that starts at not_before is accepted.
    pub async fn user_access(
        &self,
        name: &str,
        not_before: &Time,
        serial: &str,
    ) -> Result<(Principal, bool)> {
        let mut out = Principal::default();
        let mut allowed = false;
        view!(self, |t| {
            match t.get::<PrincipalRec>(&format!("{PFX_USERS}{name}")).await? {
                None => {
                    allowed = t.unrecorded_user_allowed(not_before).await?;
                    if allowed {
                        out = Principal {
                            kind: KIND_USER.to_string(),
                            name: name.to_string(),
                            roles: vec![cluster_admin()],
                            ..Default::default()
                        };
                    }
                }
                Some(r) => {
                    out = r.principal(KIND_USER, &self.now());
                    allowed = r.user_allowed(not_before, serial);
                }
            }
            Ok(())
        })?;
        Ok((out, allowed))
    }

    /// RenewedUser records that a user renewed their own certificate.
    pub async fn renewed_user(
        &self,
        name: &str,
        caller_not_before: &Time,
        caller_serial: &str,
        serial: &str,
    ) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            let k = format!("{PFX_USERS}{name}");
            match t.get::<PrincipalRec>(&k).await? {
                None => {
                    if !t.unrecorded_user_allowed(caller_not_before).await? {
                        return Err(precondition!("user:{name} is not on record"));
                    }
                    let mut r = PrincipalRec {
                        name: name.to_string(),
                        created_at: unix_milli(&now),
                        ..Default::default()
                    };
                    r.set_roles(&[cluster_admin()]);
                    t.put(&k, &r)?;
                }
                Some(r) => {
                    if !r.user_allowed(caller_not_before, caller_serial) {
                        return Err(precondition!(
                            "certificate of user:{name} was replaced or revoked"
                        ));
                    }
                }
            }
            t.audit(
                &now,
                &format!("user:{name}"),
                "user.certificate",
                name,
                &format!("serial={serial}"),
            )
            .await
        })
    }

    /// ServiceAccess returns what the service may do and whether serial is
    /// one of its valid certificates.
    pub async fn service_access(&self, name: &str, serial: &str) -> Result<(Principal, bool)> {
        let mut out = Principal::default();
        let mut allowed = false;
        view!(self, |t| {
            allowed = false;
            let Some(r) = t
                .get::<PrincipalRec>(&format!("{PFX_SERVICES}{name}"))
                .await?
            else {
                return Ok(());
            };
            out = r.principal(KIND_SERVICE, &self.now());
            allowed = out.certs.iter().any(|c| c.serial == serial);
            Ok(())
        })?;
        Ok((out, allowed))
    }
}

/// What update changes.
enum Change<'a> {
    Labels(&'a BTreeMap<String, Vec<String>>),
    Assign(&'a Grant),
    Unassign(&'a Grant),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(role: &str, space: &str) -> Grant {
        Grant {
            role: role.to_string(),
            space: space.to_string(),
        }
    }

    #[test]
    fn grants() {
        assert!(check_grant(&g(ROLE_CLUSTER_ADMIN, "")).is_ok());
        assert!(check_grant(&g(ROLE_VIEWER, "default")).is_ok());
        let e = check_grant(&g(ROLE_ADMIN, "default")).unwrap_err();
        assert_eq!(e.kind, crate::Kind::Precondition);
        assert_eq!(
            check_grant(&g("god", "")).unwrap_err().to_string(),
            "unknown role \"god\" (one of viewer, deployer, admin, space-creator, cluster-admin)"
        );
        let mut r = PrincipalRec::default();
        r.set_roles(&[
            g(ROLE_CLUSTER_ADMIN, ""),
            g(ROLE_ADMIN, "shop"),
            g(ROLE_VIEWER, ""),
            g(ROLE_VIEWER, "shop"),
            g(ROLE_VIEWER, ""),
        ]);
        let got: Vec<String> = r.roles().iter().map(ToString::to_string).collect();
        assert_eq!(
            got,
            ["viewer", "cluster-admin", "viewer in shop", "admin in shop"]
        );
    }
}

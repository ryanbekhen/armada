//! What a caller may reach (ADR 0033).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use armada_pki::{Identity, KIND_SERVER};
use armada_spec::validate::{DEFAULT_SPACE, RESERVED_LABEL_PREFIX, split_app_id};
use armada_store::{
    Grant, Principal, ROLE_ADMIN, ROLE_CLUSTER_ADMIN, ROLE_DEPLOYER, ROLE_SPACE_CREATOR,
    ROLE_VIEWER,
};
use tonic::{Code, Status};

/// What an AdminService method asks of a caller that is not cluster-admin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Need {
    /// The zero value: methods missing from [`method_needs`] are for
    /// cluster-admin only, including any added later.
    ClusterAdmin = 0,
    View = 1,
    Deploy = 2,
    Admin = 3,
    CreateSpaces = 4,
    /// Any principal, acting on its own certificate.
    SelfOnly = 5,
}

pub const ADMIN_SERVICE: &str = "/armada.v1.AdminService/";

/// Every method a role other than cluster-admin may call.
pub fn method_needs() -> &'static BTreeMap<String, Need> {
    static M: OnceLock<BTreeMap<String, Need>> = OnceLock::new();
    M.get_or_init(|| {
        use Need::*;
        let list: &[(&str, Need)] = &[
            ("Status", View),
            ("ListApps", View),
            ("GetAppSpec", View),
            ("ListRevisions", View),
            ("ListSecrets", View),
            ("ListSpaceSecrets", View),
            ("ListVolumes", View),
            ("ListDomains", View),
            ("ListJobs", View),
            ("ListJobRuns", View),
            ("ListSpaces", View),
            ("Logs", View),
            ("Top", View),
            ("Events", View),
            ("Deploy", Deploy),
            ("Rollback", Deploy),
            ("RestartApp", Deploy),
            ("SetTraffic", Deploy),
            ("SetSecret", Deploy),
            ("DeleteSecret", Deploy),
            ("RunJob", Deploy),
            ("CancelJob", Deploy),
            ("VerifyDomain", Deploy),
            ("Exec", Admin),
            ("BackupVolume", Admin),
            ("RestoreVolume", Admin),
            ("RemoveVolume", Admin),
            ("ListVolumeSnapshots", View),
            ("CreateVolumeSnapshot", Admin),
            ("RestoreVolumeSnapshot", Admin),
            ("RemoveApp", Admin),
            ("DeleteJob", Admin),
            ("DeleteSpace", Admin),
            ("CreateSpace", CreateSpaces),
            ("RenewOwnCertificate", SelfOnly),
        ];
        list.iter()
            .map(|(m, n)| (format!("{ADMIN_SERVICE}{m}"), *n))
            .collect()
    })
}

/// The space level a role gives.
pub fn role_level(role: &str) -> Option<Need> {
    match role {
        ROLE_VIEWER => Some(Need::View),
        ROLE_DEPLOYER => Some(Need::Deploy),
        ROLE_ADMIN => Some(Need::Admin),
        _ => None,
    }
}

/// What the caller of an AdminService method may reach.
#[derive(Clone, Debug)]
pub struct Access {
    /// The caller: a principal, or the server itself.
    pub id: Identity,
    /// The principal's roles; none for the server.
    pub p: Option<Principal>,
    /// What the method being called asks for.
    pub need: Need,
}

impl Access {
    /// The access of a caller that is not a principal (a node).
    pub fn of(id: Identity) -> Access {
        Access {
            id,
            p: None,
            need: Need::ClusterAdmin,
        }
    }

    /// Whether the caller has cluster-admin, or is the server itself.
    pub fn admin(&self) -> bool {
        if self.id.kind == KIND_SERVER && self.p.is_none() {
            return true;
        }
        self.p.as_ref().is_some_and(|p| {
            p.has(&Grant {
                role: ROLE_CLUSTER_ADMIN.to_string(),
                space: String::new(),
            })
        })
    }

    /// Whether the caller may create spaces.
    pub fn creates(&self) -> bool {
        self.admin()
            || self.p.as_ref().is_some_and(|p| {
                p.has(&Grant {
                    role: ROLE_SPACE_CREATOR.to_string(),
                    space: String::new(),
                })
            })
    }

    /// The most the caller's roles give in space.
    pub fn level(&self, space: &str) -> Need {
        if self.admin() {
            return Need::Admin;
        }
        let Some(p) = &self.p else {
            return Need::ClusterAdmin;
        };
        let mut best = Need::ClusterAdmin;
        for g in &p.roles {
            if let Some(l) = role_level(&g.role)
                && (g.space == space || (g.space.is_empty() && g.role == ROLE_VIEWER))
                && l > best
            {
                best = l;
            }
        }
        best
    }

    /// Whether the caller's roles give anything a method of need could use.
    pub fn reaches(&self, n: Need) -> bool {
        match n {
            Need::SelfOnly => true,
            Need::CreateSpaces => self.creates(),
            Need::View | Need::Deploy | Need::Admin => self.p.as_ref().is_some_and(|p| {
                p.roles
                    .iter()
                    .any(|g| role_level(&g.role).is_some_and(|l| l >= n))
            }),
            Need::ClusterAdmin => false,
        }
    }

    /// The space level the method being called asks for.
    pub fn required(&self) -> Need {
        if self.need >= Need::View && self.need <= Need::Admin {
            self.need
        } else {
            Need::Admin
        }
    }

    pub fn allows(&self, space: &str) -> bool {
        let space = if space.is_empty() {
            DEFAULT_SPACE
        } else {
            space
        };
        self.level(space) >= self.required()
    }

    /// Whether the caller may reach the app (or job) with ID id at the
    /// level of the method.
    pub fn sees(&self, id: &str) -> bool {
        if self.admin() {
            return true;
        }
        split_app_id(id).is_some_and(|(p, _)| self.allows(&p))
    }

    /// PermissionDenied unless the caller may act on the app with ID id.
    pub fn app(&self, id: &str) -> Result<(), Status> {
        if self.sees(id) {
            return Ok(());
        }
        Err(Status::new(
            Code::PermissionDenied,
            format!("{} may not {} {id}", self.id, self.verb()),
        ))
    }

    /// PermissionDenied unless the caller may act in space.
    pub fn space(&self, p: &str) -> Result<(), Status> {
        if self.admin() || self.allows(p) {
            return Ok(());
        }
        let p = if p.is_empty() { DEFAULT_SPACE } else { p };
        Err(Status::new(
            Code::PermissionDenied,
            format!("{} may not {} space {p}", self.id, self.verb()),
        ))
    }

    pub fn verb(&self) -> &'static str {
        match self.required() {
            Need::View => "see",
            Need::Deploy => "deploy to",
            _ => "manage",
        }
    }

    /// PermissionDenied if a spec requires node labels its caller may not
    /// name.
    pub fn placement(&self, sp: &armada_spec::App) -> Result<(), Status> {
        let Some(pl) = &sp.placement else {
            return Ok(());
        };
        if self.admin() {
            return Ok(());
        }
        let Some(p) = &self.p else {
            return Err(Status::new(Code::PermissionDenied, "permission denied"));
        };
        // The labels are checked in sorted order, so the refusal names
        // the first key that fails.
        for (k, vs) in &pl.require {
            if k.starts_with(RESERVED_LABEL_PREFIX) {
                continue;
            }
            let allowed = p.labels.get(k);
            for v in vs.iter().flatten() {
                if !allowed.is_some_and(|a| a.contains(v)) {
                    return Err(Status::new(
                        Code::PermissionDenied,
                        format!("{} may not require node label {k}={v}", self.id),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn viewer(space: &str) -> Access {
        Access {
            id: Identity::new("user", "v"),
            p: Some(Principal {
                kind: "user".into(),
                name: "v".into(),
                roles: vec![Grant {
                    role: ROLE_VIEWER.into(),
                    space: space.into(),
                }],
                ..Default::default()
            }),
            need: Need::View,
        }
    }

    #[test]
    fn levels() {
        let a = viewer("team");
        assert!(a.sees("web.team"));
        assert!(!a.sees("web"));
        let cluster = viewer("");
        assert!(cluster.sees("web"));
        assert!(cluster.sees("web.team"));
        assert_eq!(
            a.app("web").unwrap_err().message(),
            "user:v may not see web"
        );
        let mut d = viewer("team");
        d.need = Need::Deploy;
        assert!(!d.allows("team"));
        assert_eq!(
            d.space("team").unwrap_err().message(),
            "user:v may not deploy to space team"
        );
        assert!(!a.admin());
        assert!(Access::of(Identity::new(KIND_SERVER, "self")).admin());
    }
}

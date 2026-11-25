//! Access control (ADR 0033; Go's rbac.go): users and services and the
//! roles they hold. Only cluster-admin calls these methods, except
//! RenewOwnCertificate.

use std::collections::BTreeMap;
use std::time::Instant;

use armada_pki::KIND_SERVICE;
use armada_proto::armada::v1::*;
use armada_store::{Grant, KIND_USER, Kind, ROLE_CLUSTER_ADMIN};
use tonic::{Code, Status};

use crate::access::{ADMIN_SERVICE, Need, method_needs, role_level};
use crate::events::timestamp;
use crate::grpc::{Auth, cert_time};
use crate::{Server, store_err};

/// Validates a principal's kind and name: users are named like
/// certificates, services like apps.
fn check_name(kind: &str, name: &str) -> Result<(), Status> {
    match kind {
        KIND_USER => {
            if !armada_pki::valid_name(name) {
                return Err(Status::new(
                    Code::InvalidArgument,
                    format!(
                        "invalid user name {}: letters, digits, '.', '_', '-', at most 63",
                        armada_spec::go::quote(name)
                    ),
                ));
            }
        }
        armada_store::KIND_SERVICE => {
            if !armada_spec::validate::valid_name(name) {
                return Err(Status::new(
                    Code::InvalidArgument,
                    format!(
                        "invalid service name {}: lowercase letters, digits, and single hyphens",
                        armada_spec::go::quote(name)
                    ),
                ));
            }
        }
        _ => {
            return Err(Status::new(
                Code::InvalidArgument,
                format!(
                    "unknown kind {}: user or service",
                    armada_spec::go::quote(kind)
                ),
            ));
        }
    }
    Ok(())
}

/// Refuses a change a caller would make to itself.
fn not_self(a: &Auth, kind: &str, name: &str, what: &str) -> Result<(), Status> {
    if a.id.kind == kind && a.id.name == name {
        return Err(Status::new(
            Code::InvalidArgument,
            format!("you cannot {what} yourself; another cluster-admin can"),
        ));
    }
    Ok(())
}

fn check_grant(g: &Grant) -> Result<(), Status> {
    armada_store::check_grant(g).map_err(|e| {
        if e.kind == Kind::Precondition {
            Status::new(Code::FailedPrecondition, e.msg)
        } else {
            Status::new(Code::InvalidArgument, e.msg)
        }
    })
}

fn grants_from(roles: &[RoleAssignment]) -> Result<Vec<Grant>, Status> {
    roles
        .iter()
        .map(|r| {
            let g = Grant {
                role: r.role.clone(),
                space: r.space.clone(),
            };
            check_grant(&g).map(|_| g)
        })
        .collect()
}

fn labels_from(labels: &[LabelAllowance]) -> Result<BTreeMap<String, Vec<String>>, Status> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for l in labels {
        out.entry(l.key.clone())
            .or_default()
            .extend(l.values.iter().cloned());
    }
    armada_store::check_labels(&out).map_err(|e| Status::new(Code::InvalidArgument, e.msg))?;
    Ok(out)
}

const ROLE_INFO: [(&str, bool, bool, &str); 5] = [
    (
        armada_store::ROLE_VIEWER,
        true,
        true,
        "See apps, jobs, revisions, specs, secret names, domains, volumes, logs, usage, and events",
    ),
    (
        armada_store::ROLE_DEPLOYER,
        false,
        true,
        "What a viewer may, and deploy, scale, roll back, split traffic, set secrets, run jobs, verify domains",
    ),
    (
        armada_store::ROLE_ADMIN,
        false,
        true,
        "What a deployer may, and exec, back up, restore, and delete volumes, delete apps and jobs",
    ),
    (
        armada_store::ROLE_SPACE_CREATOR,
        true,
        false,
        "Create spaces (becoming admin of each), and delete empty ones it is admin of",
    ),
    (
        ROLE_CLUSTER_ADMIN,
        true,
        false,
        "Everything: nodes, servers, cluster settings, join tokens, metrics credentials, and access control",
    ),
];

/// Whether role alone allows a method of need.
fn role_allows(role: &str, n: Need) -> bool {
    match n {
        Need::SelfOnly => true,
        Need::CreateSpaces => role == armada_store::ROLE_SPACE_CREATOR,
        Need::View | Need::Deploy | Need::Admin => role_level(role).is_some_and(|l| l >= n),
        Need::ClusterAdmin => false,
    }
}

pub(crate) fn principal_info(p: &armada_store::Principal) -> Principal {
    let mut out = Principal {
        kind: p.kind.clone(),
        name: p.name.clone(),
        created_by: p.created_by.clone(),
        removed: p.removed,
        certificates: p.certs.len() as i32,
        ..Default::default()
    };
    if !p.created_at.is_zero() {
        out.created_at = Some(timestamp(&p.created_at));
    }
    for g in &p.roles {
        out.roles.push(RoleAssignment {
            role: g.role.clone(),
            space: g.space.clone(),
        });
    }
    let mut latest: Option<&armada_spec::gotime::Time> = None;
    for c in &p.certs {
        if latest.is_none_or(|l| c.not_after.after(l)) {
            latest = Some(&c.not_after);
        }
    }
    out.cert_expires_at = latest.map(timestamp);
    for (k, v) in &p.labels {
        out.labels.push(LabelAllowance {
            key: k.clone(),
            values: v.clone(),
        });
    }
    out
}

impl Server {
    fn cert_response(&self, c: &armada_pki::NodeCert) -> IssueMetricsCertificateResponse {
        IssueMetricsCertificateResponse {
            cert: c.pem.clone(),
            ca_cert: self
                .0
                .ca
                .as_ref()
                .map(|ca| ca.cert_pem.clone())
                .unwrap_or_default(),
            expires_at: Some(timestamp(&cert_time(c.not_after))),
        }
    }

    fn signer(&self) -> Result<std::sync::Arc<armada_pki::Ca>, Status> {
        self.0.ca.clone().ok_or_else(|| {
            Status::new(
                Code::FailedPrecondition,
                "this server cannot issue certificates",
            )
        })
    }

    /// CreateUser records a user with their first roles and signs a
    /// certificate for the key in the CSR.
    pub(crate) async fn create_user(
        &self,
        a: &Auth,
        req: CreateUserRequest,
    ) -> Result<IssueMetricsCertificateResponse, Status> {
        check_name(KIND_USER, &req.name)?;
        not_self(a, KIND_USER, &req.name, "create")?;
        let roles = grants_from(&req.roles)?;
        let labels = labels_from(&req.labels)?;
        let ca = self.signer()?;
        let cert = ca
            .sign_user_csr(&req.csr, &req.name)
            .map_err(|e| Status::new(Code::InvalidArgument, format!("sign certificate: {e}")))?;
        let p = self
            .store()
            .create_user(
                &armada_store::Principal {
                    name: req.name.clone(),
                    since: cert_time(cert.not_before),
                    since_serial: cert.serial.clone(),
                    roles,
                    labels,
                    ..Default::default()
                },
                &a.actor(),
            )
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "created user",
            &[
                ("name", req.name.clone()),
                ("roles", p.roles.len().to_string()),
                ("by", a.actor()),
                ("serial", cert.serial.clone()),
            ],
        );
        Ok(self.cert_response(&cert))
    }

    /// IssueUserCertificate gives a user a new certificate; the ones issued
    /// earlier stop working.
    pub(crate) async fn issue_user_certificate(
        &self,
        a: &Auth,
        req: IssuePrincipalCertificateRequest,
    ) -> Result<IssueMetricsCertificateResponse, Status> {
        check_name(KIND_USER, &req.name)?;
        if not_self(a, KIND_USER, &req.name, "replace the certificate of").is_err() {
            return Err(Status::new(
                Code::InvalidArgument,
                "renew your own certificate with `armada user renew`",
            ));
        }
        self.store()
            .get_principal(KIND_USER, &req.name)
            .await
            .map_err(|e| store_err(&e))?;
        let ca = self.signer()?;
        let cert = ca
            .sign_user_csr(&req.csr, &req.name)
            .map_err(|e| Status::new(Code::InvalidArgument, format!("sign certificate: {e}")))?;
        self.store()
            .set_user_since(
                &req.name,
                &cert_time(cert.not_before),
                &cert.serial,
                &a.actor(),
            )
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "issued user certificate",
            &[
                ("name", req.name.clone()),
                ("by", a.actor()),
                ("serial", cert.serial.clone()),
            ],
        );
        Ok(self.cert_response(&cert))
    }

    /// CreateService records a service with its first roles.
    pub(crate) async fn create_service(
        &self,
        a: &Auth,
        req: CreateServiceRequest,
    ) -> Result<Principal, Status> {
        check_name(armada_store::KIND_SERVICE, &req.name)?;
        let roles = grants_from(&req.roles)?;
        let labels = labels_from(&req.labels)?;
        let p = self
            .store()
            .create_service(
                &armada_store::Principal {
                    name: req.name.clone(),
                    roles,
                    labels,
                    ..Default::default()
                },
                &a.actor(),
            )
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "created service",
            &[
                ("name", req.name.clone()),
                ("roles", p.roles.len().to_string()),
                ("by", a.actor()),
            ],
        );
        Ok(principal_info(&p))
    }

    /// IssueServiceCertificate signs a certificate for an existing service.
    pub(crate) async fn issue_service_certificate(
        &self,
        a: &Auth,
        req: IssuePrincipalCertificateRequest,
    ) -> Result<IssueMetricsCertificateResponse, Status> {
        check_name(armada_store::KIND_SERVICE, &req.name)?;
        self.store()
            .get_principal(armada_store::KIND_SERVICE, &req.name)
            .await
            .map_err(|e| store_err(&e))?;
        self.issue_service(a, &req.name, &req.csr, "").await
    }

    async fn issue_service(
        &self,
        a: &Auth,
        name: &str,
        csr: &[u8],
        keep: &str,
    ) -> Result<IssueMetricsCertificateResponse, Status> {
        let ca = self.signer()?;
        let cert = ca
            .sign_service_csr(csr, name)
            .map_err(|e| Status::new(Code::InvalidArgument, format!("sign certificate: {e}")))?;
        self.store()
            .record_service_cert(
                name,
                &armada_store::NodeCert {
                    serial: cert.serial.clone(),
                    not_after: cert_time(cert.not_after),
                },
                keep,
                &a.actor(),
            )
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "issued service certificate",
            &[
                ("name", name.to_string()),
                ("serial", cert.serial.clone()),
                ("by", a.actor()),
            ],
        );
        Ok(self.cert_response(&cert))
    }

    /// RenewOwnCertificate gives the calling user or service a new
    /// certificate.
    pub(crate) async fn renew_own_certificate(
        &self,
        a: &Auth,
        req: RenewOwnCertificateRequest,
    ) -> Result<IssueMetricsCertificateResponse, Status> {
        if a.acc.p.is_none() {
            return Err(Status::new(
                Code::PermissionDenied,
                "only users and services renew their own certificates",
            ));
        }
        if a.id.kind == KIND_SERVICE {
            return self
                .issue_service(a, &a.id.name, &req.csr, &a.cert.serial_string())
                .await;
        }
        if !self.0.user_renew_limit.allow(&a.id.name, Instant::now()) {
            return Err(Status::new(
                Code::ResourceExhausted,
                "too many certificate renewals; try again later",
            ));
        }
        let ca = self.signer()?;
        let cert = ca
            .sign_user_csr(&req.csr, &a.id.name)
            .map_err(|e| Status::new(Code::InvalidArgument, format!("sign certificate: {e}")))?;
        // Signed first, then checked and recorded in one transaction.
        if let Err(e) = self
            .store()
            .renewed_user(
                &a.id.name,
                &cert_time(a.cert.not_before),
                &a.cert.serial_string(),
                &cert.serial,
            )
            .await
        {
            if e.kind == Kind::Precondition {
                return Err(Status::new(
                    Code::Unauthenticated,
                    format!(
                        "certificate of user:{} was replaced or revoked, or the user is not on record",
                        a.id.name
                    ),
                ));
            }
            return Err(store_err(&e));
        }
        self.0.log.info(
            "renewed user certificate",
            &[("name", a.id.name.clone()), ("serial", cert.serial.clone())],
        );
        Ok(self.cert_response(&cert))
    }

    /// ListPrincipals lists users and services with their roles.
    pub(crate) async fn list_principals(
        &self,
        a: &Auth,
        req: ListPrincipalsRequest,
    ) -> Result<ListPrincipalsResponse, Status> {
        if !req.kind.is_empty() && req.kind != KIND_USER && req.kind != armada_store::KIND_SERVICE {
            return Err(Status::new(
                Code::InvalidArgument,
                format!(
                    "unknown kind {}: user or service",
                    armada_spec::go::quote(&req.kind)
                ),
            ));
        }
        let all = self
            .store()
            .list_principals(&req.kind)
            .await
            .map_err(|e| store_err(&e))?;
        Ok(ListPrincipalsResponse {
            principals: all.iter().map(principal_info).collect(),
            you_kind: a.id.kind.clone(),
            you: a.id.name.clone(),
        })
    }

    /// UpdatePrincipal replaces the node labels a principal's apps may
    /// require.
    pub(crate) async fn update_principal(
        &self,
        a: &Auth,
        req: UpdatePrincipalRequest,
    ) -> Result<Principal, Status> {
        check_name(&req.kind, &req.name)?;
        let labels = labels_from(&req.labels)?;
        let p = self
            .store()
            .set_principal_labels(&req.kind, &req.name, &labels, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        Ok(principal_info(&p))
    }

    /// DeletePrincipal revokes every certificate of a user or service.
    pub(crate) async fn delete_principal(
        &self,
        a: &Auth,
        req: DeletePrincipalRequest,
    ) -> Result<DeletePrincipalResponse, Status> {
        check_name(&req.kind, &req.name)?;
        not_self(a, &req.kind, &req.name, "delete")?;
        self.store()
            .delete_principal(&req.kind, &req.name, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "deleted principal",
            &[
                ("kind", req.kind.clone()),
                ("name", req.name.clone()),
                ("by", a.actor()),
            ],
        );
        Ok(DeletePrincipalResponse {})
    }

    /// CreateAssignment gives a principal a role.
    pub(crate) async fn create_assignment(
        &self,
        a: &Auth,
        req: AssignmentRequest,
    ) -> Result<Principal, Status> {
        let g = assignment(&req)?;
        let p = self
            .store()
            .assign(&req.kind, &req.name, &g, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "assigned role",
            &[
                ("kind", req.kind.clone()),
                ("name", req.name.clone()),
                ("by", a.actor()),
            ],
        );
        Ok(principal_info(&p))
    }

    /// DeleteAssignment takes a role back; a caller keeps its own
    /// cluster-admin.
    pub(crate) async fn delete_assignment(
        &self,
        a: &Auth,
        req: AssignmentRequest,
    ) -> Result<Principal, Status> {
        let g = assignment(&req)?;
        if g.role == ROLE_CLUSTER_ADMIN {
            not_self(a, &req.kind, &req.name, "take cluster-admin from")?;
        }
        let p = self
            .store()
            .unassign(&req.kind, &req.name, &g, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "unassigned role",
            &[
                ("kind", req.kind.clone()),
                ("name", req.name.clone()),
                ("by", a.actor()),
            ],
        );
        Ok(principal_info(&p))
    }

    /// ListRoles lists the built-in roles and the methods each allows.
    pub(crate) async fn list_roles(
        &self,
        _a: &Auth,
        _req: ListRolesRequest,
    ) -> Result<ListRolesResponse, Status> {
        let mut out = ListRolesResponse::default();
        for (name, cluster, space, description) in ROLE_INFO {
            let mut info = RoleInfo {
                name: name.to_string(),
                description: description.to_string(),
                cluster,
                space,
                methods: Vec::new(),
            };
            for (m, n) in method_needs() {
                if role_allows(name, *n) {
                    info.methods
                        .push(m.strip_prefix(ADMIN_SERVICE).unwrap_or(m).to_string());
                }
            }
            info.methods.sort();
            if name == ROLE_CLUSTER_ADMIN {
                info.methods = vec!["*".to_string()];
            }
            out.roles.push(info);
        }
        Ok(out)
    }
}

fn assignment(req: &AssignmentRequest) -> Result<Grant, Status> {
    check_name(&req.kind, &req.name)?;
    let r = req.role.clone().unwrap_or_default();
    let g = Grant {
        role: r.role,
        space: r.space,
    };
    check_grant(&g)?;
    Ok(g)
}

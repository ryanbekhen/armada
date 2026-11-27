//! Node administration and node certificate renewal.

use std::time::{Duration, Instant};

use armada_proto::armada::v1::server_message::Msg;
use armada_proto::armada::v1::*;
use armada_spec::validate::{check_admin_label, check_label_value, validate_name};
use tonic::{Code, Status};

use crate::events::{self, event};
use crate::grpc::Auth;
use crate::{Server, store_err};

const MAX_CSR_SIZE: usize = 4 << 10;

impl Server {
    /// RenewCertificate issues a new certificate for the calling node.
    pub(crate) async fn renew_certificate(
        &self,
        a: &Auth,
        req: RenewCertificateRequest,
    ) -> Result<RenewCertificateResponse, Status> {
        let Some(ca) = self.0.ca.clone() else {
            return Err(Status::new(
                Code::FailedPrecondition,
                "certificate renewal is disabled on this server",
            ));
        };
        if req.csr.is_empty() || req.csr.len() > MAX_CSR_SIZE {
            return Err(Status::new(
                Code::InvalidArgument,
                "missing or oversized CSR",
            ));
        }
        if !self.0.renew_limit.allow(&a.id.name, Instant::now()) {
            return Err(Status::new(
                Code::ResourceExhausted,
                "too many certificate renewals for this node; try again later",
            ));
        }
        let cert = ca
            .sign_node_csr(&req.csr, &a.id.name, self.0.node_cert_validity)
            .map_err(|e| Status::new(Code::InvalidArgument, format!("CSR: {e}")))?;
        self.store()
            .record_node_cert(
                &a.id.name,
                &armada_store::NodeCert {
                    serial: cert.serial.clone(),
                    not_after: armada_store::gojson::from_unix(cert.not_after),
                },
                &a.cert.serial_string(),
            )
            .await
            .map_err(|e| store_err(&e))?;
        self.0
            .log
            .info("node certificate renewed", &[("node", a.id.name.clone())]);
        Ok(RenewCertificateResponse { cert: cert.pem })
    }

    /// CordonNode marks a node (un)schedulable.
    pub(crate) async fn cordon_node(
        &self,
        a: &Auth,
        req: CordonNodeRequest,
    ) -> Result<CordonNodeResponse, Status> {
        self.store()
            .set_node_cordoned(&req.node, req.cordoned, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "node cordon",
            &[
                ("node", req.node.clone()),
                ("cordoned", req.cordoned.to_string()),
                ("by", a.actor()),
            ],
        );
        let reason = if req.cordoned {
            "Cordoned"
        } else {
            "Uncordoned"
        };
        self.record(event(
            events::NODE,
            &req.node,
            &req.node,
            reason,
            &format!("by {}", a.actor()),
        ))
        .await;
        self.trigger();
        Ok(CordonNodeResponse {})
    }

    /// LabelNode sets and removes a node's admin labels (ADR 0014).
    pub(crate) async fn label_node(
        &self,
        a: &Auth,
        req: LabelNodeRequest,
    ) -> Result<LabelNodeResponse, Status> {
        if req.set.is_empty() && req.remove.is_empty() {
            return Err(Status::new(
                Code::InvalidArgument,
                "no labels to set or remove",
            ));
        }
        for (k, v) in &req.set {
            check_admin_label(k, v).map_err(|e| Status::new(Code::InvalidArgument, e))?;
        }
        for k in &req.remove {
            check_admin_label(k, "x").map_err(|e| Status::new(Code::InvalidArgument, e))?;
            if req.set.contains_key(k) {
                return Err(Status::new(
                    Code::InvalidArgument,
                    format!(
                        "label {} is both set and removed",
                        armada_spec::go::quote(k)
                    ),
                ));
            }
        }
        let labels = self
            .store()
            .set_node_labels(&req.node, &req.set, &req.remove, &a.actor())
            .await
            .map_err(|e| store_err(&e))?
            .unwrap_or_default();
        self.0.log.info(
            "node labels",
            &[
                ("node", req.node.clone()),
                ("labels", labels.len().to_string()),
                ("by", a.actor()),
            ],
        );
        self.trigger();
        Ok(LabelNodeResponse { labels })
    }

    /// SetNodeRelay chooses a node as its site's relay, or drops the
    /// choice (ADR 0050).
    pub(crate) async fn set_node_relay(
        &self,
        a: &Auth,
        req: SetNodeRelayRequest,
    ) -> Result<SetNodeRelayResponse, Status> {
        validate_name(&req.node)
            .map_err(|e| Status::new(Code::InvalidArgument, format!("node: {e}")))?;
        let replaced = self
            .store()
            .set_node_relay(&req.node, !req.clear, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        let (reason, mut what) = if req.clear {
            (
                "RelayCleared",
                format!(
                    "its site's relay is picked by the leader again, by {}",
                    a.actor()
                ),
            )
        } else {
            (
                "RelayChosen",
                format!("chosen as its site's relay by {}", a.actor()),
            )
        };
        if !req.clear && !replaced.is_empty() {
            what.push_str(&format!(", in place of node {}", replaced.join(", ")));
        }
        self.0.log.info(
            "node relay",
            &[
                ("node", req.node.clone()),
                ("clear", req.clear.to_string()),
                ("by", a.actor()),
            ],
        );
        self.record(event(events::NODE, &req.node, &req.node, reason, &what))
            .await;
        for id in &replaced {
            self.record(event(
                events::NODE,
                id,
                id,
                "RelayCleared",
                &format!(
                    "its site's relay is now node {}, chosen by {}",
                    req.node,
                    a.actor()
                ),
            ))
            .await;
        }
        self.trigger();
        Ok(SetNodeRelayResponse { replaced })
    }

    /// RotateNodeKey asks a connected node's agent for a new WireGuard key
    /// (ADR 0025).
    pub(crate) async fn rotate_node_key(
        &self,
        a: &Auth,
        req: RotateNodeKeyRequest,
    ) -> Result<RotateNodeKeyResponse, Status> {
        validate_name(&req.node)
            .map_err(|e| Status::new(Code::InvalidArgument, format!("node: {e}")))?;
        self.store()
            .get_node(&req.node)
            .await
            .map_err(|e| store_err(&e))?;
        let Some(sess) = self.session(&req.node) else {
            return Err(Status::new(
                Code::Unavailable,
                format!("node {} is not connected", req.node),
            ));
        };
        if !sess.caps.key_rotation {
            return Err(Status::new(
                Code::FailedPrecondition,
                format!(
                    "node {} has no network key, or its agent cannot replace it: upgrade it, or remove network.key on it and restart its service",
                    req.node
                ),
            ));
        }
        let m = ServerMessage {
            msg: Some(Msg::RotateNetworkKey(RotateNetworkKey {})),
        };
        if !sess.offer(m, Duration::from_secs(5)).await {
            return Err(Status::new(
                Code::Unavailable,
                format!("node {} did not accept the request", req.node),
            ));
        }
        if let Err(e) = self
            .store()
            .record_audit(&a.actor(), "node.rotate-key", &req.node, "")
            .await
        {
            self.0.log.warn("audit", &[("err", e.to_string())]);
        }
        self.0.log.info(
            "network key rotation",
            &[("node", req.node.clone()), ("by", a.actor())],
        );
        Ok(RotateNodeKeyResponse {})
    }

    /// SetNodeSite moves a node to another site (ADR 0050).
    pub(crate) async fn set_node_site(
        &self,
        a: &Auth,
        req: SetNodeSiteRequest,
    ) -> Result<SetNodeSiteResponse, Status> {
        if !req.site.is_empty() {
            check_label_value(&req.site)
                .map_err(|e| Status::new(Code::InvalidArgument, format!("site: {e}")))?;
        }
        self.store()
            .set_node_site(&req.node, &req.site, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "node site",
            &[
                ("node", req.node.clone()),
                ("site", req.site.clone()),
                ("by", a.actor()),
            ],
        );
        let site = if req.site.is_empty() {
            "(first site)"
        } else {
            req.site.as_str()
        };
        self.record(event(
            events::NODE,
            &req.node,
            &req.node,
            "SiteChanged",
            &format!("site {site} by {}", a.actor()),
        ))
        .await;
        self.trigger();
        Ok(SetNodeSiteResponse {})
    }

    /// RestrictNode makes a node restricted or open.
    pub(crate) async fn restrict_node(
        &self,
        a: &Auth,
        req: RestrictNodeRequest,
    ) -> Result<RestrictNodeResponse, Status> {
        self.store()
            .set_node_restricted(&req.node, req.restricted, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "node restriction",
            &[
                ("node", req.node.clone()),
                ("restricted", req.restricted.to_string()),
                ("by", a.actor()),
            ],
        );
        self.trigger();
        Ok(RestrictNodeResponse {})
    }

    /// RemoveNode deletes a node, revokes its certificates, and disconnects
    /// its agent.
    pub(crate) async fn remove_node(
        &self,
        a: &Auth,
        req: RemoveNodeRequest,
    ) -> Result<RemoveNodeResponse, Status> {
        self.store()
            .remove_node(&req.node, req.force, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        let sess = self
            .0
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&req.node);
        if let Some(sess) = sess {
            // Its last assignment runs nothing, so the agent stops the
            // replicas it ran before the session ends.
            sess.end_with(Assignment::default());
            sess.close();
        }
        self.0.log.info(
            "node removed",
            &[
                ("node", req.node.clone()),
                ("force", req.force.to_string()),
                ("by", a.actor()),
            ],
        );
        self.record(event(
            events::NODE,
            &req.node,
            &req.node,
            "Removed",
            &format!("by {}", a.actor()),
        ))
        .await;
        self.trigger();
        Ok(RemoveNodeResponse {})
    }
}

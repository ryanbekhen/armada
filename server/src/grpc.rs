//! The API's plumbing: one service that authorizes every call (Go's
//! unaryAuth and streamAuth with authorize) and hands it to AdminService
//! or AgentService, adding the control plane's addresses to every
//! AdminService answer (serversHeader).

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use armada_pki::{Certificate, Identity, KIND_NODE, KIND_SERVICE};
use armada_proto::armada::v1::admin_service_server::AdminServiceServer;
use armada_proto::armada::v1::agent_service_server::AgentServiceServer;
use tonic::body::Body;
use tonic::codegen::http;
use tonic::{Code, Status};

use crate::Server;
use crate::access::{ADMIN_SERVICE, Access, Need, method_needs};
use crate::conn::PeerInfo;

const AGENT_SERVICE: &str = "/armada.v1.AgentService/";
/// clientconfig.ServersHeader.
pub const SERVERS_HEADER: &str = "armada-servers";
/// endpointsFresh: how long addresses read for the header are used.
const ENDPOINTS_FRESH: Duration = Duration::from_secs(10);

/// The authenticated caller of one call, put in its request's extensions.
#[derive(Clone)]
pub struct Auth {
    pub id: Identity,
    pub acc: Access,
    pub cert: Arc<Certificate>,
}

impl Auth {
    /// Go's actor: the caller's identity as text.
    pub fn actor(&self) -> String {
        self.id.to_string()
    }
}

/// The caller of a request the dispatcher authorized.
pub fn auth<T>(req: &tonic::Request<T>) -> Result<Auth, Status> {
    req.extensions()
        .get::<Auth>()
        .cloned()
        .ok_or_else(|| Status::new(Code::Unauthenticated, "client certificate required"))
}

impl Server {
    /// Go's authorize.
    pub(crate) async fn authorize(
        &self,
        peer: Option<&PeerInfo>,
        method: &str,
    ) -> Result<Auth, Status> {
        let Some(peer) = peer else {
            return Err(Status::new(Code::Unauthenticated, "no peer"));
        };
        let Some(cert) = peer.cert.clone() else {
            return Err(Status::new(
                Code::Unauthenticated,
                "client certificate required",
            ));
        };
        let Ok(id) = cert.identity() else {
            return Err(Status::new(
                Code::Unauthenticated,
                "invalid client identity",
            ));
        };
        if let Some(pid) = id.principal() {
            if !method.starts_with(ADMIN_SERVICE) {
                return Err(Status::new(
                    Code::PermissionDenied,
                    format!("{pid} may not call {method}"),
                ));
            }
            let acc = self.method_access(&pid, &cert, method).await?;
            return Ok(Auth { id: pid, acc, cert });
        }
        if id.kind != KIND_NODE || !method.starts_with(AGENT_SERVICE) {
            return Err(Status::new(
                Code::PermissionDenied,
                format!("{id} may not call {method}"),
            ));
        }
        // Node certificates are only valid while recorded: removing a node
        // revokes them at once.
        match self
            .store()
            .node_cert_allowed(&id.name, &cert.serial_string())
            .await
        {
            Err(_) => Err(Status::new(Code::Unavailable, "check node certificate")),
            Ok(false) => Err(Status::new(
                Code::Unauthenticated,
                format!("certificate of {id} is revoked or the node was removed"),
            )),
            Ok(true) => Ok(Auth {
                acc: Access::of(id.clone()),
                id,
                cert,
            }),
        }
    }

    /// Go's methodAccess: the principal's access to method, or the error
    /// that refuses the call.
    pub(crate) async fn method_access(
        &self,
        pid: &Identity,
        cert: &Certificate,
        method: &str,
    ) -> Result<Access, Status> {
        let serial = cert.serial_string();
        let res = if pid.kind == KIND_SERVICE {
            self.store().service_access(&pid.name, &serial).await
        } else {
            self.store()
                .user_access(&pid.name, &cert_time(cert.not_before), &serial)
                .await
        };
        let (p, ok) =
            res.map_err(|_| Status::new(Code::Unavailable, "check client certificate"))?;
        if !ok {
            return Err(Status::new(
                Code::Unauthenticated,
                format!(
                    "certificate of {pid} is revoked, expired, or the {} was deleted",
                    pid.kind
                ),
            ));
        }
        let placed = method_needs().get(method).copied();
        let acc = Access {
            id: pid.clone(),
            p: Some(p),
            need: placed.unwrap_or(Need::ClusterAdmin),
        };
        if !acc.admin() {
            let Some(n) = placed else {
                return Err(Status::new(
                    Code::PermissionDenied,
                    format!("{pid} may not call {method}: it needs cluster-admin"),
                ));
            };
            if !acc.reaches(n) {
                return Err(Status::new(
                    Code::PermissionDenied,
                    format!(
                        "{pid} has no role that allows {}",
                        method.strip_prefix(ADMIN_SERVICE).unwrap_or(method)
                    ),
                ));
            }
        }
        Ok(acc)
    }

    /// Go's serversHeader: the control plane's API addresses for an
    /// AdminService answer, read again when older than ENDPOINTS_FRESH.
    async fn servers_header(&self, method: &str) -> Option<String> {
        if !method.starts_with(ADMIN_SERVICE) {
            return None;
        }
        let seen = self
            .0
            .endpoints_seen
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let fresh = seen
            .as_ref()
            .is_some_and(|(_, at)| at.elapsed() <= ENDPOINTS_FRESH);
        let addrs = if fresh {
            seen.map(|(a, _)| a)
        } else {
            match tokio::time::timeout(Duration::from_secs(2), self.endpoints()).await {
                Ok(Ok(eps)) => {
                    *self
                        .0
                        .endpoints_seen
                        .lock()
                        .unwrap_or_else(|p| p.into_inner()) =
                        Some((eps.clone(), tokio::time::Instant::now()));
                    Some(eps)
                }
                _ => seen.map(|(a, _)| a),
            }
        };
        addrs.filter(|a| !a.is_empty()).map(|a| a.join(","))
    }
}

/// A certificate time (Unix seconds) as a Time.
pub(crate) fn cert_time(secs: i64) -> armada_spec::gotime::Time {
    armada_store::gojson::from_unix(secs)
}

/// grpc-go's answer for a service, or a method of a known service, a
/// server does not serve.
pub(crate) fn unknown_service(path: &str, known: &str) -> Status {
    let p = path.trim_start_matches('/');
    let (svc, method) = p.rsplit_once('/').unwrap_or((p, ""));
    if svc == known {
        return Status::new(
            Code::Unimplemented,
            format!("unknown method {method} for service {svc}"),
        );
    }
    Status::new(Code::Unimplemented, format!("unknown service {svc}"))
}

/// The API's one service.
#[derive(Clone)]
pub struct Dispatch {
    srv: Server,
    admin: AdminServiceServer<crate::admin::Api>,
    agent: AgentServiceServer<crate::admin::Api>,
}

impl Dispatch {
    pub fn new(srv: Server) -> Dispatch {
        let api = crate::admin::Api(srv.clone());
        Dispatch {
            admin: AdminServiceServer::new(api.clone()).max_decoding_message_size(4 << 20),
            agent: AgentServiceServer::new(api).max_decoding_message_size(4 << 20),
            srv,
        }
    }
}

impl tower::Service<http::Request<Body>> for Dispatch {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<http::Response<Body>, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: http::Request<Body>) -> Self::Future {
        let srv = self.srv.clone();
        let mut admin = self.admin.clone();
        let mut agent = self.agent.clone();
        Box::pin(async move {
            let path = req.uri().path().to_string();
            // grpc-go answers a service it does not serve before any
            // interceptor runs.
            if !path.starts_with(ADMIN_SERVICE) && !path.starts_with(AGENT_SERVICE) {
                return Ok(unknown_service(&path, "").into_http());
            }
            let peer = req.extensions().get::<PeerInfo>().cloned();
            let auth = match srv.authorize(peer.as_ref(), &path).await {
                Ok(a) => a,
                Err(st) => return Ok(st.into_http()),
            };
            req.extensions_mut().insert(auth);
            let header = srv.servers_header(&path).await;
            let mut resp = if path.starts_with(ADMIN_SERVICE) {
                tower::Service::call(&mut admin, req).await
            } else if path.starts_with(AGENT_SERVICE) {
                tower::Service::call(&mut agent, req).await
            } else {
                Ok(Status::new(Code::Unimplemented, "").into_http())
            }
            .unwrap_or_else(|e: Infallible| match e {});
            if let Some(h) = header
                && let Ok(v) = http::HeaderValue::from_str(&h)
            {
                resp.headers_mut().insert(SERVERS_HEADER, v);
            }
            Ok(resp)
        })
    }
}

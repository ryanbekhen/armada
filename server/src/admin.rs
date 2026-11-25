//! The gRPC services' methods: each one this pull request ports runs the
//! server's own method with the caller the dispatcher authorized; the
//! others answer `Unimplemented` with grpc-go's text for a method a
//! server does not implement, until the pull request named in [`LATER`]
//! ports them (ADR 0055).

use std::pin::Pin;

use armada_proto::armada::v1::admin_service_server::AdminService;
use armada_proto::armada::v1::agent_service_server::AgentService;
use armada_proto::armada::v1::*;
use tonic::codegen::tokio_stream::Stream;
use tonic::{Code, Request, Response, Status};

use crate::Server;
use crate::grpc::auth;

/// The services' implementation over a server.
#[derive(Clone)]
pub struct Api(pub Server);

/// A response stream.
pub type Out<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

/// grpc-go's answer for a method a server does not implement.
fn unimplemented(method: &str) -> Status {
    Status::new(
        Code::Unimplemented,
        format!("method {method} not implemented"),
    )
}

/// The methods that answer `Unimplemented` in this pull request: the
/// service, the method, and the pull request of ADR 0055 that ports it
/// (15, the second part of watching: logs and exec).
pub const LATER: &[(&str, &str, u8)] = &[
    ("Admin", "Logs", 15),
    ("Admin", "Exec", 15),
    ("Agent", "PushLogs", 15),
    ("Agent", "ExecSession", 15),
];

#[tonic::codegen::async_trait]
impl AdminService for Api {
    async fn deploy(
        &self,
        request: Request<DeployRequest>,
    ) -> Result<Response<DeployResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .deploy(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn status(
        &self,
        request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .status(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn list_apps(
        &self,
        request: Request<ListAppsRequest>,
    ) -> Result<Response<ListAppsResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .list_apps(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn cluster_status(
        &self,
        request: Request<ClusterStatusRequest>,
    ) -> Result<Response<ClusterStatusResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .cluster_status(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn get_app_spec(
        &self,
        request: Request<GetAppSpecRequest>,
    ) -> Result<Response<GetAppSpecResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .get_app_spec(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn set_traffic(
        &self,
        request: Request<SetTrafficRequest>,
    ) -> Result<Response<SetTrafficResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .set_traffic(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn list_volumes(
        &self,
        request: Request<ListVolumesRequest>,
    ) -> Result<Response<ListVolumesResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .list_volumes(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn remove_volume(
        &self,
        request: Request<RemoveVolumeRequest>,
    ) -> Result<Response<RemoveVolumeResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .remove_volume(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    type BackupVolumeStream = Out<VolumeData>;
    async fn backup_volume(
        &self,
        request: Request<BackupVolumeRequest>,
    ) -> Result<Response<Self::BackupVolumeStream>, Status> {
        let a = auth(&request)?;
        self.0.backup_volume(&a, request.into_inner()).await
    }
    async fn restore_volume(
        &self,
        request: Request<tonic::Streaming<RestoreVolumeMessage>>,
    ) -> Result<Response<RestoreVolumeResponse>, Status> {
        self.0.restore_volume(request).await.map(Response::new)
    }
    async fn list_volume_snapshots(
        &self,
        request: Request<ListVolumeSnapshotsRequest>,
    ) -> Result<Response<ListVolumeSnapshotsResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .list_volume_snapshots(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn create_volume_snapshot(
        &self,
        request: Request<CreateVolumeSnapshotRequest>,
    ) -> Result<Response<CreateVolumeSnapshotResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .create_volume_snapshot(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn restore_volume_snapshot(
        &self,
        request: Request<RestoreVolumeSnapshotRequest>,
    ) -> Result<Response<RestoreVolumeResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .restore_volume_snapshot(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    type LogsStream = Out<LogEntry>;
    async fn logs(
        &self,
        request: Request<LogsRequest>,
    ) -> Result<Response<Self::LogsStream>, Status> {
        let _ = request;
        Err(unimplemented("Logs"))
    }
    async fn get_cluster_config(
        &self,
        request: Request<GetClusterConfigRequest>,
    ) -> Result<Response<ClusterConfig>, Status> {
        let a = auth(&request)?;
        self.0
            .get_cluster_config(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn set_cluster_config(
        &self,
        request: Request<SetClusterConfigRequest>,
    ) -> Result<Response<ClusterConfig>, Status> {
        let a = auth(&request)?;
        self.0
            .set_cluster_config(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn list_domains(
        &self,
        request: Request<ListDomainsRequest>,
    ) -> Result<Response<ListDomainsResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .list_domains(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn verify_domain(
        &self,
        request: Request<VerifyDomainRequest>,
    ) -> Result<Response<Domain>, Status> {
        let a = auth(&request)?;
        self.0
            .verify_domain(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn list_revisions(
        &self,
        request: Request<ListRevisionsRequest>,
    ) -> Result<Response<ListRevisionsResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .list_revisions(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn rollback(
        &self,
        request: Request<RollbackRequest>,
    ) -> Result<Response<RollbackResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .rollback(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn restart_app(
        &self,
        request: Request<RestartAppRequest>,
    ) -> Result<Response<RestartAppResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .restart_app(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn set_secret(
        &self,
        request: Request<SetSecretRequest>,
    ) -> Result<Response<SetSecretResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .set_secret(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn list_secrets(
        &self,
        request: Request<ListSecretsRequest>,
    ) -> Result<Response<ListSecretsResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .list_secrets(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn delete_secret(
        &self,
        request: Request<DeleteSecretRequest>,
    ) -> Result<Response<DeleteSecretResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .delete_secret(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn list_space_secrets(
        &self,
        request: Request<ListSpaceSecretsRequest>,
    ) -> Result<Response<ListSpaceSecretsResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .list_space_secrets(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn create_join_token(
        &self,
        request: Request<CreateJoinTokenRequest>,
    ) -> Result<Response<CreateJoinTokenResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .create_join_token(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn cordon_node(
        &self,
        request: Request<CordonNodeRequest>,
    ) -> Result<Response<CordonNodeResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .cordon_node(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn label_node(
        &self,
        request: Request<LabelNodeRequest>,
    ) -> Result<Response<LabelNodeResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .label_node(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn restrict_node(
        &self,
        request: Request<RestrictNodeRequest>,
    ) -> Result<Response<RestrictNodeResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .restrict_node(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn set_node_site(
        &self,
        request: Request<SetNodeSiteRequest>,
    ) -> Result<Response<SetNodeSiteResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .set_node_site(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn set_node_relay(
        &self,
        request: Request<SetNodeRelayRequest>,
    ) -> Result<Response<SetNodeRelayResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .set_node_relay(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn rotate_node_key(
        &self,
        request: Request<RotateNodeKeyRequest>,
    ) -> Result<Response<RotateNodeKeyResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .rotate_node_key(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn remove_node(
        &self,
        request: Request<RemoveNodeRequest>,
    ) -> Result<Response<RemoveNodeResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .remove_node(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn list_servers(
        &self,
        request: Request<ListServersRequest>,
    ) -> Result<Response<ListServersResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .list_servers(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn remove_server(
        &self,
        request: Request<RemoveServerRequest>,
    ) -> Result<Response<RemoveServerResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .remove_server(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn create_space(
        &self,
        request: Request<CreateSpaceRequest>,
    ) -> Result<Response<SpaceInfo>, Status> {
        let a = auth(&request)?;
        self.0
            .create_space(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn list_spaces(
        &self,
        request: Request<ListSpacesRequest>,
    ) -> Result<Response<ListSpacesResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .list_spaces(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn delete_space(
        &self,
        request: Request<DeleteSpaceRequest>,
    ) -> Result<Response<DeleteSpaceResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .delete_space(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn update_space(
        &self,
        request: Request<UpdateSpaceRequest>,
    ) -> Result<Response<SpaceInfo>, Status> {
        let a = auth(&request)?;
        self.0
            .update_space(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn create_user(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<IssueMetricsCertificateResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .create_user(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn issue_user_certificate(
        &self,
        request: Request<IssuePrincipalCertificateRequest>,
    ) -> Result<Response<IssueMetricsCertificateResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .issue_user_certificate(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn create_service(
        &self,
        request: Request<CreateServiceRequest>,
    ) -> Result<Response<Principal>, Status> {
        let a = auth(&request)?;
        self.0
            .create_service(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn issue_service_certificate(
        &self,
        request: Request<IssuePrincipalCertificateRequest>,
    ) -> Result<Response<IssueMetricsCertificateResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .issue_service_certificate(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn list_principals(
        &self,
        request: Request<ListPrincipalsRequest>,
    ) -> Result<Response<ListPrincipalsResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .list_principals(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn update_principal(
        &self,
        request: Request<UpdatePrincipalRequest>,
    ) -> Result<Response<Principal>, Status> {
        let a = auth(&request)?;
        self.0
            .update_principal(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn delete_principal(
        &self,
        request: Request<DeletePrincipalRequest>,
    ) -> Result<Response<DeletePrincipalResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .delete_principal(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn create_assignment(
        &self,
        request: Request<AssignmentRequest>,
    ) -> Result<Response<Principal>, Status> {
        let a = auth(&request)?;
        self.0
            .create_assignment(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn delete_assignment(
        &self,
        request: Request<AssignmentRequest>,
    ) -> Result<Response<Principal>, Status> {
        let a = auth(&request)?;
        self.0
            .delete_assignment(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn list_roles(
        &self,
        request: Request<ListRolesRequest>,
    ) -> Result<Response<ListRolesResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .list_roles(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn renew_own_certificate(
        &self,
        request: Request<RenewOwnCertificateRequest>,
    ) -> Result<Response<IssueMetricsCertificateResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .renew_own_certificate(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    type ExecStream = Out<ExecServerMessage>;
    async fn exec(
        &self,
        request: Request<tonic::Streaming<ExecClientMessage>>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        let _ = request;
        Err(unimplemented("Exec"))
    }
    async fn top(&self, request: Request<TopRequest>) -> Result<Response<TopResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .top(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn issue_metrics_certificate(
        &self,
        request: Request<IssueMetricsCertificateRequest>,
    ) -> Result<Response<IssueMetricsCertificateResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .issue_metrics_certificate(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn list_metrics_credentials(
        &self,
        request: Request<ListMetricsCredentialsRequest>,
    ) -> Result<Response<ListMetricsCredentialsResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .list_metrics_credentials(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn revoke_metrics_credentials(
        &self,
        request: Request<RevokeMetricsCredentialsRequest>,
    ) -> Result<Response<RevokeMetricsCredentialsResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .revoke_metrics_credentials(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    type EventsStream = Out<EventInfo>;
    async fn events(
        &self,
        request: Request<EventsRequest>,
    ) -> Result<Response<Self::EventsStream>, Status> {
        self.0.events(request).await
    }
    async fn create_alert_channel(
        &self,
        request: Request<AlertChannelRequest>,
    ) -> Result<Response<AlertChannel>, Status> {
        let a = auth(&request)?;
        self.0
            .create_alert_channel(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn update_alert_channel(
        &self,
        request: Request<AlertChannelRequest>,
    ) -> Result<Response<AlertChannel>, Status> {
        let a = auth(&request)?;
        self.0
            .update_alert_channel(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn list_alert_channels(
        &self,
        request: Request<ListAlertChannelsRequest>,
    ) -> Result<Response<ListAlertChannelsResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .list_alert_channels(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn delete_alert_channel(
        &self,
        request: Request<DeleteAlertChannelRequest>,
    ) -> Result<Response<DeleteAlertChannelResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .delete_alert_channel(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn test_alert_channel(
        &self,
        request: Request<TestAlertChannelRequest>,
    ) -> Result<Response<TestAlertChannelResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .test_alert_channel(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn run_job(
        &self,
        request: Request<RunJobRequest>,
    ) -> Result<Response<RunJobResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .run_job(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn list_jobs(
        &self,
        request: Request<ListJobsRequest>,
    ) -> Result<Response<ListJobsResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .list_jobs(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn list_job_runs(
        &self,
        request: Request<ListJobRunsRequest>,
    ) -> Result<Response<ListJobRunsResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .list_job_runs(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn cancel_job(
        &self,
        request: Request<CancelJobRequest>,
    ) -> Result<Response<CancelJobResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .cancel_job(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn delete_job(
        &self,
        request: Request<DeleteJobRequest>,
    ) -> Result<Response<DeleteJobResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .delete_job(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn remove_app(
        &self,
        request: Request<RemoveAppRequest>,
    ) -> Result<Response<RemoveAppResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .remove_app(&a, request.into_inner())
            .await
            .map(Response::new)
    }
}

#[tonic::codegen::async_trait]
impl AgentService for Api {
    type ConnectStream = Out<ServerMessage>;
    async fn connect(
        &self,
        request: Request<tonic::Streaming<AgentMessage>>,
    ) -> Result<Response<Self::ConnectStream>, Status> {
        self.0.connect(request).await
    }
    async fn push_logs(
        &self,
        request: Request<tonic::Streaming<LogPush>>,
    ) -> Result<Response<PushLogsResponse>, Status> {
        let _ = request;
        Err(unimplemented("PushLogs"))
    }
    type ExecSessionStream = Out<ExecInput>;
    async fn exec_session(
        &self,
        request: Request<tonic::Streaming<ExecSessionOutput>>,
    ) -> Result<Response<Self::ExecSessionStream>, Status> {
        let _ = request;
        Err(unimplemented("ExecSession"))
    }
    type VolumeSessionStream = Out<VolumeData>;
    async fn volume_session(
        &self,
        request: Request<tonic::Streaming<VolumeData>>,
    ) -> Result<Response<Self::VolumeSessionStream>, Status> {
        self.0.volume_session(request).await
    }
    async fn renew_certificate(
        &self,
        request: Request<RenewCertificateRequest>,
    ) -> Result<Response<RenewCertificateResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .renew_certificate(&a, request.into_inner())
            .await
            .map(Response::new)
    }
    async fn get_certificates(
        &self,
        request: Request<GetCertificatesRequest>,
    ) -> Result<Response<GetCertificatesResponse>, Status> {
        let a = auth(&request)?;
        self.0
            .get_certificates(&a, request.into_inner())
            .await
            .map(Response::new)
    }
}

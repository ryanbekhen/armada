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
/// (10 jobs, 12 volumes, 14 ingress and certificates, 15 watching).
pub const LATER: &[(&str, &str, u8)] = &[
    ("Admin", "ClusterStatus", 15),
    ("Admin", "ListVolumes", 12),
    ("Admin", "RemoveVolume", 12),
    ("Admin", "BackupVolume", 12),
    ("Admin", "RestoreVolume", 12),
    ("Admin", "ListVolumeSnapshots", 12),
    ("Admin", "CreateVolumeSnapshot", 12),
    ("Admin", "RestoreVolumeSnapshot", 12),
    ("Admin", "Logs", 15),
    ("Admin", "ListDomains", 14),
    ("Admin", "VerifyDomain", 14),
    ("Admin", "Exec", 15),
    ("Admin", "Top", 15),
    ("Admin", "IssueMetricsCertificate", 15),
    ("Admin", "ListMetricsCredentials", 15),
    ("Admin", "RevokeMetricsCredentials", 15),
    ("Admin", "CreateAlertChannel", 15),
    ("Admin", "UpdateAlertChannel", 15),
    ("Admin", "ListAlertChannels", 15),
    ("Admin", "DeleteAlertChannel", 15),
    ("Admin", "TestAlertChannel", 15),
    ("Admin", "RunJob", 10),
    ("Admin", "ListJobs", 10),
    ("Admin", "ListJobRuns", 10),
    ("Admin", "CancelJob", 10),
    ("Admin", "DeleteJob", 10),
    ("Agent", "PushLogs", 15),
    ("Agent", "ExecSession", 15),
    ("Agent", "VolumeSession", 12),
    ("Agent", "GetCertificates", 14),
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
        let _ = request;
        Err(unimplemented("ClusterStatus"))
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
        let _ = request;
        Err(unimplemented("ListVolumes"))
    }
    async fn remove_volume(
        &self,
        request: Request<RemoveVolumeRequest>,
    ) -> Result<Response<RemoveVolumeResponse>, Status> {
        let _ = request;
        Err(unimplemented("RemoveVolume"))
    }
    type BackupVolumeStream = Out<VolumeData>;
    async fn backup_volume(
        &self,
        request: Request<BackupVolumeRequest>,
    ) -> Result<Response<Self::BackupVolumeStream>, Status> {
        let _ = request;
        Err(unimplemented("BackupVolume"))
    }
    async fn restore_volume(
        &self,
        request: Request<tonic::Streaming<RestoreVolumeMessage>>,
    ) -> Result<Response<RestoreVolumeResponse>, Status> {
        let _ = request;
        Err(unimplemented("RestoreVolume"))
    }
    async fn list_volume_snapshots(
        &self,
        request: Request<ListVolumeSnapshotsRequest>,
    ) -> Result<Response<ListVolumeSnapshotsResponse>, Status> {
        let _ = request;
        Err(unimplemented("ListVolumeSnapshots"))
    }
    async fn create_volume_snapshot(
        &self,
        request: Request<CreateVolumeSnapshotRequest>,
    ) -> Result<Response<CreateVolumeSnapshotResponse>, Status> {
        let _ = request;
        Err(unimplemented("CreateVolumeSnapshot"))
    }
    async fn restore_volume_snapshot(
        &self,
        request: Request<RestoreVolumeSnapshotRequest>,
    ) -> Result<Response<RestoreVolumeResponse>, Status> {
        let _ = request;
        Err(unimplemented("RestoreVolumeSnapshot"))
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
        let _ = request;
        Err(unimplemented("ListDomains"))
    }
    async fn verify_domain(
        &self,
        request: Request<VerifyDomainRequest>,
    ) -> Result<Response<Domain>, Status> {
        let _ = request;
        Err(unimplemented("VerifyDomain"))
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
        let _ = request;
        Err(unimplemented("Top"))
    }
    async fn issue_metrics_certificate(
        &self,
        request: Request<IssueMetricsCertificateRequest>,
    ) -> Result<Response<IssueMetricsCertificateResponse>, Status> {
        let _ = request;
        Err(unimplemented("IssueMetricsCertificate"))
    }
    async fn list_metrics_credentials(
        &self,
        request: Request<ListMetricsCredentialsRequest>,
    ) -> Result<Response<ListMetricsCredentialsResponse>, Status> {
        let _ = request;
        Err(unimplemented("ListMetricsCredentials"))
    }
    async fn revoke_metrics_credentials(
        &self,
        request: Request<RevokeMetricsCredentialsRequest>,
    ) -> Result<Response<RevokeMetricsCredentialsResponse>, Status> {
        let _ = request;
        Err(unimplemented("RevokeMetricsCredentials"))
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
        let _ = request;
        Err(unimplemented("CreateAlertChannel"))
    }
    async fn update_alert_channel(
        &self,
        request: Request<AlertChannelRequest>,
    ) -> Result<Response<AlertChannel>, Status> {
        let _ = request;
        Err(unimplemented("UpdateAlertChannel"))
    }
    async fn list_alert_channels(
        &self,
        request: Request<ListAlertChannelsRequest>,
    ) -> Result<Response<ListAlertChannelsResponse>, Status> {
        let _ = request;
        Err(unimplemented("ListAlertChannels"))
    }
    async fn delete_alert_channel(
        &self,
        request: Request<DeleteAlertChannelRequest>,
    ) -> Result<Response<DeleteAlertChannelResponse>, Status> {
        let _ = request;
        Err(unimplemented("DeleteAlertChannel"))
    }
    async fn test_alert_channel(
        &self,
        request: Request<TestAlertChannelRequest>,
    ) -> Result<Response<TestAlertChannelResponse>, Status> {
        let _ = request;
        Err(unimplemented("TestAlertChannel"))
    }
    async fn run_job(
        &self,
        request: Request<RunJobRequest>,
    ) -> Result<Response<RunJobResponse>, Status> {
        let _ = request;
        Err(unimplemented("RunJob"))
    }
    async fn list_jobs(
        &self,
        request: Request<ListJobsRequest>,
    ) -> Result<Response<ListJobsResponse>, Status> {
        let _ = request;
        Err(unimplemented("ListJobs"))
    }
    async fn list_job_runs(
        &self,
        request: Request<ListJobRunsRequest>,
    ) -> Result<Response<ListJobRunsResponse>, Status> {
        let _ = request;
        Err(unimplemented("ListJobRuns"))
    }
    async fn cancel_job(
        &self,
        request: Request<CancelJobRequest>,
    ) -> Result<Response<CancelJobResponse>, Status> {
        let _ = request;
        Err(unimplemented("CancelJob"))
    }
    async fn delete_job(
        &self,
        request: Request<DeleteJobRequest>,
    ) -> Result<Response<DeleteJobResponse>, Status> {
        let _ = request;
        Err(unimplemented("DeleteJob"))
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
        let _ = request;
        Err(unimplemented("VolumeSession"))
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
        let _ = request;
        Err(unimplemented("GetCertificates"))
    }
}

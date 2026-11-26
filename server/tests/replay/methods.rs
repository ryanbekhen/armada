//! Every method of Armada's API with its request and response types
//! (listed from the rpc lines of api/armada/v1/armada.proto; the
//! replay calls methods by their paths, as the recordings name them).

use armada_proto::armada::v1 as pb;
use prost::Message;
use serde_json::Value;

macro_rules! methods {
    ($($path:literal => $req:ident, $resp:ident;)*) => {
        /// A request (its protobuf JSON) encoded for method path.
        pub fn encode_request(path: &str, v: &Value) -> Result<Vec<u8>, String> {
            match path {
                $($path => {
                    let m: pb::$req = serde_json::from_value(v.clone()).map_err(|e| format!("{path} request: {e}"))?;
                    Ok(m.encode_to_vec())
                })*
                _ => Err(format!("unknown method {path}")),
            }
        }

        /// A response of method path as its protobuf JSON.
        pub fn decode_response(path: &str, b: &[u8]) -> Result<Value, String> {
            match path {
                $($path => {
                    let m = pb::$resp::decode(b).map_err(|e| format!("{path} response: {e}"))?;
                    serde_json::to_value(&m).map_err(|e| e.to_string())
                })*
                _ => Err(format!("unknown method {path}")),
            }
        }
    };
}

methods! {
    "/armada.v1.AdminService/Deploy" => DeployRequest, DeployResponse;
    "/armada.v1.AdminService/Status" => StatusRequest, StatusResponse;
    "/armada.v1.AdminService/ListApps" => ListAppsRequest, ListAppsResponse;
    "/armada.v1.AdminService/ClusterStatus" => ClusterStatusRequest, ClusterStatusResponse;
    "/armada.v1.AdminService/GetAppSpec" => GetAppSpecRequest, GetAppSpecResponse;
    "/armada.v1.AdminService/SetTraffic" => SetTrafficRequest, SetTrafficResponse;
    "/armada.v1.AdminService/ListVolumes" => ListVolumesRequest, ListVolumesResponse;
    "/armada.v1.AdminService/RemoveVolume" => RemoveVolumeRequest, RemoveVolumeResponse;
    "/armada.v1.AdminService/BackupVolume" => BackupVolumeRequest, VolumeData;
    "/armada.v1.AdminService/RestoreVolume" => RestoreVolumeMessage, RestoreVolumeResponse;
    "/armada.v1.AdminService/ListVolumeSnapshots" => ListVolumeSnapshotsRequest, ListVolumeSnapshotsResponse;
    "/armada.v1.AdminService/CreateVolumeSnapshot" => CreateVolumeSnapshotRequest, CreateVolumeSnapshotResponse;
    "/armada.v1.AdminService/RestoreVolumeSnapshot" => RestoreVolumeSnapshotRequest, RestoreVolumeResponse;
    "/armada.v1.AdminService/Logs" => LogsRequest, LogEntry;
    "/armada.v1.AdminService/GetClusterConfig" => GetClusterConfigRequest, ClusterConfig;
    "/armada.v1.AdminService/SetClusterConfig" => SetClusterConfigRequest, ClusterConfig;
    "/armada.v1.AdminService/ListDomains" => ListDomainsRequest, ListDomainsResponse;
    "/armada.v1.AdminService/VerifyDomain" => VerifyDomainRequest, Domain;
    "/armada.v1.AdminService/ListRevisions" => ListRevisionsRequest, ListRevisionsResponse;
    "/armada.v1.AdminService/Rollback" => RollbackRequest, RollbackResponse;
    "/armada.v1.AdminService/RestartApp" => RestartAppRequest, RestartAppResponse;
    "/armada.v1.AdminService/SetSecret" => SetSecretRequest, SetSecretResponse;
    "/armada.v1.AdminService/ListSecrets" => ListSecretsRequest, ListSecretsResponse;
    "/armada.v1.AdminService/DeleteSecret" => DeleteSecretRequest, DeleteSecretResponse;
    "/armada.v1.AdminService/ListSpaceSecrets" => ListSpaceSecretsRequest, ListSpaceSecretsResponse;
    "/armada.v1.AdminService/CreateJoinToken" => CreateJoinTokenRequest, CreateJoinTokenResponse;
    "/armada.v1.AdminService/CordonNode" => CordonNodeRequest, CordonNodeResponse;
    "/armada.v1.AdminService/LabelNode" => LabelNodeRequest, LabelNodeResponse;
    "/armada.v1.AdminService/RestrictNode" => RestrictNodeRequest, RestrictNodeResponse;
    "/armada.v1.AdminService/SetNodeSite" => SetNodeSiteRequest, SetNodeSiteResponse;
    "/armada.v1.AdminService/SetNodeRelay" => SetNodeRelayRequest, SetNodeRelayResponse;
    "/armada.v1.AdminService/RotateNodeKey" => RotateNodeKeyRequest, RotateNodeKeyResponse;
    "/armada.v1.AdminService/RemoveNode" => RemoveNodeRequest, RemoveNodeResponse;
    "/armada.v1.AdminService/ListServers" => ListServersRequest, ListServersResponse;
    "/armada.v1.AdminService/RemoveServer" => RemoveServerRequest, RemoveServerResponse;
    "/armada.v1.AdminService/CreateSpace" => CreateSpaceRequest, SpaceInfo;
    "/armada.v1.AdminService/ListSpaces" => ListSpacesRequest, ListSpacesResponse;
    "/armada.v1.AdminService/DeleteSpace" => DeleteSpaceRequest, DeleteSpaceResponse;
    "/armada.v1.AdminService/UpdateSpace" => UpdateSpaceRequest, SpaceInfo;
    "/armada.v1.AdminService/CreateUser" => CreateUserRequest, IssueMetricsCertificateResponse;
    "/armada.v1.AdminService/IssueUserCertificate" => IssuePrincipalCertificateRequest, IssueMetricsCertificateResponse;
    "/armada.v1.AdminService/CreateService" => CreateServiceRequest, Principal;
    "/armada.v1.AdminService/IssueServiceCertificate" => IssuePrincipalCertificateRequest, IssueMetricsCertificateResponse;
    "/armada.v1.AdminService/ListPrincipals" => ListPrincipalsRequest, ListPrincipalsResponse;
    "/armada.v1.AdminService/UpdatePrincipal" => UpdatePrincipalRequest, Principal;
    "/armada.v1.AdminService/DeletePrincipal" => DeletePrincipalRequest, DeletePrincipalResponse;
    "/armada.v1.AdminService/CreateAssignment" => AssignmentRequest, Principal;
    "/armada.v1.AdminService/DeleteAssignment" => AssignmentRequest, Principal;
    "/armada.v1.AdminService/ListRoles" => ListRolesRequest, ListRolesResponse;
    "/armada.v1.AdminService/RenewOwnCertificate" => RenewOwnCertificateRequest, IssueMetricsCertificateResponse;
    "/armada.v1.AdminService/Exec" => ExecClientMessage, ExecServerMessage;
    "/armada.v1.AdminService/Top" => TopRequest, TopResponse;
    "/armada.v1.AdminService/IssueMetricsCertificate" => IssueMetricsCertificateRequest, IssueMetricsCertificateResponse;
    "/armada.v1.AdminService/ListMetricsCredentials" => ListMetricsCredentialsRequest, ListMetricsCredentialsResponse;
    "/armada.v1.AdminService/RevokeMetricsCredentials" => RevokeMetricsCredentialsRequest, RevokeMetricsCredentialsResponse;
    "/armada.v1.AdminService/Events" => EventsRequest, EventInfo;
    "/armada.v1.AdminService/CreateAlertChannel" => AlertChannelRequest, AlertChannel;
    "/armada.v1.AdminService/UpdateAlertChannel" => AlertChannelRequest, AlertChannel;
    "/armada.v1.AdminService/ListAlertChannels" => ListAlertChannelsRequest, ListAlertChannelsResponse;
    "/armada.v1.AdminService/DeleteAlertChannel" => DeleteAlertChannelRequest, DeleteAlertChannelResponse;
    "/armada.v1.AdminService/TestAlertChannel" => TestAlertChannelRequest, TestAlertChannelResponse;
    "/armada.v1.AdminService/RunJob" => RunJobRequest, RunJobResponse;
    "/armada.v1.AdminService/ListJobs" => ListJobsRequest, ListJobsResponse;
    "/armada.v1.AdminService/ListJobRuns" => ListJobRunsRequest, ListJobRunsResponse;
    "/armada.v1.AdminService/CancelJob" => CancelJobRequest, CancelJobResponse;
    "/armada.v1.AdminService/DeleteJob" => DeleteJobRequest, DeleteJobResponse;
    "/armada.v1.AdminService/RemoveApp" => RemoveAppRequest, RemoveAppResponse;
    "/armada.v1.JoinService/Join" => JoinRequest, JoinResponse;
    "/armada.v1.JoinService/JoinServer" => JoinServerRequest, JoinServerResponse;
    "/armada.v1.AgentService/Connect" => AgentMessage, ServerMessage;
    "/armada.v1.AgentService/PushLogs" => LogPush, PushLogsResponse;
    "/armada.v1.AgentService/ExecSession" => ExecSessionOutput, ExecInput;
    "/armada.v1.AgentService/VolumeSession" => VolumeData, VolumeData;
    "/armada.v1.AgentService/RenewCertificate" => RenewCertificateRequest, RenewCertificateResponse;
    "/armada.v1.AgentService/GetCertificates" => GetCertificatesRequest, GetCertificatesResponse;
}

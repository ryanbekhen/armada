//! What only the parity programs use (feature `parity`): every store
//! method called by name with its arguments as the recordings write them,
//! answered with the recordings' field names. The store's parity
//! program (`armada-store-parity`) and the server's scenario replay
//! (`server/tests/scenarios.rs`) both call it.

use std::collections::BTreeMap;

use armada_secrets::Sealed;
use armada_spec::App as Spec;
use armada_spec::TrafficTarget;
use armada_spec::go::parse_prefix;
use armada_spec::gotime::{Time, parse_rfc3339};
use serde::Serialize;
use serde_json::{Value, json};

use crate::*;
pub fn s(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}
pub fn i(v: &Value, k: &str) -> i64 {
    v.get(k).and_then(Value::as_i64).unwrap_or_default()
}
pub fn u(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or_default()
}
pub fn b(v: &Value, k: &str) -> bool {
    v.get(k).and_then(Value::as_bool).unwrap_or_default()
}
pub fn t(v: &Value, k: &str) -> Time {
    let txt = s(v, k);
    if txt.is_empty() {
        return Time::zero();
    }
    parse_rfc3339(&txt).unwrap_or_else(Time::zero)
}
pub fn strs(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}
pub fn smap(v: &Value, k: &str) -> Option<BTreeMap<String, String>> {
    v.get(k).and_then(Value::as_object).map(|m| {
        m.iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
            .collect()
    })
}
pub fn lmap(v: &Value, k: &str) -> BTreeMap<String, Vec<String>> {
    v.get(k)
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, _)| (k.clone(), strs(&m.clone().into(), k)))
                .collect()
        })
        .unwrap_or_default()
}
pub fn spec(v: &Value, k: &str) -> Spec {
    let raw = v.get(k).map(|x| x.to_string()).unwrap_or_default();
    Spec::from_json(raw.as_bytes()).expect("the test sends valid specs")
}

pub fn node(v: &Value) -> Node {
    Node {
        id: s(v, "ID"),
        private_ip: s(v, "PrivateIP"),
        cpu_millis: i(v, "CPUMillis"),
        memory_bytes: i(v, "MemoryBytes"),
        state: s(v, "State"),
        last_seen: t(v, "LastSeen"),
        created_at: t(v, "CreatedAt"),
        cordoned: b(v, "Cordoned"),
        version: s(v, "Version"),
        cert_not_after: t(v, "CertNotAfter"),
        labels: smap(v, "Labels"),
        os: s(v, "OS"),
        arch: s(v, "Arch"),
        restricted: b(v, "Restricted"),
        jobs: b(v, "Jobs"),
        volumes: b(v, "Volumes"),
        containers: b(v, "Containers"),
        nfs: b(v, "NFS"),
        subnet: s(v, "Subnet"),
        network_key: s(v, "NetworkKey"),
        endpoint: s(v, "Endpoint"),
        site: s(v, "Site"),
        mesh_address: b(v, "MeshAddress"),
        behind_nat: b(v, "BehindNAT"),
        relay: b(v, "Relay"),
    }
}

pub fn server(v: &Value) -> Server {
    Server {
        name: s(v, "Name"),
        private_ip: s(v, "PrivateIP"),
        api_addr: s(v, "APIAddr"),
        join_addr: s(v, "JoinAddr"),
        member_id: u(v, "MemberID"),
        schema: i(v, "Schema"),
        version: s(v, "Version"),
        created_at: t(v, "CreatedAt"),
    }
}

pub fn cert(v: &Value) -> NodeCert {
    NodeCert {
        serial: s(v, "Serial"),
        not_after: t(v, "NotAfter"),
    }
}

pub fn grant(v: &Value) -> Grant {
    Grant {
        role: s(v, "Role"),
        space: s(v, "Space"),
    }
}

pub fn principal(v: &Value) -> Principal {
    Principal {
        kind: s(v, "Kind"),
        name: s(v, "Name"),
        roles: v
            .get("Roles")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(grant).collect())
            .unwrap_or_default(),
        labels: lmap(v, "Labels"),
        created_at: t(v, "CreatedAt"),
        created_by: s(v, "CreatedBy"),
        since: t(v, "Since"),
        since_serial: s(v, "SinceSerial"),
        removed: b(v, "Removed"),
        certs: v
            .get("Certs")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(cert).collect())
            .unwrap_or_default(),
    }
}

pub fn traffic(v: &Value, k: &str) -> Vec<TrafficTarget> {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|x| TrafficTarget {
                    revision: s(x, "revision"),
                    weight: i(x, "weight"),
                    label: s(x, "label"),
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn job_run(v: &Value) -> JobRun {
    JobRun {
        job: s(v, "Job"),
        seq: i(v, "Seq"),
        revision: s(v, "Revision"),
        trigger: s(v, "Trigger"),
        state: s(v, "State"),
        attempts: i(v, "Attempts"),
        replica: s(v, "Replica"),
        node: s(v, "Node"),
        exit_code: i(v, "ExitCode"),
        message: s(v, "Message"),
        created_at: t(v, "CreatedAt"),
        started_at: t(v, "StartedAt"),
        attempt_at: t(v, "AttemptAt"),
        finished_at: t(v, "FinishedAt"),
        tasks: v
            .get("Tasks")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|x| RunTask {
                        index: i(x, "Index"),
                        state: s(x, "State"),
                        attempts: i(x, "Attempts"),
                        replica: s(x, "Replica"),
                        node: s(x, "Node"),
                        exit_code: i(x, "ExitCode"),
                        message: s(x, "Message"),
                        attempt_at: t(x, "AttemptAt"),
                        waiting_since: t(x, "WaitingSince"),
                        finished_at: t(x, "FinishedAt"),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

pub fn ok<T: Serialize>(v: T) -> Result<Value> {
    Ok(serde_json::to_value(v).expect("answers encode"))
}

/// One store method with its arguments as the recordings send them.
pub async fn call(st: &Etcd, method: &str, a: &Value) -> Result<Value> {
    match method {
        "GetMeta" => ok(st.get_meta(&s(a, "key")).await?),
        "SetMeta" => ok(st.set_meta(&s(a, "key"), &s(a, "value")).await?),
        "GetNetwork" => ok(st.get_network().await?),
        "InitNetwork" => {
            let n = Network {
                mode: s(a, "Mode"),
                cluster_cidr: parse_prefix(&s(a, "ClusterCIDR")),
                isolate_default: b(a, "IsolateDefault"),
                mesh_cidr: parse_prefix(&s(a, "MeshCIDR")),
                switch: None,
            };
            ok(st.init_network(&n).await?)
        }
        "SetDefaultIsolation" => ok(st.set_default_isolation(b(a, "on"), &s(a, "actor")).await?),
        "StartNetworkSwitch" => ok(st.start_network_switch(&s(a, "to"), &s(a, "actor")).await?),
        "AdvanceNetworkSwitch" => ok(st
            .advance_network_switch(&s(a, "to"), &s(a, "from"))
            .await?),
        "UpsertNode" => ok(st.upsert_node(&node(&a["node"])).await?),
        "SetNodeSite" => ok(st
            .set_node_site(&s(a, "id"), &s(a, "site"), &s(a, "actor"))
            .await?),
        "SetNodeRelay" => ok(st
            .set_node_relay(&s(a, "id"), b(a, "on"), &s(a, "actor"))
            .await?),
        "SetNodeNetworkKey" => ok(st.set_node_network_key(&s(a, "id"), &s(a, "key")).await?),
        "GetNode" => ok(st.get_node(&s(a, "id")).await?),
        "ListNodes" => ok(st.list_nodes().await?),
        "SetNodeStatus" => {
            let v = &a["status"];
            let ns = NodeStatus {
                state: s(v, "State"),
                last_seen: t(v, "LastSeen"),
                cpu_millis: i(v, "CPUMillis"),
                memory_bytes: i(v, "MemoryBytes"),
                version: s(v, "Version"),
                os: s(v, "OS"),
                arch: s(v, "Arch"),
                jobs: b(v, "Jobs"),
                volumes: b(v, "Volumes"),
                containers: b(v, "Containers"),
                nfs: b(v, "NFS"),
                egress: b(v, "Egress"),
                network_key: s(v, "NetworkKey"),
                endpoint: s(v, "Endpoint"),
                behind_nat: b(v, "BehindNAT"),
            };
            ok(st.set_node_status(&s(a, "id"), &ns).await?)
        }
        "SetNodeCordoned" => ok(st
            .set_node_cordoned(&s(a, "id"), b(a, "on"), &s(a, "actor"))
            .await?),
        "SetNodeLabels" => ok(st
            .set_node_labels(
                &s(a, "id"),
                &smap(a, "set").unwrap_or_default(),
                &strs(a, "remove"),
                &s(a, "actor"),
            )
            .await?),
        "SetNodeRestricted" => ok(st
            .set_node_restricted(&s(a, "id"), b(a, "on"), &s(a, "actor"))
            .await?),
        "RemoveNode" => ok(st
            .remove_node(&s(a, "id"), b(a, "force"), &s(a, "actor"))
            .await?),
        "CreateJoinToken" => {
            let v = &a["token"];
            let tok = JoinToken {
                id: s(v, "ID"),
                secret_hash: s(v, "SecretHash"),
                expires_at: t(v, "ExpiresAt"),
                created_at: t(v, "CreatedAt"),
                created_by: s(v, "CreatedBy"),
                server: b(v, "Server"),
                labels: smap(v, "Labels").unwrap_or_default(),
                from: s(v, "From"),
                site: s(v, "Site"),
            };
            ok(st.create_join_token(&tok).await?)
        }
        "OpenJoinTokens" => ok(st.open_join_tokens().await?),
        "FreeMeshAddress" => ok(st.free_mesh_address().await?),
        "SetMeshCIDR" => ok(st
            .set_mesh_cidr(&parse_prefix(&s(a, "prefix")), &s(a, "actor"))
            .await?),
        "RedeemJoinToken" | "RedeemServerToken" => {
            let hash = s(a, "hash");
            let check = move |h: &str| h == hash;
            let issue_err = s(a, "issueError");
            let c = cert(&a["cert"]);
            let issue = move || {
                if issue_err.is_empty() {
                    Ok(c.clone())
                } else {
                    Err(Error::other(issue_err.clone()))
                }
            };
            let n = node(&a["node"]);
            if method == "RedeemJoinToken" {
                ok(st
                    .redeem_join_token(&s(a, "id"), &check, &n, &issue)
                    .await?)
            } else {
                ok(st
                    .redeem_server_token(&s(a, "id"), &check, &server(&a["server"]), &n, &issue)
                    .await?)
            }
        }
        "RecordNodeCert" => ok(st
            .record_node_cert(&s(a, "node"), &cert(&a["cert"]), &s(a, "keep"))
            .await?),
        "NodeCertAllowed" => ok(st.node_cert_allowed(&s(a, "node"), &s(a, "serial")).await?),
        "StoredSchema" => ok(st.stored_schema().await?),
        "UpsertServer" => ok(st.upsert_server(&server(&a["server"])).await?),
        "ListServers" => ok(st.list_servers().await?),
        "RemoveServer" => ok(st.remove_server(&s(a, "name"), &s(a, "actor")).await?),
        "CreateSpace" => {
            let by = a.get("by").filter(|v| !v.is_null()).map(principal);
            ok(st
                .create_space(&s(a, "name"), &s(a, "actor"), by.as_ref())
                .await?)
        }
        "GetSpace" => ok(st.get_space(&s(a, "name")).await?),
        "ListSpaces" => ok(st.list_spaces().await?),
        "DeleteSpace" => ok(st.delete_space(&s(a, "name"), &s(a, "actor")).await?),
        "CreateUser" => ok(st
            .create_user(&principal(&a["principal"]), &s(a, "actor"))
            .await?),
        "KnowUser" => ok(st.know_user(&s(a, "name")).await?),
        "SetUserSince" => ok(st
            .set_user_since(
                &s(a, "name"),
                &t(a, "since"),
                &s(a, "serial"),
                &s(a, "actor"),
            )
            .await?),
        "RenewedUser" => ok(st
            .renewed_user(
                &s(a, "name"),
                &t(a, "notBefore"),
                &s(a, "callerSerial"),
                &s(a, "serial"),
            )
            .await?),
        "CreateService" => ok(st
            .create_service(&principal(&a["principal"]), &s(a, "actor"))
            .await?),
        "GetPrincipal" => ok(st.get_principal(&s(a, "kind"), &s(a, "name")).await?),
        "ListPrincipals" => ok(st.list_principals(&s(a, "kind")).await?),
        "SetPrincipalLabels" => ok(st
            .set_principal_labels(
                &s(a, "kind"),
                &s(a, "name"),
                &lmap(a, "labels"),
                &s(a, "actor"),
            )
            .await?),
        "Assign" => ok(st
            .assign(
                &s(a, "kind"),
                &s(a, "name"),
                &grant(&a["grant"]),
                &s(a, "actor"),
            )
            .await?),
        "Unassign" => ok(st
            .unassign(
                &s(a, "kind"),
                &s(a, "name"),
                &grant(&a["grant"]),
                &s(a, "actor"),
            )
            .await?),
        "DeletePrincipal" => ok(st
            .delete_principal(&s(a, "kind"), &s(a, "name"), &s(a, "actor"))
            .await?),
        "RecordServiceCert" => ok(st
            .record_service_cert(
                &s(a, "name"),
                &cert(&a["cert"]),
                &s(a, "keep"),
                &s(a, "actor"),
            )
            .await?),
        "UserAccess" => {
            let (p, allowed) = st
                .user_access(&s(a, "name"), &t(a, "notBefore"), &s(a, "serial"))
                .await?;
            ok(json!({"Principal": p, "Allowed": allowed}))
        }
        "ServiceAccess" => {
            let (p, allowed) = st.service_access(&s(a, "name"), &s(a, "serial")).await?;
            ok(json!({"Principal": p, "Allowed": allowed}))
        }
        "RecordMetricsCert" => ok(st
            .record_metrics_cert(&s(a, "name"), &cert(&a["cert"]), &s(a, "actor"))
            .await?),
        "RevokeMetricsCerts" => ok(st
            .revoke_metrics_certs(&s(a, "name"), &s(a, "actor"))
            .await?),
        "ListMetricsCerts" => ok(st.list_metrics_certs().await?),
        "MetricsAccess" => ok(st
            .metrics_access(&s(a, "name"), &t(a, "notBefore"), &s(a, "serial"))
            .await?),
        "Deploy" | "DeployWith" => {
            let o = &a["opts"];
            let opts = DeployOptions {
                must_create: b(o, "MustCreate"),
                must_exist: b(o, "MustExist"),
                base_revision: s(o, "BaseRevision"),
            };
            let (rev, created) = st
                .deploy_with(&spec(a, "spec"), &s(a, "actor"), &opts)
                .await?;
            ok(json!({"Rev": rev, "Created": created}))
        }
        "Rollback" => ok(st
            .rollback(&s(a, "app"), &s(a, "revision"), &s(a, "actor"))
            .await?),
        "RestartApp" => ok(st.restart_app(&s(a, "app"), &s(a, "actor")).await?),
        "CompleteRollout" => ok(st.complete_rollout(&s(a, "app"), &s(a, "revision")).await?),
        "FailRollout" => ok(st
            .fail_rollout(&s(a, "app"), &s(a, "revision"), &s(a, "message"))
            .await?),
        "MarkRolloutProgress" => ok(st.mark_rollout_progress(&s(a, "app")).await?),
        "GetApp" => ok(st.get_app(&s(a, "name")).await?),
        "ListApps" => ok(st.list_apps().await?),
        "GetApps" => ok(st.get_apps(&strs(a, "names")).await?),
        "ListAppIDs" => ok(st.list_app_ids().await?),
        "SetReplicas" => ok(st
            .set_replicas(&s(a, "app"), i(a, "n"), &s(a, "actor"))
            .await?),
        "SetTraffic" => ok(st
            .set_traffic(&s(a, "app"), &traffic(a, "weights"), &s(a, "actor"))
            .await?
            .iter()
            .map(|t| {
                let mut v = json!({"revision": t.revision, "weight": t.weight});
                if !t.label.is_empty() {
                    v["label"] = json!(t.label);
                }
                v
            })
            .collect::<Vec<_>>()),
        "AutoscaleReplicas" => ok(st
            .autoscale_replicas(&s(a, "app"), i(a, "from"), i(a, "n"), &s(a, "actor"))
            .await?),
        "GetRevision" => ok(st.get_revision(&s(a, "name")).await?),
        "GetRevisions" => ok(st.get_revisions(&strs(a, "names")).await?),
        "ListRevisions" => ok(st.list_revisions(&s(a, "app")).await?),
        "SetRevisionDigest" => ok(st
            .set_revision_digest(&s(a, "revision"), &s(a, "digest"))
            .await?),
        "SetRevisionPlatforms" => ok(st
            .set_revision_platforms(&s(a, "revision"), &strs(a, "platforms"))
            .await?),
        "CreateReplica" => {
            let v = &a["replica"];
            let r = Replica {
                id: s(v, "ID"),
                app: s(v, "App"),
                revision: s(v, "Revision"),
                node_id: s(v, "NodeID"),
                state: s(v, "State"),
                run: i(v, "Run"),
                task: i(v, "Task"),
                held: b(v, "Held"),
                ..Default::default()
            };
            ok(st.create_replica(&r).await?)
        }
        "ReplicaPlacements" => ok(st.replica_placements(&s(a, "app")).await?),
        "PrunePlacements" => ok(st.prune_placements(&t(a, "before")).await?),
        "DeleteReplica" => ok(st.delete_replica(&s(a, "id")).await?),
        "DrainReplica" => ok(st.drain_replica(&s(a, "id")).await?),
        "SetReplicaMoving" => ok(st.set_replica_moving(&s(a, "id"), b(a, "on")).await?),
        "ReleaseReplica" => ok(st.release_replica(&s(a, "id")).await?),
        "SetReplicaDone" => ok(st.set_replica_done(&s(a, "id")).await?),
        "ListReplicas" => {
            let f = ReplicaFilter {
                app: s(&a["filter"], "App"),
                node_id: s(&a["filter"], "NodeID"),
            };
            ok(st.list_replicas(&f).await?)
        }
        "UpdateReplicaStatus" => {
            let v = &a["status"];
            let rs = ReplicaStatus {
                id: s(v, "ID"),
                state: s(v, "State"),
                container_id: s(v, "ContainerID"),
                address: s(v, "Address"),
                ip: s(v, "IP"),
                message: s(v, "Message"),
                ready: b(v, "Ready"),
                finished: b(v, "Finished"),
                exit_code: i(v, "ExitCode"),
            };
            ok(st.update_replica_status(&s(a, "node"), &rs).await?)
        }
        "ListVolumes" => ok(st.list_volumes(&s(a, "app")).await?),
        "GetVolume" => ok(st.get_volume(&s(a, "app"), &s(a, "name")).await?),
        "DeleteVolume" => ok(st
            .delete_volume(&s(a, "app"), &s(a, "name"), &s(a, "actor"))
            .await?),
        "BindVolume" => ok(st
            .bind_volume(&s(a, "app"), &s(a, "name"), &s(a, "node"), &s(a, "actor"))
            .await?),
        "RecordVolumeBackup" => ok(st
            .record_volume_backup(
                &s(a, "app"),
                &s(a, "name"),
                &s(a, "id"),
                i(a, "stored"),
                i(a, "snapshots"),
                &s(a, "error"),
            )
            .await?),
        "PutEvent" => {
            let v = &a["event"];
            let e = Event {
                key: s(v, "Key"),
                kind: s(v, "Kind"),
                object: s(v, "Object"),
                app: s(v, "App"),
                node: s(v, "Node"),
                reason: s(v, "Reason"),
                message: s(v, "Message"),
                count: i(v, "Count"),
                first: t(v, "First"),
                last: t(v, "Last"),
            };
            ok(st.put_event(&e, &s(a, "replace")).await?)
        }
        "ListEvents" => ok(st.list_events(&t(a, "since")).await?),
        "TrimEvents" => ok(st.trim_events(i(a, "keep")).await?),
        "CreateJobRun" => ok(st
            .create_job_run(&s(a, "job"), &s(a, "trigger"), &t(a, "at"), &s(a, "actor"))
            .await?),
        "SkipJobSchedule" => ok(st.skip_job_schedule(&s(a, "job"), &t(a, "at")).await?),
        "UpdateJobRun" => ok(st.update_job_run(&job_run(&a["run"])).await?),
        "ListJobRuns" => ok(st.list_job_runs(&s(a, "job")).await?),
        "DeleteJobRun" => ok(st.delete_job_run(&s(a, "job"), i(a, "seq")).await?),
        "CancelJobRuns" => ok(st.cancel_job_runs(&s(a, "job"), &s(a, "actor")).await?),
        "DeleteJob" => ok(st.delete_job(&s(a, "job"), &s(a, "actor")).await?),
        "MarkAppRemoving" => ok(st.mark_app_removing(&s(a, "app"), &s(a, "actor")).await?),
        "DeleteApp" => ok(st.delete_app(&s(a, "app")).await?),
        "ListAudit" => ok(st.list_audit(i(a, "limit")).await?),
        "RecordAudit" => ok(st
            .record_audit(
                &s(a, "actor"),
                &s(a, "action"),
                &s(a, "target"),
                &s(a, "detail"),
            )
            .await?),
        "SetSecret" => {
            let value = s(a, "value");
            let seal = move |v: i64| {
                Ok(Sealed {
                    key_id: "k".to_string(),
                    wrapped_key: v.to_string().into_bytes(),
                    ciphertext: value.clone().into_bytes(),
                })
            };
            let (version, revisions) = st
                .set_secret(
                    &s(a, "secret"),
                    &s(a, "key"),
                    &seal,
                    b(a, "rollout"),
                    &s(a, "actor"),
                )
                .await?;
            ok(json!({"Version": version, "Revisions": revisions}))
        }
        "GetSecret" => {
            let x = st
                .get_secret(&s(a, "secret"), &s(a, "key"), i(a, "version"))
                .await?;
            ok(json!({
                "KeyID": x.key_id,
                // The record's nil and empty bytes both come back empty.
                "WrappedKey": (!x.wrapped_key.is_empty()).then(|| b64(&x.wrapped_key)),
                "Ciphertext": (!x.ciphertext.is_empty()).then(|| b64(&x.ciphertext)),
            }))
        }
        "ListSecrets" => ok(st.list_secrets(&s(a, "secret")).await?),
        "ListSpaceSecrets" => ok(st.list_space_secrets(&s(a, "space")).await?),
        "DeleteSecret" => ok(st
            .delete_secret(&s(a, "secret"), &s(a, "key"), &s(a, "actor"))
            .await?),
        "ListDomains" => ok(st.list_domains().await?),
        "GetDomain" => ok(st.get_domain(&s(a, "name")).await?),
        "SetDomainVerification" => ok(st
            .set_domain_verification(&s(a, "name"), b(a, "verified"), &s(a, "message"))
            .await?),
        "Migrate" => ok(st.migrate().await?),
        "MigrateTo" => ok(st.migrate_to(i(a, "target")).await?),
        "SetLegacyCerts" => ok(st.set_legacy_certs().await?),
        _ => Err(Error::other(format!(
            "armada-store-parity: unknown method {method}"
        ))),
    }
}

pub fn b64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

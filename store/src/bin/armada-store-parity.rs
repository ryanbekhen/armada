//! armada-store-parity: the program Go's parity tests of the store drive
//! (internal/store/nativestore_test.go, ARMADA_STORE_BIN). Never packed.
//!
//! It reads one JSON request per line on stdin and answers each with one
//! line on stdout, `{"id", "value"?, "error"?, "kind"?}`, running requests
//! at the same time (a campaign waits while others go on). Values are the
//! store's answers with Go's field names; the Go test reads them into its
//! own types and compares.
//!
//! Requests (`op`): `open` (handle, endpoint, dir, prefix), `fenced`
//! (handle, from, key, rev), `setNow` (handle, ms), `call` (handle, method,
//! args, repeat, parallel), `reencode` (handle), `campaign` (handle,
//! endpoint, dir, ttl, name), `resign` (handle), `leader` (endpoint, dir),
//! `lock`/`tryLock` (handle, endpoint, dir, ttl, prefix), `unlock` (handle).

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use armada_secrets::Sealed;
use armada_spec::App as Spec;
use armada_spec::TrafficTarget;
use armada_spec::go::parse_prefix;
use armada_spec::gotime::{Location, Time, parse_rfc3339};
use armada_store::election::{self, Leadership, Mutex as EtcdMutex, Session};
use armada_store::*;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

#[derive(Default)]
struct State {
    clients: Mutex<HashMap<String, Client>>,
    stores: Mutex<HashMap<String, Etcd>>,
    leaders: Mutex<HashMap<String, Leadership>>,
    mutexes: Mutex<HashMap<String, (Arc<Session>, EtcdMutex)>>,
}

fn s(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}
fn i(v: &Value, k: &str) -> i64 {
    v.get(k).and_then(Value::as_i64).unwrap_or_default()
}
fn u(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or_default()
}
fn b(v: &Value, k: &str) -> bool {
    v.get(k).and_then(Value::as_bool).unwrap_or_default()
}
fn t(v: &Value, k: &str) -> Time {
    let txt = s(v, k);
    if txt.is_empty() {
        return Time::zero();
    }
    parse_rfc3339(&txt).unwrap_or_else(Time::zero)
}
fn strs(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}
fn smap(v: &Value, k: &str) -> Option<BTreeMap<String, String>> {
    v.get(k).and_then(Value::as_object).map(|m| {
        m.iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
            .collect()
    })
}
fn lmap(v: &Value, k: &str) -> BTreeMap<String, Vec<String>> {
    v.get(k)
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, _)| (k.clone(), strs(&m.clone().into(), k)))
                .collect()
        })
        .unwrap_or_default()
}
fn spec(v: &Value, k: &str) -> Spec {
    let raw = v.get(k).map(|x| x.to_string()).unwrap_or_default();
    Spec::from_json(raw.as_bytes()).expect("the test sends valid specs")
}

fn node(v: &Value) -> Node {
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

fn server(v: &Value) -> Server {
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

fn cert(v: &Value) -> NodeCert {
    NodeCert {
        serial: s(v, "Serial"),
        not_after: t(v, "NotAfter"),
    }
}

fn grant(v: &Value) -> Grant {
    Grant {
        role: s(v, "Role"),
        space: s(v, "Space"),
    }
}

fn principal(v: &Value) -> Principal {
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

fn traffic(v: &Value, k: &str) -> Vec<TrafficTarget> {
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

fn job_run(v: &Value) -> JobRun {
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

fn ok<T: Serialize>(v: T) -> Result<Value> {
    Ok(serde_json::to_value(v).expect("answers encode"))
}

/// One store method with its arguments as the Go test sends them.
async fn call(st: &Etcd, method: &str, a: &Value) -> Result<Value> {
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

fn b64(b: &[u8]) -> String {
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

async fn client(stt: &State, req: &Value) -> Result<Client> {
    let ep = s(req, "endpoint");
    let mut cs = stt.clients.lock().await;
    if let Some(c) = cs.get(&ep) {
        return Ok(c.clone());
    }
    let c = Client::connect(&ep, Path::new(&s(req, "dir")))?;
    cs.insert(ep, c.clone());
    Ok(c)
}

async fn store(stt: &State, h: &str) -> Result<Etcd> {
    stt.stores
        .lock()
        .await
        .get(h)
        .cloned()
        .ok_or_else(|| Error::other(format!("no store {h}")))
}

/// The clocks and random sources of the handles: the Go test sets both
/// stores' clocks alike, and both follow one sequence of random bytes.
#[derive(Default)]
struct Hooks {
    now: HashMap<String, Arc<AtomicI64>>,
    rand: HashMap<String, Arc<AtomicU64>>,
}

static HOOKS: std::sync::OnceLock<std::sync::Mutex<Hooks>> = std::sync::OnceLock::new();

fn hooks() -> std::sync::MutexGuard<'static, Hooks> {
    HOOKS
        .get_or_init(|| std::sync::Mutex::new(Hooks::default()))
        .lock()
        .expect("not poisoned")
}

async fn handle(stt: &State, req: &Value) -> Result<Value> {
    let h = s(req, "handle");
    match s(req, "op").as_str() {
        "open" => {
            let c = client(stt, req).await?;
            let mut st = Etcd::new(c, &s(req, "prefix")).await?;
            let now = Arc::new(AtomicI64::new(i(req, "ms")));
            let ctr = Arc::new(AtomicU64::new(0));
            let n = now.clone();
            st.set_now(Arc::new(move || {
                let ms = n.load(Ordering::SeqCst);
                Time {
                    unix: ms.div_euclid(1000),
                    nsec: ms.rem_euclid(1000) * 1_000_000,
                    loc: Location::utc(),
                }
            }));
            let r = ctr.clone();
            st.set_random(Arc::new(move |buf: &mut [u8]| {
                let c = r.fetch_add(1, Ordering::SeqCst) + 1;
                for (j, x) in buf.iter_mut().enumerate() {
                    *x = (c.wrapping_mul(31).wrapping_add(j as u64) & 0xff) as u8;
                }
            }));
            {
                let mut hk = hooks();
                hk.now.insert(h.clone(), now);
                hk.rand.insert(h.clone(), ctr);
            }
            stt.stores.lock().await.insert(h, st);
            Ok(Value::Null)
        }
        "fenced" => {
            let from = store(stt, &s(req, "from")).await?;
            let f = from.fenced(&s(req, "key"), i(req, "rev"));
            stt.stores.lock().await.insert(h, f);
            Ok(Value::Null)
        }
        "setNow" => {
            let n = hooks()
                .now
                .get(&h)
                .cloned()
                .ok_or_else(|| Error::other("no clock"))?;
            n.store(i(req, "ms"), Ordering::SeqCst);
            Ok(Value::Null)
        }
        "call" => {
            let st = store(stt, &h).await?;
            let method = s(req, "method");
            let args = req.get("args").cloned().unwrap_or(Value::Null);
            let repeat = i(req, "repeat").max(1);
            let parallel = i(req, "parallel").max(1);
            if repeat == 1 {
                return call(&st, &method, &args).await;
            }
            let per = repeat / parallel;
            let mut tasks = Vec::new();
            for _ in 0..parallel {
                let st = st.clone();
                let (m, a) = (method.clone(), args.clone());
                tasks.push(tokio::spawn(async move {
                    for _ in 0..per {
                        call(&st, &m, &a).await?;
                    }
                    Ok::<(), Error>(())
                }));
            }
            for t in tasks {
                t.await.map_err(|e| Error::other(e.to_string()))??;
            }
            Ok(Value::Null)
        }
        "reencode" => {
            let st = store(stt, &h).await?;
            let d = st.reencode().await?;
            Ok(Value::Array(
                d.into_iter()
                    .map(|d| json!({"key": d.key, "stored": d.stored, "encoded": d.encoded}))
                    .collect(),
            ))
        }
        "campaign" => {
            let c = client(stt, req).await?;
            let l = Leadership::campaign(
                &c,
                Duration::from_secs(i(req, "ttl").max(1) as u64),
                &s(req, "name"),
            )
            .await?;
            let (key, rev) = l.fence();
            stt.leaders.lock().await.insert(h, l);
            Ok(json!({"key": key, "rev": rev}))
        }
        "resign" => {
            let l = stt
                .leaders
                .lock()
                .await
                .remove(&h)
                .ok_or_else(|| Error::other("no leadership"))?;
            l.resign().await?;
            Ok(Value::Null)
        }
        "leader" => {
            let c = client(stt, req).await?;
            Ok(Value::String(election::leader(&c).await?))
        }
        "lock" | "tryLock" => {
            let c = client(stt, req).await?;
            let sess = Arc::new(Session::new(&c, i(req, "ttl")).await?);
            let mut m = EtcdMutex::new(sess.clone(), &s(req, "prefix"));
            let r = if s(req, "op") == "lock" {
                m.lock().await
            } else {
                m.try_lock().await
            };
            if let Err(e) = r {
                let _ = sess.close().await;
                return Err(e);
            }
            let key = m.key().to_string();
            stt.mutexes.lock().await.insert(h, (sess, m));
            Ok(Value::String(key))
        }
        "unlock" => {
            let (sess, mut m) = stt
                .mutexes
                .lock()
                .await
                .remove(&h)
                .ok_or_else(|| Error::other("no lock"))?;
            m.unlock().await?;
            sess.close().await?;
            Ok(Value::Null)
        }
        op => Err(Error::other(format!(
            "armada-store-parity: unknown op {op}"
        ))),
    }
}

#[tokio::main]
async fn main() {
    let stt = Arc::new(State::default());
    let out = Arc::new(Mutex::new(tokio::io::stdout()));
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("armada-store-parity: {e}");
                continue;
            }
        };
        let (stt, out) = (stt.clone(), out.clone());
        tokio::spawn(async move {
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            let answer = match handle(&stt, &req).await {
                Ok(v) => json!({"id": id, "value": v}),
                Err(e) => json!({"id": id, "error": e.msg, "kind": e.kind.name()}),
            };
            let mut line = serde_json::to_vec(&answer).expect("answers encode");
            line.push(b'\n');
            let mut o = out.lock().await;
            let _ = o.write_all(&line).await;
            let _ = o.flush().await;
        });
    }
}

//! armada-spec-check: the recorded cases (tests/parity.rs) send it one JSON
//! request per line on stdin and compare each answer line with the
//! recorded answer. Never packed.

#![recursion_limit = "256"]

use std::collections::HashMap;
use std::io::{BufRead, Write};

use armada_spec::gotime::{Time, load_location, parse_rfc3339};
use armada_spec::validate as v;
use armada_spec::*;
use serde_json::{Value, json};

fn b64(s: &str) -> Vec<u8> {
    let val = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            _ => 63,
        }
    };
    let b: Vec<u8> = s.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::new();
    for q in b.chunks(4) {
        let mut n = 0u32;
        for &c in q {
            n = n << 6 | val(c);
        }
        n <<= 6 * (4 - q.len()) as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..q.len().saturating_sub(1)]);
    }
    out
}

fn err(r: Result<(), String>) -> Value {
    match r {
        Ok(()) => json!({"ok": true}),
        Err(e) => json!({"error": e}),
    }
}

fn s(a: &Value, i: usize) -> String {
    a.get(i)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn time_of(v: &Value) -> Time {
    let t = parse_rfc3339(v["t"].as_str().unwrap_or_default()).unwrap_or_else(Time::zero);
    match v["zone"].as_str() {
        Some(z) => t.in_loc(&load_location(z).unwrap_or_else(gotime::Location::utc)),
        None => t,
    }
}

fn app_from(v: &Value) -> Result<App, String> {
    App::from_json(v.as_str().unwrap_or_default().as_bytes())
}

/// The values of App's methods, in the recording's order.
fn summary(a: &App) -> Value {
    let (lo, hi) = a.scale_bounds();
    let ing = a.ingress.as_ref();
    let keys: HashMap<String, Vec<String>> = HashMap::from([
        (
            String::new(),
            vec![
                "database-url".into(),
                "API_KEY".into(),
                "port".into(),
                "armada-x".into(),
                "Bad-Key".into(),
            ],
        ),
        ("shared".into(), vec!["token".into(), "redis-url".into()]),
        ("db".into(), vec!["password".into(), "url".into()]),
    ]);
    let with = match a.with_secret_env(&keys) {
        Ok(c) => json!({"env": c.to_json()}),
        Err(e) => json!({"error": v::join(&e)}),
    };
    let backups: Vec<Value> = a
        .volumes
        .iter()
        .filter_map(|vol| vol.backup.as_ref())
        .map(|b| {
            let last = parse_rfc3339("2026-03-29T00:30:00Z").unwrap_or_else(Time::zero);
            json!({"next": b.next(&last).rfc3339_nano(), "location": b.location().name()})
        })
        .collect();
    let windows: Vec<Value> = a.scale.as_ref().map_or_else(Vec::new, |s| {
        s.rules
            .iter()
            .map(|r| {
                let now = parse_rfc3339("2026-11-25T08:59:30Z").unwrap_or_else(Time::zero);
                let (open, until) = r.window(&now);
                json!({"open": open, "until": until.rfc3339_nano()})
            })
            .collect()
    });
    let job_next = a.job_schedule().map(|sch| {
        let mut t = parse_rfc3339("2026-03-28T22:15:00Z").unwrap_or_else(Time::zero);
        let mut out = Vec::new();
        for _ in 0..5 {
            t = sch.next(&t);
            out.push(t.rfc3339_nano());
        }
        out
    });
    json!({
        "id": a.id(),
        "autoscaled": a.autoscaled(),
        "bounds": [lo, hi],
        "scalesToZero": a.scales_to_zero(),
        "idleAfter": a.idle_after(),
        "replicas": a.replicas(),
        "memoryBytes": a.memory_bytes(),
        "nanoCPUs": a.nano_cpus(),
        "cpuMillis": a.cpu_millis(),
        "multipleRevisions": a.multiple_revisions(),
        "queueRules": a.queue_rules().len(),
        "hasContainers": a.has_containers(),
        "containerNames": a.container_names(),
        "reservedCPUMillis": a.reserved_cpu_millis(),
        "reservedMemoryBytes": a.reserved_memory_bytes(),
        "failsOver": a.fails_over(),
        "hasVolumes": a.has_volumes(),
        "hasLocalVolumes": a.has_local_volumes(),
        "hasNFSVolumes": a.has_nfs_volumes(),
        "jobTimeout": a.job_timeout(),
        "jobHistory": a.job_history(),
        "jobTasks": a.job_tasks(),
        "jobParallelism": a.job_parallelism(),
        "jobConcurrency": a.job_concurrency(),
        "jobNext": job_next,
        "secretRefs": a.secret_refs(),
        "backupSecretRefs": a.backup_secret_refs(),
        "usesSpaceSecrets": a.uses_space_secrets(),
        "placement": Placement::string(a.placement.as_ref()),
        "spreadKey": Placement::spread_key(a.placement.as_ref()),
        "ipAllow": ing.map(|i| v::ip_ranges(&i.ip_allow)),
        "ipDeny": ing.map(|i| v::ip_ranges(&i.ip_deny)),
        "corsMethods": ing.and_then(|i| i.cors.as_ref()).map(Cors::cors_methods),
        "tcp": Ingress::tcp(ing),
        "searchDomain": v::internal_search_domain(&a.id()),
        "pollEvery": Trigger::poll_every(a.trigger.as_ref()),
        "maxRuns": Trigger::max_runs(a.trigger.as_ref()),
        "runsWanted": a.trigger.as_ref().map(|t| [0, 1, 7, 100, 1_000_000_000_000].map(|n| t.runs_wanted(n))),
        "queueName": a.queue_trigger().map(|q| q.name().to_string()),
        "withSecretEnv": with,
        "backups": backups,
        "windows": windows,
    })
}

fn call(f: &str, a: &Value) -> Value {
    match f {
        "ValidName" => json!(v::valid_name(&s(a, 0))),
        "ValidSpace" => json!(v::valid_space(&s(a, 0))),
        "ValidAppID" => json!(v::valid_app_id(&s(a, 0))),
        "SplitAppID" => match v::split_app_id(&s(a, 0)) {
            Some((sp, n)) => json!([sp, n, true]),
            None => json!(["", "", false]),
        },
        "AppID" => json!(v::app_id(&s(a, 0), &s(a, 1))),
        "InternalSearchDomain" => json!(v::internal_search_domain(&s(a, 0))),
        "ValidSearchDomain" => json!(v::valid_search_domain(&s(a, 0))),
        "ValidHostName" => json!(v::valid_host_name(&s(a, 0))),
        "LabelHost" => json!(v::label_host(&s(a, 0), &s(a, 1))),
        "InternalHost" => json!(v::internal_host(&s(a, 0))),
        "ValidRevisionName" => json!(v::valid_revision_name(&s(a, 0), &s(a, 1))),
        "CheckTCPPort" => err(v::check_tcp_port(
            a.get(0).and_then(Value::as_i64).unwrap_or_default(),
        )),
        "ValidateDomain" => err(v::validate_domain(&s(a, 0))),
        "ValidateRoutePath" => err(v::validate_route_path(&s(a, 0))),
        "ValidateProbePath" => err(v::validate_probe_path(&s(a, 0))),
        "ValidateName" => err(v::validate_name(&s(a, 0))),
        "ParseIPRange" => match v::parse_ip_range(&s(a, 0)) {
            Ok(p) => json!({"ok": p.string()}),
            Err(e) => json!({"error": e}),
        },
        "CheckNFSServer" => err(v::check_nfs_server(&s(a, 0))),
        "CheckNFSPath" => err(v::check_nfs_path(&s(a, 0))),
        "ParseOwner" => match v::parse_owner(&s(a, 0)) {
            Ok((u, g)) => json!({"ok": [u, g]}),
            Err(e) => json!({"error": e}),
        },
        "ParseMemory" => match v::parse_memory(&s(a, 0)) {
            Ok(n) => json!({"ok": n}),
            Err(e) => json!({"error": e}),
        },
        "ParseCPU" => match v::parse_cpu(&s(a, 0)) {
            Ok(n) => json!({"ok": n}),
            Err(e) => json!({"error": e}),
        },
        "ValidateSecretName" => err(v::validate_secret_name(&s(a, 0))),
        "ValidateSecretKey" => err(v::validate_secret_key(&s(a, 0))),
        "ValidateSecretRef" => err(v::validate_secret_ref(&s(a, 0))),
        "SplitSecretRef" => {
            let (x, y) = v::split_secret_ref(&s(a, 0));
            json!([x, y])
        }
        "SecretSource" => {
            let (x, y) = v::secret_source(&s(a, 0), &s(a, 1));
            json!([x, y])
        }
        "RegistryHost" => json!(v::registry_host(&s(a, 0))),
        "SecretEnvName" => json!(v::secret_env_name(&s(a, 0))),
        "ValidCORSOrigin" => json!(v::valid_cors_origin(&s(a, 0))),
        "ValidCORSHeader" => json!(v::valid_cors_header(&s(a, 0))),
        "CheckLabelKey" => err(v::check_label_key(&s(a, 0))),
        "CheckLabelValue" => err(v::check_label_value(&s(a, 0))),
        "CheckAdminLabel" => err(v::check_admin_label(&s(a, 0), &s(a, 1))),
        "ValidateVolumePath" => err(v::validate_volume_path(&s(a, 0))),
        "VarNameRe" => json!(vars::valid_var_name(&s(a, 0))),
        "FairOrder" => {
            let ids: Vec<String> = a
                .get(0)
                .and_then(Value::as_array)
                .map(|l| {
                    l.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            json!(fair_order(&ids))
        }
        "CheckTraffic" => {
            let app = s(a, 0);
            let traffic: Vec<TrafficTarget> = a
                .get(1)
                .and_then(Value::as_array)
                .map(|l| {
                    l.iter()
                        .map(|t| TrafficTarget {
                            revision: t["revision"].as_str().unwrap_or_default().to_string(),
                            weight: t["weight"].as_i64().unwrap_or_default(),
                            label: t["label"].as_str().unwrap_or_default().to_string(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let errs = v::check_traffic(
                &app,
                &traffic,
                a.get(2).and_then(Value::as_bool).unwrap_or_default(),
            );
            json!(errs.iter().map(ToString::to_string).collect::<Vec<_>>())
        }
        "CheckBackupPlan" => {
            let b = &a[0];
            let plan = VolumeBackup {
                every: Duration(b["every"].as_i64().unwrap_or_default()),
                schedule: b["schedule"].as_str().unwrap_or_default().to_string(),
                time_zone: b["timeZone"].as_str().unwrap_or_default().to_string(),
                keep: BackupKeep {
                    last: b["last"].as_i64().unwrap_or_default(),
                    hourly: b["hourly"].as_i64().unwrap_or_default(),
                    daily: b["daily"].as_i64().unwrap_or_default(),
                    weekly: b["weekly"].as_i64().unwrap_or_default(),
                    monthly: b["monthly"].as_i64().unwrap_or_default(),
                },
                ..VolumeBackup::default()
            };
            err(v::check_backup_plan(&plan))
        }
        "ParseDuration" => match go::parse_duration(&s(a, 0)) {
            Ok(d) => json!({"ok": d, "string": go::format_duration(d)}),
            Err(e) => json!({"error": e}),
        },
        "Schedule" => {
            // parseSchedule, then Next n times from a time in a zone.
            match spec::parse_schedule(&s(a, 0), &s(a, 1)) {
                Err(e) => json!({"error": e}),
                Ok(_) => {
                    let job = App {
                        schedule: s(a, 0),
                        time_zone: s(a, 1),
                        ..App::default()
                    };
                    let Some(app) = job.job_schedule() else {
                        return json!({"error": "no schedule"});
                    };
                    let mut t = time_of(&a[2]);
                    let n = a.get(3).and_then(Value::as_i64).unwrap_or(1);
                    let mut out = Vec::new();
                    for _ in 0..n {
                        t = app.next(&t);
                        out.push(t.rfc3339_nano());
                    }
                    json!({"ok": out})
                }
            }
        }
        "Window" => {
            let r = &a[0];
            let rule = ScaleRule {
                typ: r["type"].as_str().unwrap_or_default().to_string(),
                schedule: r["schedule"].as_str().unwrap_or_default().to_string(),
                time_zone: r["timeZone"].as_str().unwrap_or_default().to_string(),
                duration: Duration(r["duration"].as_i64().unwrap_or_default()),
                ..ScaleRule::default()
            };
            let now = time_of(&a[1]);
            let (open, until) = rule.window(&now);
            json!([open, until.rfc3339_nano()])
        }
        _ => json!({"unknown": f}),
    }
}

fn handle(req: &Value) -> Value {
    match req["op"].as_str().unwrap_or_default() {
        "parse" => {
            let data = b64(req["data"].as_str().unwrap_or_default());
            match parse_in(&data, req["space"].as_str().unwrap_or_default()) {
                Err(e) => json!({"error": e}),
                Ok(a) => {
                    let export = match a.export() {
                        Ok(b) => json!(String::from_utf8_lossy(&b)),
                        Err(e) => json!({"error": e}),
                    };
                    json!({"json": a.to_json(), "export": export, "summary": summary(&a)})
                }
            }
        }
        "substitute" => {
            let data = b64(req["data"].as_str().unwrap_or_default());
            let vars: HashMap<String, String> = req["vars"]
                .as_object()
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                        .collect()
                })
                .unwrap_or_default();
            match vars::substitute(&data, &vars) {
                Ok(out) => json!({"out": String::from_utf8_lossy(&out)}),
                Err(e) => json!({"error": e}),
            }
        }
        "json" => match app_from(&req["json"]) {
            Ok(a) => {
                let export = match a.export() {
                    Ok(b) => json!(String::from_utf8_lossy(&b)),
                    Err(e) => json!({"error": e}),
                };
                let valid = match a.validate() {
                    Ok(()) => Value::Null,
                    Err(e) => json!(v::join(&e)),
                };
                json!({"json": a.to_json(), "export": export, "validate": valid})
            }
            Err(e) => json!({"error": e}),
        },
        "call" => call(req["fn"].as_str().unwrap_or_default(), &req["args"]),
        other => json!({"unknown": other}),
    }
}

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::BufWriter::new(std::io::stdout());
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let req: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
        let resp = handle(&req);
        let _ = writeln!(out, "{resp}");
        let _ = out.flush();
    }
}

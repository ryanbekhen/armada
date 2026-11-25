//! armada-acme-parity: armada-server's ACME manager as a program, which
//! Go's tests in internal/certs (ARMADA_ACME_BIN) run beside Go's
//! certmagic manager against Pebble on one etcd member. Never packed.
//!
//! The first line on stdin is the configuration (JSON): the etcd member
//! (endpoint, dir), the storage prefix, the ACME directory, the account's
//! email, the cluster's DNS token (DNS-01 for wildcards and the root
//! domain), Cloudflare's API address and the resolvers to use (the
//! test's stand-ins), how often renewals are checked, and the responder's
//! listen address. The program answers `{"ready": {"responder"}}` once
//! its HTTP-01 responder listens. Later lines are requests, each answered
//! with `{"id", "error"?, ...}`: `manage` (names, root, dns: name →
//! {provider, token}), `certificate` (name → pem), `lock`/`unlock` (a
//! lock of the storage), `managed` (names), `close`. Certificates
//! obtained and failed attempts are reported as `{"event": "obtained" |
//! "failed", "name", "renewal", "error"?}`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use armada_server::acme::{Acme, Event, Options, responder};
use armada_server::certs::{Certs, Dns, EtcdStorage};
use armada_server::log::Logger;
use armada_store::Client;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::watch;

type Out = Arc<tokio::sync::Mutex<tokio::io::Stdout>>;

async fn emit(out: &Out, v: Value) {
    let mut line = v.to_string();
    line.push('\n');
    let mut o = out.lock().await;
    let _ = o.write_all(line.as_bytes()).await;
    let _ = o.flush().await;
}

fn s(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

#[tokio::main]
async fn main() {
    let out: Out = Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let Ok(Some(first)) = lines.next_line().await else {
        eprintln!("armada-acme-parity: no configuration on stdin");
        std::process::exit(2);
    };
    let cfg: Value = serde_json::from_str(&first).expect("the configuration is JSON");
    let log = if cfg.get("verbose").and_then(Value::as_bool) == Some(true) {
        Logger::stderr(true)
    } else {
        Logger::discard()
    };
    let client = Client::connect(&s(&cfg, "endpoint"), &PathBuf::from(s(&cfg, "dir")))
        .expect("connect to the etcd member");
    let storage = Arc::new(EtcdStorage::new(client, &s(&cfg, "prefix")).expect("the ACME storage"));
    let mut opts = Options::new(storage.clone(), &s(&cfg, "ca"));
    opts.email = s(&cfg, "email");
    opts.log = log;
    let token = s(&cfg, "dnsToken");
    if !token.is_empty() {
        opts.dns = Some(Dns {
            provider: "cloudflare".into(),
            token,
        });
    }
    let api = s(&cfg, "cloudflareApi");
    if !api.is_empty() {
        opts.cloudflare_api = api;
    }
    opts.resolvers = cfg
        .get("resolvers")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if let Some(ms) = cfg.get("renewCheckMs").and_then(Value::as_u64) {
        opts.renew_check_interval = Duration::from_millis(ms);
    }
    {
        let out = out.clone();
        opts.on_event = Some(Arc::new(move |e: Event| {
            let v = match e {
                Event::Obtained { name, renewal } => {
                    json!({"event": "obtained", "name": name, "renewal": renewal})
                }
                Event::Failed {
                    name,
                    renewal,
                    error,
                } => json!({"event": "failed", "name": name, "renewal": renewal, "error": error}),
            };
            let out = out.clone();
            tokio::spawn(async move { emit(&out, v).await });
        }));
    }
    let acme = Acme::new(opts).expect("the ACME manager");
    let lis = tokio::net::TcpListener::bind(s(&cfg, "responderListen"))
        .await
        .expect("listen for HTTP-01 challenges");
    let addr = lis.local_addr().map(|a| a.to_string()).unwrap_or_default();
    let (stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(responder::serve(
        lis,
        Arc::new(acme.clone()) as Arc<dyn Certs>,
        stop_rx,
    ));
    emit(&out, json!({"ready": {"responder": addr}})).await;
    while let Ok(Some(line)) = lines.next_line().await {
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("armada-acme-parity: {e}");
                continue;
            }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let answer = match s(&req, "op").as_str() {
            "manage" => {
                let names: Vec<String> = req
                    .get("names")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let mut dns = BTreeMap::new();
                if let Some(m) = req.get("dns").and_then(Value::as_object) {
                    for (n, d) in m {
                        dns.insert(
                            n.clone(),
                            Dns {
                                provider: s(d, "provider"),
                                token: s(d, "token"),
                            },
                        );
                    }
                }
                let err = acme
                    .manage(&names, &s(&req, "root"), &dns)
                    .await
                    .err()
                    .unwrap_or_default();
                json!({"id": id, "error": err})
            }
            "certificate" => {
                let pem = acme.certificate(&s(&req, "name")).await;
                json!({"id": id, "pem": pem.map(|p| String::from_utf8_lossy(&p).into_owned())})
            }
            "lock" => {
                let err = storage
                    .lock(&s(&req, "name"))
                    .await
                    .err()
                    .map(|e| e.to_string())
                    .unwrap_or_default();
                json!({"id": id, "error": err})
            }
            "unlock" => {
                let err = storage
                    .unlock(&s(&req, "name"))
                    .await
                    .err()
                    .map(|e| e.to_string())
                    .unwrap_or_default();
                json!({"id": id, "error": err})
            }
            "managed" => json!({"id": id, "names": acme.managed_names().await}),
            "close" => {
                acme.close().await;
                let _ = stop_tx.send(true);
                let _ = storage.close().await;
                emit(&out, json!({"id": id})).await;
                return;
            }
            op => json!({"id": id, "error": format!("unknown op {op:?}")}),
        };
        emit(&out, answer).await;
    }
    acme.close().await;
    let _ = storage.close().await;
}

//! armada-server-parity: the control plane Go's scenario parity tests run
//! as a program (internal/server, ARMADA_SERVER_BIN). Never packed.
//!
//! The first line on stdin is the configuration (JSON): the etcd member
//! (endpoint, dir) and the store's prefix, the CA, the server certificate,
//! the master key, the test clock's start, and the server's settings
//! (with `manualPasses`, a pass runs only on a `reconcile` request; with
//! `predictableIds`, replica IDs count up as the Go side's do). The
//! program answers `{"ready": {"api", "join", "joinLocal", "siteJoin",
//! "siteJoinLocal"}}` once it serves, on the addresses it bound (with
//! `meshJoin` the join listener, and with `siteJoin` the listener for
//! other sites, are named after a public address and listen on the
//! loopback one). Later lines are requests, each answered with
//! `{"id", "error"?}`: `now` (ms) sets the test clock, `reconcile` runs a
//! pass, `autoscale` an evaluation of the autoscaler, `backups` a round of
//! the backup loop answered once its backups ended (neither runs on its
//! own with `manualPasses`), `stop` ends the server. The server asks the test for the etcd
//! membership with `{"call", "cluster", ...}` lines, answered by
//! `{"op": "answer", "call", "value"?, "error"?}`, and tells it with
//! `{"event": "settingsChanged"}` that the cluster's settings changed.
//!
//! With `elect`, the program campaigns for leadership on the member and
//! runs terms on a store fenced on its election key, as `armadad server`
//! does, reporting `{"event": "leading", "api", "join"}` for each server a
//! term starts.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use armada_pki::Ca;
use armada_pki::encoding::base64_decode;
use armada_secrets::Keyring;
use armada_server::cluster::{Cluster, MemberInfo};
use armada_server::{Config, Server, lifecycle, log::Logger, tls::ServerCert};
use armada_store::{Client, Etcd};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{oneshot, watch};
use tonic::codegen::async_trait;

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
fn i(v: &Value, k: &str) -> i64 {
    v.get(k).and_then(Value::as_i64).unwrap_or_default()
}
fn b(v: &Value, k: &str) -> bool {
    v.get(k).and_then(Value::as_bool).unwrap_or_default()
}
fn ms(v: &Value, k: &str) -> Duration {
    Duration::from_millis(i(v, k).max(0) as u64)
}

/// The etcd membership the test keeps, asked over the control channel.
struct RemoteCluster {
    out: Out,
    next: AtomicU64,
    waiting: Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>,
}

impl RemoteCluster {
    async fn call(&self, mut req: Value) -> Result<Value, String> {
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let (tx, rx) = oneshot::channel();
        self.waiting
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, tx);
        req["call"] = json!(id);
        emit(&self.out, req).await;
        let ans = rx.await.map_err(|_| "the test went away".to_string())?;
        let err = s(&ans, "error");
        if !err.is_empty() {
            return Err(err);
        }
        Ok(ans.get("value").cloned().unwrap_or(Value::Null))
    }
}

fn member(v: &Value) -> MemberInfo {
    MemberInfo {
        id: v.get("ID").and_then(Value::as_u64).unwrap_or_default(),
        name: s(v, "Name"),
        learner: b(v, "Learner"),
        client_url: s(v, "ClientURL"),
    }
}

#[async_trait]
impl Cluster for RemoteCluster {
    async fn members(&self) -> Result<Vec<MemberInfo>, String> {
        let v = self.call(json!({"cluster": "Members"})).await?;
        Ok(v.as_array()
            .map(|a| a.iter().map(member).collect())
            .unwrap_or_default())
    }

    async fn add_learner(
        &self,
        name: &str,
        addr: IpAddr,
        peer_port: u16,
    ) -> Result<(u64, String), String> {
        let v = self
            .call(json!({"cluster": "AddLearner", "name": name, "addr": addr.to_string(), "port": peer_port}))
            .await?;
        Ok((
            v.get("id").and_then(Value::as_u64).unwrap_or_default(),
            s(&v, "initial"),
        ))
    }

    async fn promote(&self) -> Result<Vec<String>, String> {
        let v = self.call(json!({"cluster": "Promote"})).await?;
        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn reachable(&self, m: &MemberInfo) -> bool {
        self.call(json!({"cluster": "Reachable", "member": {"ID": m.id, "Name": m.name, "Learner": m.learner, "ClientURL": m.client_url}}))
            .await
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    async fn remove_member(&self, id: u64) -> Result<(), String> {
        self.call(json!({"cluster": "RemoveMember", "id": id}))
            .await
            .map(|_| ())
    }
}

struct Setup {
    cfg: Value,
    client: Client,
    store: Etcd,
    ca: Arc<Ca>,
    cert: Arc<ServerCert>,
    keys: Option<Arc<Keyring>>,
    clock: Arc<AtomicI64>,
    ids: Arc<AtomicU64>,
    cluster: Option<Arc<dyn Cluster>>,
    out: Out,
    log: Logger,
}

impl Setup {
    fn config(&self, store: Etcd, api: &str, join: Option<std::net::TcpListener>) -> Config {
        let c = &self.cfg;
        let mut cfg = Config::new(store, self.cert.clone());
        cfg.ca = Some(self.ca.clone());
        cfg.keys = self.keys.clone();
        cfg.name = s(c, "name");
        cfg.api_addr = api.to_string();
        if let Some(j) = join {
            cfg.join_addr = j.local_addr().map(|a| a.to_string()).unwrap_or_default();
            cfg.join_listener = Some(j);
        }
        cfg.join_idle = ms(c, "joinIdleMs");
        cfg.join_burst = i(c, "joinBurst").max(0) as u32;
        cfg.node_cert_validity = Duration::from_secs(i(c, "nodeCertValiditySeconds").max(0) as u64);
        cfg.resync = ms(c, "resyncMs");
        cfg.stream_recheck = ms(c, "streamRecheckMs");
        cfg.node_lost_timeout = Duration::from_secs(i(c, "nodeLostSeconds").max(0) as u64);
        let clock = self.clock.clone();
        cfg.clock = Some(Arc::new(move || {
            armada_store::gojson::from_ms(clock.load(Ordering::SeqCst))
        }));
        cfg.cluster = self.cluster.clone();
        cfg.tls_on = b(c, "tls");
        cfg.acme_email = s(c, "acmeEmail");
        cfg.acme_ca = s(c, "acmeCa");
        cfg.dns_provider = s(c, "dnsProvider");
        cfg.metrics_addr = s(c, "metricsAddr");
        cfg.plain_http = b(c, "plainHttp");
        cfg.drain_timeout = ms(c, "drainTimeoutMs");
        cfg.warmup = ms(c, "warmupMs");
        cfg.progress_deadline = ms(c, "progressDeadlineMs");
        cfg.manual_passes = b(c, "manualPasses");
        if b(c, "predictableIds") {
            let next = self.ids.clone();
            cfg.new_id = Some(Arc::new(move |n| {
                predictable_id(next.fetch_add(1, Ordering::SeqCst) + 1, n)
            }));
        }
        cfg.log = self.log.clone();
        cfg
    }
}

/// The test's predictable replica IDs: the count of IDs made so far, in
/// base 36 over the alphabet of random IDs (Go's parityID).
fn predictable_id(k: u64, n: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = vec![b'a'; n];
    let mut k = k;
    for c in out.iter_mut().rev() {
        *c = ALPHABET[(k % 36) as usize];
        k /= 36;
    }
    String::from_utf8(out).unwrap_or_default()
}

#[tokio::main]
async fn main() {
    let out: Out = Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let Ok(Some(first)) = lines.next_line().await else {
        eprintln!("armada-server-parity: no configuration on stdin");
        std::process::exit(2);
    };
    let cfg: Value = serde_json::from_str(&first).expect("the configuration is JSON");
    let log = if b(&cfg, "verbose") {
        Logger::stderr(true)
    } else {
        Logger::discard()
    };
    let client = Client::connect(&s(&cfg, "endpoint"), &PathBuf::from(s(&cfg, "dir")))
        .expect("connect to the etcd member");
    let clock = Arc::new(AtomicI64::new(i(&cfg, "nowMs")));
    let mut store = Etcd::new(client.clone(), &s(&cfg, "prefix"))
        .await
        .expect("open the store");
    {
        let clock = clock.clone();
        store.set_now(Arc::new(move || {
            armada_store::gojson::from_ms(clock.load(Ordering::SeqCst))
        }));
    }
    let ca = Arc::new(
        Ca::load(s(&cfg, "caCert").as_bytes(), s(&cfg, "caKey").as_bytes()).expect("load the CA"),
    );
    let cert = ServerCert::new(
        s(&cfg, "caCert").as_bytes(),
        s(&cfg, "serverCert").as_bytes(),
        s(&cfg, "serverKey").as_bytes(),
    )
    .expect("load the server certificate");
    let keys = match s(&cfg, "masterKey") {
        k if k.is_empty() => None,
        k => Some(Arc::new(
            Keyring::new(&base64_decode(k.as_bytes()).expect("base64 master key"))
                .expect("load the master key"),
        )),
    };
    let waiting: Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>> = Arc::default();
    let cluster: Option<Arc<dyn Cluster>> = b(&cfg, "cluster").then(|| {
        Arc::new(RemoteCluster {
            out: out.clone(),
            next: AtomicU64::new(0),
            waiting: waiting.clone(),
        }) as Arc<dyn Cluster>
    });
    let setup = Arc::new(Setup {
        cfg: cfg.clone(),
        client,
        store,
        ca,
        cert,
        keys,
        clock: clock.clone(),
        ids: Arc::default(),
        cluster,
        out: out.clone(),
        log,
    });
    let (stop_tx, stop_rx) = watch::channel(false);
    let current: Arc<Mutex<Option<Server>>> = Arc::default();
    let done = if b(&cfg, "elect") {
        tokio::spawn(elect(setup.clone(), stop_rx, current.clone()))
    } else {
        tokio::spawn(serve(setup.clone(), stop_rx, current.clone()))
    };
    while let Ok(Some(line)) = lines.next_line().await {
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("armada-server-parity: {e}");
                continue;
            }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        match s(&req, "op").as_str() {
            "answer" => {
                let call = req.get("call").and_then(Value::as_u64).unwrap_or_default();
                if let Some(tx) = waiting
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&call)
                {
                    let _ = tx.send(req);
                }
            }
            "now" => {
                clock.store(i(&req, "ms"), Ordering::SeqCst);
                emit(&out, json!({"id": id})).await;
            }
            "reconcile" => {
                let srv = current.lock().unwrap_or_else(|p| p.into_inner()).clone();
                let out = out.clone();
                tokio::spawn(async move {
                    let err = match srv {
                        None => "no server".to_string(),
                        Some(srv) => srv
                            .reconcile()
                            .await
                            .err()
                            .map(|e| e.to_string())
                            .unwrap_or_default(),
                    };
                    emit(&out, json!({"id": id, "error": err})).await;
                });
            }
            "autoscale" => {
                let srv = current.lock().unwrap_or_else(|p| p.into_inner()).clone();
                let out = out.clone();
                tokio::spawn(async move {
                    let err = match srv {
                        None => "no server".to_string(),
                        Some(srv) => srv
                            .autoscale()
                            .await
                            .err()
                            .map(|e| e.to_string())
                            .unwrap_or_default(),
                    };
                    emit(&out, json!({"id": id, "error": err})).await;
                });
            }
            "backups" => {
                let srv = current.lock().unwrap_or_else(|p| p.into_inner()).clone();
                let out = out.clone();
                tokio::spawn(async move {
                    let err = match srv {
                        None => "no server".to_string(),
                        Some(srv) => match srv.schedule_backups(None).await {
                            Err(e) => e.to_string(),
                            Ok(runs) => {
                                for r in runs {
                                    let _ = r.await;
                                }
                                String::new()
                            }
                        },
                    };
                    emit(&out, json!({"id": id, "error": err})).await;
                });
            }
            "stop" => {
                let _ = stop_tx.send(true);
                let _ = tokio::time::timeout(Duration::from_secs(10), done).await;
                emit(&out, json!({"id": id})).await;
                std::process::exit(0);
            }
            other => {
                emit(
                    &out,
                    json!({"id": id, "error": format!("unknown op {other:?}")}),
                )
                .await;
            }
        }
    }
    let _ = stop_tx.send(true);
}

/// One server on the unfenced store, as the Go tests build theirs.
async fn serve(
    setup: Arc<Setup>,
    stop: watch::Receiver<bool>,
    current: Arc<Mutex<Option<Server>>>,
) {
    let lis = tokio::net::TcpListener::bind(s(&setup.cfg, "apiListen"))
        .await
        .expect("listen for the API");
    let api = lis.local_addr().expect("a bound address").to_string();
    let join = b(&setup.cfg, "join")
        .then(|| std::net::TcpListener::bind("127.0.0.1:0").expect("listen for joins"));
    let join_addr = join
        .as_ref()
        .and_then(|j| j.local_addr().ok())
        .map(|a| a.to_string())
        .unwrap_or_default();
    let mut cfg = setup.config(setup.store.clone(), &api, join);
    // A mesh cluster's join listener (ADR 0049), or the leader's endpoint
    // for machines of other sites (ADR 0050): listening on the loopback
    // address, named after a public one.
    let public = |port: &str| format!("203.0.113.1:{port}");
    let port_of = |a: &str| {
        a.rsplit_once(':')
            .map(|(_, p)| p.to_string())
            .unwrap_or_default()
    };
    let mut join_public = join_addr.clone();
    if b(&setup.cfg, "meshJoin") {
        join_public = public(&port_of(&join_addr));
        cfg.join_addr = join_public.clone();
        cfg.join_public = true;
    }
    let (mut site, mut site_local) = (String::new(), String::new());
    if b(&setup.cfg, "siteJoin") {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("listen for other sites");
        site_local = l.local_addr().map(|a| a.to_string()).unwrap_or_default();
        site = public(&port_of(&site_local));
        cfg.join_site_addr = site.clone();
        cfg.join_site_listener = Some(l);
    }
    let out = setup.out.clone();
    cfg.on_settings_changed = Some(Arc::new(move || {
        let out = out.clone();
        tokio::spawn(async move { emit(&out, json!({"event": "settingsChanged"})).await });
    }));
    let srv = Server::new(cfg).expect("build the server");
    *current.lock().unwrap_or_else(|p| p.into_inner()) = Some(srv.clone());
    emit(
        &setup.out,
        json!({"ready": {"api": api, "join": join_public, "joinLocal": join_addr, "siteJoin": site, "siteJoinLocal": site_local}}),
    )
    .await;
    if let Err(e) = srv.serve(lis, stop).await {
        eprintln!("armada-server-parity: serve: {e}");
    }
}

/// Terms while this program leads, as `armadad server` runs them.
async fn elect(
    setup: Arc<Setup>,
    stop: watch::Receiver<bool>,
    current: Arc<Mutex<Option<Server>>>,
) {
    let api = s(&setup.cfg, "apiListen");
    emit(&setup.out, json!({"ready": {"api": api, "join": ""}})).await;
    let name = s(&setup.cfg, "name");
    let ttl = Duration::from_secs(i(&setup.cfg, "leaseSeconds").max(1) as u64);
    let res = lifecycle::lead(
        &setup.client,
        &name,
        ttl,
        &setup.log,
        stop.clone(),
        || {
            let st = setup.store.clone();
            let log = setup.log.clone();
            let mut stop = stop.clone();
            async move { lifecycle::wait_lead_ready(&st, &log, &mut stop).await }
        },
        |lead, tstop| {
            let setup = setup.clone();
            let current = current.clone();
            let api = api.clone();
            async move {
                lifecycle::term(
                    &setup.store,
                    &lead,
                    &setup.log,
                    tstop,
                    |fenced, restart, run_stop| {
                        let setup = setup.clone();
                        let current = current.clone();
                        let api = api.clone();
                        async move {
                            let lis = tokio::net::TcpListener::bind(&api)
                                .await
                                .map_err(|e| e.to_string())?;
                            let mut cfg = setup.config(fenced, &api, None);
                            cfg.on_settings_changed = Some(restart);
                            let srv = Server::new(cfg)?;
                            *current.lock().unwrap_or_else(|p| p.into_inner()) = Some(srv.clone());
                            emit(&setup.out, json!({"event": "leading", "api": api})).await;
                            srv.serve(lis, run_stop).await
                        }
                    },
                )
                .await
            }
        },
    )
    .await;
    if let Err(e) = res {
        emit(&setup.out, json!({"event": "failed", "error": e})).await;
    }
}

//! One scenario's replay: its steps against the Rust server, each answer
//! normalized and compared with Go's.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use armada_pki::{Ca, Certificate, Identity, IssueRequest, SERVER_NAME, parse_cert_pem};
use armada_proto::etcd::etcdserverpb::TxnRequest;
use armada_secrets::{Keyring, Value as SecretValue};
use armada_server::certs::{
    EtcdStorage, issuer_key, load_bundle, safe, site_cert, site_private_key,
};
use armada_store::client::op;
use armada_store::gojson::from_ms;
use armada_store::{Client, Etcd, NodeCert};
use serde_json::{Value, json};
use tonic::transport::Channel;

use super::gojson;
use super::grpc::{self, Item, Stream};
use super::methods::{decode_response, encode_request};
use super::norm::Norm;
use super::program::{Cluster, Program};
use super::standins::{self, Bucket, Sinks};
use super::volumes;
use super::watch::Watch;

const CONNECT: &str = "/armada.v1.AgentService/Connect";

/// A recording (internal/server/parity_record_test.go writes them).
pub struct Fixture {
    pub name: String,
    pub skip: Option<String>,
    pub config: Value,
    pub steps: Vec<Value>,
}

impl Fixture {
    pub fn parse(b: &[u8]) -> Result<Fixture, String> {
        let v: Value = serde_json::from_slice(b).map_err(|e| e.to_string())?;
        Ok(Fixture {
            name: v["name"].as_str().unwrap_or_default().to_string(),
            skip: v.get("skip").and_then(Value::as_str).map(str::to_string),
            config: v.get("config").cloned().unwrap_or(Value::Null),
            steps: v
                .get("steps")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        })
    }
}

/// What every scenario shares: the etcd member.
pub struct Shared {
    pub client: Client,
    pub socket: std::path::PathBuf,
    pub n: std::sync::atomic::AtomicUsize,
}

/// A fake agent's session (Go's parityAgent).
struct Agent {
    node: String,
    stream: Stream,
    /// Messages read while connecting, not yet drained.
    queue: VecDeque<Vec<u8>>,
    /// How the session ended, once it did and nobody asked yet.
    end: Option<Item>,
    ended: bool,
    last: Option<Value>,
    others: Vec<Value>,
    /// The connection the session is on, and what answers its volume
    /// requests once the scenario serves them.
    ch: Channel,
    volume: Arc<Mutex<Option<volumes::Handler>>>,
    /// What answers its log and exec requests once the scenario serves
    /// them (watchAgent).
    watch: Arc<Mutex<Option<Arc<Watch>>>>,
}

/// What the certificate scenarios keep: the fixture bundles (made with
/// the replay's CA) and certmagic's storage of the run.
struct Acme {
    prefix: String,
    issuer: String,
    bundles: Vec<(Vec<u8>, Vec<u8>)>,
    storage: Arc<EtcdStorage>,
    /// Another storage's lock being taken, and its outcome once known.
    other: Arc<EtcdStorage>,
    lock: Option<tokio::task::JoinHandle<Result<(), String>>>,
    taken: Option<bool>,
    /// A lock held as Go's mutex holds it: its lease and key.
    foreign: Option<(i64, String)>,
}

struct Run<'a> {
    shared: &'a Shared,
    ca: Ca,
    ca_pem: Vec<u8>,
    st: Etcd,
    prefix: String,
    clock: Arc<AtomicI64>,
    prog: Program,
    cluster: Arc<Mutex<Cluster>>,
    keys: Keyring,
    norm: Norm,
    conns: HashMap<i64, Channel>,
    streams: HashMap<i64, (String, Stream)>,
    agents: HashMap<String, Agent>,
    buckets: HashMap<i64, Arc<Mutex<volumes::Bucket>>>,
    raws: HashMap<i64, Value>,
    diffs: Vec<String>,
    note: String,
    /// Addresses of the stand-ins and listeners besides the program's.
    addrs: HashMap<String, String>,
    /// The streams opened with each cancelable context.
    ctxs: HashMap<i64, Vec<i64>>,
    sinks: Option<Sinks>,
    bucket: Option<Bucket>,
    acme: Option<Acme>,
    start_ms: i64,
    /// The metrics listener's port and the one recorded: the cluster's
    /// metrics port is the listener's, so the replay's reads as Go's.
    metrics_port: Option<(i64, i64)>,
}

fn s<'v>(v: &'v Value, k: &str) -> &'v str {
    v.get(k).and_then(Value::as_str).unwrap_or_default()
}

fn n(v: &Value, k: &str) -> i64 {
    v.get(k).and_then(Value::as_i64).unwrap_or_default()
}

/// The test's master key (Go's parityFixtures: bytes 1 to 32).
fn master_key() -> Vec<u8> {
    (1..=32).collect()
}

fn free_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
    l.local_addr().expect("an address").to_string()
}

/// Replays f, returning the differences from Go's answers (empty when
/// there are none).
pub async fn replay(shared: &Shared, f: &Fixture) -> Result<Vec<String>, String> {
    let cfg = &f.config;
    let i = shared.n.fetch_add(1, Ordering::SeqCst) + 1;
    let prefix = format!("/test/{i}/");
    let clock = Arc::new(AtomicI64::new(n(cfg, "startMs")));
    let mut st = Etcd::new(shared.client.clone(), &prefix)
        .await
        .map_err(|e| e.to_string())?;
    {
        let clock = clock.clone();
        st.set_now(Arc::new(move || from_ms(clock.load(Ordering::SeqCst))));
    }
    st.know_user("ryan").await.map_err(|e| e.to_string())?;
    let ca = Ca::new("test").map_err(|e| e.to_string())?;
    let (server_cert, server_key) = ca
        .issue(&IssueRequest {
            identity: Identity::new("server", "cp-1"),
            dns_names: vec![SERVER_NAME.to_string()],
            ips: Vec::new(),
            server: true,
            client: false,
            validity: Duration::ZERO,
        })
        .map_err(|e| e.to_string())?;
    let ca_pem = ca.cert_pem.clone();
    let ca_key = ca.key_pem().expose().to_vec();
    let acme = free_addr();
    let b = |k: &str| cfg.get(k).and_then(Value::as_bool).unwrap_or_default();
    let sinks = if b("alerts") {
        Some(Sinks::start().await?)
    } else {
        None
    };
    let bucket = if b("cpBackups") {
        Some(Bucket::start(clock.clone()).await?)
    } else {
        None
    };
    let metrics = if b("metrics") {
        free_addr()
    } else {
        String::new()
    };
    let mut conf = json!({
        "etcdSocket": shared.socket, "prefix": prefix,
        "caCert": String::from_utf8_lossy(&ca_pem), "caKey": String::from_utf8_lossy(&ca_key),
        "serverCert": String::from_utf8_lossy(&server_cert),
        "serverKey": String::from_utf8_lossy(server_key.expose()),
        "name": "cp-1", "apiListen": "127.0.0.1:0", "join": b("join"),
        "nowMs": n(cfg, "startMs"), "resyncMs": 3_600_000,
        "streamRecheckMs": 100,
        "nodeLostSeconds": n(cfg, "nodeLostSeconds"),
        "nodeCertValiditySeconds": n(cfg, "nodeCertValiditySeconds"),
        "cluster": b("cluster"), "joinBurst": n(cfg, "joinBurst"),
        "verbose": std::env::var_os("ARMADA_SERVER_VERBOSE").is_some(),
        "drainTimeoutMs": n(cfg, "drainTimeoutMs"), "warmupMs": n(cfg, "warmupMs"),
        "progressDeadlineMs": n(cfg, "progressDeadlineMs"), "plainHttp": b("plainHttp"),
        "manualPasses": true, "predictableIds": true,
        "meshJoin": b("meshJoin"), "siteJoin": b("siteJoin"),
        "certs": b("certs"), "wildcard": b("wildcard"), "tls": b("certs"),
        "acmePrefix": format!("/test/{i}-acme/"), "acmeDirectory": ACME_DIRECTORY,
        "acmeAddr": acme, "cpBackups": b("cpBackups"),
    });
    if !metrics.is_empty() {
        conf["metricsAddr"] = json!(metrics);
        conf["metricsCacheNs"] = json!(1);
    }
    if let Some(s) = &sinks {
        conf["telegramApi"] = json!(format!("{}/telegram", s.url));
    }
    let mut env = Vec::new();
    if let Some(b) = &bucket {
        env.push(("ARMADA_NODE_TEST_BUCKET_ADDR", b.addr.clone()));
    }
    if b("masterKey") {
        conf["masterKey"] = json!(armada_pki::encoding::base64_encode(&master_key()));
    }
    let cluster = Arc::new(Mutex::new(Cluster::new()));
    let prog = Program::start(&conf, cluster.clone(), &env).await?;
    let ca_cert = parse_cert_pem(&ca_pem).map_err(|e| e.to_string())?;
    let mut norm = Norm::new(ca_cert, ca_key, master_key());
    norm.alias(&prog.addr("api"), "<api>");
    norm.alias(&acme, "<acme>");
    norm.alias(&prog.addr("join"), "<join>");
    norm.alias(&prog.addr("siteJoin"), "<site-join>");
    let mut addrs = HashMap::new();
    if let Some(s) = &sinks {
        addrs.insert("sinks".to_string(), s.url.clone());
        addrs.insert("smtp".to_string(), s.smtp.clone());
        norm.alias(s.url.trim_start_matches("http://"), "<sinks>");
    }
    if !metrics.is_empty() {
        addrs.insert("metrics".to_string(), metrics.clone());
    }
    let acme_state = if b("certs") {
        let prefix = format!("/test/{i}-acme/");
        let storage = |c: &Client| EtcdStorage::new(c.clone(), &prefix).map_err(|e| e.to_string());
        let mut bundles = Vec::new();
        for n in 0..2 {
            let (c, k) = ca
                .issue(&IssueRequest {
                    identity: Identity::new("server", &format!("site-{n}")),
                    dns_names: vec!["example.org".into()],
                    ips: Vec::new(),
                    server: true,
                    client: false,
                    validity: Duration::ZERO,
                })
                .map_err(|e| e.to_string())?;
            let pair = (c, k.expose().to_vec());
            let (pem, sum) = bundle_served(&pair);
            norm.alias(
                &armada_pki::encoding::base64_encode(&pem),
                &format!("<bundle {n}>"),
            );
            norm.alias(
                &armada_pki::encoding::base64_encode(&sum),
                &format!("<bundle {n} sha256>"),
            );
            bundles.push(pair);
        }
        Some(Acme {
            issuer: issuer_key(ACME_DIRECTORY),
            bundles,
            storage: Arc::new(storage(&shared.client)?),
            other: Arc::new(storage(&shared.client)?),
            lock: None,
            taken: None,
            foreign: None,
            prefix,
        })
    } else {
        None
    };
    if b("cluster") {
        let srv = json!({"server": {"Name": "cp-1", "PrivateIP": "10.0.0.1", "APIAddr": prog.addr("api"), "MemberID": 100}});
        armada_store::parity_call::call(&st, "UpsertServer", &srv)
            .await
            .map_err(|e| e.to_string())?;
    }
    let mut run = Run {
        shared,
        ca,
        ca_pem,
        st,
        prefix,
        clock,
        prog,
        cluster,
        keys: Keyring::new(&master_key()).map_err(|e| e.to_string())?,
        norm,
        conns: HashMap::new(),
        streams: HashMap::new(),
        agents: HashMap::new(),
        buckets: HashMap::new(),
        raws: HashMap::new(),
        diffs: Vec::new(),
        note: String::new(),
        addrs,
        ctxs: HashMap::new(),
        sinks,
        bucket,
        acme: acme_state,
        start_ms: n(cfg, "startMs"),
        metrics_port: metrics
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .map(|p| (p, n(cfg, "metricsPort"))),
    };
    let res = run.steps(&f.steps).await;
    if let Some(a) = &mut run.acme {
        if let Some(h) = a.lock.take() {
            h.abort();
        }
        let _ = a.other.close().await;
        let _ = a.storage.close().await;
    }
    run.agents.clear();
    run.streams.clear();
    run.prog.stop();
    res?;
    Ok(run.diffs)
}

/// A step's outcome to compare: Go's answer and the replay's.
struct Seen {
    key: &'static str,
    got: Value,
    raw: Option<Value>,
}

impl Run<'_> {
    async fn steps(&mut self, steps: &[Value]) -> Result<(), String> {
        for (i, step) in steps.iter().enumerate() {
            if self.diffs.len() >= 5 {
                self.diffs.push("too many differences".into());
                return Ok(());
            }
            if s(step, "op") == "poll" {
                self.poll(i, step).await?;
                continue;
            }
            let seen = self
                .step(step)
                .await
                .map_err(|e| format!("step {i} ({}): {e}", what(step)))?;
            for d in self.compare(step, seen) {
                self.diffs.push(format!(
                    "step {i} ({}) after note {:?}:\n{d}",
                    what(step),
                    self.note
                ));
            }
        }
        Ok(())
    }

    /// Compares what a step saw with Go's answers, keeping its raw answer
    /// for later references; the differences.
    fn compare(&mut self, step: &Value, seen: Vec<Seen>) -> Vec<String> {
        let mut out = Vec::new();
        let store = s(step, "op") == "store";
        let events = store && s(step, "method") == "ListEvents";
        for sn in seen {
            let mut want = step.get(sn.key).cloned().unwrap_or(Value::Null);
            let mut got = sn.got.clone();
            if let Some((own, recorded)) = self.metrics_port {
                metrics_port(&mut got, own, recorded);
            }
            let mut got = self.norm.encode(&got);
            if store {
                // The store's answers as its parity tests compare them:
                // an empty list or map reads as none (Go's nil), and
                // events of one instant in any order (their keys end in
                // random hex).
                canon(&mut want, events);
                canon(&mut got, events);
            }
            if !gojson::equal(&want, &got) {
                out.push(diff(sn.key, &want, &got));
            }
            if let (Some(id), Some(raw)) = (step.get("id").and_then(Value::as_i64), sn.raw) {
                self.raws.insert(id, raw);
            }
        }
        out
    }

    /// A poll: its reads repeated until they give Go's answers.
    async fn poll(&mut self, i: usize, step: &Value) -> Result<(), String> {
        let inner = step["steps"].as_array().cloned().unwrap_or_default();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let saved = self.norm.clone();
            let saved_raws = self.raws.clone();
            let mut bad = Vec::new();
            for (j, st) in inner.iter().enumerate() {
                let seen = self
                    .step(st)
                    .await
                    .map_err(|e| format!("step {i}.{j} ({}): {e}", what(st)))?;
                for d in self.compare(st, seen) {
                    bad.push(format!(
                        "step {i}.{j} ({}, waiting for {}) after note {:?}:\n{d}",
                        what(st),
                        s(step, "what"),
                        self.note
                    ));
                }
            }
            if bad.is_empty() {
                return Ok(());
            }
            if Instant::now() > deadline {
                self.diffs.extend(bad);
                return Ok(());
            }
            self.norm = saved;
            self.raws = saved_raws;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn step(&mut self, step: &Value) -> Result<Vec<Seen>, String> {
        let one = |got: Value, raw: Option<Value>| {
            vec![Seen {
                key: "expect",
                got,
                raw,
            }]
        };
        match s(step, "op") {
            "note" => {
                self.note = s(step, "label").to_string();
                Ok(Vec::new())
            }
            "alias" => {
                let v = self.resolve(&step["value"])?;
                self.norm
                    .alias(v.as_str().unwrap_or_default(), s(step, "name"));
                Ok(Vec::new())
            }
            "dial" => {
                let kind = s(step, "kind");
                let name = s(step, "name");
                let (cert, key) = self
                    .ca
                    .issue(&IssueRequest {
                        identity: Identity::new(kind, name),
                        dns_names: Vec::new(),
                        ips: Vec::new(),
                        server: false,
                        client: true,
                        validity: Duration::ZERO,
                    })
                    .map_err(|e| e.to_string())?;
                if kind == "node" && step["record"].as_bool() == Some(true) {
                    let c = parse_cert_pem(&cert).map_err(|e| e.to_string())?;
                    // A node that is not registered stays unrecorded (and
                    // refused).
                    let _ = self.st.record_node_cert(name, &node_cert(&c), "").await;
                }
                let tls = grpc::tls(&self.ca_pem, Some((&cert, key.expose())))?;
                self.conns
                    .insert(n(step, "conn"), grpc::channel(&self.prog.addr("api"), tls));
                Ok(Vec::new())
            }
            "dialPEM" => {
                let cert = self.resolve(&step["cert"])?;
                let key = self.resolve(&step["key"])?;
                let tls = grpc::tls(
                    &self.ca_pem,
                    Some((
                        cert.as_str().unwrap_or_default().as_bytes(),
                        key.as_str().unwrap_or_default().as_bytes(),
                    )),
                )?;
                self.conns
                    .insert(n(step, "conn"), grpc::channel(&self.prog.addr("api"), tls));
                Ok(Vec::new())
            }
            "dialJoin" => {
                let addr = self.resolve(&step["addr"])?;
                let tls = grpc::tls(&self.ca_pem, None)?;
                self.conns.insert(
                    n(step, "conn"),
                    grpc::channel(addr.as_str().unwrap_or_default(), tls),
                );
                Ok(Vec::new())
            }
            "call" => {
                let path = s(step, "method").to_string();
                let req = encode_request(&path, &self.resolve(&step["req"])?)?;
                let mut call = Stream::open(self.conn(step)?, &path);
                call.send(req);
                call.close_send();
                let header = step.get("header").is_some();
                let servers = if header {
                    Some(call.header().await)
                } else {
                    None
                };
                let (got, raw) = match call.recv().await {
                    Item::Msg(b) => {
                        let v = decode_response(&path, &b)?;
                        (v.clone(), Some(v))
                    }
                    Item::Err(st) => (status_tree(&st), None),
                    Item::Eof => (Norm::error("Internal", "no response"), None),
                };
                let mut out = one(got, raw);
                if let Some(servers) = servers {
                    let v = if servers.is_empty() {
                        Value::Null
                    } else {
                        json!(servers)
                    };
                    out.push(Seen {
                        key: "header",
                        got: v,
                        raw: None,
                    });
                }
                Ok(out)
            }
            "probe" => {
                let path = s(step, "method").to_string();
                let mut call = Stream::open(self.conn(step)?, &path);
                call.send(Vec::new());
                call.close_send();
                let err = match call.recv().await {
                    Item::Err(st) => Some(st),
                    Item::Msg(_) | Item::Eof => None,
                };
                Ok(one(
                    probe_outcome(err, step["ported"].as_bool() == Some(true)),
                    None,
                ))
            }
            "open" => {
                let path = s(step, "method").to_string();
                let call = Stream::open(self.conn(step)?, &path);
                self.streams.insert(n(step, "stream"), (path, call));
                if let Some(c) = step.get("ctx").and_then(Value::as_i64) {
                    self.ctxs.entry(c).or_default().push(n(step, "stream"));
                }
                Ok(Vec::new())
            }
            "cancel" => {
                for id in self.ctxs.get(&n(step, "ctx")).cloned().unwrap_or_default() {
                    if let Some((_, call)) = self.streams.get_mut(&id) {
                        call.cancel();
                    }
                }
                Ok(Vec::new())
            }
            "logsTake" => {
                let (_, call) = self
                    .streams
                    .get_mut(&n(step, "stream"))
                    .ok_or("no such stream")?;
                Ok(one(logs_take(call, step).await?, None))
            }
            "send" => {
                let msg = self.resolve(&step["msg"])?;
                let (path, call) = self
                    .streams
                    .get(&n(step, "stream"))
                    .ok_or("no such stream")?;
                call.send(encode_request(path, &msg)?);
                Ok(Vec::new())
            }
            "closeSend" => {
                let (_, call) = self
                    .streams
                    .get_mut(&n(step, "stream"))
                    .ok_or("no such stream")?;
                call.close_send();
                Ok(Vec::new())
            }
            "recv" => {
                let (path, call) = self
                    .streams
                    .get_mut(&n(step, "stream"))
                    .ok_or("no such stream")?;
                let path = path.clone();
                Ok(match call.recv().await {
                    Item::Msg(b) => {
                        let v = decode_response(&path, &b)?;
                        one(v.clone(), Some(v))
                    }
                    Item::Err(st) => one(status_tree(&st), None),
                    Item::Eof => one(eof(), None),
                })
            }
            "agent" => self.agent(step).await,
            "assignment" => {
                let a = self.agent_of(step)?;
                drain(a).await?;
                let last = a.last.clone().unwrap_or_else(|| json!({}));
                Ok(one(last.clone(), Some(last)))
            }
            "agentSend" => {
                let msg = self.resolve(&step["msg"])?;
                let a = self.agent_of(step)?;
                a.stream.send(encode_request(CONNECT, &msg)?);
                Ok(Vec::new())
            }
            "agentCloseSend" => {
                self.agent_of(step)?.stream.close_send();
                Ok(Vec::new())
            }
            "agentStop" => {
                self.agent_of(step)?.stream.cancel();
                Ok(Vec::new())
            }
            "agentEnd" => {
                let a = self.agent_of(step)?;
                let end = wait_end(a).await?;
                let last = a.last.clone().unwrap_or_else(|| json!({}));
                Ok(vec![
                    Seen {
                        key: "expect",
                        got: end,
                        raw: None,
                    },
                    Seen {
                        key: "last",
                        got: last,
                        raw: None,
                    },
                ])
            }
            "others" => {
                let a = self.agent_of(step)?;
                Ok(one(Value::Array(a.others.clone()), None))
            }
            "clearOthers" => {
                self.agent_of(step)?.others.clear();
                Ok(Vec::new())
            }
            "store" => {
                let method = s(step, "method");
                let args = self.resolve(&step["args"])?;
                Ok(
                    match armada_store::parity_call::call(&self.st, method, &args).await {
                        Ok(mut v) => {
                            if method == "ListEvents" {
                                // An event's key ends in random hex.
                                if let Some(a) = v.as_array_mut() {
                                    for e in a {
                                        e["Key"] = json!("");
                                    }
                                }
                            }
                            one(v.clone(), Some(v))
                        }
                        Err(e) => one(Norm::error("Unknown", &e.to_string()), None),
                    },
                )
            }
            "setSecret" => {
                let keys = &self.keys;
                let (secret, key, value) = (s(step, "secret"), s(step, "key"), s(step, "value"));
                let seal = move |v: i64| {
                    keys.seal(secret, key, v, &SecretValue::new(value.as_bytes()))
                        .map_err(|e| armada_store::Error::other(e.to_string()))
                };
                let r = self
                    .st
                    .set_secret(
                        secret,
                        key,
                        &seal,
                        step["rollout"].as_bool() == Some(true),
                        s(step, "actor"),
                    )
                    .await;
                Ok(match r {
                    Ok((version, revs)) => {
                        let v = json!({"Version": version, "Revisions": if revs.is_empty() { Value::Null } else { json!(revs) }});
                        one(v, None)
                    }
                    Err(e) => one(Norm::error("Unknown", &e.to_string()), None),
                })
            }
            "server" => {
                let mut req = step.clone();
                let op = s(step, "do").to_string();
                req["op"] = json!(op);
                if let Some(m) = req.as_object_mut() {
                    m.remove("do");
                }
                self.prog.ask(req).await.map_err(|e| format!("{op}: {e}"))?;
                Ok(Vec::new())
            }
            "advance" => {
                let now = self.clock.fetch_add(n(step, "ms"), Ordering::SeqCst) + n(step, "ms");
                self.prog.ask(json!({"op": "now", "ms": now})).await?;
                Ok(Vec::new())
            }
            "sleep" => {
                tokio::time::sleep(Duration::from_millis(n(step, "ms") as u64)).await;
                Ok(Vec::new())
            }
            "settingsChanged" => Ok(one(json!(self.prog.changed.load(Ordering::SeqCst)), None)),
            "members" => {
                let ms = self
                    .cluster
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .members
                    .clone();
                Ok(one(Value::Array(ms), None))
            }
            "setMembers" => {
                let mut c = self.cluster.lock().unwrap_or_else(|p| p.into_inner());
                c.members = step["members"].as_array().cloned().unwrap_or_default();
                c.add_err = step
                    .get("addErr")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                Ok(Vec::new())
            }
            "keyspace" => {
                let v = self.keyspace().await?;
                Ok(one(v, None))
            }
            "keys" => {
                let pfx = format!("{}{}", self.prefix, s(step, "prefix"));
                let r = self
                    .shared
                    .client
                    .range(op::get_prefix(&pfx, 0))
                    .await
                    .map_err(|e| e.to_string())?;
                let keys: Vec<Value> = r
                    .kvs
                    .iter()
                    .map(|kv| json!(String::from_utf8_lossy(&kv.key)[self.prefix.len()..]))
                    .collect();
                Ok(one(none_if_empty(keys), None))
            }
            "txt" => {
                let values = self.resolve(&step["values"])?;
                self.prog
                    .ask(json!({"op": "txt", "name": s(step, "name"), "values": values}))
                    .await?;
                Ok(Vec::new())
            }
            "volumeAgent" => {
                let bucket = self.buckets.entry(n(step, "bucket")).or_default().clone();
                let a = self.agent_of(step)?;
                let h = volumes::Handler {
                    ch: a.ch.clone(),
                    disk: Arc::default(),
                    bucket,
                };
                *a.volume.lock().unwrap_or_else(|p| p.into_inner()) = Some(h);
                Ok(Vec::new())
            }
            "volWrite" | "volRead" | "volRequests" => {
                let a = self.agent_of(step)?;
                let h = a
                    .volume
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone()
                    .ok_or("not a volume agent")?;
                let mut d = h.disk.lock().unwrap_or_else(|p| p.into_inner());
                Ok(match s(step, "op") {
                    "volWrite" => {
                        d.disk
                            .insert(s(step, "key").to_string(), s(step, "contents").to_string());
                        Vec::new()
                    }
                    "volRead" => one(
                        json!(d.disk.get(s(step, "key")).cloned().unwrap_or_default()),
                        None,
                    ),
                    _ => {
                        let mut seen = std::mem::take(&mut d.seen);
                        seen.sort();
                        one(
                            none_if_empty(seen.into_iter().map(Value::String).collect()),
                            None,
                        )
                    }
                })
            }
            "bucketFail" => {
                let b = self.buckets.entry(n(step, "bucket")).or_default();
                b.lock().unwrap_or_else(|p| p.into_inner()).fail_put =
                    step["on"].as_bool() == Some(true);
                Ok(Vec::new())
            }
            other => self.step_more(other, step).await,
        }
    }

    /// The steps of the stand-ins: log and exec sessions, alert channels,
    /// the control plane backups' bucket, the metrics endpoint, public
    /// listeners, and certmagic's storage.
    async fn step_more(&mut self, op: &str, step: &Value) -> Result<Vec<Seen>, String> {
        let one = |got: Value| {
            vec![Seen {
                key: "expect",
                got,
                raw: None,
            }]
        };
        let none = |l: Vec<String>| none_if_empty(l.into_iter().map(Value::String).collect());
        match op {
            "watchAgent" => {
                let start_ms = self.start_ms;
                let a = self.agent_of(step)?;
                let w = Arc::new(Watch {
                    ch: a.ch.clone(),
                    start_ms,
                    st: Mutex::default(),
                });
                *a.watch.lock().unwrap_or_else(|p| p.into_inner()) = Some(w);
                Ok(Vec::new())
            }
            "watchAttachAs" => {
                let other = self
                    .agents
                    .get(s(step, "as"))
                    .ok_or("no such agent")?
                    .ch
                    .clone();
                lock(&self.watch_of(step)?.st).attach_as = Some(other);
                Ok(Vec::new())
            }
            "watchAttached" => Ok(one(self.watch_of(step)?.attached().await?)),
            "watchLive" | "watchErr" | "watchHistory" | "watchClearQueries" | "watchWindows"
            | "watchOpen" | "watchCancels" => {
                let w = self.watch_of(step)?;
                let replica = s(step, "replica").to_string();
                if op == "watchOpen" {
                    return Ok(one(json!(w.open_count())));
                }
                let mut st = lock(&w.st);
                Ok(match op {
                    "watchLive" => {
                        let lines = step["lines"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .map(|l| l.as_str().unwrap_or_default().to_string())
                                    .collect()
                            })
                            .unwrap_or_default();
                        st.live.insert(replica, lines);
                        Vec::new()
                    }
                    "watchErr" => {
                        match s(step, "error") {
                            "" => st.errs.remove(&replica),
                            e => st.errs.insert(replica, e.to_string()),
                        };
                        Vec::new()
                    }
                    "watchHistory" => {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as i64)
                            .unwrap_or_default();
                        let mut list = Vec::new();
                        for e in step["entries"].as_array().cloned().unwrap_or_default() {
                            let mut p: armada_proto::armada::v1::LogPush =
                                serde_json::from_value(e["push"].clone())
                                    .map_err(|e| format!("a history entry: {e}"))?;
                            if let Some(after) = e.get("afterNowMs").and_then(Value::as_i64) {
                                let at = now + after;
                                p.time = Some(armada_proto::google::protobuf::Timestamp {
                                    seconds: at.div_euclid(1000),
                                    nanos: (at.rem_euclid(1000) * 1_000_000) as i32,
                                });
                            }
                            list.push(p);
                        }
                        st.history = list;
                        Vec::new()
                    }
                    "watchClearQueries" => {
                        st.queries.clear();
                        Vec::new()
                    }
                    "watchWindows" => {
                        let since = i128::from(n(step, "sinceMs")) * 1_000_000;
                        let out: Vec<Value> = st
                            .queries
                            .iter()
                            .map(|q| {
                                let t = q.since.as_ref().map_or(0, |t| {
                                    i128::from(t.seconds) * 1_000_000_000 + i128::from(t.nanos)
                                });
                                json!(t == since)
                            })
                            .collect();
                        one(none_if_empty(out))
                    }
                    _ => one(json!(st.cancels.len())),
                })
            }
            "watchRequests" => {
                let mut out = serde_json::Map::new();
                for rid in step["agents"].as_array().cloned().unwrap_or_default() {
                    let rid = rid.as_str().unwrap_or_default();
                    let a = self.agents.get(rid).ok_or("no such agent")?;
                    let w = a
                        .watch
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .clone()
                        .ok_or("not a watch agent")?;
                    let mut st = lock(&w.st);
                    let mut seen = std::mem::take(&mut st.seen);
                    seen.sort();
                    let execs = std::mem::take(&mut st.execs);
                    out.insert(
                        a.node.clone(),
                        json!({"logs": none(seen), "exec": none(execs)}),
                    );
                }
                Ok(one(Value::Object(out)))
            }
            "dnsToken" => {
                let v = match armada_server::load_settings(&self.st).await {
                    Err(_) => json!({"ok": false, "value": "", "error": true}),
                    Ok(set) => match set.token(&self.keys) {
                        Err(_) => json!({"ok": false, "value": "", "error": true}),
                        Ok(None) => json!({"ok": false, "value": "", "error": false}),
                        Ok(Some(t)) => {
                            json!({"ok": true, "value": String::from_utf8_lossy(t.bytes()),
                            "error": false})
                        }
                    },
                };
                Ok(one(v))
            }
            "listening" => {
                let addr = self.resolve(&step["addr"])?;
                let tls = match step["tls"].as_bool() {
                    Some(true) => Some(grpc::tls(&self.ca_pem, None)?),
                    _ => None,
                };
                Ok(one(json!(
                    listening(addr.as_str().unwrap_or_default(), tls).await
                )))
            }
            "scrape" => {
                let tls = if step["noCert"].as_bool() == Some(true) {
                    grpc::tls(&self.ca_pem, None)?
                } else if step.get("cert").is_some() {
                    let cert = self.resolve(&step["cert"])?;
                    let key = self.resolve(&step["key"])?;
                    grpc::tls(
                        &self.ca_pem,
                        Some((
                            cert.as_str().unwrap_or_default().as_bytes(),
                            key.as_str().unwrap_or_default().as_bytes(),
                        )),
                    )?
                } else {
                    let other;
                    let ca = if step["otherCA"].as_bool() == Some(true) {
                        other = Ca::new("other").map_err(|e| e.to_string())?;
                        &other
                    } else {
                        &self.ca
                    };
                    let (cert, key) = ca
                        .issue(&IssueRequest {
                            identity: Identity::new(s(step, "kind"), s(step, "name")),
                            dns_names: Vec::new(),
                            ips: Vec::new(),
                            server: false,
                            client: true,
                            validity: Duration::ZERO,
                        })
                        .map_err(|e| e.to_string())?;
                    grpc::tls(&self.ca_pem, Some((&cert, key.expose())))?
                };
                let addr = self.addrs.get("metrics").cloned().unwrap_or_default();
                let v = match standins::scrape(&addr, tls, s(step, "method"), s(step, "path")).await
                {
                    Ok((code, body)) => json!({"status": code, "body": body, "error": false}),
                    Err(_) => json!({"status": 0, "body": "", "error": true}),
                };
                Ok(one(v))
            }
            "sinkWait" => {
                let sinks = self.sinks.as_ref().ok_or("no alert stand-ins")?;
                let got = sinks.wait(s(step, "path"), n(step, "n") as usize).await?;
                Ok(one(json!(got)))
            }
            "sinkFail" => {
                let sinks = self.sinks.as_ref().ok_or("no alert stand-ins")?;
                sinks.set_fail(s(step, "path"), step["on"].as_bool() == Some(true));
                Ok(Vec::new())
            }
            "cpBucket" => Ok(one(self.bucket.as_ref().ok_or("no bucket")?.summary())),
            "managed" => {
                let m = self.prog.ask(json!({"op": "managed"})).await?;
                Ok(one(m.get("value").cloned().unwrap_or(Value::Null)))
            }
            "deletePrefix" => {
                let pfx = format!("{}{}", self.prefix, s(step, "prefix"));
                let end = String::from_utf8_lossy(&op::prefix_end(&pfx)).into_owned();
                self.shared
                    .client
                    .delete(&pfx, Some(&end))
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(Vec::new())
            }
            _ => self.step_acme(op, step).await,
        }
    }

    /// The steps of certmagic's storage.
    async fn step_acme(&mut self, op: &str, step: &Value) -> Result<Vec<Seen>, String> {
        let one = |got: Value| {
            vec![Seen {
                key: "expect",
                got,
                raw: None,
            }]
        };
        let client = self.shared.client.clone();
        let a = self
            .acme
            .as_mut()
            .ok_or_else(|| format!("unknown step {op}"))?;
        let name = s(step, "name").to_string();
        let bundle = |a: &Acme| -> Result<(Vec<u8>, Vec<u8>), String> {
            a.bundles
                .get(n(step, "bundle") as usize)
                .cloned()
                .ok_or_else(|| "no such bundle".to_string())
        };
        let store = |a: &Acme, crt: Vec<u8>, key: Vec<u8>| {
            let (st, issuer, name) = (a.storage.clone(), a.issuer.clone(), name.clone());
            async move {
                st.store(&site_cert(&issuer, &name), &crt)
                    .await
                    .map_err(|e| e.to_string())?;
                st.store(&site_private_key(&issuer, &name), &key)
                    .await
                    .map_err(|e| e.to_string())
            }
        };
        match op {
            "storeCert" => {
                let (crt, key) = if step.get("bundle").is_some() {
                    bundle(a)?
                } else {
                    (
                        s(step, "cert").as_bytes().to_vec(),
                        s(step, "key").as_bytes().to_vec(),
                    )
                };
                store(a, crt, key).await?;
                Ok(Vec::new())
            }
            "acmeStore" => {
                let (crt, key) = bundle(a)?;
                store(a, crt, key).await?;
                Ok(Vec::new())
            }
            "acmePut" => {
                // What Go's storage wrote, byte for byte.
                for kv in step["kvs"].as_array().cloned().unwrap_or_default() {
                    let mut v = if kv["recent"].as_bool() == Some(true) {
                        now_nanos().to_be_bytes().to_vec()
                    } else {
                        vec![0; 8]
                    };
                    match kv.get("bundle").and_then(Value::as_u64) {
                        Some(i) => {
                            let b = a.bundles.get(i as usize).ok_or("no such bundle")?;
                            v.extend_from_slice(if kv["part"].as_u64() == Some(0) {
                                &b.0
                            } else {
                                &b.1
                            });
                        }
                        None => v.extend_from_slice(s(&kv, "data").as_bytes()),
                    }
                    client
                        .put(&format!("{}data/{}", a.prefix, s(&kv, "key")), &v)
                        .await
                        .map_err(|e| e.to_string())?;
                }
                Ok(Vec::new())
            }
            "acmeLoad" => {
                let want = bundle_served(&bundle(a)?).0;
                let got = load_bundle(&a.storage, &a.issuer, &name).await;
                Ok(one(json!(got.as_deref() == Some(want.as_slice()))))
            }
            "acmeKVs" => Ok(one(acme_kvs(&client, a, &name).await?)),
            "acmeList" => {
                let v = match a
                    .storage
                    .list(s(step, "dir"), step["recursive"].as_bool() == Some(true))
                    .await
                {
                    Ok(Some(mut keys)) => {
                        keys.sort();
                        json!({"keys": keys, "error": false})
                    }
                    Ok(None) | Err(_) => json!({"keys": null, "error": true}),
                };
                Ok(one(v))
            }
            "acmeLockKeys" => {
                let mut r = op::get_prefix(&format!("{}locks/", a.prefix), 0);
                r.keys_only = true;
                let resp = client.range(r).await.map_err(|e| e.to_string())?;
                let keys = resp
                    .kvs
                    .iter()
                    .map(|kv| {
                        let k = String::from_utf8_lossy(&kv.key);
                        let k = k.strip_prefix(a.prefix.as_str()).unwrap_or(&k);
                        match k.rfind('/') {
                            Some(i) => json!(format!("{}<lease>", &k[..=i])),
                            None => json!(k),
                        }
                    })
                    .collect();
                Ok(one(none_if_empty(keys)))
            }
            "acmeForeignLock" => {
                // Held as Go's concurrency.Mutex holds it: a key named
                // after its session's lease under the lock's prefix.
                let lease = client.grant(60).await.map_err(|e| e.to_string())?;
                let key = format!("{}locks/{name}/{lease:x}", a.prefix);
                client
                    .txn(TxnRequest {
                        success: vec![op::put(&key, b"", lease)],
                        ..Default::default()
                    })
                    .await
                    .map_err(|e| e.to_string())?;
                a.foreign = Some((lease, key));
                Ok(Vec::new())
            }
            "acmeForeignUnlock" => {
                if let Some((lease, key)) = a.foreign.take() {
                    client.delete(&key, None).await.map_err(|e| e.to_string())?;
                    client.revoke(lease).await.map_err(|e| e.to_string())?;
                }
                Ok(Vec::new())
            }
            "acmeLock" => {
                let other = a.other.clone();
                a.taken = None;
                a.lock = Some(tokio::spawn(async move {
                    other.lock(&name).await.map_err(|e| e.to_string())
                }));
                Ok(Vec::new())
            }
            "acmeLockTaken" => {
                if a.taken.is_none()
                    && let Some(h) = a.lock.as_mut()
                {
                    let d = Duration::from_millis(n(step, "ms") as u64);
                    if let Ok(r) = tokio::time::timeout(d, h).await {
                        a.taken = Some(matches!(r, Ok(Ok(()))));
                        a.lock = None;
                    }
                }
                Ok(one(json!(a.taken.unwrap_or(false))))
            }
            "acmeForeignWait" => {
                // A waiter as Go's mutex waits: its own key, which holds the
                // lock only once it is the oldest under the prefix.
                let lease = client.grant(60).await.map_err(|e| e.to_string())?;
                let pfx = format!("{}locks/{name}/", a.prefix);
                let key = format!("{pfx}{lease:x}");
                client
                    .txn(TxnRequest {
                        success: vec![op::put(&key, b"", lease)],
                        ..Default::default()
                    })
                    .await
                    .map_err(|e| e.to_string())?;
                tokio::time::sleep(Duration::from_millis(n(step, "ms") as u64)).await;
                let resp = client
                    .range(op::get_prefix(&pfx, 0))
                    .await
                    .map_err(|e| e.to_string())?;
                let oldest = resp
                    .kvs
                    .iter()
                    .min_by_key(|kv| kv.create_revision)
                    .map(|kv| kv.key.clone());
                client.delete(&key, None).await.map_err(|e| e.to_string())?;
                client.revoke(lease).await.map_err(|e| e.to_string())?;
                Ok(one(json!(oldest.as_deref() != Some(key.as_bytes()))))
            }
            "acmeUnlock" => {
                a.other.unlock(&name).await.map_err(|e| e.to_string())?;
                Ok(Vec::new())
            }
            other => Err(format!("unknown step {other}")),
        }
    }

    fn watch_of(&self, step: &Value) -> Result<Arc<Watch>, String> {
        let id = s(step, "agent");
        let a = self
            .agents
            .get(id)
            .ok_or_else(|| format!("no agent {id}"))?;
        a.watch
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .ok_or_else(|| format!("agent {id} is not a watch agent"))
    }

    fn conn(&self, step: &Value) -> Result<Channel, String> {
        self.conns
            .get(&n(step, "conn"))
            .cloned()
            .ok_or_else(|| format!("no connection {}", n(step, "conn")))
    }

    fn agent_of(&mut self, step: &Value) -> Result<&mut Agent, String> {
        let id = s(step, "agent");
        self.agents
            .get_mut(id)
            .ok_or_else(|| format!("no agent {id}"))
    }

    /// An agent's session: connected once the server records it, or the
    /// stream's error (Go's connectAgent).
    async fn agent(&mut self, step: &Value) -> Result<Vec<Seen>, String> {
        let node = s(step, "node").to_string();
        let before = self.connected(&node).await?;
        let ch = self.conn(step)?;
        let volume: Arc<Mutex<Option<volumes::Handler>>> = Arc::default();
        let watched: Arc<Mutex<Option<Arc<Watch>>>> = Arc::default();
        let tap: grpc::Tap = {
            let volume = volume.clone();
            let watched = watched.clone();
            Arc::new(move |m: &[u8]| {
                use armada_proto::armada::v1::{ServerMessage, server_message::Msg};
                use prost::Message;
                let Ok(ServerMessage { msg: Some(msg) }) = ServerMessage::decode(m) else {
                    return false;
                };
                let h = volume.lock().unwrap_or_else(|p| p.into_inner()).clone();
                let w = watched.lock().unwrap_or_else(|p| p.into_inner()).clone();
                match (msg, h, w) {
                    (Msg::VolumeRequest(req), Some(h), _) => {
                        tokio::spawn(h.serve(req));
                        true
                    }
                    (Msg::ExecRequest(er), _, Some(w)) => {
                        tokio::spawn(w.serve_exec(er));
                        true
                    }
                    (m @ (Msg::LogRequest(_) | Msg::LogCancel(_)), _, Some(w)) => {
                        w.serve_logs(m);
                        true
                    }
                    _ => false,
                }
            })
        };
        let mut stream = Stream::open_tapped(ch.clone(), CONNECT, Some(tap));
        match step.get("hello") {
            Some(h) if !h.is_null() => {
                let hello = self.resolve(h)?;
                stream.send(encode_request(CONNECT, &json!({"hello": hello}))?);
            }
            _ => stream.close_send(),
        }
        let mut agent = Agent {
            node: node.clone(),
            stream,
            queue: VecDeque::new(),
            end: None,
            ended: false,
            last: None,
            others: Vec::new(),
            ch,
            volume,
            watch: watched,
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match agent.stream.recv_within(Duration::from_millis(10)).await {
                Some(Item::Msg(m)) => agent.queue.push_back(m),
                Some(Item::Err(st)) => {
                    return Ok(vec![Seen {
                        key: "expect",
                        got: status_tree(&st),
                        raw: None,
                    }]);
                }
                Some(Item::Eof) => {
                    return Ok(vec![Seen {
                        key: "expect",
                        got: eof(),
                        raw: None,
                    }]);
                }
                None => {}
            }
            if self.connected(&node).await? > before {
                break;
            }
            if Instant::now() > deadline {
                return Err(format!("agent {node} did not connect"));
            }
        }
        self.agents.insert(s(step, "agent").to_string(), agent);
        Ok(Vec::new())
    }

    /// The count of a node's Connected events.
    async fn connected(&self, node: &str) -> Result<i64, String> {
        let evs = self
            .st
            .list_events(&armada_spec::gotime::Time::zero())
            .await
            .map_err(|e| e.to_string())?;
        Ok(evs
            .iter()
            .filter(|e| e.object == node && e.reason == "Connected")
            .map(|e| e.count)
            .sum())
    }

    /// The server's keyspace as Go's keyspaceOf writes it.
    async fn keyspace(&mut self) -> Result<Value, String> {
        let r = self
            .shared
            .client
            .range(op::get_prefix(&self.prefix, 0))
            .await
            .map_err(|e| e.to_string())?;
        let mut all = Vec::new();
        for kv in r.kvs {
            let k = String::from_utf8_lossy(&kv.key)[self.prefix.len()..].to_string();
            let v = serde_json::from_slice::<Value>(&kv.value)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&kv.value).into_owned()));
            all.push((k, v));
        }
        for (_, v) in &all {
            self.norm.collect(v, "");
        }
        let (mut keys, mut events, mut audit) = (Vec::new(), Vec::new(), Vec::new());
        for (k, v) in &all {
            let enc = gojson::marshal(&self.norm.encode(v));
            if k.starts_with("events/") {
                events.push(enc);
            } else if k.starts_with("audit/") {
                audit.push(enc);
            } else {
                keys.push(format!("{} = {enc}", self.norm.replace(k)));
            }
        }
        keys.sort();
        events.sort();
        audit.sort();
        let list = |l: Vec<String>| {
            if l.is_empty() { Value::Null } else { json!(l) }
        };
        Ok(json!({"keys": list(keys), "events": list(events), "audit": list(audit)}))
    }

    /// v with every reference replaced by what it names.
    fn resolve(&self, v: &Value) -> Result<Value, String> {
        match v {
            Value::Object(m) if m.contains_key("@addr") => {
                let name = m["@addr"].as_str().unwrap_or_default();
                Ok(json!(
                    self.addrs
                        .get(name)
                        .cloned()
                        .unwrap_or_else(|| self.prog.addr(name))
                ))
            }
            Value::Object(m) if m.contains_key("@b64") => {
                let v = self.resolve(&m["@b64"])?;
                Ok(json!(armada_pki::encoding::base64_encode(
                    v.as_str().unwrap_or_default().as_bytes()
                )))
            }
            Value::Object(m) if m.contains_key("@concat") => {
                let mut out = String::new();
                for p in m["@concat"].as_array().cloned().unwrap_or_default() {
                    out.push_str(self.resolve(&p)?.as_str().unwrap_or_default());
                }
                Ok(json!(out))
            }
            Value::Object(m) if m.contains_key("@ref") => {
                let id = m["@ref"].as_i64().unwrap_or_default();
                let mut cur = self
                    .raws
                    .get(&id)
                    .ok_or_else(|| format!("no answer {id} to refer to"))?;
                for p in m["path"].as_array().cloned().unwrap_or_default() {
                    cur = match &p {
                        Value::String(k) => cur.get(k.as_str()),
                        Value::Number(i) => cur.get(i.as_u64().unwrap_or_default() as usize),
                        _ => None,
                    }
                    .ok_or_else(|| format!("answer {id} has no {}", m["path"]))?;
                }
                let mut out = cur.as_str().unwrap_or_default().to_string();
                match m.get("part").and_then(Value::as_str) {
                    Some("before") => {
                        out = out.split_once('.').map_or(out.clone(), |p| p.0.to_string())
                    }
                    Some("after") => {
                        out = out
                            .split_once('.')
                            .map_or(String::new(), |p| p.1.to_string())
                    }
                    _ => {}
                }
                if m.get("enc").and_then(Value::as_str) == Some("unb64") {
                    let b = armada_pki::encoding::base64_decode(out.as_bytes())
                        .ok_or("a reference that is not base64")?;
                    out = String::from_utf8_lossy(&b).into_owned();
                }
                Ok(json!(out))
            }
            Value::Object(m) => {
                let mut out = serde_json::Map::new();
                for (k, e) in m {
                    out.insert(k.clone(), self.resolve(e)?);
                }
                Ok(Value::Object(out))
            }
            Value::Array(a) => Ok(Value::Array(
                a.iter()
                    .map(|e| self.resolve(e))
                    .collect::<Result<_, _>>()?,
            )),
            _ => Ok(v.clone()),
        }
    }
}

/// Reads what the server sent until nothing new came for a moment (Go's
/// parityAgent.drain).
async fn drain(a: &mut Agent) -> Result<(), String> {
    while let Some(m) = a.queue.pop_front() {
        take(a, &m)?;
    }
    if a.ended {
        return Ok(());
    }
    loop {
        match a.stream.recv_within(Duration::from_millis(300)).await {
            None => return Ok(()),
            Some(Item::Msg(m)) => take(a, &m)?,
            Some(end) => {
                a.ended = true;
                a.end = Some(end);
                return Ok(());
            }
        }
    }
}

fn take(a: &mut Agent, m: &[u8]) -> Result<(), String> {
    let v = decode_response(CONNECT, m)?;
    match v.get("assignment") {
        Some(as_) => a.last = Some(as_.clone()),
        None => a.others.push(v),
    }
    Ok(())
}

/// Waits for the session's end (Go's parityAgent.end): assignments sent
/// before it count.
async fn wait_end(a: &mut Agent) -> Result<Value, String> {
    while let Some(m) = a.queue.pop_front() {
        let v = decode_response(CONNECT, &m)?;
        if let Some(as_) = v.get("assignment") {
            a.last = Some(as_.clone());
        }
    }
    let end = match a.end.take() {
        Some(e) => e,
        None => match a.stream.recv_within(Duration::from_secs(15)).await {
            None => return Err(format!("agent {}'s stream did not end", a.node)),
            Some(e) => {
                let mut e = e;
                while let Item::Msg(m) = e {
                    let v = decode_response(CONNECT, &m)?;
                    if let Some(as_) = v.get("assignment") {
                        a.last = Some(as_.clone());
                    }
                    e = a
                        .stream
                        .recv_within(Duration::from_secs(15))
                        .await
                        .ok_or_else(|| format!("agent {}'s stream did not end", a.node))?;
                }
                e
            }
        },
    };
    a.ended = true;
    Ok(match end {
        Item::Err(st) => status_tree(&st),
        _ => eof(),
    })
}

/// The directory certmagic's ACME issuer stores certificates under
/// (internal/server's parityACMECA).
const ACME_DIRECTORY: &str = "https://acme.test:14000/dir";

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn now_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or_default()
}

/// A bundle as the certificate manager serves it (the chain, a newline if
/// it has none, the key) and its SHA-256.
fn bundle_served(b: &(Vec<u8>, Vec<u8>)) -> (Vec<u8>, Vec<u8>) {
    let mut out = b.0.clone();
    if out.last().is_some_and(|c| *c != b'\n') {
        out.push(b'\n');
    }
    out.extend_from_slice(&b.1);
    let sum = ring::digest::digest(&ring::digest::SHA256, &out);
    (out, sum.as_ref().to_vec())
}

/// What certmagic's storage holds for keys naming name, described as
/// Go's harness describes it (scenario.acmeKVs).
async fn acme_kvs(c: &Client, a: &Acme, name: &str) -> Result<Value, String> {
    let pfx = format!("{}data/", a.prefix);
    let resp = c
        .range(op::get_prefix(&pfx, 0))
        .await
        .map_err(|e| e.to_string())?;
    let want = format!("/{}/", safe(name));
    let mut out = Vec::new();
    for kv in resp.kvs {
        let k = String::from_utf8_lossy(&kv.key);
        let k = k.strip_prefix(pfx.as_str()).unwrap_or(&k).to_string();
        if !k.contains(&want) {
            continue;
        }
        let v = kv.value;
        if v.len() < 8 {
            out.push(json!({"key": k, "short": v.len()}));
            continue;
        }
        let mut t = [0u8; 8];
        t.copy_from_slice(&v[..8]);
        let age = now_nanos().abs_diff(u64::from_be_bytes(t));
        let mut e = json!({"key": k, "recent": age < 3_600_000_000_000});
        let data = &v[8..];
        for (i, b) in a.bundles.iter().enumerate() {
            for (j, part) in [&b.0, &b.1].into_iter().enumerate() {
                if part.as_slice() == data {
                    e["bundle"] = json!(i);
                    e["part"] = json!(j);
                }
            }
        }
        if e.get("bundle").is_none() {
            e["data"] = json!(String::from_utf8_lossy(data));
        }
        out.push(e);
    }
    Ok(none_if_empty(out))
}

/// Whether something listens at addr: with tls, a TLS handshake
/// completes (as FetchPinnedCA's), else a TCP connection does (as
/// net.Dial's).
async fn listening(addr: &str, tls: Option<rustls::ClientConfig>) -> bool {
    let go = async {
        let tcp = tokio::net::TcpStream::connect(addr).await.ok()?;
        let Some(tls) = tls else {
            return Some(());
        };
        let name = rustls_pki_types::ServerName::try_from(armada_pki::SERVER_NAME).ok()?;
        tokio_rustls::TlsConnector::from(Arc::new(tls))
            .connect(name, tcp)
            .await
            .ok()
            .map(|_| ())
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(1), go).await,
        Ok(Some(_))
    )
}

/// Reads a Logs stream's entries as Go's harness does (readLogs and the
/// follows' reads): n of them (-1: to its end), as replica|stream|data
/// (rsd) or replica|data (rd), sorted from sortFrom on, and the error that
/// ended them.
async fn logs_take(call: &mut Stream, step: &Value) -> Result<Value, String> {
    let want = n(step, "n");
    let mut lines = Vec::new();
    let mut err = Value::Null;
    while want < 0 || (lines.len() as i64) < want {
        match call.recv_within(Duration::from_secs(15)).await {
            None => return Err(format!("{} of {want} log entries", lines.len())),
            Some(Item::Msg(b)) => {
                let e =
                    <armada_proto::armada::v1::LogEntry as prost::Message>::decode(b.as_slice())
                        .map_err(|e| e.to_string())?;
                let data = String::from_utf8_lossy(&e.data);
                let data = data.strip_suffix('\n').unwrap_or(&data);
                lines.push(match s(step, "format") {
                    "rd" => format!("{}|{data}", e.replica),
                    _ => {
                        let stream = armada_proto::armada::v1::Stream::try_from(e.stream)
                            .map(|s| s.as_str_name().to_string())
                            .unwrap_or_else(|_| e.stream.to_string());
                        format!("{}|{stream}|{data}", e.replica)
                    }
                });
            }
            Some(Item::Eof) if want < 0 => break,
            Some(Item::Eof) => {
                err = eof();
                break;
            }
            Some(Item::Err(st)) => {
                err = status_tree(&st);
                break;
            }
        }
    }
    if let Ok(from) = usize::try_from(n(step, "sortFrom"))
        && from <= lines.len()
    {
        lines[from..].sort();
    }
    let lines = none_if_empty(lines.into_iter().map(Value::String).collect());
    Ok(json!({"lines": lines, "error": err}))
}

/// v with the metrics port own read as recorded.
fn metrics_port(v: &mut Value, own: i64, recorded: i64) {
    match v {
        Value::Object(m) => {
            for (k, e) in m.iter_mut() {
                if k == "metricsPort" && e.as_i64() == Some(own) {
                    *e = json!(recorded);
                } else {
                    metrics_port(e, own, recorded);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|e| metrics_port(e, own, recorded)),
        _ => {}
    }
}

/// A list as Go's nil slice writes it when empty.
fn none_if_empty(l: Vec<Value>) -> Value {
    if l.is_empty() {
        Value::Null
    } else {
        Value::Array(l)
    }
}

/// A store answer with empty lists and maps as null, and, for events,
/// the list sorted.
fn canon(v: &mut Value, sort: bool) {
    fn empties(v: &mut Value) {
        match v {
            Value::Array(a) if a.is_empty() => *v = Value::Null,
            Value::Object(m) if m.is_empty() => *v = Value::Null,
            Value::Array(a) => a.iter_mut().for_each(empties),
            Value::Object(m) => m.values_mut().for_each(empties),
            _ => {}
        }
    }
    empties(v);
    if sort && let Value::Array(a) = v {
        a.sort_by_cached_key(gojson::marshal);
    }
}

fn node_cert(c: &Certificate) -> NodeCert {
    NodeCert {
        serial: c.serial_string(),
        not_after: from_ms(c.not_after * 1000),
    }
}

pub fn status_tree(st: &tonic::Status) -> Value {
    Norm::error(grpc::code_name(st.code()), st.message())
}

/// io.EOF as grpc-go's status.Convert reads it.
pub fn eof() -> Value {
    Norm::error("Unknown", "EOF")
}

/// TestParityMethodAccess's outcome of a call with an empty message.
fn probe_outcome(err: Option<tonic::Status>, ported: bool) -> Value {
    let Some(st) = err else {
        return json!(if ported {
            "answered"
        } else {
            "reached the handler"
        });
    };
    let msg = st.message();
    let refused = matches!(
        st.code(),
        tonic::Code::PermissionDenied | tonic::Code::Unauthenticated
    ) && (msg.contains(" may not call ")
        || msg.contains("has no role that allows")
        || msg.starts_with("certificate of ")
        || msg.contains("client certificate"));
    if refused || ported {
        status_tree(&st)
    } else {
        json!("reached the handler")
    }
}

fn what(step: &Value) -> String {
    let op = s(step, "op");
    match op {
        "call" | "store" | "open" | "probe" => format!("{op} {}", s(step, "method")),
        "server" => format!("server {}", s(step, "do")),
        "agent" | "assignment" | "agentSend" | "agentEnd" => format!("{op} {}", s(step, "agent")),
        _ => op.to_string(),
    }
}

/// Go's and the replay's answers, around their first difference when long
/// (as compareTranscripts shows them).
fn diff(key: &str, want: &Value, got: &Value) -> String {
    let (mut w, mut g) = (gojson::marshal(want), gojson::marshal(got));
    if w.len() > 400 || g.len() > 400 {
        let at = w.bytes().zip(g.bytes()).take_while(|(a, b)| a == b).count();
        let cut = |s: &str| {
            let mut from = at.saturating_sub(200);
            while !s.is_char_boundary(from) {
                from -= 1;
            }
            let mut to = (at + 300).min(s.len());
            while !s.is_char_boundary(to) {
                to -= 1;
            }
            format!("…{}", &s[from..to])
        };
        w = cut(&w);
        g = cut(&g);
    }
    format!("  {key}:\n   go   {w}\n   rust {g}")
}

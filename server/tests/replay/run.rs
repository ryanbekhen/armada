//! One scenario's replay: its steps against the Rust server, each answer
//! normalized and compared with Go's.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use armada_pki::{Ca, Certificate, Identity, IssueRequest, SERVER_NAME, parse_cert_pem};
use armada_secrets::{Keyring, Value as SecretValue};
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
use super::volumes;

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
        "meshJoin": false, "siteJoin": false,
        "certs": false, "wildcard": false, "tls": false,
        "acmePrefix": format!("/test/{i}-acme/"), "acmeDirectory": "https://acme.test:14000/dir",
        "acmeAddr": acme, "cpBackups": false,
    });
    if b("masterKey") {
        conf["masterKey"] = json!(armada_pki::encoding::base64_encode(&master_key()));
    }
    let cluster = Arc::new(Mutex::new(Cluster::new()));
    let prog = Program::start(&conf, cluster.clone()).await?;
    let ca_cert = parse_cert_pem(&ca_pem).map_err(|e| e.to_string())?;
    let mut norm = Norm::new(ca_cert, ca_key, master_key());
    norm.alias(&prog.addr("api"), "<api>");
    norm.alias(&acme, "<acme>");
    norm.alias(&prog.addr("join"), "<join>");
    norm.alias(&prog.addr("siteJoin"), "<site-join>");
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
    };
    let res = run.steps(&f.steps).await;
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
            let mut got = self.norm.encode(&sn.got);
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
                Ok(Vec::new())
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
            other => Err(format!("unknown step {other}")),
        }
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
        let tap: grpc::Tap = {
            let volume = volume.clone();
            Arc::new(move |m: &[u8]| {
                use armada_proto::armada::v1::{ServerMessage, server_message::Msg};
                use prost::Message;
                let Some(h) = volume.lock().unwrap_or_else(|p| p.into_inner()).clone() else {
                    return false;
                };
                match ServerMessage::decode(m) {
                    Ok(ServerMessage {
                        msg: Some(Msg::VolumeRequest(req)),
                    }) => {
                        tokio::spawn(h.serve(req));
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
            Value::Object(m) if m.contains_key("@addr") => Ok(json!(
                self.prog.addr(m["@addr"].as_str().unwrap_or_default())
            )),
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

fn status_tree(st: &tonic::Status) -> Value {
    Norm::error(grpc::code_name(st.code()), st.message())
}

/// io.EOF as grpc-go's status.Convert reads it.
fn eof() -> Value {
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

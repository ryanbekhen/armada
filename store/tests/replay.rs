//! The store's recordings replayed: testdata/<test>.jsonl holds every
//! call with its arguments, the recorded answer, and the keys it wrote or
//! deleted. Here armada-store-parity runs the same calls on the pinned etcd
//! (`make store-replay`: scripts/etcd-cache.sh puts it in .cache/etcd, or
//! ARMADA_ETCD_DIR names it), and after each call its answer (normalized)
//! and its whole keyspace must equal the recorded ones.
//!
//! With ARMADA_STORE_BACKEND=kv the same cases run on armada-kv (ADR 0057)
//! instead, a member started in this process on a Unix socket: the
//! recordings are etcd's behaviour, so any difference is armada-kv's bug.
//! With ARMADA_STORE_BACKEND=kv3 they run on a cluster of three armada-kv
//! members in this process (Raft between them on Unix sockets), the
//! client calling a follower: every write and read goes through the
//! leader.
//!
//! What two servers do on one keyspace (two writers, stores fenced to the
//! other's term, one election and one lock) has nothing to record;
//! `shared_keyspace` checks it with two handles on one member instead.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use armada_spec::gotime::{Location, Time, parse_rfc3339};
use armada_store::Client;
use armada_store::client::op;
use serde_json::{Value, json};

/// The member the replay runs on: the pinned etcd as a process, or an
/// armada-kv member on a thread of its own.
enum Backend {
    Etcd(Child),
    Kv {
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    },
}

/// A member on Unix sockets in a directory of the build's, without TLS, as
/// `armadad backup` runs a scratch member.
struct Member {
    backend: Backend,
    dir: PathBuf,
}

impl Drop for Member {
    fn drop(&mut self) {
        match &mut self.backend {
            Backend::Etcd(child) => {
                let _ = child.kill();
                let _ = child.wait();
            }
            Backend::Kv { stop, thread } => {
                if let Some(s) = stop.take() {
                    let _ = s.send(());
                }
                if let Some(t) = thread.take() {
                    let _ = t.join();
                }
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// How many armada-kv members the replay runs on (ARMADA_STORE_BACKEND=kv:
/// one, kv3: three), or 0 for etcd (unset or `etcd`).
fn kv_members() -> usize {
    match std::env::var("ARMADA_STORE_BACKEND").as_deref() {
        Ok("kv") => 1,
        Ok("kv3") => 3,
        Ok("etcd") | Ok("") | Err(_) => 0,
        Ok(other) => panic!("ARMADA_STORE_BACKEND={other}: kv, kv3, or etcd"),
    }
}

fn on_kv() -> bool {
    kv_members() > 0
}

fn etcd_program() -> PathBuf {
    let dir = match std::env::var_os("ARMADA_ETCD_DIR") {
        Some(d) => PathBuf::from(d),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../.cache/etcd"),
    };
    let p = dir.join("etcd");
    assert!(
        p.is_file(),
        "{} is missing: run sh scripts/etcd-cache.sh (make store-replay does), or set ARMADA_ETCD_DIR",
        p.display()
    );
    p
}

impl Member {
    fn start(name: &str) -> Member {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        if kv_members() == 3 {
            return Member::start_kv3(dir);
        }
        if on_kv() {
            return Member::start_kv(dir);
        }
        let peer = "https://127.0.0.1:2380";
        // Relative paths: a socket's address holds at most 108 bytes.
        let child = Command::new(etcd_program())
            .current_dir(&dir)
            .args(["--name", "replay", "--data-dir", "data"])
            .args(["--listen-client-urls", "unix://client.sock"])
            .args(["--advertise-client-urls", "unix://client.sock"])
            .args(["--listen-peer-urls", "unix://peer.sock"])
            .args(["--initial-advertise-peer-urls", peer])
            .arg("--initial-cluster")
            .arg(format!("replay={peer}"))
            .args(["--initial-cluster-token", "armada"])
            // The store's transactions hold up to 4096 operations.
            .args(["--max-txn-ops", "4096", "--unsafe-no-fsync"])
            .args(["--enable-grpc-gateway=false", "--log-level", "error"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start etcd");
        Member {
            backend: Backend::Etcd(child),
            dir,
        }
    }

    /// An armada-kv member in dir/data, served on dir/client.sock until
    /// the member is dropped.
    fn start_kv(dir: PathBuf) -> Member {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let d = dir.clone();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
                let opts = armada_kv::Options {
                    name: "replay".to_string(),
                    ..Default::default()
                };
                let node = armada_kv::Node::open(&d.join("data"), opts)
                    .await
                    .expect("open armada-kv");
                armada_kv::serve_unix(node.clone(), &d.join("client.sock"), async {
                    let _ = stopped.await;
                })
                .await
                .expect("serve armada-kv");
                node.close().await;
            });
        });
        Member {
            backend: Backend::Kv {
                stop: Some(stop),
                thread: Some(thread),
            },
            dir,
        }
    }

    /// Three armada-kv members in dir/{a,b,c}, each serving its peer
    /// service on dir/<name>/peer.sock: a bootstraps the cluster, b and c
    /// are added as learners, join, and are promoted. b, a follower, serves
    /// the clients on dir/client.sock.
    fn start_kv3(dir: PathBuf) -> Member {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let d = dir.clone();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
                let peer = |n: &str| format!("unix://{}", d.join(n).join("peer.sock").display());
                let opts = |n: &str, start: armada_kv::Start| armada_kv::Options {
                    name: n.to_string(),
                    peer_urls: vec![peer(n)],
                    client_urls: vec![format!("unix://{}", d.join("client.sock").display())],
                    start,
                    connector: Some(std::sync::Arc::new(armada_kv::UnixConnector)),
                    ..Default::default()
                };
                let (halt, _) = tokio::sync::watch::channel(false);
                let mut nodes: Vec<armada_kv::Node> = Vec::new();
                for n in ["a", "b", "c"] {
                    let start = if n == "a" {
                        armada_kv::Start::New
                    } else {
                        let r = nodes[0].member_add(
                            armada_proto::etcd::etcdserverpb::MemberAddRequest {
                                peer_ur_ls: vec![peer(n)],
                                is_learner: true,
                            },
                        );
                        tokio::time::timeout(Duration::from_secs(30), r)
                            .await
                            .expect("add a member in time")
                            .expect("add a member");
                        armada_kv::Start::Join(vec![peer("a")])
                    };
                    std::fs::create_dir_all(d.join(n)).expect("mkdir");
                    let node = armada_kv::Node::open(&d.join(n).join("data"), opts(n, start))
                        .await
                        .expect("open armada-kv");
                    let mut h = halt.subscribe();
                    let sock = d.join(n).join("peer.sock");
                    let served = node.clone();
                    tokio::spawn(async move {
                        let _ = armada_kv::serve_peer_unix(served, &sock, async move {
                            let _ = h.wait_for(|s| *s).await;
                        })
                        .await;
                    });
                    nodes.push(node);
                }
                for n in &nodes[1..] {
                    let id = n.id();
                    let deadline = Instant::now() + Duration::from_secs(30);
                    loop {
                        let r = nodes[0]
                            .member_promote(
                                armada_proto::etcd::etcdserverpb::MemberPromoteRequest { id },
                            )
                            .await;
                        match r {
                            Ok(_) => break,
                            Err(e) => assert!(Instant::now() < deadline, "promote: {e}"),
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
                let members = nodes[1].members();
                assert!(
                    members.len() == 3 && members.iter().all(|m| !m.is_learner),
                    "three voters: {members:?}"
                );
                armada_kv::serve_unix(nodes[1].clone(), &d.join("client.sock"), async {
                    let _ = stopped.await;
                })
                .await
                .expect("serve armada-kv");
                let _ = halt.send(true);
                for n in &nodes {
                    n.close().await;
                }
            });
        });
        Member {
            backend: Backend::Kv {
                stop: Some(stop),
                thread: Some(thread),
            },
            dir,
        }
    }

    fn socket(&self) -> PathBuf {
        self.dir.join("client.sock")
    }

    async fn ready(&mut self) -> Client {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match &mut self.backend {
                Backend::Etcd(child) => {
                    if let Ok(Some(st)) = child.try_wait() {
                        panic!("etcd exited: {st}");
                    }
                }
                Backend::Kv { thread, .. } => {
                    assert!(
                        !thread.as_ref().is_some_and(|t| t.is_finished()),
                        "armada-kv stopped"
                    );
                }
            }
            if self.socket().exists() {
                let c = Client::connect_unix(&self.socket()).expect("connect");
                if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_secs(3), c.status()).await {
                    return c;
                }
            }
            assert!(
                Instant::now() < deadline,
                "the member did not become ready within a minute"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// One armada-store-parity process: requests go in as lines, answers come
/// back by ID in any order.
struct Proc {
    child: Child,
    stdin: ChildStdin,
    answers: Receiver<Value>,
    stash: HashMap<i64, Value>,
    next: i64,
    socket: String,
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Proc {
    fn start(member: &Member) -> Proc {
        let mut child = Command::new(env!("CARGO_BIN_EXE_armada-store-parity"))
            .env("TZ", "UTC")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start armada-store-parity");
        let stdin = child.stdin.take().expect("stdin");
        let out = child.stdout.take().expect("stdout");
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                let Ok(line) = line else { break };
                let v: Value = serde_json::from_str(&line).expect("a JSON answer");
                if tx.send(v).is_err() {
                    break;
                }
            }
        });
        Proc {
            child,
            stdin,
            answers: rx,
            stash: HashMap::new(),
            next: 0,
            socket: member.socket().to_str().expect("UTF-8").to_string(),
        }
    }

    /// Sends a request, with the member's socket where it opens a client.
    fn send(&mut self, mut req: Value) -> i64 {
        self.next += 1;
        req["id"] = json!(self.next);
        req["socket"] = json!(self.socket);
        let mut b = serde_json::to_vec(&req).expect("encode");
        b.push(b'\n');
        self.stdin.write_all(&b).expect("write");
        self.stdin.flush().expect("flush");
        self.next
    }

    /// The answer to request `id`, or None when it has not come within
    /// `wait`.
    fn answer_within(&mut self, id: i64, wait: Duration) -> Option<Value> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(v) = self.stash.remove(&id) {
                return Some(v);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            match self.answers.recv_timeout(left) {
                Ok(v) => {
                    let got = v["id"].as_i64().expect("an answer's id");
                    self.stash.insert(got, v);
                }
                Err(RecvTimeoutError::Timeout) => return None,
                Err(RecvTimeoutError::Disconnected) => panic!("armada-store-parity exited"),
            }
        }
    }

    fn answer(&mut self, id: i64) -> Value {
        self.answer_within(id, Duration::from_secs(120))
            .unwrap_or_else(|| panic!("armada-store-parity did not answer request {id}"))
    }

    fn call(&mut self, req: Value) -> Value {
        let id = self.send(req);
        self.answer(id)
    }

    fn ok(&mut self, req: Value) -> Value {
        let what = req.to_string();
        let a = self.call(req);
        if let Some(e) = a["error"].as_str() {
            panic!("armada-store-parity {what}: {e}");
        }
        a["value"].clone()
    }
}

/// What the replay compares: times as UTC instants, and missing and empty
/// lists and maps alike.
fn normalize(v: &Value) -> Value {
    match v {
        Value::Object(m) if m.is_empty() => Value::Null,
        Value::Object(m) => {
            Value::Object(m.iter().map(|(k, v)| (k.clone(), normalize(v))).collect())
        }
        Value::Array(a) if a.is_empty() => Value::Null,
        Value::Array(a) => Value::Array(a.iter().map(normalize).collect()),
        Value::String(s)
            if s.len() >= 20 && s.as_bytes()[4] == b'-' && s.as_bytes()[10] == b'T' =>
        {
            match parse_rfc3339(s) {
                Some(t) => Value::String(t.in_loc(&Location::utc()).rfc3339_nano()),
                None => v.clone(),
            }
        }
        _ => v.clone(),
    }
}

/// JSON values compared as values, numbers as float64.
fn same_json(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(a, b)| same_json(a, b))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| same_json(v, w)))
        }
        _ => a == b,
    }
}

async fn dump(c: &Client, prefix: &str) -> BTreeMap<String, String> {
    let r = c.range(op::get_prefix(prefix, 0)).await.expect("range");
    r.kvs
        .into_iter()
        .map(|kv| {
            let k = String::from_utf8_lossy(&kv.key);
            (
                k.strip_prefix(prefix).unwrap_or(&k).to_string(),
                String::from_utf8_lossy(&kv.value).into_owned(),
            )
        })
        .collect()
}

fn diff_keyspaces(want: &BTreeMap<String, String>, got: &BTreeMap<String, String>) -> Vec<String> {
    let mut d = Vec::new();
    for (k, v) in want {
        match got.get(k) {
            None => d.push(format!("only the recording has {k} = {v}")),
            Some(r) if r != v => d.push(format!("{k}:\n  want {v}\n  got  {r}")),
            _ => {}
        }
    }
    for (k, v) in got {
        if !want.contains_key(k) {
            d.push(format!("only the replay wrote {k} = {v}"));
        }
    }
    d
}

fn compact(v: &Value) -> String {
    let s = v.to_string();
    if s.chars().count() > 300 {
        format!("{}...", s.chars().take(300).collect::<String>())
    } else {
        s
    }
}

fn str_map(v: &Value) -> BTreeMap<String, String> {
    v.as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Replays one recording on its own prefix; the first difference fails it.
async fn replay(p: &mut Proc, c: &Client, name: &str, text: &str) -> Result<usize, String> {
    let prefix = format!("/replay/{name}/");
    let handle = format!("h-{name}");
    let mut want = BTreeMap::new();
    let mut calls = 0;
    for (n, line) in text.lines().enumerate() {
        let step: Value = serde_json::from_str(line).map_err(|e| format!("line {}: {e}", n + 1))?;
        let at = |what: String| format!("{name} step {} ({}): {what}", n + 1, step["op"]);
        match step["op"].as_str().unwrap_or_default() {
            "seed" => {
                for (k, v) in str_map(&step["keys"]) {
                    c.put(&format!("{prefix}{k}"), v.as_bytes())
                        .await
                        .map_err(|e| at(e.to_string()))?;
                    want.insert(k, v);
                }
            }
            "put" => {
                let (k, v) = (
                    step["key"].as_str().unwrap_or_default(),
                    step["value"].as_str().unwrap_or_default(),
                );
                c.put(&format!("{prefix}{k}"), v.as_bytes())
                    .await
                    .map_err(|e| at(e.to_string()))?;
                want.insert(k.to_string(), v.to_string());
            }
            "open" => {
                p.ok(json!({"op": "open", "handle": handle, "prefix": prefix, "ms": step["ms"]}));
                want = str_map(&step["keys"]);
            }
            "openFails" => {
                let pfx = step["prefix"]
                    .as_str()
                    .map_or(prefix.clone(), str::to_string);
                let a =
                    p.call(json!({"op": "open", "handle": format!("{handle}-x"), "prefix": pfx}));
                let (w, g) = (
                    step["error"].as_str().unwrap_or_default(),
                    a["error"].as_str().unwrap_or_default(),
                );
                if w != g {
                    return Err(at(format!("opening {pfx}:\n  want {w:?}\n  got  {g:?}")));
                }
                continue;
            }
            "setNow" => {
                p.ok(json!({"op": "setNow", "handle": handle, "ms": step["ms"]}));
            }
            "reencode" => {
                let d = p.ok(json!({"op": "reencode", "handle": handle}));
                if let Some(d) = d.as_array().filter(|d| !d.is_empty()) {
                    let lines: Vec<String> = d
                        .iter()
                        .map(|x| {
                            format!(
                                "{} encodes differently:\n  stored  {}\n  encoded {}",
                                x["key"], x["stored"], x["encoded"]
                            )
                        })
                        .collect();
                    return Err(at(lines.join("\n")));
                }
            }
            "leased" => {
                let pfx = format!("{prefix}{}", step["prefix"].as_str().unwrap_or_default());
                let r = c
                    .range(op::get_prefix(&pfx, 0))
                    .await
                    .map_err(|e| at(e.to_string()))?;
                let count = step["count"].as_u64().unwrap_or_default() as usize;
                if r.kvs.len() != count || r.kvs.iter().any(|kv| kv.lease == 0) {
                    return Err(at(format!(
                        "{} keys under {pfx}, want {count}, each with a lease",
                        r.kvs.len()
                    )));
                }
            }
            "call" => {
                calls += 1;
                let method = step["method"].as_str().unwrap_or_default();
                let what = format!("{method} {}", compact(&step["args"]));
                let a = p.call(
                    json!({"op": "call", "handle": handle, "method": method, "args": step["args"]}),
                );
                let w = &step["want"];
                let (wk, gk) = (
                    w["kind"].as_str().unwrap_or_default(),
                    a["kind"].as_str().unwrap_or_default(),
                );
                let (we, ge) = (
                    w["error"].as_str().unwrap_or_default(),
                    a["error"].as_str().unwrap_or_default(),
                );
                if wk != gk || we != ge {
                    return Err(at(format!(
                        "{what}:\n  want {we:?} ({wk})\n  got  {ge:?} ({gk})"
                    )));
                }
                if we.is_empty() {
                    let (gv, rv) = (normalize(&w["value"]), normalize(&a["value"]));
                    if !same_json(&gv, &rv) {
                        return Err(at(format!(
                            "{what} answers differ:\n  want {gv}\n  got  {rv}"
                        )));
                    }
                }
                for (k, v) in str_map(&step["set"]) {
                    want.insert(k, v);
                }
                for k in step["del"].as_array().into_iter().flatten() {
                    want.remove(k.as_str().unwrap_or_default());
                }
            }
            other => return Err(at(format!("unknown step {other}"))),
        }
        let d = diff_keyspaces(&want, &dump(c, &prefix).await);
        if !d.is_empty() {
            return Err(at(format!("the keyspaces differ:\n{}", d.join("\n"))));
        }
    }
    Ok(calls)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

#[test]
fn recordings_replay() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("testdata")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .collect();
    files.sort();
    assert!(
        files.len() >= 9,
        "{} recordings in {}",
        files.len(),
        dir.display()
    );
    let rt = runtime();
    let mut member = Member::start("replay");
    let c = rt.block_on(member.ready());
    let mut p = Proc::start(&member);
    let mut failed = Vec::new();
    let mut calls = 0;
    for f in &files {
        let name = f.file_stem().unwrap().to_str().unwrap().to_string();
        let text = std::fs::read_to_string(f).expect("read");
        match rt.block_on(replay(&mut p, &c, &name, &text)) {
            Ok(n) => calls += n,
            Err(e) => failed.push(e),
        }
    }
    assert!(
        failed.is_empty(),
        "{} of {} recordings differ:\n\n{}",
        failed.len(),
        files.len(),
        failed.join("\n\n")
    );
    assert!(calls >= 400, "only {calls} calls replayed");
    eprintln!(
        "replayed {calls} calls of {} recordings on {}",
        files.len(),
        match kv_members() {
            0 => "etcd",
            1 => "armada-kv",
            _ => "three armada-kv members",
        }
    );
}

fn texts() -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/texts.json");
    serde_json::from_slice(&std::fs::read(p).expect("texts.json")).expect("JSON")
}

fn rfc3339(at: SystemTime) -> String {
    let d = at.duration_since(UNIX_EPOCH).expect("after 1970");
    Time {
        unix: d.as_secs() as i64,
        nsec: i64::from(d.subsec_nanos()),
        loc: Location::utc(),
    }
    .rfc3339_nano()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// Two servers on one keyspace: two writers, fencing, one election, one
/// lock, and a lease kept alive.
#[test]
fn shared_keyspace() {
    let texts = texts();
    let rt = runtime();
    let mut member = Member::start("alone");
    let c = rt.block_on(member.ready());
    let mut p = Proc::start(&member);

    // Two stores write one keyspace at once: every transaction sees the
    // other's writes or runs again.
    let prefix = "/alone/writers/";
    for h in ["a", "b"] {
        p.ok(json!({"op": "open", "handle": h, "prefix": prefix, "ms": now_ms()}));
    }
    let each = 60;
    let ids: Vec<i64> = ["a", "b"]
        .iter()
        .map(|h| {
            p.send(json!({"op": "call", "handle": h, "method": "RecordAudit", "repeat": each, "parallel": 6,
                "args": {"actor": h, "action": "x", "target": "t"}}))
        })
        .collect();
    for id in ids {
        let a = p.answer(id);
        assert!(a["error"].is_null(), "{a}");
    }
    let events =
        p.ok(json!({"op": "call", "handle": "a", "method": "ListAudit", "args": {"limit": 1000}}));
    let events = events.as_array().expect("events");
    let mut seen = std::collections::HashSet::new();
    let mut by: HashMap<String, usize> = HashMap::new();
    for e in events {
        seen.insert(e["ID"].as_i64().expect("ID"));
        *by.entry(e["Actor"].as_str().unwrap_or_default().to_string())
            .or_default() += 1;
    }
    assert_eq!((events.len(), seen.len()), (2 * each, 2 * each), "{by:?}");
    assert_eq!((by["a"], by["b"]), (each, each));
    let other =
        p.ok(json!({"op": "call", "handle": "b", "method": "ListAudit", "args": {"limit": 1000}}));
    assert_eq!(
        &other,
        &Value::Array(events.clone()),
        "both read the same log"
    );

    // A join token redeemed by both at once is consumed once.
    let exp = rfc3339(SystemTime::now() + Duration::from_secs(3600));
    p.ok(
        json!({"op": "call", "handle": "a", "method": "CreateJoinToken",
        "args": {"token": {"ID": "tok", "SecretHash": "h", "ExpiresAt": exp}}}),
    );
    let mut redeem = Vec::new();
    for i in 0..10 {
        let h = if i % 2 == 0 { "a" } else { "b" };
        redeem.push(p.send(json!({"op": "call", "handle": h, "method": "RedeemJoinToken", "args": {
            "id": "tok", "hash": "h", "node": {"ID": format!("n{i}"), "PrivateIP": format!("10.0.1.{i}")},
            "cert": {"Serial": "x", "NotAfter": exp}}})));
    }
    let mut wins = 0;
    for id in redeem {
        let a = p.answer(id);
        match a["kind"].as_str() {
            None => wins += 1,
            Some("notFound") => {}
            Some(k) => panic!("redeem: {} ({k})", a["error"]),
        }
    }
    let nodes = p.ok(json!({"op": "call", "handle": "a", "method": "ListNodes", "args": {}}));
    assert_eq!(
        (wins, nodes.as_array().map_or(0, Vec::len)),
        (1, 1),
        "redemptions won, nodes"
    );

    // A store fenced to a term writes until the term ends, then nothing.
    let fp = "/alone/fenced/";
    p.ok(json!({"op": "open", "handle": "s", "prefix": fp, "ms": now_ms()}));
    let fence = p.ok(json!({"op": "campaign", "handle": "lead", "ttl": 5, "name": "rust-1"}));
    let key = fence["key"].as_str().expect("key").to_string();
    assert!(key.starts_with("/armada-leader//"), "election key {key}");
    p.ok(json!({"op": "fenced", "handle": "sf", "from": "s", "key": key, "rev": fence["rev"]}));
    let event = json!({"event": {"Kind": "k", "Object": "o", "Reason": "r", "Count": 1,
        "First": rfc3339(SystemTime::now()), "Last": rfc3339(SystemTime::now())}});
    p.ok(json!({"op": "call", "handle": "sf", "method": "SetMeta", "args": {"key": "a", "value": "1"}}));
    p.ok(json!({"op": "call", "handle": "sf", "method": "PutEvent", "args": event}));
    p.ok(json!({"op": "resign", "handle": "lead"}));
    for (method, args) in [
        ("SetMeta", json!({"key": "a", "value": "2"})),
        ("PutEvent", event.clone()),
    ] {
        let a = p.call(json!({"op": "call", "handle": "sf", "method": method, "args": args}));
        assert_eq!(
            (a["kind"].as_str(), a["error"].as_str()),
            (Some("notLeader"), texts["notLeader"].as_str()),
            "{method} after the term"
        );
    }
    let next = p.ok(json!({"op": "campaign", "handle": "lead2", "ttl": 5, "name": "rust-2"}));
    p.ok(json!({"op": "fenced", "handle": "sf2", "from": "s", "key": next["key"], "rev": next["rev"]}));
    p.ok(json!({"op": "call", "handle": "sf2", "method": "SetMeta", "args": {"key": "b", "value": "1"}}));
    let a = p.call(json!({"op": "call", "handle": "sf", "method": "SetMeta", "args": {"key": "b", "value": "2"}}));
    assert_eq!(
        a["kind"].as_str(),
        Some("notLeader"),
        "the old term during the new one"
    );
    let meta =
        p.ok(json!({"op": "call", "handle": "s", "method": "GetMeta", "args": {"key": "b"}}));
    assert_eq!(meta, json!("1"));
    p.ok(json!({"op": "resign", "handle": "lead2"}));

    // One election: the second campaigner waits until the first resigns.
    p.ok(json!({"op": "campaign", "handle": "ea", "ttl": 5, "name": "rust-a"}));
    let b = p.send(json!({"op": "campaign", "handle": "eb", "ttl": 5, "name": "rust-b"}));
    assert!(
        p.answer_within(b, Duration::from_secs(1)).is_none(),
        "rust-b won while rust-a led"
    );
    assert_eq!(p.ok(json!({"op": "leader"})), json!("rust-a"));
    p.ok(json!({"op": "resign", "handle": "ea"}));
    let won = p
        .answer_within(b, Duration::from_secs(30))
        .expect("rust-b took over");
    assert!(won["error"].is_null(), "{won}");
    assert_eq!(p.ok(json!({"op": "leader"})), json!("rust-b"));
    p.ok(json!({"op": "resign", "handle": "eb"}));

    // One lock: TryLock fails while it is held, Lock waits.
    let lock = "/armada-acme/locks/x";
    p.ok(json!({"op": "lock", "handle": "m", "ttl": 5, "prefix": lock}));
    let a = p.call(json!({"op": "tryLock", "handle": "m2", "ttl": 5, "prefix": lock}));
    assert_eq!(
        a["error"].as_str(),
        texts["locked"].as_str(),
        "TryLock while held"
    );
    let m3 = p.send(json!({"op": "lock", "handle": "m3", "ttl": 5, "prefix": lock}));
    assert!(
        p.answer_within(m3, Duration::from_secs(1)).is_none(),
        "locked while held"
    );
    p.ok(json!({"op": "unlock", "handle": "m"}));
    let got = p
        .answer_within(m3, Duration::from_secs(30))
        .expect("the lock once free");
    assert!(got["error"].is_null(), "{got}");
    p.ok(json!({"op": "unlock", "handle": "m3"}));

    // A leader keeps its lease alive past its TTL.
    p.ok(json!({"op": "campaign", "handle": "kept", "ttl": 2, "name": "rust-kept"}));
    std::thread::sleep(Duration::from_secs(7));
    assert_eq!(
        p.ok(json!({"op": "leader"})),
        json!("rust-kept"),
        "leader after three TTLs"
    );
    p.ok(json!({"op": "resign", "handle": "kept"}));
    drop(c);
}

//! The store's parity tests replayed from recordings of Go (ADR 0055, item
//! 20). Before the Go code was removed, Go's TestArmadaStore and
//! TestRecordStoreTexts ran the tests that compare one store with the other
//! against Go's store alone and wrote testdata/<test>.jsonl: every call
//! with its arguments, Go's answer, and the keys it wrote or deleted. Here
//! armada-store-parity runs the same calls on the pinned etcd (`make
//! store-replay`: scripts/etcd-cache.sh puts it in .cache/etcd, or
//! ARMADA_ETCD_DIR names it), with no Go, and after each call its answer
//! (normalized as the Go test normalizes) and its whole keyspace must equal
//! Go's.
//!
//! The Go tests that ran both stores at once (one keyspace written by both,
//! stores fenced to the other side's term, one election and one lock) have
//! nothing to record; `rust_alone` checks the Rust side of each with two
//! Rust writers, Rust terms, and Rust campaigners instead.

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

/// The pinned etcd on Unix sockets in a directory of the build's, without
/// TLS, as `armadad backup` runs a scratch member.
struct Member {
    child: Child,
    dir: PathBuf,
}

impl Drop for Member {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
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
        Member { child, dir }
    }

    fn socket(&self) -> PathBuf {
        self.dir.join("client.sock")
    }

    async fn ready(&mut self) -> Client {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Ok(Some(st)) = self.child.try_wait() {
                panic!("etcd exited: {st}");
            }
            if self.socket().exists() {
                let c = Client::connect_unix(&self.socket()).expect("connect");
                if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_secs(3), c.status()).await {
                    return c;
                }
            }
            assert!(
                Instant::now() < deadline,
                "etcd did not become ready within a minute"
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

/// What the Go test compares: times as UTC instants, and nil and empty
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

/// JSON values as Go's reflect.DeepEqual sees them after json.Unmarshal
/// into any: numbers as float64.
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

fn diff_keyspaces(go: &BTreeMap<String, String>, rust: &BTreeMap<String, String>) -> Vec<String> {
    let mut d = Vec::new();
    for (k, v) in go {
        match rust.get(k) {
            None => d.push(format!("only Go wrote {k} = {v}")),
            Some(r) if r != v => d.push(format!("{k}:\n  go   {v}\n  rust {r}")),
            _ => {}
        }
    }
    for (k, v) in rust {
        if !go.contains_key(k) {
            d.push(format!("only Rust wrote {k} = {v}"));
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
                    return Err(at(format!("opening {pfx}:\n  go   {w:?}\n  rust {g:?}")));
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
                        "{what}:\n  go   {we:?} ({wk})\n  rust {ge:?} ({gk})"
                    )));
                }
                if we.is_empty() {
                    let (gv, rv) = (normalize(&w["value"]), normalize(&a["value"]));
                    if !same_json(&gv, &rv) {
                        return Err(at(format!(
                            "{what} answers differ:\n  go   {gv}\n  rust {rv}"
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
        "{} of {} recordings differ from Go:\n\n{}",
        failed.len(),
        files.len(),
        failed.join("\n\n")
    );
    assert!(calls >= 400, "only {calls} calls replayed");
    eprintln!("replayed {calls} calls of {} recordings", files.len());
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

/// What the Go tests that ran both stores at once checked, with Rust on
/// both sides: two writers on one keyspace, fencing, one election, one
/// lock, and a lease kept alive.
#[test]
fn rust_alone() {
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

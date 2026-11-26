//! The replay of the agent's scenarios recorded from Go's agent (ADR 0055,
//! item 20; internal/agent/parity_record_test.go writes them with
//! -record-scenarios). Each scenario's steps are run against the Rust
//! agent's parity program, its runtime calls answered by the fakes ported
//! to Rust (fake.rs), the sessions' control plane, log endpoint, and
//! armada-node by side.rs, and every step's transcript lines are compared
//! with Go's: the same lines Go's harness wrote, JSON compared whatever
//! the order of its keys, a step's calls sorted as Go's harness sorted
//! them.

pub mod fake;
pub mod gofmt;
pub mod program;
pub mod side;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use fake::Fake;
use gofmt::{canon_line, duration, mode, quote};
use program::Program;

/// Where every scenario starts on the test clock (Go's parityT0).
pub const T0_NS: i64 = 1_767_225_600_000_000_000;

/// The recordings' directory.
pub fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata")
}

/// Every fixture of a test, by name.
pub fn fixtures(test: &str) -> Vec<(String, Value)> {
    let dir = testdata().join("scenarios").join(test);
    let mut out = Vec::new();
    for e in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let p = e.unwrap().path();
        let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        out.push((s(&v["name"]), v));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn b(v: &Value) -> bool {
    v.as_bool().unwrap_or(false)
}

/// A fresh directory for a run, under Cargo's temporary directory for
/// integration tests (never /tmp: it may be memory).
pub fn temp_dir(tag: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let d = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("agent-replay-{}-{n}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// One run of a scenario.
struct Run {
    fake: Arc<Fake>,
    prog: Program,
    side: Option<side::Side>,
    secrets: String,
    volumes: String,
    clock: i64,
    hello: Value,
    export_url: String,
    dirs: Vec<PathBuf>,
}

impl Drop for Run {
    fn drop(&mut self) {
        for d in &self.dirs {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

impl Run {
    fn new(opts: &Value) -> Run {
        let mut dirs = Vec::new();
        let secrets = if b(&opts["noSecretsDir"]) {
            String::new()
        } else {
            let d = temp_dir("secrets");
            dirs.push(d.clone());
            d.display().to_string()
        };
        let mut volumes = if b(&opts["volumesDir"]) {
            let d = temp_dir("volumes");
            dirs.push(d.clone());
            d.display().to_string()
        } else {
            String::new()
        };
        let side = b(&opts["side"]).then(|| {
            let root = temp_dir("side");
            dirs.push(root.clone());
            side::Side::start(root)
        });
        if let Some(sh) = &side {
            volumes = sh.root.join("volumes").display().to_string();
        }
        let mut norm = vec![
            (secrets.clone(), "$SECRETS".to_string()),
            (volumes.clone(), "$VOLUMES".to_string()),
        ];
        if let Some(sh) = &side {
            norm.push((sh.root.display().to_string(), "$ROOT".into()));
        }
        let fake = Arc::new(Fake::new(
            T0_NS,
            s(&opts["bridge"]),
            b(&opts["members"]),
            norm,
        ));
        let prog = Program::start(fake.clone());
        let mut config = json!({
            "nodeId": "n1", "privateIp": "10.0.0.2", "cpuMillis": 2000, "memoryBytes": 1i64 << 30,
            "bootNs": opts["bootNs"], "nowNs": T0_NS, "crashBaseNs": opts["crashBaseNs"],
            "unpublished": b(&opts["unpublished"]), "volumesDir": volumes, "secretsDir": secrets,
            "dns": s(&opts["dns"]), "os": "linux", "arch": "amd64",
            "caps": {"members": b(&opts["members"]), "volumes": b(&opts["volumes"]), "exec": b(&opts["exec"]),
                "stats": b(&opts["stats"]), "proxy": b(&opts["proxy"]), "network": b(&opts["network"]),
                "move": b(&opts["move"]), "logs": true, "encodes": b(&opts["encodes"]), "sandbox": b(&opts["sandbox"])},
            "networkKey": s(&opts["networkKey"]),
        });
        let mut export_url = String::new();
        if let Some(sh) = &side {
            for (k, v) in sh.rust_config().as_object().unwrap() {
                config[k] = v.clone();
            }
            export_url = sh.export_url();
        }
        prog.request("config", json!({"config": config}))
            .expect("config");
        if let Some(sh) = &side {
            prog.request("connect", sh.connect()).expect("connect");
        }
        Run {
            fake,
            prog,
            side,
            secrets,
            volumes,
            clock: T0_NS,
            hello: Value::Null,
            export_url,
            dirs,
        }
    }

    fn normalize(&self, s: &str) -> String {
        self.fake.normalize(s)
    }

    /// The log endpoint's URL written as $EXPORT, as Go's recording wrote it.
    fn unexport(&self, s: &str) -> String {
        if self.export_url.is_empty() {
            return s.to_string();
        }
        s.replace(&self.export_url, "$EXPORT")
    }

    /// The secret files and volume directories, as Go's files() lists them.
    fn files(&self) -> String {
        let mut lines = Vec::new();
        for root in [&self.secrets, &self.volumes] {
            if root.is_empty() {
                continue;
            }
            walk(Path::new(root), &mut |p, meta| {
                let mut line = format!(
                    "{} {}",
                    self.normalize(&p.display().to_string()),
                    mode(meta)
                );
                if meta.file_type().is_file() {
                    line += &format!(" {}", quote(&std::fs::read(p).unwrap_or_default()));
                }
                lines.push(line);
            });
        }
        lines.join("\n")
    }

    fn calls(&self) -> String {
        self.fake.take_calls().join("\n")
    }

    fn reconcile(&self) -> (Value, String) {
        let ans = self
            .prog
            .request("reconcile", json!({}))
            .expect("reconcile");
        if let Some(e) = ans.get("error") {
            return (Value::Null, s(e));
        }
        (ans["report"].clone(), String::new())
    }

    fn step_lines(&self, name: &str, report: &Value, err: &str, calls: String) -> Vec<String> {
        let mut out = vec![format!("step {name}")];
        if err.is_empty() {
            out.push(format!("report {}", self.normalize(&compact(report))));
        } else {
            out.push(format!("error {}", self.normalize(err)));
        }
        out.push(format!("calls {calls}"));
        out.push(format!("files {}", self.files()));
        out
    }

    fn side_ref(&self) -> &side::Side {
        self.side
            .as_ref()
            .expect("a scenario with the sessions' harness")
    }

    /// Runs an action of the agent; its note, if any, is returned.
    fn action(&mut self, a: &Value) -> Option<String> {
        let op = s(&a["op"]);
        let p = &self.prog;
        let res = match op.as_str() {
            "assign" => {
                let text = a["assignment"]
                    .to_string()
                    .replace("$EXPORT", &self.export_url);
                let asg: Value = serde_json::from_str(&text).unwrap();
                p.request("assign", json!({"assignment": asg}))
            }
            "contact" => p.request("contact", json!({"up": a["up"]})),
            "fence" | "prune" | "rotate" | "pruneLogs" | "queues" | "sandboxes" | "cleanNfs" => {
                p.request(&op, json!({}))
            }
            "move" => p.request("move", json!({"to": a["to"]})),
            "hello" => {
                let ans = p.request("hello", json!({})).expect("hello");
                self.hello = ans["hello"].clone();
                Ok(ans)
            }
            "exec" | "logs" | "volume" => p.request(&op, json!({"request": a["request"]})),
            "export" => p.request("export", json!({})),
            other => panic!("unknown action {other}"),
        };
        let res = res.unwrap_or_else(|e| panic!("{e}"));
        match a["note"].as_str() {
            Some("wait") => Some(format!(
                "wait {}",
                duration(res["waitMs"].as_i64().unwrap_or(0) * 1_000_000)
            )),
            Some(k) => panic!("unknown note {k}"),
            None => None,
        }
    }

    /// Runs one step and returns the lines it wrote.
    fn step(&mut self, st: &Value) -> Vec<String> {
        let name = s(&st["name"]);
        match st["op"].as_str().unwrap_or("") {
            "fake" => {
                self.fake.set_script(st["script"].clone());
                vec![]
            }
            "add" => {
                self.fake.add(&st["container"]);
                vec![]
            }
            "setState" => {
                self.fake.set_state(
                    &s(&st["id"]),
                    &s(&st["state"]),
                    st["code"].as_i64().unwrap(),
                );
                vec![]
            }
            "setMember" => {
                self.fake.set_member_state(
                    &s(&st["id"]),
                    &s(&st["name"]),
                    &s(&st["state"]),
                    st["code"].as_i64().unwrap(),
                );
                vec![]
            }
            "nodeScript" => {
                self.side_ref().script(&st["script"]);
                vec![]
            }
            "advance" => {
                self.clock += st["ns"].as_i64().unwrap();
                self.fake.set_clock(self.clock);
                self.prog
                    .request("now", json!({"ns": self.clock}))
                    .expect("now");
                vec![]
            }
            "reconcile" => {
                let (r, e) = self.reconcile();
                let calls = self.calls();
                self.step_lines(&name, &r, &e, calls)
            }
            "until" => {
                // Go's run stopped once its report said what the scenario
                // waited for: this one once it says what Go's said.
                let want = st["expect"][1].as_str().map(canon_line).unwrap_or_default();
                let deadline = Instant::now() + Duration::from_secs(15);
                let mut calls: Vec<String> = Vec::new();
                loop {
                    let (r, e) = self.reconcile();
                    calls.extend(self.fake.take_calls());
                    let line = format!("report {}", self.normalize(&compact(&r)));
                    if e.is_empty() && canon_line(&line) == want || Instant::now() > deadline {
                        calls.sort();
                        calls.dedup();
                        return self.step_lines(&name, &r, &e, calls.join("\n"));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            "sample" => {
                let u = self.prog.request("sample", json!({})).expect("sample");
                vec![
                    format!("usage {name} {}", compact(&u["usage"])),
                    format!("calls {}", self.calls()),
                ]
            }
            "sampleSide" => {
                let mut u =
                    self.prog.request("sample", json!({})).expect("sample")["usage"].clone();
                if let Some(a) = u.get_mut("sandboxes").and_then(Value::as_array_mut) {
                    for x in a {
                        if let Some(o) = x.as_object_mut() {
                            o.remove("ageMillis");
                        }
                    }
                }
                vec![
                    format!("usage {name} {}", self.normalize(&compact(&u))),
                    format!("calls {}", self.calls()),
                    format!("node {}", self.side_ref().node_calls().join("\n")),
                ]
            }
            "other" => {
                for a in st["actions"].as_array().cloned().unwrap_or_default() {
                    assert!(self.action(&a).is_none());
                }
                vec![
                    format!("step {name}"),
                    format!("calls {}", self.calls()),
                    format!("files {}", self.files()),
                ]
            }
            "side" => {
                self.side_ref().set_input(st);
                let mut out = Vec::new();
                for a in st["actions"].as_array().cloned().unwrap_or_default() {
                    out.extend(self.action(&a));
                }
                let sh = self.side_ref();
                out.push(format!("side {name}"));
                out.push(format!("calls {}", self.calls()));
                out.push(format!(
                    "server {}",
                    self.normalize(&sh.server_take().join("\n"))
                ));
                out.push(format!("node {}", sh.node_calls().join("\n")));
                out.push(format!(
                    "export {}",
                    self.unexport(&sh.export_take().join("\n"))
                ));
                out
            }
            "note" => {
                let kind = s(&st["kind"]);
                assert_eq!(st["from"], "hello", "a note of {kind}");
                let mut h = self.hello.clone();
                h["version"] = json!("VERSION");
                vec![format!("{kind} {}", compact(&h))]
            }
            _ => {
                assert!(self.action(st).is_none());
                vec![]
            }
        }
    }
}

/// A message as protojson writes it compactly; null for none.
fn compact(v: &Value) -> String {
    if v.is_null() {
        return "null".into();
    }
    v.to_string()
}

/// Walks a directory as Go's filepath.WalkDir does: lexical order, a
/// directory before what it holds, the root left out.
fn walk(root: &Path, f: &mut dyn FnMut(&Path, &std::fs::Metadata)) {
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    let mut names: Vec<_> = rd.flatten().map(|e| e.file_name()).collect();
    names.sort();
    for n in names {
        let p = root.join(n);
        let Ok(meta) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        f(&p, &meta);
        if meta.is_dir() {
            walk(&p, f);
        }
    }
}

/// Replays one scenario; the differences from Go's transcript, if any.
pub fn replay(fx: &Value) -> Vec<String> {
    let mut run = Run::new(&fx["opts"]);
    let mut diffs = Vec::new();
    for (i, st) in fx["steps"].as_array().unwrap().iter().enumerate() {
        let got = run.step(st);
        let want: Vec<String> = st["expect"]
            .as_array()
            .map(|a| a.iter().map(s).collect())
            .unwrap_or_default();
        let n = want.len().max(got.len());
        for j in 0..n {
            let w = want.get(j).map(|l| canon_line(l)).unwrap_or_default();
            let g = got
                .get(j)
                .map(|l| canon_line(&run.unexport(l)))
                .unwrap_or_default();
            if w != g {
                diffs.push(format!(
                    "step {i} ({} {}):\n go:   {}\n rust: {}",
                    s(&st["op"]),
                    s(&st["name"]),
                    want.get(j).cloned().unwrap_or_default(),
                    got.get(j).cloned().unwrap_or_default()
                ));
            }
        }
        if diffs.len() >= 3 {
            break;
        }
    }
    diffs
}

/// Replays every scenario of a test, a few at once, and fails with every
/// difference.
pub fn replay_all(test: &str) {
    let fxs = fixtures(test);
    assert!(!fxs.is_empty(), "no recordings of {test}");
    let only = std::env::var("ARMADA_REPLAY_ONLY").unwrap_or_default();
    let queue = std::sync::Mutex::new(fxs.into_iter());
    let failures = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|sc| {
        for _ in 0..4 {
            sc.spawn(|| {
                loop {
                    let Some((name, fx)) = queue.lock().unwrap().next() else {
                        break;
                    };
                    if !only.is_empty() && !name.contains(&only) {
                        continue;
                    }
                    let diffs = replay(&fx);
                    if !diffs.is_empty() {
                        failures
                            .lock()
                            .unwrap()
                            .push(format!("{name}:\n{}", diffs.join("\n")));
                    }
                }
            });
        }
    });
    let failures = failures.into_inner().unwrap();
    assert!(
        failures.is_empty(),
        "{} scenario(s) differ from Go's recording:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

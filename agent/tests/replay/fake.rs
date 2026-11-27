//! pfake and the fakes beside it: the runtime, the proxy, the cluster
//! network, the resolver, the certificate source, and the runtime move
//! hooks, answering the program's calls as the recordings say and noting
//! each call in the recordings' form.
//! What a scenario sets on them comes from the recording (`fake` steps:
//! the whole script after each change).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use super::gofmt::{b64_decode, fnv32a};

const RUNNING: &str = "running";
const STARTING: &str = "starting";
const EXITED: &str = "exited";
const LABEL_ROLE: &str = "armada.role";
const LABEL_CONTAINER: &str = "armada.container";
const LABEL_REPLICA: &str = "armada.replica";

#[derive(Clone, Debug, Default)]
struct Ctr {
    id: String,
    name: String,
    image: String,
    labels: BTreeMap<String, String>,
    state: String,
    exit_code: i64,
    host_ip: String,
    host_port: i64,
    ip: String,
    started_ns: i64,
    start_error: String,
}

#[derive(Default)]
struct State {
    clock_ns: i64,
    containers: BTreeMap<String, Ctr>,
    specs: HashMap<String, Value>,
    pod: BTreeMap<String, String>,
    generation: HashMap<String, i64>,
    calls: Vec<String>,
    script: Value,
    failed: HashMap<String, i64>,
    keys: i64,
    boxes: BTreeMap<String, String>,
}

/// The fakes of one run.
pub struct Fake {
    st: Mutex<State>,
    pulls: Condvar,
    pub bridge: String,
    pub members: bool,
    /// Directories written as $SECRETS, $VOLUMES, and $ROOT.
    pub norm: Vec<(String, String)>,
}

pub type Answer = Result<Value, Value>;

fn other(text: impl Into<String>) -> Value {
    json!({"kind": "other", "text": text.into()})
}

fn not_found() -> Value {
    json!({"kind": "notFound"})
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn int(v: &Value) -> i64 {
    v.as_i64().unwrap_or(0)
}

fn empty(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Array(a) => a.is_empty(),
        Value::Object(m) => m.is_empty(),
        Value::String(s) => s.is_empty(),
        Value::Number(n) => n.as_f64() == Some(0.0),
        Value::Bool(b) => !b,
    }
}

/// Sets k on m when v is not empty.
fn omit(m: &mut serde_json::Map<String, Value>, k: &str, v: &Value) {
    if !empty(v) {
        m.insert(k.into(), v.clone());
    }
}

fn wire_files(v: &Value) -> Value {
    match v.as_array() {
        Some(a) if !a.is_empty() => Value::Array(
            a.iter()
                .map(|f| json!({"source": s(&f["source"]), "target": s(&f["target"])}))
                .collect(),
        ),
        _ => Value::Null,
    }
}

fn wire_volumes(v: &Value) -> Value {
    match v.as_array() {
        Some(a) if !a.is_empty() => Value::Array(
            a.iter()
                .map(|x| {
                    let mut m = serde_json::Map::new();
                    m.insert("source".into(), json!(s(&x["source"])));
                    m.insert("target".into(), json!(s(&x["target"])));
                    omit(&mut m, "shared", &x["shared"]);
                    omit(&mut m, "readOnly", &x["readOnly"]);
                    Value::Object(m)
                })
                .collect(),
        ),
        _ => Value::Null,
    }
}

fn wire_member(x: &Value) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("name".into(), json!(s(&x["name"])));
    m.insert("image".into(), json!(s(&x["image"])));
    for k in [
        "entrypoint",
        "cmd",
        "env",
        "memoryBytes",
        "nanoCpus",
        "cpuReserveMillis",
        "pidsLimit",
    ] {
        omit(&mut m, k, &x[k]);
    }
    omit(&mut m, "files", &wire_files(&x["files"]));
    omit(&mut m, "volumes", &wire_volumes(&x["volumes"]));
    Value::Object(m)
}

/// The spec in the recordings' form after reading it back.
fn wire_spec(x: &Value) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("name".into(), json!(s(&x["name"])));
    m.insert("image".into(), json!(s(&x["image"])));
    for k in [
        "entrypoint",
        "cmd",
        "env",
        "labels",
        "port",
        "hostIp",
        "memoryBytes",
        "nanoCpus",
        "cpuReserveMillis",
        "pidsLimit",
    ] {
        omit(&mut m, k, &x[k]);
    }
    omit(&mut m, "files", &wire_files(&x["files"]));
    omit(&mut m, "dns", &x["dns"]);
    omit(&mut m, "dnsSearch", &x["dnsSearch"]);
    omit(&mut m, "volumes", &wire_volumes(&x["volumes"]));
    for k in ["init", "sidecars"] {
        if let Some(a) = x[k].as_array().filter(|a| !a.is_empty()) {
            m.insert(k.into(), Value::Array(a.iter().map(wire_member).collect()));
        }
    }
    Value::Object(m)
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(s).collect())
        .unwrap_or_default()
}

/// A plain name quoted (see gofmt::quote).
fn q(name: &str) -> String {
    super::gofmt::quote(name.as_bytes())
}

/// A duration as the scripts write them ("300ms", "2s").
fn parse_duration(d: &str) -> Duration {
    if let Some(n) = d.strip_suffix("ms") {
        return Duration::from_millis(n.parse().unwrap_or(0));
    }
    if let Some(n) = d.strip_suffix('s') {
        return Duration::from_secs_f64(n.parse().unwrap_or(0.0));
    }
    Duration::ZERO
}

impl Fake {
    pub fn new(clock_ns: i64, bridge: String, members: bool, norm: Vec<(String, String)>) -> Fake {
        Fake {
            st: Mutex::new(State {
                clock_ns,
                script: json!({}),
                ..State::default()
            }),
            pulls: Condvar::new(),
            bridge,
            members,
            norm,
        }
    }

    pub fn normalize(&self, s: &str) -> String {
        let mut s = s.to_string();
        for (from, to) in &self.norm {
            if !from.is_empty() {
                s = s.replace(from.as_str(), to);
            }
        }
        s
    }

    pub fn set_clock(&self, ns: i64) {
        self.st.lock().unwrap().clock_ns = ns;
    }

    /// A whole script, as recorded after a change.
    pub fn set_script(&self, sc: Value) {
        let mut st = self.st.lock().unwrap();
        st.boxes = sc["side"]["boxes"]
            .as_object()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), s(v))).collect())
            .unwrap_or_default();
        st.script = sc;
        drop(st);
        self.pulls.notify_all();
    }

    pub fn add(&self, c: &Value) {
        let ctr = Ctr {
            id: s(&c["id"]),
            name: s(&c["name"]),
            image: s(&c["image"]),
            labels: c["labels"]
                .as_object()
                .map(|m| m.iter().map(|(k, v)| (k.clone(), s(v))).collect())
                .unwrap_or_default(),
            state: s(&c["state"]),
            exit_code: int(&c["exitCode"]),
            host_ip: s(&c["hostIp"]),
            host_port: int(&c["hostPort"]),
            ip: s(&c["ip"]),
            started_ns: int(&c["startedNs"]),
            start_error: s(&c["startError"]),
        };
        self.st
            .lock()
            .unwrap()
            .containers
            .insert(ctr.id.clone(), ctr);
    }

    pub fn set_state(&self, id: &str, state: &str, code: i64) {
        if let Some(c) = self.st.lock().unwrap().containers.get_mut(id) {
            c.state = state.into();
            c.exit_code = code;
        }
    }

    /// The calls since the last time, sorted, equal pulls once.
    pub fn take_calls(&self) -> Vec<String> {
        let mut c = std::mem::take(&mut self.st.lock().unwrap().calls);
        c.sort();
        c.dedup_by(|a, b| a == b && a.starts_with("pull "));
        c
    }

    fn record(&self, st: &mut State, method: &str, args: Value) {
        let line = format!("{method} {}", self.normalize(&args.to_string()));
        st.calls.push(line);
    }

    fn members_of(st: &State, id: &str) -> Vec<Value> {
        let mut out: Vec<(String, Value)> = Vec::new();
        for (mid, main) in &st.pod {
            if main != id {
                continue;
            }
            let Some(c) = st.containers.get(mid) else {
                continue;
            };
            out.push((
                mid.clone(),
                json!({"id": mid, "name": c.labels.get(LABEL_CONTAINER).cloned().unwrap_or_default(),
                    "role": c.labels.get(LABEL_ROLE).cloned().unwrap_or_default(), "state": c.state,
                    "exitCode": c.exit_code, "startedNs": c.started_ns}),
            ));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out.into_iter().map(|(_, v)| v).collect()
    }

    fn wire(st: &State, c: &Ctr) -> Value {
        json!({"id": c.id, "name": c.name, "image": c.image, "labels": c.labels, "state": c.state,
            "exitCode": c.exit_code, "hostIp": c.host_ip, "hostPort": c.host_port, "ip": c.ip,
            "startedNs": c.started_ns, "members": Self::members_of(st, &c.id), "startError": c.start_error})
    }

    fn bring_up(st: &mut State, id: &str) {
        let (Some(c), Some(spec)) = (st.containers.get(id).cloned(), st.specs.get(id).cloned())
        else {
            return;
        };
        if c.state != STARTING {
            return;
        }
        let labels: BTreeMap<String, String> = spec["labels"]
            .as_object()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), s(v))).collect())
            .unwrap_or_default();
        let now = st.clock_ns;
        let add = |st: &mut State, m: &Value, role: &str, state: &str, code: i64| {
            let mid = format!("{id}-{}", s(&m["name"]));
            let mut l = labels.clone();
            l.insert(LABEL_ROLE.into(), role.into());
            l.insert(LABEL_CONTAINER.into(), s(&m["name"]));
            st.containers.insert(
                mid.clone(),
                Ctr {
                    id: mid.clone(),
                    name: format!("{}-{}", s(&spec["name"]), s(&m["name"])),
                    image: s(&m["image"]),
                    labels: l,
                    state: state.into(),
                    exit_code: code,
                    started_ns: now,
                    ..Ctr::default()
                },
            );
            st.pod.insert(mid, id.to_string());
        };
        for m in spec["init"].as_array().cloned().unwrap_or_default() {
            let code = int(&st.script["initExits"][s(&m["name"])]);
            add(st, &m, "init", EXITED, code);
            if code != 0 {
                let c = st.containers.get_mut(id).unwrap();
                c.state = EXITED.into();
                c.exit_code = 255;
                return;
            }
        }
        for m in spec["sidecars"].as_array().cloned().unwrap_or_default() {
            add(st, &m, "sidecar", RUNNING, 0);
        }
        st.containers.get_mut(id).unwrap().state = RUNNING.into();
    }

    pub fn set_member_state(&self, id: &str, name: &str, state: &str, code: i64) {
        self.set_state(&format!("{id}-{name}"), state, code);
    }

    fn local(v: &Value) -> Value {
        match v {
            Value::Object(_) => v.clone(),
            _ => Value::Null,
        }
    }

    fn err_of(sc: &Value, key: &str) -> Result<(), Value> {
        match sc[key].as_str() {
            Some(e) if !e.is_empty() => Err(other(e)),
            _ => Ok(()),
        }
    }

    /// Answers one call of the program.
    pub fn answer(&self, method: &str, c: &Value) -> Answer {
        match method {
            "pull" => return self.pull(c),
            "exec" => return self.exec_probe(c),
            "check" => return Ok(self.check(c)),
            _ => {}
        }
        let mut st = self.st.lock().unwrap();
        let st = &mut *st;
        let sc = st.script.clone();
        match method {
            "ping" => Ok(Value::Null),
            "run" => self.run(st, c),
            "stop" => {
                let id = s(&c["id"]);
                self.record(st, "stop", json!({"id": id, "graceMs": int(&c["graceMs"])}));
                let Some(ct) = st.containers.get_mut(&id) else {
                    return Err(not_found());
                };
                ct.state = EXITED.into();
                let members: Vec<String> = st
                    .pod
                    .iter()
                    .filter(|(_, m)| **m == id)
                    .map(|(k, _)| k.clone())
                    .collect();
                for m in members {
                    if let Some(mc) = st.containers.get_mut(&m)
                        && mc.labels.get(LABEL_ROLE).map(String::as_str) == Some("sidecar")
                        && mc.state == RUNNING
                    {
                        mc.state = EXITED.into();
                    }
                }
                Ok(Value::Null)
            }
            "remove" => {
                let id = s(&c["id"]);
                self.record(st, "remove", json!({"id": id}));
                if !st.containers.contains_key(&id) {
                    return Err(not_found());
                }
                let members: Vec<String> = st
                    .pod
                    .iter()
                    .filter(|(_, m)| **m == id)
                    .map(|(k, _)| k.clone())
                    .collect();
                for m in members {
                    st.containers.remove(&m);
                    st.pod.remove(&m);
                }
                st.containers.remove(&id);
                st.specs.remove(&id);
                st.pod.remove(&id);
                Ok(Value::Null)
            }
            "list" => {
                let labels = match &c["labels"] {
                    Value::Object(m) => Value::Object(m.clone()),
                    _ => Value::Null,
                };
                self.record(st, "list", json!({"labels": labels}));
                let want: BTreeMap<String, String> = labels
                    .as_object()
                    .map(|m| m.iter().map(|(k, v)| (k.clone(), s(v))).collect())
                    .unwrap_or_default();
                let mut out: Vec<&Ctr> = st
                    .containers
                    .values()
                    .filter(|ct| {
                        !st.pod
                            .get(&ct.id)
                            .is_some_and(|main| st.containers.contains_key(main))
                    })
                    .filter(|ct| {
                        want.iter()
                            .all(|(k, v)| ct.labels.get(k).map(String::as_str).unwrap_or("") == v)
                    })
                    .collect();
                out.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(Value::Array(
                    out.into_iter().map(|ct| Self::wire(st, ct)).collect(),
                ))
            }
            "inspect" => {
                let id = s(&c["id"]);
                self.record(st, "inspect", json!({"id": id}));
                match st.containers.get(&id) {
                    Some(ct) => Ok(Self::wire(st, ct)),
                    None => Err(not_found()),
                }
            }
            "stats" => {
                let id = s(&c["id"]);
                self.record(st, "stats", json!({"id": id}));
                let Some(ct) = st.containers.get(&id) else {
                    return Err(not_found());
                };
                let replica = ct.labels.get(LABEL_REPLICA).cloned().unwrap_or_default();
                let u = &sc["usage"][&replica];
                if ct.state != RUNNING && int(&u["oomKills"]) == 0 {
                    return Err(other(format!("container {id} is not running")));
                }
                Ok(
                    json!({"cpuNs": int(&u["cpuNs"]), "memoryBytes": int(&u["memoryBytes"]),
                    "egressBytes": int(&u["egressBytes"]), "networkLost": u["networkLost"].as_bool().unwrap_or(false),
                    "oomKills": int(&u["oomKills"])}),
                )
            }
            "release" => {
                self.record(st, "release", json!({"id": s(&c["id"])}));
                Ok(Value::Null)
            }
            "prune" => {
                let mut keep = strings(&c["keep"]);
                keep.sort();
                let keep = if keep.is_empty() {
                    Value::Null
                } else {
                    json!(keep)
                };
                self.record(
                    st,
                    "prune",
                    json!({"keep": keep, "graceMs": int(&c["graceMs"])}),
                );
                Ok(Value::Null)
            }
            "runtimeAgent" => {
                let a = &sc["agentStatus"];
                Ok(if a.is_object() {
                    json!({"runcContainers": int(&a["runcContainers"])})
                } else {
                    Value::Null
                })
            }
            _ => self.answer_more(st, &sc, method, c),
        }
    }

    fn pull(&self, c: &Value) -> Answer {
        let mut st = self.st.lock().unwrap();
        while st.script["holdPulls"].as_bool().unwrap_or(false) {
            st = self.pulls.wait(st).unwrap();
        }
        let image = s(&c["image"]);
        let auth = match &c["auth"] {
            Value::Object(a) => {
                json!({"username": s(&a["username"]), "password": s(&a["password"]),
                "serverAddress": s(&a["serverAddress"])})
            }
            _ => Value::Null,
        };
        self.record(&mut st, "pull", json!({"image": image, "auth": auth}));
        let sc = &st.script;
        if let Some(e) = sc["pullErr"].get(&image) {
            return Err(e.clone());
        }
        let platforms = match sc["platforms"].get(&image) {
            Some(Value::Array(a)) => Value::Array(a.clone()),
            _ => Value::Null,
        };
        Ok(json!({"ref": s(&sc["digests"][&image]), "platforms": platforms}))
    }

    fn run(&self, st: &mut State, c: &Value) -> Answer {
        let spec = wire_spec(&c["spec"]);
        self.record(st, "run", json!({"spec": spec}));
        let name = s(&spec["name"]);
        let image = s(&spec["image"]);
        if let Some(e) = st.script["runErr"][&image]
            .as_str()
            .filter(|e| !e.is_empty())
        {
            return Err(other(e));
        }
        if st.containers.values().any(|ct| ct.name == name) {
            return Err(other(format!("container name {} already in use", q(&name))));
        }
        let has_members = spec.get("init").is_some() || spec.get("sidecars").is_some();
        if has_members && !self.members {
            return Err(other("this runtime runs no init containers or sidecars"));
        }
        let n = {
            let g = st.generation.entry(name.clone()).or_default();
            *g += 1;
            *g
        };
        let id = format!("{name}-{n}");
        let mut ct = Ctr {
            id: id.clone(),
            name: name.clone(),
            image,
            labels: spec["labels"]
                .as_object()
                .map(|m| m.iter().map(|(k, v)| (k.clone(), s(v))).collect())
                .unwrap_or_default(),
            state: RUNNING.into(),
            started_ns: st.clock_ns,
            ..Ctr::default()
        };
        if int(&spec["port"]) != 0 {
            ct.host_ip = s(&spec["hostIp"]);
            ct.host_port = 30000 + fnv32a(&name) % 2000;
        }
        if !self.bridge.is_empty() {
            ct.ip = format!("{}{}", self.bridge, 2 + fnv32a(&name) % 200);
        }
        if has_members {
            ct.state = STARTING.into();
        }
        st.containers.insert(id.clone(), ct);
        st.specs.insert(id.clone(), spec);
        if has_members && !st.script["holdStarts"].as_bool().unwrap_or(false) {
            Self::bring_up(st, &id);
        }
        Ok(json!(id))
    }

    /// Probe commands, never recorded: they run on their own timers.
    fn exec_probe(&self, c: &Value) -> Answer {
        let cmd = strings(&c["cmd"]);
        let first = cmd.first().cloned().unwrap_or_default();
        let code = int(&self.st.lock().unwrap().script["execCodes"][&first]);
        match first.as_str() {
            "sleep" => {
                std::thread::sleep(Duration::from_secs(5));
                Err(other("context deadline exceeded"))
            }
            "missing" => Err(other("exec: no such file")),
            _ => Ok(json!(code)),
        }
    }

    /// Health checks, never recorded either.
    fn check(&self, c: &Value) -> Value {
        let key = format!("{} {}", s(&c["addr"]), s(&c["path"]));
        let timeout = Duration::from_millis(int(&c["timeoutMs"]).max(0) as u64);
        let mut ans = {
            let mut st = self.st.lock().unwrap();
            let mut ans = s(&st.script["checks"][&key]);
            if let Some(rest) = ans.strip_prefix("fail ")
                && let Some((n, text)) = rest.split_once(' ')
            {
                let limit: i64 = n.parse().unwrap_or(0);
                let text = text.to_string();
                let f = st.failed.entry(key.clone()).or_default();
                *f += 1;
                ans = if *f <= limit { text } else { String::new() };
            }
            ans
        };
        if let Some(rest) = ans.strip_prefix("slow ")
            && let Some((d, text)) = rest.split_once(' ')
        {
            let d = parse_duration(d);
            if d > timeout {
                std::thread::sleep(timeout);
                return json!("context deadline exceeded");
            }
            std::thread::sleep(d);
            ans = text.to_string();
        }
        if ans == "timeout" {
            std::thread::sleep(timeout);
            return json!("context deadline exceeded");
        }
        json!(ans)
    }

    fn running(st: &State) -> usize {
        st.containers
            .values()
            .filter(|c| c.state == RUNNING)
            .count()
    }

    fn answer_more(&self, st: &mut State, sc: &Value, method: &str, c: &Value) -> Answer {
        let inn = &sc["in"];
        match method {
            "proxyApply" => {
                let mut cfg = c["config"].clone();
                // The recorded configuration has no digests.
                if let Some(certs) = cfg.get_mut("certificates").and_then(Value::as_array_mut) {
                    for crt in certs {
                        if let Some(o) = crt.as_object_mut() {
                            o.remove("sha256");
                        }
                    }
                }
                let n = Self::running(st);
                self.record(st, "proxy.apply", json!({"running": n, "config": cfg}));
                Self::err_of(inn, "proxyErr").map(|_| Value::Null)
            }
            "proxyHealth" => {
                self.record(st, "proxy.health", Value::Null);
                Self::err_of(inn, "healthErr").map(|_| Value::Null)
            }
            "proxyClients" => {
                self.record(st, "proxy.clients", Self::local(&c["local"]));
                Self::err_of(inn, "clientsErr").map(|_| Value::Null)
            }
            "proxyLoad" => {
                self.record(st, "proxy.load", Value::Null);
                Self::err_of(inn, "loadErr")?;
                Ok(match &inn["load"] {
                    Value::Object(m) => Value::Object(m.clone()),
                    _ => json!({}),
                })
            }
            "netApply" => {
                self.record(
                    st,
                    "net.apply",
                    json!({"config": c["config"], "local": Self::local(&c["local"])}),
                );
                Self::err_of(inn, "netErr").map(|_| Value::Null)
            }
            "netSwitch" => Ok(inn["switching"].clone()),
            "netPeers" => Ok(match &inn["peers"] {
                Value::Array(a) => Value::Array(a.clone()),
                _ => Value::Null,
            }),
            "netUserspace" => Ok(json!(inn["userspace"].as_bool().unwrap_or(false))),
            "netRotate" => {
                self.record(st, "net.rotate", Value::Null);
                Self::err_of(inn, "keyErr")?;
                st.keys += 1;
                Ok(json!(format!("key-{}", st.keys)))
            }
            "dnsNames" => {
                let apps = match &c["apps"] {
                    Value::Array(a) if !a.is_empty() => Value::Array(a.clone()),
                    _ => Value::Null,
                };
                self.record(st, "dns.names", apps);
                Ok(Value::Null)
            }
            "dnsClients" => {
                self.record(st, "dns.clients", Self::local(&c["local"]));
                Ok(Value::Null)
            }
            "certs" => {
                let names = match &c["names"] {
                    Value::Array(a) => Value::Array(a.clone()),
                    _ => Value::Null,
                };
                self.record(st, "certs", names.clone());
                Self::err_of(inn, "certErr")?;
                let mut out = Vec::new();
                for n in strings(&names) {
                    if let Some(pem) = inn["certs"].get(&n) {
                        let mut m = serde_json::Map::new();
                        m.insert("name".into(), json!(n));
                        if !s(pem).is_empty() {
                            m.insert("pem".into(), pem.clone());
                        }
                        out.push(Value::Object(m));
                    }
                }
                Ok(if out.is_empty() {
                    Value::Null
                } else {
                    Value::Array(out)
                })
            }
            _ => self.answer_side(st, sc, method, c),
        }
    }

    fn records(v: &Value) -> Value {
        Value::Array(
            v.as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|mut r| {
                    let data = b64_decode(&s(&r["data"]));
                    r["data"] = json!(String::from_utf8_lossy(&data));
                    r
                })
                .collect(),
        )
    }

    fn answer_side(&self, st: &mut State, sc: &Value, method: &str, c: &Value) -> Answer {
        let side = &sc["side"];
        let target = !s(&c["target"]).is_empty();
        match method {
            "execSession" => {
                let cmd = strings(&c["cmd"]);
                let stdin = c["stdin"].clone();
                self.record(
                    st,
                    "execSession",
                    json!({"id": s(&c["id"]), "cmd": c["cmd"], "tty": c["tty"].as_bool().unwrap_or(false),
                        "rows": int(&c["rows"]), "cols": int(&c["cols"]),
                        "stdin": if stdin.is_string() { stdin.clone() } else { Value::Null }}),
                );
                let input = s(&stdin);
                let first = cmd.first().map(String::as_str).unwrap_or("");
                let (out, err, code) = match first {
                    "echo" => (format!("{}\n{input}", cmd[1..].join(" ")), String::new(), 0),
                    "big" => ("x".repeat(70_000), String::new(), 0),
                    "fail" => (String::new(), "oops\n".to_string(), 3),
                    "num" => (cmd[1..].join(" "), String::new(), 0),
                    "missing" => return Err(other("exec: no such file")),
                    _ => (String::new(), String::new(), 0),
                };
                Ok(json!({"stdout": out, "stderr": err, "code": code}))
            }
            "logs" => {
                let id = s(&c["id"]);
                self.record(
                    st,
                    "logs",
                    json!({"id": id, "follow": c["follow"].as_bool().unwrap_or(false),
                        "tail": int(&c["tail"]), "grep": s(&c["grep"])}),
                );
                Self::err_of(side, "logsErr")?;
                Ok(Self::records(&side["frames"][&id]))
            }
            "searchLogs" => {
                self.record(
                    st,
                    "searchLogs",
                    json!({"app": s(&c["app"]), "replica": s(&c["replica"]), "container": s(&c["container"]),
                        "sinceNs": int(&c["sinceNs"]), "untilNs": int(&c["untilNs"]), "grep": s(&c["grep"]),
                        "limit": int(&c["limit"]), "maxBytes": int(&c["maxBytes"])}),
                );
                Ok(json!({"records": Self::records(&side["search"]), "notice": s(&side["notice"])}))
            }
            "pruneLogs" => {
                self.record(
                    st,
                    "pruneLogs",
                    json!({"retentionMs": int(&c["retentionMs"]), "maxBytes": int(&c["maxBytes"])}),
                );
                Ok(Value::Null)
            }
            "tailLogs" => {
                self.record(
                    st,
                    "tailLogs",
                    json!({"target": target, "maxBytes": int(&c["maxBytes"])}),
                );
                Self::err_of(side, "tailErr")?;
                Ok(json!({"records": Self::records(&side["tail"])}))
            }
            "tailLogsEncoded" => {
                self.record(
                    st,
                    "tailLogsEncoded",
                    json!({"target": target, "maxBytes": int(&c["maxBytes"]), "format": s(&c["format"]),
                        "node": s(&c["node"]), "batchRecords": int(&c["batchRecords"]), "batchBytes": int(&c["batchBytes"])}),
                );
                Self::err_of(side, "tailErr")?;
                let bodies: Vec<Value> = strings(&side["bodies"])
                    .iter()
                    .map(|b| json!(String::from_utf8_lossy(&b64_decode(b))))
                    .collect();
                Ok(json!({"bodies": bodies, "size": int(&side["size"])}))
            }
            "commitLogs" => {
                self.record(st, "commitLogs", json!({"target": target}));
                Ok(Value::Null)
            }
            "readQueue" | "readSandboxQueue" => {
                let name = s(&c["name"]);
                self.record(
                    st,
                    method,
                    json!({"id": s(&c["id"]), "type": s(&c["type"]), "name": name, "url": s(&c["url"]), "addresses": 0}),
                );
                if let Some(e) = side["qerr"][&name].as_str().filter(|e| !e.is_empty()) {
                    return Err(other(e));
                }
                Ok(json!(int(&side["queues"][&name])))
            }
            "ensureSandbox" => {
                let id = s(&c["id"]);
                self.record(st, "ensureSandbox", json!({"id": id}));
                let ip = format!("10.120.0.{}", 100 + fnv32a(&id) % 100);
                st.boxes.insert(id.clone(), ip.clone());
                Ok(json!({"id": id, "ip": ip}))
            }
            "removeSandbox" => {
                let id = s(&c["id"]);
                self.record(st, "removeSandbox", json!({"id": id}));
                st.boxes.remove(&id);
                Ok(Value::Null)
            }
            "listSandboxes" => {
                self.record(st, "listSandboxes", json!({}));
                Ok(Value::Array(
                    st.boxes
                        .iter()
                        .map(|(id, ip)| json!({"id": id, "ip": ip}))
                        .collect(),
                ))
            }
            _ => Err(other(format!("unknown call {}", q(method)))),
        }
    }
}

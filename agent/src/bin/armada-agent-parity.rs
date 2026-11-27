//! The program the agent's replays drive (tests/scenarios.rs): the agent
//! with a test clock and a runtime whose every call goes to the test, which
//! answers it from the recorded scenario's fake runtime. JSON lines both
//! ways: the test's
//! requests (`{"id", "op", ...}`, answered with `{"id", ...}`), and the
//! program's runtime calls (`{"call", "method", ...}`, answered with
//! `{"reply", "result"}` or `{"reply", "error"}`). Never part of a release.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use armada_agent::clock::{TestClock, from_unix_nanos, unix_nanos};
use armada_agent::network::Network;
use armada_agent::proxy::{BoxFut, CertificateSource, Clients, InternalDns, Proxy, ServerLoad};
use armada_agent::runtime::{
    Container, ContainerSpec, Error, Image, Member, MemberSpec, RegistryAuth, Result, Runtime,
    Stats,
};
use armada_agent::session::{ServerConn, reconnect_wait};
use armada_agent::side::conntrack::NodeConntrack;
use armada_agent::side::logexport::ExportState;
use armada_agent::side::nfs::NodeNfs;
use armada_agent::side::volume::NodeVolumes;
use armada_agent::side::{
    CommitFn, ExecOptions, LogEncoding, LogFrame, LogFrames, LogOptions, LogQuery, LogRecord,
    LogTail, QueueRead, Sandbox, SideConfig,
};
use armada_agent::usage::UsageState;
use armada_agent::{Agent, Config};
use armada_proto::armada::v1 as pb;
use serde_json::{Value, json};
use tokio::sync::oneshot;

/// The line protocol with the test.
struct Wire {
    out: Mutex<std::io::Stdout>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Value>>>,
    next: AtomicU64,
}

impl Wire {
    fn send(&self, v: &Value) {
        let mut o = self.out.lock().unwrap();
        let _ = writeln!(o, "{v}");
        let _ = o.flush();
    }

    /// A runtime call answered by the test.
    async fn call(&self, method: &str, mut args: Value) -> std::result::Result<Value, Error> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        args["call"] = json!(id);
        args["method"] = json!(method);
        self.send(&args);
        let v = rx.await.map_err(|_| Error::other("the test went away"))?;
        if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
            return Err(match e["kind"].as_str().unwrap_or("") {
                "notFound" => Error::NotFound,
                "platform" => Error::Platform {
                    image: s(&e["image"]),
                    want: s(&e["want"]),
                    have: strings(&e["have"]),
                },
                _ => Error::Other(s(&e["text"])),
            });
        }
        Ok(v["result"].clone())
    }
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(s).collect())
        .unwrap_or_default()
}

fn int(v: &Value) -> i64 {
    v.as_i64().unwrap_or(0)
}

fn time(v: &Value) -> Option<SystemTime> {
    match int(v) {
        0 => None,
        n => Some(from_unix_nanos(i128::from(n))),
    }
}

fn container(v: &Value) -> Container {
    Container {
        id: s(&v["id"]),
        name: s(&v["name"]),
        image: s(&v["image"]),
        labels: v["labels"]
            .as_object()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), s(v))).collect())
            .unwrap_or_default(),
        state: s(&v["state"]),
        exit_code: int(&v["exitCode"]),
        host_ip: s(&v["hostIp"]),
        host_port: int(&v["hostPort"]),
        ip: s(&v["ip"]),
        started_at: time(&v["startedNs"]),
        members: v["members"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|m| Member {
                        id: s(&m["id"]),
                        name: s(&m["name"]),
                        role: s(&m["role"]),
                        state: s(&m["state"]),
                        exit_code: int(&m["exitCode"]),
                        started_at: time(&m["startedNs"]),
                        ..Default::default()
                    })
                    .collect()
            })
            .unwrap_or_default(),
        start_error: s(&v["startError"]),
        ..Default::default()
    }
}

fn member_json(m: &MemberSpec) -> Value {
    json!({
        "name": m.name, "image": m.image, "entrypoint": m.entrypoint, "cmd": m.cmd, "env": m.env,
        "memoryBytes": m.memory_bytes, "nanoCpus": m.nano_cpus, "cpuReserveMillis": m.cpu_reserve_millis,
        "pidsLimit": m.pids_limit,
        "files": m.files.iter().map(|f| json!({"source": f.source, "target": f.target})).collect::<Vec<_>>(),
        "volumes": m.volumes.iter().map(|v| json!({"source": v.source, "target": v.target, "shared": v.shared, "readOnly": v.read_only})).collect::<Vec<_>>(),
    })
}

fn spec_json(c: &ContainerSpec) -> Value {
    json!({
        "name": c.name, "image": c.image, "entrypoint": c.entrypoint, "cmd": c.cmd, "env": c.env,
        "labels": c.labels, "port": c.port, "hostIp": c.host_ip, "memoryBytes": c.memory_bytes,
        "nanoCpus": c.nano_cpus, "cpuReserveMillis": c.cpu_reserve_millis, "pidsLimit": c.pids_limit,
        "files": c.files.iter().map(|f| json!({"source": f.source, "target": f.target})).collect::<Vec<_>>(),
        "dns": c.dns, "dnsSearch": c.dns_search,
        "volumes": c.volumes.iter().map(|v| json!({"source": v.source, "target": v.target, "shared": v.shared, "readOnly": v.read_only})).collect::<Vec<_>>(),
        "init": c.init.iter().map(member_json).collect::<Vec<_>>(),
        "sidecars": c.sidecars.iter().map(member_json).collect::<Vec<_>>(),
    })
}

/// What the fake runtime offers, fixed for a scenario.
#[derive(Clone, Copy, Default)]
struct Caps {
    members: bool,
    volumes: bool,
    exec: bool,
    stats: bool,
    logs: bool,
    encodes: bool,
    sandbox: bool,
}

fn bytes_of(v: &Value) -> Vec<u8> {
    v.as_str().unwrap_or("").as_bytes().to_vec()
}

fn record(v: &Value) -> LogRecord {
    LogRecord {
        time: time(&v["timeNs"]).unwrap_or(SystemTime::UNIX_EPOCH),
        stderr: v["stderr"].as_bool().unwrap_or(false),
        data: bytes_of(&v["data"]),
        replica: s(&v["replica"]),
        container: s(&v["container"]),
        app: s(&v["app"]),
        revision: s(&v["revision"]),
    }
}

fn ns(t: SystemTime) -> i64 {
    unix_nanos(t) as i64
}

/// The runtime whose calls the test answers.
struct Remote {
    wire: Arc<Wire>,
    caps: Caps,
}

impl Runtime for Remote {
    async fn ping(&self) -> Result<()> {
        self.wire.call("ping", json!({})).await.map(|_| ())
    }

    async fn pull(&self, image: &str, auth: Option<&RegistryAuth>) -> Result<Image> {
        let auth = auth.map(|a| json!({"username": a.username, "password": a.password, "serverAddress": a.server_address}));
        let v = self
            .wire
            .call("pull", json!({"image": image, "auth": auth}))
            .await?;
        Ok(Image {
            reference: s(&v["ref"]),
            platforms: strings(&v["platforms"]),
        })
    }

    async fn run(&self, spec: &ContainerSpec) -> Result<String> {
        let v = self
            .wire
            .call("run", json!({"spec": spec_json(spec)}))
            .await?;
        Ok(s(&v))
    }

    async fn stop(&self, id: &str, grace: Duration) -> Result<()> {
        self.wire
            .call(
                "stop",
                json!({"id": id, "graceMs": grace.as_millis() as i64}),
            )
            .await
            .map(|_| ())
    }

    async fn remove(&self, id: &str) -> Result<()> {
        self.wire
            .call("remove", json!({"id": id}))
            .await
            .map(|_| ())
    }

    async fn list(&self, labels: &BTreeMap<String, String>) -> Result<Vec<Container>> {
        let v = self.wire.call("list", json!({"labels": labels})).await?;
        Ok(v.as_array()
            .map(|a| a.iter().map(container).collect())
            .unwrap_or_default())
    }

    async fn inspect(&self, id: &str) -> Result<Container> {
        let v = self.wire.call("inspect", json!({"id": id})).await?;
        Ok(container(&v))
    }

    fn can_run_members(&self) -> bool {
        self.caps.members
    }

    fn can_mount_volumes(&self) -> bool {
        self.caps.volumes
    }

    fn can_exec(&self) -> bool {
        self.caps.exec
    }

    async fn exec_app(&self, id: &str, cmd: &[String]) -> Result<i64> {
        let v = self
            .wire
            .call("exec", json!({"id": id, "cmd": cmd}))
            .await?;
        Ok(int(&v))
    }

    fn can_stats(&self) -> bool {
        self.caps.stats
    }

    async fn stats(&self, id: &str) -> Result<Stats> {
        let v = self.wire.call("stats", json!({"id": id})).await?;
        Ok(Stats {
            cpu: Duration::from_nanos(int(&v["cpuNs"]).max(0) as u64),
            memory_bytes: int(&v["memoryBytes"]),
            egress_bytes: int(&v["egressBytes"]),
            network_lost: v["networkLost"].as_bool().unwrap_or(false),
            oom_kills: int(&v["oomKills"]),
        })
    }

    async fn release_network(&self, id: &str) -> Option<Result<()>> {
        Some(
            self.wire
                .call("release", json!({"id": id}))
                .await
                .map(|_| ()),
        )
    }

    async fn prune_images(&self, keep: &[String], grace: Duration) -> Option<Result<Vec<String>>> {
        Some(
            self.wire
                .call(
                    "prune",
                    json!({"keep": keep, "graceMs": grace.as_millis() as i64}),
                )
                .await
                .map(|v| strings(&v)),
        )
    }

    fn has_log_history(&self) -> bool {
        self.caps.logs
    }

    fn prunes_logs(&self) -> bool {
        self.caps.logs
    }

    fn tails_logs(&self) -> bool {
        self.caps.logs
    }

    fn encodes_logs(&self) -> bool {
        self.caps.encodes
    }

    fn can_sandbox(&self) -> bool {
        self.caps.sandbox
    }

    async fn exec_session(&self, id: &str, mut opts: ExecOptions) -> Result<i64> {
        let mut stdin = Value::Null;
        if let Some(mut rx) = opts.stdin.take() {
            let mut b = Vec::new();
            while let Some(x) = rx.recv().await {
                b.extend(x);
            }
            stdin = json!(String::from_utf8_lossy(&b));
        }
        let v = self
            .wire
            .call(
                "execSession",
                json!({"id": id, "cmd": opts.cmd, "tty": opts.tty, "rows": opts.size.rows,
                    "cols": opts.size.cols, "stdin": stdin}),
            )
            .await?;
        if let Some(out) = &opts.output {
            for (k, stdout) in [("stdout", true), ("stderr", false)] {
                let b = bytes_of(&v[k]);
                if !b.is_empty() {
                    let _ = out.send((stdout, b)).await;
                }
            }
        }
        Ok(int(&v["code"]))
    }

    async fn logs(&self, id: &str, o: &LogOptions) -> Result<LogFrames> {
        let v = self
            .wire
            .call(
                "logs",
                json!({"id": id, "follow": o.follow, "tail": o.tail, "grep": o.grep}),
            )
            .await?;
        let frames = v.as_array().cloned().unwrap_or_default();
        let (tx, rx) = tokio::sync::mpsc::channel(frames.len() + 1);
        for f in frames {
            let _ = tx
                .send(Ok(LogFrame {
                    stderr: f["stderr"].as_bool().unwrap_or(false),
                    data: bytes_of(&f["data"]),
                    time: time(&f["timeNs"]),
                }))
                .await;
        }
        Ok(rx)
    }

    async fn search_logs(&self, q: &LogQuery) -> Result<(Vec<LogRecord>, String)> {
        let v = self
            .wire
            .call(
                "searchLogs",
                json!({"app": q.app, "replica": q.replica, "container": q.container,
                    "sinceNs": ns(q.since), "untilNs": q.until.map(ns).unwrap_or(0),
                    "grep": q.grep, "limit": q.limit, "maxBytes": q.max_bytes}),
            )
            .await?;
        let recs = v["records"]
            .as_array()
            .map(|a| a.iter().map(record).collect())
            .unwrap_or_default();
        Ok((recs, s(&v["notice"])))
    }

    async fn prune_logs(&self, retention: Duration, max_bytes: i64) -> Result<()> {
        self.wire
            .call(
                "pruneLogs",
                json!({"retentionMs": retention.as_millis() as i64, "maxBytes": max_bytes}),
            )
            .await
            .map(|_| ())
    }

    async fn tail_logs(
        &self,
        target: &str,
        max_bytes: i64,
        enc: Option<&LogEncoding>,
    ) -> Result<LogTail> {
        let w = self.wire.clone();
        let t = target.to_string();
        let commit: CommitFn = Box::new(move || {
            Box::pin(async move { w.call("commitLogs", json!({"target": t})).await.map(|_| ()) })
        });
        if let Some(e) = enc {
            let v = self
                .wire
                .call(
                    "tailLogsEncoded",
                    json!({"target": target, "maxBytes": max_bytes, "format": e.format, "node": e.node,
                        "batchRecords": e.batch_records, "batchBytes": e.batch_bytes}),
                )
                .await?;
            return Ok(LogTail {
                bodies: Some(
                    v["bodies"]
                        .as_array()
                        .map(|a| a.iter().map(bytes_of).collect())
                        .unwrap_or_default(),
                ),
                size: int(&v["size"]),
                commit: Some(commit),
                ..LogTail::default()
            });
        }
        let v = self
            .wire
            .call("tailLogs", json!({"target": target, "maxBytes": max_bytes}))
            .await?;
        Ok(LogTail {
            records: v["records"]
                .as_array()
                .map(|a| a.iter().map(record).collect())
                .unwrap_or_default(),
            commit: Some(commit),
            ..LogTail::default()
        })
    }

    async fn read_queue(&self, container: &str, q: &QueueRead) -> Result<i64> {
        let v = self
            .wire
            .call(
                "readQueue",
                json!({"id": container, "type": q.kind, "name": q.name, "url": q.url,
                    "addresses": q.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>()}),
            )
            .await?;
        Ok(int(&v))
    }

    async fn ensure_sandbox(&self, id: &str) -> Result<Sandbox> {
        let v = self.wire.call("ensureSandbox", json!({"id": id})).await?;
        Ok(Sandbox {
            id: s(&v["id"]),
            ip: s(&v["ip"]),
        })
    }

    async fn remove_sandbox(&self, id: &str) -> Result<()> {
        self.wire
            .call("removeSandbox", json!({"id": id}))
            .await
            .map(|_| ())
    }

    async fn list_sandboxes(&self) -> Result<Vec<Sandbox>> {
        let v = self.wire.call("listSandboxes", json!({})).await?;
        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .map(|x| Sandbox {
                        id: s(&x["id"]),
                        ip: s(&x["ip"]),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn read_sandbox_queue(&self, id: &str, q: &QueueRead) -> Result<i64> {
        let v = self
            .wire
            .call(
                "readSandboxQueue",
                json!({"id": id, "type": q.kind, "name": q.name, "url": q.url,
                    "addresses": q.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>()}),
            )
            .await?;
        Ok(int(&v))
    }
}

/// The node's proxy, answered by the test's fakes.
struct RemoteProxy(Arc<Wire>);

fn clients_json(c: &Clients) -> Value {
    Value::Object(c.iter().map(|(k, v)| (k.to_string(), json!(v))).collect())
}

impl Proxy for RemoteProxy {
    fn apply<'a>(
        &'a self,
        cfg: &'a pb::ProxyConfig,
    ) -> BoxFut<'a, std::result::Result<(), String>> {
        Box::pin(async move {
            self.0
                .call("proxyApply", json!({"config": proto_json(cfg)}))
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        })
    }

    fn health(&self) -> BoxFut<'_, std::result::Result<(), String>> {
        Box::pin(async move {
            self.0
                .call("proxyHealth", json!({}))
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        })
    }

    fn sets_clients(&self) -> bool {
        true
    }

    fn set_clients<'a>(&'a self, c: &'a Clients) -> BoxFut<'a, std::result::Result<(), String>> {
        Box::pin(async move {
            self.0
                .call("proxyClients", json!({"local": clients_json(c)}))
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        })
    }

    fn reads_load(&self) -> bool {
        true
    }

    fn load(&self) -> BoxFut<'_, std::result::Result<BTreeMap<String, ServerLoad>, String>> {
        Box::pin(async move {
            let v = self
                .0
                .call("proxyLoad", json!({}))
                .await
                .map_err(|e| e.to_string())?;
            Ok(v.as_object()
                .map(|m| {
                    m.iter()
                        .map(|(k, l)| {
                            (
                                k.clone(),
                                ServerLoad {
                                    in_flight: int(&l["inFlight"]),
                                    total: int(&l["total"]),
                                },
                            )
                        })
                        .collect()
                })
                .unwrap_or_default())
        })
    }
}

/// The cluster network, with every optional part.
struct RemoteNet(Arc<Wire>);

impl Network for RemoteNet {
    fn apply<'a>(
        &'a self,
        cfg: &'a pb::NetworkConfig,
        local: Option<&'a Clients>,
    ) -> BoxFut<'a, std::result::Result<(), String>> {
        Box::pin(async move {
            let local = local.map(clients_json).unwrap_or(Value::Null);
            self.0
                .call(
                    "netApply",
                    json!({"config": proto_json(cfg), "local": local}),
                )
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        })
    }

    fn switches(&self) -> bool {
        true
    }

    fn switch_status(&self) -> BoxFut<'_, Option<pb::NetworkSwitchStatus>> {
        Box::pin(async move {
            let v = self.0.call("netSwitch", json!({})).await.ok()?;
            serde_json::from_value(v).ok()
        })
    }

    fn checks_peers(&self) -> bool {
        true
    }

    fn unreachable_peers(&self) -> BoxFut<'_, Vec<String>> {
        Box::pin(
            async move { strings(&self.0.call("netPeers", json!({})).await.unwrap_or_default()) },
        )
    }

    fn rotates_keys(&self) -> bool {
        true
    }

    fn rotate_key(&self) -> BoxFut<'_, std::result::Result<String, String>> {
        Box::pin(async move {
            self.0
                .call("netRotate", json!({}))
                .await
                .map(|v| s(&v))
                .map_err(|e| e.to_string())
        })
    }
}

/// The node's resolver.
struct RemoteDns(Arc<Wire>, String);

impl InternalDns for RemoteDns {
    fn address(&self) -> String {
        self.1.clone()
    }

    fn set_names(&self, apps: Vec<String>) -> BoxFut<'_, ()> {
        Box::pin(async move {
            let _ = self.0.call("dnsNames", json!({"apps": apps})).await;
        })
    }

    fn set_clients<'a>(&'a self, c: &'a Clients) -> BoxFut<'a, ()> {
        Box::pin(async move {
            let _ = self
                .0
                .call("dnsClients", json!({"local": clients_json(c)}))
                .await;
        })
    }
}

/// The control plane's GetCertificates.
struct RemoteCerts(Arc<Wire>);

impl CertificateSource for RemoteCerts {
    fn get_certificates(
        &self,
        names: Vec<String>,
    ) -> BoxFut<'_, std::result::Result<Vec<pb::ProxyCertificate>, String>> {
        Box::pin(async move {
            let v = self
                .0
                .call("certs", json!({"names": names}))
                .await
                .map_err(|e| e.to_string())?;
            Ok(v.as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|c| serde_json::from_value(c.clone()).ok())
                        .collect()
                })
                .unwrap_or_default())
        })
    }
}

/// The agent under test and what the requests keep between them.
struct Under {
    agent: Agent<Remote>,
    clock: Arc<TestClock>,
    samples: Mutex<UsageState>,
    export: tokio::sync::Mutex<ExportState>,
}

/// The sessions' and loops' part of the configuration: the fake
/// armada-node behind every program seam.
fn side_config(c: &Value) -> SideConfig {
    let bin = s(&c["nodeBin"]);
    let ms = |k: &str, d: u64| Duration::from_millis(c[k].as_u64().unwrap_or(d));
    let mut side = SideConfig {
        queue_interval: ms("queueMs", 15_000),
        sandbox_interval: c["sandboxMs"].as_u64().map(Duration::from_millis),
        volume_interval: Duration::ZERO,
        nfs_dir: s(&c["nfsDir"]),
        ..SideConfig::default()
    };
    if !bin.is_empty() {
        side.volumes = Some(Arc::new(NodeVolumes { bin: bin.clone() }));
        side.nfs = Some(Arc::new(NodeNfs {
            bin: bin.clone(),
            supported: Some(true),
        }));
        if !s(&c["conntrackDir"]).is_empty() {
            side.conntrack = Some(Arc::new(NodeConntrack {
                bin,
                dir: s(&c["conntrackDir"]),
                memory: c["conntrackMemory"].as_i64(),
            }));
        }
    }
    side
}

static UNDER: OnceLock<Under> = OnceLock::new();

fn proto_json<T: serde::Serialize>(m: &T) -> Value {
    serde_json::to_value(m).unwrap_or(Value::Null)
}

fn under() -> std::result::Result<&'static Under, String> {
    UNDER.get().ok_or_else(|| "no config yet".to_string())
}

async fn handle(wire: Arc<Wire>, req: Value) -> std::result::Result<Value, String> {
    match req["op"].as_str().unwrap_or("") {
        "config" => {
            let c = &req["config"];
            let clock = Arc::new(TestClock::new(
                time(&c["nowNs"]).unwrap_or(SystemTime::UNIX_EPOCH),
            ));
            let check_wire = wire.clone();
            let on = |k: &str| c["caps"][k].as_bool().unwrap_or(false);
            let cfg = Config {
                node_id: s(&c["nodeId"]),
                private_ip: s(&c["privateIp"]),
                boot_time: time(&c["bootNs"]),
                cpu_millis: int(&c["cpuMillis"]),
                memory_bytes: int(&c["memoryBytes"]),
                unpublished: c["unpublished"].as_bool().unwrap_or(false),
                volumes_dir: s(&c["volumesDir"]),
                secrets_dir: s(&c["secretsDir"]),
                dns: c["dns"].as_str().filter(|d| !d.is_empty()).map(|d| {
                    Arc::new(RemoteDns(wire.clone(), d.to_string())) as Arc<dyn InternalDns>
                }),
                proxy: on("proxy").then(|| Arc::new(RemoteProxy(wire.clone())) as Arc<dyn Proxy>),
                certificates: on("proxy")
                    .then(|| Arc::new(RemoteCerts(wire.clone())) as Arc<dyn CertificateSource>),
                network: on("network")
                    .then(|| Arc::new(RemoteNet(wire.clone())) as Arc<dyn Network>),
                os: s(&c["os"]),
                arch: s(&c["arch"]),
                servers: strings(&c["servers"]),
                network_key: s(&c["networkKey"]),
                endpoint: s(&c["endpoint"]),
                behind_nat: c["behindNat"].as_bool().unwrap_or(false),
                usage_interval: Duration::from_millis(c["usageMs"].as_u64().unwrap_or(3_600_000)),
                image_prune: None,
                check: Some(Arc::new(move |addr, path, timeout: Duration| {
                    let w = check_wire.clone();
                    Box::pin(async move {
                        let v = w
                            .call(
                                "check",
                                json!({"addr": addr, "path": path, "timeoutMs": timeout.as_millis() as i64}),
                            )
                            .await
                            .map_err(|e| e.to_string())?;
                        match v.as_str() {
                            Some(e) if !e.is_empty() => Err(e.to_string()),
                            _ => Ok(()),
                        }
                    })
                })),
                clock: clock.clone(),
                side: side_config(c),
                ..Config::default()
            };
            let caps = Caps {
                members: c["caps"]["members"].as_bool().unwrap_or(false),
                volumes: c["caps"]["volumes"].as_bool().unwrap_or(false),
                exec: c["caps"]["exec"].as_bool().unwrap_or(false),
                stats: c["caps"]["stats"].as_bool().unwrap_or(false),
                logs: on("logs"),
                encodes: on("encodes"),
                sandbox: on("sandbox"),
            };
            let agent = Agent::new(cfg, Remote { wire, caps });
            if let Some(n) = c["crashBaseNs"].as_u64() {
                agent.set_crash_base(Duration::from_nanos(n));
            }
            UNDER
                .set(Under {
                    agent,
                    clock,
                    samples: Mutex::new(UsageState::default()),
                    export: tokio::sync::Mutex::new(ExportState::default()),
                })
                .map_err(|_| "configured twice".to_string())?;
            Ok(json!({}))
        }
        "now" => {
            under()?
                .clock
                .set(time(&req["ns"]).unwrap_or(SystemTime::UNIX_EPOCH));
            Ok(json!({}))
        }
        "assign" => {
            let a: pb::Assignment =
                serde_json::from_value(req["assignment"].clone()).map_err(|e| e.to_string())?;
            under()?.agent.set_assignment(&a);
            Ok(json!({}))
        }
        "reconcile" => match under()?.agent.reconcile().await {
            Ok(r) => Ok(json!({"report": r.as_ref().map(proto_json)})),
            Err(e) => Ok(json!({"error": e.to_string()})),
        },
        "contact" => {
            under()?
                .agent
                .set_contact(req["up"].as_bool().unwrap_or(false));
            Ok(json!({}))
        }
        "fence" => {
            under()?.agent.fence_unassigned().await;
            Ok(json!({}))
        }
        "prune" => {
            under()?.agent.prune_images().await;
            Ok(json!({}))
        }
        "rotate" => {
            under()?.agent.rotate_network_key().await;
            Ok(json!({}))
        }
        "sample" => {
            let u = under()?;
            let prev = std::mem::take(&mut *u.samples.lock().unwrap());
            let mut prev = prev;
            let r = u.agent.usage_report(&mut prev).await;
            *u.samples.lock().unwrap() = prev;
            Ok(json!({"usage": r.as_ref().map(proto_json)}))
        }
        "hello" => Ok(json!({"hello": proto_json(&under()?.agent.hello())})),
        "connect" => {
            let creds = armada_agent::creds::Credentials::load(
                Path::new(&s(&req["dataDir"])),
                &s(&req["node"]),
            )?;
            let conn = ServerConn::new(Arc::new(creds), strings(&req["servers"]))?;
            under()?.agent.set_connection(Arc::new(conn));
            Ok(json!({}))
        }
        "exec" => {
            let r = serde_json::from_value(req["request"].clone()).map_err(|e| e.to_string())?;
            under()?.agent.serve_exec(r).await;
            Ok(json!({}))
        }
        "logs" => {
            let r = serde_json::from_value(req["request"].clone()).map_err(|e| e.to_string())?;
            under()?.agent.serve_logs(r).await;
            Ok(json!({}))
        }
        "cancelLogs" => {
            under()?.agent.cancel_logs(&s(&req["requestId"]));
            Ok(json!({}))
        }
        "volume" => {
            let r = serde_json::from_value(req["request"].clone()).map_err(|e| e.to_string())?;
            under()?.agent.serve_volume(r).await;
            Ok(json!({}))
        }
        "pruneLogs" => {
            under()?.agent.prune_logs().await;
            Ok(json!({}))
        }
        "queues" => {
            under()?.agent.measure_queues().await;
            Ok(json!({}))
        }
        "sandboxes" => {
            let u = under()?;
            u.agent.sync_sandboxes().await;
            while !u.agent.sandbox_reads_idle() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok(json!({}))
        }
        "export" => {
            let u = under()?;
            let mut st = u.export.lock().await;
            let wait = u.agent.export_round(&mut st).await;
            Ok(json!({"waitMs": wait.as_millis() as i64}))
        }
        "cleanNfs" => {
            under()?.agent.clean_nfs().await;
            Ok(json!({}))
        }
        "hash" => {
            let spec: pb::ReplicaSpec =
                serde_json::from_value(req["spec"].clone()).map_err(|e| e.to_string())?;
            Ok(json!({"hash": armada_agent::spec::spec_hash(&spec)}))
        }
        "reconnect" => {
            let (wait, backoff, lost) = reconnect_wait(
                req["accepted"].as_bool().unwrap_or(false),
                Duration::from_nanos(int(&req["backoffNs"]).max(0) as u64),
                time(&req["lostNs"]),
                time(&req["nowNs"]).unwrap_or(SystemTime::UNIX_EPOCH),
                Duration::ZERO,
            );
            Ok(json!({
                "waitNs": wait.as_nanos() as i64,
                "backoffNs": backoff.as_nanos() as i64,
                "lostNs": lost.map(|l| unix_nanos(l) as i64).unwrap_or(0),
            }))
        }
        "check" => {
            let r = armada_agent::check::check(
                s(&req["addr"]),
                s(&req["path"]),
                Duration::from_millis(int(&req["timeoutMs"]).max(0) as u64),
                "test",
            )
            .await;
            Ok(json!({"error": r.err().unwrap_or_default()}))
        }
        "run" => {
            let u = under()?;
            let creds = armada_agent::creds::Credentials::load(
                Path::new(&s(&req["dataDir"])),
                &s(&req["node"]),
            )?;
            let conn = Arc::new(ServerConn::new(Arc::new(creds), strings(&req["servers"]))?);
            let agent = u.agent.clone();
            tokio::spawn(async move {
                if let Err(e) = agent.run(conn).await {
                    eprintln!("agent: {e}");
                }
            });
            Ok(json!({}))
        }
        op => Err(format!("unknown op {op:?}")),
    }
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio");
    rt.block_on(async {
        let wire = Arc::new(Wire {
            out: Mutex::new(std::io::stdout()),
            pending: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        });
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        std::thread::spawn(move || {
            for line in std::io::stdin().lock().lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        while let Some(line) = rx.recv().await {
            let Ok(v) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if let Some(id) = v.get("reply").and_then(Value::as_u64) {
                if let Some(tx) = wire.pending.lock().unwrap().remove(&id) {
                    let _ = tx.send(v);
                }
                continue;
            }
            let wire = wire.clone();
            tokio::spawn(async move {
                let id = v["id"].clone();
                let mut out = match handle(wire.clone(), v).await {
                    Ok(o) => o,
                    Err(e) => json!({"fail": e}),
                };
                out["id"] = id;
                wire.send(&out);
            });
        }
    });
}

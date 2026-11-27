//! armada-server-parity, the control plane as a program, driven as the
//! recordings say: one JSON line of configuration, then requests answered by ID, the
//! etcd membership asked of the test, and settings changes told.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::oneshot;

/// The fake etcd membership.
#[derive(Default)]
pub struct Cluster {
    pub members: Vec<Value>,
    pub add_err: Option<String>,
    next: u64,
}

impl Cluster {
    pub fn new() -> Cluster {
        Cluster {
            members: vec![member(100, "cp-1", false)],
            ..Default::default()
        }
    }
}

/// A member as the recordings write it.
pub fn member(id: u64, name: &str, learner: bool) -> Value {
    json!({"ID": id, "Name": name, "PeerURL": "", "ClientURL": "", "Learner": learner})
}

pub struct Program {
    child: Child,
    stdin: Arc<Mutex<ChildStdin>>,
    next: AtomicI64,
    waiting: Arc<Mutex<HashMap<i64, oneshot::Sender<Value>>>>,
    pub changed: Arc<AtomicUsize>,
    pub ready: Value,
    /// The events the program tells besides settings changes (`leading`,
    /// `failed` in election mode).
    events: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Value>>,
}

impl Drop for Program {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write(stdin: &Mutex<ChildStdin>, v: &Value) {
    let mut line = v.to_string();
    line.push('\n');
    let mut w = stdin.lock().unwrap_or_else(|p| p.into_inner());
    let _ = w.write_all(line.as_bytes());
    let _ = w.flush();
}

impl Program {
    /// Starts the program with conf and waits until it serves.
    pub async fn start(
        conf: &Value,
        cluster: Arc<Mutex<Cluster>>,
        env: &[(&str, String)],
    ) -> Result<Program, String> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_armada-server-parity"))
            .env("TZ", "UTC")
            .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("start armada-server-parity: {e}"))?;
        let stdin = Arc::new(Mutex::new(child.stdin.take().expect("stdin")));
        let stdout = child.stdout.take().expect("stdout");
        let waiting: Arc<Mutex<HashMap<i64, oneshot::Sender<Value>>>> = Arc::default();
        let changed = Arc::new(AtomicUsize::new(0));
        let (ready_tx, ready_rx) = oneshot::channel();
        let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel();
        {
            let waiting = waiting.clone();
            let changed = changed.clone();
            let stdin = stdin.clone();
            std::thread::spawn(move || {
                let mut ready = Some(ready_tx);
                for line in BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    let Ok(m) = serde_json::from_str::<Value>(&line) else {
                        continue;
                    };
                    if let Some(r) = m.get("ready") {
                        if let Some(tx) = ready.take() {
                            let _ = tx.send(r.clone());
                        }
                    } else if m.get("call").is_some() {
                        let ans = answer_cluster(&cluster, &m);
                        write(&stdin, &ans);
                    } else if m.get("event").and_then(Value::as_str) == Some("settingsChanged") {
                        changed.fetch_add(1, Ordering::SeqCst);
                    } else if m.get("event").is_some() {
                        let _ = events_tx.send(m);
                    } else if let Some(id) = m.get("id").and_then(Value::as_i64) {
                        let tx = waiting
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .remove(&id);
                        if let Some(tx) = tx {
                            let _ = tx.send(m);
                        }
                    }
                }
            });
        }
        write(&stdin, conf);
        let ready = match tokio::time::timeout(Duration::from_secs(60), ready_rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => return Err("armada-server-parity exited before it was ready".into()),
            Err(_) => return Err("armada-server-parity did not get ready".into()),
        };
        Ok(Program {
            child,
            stdin,
            next: AtomicI64::new(0),
            waiting,
            changed,
            ready,
            events: tokio::sync::Mutex::new(events_rx),
        })
    }

    /// A request, answered once the program did it.
    pub async fn ask(&self, mut req: Value) -> Result<Value, String> {
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let (tx, rx) = oneshot::channel();
        self.waiting
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, tx);
        req["id"] = json!(id);
        write(&self.stdin, &req);
        match tokio::time::timeout(Duration::from_secs(60), rx).await {
            Ok(Ok(m)) => match m.get("error").and_then(Value::as_str) {
                Some(e) if !e.is_empty() => Err(e.to_string()),
                _ => Ok(m),
            },
            _ => Err(format!("armada-server-parity did not answer {req}")),
        }
    }

    /// The next event within d.
    pub async fn event(&self, d: Duration) -> Option<Value> {
        let mut rx = self.events.lock().await;
        tokio::time::timeout(d, rx.recv()).await.ok().flatten()
    }

    /// One of the addresses the program bound: api, join, joinLocal,
    /// siteJoin, or siteJoinLocal.
    pub fn addr(&self, name: &str) -> String {
        self.ready
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    pub fn stop(&mut self) {
        let mut req = json!({"op": "stop"});
        req["id"] = json!(0);
        write(&self.stdin, &req);
        for _ in 0..150 {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Answers the program's membership calls from the fake cluster.
fn answer_cluster(cluster: &Mutex<Cluster>, m: &Value) -> Value {
    let mut fc = cluster.lock().unwrap_or_else(|p| p.into_inner());
    let mut ans = json!({"op": "answer", "call": m["call"]});
    let s = |k: &str| m.get(k).and_then(Value::as_str).unwrap_or_default();
    match s("cluster") {
        "Members" => ans["value"] = Value::Array(fc.members.clone()),
        "AddLearner" => {
            if let Some(e) = &fc.add_err {
                ans["error"] = json!(e);
                ans["value"] = json!({"id": 0, "initial": ""});
            } else {
                fc.next += 1;
                let id = fc.next;
                let name = s("name").to_string();
                fc.members.push(member(id, &name, true));
                let addr: std::net::IpAddr = s("addr").parse().unwrap_or([0, 0, 0, 0].into());
                let port = m.get("port").and_then(Value::as_u64).unwrap_or_default() as u16;
                let ap = std::net::SocketAddr::new(addr, port);
                ans["value"] = json!({"id": id,
                    "initial": format!("cp-1=https://10.0.0.1:2380,{name}=https://{ap}")});
            }
        }
        "Promote" => {
            let mut out = Vec::new();
            for mm in fc.members.iter_mut() {
                if mm["Learner"].as_bool() == Some(true) {
                    mm["Learner"] = json!(false);
                    out.push(mm["Name"].clone());
                }
            }
            ans["value"] = if out.is_empty() {
                Value::Null
            } else {
                Value::Array(out)
            };
        }
        "Reachable" => ans["value"] = json!(m["member"]["Learner"].as_bool() != Some(true)),
        "RemoveMember" => {
            let id = m.get("id").and_then(Value::as_u64).unwrap_or_default();
            match fc
                .members
                .iter()
                .position(|mm| mm["ID"].as_u64() == Some(id))
            {
                Some(i) => {
                    fc.members.remove(i);
                }
                None => ans["error"] = json!("no such member"),
            }
        }
        _ => {}
    }
    ans
}

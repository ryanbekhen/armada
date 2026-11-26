//! The Rust agent's parity program (src/bin/armada-agent-parity.rs), driven
//! as Go's harness drove it: requests on stdin, its runtime calls answered
//! by the fakes.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use super::fake::Fake;

pub struct Program {
    child: Child,
    stdin: Arc<Mutex<ChildStdin>>,
    pending: Arc<Mutex<HashMap<u64, mpsc::Sender<Value>>>>,
    next: Mutex<u64>,
}

fn write_line(w: &Mutex<ChildStdin>, v: &Value) {
    let mut w = w.lock().unwrap();
    let _ = writeln!(w, "{v}");
    let _ = w.flush();
}

impl Program {
    pub fn start(fake: Arc<Fake>) -> Program {
        let mut child = Command::new(env!("CARGO_BIN_EXE_armada-agent-parity"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start armada-agent-parity");
        let stdin = Arc::new(Mutex::new(child.stdin.take().unwrap()));
        let out = child.stdout.take().unwrap();
        let pending: Arc<Mutex<HashMap<u64, mpsc::Sender<Value>>>> = Arc::default();
        {
            let stdin = stdin.clone();
            let pending = pending.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(out).lines() {
                    let Ok(line) = line else { break };
                    let Ok(v) = serde_json::from_str::<Value>(&line) else {
                        continue;
                    };
                    if let Some(call) = v.get("call").cloned() {
                        let fake = fake.clone();
                        let stdin = stdin.clone();
                        std::thread::spawn(move || {
                            let method = v["method"].as_str().unwrap_or("").to_string();
                            let mut m = json!({"reply": call});
                            match fake.answer(&method, &v) {
                                Ok(r) => m["result"] = r,
                                Err(e) => m["error"] = e,
                            }
                            write_line(&stdin, &m);
                        });
                        continue;
                    }
                    let id = v["id"].as_u64().unwrap_or(0);
                    if let Some(tx) = pending.lock().unwrap().remove(&id) {
                        let _ = tx.send(v);
                    }
                }
                // The program ended: every request waiting fails.
                pending.lock().unwrap().clear();
            });
        }
        Program {
            child,
            stdin,
            pending,
            next: Mutex::new(0),
        }
    }

    /// One request and its answer.
    pub fn request(&self, op: &str, fields: Value) -> Result<Value, String> {
        let id = {
            let mut n = self.next.lock().unwrap();
            *n += 1;
            *n
        };
        let (tx, rx) = mpsc::channel();
        self.pending.lock().unwrap().insert(id, tx);
        let mut m = if fields.is_object() {
            fields
        } else {
            json!({})
        };
        m["id"] = json!(id);
        m["op"] = json!(op);
        write_line(&self.stdin, &m);
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(ans) => match ans.get("fail") {
                Some(f) => Err(format!("{op}: {f}")),
                None => Ok(ans),
            },
            Err(_) => Err(format!("{op}: no answer")),
        }
    }
}

impl Drop for Program {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

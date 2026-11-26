//! Fake agents that answer log and exec requests (internal/server/
//! parity_logs_test.go's watchAgent): the lines each replica's live logs
//! send, the entries the node's log history answers searches with, and
//! exec sessions by the command's name, with what the node was asked.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use armada_pki::go_quote;
use armada_proto::armada::v1 as pb;
use armada_proto::google::protobuf::Timestamp;
use pb::exec_session_output::Output;
use prost::Message;
use serde_json::Value;
use tonic::transport::Channel;

use super::grpc::{Item, Stream};

const PUSH: &str = "/armada.v1.AgentService/PushLogs";
const SESSION: &str = "/armada.v1.AgentService/ExecSession";

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// What the node keeps and was asked.
#[derive(Default)]
pub struct State {
    pub history: Vec<pb::LogPush>,
    pub live: HashMap<String, Vec<String>>,
    pub errs: HashMap<String, String>,
    pub seen: Vec<String>,
    pub queries: Vec<pb::LogQuery>,
    pub cancels: HashSet<String>,
    open: HashMap<String, Option<tokio::task::AbortHandle>>,
    pub execs: Vec<String>,
    pub attach_as: Option<Channel>,
    /// What the attaches with another node's client answered.
    pub attached: Vec<Value>,
    /// Sessions the node leaves open without ending them (Go's harness
    /// returns without cancelling their streams).
    kept: Vec<Stream>,
}

/// A watch agent: its connection and state.
pub struct Watch {
    pub ch: Channel,
    pub start_ms: i64,
    pub st: Mutex<State>,
}

/// t as a protobuf timestamp.
fn ts(ms: i64) -> Timestamp {
    Timestamp {
        seconds: ms.div_euclid(1000),
        nanos: (ms.rem_euclid(1000) * 1_000_000) as i32,
    }
}

impl Watch {
    /// Takes a log request or cancel as serveLogs does: what the node was
    /// asked is recorded at once, the entries go out on a PushLogs stream
    /// of their own.
    pub fn serve_logs(self: &Arc<Self>, m: pb::server_message::Msg) {
        use pb::server_message::Msg;
        let req = match m {
            Msg::LogCancel(c) => {
                let mut st = lock(&self.st);
                st.cancels.insert(c.request_id.clone());
                if let Some(Some(h)) = st.open.get(&c.request_id) {
                    h.abort();
                }
                return;
            }
            Msg::LogRequest(r) => r,
            _ => return,
        };
        {
            let mut st = lock(&self.st);
            st.open.insert(req.request_id.clone(), None);
            match &req.query {
                Some(q) => {
                    st.queries.push(q.clone());
                    st.seen.push(format!(
                        "search {} replica={} container={} grep={} limit={} until={}",
                        q.app,
                        go_quote(&q.replica),
                        go_quote(&q.container),
                        go_quote(&q.grep),
                        q.limit,
                        q.until.is_some()
                    ));
                }
                None => st.seen.push(format!(
                    "live {} follow={} tail={} container={} grep={}",
                    req.replica_id,
                    req.follow,
                    req.tail,
                    go_quote(&req.container),
                    go_quote(&req.grep)
                )),
            }
        }
        let me = self.clone();
        let id = req.request_id.clone();
        let task = tokio::spawn(async move { me.push(req).await });
        let mut st = lock(&self.st);
        if st.cancels.contains(&id) {
            task.abort();
        }
        st.open.insert(id, Some(task.abort_handle()));
    }

    async fn push(&self, req: pb::LogRequest) {
        let mut stream = Stream::open(self.ch.clone(), PUSH);
        let send = |stream: &Stream, mut p: pb::LogPush| {
            p.request_id = req.request_id.clone();
            stream.send(p.encode_to_vec());
        };
        if let Some(q) = &req.query {
            // The node's own search: the app's entries holding the text,
            // the newest limit of them.
            let mut got: Vec<pb::LogPush> = {
                let st = lock(&self.st);
                st.history
                    .iter()
                    .filter(|h| {
                        h.replica.starts_with(&format!("{}-", q.app))
                            && String::from_utf8_lossy(&h.data)
                                .to_lowercase()
                                .contains(&q.grep.to_lowercase())
                            && (q.replica.is_empty() || h.replica == q.replica)
                    })
                    .cloned()
                    .collect()
            };
            let n = q.limit.max(0) as usize;
            if n > 0 && got.len() > n {
                got.drain(..got.len() - n);
            }
            send(&stream, pb::LogPush::default());
            for h in got {
                send(
                    &stream,
                    pb::LogPush {
                        replica: h.replica,
                        stream: h.stream,
                        data: h.data,
                        time: h.time,
                        ..Default::default()
                    },
                );
            }
            stream.close_send();
            let _ = stream.recv().await;
            return;
        }
        let (lines, fail) = {
            let st = lock(&self.st);
            (
                st.live.get(&req.replica_id).cloned().unwrap_or_default(),
                st.errs.get(&req.replica_id).cloned().unwrap_or_default(),
            )
        };
        if !fail.is_empty() {
            send(
                &stream,
                pb::LogPush {
                    error: fail,
                    ..Default::default()
                },
            );
        }
        send(&stream, pb::LogPush::default());
        for (i, l) in lines.iter().enumerate() {
            send(
                &stream,
                pb::LogPush {
                    stream: pb::Stream::Stdout as i32,
                    data: format!("{l}\n").into_bytes(),
                    time: Some(ts(self.start_ms + i as i64 * 60_000)),
                    ..Default::default()
                },
            );
        }
        if req.follow {
            // Until the request is cancelled (the task aborted, which
            // cancels the stream).
            std::future::pending::<()>().await;
        }
        stream.close_send();
        let _ = stream.recv().await;
    }

    /// Answers an exec request as serveExec does, by the command's name.
    pub async fn serve_exec(self: Arc<Self>, er: pb::ExecRequest) {
        let ch = {
            let mut st = lock(&self.st);
            st.execs.push(format!(
                "{} {} tty={} stdin={} container={} size={}",
                er.replica_id,
                er.cmd.join(" "),
                er.tty,
                er.stdin,
                go_quote(&er.container),
                er.size.is_some()
            ));
            st.attach_as.clone()
        };
        let attach = ch.is_some();
        let mut stream = Stream::open(ch.unwrap_or_else(|| self.ch.clone()), SESSION);
        let cmd = er.cmd.first().cloned().unwrap_or_default();
        let send = |stream: &Stream, o: Output| {
            stream.send(
                pb::ExecSessionOutput {
                    request_id: String::new(),
                    output: Some(o),
                }
                .encode_to_vec(),
            )
        };
        let mut first = pb::ExecSessionOutput {
            request_id: er.request_id.clone(),
            output: None,
        };
        if cmd == "missing" {
            first.output = Some(Output::Error(
                r#"exec: "missing": executable file not found in $PATH"#.into(),
            ));
        }
        stream.send(first.encode_to_vec());
        if attach {
            let v = match stream.recv().await {
                Item::Msg(_) => Value::Null,
                Item::Err(st) => super::run::status_tree(&st),
                Item::Eof => super::run::eof(),
            };
            let mut st = lock(&self.st);
            st.attached.push(v);
            st.kept.push(stream);
            return;
        }
        match cmd.as_str() {
            "missing" => {}
            "cat" => {
                // Echoes its input once it ends.
                let mut input = Vec::new();
                while let Item::Msg(b) = stream.recv().await {
                    let Ok(m) = pb::ExecInput::decode(b.as_slice()) else {
                        break;
                    };
                    match m.input {
                        Some(pb::exec_input::Input::CloseStdin(true)) => break,
                        Some(pb::exec_input::Input::Stdin(b)) => input.extend_from_slice(&b),
                        _ => {}
                    }
                }
                send(&stream, Output::Stdout(input));
                send(&stream, Output::Stderr(b"cat".to_vec()));
                send(&stream, Output::ExitCode(2));
            }
            "boom" => {
                send(&stream, Output::Stdout(b"partial".to_vec()));
                send(&stream, Output::Error("the container went away".into()));
            }
            "gone" => {
                // The node ends its session without an exit code.
                stream.close_send();
                lock(&self.st).kept.push(stream);
                return;
            }
            other => {
                send(&stream, Output::Stdout(other.as_bytes().to_vec()));
                send(&stream, Output::ExitCode(0));
            }
        }
        stream.close_send();
        while let Item::Msg(_) = stream.recv().await {}
    }

    /// The answer of the last attach with another node's client.
    pub async fn attached(&self) -> Result<Value, String> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            {
                let mut st = lock(&self.st);
                if !st.attached.is_empty() {
                    return Ok(st.attached.remove(0));
                }
            }
            if Instant::now() > deadline {
                return Err("no attach with another node's client".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The requests not cancelled.
    pub fn open_count(&self) -> usize {
        let st = lock(&self.st);
        st.open
            .keys()
            .filter(|id| !st.cancels.contains(*id))
            .count()
    }
}

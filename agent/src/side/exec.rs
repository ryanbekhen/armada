//! Exec sessions (ADR 0015): the control plane offers an
//! ExecRequest on the Connect stream; the agent opens AgentService's
//! ExecSession, checks the replica is its own and has a running container
//! (or sidecar), and relays the command's input and output. It never logs
//! the command's arguments.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use armada_proto::armada::v1 as pb;
use pb::exec_session_output::Output as Out;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::{ExecOptions, Inbound, TermSize};
use crate::agent::{Inner, lock};
use crate::runtime::{
    LABEL_MANAGED, LABEL_REPLICA, LABEL_ROLE, ROLE_SIDECAR, Runtime, STATE_RUNNING,
};

/// The exec sessions an agent runs at once.
pub const MAX_EXEC_SESSIONS: i32 = 8;
/// Exec limits.
pub const MAX_EXEC_ARGS: usize = 64;
pub const MAX_EXEC_ARG_LEN: usize = 4096;
/// The most data one exec message carries.
pub const MAX_EXEC_CHUNK: usize = 32 << 10;

/// Checks a command's bounds; errors never repeat the arguments.
pub fn check_exec_command(cmd: &[String]) -> Result<(), String> {
    if cmd.is_empty() || cmd[0].is_empty() {
        return Err("command is empty".into());
    }
    if cmd.len() > MAX_EXEC_ARGS {
        return Err(format!("command has more than {MAX_EXEC_ARGS} arguments"));
    }
    for (i, a) in cmd.iter().enumerate() {
        if a.len() > MAX_EXEC_ARG_LEN {
            return Err(format!(
                "argument {i} is longer than {MAX_EXEC_ARG_LEN} bytes"
            ));
        }
        if a.contains('\0') {
            return Err(format!("argument {i} contains a NUL byte"));
        }
    }
    Ok(())
}

pub(crate) fn term_size(t: Option<&pb::TermSize>) -> TermSize {
    let t = t.cloned().unwrap_or_default();
    TermSize {
        rows: t.rows.min(0xffff) as u16,
        cols: t.cols.min(0xffff) as u16,
    }
}

/// The last element of a path, trailing slashes dropped; "." for an
/// empty path, "/" for slashes only.
fn base(p: &str) -> String {
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        return if p.is_empty() { ".".into() } else { "/".into() };
    }
    t.rsplit('/').next().unwrap_or(t).to_string()
}

impl<R: Runtime> Inner<R> {
    /// One exec request.
    pub(crate) async fn serve_exec(self: Arc<Self>, req: pb::ExecRequest) {
        let Some(conn) = lock(&self.side.conn).clone() else {
            return;
        };
        let (tx, rx) = mpsc::channel::<pb::ExecSessionOutput>(16);
        let mut client = conn.client();
        let mut inbound =
            Inbound::new(async move { client.exec_session(ReceiverStream::new(rx)).await });
        let rid = req.request_id.clone();
        // finish sends the last message and waits for the server to end the
        // session, so it is delivered before the stream goes.
        async fn finish(
            tx: mpsc::Sender<pb::ExecSessionOutput>,
            inbound: Option<&mut Inbound<pb::ExecInput>>,
            done: Option<tokio::sync::oneshot::Receiver<()>>,
            m: pb::ExecSessionOutput,
        ) {
            let _ = tx.send(m).await;
            drop(tx);
            if let Some(d) = done {
                let _ = d.await;
                return;
            }
            if let Some(i) = inbound {
                i.drain().await;
            }
        }
        let fail = |msg: String| pb::ExecSessionOutput {
            request_id: rid.clone(),
            output: Some(Out::Error(msg)),
        };

        let n = self.side.execs.fetch_add(1, Ordering::SeqCst) + 1;
        let _guard = Counter(&self.side.execs);
        if n > MAX_EXEC_SESSIONS {
            let m = fail("this node already runs the most exec sessions it allows".into());
            return finish(tx, Some(&mut inbound), None, m).await;
        }
        if let Err(e) = check_exec_command(&req.cmd) {
            return finish(tx, Some(&mut inbound), None, fail(e)).await;
        }
        if !self.rt.can_exec() {
            let m =
                fail("this node's container runtime does not run commands in containers".into());
            return finish(tx, Some(&mut inbound), None, m).await;
        }
        let assigned = lock(&self.st)
            .desired
            .as_ref()
            .is_some_and(|d| d.contains_key(&req.replica_id));
        if !assigned {
            let m = fail(format!(
                "replica {} is not assigned to this node",
                req.replica_id
            ));
            return finish(tx, Some(&mut inbound), None, m).await;
        }
        let labels = std::collections::BTreeMap::from([
            (LABEL_MANAGED.to_string(), "true".to_string()),
            (LABEL_REPLICA.to_string(), req.replica_id.clone()),
        ]);
        let cs = match self.rt.list(&labels).await {
            Ok(cs) => cs,
            Err(e) => {
                let m = fail(format!("list containers: {e}"));
                return finish(tx, Some(&mut inbound), None, m).await;
            }
        };
        let app = req.container.is_empty() || req.container == "app";
        let mut id = String::new();
        for c in &cs {
            if !c.label(LABEL_ROLE).is_empty() {
                continue; // an init container or sidecar left behind
            }
            if app {
                if c.state == STATE_RUNNING {
                    id = c.id.clone();
                }
                continue;
            }
            // A sidecar (ADR 0038); an init container has run to its end.
            if let Some(m) = c.members.iter().find(|m| m.name == req.container)
                && m.role == ROLE_SIDECAR
                && m.state == STATE_RUNNING
            {
                id = m.id.clone();
            }
        }
        if id.is_empty() {
            let m = if app {
                fail(format!(
                    "replica {} has no running container on this node",
                    req.replica_id
                ))
            } else {
                fail(format!(
                    "replica {} has no running sidecar {} on this node",
                    req.replica_id, req.container
                ))
            };
            return finish(tx, Some(&mut inbound), None, m).await;
        }
        if tx
            .send(pb::ExecSessionOutput {
                request_id: rid.clone(),
                output: None,
            })
            .await
            .is_err()
        {
            return;
        }

        let (resize_tx, resize_rx) = mpsc::channel(4);
        let (stdin_tx, stdin_rx) = if req.stdin {
            let (t, r) = mpsc::channel::<Vec<u8>>(16);
            (Some(t), Some(r))
        } else {
            (None, None)
        };
        let (out_tx, mut out_rx) = mpsc::channel::<super::Output>(16);
        // The server ending the stream ends the command.
        let (ended_tx, ended_rx) = tokio::sync::oneshot::channel::<()>();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let mut stdin = stdin_tx;
            while let Some(m) = inbound.message().await {
                use pb::exec_input::Input;
                match m.input {
                    Some(Input::Resize(t)) => {
                        let _ = resize_tx.try_send(term_size(Some(&t)));
                    }
                    Some(Input::CloseStdin(true)) => stdin = None,
                    Some(Input::Stdin(b)) if !b.is_empty() => {
                        if let Some(s) = &stdin
                            && s.send(b).await.is_err()
                        {
                            stdin = None;
                        }
                    }
                    _ => {}
                }
            }
            drop(stdin);
            let _ = ended_tx.send(());
            let _ = done_tx.send(());
        });
        // Output goes out as it is written, in chunks.
        let fwd_tx = tx.clone();
        let forward = tokio::spawn(async move {
            while let Some((stdout, data)) = out_rx.recv().await {
                for chunk in data.chunks(MAX_EXEC_CHUNK) {
                    let o = if stdout {
                        Out::Stdout(chunk.to_vec())
                    } else {
                        Out::Stderr(chunk.to_vec())
                    };
                    if fwd_tx
                        .send(pb::ExecSessionOutput {
                            request_id: String::new(),
                            output: Some(o),
                        })
                        .await
                        .is_err()
                    {
                        // The stream is gone: drain so the command ends.
                        while out_rx.recv().await.is_some() {}
                        return;
                    }
                }
            }
        });
        self.log.info(
            "exec session",
            &[
                ("replica", req.replica_id.clone()),
                ("command", base(&req.cmd[0])),
                ("tty", req.tty.to_string()),
            ],
        );
        let opts = ExecOptions {
            cmd: req.cmd.clone(),
            tty: req.tty,
            size: term_size(req.size.as_ref()),
            stdin: stdin_rx,
            output: Some(out_tx),
            resize: Some(resize_rx),
        };
        let res = tokio::select! {
            r = self.rt.exec_session(&id, opts) => r,
            _ = ended_rx => return, // context canceled
        };
        let _ = forward.await;
        let m = match res {
            Ok(code) => pb::ExecSessionOutput {
                request_id: String::new(),
                output: Some(Out::ExitCode(code as i32)),
            },
            Err(e) => fail(e.to_string()),
        };
        finish(tx, None, Some(done_rx), m).await;
    }
}

/// Decrements a counter when dropped.
struct Counter<'a>(&'a std::sync::atomic::AtomicI32);

impl Drop for Counter<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(check_exec_command(&[]).unwrap_err(), "command is empty");
        assert_eq!(
            check_exec_command(&s(&[""])).unwrap_err(),
            "command is empty"
        );
        assert!(check_exec_command(&s(&["sh", "-c", "x"])).is_ok());
        assert_eq!(
            check_exec_command(&vec!["a".to_string(); 65]).unwrap_err(),
            "command has more than 64 arguments"
        );
        assert_eq!(
            check_exec_command(&["a".into(), "x".repeat(4097)]).unwrap_err(),
            "argument 1 is longer than 4096 bytes"
        );
        assert_eq!(
            check_exec_command(&s(&["a\0"])).unwrap_err(),
            "argument 0 contains a NUL byte"
        );
        assert_eq!(base("/bin/sh"), "sh");
        assert_eq!(base("sh"), "sh");
    }
}

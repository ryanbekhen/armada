//! Exec (ADR 0015): a command runs in one
//! replica of an app. The leader picks the replica, audits the command's
//! name (never its arguments), offers an ExecRequest on the node's Connect
//! stream, and relays between the admin's stream and the ExecSession the
//! agent opens for it (the router pairs them, once and only for the node
//! the request went to).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use armada_proto::armada::v1::exec_client_message::Msg as ClientMsg;
use armada_proto::armada::v1::exec_input::Input;
use armada_proto::armada::v1::exec_server_message::Msg as OutMsg;
use armada_proto::armada::v1::exec_session_output::Output;
use armada_proto::armada::v1::server_message::Msg;
use armada_proto::armada::v1::*;
use armada_spec::MAIN_CONTAINER;
use armada_store::{App, REPLICA_RUNNING, Replica, ReplicaFilter};
use tokio::sync::{mpsc, oneshot};
use tonic::{Code, Request, Response, Status, Streaming};

use crate::Server;
use crate::admin::Out;
use crate::apps::spec_containers;
use crate::grpc::auth;
use crate::store_err;

/// Bounds the names an error lists as choices.
const MAX_CHOICES: usize = 20;
/// Ends an exec session without input or output.
const EXEC_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// How often an exec session checks for idleness.
const EXEC_IDLE_CHECK: Duration = Duration::from_secs(60);
/// How long an agent has to open the session.
pub(crate) const ATTACH_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a request waits for room in a session's queue.
pub(crate) const OFFER_TIMEOUT: Duration = Duration::from_secs(5);
/// The most arguments of a command, bytes of its arguments, and bytes of
/// one message.
const MAX_EXEC_ARGS: usize = 64;
const MAX_EXEC_ARG_LEN: usize = 4096;
const MAX_EXEC_CHUNK: usize = 32 << 10;

/// The name `armada replica list` prints for a replica, the
/// part of its ID after the last hyphen (ADR 0052).
pub(crate) fn short_replica(id: &str) -> &str {
    match id.rfind('-') {
        Some(i) => &id[i + 1..],
        None => id,
    }
}

/// choices: names for an error, sorted and unique, at most MAX_CHOICES.
pub(crate) fn choices(names: &[String]) -> String {
    let mut names = names.to_vec();
    names.sort();
    names.dedup();
    if names.len() > MAX_CHOICES {
        return format!(
            "{}, and {} more",
            names[..MAX_CHOICES].join(", "),
            names.len() - MAX_CHOICES
        );
    }
    names.join(", ")
}

/// The replica of app a person named, by ID or short name.
pub(crate) fn find_replica(app: &str, reps: &[Replica], name: &str) -> Result<Replica, Status> {
    let mut found = Vec::new();
    for r in reps {
        if r.id == name {
            return Ok(r.clone());
        }
        if short_replica(&r.id) == name {
            found.push(r);
        }
    }
    match found.len() {
        1 => Ok(found[0].clone()),
        0 => {
            let names: Vec<String> = reps
                .iter()
                .map(|r| short_replica(&r.id).to_string())
                .collect();
            if names.is_empty() {
                return Err(Status::new(
                    Code::NotFound,
                    format!("{app} has no replicas"),
                ));
            }
            Err(Status::new(
                Code::NotFound,
                format!(
                    "{app} has no replica {}; its replicas: {}",
                    armada_spec::go::quote(name),
                    choices(&names)
                ),
            ))
        }
        _ => {
            let ids: Vec<String> = found.iter().map(|r| r.id.clone()).collect();
            Err(Status::new(
                Code::InvalidArgument,
                format!(
                    "{} names more than one replica of {app}; give the full ID: {}",
                    armada_spec::go::quote(name),
                    choices(&ids)
                ),
            ))
        }
    }
}

/// Empty or "app" for the app's own container, else
/// an init container's or sidecar's name.
pub(crate) fn check_container_name(name: &str) -> Result<(), Status> {
    if name.is_empty()
        || name == MAIN_CONTAINER
        || (armada_spec::validate::valid_name(name) && name.len() <= 30)
    {
        return Ok(());
    }
    Err(Status::new(
        Code::InvalidArgument,
        format!("{} is not a container name", armada_spec::go::quote(name)),
    ))
}

/// A command's bounds checked; errors never repeat the arguments.
fn check_exec_command(cmd: &[String]) -> Result<(), String> {
    if cmd.first().is_none_or(String::is_empty) {
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

fn base(p: &str) -> &str {
    if p.is_empty() {
        return ".";
    }
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        return "/";
    }
    match t.rfind('/') {
        Some(i) => &t[i + 1..],
        None => t,
    }
}

/// An agent's session for an exec request, as the router hands it over.
struct Attached {
    first: ExecSessionOutput,
    inbound: Streaming<ExecSessionOutput>,
    out: mpsc::Sender<Result<ExecInput, Status>>,
}

struct Pending {
    node: String,
    tx: oneshot::Sender<Attached>,
}

/// Pairs exec requests with the agent streams that serve them.
#[derive(Default)]
pub struct ExecRouter {
    pending: Mutex<HashMap<String, Pending>>,
}

impl ExecRouter {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pending>> {
        self.pending.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn register(&self, node: &str) -> (String, oneshot::Receiver<Attached>) {
        let id = crate::random_id(20);
        let (tx, rx) = oneshot::channel();
        self.lock().insert(
            id.clone(),
            Pending {
                node: node.to_string(),
                tx,
            },
        );
        (id, rx)
    }

    /// attach: claims a pending request for node with the agent's stream,
    /// once and only by the node it was sent to.
    fn attach(
        &self,
        id: &str,
        node: &str,
        first: ExecSessionOutput,
        inbound: Streaming<ExecSessionOutput>,
    ) -> Option<mpsc::Receiver<Result<ExecInput, Status>>> {
        let p = {
            let mut m = self.lock();
            match m.get(id) {
                Some(p) if p.node == node => {}
                _ => return None,
            }
            m.remove(id)?
        };
        let (out, rx) = mpsc::channel(16);
        let _ = p.tx.send(Attached {
            first,
            inbound,
            out,
        });
        Some(rx)
    }

    fn cancel(&self, id: &str) {
        self.lock().remove(id);
    }
}

impl Server {
    /// Refuses a container no revision of revs has,
    /// naming the ones they have; exec takes only running ones.
    pub(crate) async fn check_container(
        &self,
        app: &str,
        name: &str,
        revs: &[String],
        exec: bool,
    ) -> Result<(), Status> {
        if name.is_empty() || name == MAIN_CONTAINER {
            return Ok(());
        }
        let (mut running, mut inits): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
        for n in revs {
            let rev = self
                .store()
                .get_revision(n)
                .await
                .map_err(|e| store_err(&e))?;
            let (r, i) = spec_containers(rev.spec());
            for c in r {
                if !running.contains(&c) {
                    running.push(c);
                }
            }
            for c in i {
                if !inits.contains(&c) {
                    inits.push(c);
                }
            }
        }
        let name_s = name.to_string();
        if running.contains(&name_s) || (inits.contains(&name_s) && !exec) {
            return Ok(());
        }
        if inits.contains(&name_s) {
            return Err(Status::new(
                Code::FailedPrecondition,
                format!(
                    "{name} is an init container of {app} and runs only before the app starts; see its output with armada app logs {app} --container {name}"
                ),
            ));
        }
        let mut all = running;
        if !exec {
            all.extend(inits);
        }
        Err(Status::new(
            Code::NotFound,
            format!(
                "{app} has no container {}; its containers: {}",
                armada_spec::go::quote(name),
                choices(&all)
            ),
        ))
    }

    /// The replica named, or a running, ready replica of the
    /// serving revision.
    async fn exec_replica(&self, app: &App, replica: &str) -> Result<Replica, Status> {
        let reps = self
            .store()
            .list_replicas(&ReplicaFilter {
                app: app.name.clone(),
                ..Default::default()
            })
            .await
            .map_err(|e| store_err(&e))?;
        if !replica.is_empty() {
            let r = find_replica(&app.name, &reps, replica)?;
            if r.state != REPLICA_RUNNING {
                return Err(Status::new(
                    Code::FailedPrecondition,
                    format!(
                        "replica {} is {}, not running",
                        short_replica(&r.id),
                        r.state
                    ),
                ));
            }
            return Ok(r);
        }
        for r in reps {
            if r.revision == app.active_revision
                && r.state == REPLICA_RUNNING
                && r.ready
                && r.draining_since.is_zero()
            {
                return Ok(r);
            }
        }
        Err(Status::new(
            Code::FailedPrecondition,
            format!(
                "app {} has no running, ready replica of its serving revision; name one with --replica",
                app.name
            ),
        ))
    }

    /// Exec: runs a command in one replica of an app.
    pub(crate) async fn exec(
        &self,
        request: Request<Streaming<ExecClientMessage>>,
    ) -> Result<Response<Out<ExecServerMessage>>, Status> {
        let a = auth(&request)?;
        let mut inbound = request.into_inner();
        let Some(first) = inbound.message().await? else {
            return Err(Status::new(Code::Unknown, "EOF"));
        };
        let Some(ClientMsg::Start(start)) = first.msg else {
            return Err(Status::new(
                Code::InvalidArgument,
                "the first message must be start",
            ));
        };
        // Checked again while the session is open (the stream's guard).
        let app_id = start.app.clone();
        let guard = self.stream_guard(
            &a,
            "/armada.v1.AdminService/Exec",
            Box::new(move |acc| acc.app(&app_id)),
        )?;
        let stop = |e: Status| {
            if let Some(g) = &guard {
                g.stop();
            }
            e
        };
        check_exec_command(&start.cmd).map_err(|e| stop(Status::new(Code::InvalidArgument, e)))?;
        check_container_name(&start.container).map_err(stop)?;
        let app = self
            .store()
            .get_app(&start.app)
            .await
            .map_err(|e| stop(store_err(&e)))?;
        let r = self
            .exec_replica(&app, &start.replica)
            .await
            .map_err(stop)?;
        self.check_container(
            &app.name,
            &start.container,
            std::slice::from_ref(&r.revision),
            true,
        )
        .await
        .map_err(stop)?;
        let Some(sess) = self.session(&r.node_id) else {
            return Err(stop(Status::new(
                Code::Unavailable,
                format!("node {} is not connected", r.node_id),
            )));
        };
        let name = base(&start.cmd[0]).to_string();
        let mut detail = format!("replica={} command={name} tty={}", r.id, start.tty);
        if !start.container.is_empty() {
            detail.push_str(&format!(" container={}", start.container));
        }
        self.store()
            .record_audit(&a.actor(), "app.exec", &app.name, &detail)
            .await
            .map_err(|e| stop(store_err(&e)))?;
        self.0.log.info(
            "exec",
            &[
                ("app", app.name.clone()),
                ("replica", r.id.clone()),
                ("node", r.node_id.clone()),
                ("container", start.container.clone()),
                ("command", name),
                ("tty", start.tty.to_string()),
                ("by", a.actor()),
            ],
        );
        let (id, rx) = self.0.execs.register(&r.node_id);
        let req = ExecRequest {
            request_id: id.clone(),
            replica_id: r.id.clone(),
            cmd: start.cmd.clone(),
            tty: start.tty,
            stdin: start.stdin,
            size: start.size,
            container: start.container.clone(),
        };
        if !sess
            .offer(
                ServerMessage {
                    msg: Some(Msg::ExecRequest(req)),
                },
                OFFER_TIMEOUT,
            )
            .await
        {
            self.0.execs.cancel(&id);
            return Err(stop(Status::new(
                Code::Unavailable,
                format!("node {} did not accept the exec request", r.node_id),
            )));
        }
        let att = match tokio::time::timeout(ATTACH_TIMEOUT, rx).await {
            Ok(Ok(att)) => att,
            _ => {
                self.0.execs.cancel(&id);
                return Err(stop(Status::new(
                    Code::Unavailable,
                    format!("node {} did not start the exec session", r.node_id),
                )));
            }
        };
        // The agent's first message carried the request ID; an error there
        // means the command did not start.
        if let Some(Output::Error(e)) = &att.first.output
            && !e.is_empty()
        {
            return Err(stop(Status::new(Code::FailedPrecondition, e.clone())));
        }
        let (tx, out_rx) = mpsc::channel::<Result<ExecServerMessage, Status>>(16);
        let replica = r.id.clone();
        tokio::spawn(async move {
            let Attached {
                inbound: mut agent_in,
                out: agent_out,
                ..
            } = att;
            let send = |m: OutMsg| ExecServerMessage { msg: Some(m) };
            let res: Result<(), Status> = async {
                if tx.send(Ok(send(OutMsg::Replica(replica)))).await.is_err() {
                    return Ok(());
                }
                let mut last = tokio::time::Instant::now();
                let mut idle = tokio::time::interval_at(
                    tokio::time::Instant::now() + EXEC_IDLE_CHECK,
                    EXEC_IDLE_CHECK,
                );
                let mut admin_open = true;
                loop {
                    let cancelled = async {
                        match &guard {
                            Some(g) => g.cancelled().await,
                            None => std::future::pending().await,
                        }
                    };
                    tokio::select! {
                        m = inbound.message(), if admin_open => {
                            match m {
                                Ok(Some(m)) => {
                                    let input = match m.msg {
                                        Some(ClientMsg::Input(i)) => i,
                                        _ => return Err(Status::new(Code::InvalidArgument, "expected input of at most 32 KiB")),
                                    };
                                    if matches!(&input.input, Some(Input::Stdin(b)) if b.len() > MAX_EXEC_CHUNK) {
                                        return Err(Status::new(Code::InvalidArgument, "expected input of at most 32 KiB"));
                                    }
                                    last = tokio::time::Instant::now();
                                    if agent_out.send(Ok(input)).await.is_err() {
                                        return Err(Status::new(Code::Unavailable, "the node ended the exec session"));
                                    }
                                }
                                // The CLI has nothing more to send; output may follow.
                                Ok(None) => admin_open = false,
                                Err(e) => return Err(e),
                            }
                        }
                        m = agent_in.message() => {
                            let Ok(Some(m)) = m else {
                                return Err(Status::new(Code::Unavailable, "the node ended the exec session"));
                            };
                            last = tokio::time::Instant::now();
                            let msg = match m.output {
                                Some(Output::Stdout(b)) => OutMsg::Stdout(b),
                                Some(Output::Stderr(b)) => OutMsg::Stderr(b),
                                Some(Output::ExitCode(c)) => {
                                    let _ = tx.send(Ok(send(OutMsg::ExitCode(c)))).await;
                                    return Ok(());
                                }
                                Some(Output::Error(e)) => {
                                    return Err(Status::new(Code::FailedPrecondition, e));
                                }
                                None => continue,
                            };
                            if tx.send(Ok(send(msg))).await.is_err() {
                                return Ok(());
                            }
                        }
                        _ = idle.tick() => {
                            if last.elapsed() > EXEC_IDLE_TIMEOUT {
                                return Err(Status::new(Code::DeadlineExceeded, "exec session idle for too long"));
                            }
                        }
                        _ = cancelled => return Ok(()),
                        _ = tx.closed() => return Ok(()),
                    }
                }
            }
            .await;
            // The guard's reason first.
            let err = guard.as_ref().and_then(|g| g.ended()).or(res.err());
            if let Some(e) = err {
                let _ = tx.send(Err(e)).await;
            }
            if let Some(g) = &guard {
                g.stop();
            }
            drop(agent_out);
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(out_rx),
        )))
    }

    /// ExecSession: the session stream for a pending exec request, from
    /// the agent it was sent to, held until the admin side is done.
    pub(crate) async fn exec_session(
        &self,
        request: Request<Streaming<ExecSessionOutput>>,
    ) -> Result<Response<Out<ExecInput>>, Status> {
        let a = auth(&request)?;
        let mut inbound = request.into_inner();
        let Some(first) = inbound.message().await? else {
            return Err(Status::new(Code::Unknown, "EOF"));
        };
        let id = first.request_id.clone();
        let Some(rx) = self.0.execs.attach(&id, &a.id.name, first, inbound) else {
            return Err(Status::new(Code::PermissionDenied, "unknown exec request"));
        };
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rep(id: &str) -> Replica {
        Replica {
            id: id.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn finds_replicas() {
        let reps = vec![
            rep("web-r1-abcde"),
            rep("web-r2-fghij"),
            rep("web-r3-abcde"),
        ];
        assert_eq!(
            find_replica("web", &reps, "fghij").unwrap().id,
            "web-r2-fghij"
        );
        assert_eq!(
            find_replica("web", &reps, "web-r1-abcde").unwrap().id,
            "web-r1-abcde"
        );
        let e = find_replica("web", &reps, "abcde").unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument);
        assert_eq!(
            e.message(),
            "\"abcde\" names more than one replica of web; give the full ID: web-r1-abcde, web-r3-abcde"
        );
        let e = find_replica("web", &reps, "zzz").unwrap_err();
        assert_eq!(
            e.message(),
            "web has no replica \"zzz\"; its replicas: abcde, fghij"
        );
        assert_eq!(
            find_replica("web", &[], "x").unwrap_err().message(),
            "web has no replicas"
        );
    }

    #[test]
    fn choices_bounded() {
        let names: Vec<String> = (0..25).map(|i| format!("n{i:02}")).collect();
        assert!(choices(&names).ends_with(", and 5 more"));
    }

    #[test]
    fn commands_checked() {
        assert!(check_exec_command(&[]).is_err());
        assert!(check_exec_command(&["".into()]).is_err());
        assert!(check_exec_command(&["sh".into(), "a\0b".into()]).is_err());
        assert!(check_exec_command(&vec!["x".into(); 65]).is_err());
        assert!(check_exec_command(&["sh".into()]).is_ok());
        assert_eq!(base("/bin/sh"), "sh");
        assert_eq!(base("sh/"), "sh");
        assert_eq!(base("///"), "/");
        assert!(check_container_name("side-1").is_ok());
        assert!(check_container_name("Bad Name").is_err());
    }
}

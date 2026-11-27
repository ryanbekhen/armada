//! armada-shim as the driver reaches it: one shim per group, started as a
//! transient systemd unit, asked one line per connection. armada-node's
//! code does the calls, the start, and the abandon in process; a wait,
//! which lasts as long as its container, is asked here so dropping it
//! closes the connection.

use std::collections::BTreeMap;
use std::path::PathBuf;

use armada_node::runtime::container::oci::OciRuntime;
use armada_node::runtime::container::shim::{self, CallError, Request};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// What a shim reports about a container.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskState {
    /// "created", "running", or "exited".
    pub status: &'static str,
    pub pid: i64,
    pub exit: i64,
}

/// The shims of a node.
#[derive(Clone, Debug, Default)]
pub struct Shims {
    /// Each shim's socket and state (tmpfs).
    pub dir: PathBuf,
    /// The programs a shim runs.
    pub bin: String,
    /// The OCI runtimes (ADR 0056): crun for new containers, runc for
    /// those it created before.
    pub runc: String,
    pub crun: String,
    pub logger: String,
    /// The programs systemd is reached through; "" for systemd-run and
    /// systemctl (tests name stand-ins).
    pub systemd_run: String,
    pub systemctl: String,
}

/// Whether a shim's own error ("err TEXT") says what it was asked for is
/// not found.
pub fn not_found(e: &CallError) -> bool {
    matches!(e, CallError::Shim(t) if t.ends_with(" not found"))
}

/// The text of an error.
pub fn text(e: &CallError) -> String {
    e.text().to_string()
}

fn parse_state(w: &[&str]) -> Result<TaskState, String> {
    let bad = || {
        format!(
            "shim: unexpected state {}",
            armada_pki::go_quote(&w.join(" "))
        )
    };
    if w.len() != 2 {
        return Err(bad());
    }
    let n = atoi(w[1]).ok_or_else(bad)?;
    match w[0] {
        "created" => Ok(TaskState {
            status: "created",
            pid: n,
            exit: 0,
        }),
        "running" => Ok(TaskState {
            status: "running",
            pid: n,
            exit: 0,
        }),
        "exited" => Ok(TaskState {
            status: "exited",
            pid: 0,
            exit: n,
        }),
        _ => Err(bad()),
    }
}

/// A decimal integer with an optional sign; None for anything else.
pub fn atoi(s: &str) -> Option<i64> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

impl Shims {
    fn request(&self, group: &str, words: Vec<String>) -> Request {
        Request {
            dir: self.dir.display().to_string(),
            bin: self.bin.clone(),
            runc: self.runc.clone(),
            crun: self.crun.clone(),
            logger: self.logger.clone(),
            group: group.to_string(),
            systemd_run: self.systemd_run.clone(),
            systemctl: self.systemctl.clone(),
            timeout_ms: 0,
            words,
            deadline: None,
        }
    }

    /// The group's socket.
    pub fn socket(&self, group: &str) -> PathBuf {
        self.dir.join(format!("{}.sock", shim::shim_name(group)))
    }

    /// The OCI runtime's state directory for the group's containers.
    pub fn root(&self, group: &str, rt: OciRuntime) -> PathBuf {
        rt.root(&self.dir.join(shim::shim_name(group)))
    }

    /// The OCI runtime's program.
    pub fn program(&self, rt: OciRuntime) -> &str {
        match rt {
            OciRuntime::Runc => &self.runc,
            OciRuntime::Crun => &self.crun,
        }
    }

    /// One request; the words after "ok".
    pub async fn call(&self, group: &str, words: &[&str]) -> Result<String, CallError> {
        let socket = self.socket(group);
        let words: Vec<String> = words.iter().map(|w| w.to_string()).collect();
        tokio::task::spawn_blocking(move || shim::call(&socket, &words, None))
            .await
            .unwrap_or_else(|e| Err(CallError::Conn(e.to_string(), None)))
    }

    /// The group's shim, started when none runs.
    pub async fn start(&self, group: &str) -> Result<(), String> {
        let r = self.request(group, Vec::new());
        tokio::task::spawn_blocking(move || r.start())
            .await
            .map_err(|e| e.to_string())?
    }

    /// Whether the shim was gone, its containers ended.
    pub async fn abandon(&self, group: &str) -> (bool, Option<String>) {
        let r = self.request(group, Vec::new());
        tokio::task::spawn_blocking(move || r.abandon())
            .await
            .unwrap_or_else(|e| (false, Some(e.to_string())))
    }

    pub async fn state(&self, group: &str, id: &str) -> Result<TaskState, CallError> {
        let out = self.call(group, &["state", id]).await?;
        parse_state(&out.split_whitespace().collect::<Vec<_>>())
            .map_err(|t| CallError::Conn(t, None))
    }

    /// Every container of the group's shim.
    pub async fn list(&self, group: &str) -> Result<BTreeMap<String, TaskState>, CallError> {
        let out = self.call(group, &["list"]).await?;
        let f: Vec<&str> = out.split_whitespace().collect();
        if !f.len().is_multiple_of(2) {
            return Err(CallError::Conn(
                format!("shim: unexpected list {}", armada_pki::go_quote(&out)),
                None,
            ));
        }
        let mut states = BTreeMap::new();
        for pair in f.chunks(2) {
            let (status, n) = pair[1].split_once(':').unwrap_or((pair[1], ""));
            let st = parse_state(&[status, n]).map_err(|t| CallError::Conn(t, None))?;
            states.insert(pair[0].to_string(), st);
        }
        Ok(states)
    }

    /// The container made from its bundle by the OCI
    /// runtime rt, not started; its output goes to armada-log in logs. Its
    /// process ID. runc is asked for as before ADR 0056 (no runtime word).
    pub async fn create(
        &self,
        group: &str,
        id: &str,
        bundle: &str,
        logs: &str,
        rt: OciRuntime,
    ) -> Result<i64, String> {
        let mut words = vec!["create", id, bundle, logs];
        if rt != OciRuntime::Runc {
            words.push(rt.name());
        }
        let out = self.call(group, &words).await.map_err(|e| text(&e))?;
        atoi(&out).ok_or_else(|| {
            format!(
                "strconv.Atoi: parsing {}: invalid syntax",
                armada_pki::go_quote(&out)
            )
        })
    }

    /// Over a connection of its own: the exit code once the
    /// container exits. Dropping the future closes the connection.
    pub async fn wait(&self, group: &str, id: &str) -> Result<i64, String> {
        let socket = self.socket(group);
        let mut c = tokio::net::UnixStream::connect(&socket)
            .await
            .map_err(|e| {
                format!(
                    "dial unix {}: connect: {}",
                    socket.display(),
                    super::errno(&e)
                )
            })?;
        c.write_all(format!("wait {id}\n").as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut line = String::new();
        BufReader::new(c)
            .read_line(&mut line)
            .await
            .map_err(|e| format!("shim: {e}"))?;
        if !line.ends_with('\n') {
            return Err("shim: EOF".into());
        }
        let line = line.trim_end_matches('\n');
        if let Some(rest) = line.strip_prefix("ok ") {
            return atoi(rest).ok_or_else(|| {
                format!(
                    "strconv.Atoi: parsing {}: invalid syntax",
                    armada_pki::go_quote(rest)
                )
            });
        }
        if let Some(e) = line.strip_prefix("err ") {
            return Err(e.to_string());
        }
        Err(format!(
            "shim: unexpected answer {}",
            armada_pki::go_quote(line)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_parsed() {
        assert_eq!(
            parse_state(&["running", "42"]).unwrap(),
            TaskState {
                status: "running",
                pid: 42,
                exit: 0
            }
        );
        assert_eq!(parse_state(&["exited", "137"]).unwrap().exit, 137);
        assert_eq!(
            parse_state(&["paused", "1"]).unwrap_err(),
            "shim: unexpected state \"paused 1\""
        );
        assert!(not_found(&CallError::Shim("container x not found".into())));
        assert!(!not_found(&CallError::Conn("x not found".into(), None)));
    }
}

//! Log sessions and the log history (ADR 0043): live logs and follows of a
//! replica's container, searches of the node's history, and its prune with
//! the cluster's settings.

use std::sync::Arc;
use std::time::Duration;

use armada_proto::armada::v1 as pb;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;

use super::{LogOptions, LogQuery, from_ts, ts};
use crate::agent::{Inner, lock};
use crate::runtime::{LABEL_MANAGED, LABEL_REPLICA, LABEL_ROLE, Runtime};

/// How often the node's log history is bounded.
pub const LOG_PRUNE_EVERY: Duration = Duration::from_secs(60);
/// What one search on this node reads at most, and for how long.
pub const MAX_SEARCH_BYTES: i64 = 1 << 30;
pub const SEARCH_TIMEOUT: Duration = Duration::from_secs(30);
/// The entries one search returns at most.
pub const MAX_SEARCH_LIMIT: i64 = 5000;
/// The searches the node runs at once: each may hold its entries in memory.
pub const MAX_SEARCHES: usize = 2;
/// The live log streams the node serves at once: each holds a log file and
/// its tail in memory.
pub const MAX_LIVE_LOGS: usize = 32;

/// Whether line holds needle (lower case),
/// ignoring case.
pub fn contains_fold(line: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.iter().any(|&c| c >= 0x80) {
        // Unicode lower case of valid UTF-8, other bytes as
        // they are.
        let lower = lower_bytes(line);
        return lower.windows(needle.len()).any(|w| w == needle);
    }
    if line.len() < needle.len() {
        return false;
    }
    (0..=line.len() - needle.len()).any(|i| line[i..i + needle.len()].eq_ignore_ascii_case(needle))
}

/// b in lower case, rune by rune; invalid UTF-8 kept as it is.
fn lower_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    for chunk in b.utf8_chunks() {
        for c in chunk.valid().chars() {
            // Lower case maps one rune to one rune here.
            let mut l = c.to_lowercase();
            let lower = match (l.next(), l.next()) {
                (Some(x), None) => x,
                _ => c,
            };
            let mut buf = [0u8; 4];
            out.extend_from_slice(lower.encode_utf8(&mut buf).as_bytes());
        }
        out.extend_from_slice(chunk.invalid());
    }
    out
}

/// The replica's own container, or its init container
/// or sidecar by name.
pub(crate) fn container_for(
    cs: &[crate::runtime::Container],
    name: &str,
) -> Result<String, String> {
    for c in cs {
        if !c.label(LABEL_ROLE).is_empty() {
            continue; // left over from a replica's container that is gone
        }
        if name.is_empty() || name == "app" {
            return Ok(c.id.clone());
        }
        return match c.members.iter().find(|m| m.name == name) {
            Some(m) => Ok(m.id.clone()),
            None => Err(format!("the replica has no container {name}")),
        };
    }
    Err("no container on this node".into())
}

fn stream_of(stderr: bool) -> i32 {
    if stderr {
        pb::Stream::Stderr as i32
    } else {
        pb::Stream::Stdout as i32
    }
}

impl<R: Runtime> Inner<R> {
    /// One log request.
    pub(crate) async fn serve_logs(self: Arc<Self>, req: pb::LogRequest) {
        let (cancel_tx, mut cancel) = watch::channel(false);
        lock(&self.side.cancels).insert(req.request_id.clone(), cancel_tx);
        let me = self.clone();
        let rid = req.request_id.clone();
        tokio::select! {
            _ = me.serve_logs_inner(&req) => {}
            _ = cancel.wait_for(|c| *c) => {}
        }
        lock(&self.side.cancels).remove(&rid);
    }

    async fn serve_logs_inner(&self, req: &pb::LogRequest) {
        let Some(conn) = lock(&self.side.conn).clone() else {
            return;
        };
        let (tx, rx) = mpsc::channel::<pb::LogPush>(16);
        let mut client = conn.client();
        let call = tokio::spawn(async move { client.push_logs(ReceiverStream::new(rx)).await });
        let push = Push {
            tx,
            rid: req.request_id.clone(),
        };
        // Attach at once: a container that has written nothing yet would
        // otherwise look like a node that never answered.
        if !push.send(pb::LogPush::default()).await {
            call.abort();
            return;
        }
        if let Some(q) = &req.query {
            self.serve_search(req, q, &push).await;
        } else {
            self.serve_live(req, &push).await;
        }
        // CloseAndRecv.
        drop(push);
        let _ = call.await;
    }

    /// Streams a replica's live logs, at most MAX_LIVE_LOGS at
    /// once.
    async fn serve_live(&self, req: &pb::LogRequest, push: &Push) {
        let Ok(_permit) = self.side.live_logs.clone().try_acquire_owned() else {
            push.finish("busy with other log streams; try again shortly")
                .await;
            return;
        };
        let labels = std::collections::BTreeMap::from([
            (LABEL_MANAGED.to_string(), "true".to_string()),
            (LABEL_REPLICA.to_string(), req.replica_id.clone()),
        ]);
        let cs = match self.rt.list(&labels).await {
            Ok(cs) if !cs.is_empty() => cs,
            _ => {
                push.finish(&format!(
                    "replica {} has no container on this node",
                    req.replica_id
                ))
                .await;
                return;
            }
        };
        let id = match container_for(&cs, &req.container) {
            Ok(id) => id,
            Err(e) => {
                push.finish(&format!("replica {}: {e}", req.replica_id))
                    .await;
                return;
            }
        };
        let grep = req.grep.to_lowercase();
        let opts = LogOptions {
            follow: req.follow,
            tail: i64::from(req.tail),
            grep: grep.clone(),
        };
        let mut frames = match self.rt.logs(&id, &opts).await {
            Ok(f) => f,
            Err(e) => {
                push.finish(&e.to_string()).await;
                return;
            }
        };
        loop {
            let f = match frames.recv().await {
                None => {
                    push.finish("").await;
                    return;
                }
                Some(Err(e)) => {
                    push.finish(&e.to_string()).await;
                    return;
                }
                Some(Ok(f)) => f,
            };
            if !contains_fold(&f.data, grep.as_bytes()) {
                continue; // a runtime that does not filter
            }
            let lp = pb::LogPush {
                stream: stream_of(f.stderr),
                data: f.data,
                time: f.time.map(ts),
                ..Default::default()
            };
            if !push.send(lp).await {
                return;
            }
        }
    }

    /// Answers a search of the node's log history.
    async fn serve_search(&self, req: &pb::LogRequest, q: &pb::LogQuery, push: &Push) {
        let Ok(_permit) = self.side.searches.clone().try_acquire_owned() else {
            push.finish("busy with other log searches; try again shortly")
                .await;
            return;
        };
        if !self.rt.has_log_history() {
            push.finish("this node keeps no log history").await;
            return;
        }
        let _ = req;
        let query = LogQuery {
            app: q.app.clone(),
            replica: q.replica.clone(),
            container: q.container.clone(),
            since: from_ts(q.since.as_ref()),
            until: q.until.as_ref().map(|t| from_ts(Some(t))),
            grep: q.grep.clone(),
            limit: i64::from(q.limit).clamp(1, MAX_SEARCH_LIMIT),
            max_bytes: MAX_SEARCH_BYTES,
        };
        let res = match tokio::time::timeout(SEARCH_TIMEOUT, self.rt.search_logs(&query)).await {
            Ok(r) => r,
            Err(_) => Err(crate::runtime::Error::other("context deadline exceeded")),
        };
        let (recs, notice) = match res {
            Ok(r) => r,
            Err(e) => {
                push.finish(&e.to_string()).await;
                return;
            }
        };
        for r in recs {
            let lp = pb::LogPush {
                stream: stream_of(r.stderr),
                data: r.data,
                time: Some(ts(r.time)),
                replica: r.replica,
                ..Default::default()
            };
            if !push.send(lp).await {
                return;
            }
        }
        push.finish(&notice).await;
    }

    /// Ends the log request id (LogCancel).
    pub(crate) fn cancel_logs(&self, id: &str) {
        if let Some(c) = lock(&self.side.cancels).get(id) {
            let _ = c.send(true);
        }
    }

    /// Keeps the latest Assignment.logs.
    pub(crate) fn set_log_settings(&self, s: Option<&pb::LogSettings>) {
        *lock(&self.side.logs) = Some(s.cloned().unwrap_or_default());
    }

    /// Bounds the node's log history with the cluster's settings; nothing
    /// before the first assignment.
    pub(crate) async fn prune_logs(&self) {
        if !self.rt.prunes_logs() {
            return;
        }
        let Some(s) = lock(&self.side.logs).clone() else {
            return;
        };
        let retention = Duration::from_secs(s.retention_seconds.max(0) as u64);
        if let Err(e) = self.rt.prune_logs(retention, s.max_bytes).await {
            self.log
                .warn("log history: prune", &[("err", e.to_string())]);
        }
    }
}

/// The PushLogs stream of one request.
struct Push {
    tx: mpsc::Sender<pb::LogPush>,
    rid: String,
}

impl Push {
    async fn send(&self, mut m: pb::LogPush) -> bool {
        m.request_id = self.rid.clone();
        self.tx.send(m).await.is_ok()
    }

    /// Closes the stream with an optional notice.
    async fn finish(&self, msg: &str) {
        if !msg.is_empty() {
            self.send(pb::LogPush {
                error: msg.to_string(),
                ..Default::default()
            })
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold() {
        assert!(contains_fold(b"Hello World", b"world"));
        assert!(contains_fold(b"x", b""));
        assert!(!contains_fold(b"wor", b"world"));
        assert!(contains_fold("ÄBC".as_bytes(), "äb".as_bytes()));
        assert!(!contains_fold(b"abc", "ä".as_bytes()));
    }
}

//! Volume backups to an S3-compatible bucket (ADR 0041) as the Go agent
//! makes and reads them (internal/volbackup, internal/agent/backup.go;
//! ADR 0054 step 5, third part): deduplicated, encrypted snapshots in a
//! repository per volume, in Go's format, so either side reads what the
//! other wrote. The agent keeps the volume session, the per-volume lock,
//! and the pause and resume of the app; it runs these with the request on
//! stdin (the bucket's URL and the key never reach the command line, and
//! no answer or log line holds them):
//!
//!   armada-node volume snapshot [--extra-ca FILE]
//!       stdin {"url", "key" (base64), "app", "volume", "dir", "node",
//!       "now" (Unix nanoseconds)}: Backup; stdout
//!       {"snapshot": {"id", "time", "files", "bytes", "node"},
//!       "newBytes", "uploaded"} or {"error", "changed"}
//!   armada-node volume prune [--extra-ca FILE]
//!       stdin {"url", "key", "app", "volume", "keep", "zone", "now"}:
//!       Prune, keep counted in the zone the agent gives as offsets from
//!       UTC and the times they start; stdout {"snapshots", "stored",
//!       "deletedSnapshots", "deletedChunks"[, "error"]}
//!   armada-node volume snapshots [--extra-ca FILE]
//!       stdin {"url", "key", "app", "volume"}: Snapshots; stdout
//!       {"snapshots": [{"id", "time"}]} or {"error"}
//!   armada-node volume restore-snapshot [--extra-ca FILE]
//!       stdin {"url", "key", "app", "volume", "dir", "snapshot"} and a
//!       newline, then, once stdout says "ready ID" (latest resolved),
//!       "go" and a newline when the agent paused the app (stdin ending
//!       instead stops the call before anything changed); stdout then
//!       {"snapshot": {...}} or {"error"}
//!   armada-node volume target
//!       stdin {"url"}: ParseTarget's checks; stdout {"endpoint",
//!       "secure", "bucket", "prefix", "region"} or {"error"}
//!
//! Before its first write to the bucket or the volume, a call prints
//! "touched" on a line of its own: a call that fails without an answer
//! before that line changed nothing, so the agent does it with Go's code.
//! --extra-ca and ARMADA_NODE_TEST_BUCKET_ADDR (s3.rs) are for tests.

mod chunker;
mod gotime;
mod keys;
mod repo;
mod s3;
mod target;

use gotime::{Instant, Keep};
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};

static TOUCHED: AtomicBool = AtomicBool::new(false);
static STOPPED: AtomicBool = AtomicBool::new(false);

/// Whether the agent gave up on a restore (closed stdin).
pub(crate) fn stopped() -> bool {
    STOPPED.load(Ordering::SeqCst)
}

/// Says once, before the first write to the bucket or the volume, that
/// the call changed something.
pub(crate) fn touch() {
    if !TOUCHED.swap(true, Ordering::SeqCst) {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(b"touched\n");
        let _ = out.flush();
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct Request {
    url: String,
    key: String,
    app: String,
    volume: String,
    dir: String,
    node: String,
    now: i64,
    keep: Keep,
    zone: Vec<(i64, i64)>,
    snapshot: String,
}

fn answer(v: serde_json::Value) -> Result<(), String> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{v}")
        .and_then(|()| out.flush())
        .map_err(|e| format!("answer: {e}"))
}

fn error(e: &str) -> Result<(), String> {
    answer(serde_json::json!({ "error": e }))
}

/// encoding/base64's StdEncoding, as encoding/json writes []byte.
fn unbase64(s: &str) -> Option<Vec<u8>> {
    let v = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let b = s.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for (i, q) in b.chunks(4).enumerate() {
        let last = i == b.len() / 4 - 1;
        let pad = q.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for c in &q[..4 - pad] {
            n = n << 6 | v(*c)?;
        }
        n <<= 6 * pad as u32;
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - pad]);
    }
    Some(out)
}

pub fn command(op: &str, args: &[&str]) -> Result<(), String> {
    let extra_ca = match args {
        [] => None,
        ["--extra-ca", f] => Some(*f),
        _ => return Err(format!("unknown arguments {args:?}; try: --extra-ca FILE")),
    };
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut line = String::new();
    input
        .read_line(&mut line)
        .map_err(|e| format!("read the request: {e}"))?;
    let req: Request = serde_json::from_str(&line).map_err(|e| format!("read the request: {e}"))?;
    drop(line);
    if op == "target" {
        return match target::parse(&req.url) {
            Ok(t) => answer(serde_json::json!({
                "endpoint": t.endpoint, "secure": t.secure, "bucket": t.bucket,
                "prefix": t.prefix, "region": t.region,
            })),
            Err(e) => error(&e),
        };
    }
    let secret = unbase64(&req.key).ok_or("read the request: the key is not base64")?;
    if op == "snapshot" || op == "restore-snapshot" {
        // A kernel without openat2 leaves the call to Go before anything
        // is written.
        if let Ok(root) = crate::volume::walk::Root::open(req.dir.as_bytes()) {
            root.probe()?;
        }
    }
    let t = match target::parse(&req.url) {
        Ok(t) => t,
        Err(e) => return error(&e),
    };
    let bucket = s3::Bucket::new(t.clone(), extra_ca)?;
    let root = repo::root(&t.prefix, &req.app, &req.volume);
    let mut repo = match repo::Repo::open(&bucket, &root, &secret) {
        Ok(r) => r,
        Err(e) => return error(&e),
    };
    match op {
        "snapshot" => {
            let now = Instant::from_nanos(i128::from(req.now));
            match repo.backup(req.dir.as_bytes(), &req.node, now) {
                Ok((s, st)) => answer(serde_json::json!({
                    "snapshot": snapshot_json(&s),
                    "newBytes": st.new_bytes,
                    "uploaded": st.uploaded,
                })),
                Err(f) => answer(serde_json::json!({ "error": f.text, "changed": f.changed })),
            }
        }
        "prune" => {
            let now = Instant::from_nanos(i128::from(req.now));
            let zone = if req.zone.is_empty() {
                vec![(i64::MIN, 0)]
            } else {
                req.zone
            };
            let (u, err) = repo.prune(&req.keep, &zone, now);
            let mut v = serde_json::json!({
                "snapshots": u.snapshots, "stored": u.stored,
                "deletedSnapshots": u.deleted_snapshots, "deletedChunks": u.deleted_chunks,
            });
            if let Some(e) = err {
                v["error"] = serde_json::Value::String(e);
            }
            answer(v)
        }
        "snapshots" => match repo.snapshots() {
            Ok(s) => answer(serde_json::json!({
                "snapshots": s.iter().map(|(id, t)| serde_json::json!({
                    "id": id, "time": t.rfc3339_nano(),
                })).collect::<Vec<_>>(),
            })),
            Err(e) => error(&e),
        },
        "restore-snapshot" => {
            let mut id = req.snapshot.clone();
            if id == "latest" {
                id = match repo.latest() {
                    Ok(id) => id,
                    Err(e) => return error(&e),
                };
            }
            {
                let mut out = std::io::stdout().lock();
                writeln!(out, "ready {id}")
                    .and_then(|()| out.flush())
                    .map_err(|e| format!("answer: {e}"))?;
            }
            let mut go = String::new();
            input
                .read_line(&mut go)
                .map_err(|e| format!("read the request: {e}"))?;
            if go != "go\n" {
                return Ok(()); // the agent stopped the call
            }
            // The agent closes stdin when its caller gives up: the restore
            // stops before the next entry, as Go's does on its context.
            drop(input);
            std::thread::spawn(|| {
                let _ = std::io::copy(&mut std::io::stdin(), &mut std::io::sink());
                STOPPED.store(true, Ordering::SeqCst);
            });
            touch();
            match repo::restore_into(&mut repo, req.dir.as_bytes(), &id) {
                Ok(s) => answer(serde_json::json!({ "snapshot": snapshot_json(&s) })),
                Err(e) => error(&e),
            }
        }
        _ => Err(format!("unknown volume command {op}")),
    }
}

fn snapshot_json(s: &repo::Snapshot) -> serde_json::Value {
    serde_json::json!({
        "id": s.id, "time": s.time.rfc3339_nano(), "files": s.files,
        "bytes": s.bytes, "node": s.node,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_base64_as_go_writes_it() {
        assert_eq!(unbase64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(unbase64("aGVsbG8h").unwrap(), b"hello!");
        assert_eq!(unbase64("aGVsbA==").unwrap(), b"hell");
        assert_eq!(unbase64("").unwrap(), b"");
        assert!(unbase64("aGVsbG8").is_none());
        assert!(unbase64("a=Vs").is_none());
    }
}

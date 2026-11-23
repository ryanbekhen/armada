//! The supervisor runtime's container lifecycle (ADR 0054 step 4, fourth
//! part): what internal/runtime/supervisor does below the driver for a
//! container, on the image store of ../image. The Go driver still builds
//! each container's spec and runs its network, logs, and exec; it hands
//! the rest to these commands when agent.json says "runtimeAgent": "rust".
//!
//!   armada-node runtime prepare ROOT
//!       stdin: {"key", "image"}; stdout: {"mounts": [mount.Mount]}, the
//!       container's root filesystem on the image's layers (the one key
//!       has when it exists), or {"error"} (image/snapshot.rs)
//!   armada-node runtime release ROOT KEY
//!       stdout: {} or {"error"}; the root filesystem removed
//!   armada-node runtime snapshots ROOT
//!       stdout: {"keys": [KEY]}, every container's root filesystem
//!   armada-node runtime bundle create
//!       stdin: {"dir", "id", "image", "labels", "spec", "mounts"};
//!       stdout: {"record": Record} or {"error"} (bundle.rs)
//!   armada-node runtime bundle remove DIR ID
//!   armada-node runtime bundle records DIR
//!       stdout: {"records": [Record]}
//!   armada-node runtime bundle labels DIR ID
//!       stdin: {"labels"}; stdout: {"record": Record}
//!   armada-node runtime shim call|start|abandon
//!       stdin: {"dir", "bin", "runc", "logger", "group", "words",
//!       "timeoutMs", "systemdRun", "systemctl"}; call: stdout {"answer"},
//!       {"shim": TEXT} (the shim's own error), or {"error", "errno"};
//!       start: {} or {"error"}; abandon: {"gone"} or {"error"}
//!       (shim.rs)
//!
//! Go's TestArmadaNode*MatchesGo tests (internal/runtime/supervisor)
//! compare them with Go's Bundles, Shims, and the overlay snapshotter.

pub mod bundle;
pub mod mount;
pub mod shim;

use super::{read_stdin, spec::to_go_json, write_out};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

pub use super::user::errno_text;

fn error_out(e: &str) -> Result<(), String> {
    write_out(&to_go_json(&serde_json::json!({ "error": e })))
}

fn json_out(v: &serde_json::Value) -> Result<(), String> {
    write_out(&to_go_json(v))
}

#[derive(Deserialize)]
struct PrepareRequest {
    key: String,
    image: String,
}

/// armada-node runtime prepare ROOT.
pub fn prepare_command(root: &str) -> Result<(), String> {
    let r: PrepareRequest =
        serde_json::from_slice(&read_stdin()?).map_err(|e| format!("read request: {e}"))?;
    let store = super::image::open_store(Path::new(root))?;
    match super::image::prepare(&store, &r.key, &r.image) {
        Ok(m) => json_out(&serde_json::json!({ "mounts": m })),
        Err(e) => error_out(&e),
    }
}

/// armada-node runtime release ROOT KEY.
pub fn release_command(root: &str, key: &str) -> Result<(), String> {
    let store = super::image::open_store(Path::new(root))?;
    match super::image::release(&store, key) {
        Ok(()) => write_out(b"{}"),
        Err(e) => error_out(&e),
    }
}

/// armada-node runtime snapshots ROOT.
pub fn snapshots_command(root: &str) -> Result<(), String> {
    let store = super::image::open_store(Path::new(root))?;
    json_out(&serde_json::json!({ "keys": super::image::snapshot_keys(&store) }))
}

#[derive(Deserialize)]
struct LabelsRequest {
    #[serde(default, deserialize_with = "crate::runtime::nullable")]
    labels: BTreeMap<String, String>,
}

/// armada-node runtime bundle OP [DIR [ID]].
pub fn bundle_command(args: &[&str]) -> Result<(), String> {
    match args {
        ["create"] => {
            let r: bundle::CreateRequest =
                serde_json::from_slice(&read_stdin()?).map_err(|e| format!("read request: {e}"))?;
            match bundle::create(&r) {
                Ok(rec) => json_out(&serde_json::json!({ "record": rec })),
                Err(e) => error_out(&e),
            }
        }
        ["remove", dir, id] => match bundle::remove(dir, id) {
            Ok(()) => write_out(b"{}"),
            Err(e) => error_out(&e),
        },
        ["records", dir] => match bundle::records(dir) {
            Ok(r) => json_out(&serde_json::json!({ "records": r })),
            Err(e) => error_out(&e),
        },
        ["labels", dir, id] => {
            let r: LabelsRequest =
                serde_json::from_slice(&read_stdin()?).map_err(|e| format!("read request: {e}"))?;
            match bundle::set_labels(dir, id, &r.labels) {
                Ok(rec) => json_out(&serde_json::json!({ "record": rec })),
                Err(e) => error_out(&e),
            }
        }
        _ => {
            Err("usage: runtime bundle create | remove DIR ID | records DIR | labels DIR ID".into())
        }
    }
}

/// armada-node runtime shim call|start|abandon.
pub fn shim_command(op: &str) -> Result<(), String> {
    let mut r: shim::Request =
        serde_json::from_slice(&read_stdin()?).map_err(|e| format!("read request: {e}"))?;
    let t = (r.timeout_ms > 0).then(|| std::time::Duration::from_millis(r.timeout_ms));
    r.deadline = t.map(|t| std::time::Instant::now() + t);
    match op {
        "call" => match shim::call(&r.socket(), &r.words, t) {
            Ok(a) => json_out(&serde_json::json!({ "answer": a })),
            Err(shim::CallError::Shim(t)) => json_out(&serde_json::json!({ "shim": t })),
            Err(shim::CallError::Conn(t, errno)) => {
                json_out(&serde_json::json!({ "error": t, "errno": errno.unwrap_or(0) }))
            }
        },
        "start" => match r.start() {
            Ok(()) => write_out(b"{}"),
            Err(e) => error_out(&e),
        },
        // Abandon may fail after it found the shim gone: both are said.
        "abandon" => match r.abandon() {
            (g, None) => json_out(&serde_json::json!({ "gone": g })),
            (g, Some(e)) => json_out(&serde_json::json!({ "gone": g, "error": e })),
        },
        _ => Err("usage: runtime shim call|start|abandon".into()),
    }
}

//! Image pulls and the image store (ADR 0054 step 4, second part; not used
//! by nodes yet): what internal/runtime/containerd (registry.go, proof.go,
//! platforms.go, Driver.Pull) and internal/runtime/supervisor/images.go do
//! for a pull, into the store of store.rs. Layers are checked, not
//! unpacked: snapshots come with the third part.
//!
//!   armada-node runtime pull ROOT [--extra-ca FILE]
//!       stdin: {"image": REF, "auth": {"Username", "Password",
//!       "ServerAddress"} | null}; stdout: {"ref", "platforms"} as
//!       runtime.Image, or {"error": TEXT[, "platform": {"image", "want",
//!       "have"}]} (runtime.PlatformError). --extra-ca trusts a PEM file's
//!       certificates besides the machine's roots: for tests only, nodes
//!       never pass it.
//!   armada-node runtime images ROOT
//!       stdout: the store's image records, sorted by name
//!   armada-node runtime prune ROOT
//!       stdin: {"keep": [REF], "inUse": [NAME], "graceSeconds": N};
//!       stdout: {"removed": [NAME]} (PruneImages)
//!   armada-node runtime reference
//!       stdin: [{"image", "auth"}]; stdout: per entry {"ref", "familiar",
//!       "digested", "pullKey"} or {"error"} (normalize, pullKey)
//!   armada-node runtime platforms
//!       stdin: [Platform]; stdout: platformStrings of them, and whether
//!       this node runs each and in which order it prefers them
//!   armada-node runtime proxy URL
//!       stdout: {"proxy": URL or ""}, the proxy a request to URL takes
//!       under this environment
//!
//! Go's TestArmadaNode*MatchesGo tests (internal/runtime/containerd)
//! compare them with Go against registries in the test process.

mod check;
mod digest;
mod http;
mod platform;
mod pull;
mod reference;
mod registry;
mod store;

use super::{read_stdin, write_out};
use serde::{Deserialize, Serialize};
use std::path::Path;

fn error_json(e: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "error": e })).unwrap_or_default()
}

/// armada-node runtime pull ROOT [--extra-ca FILE].
pub fn pull_command(args: &[&str]) -> Result<(), String> {
    let (root, extra_ca) = match args {
        [root] => (*root, None),
        [root, "--extra-ca", f] => (*root, Some(*f)),
        _ => return Err("usage: runtime pull ROOT [--extra-ca FILE]".into()),
    };
    let req: pull::PullRequest =
        serde_json::from_slice(&read_stdin()?).map_err(|e| format!("read request: {e}"))?;
    let client = http::Client::new(extra_ca, http::Proxy::from_env())?;
    let store = store::Store::open(Path::new(root))?;
    let out = match pull::pull(&store, &client, &req) {
        Ok(p) => serde_json::to_vec(&p).map_err(|e| e.to_string())?,
        Err(e) => {
            let msg = e.to_string();
            match e {
                pull::PullError::Platform(p) => {
                    serde_json::to_vec(&serde_json::json!({ "error": msg, "platform": p }))
                        .map_err(|e| e.to_string())?
                }
                pull::PullError::Other(_) => error_json(&msg),
            }
        }
    };
    write_out(&out)
}

/// armada-node runtime images ROOT.
pub fn images_command(root: &str) -> Result<(), String> {
    let store = store::Store::open(Path::new(root))?;
    let idx = store.index()?;
    let recs: Vec<&store::ImageRecord> = idx.images.values().collect();
    write_out(&serde_json::to_vec(&recs).map_err(|e| e.to_string())?)
}

/// armada-node runtime prune ROOT.
pub fn prune_command(root: &str) -> Result<(), String> {
    let req: pull::PruneRequest =
        serde_json::from_slice(&read_stdin()?).map_err(|e| format!("read request: {e}"))?;
    let store = store::Store::open(Path::new(root))?;
    match pull::prune(&store, &req) {
        Ok(removed) => write_out(
            &serde_json::to_vec(&serde_json::json!({ "removed": removed }))
                .map_err(|e| e.to_string())?,
        ),
        Err(e) => write_out(&error_json(&e)),
    }
}

#[derive(Deserialize)]
struct RefRequest {
    image: String,
    #[serde(default)]
    auth: Option<reference::RegistryAuth>,
}

#[derive(Serialize)]
struct RefAnswer {
    #[serde(rename = "ref", skip_serializing_if = "String::is_empty")]
    reference: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    familiar: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    digested: bool,
    #[serde(rename = "pullKey", skip_serializing_if = "String::is_empty")]
    pull_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

/// armada-node runtime reference.
pub fn reference_command() -> Result<(), String> {
    let reqs: Vec<RefRequest> =
        serde_json::from_slice(&read_stdin()?).map_err(|e| format!("read request: {e}"))?;
    let out: Vec<RefAnswer> = reqs
        .iter()
        .map(|r| match reference::parse_docker_ref(&r.image) {
            Ok(n) => RefAnswer {
                reference: n.to_string(),
                familiar: n.familiar_name(),
                digested: n.digest.is_some(),
                pull_key: reference::pull_key(&n, r.auth.as_ref()),
                error: String::new(),
            },
            Err(e) => RefAnswer {
                reference: String::new(),
                familiar: String::new(),
                digested: false,
                pull_key: String::new(),
                error: e,
            },
        })
        .collect();
    write_out(&serde_json::to_vec(&out).map_err(|e| e.to_string())?)
}

/// armada-node runtime platforms.
pub fn platforms_command() -> Result<(), String> {
    let ps: Vec<platform::Platform> =
        serde_json::from_slice(&read_stdin()?).map_err(|e| format!("read request: {e}"))?;
    let m = platform::Matcher::default_for_node();
    let matches: Vec<bool> = ps.iter().map(|p| m.matches(p)).collect();
    // The order a stable sort by the node's preference gives (indexes).
    let mut order: Vec<usize> = (0..ps.len()).collect();
    for i in 1..order.len() {
        let mut j = i;
        while j > 0 && m.less(&ps[order[j]], &ps[order[j - 1]]) {
            order.swap(j, j - 1);
            j -= 1;
        }
    }
    write_out(
        &serde_json::to_vec(&serde_json::json!({
            "strings": platform::platform_strings(&ps),
            "matches": matches,
            "order": order,
            "node": platform::node_platform(),
        }))
        .map_err(|e| e.to_string())?,
    )
}

/// armada-node runtime proxy URL.
pub fn proxy_command(url: &str) -> Result<(), String> {
    let u = http::Url::parse(url)?;
    let p = http::Proxy::from_env()
        .for_url(&u)
        .map(|p| p.to_string())
        .unwrap_or_default();
    write_out(&serde_json::to_vec(&serde_json::json!({ "proxy": p })).map_err(|e| e.to_string())?)
}

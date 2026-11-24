//! Image pulls and the image store (ADR 0054 step 4, second and third
//! parts; not used by nodes yet): what internal/runtime/containerd
//! (registry.go, proof.go, platforms.go, Driver.Pull) and
//! internal/runtime/supervisor/images.go do for a pull, into the store of
//! store.rs, with every layer unpacked under layers/ as containerd's
//! applier unpacks it for the overlay snapshotter (layers.rs, unpack.rs,
//! tar.rs).
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
//!       Unpacked layers no kept image needs are removed with the blobs.
//!   armada-node runtime mounts ROOT IMAGE
//!       stdout: {"lowerdirs": [DIR]}, the image's unpacked layers as
//!       overlay's lowerdir option names them (top first), or {"error"}
//!   armada-node runtime apply DIR [--media-type MT] [--lower DIR]...
//!       stdin: a layer blob; applies it to DIR as the applier does (with
//!       lower directories: as an overlay upper directory, closest
//!       first); stdout: {"diffID"} or {"error"}. For the parity tests.
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
pub(crate) mod http;
mod layers;
mod platform;
mod pull;
mod reference;
mod registry;
mod snapshot;
mod store;
pub(crate) mod tar;
pub(crate) mod unpack;

use super::{read_stdin, write_out};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub use store::now_rfc3339;

/// The store under root, for the container commands (../container).
pub fn open_store(root: &Path) -> Result<store::Store, String> {
    store::Store::open(root)
}

pub use snapshot::{keys as snapshot_keys, prepare, release};

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

/// armada-node runtime mounts ROOT IMAGE.
pub fn mounts_command(root: &str, image: &str) -> Result<(), String> {
    let store = store::Store::open(Path::new(root))?;
    let out = (|| {
        let idx = store.index()?;
        let rec = idx
            .images
            .get(image)
            .or_else(|| {
                reference::parse_docker_ref(image)
                    .ok()
                    .and_then(|r| idx.images.get(&r.to_string()))
            })
            .ok_or_else(|| format!("image {image}: not found"))?;
        let dirs = layers::lower_dirs(&store, &rec.diff_ids);
        if let Some(d) = dirs.iter().find(|d| !d.is_dir()) {
            return Err(format!(
                "image {image}: layer {} is not unpacked",
                d.display()
            ));
        }
        let dirs: Vec<String> = dirs.iter().map(|d| d.display().to_string()).collect();
        Ok(serde_json::json!({ "lowerdirs": dirs }))
    })();
    match out {
        Ok(v) => write_out(&serde_json::to_vec(&v).map_err(|e| e.to_string())?),
        Err(e) => write_out(&error_json(&e)),
    }
}

/// armada-node runtime apply DIR [--media-type MT] [--lower DIR]...
pub fn apply_command(args: &[&str]) -> Result<(), String> {
    let usage = "usage: runtime apply DIR [--media-type MT] [--lower DIR]...";
    let (dir, mut rest) = args.split_first().ok_or(usage)?;
    let mut media_type = "application/vnd.oci.image.layer.v1.tar+gzip".to_string();
    let mut lowers: Vec<Vec<u8>> = Vec::new();
    while let [flag, value, more @ ..] = rest {
        match *flag {
            "--media-type" => media_type = value.to_string(),
            "--lower" => lowers.push(value.as_bytes().to_vec()),
            _ => return Err(usage.into()),
        }
        rest = more;
    }
    if !rest.is_empty() {
        return Err(usage.into());
    }
    let out = (|| {
        let r = check::layer_reader(std::io::stdin().lock(), &media_type)?;
        let mut h = digest::Algorithm::Sha256.hasher();
        let mut tee = HashRead { r, h: &mut h };
        unpack::apply(dir.as_bytes(), &mut tee, &lowers)?;
        std::io::copy(&mut tee, &mut std::io::sink()).map_err(|e| e.to_string())?;
        Ok::<_, String>(h.finish())
    })();
    match out {
        Ok(d) => write_out(
            &serde_json::to_vec(&serde_json::json!({ "diffID": d.to_string() }))
                .map_err(|e| e.to_string())?,
        ),
        Err(e) => write_out(&error_json(&e)),
    }
}

struct HashRead<'a, R> {
    r: R,
    h: &'a mut digest::Hasher,
}

impl<R: std::io::Read> std::io::Read for HashRead<'_, R> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.r.read(b)?;
        self.h.update(&b[..n]);
        Ok(n)
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

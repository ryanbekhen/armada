//! A pull as the Go driver does it (Driver.Pull with the supervisor
//! backend's Images.Pull): normalize the reference, reuse a digest-pinned
//! image on the node only under the same credentials, prove content this
//! pull did not download (proveContent), fetch the node's platform with
//! two fetches at a time, check every layer against its diff ID, record
//! the image with who pulled it, and tell an image built for other
//! platforms from other failures (PlatformError).

use super::check;
use super::digest::{Digest, chain_ids};
use super::platform::{Matcher, Platform, node_platform, normalize, platform_strings};
use super::reference::{PULL_ANYONE, PULL_LABEL, RegistryAuth, parse_docker_ref, pull_key};
use super::registry::{self, Descriptor, MEDIA_DOCKER_SCHEMA1, Registry, is_index, is_manifest};
use super::store::{ImageRecord, Index, Store, now_rfc3339};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::io::Read;
use std::sync::{Condvar, Mutex, OnceLock};

/// pullParallel: blobs one pull fetches at once.
pub const PULL_PARALLEL: usize = 2;
/// maxManifest: the largest manifest or config read to find platforms.
const MAX_MANIFEST: u64 = 4 << 20;

const MEDIA_DOCKER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";
const MEDIA_OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";

/// The parts of a manifest or an index a pull reads (images.Children and
/// validateMediaType).
#[derive(Deserialize, Default)]
pub struct Document {
    #[serde(default)]
    pub config: Option<Descriptor>,
    #[serde(default, deserialize_with = "crate::runtime::nullable")]
    pub layers: Vec<Descriptor>,
    #[serde(default, deserialize_with = "crate::runtime::nullable")]
    pub manifests: Vec<Descriptor>,
}

/// validateMediaType: a document must be what its descriptor says.
fn validate_media_type(b: &[u8], mt: &str) -> Result<Document, String> {
    let raw: serde_json::Value = serde_json::from_slice(b).map_err(|e| e.to_string())?;
    // Go reads these fields as json.RawMessage: present at all (even null
    // or empty) counts.
    let present = |k: &str| raw.get(k).is_some();
    if present("fsLayers") {
        return Err("media-type: schema 1 not supported".into());
    }
    let doc_mt = raw.get("mediaType").and_then(|v| v.as_str()).unwrap_or("");
    if is_manifest(mt) && (present("manifests") || is_index(doc_mt)) {
        return Err(format!(
            "media-type: expected manifest but found index ({mt})"
        ));
    }
    if is_index(mt) && (present("config") || present("layers") || is_manifest(doc_mt)) {
        return Err(format!(
            "media-type: expected index but found manifest ({mt})"
        ));
    }
    serde_json::from_slice(b).map_err(|e| e.to_string())
}

/// The fields of an image config a pull reads.
#[derive(Deserialize, Default)]
struct Config {
    #[serde(flatten)]
    platform: Platform,
    #[serde(default)]
    rootfs: RootFs,
}

#[derive(Deserialize, Default)]
struct RootFs {
    #[serde(default, deserialize_with = "crate::runtime::nullable")]
    diff_ids: Vec<Digest>,
}

#[derive(Deserialize)]
pub struct PullRequest {
    pub image: String,
    #[serde(default)]
    pub auth: Option<RegistryAuth>,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct Pulled {
    #[serde(rename = "ref")]
    pub reference: String,
    pub platforms: Vec<String>,
}

#[derive(Serialize, Debug)]
pub struct PlatformError {
    pub image: String,
    pub want: String,
    pub have: Vec<String>,
}

#[derive(Debug)]
pub enum PullError {
    Platform(PlatformError),
    Other(String),
}

impl std::fmt::Display for PullError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PullError::Platform(p) => write!(
                f,
                "image {} has no {} variant (it has {})",
                p.image,
                p.want,
                p.have.join(", ")
            ),
            PullError::Other(s) => f.write_str(s),
        }
    }
}

fn denied_message(msg: &str) -> bool {
    [
        "403 Forbidden",
        "401 Unauthorized",
        "insufficient_scope",
        "pull access denied",
        "authorization failed",
    ]
    .iter()
    .any(|s| msg.contains(s))
}

/// refused: the registry said no, as opposed to not answering.
fn refused(e: &registry::Error) -> bool {
    e.not_found || e.msg.contains("not found") || denied_message(&e.msg)
}

/// pullError: what a failed pull most likely means, before the
/// registry's own words.
fn pull_error(image: &str, with_auth: bool, not_found: bool, msg: &str) -> PullError {
    let denied = denied_message(msg);
    PullError::Other(if not_found || msg.contains("not found") {
        format!("pull {image}: no such image or tag in the registry: {msg}")
    } else if denied && with_auth {
        format!(
            "pull {image}: the registry refused the app's credentials, or the image does not exist: {msg}"
        )
    } else if denied {
        format!(
            "pull {image}: the image does not exist, or it is private and the app has no registry credentials (spec registry, --registry-user/--registry-secret): {msg}"
        )
    } else {
        format!("pull {image}: {msg}")
    })
}

/// pulledWith: anyone may use an image that needed no credentials.
pub fn pulled_with(labels: &BTreeMap<String, String>, key: &str) -> bool {
    labels
        .get(&format!("{PULL_LABEL}{PULL_ANYONE}"))
        .is_some_and(|v| !v.is_empty())
        || labels
            .get(&format!("{PULL_LABEL}{key}"))
            .is_some_and(|v| !v.is_empty())
}

fn unrecorded(labels: &BTreeMap<String, String>) -> bool {
    !labels.keys().any(|k| k.starts_with(PULL_LABEL))
}

fn mark_pulled(store: &Store, name: &str, key: &str) -> Result<(), PullError> {
    store
        .update(|idx| {
            let r = idx
                .images
                .get_mut(name)
                .ok_or_else(|| format!("image {name}: not found"))?;
            r.labels.insert(format!("{PULL_LABEL}{key}"), "1".into());
            r.updated = now_rfc3339();
            Ok(())
        })
        .map_err(|e| PullError::Other(format!("image {name}: record the pull: {e}")))
}

/// The platforms a record names, as Platform values for platformStrings.
fn record_platforms(r: &ImageRecord) -> Vec<String> {
    let ps: Vec<Platform> = r
        .platforms
        .iter()
        .map(|s| {
            let (os, arch) = s.split_once('/').unwrap_or((s, ""));
            Platform {
                os: os.into(),
                architecture: arch.into(),
                ..Default::default()
            }
        })
        .collect();
    platform_strings(&ps)
}

/// Driver.Pull.
pub fn pull(
    store: &Store,
    client: &super::http::Client,
    req: &PullRequest,
) -> Result<Pulled, PullError> {
    let r = parse_docker_ref(&req.image)
        .map_err(|e| PullError::Other(format!("invalid image reference {:?}: {e}", req.image)))?;
    let name = r.to_string();
    let familiar = r.familiar_name();
    let key = pull_key(&r, req.auth.as_ref());
    let reg = Registry::new(client, &r, req.auth.clone());
    let with_auth = req.auth.is_some();
    if r.digest.is_some() {
        let idx = store.index().map_err(PullError::Other)?;
        if let Some(img) = idx.images.get(&name) {
            if !pulled_with(&img.labels, &key) {
                match reg.resolve(&r) {
                    Ok(_) => mark_pulled(store, &name, &key)?,
                    Err(e) if unrecorded(&img.labels) && !refused(&e) => {
                        // Pulled by a release that kept no record: while
                        // the registry cannot be reached, it stays usable.
                    }
                    Err(e) => return Err(pull_error(&req.image, with_auth, e.not_found, &e.msg)),
                }
            }
            return Ok(Pulled {
                reference: req.image.clone(),
                platforms: record_platforms(img),
            });
        }
    }
    let result = {
        let _pulls = store.pulls_shared().map_err(PullError::Other)?;
        fetch_and_record(store, &reg, &r, &name, &key)
    };
    if let Err(e) = store.collect_idle() {
        eprintln!("armada-node: collect unused image blobs: {e}");
    }
    let rec = match result {
        Ok(rec) => rec,
        Err(e) => {
            // Tell an image built for other platforms from other failures.
            let want = node_platform();
            if let Ok(have) = remote_platforms(&reg, &r)
                && !have.is_empty()
                && !have.contains(&want)
            {
                return Err(PullError::Platform(PlatformError {
                    image: req.image.clone(),
                    want,
                    have,
                }));
            }
            return Err(pull_error(&req.image, with_auth, e.not_found, &e.msg));
        }
    };
    mark_pulled(store, &name, &key)?;
    Ok(Pulled {
        reference: format!("{familiar}@{}", rec.target.digest),
        platforms: record_platforms(&rec),
    })
}

/// Images.Pull: resolve, fetch, check, record.
fn fetch_and_record(
    store: &Store,
    reg: &Registry,
    r: &super::reference::Reference,
    name: &str,
    key: &str,
) -> Result<ImageRecord, registry::Error> {
    let desc = reg.resolve(r)?;
    let matcher = Matcher::default_for_node();
    let fetch = Fetch {
        store,
        reg,
        key,
        matcher: &matcher,
        fetched: Mutex::new(HashSet::new()),
        proven: OnceLock::new(),
    };
    fetch.dispatch(desc.clone()).map_err(|e| registry::Error {
        msg: format!("fetch: {}", e.msg),
        not_found: e.not_found,
    })?;
    record(store, name, &desc, &matcher).map_err(registry::Error::new)
}

struct Fetch<'a> {
    store: &'a Store,
    reg: &'a Registry<'a>,
    key: &'a str,
    matcher: &'a Matcher,
    /// Blobs this pull's fetcher downloaded (recordingResolver).
    fetched: Mutex<HashSet<Digest>>,
    proven: OnceLock<Result<HashSet<Digest>, String>>,
}

struct Queue {
    todo: VecDeque<Descriptor>,
    running: usize,
    err: Option<registry::Error>,
}

impl Fetch<'_> {
    /// images.Dispatch with at most PULL_PARALLEL handlers at once.
    fn dispatch(&self, root: Descriptor) -> Result<(), registry::Error> {
        let q = Mutex::new(Queue {
            todo: VecDeque::from([root]),
            running: 0,
            err: None,
        });
        let cv = Condvar::new();
        std::thread::scope(|s| {
            for _ in 0..PULL_PARALLEL {
                s.spawn(|| {
                    loop {
                        let desc = {
                            let mut g = q.lock().unwrap_or_else(|p| p.into_inner());
                            loop {
                                if g.err.is_some() || (g.todo.is_empty() && g.running == 0) {
                                    cv.notify_all();
                                    return;
                                }
                                if let Some(d) = g.todo.pop_front() {
                                    g.running += 1;
                                    break d;
                                }
                                g = cv.wait(g).unwrap_or_else(|p| p.into_inner());
                            }
                        };
                        let out = self.handle(&desc);
                        let mut g = q.lock().unwrap_or_else(|p| p.into_inner());
                        g.running -= 1;
                        match out {
                            Ok(children) => g.todo.extend(children),
                            Err(e) => {
                                g.err.get_or_insert(e);
                            }
                        }
                        cv.notify_all();
                    }
                });
            }
        });
        let g = q.into_inner().unwrap_or_else(|p| p.into_inner());
        match g.err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// The wrapped handler: fetch, find the children (for this node's
    /// platform), and prove what this pull did not download.
    fn handle(&self, desc: &Descriptor) -> Result<Vec<Descriptor>, registry::Error> {
        if desc.media_type == MEDIA_DOCKER_SCHEMA1 {
            return Err(registry::Error::new(format!(
                "{} not supported",
                desc.media_type
            )));
        }
        self.fetch(desc)?;
        let children = self.children(desc).map_err(registry::Error::new)?;
        let fetched = self
            .fetched
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(&desc.digest);
        if !fetched {
            let proven = self
                .proven
                .get_or_init(|| proven_content(self.store, self.key))
                .as_ref()
                .map_err(|e| registry::Error::new(e.clone()))?;
            if !proven.contains(&desc.digest) {
                fetch_verified(self.reg, desc).map_err(|e| {
                    registry::Error::new(format!(
                        "{} is on this node but its registry did not serve it to these credentials: {}",
                        desc.digest, e.msg
                    ))
                })?;
            }
        }
        Ok(children)
    }

    /// remotes.FetchHandler: a blob already here is not fetched again.
    fn fetch(&self, desc: &Descriptor) -> Result<(), registry::Error> {
        if desc.size == 0 {
            return Err(registry::Error::new(format!(
                "unable to fetch descriptor ({}) which reports content size of zero: invalid argument",
                desc.digest
            )));
        }
        if desc.size < 0 {
            return Err(registry::Error::new(format!(
                "unable to fetch descriptor ({}) which reports negative content size ({}): invalid argument",
                desc.digest, desc.size
            )));
        }
        if self.store.has(&desc.digest) {
            return Ok(());
        }
        if let Some(data) = &desc.data
            && data.len() as i64 == desc.size
        {
            return self
                .store
                .write(desc, &mut &data[..])
                .map_err(registry::Error::new);
        }
        let mut body = self.reg.fetch(desc)?;
        self.fetched
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(desc.digest.clone());
        self.store
            .write(desc, &mut body)
            .map_err(registry::Error::new)
    }

    /// ChildrenHandler with FilterPlatforms and LimitManifests(1).
    fn children(&self, desc: &Descriptor) -> Result<Vec<Descriptor>, String> {
        let manifest = is_manifest(&desc.media_type);
        let index = is_index(&desc.media_type);
        if !manifest && !index {
            return Ok(Vec::new());
        }
        let b = self.store.read_blob(desc, registry::MAX_MANIFEST_SIZE)?;
        let doc = validate_media_type(&b, &desc.media_type)
            .map_err(|e| format!("children: invalid desc {}: {e}", desc.digest))?;
        let mut children: Vec<Descriptor> = if manifest {
            doc.config.into_iter().chain(doc.layers).collect()
        } else {
            doc.manifests
        };
        children.retain(|d| d.platform.as_ref().is_none_or(|p| self.matcher.matches(p)));
        if index {
            sort_by_platform(&mut children, self.matcher);
            if children.is_empty() {
                return Err("no match for platform in manifest: not found".into());
            }
            children.truncate(1);
        }
        Ok(children)
    }
}

/// sort.SliceStable by the matcher's order, descriptors without a
/// platform last.
fn sort_by_platform(ds: &mut [Descriptor], m: &Matcher) {
    // A stable insertion sort with Go's less, which is not a total order
    // when platforms do not match: keep it exactly.
    for i in 1..ds.len() {
        let mut j = i;
        while j > 0 && less(&ds[j], &ds[j - 1], m) {
            ds.swap(j, j - 1);
            j -= 1;
        }
    }
}

fn less(a: &Descriptor, b: &Descriptor, m: &Matcher) -> bool {
    match (&a.platform, &b.platform) {
        (None, _) => false,
        (_, None) => true,
        (Some(x), Some(y)) => m.less(x, y),
    }
}

/// provenContent: every blob images pulled with key's credentials (or
/// with none) reference.
fn proven_content(store: &Store, key: &str) -> Result<HashSet<Digest>, String> {
    let idx = store.index()?;
    let mut proven = HashSet::new();
    for r in idx.images.values() {
        if !pulled_with(&r.labels, key) {
            continue;
        }
        let mut stack = vec![r.target.clone()];
        while let Some(d) = stack.pop() {
            if !proven.insert(d.digest.clone()) {
                continue;
            }
            if store.has(&d.digest) {
                stack.extend(store.stored_children(&d).unwrap_or_default());
            }
        }
    }
    Ok(proven)
}

/// fetchVerified: desc read from its registry must be exactly desc's
/// content; what is read is dropped.
fn fetch_verified(reg: &Registry, desc: &Descriptor) -> Result<(), registry::Error> {
    let body = reg.fetch(desc)?;
    let mut h = desc.digest.algorithm().hasher();
    let n = std::io::copy(&mut body.take(desc.size as u64 + 1), &mut h)
        .map_err(|e| registry::Error::new(e.to_string()))?;
    if n != desc.size as u64 || h.finish() != desc.digest {
        return Err(registry::Error::new("content does not match its digest"));
    }
    Ok(())
}

/// images.Manifest: the manifest of desc for this node's platform.
fn select_manifest(
    store: &Store,
    top: &Descriptor,
    m: &Matcher,
) -> Result<(Descriptor, Document), String> {
    let mut found: Vec<(Descriptor, Document)> = Vec::new();
    let mut was_index = false;
    let mut stack = vec![top.clone()];
    while let Some(desc) = stack.pop() {
        if is_manifest(&desc.media_type) {
            let b = store.read_blob(&desc, registry::MAX_MANIFEST_SIZE)?;
            let doc = validate_media_type(&b, &desc.media_type)
                .map_err(|e| format!("manifest: invalid desc {}: {e}", desc.digest))?;
            if desc.digest != top.digest {
                match &desc.platform {
                    Some(p) if !m.matches(p) => continue,
                    Some(_) => {}
                    None => {
                        let cfg = doc.config.as_ref().ok_or("manifest has no config")?;
                        let c: Config =
                            serde_json::from_slice(&store.read_blob(cfg, MAX_MANIFEST)?)
                                .map_err(|e| e.to_string())?;
                        if !m.matches(&normalize(&c.platform)) {
                            continue;
                        }
                    }
                }
            }
            found.push((desc, doc));
        } else if is_index(&desc.media_type) {
            let b = store.read_blob(&desc, registry::MAX_MANIFEST_SIZE)?;
            let doc = validate_media_type(&b, &desc.media_type)
                .map_err(|e| format!("manifest: invalid desc {}: {e}", desc.digest))?;
            let mut ds: Vec<Descriptor> = doc
                .manifests
                .into_iter()
                .filter(|d| d.platform.as_ref().is_none_or(|p| m.matches(p)))
                .collect();
            sort_by_platform(&mut ds, m);
            was_index = true;
            ds.truncate(1);
            // Walk visits children in order: push them reversed.
            stack.extend(ds.into_iter().rev());
        } else {
            return Err(format!(
                "unexpected media type {} for {}: not found",
                desc.media_type, desc.digest
            ));
        }
    }
    match found.into_iter().next() {
        Some(f) => Ok(f),
        None if was_index => Err(format!(
            "no match for platform in manifest {}: not found",
            top.digest
        )),
        None => Err(format!("manifest {}: not found", top.digest)),
    }
}

/// images.Platforms over what is in the store: the platforms an index
/// lists (attestations left out), or a config's.
fn image_platforms(store: &Store, top: &Descriptor) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut stack = vec![top.clone()];
    while let Some(d) = stack.pop() {
        if let Some(p) = &d.platform {
            if p.os != "unknown" && p.architecture != "unknown" {
                out.push(format!("{}/{}", p.os, p.architecture));
            }
            continue;
        }
        if d.media_type == MEDIA_DOCKER_CONFIG || d.media_type == MEDIA_OCI_CONFIG {
            let c: Config = serde_json::from_slice(&store.read_blob(&d, MAX_MANIFEST)?)
                .map_err(|e| e.to_string())?;
            let p = normalize(&c.platform);
            out.push(format!("{}/{}", p.os, p.architecture));
            continue;
        }
        if is_manifest(&d.media_type) || is_index(&d.media_type) {
            let b = store.read_blob(&d, registry::MAX_MANIFEST_SIZE)?;
            let doc = validate_media_type(&b, &d.media_type)?;
            let children: Vec<Descriptor> = if is_manifest(&d.media_type) {
                doc.config.into_iter().chain(doc.layers).collect()
            } else {
                doc.manifests
            };
            stack.extend(children.into_iter().rev());
        }
    }
    Ok(out)
}

/// unpack, without unpacking yet: the chosen manifest, its config's diff
/// IDs, every layer checked against its diff ID, and the record.
fn record(
    store: &Store,
    name: &str,
    desc: &Descriptor,
    m: &Matcher,
) -> Result<ImageRecord, String> {
    let (manifest_desc, manifest) = select_manifest(store, desc, m)?;
    let config = manifest.config.clone().ok_or("manifest has no config")?;
    let c: Config = serde_json::from_slice(&store.read_blob(&config, registry::MAX_MANIFEST_SIZE)?)
        .map_err(|e| e.to_string())?;
    let diffs = c.rootfs.diff_ids;
    if diffs.len() != manifest.layers.len() {
        return Err(format!(
            "image has {} layers and {} diff IDs",
            manifest.layers.len(),
            diffs.len()
        ));
    }
    let verified: Index = store.index()?;
    let mut newly: Vec<(String, Digest)> = Vec::new();
    for (blob, diff) in manifest.layers.iter().zip(&diffs) {
        if verified.verified.get(&blob.digest.to_string()) == Some(diff) {
            continue;
        }
        let f = store
            .open_blob(&blob.digest)
            .map_err(|e| format!("layer {}: {e}", blob.digest))?;
        check::layer(f, &blob.digest, diff)?;
        newly.push((blob.digest.to_string(), diff.clone()));
    }
    let chain = chain_ids(&diffs)
        .last()
        .map(|d| d.to_string())
        .unwrap_or_default();
    let platforms = image_platforms(store, desc).unwrap_or_default();
    let now = now_rfc3339();
    let mut rec = ImageRecord {
        name: name.to_string(),
        target: desc.clone(),
        manifest: Descriptor {
            platform: None,
            ..manifest_desc
        },
        config,
        layers: manifest.layers,
        diff_ids: diffs,
        chain_id: chain,
        platforms,
        labels: BTreeMap::new(),
        created: now.clone(),
        updated: now,
    };
    store.update(|idx| {
        for (b, d) in &newly {
            idx.verified.insert(b.clone(), d.clone());
        }
        if let Some(old) = idx.images.get(name)
            && old.target.digest == desc.digest
        {
            // The labels record who may use this target (pulled-with).
            rec.created = old.created.clone();
            rec.labels = old.labels.clone();
        }
        idx.images.insert(name.to_string(), rec.clone());
        Ok(())
    })?;
    Ok(rec)
}

/// remotePlatforms: the platforms of ref from its registry, without
/// pulling it.
fn remote_platforms(
    reg: &Registry,
    r: &super::reference::Reference,
) -> Result<Vec<String>, registry::Error> {
    let desc = reg.resolve(r)?;
    let fetch_json = |d: &Descriptor| -> Result<Vec<u8>, registry::Error> {
        if d.size as u64 > MAX_MANIFEST {
            return Err(registry::Error::new(format!(
                "{} is larger than {MAX_MANIFEST} bytes",
                d.media_type
            )));
        }
        let mut b = Vec::new();
        reg.fetch(d)?
            .take(MAX_MANIFEST + 1)
            .read_to_end(&mut b)
            .map_err(|e| registry::Error::new(e.to_string()))?;
        if b.len() as u64 > MAX_MANIFEST {
            return Err(registry::Error::new(format!(
                "{} is larger than {MAX_MANIFEST} bytes",
                d.media_type
            )));
        }
        Ok(b)
    };
    let bad = |e: serde_json::Error| registry::Error::new(e.to_string());
    if is_index(&desc.media_type) {
        let doc: Document = serde_json::from_slice(&fetch_json(&desc)?).map_err(bad)?;
        let ps: Vec<Platform> = doc
            .manifests
            .into_iter()
            .filter_map(|m| m.platform)
            .collect();
        return Ok(platform_strings(&ps));
    }
    if is_manifest(&desc.media_type) {
        let doc: Document = serde_json::from_slice(&fetch_json(&desc)?).map_err(bad)?;
        let cfg = doc
            .config
            .ok_or_else(|| registry::Error::new("manifest has no config"))?;
        let c: Config = serde_json::from_slice(&fetch_json(&cfg)?).map_err(bad)?;
        return Ok(platform_strings(&[c.platform]));
    }
    Err(registry::Error::new(format!(
        "unsupported media type {:?}",
        desc.media_type
    )))
}

#[derive(Deserialize, Default)]
pub struct PruneRequest {
    /// References the node's replicas name (the assignment).
    #[serde(default, deserialize_with = "crate::runtime::nullable")]
    pub keep: Vec<String>,
    /// Image names containers use.
    #[serde(
        rename = "inUse",
        default,
        deserialize_with = "crate::runtime::nullable"
    )]
    pub in_use: Vec<String>,
    #[serde(rename = "graceSeconds", default)]
    pub grace_seconds: u64,
}

/// PruneImages: every image no container uses, that keep does not name
/// (by reference or digest), and that was not pulled or changed within the
/// grace; then the blobs no image keeps, once no pull runs.
pub fn prune(store: &Store, req: &PruneRequest) -> Result<Vec<String>, String> {
    let mut names: HashSet<String> = HashSet::new();
    let mut digests: HashSet<String> = HashSet::new();
    for k in &req.keep {
        let Ok(r) = parse_docker_ref(k) else { continue };
        names.insert(r.to_string());
        if let Some(d) = &r.digest {
            digests.insert(d.to_string());
        }
    }
    names.extend(req.in_use.iter().cloned());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    let cutoff = now - req.grace_seconds as f64;
    let removed = store.update(|idx| {
        for (name, r) in &idx.images {
            if names.contains(name) {
                digests.insert(r.target.digest.to_string());
            }
        }
        let after = |t: &str| super::store::parse_rfc3339(t).is_none_or(|t| t > cutoff);
        let unused: Vec<String> = idx
            .images
            .values()
            .filter(|r| {
                !names.contains(&r.name)
                    && !digests.contains(&r.target.digest.to_string())
                    && !after(&r.created)
                    && !after(&r.updated)
            })
            .map(|r| r.name.clone())
            .collect();
        for n in &unused {
            idx.images.remove(n);
        }
        if !unused.is_empty() {
            idx.uncollected = true;
        }
        Ok(unused)
    })?;
    store.collect_idle()?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_media_types() {
        assert!(validate_media_type(br#"{"manifests":[]}"#, registry::MEDIA_OCI_MANIFEST).is_err());
        assert!(validate_media_type(br#"{"config":{"digest":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size":0}}"#, registry::MEDIA_OCI_INDEX).is_err());
        assert!(
            validate_media_type(br#"{"fsLayers":[{}]}"#, registry::MEDIA_OCI_MANIFEST).is_err()
        );
        assert!(validate_media_type(br#"{"layers":[]}"#, registry::MEDIA_OCI_MANIFEST).is_ok());
    }

    #[test]
    fn errors_as_go() {
        let e = pull_error(
            "x",
            false,
            false,
            "unexpected status from HEAD request to u: 401 Unauthorized",
        );
        assert!(
            e.to_string()
                .contains("it is private and the app has no registry credentials")
        );
        let e = pull_error("x", true, false, "403 Forbidden");
        assert!(e.to_string().contains("refused the app's credentials"));
        let e = pull_error("x", true, true, "x");
        assert!(e.to_string().contains("no such image or tag"));
    }
}

//! ConvertImages (internal/runtime/supervisor/convert.go): Go's image
//! store's images written into this store, blobs hard-linked (copied
//! across file systems), committed snapshots' directories renamed to
//! layers/<chain ID hex>, every record verified, and index.json written
//! last, under this store's pull.lock and index.lock.

use super::super::digest::{Digest, chain_ids};
use super::super::platform::Matcher;
use super::super::pull::select_manifest;
use super::super::registry::{Descriptor, is_index, is_manifest};
use super::super::store::{ImageRecord, Index, Store};
use super::{committed_snapshots, errno, exists, mkdir_all, os_err, rename_err};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Go's images.json.
const RECORDS_FILE: &str = "images.json";
/// readBlob's bound on a manifest, index, or config.
const MAX_BLOB: u64 = 4 << 20;

/// ConvertSummary: what convert_images did.
#[derive(Serialize, Default, Debug, PartialEq)]
pub struct ConvertSummary {
    /// The image names now in this store.
    pub converted: Vec<String>,
    /// The image names this store already recorded, left as they are.
    pub kept: Vec<String>,
    /// Each image left out, and why; it is pulled again when needed.
    pub skipped: BTreeMap<String, String>,
    /// The unpacked layers moved.
    pub layers: usize,
}

/// Go's Image record, read loosely: each image is checked on its own.
#[derive(Deserialize)]
struct GoImage {
    #[serde(default)]
    name: String,
    #[serde(default)]
    target: serde_json::Value,
    #[serde(default)]
    config: serde_json::Value,
    #[serde(rename = "chainID", default)]
    chain_id: String,
    #[serde(default, deserialize_with = "crate::runtime::nullable")]
    platforms: Vec<String>,
    #[serde(default, deserialize_with = "crate::runtime::nullable")]
    labels: BTreeMap<String, String>,
    #[serde(default)]
    created: String,
    #[serde(default)]
    updated: String,
}

/// The fields of an image config read here.
#[derive(Deserialize, Default)]
struct ImageConfig {
    #[serde(default)]
    rootfs: RootFs,
}

#[derive(Deserialize, Default)]
struct RootFs {
    #[serde(default, deserialize_with = "crate::runtime::nullable")]
    diff_ids: Vec<String>,
}

/// convert_images: Go's store under src (<data dir>/supervisor/images)
/// into this store under dst (<data dir>/node/images). Active snapshots
/// (containers' root filesystems) are left where they are; an image that
/// cannot be converted is left out and named in the summary; records
/// already in dst's index are kept as they are. Neither store may be in
/// use.
pub fn convert_images(src: &Path, dst: &Path) -> (ConvertSummary, Result<(), String>) {
    let mut sum = ConvertSummary::default();
    let r = convert_into(src, dst, &mut sum);
    (sum, r)
}

fn convert_into(src: &Path, dst: &Path, sum: &mut ConvertSummary) -> Result<(), String> {
    let recs_path = src.join(RECORDS_FILE);
    let recs: BTreeMap<String, GoImage> = match fs::read(&recs_path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
        Err(e) => return Err(os_err("open", &recs_path, &e)),
        Ok(b) => serde_json::from_slice::<Option<_>>(&b)
            .map_err(|e| format!("{RECORDS_FILE}: {e}"))?
            .unwrap_or_default(),
    };
    let committed = committed_snapshots(&src.join("snapshots"))?;
    let store = Store::open(dst)?;
    // This store's locks: no pull and no other change while converting.
    let _pulls = store.lock_exclusive("pull.lock")?;
    let _index = store.lock_exclusive("index.lock")?;
    let mut idx: Index = store
        .read_index()
        .map_err(|e| e.replacen("is newer than this program's", "is newer than", 1))?;
    let mut c = Converter {
        src: Store::at(src),
        dst: &store,
        committed,
        checked: BTreeMap::new(),
    };
    // BTreeMap: names in order, as Go sorts them.
    for (name, img) in &recs {
        if idx.images.contains_key(name) {
            sum.kept.push(name.clone());
            continue;
        }
        let (rec, moved) = c.convert(img);
        sum.layers += moved;
        match rec.and_then(|r| c.verify(&r).map(|()| r)) {
            Ok(r) => {
                idx.images.insert(name.clone(), r);
                sum.converted.push(name.clone());
            }
            Err(e) => {
                sum.skipped.insert(name.clone(), e);
                // Blobs and layers it brought along go with the next
                // collection.
                idx.uncollected = true;
            }
        }
    }
    store.write_index(&mut idx)
}

struct Converter<'a> {
    src: Store,
    dst: &'a Store,
    committed: BTreeMap<String, PathBuf>,
    /// Each blob's digest check in dst.
    checked: BTreeMap<String, Result<(), String>>,
}

/// Go's time as JSON writes it, in UTC as RFC 3339 with nanoseconds
/// (img.Created.UTC().Format(time.RFC3339Nano)); as written when it does
/// not parse.
fn utc(s: &str) -> String {
    parse_time(s)
        .map(|(secs, nanos)| super::super::store::format_rfc3339(secs, nanos))
        .unwrap_or_else(|| s.to_string())
}

/// An RFC 3339 time: seconds since the epoch and nanoseconds.
fn parse_time(s: &str) -> Option<(i64, u32)> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        t.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| t.parse().ok())?
    };
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let mut i = 19;
    let mut nanos: u32 = 0;
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        i = start;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let frac = &s[start..i];
        if frac.is_empty() || frac.len() > 9 {
            return None;
        }
        nanos = format!("{frac:0<9}").parse().ok()?;
    }
    let offset = match &s[i..] {
        "Z" => 0,
        z if z.len() == 6 && (z.starts_with('+') || z.starts_with('-')) => {
            let oh = num(i + 1..i + 3)?;
            let om = num(i + 4..i + 6)?;
            let o = oh * 3600 + om * 60;
            if z.starts_with('-') { -o } else { o }
        }
        _ => return None,
    };
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some((days * 86400 + h * 3600 + mi * 60 + se - offset, nanos))
}

impl Converter<'_> {
    /// convert: this store's record of one image, its blobs linked and
    /// its unpacked layers moved; also how many layers it moved.
    fn convert(&self, img: &GoImage) -> (Result<ImageRecord, String>, usize) {
        let mut moved = 0;
        let r = self.convert_counting(img, &mut moved);
        (r, moved)
    }

    fn convert_counting(&self, img: &GoImage, moved: &mut usize) -> Result<ImageRecord, String> {
        let target: Descriptor =
            serde_json::from_value(img.target.clone()).map_err(|e| format!("target: {e}"))?;
        let m = Matcher::default_for_node();
        let (mdesc, mf) = select_manifest(&self.src, &target, &m)?;
        let config = mf.config.clone().ok_or("manifest has no config")?;
        let record_config = img
            .config
            .get("digest")
            .and_then(|d| d.as_str())
            .unwrap_or_default();
        if config.digest.to_string() != record_config {
            return Err(format!(
                "manifest {} names config {}, the record {record_config}",
                mdesc.digest, config.digest
            ));
        }
        let cb = self.src.read_blob(&config, MAX_BLOB)?;
        let cfg: ImageConfig = serde_json::from_slice(&cb).map_err(|e| format!("config: {e}"))?;
        let raw = cfg.rootfs.diff_ids;
        if raw.len() != mf.layers.len() {
            return Err(format!(
                "image has {} layers and {} diff IDs",
                mf.layers.len(),
                raw.len()
            ));
        }
        let diffs = raw
            .iter()
            .map(|d| Digest::parse(d).map_err(|e| format!("diff ID: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        let chains = chain_ids(&diffs);
        let top = chains.last().map(|d| d.to_string()).unwrap_or_default();
        if top != img.chain_id {
            return Err(format!("chain ID {top}, the record {}", img.chain_id));
        }
        // Every blob the record keeps: the target and what it reaches
        // that is in the store, which must include the manifest, config,
        // and layers.
        let blobs = self.reachable(&target)?;
        for d in std::iter::once(&mdesc)
            .chain(std::iter::once(&config))
            .chain(mf.layers.iter())
        {
            if !blobs.contains(&d.digest) {
                return Err(format!("blob {} is missing", d.digest));
            }
        }
        for d in &blobs {
            self.link(d)?;
        }
        for ch in &chains {
            let dir = self.dst.layer_dir(ch);
            if exists(&dir) {
                continue;
            }
            let Some(from) = self.committed.get(&ch.to_string()) else {
                return Err(format!("layer {ch} is not unpacked"));
            };
            fs::rename(from, &dir)
                .map_err(|e| format!("layer {ch}: {}", rename_err(from, &dir, &e)))?;
            *moved += 1;
        }
        Ok(ImageRecord {
            name: img.name.clone(),
            target,
            manifest: Descriptor {
                platform: None,
                ..mdesc
            },
            config,
            layers: mf.layers,
            diff_ids: diffs,
            chain_id: top,
            platforms: img.platforms.clone(),
            labels: img.labels.clone(),
            created: utc(&img.created),
            updated: utc(&img.updated),
        })
    }

    /// reachable: target and every blob in src it reaches (an index's
    /// manifests that are there, a manifest's config and layers).
    fn reachable(&self, target: &Descriptor) -> Result<Vec<Digest>, String> {
        let mut out: Vec<Digest> = Vec::new();
        self.walk(target, &mut out)?;
        if out.is_empty() {
            return Err(format!("blob {} is missing", target.digest));
        }
        Ok(out)
    }

    fn walk(&self, d: &Descriptor, out: &mut Vec<Digest>) -> Result<(), String> {
        if out.contains(&d.digest) || fs::metadata(self.src.blob_path(&d.digest)).is_err() {
            return Ok(());
        }
        out.push(d.digest.clone());
        if !is_manifest(&d.media_type) && !is_index(&d.media_type) {
            return Ok(());
        }
        let b = self.src.read_blob(d, MAX_BLOB)?;
        let doc: super::super::pull::Document =
            serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", d.digest))?;
        if let Some(c) = &doc.config {
            self.walk(c, out)?;
        }
        for x in doc.layers.iter().chain(doc.manifests.iter()) {
            self.walk(x, out)?;
        }
        Ok(())
    }

    /// link: a blob hard-linked into dst (copied when the stores are on
    /// different file systems), read-only as this store writes blobs.
    fn link(&self, d: &Digest) -> Result<(), String> {
        let to = self.dst.blob_path(d);
        if exists(&to) {
            return Ok(());
        }
        let wrap = |e: String| format!("blob {d}: {e}");
        if let Some(dir) = to.parent() {
            mkdir_all(dir).map_err(wrap)?;
        }
        let from = self.src.blob_path(d);
        match fs::hard_link(&from, &to) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EXDEV) => copy_blob(&from, &to).map_err(wrap),
            Err(e) => Err(wrap(format!(
                "link {} {}: {}",
                from.display(),
                to.display(),
                errno(&e)
            ))),
        }
    }

    /// verify: every blob a converted record keeps is in dst with its
    /// digest (a blob that does not match is removed), and every chain has
    /// its directory.
    fn verify(&mut self, rec: &ImageRecord) -> Result<(), String> {
        let ds = [&rec.target.digest, &rec.manifest.digest, &rec.config.digest]
            .into_iter()
            .chain(rec.layers.iter().map(|l| &l.digest));
        for d in ds {
            let key = d.to_string();
            if !self.checked.contains_key(&key) {
                let r = check_blob(&self.dst.blob_path(d), d);
                if r.is_err() {
                    let _ = fs::remove_file(self.dst.blob_path(d));
                }
                self.checked.insert(key.clone(), r);
            }
            self.checked[&key].clone()?;
        }
        for ch in chain_ids(&rec.diff_ids) {
            match fs::symlink_metadata(self.dst.layer_dir(&ch)) {
                Ok(m) if m.is_dir() => {}
                _ => return Err(format!("layer {ch} is missing")),
            }
        }
        Ok(())
    }
}

fn copy_blob(from: &Path, to: &Path) -> Result<(), String> {
    let mut input = fs::File::open(from).map_err(|e| os_err("open", from, &e))?;
    let mut tmp = to.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let r = (|| {
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o400)
            .open(&tmp)
            .map_err(|e| os_err("open", &tmp, &e))?;
        io::copy(&mut input, &mut out).map_err(|e| os_err("write", &tmp, &e))?;
        fs::rename(&tmp, to).map_err(|e| rename_err(&tmp, to, &e))
    })();
    if r.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    r
}

fn check_blob(path: &Path, d: &Digest) -> Result<(), String> {
    let mut f =
        fs::File::open(path).map_err(|e| format!("blob {d}: {}", os_err("open", path, &e)))?;
    let mut h = d.algorithm().hasher();
    io::copy(&mut f, &mut h).map_err(|e| format!("blob {d}: {}", errno(&e)))?;
    if h.finish() != *d {
        return Err(format!("blob {d} does not match its digest"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_in_utc_as_go() {
        assert_eq!(
            utc("2026-11-25T21:10:03.123456789+01:00"),
            "2026-11-25T20:10:03.123456789Z"
        );
        assert_eq!(utc("2026-11-25T20:10:03.5000Z"), "2026-11-25T20:10:03.5Z");
        assert_eq!(utc("2026-01-01T00:30:00-01:00"), "2026-01-01T01:30:00Z");
        assert_eq!(utc("nonsense"), "nonsense");
    }
}

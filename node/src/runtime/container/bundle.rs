//! Containers' OCI bundles under DIR/<id>: config.json, the root
//! filesystem mounted at rootfs, and record.json, written last, so a
//! bundle without a record is one that was never finished. The files keep
//! their recorded format, so containers made by an earlier release are
//! adopted.

use super::errno_text;
use super::mount::{Mount, mount_all, unmount_all};
use crate::runtime::spec::to_go_json;
use serde::de::{Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const CONFIG: &str = "config.json";
const RECORD: &str = "record.json";
const ROOTFS: &str = "rootfs";

/// The annotation naming the shim a container shares (GroupAnnotation).
pub const GROUP_ANNOTATION: &str = "io.containerd.runc.v2.group";

/// A bundle's record (record.json).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Record {
    pub id: String,
    pub image: String,
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "crate::runtime::nullable"
    )]
    pub labels: BTreeMap<String, String>,
    pub group: String,
    /// The OCI runtime that created the container (oci.rs): "crun"; none
    /// (or "runc") for a container runc created, which is only ended and
    /// created again.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub runtime: String,
    pub created: String,
}

fn os_err(op: &str, p: &Path, e: &io::Error) -> String {
    format!(
        "{op} {}: {}",
        p.display(),
        errno_text(e.raw_os_error().unwrap_or(libc::EIO))
    )
}

/// writeJSON: to path.tmp (0600), then renamed over path.
fn write_file(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| os_err("open", &tmp, &e))?;
    f.write_all(data).map_err(|e| os_err("write", &tmp, &e))?;
    drop(f);
    fs::rename(&tmp, path).map_err(|e| {
        format!(
            "rename {} {}: {}",
            tmp.display(),
            path.display(),
            errno_text(e.raw_os_error().unwrap_or(libc::EIO))
        )
    })
}

/// A whole file: the error names the step that failed (open or read).
fn read_file(p: &Path) -> Result<Vec<u8>, (io::Error, &'static str)> {
    let mut f = fs::File::open(p).map_err(|e| (e, "open"))?;
    let mut b = Vec::new();
    io::Read::read_to_end(&mut f, &mut b).map_err(|e| (e, "read"))?;
    Ok(b)
}

/// A JSON object's members in their order, values as written.
struct Members(Vec<(String, Box<RawValue>)>);

impl<'de> Deserialize<'de> for Members {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Members;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an OCI runtime spec")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Members, A::Error> {
                let mut out = Vec::new();
                while let Some(k) = m.next_key::<String>()? {
                    out.push((k, m.next_value::<Box<RawValue>>()?));
                }
                Ok(Members(out))
            }
        }
        d.deserialize_map(V)
    }
}

#[derive(Deserialize, Default)]
struct Root {
    #[serde(default)]
    readonly: bool,
}

#[derive(Deserialize, Default)]
struct Annotations {
    #[serde(default, deserialize_with = "crate::runtime::nullable")]
    annotations: BTreeMap<String, String>,
}

/// The spec as a bundle's config.json holds it: the compact JSON of the
/// spec, its root replaced by {"path": "rootfs"} (keeping
/// readonly), in the place the struct gives root (after process).
pub fn bundle_spec(spec: &RawValue) -> Result<(Vec<u8>, String), String> {
    let Members(mut members) =
        serde_json::from_str(spec.get()).map_err(|e| format!("spec: {e}"))?;
    let readonly = members
        .iter()
        .find(|(k, _)| k == "root")
        .and_then(|(_, v)| serde_json::from_str::<Option<Root>>(v.get()).ok().flatten())
        .unwrap_or_default()
        .readonly;
    let root = if readonly {
        r#"{"path":"rootfs","readonly":true}"#
    } else {
        r#"{"path":"rootfs"}"#
    };
    let root = RawValue::from_string(root.to_string()).map_err(|e| e.to_string())?;
    match members.iter().position(|(k, _)| k == "root") {
        Some(i) => members[i].1 = root,
        None => {
            let at = members
                .iter()
                .rposition(|(k, _)| k == "ociVersion" || k == "process")
                .map_or(0, |i| i + 1);
            members.insert(at, ("root".into(), root));
        }
    }
    let group = serde_json::from_str::<Annotations>(spec.get())
        .map(|a| {
            a.annotations
                .get(GROUP_ANNOTATION)
                .cloned()
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let mut out = vec![b'{'];
    for (i, (k, v)) in members.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend(to_go_json(k));
        out.push(b':');
        out.extend(v.get().as_bytes());
    }
    out.push(b'}');
    Ok((out, group))
}

#[derive(Deserialize, Clone)]
pub struct CreateRequest {
    pub dir: String,
    pub id: String,
    pub image: String,
    #[serde(default, deserialize_with = "crate::runtime::nullable")]
    pub labels: BTreeMap<String, String>,
    pub spec: Box<RawValue>,
    #[serde(default, deserialize_with = "crate::runtime::nullable")]
    pub mounts: Vec<Mount>,
    /// The OCI runtime the container is created with (oci.rs): "crun", or
    /// none for crun.
    #[serde(default)]
    pub runtime: String,
}

/// A bundle directory's name is a container ID: no separator, not "."
/// or "..".
fn valid_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id == "." || id == ".." || id.contains('/') || id.contains('\0') {
        return Err(format!(
            "invalid container ID {}",
            crate::net::addr::quote(id)
        ));
    }
    Ok(())
}

/// NewContainer's refusal and Bundles.Create: the rootfs directory, the
/// root filesystem mounted on it, config.json, then record.json.
pub fn create(r: &CreateRequest) -> Result<Record, String> {
    create_with(r, &mount_all)
}

/// A mount of a bundle's root filesystem: mount_all, or a stand-in in the
/// tests of a caller that runs without root (the agent's).
pub type MountFn<'a> = &'a dyn Fn(&[Mount], &Path) -> Result<(), String>;

/// create, the root filesystem mounted by mount.
pub fn create_with(r: &CreateRequest, mount: MountFn) -> Result<Record, String> {
    valid_id(&r.id)?;
    let runtime = super::oci::OciRuntime::for_create(&r.runtime)?
        .name()
        .to_string();
    let dir = Path::new(&r.dir).join(&r.id);
    if fs::metadata(&dir).is_ok() {
        return Err(format!("container {}: already exists", r.id));
    }
    let (config, group) = bundle_spec(&r.spec)?;
    let rootfs = dir.join(ROOTFS);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&rootfs)
        .map_err(|e| os_err("mkdir", &rootfs, &e))?;
    mount(&r.mounts, &rootfs).map_err(|e| format!("mount root filesystem: {e}"))?;
    write_file(&dir.join(CONFIG), &config)?;
    let rec = Record {
        id: r.id.clone(),
        image: r.image.clone(),
        labels: r.labels.clone(),
        group: if group.is_empty() {
            r.id.clone()
        } else {
            group
        },
        runtime,
        created: crate::runtime::image::now_rfc3339(),
    };
    write_file(&dir.join(RECORD), &to_go_json(&rec))?;
    Ok(rec)
}

/// Bundles.Remove: the root filesystem unmounted, the bundle removed.
pub fn remove(dir: &str, id: &str) -> Result<(), String> {
    remove_with(dir, id, &unmount_all)
}

/// An unmount of a bundle's root filesystem: unmount_all, or a stand-in.
pub type UnmountFn<'a> = &'a dyn Fn(&Path) -> Result<(), (String, i32)>;

/// remove, the root filesystem unmounted by unmount.
pub fn remove_with(dir: &str, id: &str, unmount: UnmountFn) -> Result<(), String> {
    valid_id(id)?;
    let dir = Path::new(dir).join(id);
    if let Err((text, errno)) = unmount(&dir.join(ROOTFS))
        && errno != libc::ENOENT
    {
        return Err(format!("unmount root filesystem: {text}"));
    }
    match fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(os_err("unlinkat", &dir, &e)),
    }
}

/// Whether s is a time: RFC 3339 strictly, with Z or a numeric
/// offset, every field in its range.
fn rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let x = b.get(r)?;
        if !x.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(x).ok()?.parse().ok()
    };
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(se)) = (
        num(0..4),
        num(5..7),
        num(8..10),
        num(11..13),
        num(14..16),
        num(17..19),
    ) else {
        return false;
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return false;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    if d == 0 || d > days || h > 23 || mi > 59 || se > 59 {
        return false;
    }
    let mut rest = &b[19..];
    if let Some(frac) = rest.strip_prefix(b".") {
        let n = frac.iter().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 || n > 9 {
            return false;
        }
        rest = &frac[n..];
    }
    match rest {
        b"Z" => true,
        [sign, h1, h2, b':', m1, m2] if *sign == b'+' || *sign == b'-' => {
            let digits = [h1, h2, m1, m2].iter().all(|c| c.is_ascii_digit());
            let hh = (h1 - b'0') * 10 + h2.wrapping_sub(b'0');
            let mm = (m1 - b'0') * 10 + m2.wrapping_sub(b'0');
            digits && hh < 24 && mm < 60
        }
        _ => false,
    }
}

/// A record left out of a listing: its directory's name and why.
#[derive(serde::Serialize, Debug, PartialEq)]
pub struct Skipped {
    pub id: String,
    pub error: String,
}

/// Every finished bundle's record, by directory name. A record that
/// cannot be read, does not parse, or names another ID is left out and
/// named in the second list, so one bad bundle never hides every
/// container.
pub fn records(dir: &str) -> Result<(Vec<Record>, Vec<Skipped>), String> {
    let dir = Path::new(dir);
    let mut names: Vec<String> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<Result<_, _>>()
            .map_err(|e| os_err("readdirent", dir, &e))?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), Vec::new())),
        Err(e) => return Err(os_err("open", dir, &e)),
    };
    names.sort();
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    for n in names {
        let p = dir.join(&n).join(RECORD);
        let data = match read_file(&p) {
            Ok(d) => d,
            Err((e, _)) if e.kind() == io::ErrorKind::NotFound => continue,
            Err((e, op)) => {
                skipped.push(Skipped {
                    id: n,
                    error: os_err(op, &p, &e),
                });
                continue;
            }
        };
        let why = match serde_json::from_slice::<Record>(&data) {
            Ok(r) if r.id == n && rfc3339(&r.created) => {
                out.push(r);
                continue;
            }
            Ok(r) if r.id != n => format!("{}: names container {:?}", p.display(), r.id),
            Ok(_) => format!("{}: no valid creation time", p.display()),
            Err(e) => format!("{}: {e}", p.display()),
        };
        skipped.push(Skipped { id: n, error: why });
    }
    Ok((out, skipped))
}

/// container.SetLabels: labels merged into the record, which is written
/// again.
pub fn set_labels(
    dir: &str,
    id: &str,
    labels: &BTreeMap<String, String>,
) -> Result<Record, String> {
    valid_id(id)?;
    let p = Path::new(dir).join(id).join(RECORD);
    let data = read_file(&p).map_err(|(e, op)| os_err(op, &p, &e))?;
    let mut rec: Record =
        serde_json::from_slice(&data).map_err(|e| format!("{}: {e}", p.display()))?;
    for (k, v) in labels {
        rec.labels.insert(k.clone(), v.clone());
    }
    write_file(&p, &to_go_json(&rec))?;
    Ok(rec)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(s: &str) -> Box<RawValue> {
        RawValue::from_string(s.to_string()).unwrap()
    }

    #[test]
    fn root_replaced_in_place() {
        let (b, g) = bundle_spec(&raw(
            r#"{"ociVersion":"1.2.1","process":{"cwd":"/"},"root":{"path":"/x","readonly":true},"annotations":{"io.containerd.runc.v2.group":"web"},"linux":{}}"#,
        ))
        .unwrap();
        assert_eq!(
            String::from_utf8(b).unwrap(),
            r#"{"ociVersion":"1.2.1","process":{"cwd":"/"},"root":{"path":"rootfs","readonly":true},"annotations":{"io.containerd.runc.v2.group":"web"},"linux":{}}"#
        );
        assert_eq!(g, "web");
        let (b, g) = bundle_spec(&raw(r#"{"ociVersion":"1.2.1","hostname":"h"}"#)).unwrap();
        assert_eq!(
            String::from_utf8(b).unwrap(),
            r#"{"ociVersion":"1.2.1","root":{"path":"rootfs"},"hostname":"h"}"#
        );
        assert_eq!(g, "");
        let (b, _) = bundle_spec(&raw(r#"{"ociVersion":"1","process":{},"root":null}"#)).unwrap();
        assert_eq!(
            String::from_utf8(b).unwrap(),
            r#"{"ociVersion":"1","process":{},"root":{"path":"rootfs"}}"#
        );
    }

    #[test]
    fn rfc3339_times() {
        assert!(rfc3339("2026-11-23T08:00:00Z"));
        assert!(rfc3339("2026-11-23T08:00:00.123456789Z"));
        assert!(rfc3339("2026-11-23T08:00:00.5+07:00"));
        assert!(rfc3339("2024-02-29T00:00:00-00:30"));
        assert!(!rfc3339("2026-02-29T00:00:00Z"));
        assert!(!rfc3339("2026-11-23 08:00:00Z"));
        assert!(!rfc3339("2026-11-23T08:00:00"));
        assert!(!rfc3339("2026-11-23T08:00:00.Z"));
        assert!(!rfc3339("2026-11-23T24:00:00Z"));
        assert!(!rfc3339("yesterday"));
    }

    #[test]
    fn records_skip_bad_ones() {
        let dir = std::env::temp_dir().join(format!("armada-records-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let rec = |id: &str| {
            format!(r#"{{"id":"{id}","image":"i","group":"g","created":"2026-11-23T08:00:00Z"}}"#)
        };
        for (id, body) in [
            ("a", Some(rec("a"))),
            ("b", None), // record.json a directory: unreadable
            ("c", Some("{".to_string())),
            ("d", Some(rec("other"))),
            ("e", Some(rec("e"))),
        ] {
            fs::create_dir_all(dir.join(id)).unwrap();
            match body {
                Some(b) => fs::write(dir.join(id).join(RECORD), b).unwrap(),
                None => fs::create_dir(dir.join(id).join(RECORD)).unwrap(),
            }
        }
        // Unfinished: no record yet.
        fs::create_dir_all(dir.join("f")).unwrap();
        let (recs, skipped) = records(dir.to_str().unwrap()).unwrap();
        let ids: Vec<&str> = recs.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["a", "e"]);
        let names: Vec<&str> = skipped.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(names, ["b", "c", "d"]);
        assert!(
            skipped[0].error.contains("is a directory"),
            "{:?}",
            skipped[0]
        );
        assert!(skipped[2].error.contains("names container \"other\""));
        let _ = fs::remove_dir_all(&dir);
    }

    /// A new record names crun (ADR 0056), and nothing creates one for
    /// runc; a record written by an older release names none, and keeps
    /// naming none when it is written again.
    #[test]
    fn records_name_their_runtime() {
        let dir = std::env::temp_dir().join(format!("armada-bundle-rt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let d = dir.display().to_string();
        let req = CreateRequest {
            dir: d.clone(),
            id: "web-r1-a".into(),
            image: "i".into(),
            labels: BTreeMap::new(),
            spec: raw(
                r#"{"ociVersion":"1.2.1","annotations":{"io.containerd.runc.v2.group":"web"}}"#,
            ),
            mounts: Vec::new(),
            runtime: "crun".into(),
        };
        let runc = CreateRequest {
            runtime: "runc".into(),
            ..req.clone()
        };
        assert!(create_with(&runc, &|_, _| Ok(())).is_err());
        let odd = CreateRequest {
            dir: d.clone(),
            id: "web-r1-c".into(),
            image: "i".into(),
            labels: BTreeMap::new(),
            spec: raw("{}"),
            mounts: Vec::new(),
            runtime: "youki".into(),
        };
        assert_eq!(
            create_with(&odd, &|_, _| Ok(())).unwrap_err(),
            "unknown OCI runtime \"youki\""
        );
        let rec = create_with(&req, &|_, _| Ok(())).unwrap();
        assert_eq!(rec.runtime, "crun");
        let written = fs::read_to_string(dir.join("web-r1-a").join(RECORD)).unwrap();
        assert!(
            written.contains(r#""group":"web","runtime":"crun","created":"#),
            "{written}"
        );
        let old = r#"{"id":"web-r1-b","image":"i","group":"web","created":"2026-11-23T08:00:00Z"}"#;
        fs::create_dir_all(dir.join("web-r1-b")).unwrap();
        fs::write(dir.join("web-r1-b").join(RECORD), old).unwrap();
        let labels: BTreeMap<String, String> = [("a".to_string(), "b".to_string())].into();
        let rec = set_labels(&d, "web-r1-b", &labels).unwrap();
        assert_eq!(rec.runtime, "");
        let again = fs::read_to_string(dir.join("web-r1-b").join(RECORD)).unwrap();
        assert!(!again.contains("runtime"), "{again}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ids_are_names() {
        assert!(valid_id("web-r1-3f2a").is_ok());
        assert!(valid_id("..").is_err());
        assert!(valid_id("a/b").is_err());
        assert!(valid_id("").is_err());
    }
}

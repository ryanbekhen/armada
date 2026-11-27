//! What the runtime keeps of a container's output: armada-log writes
//! <logs>/<id>.log (rotated to .1 and .2), the driver records whose container
//! it is in <logs>/history/<id>.meta (ADR 0043), moves the files of a removed
//! container into history, and reads the last lines of one.

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Log files per container: the current file and the rotated ones.
pub const LOG_MAX_FILES: usize = 3;
/// What a tail keeps of the newest entries, whatever their number.
const MAX_TAIL_BYTES: usize = 4 << 20;
const HISTORY: &str = "history";
const META_SUFFIX: &str = ".meta";

/// Whether id may name a container's log files:
/// ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$.
pub fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && b[0].is_ascii_alphanumeric()
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

/// The current log file of container id.
pub fn log_path(dir: &Path, id: &str) -> Result<PathBuf, String> {
    if !valid_id(id) {
        return Err(format!("invalid container id {}", armada_pki::go_quote(id)));
    }
    Ok(dir.join(format!("{id}.log")))
}

/// A container's .meta file: compact JSON in the fields' order.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct LogMeta {
    pub app: String,
    pub replica: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub revision: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub container: String,
    pub created: String,
}

fn history(dir: &Path) -> PathBuf {
    dir.join(HISTORY)
}

/// Records whose container id is, so its output is kept in
/// history when it rotates out or the container is removed.
pub fn write_log_meta(dir: &Path, id: &str, m: &LogMeta) -> Result<(), String> {
    if !valid_id(id) {
        return Err(format!("invalid container id {}", armada_pki::go_quote(id)));
    }
    let h = history(dir);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&h)
        .map_err(|e| super::os_err("mkdir", &h, &e))?;
    let p = h.join(format!("{id}{META_SUFFIX}"));
    let data = armada_node::runtime::spec::to_go_json(m);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&p)
        .map_err(|e| super::os_err("open", &p, &e))?;
    std::io::Write::write_all(&mut f, &data).map_err(|e| super::os_err("write", &p, &e))
}

fn has_meta(dir: &Path, id: &str) -> bool {
    history(dir).join(format!("{id}{META_SUFFIX}")).exists()
}

fn unix_nanos() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0)
}

/// keep: moves a log file of container id into history, or removes it when
/// the container has no meta file; seq orders files moved at once.
fn keep(dir: &Path, id: &str, path: &Path, seq: i128) -> Result<(), String> {
    if !has_meta(dir, id) {
        return match fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(super::os_err("remove", path, &e))
            }
            _ => Ok(()),
        };
    }
    let to = history(dir).join(format!("{id}.{}.log", unix_nanos() + seq));
    match fs::rename(path, &to) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!(
            "rename {} {}: {}",
            path.display(),
            to.display(),
            super::errno(&e)
        )),
        _ => Ok(()),
    }
}

/// A removed container's log files into history, oldest first,
/// or deleted when it keeps none.
pub fn remove_logs(dir: &Path, id: &str) -> Result<(), String> {
    let path = log_path(dir, id)?;
    let mut errs = Vec::new();
    for i in (0..LOG_MAX_FILES).rev() {
        let p = if i > 0 {
            PathBuf::from(format!("{}.{i}", path.display()))
        } else {
            path.clone()
        };
        if let Err(e) = keep(dir, id, &p, (LOG_MAX_FILES - i) as i128) {
            errs.push(e);
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("\n"))
    }
}

#[derive(Deserialize)]
struct Entry {
    #[serde(default)]
    log: String,
}

/// The output of the container's last `n` entries, joined (what the
/// HAProxy engine reads of its container); None when the
/// container has no log file.
pub fn tail(dir: &Path, id: &str, n: usize) -> Result<Option<String>, String> {
    let path = log_path(dir, id)?;
    if fs::metadata(&path).is_err() {
        return Ok(None);
    }
    let mut entries: std::collections::VecDeque<String> = Default::default();
    let mut kept = 0usize;
    let mut files: Vec<PathBuf> = (1..LOG_MAX_FILES)
        .rev()
        .map(|i| PathBuf::from(format!("{}.{i}", path.display())))
        .collect();
    files.push(path);
    for p in files {
        let Ok(f) = fs::File::open(&p) else { continue };
        let mut r = BufReader::with_capacity(64 << 10, f);
        let mut line = Vec::new();
        loop {
            line.clear();
            match r.read_until(b'\n', &mut line) {
                Ok(0) => break,
                Ok(_) if line.last() != Some(&b'\n') => break,
                Ok(_) => {}
                Err(e) => return Err(super::os_err("read", &p, &e)),
            }
            let Ok(e) = serde_json::from_slice::<Entry>(&line) else {
                continue;
            };
            kept += e.log.len();
            entries.push_back(e.log);
            while entries.len() > 1 && (entries.len() > n || kept > MAX_TAIL_BYTES) {
                if let Some(old) = entries.pop_front() {
                    kept -= old.len();
                }
            }
        }
    }
    Ok(Some(entries.into_iter().collect()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        assert!(valid_id("web-r1-0a1b2c3d"));
        assert!(!valid_id("-web"));
        assert!(!valid_id("a/b"));
        assert!(!valid_id(&"a".repeat(129)));
        assert_eq!(
            log_path(Path::new("/l"), "x y").unwrap_err(),
            "invalid container id \"x y\""
        );
    }

    #[test]
    fn meta_history_and_tail() {
        let dir = std::env::temp_dir().join(format!("armada-logs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let m = LogMeta {
            app: "web".into(),
            replica: "web-r1".into(),
            created: "2026-01-01T00:00:00Z".into(),
            ..Default::default()
        };
        write_log_meta(&dir, "web-r1-aa", &m).unwrap();
        assert_eq!(
            fs::read_to_string(dir.join("history/web-r1-aa.meta")).unwrap(),
            r#"{"app":"web","replica":"web-r1","created":"2026-01-01T00:00:00Z"}"#
        );
        let line = |s: &str| {
            format!(
                "{{\"log\":\"{s}\\n\",\"stream\":\"stdout\",\"time\":\"2026-01-01T00:00:00Z\"}}\n"
            )
        };
        fs::write(dir.join("web-r1-aa.log.1"), line("one")).unwrap();
        fs::write(
            dir.join("web-r1-aa.log"),
            line("two") + &line("three") + "{\"log\":\"cut",
        )
        .unwrap();
        assert_eq!(tail(&dir, "web-r1-aa", 2).unwrap().unwrap(), "two\nthree\n");
        assert_eq!(
            tail(&dir, "web-r1-aa", 20).unwrap().unwrap(),
            "one\ntwo\nthree\n"
        );
        assert_eq!(tail(&dir, "nope", 2).unwrap(), None);
        remove_logs(&dir, "web-r1-aa").unwrap();
        let moved: Vec<String> = fs::read_dir(dir.join("history"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".log"))
            .collect();
        assert_eq!(moved.len(), 2);
        // A container without meta loses its files.
        fs::write(dir.join("other.log"), line("x")).unwrap();
        remove_logs(&dir, "other").unwrap();
        assert!(!dir.join("other.log").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}

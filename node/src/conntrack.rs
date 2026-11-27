//! The kernel's connection tracking table (ADR 0025), read and raised:
//!
//!   armada-node conntrack read    stdin {"dir"}; stdout {"entries",
//!                                 "limit", "ok"}
//!   armada-node conntrack raise   stdin {"dir", "memory"?}; stdout
//!                                 {"previous"} or {"error": TEXT}:
//!                                 the limit raised
//!
//! "memory" is the machine's memory in bytes; without it the program asks
//! the kernel (sysinfo).

use crate::runtime::container::errno_text;
use crate::runtime::gopath;
use serde::Deserialize;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;

/// Minimum is the limit a node gets when it has the memory for it.
const MINIMUM: i64 = 262144;
/// An entry takes about 256 bytes; a full table stays near 6% of memory.
const MEMORY_PER_ENTRY: i64 = 4096;
const FILE_COUNT: &str = "nf_conntrack_count";
const FILE_MAX: &str = "nf_conntrack_max";

#[derive(Deserialize)]
struct Request {
    dir: String,
    memory: Option<i64>,
}

/// conntrack.Target.
pub fn target(memory: i64) -> i64 {
    MINIMUM.min(memory.max(0) / MEMORY_PER_ENTRY)
}

/// The machine's memory as conntrack.New reads it, 0 when sysinfo fails.
pub fn machine_memory() -> i64 {
    // SAFETY: an all-zero sysinfo is valid and the kernel fills it.
    let mut si: libc::sysinfo = unsafe { std::mem::zeroed() };
    // SAFETY: a pointer to a sysinfo.
    if unsafe { libc::sysinfo(&mut si) } != 0 {
        return 0;
    }
    (si.totalram as i64).wrapping_mul(i64::from(si.mem_unit))
}

struct ReadError {
    text: String,
    not_exist: bool,
}

fn os_errno(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

/// The file's number, or the error reading or parsing it.
fn read(dir: &str, name: &str) -> Result<i64, ReadError> {
    let path = gopath::join(dir, name);
    let mut f = std::fs::File::open(&path).map_err(|e| ReadError {
        text: format!("open {path}: {}", errno_text(os_errno(&e))),
        not_exist: os_errno(&e) == libc::ENOENT,
    })?;
    let mut b = Vec::new();
    f.read_to_end(&mut b).map_err(|e| ReadError {
        text: format!("read {path}: {}", errno_text(os_errno(&e))),
        not_exist: os_errno(&e) == libc::ENOENT,
    })?;
    crate::textutil::parse_int(crate::textutil::trim_space(&b), 64).map_err(|e| ReadError {
        text: format!("read {name}: {e}"),
        not_exist: false,
    })
}

/// Table.Read.
pub fn read_table(dir: &str) -> (i64, i64, bool) {
    let Ok(entries) = read(dir, FILE_COUNT) else {
        return (0, 0, false);
    };
    match read(dir, FILE_MAX) {
        Ok(limit) if limit > 0 => (entries, limit, true),
        _ => (0, 0, false),
    }
}

/// Writes data to path (created 0600), with the error texts of each step.
fn write_file(path: &str, data: &[u8]) -> Result<(), String> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("open {path}: {}", errno_text(os_errno(&e))))?;
    match f.write(data) {
        Ok(n) if n < data.len() => return Err("short write".into()),
        Ok(_) => {}
        Err(e) => return Err(format!("write {path}: {}", errno_text(os_errno(&e)))),
    }
    // SAFETY: closing the descriptor f owns, once: f is forgotten below.
    let fd = std::os::fd::IntoRawFd::into_raw_fd(f);
    // SAFETY: fd is open and owned here.
    if unsafe { libc::close(fd) } != 0 {
        let e = std::io::Error::last_os_error();
        return Err(format!("close {path}: {}", errno_text(os_errno(&e))));
    }
    Ok(())
}

/// Table.Raise: the previous limit when it changed anything.
pub fn raise(dir: &str, memory: i64) -> Result<i64, String> {
    let limit = match read(dir, FILE_MAX) {
        Ok(l) => l,
        Err(e) if e.not_exist => return Ok(0),
        Err(e) => return Err(e.text),
    };
    let target = target(memory);
    if limit >= target {
        return Ok(0);
    }
    let path = gopath::join(dir, FILE_MAX);
    write_file(&path, format!("{target}\n").as_bytes())
        .map_err(|e| format!("raise the connection tracking limit: {e}"))?;
    Ok(limit)
}

/// armada-node conntrack read|raise.
pub fn command(op: &str) -> Result<(), String> {
    let r: Request = serde_json::from_slice(&crate::runtime::read_stdin()?)
        .map_err(|e| format!("read request: {e}"))?;
    let out = match op {
        "read" => {
            let (entries, limit, ok) = read_table(&r.dir);
            serde_json::json!({ "entries": entries, "limit": limit, "ok": ok })
        }
        "raise" => match raise(&r.dir, r.memory.unwrap_or_else(machine_memory)) {
            Ok(previous) => serde_json::json!({ "previous": previous }),
            Err(e) => serde_json::json!({ "error": e }),
        },
        _ => {
            return Err(format!(
                "unknown conntrack command {op:?}; try read or raise"
            ));
        }
    };
    crate::runtime::write_out(&crate::runtime::spec::to_go_json(&out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(files: &[(&str, &str)]) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "armada-conntrack-{}-{}",
            std::process::id(),
            files.len() * 7 + files.first().map_or(0, |f| f.1.len())
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        for (n, v) in files {
            std::fs::write(d.join(n), v).unwrap();
        }
        d
    }

    #[test]
    fn raises_and_never_lowers() {
        assert_eq!(target(1 << 30), MINIMUM);
        assert_eq!(target(64 << 20), 16384);
        assert_eq!(target(-1), 0);
        let d = dir(&[(FILE_COUNT, "12\n"), (FILE_MAX, "65536\n")]);
        let s = d.to_str().unwrap();
        assert_eq!(read_table(s), (12, 65536, true));
        assert_eq!(raise(s, 8 << 30), Ok(65536));
        assert_eq!(
            std::fs::read_to_string(d.join(FILE_MAX)).unwrap(),
            "262144\n"
        );
        assert_eq!(raise(s, 8 << 30), Ok(0));
        std::fs::write(d.join(FILE_MAX), "x").unwrap();
        assert_eq!(
            raise(s, 8 << 30).unwrap_err(),
            "read nf_conntrack_max: invalid number \"x\""
        );
        std::fs::remove_dir_all(&d).unwrap();
        assert_eq!(raise(s, 8 << 30), Ok(0));
        assert_eq!(read_table(s), (0, 0, false));
    }
}

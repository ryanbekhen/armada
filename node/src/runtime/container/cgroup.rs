//! Ending a container's processes without its OCI runtime (ADR 0056): a
//! container runc created, now that the runtime pack carries no runc, is
//! ended through the cgroup v2 hierarchy alone. Every container Armada
//! makes has a cgroup of its own, `/armada/<container ID>` (the spec's
//! `linux.cgroupsPath`, a cgroupfs path), so killing every process in it
//! ends the container, whoever created it, and nothing else: no other
//! path is accepted.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The parent of every container's cgroup.
pub const PARENT: &str = "/armada";

/// How long `end` waits for a cgroup's processes to be gone.
pub const END_WAIT: Duration = Duration::from_secs(10);

const POLL: Duration = Duration::from_millis(20);

/// A container's cgroup path checked to be one Armada makes:
/// `/armada/<name>`, the name a single path component.
pub fn armada_path(path: &str) -> Result<&str, String> {
    let bad = || {
        format!(
            "cgroup {}: not a container cgroup of Armada's",
            crate::net::addr::quote(path)
        )
    };
    let name = path
        .strip_prefix(PARENT)
        .and_then(|r| r.strip_prefix('/'))
        .ok_or_else(bad)?;
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > 255
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(bad());
    }
    Ok(path)
}

/// The `linux.cgroupsPath` of a bundle's config.json; None when it has
/// none or cannot be read (the agent's, through the library).
#[allow(dead_code)]
pub fn spec_cgroups_path(config: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(config).ok()?;
    v.get("linux")?
        .get("cgroupsPath")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn io_text(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(n) => super::errno_text(n),
        None => e.to_string(),
    }
}

/// The cgroup and every cgroup below it, parents first; symbolic links
/// are never followed.
fn tree(dir: &Path) -> Vec<PathBuf> {
    let mut out = vec![dir.to_path_buf()];
    let mut i = 0;
    while i < out.len() {
        if let Ok(rd) = fs::read_dir(&out[i]) {
            let mut subs: Vec<PathBuf> = rd
                .flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .map(|e| e.path())
                .collect();
            subs.sort();
            out.extend(subs);
        }
        i += 1;
    }
    out
}

/// The processes listed in the cgroups, those still alive.
fn live_pids(cgroups: &[PathBuf]) -> Vec<i32> {
    let mut pids = Vec::new();
    for c in cgroups {
        let Ok(s) = fs::read_to_string(c.join("cgroup.procs")) else {
            continue;
        };
        for pid in s.split_whitespace().filter_map(|w| w.parse::<i32>().ok()) {
            // SAFETY: signal 0 only checks that the process exists.
            if pid > 1 && unsafe { libc::kill(pid, 0) } == 0 {
                pids.push(pid);
            }
        }
    }
    pids
}

/// Every process in the container's cgroup `path` (under the cgroup v2
/// mount `root`) and in the cgroups below it killed, waited for until
/// none is left (within `wait`), and the cgroups removed, deepest first.
/// `cgroup.kill` ends them all at once where the kernel has it (5.14 and
/// later); each listed process also gets SIGKILL, which is all an older
/// kernel offers. Ok(false) when there is no such cgroup.
pub fn end(root: &Path, path: &str, wait: Duration) -> Result<bool, String> {
    end_with(root, path, wait, &|p| fs::remove_dir(p))
}

/// end, with the removal of each cgroup directory given (tests stand in
/// for cgroupfs, whose directories hold files a plain rmdir refuses).
pub fn end_with(
    root: &Path,
    path: &str,
    wait: Duration,
    rmdir: &dyn Fn(&Path) -> io::Result<()>,
) -> Result<bool, String> {
    let path = armada_path(path)?;
    let dir = root.join(path.trim_start_matches('/'));
    match fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("lstat {}: {}", dir.display(), io_text(&e))),
        Ok(m) if !m.file_type().is_dir() => {
            return Err(format!("{}: not a cgroup", dir.display()));
        }
        Ok(_) => {}
    }
    let deadline = Instant::now() + wait;
    let kill_file = dir.join("cgroup.kill");
    loop {
        // Each round: a process forked meanwhile is caught by the next.
        let written = fs::OpenOptions::new()
            .write(true)
            .open(&kill_file)
            .and_then(|mut f| io::Write::write_all(&mut f, b"1"));
        match written {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(format!("write {}: {}", kill_file.display(), io_text(&e)));
            }
        }
        let pids = live_pids(&tree(&dir));
        if pids.is_empty() {
            break;
        }
        for pid in &pids {
            // SAFETY: a process listed in the container's own cgroup.
            unsafe { libc::kill(*pid, libc::SIGKILL) };
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "cgroup {path}: {} processes left after SIGKILL",
                pids.len()
            ));
        }
        std::thread::sleep(POLL);
    }
    let mut all = tree(&dir);
    all.reverse();
    for c in all {
        loop {
            match rmdir(&c) {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::NotFound => break,
                // Busy until the kernel is done with the processes that
                // just ended.
                Err(e) if e.raw_os_error() == Some(libc::EBUSY) && Instant::now() < deadline => {
                    std::thread::sleep(POLL);
                }
                Err(e) => return Err(format!("rmdir {}: {}", c.display(), io_text(&e))),
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    #[test]
    fn only_armada_paths() {
        assert_eq!(armada_path("/armada/web-r1-0a"), Ok("/armada/web-r1-0a"));
        for bad in [
            "",
            "/armada",
            "/armada/",
            "/armada/..",
            "/armada/a/b",
            "/system.slice/x",
            "armada/x",
            "/armadax/y",
            "/armada/a b",
        ] {
            assert!(armada_path(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            spec_cgroups_path(br#"{"linux":{"cgroupsPath":"/armada/c1"}}"#),
            Some("/armada/c1".into())
        );
        assert_eq!(spec_cgroups_path(br#"{"linux":{}}"#), None);
        assert_eq!(spec_cgroups_path(b"not json"), None);
    }

    /// A stand-in cgroup tree: the container's cgroup and one below it,
    /// each listing a process of this test; both processes end, cgroup.kill
    /// is written, and the tree is removed deepest first.
    #[test]
    fn ends_every_process_and_removes_the_tree() {
        let root = std::env::temp_dir().join(format!("armada-cgroup-end-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let c = root.join("armada/c1");
        fs::create_dir_all(c.join("sub")).unwrap();
        let spawn = || {
            Command::new("sleep")
                .arg("30")
                .stdin(Stdio::null())
                .spawn()
                .unwrap()
        };
        let (mut a, mut b) = (spawn(), spawn());
        fs::write(c.join("cgroup.procs"), format!("{}\n", a.id())).unwrap();
        fs::write(c.join("sub/cgroup.procs"), format!("{}\n", b.id())).unwrap();
        fs::write(c.join("cgroup.kill"), "").unwrap();
        // The parent reaps them, as a shim or init does.
        let reaper = std::thread::spawn(move || (a.wait().unwrap(), b.wait().unwrap()));
        let removed = std::sync::Mutex::new(Vec::new());
        let rmdir = |p: &Path| {
            removed.lock().unwrap().push(p.to_path_buf());
            assert_eq!(fs::read_to_string(c.join("cgroup.kill")).unwrap(), "1");
            fs::remove_dir_all(p)
        };
        assert_eq!(end_with(&root, "/armada/c1", END_WAIT, &rmdir), Ok(true));
        let (sa, sb) = reaper.join().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!((sa.signal(), sb.signal()), (Some(9), Some(9)));
        assert_eq!(*removed.lock().unwrap(), vec![c.join("sub"), c.clone()]);
        assert!(!c.exists());
        // Gone already: nothing to do.
        assert_eq!(end_with(&root, "/armada/c1", END_WAIT, &rmdir), Ok(false));
        // Never outside Armada's cgroups.
        assert!(end_with(&root, "/user.slice", END_WAIT, &rmdir).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    /// A kernel without cgroup.kill: SIGKILL to each listed process.
    #[test]
    fn without_cgroup_kill() {
        let root = std::env::temp_dir().join(format!("armada-cgroup-old-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let c = root.join("armada/c2");
        fs::create_dir_all(&c).unwrap();
        let mut p = Command::new("sleep").arg("30").spawn().unwrap();
        fs::write(c.join("cgroup.procs"), format!("{}\n", p.id())).unwrap();
        let reaper = std::thread::spawn(move || p.wait().unwrap());
        assert_eq!(
            end_with(&root, "/armada/c2", END_WAIT, &|p| fs::remove_dir_all(p)),
            Ok(true)
        );
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(reaper.join().unwrap().signal(), Some(9));
        assert!(!c.join("cgroup.kill").exists());
        let _ = fs::remove_dir_all(&root);
    }
}

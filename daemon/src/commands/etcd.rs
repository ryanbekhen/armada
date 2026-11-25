//! armadad etcd: this server's etcd member run from the runtime pack
//! (Go's etcdunit.go, ADR 0055).

use std::fs;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

use armada_client::cli::{Ctx, Error, Result};

use crate::agentconfig::{DIR_ETCD, FILE_SERVER_CERT};
use crate::{etcdmember, pack};

/// dirEtcdBeforeUnit.
const DIR_ETCD_BEFORE_UNIT: &str = "etcd/data.before-unit";

pub fn run(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let data_dir = ctx.str("data-dir");
    let bin_dir = ctx.str("bin-dir");
    let (bin, config) = prepare(&data_dir, &bin_dir, ctx.err)?;
    let env = etcd_env(std::env::vars_os());
    let err = std::process::Command::new(&bin)
        .arg("--config-file")
        .arg(&config)
        .env_clear()
        .envs(env)
        .exec();
    Err(Error::Msg(armada_fsutil::errno_text(&err)))
}

/// etcdEnv: armadad's environment without etcd's own variables.
fn etcd_env(
    vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    vars.filter(|(k, _)| !k.to_string_lossy().starts_with("ETCD_"))
        .collect()
}

/// prepareEtcd.
fn prepare(
    data_dir: &str,
    bin_dir: &str,
    w: &mut dyn Write,
) -> std::result::Result<(PathBuf, PathBuf), String> {
    let dd = Path::new(data_dir);
    if let Err(e) = fs::metadata(dd.join(FILE_SERVER_CERT))
        && e.kind() == std::io::ErrorKind::NotFound
    {
        return Err(format!(
            "{data_dir} is not a server's data directory; run `armadad init` or `armadad server join`"
        ));
    }
    let mut cfg = etcdmember::etcd_config(data_dir)?;
    let bin = etcd_program(data_dir, bin_dir)?;
    let hold = hold_member(&cfg.dir)?;
    keep_before_unit(dd, w)?;
    let config = etcdmember::write_config_file(&mut cfg)?;
    drop(hold);
    Ok((bin, config))
}

/// etcdProgram: the pinned etcd in bin_dir, else the pack this armadad
/// carries (installed first), else one installed earlier.
fn etcd_program(data_dir: &str, bin_dir: &str) -> std::result::Result<PathBuf, String> {
    let p = crate::paths(data_dir);
    let mut path = p.bin().join(pack::BIN_ETCD);
    if !bin_dir.is_empty() {
        path = Path::new(bin_dir).join(pack::BIN_ETCD);
    } else if !pack::bundled().is_empty() {
        pack::install(&p.bundle(), pack::bundled()).map_err(|e| format!("runtime pack: {e}"))?;
    }
    match fs::metadata(&path) {
        Ok(fi) if fi.is_file() => Ok(path),
        _ => Err(format!(
            "no etcd program at {}: this armadad carries no runtime pack with etcd; pass --bin-dir",
            path.display()
        )),
    }
}

/// holdMember: the lock etcd's database takes, held while the member is
/// copied and its file written.
fn hold_member(dir: &Path) -> std::result::Result<Option<fs::File>, String> {
    let db = dir.join("data").join("member").join("snap").join("db");
    let f = match fs::OpenOptions::new().read(true).write(true).open(&db) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(format!(
                "open {}: {}",
                db.display(),
                armada_fsutil::errno_text(&e)
            ));
        }
    };
    // SAFETY: flock on a descriptor this function owns.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(format!(
                "another process runs the etcd member in {} (armadad server with --etcd-member embedded?); stop it first",
                dir.display()
            ));
        }
        return Err(format!(
            "lock {}: {}",
            db.display(),
            armada_fsutil::errno_text(&e)
        ));
    }
    Ok(Some(f))
}

/// keepBeforeUnit: the member's data copied once, before the pack's etcd
/// first runs on a member that ran.
fn keep_before_unit(dd: &Path, w: &mut dyn Write) -> std::result::Result<(), String> {
    let data = dd.join(DIR_ETCD).join("data");
    let dst = dd.join(DIR_ETCD_BEFORE_UNIT);
    if fs::metadata(data.join("member").join("wal")).is_err() {
        return Ok(());
    }
    if fs::symlink_metadata(&dst).is_ok() {
        return Ok(());
    }
    let tmp = PathBuf::from(format!("{}.tmp", dst.display()));
    remove_all(&tmp)?;
    if let Err(e) = copy_tree(&data, &tmp) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!("copy the etcd member's data: {e}"));
    }
    fs::rename(&tmp, &dst).map_err(|e| {
        format!(
            "rename {} {}: {}",
            tmp.display(),
            dst.display(),
            armada_fsutil::errno_text(&e)
        )
    })?;
    let _ = writeln!(
        w,
        "copied the etcd member's data to {} before its first start from the runtime pack",
        dst.display()
    );
    Ok(())
}

fn remove_all(p: &Path) -> std::result::Result<(), String> {
    match fs::symlink_metadata(p) {
        Err(_) => Ok(()),
        Ok(m) if m.is_dir() => fs::remove_dir_all(p).map_err(|e| {
            format!(
                "unlinkat {}: {}",
                p.display(),
                armada_fsutil::errno_text(&e)
            )
        }),
        Ok(_) => fs::remove_file(p)
            .map_err(|e| format!("remove {}: {}", p.display(), armada_fsutil::errno_text(&e))),
    }
}

/// copyTree: directories and regular files, owner-only, in WalkDir's
/// lexical order.
fn copy_tree(src: &Path, dst: &Path) -> std::result::Result<(), String> {
    let m = fs::symlink_metadata(src)
        .map_err(|e| format!("lstat {}: {}", src.display(), armada_fsutil::errno_text(&e)))?;
    if m.is_dir() {
        armada_fsutil::mkdir_private(dst).map_err(|e| e.to_string())?;
        let mut names: Vec<_> = fs::read_dir(src)
            .map_err(|e| format!("open {}: {}", src.display(), armada_fsutil::errno_text(&e)))?
            .flatten()
            .map(|e| e.file_name())
            .collect();
        names.sort();
        for n in names {
            copy_tree(&src.join(&n), &dst.join(&n))?;
        }
        Ok(())
    } else if m.is_file() {
        copy_file(src, dst)
    } else {
        Err(format!(
            "{} is not a regular file or directory",
            src.display()
        ))
    }
}

fn copy_file(src: &Path, dst: &Path) -> std::result::Result<(), String> {
    let errno = |op: &str, p: &Path, e: std::io::Error| {
        format!("{op} {}: {}", p.display(), armada_fsutil::errno_text(&e))
    };
    let mut input = fs::File::open(src).map_err(|e| errno("open", src, e))?;
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dst)
        .map_err(|e| errno("open", dst, e))?;
    std::io::copy(&mut input, &mut out).map_err(|e| e.to_string())?;
    out.sync_all().map_err(|e| errno("sync", dst, e))
}

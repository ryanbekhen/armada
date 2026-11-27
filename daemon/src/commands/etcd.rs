//! armadad etcd: this server's etcd member run from the runtime pack
//! (armada-etcd.service).

use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

use armada_client::cli::{Ctx, Error, Result};

use crate::agentconfig::FILE_SERVER_CERT;
use crate::{etcdmember, pack};

pub fn run(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let data_dir = ctx.str("data-dir");
    let bin_dir = ctx.str("bin-dir");
    let (bin, config) = prepare(&data_dir, &bin_dir)?;
    let env = etcd_env(std::env::vars_os());
    let err = std::process::Command::new(&bin)
        .arg("--config-file")
        .arg(&config)
        .env_clear()
        .envs(env)
        .exec();
    Err(Error::Msg(armada_fsutil::errno_text(&err)))
}

/// armadad's environment without etcd's own variables.
fn etcd_env(
    vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    vars.filter(|(k, _)| !k.to_string_lossy().starts_with("ETCD_"))
        .collect()
}

fn prepare(data_dir: &str, bin_dir: &str) -> std::result::Result<(PathBuf, PathBuf), String> {
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
    let config = etcdmember::write_config_file(&mut cfg)?;
    drop(hold);
    Ok((bin, config))
}

/// The pinned etcd in bin_dir, else the pack this armadad
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

/// The lock etcd's database takes, held while the member is
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
                "another process runs the etcd member in {}; stop it first",
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

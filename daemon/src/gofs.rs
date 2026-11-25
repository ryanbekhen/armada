//! os.MkdirAll with Go's errors: the directory that could not be made is
//! named (`mkdir /run/armada: permission denied`).

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

/// os.MkdirAll(path, mode).
pub fn mkdir_all(path: &Path, mode: u32) -> Result<(), String> {
    if let Ok(m) = fs::metadata(path) {
        if m.is_dir() {
            return Ok(());
        }
        return Err(format!("mkdir {}: not a directory", path.display()));
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && parent != path
    {
        mkdir_all(parent, mode)?;
    }
    match fs::DirBuilder::new().mode(mode).create(path) {
        Ok(()) => Ok(()),
        Err(e) => {
            if fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
                return Ok(());
            }
            Err(format!(
                "mkdir {}: {}",
                path.display(),
                armada_fsutil::errno_text(&e)
            ))
        }
    }
}

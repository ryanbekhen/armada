//! Mounts as containerd's core/mount describes and makes them: the
//! mount.Mount JSON a snapshot's root filesystem is handed over in,
//! Mount.Mount (parseMountOptions, compactLowerdirOption, mountAt, the
//! read-only bind remount), and UnmountAll.

use super::errno_text;
use crate::net::addr::quote;
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// mount.Mount, which has no JSON tags: its field names as they are.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Mount {
    #[serde(rename = "Type")]
    pub kind: String,
    pub source: String,
    pub target: String,
    #[serde(deserialize_with = "crate::runtime::nullable")]
    pub options: Vec<String>,
}

const MS_RDONLY: u64 = libc::MS_RDONLY;
const MS_BIND: u64 = libc::MS_BIND;
const MS_REC: u64 = libc::MS_REC;
const MS_REMOUNT: u64 = libc::MS_REMOUNT;
const PTYPES: u64 = libc::MS_SHARED | libc::MS_PRIVATE | libc::MS_SLAVE | libc::MS_UNBINDABLE;

/// parseMountOptions' flag table: (clear, flag).
fn flag(o: &str) -> Option<(bool, u64)> {
    Some(match o {
        "async" => (true, libc::MS_SYNCHRONOUS),
        "atime" => (true, libc::MS_NOATIME),
        "bind" => (false, MS_BIND),
        "defaults" => (false, 0),
        "dev" => (true, libc::MS_NODEV),
        "diratime" => (true, libc::MS_NODIRATIME),
        "dirsync" => (false, libc::MS_DIRSYNC),
        "exec" => (true, libc::MS_NOEXEC),
        "mand" => (false, libc::MS_MANDLOCK),
        "noatime" => (false, libc::MS_NOATIME),
        "nodev" => (false, libc::MS_NODEV),
        "nodiratime" => (false, libc::MS_NODIRATIME),
        "noexec" => (false, libc::MS_NOEXEC),
        "nomand" => (true, libc::MS_MANDLOCK),
        "norelatime" => (true, libc::MS_RELATIME),
        "nostrictatime" => (true, libc::MS_STRICTATIME),
        "nosuid" => (false, libc::MS_NOSUID),
        "rbind" => (false, MS_BIND | MS_REC),
        "relatime" => (false, libc::MS_RELATIME),
        "remount" => (false, MS_REMOUNT),
        "ro" => (false, MS_RDONLY),
        "rw" => (true, MS_RDONLY),
        "strictatime" => (false, libc::MS_STRICTATIME),
        "suid" => (true, libc::MS_NOSUID),
        "sync" => (false, libc::MS_SYNCHRONOUS),
        _ => return None,
    })
}

/// The flags and file system data of a mount's options. Loop devices,
/// ID mappings, and helper programs are not used by the runtime's
/// snapshots and are refused.
pub fn parse_options(options: &[String]) -> Result<(u64, Vec<String>), String> {
    let mut flags = 0u64;
    let mut data = Vec::new();
    for o in options {
        if o.starts_with("X-containerd.") {
            return Err(format!(
                "internal mount option {} was not consumed by the mount manager",
                quote(o)
            ));
        }
        match flag(o) {
            Some((clear, f)) if f != 0 => {
                if clear {
                    flags &= !f;
                } else {
                    flags |= f;
                }
            }
            _ if o == "loop" || o.starts_with("uidmap=") || o.starts_with("gidmap=") => {
                return Err(format!("mount option {} is not supported", quote(o)));
            }
            _ => data.push(o.clone()),
        }
    }
    Ok((flags, data))
}

fn page_size() -> usize {
    // SAFETY: sysconf has no preconditions.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n > 0 { n as usize } else { 4096 }
}

/// longestCommonPrefix of strings, by the smallest and largest of them.
fn longest_common_prefix(strs: &[&str]) -> String {
    let (Some(min), Some(max)) = (strs.iter().min(), strs.iter().max()) else {
        return String::new();
    };
    let n = min
        .bytes()
        .zip(max.bytes())
        .take_while(|(a, b)| a == b)
        .count();
    min[..n].to_string()
}

/// compactLowerdirOption: the lower directories relative to the
/// directory they share, which the mount is made from.
pub fn compact_lowerdir(opts: &[String]) -> (String, Vec<String>) {
    let Some(idx) = opts.iter().position(|o| o.starts_with("lowerdir=")) else {
        return (String::new(), opts.to_vec());
    };
    let dirs: Vec<&str> = opts[idx]["lowerdir=".len()..].split(':').collect();
    if dirs.len() == 1 {
        return (String::new(), opts.to_vec());
    }
    let common = longest_common_prefix(&dirs);
    if common.is_empty() {
        return (String::new(), opts.to_vec());
    }
    let common = crate::runtime::gopath::dir(&common);
    if common == "/" || common == "." {
        return (String::new(), opts.to_vec());
    }
    let common = common + "/";
    let mut newdirs = Vec::with_capacity(dirs.len());
    for d in &dirs {
        if d.len() <= common.len() {
            return (String::new(), opts.to_vec());
        }
        newdirs.push(&d[common.len()..]);
    }
    let mut out = opts.to_vec();
    out.remove(idx);
    out.push(format!("lowerdir={}", newdirs.join(":")));
    (common, out)
}

fn cstr(s: &[u8]) -> Result<CString, String> {
    CString::new(s).map_err(|_| "invalid argument".to_string())
}

fn sys_mount(source: &str, target: &Path, fstype: &str, flags: u64, data: &str) -> io::Result<()> {
    let (s, t, f, d) = (
        cstr(source.as_bytes()),
        cstr(target.as_os_str().as_bytes()),
        cstr(fstype.as_bytes()),
        cstr(data.as_bytes()),
    );
    let (Ok(s), Ok(t), Ok(f), Ok(d)) = (s, t, f, d) else {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    };
    // SAFETY: every pointer is a NUL-terminated string that outlives the call.
    let r = unsafe {
        libc::mount(
            if source.is_empty() {
                std::ptr::null()
            } else {
                s.as_ptr()
            },
            t.as_ptr(),
            if fstype.is_empty() {
                std::ptr::null()
            } else {
                f.as_ptr()
            },
            flags,
            if data.is_empty() {
                std::ptr::null()
            } else {
                d.as_ptr().cast()
            },
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn os_errno(e: &io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

/// mountAt: the mount, made from chdir when it is set (this program
/// runs one request on one thread, so it changes its own directory and
/// changes it back).
fn mount_at(
    chdir: &str,
    source: &str,
    target: &Path,
    fstype: &str,
    flags: u64,
    data: &str,
) -> Result<(), String> {
    let describe = |e: &io::Error| {
        format!(
            "mount source: {}, target: {}, fstype: {fstype}, flags: {flags}, data: {}, err: {}",
            quote(source),
            quote(&target.to_string_lossy()),
            quote(data),
            errno_text(os_errno(e))
        )
    };
    if chdir.is_empty() {
        return sys_mount(source, target, fstype, flags, data).map_err(|e| describe(&e));
    }
    let back = std::env::current_dir().map_err(|e| errno_text(os_errno(&e)))?;
    std::env::set_current_dir(chdir).map_err(|e| errno_text(os_errno(&e)))?;
    let r = sys_mount(source, target, fstype, flags, data).map_err(|e| describe(&e));
    let _ = std::env::set_current_dir(back);
    r
}

impl Mount {
    /// Mount.Mount onto target (the mount's own Target is not used by
    /// the runtime's snapshots and must be empty).
    pub fn mount(&self, target: &Path) -> Result<(), String> {
        if !self.target.is_empty() {
            return Err(format!(
                "mount target {} is not supported",
                quote(&self.target)
            ));
        }
        let (mut flags, mut data) = parse_options(&self.options)?;
        let mut chdir = String::new();
        let size: usize = self.options.iter().map(String::len).sum();
        if self.kind == "overlay" && size >= page_size() - 512 {
            let (c, opts) = compact_lowerdir(&self.options);
            chdir = c;
            (flags, data) = parse_options(&opts)?;
        }
        let oflags = flags & !PTYPES;
        let data = data.join(",");
        if data.len() > page_size() {
            return Err("mount options is too long".into());
        }
        if flags & MS_REMOUNT == 0 || !data.is_empty() {
            mount_at(&chdir, &self.source, target, &self.kind, oflags, &data)?;
        }
        if flags & PTYPES != 0 {
            let pflags = PTYPES | MS_REC | libc::MS_SILENT;
            sys_mount("", target, "", flags & pflags, "").map_err(|e| errno_text(os_errno(&e)))?;
        }
        if oflags & (MS_BIND | MS_RDONLY) == MS_BIND | MS_RDONLY {
            sys_mount("", target, "", oflags | MS_REMOUNT, "")
                .map_err(|e| errno_text(os_errno(&e)))?;
        }
        Ok(())
    }
}

/// mount.All: each mount onto target in order.
pub fn mount_all(mounts: &[Mount], target: &Path) -> Result<(), String> {
    for m in mounts {
        m.mount(target)?;
    }
    Ok(())
}

/// unmount: umount2, waiting out EBUSY up to 50 times.
fn unmount(target: &Path) -> Result<(), i32> {
    let t = CString::new(target.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
    for _ in 0..50 {
        // SAFETY: t is a NUL-terminated path.
        if unsafe { libc::umount2(t.as_ptr(), 0) } == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if e == libc::EBUSY {
            std::thread::sleep(std::time::Duration::from_millis(50));
            continue;
        }
        return Err(e);
    }
    Err(-libc::EBUSY)
}

/// Unmounts every mount stacked on target until none is left (EINVAL);
/// nothing when target does not exist. The error is its text and errno.
pub fn unmount_all(target: &Path) -> Result<(), (String, i32)> {
    if std::fs::metadata(target).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
        return Ok(());
    }
    loop {
        match unmount(target) {
            Ok(()) => {}
            Err(libc::EINVAL) => return Ok(()),
            Err(e) if e < 0 => {
                return Err((
                    format!(
                        "failed to unmount target {}: {}",
                        target.display(),
                        errno_text(-e)
                    ),
                    -e,
                ));
            }
            Err(e) => return Err((errno_text(e), e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn options_as_containerd() {
        let (f, d) = parse_options(&s(&["rw", "rbind"])).unwrap();
        assert_eq!(f, MS_BIND | MS_REC);
        assert!(d.is_empty());
        let (f, d) = parse_options(&s(&[
            "workdir=/w",
            "upperdir=/u",
            "lowerdir=/a:/b",
            "index=off",
        ]))
        .unwrap();
        assert_eq!(f, 0);
        assert_eq!(
            d,
            s(&["workdir=/w", "upperdir=/u", "lowerdir=/a:/b", "index=off"])
        );
        assert!(parse_options(&s(&["uidmap=0:1:2"])).is_err());
        assert!(parse_options(&s(&["X-containerd.mkdir.path=/x"])).is_err());
    }

    #[test]
    fn compacts_as_containerd() {
        let (dir, o) = compact_lowerdir(&s(&[
            "workdir=/r/a/w",
            "lowerdir=/r/layers/ab12:/r/layers/ab34",
            "index=off",
        ]));
        assert_eq!(dir, "/r/layers/");
        assert_eq!(o, s(&["workdir=/r/a/w", "index=off", "lowerdir=ab12:ab34"]));
        let (dir, o) = compact_lowerdir(&s(&["lowerdir=/r/layers/ab12"]));
        assert_eq!(dir, "");
        assert_eq!(o, s(&["lowerdir=/r/layers/ab12"]));
        let (dir, _) = compact_lowerdir(&s(&["lowerdir=/a:/b"]));
        assert_eq!(dir, "");
    }
}

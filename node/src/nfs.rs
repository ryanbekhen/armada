//! NFS volumes' mounts on the node (ADR 0042):
//!
//!   armada-node nfs mount     stdin {"server", "path", "target",
//!                             "readOnly", "timeoutMs"}; stdout {} or
//!                             {"error": TEXT}: the export checked again,
//!                             then mounted (nfs4, nosuid and nodev, hard,
//!                             over TCP, 4.2 then 4.1 then 4.0)
//!   armada-node nfs unmount   stdin {"target"}: unmounted (detached)
//!   armada-node nfs source    stdin {"target", "export", "mountinfo"?}; stdout
//!                             {"source", "mounted", "readOnly"} or
//!                             {"error"}: what is mounted there, and
//!                             whether read-only
//!   armada-node nfs plan      stdin as mount plus "selinux" and "errnos";
//!                             stdout {"calls", "error"?}: the mount(2)
//!                             calls mount makes when the kernel answers
//!                             with errnos in turn (tests; no mount made)

use crate::net::addr::Addr;
use crate::runtime::container::errno_text;
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::time::{Duration, Instant};

/// The label NFS mounts get on SELinux systems, so containers may use them.
const NFS_CONTEXT: &str = "system_u:object_r:container_file_t:s0";
/// spec.maxNFSPath.
const MAX_NFS_PATH: usize = 256;
const SELINUX_MAGIC: i64 = 0xf97cff8c;
const SELINUXFS_MOUNT: &str = "/sys/fs/selinux";
/// bufio.Scanner's longest line as mountedSource sets it.
const MAX_LINE: usize = 1 << 20;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Request {
    server: String,
    path: String,
    target: String,
    #[serde(rename = "readOnly")]
    read_only: bool,
    #[serde(rename = "timeoutMs")]
    timeout_ms: u64,
    mountinfo: String,
    /// The source whose mount's read-only flag is asked (prepareNFS's
    /// want): another source's file system is never looked at.
    export: String,
    selinux: bool,
    errnos: Vec<i32>,
}

/// One mount(2) call.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Call {
    source: String,
    target: String,
    fstype: String,
    flags: u64,
    data: String,
}

/// spec.CheckNFSServer.
fn check_server(s: &str) -> Result<(), String> {
    let ip = match Addr::parse(s) {
        Some(ip) if ip.zone().is_empty() => ip.unmap(),
        _ => return Err("must be an IP address".into()),
    };
    let shared = match &ip {
        Addr::V4(b) => b[0] == 100 && (b[1] & 0xc0) == 64,
        Addr::V6(..) => false,
    };
    if !ip.is_private() && !shared {
        return Err(
            "must be a private address (10/8, 172.16/12, 192.168/16, 100.64/10, or fc00::/7)"
                .into(),
        );
    }
    Ok(())
}

/// spec.CheckNFSPath.
fn check_path(p: &str) -> Result<(), String> {
    let chars_ok = p.starts_with('/')
        && p.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'/' | b'-'));
    if p.len() > MAX_NFS_PATH || !chars_ok || crate::runtime::gopath::clean(p) != p {
        return Err(format!(
            "must be an absolute, clean path of letters, digits, '.', '_', '-', and '/', at most {MAX_NFS_PATH} characters"
        ));
    }
    Ok(())
}

/// The export as the kernel names it.
pub fn nfs_source(server: &str, path: &str) -> String {
    match Addr::parse(server) {
        Some(Addr::V6(..)) => format!("[{server}]:{path}"),
        _ => format!("{server}:{path}"),
    }
}

/// selinux.GetEnabled (go-selinux): an selinuxfs mounted read-write, and
/// this thread's label other than "kernel".
pub fn selinux_enabled() -> bool {
    if selinux_mount().is_empty() {
        return false;
    }
    let label = std::fs::read("/proc/thread-self/attr/current")
        .map(|mut b| {
            if b.last() == Some(&0) {
                b.pop();
            }
            b
        })
        .unwrap_or_default();
    label != b"kernel"
}

fn verify_selinuxfs(mnt: &str) -> bool {
    let Ok(c) = CString::new(mnt) else {
        return false;
    };
    // SAFETY: an all-zero statfs is valid and statfs fills it.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    loop {
        // SAFETY: a NUL-terminated path and a statfs.
        if unsafe { libc::statfs(c.as_ptr(), &mut st) } == 0 {
            break;
        }
        let e = std::io::Error::last_os_error().raw_os_error();
        if e != Some(libc::EAGAIN) && e != Some(libc::EINTR) {
            return false;
        }
    }
    (st.f_type as i64 & 0xffff_ffff) == SELINUX_MAGIC && !read_only(&c)
}

/// Statfs's ST_RDONLY flag (statvfs reads the same flags).
fn read_only(c: &CString) -> bool {
    // SAFETY: an all-zero statvfs is valid and statvfs fills it.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path and a statvfs.
    unsafe { libc::statvfs(c.as_ptr(), &mut st) == 0 && (st.f_flag & libc::ST_RDONLY) != 0 }
}

/// Where selinuxfs is mounted read-write, or "".
pub fn selinux_mount() -> String {
    if verify_selinuxfs(SELINUXFS_MOUNT) {
        return SELINUXFS_MOUNT.into();
    }
    match std::fs::read("/proc/filesystems") {
        Ok(b) if b.windows(11).any(|w| w == b"\tselinuxfs\n") => {}
        _ => return String::new(),
    }
    let Ok(info) = std::fs::read("/proc/self/mountinfo") else {
        return String::new();
    };
    for line in info.split(|&c| c == b'\n') {
        if !line.windows(13).any(|w| w == b" - selinuxfs ") {
            continue;
        }
        let fields: Vec<&[u8]> = line.splitn(6, |&c| c == b' ').collect();
        if fields.len() < 6 {
            continue;
        }
        let mnt = String::from_utf8_lossy(fields[4]).into_owned();
        // findSELinuxfsMount's first find ends the search when it fails.
        return if verify_selinuxfs(&mnt) {
            mnt
        } else {
            String::new()
        };
    }
    String::new()
}

/// A mount(2) call, bounded by a deadline.
type MountFn<'a> = dyn FnMut(&Call, Option<Instant>) -> Result<(), MountError> + 'a;

/// The mount(2) calls of mountNFS, the kernel answering through sys.
fn mount_with(
    r: &Request,
    selinux: bool,
    deadline: Option<Instant>,
    sys: &mut MountFn,
) -> Result<(), String> {
    let mut flags = libc::MS_NOSUID | libc::MS_NODEV;
    if r.read_only {
        flags |= libc::MS_RDONLY;
    }
    let mut last = String::new();
    for vers in ["4.2", "4.1", "4.0"] {
        let mut data = format!(
            "vers={vers},proto=tcp,hard,timeo=600,retrans=2,addr={}",
            r.server
        );
        if selinux {
            data.push_str(&format!(",context=\"{NFS_CONTEXT}\""));
        }
        let call = Call {
            source: nfs_source(&r.server, &r.path),
            target: r.target.clone(),
            fstype: "nfs4".into(),
            flags,
            data,
        };
        match sys(&call, deadline) {
            Ok(()) => return Ok(()),
            Err(MountError::Timeout) => {
                return Err("the server did not answer: context deadline exceeded".into());
            }
            Err(MountError::Errno(e)) => {
                last = errno_text(e);
                if e != libc::EPROTONOSUPPORT && e != libc::EINVAL {
                    return Err(last);
                }
            }
        }
    }
    Err(last)
}

enum MountError {
    Errno(i32),
    Timeout,
}

fn sys_mount(c: &Call) -> Result<(), i32> {
    let cs = |s: &str| CString::new(s).map_err(|_| libc::EINVAL);
    let (source, target, fstype, data) =
        (cs(&c.source)?, cs(&c.target)?, cs(&c.fstype)?, cs(&c.data)?);
    // SAFETY: NUL-terminated strings that live through the call.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            c.flags,
            data.as_ptr().cast(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO));
    }
    Ok(())
}

/// The real mount, bounded by the deadline: the call runs on a thread of
/// its own, which the process leaves behind when the server does not
/// answer in time.
fn real_mount(c: &Call, deadline: Option<Instant>) -> Result<(), MountError> {
    let (tx, rx) = std::sync::mpsc::channel();
    let call = c.clone();
    std::thread::spawn(move || {
        let _ = tx.send(sys_mount(&call));
    });
    let got = match deadline {
        None => rx.recv().map_err(|_| ()),
        Some(d) => rx
            .recv_timeout(d.saturating_duration_since(Instant::now()))
            .map_err(|_| ()),
    };
    match got {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(MountError::Errno(e)),
        Err(()) => Err(MountError::Timeout),
    }
}

/// nfs mount: the checks prepareNFS makes before calling the kernel, then
/// mountNFS.
fn mount(r: &Request) -> Result<(), String> {
    check_server(&r.server).map_err(|e| format!("NFS server: {e}"))?;
    check_path(&r.path).map_err(|e| format!("NFS path: {e}"))?;
    let deadline = (r.timeout_ms > 0).then(|| Instant::now() + Duration::from_millis(r.timeout_ms));
    mount_with(r, selinux_enabled(), deadline, &mut real_mount)
}

/// unmountNFS.
fn unmount(target: &str) -> Result<(), String> {
    let c = CString::new(target).map_err(|_| errno_text(libc::EINVAL))?;
    // SAFETY: a NUL-terminated path.
    if unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) } != 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if e != libc::EINVAL && e != libc::ENOENT {
            return Err(errno_text(e));
        }
    }
    Ok(())
}

/// mountinfo's octal escapes undone. The kernel writes
/// every escape as a backslash and exactly three octal digits (`\040`
/// for a space), so only that form is decoded; anything else (a
/// backslash before fewer digits, a value past 255, a backslash at the
/// end) is kept as it is, never half decoded.
pub fn unescape_mount(s: &[u8]) -> Vec<u8> {
    if !s.contains(&b'\\') {
        return s.to_vec();
    }
    let octal = |c: u8| (b'0'..=b'7').contains(&c).then(|| u32::from(c - b'0'));
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'\\'
            && let Some(d) = s.get(i + 1..i + 4)
            && let (Some(a), Some(b), Some(c)) = (octal(d[0]), octal(d[1]), octal(d[2]))
            && a * 64 + b * 8 + c <= 255
        {
            out.push((a * 64 + b * 8 + c) as u8);
            i += 4;
            continue;
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

/// mountedSource on the mountinfo text: the NFS source mounted on target
/// last, as a bufio.Scanner with a 1 MiB limit reads its lines.
pub fn mounted_source(info: &[u8], target: &str) -> (String, bool, Option<String>) {
    let mut source = String::new();
    let mut found = false;
    let mut rest = info;
    while !rest.is_empty() {
        let (mut line, next) = match rest.iter().position(|&c| c == b'\n') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, &rest[rest.len()..]),
        };
        if line.len() >= MAX_LINE {
            return (source, found, Some("bufio.Scanner: token too long".into()));
        }
        rest = next;
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        let fields = crate::gostr::fields(line);
        if fields.len() < 10 || unescape_mount(fields[4]) != target.as_bytes() {
            continue;
        }
        for (i, f) in fields.iter().enumerate() {
            if *f == b"-" && i + 2 < fields.len() {
                if fields[i + 1].starts_with(b"nfs") {
                    source = String::from_utf8_lossy(fields[i + 2]).into_owned();
                    found = true;
                } else {
                    source.clear();
                    found = false;
                }
                break;
            }
        }
    }
    (source, found, None)
}

/// How long the read-only flag of a mounted export may take: statfs on
/// a hard NFS mount whose server is gone waits for it without end.
const STAT_TIMEOUT: Duration = Duration::from_secs(10);

/// What `within` answers when f did not end in time.
fn not_answering(target: &str) -> String {
    format!("the NFS mount on {target} does not answer")
}

/// Runs f on a thread of its own and waits for it at most limit; None
/// when it did not end in time (the thread is left behind, and the
/// process leaves once it answered).
fn within<T: Send + 'static>(limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit).ok()
}

/// mountedReadOnly, bounded by STAT_TIMEOUT.
fn mounted_read_only(target: &str) -> Result<bool, String> {
    let Ok(c) = CString::new(target) else {
        return Ok(false);
    };
    within(STAT_TIMEOUT, move || read_only(&c)).ok_or_else(|| not_answering(target))
}

/// nfs source's answer; the flag says a statfs did not end in time, so
/// the process must leave without waiting for its thread.
fn source(r: &Request) -> (serde_json::Value, bool) {
    let path = if r.mountinfo.is_empty() {
        "/proc/self/mountinfo"
    } else {
        &r.mountinfo
    };
    let info = match read_mountinfo(path) {
        Ok(b) => b,
        Err(e) => return (serde_json::json!({ "error": e }), false),
    };
    match mounted_source(&info, &r.target) {
        (_, _, Some(e)) => (serde_json::json!({ "error": e }), false),
        (source, mounted, None) => {
            let read_only = if mounted && source == r.export {
                match mounted_read_only(&r.target) {
                    Ok(ro) => ro,
                    Err(e) => return (serde_json::json!({ "error": e }), true),
                }
            } else {
                false
            };
            (
                serde_json::json!({
                    "source": source,
                    "mounted": mounted,
                    "readOnly": read_only,
                }),
                false,
            )
        }
    }
}

fn read_mountinfo(path: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let errno = |e: &std::io::Error| errno_text(e.raw_os_error().unwrap_or(libc::EIO));
    let mut f = std::fs::File::open(path).map_err(|e| format!("open {path}: {}", errno(&e)))?;
    let mut b = Vec::new();
    f.read_to_end(&mut b)
        .map_err(|e| format!("read {path}: {}", errno(&e)))?;
    Ok(b)
}

/// armada-node nfs mount|unmount|source|plan.
pub fn command(op: &str) -> Result<(), String> {
    let r: Request = serde_json::from_slice(&crate::runtime::read_stdin()?)
        .map_err(|e| format!("read request: {e}"))?;
    let result = |res: Result<(), String>| match res {
        Ok(()) => serde_json::json!({}),
        Err(e) => serde_json::json!({ "error": e }),
    };
    let mut hung = false;
    let out = match op {
        "mount" => result(mount(&r)),
        "unmount" => result(unmount(&r.target)),
        "source" => {
            let (v, h) = source(&r);
            hung = h;
            v
        }
        "plan" => {
            let mut calls = Vec::new();
            let mut errnos = r.errnos.iter();
            let res = mount_with(&r, r.selinux, None, &mut |c, _| {
                calls.push(c.clone());
                match errnos.next() {
                    Some(&0) | None => Ok(()),
                    Some(&e) => Err(MountError::Errno(e)),
                }
            });
            let mut v = serde_json::json!({ "calls": calls });
            if let Err(e) = res {
                v["error"] = e.into();
            }
            v
        }
        _ => {
            return Err(format!(
                "unknown nfs command {op:?}; try mount, unmount, source, or plan"
            ));
        }
    };
    crate::runtime::write_out(&crate::runtime::spec::to_go_json(&out))?;
    if op == "mount" || hung {
        // A mount or statfs the server never answered may still hold a
        // thread: the answer is out, so leave at once.
        // SAFETY: _exit ends the process without running destructors.
        unsafe { libc::_exit(0) };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_of_last_mount() {
        let info = b"36 35 98:0 / /data/nfs/web/files rw,nosuid - nfs4 10.0.0.5:/exports/a rw\n\
37 35 98:0 / /data/nfs/web/files rw - nfs4 10.0.0.6:/exports/b rw\n\
38 35 98:0 / /data/nfs/web/oth\\040er rw - ext4 /dev/sda rw\n";
        assert_eq!(
            mounted_source(info, "/data/nfs/web/files"),
            ("10.0.0.6:/exports/b".into(), true, None)
        );
        assert_eq!(
            mounted_source(info, "/data/nfs/web/oth er"),
            (String::new(), false, None)
        );
        assert_eq!(unescape_mount(b"a\\040b\\134c"), b"a b\\c");
        // Only a backslash and three octal digits is an escape: a shorter
        // or larger one, or a backslash at the end, stays as written.
        assert_eq!(unescape_mount(b"a\\04x"), b"a\\04x");
        assert_eq!(unescape_mount(b"a\\04"), b"a\\04");
        assert_eq!(unescape_mount(b"a\\7"), b"a\\7");
        assert_eq!(unescape_mount(b"a\\"), b"a\\");
        assert_eq!(unescape_mount(b"a\\777b"), b"a\\777b");
        assert_eq!(unescape_mount(b"a\\08b"), b"a\\08b");
        assert_eq!(unescape_mount(b"\\\\040"), b"\\ ");
    }

    #[test]
    fn statfs_is_bounded() {
        assert_eq!(within(Duration::from_secs(5), || 7), Some(7));
        let start = Instant::now();
        let hung = within(Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_secs(3600));
        });
        assert!(hung.is_none() && start.elapsed() < Duration::from_secs(5));
        assert_eq!(
            not_answering("/var/lib/armada/nfs/web/files"),
            "the NFS mount on /var/lib/armada/nfs/web/files does not answer"
        );
    }

    #[test]
    fn plan_falls_back_through_versions() {
        let r = Request {
            server: "fd00::5".into(),
            path: "/exports".into(),
            target: "/t".into(),
            read_only: true,
            ..Default::default()
        };
        let mut calls = Vec::new();
        let mut errs = vec![libc::EPROTONOSUPPORT, libc::EINVAL, libc::EINVAL].into_iter();
        let res = mount_with(&r, true, None, &mut |c, _| {
            calls.push(c.clone());
            Err(MountError::Errno(errs.next().unwrap()))
        });
        assert_eq!(res, Err("invalid argument".into()));
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].source, "[fd00::5]:/exports");
        assert!(calls[2].data.starts_with("vers=4.0,"));
        assert!(
            calls[0]
                .data
                .ends_with(",context=\"system_u:object_r:container_file_t:s0\"")
        );
        assert_eq!(
            calls[0].flags,
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_RDONLY
        );
        assert!(check_server("8.8.8.8").is_err());
        assert!(check_server("100.64.1.1").is_ok());
        assert!(check_path("/a/../b").is_err());
    }
}

//! The users and groups of an image (containerd's pkg/oci user options and
//! moby/sys/user's parsers): /etc/passwd and /etc/group read from the
//! container's root filesystem, symbolic links resolved inside it as
//! containerd's resolveInRootFS does, never outside it.

use std::ffi::CString;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// An error's text ("OP PATH: ERRNO TEXT"), and whether it means the file
/// does not exist.
#[derive(Debug, Clone, PartialEq)]
pub struct FsError {
    pub text: String,
    pub not_exist: bool,
}

impl FsError {
    fn errno(op: &str, path: &str, errno: i32) -> FsError {
        FsError {
            text: format!("{op} {path}: {}", errno_text(errno)),
            not_exist: errno == libc::ENOENT,
        }
    }

    fn plain(text: String) -> FsError {
        FsError {
            text,
            not_exist: false,
        }
    }
}

/// The text of a Linux errno (the same for
/// amd64 and arm64 but for 133, which only arm64's names).
pub fn errno_text(e: i32) -> String {
    let text = match e {
        1 => "operation not permitted",
        2 => "no such file or directory",
        3 => "no such process",
        4 => "interrupted system call",
        5 => "input/output error",
        6 => "no such device or address",
        7 => "argument list too long",
        8 => "exec format error",
        9 => "bad file descriptor",
        10 => "no child processes",
        11 => "resource temporarily unavailable",
        12 => "cannot allocate memory",
        13 => "permission denied",
        14 => "bad address",
        15 => "block device required",
        16 => "device or resource busy",
        17 => "file exists",
        18 => "invalid cross-device link",
        19 => "no such device",
        20 => "not a directory",
        21 => "is a directory",
        22 => "invalid argument",
        23 => "too many open files in system",
        24 => "too many open files",
        25 => "inappropriate ioctl for device",
        26 => "text file busy",
        27 => "file too large",
        28 => "no space left on device",
        29 => "illegal seek",
        30 => "read-only file system",
        31 => "too many links",
        32 => "broken pipe",
        33 => "numerical argument out of domain",
        34 => "numerical result out of range",
        35 => "resource deadlock avoided",
        36 => "file name too long",
        37 => "no locks available",
        38 => "function not implemented",
        39 => "directory not empty",
        40 => "too many levels of symbolic links",
        42 => "no message of desired type",
        43 => "identifier removed",
        44 => "channel number out of range",
        45 => "level 2 not synchronized",
        46 => "level 3 halted",
        47 => "level 3 reset",
        48 => "link number out of range",
        49 => "protocol driver not attached",
        50 => "no CSI structure available",
        51 => "level 2 halted",
        52 => "invalid exchange",
        53 => "invalid request descriptor",
        54 => "exchange full",
        55 => "no anode",
        56 => "invalid request code",
        57 => "invalid slot",
        59 => "bad font file format",
        60 => "device not a stream",
        61 => "no data available",
        62 => "timer expired",
        63 => "out of streams resources",
        64 => "machine is not on the network",
        65 => "package not installed",
        66 => "object is remote",
        67 => "link has been severed",
        68 => "advertise error",
        69 => "srmount error",
        70 => "communication error on send",
        71 => "protocol error",
        72 => "multihop attempted",
        73 => "RFS specific error",
        74 => "bad message",
        75 => "value too large for defined data type",
        76 => "name not unique on network",
        77 => "file descriptor in bad state",
        78 => "remote address changed",
        79 => "can not access a needed shared library",
        80 => "accessing a corrupted shared library",
        81 => ".lib section in a.out corrupted",
        82 => "attempting to link in too many shared libraries",
        83 => "cannot exec a shared library directly",
        84 => "invalid or incomplete multibyte or wide character",
        85 => "interrupted system call should be restarted",
        86 => "streams pipe error",
        87 => "too many users",
        88 => "socket operation on non-socket",
        89 => "destination address required",
        90 => "message too long",
        91 => "protocol wrong type for socket",
        92 => "protocol not available",
        93 => "protocol not supported",
        94 => "socket type not supported",
        95 => "operation not supported",
        96 => "protocol family not supported",
        97 => "address family not supported by protocol",
        98 => "address already in use",
        99 => "cannot assign requested address",
        100 => "network is down",
        101 => "network is unreachable",
        102 => "network dropped connection on reset",
        103 => "software caused connection abort",
        104 => "connection reset by peer",
        105 => "no buffer space available",
        106 => "transport endpoint is already connected",
        107 => "transport endpoint is not connected",
        108 => "cannot send after transport endpoint shutdown",
        109 => "too many references: cannot splice",
        110 => "connection timed out",
        111 => "connection refused",
        112 => "host is down",
        113 => "no route to host",
        114 => "operation already in progress",
        115 => "operation now in progress",
        116 => "stale file handle",
        117 => "structure needs cleaning",
        118 => "not a XENIX named type file",
        119 => "no XENIX semaphores available",
        120 => "is a named type file",
        121 => "remote I/O error",
        122 => "disk quota exceeded",
        123 => "no medium found",
        124 => "wrong medium type",
        125 => "operation canceled",
        126 => "required key not available",
        127 => "key has expired",
        128 => "key has been revoked",
        129 => "key was rejected by service",
        130 => "owner died",
        131 => "state not recoverable",
        132 => "operation not possible due to RF-kill",
        #[cfg(target_arch = "aarch64")]
        133 => "memory page has hardware error",
        _ => return format!("errno {e}"),
    };
    text.to_string()
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// struct open_how of openat2(2).
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

/// A container's root filesystem, opened once.
pub struct Rootfs {
    dir: OwnedFd,
}

impl Rootfs {
    pub fn open(path: &str) -> Result<Rootfs, FsError> {
        let c = CString::new(path).map_err(|_| FsError::errno("open", path, libc::EINVAL))?;
        // SAFETY: a valid C string; the descriptor is owned below.
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(FsError::errno("open", path, last_errno()));
        }
        // SAFETY: fd was just opened and is owned by nobody else.
        Ok(Rootfs {
            dir: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    /// openat2 beneath the root with no symbolic link followed: what a
    /// path resolveInRoot produced names, or an error if the tree changed.
    fn open_beneath(&self, name: &str, flags: i32) -> Result<OwnedFd, i32> {
        let c = CString::new(name).map_err(|_| libc::EINVAL)?;
        let how = OpenHow {
            flags: (flags | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,
        };
        // SAFETY: valid pointers for the call's duration.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                self.dir.as_raw_fd(),
                c.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            return Err(last_errno());
        }
        // SAFETY: fd was just opened and is owned by nobody else.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }

    /// The entry itself, not following a link, beneath the root; its error as
    /// "statat NAME: ...".
    fn lstat(&self, name: &str) -> Result<(libc::stat, Option<OwnedFd>), FsError> {
        let fd = self
            .open_beneath(name, libc::O_PATH | libc::O_NOFOLLOW)
            .map_err(|e| FsError::errno("statat", name, e))?;
        // SAFETY: zeroed stat filled by fstat on an open descriptor.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
            return Err(FsError::errno("statat", name, last_errno()));
        }
        Ok((st, Some(fd)))
    }

    fn readlink(fd: &OwnedFd, name: &str) -> Result<String, FsError> {
        let mut buf = vec![0u8; 4096];
        let empty = c"";
        // SAFETY: buffer of the given length; readlinkat on an O_PATH
        // descriptor of the link with an empty path reads that link.
        let n = unsafe {
            libc::readlinkat(
                fd.as_raw_fd(),
                empty.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if n < 0 {
            return Err(FsError::errno("readlinkat", name, last_errno()));
        }
        buf.truncate(n as usize);
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    /// containerd's resolveInRootFS: name with every symbolic link
    /// followed as if the root were "/", as a path relative to it.
    fn resolve(&self, name: &str) -> Result<String, FsError> {
        if name.is_empty() {
            return Err(FsError::errno("resolve", name, libc::ENOENT));
        }
        const SYMLOOP_MAX: usize = 40;
        let mut followed = 0;
        let mut pending: std::collections::VecDeque<String> = split_components(name).into();
        let mut candidates: Vec<String> = Vec::new();
        while let Some(part) = pending.pop_front() {
            if part == "." {
                continue;
            }
            if part == ".." {
                candidates.pop();
                continue;
            }
            candidates.push(part);
            let resolved = candidates.join("/");
            let (st, fd) = self.lstat(&resolved)?;
            let kind = st.st_mode & libc::S_IFMT;
            if kind == libc::S_IFLNK {
                followed += 1;
                if followed > SYMLOOP_MAX {
                    return Err(FsError::errno("resolve", &resolved, libc::ELOOP));
                }
                let target = Self::readlink(fd.as_ref().expect("descriptor"), &resolved)?;
                if target.starts_with('/') {
                    candidates.clear();
                } else {
                    candidates.pop();
                }
                for (i, c) in split_components(&target).into_iter().enumerate() {
                    pending.insert(i, c);
                }
                continue;
            }
            if kind != libc::S_IFDIR && !pending.is_empty() {
                return Err(FsError::errno("resolve", &resolved, libc::ENOTDIR));
            }
        }
        let r = candidates.join("/");
        Ok(if r.is_empty() { ".".into() } else { r })
    }

    /// openUserFile: name ("etc/passwd" or "etc/group") read whole, at
    /// most maxUserFileBytes, refused unless a regular file. A longer file
    /// gives its first bytes and the read error past them,
    /// which the parser reports unless a line was too long before it.
    pub fn read_user_file(&self, name: &str) -> Result<UserFile, FsError> {
        let resolved = self.resolve(name)?;
        // Never blocks on a FIFO or opens a device as a terminal: such a
        // file is refused below anyway.
        let fd = self
            .open_beneath(
                &resolved,
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY,
            )
            .map_err(|e| FsError::errno("openat", &resolved, e))?;
        // SAFETY: zeroed stat filled by fstat on an open descriptor.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
            return Err(FsError::errno("stat", name, last_errno()));
        }
        if st.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(FsError::plain(format!("{name} is not a regular file")));
        }
        const MAX_USER_FILE_BYTES: u64 = 10 << 20;
        let mut data = Vec::new();
        let mut f = std::fs::File::from(fd).take(MAX_USER_FILE_BYTES + 1);
        f.read_to_end(&mut data)
            .map_err(|e| FsError::errno("read", name, e.raw_os_error().unwrap_or(libc::EIO)))?;
        let over = (data.len() as u64 > MAX_USER_FILE_BYTES).then(|| {
            FsError::plain(format!(
                "{} exceeds {MAX_USER_FILE_BYTES} bytes",
                crate::net::addr::quote(name)
            ))
        });
        Ok(UserFile { data, over })
    }
}

/// A user database file as read, with the error reading past its limit.
pub struct UserFile {
    pub data: Vec<u8>,
    pub over: Option<FsError>,
}

impl UserFile {
    /// The file's lines, or the scanner's error: a line too long, else
    /// the reader's past the limit.
    fn lines(&self, max: usize) -> Result<Vec<&[u8]>, FsError> {
        let lines = scan_lines(&self.data, max)?;
        match &self.over {
            Some(e) => Err(e.clone()),
            None => Ok(lines),
        }
    }
}

/// splitPathComponents: the non-empty parts, plus "." after a trailing
/// slash.
fn split_components(name: &str) -> Vec<String> {
    let mut out: Vec<String> = name
        .split('/')
        .filter(|p| !p.is_empty())
        .map(String::from)
        .collect();
    if name.ends_with('/') {
        out.push(".".into());
    }
    out
}

/// A user of /etc/passwd as moby/sys/user parses one.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PasswdUser {
    pub name: Vec<u8>,
    pub uid: i64,
    pub gid: i64,
}

/// A group of /etc/group.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Group {
    pub name: Vec<u8>,
    pub gid: i64,
    pub list: Vec<Vec<u8>>,
}

/// A signed decimal 64-bit integer: the value (clamped on overflow) and whether
/// it parsed, and whether it overflowed.
pub fn atoi(s: &[u8]) -> (i64, Result<(), AtoiError>) {
    let (neg, digits) = match s.first() {
        Some(b'+') => (false, &s[1..]),
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return (0, Err(AtoiError::Syntax));
    }
    let mut v: u64 = 0;
    for &d in digits {
        match v
            .checked_mul(10)
            .and_then(|x| x.checked_add(u64::from(d - b'0')))
        {
            Some(x) => v = x,
            None => {
                return (if neg { i64::MIN } else { i64::MAX }, Err(AtoiError::Range));
            }
        }
    }
    if neg {
        if v > 1 << 63 {
            (i64::MIN, Err(AtoiError::Range))
        } else {
            ((v as i64).wrapping_neg(), Ok(()))
        }
    } else if v > i64::MAX as u64 {
        (i64::MAX, Err(AtoiError::Range))
    } else {
        (v as i64, Ok(()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AtoiError {
    Syntax,
    Range,
}

/// bytes.TrimSpace: ASCII and Unicode white space at both ends; it stops
/// at a byte that does not start a valid UTF-8 character.
fn trim_space(mut b: &[u8]) -> &[u8] {
    loop {
        match first_char(b) {
            Some((c, n)) if c.is_whitespace() => b = &b[n..],
            _ => break,
        }
    }
    loop {
        match last_char(b) {
            Some((c, n)) if c.is_whitespace() => b = &b[..b.len() - n],
            _ => break,
        }
    }
    b
}

fn first_char(b: &[u8]) -> Option<(char, usize)> {
    for n in 1..=4.min(b.len()) {
        if let Ok(s) = std::str::from_utf8(&b[..n]) {
            return s.chars().next().map(|c| (c, n));
        }
    }
    None
}

fn last_char(b: &[u8]) -> Option<(char, usize)> {
    for n in 1..=4.min(b.len()) {
        if let Ok(s) = std::str::from_utf8(&b[b.len() - n..]) {
            return s.chars().next_back().map(|c| (c, n));
        }
    }
    None
}

/// bufio.Scanner with ScanLines over data, at most max bytes a line:
/// each line without its "\n" (and a "\r" before it), or the scanner's
/// error.
fn scan_lines(data: &[u8], max: usize) -> Result<Vec<&[u8]>, FsError> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let (line, next) = match rest.iter().position(|&c| c == b'\n') {
            Some(i) => {
                if i + 1 > max {
                    return Err(FsError::plain("bufio.Scanner: token too long".into()));
                }
                (&rest[..i], &rest[i + 1..])
            }
            None => {
                if rest.len() >= max {
                    return Err(FsError::plain("bufio.Scanner: token too long".into()));
                }
                (rest, &rest[rest.len()..])
            }
        };
        out.push(line.strip_suffix(b"\r").unwrap_or(line));
        rest = next;
    }
    Ok(out)
}

/// user.ParsePasswdFilter with every user kept: the scanner's 64 KiB
/// lines, no comments.
pub fn parse_passwd(f: &UserFile) -> Result<Vec<PasswdUser>, FsError> {
    let mut out = Vec::new();
    for line in f.lines(64 * 1024)? {
        let line = trim_space(line);
        if line.is_empty() {
            continue;
        }
        let mut u = PasswdUser::default();
        for (i, p) in line.split(|&c| c == b':').enumerate() {
            match i {
                0 => u.name = p.to_vec(),
                2 => u.uid = atoi(p).0,
                3 => u.gid = atoi(p).0,
                _ => {}
            }
        }
        out.push(u);
    }
    Ok(out)
}

/// user.ParseGroupFilter with every group kept: 1 MiB lines, "#" lines
/// skipped.
pub fn parse_group(f: &UserFile) -> Result<Vec<Group>, FsError> {
    let mut out = Vec::new();
    for line in f.lines(1024 * 1024)? {
        let line = trim_space(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let mut g = Group::default();
        for (i, p) in line.split(|&c| c == b':').enumerate() {
            match i {
                0 => g.name = p.to_vec(),
                2 => g.gid = atoi(p).0,
                3 => {
                    g.list = if p.is_empty() {
                        Vec::new()
                    } else {
                        p.split(|&c| c == b',').map(<[u8]>::to_vec).collect()
                    }
                }
                _ => {}
            }
        }
        out.push(g);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(b: &[u8]) -> UserFile {
        UserFile {
            data: b.to_vec(),
            over: None,
        }
    }

    fn parse_passwd(b: &[u8]) -> Result<Vec<PasswdUser>, FsError> {
        super::parse_passwd(&file(b))
    }

    fn parse_group(b: &[u8]) -> Result<Vec<Group>, FsError> {
        super::parse_group(&file(b))
    }

    #[test]
    fn atoi_signs_and_bounds() {
        assert_eq!(atoi(b"1000"), (1000, Ok(())));
        assert_eq!(atoi(b"+7"), (7, Ok(())));
        assert_eq!(atoi(b"-7"), (-7, Ok(())));
        assert_eq!(atoi(b""), (0, Err(AtoiError::Syntax)));
        assert_eq!(atoi(b"-"), (0, Err(AtoiError::Syntax)));
        assert_eq!(atoi(b"1x"), (0, Err(AtoiError::Syntax)));
        assert_eq!(
            atoi(b"99999999999999999999"),
            (i64::MAX, Err(AtoiError::Range))
        );
        assert_eq!(atoi(b"-9223372036854775808"), (i64::MIN, Ok(())));
    }

    #[test]
    fn parses_passwd_and_group() {
        let u =
            parse_passwd(b"root:x:0:0::/root:/bin/sh\n\n  app:x:1000:1001\r\nbad:x:z\n").unwrap();
        assert_eq!(u.len(), 3);
        assert_eq!(
            (u[1].name.as_slice(), u[1].uid, u[1].gid),
            (&b"app"[..], 1000, 1001)
        );
        assert_eq!(u[2].uid, 0);
        let g = parse_group(b"# c\nwheel:x:10:root,app\nnone:x:11:\n").unwrap();
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].list, [b"root".to_vec(), b"app".to_vec()]);
        assert!(g[1].list.is_empty());
    }

    #[test]
    fn long_lines_fail_as_the_scanner_does() {
        let mut long = vec![b'a'; 65535];
        long.push(b'\n');
        assert!(parse_passwd(&long).is_ok());
        long.insert(0, b'a');
        assert!(parse_passwd(&long).is_err());
        assert!(parse_passwd(&vec![b'a'; 65535]).is_ok());
        assert!(parse_passwd(&vec![b'a'; 65536]).is_err());
    }
}

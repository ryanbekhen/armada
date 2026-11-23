//! A layer applied as containerd's applier applies it for the overlay
//! snapshotter (core/diff/apply, pkg/archive Apply, continuity's
//! RootPath): the first layer of a chain as a plain directory, where
//! whiteouts remove what they name; every later one as an overlay upper
//! directory over its parents, where whiteouts become character devices
//! 0/0 and opaque markers the trusted.overlay.opaque attribute, and
//! directories a layer creates implicitly take their parents' owner,
//! mode, times, and attributes.
//!
//! Names are resolved as Go resolves them: every entry stays inside the
//! layer's directory, "../" and absolute names are taken from its root,
//! and symbolic links are followed only within it. On top of that, every
//! change is made through a descriptor of its parent directory opened
//! with openat2 beneath the root and with no symbolic link followed, so a
//! name that would leave the directory is an error, never a write
//! elsewhere.

use super::tar::{self, Header, Time};
use std::collections::HashSet;
use std::ffi::{CString, OsStr};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

const WHITEOUT: &[u8] = b".wh.";
const OPAQUE: &[u8] = b".wh..wh..opq";

// --- Go's path/filepath on bytes ---------------------------------------

pub fn clean(p: &[u8]) -> Vec<u8> {
    if p.is_empty() {
        return b".".to_vec();
    }
    let rooted = p[0] == b'/';
    let mut parts: Vec<&[u8]> = Vec::new();
    for part in p.split(|c| *c == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                if parts.last().is_some_and(|l| *l != b"..") {
                    parts.pop();
                } else if !rooted {
                    parts.push(b"..");
                }
            }
            _ => parts.push(part),
        }
    }
    let body = parts.join(&b'/');
    match (rooted, body.is_empty()) {
        (true, _) => [b"/".as_slice(), &body].concat(),
        (false, true) => b".".to_vec(),
        (false, false) => body,
    }
}

pub fn join(a: &[u8], b: &[u8]) -> Vec<u8> {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => Vec::new(),
        (true, false) => clean(b),
        (false, true) => clean(a),
        (false, false) => clean(&[a, b"/", b].concat()),
    }
}

/// filepath.Split: everything up to the last slash, and the rest.
pub fn split(p: &[u8]) -> (&[u8], &[u8]) {
    let i = p.iter().rposition(|c| *c == b'/').map_or(0, |i| i + 1);
    (&p[..i], &p[i..])
}

fn dir(p: &[u8]) -> Vec<u8> {
    clean(split(p).0)
}

fn base(p: &[u8]) -> &[u8] {
    let t = {
        let mut e = p.len();
        while e > 0 && p[e - 1] == b'/' {
            e -= 1;
        }
        &p[..e]
    };
    if t.is_empty() {
        return if p.is_empty() { b"." } else { b"/" };
    }
    split(t).1
}

fn show(p: &[u8]) -> String {
    String::from_utf8_lossy(p).into_owned()
}

/// Go's %q of a path, close enough for messages.
fn quote(p: &[u8]) -> String {
    format!("{:?}", show(p))
}

// --- errors as Go words them -------------------------------------------

fn errno_text(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(n) => {
            // SAFETY: strerror returns a pointer to a static string.
            let s = unsafe { std::ffi::CStr::from_ptr(libc::strerror(n)) }
                .to_string_lossy()
                .into_owned();
            let mut c = s.chars();
            match c.next() {
                Some(f) => f.to_lowercase().chain(c).collect(),
                None => s,
            }
        }
        None => e.to_string(),
    }
}

/// An os.PathError's text.
fn path_err(op: &str, p: &[u8], e: &io::Error) -> String {
    format!("{op} {}: {}", show(p), errno_text(e))
}

fn errno(e: &io::Error) -> i32 {
    e.raw_os_error().unwrap_or(0)
}

fn last() -> io::Error {
    io::Error::last_os_error()
}

fn cstr(b: &[u8]) -> io::Result<CString> {
    CString::new(b).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

// --- plain path reads (RootPath, parents) -------------------------------

fn lstat_path(p: &[u8]) -> io::Result<libc::stat> {
    let c = cstr(p)?;
    // SAFETY: a zeroed stat filled by lstat with a valid C string.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(c.as_ptr(), &mut st) } != 0 {
        return Err(last());
    }
    Ok(st)
}

fn readlink_path(p: &[u8]) -> io::Result<Vec<u8>> {
    std::fs::read_link(OsStr::from_bytes(p)).map(|t| t.as_os_str().as_bytes().to_vec())
}

fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

fn is_symlink(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFLNK
}

fn is_reg(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFREG
}

fn llistxattr(p: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let c = cstr(p)?;
    loop {
        // SAFETY: a size query with a null buffer.
        let n = unsafe { libc::llistxattr(c.as_ptr(), std::ptr::null_mut(), 0) };
        if n < 0 {
            return Err(last());
        }
        let mut b = vec![0u8; n as usize];
        // SAFETY: a buffer of the length passed.
        let m = unsafe { libc::llistxattr(c.as_ptr(), b.as_mut_ptr().cast(), b.len()) };
        if m < 0 {
            if errno(&last()) == libc::ERANGE {
                continue;
            }
            return Err(last());
        }
        b.truncate(m as usize);
        return Ok(b
            .split(|x| *x == 0)
            .filter(|n| !n.is_empty())
            .map(<[u8]>::to_vec)
            .collect());
    }
}

fn lgetxattr(p: &[u8], name: &[u8]) -> io::Result<Vec<u8>> {
    let c = cstr(p)?;
    let n = cstr(name)?;
    loop {
        // SAFETY: a size query with a null buffer.
        let size = unsafe { libc::lgetxattr(c.as_ptr(), n.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            return Err(last());
        }
        let mut b = vec![0u8; size as usize];
        // SAFETY: a buffer of the length passed.
        let m = unsafe { libc::lgetxattr(c.as_ptr(), n.as_ptr(), b.as_mut_ptr().cast(), b.len()) };
        if m < 0 {
            if errno(&last()) == libc::ERANGE {
                continue;
            }
            return Err(last());
        }
        b.truncate(m as usize);
        return Ok(b);
    }
}

// --- continuity's fs.RootPath -------------------------------------------

/// RootPath: path joined to root with every symbolic link on the way
/// evaluated within root.
pub fn root_path(root: &[u8], path: &[u8]) -> io::Result<Vec<u8>> {
    if path.is_empty() {
        return Ok(root.to_vec());
    }
    let mut walked = 0;
    let mut path = path.to_vec();
    loop {
        let i = walked;
        path = walk_links(root, &path, &mut walked)?;
        if i == walked {
            let np = join(b"/", &path);
            if path == np {
                return Ok(join(root, &np));
            }
            path = np;
        }
    }
}

fn walk_link(root: &[u8], path: &[u8], walked: &mut u32) -> io::Result<(Vec<u8>, bool)> {
    if *walked > 255 {
        return Err(io::Error::other("too many links"));
    }
    let path = join(b"/", path);
    if path == b"/" {
        return Ok((path, false));
    }
    let real = join(root, &path);
    match lstat_path(&real) {
        Err(e) if errno(&e) == libc::ENOENT => Ok((path, false)),
        Err(e) => Err(io::Error::other(path_err("lstat", &real, &e))),
        Ok(st) if !is_symlink(&st) => Ok((path, false)),
        Ok(_) => {
            let t = readlink_path(&real)
                .map_err(|e| io::Error::other(path_err("readlink", &real, &e)))?;
            *walked += 1;
            Ok((t, true))
        }
    }
}

fn walk_links(root: &[u8], path: &[u8], walked: &mut u32) -> io::Result<Vec<u8>> {
    let (d, f) = split(path);
    if d.is_empty() {
        return Ok(walk_link(root, f, walked)?.0);
    }
    if f.is_empty() {
        if d == b"/" {
            return Ok(d.to_vec());
        }
        return walk_links(root, &d[..d.len() - 1], walked);
    }
    let newdir = walk_links(root, d, walked)?;
    let (np, link) = walk_link(root, &join(&newdir, f), walked)?;
    if !link || np.first() == Some(&b'/') {
        return Ok(np);
    }
    Ok(join(&newdir, &np))
}

// --- changes beneath the root -------------------------------------------

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

/// The layer's directory: every change goes through it.
pub struct Root {
    fd: OwnedFd,
    path: Vec<u8>,
}

impl Root {
    pub fn open(path: &[u8]) -> io::Result<Root> {
        let c = cstr(path)?;
        // SAFETY: a valid C string; the descriptor is owned below.
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(last());
        }
        Ok(Root {
            // SAFETY: just opened, owned by nobody else.
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            path: path.to_vec(),
        })
    }

    fn open_beneath(&self, rel: &[u8], flags: i32) -> io::Result<OwnedFd> {
        let c = cstr(rel)?;
        let how = OpenHow {
            flags: (flags | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
        };
        // SAFETY: valid pointers for the call's duration.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                self.fd.as_raw_fd(),
                c.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            return Err(last());
        }
        // SAFETY: just opened, owned by nobody else.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }

    /// The directory holding p, opened beneath the root, and p's last
    /// name in it ("." for the root itself).
    fn at(&self, p: &[u8]) -> io::Result<(OwnedFd, CString)> {
        let rel: &[u8] = if p == self.path.as_slice() {
            b"."
        } else if p.len() > self.path.len()
            && p.starts_with(&self.path)
            && (p[self.path.len()] == b'/' || self.path == b"/")
        {
            let r = &p[self.path.len()..];
            r.strip_prefix(b"/").unwrap_or(r)
        } else {
            return Err(io::Error::from_raw_os_error(libc::EXDEV));
        };
        if rel == b"." {
            return Ok((
                self.open_beneath(b".", libc::O_PATH | libc::O_DIRECTORY)?,
                cstr(b".")?,
            ));
        }
        let (d, b) = split(rel);
        let d = if d.is_empty() {
            b".".as_slice()
        } else {
            &d[..d.len() - 1]
        };
        Ok((
            self.open_beneath(d, libc::O_PATH | libc::O_DIRECTORY)?,
            cstr(b)?,
        ))
    }

    pub fn lstat(&self, p: &[u8]) -> io::Result<libc::stat> {
        let (d, b) = self.at(p)?;
        // SAFETY: a zeroed stat filled by fstatat.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                d.as_raw_fd(),
                b.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(last());
        }
        Ok(st)
    }

    fn mkdir(&self, p: &[u8], mode: u32) -> io::Result<()> {
        let (d, b) = self.at(p)?;
        // SAFETY: valid descriptor and C string.
        if unsafe { libc::mkdirat(d.as_raw_fd(), b.as_ptr(), mode) } != 0 {
            return Err(last());
        }
        Ok(())
    }

    /// chmod of something that is not a symbolic link.
    fn chmod(&self, p: &[u8], mode: u32) -> io::Result<()> {
        let (d, b) = self.at(p)?;
        // SAFETY: valid descriptor and C string.
        if unsafe { libc::fchmodat(d.as_raw_fd(), b.as_ptr(), mode, 0) } != 0 {
            return Err(last());
        }
        Ok(())
    }

    fn create(&self, p: &[u8], mode: u32) -> io::Result<std::fs::File> {
        let (d, b) = self.at(p)?;
        // SAFETY: valid descriptor and C string; the result is owned below.
        let fd = unsafe {
            libc::openat(
                d.as_raw_fd(),
                b.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            )
        };
        if fd < 0 {
            return Err(last());
        }
        // SAFETY: just opened, owned by nobody else.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    fn mknod(&self, p: &[u8], mode: u32, dev: u64) -> io::Result<()> {
        let (d, b) = self.at(p)?;
        // SAFETY: valid descriptor and C string.
        if unsafe { libc::mknodat(d.as_raw_fd(), b.as_ptr(), mode, dev as libc::dev_t) } != 0 {
            return Err(last());
        }
        Ok(())
    }

    fn link(&self, old: &[u8], new: &[u8]) -> io::Result<()> {
        let (od, ob) = self.at(old)?;
        let (nd, nb) = self.at(new)?;
        // SAFETY: valid descriptors and C strings; flags 0 never follows.
        if unsafe { libc::linkat(od.as_raw_fd(), ob.as_ptr(), nd.as_raw_fd(), nb.as_ptr(), 0) } != 0
        {
            return Err(last());
        }
        Ok(())
    }

    fn symlink(&self, target: &[u8], p: &[u8]) -> io::Result<()> {
        let t = cstr(target)?;
        let (d, b) = self.at(p)?;
        // SAFETY: valid descriptor and C strings.
        if unsafe { libc::symlinkat(t.as_ptr(), d.as_raw_fd(), b.as_ptr()) } != 0 {
            return Err(last());
        }
        Ok(())
    }

    fn lchown(&self, p: &[u8], uid: i64, gid: i64) -> io::Result<()> {
        let (d, b) = self.at(p)?;
        // Go passes ints the kernel reads as 32-bit IDs (-1: unchanged).
        // SAFETY: valid descriptor and C string.
        if unsafe {
            libc::fchownat(
                d.as_raw_fd(),
                b.as_ptr(),
                uid as u32,
                gid as u32,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(last());
        }
        Ok(())
    }

    /// lsetxattr of p, reached through its parent's descriptor.
    fn lsetxattr(&self, p: &[u8], name: &[u8], value: &[u8], flags: i32) -> io::Result<()> {
        let (d, b) = self.at(p)?;
        let path = [
            format!("/proc/self/fd/{}/", d.as_raw_fd()).as_bytes(),
            b.as_bytes(),
        ]
        .concat();
        let c = cstr(&path)?;
        let n = cstr(name)?;
        // SAFETY: valid C strings and a buffer of the given length.
        if unsafe {
            libc::lsetxattr(
                c.as_ptr(),
                n.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                flags,
            )
        } != 0
        {
            return Err(last());
        }
        Ok(())
    }

    fn utimes(&self, p: &[u8], atime: i128, mtime: i128) -> io::Result<()> {
        let ts = |t: i128| libc::timespec {
            tv_sec: t.div_euclid(1_000_000_000) as _,
            tv_nsec: t.rem_euclid(1_000_000_000) as _,
        };
        let times = [ts(atime), ts(mtime)];
        let (d, b) = self.at(p)?;
        // SAFETY: valid descriptor, C string, and two timespecs.
        if unsafe {
            libc::utimensat(
                d.as_raw_fd(),
                b.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(last());
        }
        Ok(())
    }

    /// os.RemoveAll: p and everything under it, never following a link.
    fn remove_all(&self, p: &[u8]) -> io::Result<()> {
        if base(p) == b"." || p.ends_with(b"/.") {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let (d, b) = match self.at(p) {
            Ok(x) => x,
            Err(e) if errno(&e) == libc::ENOENT => return Ok(()),
            Err(e) => return Err(e),
        };
        // The parent was opened O_PATH: reopen it to change entries.
        let parent = reopen_dir(&d)?;
        remove_at(&parent, &b)
    }
}

fn reopen_dir(d: &OwnedFd) -> io::Result<OwnedFd> {
    let dot = c".";
    // SAFETY: a valid descriptor; the result is owned below.
    let fd = unsafe {
        libc::openat(
            d.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(last());
    }
    // SAFETY: just opened, owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// removeAllFrom: unlink, else empty the directory and remove it.
fn remove_at(parent: &OwnedFd, name: &CString) -> io::Result<()> {
    // SAFETY: valid descriptor and C string.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == 0 {
        return Ok(());
    }
    let e = last();
    if errno(&e) == libc::ENOENT {
        return Ok(());
    }
    // SAFETY: valid descriptor and C string; the result is owned below.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let oe = last();
        if errno(&oe) == libc::ENOENT {
            return Ok(());
        }
        // Not a directory: the unlink's error is the one that counts.
        if errno(&oe) == libc::ENOTDIR || errno(&oe) == libc::ELOOP {
            return Err(e);
        }
        return Err(oe);
    }
    // SAFETY: just opened, owned by nobody else.
    let dir = unsafe { OwnedFd::from_raw_fd(fd) };
    for n in read_names(&dir)? {
        remove_at(&dir, &cstr(&n)?)?;
    }
    // SAFETY: valid descriptor and C string.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        let e = last();
        if errno(&e) != libc::ENOENT {
            return Err(e);
        }
    }
    Ok(())
}

/// The names in a directory open for reading, sorted.
fn read_names(dir: &OwnedFd) -> io::Result<Vec<Vec<u8>>> {
    // SAFETY: dup of an owned descriptor, handed to fdopendir below.
    let fd = unsafe { libc::dup(dir.as_raw_fd()) };
    if fd < 0 {
        return Err(last());
    }
    // SAFETY: a descriptor fdopendir takes over.
    let d = unsafe { libc::fdopendir(fd) };
    if d.is_null() {
        let e = last();
        // SAFETY: fdopendir failed, so the descriptor is still ours.
        unsafe { libc::close(fd) };
        return Err(e);
    }
    // SAFETY: rewind the shared offset so every name is read.
    unsafe { libc::rewinddir(d) };
    let mut out = Vec::new();
    loop {
        // SAFETY: readdir on an open stream.
        let ent = unsafe { libc::readdir(d) };
        if ent.is_null() {
            break;
        }
        // SAFETY: d_name is a NUL-terminated array in the entry.
        let name = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            out.push(name.to_vec());
        }
    }
    // SAFETY: closes the stream and its descriptor.
    unsafe { libc::closedir(d) };
    out.sort();
    Ok(out)
}

/// Names under a path for filepath.Walk (sorted), read without
/// following a link at its end.
fn dir_names(p: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let c = cstr(p)?;
    // SAFETY: a valid C string; the result is owned below.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(last());
    }
    // SAFETY: just opened, owned by nobody else.
    read_names(&unsafe { OwnedFd::from_raw_fd(fd) })
}

// --- times ------------------------------------------------------------

/// Go's zero time.Time, in nanoseconds since the epoch.
const ZERO_TIME: i128 = -62_135_596_800 * 1_000_000_000;

fn time_of(t: Time) -> i128 {
    t.unwrap_or(ZERO_TIME)
}

/// boundTime: times before the epoch or past what a 64-bit count of
/// nanoseconds holds become the epoch.
fn bound(t: i128) -> i128 {
    if !(0..=i128::from(i64::MAX)).contains(&t) {
        0
    } else {
        t
    }
}

fn chtimes(root: &Root, p: &[u8], h: &Header) -> Result<(), String> {
    // bound(latestTime(atime, mtime)), bound(mtime).
    let m = time_of(h.mtime);
    let at = time_of(h.atime);
    let a = if at < m { m } else { at };
    root.utimes(p, bound(a), bound(m)).map_err(|e| {
        format!(
            "failed call to UtimesNanoAt for {}: {}",
            show(p),
            errno_text(&e)
        )
    })
}

// --- the applier ---------------------------------------------------------

struct Apply<'a> {
    root: &'a Root,
    rootp: Vec<u8>,
    parents: &'a [Vec<u8>],
    unpacked: HashSet<Vec<u8>>,
    opaque: HashSet<Vec<u8>>,
}

/// archive.Apply with the options apply() gives it: overlay whiteouts and
/// parents when there are parents, removals otherwise.
pub fn apply(root_dir: &[u8], r: &mut dyn Read, parents: &[Vec<u8>]) -> Result<(), String> {
    let rootp = clean(root_dir);
    let root = Root::open(&rootp).map_err(|e| path_err("open", &rootp, &e))?;
    let mut a = Apply {
        root: &root,
        rootp,
        parents,
        unpacked: HashSet::new(),
        opaque: HashSet::new(),
    };
    let mut tr = tar::Reader::new(r);
    let mut dirs: Vec<Header> = Vec::new();
    while let Some(mut h) = tr.next().map_err(|e| e.to_string())? {
        h.name = clean(&h.name);
        let (pp, b) = split(&h.name);
        let ppath = root_path(&a.rootp, pp).map_err(|e| format!("failed to get root path: {e}"))?;
        let path = join(&ppath, &join(b"/", b));
        if path == a.rootp {
            continue;
        }
        if ppath != a.rootp {
            let parent = if b.is_empty() {
                dir(&path)
            } else {
                ppath.clone()
            };
            a.mkparent(&parent)?;
        }
        validate_whiteout(&path)?;
        let write = if parents.is_empty() {
            a.remove_whiteout(&path)
        } else {
            a.overlay_whiteout(&h, &path)
        }
        .map_err(|e| format!("failed to convert whiteout file {}: {e}", quote(&h.name)))?;
        if !write {
            continue;
        }
        if let Ok(st) = root.lstat(&path)
            && (!is_dir(&st) || h.typeflag != tar::TYPE_DIR)
        {
            root.remove_all(&path)
                .map_err(|e| path_err("unlinkat", &path, &e))?;
        }
        a.create(&path, &h, &mut tr)?;
        if h.typeflag == tar::TYPE_DIR {
            dirs.push(h);
        }
        a.unpacked.insert(path);
    }
    for h in &dirs {
        let p = root_path(&a.rootp, &h.name).map_err(|e| e.to_string())?;
        chtimes(&root, &p, h)?;
    }
    // What follows the archive is read by the caller, for the digest.
    Ok(())
}

fn validate_whiteout(path: &[u8]) -> Result<(), String> {
    let b = base(path);
    if b == OPAQUE {
        return Ok(());
    }
    if let Some(orig) = b.strip_prefix(WHITEOUT) {
        let mut d = dir(path);
        let op = join(&d, orig);
        if d.last() != Some(&b'/') {
            d.push(b'/');
        }
        if !op.starts_with(&d) {
            return Err(format!(
                "invalid whiteout name: {}: invalid archive",
                show(b)
            ));
        }
    }
    Ok(())
}

impl Apply<'_> {
    /// The whiteout conversion with no parents: whiteouts remove what they
    /// name, an opaque marker everything in its directory this layer did
    /// not unpack.
    fn remove_whiteout(&mut self, path: &[u8]) -> Result<bool, String> {
        let b = base(path).to_vec();
        let d = dir(path);
        if b == OPAQUE {
            if !self.opaque.insert(d.clone()) {
                return Ok(false);
            }
            lstat_path(&d).map_err(|e| path_err("lstat", &d, &e))?;
            self.walk_opaque(&d)?;
            return Ok(false);
        }
        if let Some(orig) = b.strip_prefix(WHITEOUT) {
            let op = join(&d, orig);
            self.root
                .remove_all(&op)
                .map_err(|e| path_err("unlinkat", &op, &e))?;
            return Ok(false);
        }
        Ok(true)
    }

    /// filepath.Walk of d removing what was not unpacked.
    fn walk_opaque(&self, d: &[u8]) -> Result<(), String> {
        let names = match dir_names(d) {
            Ok(n) => n,
            Err(e) if errno(&e) == libc::ENOENT => return Ok(()),
            Err(e) => return Err(path_err("open", d, &e)),
        };
        for n in names {
            let p = join(d, &n);
            let st = match lstat_path(&p) {
                Ok(st) => st,
                Err(e) if errno(&e) == libc::ENOENT => continue,
                Err(e) => return Err(path_err("lstat", &p, &e)),
            };
            if !self.unpacked.contains(&p) {
                self.root
                    .remove_all(&p)
                    .map_err(|e| path_err("unlinkat", &p, &e))?;
                continue;
            }
            if is_dir(&st) {
                self.walk_opaque(&p)?;
            }
        }
        Ok(())
    }

    /// OverlayConvertWhiteout.
    fn overlay_whiteout(&self, h: &Header, path: &[u8]) -> Result<bool, String> {
        let b = base(path);
        let d = dir(path);
        if b == OPAQUE {
            self.root
                .lsetxattr(&d, b"trusted.overlay.opaque", b"y", 0)
                .map_err(|e| path_err("setxattr", &d, &e))?;
            return Ok(false);
        }
        if let Some(orig) = b.strip_prefix(WHITEOUT) {
            let op = join(&d, orig);
            self.root
                .mknod(&op, libc::S_IFCHR, 0)
                .map_err(|e| errno_text(&e))?;
            self.root
                .lchown(&op, h.uid, h.gid)
                .map_err(|e| path_err("chown", &op, &e))?;
            return Ok(false);
        }
        Ok(true)
    }

    /// mkparent: creates path's missing directories, each taking what the
    /// first parent layer holding it has.
    fn mkparent(&self, path: &[u8]) -> Result<(), String> {
        match self.root.lstat(path) {
            Ok(st) if is_dir(&st) => return Ok(()),
            Ok(_) => return Err(format!("mkparent {}: not a directory", show(path))),
            Err(e) if errno(&e) != libc::ENOENT => return Err(path_err("lstat", path, &e)),
            Err(_) => {}
        }
        let rl = self.rootp.len();
        let mut i = path.len();
        while i > rl && path[i - 1] != b'/' {
            i -= 1;
        }
        if i > rl + 1 {
            self.mkparent(&path[..i - 1])?;
        }
        if let Err(e) = self
            .root
            .mkdir(path, 0o755)
            .and_then(|()| self.root.chmod(path, 0o755))
        {
            if self.root.lstat(path).is_ok_and(|st| is_dir(&st)) {
                return Ok(());
            }
            return Err(path_err("mkdir", path, &e));
        }
        for p in self.parents {
            let pp = root_path(p, &path[rl..]).map_err(|e| e.to_string())?;
            match lstat_path(&pp) {
                Ok(st) => {
                    if !is_dir(&st) {
                        break;
                    }
                    self.copy_dir_info(&st, path)?;
                    return self.copy_up_xattrs(path, &pp);
                }
                Err(e) if errno(&e) == libc::ENOENT => {}
                Err(e) => return Err(path_err("lstat", &pp, &e)),
            }
        }
        Ok(())
    }

    fn copy_dir_info(&self, st: &libc::stat, path: &[u8]) -> Result<(), String> {
        if let Err(e) = self
            .root
            .lchown(path, i64::from(st.st_uid), i64::from(st.st_gid))
        {
            let same = matches!(errno(&e), libc::EPERM | libc::EACCES)
                && self
                    .root
                    .lstat(path)
                    .is_ok_and(|d| d.st_uid == st.st_uid && d.st_gid == st.st_gid);
            if !same {
                return Err(format!(
                    "failed to chown {}: {}",
                    show(path),
                    path_err("lchown", path, &e)
                ));
            }
        }
        self.root.chmod(path, st.st_mode & 0o7777).map_err(|e| {
            format!(
                "failed to chmod {}: {}",
                show(path),
                path_err("chmod", path, &e)
            )
        })?;
        let a = i128::from(st.st_atime) * 1_000_000_000 + i128::from(st.st_atime_nsec);
        let m = i128::from(st.st_mtime) * 1_000_000_000 + i128::from(st.st_mtime_nsec);
        self.root
            .utimes(path, a, m)
            .map_err(|e| format!("failed to utime {}: {}", show(path), errno_text(&e)))
    }

    fn copy_up_xattrs(&self, dst: &[u8], src: &[u8]) -> Result<(), String> {
        let names = match llistxattr(src) {
            Ok(n) => n,
            Err(e) if matches!(errno(&e), libc::ENOTSUP | libc::ENODATA) => return Ok(()),
            Err(e) => {
                return Err(format!(
                    "failed to list xattrs on {}: {}",
                    show(src),
                    errno_text(&e)
                ));
            }
        };
        for n in names {
            if n.starts_with(b"trusted.") {
                continue;
            }
            let v = match lgetxattr(src, &n) {
                Ok(v) => v,
                Err(e) if matches!(errno(&e), libc::ENOTSUP | libc::ENODATA) => continue,
                Err(e) => {
                    return Err(format!(
                        "failed to get xattr {} on {}: {}",
                        quote(&n),
                        show(src),
                        errno_text(&e)
                    ));
                }
            };
            match self.root.lsetxattr(dst, &n, &v, libc::XATTR_CREATE) {
                Ok(()) => {}
                Err(e) if matches!(errno(&e), libc::ENOTSUP | libc::ENODATA | libc::EEXIST) => {}
                Err(e) => {
                    return Err(format!(
                        "failed to set xattr {} on {}: {}",
                        quote(&n),
                        show(dst),
                        errno_text(&e)
                    ));
                }
            }
        }
        Ok(())
    }

    /// createTarFile.
    fn create(&self, path: &[u8], h: &Header, data: &mut dyn Read) -> Result<(), String> {
        let mode = (h.mode & 0o7777) as u32;
        match h.typeflag {
            tar::TYPE_DIR => {
                if !self.root.lstat(path).is_ok_and(|st| is_dir(&st)) {
                    self.root
                        .mkdir(path, mode)
                        .and_then(|()| self.root.chmod(path, mode))
                        .map_err(|e| path_err("mkdir", path, &e))?;
                }
            }
            tar::TYPE_REG | tar::TYPE_REGA => {
                let mut f = self
                    .root
                    .create(path, mode)
                    .map_err(|e| path_err("open", path, &e))?;
                // SAFETY: fchmod on the descriptor just opened.
                if unsafe { libc::fchmod(f.as_raw_fd(), mode) } != 0 {
                    return Err(path_err("chmod", path, &last()));
                }
                io::copy(data, &mut f).map_err(|e| match e.raw_os_error() {
                    Some(_) => path_err("write", path, &e),
                    None if e.kind() == io::ErrorKind::UnexpectedEof => {
                        "unexpected EOF".to_string()
                    }
                    None => e.to_string(),
                })?;
            }
            tar::TYPE_BLOCK | tar::TYPE_CHAR | tar::TYPE_FIFO => {
                let kind = match h.typeflag {
                    tar::TYPE_BLOCK => libc::S_IFBLK,
                    tar::TYPE_CHAR => libc::S_IFCHR,
                    _ => libc::S_IFIFO,
                };
                if !(0..=i64::from(u32::MAX)).contains(&h.devmajor)
                    || !(0..=i64::from(u32::MAX)).contains(&h.devminor)
                {
                    return Err(format!(
                        "device number {}:{} for {} out of range: invalid archive",
                        h.devmajor,
                        h.devminor,
                        quote(&h.name)
                    ));
                }
                let dev = makedev(h.devmajor as u32, h.devminor as u32);
                self.root
                    .mknod(path, mode | kind, dev)
                    .map_err(|e| errno_text(&e))?;
            }
            tar::TYPE_LINK => {
                let target = hardlink_root_path(&self.rootp, &h.linkname)?;
                self.root.link(&target, path).map_err(|e| {
                    format!("link {} {}: {}", show(&target), show(path), errno_text(&e))
                })?;
            }
            tar::TYPE_SYMLINK => {
                self.root.symlink(&h.linkname, path).map_err(|e| {
                    format!(
                        "symlink {} {}: {}",
                        show(&h.linkname),
                        show(path),
                        errno_text(&e)
                    )
                })?;
            }
            tar::TYPE_XGLOBAL => return Ok(()),
            t => return Err(format!("unhandled tar header type {t}")),
        }
        self.root.lchown(path, h.uid, h.gid).map_err(|e| {
            format!(
                "failed to Lchown {} for UID {}, GID {}: {}",
                quote(path),
                h.uid,
                h.gid,
                path_err("lchown", path, &e)
            )
        })?;
        for (k, v) in h.xattrs() {
            if k.starts_with(b"trusted.") {
                // Archives never set admin attributes.
                continue;
            }
            if let Err(e) = self.root.lsetxattr(path, k, v, 0) {
                let n = errno(&e);
                if n == libc::EPERM
                    && k.starts_with(b"user.")
                    && self
                        .root
                        .lstat(path)
                        .is_ok_and(|st| !is_reg(&st) && !is_dir(&st))
                {
                    continue;
                }
                if n == libc::ENOTSUP {
                    continue;
                }
                return Err(format!(
                    "failed to setxattr {} for key {}: {}",
                    quote(path),
                    quote(k),
                    errno_text(&e)
                ));
            }
        }
        let st = self
            .root
            .lstat(path)
            .map_err(|e| path_err("lstat", path, &e))?;
        if !is_symlink(&st) {
            self.root
                .chmod(path, mode)
                .map_err(|e| path_err("chmod", path, &e))?;
        }
        chtimes(self.root, path, h)
    }
}

/// hardlinkRootPath: a link's target resolved within root, the root
/// itself when it would leave it.
fn hardlink_root_path(root: &[u8], linkname: &[u8]) -> Result<Vec<u8>, String> {
    let (pp, b) = split(linkname);
    let pp = root_path(root, pp).map_err(|e| e.to_string())?;
    let t = join(&pp, b);
    if !t.starts_with(root) {
        return Ok(root.to_vec());
    }
    Ok(t)
}

/// unix.Mkdev.
fn makedev(major: u32, minor: u32) -> u64 {
    let (ma, mi) = (u64::from(major), u64::from(minor));
    ((ma & 0xffff_f000) << 32)
        | ((ma & 0x0000_0fff) << 8)
        | ((mi & 0xffff_ff00) << 12)
        | (mi & 0xff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_as_go() {
        assert_eq!(clean(b"../x"), b"../x");
        assert_eq!(join(b"/", b".."), b"/");
        assert_eq!(split(b"a/b/c"), (&b"a/b/"[..], &b"c"[..]));
        assert_eq!(split(b"c"), (&b""[..], &b"c"[..]));
        assert_eq!(base(b"/a/b/"), b"b");
        assert_eq!(dir(b"/a/b"), b"/a");
        assert!(validate_whiteout(b"/r/a/.wh..").is_err());
        assert!(validate_whiteout(b"/r/a/.wh.").is_err());
        assert!(validate_whiteout(b"/r/a/.wh.x").is_ok());
        assert!(validate_whiteout(b"/r/a/.wh..wh..opq").is_ok());
        assert_eq!(makedev(1, 3), libc::makedev(1, 3));
        assert_eq!(makedev(259, 70_000), libc::makedev(259, 70_000));
    }

    #[test]
    fn applies_inside_the_root() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("armada-node-apply-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let a = tar::test_archive(&[
            ("../escape", tar::TYPE_REG, "", "up"),
            ("/abs", tar::TYPE_REG, "", "abs"),
            ("out", tar::TYPE_SYMLINK, "/outside", ""),
            ("out/file", tar::TYPE_REG, "", "through"),
            ("up", tar::TYPE_SYMLINK, "../..", ""),
            ("up/file2", tar::TYPE_REG, "", "through"),
            ("h", tar::TYPE_LINK, "../../abs", ""),
            ("gone", tar::TYPE_REG, "", "x"),
            (".wh.gone", tar::TYPE_REG, "", ""),
        ]);
        apply(root.as_os_str().as_bytes(), &mut &a[..], &[]).unwrap();
        let read = |p: &str| std::fs::read_to_string(root.join(p)).unwrap();
        assert_eq!(read("escape"), "up");
        assert_eq!(read("abs"), "abs");
        assert_eq!(read("outside/file"), "through");
        assert_eq!(read("file2"), "through");
        assert_eq!(read("h"), "abs");
        assert!(!root.join("gone").exists());
        assert!(!base.join("escape").exists());
        assert_eq!(
            std::fs::metadata(root.join("abs"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o644
        );
        // An upper layer: whiteouts are character devices 0/0.
        let upper = base.join("upper");
        std::fs::create_dir_all(&upper).unwrap();
        let a = tar::test_archive(&[(".wh.abs", tar::TYPE_REG, "", "")]);
        let lower = root.as_os_str().as_bytes().to_vec();
        match apply(upper.as_os_str().as_bytes(), &mut &a[..], &[lower]) {
            Ok(()) => {
                let st = lstat_path(upper.join("abs").as_os_str().as_bytes()).unwrap();
                assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFCHR);
                assert_eq!(st.st_rdev, 0);
            }
            // Without the privilege to make whiteouts.
            Err(e) => assert!(e.contains("not permitted"), "{e}"),
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn root_paths_stay_inside() {
        let dir = std::env::temp_dir().join(format!("armada-node-rootpath-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("d")).unwrap();
        std::os::unix::fs::symlink("/etc", dir.join("abs")).unwrap();
        std::os::unix::fs::symlink("../../..", dir.join("d/up")).unwrap();
        let root = dir.as_os_str().as_bytes();
        let rp = |p: &str| root_path(root, p.as_bytes()).unwrap();
        assert_eq!(rp("../x"), join(root, b"x"));
        assert_eq!(rp("abs/passwd"), join(root, b"etc/passwd"));
        assert_eq!(rp("d/up/x"), join(root, b"x"));
        assert_eq!(rp(""), root);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

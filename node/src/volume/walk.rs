//! volbackup.Walk and OpenFile: a volume walked while its app may keep
//! running and change it. Every lookup goes beneath the volume's directory
//! (Go: an os.Root; here openat2 with RESOLVE_BENEATH, which follows links
//! only while they stay inside), every entry is opened without blocking,
//! and an entry opened is refused unless it is the one just looked up.

use super::{cstr, errno, last_errno, quote};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// What volbackup.ErrChanged says.
pub const CHANGED: &str =
    "changed while it was read; try again, or stop the app while backing up (--stop, backup.stop)";

/// An entry's Lstat.
#[derive(Clone, Copy, Debug)]
pub struct Stat {
    pub mode: u32,
    pub dev: u64,
    pub ino: u64,
    pub size: i64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub uid: u32,
    pub gid: u32,
}

impl Stat {
    fn from(st: &libc::stat) -> Stat {
        Stat {
            mode: st.st_mode,
            dev: st.st_dev,
            ino: st.st_ino,
            size: st.st_size,
            mtime: st.st_mtime,
            mtime_nsec: st.st_mtime_nsec,
            uid: st.st_uid,
            gid: st.st_gid,
        }
    }
    fn kind(&self) -> u32 {
        self.mode & libc::S_IFMT
    }
    pub fn is_dir(&self) -> bool {
        self.kind() == libc::S_IFDIR
    }
    pub fn is_reg(&self) -> bool {
        self.kind() == libc::S_IFREG
    }
    pub fn is_link(&self) -> bool {
        self.kind() == libc::S_IFLNK
    }
}

/// What went wrong with an entry, as Go's error under EntryError.
#[derive(Debug)]
pub enum Fail {
    /// An os.PathError: its Op and errno.
    Op(&'static str, i32),
    /// os.Root's errPathEscapes under an op.
    Escapes(&'static str),
    /// volbackup.ErrChanged.
    Changed,
    /// io.EOF: a file shorter than its lookup said.
    Eof,
}

/// volbackup.EntryError: the entry quoted, with what went wrong.
#[derive(Debug)]
pub struct EntryError {
    pub p: Vec<u8>,
    pub fail: Fail,
}

impl EntryError {
    pub fn new(p: &[u8], fail: Fail) -> EntryError {
        EntryError {
            p: p.to_vec(),
            fail,
        }
    }
    pub fn text(&self) -> String {
        let q = quote(&self.p);
        match self.fail {
            Fail::Op(op, e) => format!("{op} {q}: {}", errno::text(e)),
            Fail::Escapes(op) => format!("{op} {q}: path escapes from parent"),
            Fail::Changed => format!("{q}: {CHANGED}"),
            Fail::Eof => format!("{q}: EOF"),
        }
    }
    pub fn changed(&self) -> bool {
        matches!(self.fail, Fail::Changed)
    }
}

/// struct open_how of openat2(2).
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_BENEATH: u64 = 0x08;

/// A handle on a volume's directory.
pub struct Root {
    fd: OwnedFd,
}

impl Root {
    /// os.OpenRoot: the errno of opening dir.
    pub fn open(dir: &[u8]) -> Result<Root, i32> {
        let c = cstr(dir)?;
        // SAFETY: open with a valid C string.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(last_errno());
        }
        // SAFETY: fd was just opened and is owned here.
        Ok(Root {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    /// Checks that the kernel resolves beneath a directory (openat2, Linux
    /// 5.6), before anything is written.
    pub fn probe(&self) -> Result<(), String> {
        self.beneath(b".", libc::O_PATH | libc::O_DIRECTORY)
            .map(drop)
            .map_err(|e| format!("openat2: {}", errno::text(e)))
    }

    /// openat2 of p beneath the root, retried while the kernel asks to.
    fn beneath(&self, p: &[u8], flags: i32) -> Result<OwnedFd, i32> {
        let c = cstr(p)?;
        let how = OpenHow {
            flags: (flags | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH,
        };
        for _ in 0..16 {
            // SAFETY: openat2 with a valid C string and open_how.
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    self.fd.as_raw_fd(),
                    c.as_ptr(),
                    &how as *const OpenHow,
                    std::mem::size_of::<OpenHow>(),
                )
            };
            if fd >= 0 {
                // SAFETY: fd was just opened and is owned here.
                return Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) });
            }
            match last_errno() {
                libc::EAGAIN | libc::EINTR => continue,
                e => return Err(e),
            }
        }
        Err(libc::EAGAIN)
    }

    /// The directory holding p, and p's last name.
    fn parent<'a>(
        &self,
        p: &'a [u8],
        op: &'static str,
    ) -> Result<(Option<OwnedFd>, &'a [u8]), Fail> {
        match p.iter().rposition(|c| *c == b'/') {
            None => Ok((None, p)),
            Some(i) => {
                let fd = self
                    .beneath(&p[..i], libc::O_PATH | libc::O_DIRECTORY)
                    .map_err(|e| escapes(op, e))?;
                Ok((Some(fd), &p[i + 1..]))
            }
        }
    }

    /// Root.Lstat.
    pub fn lstat(&self, p: &[u8]) -> Result<Stat, Fail> {
        let (dir, name) = self.parent(p, "statat")?;
        let dfd = dir.as_ref().map_or(self.fd.as_raw_fd(), |d| d.as_raw_fd());
        let c = cstr(name).map_err(|e| Fail::Op("statat", e))?;
        // SAFETY: a zeroed stat filled by fstatat with a valid C string.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { libc::fstatat(dfd, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } < 0 {
            return Err(Fail::Op("statat", last_errno()));
        }
        Ok(Stat::from(&st))
    }

    /// Root.Readlink.
    pub fn readlink(&self, p: &[u8]) -> Result<Vec<u8>, Fail> {
        let (dir, name) = self.parent(p, "readlinkat")?;
        let dfd = dir.as_ref().map_or(self.fd.as_raw_fd(), |d| d.as_raw_fd());
        let c = cstr(name).map_err(|e| Fail::Op("readlinkat", e))?;
        let mut buf = vec![0u8; 256];
        loop {
            // SAFETY: readlinkat into a buffer of the given length.
            let n =
                unsafe { libc::readlinkat(dfd, c.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                return Err(Fail::Op("readlinkat", last_errno()));
            }
            let n = n as usize;
            if n < buf.len() {
                buf.truncate(n);
                return Ok(buf);
            }
            buf.resize(buf.len() * 2, 0);
        }
    }

    /// openSame: p opened for reading without blocking (a directory with
    /// O_DIRECTORY), refused with Changed unless it is the entry st
    /// describes.
    pub fn open_same(&self, p: &[u8], st: &Stat, dir: bool) -> Result<OwnedFd, Fail> {
        let mut flags = libc::O_RDONLY | libc::O_NONBLOCK;
        if dir {
            flags |= libc::O_DIRECTORY;
        }
        let fd = self.beneath(p, flags).map_err(|e| match e {
            libc::ENOTDIR | libc::ELOOP => Fail::Changed,
            e => escapes("openat", e),
        })?;
        // SAFETY: a zeroed stat filled by fstat.
        let mut ost: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: as above, on a descriptor owned here.
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut ost) } < 0 {
            return Err(Fail::Op("stat", last_errno()));
        }
        let o = Stat::from(&ost);
        if o.kind() != st.kind() || o.dev != st.dev || o.ino != st.ino {
            return Err(Fail::Changed);
        }
        Ok(fd)
    }
}

/// An openat2 errno as os.Root words it: EXDEV is a name leaving the root.
fn escapes(op: &'static str, e: i32) -> Fail {
    if e == libc::EXDEV {
        Fail::Escapes(op)
    } else {
        Fail::Op(op, e)
    }
}

/// Readdirnames of an opened directory: every name but "." and "..".
fn read_names(fd: &OwnedFd) -> Result<Vec<Vec<u8>>, i32> {
    // SAFETY: a duplicate the directory stream owns and closes.
    let dup = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return Err(last_errno());
    }
    // SAFETY: dup is a directory descriptor handed to the stream.
    let d = unsafe { libc::fdopendir(dup) };
    if d.is_null() {
        let e = last_errno();
        // SAFETY: dup is still ours when fdopendir fails.
        unsafe { libc::close(dup) };
        return Err(e);
    }
    let mut names = Vec::new();
    let res = loop {
        // SAFETY: errno is thread-local; readdir reads the stream opened above.
        unsafe { *libc::__errno_location() = 0 };
        let ent = unsafe { libc::readdir(d) };
        if ent.is_null() {
            let e = last_errno();
            break if e == 0 { Ok(()) } else { Err(e) };
        }
        // SAFETY: d_name is a NUL-terminated name in the entry.
        let name = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(name.to_vec());
        }
    };
    // SAFETY: closes the stream and dup.
    unsafe { libc::closedir(d) };
    res.map(|()| names)
}

fn join(p: &[u8], name: &[u8]) -> Vec<u8> {
    if p == b"." {
        return name.to_vec();
    }
    [p, b"/", name].concat()
}

/// What Walk hands its function: an entry's Lstat, or the error that
/// looking it up, opening it, or reading it gave.
pub type Visit<'a> = Result<&'a Stat, EntryError>;

/// The function Walk calls for each entry.
pub type WalkFn<'f, E> = dyn FnMut(&[u8], Visit) -> Result<(), E> + 'f;

/// volbackup.Walk: "." and then every entry below it, depth first in byte
/// order. Links are reported, never followed. The function's error ends
/// the walk; Ok after an error skips the entry.
pub fn walk<E>(root: &Root, f: &mut WalkFn<'_, E>) -> Result<(), E> {
    walk_at(root, b".", f)
}

fn walk_at<E>(root: &Root, p: &[u8], f: &mut WalkFn<'_, E>) -> Result<(), E> {
    let st = match root.lstat(p) {
        Ok(st) => st,
        Err(e) => return f(p, Err(EntryError::new(p, e))),
    };
    f(p, Ok(&st))?;
    if !st.is_dir() {
        return Ok(());
    }
    let fd = match root.open_same(p, &st, true) {
        Ok(fd) => fd,
        Err(e) => return f(p, Err(EntryError::new(p, e))),
    };
    let names = read_names(&fd);
    drop(fd);
    let mut names = match names {
        Ok(n) => n,
        Err(e) => return f(p, Err(EntryError::new(p, Fail::Op("readdirent", e)))),
    };
    names.sort();
    for n in names {
        walk_at(root, &join(p, &n), f)?;
    }
    Ok(())
}

/// volumeSize: the regular files of dir added up, entries that fail
/// skipped, 0 when dir cannot be opened.
pub fn size(dir: &[u8]) -> Result<i64, String> {
    let Ok(root) = Root::open(dir) else {
        return Ok(0);
    };
    root.probe()?;
    let mut size: i64 = 0;
    let _ = walk::<()>(&root, &mut |_, v| {
        if let Ok(st) = v
            && st.is_reg()
        {
            size = size.wrapping_add(st.size);
        }
        Ok(())
    });
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    fn tmp() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "armada-node-walk-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn walks_in_order_without_following_links() {
        let d = tmp();
        std::fs::create_dir_all(d.join("b/c")).unwrap();
        std::fs::write(d.join("a"), b"12").unwrap();
        std::fs::write(d.join("b/c/f"), b"123").unwrap();
        std::os::unix::fs::symlink("/etc", d.join("b/l")).unwrap();
        let root = Root::open(d.as_os_str().as_bytes()).unwrap();
        let mut seen = Vec::new();
        walk::<()>(&root, &mut |p, v| {
            assert!(v.is_ok());
            seen.push(String::from_utf8(p.to_vec()).unwrap());
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, [".", "a", "b", "b/c", "b/c/f", "b/l"]);
        assert_eq!(size(d.as_os_str().as_bytes()).unwrap(), 5);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn refuses_a_changed_entry() {
        let d = tmp();
        std::fs::write(d.join("f"), b"x").unwrap();
        let root = Root::open(d.as_os_str().as_bytes()).unwrap();
        let st = root.lstat(b"f").unwrap();
        std::fs::remove_file(d.join("f")).unwrap();
        std::fs::create_dir(d.join("f")).unwrap();
        let e = root.open_same(b"f", &st, false).unwrap_err();
        assert!(matches!(e, Fail::Changed));
        // A directory swapped for a link that leaves the volume.
        std::fs::remove_dir(d.join("f")).unwrap();
        std::os::unix::fs::symlink("/", d.join("f")).unwrap();
        let st = Stat {
            mode: libc::S_IFDIR,
            ..st
        };
        let e = root.open_same(b"f", &st, true).unwrap_err();
        assert_eq!(
            EntryError::new(b"f", e).text(),
            "openat \"f\": path escapes from parent"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}

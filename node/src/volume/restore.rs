//! restoreArchive: a gzipped tar from stdin into a new directory next to
//! the volume, swapped in only when every entry was restored. Entries may
//! only be directories, regular files (sparse ones expanded), and links,
//! with relative names that stay inside the volume; no entry is written
//! through a link, setuid and setgid bits are kept only when the agent
//! runs as root (the sticky bit always), and an entry is refused when
//! writing it would leave less than the reserve free (restoreReserve).
//! Directories get their modes and times once every entry is written,
//! deepest first, so a read-only directory still takes its entries. The
//! whole stream is read: what follows the tar's end blocks may only be
//! zeros, and the gzip trailer (CRC-32 and length) of every member is
//! checked, so a damaged or extended archive is refused. Paths are used as
//! Go uses them: the new directory is private (0700, under the volumes'
//! root-owned 0700 directory), so nothing else changes it meanwhile.

use super::gzip;
use super::{answer_file, cstr, errno, last_errno, path_err, quote, send_answer, show};
use crate::runtime::image::tar::{self, TYPE_DIR, TYPE_GNU_SPARSE, TYPE_REG, TYPE_SYMLINK};
use std::fs::File;
use std::io::{self, BufReader, Read, Write};

pub fn command(dir: &str) -> Result<(), String> {
    let mut answer = answer_file(3);
    let abort = answer_file(4);
    if let Some(f) = answer.as_mut() {
        f.write_all(b"ready\n")
            .map_err(|e| format!("answer: {e}"))?;
    }
    let input = BufReader::with_capacity(
        64 << 10,
        Feed {
            r: io::stdin(),
            abort,
            failed: None,
        },
    );
    let res = restore(dir.as_bytes(), input, restore_space());
    let v = match res {
        Ok(()) => serde_json::json!({}),
        Err(e) => serde_json::json!({ "error": e }),
    };
    send_answer(&mut answer, &v)
}

/// stdin, whose end is the agent's error when it wrote one on descriptor
/// 4 (the session failed): Go's reader gives that error where it read,
/// and again on every later read. The agent closes descriptor 4 before
/// stdin, so it is complete once stdin ends.
struct Feed {
    r: io::Stdin,
    abort: Option<File>,
    failed: Option<String>,
}

impl Read for Feed {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if let Some(t) = &self.failed {
            return Err(io::Error::other(t.clone()));
        }
        let n = self.r.read(b)?;
        if n > 0 || b.is_empty() {
            return Ok(n);
        }
        if let Some(mut f) = self.abort.take() {
            let mut s = String::new();
            let _ = f.read_to_string(&mut s);
            if let Ok(text) = serde_json::from_str::<String>(s.trim()) {
                self.failed = Some(text.clone());
                return Err(io::Error::other(text));
            }
        }
        Ok(0)
    }
}

/// What a file system has left (fsFree).
#[derive(Clone, Copy, Debug, Default)]
pub struct Free {
    pub bytes: u64,
    pub total_bytes: u64,
    pub inodes: u64,
    pub total_inodes: u64,
}

pub type Space = fn(&[u8]) -> Option<Free>;

/// fsSpace, or the test hook's numbers (builds with test hooks only).
pub fn restore_space() -> Space {
    match crate::hooks::var("ARMADA_NODE_TEST_VOLUME_SPACE") {
        Some(v) if v == "unknown" => |_| None,
        Some(_) => |_| {
            let v = crate::hooks::var("ARMADA_NODE_TEST_VOLUME_SPACE")?;
            let n: Vec<u64> = v.split(',').filter_map(|s| s.parse().ok()).collect();
            (n.len() == 4).then(|| Free {
                bytes: n[0],
                total_bytes: n[1],
                inodes: n[2],
                total_inodes: n[3],
            })
        },
        None => fs_space,
    }
}

fn fs_space(p: &[u8]) -> Option<Free> {
    let c = cstr(p).ok()?;
    // SAFETY: a zeroed statfs filled by statfs with a valid C string.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } < 0 {
        return None;
    }
    let bs = st.f_bsize as u64;
    Some(Free {
        bytes: (st.f_bavail as u64).wrapping_mul(bs),
        total_bytes: (st.f_blocks as u64).wrapping_mul(bs),
        inodes: st.f_ffree as u64,
        total_inodes: st.f_files as u64,
    })
}

/// restoreArchive.
pub fn restore(dir: &[u8], input: impl io::BufRead, space: Space) -> Result<(), String> {
    let gz = gzip::Reader::new(input).map_err(|e| format!("read archive: {}", gzip::text(&e)))?;
    let mut tr = tar::Reader::new(gz).sparse(true);
    replace_dir(dir, space, |w| {
        loop {
            let h = match tr.next() {
                Ok(Some(h)) => h,
                Ok(None) => return check_end(tr.get_mut()),
                Err(e) => return Err(format!("read archive: {}", tar_text(&e))),
            };
            let typ = match h.typeflag {
                TYPE_DIR => b'd',
                TYPE_REG | TYPE_GNU_SPARSE => b'f',
                TYPE_SYMLINK => b'l',
                _ => {
                    return Err(format!(
                        "archive entry {}: only directories, regular files, and links can be restored",
                        quote(&h.name)
                    ));
                }
            };
            let e = Entry {
                name: h.name.clone(),
                typ,
                mode: (h.mode & 0o7777) as u32,
                uid: h.uid,
                gid: h.gid,
                mtime: h.mtime,
                link: h.linkname.clone(),
                size: h.size,
            };
            w.write(&e, &mut tr)?;
        }
    })
}

/// The padding after the tar's end blocks a restore reads at most: tar
/// writers pad to a record (10 KiB by default), never more than this.
const MAX_PADDING: u64 = 1 << 20;

/// What follows the tar's end: zeros only, up to the end of the gzip
/// stream, whose every member's trailer is checked on the way and after
/// whose last member nothing may follow.
fn check_end(r: &mut impl Read) -> Result<(), String> {
    let mut buf = vec![0u8; 32 << 10];
    let mut seen: u64 = 0;
    loop {
        match r.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                seen += n as u64;
                if buf[..n].iter().any(|c| *c != 0) || seen > MAX_PADDING {
                    return Err("read archive: data after the archive's end".into());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("read archive: {}", gzip::text(&e))),
        }
    }
}

fn tar_text(e: &tar::Error) -> String {
    match e {
        tar::Error::Io(e) => gzip::text(e),
        e => e.to_string(),
    }
}

/// restoreEntry.
pub struct Entry {
    pub name: Vec<u8>,
    pub typ: u8,
    /// Permission, setuid, setgid, and sticky bits.
    pub mode: u32,
    pub uid: i64,
    pub gid: i64,
    pub mtime: tar::Time,
    pub link: Vec<u8>,
    pub size: i64,
}

/// entryWriter.
pub struct Writer {
    root: Vec<u8>,
    /// Directories written: their modes and times are set last.
    dirs: Vec<(Vec<u8>, u32, tar::Time)>,
    space: Space,
    /// The mode bits chmod keeps: setuid and setgid only for root.
    keep: u32,
}

fn random_suffix() -> String {
    let mut b = [0u8; 6];
    // SAFETY: getrandom fills the buffer it is given.
    let n = unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) };
    if n != b.len() as isize {
        // Unique enough without randomness: the process and the clock.
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        b.copy_from_slice(&(t ^ u64::from(std::process::id()) << 32).to_le_bytes()[..6]);
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn lstat(p: &[u8]) -> Result<libc::stat, i32> {
    let c = cstr(p)?;
    // SAFETY: a zeroed stat filled by lstat with a valid C string.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::lstat(c.as_ptr(), &mut st) } < 0 {
        return Err(last_errno());
    }
    Ok(st)
}

fn stat(p: &[u8]) -> Result<libc::stat, i32> {
    let c = cstr(p)?;
    // SAFETY: as lstat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::stat(c.as_ptr(), &mut st) } < 0 {
        return Err(last_errno());
    }
    Ok(st)
}

fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

fn mkdir(p: &[u8], mode: u32) -> Result<(), i32> {
    let c = cstr(p)?;
    // SAFETY: mkdir with a valid C string.
    if unsafe { libc::mkdir(c.as_ptr(), mode) } < 0 {
        return Err(last_errno());
    }
    Ok(())
}

fn rename(a: &[u8], b: &[u8]) -> Result<(), String> {
    let (ca, cb) = (cstr(a).map_err(errno::text)?, cstr(b).map_err(errno::text)?);
    // SAFETY: rename with valid C strings.
    if unsafe { libc::rename(ca.as_ptr(), cb.as_ptr()) } < 0 {
        let e = last_errno();
        return Err(format!(
            "rename {} {}: {}",
            show(a),
            show(b),
            errno::text(e)
        ));
    }
    Ok(())
}

/// filepath.Dir.
fn parent(p: &[u8]) -> Vec<u8> {
    let i = p.iter().rposition(|c| *c == b'/').map_or(0, |i| i + 1);
    crate::runtime::image::unpack::clean(&p[..i])
}

/// os.MkdirAll(p, 0700).
fn mkdir_all(p: &[u8]) -> Result<(), String> {
    match stat(p) {
        Ok(st) if is_dir(&st) => return Ok(()),
        Ok(_) => return Err(path_err("mkdir", p, libc::ENOTDIR)),
        Err(_) => {}
    }
    let mut i = p.len();
    while i > 0 && p[i - 1] == b'/' {
        i -= 1;
    }
    let mut j = i;
    while j > 0 && p[j - 1] != b'/' {
        j -= 1;
    }
    if j > 1 {
        let up = &p[..j - 1];
        mkdir_all(if up.is_empty() { b"/" } else { up })?;
    }
    if let Err(e) = mkdir(p, 0o700) {
        if let Ok(st) = lstat(p)
            && is_dir(&st)
        {
            return Ok(());
        }
        return Err(path_err("mkdir", p, e));
    }
    Ok(())
}

/// fsutil.MkdirPrivate.
fn mkdir_private(p: &[u8]) -> Result<(), String> {
    mkdir_all(p)?;
    let st = stat(p).map_err(|e| path_err("stat", p, e))?;
    let perm = st.st_mode & 0o777;
    if perm & 0o077 != 0 {
        return Err(format!(
            "{} has mode {perm:04o}, want no group/other access (chmod go-rwx): insecure permissions",
            show(p)
        ));
    }
    Ok(())
}

fn remove_all(p: &[u8]) -> io::Result<()> {
    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(p));
    match std::fs::remove_dir_all(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}

use std::os::unix::ffi::OsStrExt;

/// replaceDir.
pub fn replace_dir(
    dir: &[u8],
    space: Space,
    fill: impl FnOnce(&mut Writer) -> Result<(), String>,
) -> Result<(), String> {
    mkdir_private(&parent(dir))?;
    let tmp = [dir, b".restore-", random_suffix().as_bytes()].concat();
    mkdir(&tmp, 0o700).map_err(|e| path_err("mkdir", &tmp, e))?;
    // SAFETY: geteuid cannot fail.
    let root_user = unsafe { libc::geteuid() } == 0;
    let mut w = Writer {
        root: tmp.clone(),
        dirs: Vec::new(),
        space,
        keep: if root_user { 0o7777 } else { 0o1777 },
    };
    let res = (|| {
        fill(&mut w)?;
        w.finish_dirs()?;
        let old = [dir, b".old-", random_suffix().as_bytes()].concat();
        let (cd, co) = (
            cstr(dir).map_err(errno::text)?,
            cstr(&old).map_err(errno::text)?,
        );
        // SAFETY: rename with valid C strings.
        if unsafe { libc::rename(cd.as_ptr(), co.as_ptr()) } < 0 {
            let e = last_errno();
            if e != libc::ENOENT {
                return Err(format!(
                    "rename {} {}: {}",
                    show(dir),
                    show(&old),
                    errno::text(e)
                ));
            }
        }
        if let Err(e) = rename(&tmp, dir) {
            let _ = rename(&old, dir);
            return Err(e);
        }
        Ok(old)
    })();
    match res {
        Ok(old) => remove_all(&old).map_err(|e| match e.raw_os_error() {
            Some(n) => path_err("unlinkat", &old, n),
            None => e.to_string(),
        }),
        Err(e) => {
            let _ = remove_all(&tmp);
            Err(e)
        }
    }
}

/// restoreReserve.
fn reserve(f: &Free) -> (u64, u64) {
    ((f.total_bytes / 20).max(1 << 30), f.total_inodes / 20)
}

/// os.Chtimes(p, t, t): the zero time leaves a time alone. A time past
/// what 64 bits of nanoseconds hold (2262) is set whole, not wrapped as
/// Go's UnixNano wraps it.
fn chtimes(p: &[u8], t: tar::Time) -> Result<(), i32> {
    const ZERO_SECS: i128 = -62_135_596_800;
    let ts = match t {
        Some(n) if n != ZERO_SECS * 1_000_000_000 => {
            let sec = n.div_euclid(1_000_000_000);
            libc::timespec {
                tv_sec: i64::try_from(sec).unwrap_or(if sec < 0 { i64::MIN } else { i64::MAX }),
                tv_nsec: n.rem_euclid(1_000_000_000) as i64,
            }
        }
        _ => libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
    };
    let c = cstr(p)?;
    let times = [ts, ts];
    // SAFETY: utimensat with a valid C string and two timespecs.
    if unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) } < 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// filepath.Join of a clean directory and one name.
fn join(a: &[u8], b: &[u8]) -> Vec<u8> {
    crate::runtime::image::unpack::join(a, b)
}

/// archivePath: "." (or "./") names the volume itself; an empty name
/// names nothing and is refused.
fn archive_path(root: &[u8], name: &[u8]) -> Result<Vec<u8>, String> {
    if name.is_empty() {
        return Err("archive entry \"\" has no name".into());
    }
    let trimmed = name.strip_suffix(b"/").unwrap_or(name);
    let clean = crate::runtime::image::unpack::clean(trimmed);
    if clean == b"." {
        return Ok(root.to_vec());
    }
    if clean.first() == Some(&b'/')
        || clean == b".."
        || clean.starts_with(b"../")
        || name.contains(&0)
    {
        return Err(format!(
            "archive entry {} is outside the volume",
            quote(name)
        ));
    }
    let parts: Vec<&[u8]> = clean.split(|c| *c == b'/').collect();
    let mut cur = root.to_vec();
    for p in &parts[..parts.len() - 1] {
        cur = join(&cur, p);
        match lstat(&cur) {
            Ok(st) if is_dir(&st) => {}
            _ => {
                return Err(format!(
                    "archive entry {}: {} is not a directory",
                    quote(name),
                    quote(p)
                ));
            }
        }
    }
    Ok(join(&cur, parts[parts.len() - 1]))
}

impl Writer {
    /// room.
    fn room(&self, e: &Entry) -> Result<(), String> {
        if e.size < 0 {
            return Err(format!("archive entry {}: negative size", quote(&e.name)));
        }
        let Some(f) = (self.space)(&self.root) else {
            return Ok(());
        };
        let (bytes, inodes) = reserve(&f);
        if f.bytes < bytes
            || f.bytes - bytes < e.size as u64
            || (f.total_inodes > 0 && f.inodes <= inodes)
        {
            return Err(format!(
                "archive entry {}: not enough space on the node: a restore leaves 5% of the volumes' file system free",
                quote(&e.name)
            ));
        }
        Ok(())
    }

    /// Every directory's mode, then its times, deepest first (a later
    /// entry of the same directory wins), so a directory that takes no
    /// writes still took its entries.
    fn finish_dirs(&mut self) -> Result<(), String> {
        let mut seen = std::collections::HashSet::new();
        let mut dirs: Vec<&(Vec<u8>, u32, tar::Time)> = self
            .dirs
            .iter()
            .rev()
            .filter(|d| seen.insert(d.0.clone()))
            .collect();
        let depth = |p: &[u8]| p.iter().filter(|c| **c == b'/').count();
        dirs.sort_by_key(|d| std::cmp::Reverse(depth(&d.0)));
        for (p, mode, t) in dirs {
            let c = cstr(p).map_err(errno::text)?;
            // SAFETY: chmod with a valid C string.
            if unsafe { libc::chmod(c.as_ptr(), *mode) } < 0 {
                return Err(path_err("chmod", p, last_errno()));
            }
            let _ = chtimes(p, *t);
        }
        Ok(())
    }

    /// write.
    pub fn write(&mut self, e: &Entry, content: &mut impl Read) -> Result<(), String> {
        let target = archive_path(&self.root, &e.name)?;
        let q = quote(&e.name);
        if target == self.root && e.typ != b'd' {
            return Err(format!(
                "archive entry {q} names the volume itself, which only a directory can"
            ));
        }
        self.room(e)?;
        let mode = e.mode & self.keep;
        match e.typ {
            b'd' => {
                if target != self.root
                    && let Err(err) = mkdir(&target, 0o700)
                    && err != libc::EEXIST
                {
                    return Err(path_err("mkdir", &target, err));
                }
                match lstat(&target) {
                    Ok(st) if is_dir(&st) => {}
                    _ => return Err(format!("archive entry {q} is not a directory")),
                }
                self.dirs.push((target.clone(), mode, e.mtime));
            }
            b'f' => {
                let c = cstr(&target)
                    .map_err(|n| format!("archive entry {q}: {}", path_err("open", &target, n)))?;
                // SAFETY: open with a valid C string.
                let fd = unsafe {
                    libc::open(
                        c.as_ptr(),
                        libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_WRONLY
                            | libc::O_NOFOLLOW
                            | libc::O_CLOEXEC,
                        0o600,
                    )
                };
                if fd < 0 {
                    return Err(format!(
                        "archive entry {q}: {}",
                        path_err("open", &target, last_errno())
                    ));
                }
                // SAFETY: fd was just opened and is owned by the file.
                let mut f = unsafe { <File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
                let res = copy_into(&mut f, &target, content, e.size);
                let close = close_file(f, &target);
                let n = match (res, close) {
                    (Err(err), _) | (Ok(_), Err(err)) => {
                        return Err(format!("archive entry {q}: {err}"));
                    }
                    (Ok(n), Ok(())) => n,
                };
                if n != e.size as u64 {
                    return Err(format!(
                        "archive entry {q}: content of {n} bytes, expected {}",
                        e.size
                    ));
                }
                chtimes(&target, e.mtime).map_err(|n| path_err("chtimes", &target, n))?;
            }
            b'l' => {
                let made = match (cstr(&e.link), cstr(&target)) {
                    // SAFETY: symlink with valid C strings.
                    (Ok(cl), Ok(ct)) => match unsafe { libc::symlink(cl.as_ptr(), ct.as_ptr()) } {
                        0 => Ok(()),
                        _ => Err(last_errno()),
                    },
                    _ => Err(libc::EINVAL),
                };
                if let Err(n) = made {
                    return Err(format!(
                        "archive entry {q}: symlink {} {}: {}",
                        show(&e.link),
                        show(&target),
                        errno::text(n)
                    ));
                }
            }
            _ => {
                return Err(format!(
                    "archive entry {q}: only directories, regular files, and links can be restored"
                ));
            }
        }
        let c = cstr(&target).map_err(errno::text)?;
        // SAFETY: lchown with a valid C string; ids truncate as Go's do.
        if unsafe { libc::lchown(c.as_ptr(), e.uid as u32, e.gid as u32) } < 0 {
            return Err(format!(
                "archive entry {q}: {}",
                path_err("lchown", &target, last_errno())
            ));
        }
        if e.typ == b'f' {
            // After the owner, which clears setuid and setgid.
            // SAFETY: chmod with a valid C string.
            if unsafe { libc::chmod(c.as_ptr(), mode) } < 0 {
                return Err(path_err("chmod", &target, last_errno()));
            }
        }
        Ok(())
    }
}

/// io.Copy(f, io.LimitReader(content, size+1)): the bytes copied.
fn copy_into(
    f: &mut File,
    target: &[u8],
    content: &mut impl Read,
    size: i64,
) -> Result<u64, String> {
    let mut left = (size as u64).saturating_add(1);
    let mut buf = vec![0u8; 32 << 10];
    let mut n: u64 = 0;
    while left > 0 {
        let want = buf.len().min(left.min(usize::MAX as u64) as usize);
        let k = match content.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(k) => k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(gzip::text(&e)),
        };
        if let Err(e) = f.write_all(&buf[..k]) {
            return Err(path_err(
                "write",
                target,
                e.raw_os_error().unwrap_or(libc::EIO),
            ));
        }
        n += k as u64;
        left -= k as u64;
    }
    Ok(n)
}

fn close_file(f: File, target: &[u8]) -> Result<(), String> {
    let fd = std::os::fd::IntoRawFd::into_raw_fd(f);
    // SAFETY: closes the descriptor the file owned.
    if unsafe { libc::close(fd) } < 0 {
        return Err(path_err("close", target, last_errno()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(name: &str) -> Vec<u8> {
        let d =
            std::env::temp_dir().join(format!("armada-node-restore-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let mut p = d.as_os_str().as_bytes().to_vec();
        p.extend_from_slice(b"/app/data");
        p
    }

    fn gz(b: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b).unwrap();
        e.finish().unwrap()
    }

    /// An archive Go's writer would make of entries (name, type, mode,
    /// mtime, body), owned by the user running the tests.
    fn archive(entries: &[(&str, u8, i64, i64, &str)]) -> Vec<u8> {
        let mut tw = super::super::archive::TarWriter::new(Vec::new());
        let (uid, gid) = unsafe { (i64::from(libc::getuid()), i64::from(libc::getgid())) };
        for (name, typeflag, mode, mtime, body) in entries {
            let h = super::super::archive::Hdr {
                name: name.as_bytes().to_vec(),
                link: Vec::new(),
                typeflag: *typeflag,
                mode: *mode,
                uid,
                gid,
                size: body.len() as i64,
                mtime: *mtime,
            };
            tw.write_header(&h).unwrap();
            tw.write_content(body.as_bytes()).unwrap();
        }
        tw.close().unwrap();
        tw.w
    }

    #[test]
    fn checks_the_whole_stream() {
        let dir = tmp("stream");
        let a = gz(&archive(&[("f", b'0', 0o600, 1, "hello")]));
        let mut bad = a.clone();
        let n = bad.len();
        bad[n - 8] ^= 0xff;
        assert_eq!(
            restore(&dir, &bad[..], |_| None).unwrap_err(),
            "read archive: gzip: invalid checksum"
        );
        let mut extra = a.clone();
        extra.extend_from_slice(b"garbage after the archive");
        assert_eq!(
            restore(&dir, &extra[..], |_| None).unwrap_err(),
            "read archive: gzip: invalid header"
        );
        // Data after the tar's end blocks, inside the gzip stream.
        let mut raw = archive(&[("f", b'0', 0o600, 1, "hello")]);
        raw.extend_from_slice(b"more");
        assert_eq!(
            restore(&dir, &gz(&raw)[..], |_| None).unwrap_err(),
            "read archive: data after the archive's end"
        );
        // Zeros after the end are a tar writer's padding.
        let mut raw = archive(&[("f", b'0', 0o600, 1, "hello")]);
        raw.extend_from_slice(&[0u8; 8192]);
        restore(&dir, &gz(&raw)[..], |_| None).unwrap();
        // Two gzip members are one stream.
        let raw = archive(&[("f", b'0', 0o600, 1, "hello")]);
        let mut two = gz(&raw[..1024]);
        two.extend(gz(&raw[1024..]));
        restore(&dir, &two[..], |_| None).unwrap();
        let _ = std::fs::remove_dir_all(
            std::path::Path::new(std::ffi::OsStr::from_bytes(&dir))
                .parent()
                .unwrap()
                .parent()
                .unwrap(),
        );
    }

    #[test]
    fn names_modes_and_times() {
        let dir = tmp("names");
        let p = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&dir));
        // An empty name, and a file naming the volume itself.
        for (name, want) in [
            ("", "archive entry \"\" has no name"),
            (
                "./",
                "archive entry \"./\" names the volume itself, which only a directory can",
            ),
        ] {
            let mut raw = archive(&[("x", b'0', 0o600, 1, "")]);
            // The name of the only entry, rewritten with its checksum.
            raw[..100].fill(0);
            raw[..name.len()].copy_from_slice(name.as_bytes());
            raw[148..156].copy_from_slice(b"        ");
            let sum: u32 = raw[..512].iter().map(|c| u32::from(*c)).sum();
            raw[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
            assert_eq!(restore(&dir, &gz(&raw)[..], |_| None).unwrap_err(), want);
        }
        // A read-only directory takes its entries; its mode and time are
        // set last; setuid and setgid are kept only for root; a time past
        // 2262 is not wrapped.
        let future = 10_413_792_000; // 2300-01-01
        let a = archive(&[
            ("ro/", b'5', 0o555, 1_600_000_000, ""),
            ("ro/f", b'0', 0o4755, future, "x"),
            ("ro/sub/", b'5', 0o500, 1_600_000_001, ""),
            ("ro/sub/g", b'0', 0o2644, 1, "y"),
        ]);
        restore(&dir, &gz(&a)[..], |_| None).unwrap();
        use std::os::unix::fs::MetadataExt;
        let m = |q: &str| std::fs::symlink_metadata(p.join(q)).unwrap();
        let special = if unsafe { libc::geteuid() } == 0 {
            0o6000
        } else {
            0
        };
        assert_eq!(m("ro").mode() & 0o7777, 0o555);
        assert_eq!(m("ro").mtime(), 1_600_000_000);
        assert_eq!(m("ro/sub").mode() & 0o7777, 0o500);
        assert_eq!(m("ro/sub").mtime(), 1_600_000_001);
        assert_eq!(m("ro/f").mode() & 0o7777, 0o755 | (special & 0o4000));
        assert_eq!(m("ro/sub/g").mode() & 0o7777, 0o644 | (special & 0o2000));
        assert_eq!(m("ro/f").mtime(), future);
        for d in ["ro/sub", "ro"] {
            std::fs::set_permissions(
                p.join(d),
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
        }
        let _ = std::fs::remove_dir_all(p.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn restores_sparse_files() {
        let dir = tmp("sparse");
        let p = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&dir));
        // A PAX 1.0 sparse file of 10 bytes holding "abc" at 2.
        let mut raw = Vec::new();
        let recs = "22 GNU.sparse.major=1\n22 GNU.sparse.minor=0\n21 GNU.sparse.name=s\n26 GNU.sparse.realsize=10\n";
        let mut tw = super::super::archive::TarWriter::new(Vec::new());
        let (uid, gid) = unsafe { (i64::from(libc::getuid()), i64::from(libc::getgid())) };
        let hdr = |name: &str, typeflag: u8, size: usize| super::super::archive::Hdr {
            name: name.as_bytes().to_vec(),
            link: Vec::new(),
            typeflag,
            mode: 0o640,
            uid,
            gid,
            size: size as i64,
            mtime: 1,
        };
        tw.write_header(&hdr("PaxHeaders/s", b'x', recs.len()))
            .unwrap();
        tw.write_content(recs.as_bytes()).unwrap();
        let mut map = b"1\n2\n3\n".to_vec();
        map.resize(512, 0);
        tw.write_header(&hdr("GNUSparseFile.0/s", b'0', 515))
            .unwrap();
        tw.write_content(&map).unwrap();
        tw.write_content(b"abc").unwrap();
        tw.close().unwrap();
        raw.extend(tw.w);
        restore(&dir, &gz(&raw)[..], |_| None).unwrap();
        assert_eq!(std::fs::read(p.join("s")).unwrap(), b"\0\0abc\0\0\0\0\0");
        let _ = std::fs::remove_dir_all(p.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn restores_and_refuses_as_go() {
        let dir = tmp("ok");
        let mut tw = super::super::archive::TarWriter::new(Vec::new());
        let (uid, gid) = unsafe { (i64::from(libc::getuid()), i64::from(libc::getgid())) };
        for (name, typeflag, mode, link, body) in [
            (".", b'5', 0o750, "", ""),
            ("d/", b'5', 0o755, "", ""),
            ("d/f", b'0', 0o640, "", "hi"),
            ("l", b'2', 0o777, "d/f", ""),
        ] {
            let h = super::super::archive::Hdr {
                name: name.into(),
                link: link.into(),
                typeflag,
                mode,
                uid,
                gid,
                size: body.len() as i64,
                mtime: 1_700_000_000,
            };
            tw.write_header(&h).unwrap();
            tw.write_content(body.as_bytes()).unwrap();
        }
        tw.close().unwrap();
        let a = tw.w;
        restore(&dir, &gz(&a)[..], |_| None).unwrap();
        let p = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&dir));
        assert_eq!(std::fs::read(p.join("d/f")).unwrap(), b"hi");
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(p.join("d/f")).unwrap();
        assert_eq!((m.mode() & 0o7777, m.mtime()), (0o640, 1_700_000_000));
        assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o7777, 0o750);
        assert_eq!(
            std::fs::read_link(p.join("l"))
                .unwrap()
                .as_os_str()
                .as_bytes(),
            b"d/f"
        );

        let a = tar::test_archive(&[("../x", TYPE_REG, "", "x")]);
        assert_eq!(
            restore(&dir, &gz(&a)[..], |_| None).unwrap_err(),
            "archive entry \"../x\" is outside the volume"
        );
        let a = tar::test_archive(&[("l/x", TYPE_REG, "", "x")]);
        assert_eq!(
            restore(&dir, &gz(&a)[..], |_| None).unwrap_err(),
            "archive entry \"l/x\": \"l\" is not a directory"
        );
        assert_eq!(std::fs::read(p.join("d/f")).unwrap(), b"hi");
        let full: Space = |_| {
            Some(Free {
                bytes: 1 << 30,
                total_bytes: 1 << 34,
                inodes: 10,
                total_inodes: 100,
            })
        };
        let a = tar::test_archive(&[("f", TYPE_REG, "", "x")]);
        assert!(
            restore(&dir, &gz(&a)[..], full)
                .unwrap_err()
                .contains("not enough space")
        );
        assert_eq!(
            restore(&dir, &b"nope, not a gzip stream"[..], |_| None).unwrap_err(),
            "read archive: gzip: invalid header"
        );
        let parent = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&dir))
            .parent()
            .unwrap()
            .to_path_buf();
        assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(parent.parent().unwrap());
    }
}

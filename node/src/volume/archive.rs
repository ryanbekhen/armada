//! writeArchive: a volume as a gzipped tar, with the headers Go's
//! archive/tar writes for tar.FileInfoHeader's fields (Uname and Gname
//! left empty): USTAR while every field fits it, PAX records otherwise,
//! modification times rounded to the second. The gzip stream is flate2's,
//! so the compressed bytes differ from Go's; the tar inside is the same.

use super::walk::{self, EntryError, Fail, Root, Stat};
use super::{answer_file, send_answer};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::os::fd::AsRawFd;

const BLOCK: usize = 512;

pub fn command(dir: &str) -> Result<(), String> {
    let mut answer = answer_file(3);
    let root = match Root::open(dir.as_bytes()) {
        Ok(r) => r,
        Err(e) => {
            let text = format!(
                "archive volume: {}",
                super::path_err("open", dir.as_bytes(), e)
            );
            return send_answer(
                &mut answer,
                &serde_json::json!({ "error": text, "changed": false }),
            );
        }
    };
    root.probe()?;
    let hook = Hook::from_env(dir);
    let out = io::BufWriter::with_capacity(64 << 10, io::stdout().lock());
    let gz = flate2::write::GzEncoder::new(out, flate2::Compression::default());
    let mut tw = TarWriter::new(gz);
    match archive(&root, &mut tw, &hook) {
        Ok(()) => {}
        Err(Failure::Entry(e)) => {
            // As Go, an archive that failed is not ended: the gzip stream
            // stays unfinished.
            std::mem::forget(tw);
            let text = format!("archive volume: {}", e.text());
            return send_answer(
                &mut answer,
                &serde_json::json!({ "error": text, "changed": e.changed() }),
            );
        }
        Err(Failure::Out(e)) => {
            std::mem::forget(tw);
            return Err(format!("write archive: {e}"));
        }
    }
    let finish = || -> io::Result<()> {
        tw.close()?;
        let mut out = tw.w.finish()?;
        out.flush()
    };
    finish().map_err(|e| format!("write archive: {e}"))?;
    send_answer(&mut answer, &serde_json::json!({}))
}

enum Failure {
    /// An entry's error, which the agent passes on.
    Entry(EntryError),
    /// stdout failed: the agent reads its own error.
    Out(io::Error),
}

fn archive<W: Write>(root: &Root, tw: &mut TarWriter<W>, hook: &Hook) -> Result<(), Failure> {
    walk::walk(root, &mut |p, v| {
        let st = v.map_err(Failure::Entry)?;
        if !st.is_dir() && !st.is_reg() && !st.is_link() {
            return Ok(());
        }
        let link = if st.is_link() {
            root.readlink(p)
                .map_err(|f| Failure::Entry(EntryError::new(p, f)))?
        } else {
            Vec::new()
        };
        let h = header(p, st, link);
        tw.write_header(&h).map_err(Failure::Out)?;
        if !st.is_reg() {
            return Ok(());
        }
        hook.run(p);
        let fd = root
            .open_same(p, st, false)
            .map_err(|f| Failure::Entry(EntryError::new(p, f)))?;
        copy(p, &fd, h.size, tw)
    })
}

/// io.CopyN of a file's size into the archive.
fn copy<W: Write>(
    p: &[u8],
    fd: &std::os::fd::OwnedFd,
    size: i64,
    tw: &mut TarWriter<W>,
) -> Result<(), Failure> {
    let mut left = size.max(0) as u64;
    let mut buf = vec![0u8; 64 << 10];
    while left > 0 {
        let want = buf.len().min(left.min(usize::MAX as u64) as usize);
        // SAFETY: read into a buffer of at least want bytes.
        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), want) };
        if n < 0 {
            let e = super::last_errno();
            if e == libc::EINTR {
                continue;
            }
            return Err(Failure::Entry(EntryError::new(p, Fail::Op("read", e))));
        }
        if n == 0 {
            return Err(Failure::Entry(EntryError::new(p, Fail::Eof)));
        }
        tw.write_content(&buf[..n as usize]).map_err(Failure::Out)?;
        left -= n as u64;
    }
    Ok(())
}

/// The fields of tar.FileInfoHeader that writeArchive keeps.
#[derive(Debug, Default, Clone)]
pub struct Hdr {
    pub name: Vec<u8>,
    pub link: Vec<u8>,
    pub typeflag: u8,
    pub mode: i64,
    pub uid: i64,
    pub gid: i64,
    pub size: i64,
    /// Seconds, already rounded (WriteHeader's ModTime.Round(time.Second)).
    pub mtime: i64,
}

fn header(p: &[u8], st: &Stat, link: Vec<u8>) -> Hdr {
    let mut name = p.to_vec();
    if st.is_dir() && p != b"." {
        name.push(b'/');
    }
    let typeflag = if st.is_reg() {
        b'0'
    } else if st.is_dir() {
        b'5'
    } else {
        b'2'
    };
    Hdr {
        name,
        link,
        typeflag,
        mode: i64::from(st.mode & 0o7777),
        uid: i64::from(st.uid),
        gid: i64::from(st.gid),
        size: if st.is_reg() { st.size } else { 0 },
        mtime: st.mtime + i64::from(st.mtime_nsec >= 500_000_000),
    }
}

/// Go's tar.Writer for the headers above.
pub struct TarWriter<W: Write> {
    pub w: W,
    pad: usize,
}

fn is_ascii(s: &[u8]) -> bool {
    s.iter().all(|c| *c < 0x80 && *c != 0)
}

fn to_ascii(s: &[u8]) -> Vec<u8> {
    s.iter().copied().filter(|c| *c < 0x80 && *c != 0).collect()
}

fn fits_octal(n: usize, x: i64) -> bool {
    let bits = (n as u32 - 1) * 3;
    x >= 0 && (n >= 22 || x < 1i64 << bits)
}

/// splitUSTARPath.
fn split_ustar(name: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut length = name.len();
    if length <= 100 || !is_ascii(name) {
        return None;
    } else if length > 156 {
        length = 156;
    } else if name[length - 1] == b'/' {
        length -= 1;
    }
    let i = name[..length].iter().rposition(|c| *c == b'/')?;
    let nlen = name.len() - i - 1;
    if i == 0 || nlen > 100 || nlen == 0 || i > 155 {
        return None;
    }
    Some((&name[..i], &name[i + 1..]))
}

/// formatter.formatString.
fn format_string(b: &mut [u8], s: &[u8]) {
    let n = s.len().min(b.len());
    b[..n].copy_from_slice(&s[..n]);
    if s.len() < b.len() {
        b[s.len()] = 0;
    }
    if s.len() > b.len() && b[b.len() - 1] == b'/' {
        let mut k = b.len() - 1;
        while k > 0 && s[k - 1] == b'/' {
            k -= 1;
        }
        b[k] = 0;
    }
}

/// formatter.formatOctal (zero when it does not fit).
fn format_octal(b: &mut [u8], x: i64) {
    let x = if fits_octal(b.len(), x) { x } else { 0 };
    let s = format!("{x:o}");
    let pad = (b.len() - 1).saturating_sub(s.len());
    let s = format!("{}{s}", "0".repeat(pad));
    format_string(b, s.as_bytes());
}

fn checksum(b: &[u8; BLOCK]) -> i64 {
    b.iter()
        .enumerate()
        .map(|(i, c)| i64::from(if (148..156).contains(&i) { b' ' } else { *c }))
        .sum()
}

/// setFormat for USTAR and PAX: the magic, then the checksum.
fn set_ustar(b: &mut [u8; BLOCK]) {
    b[257..263].copy_from_slice(b"ustar\0");
    b[263..265].copy_from_slice(b"00");
    let c = checksum(b);
    format_octal(&mut b[148..155], c);
    b[155] = b' ';
}

/// formatPAXRecord.
fn pax_record(k: &str, v: &[u8]) -> Vec<u8> {
    let mut size = k.len() + v.len() + 3;
    size += size.to_string().len();
    let rec = |size: usize| {
        [
            size.to_string().as_bytes(),
            b" ",
            k.as_bytes(),
            b"=",
            v,
            b"\n",
        ]
        .concat()
    };
    let r = rec(size);
    if r.len() != size { rec(r.len()) } else { r }
}

/// path.Join of the PAX header's name.
fn pax_name(real: &[u8]) -> Vec<u8> {
    let i = real.iter().rposition(|c| *c == b'/').map_or(0, |i| i + 1);
    let (dir, file) = (&real[..i], &real[i..]);
    let parts: Vec<&[u8]> = [dir, b"PaxHeaders.0".as_slice(), file]
        .into_iter()
        .filter(|p| !p.is_empty())
        .collect();
    crate::runtime::image::unpack::clean(&parts.join(&b'/'))
}

impl<W: Write> TarWriter<W> {
    pub fn new(w: W) -> Self {
        TarWriter { w, pad: 0 }
    }

    fn flush_pad(&mut self) -> io::Result<()> {
        if self.pad > 0 {
            self.w.write_all(&[0u8; BLOCK][..self.pad])?;
            self.pad = 0;
        }
        Ok(())
    }

    fn template(&self, h: &Hdr, ascii: bool) -> [u8; BLOCK] {
        let mut b = [0u8; BLOCK];
        let s = |v: &[u8]| if ascii { to_ascii(v) } else { v.to_vec() };
        b[156] = h.typeflag;
        format_string(&mut b[0..100], &s(&h.name));
        format_string(&mut b[157..257], &s(&h.link));
        format_octal(&mut b[100..108], h.mode);
        format_octal(&mut b[108..116], h.uid);
        format_octal(&mut b[116..124], h.gid);
        format_octal(&mut b[124..136], h.size);
        format_octal(&mut b[136..148], h.mtime);
        format_string(&mut b[265..297], b"");
        format_string(&mut b[297..329], b"");
        format_octal(&mut b[329..337], 0);
        format_octal(&mut b[337..345], 0);
        b
    }

    fn raw(&mut self, b: &[u8; BLOCK], size: i64, typeflag: u8) -> io::Result<()> {
        self.w.write_all(b)?;
        let size = if matches!(typeflag, b'1'..=b'6') {
            0
        } else {
            size
        };
        self.pad = (BLOCK - (size as usize % BLOCK)) % BLOCK;
        Ok(())
    }

    /// WriteHeader with no format chosen.
    pub fn write_header(&mut self, h: &Hdr) -> io::Result<()> {
        self.flush_pad()?;
        let mut pax: BTreeMap<&str, Vec<u8>> = BTreeMap::new();
        let mut ustar = true;
        if !is_ascii(&h.name) || h.name.len() > 100 {
            if split_ustar(&h.name).is_none() {
                ustar = false;
            }
            pax.insert("path", h.name.clone());
        }
        if !is_ascii(&h.link) || h.link.len() > 100 {
            ustar = false;
            pax.insert("linkpath", h.link.clone());
        }
        for (k, n, v) in [
            ("uid", 8, h.uid),
            ("gid", 8, h.gid),
            ("size", 12, h.size),
            ("mtime", 12, h.mtime),
        ] {
            if !fits_octal(n, v) {
                ustar = false;
                pax.insert(k, v.to_string().into_bytes());
            }
        }
        if ustar {
            let (prefix, name) = split_ustar(&h.name).unwrap_or((b"", &h.name));
            let short = Hdr {
                name: name.to_vec(),
                ..h.clone()
            };
            let mut b = self.template(&short, false);
            format_string(&mut b[345..500], prefix);
            set_ustar(&mut b);
            return self.raw(&b, h.size, h.typeflag);
        }
        let data: Vec<u8> = pax.iter().flat_map(|(k, v)| pax_record(k, v)).collect();
        let mut name = to_ascii(&pax_name(&h.name));
        name.truncate(100);
        while name.last() == Some(&b'/') {
            name.pop();
        }
        let mut b = [0u8; BLOCK];
        b[156] = b'x';
        format_string(&mut b[0..100], &name);
        format_octal(&mut b[100..108], 0);
        format_octal(&mut b[108..116], 0);
        format_octal(&mut b[116..124], 0);
        format_octal(&mut b[124..136], data.len() as i64);
        format_octal(&mut b[136..148], 0);
        set_ustar(&mut b);
        self.raw(&b, data.len() as i64, b'x')?;
        self.w.write_all(&data)?;
        self.flush_pad()?;
        let mut b = self.template(h, true);
        set_ustar(&mut b);
        self.raw(&b, h.size, h.typeflag)
    }

    pub fn write_content(&mut self, b: &[u8]) -> io::Result<()> {
        self.w.write_all(b)
    }

    /// Close: the padding of the last entry and two zero blocks.
    pub fn close(&mut self) -> io::Result<()> {
        self.flush_pad()?;
        self.w.write_all(&[0u8; 2 * BLOCK])
    }
}

/// The test hook (ARMADA_NODE_TEST_VOLUME_HOOK=ENTRY:fifo|truncate).
struct Hook {
    dir: String,
    entry: Vec<u8>,
    action: String,
}

impl Hook {
    fn from_env(dir: &str) -> Hook {
        let v = std::env::var_os("ARMADA_NODE_TEST_VOLUME_HOOK").unwrap_or_default();
        let v = std::os::unix::ffi::OsStrExt::as_bytes(v.as_os_str()).to_vec();
        let (entry, action) = match v.iter().rposition(|c| *c == b':') {
            Some(i) => (
                v[..i].to_vec(),
                String::from_utf8_lossy(&v[i + 1..]).into_owned(),
            ),
            None => (Vec::new(), String::new()),
        };
        Hook {
            dir: dir.to_string(),
            entry,
            action,
        }
    }

    fn run(&self, p: &[u8]) {
        if self.entry.is_empty() || p != self.entry.as_slice() {
            return;
        }
        let mut path = self.dir.as_bytes().to_vec();
        path.push(b'/');
        path.extend_from_slice(p);
        let Ok(c) = super::cstr(&path) else { return };
        // SAFETY: plain calls with a valid C string, for tests only.
        unsafe {
            match self.action.as_str() {
                "fifo" => {
                    libc::unlink(c.as_ptr());
                    libc::mkfifo(c.as_ptr(), 0o600);
                }
                "truncate" => {
                    libc::truncate(c.as_ptr(), 0);
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_ustar_names_as_go() {
        let long = format!("{}/{}", "a".repeat(60), "b".repeat(60));
        assert_eq!(
            split_ustar(long.as_bytes()),
            Some(("a".repeat(60).as_bytes(), "b".repeat(60).as_bytes()))
        );
        assert_eq!(split_ustar(b"short"), None);
        assert_eq!(split_ustar("x".repeat(101).as_bytes()), None);
    }

    #[test]
    fn formats_pax_records_as_go() {
        assert_eq!(pax_record("path", b"abc"), b"12 path=abc\n");
        assert_eq!(pax_record("k", &[b'v'; 4]), b"9 k=vvvv\n");
        assert_eq!(pax_record("k", &[b'v'; 5]), b"11 k=vvvvv\n");
        assert_eq!(pax_name(b"a/b/"), b"a/b/PaxHeaders.0");
        assert_eq!(pax_name(b"f"), b"PaxHeaders.0/f");
    }
}

//! Go's archive/tar reader (reader.go, strconv.go, format.go) as
//! containerd's applier reads a layer with it: the same headers (V7,
//! USTAR, PAX, GNU, STAR), the same PAX records and GNU long names, the
//! same numbers (octal and base-256), and the same errors where an
//! archive is malformed. GNU sparse files, which no image builder writes,
//! are refused rather than read.

use std::collections::BTreeMap;
use std::io::{self, Read};

pub const TYPE_REG: u8 = b'0';
pub const TYPE_REGA: u8 = 0;
pub const TYPE_LINK: u8 = b'1';
pub const TYPE_SYMLINK: u8 = b'2';
pub const TYPE_CHAR: u8 = b'3';
pub const TYPE_BLOCK: u8 = b'4';
pub const TYPE_DIR: u8 = b'5';
pub const TYPE_FIFO: u8 = b'6';
pub const TYPE_XHEADER: u8 = b'x';
pub const TYPE_XGLOBAL: u8 = b'g';
pub const TYPE_GNU_SPARSE: u8 = b'S';
pub const TYPE_GNU_LONGNAME: u8 = b'L';
pub const TYPE_GNU_LONGLINK: u8 = b'K';

const BLOCK: usize = 512;
const MAX_SPECIAL_FILE: usize = 1 << 20;
const PAX_XATTR: &str = "SCHILY.xattr.";

/// A time as Go's time.Time holds it: nanoseconds since the epoch, or
/// none for the zero time (year 1).
pub type Time = Option<i128>;

fn unix(secs: i64, nanos: i64) -> Time {
    Some(i128::from(secs) * 1_000_000_000 + i128::from(nanos))
}

/// tar.Header: the fields the applier reads.
#[derive(Clone, Debug, Default)]
pub struct Header {
    pub typeflag: u8,
    pub name: Vec<u8>,
    pub linkname: Vec<u8>,
    pub size: i64,
    pub mode: i64,
    pub uid: i64,
    pub gid: i64,
    pub mtime: Time,
    pub atime: Time,
    pub devmajor: i64,
    pub devminor: i64,
    /// Every PAX record of the entry (PAXRecords), keys as written.
    pub pax: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Header {
    /// The extended attributes the entry carries (SCHILY.xattr.*).
    pub fn xattrs(&self) -> Vec<(&[u8], &[u8])> {
        self.pax
            .iter()
            .filter_map(|(k, v)| {
                k.strip_prefix(PAX_XATTR.as_bytes())
                    .map(|n| (n, v.as_slice()))
            })
            .collect()
    }
}

#[derive(Debug)]
pub enum Error {
    /// tar.ErrHeader and the other format errors.
    Header(&'static str),
    Io(io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Header(m) => write!(f, "{m}"),
            Error::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof => write!(f, "unexpected EOF"),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

const ERR_HEADER: Error = Error::Header("archive/tar: invalid tar header");

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

pub struct Reader<R: Read> {
    r: R,
    /// Bytes of the current entry not read yet.
    remaining: u64,
    pad: u64,
    failed: bool,
}

/// io.ReadFull: Ok(false) for a clean EOF before any byte.
fn read_full(r: &mut impl Read, b: &mut [u8]) -> Result<bool, io::Error> {
    let mut n = 0;
    while n < b.len() {
        match r.read(&mut b[n..]) {
            Ok(0) if n == 0 => return Ok(false),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

fn discard(r: &mut impl Read, n: u64) -> Result<(), io::Error> {
    let got = io::copy(&mut r.take(n), &mut io::sink())?;
    if got < n {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

fn parse_string(b: &[u8]) -> Vec<u8> {
    match b.iter().position(|c| *c == 0) {
        Some(i) => b[..i].to_vec(),
        None => b.to_vec(),
    }
}

/// parser: remembers the last error like Go's.
#[derive(Default)]
struct Parser {
    err: bool,
}

impl Parser {
    fn numeric(&mut self, b: &[u8]) -> i64 {
        if !b.is_empty() && b[0] & 0x80 != 0 {
            let inv: u8 = if b[0] & 0x40 != 0 { 0xff } else { 0 };
            let mut x: u64 = 0;
            for (i, c) in b.iter().enumerate() {
                let mut c = c ^ inv;
                if i == 0 {
                    c &= 0x7f;
                }
                if x >> 56 > 0 {
                    self.err = true;
                    return 0;
                }
                x = x << 8 | u64::from(c);
            }
            if x >> 63 > 0 {
                self.err = true;
                return 0;
            }
            return if inv == 0xff { !(x as i64) } else { x as i64 };
        }
        self.octal(b)
    }

    fn octal(&mut self, b: &[u8]) -> i64 {
        let trim = |c: &u8| *c == b' ' || *c == 0;
        let start = b.iter().position(|c| !trim(c)).unwrap_or(b.len());
        let end = b.iter().rposition(|c| !trim(c)).map_or(start, |i| i + 1);
        let b = &b[start..end.max(start)];
        if b.is_empty() {
            return 0;
        }
        let s = parse_string(b);
        match std::str::from_utf8(&s).ok().and_then(|s| parse_uint(s, 8)) {
            Some(v) => v as i64,
            None => {
                self.err = true;
                // strconv.ParseUint returns the largest value on range
                // errors and 0 on syntax errors; either way an error.
                0
            }
        }
    }
}

/// strconv.ParseUint(s, base, 64) without sign or underscores.
fn parse_uint(s: &str, base: u32) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for c in s.chars() {
        let d = c.to_digit(base)?;
        v = v.checked_mul(u64::from(base))?.checked_add(u64::from(d))?;
    }
    Some(v)
}

/// strconv.ParseInt(s, 10, 64).
fn parse_int(s: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(s).ok()?;
    let (neg, digits) = match s.as_bytes().first()? {
        b'-' => (true, &s[1..]),
        b'+' => (false, &s[1..]),
        _ => (false, s),
    };
    let v = parse_uint(digits, 10)?;
    if neg {
        if v > 1 << 63 {
            return None;
        }
        Some((v as i64).wrapping_neg())
    } else {
        i64::try_from(v).ok()
    }
}

/// parsePAXTime.
fn parse_pax_time(s: &[u8]) -> Result<Time, Error> {
    let (ss, sn) = match s.iter().position(|c| *c == b'.') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, &[][..]),
    };
    let secs = parse_int(ss).ok_or(ERR_HEADER)?;
    if sn.is_empty() {
        return Ok(unix(secs, 0));
    }
    let mut digits = [b'0'; 9];
    for (i, c) in sn.iter().enumerate() {
        if !c.is_ascii_digit() {
            return Err(ERR_HEADER);
        }
        if i < 9 {
            digits[i] = *c;
        }
    }
    let nanos = parse_int(&digits).unwrap_or(0);
    if ss.first() == Some(&b'-') {
        return Ok(unix(secs, -nanos));
    }
    Ok(unix(secs, nanos))
}

fn has_nul(b: &[u8]) -> bool {
    b.contains(&0)
}

/// parsePAXRecord.
/// A PAX record's key and value, and what follows it.
type Record<'a> = (Vec<u8>, Vec<u8>, &'a [u8]);

fn parse_pax_record(s: &[u8]) -> Result<Record<'_>, Error> {
    let sp = s.iter().position(|c| *c == b' ').ok_or(ERR_HEADER)?;
    let n_str = &s[..sp];
    let rest = &s[sp + 1..];
    let n = parse_int(n_str).ok_or(ERR_HEADER)?;
    if n < 5 || n > s.len() as i64 {
        return Err(ERR_HEADER);
    }
    let n = n - (n_str.len() as i64 + 1);
    if n <= 0 {
        return Err(ERR_HEADER);
    }
    let n = n as usize;
    if n > rest.len() {
        return Err(ERR_HEADER);
    }
    let (rec, nl, rem) = (&rest[..n - 1], &rest[n - 1..n], &rest[n..]);
    if nl != b"\n" {
        return Err(ERR_HEADER);
    }
    let eq = rec.iter().position(|c| *c == b'=').ok_or(ERR_HEADER)?;
    let (k, v) = (&rec[..eq], &rec[eq + 1..]);
    let valid = !k.is_empty()
        && !k.contains(&b'=')
        && match k {
            b"path" | b"linkpath" | b"uname" | b"gname" => !has_nul(v),
            _ => !has_nul(k),
        };
    if !valid {
        return Err(ERR_HEADER);
    }
    Ok((k.to_vec(), v.to_vec(), rem))
}

fn is_header_only(flag: u8) -> bool {
    matches!(
        flag,
        TYPE_LINK | TYPE_SYMLINK | TYPE_CHAR | TYPE_BLOCK | TYPE_DIR | TYPE_FIFO
    )
}

#[derive(PartialEq)]
enum Format {
    Unknown,
    V7,
    Ustar,
    Star,
    Gnu,
}

fn checksum(b: &[u8; BLOCK]) -> (i64, i64) {
    let (mut u, mut s) = (0i64, 0i64);
    for (i, c) in b.iter().enumerate() {
        let c = if (148..156).contains(&i) { b' ' } else { *c };
        u += i64::from(c);
        s += i64::from(c as i8);
    }
    (u, s)
}

fn get_format(b: &[u8; BLOCK]) -> Format {
    let mut p = Parser::default();
    let value = p.octal(&b[148..156]);
    let (u, s) = checksum(b);
    if p.err || (value != u && value != s) {
        return Format::Unknown;
    }
    let magic = &b[257..263];
    let version = &b[263..265];
    let trailer = &b[508..512];
    if magic == b"ustar\0" && trailer == b"tar\0" {
        Format::Star
    } else if magic == b"ustar\0" {
        Format::Ustar
    } else if magic == b"ustar " && version == b" \0" {
        Format::Gnu
    } else {
        Format::V7
    }
}

impl<R: Read> Reader<R> {
    pub fn new(r: R) -> Self {
        Reader {
            r,
            remaining: 0,
            pad: 0,
            failed: false,
        }
    }

    /// Next: the next entry, or None at the end of the archive.
    pub fn next(&mut self) -> Result<Option<Header>, Error> {
        if self.failed {
            return Err(Error::Header("archive/tar: read after an error"));
        }
        let r = self.next_inner();
        if r.is_err() {
            self.failed = true;
        }
        r
    }

    fn set_entry(&mut self, h: &Header) -> Result<(), Error> {
        let nb = if is_header_only(h.typeflag) {
            0
        } else {
            h.size
        };
        if nb < 0 {
            return Err(ERR_HEADER);
        }
        self.remaining = nb as u64;
        self.pad = (BLOCK as u64 - (nb as u64 % BLOCK as u64)) % BLOCK as u64;
        Ok(())
    }

    fn read_special(&mut self) -> Result<Vec<u8>, Error> {
        let mut b = Vec::new();
        let n = self.remaining.min(MAX_SPECIAL_FILE as u64 + 1);
        (&mut self.r).take(n).read_to_end(&mut b)?;
        self.remaining -= b.len() as u64;
        if b.len() > MAX_SPECIAL_FILE {
            return Err(Error::Header("archive/tar: header field too long"));
        }
        if self.remaining > 0 && (b.len() as u64) < n {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        Ok(b)
    }

    fn next_inner(&mut self) -> Result<Option<Header>, Error> {
        let mut pax: Option<BTreeMap<Vec<u8>, Vec<u8>>> = None;
        let mut long_name: Vec<u8> = Vec::new();
        let mut long_link: Vec<u8> = Vec::new();
        loop {
            discard(&mut self.r, self.remaining)?;
            self.remaining = 0;
            // tryReadFull of the padding.
            let mut padb = vec![0u8; self.pad as usize];
            let mut got = 0;
            while got < padb.len() {
                match self.r.read(&mut padb[got..]) {
                    Ok(0) => break,
                    Ok(k) => got += k,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e.into()),
                }
            }
            if got < padb.len() {
                // tryReadFull's io.EOF, which ends the archive.
                return Ok(None);
            }
            self.pad = 0;
            let Some(mut h) = self.read_header()? else {
                return Ok(None);
            };
            self.set_entry(&h)?;
            match h.typeflag {
                TYPE_XHEADER | TYPE_XGLOBAL => {
                    let recs = self.parse_pax()?;
                    if h.typeflag == TYPE_XGLOBAL {
                        merge_pax(&mut h, &recs)?;
                        return Ok(Some(Header {
                            typeflag: h.typeflag,
                            name: h.name,
                            pax: recs,
                            ..Default::default()
                        }));
                    }
                    pax = Some(recs);
                    continue;
                }
                TYPE_GNU_LONGNAME | TYPE_GNU_LONGLINK => {
                    let b = self.read_special()?;
                    if h.typeflag == TYPE_GNU_LONGNAME {
                        long_name = parse_string(&b);
                    } else {
                        long_link = parse_string(&b);
                    }
                    continue;
                }
                _ => {
                    if let Some(recs) = &pax {
                        merge_pax(&mut h, recs)?;
                    }
                    if !long_name.is_empty() {
                        h.name = std::mem::take(&mut long_name);
                    }
                    if !long_link.is_empty() {
                        h.linkname = std::mem::take(&mut long_link);
                    }
                    if h.typeflag == TYPE_REGA {
                        h.typeflag = if h.name.ends_with(b"/") {
                            TYPE_DIR
                        } else {
                            TYPE_REG
                        };
                    }
                    self.set_entry(&h)?;
                    let sparse_pax = [
                        b"GNU.sparse.major".as_slice(),
                        b"GNU.sparse.minor",
                        b"GNU.sparse.map",
                        b"GNU.sparse.numblocks",
                    ]
                    .iter()
                    .any(|k| h.pax.get(*k).is_some_and(|v| !v.is_empty()));
                    if h.typeflag == TYPE_GNU_SPARSE || sparse_pax {
                        return Err(Error::Header("archive/tar: sparse files are not supported"));
                    }
                    return Ok(Some(h));
                }
            }
        }
    }

    fn parse_pax(&mut self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Error> {
        let buf = self.read_special()?;
        let mut s: &[u8] = &buf;
        let mut out = BTreeMap::new();
        let mut sparse: Vec<Vec<u8>> = Vec::new();
        while !s.is_empty() {
            let (k, v, rest) = parse_pax_record(s)?;
            s = rest;
            match k.as_slice() {
                b"GNU.sparse.offset" | b"GNU.sparse.numbytes" => {
                    let even = sparse.len().is_multiple_of(2);
                    if (even && k != b"GNU.sparse.offset")
                        || (!even && k != b"GNU.sparse.numbytes")
                        || v.contains(&b',')
                    {
                        return Err(ERR_HEADER);
                    }
                    sparse.push(v);
                }
                _ => {
                    out.insert(k, v);
                }
            }
        }
        if !sparse.is_empty() {
            out.insert(b"GNU.sparse.map".to_vec(), sparse.join(&b","[..]));
        }
        Ok(out)
    }

    fn read_header(&mut self) -> Result<Option<Header>, Error> {
        let mut b = [0u8; BLOCK];
        if !read_full(&mut self.r, &mut b)? {
            return Ok(None);
        }
        if b.iter().all(|c| *c == 0) {
            if !read_full(&mut self.r, &mut b)? {
                return Ok(None);
            }
            if b.iter().all(|c| *c == 0) {
                return Ok(None);
            }
            return Err(ERR_HEADER);
        }
        let format = get_format(&b);
        if format == Format::Unknown {
            return Err(ERR_HEADER);
        }
        let mut p = Parser::default();
        let mut h = Header {
            typeflag: b[156],
            name: parse_string(&b[0..100]),
            linkname: parse_string(&b[157..257]),
            size: p.numeric(&b[124..136]),
            mode: p.numeric(&b[100..108]),
            uid: p.numeric(&b[108..116]),
            gid: p.numeric(&b[116..124]),
            ..Default::default()
        };
        h.mtime = unix(p.numeric(&b[136..148]), 0);
        if format != Format::V7 {
            h.devmajor = p.numeric(&b[329..337]);
            h.devminor = p.numeric(&b[337..345]);
            let mut prefix: Vec<u8> = Vec::new();
            match format {
                Format::Ustar => prefix = parse_string(&b[345..500]),
                Format::Star => {
                    prefix = parse_string(&b[345..476]);
                    h.atime = unix(p.numeric(&b[476..488]), 0);
                }
                Format::Gnu => {
                    let mut p2 = Parser::default();
                    if b[345] != 0 {
                        h.atime = unix(p2.numeric(&b[345..357]), 0);
                    }
                    if b[357] != 0 {
                        let _ = p2.numeric(&b[357..369]);
                    }
                    if p2.err {
                        h.atime = None;
                        let s = parse_string(&b[345..500]);
                        if s.iter().all(|c| *c < 0x80 && *c != 0) {
                            prefix = s;
                        }
                    }
                }
                _ => {}
            }
            if !prefix.is_empty() {
                let mut n = prefix;
                n.push(b'/');
                n.extend_from_slice(&h.name);
                h.name = n;
            }
        }
        if p.err {
            return Err(ERR_HEADER);
        }
        Ok(Some(h))
    }
}

/// mergePAX.
fn merge_pax(h: &mut Header, recs: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<(), Error> {
    for (k, v) in recs {
        if v.is_empty() {
            continue;
        }
        match k.as_slice() {
            b"path" => h.name = v.clone(),
            b"linkpath" => h.linkname = v.clone(),
            b"uid" => h.uid = parse_int(v).ok_or(ERR_HEADER)?,
            b"gid" => h.gid = parse_int(v).ok_or(ERR_HEADER)?,
            b"atime" => h.atime = parse_pax_time(v)?,
            b"mtime" => h.mtime = parse_pax_time(v)?,
            b"ctime" => {
                parse_pax_time(v)?;
            }
            b"size" => h.size = parse_int(v).ok_or(ERR_HEADER)?,
            _ => {}
        }
    }
    h.pax = recs.clone();
    Ok(())
}

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let n = buf
            .len()
            .min(self.remaining.min(usize::MAX as u64) as usize);
        let k = self.r.read(&mut buf[..n])?;
        if k == 0 {
            self.failed = true;
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.remaining -= k as u64;
        Ok(k)
    }
}

/// An archive of entries (name, type, link name, body) for tests, owned
/// by the user running them.
#[cfg(test)]
pub fn test_archive(entries: &[(&str, u8, &str, &str)]) -> Vec<u8> {
    let mut a = Vec::new();
    for (name, flag, link, body) in entries {
        let mut h = tests::header(name, *flag, body.len());
        h[157..157 + link.len()].copy_from_slice(link.as_bytes());
        // SAFETY: getuid and getgid cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        h[108..116].copy_from_slice(format!("{uid:07o}\0").as_bytes());
        h[116..124].copy_from_slice(format!("{gid:07o}\0").as_bytes());
        h[148..156].copy_from_slice(b"        ");
        let (u, _) = checksum(&h);
        h[148..156].copy_from_slice(format!("{u:06o}\0 ").as_bytes());
        a.extend(h);
        a.extend(body.as_bytes());
        tests::pad(&mut a);
    }
    a.extend([0u8; 2 * BLOCK]);
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn header(name: &str, flag: u8, size: usize) -> [u8; BLOCK] {
        let mut b = [0u8; BLOCK];
        b[..name.len()].copy_from_slice(name.as_bytes());
        b[100..108].copy_from_slice(b"0000644\0");
        b[108..116].copy_from_slice(b"0001750\0");
        b[116..124].copy_from_slice(b"0001750\0");
        b[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        b[136..148].copy_from_slice(b"00000000001\0");
        b[156] = flag;
        b[257..263].copy_from_slice(b"ustar\0");
        b[263..265].copy_from_slice(b"00");
        let (u, _) = checksum(&b);
        b[148..156].copy_from_slice(format!("{u:06o}\0 ").as_bytes());
        b
    }

    pub fn pad(v: &mut Vec<u8>) {
        while !v.len().is_multiple_of(BLOCK) {
            v.push(0);
        }
    }

    #[test]
    fn reads_ustar_and_pax() {
        let mut a = Vec::new();
        let recs = "30 mtime=1700000000.123456789\n25 SCHILY.xattr.user.a=b\n";
        a.extend(header("PaxHeaders/f", TYPE_XHEADER, recs.len()));
        a.extend(recs.as_bytes());
        pad(&mut a);
        a.extend(header("f", TYPE_REG, 3));
        a.extend(b"abc");
        pad(&mut a);
        a.extend(header("d/", TYPE_REGA, 0));
        a.extend([0u8; 1024]);
        let mut r = Reader::new(&a[..]);
        let h = r.next().unwrap().unwrap();
        assert_eq!(h.name, b"f");
        assert_eq!(h.uid, 1000);
        assert_eq!(h.mtime, Some(1_700_000_000_123_456_789));
        assert_eq!(h.xattrs(), vec![(&b"user.a"[..], &b"b"[..])]);
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "abc");
        let h = r.next().unwrap().unwrap();
        assert_eq!(h.typeflag, TYPE_DIR);
        assert!(r.next().unwrap().is_none());
    }

    #[test]
    fn refuses_bad_headers() {
        let mut b = header("f", TYPE_REG, 0);
        b[0] = b'g';
        let mut r = Reader::new(&b[..]);
        assert!(r.next().is_err());
        let mut a = vec![0u8; BLOCK];
        a.extend(header("f", TYPE_REG, 0));
        assert!(Reader::new(&a[..]).next().is_err());
    }

    #[test]
    fn parses_numbers_as_go() {
        let mut p = Parser::default();
        assert_eq!(p.numeric(&[0x80, 0, 0, 0, 0, 0, 0, 1]), 1);
        assert_eq!(p.numeric(&[0xff; 8]), -1);
        assert_eq!(p.numeric(b" 17 \0"), 15);
        assert!(!p.err);
        p.numeric(b"9");
        assert!(p.err);
        assert_eq!(parse_pax_time(b"-1.5").unwrap(), unix(-1, -500_000_000));
        assert!(parse_pax_time(b"1.x").is_err());
    }
}

//! A reader of the tar archives armadad opens (the runtime pack, release
//! archives): USTAR, PAX extended headers, and GNU long names, as Go's
//! archive/tar reads the ones Go's writers and GoReleaser make.

use std::io::Read;

/// One entry's header.
#[derive(Debug, Clone)]
pub struct Header {
    pub name: String,
    pub size: u64,
    /// The type flag ('0' for a regular file, '5' for a directory, ...).
    pub typeflag: u8,
    pub mode: u32,
}

impl Header {
    /// TypeReg (or the old '\0').
    pub fn is_regular(&self) -> bool {
        self.typeflag == b'0' || self.typeflag == 0
    }
}

/// A tar reader over r.
pub struct Reader<R: Read> {
    r: R,
    /// What is left of the current entry, and its padding.
    left: u64,
    pad: u64,
}

impl<R: Read> Reader<R> {
    pub fn new(r: R) -> Self {
        Reader { r, left: 0, pad: 0 }
    }

    fn skip(&mut self, mut n: u64) -> std::io::Result<()> {
        let mut buf = [0u8; 8192];
        while n > 0 {
            let k = n.min(buf.len() as u64) as usize;
            self.r.read_exact(&mut buf[..k])?;
            n -= k as u64;
        }
        Ok(())
    }

    fn block(&mut self) -> Result<Option<[u8; 512]>, String> {
        let mut b = [0u8; 512];
        let mut got = 0;
        while got < 512 {
            match self.r.read(&mut b[got..]) {
                Ok(0) if got == 0 => return Ok(None),
                Ok(0) => return Err("unexpected EOF".to_string()),
                Ok(n) => got += n,
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(Some(b))
    }

    fn read_all(&mut self, size: u64) -> Result<Vec<u8>, String> {
        if size > 1 << 20 {
            return Err("archive/tar: header too large".to_string());
        }
        let mut b = vec![0u8; size as usize];
        self.r
            .read_exact(&mut b)
            .map_err(|_| "unexpected EOF".to_string())?;
        self.skip((512 - size % 512) % 512)
            .map_err(|_| "unexpected EOF".to_string())?;
        Ok(b)
    }

    /// Next: the next entry's header, or None at the archive's end.
    pub fn next_entry(&mut self) -> Result<Option<Header>, String> {
        self.skip(self.left + self.pad)
            .map_err(|_| "unexpected EOF".to_string())?;
        self.left = 0;
        self.pad = 0;
        let mut long_name: Option<String> = None;
        let mut pax_path: Option<String> = None;
        let mut pax_size: Option<u64> = None;
        loop {
            let Some(b) = self.block()? else {
                return Ok(None);
            };
            if b.iter().all(|&x| x == 0) {
                return Ok(None);
            }
            if !checksum_ok(&b) {
                return Err("archive/tar: invalid tar header".to_string());
            }
            let size = number(&b[124..136])?;
            let typeflag = b[156];
            match typeflag {
                b'x' => {
                    let recs = self.read_all(size)?;
                    for (k, v) in pax_records(&recs)? {
                        match k.as_str() {
                            "path" => pax_path = Some(v),
                            "size" => {
                                pax_size =
                                    Some(v.parse().map_err(|_| "archive/tar: invalid tar header")?)
                            }
                            _ => {}
                        }
                    }
                    continue;
                }
                b'g' => {
                    self.read_all(size)?;
                    continue;
                }
                b'L' => {
                    let n = self.read_all(size)?;
                    long_name = Some(cstr(&n));
                    continue;
                }
                _ => {}
            }
            let mut name = cstr(&b[0..100]);
            if &b[257..262] == b"ustar" {
                let prefix = cstr(&b[345..500]);
                if !prefix.is_empty() && &b[257..263] == b"ustar\0" {
                    name = format!("{prefix}/{name}");
                }
            }
            if let Some(n) = long_name.take() {
                name = n;
            }
            if let Some(p) = pax_path.take() {
                name = p;
            }
            let size = pax_size.take().unwrap_or(size);
            let mode = number(&b[100..108])? as u32;
            // Only regular files carry data.
            let data = if matches!(typeflag, b'0' | 0 | b'7') {
                size
            } else {
                0
            };
            self.left = data;
            self.pad = (512 - data % 512) % 512;
            return Ok(Some(Header {
                name,
                size,
                typeflag,
                mode,
            }));
        }
    }

    /// Reads the current entry's data (at most what is left of it).
    pub fn read_data(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            return Ok(0);
        }
        let k = (self.left.min(buf.len() as u64)) as usize;
        let n = self.r.read(&mut buf[..k])?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF",
            ));
        }
        self.left -= n as u64;
        Ok(n)
    }

    /// The current entry's data, as a reader.
    pub fn data(&mut self) -> Data<'_, R> {
        Data(self)
    }
}

/// The current entry's data.
pub struct Data<'a, R: Read>(&'a mut Reader<R>);

impl<R: Read> Read for Data<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read_data(buf)
    }
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn number(b: &[u8]) -> Result<u64, String> {
    if b[0] & 0x80 != 0 {
        let mut n: u64 = u64::from(b[0] & 0x7f);
        for &c in &b[1..] {
            n = n
                .checked_mul(256)
                .and_then(|x| x.checked_add(u64::from(c)))
                .ok_or("archive/tar: invalid tar header")?;
        }
        return Ok(n);
    }
    let s = cstr(b);
    let s = s.trim_matches([' ', '\0']);
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8).map_err(|_| "archive/tar: invalid tar header".to_string())
}

fn checksum_ok(b: &[u8; 512]) -> bool {
    let Ok(want) = number(&b[148..156]) else {
        return false;
    };
    let mut unsigned: u64 = 0;
    let mut signed: i64 = 0;
    for (i, &c) in b.iter().enumerate() {
        let c = if (148..156).contains(&i) { b' ' } else { c };
        unsigned += u64::from(c);
        signed += i64::from(c as i8);
    }
    want == unsigned || want as i64 == signed
}

fn pax_records(b: &[u8]) -> Result<Vec<(String, String)>, String> {
    let bad = || "archive/tar: invalid tar header".to_string();
    let mut out = Vec::new();
    let mut rest = b;
    while !rest.is_empty() {
        let sp = rest.iter().position(|&c| c == b' ').ok_or_else(bad)?;
        let n: usize = std::str::from_utf8(&rest[..sp])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(bad)?;
        if n > rest.len() || n <= sp + 1 {
            return Err(bad());
        }
        let rec = &rest[sp + 1..n];
        let rec = rec.strip_suffix(b"\n").ok_or_else(bad)?;
        let eq = rec.iter().position(|&c| c == b'=').ok_or_else(bad)?;
        out.push((
            String::from_utf8_lossy(&rec[..eq]).into_owned(),
            String::from_utf8_lossy(&rec[eq + 1..]).into_owned(),
        ));
        rest = &rest[n..];
    }
    Ok(out)
}

/// A writer of the small archives tests make (USTAR regular files).
#[cfg(test)]
pub fn write_test_archive(files: &[(&str, u32, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, mode, body) in files {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..107].copy_from_slice(format!("{mode:07o}").as_bytes());
        h[124..135].copy_from_slice(format!("{:011o}", body.len()).as_bytes());
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|&c| u32::from(c)).sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(body);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_entries() {
        let a = write_test_archive(&[("a", 0o644, b"hello"), ("dir/b", 0o755, b"")]);
        let mut r = Reader::new(&a[..]);
        let h = r.next_entry().unwrap().unwrap();
        assert_eq!((h.name.as_str(), h.size, h.mode), ("a", 5, 0o644));
        let mut s = String::new();
        r.data().read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello");
        assert_eq!(r.next_entry().unwrap().unwrap().name, "dir/b");
        assert!(r.next_entry().unwrap().is_none());
    }
}

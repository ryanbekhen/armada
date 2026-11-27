//! A gzip reader (multistream) over a buffered reader: the header read
//! when it is made, and the trailer checked only when the deflate stream
//! ends inside a read, an error found then returned on the next read when
//! that one returned data. Derived from Go's compress/gzip (BSD-3-Clause,
//! The Go Authors).

use std::io::{self, BufRead, Read};

pub const ERR_HEADER: &str = "gzip: invalid header";
const ERR_CHECKSUM: &str = "gzip: invalid checksum";

fn other(text: &str) -> io::Error {
    io::Error::other(text.to_string())
}

fn unexpected() -> io::Error {
    io::ErrorKind::UnexpectedEof.into()
}

/// The text of a reading error.
pub fn text(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::UnexpectedEof => "unexpected EOF".into(),
        _ => match e.get_ref() {
            Some(inner) => inner.to_string(),
            None => match e.raw_os_error() {
                Some(n) => super::errno::text(n),
                None => e.to_string(),
            },
        },
    }
}

/// The end of the input ("EOF").
pub fn eof() -> io::Error {
    other("EOF")
}

pub struct Reader<R: BufRead> {
    r: R,
    dec: flate2::Decompress,
    crc: flate2::Crc,
    /// The sticky error; None with done for the end of the input.
    err: Option<io::Error>,
    done: bool,
}

/// io.ReadFull: Ok(false) for no byte at all.
fn read_full(r: &mut impl Read, b: &mut [u8]) -> io::Result<bool> {
    let mut n = 0;
    while n < b.len() {
        match r.read(&mut b[n..]) {
            Ok(0) if n == 0 => return Ok(false),
            Ok(0) => return Err(unexpected()),
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// noEOF of an io.ReadFull.
fn need(r: &mut impl Read, b: &mut [u8]) -> io::Result<()> {
    if read_full(r, b)? {
        Ok(())
    } else {
        Err(unexpected())
    }
}

impl<R: BufRead> Reader<R> {
    /// gzip.NewReader: the first member's header, or the error reading it
    /// (eof() for no input at all).
    pub fn new(r: R) -> io::Result<Reader<R>> {
        let mut z = Reader {
            r,
            dec: flate2::Decompress::new(false),
            crc: flate2::Crc::new(),
            err: None,
            done: false,
        };
        if !z.read_header()? {
            return Err(eof());
        }
        Ok(z)
    }

    /// Ok(false) for the end of the input before any byte.
    fn read_header(&mut self) -> io::Result<bool> {
        let mut h = [0u8; 10];
        if !read_full(&mut self.r, &mut h)? {
            return Ok(false);
        }
        if h[0] != 0x1f || h[1] != 0x8b || h[2] != 8 {
            return Err(other(ERR_HEADER));
        }
        let flg = h[3];
        let mut digest = flate2::Crc::new();
        digest.update(&h);
        if flg & 0x04 != 0 {
            let mut l = [0u8; 2];
            need(&mut self.r, &mut l)?;
            digest.update(&l);
            let mut data = vec![0u8; usize::from(u16::from_le_bytes(l))];
            need(&mut self.r, &mut data)?;
            digest.update(&data);
        }
        for flag in [0x08, 0x10] {
            if flg & flag != 0 {
                let mut s = Vec::new();
                loop {
                    if s.len() >= 512 {
                        return Err(other(ERR_HEADER));
                    }
                    let mut c = [0u8; 1];
                    need(&mut self.r, &mut c)?;
                    s.push(c[0]);
                    if c[0] == 0 {
                        break;
                    }
                }
                digest.update(&s);
            }
        }
        if flg & 0x02 != 0 {
            let mut c = [0u8; 2];
            need(&mut self.r, &mut c)?;
            if u16::from_le_bytes(c) != digest.sum() as u16 {
                return Err(other(ERR_HEADER));
            }
        }
        self.dec.reset(false);
        self.crc.reset();
        Ok(true)
    }

    /// One decompressor read: the bytes it gave and whether the deflate
    /// stream ended.
    fn inflate(&mut self, p: &mut [u8]) -> io::Result<(usize, bool)> {
        loop {
            let input = self.r.fill_buf()?;
            let eof = input.is_empty();
            let (before_in, before_out) = (self.dec.total_in(), self.dec.total_out());
            let status = self
                .dec
                .decompress(input, p, flate2::FlushDecompress::None)
                .map_err(|_| {
                    other(&format!(
                        "flate: corrupt input before offset {}",
                        self.dec.total_in()
                    ))
                })?;
            let used = (self.dec.total_in() - before_in) as usize;
            let n = (self.dec.total_out() - before_out) as usize;
            self.r.consume(used);
            if status == flate2::Status::StreamEnd {
                return Ok((n, true));
            }
            if n > 0 {
                return Ok((n, false));
            }
            if eof {
                return Err(unexpected());
            }
        }
    }

    /// The trailer and the next member's header after a member ended:
    /// Ok(true) when another member follows.
    fn end_member(&mut self) -> io::Result<bool> {
        let mut t = [0u8; 8];
        need(&mut self.r, &mut t)?;
        let crc = u32::from_le_bytes([t[0], t[1], t[2], t[3]]);
        let size = u32::from_le_bytes([t[4], t[5], t[6], t[7]]);
        if crc != self.crc.sum() || size != self.crc.amount() {
            return Err(other(ERR_CHECKSUM));
        }
        self.read_header()
    }
}

impl<R: BufRead> Read for Reader<R> {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = self.err.take() {
            let again = io::Error::new(e.kind(), text(&e));
            self.err = Some(e);
            return Err(again);
        }
        if self.done || p.is_empty() {
            return Ok(0);
        }
        loop {
            let (n, ended) = match self.inflate(p) {
                Ok(v) => v,
                Err(e) => {
                    let again = io::Error::new(e.kind(), text(&e));
                    self.err = Some(e);
                    return Err(again);
                }
            };
            self.crc.update(&p[..n]);
            if !ended {
                return Ok(n);
            }
            match self.end_member() {
                Ok(true) => {
                    if n > 0 {
                        return Ok(n);
                    }
                }
                Ok(false) => {
                    self.done = true;
                    return Ok(n);
                }
                Err(e) => {
                    if n > 0 {
                        self.err = Some(e);
                        return Ok(n);
                    }
                    let again = io::Error::new(e.kind(), text(&e));
                    self.err = Some(e);
                    return Err(again);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gz(b: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn reads_members_and_checks_trailers() {
        let mut two = gz(b"hello ");
        two.extend(gz(b"world"));
        let mut s = String::new();
        Reader::new(&two[..])
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "hello world");

        let mut bad = gz(b"hello");
        let n = bad.len();
        bad[n - 8] ^= 1;
        let mut r = Reader::new(&bad[..]).unwrap();
        let mut b = [0u8; 64];
        assert_eq!(r.read(&mut b).unwrap(), 5);
        assert_eq!(text(&r.read(&mut b).unwrap_err()), ERR_CHECKSUM);

        assert_eq!(
            text(&Reader::new(&b"nope, not gzip"[..]).err().unwrap()),
            ERR_HEADER
        );
        assert_eq!(text(&Reader::new(&b""[..]).err().unwrap()), "EOF");
        assert_eq!(
            text(&Reader::new(&b"\x1f\x8b"[..]).err().unwrap()),
            "unexpected EOF"
        );
        let cut = gz(&[7u8; 4000]);
        let mut r = Reader::new(&cut[..cut.len() / 2]).unwrap();
        let mut v = Vec::new();
        assert_eq!(text(&r.read_to_end(&mut v).unwrap_err()), "unexpected EOF");
    }
}

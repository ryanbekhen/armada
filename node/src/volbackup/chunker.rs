//! volbackup's chunker: content-defined chunks from a gear rolling hash
//! keyed by the repository, between 512 KiB and 8 MiB, cut where Go cuts.

use std::io::{self, Read};

pub const MIN_CHUNK: usize = 512 << 10;
pub const MAX_CHUNK: usize = 8 << 20;
const CHUNK_MASK: u64 = (1 << 21) - 1;

pub struct Chunker<'a, R> {
    r: R,
    gear: &'a [u64; 256],
    buf: Vec<u8>,
    n: usize,
    eof: bool,
}

impl<'a, R: Read> Chunker<'a, R> {
    /// newChunker over buf, which holds MAX_CHUNK bytes.
    pub fn new(r: R, gear: &'a [u64; 256], mut buf: Vec<u8>) -> Chunker<'a, R> {
        buf.resize(MAX_CHUNK, 0);
        Chunker {
            r,
            gear,
            buf,
            n: 0,
            eof: false,
        }
    }

    /// The buffer, for the next file.
    pub fn into_buf(self) -> Vec<u8> {
        self.buf
    }

    /// next: the next chunk, or None at the end.
    pub fn next_chunk(&mut self) -> io::Result<Option<Vec<u8>>> {
        while !self.eof && self.n < MAX_CHUNK {
            match self.r.read(&mut self.buf[self.n..]) {
                Ok(0) => self.eof = true,
                Ok(m) => self.n += m,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        if self.n == 0 {
            return Ok(None);
        }
        let cut = cut(&self.buf[..self.n], self.gear);
        let out = self.buf[..cut].to_vec();
        self.buf.copy_within(cut..self.n, 0);
        self.n -= cut;
        Ok(Some(out))
    }
}

/// Where the next chunk of b ends.
pub fn cut(b: &[u8], gear: &[u64; 256]) -> usize {
    if b.len() > MIN_CHUNK {
        let mut h: u64 = 0;
        for (i, c) in b.iter().enumerate().skip(MIN_CHUNK) {
            h = (h << 1).wrapping_add(gear[usize::from(*c)]);
            if h & CHUNK_MASK == 0 {
                return i + 1;
            }
        }
    }
    b.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cuts_between_the_bounds() {
        let mut gear = [0u64; 256];
        let mut x: u64 = 88172645463325252;
        for g in gear.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *g = x;
        }
        let data: Vec<u8> = (0..20_000_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let mut c = Chunker::new(&data[..], &gear, Vec::new());
        let mut total = 0;
        let mut sizes = Vec::new();
        while let Some(ch) = c.next_chunk().unwrap() {
            total += ch.len();
            sizes.push(ch.len());
        }
        assert_eq!(total, data.len());
        let last = sizes.pop().unwrap();
        assert!(last <= MAX_CHUNK);
        assert!(sizes.iter().all(|s| (MIN_CHUNK..=MAX_CHUNK).contains(s)));
    }
}

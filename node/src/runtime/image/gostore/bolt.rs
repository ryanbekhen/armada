//! A read-only reader of bbolt databases (go.etcd.io/bbolt, file format
//! version 2), enough for the overlay snapshotter's metadata.db: the meta
//! pages (the newer valid one), branch and leaf pages with their overflow,
//! nested buckets, and inline buckets. The freelist is not read: only
//! pages the root reaches are. Every offset is checked against the file,
//! so a damaged database is an error, never a panic.
//!
//! The file is read whole under a shared flock, which bbolt takes for a
//! read-only open, so a writer holding it exclusively is waited for (up
//! to the timeout, as bolt.Options.Timeout).

use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant};

const MAGIC: u32 = 0xED0C_DAED;
const VERSION: u32 = 2;
const PAGE_HEADER: usize = 16;
const ELEMENT: usize = 16;
const BUCKET_HEADER: usize = 16;
const META_SIZE: usize = 64;
/// Offset of the checksum in a meta: what it is the FNV-1a of.
const META_SUMMED: usize = 56;

const BRANCH_PAGE: u16 = 0x01;
const LEAF_PAGE: u16 = 0x02;
const BUCKET_LEAF: u32 = 0x01;

/// How deep pages and buckets may nest before the database counts as
/// damaged (a cycle of page IDs would never end otherwise).
const MAX_DEPTH: usize = 64;

/// A database read into memory.
pub struct Db {
    data: Vec<u8>,
    page_size: usize,
    root: u64,
}

/// A bucket: on its own pages from root, or inline (its page in the
/// value that names it).
#[derive(Clone, Copy)]
pub struct Bucket<'a> {
    db: &'a Db,
    root: u64,
    inline: Option<&'a [u8]>,
}

/// One entry of a bucket: a value, or a nested bucket.
pub enum Entry<'a> {
    Value(&'a [u8]),
    Bucket(Bucket<'a>),
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

fn fnv64a(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &c in b {
        h ^= u64::from(c);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// A meta page's fields, when it validates (magic, version, checksum).
struct Meta {
    page_size: u32,
    root: u64,
    txid: u64,
}

fn meta_at(data: &[u8], page_off: usize) -> Option<Meta> {
    let m = data.get(page_off + PAGE_HEADER..page_off + PAGE_HEADER + META_SIZE)?;
    if u32_at(m, 0)? != MAGIC || u32_at(m, 4)? != VERSION {
        return None;
    }
    if u64_at(m, META_SUMMED)? != fnv64a(&m[..META_SUMMED]) {
        return None;
    }
    Some(Meta {
        page_size: u32_at(m, 8)?,
        root: u64_at(m, 16)?,
        txid: u64_at(m, 48)?,
    })
}

fn invalid() -> String {
    "invalid database".into()
}

impl Db {
    /// Opens path read-only (bolt.Open with ReadOnly), waiting up to
    /// timeout for a writer's lock.
    pub fn open(path: &Path, timeout: Duration) -> Result<Db, String> {
        let mut f = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
        let start = Instant::now();
        loop {
            // SAFETY: flock on a descriptor this function owns.
            if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
                break;
            }
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EWOULDBLOCK) if start.elapsed() < timeout => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Some(libc::EWOULDBLOCK) => return Err("timeout".into()),
                _ => return Err(format!("flock {}: {e}", path.display())),
            }
        }
        let mut data = Vec::new();
        f.read_to_end(&mut data)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        // The lock goes with the file.
        drop(f);
        Db::from_bytes(data)
    }

    /// A database from its bytes.
    pub fn from_bytes(data: Vec<u8>) -> Result<Db, String> {
        // The page size from the first meta, else from the second at
        // each size bbolt tries (getPageSize).
        let first = meta_at(&data, 0);
        let page_size = match &first {
            Some(m) => m.page_size as usize,
            None => (0..=14)
                .map(|i| 1024usize << i)
                .take_while(|&pos| pos + 1024 < data.len())
                .find_map(|pos| meta_at(&data, pos).map(|m| m.page_size as usize))
                .ok_or_else(invalid)?,
        };
        if !(512..=1 << 24).contains(&page_size) {
            return Err(invalid());
        }
        let second = meta_at(&data, page_size);
        // db.meta(): the higher transaction that validates.
        let meta = match (first, second) {
            (Some(a), Some(b)) => {
                if b.txid > a.txid {
                    b
                } else {
                    a
                }
            }
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => return Err(invalid()),
        };
        Ok(Db {
            data,
            page_size,
            root: meta.root,
        })
    }

    /// The root bucket, holding the top-level buckets.
    pub fn root(&self) -> Bucket<'_> {
        Bucket {
            db: self,
            root: self.root,
            inline: None,
        }
    }

    /// The bytes of page id with its overflow.
    fn page(&self, id: u64) -> Result<&[u8], String> {
        let off = usize::try_from(id)
            .ok()
            .and_then(|i| i.checked_mul(self.page_size))
            .ok_or_else(invalid)?;
        let head = self.data.get(off..off + PAGE_HEADER).ok_or_else(invalid)?;
        let overflow = u32_at(head, 12).ok_or_else(invalid)? as usize;
        let len = (overflow + 1)
            .checked_mul(self.page_size)
            .ok_or_else(invalid)?;
        // The last page of a file may be cut short of a whole page.
        let end = (off + len).min(self.data.len());
        Ok(&self.data[off..end])
    }
}

impl<'a> Bucket<'a> {
    /// Calls f with every entry in key order (bucket.ForEach, with nested
    /// buckets told apart).
    pub fn for_each(
        &self,
        f: &mut dyn FnMut(&'a [u8], Entry<'a>) -> Result<(), String>,
    ) -> Result<(), String> {
        match self.inline {
            Some(p) => self.walk(p, f, 0),
            None => {
                let p = self.db.page(self.root)?;
                self.walk(p, f, 0)
            }
        }
    }

    fn walk(
        &self,
        page: &'a [u8],
        f: &mut dyn FnMut(&'a [u8], Entry<'a>) -> Result<(), String>,
        depth: usize,
    ) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err(invalid());
        }
        let flags = u16_at(page, 8).ok_or_else(invalid)?;
        let count = u16_at(page, 10).ok_or_else(invalid)? as usize;
        for i in 0..count {
            let at = PAGE_HEADER + i * ELEMENT;
            let el = page.get(at..at + ELEMENT).ok_or_else(invalid)?;
            match flags {
                BRANCH_PAGE => {
                    let child = u64_at(el, 8).ok_or_else(invalid)?;
                    if self.inline.is_some() {
                        return Err(invalid());
                    }
                    let p = self.db.page(child)?;
                    self.walk(p, f, depth + 1)?;
                }
                LEAF_PAGE => {
                    let eflags = u32_at(el, 0).ok_or_else(invalid)?;
                    let pos = u32_at(el, 4).ok_or_else(invalid)? as usize;
                    let ksize = u32_at(el, 8).ok_or_else(invalid)? as usize;
                    let vsize = u32_at(el, 12).ok_or_else(invalid)? as usize;
                    let k0 = at.checked_add(pos).ok_or_else(invalid)?;
                    let key = page.get(k0..k0 + ksize).ok_or_else(invalid)?;
                    let value = page
                        .get(k0 + ksize..k0 + ksize + vsize)
                        .ok_or_else(invalid)?;
                    if eflags & BUCKET_LEAF == 0 {
                        f(key, Entry::Value(value))?;
                        continue;
                    }
                    let root = u64_at(value, 0).ok_or_else(invalid)?;
                    let inline = if root == 0 {
                        let p = value.get(BUCKET_HEADER..).ok_or_else(invalid)?;
                        Some(p)
                    } else {
                        None
                    };
                    f(
                        key,
                        Entry::Bucket(Bucket {
                            db: self.db,
                            root,
                            inline,
                        }),
                    )?;
                }
                _ => return Err(invalid()),
            }
        }
        Ok(())
    }

    /// The entry under key, if any.
    pub fn entry(&self, key: &[u8]) -> Result<Option<Entry<'a>>, String> {
        let mut out = None;
        self.for_each(&mut |k, e| {
            if out.is_none() && k == key {
                out = Some(e);
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// bucket.Bucket: the nested bucket under key.
    pub fn bucket(&self, key: &[u8]) -> Result<Option<Bucket<'a>>, String> {
        Ok(match self.entry(key)? {
            Some(Entry::Bucket(b)) => Some(b),
            _ => None,
        })
    }

    /// bucket.Get: the value under key (none for a nested bucket).
    pub fn get(&self, key: &[u8]) -> Result<Option<&'a [u8]>, String> {
        Ok(match self.entry(key)? {
            Some(Entry::Value(v)) => Some(v),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-page leaf with the given entries at page id, flags per entry.
    fn leaf(page_size: usize, id: u64, entries: &[(&[u8], &[u8], u32)]) -> Vec<u8> {
        let mut p = vec![0u8; page_size];
        p[0..8].copy_from_slice(&id.to_le_bytes());
        p[8..10].copy_from_slice(&LEAF_PAGE.to_le_bytes());
        p[10..12].copy_from_slice(&(entries.len() as u16).to_le_bytes());
        let mut data = PAGE_HEADER + entries.len() * ELEMENT;
        for (i, (k, v, fl)) in entries.iter().enumerate() {
            let at = PAGE_HEADER + i * ELEMENT;
            p[at..at + 4].copy_from_slice(&fl.to_le_bytes());
            p[at + 4..at + 8].copy_from_slice(&((data - at) as u32).to_le_bytes());
            p[at + 8..at + 12].copy_from_slice(&(k.len() as u32).to_le_bytes());
            p[at + 12..at + 16].copy_from_slice(&(v.len() as u32).to_le_bytes());
            p[data..data + k.len()].copy_from_slice(k);
            p[data + k.len()..data + k.len() + v.len()].copy_from_slice(v);
            data += k.len() + v.len();
        }
        p
    }

    fn meta(page_size: usize, id: u64, root: u64, txid: u64) -> Vec<u8> {
        let mut p = vec![0u8; page_size];
        p[0..8].copy_from_slice(&id.to_le_bytes());
        p[8..10].copy_from_slice(&0x04u16.to_le_bytes());
        let m = &mut p[PAGE_HEADER..PAGE_HEADER + META_SIZE];
        m[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        m[4..8].copy_from_slice(&VERSION.to_le_bytes());
        m[8..12].copy_from_slice(&(page_size as u32).to_le_bytes());
        m[16..24].copy_from_slice(&root.to_le_bytes());
        m[48..56].copy_from_slice(&txid.to_le_bytes());
        let sum = fnv64a(&m[..META_SUMMED]);
        m[56..64].copy_from_slice(&sum.to_le_bytes());
        p
    }

    /// Two metas (the newer pointing at page 3), a stale root at 2, and a
    /// root at 3 with a page bucket (4) and an inline one.
    #[test]
    fn reads_nested_and_inline_buckets() {
        let ps = 4096;
        let inline_page = {
            let p = leaf(64, 0, &[(b"id", b"\x07", 0)]);
            let used = PAGE_HEADER + ELEMENT + 3;
            let mut v = vec![0u8; BUCKET_HEADER];
            v.extend_from_slice(&p[..used]);
            v
        };
        let mut bucket_value = vec![0u8; BUCKET_HEADER];
        bucket_value[0..8].copy_from_slice(&4u64.to_le_bytes());
        let mut db = Vec::new();
        db.extend(meta(ps, 0, 2, 1));
        db.extend(meta(ps, 1, 3, 2));
        db.extend(leaf(ps, 2, &[(b"old", b"x", 0)]));
        db.extend(leaf(
            ps,
            3,
            &[
                (b"inline", &inline_page, BUCKET_LEAF),
                (b"paged", &bucket_value, BUCKET_LEAF),
            ],
        ));
        db.extend(leaf(ps, 4, &[(b"a", b"1", 0), (b"b", b"2", 0)]));
        let db = Db::from_bytes(db).unwrap();
        let root = db.root();
        assert!(root.bucket(b"old").unwrap().is_none());
        let inl = root.bucket(b"inline").unwrap().unwrap();
        assert_eq!(inl.get(b"id").unwrap(), Some(&b"\x07"[..]));
        let paged = root.bucket(b"paged").unwrap().unwrap();
        let mut seen = Vec::new();
        paged
            .for_each(&mut |k, e| {
                if let Entry::Value(v) = e {
                    seen.push((k.to_vec(), v.to_vec()));
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(
            seen,
            vec![
                (b"a".to_vec(), b"1".to_vec()),
                (b"b".to_vec(), b"2".to_vec())
            ]
        );
        // A damaged newer meta: the older one.
        let mut bytes = db.data.clone();
        bytes[ps + PAGE_HEADER + 20] ^= 1;
        let old = Db::from_bytes(bytes).unwrap();
        assert!(old.root().get(b"old").unwrap().is_some());
    }

    #[test]
    fn refuses_garbage() {
        assert!(Db::from_bytes(vec![0u8; 8192]).is_err());
        assert!(Db::from_bytes(Vec::new()).is_err());
        // A root page past the end.
        let mut db = meta(4096, 0, 99, 1);
        db.extend(meta(4096, 1, 99, 0));
        let db = Db::from_bytes(db).unwrap();
        assert!(db.root().bucket(b"x").is_err());
    }
}

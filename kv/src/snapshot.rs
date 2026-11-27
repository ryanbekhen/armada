//! The store's snapshot format (ADR 0057), what `Maintenance.Snapshot`
//! streams and a restore reads:
//!
//! ```text
//! MAGIC                       "armada-kv snapshot\n"
//! header                      length-delimited Header (format, revision, counts)
//! record...                   length-delimited Record: each lease, then each key
//! SHA-256                     32 bytes, of everything before it
//! ```
//!
//! The key space is the one at the header's revision: each key's current
//! version with its creation and modification revision, version, and
//! lease, and every lease with its granted TTL. History before that
//! revision is not kept: a restored store is compacted at it.

use armada_proto::etcd::mvccpb::KeyValue;
use prost::Message;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// The first bytes of every snapshot.
pub const MAGIC: &[u8] = b"armada-kv snapshot\n";

/// The format this binary writes and reads.
pub const FORMAT: u32 = 1;

const HASH_LEN: usize = 32;

#[derive(Clone, PartialEq, prost::Message)]
struct Header {
    #[prost(uint32, tag = "1")]
    format: u32,
    #[prost(int64, tag = "2")]
    revision: i64,
    #[prost(uint64, tag = "3")]
    leases: u64,
    #[prost(uint64, tag = "4")]
    keys: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Lease {
    #[prost(int64, tag = "1")]
    id: i64,
    #[prost(int64, tag = "2")]
    ttl: i64,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Record {
    #[prost(oneof = "Item", tags = "1, 2")]
    item: Option<Item>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
enum Item {
    #[prost(message, tag = "1")]
    Kv(KeyValue),
    #[prost(message, tag = "2")]
    Lease(Lease),
}

/// Writes a snapshot: leases, then keys, then finish.
pub struct Writer {
    revision: i64,
    leases: Vec<Lease>,
    body: Vec<u8>,
    keys: u64,
}

impl Writer {
    pub fn new(revision: i64) -> Writer {
        Writer {
            revision,
            leases: Vec::new(),
            body: Vec::new(),
            keys: 0,
        }
    }

    pub fn lease(&mut self, id: i64, ttl: i64) {
        self.leases.push(Lease { id, ttl });
    }

    pub fn kv(&mut self, kv: &KeyValue) {
        Record {
            item: Some(Item::Kv(kv.clone())),
        }
        .encode_length_delimited(&mut self.body)
        .expect("a Vec grows");
        self.keys += 1;
    }

    /// The whole snapshot with its hash.
    pub fn finish(self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        Header {
            format: FORMAT,
            revision: self.revision,
            leases: self.leases.len() as u64,
            keys: self.keys,
        }
        .encode_length_delimited(&mut out)
        .expect("a Vec grows");
        for l in self.leases {
            Record {
                item: Some(Item::Lease(l)),
            }
            .encode_length_delimited(&mut out)
            .expect("a Vec grows");
        }
        out.extend_from_slice(&self.body);
        let sum = Sha256::digest(&out);
        out.extend_from_slice(&sum);
        out
    }
}

/// A snapshot read and checked.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Snapshot {
    pub revision: i64,
    pub leases: Vec<(i64, i64)>,
    pub kvs: Vec<KeyValue>,
}

fn bad(what: impl Into<String>) -> Error {
    Error::Snapshot(what.into())
}

/// Reads a snapshot: its magic, hash, format, and counts are checked, and
/// keys must come in order, each with revisions at or below the
/// snapshot's and a lease the snapshot holds.
pub fn read(b: &[u8]) -> Result<Snapshot> {
    if b.len() < MAGIC.len() + HASH_LEN || !b.starts_with(MAGIC) {
        return Err(bad("not a snapshot of armada-kv"));
    }
    let (body, sum) = b.split_at(b.len() - HASH_LEN);
    if Sha256::digest(body).as_slice() != sum {
        return Err(bad("the SHA-256 does not match: the snapshot is damaged"));
    }
    let mut rest = &body[MAGIC.len()..];
    let h = Header::decode_length_delimited(&mut rest).map_err(|e| bad(e.to_string()))?;
    if h.format != FORMAT {
        return Err(bad(format!(
            "format {}, this binary reads {FORMAT}",
            h.format
        )));
    }
    if h.revision < 1 {
        return Err(bad(format!("revision {}", h.revision)));
    }
    let mut s = Snapshot {
        revision: h.revision,
        ..Default::default()
    };
    while !rest.is_empty() {
        let r = Record::decode_length_delimited(&mut rest).map_err(|e| bad(e.to_string()))?;
        match r.item {
            Some(Item::Lease(l)) => {
                if !s.kvs.is_empty() {
                    return Err(bad("a lease after the keys"));
                }
                if l.id == 0 || s.leases.iter().any(|(id, _)| *id == l.id) {
                    return Err(bad(format!("lease {}", l.id)));
                }
                s.leases.push((l.id, l.ttl));
            }
            Some(Item::Kv(kv)) => {
                if kv.key.is_empty()
                    || s.kvs.last().is_some_and(|p| p.key >= kv.key)
                    || kv.version < 1
                    || kv.create_revision < 1
                    || kv.create_revision > kv.mod_revision
                    || kv.mod_revision > h.revision
                {
                    return Err(bad(format!(
                        "key {:?} is out of order or has invalid revisions",
                        String::from_utf8_lossy(&kv.key)
                    )));
                }
                if kv.lease != 0 && !s.leases.iter().any(|(id, _)| *id == kv.lease) {
                    return Err(bad(format!(
                        "key {:?} names a lease the snapshot lacks",
                        String::from_utf8_lossy(&kv.key)
                    )));
                }
                s.kvs.push(kv);
            }
            None => return Err(bad("an empty record")),
        }
    }
    if s.leases.len() as u64 != h.leases || s.kvs.len() as u64 != h.keys {
        return Err(bad("the counts do not match the header"));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let mut w = Writer::new(9);
        w.lease(5, 60);
        for (k, l) in [("a", 0), ("b", 5)] {
            w.kv(&KeyValue {
                key: k.as_bytes().to_vec(),
                create_revision: 2,
                mod_revision: 8,
                version: 3,
                value: b"v".to_vec(),
                lease: l,
            });
        }
        w.finish()
    }

    #[test]
    fn round_trip() {
        let s = read(&sample()).unwrap();
        assert_eq!(s.revision, 9);
        assert_eq!(s.leases, vec![(5, 60)]);
        assert_eq!(s.kvs.len(), 2);
        assert_eq!(s.kvs[1].lease, 5);
    }

    #[test]
    fn damage_is_refused() {
        let good = sample();
        let mut b = good.clone();
        let mid = b.len() / 2;
        b[mid] ^= 1;
        assert!(matches!(read(&b), Err(Error::Snapshot(m)) if m.contains("SHA-256")));
        assert!(read(&good[..good.len() - 1]).is_err());
        assert!(read(b"etcd").is_err());
        // A body that hashes right but holds a key past the revision.
        let mut w = Writer::new(3);
        w.kv(&KeyValue {
            key: b"a".to_vec(),
            create_revision: 2,
            mod_revision: 4,
            version: 1,
            ..Default::default()
        });
        assert!(read(&w.finish()).is_err());
    }
}

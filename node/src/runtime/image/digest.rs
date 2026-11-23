//! Content digests as go-digest parses and checks them: `ALGORITHM:HEX`
//! with sha256, sha384, or sha512 (the algorithms containerd links).

use sha2::{Digest as _, Sha256, Sha384, Sha512};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub enum Algorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl Algorithm {
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha384 => "sha384",
            Algorithm::Sha512 => "sha512",
        }
    }

    fn hex_len(self) -> usize {
        match self {
            Algorithm::Sha256 => 64,
            Algorithm::Sha384 => 96,
            Algorithm::Sha512 => 128,
        }
    }

    pub fn hasher(self) -> Hasher {
        match self {
            Algorithm::Sha256 => Hasher::Sha256(Sha256::new()),
            Algorithm::Sha384 => Hasher::Sha384(Sha384::new()),
            Algorithm::Sha512 => Hasher::Sha512(Sha512::new()),
        }
    }
}

/// A validated digest.
#[derive(Clone, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub struct Digest {
    alg: Algorithm,
    hex: String,
}

impl Digest {
    /// digest.Parse: the algorithm must be one this program has and the
    /// encoded part its length in lower-case hex.
    pub fn parse(s: &str) -> Result<Digest, String> {
        let Some((alg, hex)) = s.split_once(':') else {
            return Err(format!(
                "invalid digest {s:?}: invalid checksum digest format"
            ));
        };
        if alg.is_empty() || hex.is_empty() {
            return Err(format!(
                "invalid digest {s:?}: invalid checksum digest format"
            ));
        }
        let alg = match alg {
            "sha256" => Algorithm::Sha256,
            "sha384" => Algorithm::Sha384,
            "sha512" => Algorithm::Sha512,
            _ => {
                // go-digest tells a well-formed unknown algorithm from a
                // malformed one; both are refused.
                return Err(format!(
                    "invalid digest {s:?}: unsupported digest algorithm"
                ));
            }
        };
        if hex.len() != alg.hex_len()
            || !hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(format!(
                "invalid digest {s:?}: invalid checksum digest length"
            ));
        }
        Ok(Digest {
            alg,
            hex: hex.to_string(),
        })
    }

    pub fn algorithm(&self) -> Algorithm {
        self.alg
    }

    pub fn hex(&self) -> &str {
        &self.hex
    }

    pub fn of(alg: Algorithm, b: &[u8]) -> Digest {
        let mut h = alg.hasher();
        h.update(b);
        h.finish()
    }

    pub fn sha256(b: &[u8]) -> Digest {
        Digest::of(Algorithm::Sha256, b)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.alg.name(), self.hex)
    }
}

impl serde::Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Digest::parse(&s).map_err(serde::de::Error::custom)
    }
}

pub enum Hasher {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    pub fn update(&mut self, b: &[u8]) {
        match self {
            Hasher::Sha256(h) => h.update(b),
            Hasher::Sha384(h) => h.update(b),
            Hasher::Sha512(h) => h.update(b),
        }
    }

    pub fn finish(self) -> Digest {
        let (alg, sum) = match self {
            Hasher::Sha256(h) => (Algorithm::Sha256, h.finalize().to_vec()),
            Hasher::Sha384(h) => (Algorithm::Sha384, h.finalize().to_vec()),
            Hasher::Sha512(h) => (Algorithm::Sha512, h.finalize().to_vec()),
        };
        Digest {
            alg,
            hex: sum.iter().map(|b| format!("{b:02x}")).collect(),
        }
    }
}

impl std::io::Write for Hasher {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// identity.ChainIDs: the chain of each layer from the diff IDs.
pub fn chain_ids(diffs: &[Digest]) -> Vec<Digest> {
    let mut out: Vec<Digest> = Vec::with_capacity(diffs.len());
    for d in diffs {
        let next = match out.last() {
            None => d.clone(),
            Some(prev) => Digest::sha256(format!("{prev} {d}").as_bytes()),
        };
        out.push(next);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_as_go_digest() {
        let d = Digest::sha256(b"x");
        assert_eq!(Digest::parse(&d.to_string()).unwrap(), d);
        for bad in [
            "sha256:short",
            "sha256:",
            ":abc",
            "md5:d41d8cd98f00b204e9800998ecf8427e",
            "sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            "nocolon",
        ] {
            assert!(Digest::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn chains_as_identity() {
        let a = Digest::sha256(b"a");
        let b = Digest::sha256(b"b");
        let c = chain_ids(&[a.clone(), b.clone()]);
        assert_eq!(c[0], a);
        assert_eq!(c[1], Digest::sha256(format!("{a} {b}").as_bytes()));
    }
}

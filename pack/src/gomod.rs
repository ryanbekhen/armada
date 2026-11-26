//! Go modules of the pack's Go programs, without Go: the module list a Go
//! program records in itself (debug/buildinfo's `dep` and `=>` lines),
//! module zips from the Go module proxy checked against their go.sum
//! hash (dirhash's h1), and the license files at each module's root.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use flate2::read::DeflateDecoder;
use sha2::{Digest, Sha256};

use crate::fetch;

/// The proxy module zips come from.
pub const PROXY: &str = "https://proxy.golang.org";

/// A dependency a Go program records: its module path, version, and h1
/// hash (empty for modules built from the program's own repository, whose
/// version is "(devel)", and for vendored builds).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Dep {
    pub path: String,
    pub version: String,
    pub sum: String,
}

/// deps: the modules a Go program links, from its build information;
/// None for a program that is not a Go program.
pub fn deps(program: &[u8]) -> Result<Option<Vec<Dep>>, String> {
    const MAGIC: &[u8] = b"\xff Go buildinf:";
    let Some(at) = find(program, MAGIC) else {
        return Ok(None);
    };
    let h = &program[at..];
    if h.len() < 32 {
        return Err("buildinfo: short header".into());
    }
    if h[15] & 2 == 0 {
        return Err("buildinfo: a Go release before 1.18 (pointers, not strings)".into());
    }
    let mut rest = &h[32..];
    let _version = uvarint_str(&mut rest)?;
    let mut info = uvarint_str(&mut rest)?;
    if info.len() >= 33 && info[info.len() - 17] == b'\n' {
        info = &info[16..info.len() - 16];
    }
    let info = std::str::from_utf8(info).map_err(|_| "buildinfo: not UTF-8")?;
    let mut out: Vec<Dep> = Vec::new();
    for line in info.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let dep = |f: &[&str]| Dep {
            path: f.get(1).unwrap_or(&"").to_string(),
            version: f.get(2).unwrap_or(&"").to_string(),
            sum: f.get(3).unwrap_or(&"").to_string(),
        };
        match f[0] {
            "dep" => out.push(dep(&f)),
            "=>" => {
                let last = out.last_mut().ok_or("buildinfo: => before any dep")?;
                *last = dep(&f);
            }
            _ => {}
        }
    }
    Ok(Some(out))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    let first = needle[0];
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        i += hay[i..hay.len() - needle.len() + 1]
            .iter()
            .position(|&c| c == first)?;
        if &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn uvarint_str<'a>(b: &mut &'a [u8]) -> Result<&'a [u8], String> {
    let (mut n, mut shift, mut i) = (0u64, 0, 0);
    loop {
        let c = *b.get(i).ok_or("buildinfo: short varint")?;
        n |= ((c & 0x7f) as u64) << shift;
        i += 1;
        if c & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err("buildinfo: varint overflows".into());
        }
    }
    let n = n as usize;
    if b.len() < i + n {
        return Err("buildinfo: short string".into());
    }
    let s = &b[i..i + n];
    *b = &b[i + n..];
    Ok(s)
}

/// escape: the module proxy's case encoding of a path or version.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// A module zip's files by name (`path@version/...`).
pub type Zip = BTreeMap<String, Vec<u8>>;

/// module_zip: the module's zip from the cache or the proxy, only when
/// its h1 hash is sum.
pub fn module_zip(path: &str, version: &str, sum: &str, cache: &Path) -> Result<Zip, String> {
    let name = format!("{}/@v/{}.zip", escape(path), escape(version));
    let cached = cache.join(&name);
    if let Ok(b) = std::fs::read(&cached)
        && let Ok(z) = read_zip(&b)
        && h1(&z)? == sum
    {
        return Ok(z);
    }
    let b = fetch::download(&format!("{PROXY}/{name}"), cache)?;
    let z = read_zip(&b).map_err(|e| format!("{path}@{version}: {e}"))?;
    let got = h1(&z)?;
    if got != sum {
        return Err(format!(
            "{path}@{version}: checksum mismatch: got {got}, want {sum}"
        ));
    }
    fetch::keep(&cached, &b);
    Ok(z)
}

/// h1: dirhash.Hash1 of a module zip's files.
pub fn h1(z: &Zip) -> Result<String, String> {
    let mut summary = String::new();
    for (name, b) in z {
        if name.contains('\n') {
            return Err("dirhash: filenames with newlines are not supported".into());
        }
        summary.push_str(&fetch::sum_hex(b));
        summary.push_str("  ");
        summary.push_str(name);
        summary.push('\n');
    }
    Ok(format!(
        "h1:{}",
        base64(&Sha256::digest(summary.as_bytes()))
    ))
}

fn base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// read_zip: every file of a zip (stored or deflated; no zip64).
pub fn read_zip(b: &[u8]) -> Result<Zip, String> {
    let u16le = |at: usize| -> Result<usize, String> {
        b.get(at..at + 2)
            .map(|s| u16::from_le_bytes([s[0], s[1]]) as usize)
            .ok_or_else(|| "zip: truncated".to_string())
    };
    let u32le = |at: usize| -> Result<usize, String> {
        b.get(at..at + 4)
            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
            .ok_or_else(|| "zip: truncated".to_string())
    };
    let eocd = (0..b.len().saturating_sub(21))
        .rev()
        .take(65536 + 22)
        .find(|&i| b[i..].starts_with(b"PK\x05\x06"))
        .ok_or("zip: no end of central directory")?;
    let count = u16le(eocd + 10)?;
    let mut at = u32le(eocd + 16)?;
    let mut out = Zip::new();
    for _ in 0..count {
        if b.get(at..at + 4) != Some(b"PK\x01\x02") {
            return Err("zip: bad central directory".into());
        }
        let method = u16le(at + 10)?;
        let csize = u32le(at + 20)?;
        let usize_ = u32le(at + 24)?;
        let (nlen, elen, clen) = (u16le(at + 28)?, u16le(at + 30)?, u16le(at + 32)?);
        let local = u32le(at + 42)?;
        let name = b.get(at + 46..at + 46 + nlen).ok_or("zip: truncated")?;
        let name = String::from_utf8(name.to_vec()).map_err(|_| "zip: name not UTF-8")?;
        at += 46 + nlen + elen + clen;
        if b.get(local..local + 4) != Some(b"PK\x03\x04") {
            return Err("zip: bad local header".into());
        }
        let start = local + 30 + u16le(local + 26)? + u16le(local + 28)?;
        let data = b.get(start..start + csize).ok_or("zip: truncated")?;
        let content = match method {
            0 => data.to_vec(),
            8 => {
                let mut v = Vec::with_capacity(usize_);
                DeflateDecoder::new(data)
                    .take(usize_ as u64 + 1)
                    .read_to_end(&mut v)
                    .map_err(|e| format!("zip: {name}: {e}"))?;
                v
            }
            m => return Err(format!("zip: {name}: method {m}")),
        };
        if content.len() != usize_ {
            return Err(format!("zip: {name}: size mismatch"));
        }
        if out.insert(name.clone(), content).is_some() {
            return Err(format!("zip: {name} twice"));
        }
    }
    Ok(out)
}

/// is_license_file: the files at a module's root release archives carry.
pub fn is_license_file(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "license",
        "licence",
        "unlicense",
        "copying",
        "notice",
        "patents",
    ]
    .iter()
    .any(|p| n.starts_with(p))
}

/// license_files: the license files at the root of a module zip, by name.
pub fn license_files(z: &Zip, path: &str, version: &str) -> Vec<(String, Vec<u8>)> {
    let prefix = format!("{path}@{version}/");
    z.iter()
        .filter_map(|(n, b)| {
            let rest = n.strip_prefix(&prefix)?;
            (!rest.contains('/') && is_license_file(rest)).then(|| (rest.to_string(), b.clone()))
        })
        .collect()
}

/// extract writes a module zip's files under dir (each name checked) and
/// returns the module's directory, `dir/path@version`.
pub fn extract(z: &Zip, path: &str, version: &str, dir: &Path) -> Result<PathBuf, String> {
    let prefix = format!("{path}@{version}/");
    for (n, b) in z {
        let ok = n.starts_with(&prefix)
            && !n.split('/').any(|s| s.is_empty() || s == "." || s == "..")
            && !n.contains('\\');
        if !ok {
            return Err(format!("zip: unexpected name {n:?}"));
        }
        let to = dir.join(n);
        if let Some(p) = to.parent() {
            std::fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
        }
        std::fs::write(&to, b).map_err(|e| format!("{}: {e}", to.display()))?;
    }
    Ok(dir.join(format!("{path}@{version}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_case() {
        assert_eq!(
            escape("github.com/BurntSushi/toml"),
            "github.com/!burnt!sushi/toml"
        );
    }

    #[test]
    fn base64_std() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
    }

    #[test]
    fn h1_is_dirhash() {
        // dirhash.Hash1 of {"a@v1/x": "hello\n"}: sha256 of the line
        // "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  a@v1/x\n".
        let z: Zip = [("a@v1/x".to_string(), b"hello\n".to_vec())].into();
        let line = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  a@v1/x\n";
        let want = format!("h1:{}", base64(&Sha256::digest(line.as_bytes())));
        assert_eq!(h1(&z).unwrap(), want);
    }

    #[test]
    fn reads_buildinfo() {
        let info = "path\tx\nmod\tx\tv1\t\ndep\ta\tv1.0.0\th1:A=\ndep\tb\tv2.0.0\th1:B=\n=>\tc\tv3.0.0\th1:C=\n";
        let mut wrapped = vec![b'0'; 16];
        wrapped.extend_from_slice(info.as_bytes());
        wrapped.extend_from_slice(&[b'0'; 16]);
        let n = wrapped.len() - 17;
        wrapped[n] = b'\n';
        let mut prog = b"junk".to_vec();
        prog.extend_from_slice(b"\xff Go buildinf:\x08\x02");
        prog.extend_from_slice(&[0u8; 16]);
        prog.push(4);
        prog.extend_from_slice(b"go1x");
        prog.push(wrapped.len() as u8);
        prog.extend_from_slice(&wrapped);
        let d = deps(&prog).unwrap().unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].path, "a");
        assert_eq!((d[1].path.as_str(), d[1].sum.as_str()), ("c", "h1:C="));
        assert!(deps(b"\x7fELF not go").unwrap().is_none());
    }
}

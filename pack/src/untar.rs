//! members: the listed regular files of a gzipped tar (Go's mkbundle with
//! archive/tar's reader): V7, USTAR (with its prefix), GNU, and PAX
//! headers, GNU long names, and PAX path and size records.

use std::collections::BTreeMap;
use std::io::{self, Read};

use flate2::read::MultiGzDecoder;

const BLOCK: usize = 512;

/// members extracts want's entries (a path in the archive to its name in
/// the pack) from a gzipped tar; every one must be a regular file.
pub fn members(
    archive: &[u8],
    want: &BTreeMap<String, String>,
    max: u64,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut r = MultiGzDecoder::new(archive);
    let mut out = BTreeMap::new();
    let mut long_name: Option<String> = None;
    let mut pax: BTreeMap<String, String> = BTreeMap::new();
    let mut zeros = 0;
    loop {
        let mut h = [0u8; BLOCK];
        if !read_block(&mut r, &mut h).map_err(|e| e.to_string())? {
            break;
        }
        if h.iter().all(|&c| c == 0) {
            zeros += 1;
            if zeros == 2 {
                break;
            }
            continue;
        }
        zeros = 0;
        check_sum(&h)?;
        let flag = h[156];
        let mut size = numeric(&h[124..136])?;
        let mut name = cstr(&h[0..100]);
        let ustar = &h[257..263] == b"ustar\0";
        if ustar {
            let prefix = cstr(&h[345..500]);
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        match flag {
            b'x' | b'g' | b'L' | b'K' => {
                if size > 1 << 20 {
                    return Err("tar: header record too large".into());
                }
                let data = read_data(&mut r, size)?;
                match flag {
                    b'x' => pax = parse_pax(&data)?,
                    b'L' => long_name = Some(cstr(&data)),
                    _ => {}
                }
                continue;
            }
            _ => {}
        }
        if let Some(n) = long_name.take() {
            name = n;
        }
        if let Some(p) = pax.remove("path") {
            name = p;
        }
        if let Some(s) = pax.remove("size") {
            size = s
                .parse()
                .map_err(|_| format!("tar: invalid PAX size {s:?}"))?;
        }
        pax.clear();
        let regular = flag == b'0' || (flag == 0 && !name.ends_with('/'));
        match want.get(&name) {
            Some(to) => {
                if !regular {
                    return Err(format!("{name} is not a regular file"));
                }
                if size > max {
                    return Err(format!("{name} is larger than {max} bytes"));
                }
                out.insert(to.clone(), read_data(&mut r, size)?);
            }
            None => skip(&mut r, size)?,
        }
    }
    for (from, to) in want {
        if !out.contains_key(to) {
            return Err(format!("archive has no {from}"));
        }
    }
    Ok(out)
}

fn read_block(r: &mut impl Read, b: &mut [u8; BLOCK]) -> io::Result<bool> {
    let mut n = 0;
    while n < BLOCK {
        let m = r.read(&mut b[n..])?;
        if m == 0 {
            if n == 0 {
                return Ok(false);
            }
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        n += m;
    }
    Ok(true)
}

fn padded(size: u64) -> u64 {
    size.div_ceil(BLOCK as u64) * BLOCK as u64
}

fn read_data(r: &mut impl Read, size: u64) -> Result<Vec<u8>, String> {
    let mut b = vec![0u8; padded(size) as usize];
    r.read_exact(&mut b).map_err(|e| format!("tar: {e}"))?;
    b.truncate(size as usize);
    Ok(b)
}

fn skip(r: &mut impl Read, size: u64) -> Result<(), String> {
    let want = padded(size);
    let n = io::copy(&mut r.take(want), &mut io::sink()).map_err(|e| format!("tar: {e}"))?;
    if n != want {
        return Err("tar: unexpected EOF".into());
    }
    Ok(())
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn check_sum(h: &[u8; BLOCK]) -> Result<(), String> {
    let want = numeric(&h[148..156])?;
    let (mut unsigned, mut signed) = (0i64, 0i64);
    for (i, &c) in h.iter().enumerate() {
        let c = if (148..156).contains(&i) { b' ' } else { c };
        unsigned += c as i64;
        signed += c as i8 as i64;
    }
    if want as i64 != unsigned && want as i64 != signed {
        return Err("archive/tar: invalid tar header".into());
    }
    Ok(())
}

/// numeric: octal, or GNU base-256 when the first byte has its high bit.
fn numeric(b: &[u8]) -> Result<u64, String> {
    if !b.is_empty() && b[0] & 0x80 != 0 {
        let mut v: u64 = (b[0] & 0x7f) as u64;
        for &c in &b[1..] {
            v = v
                .checked_mul(256)
                .and_then(|v| v.checked_add(c as u64))
                .ok_or("tar: numeric field overflows")?;
        }
        return Ok(v);
    }
    let s: Vec<u8> = b
        .iter()
        .copied()
        .skip_while(|&c| c == b' ' || c == 0)
        .take_while(|&c| c != b' ' && c != 0)
        .collect();
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(std::str::from_utf8(&s).unwrap_or("x"), 8)
        .map_err(|_| "archive/tar: invalid tar header".to_string())
}

fn parse_pax(mut b: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    while !b.is_empty() {
        let sp = b
            .iter()
            .position(|&c| c == b' ')
            .ok_or("tar: invalid PAX record")?;
        let n: usize = std::str::from_utf8(&b[..sp])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or("tar: invalid PAX record")?;
        if n <= sp + 1 || n > b.len() || b[n - 1] != b'\n' {
            return Err("tar: invalid PAX record".into());
        }
        let rec = &b[sp + 1..n - 1];
        let eq = rec
            .iter()
            .position(|&c| c == b'=')
            .ok_or("tar: invalid PAX record")?;
        out.insert(
            String::from_utf8_lossy(&rec[..eq]).into_owned(),
            String::from_utf8_lossy(&rec[eq + 1..]).into_owned(),
        );
        b = &b[n..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gz(tar: &[u8]) -> Vec<u8> {
        let mut w = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        w.write_all(tar).unwrap();
        w.finish().unwrap()
    }

    #[test]
    fn reads_what_the_pack_writes() {
        let files: BTreeMap<String, Vec<u8>> = [
            ("cni/bridge".to_string(), b"bridge".to_vec()),
            ("runc".to_string(), vec![7u8; 1000]),
        ]
        .into();
        let mut tar = Vec::new();
        crate::pack::write_tar(&mut tar, b"{}", &files).unwrap();
        let want: BTreeMap<String, String> = [
            ("runc".to_string(), "r".to_string()),
            ("cni/bridge".to_string(), "b".to_string()),
        ]
        .into();
        let got = members(&gz(&tar), &want, 1 << 20).unwrap();
        assert_eq!(got["r"], vec![7u8; 1000]);
        assert_eq!(got["b"], b"bridge");
        let missing: BTreeMap<String, String> = [("nope".to_string(), "n".to_string())].into();
        assert_eq!(
            members(&gz(&tar), &missing, 1 << 20).unwrap_err(),
            "archive has no nope"
        );
    }
}

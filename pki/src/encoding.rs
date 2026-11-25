//! PEM, base64, hex, and the little DER Armada writes and reads by hand:
//! the extensions of the certificates it issues (in Go's order and
//! encoding), and the outer layer of PKCS#8 keys.

/// Standard base64 with padding (Go's `base64.StdEncoding`).
pub fn base64_encode(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        s.push(A[(n >> 18) as usize & 63] as char);
        s.push(A[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        s.push(if c.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    s
}

/// Decodes standard base64 with padding; `None` for anything else.
pub fn base64_decode(s: &[u8]) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(4) {
        return None;
    }
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let chunks = s.len() / 4;
    for (i, c) in s.chunks(4).enumerate() {
        let last = i + 1 == chunks;
        let pad = c.iter().rev().take_while(|&&x| x == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &x in &c[..4 - pad] {
            n = (n << 6) | val(x)?;
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        // Go's decoder refuses non-zero bits past the data (strict
        // padding is not Go's default, but PEM bodies never have them).
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Some(out)
}

/// Lowercase hex.
pub fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(D[(x >> 4) as usize] as char);
        s.push(D[(x & 15) as usize] as char);
    }
    s
}

/// One PEM block.
pub struct Block {
    pub kind: String,
    pub bytes: Vec<u8>,
}

/// Encodes a PEM block as Go's `pem.EncodeToMemory` does: 64 characters a
/// line, a newline after the END line.
pub fn pem_encode(kind: &str, der: &[u8]) -> Vec<u8> {
    let body = base64_encode(der);
    let mut s = format!("-----BEGIN {kind}-----\n");
    for line in body.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        s.push('\n');
    }
    s.push_str(&format!("-----END {kind}-----\n"));
    s.into_bytes()
}

/// Finds the first well-formed PEM block in `data`, skipping anything
/// before it and blocks that do not decode, as Go's `pem.Decode` does.
/// Headers (`Key: value` lines) are skipped.
pub fn pem_decode(data: &[u8]) -> Option<Block> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    let mut rest = data;
    loop {
        let start = find(rest, BEGIN)?;
        // Go requires the BEGIN line at the start of the data or of a line.
        if start > 0 && rest[start - 1] != b'\n' {
            rest = &rest[start + BEGIN.len()..];
            continue;
        }
        let after = &rest[start + BEGIN.len()..];
        let line_end = after
            .iter()
            .position(|&c| c == b'\n')
            .unwrap_or(after.len());
        let line = trim_right_ascii(&after[..line_end]);
        let Some(kind) = line.strip_suffix(b"-----") else {
            rest = after;
            continue;
        };
        let kind = String::from_utf8_lossy(kind).into_owned();
        let body_start = (line_end + 1).min(after.len());
        let body_all = &after[body_start..];
        let end_marker = format!("-----END {kind}-----");
        let end = find(body_all, b"-----END ")?;
        let end_ok = body_all[end..].starts_with(end_marker.as_bytes());
        let mut body = &body_all[..end];
        // Headers end at the first empty line, when the first line has a
        // colon.
        if let Some(first) = body.split(|&c| c == b'\n').next()
            && first.contains(&b':')
            && let Some(blank) = find(body, b"\n\n").or_else(|| find(body, b"\r\n\r\n"))
        {
            body = &body[blank..];
        }
        let compact: Vec<u8> = body
            .iter()
            .copied()
            .filter(|c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
            .collect();
        if end_ok && let Some(bytes) = base64_decode(&compact) {
            return Some(Block { kind, bytes });
        }
        rest = &body_all[end..];
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn trim_right_ascii(b: &[u8]) -> &[u8] {
    let mut b = b;
    while let [rest @ .., last] = b {
        if last.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    b
}

/// A DER element: tag, length, content.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes = n.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// A SEQUENCE of already encoded elements.
pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// Reads one DER element: `(tag, content, rest)`. Definite lengths only,
/// in their shortest form.
pub fn read_tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, b) = b.split_first()?;
    let (&first, b) = b.split_first()?;
    let (len, b) = if first < 0x80 {
        (first as usize, b)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || b.len() < n || b[0] == 0 {
            return None;
        }
        let len = b[..n].iter().fold(0usize, |a, &x| (a << 8) | x as usize);
        if len < 0x80 {
            return None;
        }
        (len, &b[n..])
    };
    if b.len() < len {
        return None;
    }
    Some((tag, &b[..len], &b[len..]))
}

/// Encoded object identifiers Armada writes or looks for.
pub mod oid {
    /// 1.2.840.10045.2.1, id-ecPublicKey.
    pub const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    /// 1.2.840.10045.3.1.7, prime256v1 (P-256).
    pub const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    /// 1.2.840.113549.1.1.1, rsaEncryption.
    pub const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    /// 1.3.101.112, Ed25519.
    pub const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
    /// 1.3.101.110, X25519.
    pub const X25519: &[u8] = &[0x2b, 0x65, 0x6e];
    /// Extended key usages, 1.3.6.1.5.5.7.3.N, and anyExtendedKeyUsage.
    pub const EKU_PREFIX: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03];
    pub const EKU_ANY: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
    /// 1.3.6.1.4.1.311.10.3.3, 2.16.840.1.113730.4.1,
    /// 1.3.6.1.4.1.311.2.1.22, 1.3.6.1.4.1.311.61.1.1: the usages Go
    /// knows outside the PKIX arc.
    pub const EKU_MS_SGC: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x03, 0x03];
    pub const EKU_NS_SGC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x04, 0x01];
    pub const EKU_MS_COMMERCIAL: &[u8] =
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x16];
    pub const EKU_MS_KERNEL: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3d, 0x01, 0x01];
    /// Certificate extensions, 2.5.29.N.
    pub const SUBJECT_KEY_ID: u64 = 14;
    pub const KEY_USAGE: u64 = 15;
    pub const SUBJECT_ALT_NAME: u64 = 17;
    pub const BASIC_CONSTRAINTS: u64 = 19;
    pub const AUTHORITY_KEY_ID: u64 = 35;
    pub const EXT_KEY_USAGE: u64 = 37;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip() {
        for n in 0..70 {
            let b: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            let s = base64_encode(&b);
            assert_eq!(base64_decode(s.as_bytes()).unwrap(), b);
        }
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert!(base64_decode(b"Zm9v=g==").is_none());
        assert!(base64_decode(b"Zm9").is_none());
        assert!(base64_decode(b"Zm9!").is_none());
    }

    #[test]
    fn pem_round_trip_and_garbage() {
        let der: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let pem = pem_encode("CERTIFICATE", &der);
        let b = pem_decode(&pem).unwrap();
        assert_eq!(b.kind, "CERTIFICATE");
        assert_eq!(b.bytes, der);
        let mut noisy = b"junk before\n".to_vec();
        noisy.extend_from_slice(&pem_encode("X", b"bad?"));
        noisy.extend_from_slice(&pem);
        assert_eq!(pem_decode(&noisy).unwrap().kind, "X");
        assert!(pem_decode(b"not pem").is_none());
        assert!(pem_decode(b"-----BEGIN X-----\n!!!!\n-----END X-----\n").is_none());
        assert!(pem_decode(b"-----BEGIN X-----\nAAAA\n-----END Y-----\n").is_none());
    }

    #[test]
    fn der() {
        let long = vec![7u8; 300];
        let e = tlv(0x04, &long);
        assert_eq!(&e[..4], &[0x04, 0x82, 0x01, 0x2c]);
        let (tag, content, rest) = read_tlv(&e).unwrap();
        assert_eq!((tag, content.len(), rest.len()), (0x04, 300, 0));
        assert!(
            read_tlv(&[0x04, 0x81, 0x05, 0, 0, 0, 0, 0]).is_none(),
            "long form for a short length"
        );
        assert!(read_tlv(&[0x04, 0x05, 0]).is_none());
    }
}

//! Addresses and prefixes, parsed, compared, and printed strictly: the
//! cluster network's checks depend on exactly what is accepted (no leading
//! zeros, zones only on IPv6, canonical text) and on how addresses are
//! ordered and printed.

use std::cmp::Ordering;
use std::fmt;

/// An IP address (netip.Addr): IPv4, or IPv6 with an optional zone.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Addr {
    V4([u8; 4]),
    V6([u8; 16], String),
}

impl Ord for Addr {
    /// netip.Addr.Compare: IPv4 before IPv6, then the bytes, then the zone.
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Addr::V4(a), Addr::V4(b)) => a.cmp(b),
            (Addr::V4(_), Addr::V6(..)) => Ordering::Less,
            (Addr::V6(..), Addr::V4(_)) => Ordering::Greater,
            (Addr::V6(a, za), Addr::V6(b, zb)) => a.cmp(b).then_with(|| za.cmp(zb)),
        }
    }
}

impl PartialOrd for Addr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Four decimal fields, no leading zeros, each at most 255.
fn parse_v4_fields(s: &[u8]) -> Option<[u8; 4]> {
    let mut fields = [0u8; 4];
    let (mut val, mut pos, mut dig) = (0u32, 0usize, 0usize);
    for (i, &c) in s.iter().enumerate() {
        match c {
            b'0'..=b'9' => {
                if dig == 1 && val == 0 {
                    return None;
                }
                val = val * 10 + u32::from(c - b'0');
                dig += 1;
                if val > 255 {
                    return None;
                }
            }
            b'.' => {
                if i == 0 || i == s.len() - 1 || s[i - 1] == b'.' || pos == 3 {
                    return None;
                }
                fields[pos] = val as u8;
                pos += 1;
                val = 0;
                dig = 0;
            }
            _ => return None,
        }
    }
    if pos < 3 {
        return None;
    }
    fields[3] = val as u8;
    Some(fields)
}

/// An IPv6 address: at most four hex digits a group, one "::", an
/// embedded IPv4 address only last, and a zone after '%'.
fn parse_v6(input: &str) -> Option<Addr> {
    let (mut s, zone) = match input.find('%') {
        Some(i) => {
            let zone = &input[i + 1..];
            if zone.is_empty() {
                return None;
            }
            (&input.as_bytes()[..i], zone.to_string())
        }
        None => (input.as_bytes(), String::new()),
    };
    let mut ip = [0u8; 16];
    let mut ellipsis: isize = -1;
    if s.len() >= 2 && s[0] == b':' && s[1] == b':' {
        ellipsis = 0;
        s = &s[2..];
        if s.is_empty() {
            return Some(Addr::V6(ip, zone));
        }
    }
    let mut i = 0usize;
    while i < 16 {
        let mut off = 0usize;
        let mut acc = 0u32;
        while off < s.len() {
            let c = s[off];
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => break,
            };
            acc = (acc << 4) + u32::from(d);
            if off > 3 || acc > 0xffff {
                return None;
            }
            off += 1;
        }
        if off == 0 {
            return None;
        }
        if off < s.len() && s[off] == b'.' {
            if (ellipsis < 0 && i != 12) || i + 4 > 16 {
                return None;
            }
            let v4 = parse_v4_fields(s)?;
            ip[i..i + 4].copy_from_slice(&v4);
            s = &[];
            i += 4;
            break;
        }
        ip[i] = (acc >> 8) as u8;
        ip[i + 1] = acc as u8;
        i += 2;
        s = &s[off..];
        if s.is_empty() {
            break;
        }
        if s[0] != b':' || s.len() == 1 {
            return None;
        }
        s = &s[1..];
        if s[0] == b':' {
            if ellipsis >= 0 {
                return None;
            }
            ellipsis = i as isize;
            s = &s[1..];
            if s.is_empty() {
                break;
            }
        }
    }
    if !s.is_empty() {
        return None;
    }
    if i < 16 {
        if ellipsis < 0 {
            return None;
        }
        let e = ellipsis as usize;
        let n = 16 - i;
        for j in (e..i).rev() {
            ip[j + n] = ip[j];
        }
        for b in &mut ip[e..e + n] {
            *b = 0;
        }
    } else if ellipsis >= 0 {
        return None;
    }
    Some(Addr::V6(ip, zone))
}

impl Addr {
    /// netip.ParseAddr.
    pub fn parse(s: &str) -> Option<Addr> {
        for &c in s.as_bytes() {
            match c {
                b'.' => return parse_v4_fields(s.as_bytes()).map(Addr::V4),
                b':' => return parse_v6(s),
                b'%' => return None,
                _ => {}
            }
        }
        None
    }

    pub fn is4(&self) -> bool {
        matches!(self, Addr::V4(_))
    }

    pub fn zone(&self) -> &str {
        match self {
            Addr::V4(_) => "",
            Addr::V6(_, z) => z,
        }
    }

    fn is4in6(&self) -> bool {
        matches!(self, Addr::V6(b, _) if b[..10] == [0; 10] && b[10] == 0xff && b[11] == 0xff)
    }

    /// netip.Addr.Unmap.
    pub fn unmap(&self) -> Addr {
        match self {
            Addr::V6(b, _) if self.is4in6() => Addr::V4([b[12], b[13], b[14], b[15]]),
            a => a.clone(),
        }
    }

    pub fn is_private(&self) -> bool {
        match self.unmap() {
            Addr::V4(b) => {
                b[0] == 10 || (b[0] == 172 && b[1] & 0xf0 == 16) || (b[0] == 192 && b[1] == 168)
            }
            Addr::V6(b, _) => b[0] & 0xfe == 0xfc,
        }
    }

    pub fn is_loopback(&self) -> bool {
        match self.unmap() {
            Addr::V4(b) => b[0] == 127,
            Addr::V6(b, _) => b[..15] == [0; 15] && b[15] == 1,
        }
    }

    fn is_multicast(&self) -> bool {
        match self.unmap() {
            Addr::V4(b) => b[0] & 0xf0 == 0xe0,
            Addr::V6(b, _) => b[0] == 0xff,
        }
    }

    fn is_link_local_unicast(&self) -> bool {
        match self.unmap() {
            Addr::V4(b) => b[0] == 169 && b[1] == 254,
            Addr::V6(b, _) => b[0] == 0xfe && b[1] & 0xc0 == 0x80,
        }
    }

    /// netip.Addr.IsGlobalUnicast.
    pub fn is_global_unicast(&self) -> bool {
        let ip = self.unmap();
        match &ip {
            Addr::V4(b) if *b == [0; 4] || *b == [255; 4] => return false,
            Addr::V6(b, z) if *b == [0; 16] && z.is_empty() => return false,
            _ => {}
        }
        !ip.is_loopback() && !ip.is_multicast() && !ip.is_link_local_unicast()
    }

    /// The next address (netip.Addr.Next), for IPv4 only; None past the end.
    pub fn next4(&self) -> Option<Addr> {
        match self {
            Addr::V4(b) => u32::from_be_bytes(*b)
                .checked_add(1)
                .map(|n| Addr::V4(n.to_be_bytes())),
            Addr::V6(..) => None,
        }
    }
}

fn write_v4(f: &mut fmt::Formatter<'_>, b: &[u8]) -> fmt::Result {
    write!(f, "{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn write_v6(f: &mut fmt::Formatter<'_>, b: &[u8; 16]) -> fmt::Result {
    let group = |i: usize| u16::from_be_bytes([b[2 * i], b[2 * i + 1]]);
    let (mut zs, mut ze) = (255usize, 255usize);
    for i in 0..8 {
        let mut j = i;
        while j < 8 && group(j) == 0 {
            j += 1;
        }
        let l = j - i;
        if l >= 2 && l > ze.wrapping_sub(zs) {
            zs = i;
            ze = j;
        }
    }
    let mut i = 0;
    while i < 8 {
        if i == zs {
            f.write_str("::")?;
            i = ze;
            if i >= 8 {
                break;
            }
        } else if i > 0 {
            f.write_str(":")?;
        }
        write!(f, "{:x}", group(i))?;
        i += 1;
    }
    Ok(())
}

impl fmt::Display for Addr {
    /// netip.Addr.String.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Addr::V4(b) => write_v4(f, b),
            Addr::V6(b, z) => {
                if self.is4in6() {
                    f.write_str("::ffff:")?;
                    write_v4(f, &b[12..])?;
                } else {
                    write_v6(f, b)?;
                }
                if !z.is_empty() {
                    write!(f, "%{z}")?;
                }
                Ok(())
            }
        }
    }
}

/// The text of an address that may be missing ("invalid IP").
pub fn addr_text(a: &Option<Addr>) -> String {
    a.as_ref()
        .map_or_else(|| "invalid IP".to_string(), Addr::to_string)
}

/// A prefix (netip.Prefix); its address carries no zone.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Prefix {
    pub addr: Addr,
    pub bits: u8,
}

impl Ord for Prefix {
    fn cmp(&self, other: &Self) -> Ordering {
        self.addr.cmp(&other.addr).then(self.bits.cmp(&other.bits))
    }
}

impl PartialOrd for Prefix {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn mask(b: &mut [u8], bits: usize) {
    for (i, byte) in b.iter_mut().enumerate() {
        let start = i * 8;
        if start >= bits {
            *byte = 0;
        } else if bits - start < 8 {
            *byte &= 0xffu8 << (8 - (bits - start));
        }
    }
}

impl Prefix {
    /// Parses an address and a prefix length.
    pub fn parse(s: &str) -> Option<Prefix> {
        let i = s.rfind('/')?;
        let addr = Addr::parse(&s[..i])?;
        if !addr.zone().is_empty() {
            return None;
        }
        let bits = &s[i + 1..];
        if bits.is_empty()
            || !bits.bytes().all(|c| c.is_ascii_digit())
            || (bits.len() > 1 && bits.starts_with('0'))
            || bits.len() > 3
        {
            return None;
        }
        let n: u32 = bits.parse().ok()?;
        let max = if addr.is4() { 32 } else { 128 };
        if n > max {
            return None;
        }
        Some(Prefix {
            addr,
            bits: n as u8,
        })
    }

    /// netip.PrefixFrom for bits within the address's length.
    pub fn from(addr: &Addr, bits: u8) -> Prefix {
        let addr = match addr {
            Addr::V6(b, _) => Addr::V6(*b, String::new()),
            a => a.clone(),
        };
        Prefix { addr, bits }
    }

    pub fn masked(&self) -> Prefix {
        let addr = match &self.addr {
            Addr::V4(b) => {
                let mut b = *b;
                mask(&mut b, usize::from(self.bits));
                Addr::V4(b)
            }
            Addr::V6(b, _) => {
                let mut b = *b;
                mask(&mut b, usize::from(self.bits));
                Addr::V6(b, String::new())
            }
        };
        Prefix {
            addr,
            bits: self.bits,
        }
    }

    /// netip.Prefix.Contains.
    pub fn contains(&self, ip: &Addr) -> bool {
        if !ip.zone().is_empty() {
            return false;
        }
        let bits = usize::from(self.bits);
        match (&self.addr, ip) {
            (Addr::V4(p), Addr::V4(a)) => {
                let (mut p, mut a) = (*p, *a);
                mask(&mut p, bits);
                mask(&mut a, bits);
                p == a
            }
            (Addr::V6(p, _), Addr::V6(a, _)) => {
                let (mut p, mut a) = (*p, *a);
                mask(&mut p, bits);
                mask(&mut a, bits);
                p == a
            }
            _ => false,
        }
    }

    /// netip.Prefix.Overlaps.
    pub fn overlaps(&self, o: &Prefix) -> bool {
        if self == o {
            return true;
        }
        if self.addr.is4() != o.addr.is4() {
            return false;
        }
        let min = self.bits.min(o.bits);
        if min == 0 {
            return true;
        }
        Prefix::from(&self.addr, min).masked() == Prefix::from(&o.addr, min).masked()
    }
}

impl fmt::Display for Prefix {
    /// netip.Prefix.String.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.addr {
            Addr::V4(b) => write_v4(f, b)?,
            a @ Addr::V6(b, _) => {
                if a.is4in6() {
                    f.write_str("::ffff:")?;
                    write_v4(f, &b[12..])?;
                } else {
                    write_v6(f, b)?;
                }
            }
        }
        write!(f, "/{}", self.bits)
    }
}

/// The text of a prefix that may be missing ("invalid Prefix").
pub fn prefix_text(p: &Option<Prefix>) -> String {
    p.as_ref()
        .map_or_else(|| "invalid Prefix".to_string(), Prefix::to_string)
}

/// Whether an optional prefix contains ip; a missing one contains nothing.
pub fn opt_contains(p: &Option<Prefix>, ip: &Addr) -> bool {
    p.as_ref().is_some_and(|p| p.contains(ip))
}

/// A double-quoted string: `"` and `\` escaped, \a \b \f \n \r \t \v,
/// other ASCII control bytes as \xHH; other characters kept unless they
/// are control characters (\uXXXX, \UXXXXXXXX).
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            ' '..='~' => out.push(c),
            c if (c as u32) < 0x80 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if c.is_control() || c == '\u{ad}' || c == '\u{feff}' => {
                if (c as u32) < 0x10000 {
                    out.push_str(&format!("\\u{:04x}", c as u32));
                } else {
                    out.push_str(&format!("\\U{:08x}", c as u32));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Option<String> {
        Addr::parse(s).map(|a| a.to_string())
    }

    #[test]
    fn parses_strictly() {
        assert_eq!(p("10.0.0.1").as_deref(), Some("10.0.0.1"));
        assert_eq!(p("010.0.0.1"), None);
        assert_eq!(p("1.2.3"), None);
        assert_eq!(p("1.2.3.4.5"), None);
        assert_eq!(p("1.2.3.256"), None);
        assert_eq!(p("1.2.3.4%eth0"), None);
        assert_eq!(p("fd00::1").as_deref(), Some("fd00::1"));
        assert_eq!(p("FD00:0:0:0:0:0:0:1").as_deref(), Some("fd00::1"));
        assert_eq!(p("::ffff:10.0.0.1").as_deref(), Some("::ffff:10.0.0.1"));
        assert_eq!(p("::").as_deref(), Some("::"));
        assert_eq!(p("1::2:0:0:3").as_deref(), Some("1::2:0:0:3"));
        assert_eq!(p("1:0:0:2:0:0:0:3").as_deref(), Some("1:0:0:2::3"));
        assert_eq!(p("fe80::1%eth0").as_deref(), Some("fe80::1%eth0"));
        assert_eq!(p("fe80::1%"), None);
        assert_eq!(p("1:2:3:4:5:6:7:8::"), None);
        assert_eq!(p("12345::"), None);
        assert_eq!(p(""), None);
        assert_eq!(
            Addr::parse("::ffff:10.0.0.1").unwrap().unmap().to_string(),
            "10.0.0.1"
        );
    }

    #[test]
    fn prefixes_parse_strictly() {
        let pr = |s: &str| Prefix::parse(s).map(|p| p.to_string());
        assert_eq!(pr("10.120.0.1/16").as_deref(), Some("10.120.0.1/16"));
        assert_eq!(pr("10.120.0.0/016"), None);
        assert_eq!(pr("10.120.0.0/+8"), None);
        assert_eq!(pr("10.120.0.0/33"), None);
        assert_eq!(pr("10.120.0.0/"), None);
        assert_eq!(pr("fe80::/10").as_deref(), Some("fe80::/10"));
        assert_eq!(pr("fe80::%x/10"), None);
        let c = Prefix::parse("10.120.0.0/16").unwrap();
        assert!(c.contains(&Addr::parse("10.120.9.9").unwrap()));
        assert!(!c.contains(&Addr::parse("10.121.0.0").unwrap()));
        assert_eq!(
            Prefix::parse("10.120.3.7/24").unwrap().masked().to_string(),
            "10.120.3.0/24"
        );
        assert!(
            Prefix::parse("10.0.0.0/8")
                .unwrap()
                .overlaps(&Prefix::parse("10.121.0.0/16").unwrap())
        );
    }

    #[test]
    fn quotes_with_escapes() {
        assert_eq!(quote("a\"b\\\n\x01"), "\"a\\\"b\\\\\\n\\x01\"");
    }
}

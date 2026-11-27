//! The text rules specs keep, with their error texts: quoting with
//! backslash escapes, integers (errors `strconv.Atoi: parsing ...`),
//! durations ("1m30s"), IP addresses and prefixes, and Unicode classes.
//! Derived from the Go standard library (BSD-3-Clause).

use crate::gotables::{IS_DIGIT, IS_LETTER, IS_PRINT, IS_SPACE};

fn in_table(t: &[(u32, u32)], r: char) -> bool {
    let r = r as u32;
    t.binary_search_by(|&(lo, hi)| {
        if hi < r {
            std::cmp::Ordering::Less
        } else if lo > r {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    })
    .is_ok()
}

/// strconv.IsPrint.
pub fn is_print(r: char) -> bool {
    in_table(IS_PRINT, r)
}

/// unicode.IsSpace.
pub fn is_space(r: char) -> bool {
    in_table(IS_SPACE, r)
}

/// unicode.IsLetter.
pub fn is_letter(r: char) -> bool {
    in_table(IS_LETTER, r)
}

/// unicode.IsDigit.
pub fn is_digit(r: char) -> bool {
    in_table(IS_DIGIT, r)
}

/// unicode.IsControl: C0 and C1 control characters only.
pub fn is_control(r: char) -> bool {
    let r = r as u32;
    r < 0x20 || (0x7f..=0x9f).contains(&r)
}

const LOWERHEX: &[u8; 16] = b"0123456789abcdef";

/// strconv.Quote of a byte string, invalid UTF-8 written as \x escapes.
pub fn quote_bytes(s: &[u8]) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    let mut i = 0;
    while i < s.len() {
        let (r, width) = decode_rune(&s[i..]);
        match r {
            None => {
                out.push_str("\\x");
                out.push(LOWERHEX[(s[i] >> 4) as usize] as char);
                out.push(LOWERHEX[(s[i] & 0xf) as usize] as char);
            }
            Some(r) => escape_rune(&mut out, r),
        }
        i += width;
    }
    out.push('"');
    out
}

/// strconv.Quote, which `%q` and `%#v` of a string print.
pub fn quote(s: &str) -> String {
    quote_bytes(s.as_bytes())
}

fn escape_rune(out: &mut String, r: char) {
    if r == '"' || r == '\\' {
        out.push('\\');
        out.push(r);
        return;
    }
    if is_print(r) {
        out.push(r);
        return;
    }
    match r {
        '\u{7}' => out.push_str("\\a"),
        '\u{8}' => out.push_str("\\b"),
        '\u{c}' => out.push_str("\\f"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        '\u{b}' => out.push_str("\\v"),
        _ => {
            let v = r as u32;
            if v < 0x20 || v == 0x7f {
                out.push_str(&format!("\\x{v:02x}"));
            } else if v < 0x10000 {
                out.push_str(&format!("\\u{v:04x}"));
            } else {
                out.push_str(&format!("\\U{v:08x}"));
            }
        }
    }
}

/// utf8.DecodeRune: the rune at the start of b and its width, None for an
/// invalid encoding (width 1).
pub fn decode_rune(b: &[u8]) -> (Option<char>, usize) {
    let n = match b.first() {
        None => return (None, 0),
        Some(&c) if c < 0x80 => return (Some(c as char), 1),
        Some(&c) if c & 0xe0 == 0xc0 => 2,
        Some(&c) if c & 0xf0 == 0xe0 => 3,
        Some(&c) if c & 0xf8 == 0xf0 => 4,
        _ => return (None, 1),
    };
    if b.len() < n {
        return (None, 1);
    }
    match std::str::from_utf8(&b[..n]) {
        Ok(s) => (s.chars().next(), n),
        Err(_) => (None, 1),
    }
}

/// A byte string as a JSON string: each byte of an invalid
/// UTF-8 sequence becomes U+FFFD.
pub fn lossy(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let (r, w) = decode_rune(&b[i..]);
        out.push(r.unwrap_or('\u{fffd}'));
        i += w.max(1);
    }
    out
}

/// strings.Fields: s split around runs of unicode.IsSpace.
pub fn fields(s: &str) -> Vec<&str> {
    s.split(is_space).filter(|f| !f.is_empty()).collect()
}

/// strings.TrimSpace.
pub fn trim_space(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// The error of strconv.Atoi or ParseInt, with its fixed text.
fn num_error(func: &str, s: &str, why: &str) -> String {
    format!("strconv.{func}: parsing {}: {why}", quote(s))
}

/// strconv.ParseInt(s, 10, 64) with function name func in errors.
fn parse_int10(func: &str, s: &str) -> Result<i64, String> {
    if s.is_empty() {
        return Err(num_error(func, s, "invalid syntax"));
    }
    let (neg, digits) = match s.as_bytes()[0] {
        b'+' => (false, &s[1..]),
        b'-' => (true, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() {
        return Err(num_error(func, s, "invalid syntax"));
    }
    let mut n: u64 = 0;
    let mut range = false;
    for c in digits.bytes() {
        if !c.is_ascii_digit() {
            return Err(num_error(func, s, "invalid syntax"));
        }
        if range {
            continue;
        }
        match n
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(c - b'0')))
        {
            Some(v) => n = v,
            None => range = true,
        }
    }
    let cutoff: u64 = 1 << 63;
    if range || (!neg && n >= cutoff) || (neg && n > cutoff) {
        return Err(num_error(func, s, "value out of range"));
    }
    if neg {
        Ok((n as i64).wrapping_neg())
    } else {
        Ok(n as i64)
    }
}

/// strconv.Atoi on a 64-bit machine.
pub fn atoi(s: &str) -> Result<i64, String> {
    parse_int10("Atoi", s)
}

/// strconv.ParseInt(s, 10, 64).
pub fn parse_int(s: &str) -> Result<i64, String> {
    parse_int10("ParseInt", s)
}

/// strconv.Itoa.
pub fn itoa(n: i64) -> String {
    n.to_string()
}

/// The time package's own quote, used in duration errors: non-ASCII and
/// control bytes as \x escapes.
pub fn time_quote(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::from("\"");
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if !(b' '..0x80).contains(&c) {
            let (r, w) = decode_rune(&b[i..]);
            let width = match r {
                None => 1,
                Some('\u{fffd}') => w,
                Some(_) => w,
            };
            for j in 0..width {
                let x = b[i + j];
                out.push_str("\\x");
                out.push(LOWERHEX[(x >> 4) as usize] as char);
                out.push(LOWERHEX[(x & 0xf) as usize] as char);
            }
            i += width;
        } else {
            if c == b'"' || c == b'\\' {
                out.push('\\');
            }
            out.push(c as char);
            i += 1;
        }
    }
    out.push('"');
    out
}

pub const NANOSECOND: i64 = 1;
pub const MICROSECOND: i64 = 1000;
pub const MILLISECOND: i64 = 1_000_000;
pub const SECOND: i64 = 1_000_000_000;
pub const MINUTE: i64 = 60 * SECOND;
pub const HOUR: i64 = 60 * MINUTE;

fn duration_error(msg: &str, orig: &str) -> String {
    format!("time: {msg} {}", time_quote(orig))
}

/// time.ParseDuration, in nanoseconds.
pub fn parse_duration(orig: &str) -> Result<i64, String> {
    let mut s = orig.as_bytes();
    let mut d: u64 = 0;
    let mut neg = false;
    if let Some(&c) = s.first()
        && (c == b'-' || c == b'+')
    {
        neg = c == b'-';
        s = &s[1..];
    }
    if s == b"0" {
        return Ok(0);
    }
    if s.is_empty() {
        return Err(duration_error("invalid duration", orig));
    }
    let invalid = || duration_error("invalid duration", orig);
    while !s.is_empty() {
        let mut f: u64 = 0;
        let mut scale: f64 = 1.0;
        if !(s[0] == b'.' || s[0].is_ascii_digit()) {
            return Err(invalid());
        }
        // leadingInt
        let pl = s.len();
        let mut v: u64 = 0;
        let mut i = 0;
        while i < s.len() && s[i].is_ascii_digit() {
            if v > (1u64 << 63) / 10 {
                return Err(invalid());
            }
            v = v * 10 + u64::from(s[i] - b'0');
            if v > 1 << 63 {
                return Err(invalid());
            }
            i += 1;
        }
        s = &s[i..];
        let pre = pl != s.len();
        let mut post = false;
        if !s.is_empty() && s[0] == b'.' {
            s = &s[1..];
            let pl = s.len();
            // leadingFraction
            let mut i = 0;
            let mut overflow = false;
            while i < s.len() && s[i].is_ascii_digit() {
                let c = s[i];
                i += 1;
                if overflow {
                    continue;
                }
                if f > ((1u64 << 63) - 1) / 10 {
                    overflow = true;
                    continue;
                }
                let y = f * 10 + u64::from(c - b'0');
                if y > 1 << 63 {
                    overflow = true;
                    continue;
                }
                f = y;
                scale *= 10.0;
            }
            s = &s[i..];
            post = pl != s.len();
        }
        if !pre && !post {
            return Err(invalid());
        }
        let mut i = 0;
        while i < s.len() && !(s[i] == b'.' || s[i].is_ascii_digit()) {
            i += 1;
        }
        if i == 0 {
            return Err(duration_error("missing unit in duration", orig));
        }
        let u = &s[..i];
        s = &s[i..];
        let unit: u64 = match u {
            b"ns" => 1,
            b"us" | b"\xc2\xb5s" | b"\xce\xbcs" => 1000,
            b"ms" => 1_000_000,
            b"s" => SECOND as u64,
            b"m" => MINUTE as u64,
            b"h" => HOUR as u64,
            _ => {
                let unit = String::from_utf8_lossy(u);
                return Err(duration_error(
                    &format!("unknown unit {} in duration", time_quote(&unit)),
                    orig,
                ));
            }
        };
        if v > (1u64 << 63) / unit {
            return Err(invalid());
        }
        v *= unit;
        if f > 0 {
            v += (f as f64 * (unit as f64 / scale)) as u64;
            if v > 1 << 63 {
                return Err(invalid());
            }
        }
        d += v;
        if d > 1 << 63 {
            return Err(invalid());
        }
    }
    if neg {
        return Ok((d as i64).wrapping_neg());
    }
    if d > (1u64 << 63) - 1 {
        return Err(invalid());
    }
    Ok(d as i64)
}

fn fmt_frac(buf: &mut Vec<u8>, mut v: u64, prec: usize) -> u64 {
    let mut print = false;
    for _ in 0..prec {
        let digit = v % 10;
        print = print || digit != 0;
        if print {
            buf.push(b'0' + digit as u8);
        }
        v /= 10;
    }
    if print {
        buf.push(b'.');
    }
    v
}

fn fmt_int(buf: &mut Vec<u8>, mut v: u64) {
    if v == 0 {
        buf.push(b'0');
        return;
    }
    while v > 0 {
        buf.push(b'0' + (v % 10) as u8);
        v /= 10;
    }
}

/// A duration as text ("1h2m3.5s", "10ms"). The buffer is built backwards.
pub fn format_duration(d: i64) -> String {
    let mut buf: Vec<u8> = Vec::with_capacity(32);
    let neg = d < 0;
    let mut u = d as u64;
    if neg {
        u = u.wrapping_neg();
    }
    if u < SECOND as u64 {
        buf.push(b's');
        let prec;
        if u == 0 {
            return "0s".to_string();
        } else if u < MICROSECOND as u64 {
            prec = 0;
            buf.push(b'n');
        } else if u < MILLISECOND as u64 {
            prec = 3;
            // "µ" backwards
            buf.push(0xb5);
            buf.push(0xc2);
        } else {
            prec = 6;
            buf.push(b'm');
        }
        u = fmt_frac(&mut buf, u, prec);
        fmt_int(&mut buf, u);
    } else {
        buf.push(b's');
        u = fmt_frac(&mut buf, u, 9);
        fmt_int(&mut buf, u % 60);
        u /= 60;
        if u > 0 {
            buf.push(b'm');
            fmt_int(&mut buf, u % 60);
            u /= 60;
            if u > 0 {
                buf.push(b'h');
                fmt_int(&mut buf, u);
            }
        }
    }
    if neg {
        buf.push(b'-');
    }
    buf.reverse();
    String::from_utf8(buf).expect("duration text is UTF-8")
}

/// A net/netip address: 4 or 16 bytes and an IPv6 zone.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Addr {
    pub bytes: [u8; 16],
    pub is4: bool,
    pub zone: String,
}

impl Addr {
    fn from4(b: [u8; 4]) -> Addr {
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&b);
        Addr {
            bytes,
            is4: true,
            zone: String::new(),
        }
    }
    pub fn bit_len(&self) -> u8 {
        if self.is4 { 32 } else { 128 }
    }
    pub fn is4in6(&self) -> bool {
        !self.is4
            && self.bytes[..10].iter().all(|&b| b == 0)
            && self.bytes[10] == 0xff
            && self.bytes[11] == 0xff
    }
    pub fn unmap(&self) -> Addr {
        if self.is4in6() {
            Addr::from4([
                self.bytes[12],
                self.bytes[13],
                self.bytes[14],
                self.bytes[15],
            ])
        } else {
            self.clone()
        }
    }
    pub fn is_private(&self) -> bool {
        let ip = self.unmap();
        if ip.is4 {
            let b = &ip.bytes;
            return b[0] == 10
                || (b[0] == 172 && b[1] & 0xf0 == 16)
                || (b[0] == 192 && b[1] == 168);
        }
        ip.bytes[0] & 0xfe == 0xfc
    }
    fn u16at(&self, i: usize) -> u16 {
        u16::from_be_bytes([self.bytes[2 * i], self.bytes[2 * i + 1]])
    }
    /// Addr.String.
    pub fn string(&self) -> String {
        if self.is4 {
            let b = &self.bytes;
            return format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
        }
        let mut out = String::new();
        if self.is4in6() {
            let b = &self.bytes;
            out.push_str(&format!("::ffff:{}.{}.{}.{}", b[12], b[13], b[14], b[15]));
        } else {
            let (mut zs, mut ze) = (255u8, 255u8);
            for i in 0..8u8 {
                let mut j = i;
                while j < 8 && self.u16at(j as usize) == 0 {
                    j += 1;
                }
                let l = j - i;
                if l >= 2 && l > ze.wrapping_sub(zs) {
                    zs = i;
                    ze = j;
                }
            }
            let mut i = 0u8;
            while i < 8 {
                if i == zs {
                    out.push_str("::");
                    i = ze;
                    if i >= 8 {
                        break;
                    }
                } else if i > 0 {
                    out.push(':');
                }
                out.push_str(&format!("{:x}", self.u16at(i as usize)));
                i += 1;
            }
        }
        if !self.zone.is_empty() {
            out.push('%');
            out.push_str(&self.zone);
        }
        out
    }
}

fn parse_ipv4_fields(s: &[u8], fields: &mut [u8]) -> Result<(), ()> {
    let (mut val, mut pos, mut dig_len) = (0u32, 0usize, 0);
    for i in 0..s.len() {
        let c = s[i];
        if c.is_ascii_digit() {
            if dig_len == 1 && val == 0 {
                return Err(());
            }
            val = val * 10 + u32::from(c - b'0');
            dig_len += 1;
            if val > 255 {
                return Err(());
            }
        } else if c == b'.' {
            if i == 0 || i == s.len() - 1 || s[i - 1] == b'.' {
                return Err(());
            }
            if pos == 3 {
                return Err(());
            }
            fields[pos] = val as u8;
            pos += 1;
            val = 0;
            dig_len = 0;
        } else {
            return Err(());
        }
    }
    if pos < 3 {
        return Err(());
    }
    fields[3] = val as u8;
    Ok(())
}

fn parse_ipv6(input: &str) -> Result<Addr, ()> {
    let mut s = input.as_bytes();
    let mut zone = "";
    if let Some(i) = input.find('%') {
        s = &input.as_bytes()[..i];
        zone = &input[i + 1..];
        if zone.is_empty() {
            return Err(());
        }
    }
    let mut ip = [0u8; 16];
    let mut ellipsis: isize = -1;
    if s.len() >= 2 && s[0] == b':' && s[1] == b':' {
        ellipsis = 0;
        s = &s[2..];
        if s.is_empty() {
            return Ok(Addr {
                bytes: ip,
                is4: false,
                zone: zone.to_string(),
            });
        }
    }
    let mut i = 0usize;
    while i < 16 {
        let mut off = 0;
        let mut acc: u32 = 0;
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
                return Err(());
            }
            off += 1;
        }
        if off == 0 {
            return Err(());
        }
        if off < s.len() && s[off] == b'.' {
            if ellipsis < 0 && i != 12 {
                return Err(());
            }
            if i + 4 > 16 {
                return Err(());
            }
            let mut end = input.len();
            if !zone.is_empty() {
                end -= zone.len() + 1;
            }
            let start = end - s.len();
            parse_ipv4_fields(&input.as_bytes()[start..end], &mut ip[i..i + 4])?;
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
            return Err(());
        }
        s = &s[1..];
        if s[0] == b':' {
            if ellipsis >= 0 {
                return Err(());
            }
            ellipsis = i as isize;
            s = &s[1..];
            if s.is_empty() {
                break;
            }
        }
    }
    if !s.is_empty() {
        return Err(());
    }
    if i < 16 {
        if ellipsis < 0 {
            return Err(());
        }
        let e = ellipsis as usize;
        let n = 16 - i;
        let mut j = i as isize - 1;
        while j >= e as isize {
            ip[j as usize + n] = ip[j as usize];
            j -= 1;
        }
        for b in &mut ip[e..e + n] {
            *b = 0;
        }
    } else if ellipsis >= 0 {
        return Err(());
    }
    Ok(Addr {
        bytes: ip,
        is4: false,
        zone: zone.to_string(),
    })
}

/// netip.ParseAddr (acceptance only: the error texts are never shown).
pub fn parse_addr(s: &str) -> Option<Addr> {
    for c in s.bytes() {
        match c {
            b'.' => {
                let mut f = [0u8; 4];
                parse_ipv4_fields(s.as_bytes(), &mut f).ok()?;
                return Some(Addr::from4(f));
            }
            b':' => return parse_ipv6(s).ok(),
            b'%' => return None,
            _ => {}
        }
    }
    None
}

/// A net/netip prefix. Its address never has a zone.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Prefix {
    pub addr: Addr,
    pub bits: u8,
}

impl Prefix {
    /// netip.PrefixFrom of a valid length.
    pub fn from(addr: &Addr, bits: u8) -> Prefix {
        let mut a = addr.clone();
        a.zone.clear();
        Prefix { addr: a, bits }
    }
    /// Prefix.Masked.
    pub fn masked(&self) -> Prefix {
        let mut a = self.addr.clone();
        let n = if a.is4 { 4 } else { 16 };
        for (i, b) in a.bytes.iter_mut().take(n).enumerate() {
            let keep = (self.bits as usize).saturating_sub(i * 8).min(8);
            let mask = if keep == 0 { 0 } else { 0xffu8 << (8 - keep) };
            *b &= mask;
        }
        Prefix {
            addr: a,
            bits: self.bits,
        }
    }
    /// Prefix.Contains.
    pub fn contains(&self, ip: &Addr) -> bool {
        if !ip.zone.is_empty() || ip.is4 != self.addr.is4 {
            return false;
        }
        let m = Prefix {
            addr: ip.clone(),
            bits: self.bits,
        }
        .masked();
        m.addr.bytes == self.masked().addr.bytes
    }
    /// Prefix.String.
    pub fn string(&self) -> String {
        format!("{}/{}", self.addr.string(), self.bits)
    }
}

/// netip.ParsePrefix (acceptance only).
pub fn parse_prefix(s: &str) -> Option<Prefix> {
    let i = s.rfind('/')?;
    let ip = parse_addr(&s[..i])?;
    if !ip.is4 && !ip.zone.is_empty() {
        return None;
    }
    let bits_str = &s[i + 1..];
    let b = bits_str.as_bytes();
    if b.len() > 1 && !(b'1'..=b'9').contains(&b[0]) {
        return None;
    }
    let bits = atoi(bits_str).ok()?;
    let max = if ip.is4 { 32 } else { 128 };
    if !(0..=max).contains(&bits) {
        return None;
    }
    Some(Prefix::from(&ip, bits as u8))
}

/// path.Clean.
pub fn clean_path(p: &str) -> String {
    if p.is_empty() {
        return ".".to_string();
    }
    let rooted = p.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|l| *l != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            _ => parts.push(part),
        }
    }
    let joined = parts.join("/");
    if rooted {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("1h30m"), Ok(90 * MINUTE));
        assert_eq!(parse_duration("1.5s"), Ok(1_500_000_000));
        assert_eq!(
            parse_duration("x").unwrap_err(),
            "time: invalid duration \"x\""
        );
        assert_eq!(
            parse_duration("1").unwrap_err(),
            "time: missing unit in duration \"1\""
        );
        assert_eq!(
            parse_duration("1d").unwrap_err(),
            "time: unknown unit \"d\" in duration \"1d\""
        );
        assert_eq!(format_duration(90 * MINUTE), "1h30m0s");
        assert_eq!(format_duration(1500), "1.5µs");
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(-SECOND), "-1s");
        assert_eq!(format_duration(i64::MIN), "-2562047h47m16.854775808s");
    }

    #[test]
    fn quoting() {
        assert_eq!(quote("a\"b\n\u{7f}é\u{200b}"), "\"a\\\"b\\n\\x7fé\\u200b\"");
        assert_eq!(
            atoi("12x").unwrap_err(),
            "strconv.Atoi: parsing \"12x\": invalid syntax"
        );
        assert_eq!(
            atoi("99999999999999999999").unwrap_err(),
            "strconv.Atoi: parsing \"99999999999999999999\": value out of range"
        );
    }

    #[test]
    fn addresses() {
        let a = parse_addr("2001:db8::1").unwrap();
        assert_eq!(a.string(), "2001:db8::1");
        assert!(parse_addr("01.2.3.4").is_none());
        assert!(parse_addr("::ffff:1.2.3.4").unwrap().is4in6());
        let p = parse_prefix("10.1.2.3/8").unwrap().masked();
        assert_eq!(p.string(), "10.0.0.0/8");
        assert!(parse_prefix("10.0.0.0/08").is_none());
        assert_eq!(clean_path("/a/../b/./c/"), "/b/c");
    }
}

//! Tag resolution of plain scalars (go-yaml's resolve.go): which values are
//! null, booleans, numbers, timestamps, or strings, with Go's strconv and
//! time.Parse rules for what counts as a number or a timestamp.

use super::types::{
    BINARY_TAG, BOOL_TAG, DOUBLE_QUOTED_STYLE, FLOAT_TAG, FOLDED_STYLE, INT_TAG, Kind,
    LITERAL_STYLE, MAP_TAG, MERGE_TAG, NULL_TAG, Node, NodeId, SEQ_TAG, SINGLE_QUOTED_STYLE,
    STR_TAG, TIMESTAMP_TAG, Tree,
};

/// What a scalar resolves to (the value go-yaml's resolve returns).
#[derive(Clone, Debug, PartialEq)]
pub enum Resolved {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    Str(String),
    /// A timestamp; the input as written.
    Timestamp(String),
}

const LONG_TAG_PREFIX: &str = "tag:yaml.org,2002:";

/// Go's math.NaN(), whose bits differ from f64::NAN's.
pub fn go_nan() -> f64 {
    f64::from_bits(0x7ff8_0000_0000_0001)
}

/// The short form of a tag: tag:yaml.org,2002:str is !!str (go-yaml maps
/// its known tags and every other tag under the prefix the same way).
pub fn short_tag(tag: &str) -> String {
    match tag.strip_prefix(LONG_TAG_PREFIX) {
        Some(rest) => format!("!!{rest}"),
        None => tag.to_string(),
    }
}

/// The long form of a tag: !!str is tag:yaml.org,2002:str.
pub fn long_tag(tag: &str) -> String {
    match tag.strip_prefix("!!") {
        Some(rest) => format!("{LONG_TAG_PREFIX}{rest}"),
        None => tag.to_string(),
    }
}

fn resolvable_tag(tag: &str) -> bool {
    matches!(
        tag,
        "" | STR_TAG | BOOL_TAG | INT_TAG | FLOAT_TAG | NULL_TAG | TIMESTAMP_TAG
    )
}

fn hint(c: u8) -> u8 {
    match c {
        b'+' | b'-' => b'S',
        b'0'..=b'9' => b'D',
        b'y' | b'Y' | b'n' | b'N' | b't' | b'T' | b'f' | b'F' | b'o' | b'O' | b'~' | b'<' => b'M',
        b'.' => b'.',
        _ => 0,
    }
}

fn resolve_map(s: &str) -> Option<(&'static str, Resolved)> {
    Some(match s {
        "true" | "True" | "TRUE" => (BOOL_TAG, Resolved::Bool(true)),
        "false" | "False" | "FALSE" => (BOOL_TAG, Resolved::Bool(false)),
        "" | "~" | "null" | "Null" | "NULL" => (NULL_TAG, Resolved::Null),
        ".nan" | ".NaN" | ".NAN" => (FLOAT_TAG, Resolved::Float(go_nan())),
        ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" => {
            (FLOAT_TAG, Resolved::Float(f64::INFINITY))
        }
        "-.inf" | "-.Inf" | "-.INF" => (FLOAT_TAG, Resolved::Float(f64::NEG_INFINITY)),
        "<<" => (MERGE_TAG, Resolved::Str("<<".to_string())),
        _ => return None,
    })
}

/// Resolves a scalar with tag (short or long, or "") and value in, as
/// go-yaml's resolve does, including its error when an explicit tag does
/// not fit the value ("yaml: cannot decode !!str `x` as a !!int").
pub fn resolve(tag: &str, input: &str) -> Result<(String, Resolved), String> {
    let tag = short_tag(tag);
    if !resolvable_tag(&tag) {
        return Ok((tag, Resolved::Str(input.to_string())));
    }
    let (rtag, out) = resolve_inner(&tag, input);
    if tag.is_empty() || tag == rtag || tag == STR_TAG || tag == BINARY_TAG {
        return Ok((rtag.to_string(), out));
    }
    if tag == FLOAT_TAG
        && rtag == INT_TAG
        && let Resolved::Int(v) = out
    {
        return Ok((FLOAT_TAG.to_string(), Resolved::Float(v as f64)));
    }
    Err(format!(
        "yaml: cannot decode {} `{}` as a {}",
        short_tag(rtag),
        input,
        short_tag(&tag)
    ))
}

fn int_result(v: i64) -> (&'static str, Resolved) {
    (INT_TAG, Resolved::Int(v))
}

fn resolve_inner(tag: &str, input: &str) -> (&'static str, Resolved) {
    let h = if input.is_empty() {
        b'N'
    } else {
        hint(input.as_bytes()[0])
    };
    if h != 0 && tag != STR_TAG && tag != BINARY_TAG {
        if let Some(item) = resolve_map(input) {
            return item;
        }
        match h {
            b'M' => {}
            b'.' => {
                if let Some(f) = parse_float(input) {
                    return (FLOAT_TAG, Resolved::Float(f));
                }
            }
            b'D' | b'S' => {
                if (tag.is_empty() || tag == TIMESTAMP_TAG) && parse_timestamp(input) {
                    return (TIMESTAMP_TAG, Resolved::Timestamp(input.to_string()));
                }
                let plain = input.replace('_', "");
                if let Some(v) = parse_int(&plain, 0) {
                    return int_result(v);
                }
                if let Some(v) = parse_uint(&plain, 0) {
                    return (INT_TAG, Resolved::Uint(v));
                }
                if yaml_style_float(&plain)
                    && let Some(f) = parse_float(&plain)
                {
                    return (FLOAT_TAG, Resolved::Float(f));
                }
                if let Some(rest) = plain.strip_prefix("0b") {
                    if let Some(v) = parse_int(rest, 2) {
                        return int_result(v);
                    }
                    if let Some(v) = parse_uint(rest, 2) {
                        return (INT_TAG, Resolved::Uint(v));
                    }
                } else if let Some(rest) = plain.strip_prefix("-0b")
                    && let Some(v) = parse_int(&format!("-{rest}"), 2)
                {
                    return int_result(v);
                }
                if let Some(rest) = plain.strip_prefix("0o") {
                    if let Some(v) = parse_int(rest, 8) {
                        return int_result(v);
                    }
                    if let Some(v) = parse_uint(rest, 8) {
                        return (INT_TAG, Resolved::Uint(v));
                    }
                } else if let Some(rest) = plain.strip_prefix("-0o")
                    && let Some(v) = parse_int(&format!("-{rest}"), 8)
                {
                    return int_result(v);
                }
            }
            _ => unreachable!("hint table"),
        }
    }
    (STR_TAG, Resolved::Str(input.to_string()))
}

/// ^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$
fn yaml_style_float(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    if i < b.len() && (b[i] == b'-' || b[i] == b'+') {
        i += 1;
    }
    let digits = |i: &mut usize| {
        let start = *i;
        while *i < b.len() && b[*i].is_ascii_digit() {
            *i += 1;
        }
        *i - start
    };
    if i < b.len() && b[i] == b'.' {
        i += 1;
        if digits(&mut i) == 0 {
            return false;
        }
    } else {
        if digits(&mut i) == 0 {
            return false;
        }
        if i < b.len() && b[i] == b'.' {
            i += 1;
            digits(&mut i);
        }
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        i += 1;
        if i < b.len() && (b[i] == b'-' || b[i] == b'+') {
            i += 1;
        }
        if digits(&mut i) == 0 {
            return false;
        }
    }
    i == b.len()
}

/// Go's strconv.ParseUint(s, base, 64): base 0 reads a 0b, 0o, 0x, or 0
/// prefix and allows underscores between digits.
pub fn parse_uint(s: &str, base: u32) -> Option<u64> {
    let b = s.as_bytes();
    if b.is_empty() {
        return None;
    }
    let base0 = base == 0;
    let mut base = base as u64;
    let mut digits = b;
    if base0 {
        base = 10;
        if b[0] == b'0' {
            let l = |c: u8| c | 0x20;
            if b.len() >= 3 && l(b[1]) == b'b' {
                base = 2;
                digits = &b[2..];
            } else if b.len() >= 3 && l(b[1]) == b'o' {
                base = 8;
                digits = &b[2..];
            } else if b.len() >= 3 && l(b[1]) == b'x' {
                base = 16;
                digits = &b[2..];
            } else {
                base = 8;
                digits = &b[1..];
            }
        }
    }
    let mut n: u64 = 0;
    let mut underscores = false;
    for &c in digits {
        let lc = c | 0x20;
        let d = if c == b'_' && base0 {
            underscores = true;
            continue;
        } else if c.is_ascii_digit() {
            (c - b'0') as u64
        } else if lc.is_ascii_lowercase() {
            (lc - b'a') as u64 + 10
        } else {
            return None;
        };
        if d >= base {
            return None;
        }
        n = n.checked_mul(base).and_then(|n| n.checked_add(d))?;
    }
    if underscores && !underscore_ok(s) {
        return None;
    }
    Some(n)
}

/// Go's strconv.ParseInt(s, base, 64).
pub fn parse_int(s: &str, base: u32) -> Option<i64> {
    if s.is_empty() {
        return None;
    }
    let (neg, rest) = match s.as_bytes()[0] {
        b'+' => (false, &s[1..]),
        b'-' => (true, &s[1..]),
        _ => (false, s),
    };
    let un = parse_uint(rest, base)?;
    let cutoff = 1u64 << 63;
    if !neg && un >= cutoff {
        return None;
    }
    if neg && un > cutoff {
        return None;
    }
    Some(if neg {
        (un as i64).wrapping_neg()
    } else {
        un as i64
    })
}

/// Go's strconv.underscoreOK: underscores only between digits (or after
/// a base prefix).
fn underscore_ok(s: &str) -> bool {
    let mut b = s.as_bytes();
    let mut saw = b'^';
    let mut i = 0;
    if !b.is_empty() && (b[0] == b'-' || b[0] == b'+') {
        b = &b[1..];
    }
    let mut hex = false;
    if b.len() >= 2 && b[0] == b'0' && matches!(b[1] | 0x20, b'b' | b'o' | b'x') {
        i = 2;
        saw = b'0';
        hex = b[1] | 0x20 == b'x';
    }
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_digit() || (hex && (b'a'..=b'f').contains(&(c | 0x20))) {
            saw = b'0';
            i += 1;
            continue;
        }
        if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
            i += 1;
            continue;
        }
        if saw == b'_' {
            return false;
        }
        saw = b'!';
        i += 1;
    }
    saw != b'_'
}

fn prefix_len_ignore_case(s: &[u8], prefix: &[u8]) -> usize {
    let mut n = 0;
    while n < s.len() && n < prefix.len() && (s[n] | 0x20) == prefix[n] {
        n += 1;
    }
    n
}

/// Go's strconv.ParseFloat(s, 64): decimal and hexadecimal forms with
/// underscores, inf, infinity, and nan in any case; an error for a value
/// out of range.
pub fn parse_float(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    if b.is_empty() {
        return None;
    }
    // special()
    {
        let mut sign = 1.0;
        let mut nsign = 0;
        let mut t = b;
        let first = t[0];
        if first == b'+' || first == b'-' {
            if first == b'-' {
                sign = -1.0;
            }
            nsign = 1;
            t = &t[1..];
        }
        if first == b'+' || first == b'-' || first == b'i' || first == b'I' {
            let mut n = prefix_len_ignore_case(t, b"infinity");
            if 3 < n && n < 8 {
                n = 3;
            }
            if n == 3 || n == 8 {
                if nsign + n == b.len() {
                    return Some(sign * f64::INFINITY);
                }
                return None;
            }
        } else if (first == b'n' || first == b'N') && prefix_len_ignore_case(t, b"nan") == 3 {
            if b.len() == 3 {
                return Some(go_nan());
            }
            return None;
        }
    }
    // readFloat()
    let mut i = 0;
    let mut neg = false;
    if b[i] == b'+' {
        i += 1;
    } else if b[i] == b'-' {
        neg = true;
        i += 1;
    }
    let mut base = 10;
    if i + 2 < b.len() && b[i] == b'0' && b[i + 1] | 0x20 == b'x' {
        base = 16;
        i += 2;
    }
    let mant_start = i;
    let mut underscores = false;
    let mut saw_dot = false;
    let mut saw_digits = false;
    while i < b.len() {
        let c = b[i];
        if c == b'_' {
            underscores = true;
        } else if c == b'.' {
            if saw_dot {
                break;
            }
            saw_dot = true;
        } else if c.is_ascii_digit() || (base == 16 && (b'a'..=b'f').contains(&(c | 0x20))) {
            saw_digits = true;
        } else {
            break;
        }
        i += 1;
    }
    if !saw_digits {
        return None;
    }
    let mant_end = i;
    let mut exp_text: Option<(usize, usize)> = None;
    let expchar = if base == 16 { b'p' } else { b'e' };
    if i < b.len() && b[i] | 0x20 == expchar {
        i += 1;
        if i >= b.len() {
            return None;
        }
        let es = i;
        if b[i] == b'+' || b[i] == b'-' {
            i += 1;
        }
        if i >= b.len() || !b[i].is_ascii_digit() {
            return None;
        }
        while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'_') {
            if b[i] == b'_' {
                underscores = true;
            }
            i += 1;
        }
        exp_text = Some((es, i));
    } else if base == 16 {
        // A hexadecimal mantissa needs a 'p' exponent.
        return None;
    }
    if underscores && !underscore_ok(&s[..i]) {
        return None;
    }
    if i != b.len() {
        return None;
    }
    let mantissa: String = s[mant_start..mant_end]
        .chars()
        .filter(|&c| c != '_')
        .collect();
    let exponent: String = match exp_text {
        Some((a, z)) => s[a..z].chars().filter(|&c| c != '_').collect(),
        None => String::new(),
    };
    let v = if base == 10 {
        let text = if exponent.is_empty() {
            mantissa
        } else {
            format!("{mantissa}e{exponent}")
        };
        text.parse::<f64>().ok()?
    } else {
        hex_float(&mantissa, &exponent)?
    };
    if v.is_infinite() {
        return None;
    }
    Some(if neg { -v } else { v })
}

/// The value of a hexadecimal float's mantissa (hex digits with an
/// optional point) times 2 to the exponent, correctly rounded.
fn hex_float(mantissa: &str, exponent: &str) -> Option<f64> {
    let mut mant: u64 = 0;
    let mut exp: i64 = 0;
    let mut sticky = false;
    let mut after_dot = false;
    for c in mantissa.bytes() {
        if c == b'.' {
            after_dot = true;
            continue;
        }
        let d = (c as char).to_digit(16)? as u64;
        if mant >> 60 == 0 {
            mant = mant * 16 + d;
            if after_dot {
                exp -= 4;
            }
        } else {
            sticky |= d != 0;
            if !after_dot {
                exp += 4;
            }
        }
    }
    let e: i64 = exponent
        .parse::<i64>()
        .unwrap_or(if exponent.starts_with('-') {
            i64::MIN / 4
        } else {
            i64::MAX / 4
        });
    exp = exp.saturating_add(e);
    if mant == 0 {
        return Some(0.0);
    }
    // Normalise to 64 bits: mant has its top bit at 63.
    let lz = mant.leading_zeros() as i64;
    mant <<= lz;
    exp -= lz;
    // value = mant * 2^exp, mant in [2^63, 2^64).
    // The unbiased exponent of the leading bit:
    let lead = exp + 63;
    let (keep_bits, denormal) = if lead < -1022 {
        let k = 53 - (-1022 - lead);
        if k <= 0 {
            // Below half the smallest denormal: rounds to 0 or the smallest.
            if k == 0 && (mant > 1 << 63 || (mant == 1 << 63 && sticky)) {
                return Some(f64::from_bits(1));
            }
            return Some(0.0);
        }
        (k as u32, true)
    } else {
        (53u32, false)
    };
    let shift = 64 - keep_bits;
    let mut m = mant >> shift;
    let rem = mant & ((1u64 << shift) - 1);
    let half = 1u64 << (shift - 1);
    if rem > half || (rem == half && (sticky || m & 1 == 1)) || (rem == half && sticky) {
        m += 1;
    }
    let v = if denormal {
        // m counts units of 2^-1074.
        f64::from_bits(m)
    } else {
        let mut lead = lead;
        if m == 1 << 53 {
            m >>= 1;
            lead += 1;
        }
        if lead > 1023 {
            return Some(f64::INFINITY);
        }
        f64::from_bits((((lead + 1023) as u64) << 52) | (m & ((1 << 52) - 1)))
    };
    Some(v)
}

/// Whether s is a timestamp go-yaml accepts: four digits and a dash, then
/// one of its formats as Go's time.Parse reads them.
pub fn parse_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    let i = b.iter().take_while(|c| c.is_ascii_digit()).count();
    if i != 4 || i == b.len() || b[i] != b'-' {
        return false;
    }
    ts_format(b, Some(b'T'), true)
        || ts_format(b, Some(b't'), true)
        || ts_format(b, Some(b' '), false)
        || ts_format(b, None, false)
}

/// getnum: one or two digits (two with fixed).
fn getnum(v: &[u8], fixed: bool) -> Option<(i64, &[u8])> {
    if v.is_empty() || !v[0].is_ascii_digit() {
        return None;
    }
    if v.len() < 2 || !v[1].is_ascii_digit() {
        if fixed {
            return None;
        }
        return Some(((v[0] - b'0') as i64, &v[1..]));
    }
    Some((((v[0] - b'0') as i64) * 10 + (v[1] - b'0') as i64, &v[2..]))
}

fn cutspace(mut v: &[u8]) -> &[u8] {
    while let [b' ', rest @ ..] = v {
        v = rest;
    }
    v
}

/// time.Parse's skip of a literal of the layout.
fn skip<'a>(mut v: &'a [u8], mut prefix: &[u8]) -> Option<&'a [u8]> {
    while !prefix.is_empty() {
        if prefix[0] == b' ' {
            if !v.is_empty() && v[0] != b' ' {
                return None;
            }
            prefix = cutspace(prefix);
            v = cutspace(v);
            continue;
        }
        if v.is_empty() || v[0] != prefix[0] {
            return None;
        }
        prefix = &prefix[1..];
        v = &v[1..];
    }
    Some(v)
}

fn days_in(month: i64, year: i64) -> i64 {
    match month {
        2 => {
            if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// One of the layouts "2006-1-2" followed, when sep is set, by
/// sep "15:4:5.999999999", and with zone "Z07:00".
fn ts_format(v: &[u8], sep: Option<u8>, zone: bool) -> bool {
    let year: i64 = match std::str::from_utf8(&v[..4])
        .ok()
        .and_then(|y| y.parse().ok())
    {
        Some(y) => y,
        None => return false,
    };
    let Some(v) = skip(&v[4..], b"-") else {
        return false;
    };
    let Some((month, v)) = getnum(v, false) else {
        return false;
    };
    if !(1..=12).contains(&month) {
        return false;
    }
    let Some(v) = skip(v, b"-") else { return false };
    let Some((day, mut v)) = getnum(v, false) else {
        return false;
    };
    if let Some(sep) = sep {
        let Some(r) = skip(v, &[sep]) else {
            return false;
        };
        let Some((hour, r)) = getnum(r, false) else {
            return false;
        };
        if !(0..24).contains(&hour) {
            return false;
        }
        let Some(r) = skip(r, b":") else { return false };
        let Some((min, r)) = getnum(r, false) else {
            return false;
        };
        if !(0..60).contains(&min) {
            return false;
        }
        let Some(r) = skip(r, b":") else { return false };
        let Some((sec, mut r)) = getnum(r, false) else {
            return false;
        };
        if !(0..60).contains(&sec) {
            return false;
        }
        // stdFracSecond9: optional, any number of digits.
        if r.len() >= 2 && (r[0] == b'.' || r[0] == b',') && r[1].is_ascii_digit() {
            let mut i = 0;
            while i + 1 < r.len() && r[i + 1].is_ascii_digit() {
                i += 1;
            }
            r = &r[1 + i..];
        }
        if zone {
            if !r.is_empty() && r[0] == b'Z' {
                r = &r[1..];
            } else {
                if r.len() < 6 || r[3] != b':' {
                    return false;
                }
                let (sign, h, m) = (r[0], &r[1..3], &r[4..6]);
                let Some((hr, _)) = getnum(h, true) else {
                    return false;
                };
                let Some((mm, _)) = getnum(m, true) else {
                    return false;
                };
                if hr > 24 || mm > 60 || (sign != b'+' && sign != b'-') {
                    return false;
                }
                r = &r[6..];
            }
        }
        v = r;
    }
    if !v.is_empty() {
        return false;
    }
    day >= 1 && day <= days_in(month, year)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding, in lines of 70 characters each ended by
/// a line break when there is more than one line (go-yaml's encodeBase64).
pub fn encode_base64(s: &[u8]) -> String {
    let mut enc = Vec::with_capacity(s.len().div_ceil(3) * 4);
    for chunk in s.chunks(3) {
        let n = match chunk.len() {
            3 => (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8 | chunk[2] as u32,
            2 => (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8,
            _ => (chunk[0] as u32) << 16,
        };
        enc.push(B64[(n >> 18) as usize & 63]);
        enc.push(B64[(n >> 12) as usize & 63]);
        enc.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63]
        } else {
            b'='
        });
        enc.push(if chunk.len() > 2 {
            B64[n as usize & 63]
        } else {
            b'='
        });
    }
    const LINE: usize = 70;
    let lines = enc.len() / LINE + 1;
    let mut out = Vec::with_capacity(enc.len() + lines);
    for part in enc.chunks(LINE) {
        out.extend_from_slice(part);
        if lines > 1 {
            out.push(b'\n');
        }
    }
    String::from_utf8(out).expect("base64 is ASCII")
}

impl Node {
    /// Node.IsZero.
    pub fn is_zero(&self) -> bool {
        self.kind == Kind::Zero
            && self.style == 0
            && self.tag.is_empty()
            && self.value.is_empty()
            && self.anchor.is_empty()
            && self.alias.is_none()
            && self.content.is_empty()
            && self.head_comment.is_empty()
            && self.line_comment.is_empty()
            && self.foot_comment.is_empty()
            && self.line == 0
            && self.column == 0
    }
}

impl Tree {
    /// Node.ShortTag: the node's tag, resolved when it has none.
    pub fn short_tag(&self, id: NodeId) -> String {
        if self.indicated_string(id) {
            return STR_TAG.to_string();
        }
        let n = self.get(id);
        if n.tag.is_empty() || n.tag == "!" {
            return match n.kind {
                Kind::Mapping => MAP_TAG.to_string(),
                Kind::Sequence => SEQ_TAG.to_string(),
                Kind::Alias => match n.alias {
                    Some(a) => self.short_tag(a),
                    None => String::new(),
                },
                Kind::Scalar => match resolve("", &n.value) {
                    Ok((tag, _)) => tag,
                    Err(_) => String::new(),
                },
                Kind::Zero if n.is_zero() => NULL_TAG.to_string(),
                _ => String::new(),
            };
        }
        short_tag(&n.tag)
    }

    /// Node.indicatedString: a scalar tagged !!str, or quoted, literal, or
    /// folded without a tag.
    pub fn indicated_string(&self, id: NodeId) -> bool {
        let n = self.get(id);
        n.kind == Kind::Scalar
            && (short_tag(&n.tag) == STR_TAG
                || ((n.tag.is_empty() || n.tag == "!")
                    && n.style
                        & (SINGLE_QUOTED_STYLE
                            | DOUBLE_QUOTED_STYLE
                            | LITERAL_STYLE
                            | FOLDED_STYLE)
                        != 0))
    }
}

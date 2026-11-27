//! The string functions whose results and error texts the node's readings
//! depend on: decimal integer parsing (signed, unsigned, and int), quoting
//! of arbitrary bytes, trimming of white space, and splitting into fields.

/// The unsigned decimal value of the digits alone: the error's kind
/// ("invalid syntax" or "value out of range") on failure. The first
/// character that is not a digit is a syntax error and the first
/// overflow a range error, whichever comes first.
fn parse_digits(s: &[u8], max: u64) -> Result<u64, &'static str> {
    if s.is_empty() {
        return Err("invalid syntax");
    }
    let mut n: u64 = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return Err("invalid syntax");
        }
        let d = u64::from(c - b'0');
        if n > u64::MAX / 10 {
            return Err("value out of range");
        }
        n *= 10;
        let n1 = n.wrapping_add(d);
        if n1 < n || n1 > max {
            return Err("value out of range");
        }
        n = n1;
    }
    Ok(n)
}

/// An unsigned decimal integer of at most bits bits.
pub fn parse_uint(s: &str, bits: u32) -> Result<u64, String> {
    let max = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    parse_digits(s.as_bytes(), max).map_err(|why| num_error("ParseUint", s.as_bytes(), why))
}

/// A signed decimal integer of at most bits bits.
pub fn parse_int(s: &[u8], bits: u32) -> Result<i64, String> {
    let fail = |why| num_error("ParseInt", s, why);
    if s.is_empty() {
        return Err(fail("invalid syntax"));
    }
    let (neg, digits) = match s[0] {
        b'+' => (false, &s[1..]),
        b'-' => (true, &s[1..]),
        _ => (false, s),
    };
    let un = parse_digits(digits, u64::MAX).map_err(fail)?;
    let cutoff = 1u64 << (bits - 1);
    if !neg && un >= cutoff {
        return Err(fail("value out of range"));
    }
    if neg && un > cutoff {
        return Err(fail("value out of range"));
    }
    Ok(if neg {
        (un as i64).wrapping_neg()
    } else {
        un as i64
    })
}

/// A signed decimal 64-bit integer (errors name Atoi).
pub fn atoi(s: &str) -> Result<i64, String> {
    parse_int(s.as_bytes(), 64).map_err(|e| e.replacen("ParseInt", "Atoi", 1))
}

fn num_error(func: &str, s: &[u8], why: &str) -> String {
    format!("strconv.{func}: parsing {}: {why}", quote_bytes(s))
}

/// A byte string double-quoted: valid UTF-8 with `"`, `\`, and
/// non-printable characters escaped, each byte of invalid UTF-8 as \xNN.
pub fn quote_bytes(b: &[u8]) -> String {
    let mut out = String::from("\"");
    for chunk in b.utf8_chunks() {
        let q = crate::net::addr::quote(chunk.valid());
        out.push_str(&q[1..q.len() - 1]);
        for x in chunk.invalid() {
            out.push_str(&format!("\\x{x:02x}"));
        }
    }
    out.push('"');
    out
}

/// unicode.IsSpace.
fn is_space(c: char) -> bool {
    c.is_whitespace()
}

/// strings.TrimSpace on bytes: invalid UTF-8 is never space.
pub fn trim_space(b: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = b.len();
    // Leading.
    'lead: for chunk in b.utf8_chunks() {
        for c in chunk.valid().chars() {
            if !is_space(c) {
                break 'lead;
            }
            start += c.len_utf8();
        }
        if !chunk.invalid().is_empty() {
            break;
        }
    }
    // Trailing: decode from the end.
    while end > start {
        let tail = &b[start..end];
        let mut found = None;
        for back in 1..=4.min(tail.len()) {
            if let Ok(s) = std::str::from_utf8(&tail[tail.len() - back..])
                && let Some(c) = s.chars().next()
                && c.len_utf8() == back
            {
                found = Some(c);
                break;
            }
        }
        match found {
            Some(c) if is_space(c) => end -= c.len_utf8(),
            _ => break,
        }
    }
    &b[start..end]
}

/// strings.Fields on bytes: runs of characters that are not
/// unicode.IsSpace; invalid UTF-8 is never space.
pub fn fields(b: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    let mut i = 0;
    for chunk in b.utf8_chunks() {
        for c in chunk.valid().chars() {
            if is_space(c) {
                if let Some(s) = start.take() {
                    out.push(&b[s..i]);
                }
            } else if start.is_none() {
                start = Some(i);
            }
            i += c.len_utf8();
        }
        if !chunk.invalid().is_empty() {
            if start.is_none() {
                start = Some(i);
            }
            i += chunk.invalid().len();
        }
    }
    if let Some(s) = start {
        out.push(&b[s..]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_int_texts() {
        assert_eq!(parse_int(b"42", 64), Ok(42));
        assert_eq!(parse_int(b"+7", 64), Ok(7));
        assert_eq!(parse_int(b"-9223372036854775808", 64), Ok(i64::MIN));
        assert_eq!(
            parse_int(b"9223372036854775808", 64).unwrap_err(),
            "strconv.ParseInt: parsing \"9223372036854775808\": value out of range"
        );
        assert_eq!(
            parse_int(b"99999999999999999999x", 64).unwrap_err(),
            "strconv.ParseInt: parsing \"99999999999999999999x\": value out of range"
        );
        assert_eq!(
            parse_int(b"1_0", 64).unwrap_err(),
            "strconv.ParseInt: parsing \"1_0\": invalid syntax"
        );
        assert_eq!(
            parse_int(b"", 64).unwrap_err(),
            "strconv.ParseInt: parsing \"\": invalid syntax"
        );
        assert_eq!(
            parse_int(b"\xff1", 64).unwrap_err(),
            "strconv.ParseInt: parsing \"\\xff1\": invalid syntax"
        );
        assert_eq!(parse_uint("65535", 16), Ok(65535));
        assert!(parse_uint("65536", 16).is_err());
        assert_eq!(
            atoi("x").unwrap_err(),
            "strconv.Atoi: parsing \"x\": invalid syntax"
        );
    }

    #[test]
    fn trim_and_fields() {
        assert_eq!(trim_space(b" \t12\n"), b"12");
        assert_eq!(trim_space(b"\xc2\xa012\xc2\x85"), b"12");
        assert_eq!(trim_space(b"\xff "), b"\xff");
        assert_eq!(
            fields(b" a  b\tc\xff d "),
            vec![&b"a"[..], &b"b"[..], &b"c\xff"[..], &b"d"[..]]
        );
    }
}

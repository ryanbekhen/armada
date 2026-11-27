//! Records as JSON in the keyspace's format: struct fields in
//! declaration order, map keys sorted, HTML characters and U+2028/U+2029
//! escaped in strings, []byte as standard base64 (nil as null), and times
//! as Unix milliseconds or RFC 3339 text.

use std::sync::OnceLock;

use armada_spec::gotime::{Location, Time, load_location};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

/// json.Marshal of v. serde_json writes fields in declaration order, map
/// keys sorted (BTreeMap), and control characters escaped; the HTML
/// characters and the two line separators, also escaped in the format,
/// appear only inside strings, so they are escaped afterwards.
pub(crate) fn marshal<T: Serialize + ?Sized>(v: &T) -> Vec<u8> {
    let s = serde_json::to_string(v).expect("records always encode");
    escape_html(s).into_bytes()
}

/// Escapes `<`, `>`, `&`, U+2028, and U+2029 in encoded JSON as `\u003c` and the like.
pub(crate) fn escape_html(s: String) -> String {
    if !s.contains(['<', '>', '&', '\u{2028}', '\u{2029}']) {
        return s;
    }
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out
}

/// json.Compact with HTML escaping, as json.Marshal writes a
/// json.RawMessage: whitespace outside strings dropped, <, >, &, U+2028,
/// and U+2029 inside strings escaped.
pub(crate) fn compact(b: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(b);
    let mut out = String::with_capacity(s.len());
    let mut in_str = false;
    let mut esc = false;
    for c in s.chars() {
        if in_str {
            if esc {
                esc = false;
                out.push(c);
                continue;
            }
            match c {
                '\\' => {
                    esc = true;
                    out.push(c);
                }
                '"' => {
                    in_str = false;
                    out.push(c);
                }
                '<' => out.push_str("\\u003c"),
                '>' => out.push_str("\\u003e"),
                '&' => out.push_str("\\u0026"),
                '\u{2028}' => out.push_str("\\u2028"),
                '\u{2029}' => out.push_str("\\u2029"),
                c => out.push(c),
            }
            continue;
        }
        match c {
            ' ' | '\t' | '\n' | '\r' => {}
            '"' => {
                in_str = true;
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.into_bytes()
}

/// Decodes the record at key k; errors read `decode KEY: ...`.
pub(crate) fn decode<T: DeserializeOwned>(k: &str, b: &[u8]) -> Result<T> {
    serde_json::from_slice(b).map_err(|e| Error::other(format!("decode {k}: {e}")))
}

/// omitempty tests.
pub(crate) fn is_false(b: &bool) -> bool {
    !*b
}
pub(crate) fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

/// time.Local, read once.
pub fn local() -> &'static Location {
    static LOCAL: OnceLock<Location> = OnceLock::new();
    LOCAL.get_or_init(|| load_location("Local").unwrap_or_else(Location::utc))
}

/// The current time in time.Local.
pub fn now() -> Time {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Time {
        unix: d.as_secs() as i64,
        nsec: i64::from(d.subsec_nanos()),
        loc: local().clone(),
    }
}

/// Time.UnixMilli.
pub fn unix_milli(t: &Time) -> i64 {
    t.unix * 1000 + t.nsec / 1_000_000
}

/// Time.UnixNano.
pub fn unix_nano(t: &Time) -> i64 {
    t.unix.wrapping_mul(1_000_000_000).wrapping_add(t.nsec)
}

/// ms: a time in Unix milliseconds, 0 for the zero time.
pub fn ms(t: &Time) -> i64 {
    if t.is_zero() { 0 } else { unix_milli(t) }
}

/// fromMS: Unix milliseconds as a time in time.Local, the zero time for 0.
pub fn from_ms(v: i64) -> Time {
    if v == 0 {
        return Time::zero();
    }
    Time {
        unix: v.div_euclid(1000),
        nsec: v.rem_euclid(1000) * 1_000_000,
        loc: local().clone(),
    }
}

/// time.Unix(sec, 0) in time.Local.
pub fn from_unix(sec: i64) -> Time {
    Time {
        unix: sec,
        nsec: 0,
        loc: local().clone(),
    }
}

/// Time.Truncate(time.Millisecond).
pub fn truncate_ms(t: &Time) -> Time {
    Time {
        unix: t.unix,
        nsec: t.nsec - t.nsec % 1_000_000,
        loc: t.loc.clone(),
    }
}

/// Times as RFC 3339 with nanoseconds, for the answers of the parity
/// program.
pub mod time_text {
    use super::*;

    pub fn serialize<S: Serializer>(t: &Time, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&t.rfc3339_nano())
    }
}

/// []byte fields: standard base64 with padding, nil as null.
pub(crate) mod b64 {
    use super::*;

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(b: &[u8]) -> String {
        let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
        for c in b.chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            out.push(ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(ALPHABET[(n >> 12) as usize & 63] as char);
            out.push(if c.len() > 1 {
                ALPHABET[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if c.len() > 2 {
                ALPHABET[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    /// base64.StdEncoding.Decode as encoding/json uses it: line breaks
    /// are skipped, padding is required.
    pub fn decode(s: &str) -> Option<Vec<u8>> {
        let clean: Vec<u8> = s.bytes().filter(|&c| c != b'\r' && c != b'\n').collect();
        if !clean.len().is_multiple_of(4) {
            return None;
        }
        let val = |c: u8| ALPHABET.iter().position(|&a| a == c).map(|p| p as u32);
        let mut out = Vec::with_capacity(clean.len() / 4 * 3);
        for (i, q) in clean.chunks(4).enumerate() {
            let last = i == clean.len() / 4 - 1;
            let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
            if pad > 2 || (pad > 0 && !last) {
                return None;
            }
            let mut n = 0u32;
            for &c in &q[..4 - pad] {
                n = (n << 6) | val(c)?;
            }
            n <<= 6 * pad as u32;
            out.push((n >> 16) as u8);
            if pad < 2 {
                out.push((n >> 8) as u8);
            }
            if pad < 1 {
                out.push(n as u8);
            }
        }
        Some(out)
    }

    pub fn serialize<S: Serializer>(
        v: &Option<Vec<u8>>,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match v {
            None => s.serialize_none(),
            Some(b) => s.serialize_str(&encode(b)),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<Option<Vec<u8>>, D::Error> {
        let v: Option<String> = Option::deserialize(d)?;
        match v {
            None => Ok(None),
            Some(s) => decode(&s)
                .map(Some)
                .ok_or_else(|| serde::de::Error::custom("illegal base64 data")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escaped() {
        assert_eq!(
            String::from_utf8(marshal(&"a<b>&\u{2028}")).unwrap(),
            "\"a\\u003cb\\u003e\\u0026\\u2028\""
        );
        assert_eq!(
            String::from_utf8(marshal(&"\u{1}\n")).unwrap(),
            "\"\\u0001\\n\""
        );
    }

    #[test]
    fn compacts() {
        assert_eq!(
            compact(b"{ \"a\" : \"x y<\" ,\"b\":[1, 2]}"),
            b"{\"a\":\"x y\\u003c\",\"b\":[1,2]}".to_vec()
        );
        assert_eq!(
            compact(b"{\"a\":\"\\\" <\"}"),
            b"{\"a\":\"\\\" \\u003c\"}".to_vec()
        );
    }

    #[test]
    fn base64() {
        for (b, s) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"\xff\xfe\x00", "//4A"),
        ] {
            assert_eq!(b64::encode(b), s);
            assert_eq!(b64::decode(s).unwrap(), b);
        }
        assert!(b64::decode("Zg=").is_none());
        assert!(b64::decode("Zg==Zg==").is_none());
    }

    #[test]
    fn millis() {
        assert!(from_ms(0).is_zero());
        assert_eq!(ms(&from_ms(1_700_000_000_123)), 1_700_000_000_123);
        assert_eq!(ms(&from_ms(-1500)), -1500);
        assert_eq!(ms(&Time::zero()), 0);
    }
}

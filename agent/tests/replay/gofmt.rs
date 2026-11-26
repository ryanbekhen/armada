//! What the transcripts write as Go's harness wrote them: strconv.Quote,
//! time.Duration's String, fs.FileMode's String, FNV-1a, base64, and the
//! canonical form transcripts are compared in.

use serde_json::Value;

/// Go's strconv.Quote of bytes taken as a string.
pub fn quote(b: &[u8]) -> String {
    let mut out = String::from("\"");
    let mut i = 0;
    while i < b.len() {
        let rest = &b[i..];
        let (ch, n) = match std::str::from_utf8(&rest[..rest.len().min(4)]) {
            Ok(s) => {
                let c = s.chars().next().unwrap();
                (Some(c), c.len_utf8())
            }
            Err(e) if e.valid_up_to() > 0 => {
                let s = std::str::from_utf8(&rest[..e.valid_up_to()]).unwrap();
                let c = s.chars().next().unwrap();
                (Some(c), c.len_utf8())
            }
            Err(_) => (None, 1),
        };
        match ch {
            None => out.push_str(&format!("\\x{:02x}", b[i])),
            Some('"') => out.push_str("\\\""),
            Some('\\') => out.push_str("\\\\"),
            Some('\x07') => out.push_str("\\a"),
            Some('\x08') => out.push_str("\\b"),
            Some('\x0c') => out.push_str("\\f"),
            Some('\n') => out.push_str("\\n"),
            Some('\r') => out.push_str("\\r"),
            Some('\t') => out.push_str("\\t"),
            Some('\x0b') => out.push_str("\\v"),
            Some(c) if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            Some(c) if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            Some(c) => out.push(c),
        }
        i += n;
    }
    out.push('"');
    out
}

/// Go's time.Duration String.
pub fn duration(ns: i64) -> String {
    if ns == 0 {
        return "0s".into();
    }
    let neg = ns < 0;
    let u = ns.unsigned_abs();
    let mut s = if u < 1_000_000_000 {
        let (unit, div) = if u < 1_000 {
            ("ns", 1)
        } else if u < 1_000_000 {
            ("µs", 1_000)
        } else {
            ("ms", 1_000_000)
        };
        format!("{}{unit}", frac(u, div))
    } else {
        let secs = u / 1_000_000_000;
        let sub = u % 1_000_000_000;
        let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
        let sec = format!("{}s", frac(s * 1_000_000_000 + sub, 1_000_000_000));
        if h > 0 {
            format!("{h}h{m}m{sec}")
        } else if m > 0 {
            format!("{m}m{sec}")
        } else {
            sec
        }
    };
    if neg {
        s.insert(0, '-');
    }
    s
}

fn frac(v: u64, div: u64) -> String {
    let whole = v / div;
    let mut rem = v % div;
    if rem == 0 {
        return whole.to_string();
    }
    let mut digits = String::new();
    let mut d = div;
    while rem > 0 {
        d /= 10;
        digits.push(char::from(b'0' + (rem / d) as u8));
        rem %= d;
    }
    format!("{whole}.{digits}")
}

/// Go's fs.FileMode String for what the agent writes.
pub fn mode(meta: &std::fs::Metadata) -> String {
    use std::os::unix::fs::PermissionsExt;
    let ft = meta.file_type();
    let mut s = String::new();
    if ft.is_dir() {
        s.push('d');
    } else if ft.is_symlink() {
        s.push('L');
    }
    let p = meta.permissions().mode();
    if s.is_empty() {
        s.push('-');
    }
    for (i, c) in "rwxrwxrwx".chars().enumerate() {
        s.push(if p & (1 << (8 - i)) != 0 { c } else { '-' });
    }
    s
}

/// FNV-1a, 32 bits, as Go's hash/fnv.
pub fn fnv32a(s: &str) -> i64 {
    let mut h: u32 = 0x811c9dc5;
    for b in s.bytes() {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x01000193);
    }
    i64::from(h)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding.
pub fn b64_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let Some(v) = B64.iter().position(|&x| x == c) else {
            continue;
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

/// A JSON value with its objects' keys sorted, written compactly.
pub fn canon(v: &Value) -> String {
    fn sorted(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut keys: Vec<_> = m.keys().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for k in keys {
                    out.insert(k.clone(), sorted(&m[k]));
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
            x => x.clone(),
        }
    }
    // serde_json's map keeps keys sorted unless preserve_order is on; sort
    // anyway and write by hand to be sure.
    fn write(v: &Value, out: &mut String) {
        match v {
            Value::Object(m) => {
                let mut keys: Vec<_> = m.keys().collect();
                keys.sort();
                out.push('{');
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(k).unwrap());
                    out.push(':');
                    write(&m[*k], out);
                }
                out.push('}');
            }
            Value::Array(a) => {
                out.push('[');
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(x, out);
                }
                out.push(']');
            }
            x => out.push_str(&serde_json::to_string(x).unwrap()),
        }
    }
    let mut out = String::new();
    write(&sorted(v), &mut out);
    out
}

/// A text with a JSON value from its first brace on, in canonical form.
pub fn canon_embedded(s: &str) -> String {
    if let Some(i) = s.find(['{', '['])
        && let Ok(v) = serde_json::from_str::<Value>(&s[i..])
    {
        return format!("{}{}", &s[..i], canon(&v));
    }
    s.to_string()
}

/// A recorded call, "method JSON", in canonical form.
pub fn canon_call(s: &str) -> String {
    match s.split_once(' ') {
        Some((m, rest)) => match serde_json::from_str::<Value>(rest) {
            Ok(v) => format!("{m} {}", canon(&v)),
            Err(_) => s.to_string(),
        },
        None => s.to_string(),
    }
}

/// A transcript line in canonical form: JSON in any key order, and a
/// step's calls sorted with equal pulls once, as Go's harness takes them.
pub fn canon_line(l: &str) -> String {
    let (kind, rest) = l.split_once(' ').unwrap_or((l, ""));
    match kind {
        "calls" => {
            let mut calls: Vec<String> = if rest.is_empty() {
                Vec::new()
            } else {
                rest.split('\n').map(canon_call).collect()
            };
            calls.sort();
            calls.dedup_by(|a, b| a == b && a.starts_with("pull "));
            format!("calls {}", calls.join("\n"))
        }
        "server" | "node" | "export" | "files" => {
            let lines: Vec<String> = rest.split('\n').map(canon_embedded).collect();
            format!("{kind} {}", lines.join("\n"))
        }
        _ => canon_embedded(l),
    }
}

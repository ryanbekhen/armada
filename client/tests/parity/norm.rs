//! The normalizations the comparison applies: `normalize` for outputs,
//! `private_keys` for files and the config, and `request` for the requests the fake
//! received.

use serde_json::Value;

fn word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// `\b` between s[..i] and s[i..].
fn boundary(s: &[u8], i: usize) -> bool {
    let before = i > 0 && word(s[i - 1]);
    let after = i < s.len() && word(s[i]);
    before != after
}

/// toolchain: `\b(go[0-9][0-9.a-z]*|rust[0-9][0-9.a-z-]*)\b` → TOOLCHAIN.
fn toolchain(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    let mut last = 0;
    while i < b.len() {
        if boundary(b, i) {
            let found = [("go", false), ("rust", true)]
                .iter()
                .find_map(|(p, dash)| {
                    let start = i + p.len();
                    if !b[i..].starts_with(p.as_bytes())
                        || start >= b.len()
                        || !b[start].is_ascii_digit()
                    {
                        return None;
                    }
                    let mut end = start + 1;
                    while end < b.len()
                        && (b[end].is_ascii_digit()
                            || b[end] == b'.'
                            || b[end].is_ascii_lowercase()
                            || (*dash && b[end] == b'-'))
                    {
                        end += 1;
                    }
                    while end > start + 1 && !boundary(b, end) {
                        end -= 1;
                    }
                    boundary(b, end).then_some(end)
                });
            if let Some(end) = found {
                out.push_str(&s[last..i]);
                out.push_str("TOOLCHAIN");
                i = end;
                last = end;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&s[last..]);
    out
}

/// `\b([0-9]+[hms])+ ago\b` → `DURATION ago`.
fn since_time(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    let mut last = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() && boundary(b, i) {
            let mut j = i;
            let mut groups = 0;
            loop {
                let mut k = j;
                while k < b.len() && b[k].is_ascii_digit() {
                    k += 1;
                }
                if k == j || k >= b.len() || !matches!(b[k], b'h' | b'm' | b's') {
                    break;
                }
                j = k + 1;
                groups += 1;
            }
            if groups > 0 && b[j..].starts_with(b" ago") && boundary(b, j + 4) {
                out.push_str(&s[last..i]);
                out.push_str("DURATION ago");
                i = j + 4;
                last = i;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&s[last..]);
    out
}

/// Numbers as the recording reads them: every number a float64.
pub fn go_numbers(v: Value) -> Value {
    match v {
        Value::Number(n) => n
            .as_f64()
            .and_then(serde_json::Number::from_f64)
            .map_or(Value::Null, Value::Number),
        Value::Array(a) => Value::Array(a.into_iter().map(go_numbers).collect()),
        Value::Object(o) => Value::Object(o.into_iter().map(|(k, v)| (k, go_numbers(v))).collect()),
        v => v,
    }
}

/// An output made comparable: the compiler's name, durations since a
/// time, and JSON compared as values.
#[derive(Debug, PartialEq)]
pub enum Output {
    Text(String),
    Json(Vec<Value>),
}

pub fn normalize(s: &str) -> Output {
    let s = since_time(&toolchain(s));
    let mut vs = Vec::new();
    for v in serde_json::Deserializer::from_str(&s).into_iter::<Value>() {
        match v {
            Ok(v) => vs.push(go_numbers(v)),
            Err(_) => return Output::Text(s),
        }
    }
    if vs.is_empty() {
        Output::Text(s)
    } else {
        Output::Json(vs)
    }
}

/// Every PEM private key, as written or inside a JSON string,
/// replaced by its kind: `-----BEGIN ([A-Z ]*PRIVATE KEY)-----(\\n|\n)
/// [A-Za-z0-9+/=\\\n]*-----END [A-Z ]*PRIVATE KEY-----` → `<$1>`.
pub fn private_keys(s: &str) -> String {
    const BEGIN: &str = "-----BEGIN ";
    let mut out = String::new();
    let mut rest = s;
    'outer: while let Some(at) = rest.find(BEGIN) {
        let tail = &rest[at + BEGIN.len()..];
        let kind_len = tail
            .bytes()
            .take_while(|b| b.is_ascii_uppercase() || *b == b' ')
            .count();
        let kind = &tail[..kind_len];
        let after = &tail[kind_len..];
        if kind.ends_with("PRIVATE KEY")
            && let Some(body) = after.strip_prefix("-----")
        {
            let body = body.strip_prefix("\\n").or_else(|| body.strip_prefix('\n'));
            if let Some(body) = body {
                // The body's class includes the backslash and the newline;
                // the END line follows it (the regex backtracks to the last
                // END that fits, which is the one right after the body).
                let n = body
                    .bytes()
                    .take_while(|b| b.is_ascii_alphanumeric() || b"+/=\\\n".contains(b))
                    .count();
                let mut end = n;
                loop {
                    let t = &body[end..];
                    if let Some(t) = t.strip_prefix("-----END ") {
                        let k = t
                            .bytes()
                            .take_while(|b| b.is_ascii_uppercase() || *b == b' ')
                            .count();
                        if t[..k].ends_with("PRIVATE KEY") && t[k..].starts_with("-----") {
                            out.push_str(&rest[..at]);
                            out.push('<');
                            out.push_str(kind);
                            out.push('>');
                            let used = (body.as_ptr() as usize - rest.as_ptr() as usize)
                                + end
                                + "-----END ".len()
                                + k
                                + 5;
                            rest = &rest[used..];
                            continue 'outer;
                        }
                    }
                    if end == 0 {
                        break;
                    }
                    end -= 1;
                }
            }
        }
        out.push_str(&rest[..at + BEGIN.len()]);
        rest = &rest[at + BEGIN.len()..];
    }
    out.push_str(rest);
    out
}

/// A whole number of minutes as a duration's text ("1h30m0s", "5m0s", "0s").
fn minutes(m: i64) -> String {
    if m == 0 {
        return "0s".to_string();
    }
    let sign = if m < 0 { "-" } else { "" };
    let m = m.unsigned_abs();
    if m >= 60 {
        format!("{sign}{}h{}m0s", m / 60, m % 60)
    } else {
        format!("{sign}{m}m0s")
    }
}

/// Unix nanoseconds of an RFC 3339 time as protojson writes them.
fn rfc3339_nanos(s: &str) -> Option<i128> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let mut i = 19;
    let mut frac: i128 = 0;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let digits = &s[start..i];
        if digits.is_empty() || digits.len() > 9 {
            return None;
        }
        frac = digits.parse::<i128>().ok()? * 10i128.pow(9 - digits.len() as u32);
    }
    let offset = match &s[i..] {
        "Z" => 0,
        o if o.len() == 6 && (o.starts_with('+') || o.starts_with('-')) => {
            let v = num(i + 1..i + 3)? * 3600 + num(i + 4..i + 6)? * 60;
            if o.starts_with('-') { -v } else { v }
        }
        _ => return None,
    };
    // Days from the civil date (proleptic Gregorian).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 + se - offset;
    Some(i128::from(secs) * 1_000_000_000 + frac)
}

/// Times worked out from now become how long ago they
/// are, and a CSR what it asks for once its signature checks.
pub fn request(mut v: Value, now: i128) -> Value {
    fn times(v: &mut Value, now: i128) {
        match v {
            Value::Object(o) => {
                for (k, x) in o.iter_mut() {
                    if (k == "since" || k == "until")
                        && let Value::String(s) = x
                        && s.bytes()
                            .all(|b| b.is_ascii_digit() || b"TZ:.+-".contains(&b))
                        && let Some(t) = rfc3339_nanos(s)
                    {
                        let ago = now - t;
                        if ago <= 30 * 24 * 3600 * 1_000_000_000 {
                            // Round to the minute, halves away from zero.
                            let m = 60_000_000_000i128;
                            let r = if ago >= 0 {
                                (ago + m / 2) / m
                            } else {
                                -((-ago + m / 2) / m)
                            };
                            *x = Value::String(format!("now-{}", minutes(r as i64)));
                        }
                        continue;
                    }
                    times(x, now);
                }
            }
            Value::Array(a) => a.iter_mut().for_each(|x| times(x, now)),
            _ => {}
        }
    }
    times(&mut v, now);
    if let Some(Value::String(s)) = v.get("csr") {
        let summary = csr_summary(s);
        v["csr"] = Value::String(summary);
    }
    v
}

fn csr_summary(s: &str) -> String {
    use x509_parser::prelude::*;
    let Some(der) = crate::base64_decode(s) else {
        return s.to_string();
    };
    let Ok((_, csr)) = X509CertificationRequest::from_der(&der) else {
        return "invalid CSR".to_string();
    };
    if csr.verify_signature().is_err() {
        return "invalid CSR".to_string();
    }
    let info = &csr.certification_request_info;
    let cn = info
        .subject
        .iter_common_name()
        .next()
        .and_then(|c| c.as_str().ok())
        .unwrap_or("")
        .to_string();
    let alg = match info.subject_pki.algorithm.algorithm.to_id_string().as_str() {
        "1.2.840.10045.2.1" => "ECDSA",
        "1.2.840.113549.1.1.1" => "RSA",
        "1.3.101.112" => "Ed25519",
        _ => "UnknownPublicKeyAlgorithm",
    };
    format!("CSR of {cn}, {alg}")
}

//! A backup's manifest (Go's backup.Manifest): written as
//! json.MarshalIndent writes it, and read as a json.Decoder with
//! DisallowUnknownFields reads it, with Go's texts for every error a
//! restore can meet (syntax, unknown fields, types, times).

use std::collections::BTreeMap;

use armada_client::config::json_string;
use armada_spec::gotime::{self, Location, Time};

/// Manifest.
#[derive(Clone, Debug, Default)]
pub struct Manifest {
    pub format: i64,
    pub armada_version: String,
    pub created: Created,
    pub schema: i64,
    pub listen: String,
    pub master_key_id: String,
    pub ca_fingerprint: String,
    /// name → SHA-256 (hex); None is a nil map.
    pub files: Option<BTreeMap<String, String>>,
}

/// A time as a manifest holds it: an instant and the offset it was written
/// with (None for UTC, "Z").
#[derive(Clone, Debug)]
pub struct Created {
    pub unix: i64,
    pub nsec: i64,
    pub offset: Option<i64>,
    /// time.Time{}: never set.
    pub zero: bool,
}

impl Created {
    pub fn utc(unix: i64) -> Created {
        Created {
            unix,
            nsec: 0,
            offset: None,
            zero: false,
        }
    }

    /// The wall clock: the instant moved by its offset, read as UTC.
    fn wall(&self) -> Time {
        if self.zero {
            return Time::zero();
        }
        Time {
            unix: self.unix + self.offset.unwrap_or(0),
            nsec: self.nsec,
            loc: Location::utc(),
        }
    }

    /// Format("2006-01-02 15:04 MST").
    pub fn minute_zone(&self) -> String {
        let c = self.wall().civil();
        let zone = match self.offset {
            None => "UTC".to_string(),
            Some(o) => {
                let sign = if o < 0 { '-' } else { '+' };
                let a = o.abs();
                format!("{sign}{:02}{:02}", a / 3600, a % 3600 / 60)
            }
        };
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02} {zone}",
            c.year, c.month, c.day, c.hour, c.minute
        )
    }

    /// MarshalJSON: RFC 3339 with nanoseconds.
    fn rfc3339_nano(&self) -> String {
        let s = self.wall().rfc3339_nano();
        match self.offset {
            None | Some(0) => s,
            Some(o) => {
                let sign = if o < 0 { '-' } else { '+' };
                let a = o.abs();
                format!(
                    "{}{sign}{:02}:{:02}",
                    s.trim_end_matches('Z'),
                    a / 3600,
                    a % 3600 / 60
                )
            }
        }
    }
}

impl Default for Created {
    fn default() -> Self {
        Created {
            unix: 0,
            nsec: 0,
            offset: None,
            zero: true,
        }
    }
}

impl Manifest {
    /// json.MarshalIndent(m, "", "  ").
    pub fn to_json(&self) -> String {
        let mut s = String::from("{\n");
        s.push_str(&format!("  \"format\": {},\n", self.format));
        s.push_str(&format!(
            "  \"armadaVersion\": {},\n",
            json_string(&self.armada_version)
        ));
        s.push_str(&format!(
            "  \"created\": \"{}\",\n",
            self.created.rfc3339_nano()
        ));
        s.push_str(&format!("  \"schema\": {},\n", self.schema));
        s.push_str(&format!("  \"listen\": {},\n", json_string(&self.listen)));
        s.push_str(&format!(
            "  \"masterKeyId\": {},\n",
            json_string(&self.master_key_id)
        ));
        s.push_str(&format!(
            "  \"caFingerprint\": {},\n",
            json_string(&self.ca_fingerprint)
        ));
        match &self.files {
            None => s.push_str("  \"files\": null\n"),
            Some(f) if f.is_empty() => s.push_str("  \"files\": {}\n"),
            Some(f) => {
                s.push_str("  \"files\": {\n");
                let items: Vec<String> = f
                    .iter()
                    .map(|(k, v)| format!("    {}: {}", json_string(k), json_string(v)))
                    .collect();
                s.push_str(&items.join(",\n"));
                s.push_str("\n  }\n");
            }
        }
        s.push('}');
        s
    }

    /// A json.Decoder's Decode with DisallowUnknownFields: the first value
    /// in b (what follows it is not read), or Go's error.
    pub fn decode(b: &[u8]) -> Result<Manifest, String> {
        let mut p = Scanner { b, i: 0 };
        let v = p.top()?;
        let mut m = Manifest::default();
        let mut d = Decoder { first: None };
        d.manifest(&v, &mut m);
        match d.first {
            Some(e) => Err(e),
            None => Ok(m),
        }
    }
}

/// A JSON value with Go's view of it.
enum Value {
    Null,
    Bool,
    /// The literal.
    Num(String),
    Str(String),
    Arr,
    Obj(Vec<(String, Value)>),
}

impl Value {
    fn kind(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool => "bool",
            Value::Num(_) => "number",
            Value::Str(_) => "string",
            Value::Arr => "array",
            Value::Obj(_) => "object",
        }
    }
}

/// Go's quoteChar.
fn quote_char(c: u8) -> String {
    match c {
        b'\'' => "'\\''".to_string(),
        b'"' => "'\"'".to_string(),
        _ => {
            let q = armada_spec::go::quote(&char::from(c).to_string());
            format!("'{}'", &q[1..q.len() - 1])
        }
    }
}

const UNEXPECTED_EOF: &str = "unexpected EOF";

/// The syntax check of json.Decoder.readValue and a parse of the value.
struct Scanner<'a> {
    b: &'a [u8],
    i: usize,
}

impl Scanner<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn top(&mut self) -> Result<Value, String> {
        self.ws();
        if self.i == self.b.len() {
            return Err("EOF".to_string());
        }
        self.value("looking for beginning of value")
    }

    fn invalid(&self, c: u8, ctx: &str) -> String {
        format!("invalid character {} {ctx}", quote_char(c))
    }

    fn value(&mut self, ctx: &str) -> Result<Value, String> {
        self.ws();
        let Some(c) = self.peek() else {
            return Err(UNEXPECTED_EOF.to_string());
        };
        match c {
            b'{' => {
                self.i += 1;
                let mut out = Vec::new();
                self.ws();
                match self.peek() {
                    None => return Err(UNEXPECTED_EOF.to_string()),
                    Some(b'}') => {
                        self.i += 1;
                        return Ok(Value::Obj(out));
                    }
                    _ => {}
                }
                loop {
                    self.ws();
                    match self.peek() {
                        None => return Err(UNEXPECTED_EOF.to_string()),
                        Some(b'"') => {}
                        Some(c) => {
                            return Err(
                                self.invalid(c, "looking for beginning of object key string")
                            );
                        }
                    }
                    let k = self.string()?;
                    self.ws();
                    match self.peek() {
                        None => return Err(UNEXPECTED_EOF.to_string()),
                        Some(b':') => self.i += 1,
                        Some(c) => return Err(self.invalid(c, "after object key")),
                    }
                    let v = self.value("looking for beginning of value")?;
                    out.push((k, v));
                    self.ws();
                    match self.peek() {
                        None => return Err(UNEXPECTED_EOF.to_string()),
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Value::Obj(out));
                        }
                        Some(c) => return Err(self.invalid(c, "after object key:value pair")),
                    }
                }
            }
            b'[' => {
                self.i += 1;
                self.ws();
                match self.peek() {
                    None => return Err(UNEXPECTED_EOF.to_string()),
                    Some(b']') => {
                        self.i += 1;
                        return Ok(Value::Arr);
                    }
                    _ => {}
                }
                loop {
                    self.value("looking for beginning of value")?;
                    self.ws();
                    match self.peek() {
                        None => return Err(UNEXPECTED_EOF.to_string()),
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Value::Arr);
                        }
                        Some(c) => return Err(self.invalid(c, "after array element")),
                    }
                }
            }
            b'"' => Ok(Value::Str(self.string()?)),
            b't' => self.literal(b"true").map(|()| Value::Bool),
            b'f' => self.literal(b"false").map(|()| Value::Bool),
            b'n' => self.literal(b"null").map(|()| Value::Null),
            b'-' | b'0'..=b'9' => self.number().map(Value::Num),
            c => Err(self.invalid(c, ctx)),
        }
    }

    fn literal(&mut self, lit: &[u8]) -> Result<(), String> {
        let name = std::str::from_utf8(lit).unwrap_or_default();
        for (k, want) in lit.iter().enumerate() {
            match self.peek() {
                None => return Err(UNEXPECTED_EOF.to_string()),
                Some(c) if c == *want => self.i += 1,
                Some(c) if k == 0 => return Err(self.invalid(c, "looking for beginning of value")),
                Some(c) => {
                    return Err(self.invalid(
                        c,
                        &format!("in literal {name} (expecting {})", quote_char(*want)),
                    ));
                }
            }
        }
        Ok(())
    }

    /// A number; what ends it is left to the caller.
    fn number(&mut self) -> Result<String, String> {
        let start = self.i;
        let digit = |s: &mut Self| s.peek().is_some_and(|c| c.is_ascii_digit());
        let bad = |s: &Self| -> String {
            match s.peek() {
                None => UNEXPECTED_EOF.to_string(),
                Some(c) => s.invalid(c, "in numeric literal"),
            }
        };
        if self.peek() == Some(b'-') {
            self.i += 1;
            if !digit(self) {
                return Err(bad(self));
            }
        }
        if self.peek() == Some(b'0') {
            self.i += 1;
        } else {
            while digit(self) {
                self.i += 1;
            }
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !digit(self) {
                return Err(bad(self));
            }
            while digit(self) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !digit(self) {
                return Err(bad(self));
            }
            while digit(self) {
                self.i += 1;
            }
        }
        Ok(String::from_utf8_lossy(&self.b[start..self.i]).into_owned())
    }

    /// A string, its escapes decoded and invalid UTF-8 replaced.
    fn string(&mut self) -> Result<String, String> {
        self.i += 1;
        let mut out: Vec<u8> = Vec::new();
        let mut units: Vec<u16> = Vec::new();
        let flush = |units: &mut Vec<u16>, out: &mut Vec<u8>| {
            if !units.is_empty() {
                let s: String = char::decode_utf16(units.drain(..))
                    .map(|r| r.unwrap_or('\u{fffd}'))
                    .collect();
                out.extend_from_slice(s.as_bytes());
            }
        };
        loop {
            let Some(c) = self.peek() else {
                return Err(UNEXPECTED_EOF.to_string());
            };
            match c {
                b'"' => {
                    self.i += 1;
                    flush(&mut units, &mut out);
                    return Ok(String::from_utf8_lossy(&out).into_owned());
                }
                b'\\' => {
                    let at = self.i;
                    self.i += 1;
                    let Some(e) = self.peek() else {
                        return Err(UNEXPECTED_EOF.to_string());
                    };
                    self.i += 1;
                    let simple = match e {
                        b'"' => Some(b'"'),
                        b'\\' => Some(b'\\'),
                        b'/' => Some(b'/'),
                        b'b' => Some(8),
                        b'f' => Some(12),
                        b'n' => Some(b'\n'),
                        b'r' => Some(b'\r'),
                        b't' => Some(b'\t'),
                        _ => None,
                    };
                    if let Some(s) = simple {
                        flush(&mut units, &mut out);
                        out.push(s);
                        continue;
                    }
                    if e != b'u' {
                        return Err(format!(
                            "invalid escape sequence `{}` in string",
                            String::from_utf8_lossy(&self.b[at..self.i])
                        ));
                    }
                    let mut n = 0u16;
                    for _ in 0..4 {
                        let Some(h) = self.peek() else {
                            return Err(UNEXPECTED_EOF.to_string());
                        };
                        self.i += 1;
                        let d = match h {
                            b'0'..=b'9' => h - b'0',
                            b'a'..=b'f' => h - b'a' + 10,
                            b'A'..=b'F' => h - b'A' + 10,
                            _ => {
                                let end = (at + 6).min(self.b.len());
                                return Err(format!(
                                    "invalid escape sequence `{}` in string",
                                    String::from_utf8_lossy(&self.b[at..end])
                                ));
                            }
                        };
                        n = n * 16 + u16::from(d);
                    }
                    units.push(n);
                }
                c if c < 0x20 => {
                    return Err(format!("invalid character {} in string", quote_char(c)));
                }
                _ => {
                    flush(&mut units, &mut out);
                    out.push(c);
                    self.i += 1;
                }
            }
        }
    }
}

/// d.unmarshal into a Manifest: the first error saved, as Go's decoder
/// saves type errors and unknown fields and goes on.
struct Decoder {
    first: Option<String>,
}

const FIELDS: [&str; 8] = [
    "format",
    "armadaVersion",
    "created",
    "schema",
    "listen",
    "masterKeyId",
    "caFingerprint",
    "files",
];

const GO_TYPE: &str = "backup.Manifest";

impl Decoder {
    fn save(&mut self, e: String) {
        if self.first.is_none() {
            self.first = Some(e);
        }
    }

    fn type_error(&mut self, v: &Value, field: &str, typ: &str, with_literal: bool) {
        let what = match v {
            Value::Num(n) if with_literal => format!("number {n}"),
            _ => v.kind().to_string(),
        };
        self.save(format!(
            "json: cannot unmarshal {what} into Go struct field Manifest.{field} of type {typ}"
        ));
    }

    fn manifest(&mut self, v: &Value, m: &mut Manifest) {
        let fields = match v {
            Value::Null => return,
            Value::Obj(f) => f,
            other => {
                // Unmarshal stops at a type error of the whole value.
                self.save(format!(
                    "json: cannot unmarshal {} into Go value of type {GO_TYPE}",
                    other.kind()
                ));
                return;
            }
        };
        for (k, v) in fields {
            let name = FIELDS
                .iter()
                .find(|f| **f == k.as_str())
                .or_else(|| FIELDS.iter().find(|f| fold_eq(f, k)));
            let Some(name) = name else {
                self.save(format!("json: unknown field {}", armada_spec::go::quote(k)));
                continue;
            };
            match *name {
                "format" => self.int(v, name, &mut m.format),
                "schema" => self.int(v, name, &mut m.schema),
                "armadaVersion" => self.string(v, name, &mut m.armada_version),
                "listen" => self.string(v, name, &mut m.listen),
                "masterKeyId" => self.string(v, name, &mut m.master_key_id),
                "caFingerprint" => self.string(v, name, &mut m.ca_fingerprint),
                "created" => self.time(v, name, &mut m.created),
                _ => self.files(v, &mut m.files),
            }
        }
    }

    fn int(&mut self, v: &Value, field: &str, dst: &mut i64) {
        match v {
            Value::Null => {}
            Value::Num(n) => match n.parse::<i64>() {
                Ok(x) => *dst = x,
                Err(_) => self.type_error(v, field, "int", true),
            },
            _ => self.type_error(v, field, "int", true),
        }
    }

    fn string(&mut self, v: &Value, field: &str, dst: &mut String) {
        match v {
            Value::Null => {}
            Value::Str(s) => *dst = s.clone(),
            _ => self.type_error(v, field, "string", false),
        }
    }

    fn time(&mut self, v: &Value, field: &str, dst: &mut Created) {
        match v {
            Value::Null => {}
            Value::Str(s) => match parse_rfc3339(s) {
                Ok(c) => *dst = c,
                Err(e) => self.save(e),
            },
            _ => self.type_error(v, field, "time.Time", false),
        }
    }

    fn files(&mut self, v: &Value, dst: &mut Option<BTreeMap<String, String>>) {
        match v {
            Value::Null => *dst = None,
            Value::Obj(items) => {
                let m = dst.get_or_insert_with(BTreeMap::new);
                for (k, v) in items {
                    match v {
                        Value::Str(s) => {
                            m.insert(k.clone(), s.clone());
                        }
                        Value::Null => {
                            m.insert(k.clone(), String::new());
                        }
                        _ => {
                            m.insert(k.clone(), String::new());
                            let what = v.kind();
                            self.save(format!(
                                "json: cannot unmarshal {what} into Go struct field Manifest.files.{k} of type string"
                            ));
                        }
                    }
                }
            }
            _ => self.type_error(v, "files", "map[string]string", false),
        }
    }
}

/// Go's foldName match of a JSON key and a field name: equal under simple
/// case folding.
fn fold_eq(field: &str, key: &str) -> bool {
    let f: Vec<char> = field.chars().collect();
    let k: Vec<char> = key.chars().collect();
    f.len() == k.len()
        && f.iter().zip(&k).all(|(a, b)| {
            a == b
                || a.to_lowercase().eq(b.to_lowercase())
                || (*b == '\u{212a}' && a.eq_ignore_ascii_case(&'k'))
                || (*b == '\u{17f}' && a.eq_ignore_ascii_case(&'s'))
        })
}

/// time.Time's UnmarshalJSON of a JSON string: RFC 3339, with Go's error
/// for the common case and a fixed text past it.
fn parse_rfc3339(s: &str) -> Result<Created, String> {
    let fail = || {
        let layout = "2006-01-02T15:04:05Z07:00";
        let year: String = s.chars().take(4).collect();
        if s.len() < 4 || !year.bytes().all(|c| c.is_ascii_digit()) {
            format!(
                "parsing time {} as {}: cannot parse {} as \"2006\"",
                armada_spec::go::quote(s),
                armada_spec::go::quote(layout),
                armada_spec::go::quote(s)
            )
        } else {
            format!(
                "parsing time {} as {}: cannot parse {} as {}",
                armada_spec::go::quote(s),
                armada_spec::go::quote(layout),
                armada_spec::go::quote(&s[4.min(s.len())..]),
                armada_spec::go::quote(&layout[4..])
            )
        }
    };
    let t = gotime::parse_rfc3339(s).ok_or_else(fail)?;
    let offset = if s.ends_with('Z') || s.ends_with('z') {
        None
    } else {
        let tail = &s[s.len().saturating_sub(6)..];
        let sign = if tail.starts_with('-') { -1 } else { 1 };
        let h: i64 = tail.get(1..3).and_then(|x| x.parse().ok()).unwrap_or(0);
        let m: i64 = tail.get(4..6).and_then(|x| x.parse().ok()).unwrap_or(0);
        Some(sign * (h * 3600 + m * 60))
    };
    Ok(Created {
        unix: t.unix,
        nsec: t.nsec,
        offset,
        zero: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(s: &str) -> String {
        Manifest::decode(s.as_bytes()).unwrap_err()
    }

    #[test]
    fn errors_as_go() {
        assert_eq!(err(""), "EOF");
        assert_eq!(err(" "), "EOF");
        assert_eq!(err("{"), "unexpected EOF");
        assert_eq!(err(r#"{"format":3"#), "unexpected EOF");
        assert_eq!(
            err("x"),
            "invalid character 'x' looking for beginning of value"
        );
        assert_eq!(
            err("{x}"),
            "invalid character 'x' looking for beginning of object key string"
        );
        assert_eq!(err(r#"{"a" 1}"#), "invalid character '1' after object key");
        assert_eq!(
            err(r#"{"a":1 x}"#),
            "invalid character 'x' after object key:value pair"
        );
        assert_eq!(err("[1 x]"), "invalid character 'x' after array element");
        assert_eq!(err("\"\x01\""), "invalid character '\\x01' in string");
        assert_eq!(err(r#""\q""#), "invalid escape sequence `\\q` in string");
        assert_eq!(
            err(r#""\u12g4""#),
            "invalid escape sequence `\\u12g4` in string"
        );
        assert_eq!(err("1.x"), "invalid character 'x' in numeric literal");
        assert_eq!(err("tru"), "unexpected EOF");
        assert_eq!(
            err("trux"),
            "invalid character 'x' in literal true (expecting 'e')"
        );
        assert_eq!(
            err(r#"{"format":3,}"#),
            "invalid character '}' looking for beginning of object key string"
        );
        assert_eq!(
            err("[]"),
            "json: cannot unmarshal array into Go value of type backup.Manifest"
        );
        assert_eq!(
            err(r#"{"format":"3"}"#),
            "json: cannot unmarshal string into Go struct field Manifest.format of type int"
        );
        assert_eq!(
            err(r#"{"format":1.5}"#),
            "json: cannot unmarshal number 1.5 into Go struct field Manifest.format of type int"
        );
        assert_eq!(
            err(r#"{"listen":3}"#),
            "json: cannot unmarshal number into Go struct field Manifest.listen of type string"
        );
        assert_eq!(
            err(r#"{"files":[]}"#),
            "json: cannot unmarshal array into Go struct field Manifest.files of type map[string]string"
        );
        assert_eq!(
            err(r#"{"files":{"a":1}}"#),
            "json: cannot unmarshal number into Go struct field Manifest.files.a of type string"
        );
        assert_eq!(
            err(r#"{"created":3}"#),
            "json: cannot unmarshal number into Go struct field Manifest.created of type time.Time"
        );
        assert_eq!(
            err(r#"{"created":"x"}"#),
            r#"parsing time "x" as "2006-01-02T15:04:05Z07:00": cannot parse "x" as "2006""#
        );
        assert_eq!(err(r#"{"x":1,"format":"a"}"#), r#"json: unknown field "x""#);
        assert_eq!(
            err(r#"{"format":01}"#),
            "invalid character '1' after object key:value pair"
        );
    }

    #[test]
    fn decodes_as_go() {
        let m =
            Manifest::decode(br#"{"FORMAT":3,"Listen":"a","masterKeyID":"k","format":4} trailing"#)
                .unwrap();
        assert_eq!(
            (m.format, m.listen.as_str(), m.master_key_id.as_str()),
            (4, "a", "k")
        );
        let m = Manifest::decode(br#"{"files":{"a":"1"},"files":{"b":"2"}}"#).unwrap();
        assert_eq!(m.files.unwrap().len(), 2);
        let m = Manifest::decode(br#"{"created":"2026-11-25T12:00:00+07:00"}"#).unwrap();
        assert_eq!(m.created.minute_zone(), "2026-11-25 12:00 +0700");
        let m = Manifest::decode(br#"{"created":"2026-11-25T12:00:00.5Z"}"#).unwrap();
        assert_eq!(m.created.minute_zone(), "2026-11-25 12:00 UTC");
        assert_eq!(
            Manifest::default().created.minute_zone(),
            "0001-01-01 00:00 UTC"
        );
    }

    #[test]
    fn writes_as_go() {
        let mut files = BTreeMap::new();
        files.insert("ca.crt".to_string(), "ab".to_string());
        files.insert("agent.json".to_string(), "cd".to_string());
        let m = Manifest {
            format: 3,
            armada_version: "dev".into(),
            created: Created::utc(1_795_000_000),
            schema: 15,
            listen: "10.0.0.5:7443".into(),
            master_key_id: "k<1>".into(),
            ca_fingerprint: "ff".into(),
            files: Some(files),
        };
        assert_eq!(
            m.to_json(),
            "{\n  \"format\": 3,\n  \"armadaVersion\": \"dev\",\n  \"created\": \"2026-11-18T11:06:40Z\",\n  \"schema\": 15,\n  \"listen\": \"10.0.0.5:7443\",\n  \"masterKeyId\": \"k\\u003c1\\u003e\",\n  \"caFingerprint\": \"ff\",\n  \"files\": {\n    \"agent.json\": \"cd\",\n    \"ca.crt\": \"ab\"\n  }\n}"
        );
    }
}

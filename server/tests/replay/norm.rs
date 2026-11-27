//! The transcripts' normalization (encoding, placeholders for random
//! values, and the summaries of certificates and keys), with the
//! recording's extra random fields, so the replay's answers read as the
//! recorded ones.

use std::collections::HashMap;

use armada_pki::encoding::base64_decode;
use armada_pki::{Certificate, ExtKeyUsage, PrivateKey, parse_cert_pem};
use serde_json::{Map, Value};

use super::gojson;

const TIME_KEYS: &[&str] = &[
    "at",
    "addedat",
    "attemptat",
    "createdat",
    "cutoff",
    "drainingsince",
    "expiresat",
    "finishedat",
    "first",
    "last",
    "lastrestartat",
    "lastscheduled",
    "lastseen",
    "movingsince",
    "notafter",
    "readysince",
    "rolloutprogressat",
    "scaledat",
    "since",
    "startedat",
    "updatedat",
    "usedat",
    "verifiedat",
    "waitingsince",
    "certexpiresat",
    "certnotafter",
];
const RANDOM_KEYS: &[&str] = &[
    "serial",
    "sinceserial",
    "secrethash",
    "ciphertext",
    "wrappedkey",
    "lastid",
    "lastsnapshot",
    // The recording's own.
    "token",
    "cahash",
];
const COMPRESSED_KEYS: &[&str] = &["stored", "storedbytes"];
const CERT_KEYS: &[&str] = &["cert", "cacert", "nodecert", "servercert"];
const SECRET_KEYS: &[&str] = &["cakey", "serverkey", "masterkey"];

/// The normalizer's state: names given to values (addresses, aliases,
/// random values in the order first seen), and what certificates and
/// keys are compared with.
#[derive(Clone)]
pub struct Norm {
    aliases: Vec<(String, String)>,
    seen: HashMap<String, HashMap<String, String>>,
    ca: Certificate,
    ca_key_pem: Vec<u8>,
    master_key: Vec<u8>,
}

impl Norm {
    pub fn new(ca: Certificate, ca_key_pem: Vec<u8>, master_key: Vec<u8>) -> Self {
        Norm {
            aliases: Vec::new(),
            seen: HashMap::new(),
            ca,
            ca_key_pem,
            master_key,
        }
    }

    /// Replaces value by name wherever a transcript holds it.
    pub fn alias(&mut self, value: &str, name: &str) {
        if value.is_empty() {
            return;
        }
        self.aliases.push((value.to_string(), name.to_string()));
        self.sort();
    }

    fn sort(&mut self) {
        // A stable sort by length, longest first.
        self.aliases.sort_by_key(|a| std::cmp::Reverse(a.0.len()));
    }

    /// A tree's normalized form.
    pub fn encode(&mut self, tree: &Value) -> Value {
        self.collect(tree, "");
        self.normalize(tree, "")
    }

    /// An error as the transcripts write it.
    pub fn error(code: &str, message: &str) -> Value {
        let mut msg = message.to_string();
        if let Some(i) = msg.find("parse CSR: ") {
            msg = format!("{}parse CSR: <asn1 error>", &msg[..i]);
        }
        serde_json::json!({"code": code, "message": msg})
    }

    pub fn normalize(&mut self, v: &Value, key: &str) -> Value {
        let lk = key.to_lowercase();
        match v {
            Value::Object(m) => {
                let mut out = Map::new();
                for (k, e) in m {
                    let nk = self.replace(k);
                    let ne = self.normalize(e, k);
                    out.insert(nk, ne);
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(|e| self.normalize(e, key)).collect()),
            Value::Number(n) => {
                let x = n.as_f64().unwrap_or_default();
                if TIME_KEYS.contains(&lk.as_str()) && x != 0.0 {
                    return Value::String("<time>".into());
                }
                if COMPRESSED_KEYS.contains(&lk.as_str()) && x != 0.0 {
                    return Value::String("<compressed>".into());
                }
                v.clone()
            }
            Value::String(x) => {
                if x.is_empty() {
                    return v.clone();
                }
                if TIME_KEYS.contains(&lk.as_str()) || rfc3339(x) {
                    if x.starts_with("0001-01-01") {
                        return v.clone();
                    }
                    return Value::String("<time>".into());
                }
                if RANDOM_KEYS.contains(&lk.as_str()) {
                    return Value::String(self.placeholder(&lk, x));
                }
                if COMPRESSED_KEYS.contains(&lk.as_str()) {
                    return Value::String("<compressed>".into());
                }
                if CERT_KEYS.contains(&lk.as_str()) {
                    return Value::String(self.cert_summary(x));
                }
                if SECRET_KEYS.contains(&lk.as_str()) {
                    return Value::String(self.secret_summary(&lk, x));
                }
                if let Some(nested) = nested_json(x) {
                    let n = self.normalize(&nested, key);
                    return Value::String(gojson::marshal(&n));
                }
                Value::String(self.replace(x))
            }
            _ => v.clone(),
        }
    }

    pub fn replace(&self, s: &str) -> String {
        let mut s = s.to_string();
        for (from, to) in &self.aliases {
            if s.contains(from.as_str()) {
                s = s.replace(from.as_str(), to);
            }
        }
        replace_serials(&s)
    }

    fn placeholder(&mut self, cat: &str, v: &str) -> String {
        let m = self.seen.entry(cat.to_string()).or_default();
        if let Some(p) = m.get(v) {
            return p.clone();
        }
        let p = format!("<{cat}>");
        m.insert(v.to_string(), p.clone());
        self.aliases.push((v.to_string(), p.clone()));
        self.sort();
        p
    }

    pub fn collect(&mut self, v: &Value, key: &str) {
        match v {
            Value::Object(m) => {
                for (k, e) in m {
                    self.collect(e, k);
                }
            }
            Value::Array(a) => {
                for e in a {
                    self.collect(e, key);
                }
            }
            Value::String(x) => {
                let lk = key.to_lowercase();
                if RANDOM_KEYS.contains(&lk.as_str()) && !x.is_empty() {
                    self.placeholder(&lk, x);
                } else if let Some(nested) = nested_json(x) {
                    self.collect(&nested, key);
                }
            }
            _ => {}
        }
    }

    fn cert_summary(&self, s: &str) -> String {
        let Ok(cert) = parse_cert_pem(&pem_of(s)) else {
            return "<not a certificate>".into();
        };
        let id = cert
            .identity()
            .map(|i| i.to_string())
            .unwrap_or_else(|_| ":".into());
        let days = (cert.not_after - cert.not_before) / 86400;
        let signed = cert.check_signature_from(&self.ca).is_ok();
        if cert.raw == self.ca.raw {
            return "<the CA>".into();
        }
        let ips: Vec<String> = cert.ip_addresses.iter().map(|i| i.to_string()).collect();
        format!(
            "<cert {id} days={days} ca={signed} ips=[{}] dns=[{}] client={} server={}>",
            ips.join(" "),
            cert.dns_names.join(" "),
            cert.ext_key_usage.contains(&ExtKeyUsage::ClientAuth),
            cert.ext_key_usage.contains(&ExtKeyUsage::ServerAuth),
        )
    }

    fn secret_summary(&self, key: &str, s: &str) -> String {
        let b = pem_of(s);
        match key {
            "masterkey" => format!("<master key {}>", b == self.master_key),
            "cakey" => format!("<CA key {}>", b == self.ca_key_pem),
            _ => {
                if PrivateKey::from_pem(&b).is_ok() {
                    "<key>".into()
                } else {
                    "<not a key>".into()
                }
            }
        }
    }
}

/// A protojson bytes field decoded, or a PEM as it is.
fn pem_of(s: &str) -> Vec<u8> {
    if s.starts_with("-----BEGIN") {
        return s.as_bytes().to_vec();
    }
    base64_decode(s.as_bytes()).unwrap_or_else(|| s.as_bytes().to_vec())
}

/// A JSON object a string holds (meta records), or None.
fn nested_json(s: &str) -> Option<Value> {
    if !s.starts_with('{') {
        return None;
    }
    match serde_json::from_str::<Value>(s) {
        Ok(v @ Value::Object(_)) => Some(v),
        _ => None,
    }
}

/// Whether s matches `^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$`.
fn rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    let d = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    let at = |i: usize, c: u8| b.get(i) == Some(&c);
    if !(d(0) && d(1) && d(2) && d(3) && at(4, b'-') && d(5) && d(6) && at(7, b'-') && d(8) && d(9))
    {
        return false;
    }
    if !(at(10, b'T') && d(11) && d(12) && at(13, b':') && d(14) && d(15) && at(16, b':'))
        || !(d(17) && d(18))
    {
        return false;
    }
    let mut i = 19;
    if at(i, b'.') {
        i += 1;
        let start = i;
        while d(i) {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    if at(i, b'Z') {
        return i + 1 == b.len();
    }
    if at(i, b'+') || at(i, b'-') {
        return d(i + 1) && d(i + 2) && at(i + 3, b':') && d(i + 4) && d(i + 5) && i + 6 == b.len();
    }
    false
}

/// `serial=[0-9a-f]+` replaced by `serial=<serial>`.
fn replace_serials(s: &str) -> String {
    const PAT: &str = "serial=";
    if !s.contains(PAT) {
        return s.to_string();
    }
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find(PAT) {
        let after = &rest[i + PAT.len()..];
        let n = after
            .bytes()
            .take_while(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
            .count();
        out.push_str(&rest[..i + PAT.len()]);
        if n > 0 {
            out.push_str("<serial>");
        }
        rest = &after[n..];
    }
    out.push_str(rest);
    out
}

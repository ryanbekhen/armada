//! Identities: `<kind>:<name>` in a certificate's common name.

use std::fmt;

use crate::Error;

/// A person (ADR 0033).
pub const KIND_USER: &str = "user";
/// A tool (ADR 0033).
pub const KIND_SERVICE: &str = "service";
pub const KIND_NODE: &str = "node";
pub const KIND_SERVER: &str = "server";
/// The embedded etcd members of the control plane: every member shares one
/// identity ([`etcd_member`]), and the Armada API never authorizes it.
pub const KIND_ETCD: &str = "etcd";
/// May only scrape the metrics endpoint (ADR 0017).
pub const KIND_METRICS: &str = "metrics";
/// No longer issued: certificates of earlier releases with this kind are
/// read as a user of the same name ([`Identity::principal`]).
pub const KIND_ADMIN: &str = "admin";
/// No longer issued: read as a service of the same name.
pub const KIND_AUTOMATION: &str = "automation";

const KINDS: [&str; 8] = [
    KIND_USER,
    KIND_SERVICE,
    KIND_ADMIN,
    KIND_AUTOMATION,
    KIND_NODE,
    KIND_SERVER,
    KIND_ETCD,
    KIND_METRICS,
];

/// The authenticated principal of a TLS peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Identity {
    pub kind: String,
    pub name: String,
}

impl Identity {
    pub fn new(kind: &str, name: &str) -> Self {
        Identity {
            kind: kind.to_string(),
            name: name.to_string(),
        }
    }

    /// The user or service an identity is (ADR 0033), reading the kinds of
    /// earlier releases, admin and automation, as the same principal;
    /// `None` for every other kind.
    pub fn principal(&self) -> Option<Identity> {
        match self.kind.as_str() {
            KIND_USER | KIND_ADMIN => Some(Identity::new(KIND_USER, &self.name)),
            KIND_SERVICE | KIND_AUTOMATION => Some(Identity::new(KIND_SERVICE, &self.name)),
            _ => None,
        }
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind, self.name)
    }
}

/// The identity of every etcd member certificate, `etcd:member`.
pub fn etcd_member() -> Identity {
    Identity::new(KIND_ETCD, "member")
}

/// Whether `name` may be an identity's name: `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`.
pub fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b[0].is_ascii_alphanumeric()
        && b[1..]
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// Parses a `<kind>:<name>` common name.
pub fn parse_identity(cn: &str) -> Result<Identity, Error> {
    let Some((kind, name)) = cn.split_once(':') else {
        return Err(Error::new(format!(
            "common name {} is not an armada identity",
            go_quote(cn)
        )));
    };
    if !KINDS.contains(&kind) {
        return Err(Error::new(format!(
            "unknown identity kind {}",
            go_quote(kind)
        )));
    }
    if !valid_name(name) {
        return Err(Error::new(format!(
            "invalid identity name {}",
            go_quote(name)
        )));
    }
    Ok(Identity::new(kind, name))
}

/// Go's `%q` of a string (`strconv.Quote`): Go escapes, `\u`/`\U` for
/// characters that do not print.
pub fn go_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            c if go_printable(c) => out.push(c),
            c if (c as u32) < 0x80 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push('"');
    out
}

/// An approximation of Go's `strconv.IsPrint` that agrees on ASCII,
/// controls, spaces, and the common format characters.
fn go_printable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    if c.is_control() || c.is_whitespace() {
        return false;
    }
    !matches!(c as u32,
        0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x180e | 0x200b..=0x200f | 0x202a..=0x202e
        | 0x2060..=0x2064 | 0x2066..=0x206f | 0xd800..=0xdfff | 0xfeff | 0xfff9..=0xfffb
        | 0xe000..=0xf8ff | 0xf0000..=0x10ffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        assert_eq!(
            parse_identity("node:web-1").unwrap(),
            Identity::new("node", "web-1")
        );
        assert_eq!(parse_identity("etcd:member").unwrap(), etcd_member());
        for (cn, text) in [
            ("web-1", "common name \"web-1\" is not an armada identity"),
            ("root:x", "unknown identity kind \"root\""),
            ("node:", "invalid identity name \"\""),
            ("node:../x", "invalid identity name \"../x\""),
            ("node:-x", "invalid identity name \"-x\""),
            ("node:a\nb", "invalid identity name \"a\\nb\""),
            ("node:a:b", "invalid identity name \"a:b\""),
        ] {
            assert_eq!(parse_identity(cn).unwrap_err().to_string(), text, "{cn}");
        }
        assert!(parse_identity(&format!("node:{}", "a".repeat(63))).is_ok());
        assert!(parse_identity(&format!("node:{}", "a".repeat(64))).is_err());
    }

    #[test]
    fn principals() {
        let p = |k: &str| Identity::new(k, "n").principal();
        assert_eq!(p(KIND_ADMIN), Some(Identity::new(KIND_USER, "n")));
        assert_eq!(p(KIND_USER), Some(Identity::new(KIND_USER, "n")));
        assert_eq!(p(KIND_AUTOMATION), Some(Identity::new(KIND_SERVICE, "n")));
        assert_eq!(p(KIND_SERVICE), Some(Identity::new(KIND_SERVICE, "n")));
        for k in [KIND_NODE, KIND_SERVER, KIND_ETCD, KIND_METRICS] {
            assert_eq!(p(k), None);
        }
    }

    #[test]
    fn quoting() {
        assert_eq!(go_quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(
            go_quote("\x01\u{7f}é\u{a0}\u{2028}"),
            "\"\\x01\\x7fé\\u00a0\\u2028\""
        );
    }
}

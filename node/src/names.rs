//! The name rules of internal/spec the node applies (the same port as
//! dns/src/names.rs; Go's parity tests check both).

/// The space of apps whose ID carries no space (spec.DefaultSpace).
pub const DEFAULT_SPACE: &str = "default";
/// The suffix of internal names (spec.InternalSuffix).
pub const INTERNAL_SUFFIX: &str = ".internal";
/// The longest space name (spec.maxSpaceLen).
const MAX_SPACE_LEN: usize = 30;

/// spec.ValidName: at most 63 characters of `^[a-z]([a-z0-9]|-[a-z0-9])*$`.
pub fn valid_name(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 63 || !b[0].is_ascii_lowercase() {
        return false;
    }
    let mut i = 1;
    while i < b.len() {
        match b[i] {
            b'a'..=b'z' | b'0'..=b'9' => i += 1,
            b'-' if i + 1 < b.len() && matches!(b[i + 1], b'a'..=b'z' | b'0'..=b'9') => i += 2,
            _ => return false,
        }
    }
    true
}

fn valid_space(s: &str) -> bool {
    s.len() <= MAX_SPACE_LEN && valid_name(s)
}

/// spec.SplitAppID: the space of an app ID (`name` or `name.space`).
pub fn space_of(id: &str) -> Option<&str> {
    let (name, space) = match id.split_once('.') {
        None => (id, DEFAULT_SPACE),
        Some((name, space)) => {
            if space == DEFAULT_SPACE || !valid_space(space) {
                return None;
            }
            (name, space)
        }
    };
    valid_name(name).then_some(space)
}

/// spec.ValidAppID.
pub fn valid_app_id(id: &str) -> bool {
    space_of(id).is_some()
}

/// spec.ValidateName's error, or None.
pub fn validate_name(s: &str) -> Option<String> {
    if s.is_empty() {
        Some("name: is required".into())
    } else if s.len() > 63 {
        Some("name: must be at most 63 characters".into())
    } else if !valid_name(s) {
        Some(
            "name: must be lowercase letters, digits, and single hyphens, starting with a letter and not ending with a hyphen"
                .into(),
        )
    } else {
        None
    }
}

/// The longest label value (spec.maxLabelLen).
const MAX_LABEL_LEN: usize = 63;

/// spec.CheckLabelValue's error, or None: `^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`.
pub fn check_label_value(v: &str) -> Option<String> {
    let b = v.as_bytes();
    let end = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let ok = !b.is_empty()
        && end(b[0])
        && end(b[b.len() - 1])
        && b.iter().all(|&c| end(c) || matches!(c, b'.' | b'_' | b'-'));
    if v.is_empty() {
        Some("label value is empty".into())
    } else if v.len() > MAX_LABEL_LEN {
        Some(format!(
            "label value {} is longer than {MAX_LABEL_LEN} characters",
            crate::net::addr::quote(v)
        ))
    } else if !ok {
        Some(format!(
            "label value {} must be lowercase letters, digits, '.', '-', or '_', starting and ending with a letter or digit",
            crate::net::addr::quote(v)
        ))
    } else {
        None
    }
}

/// spec.ReservedTCPPorts.
const RESERVED_TCP_PORTS: [u64; 12] = [
    22, 53, 80, 443, 2379, 2380, 4789, 7443, 7444, 7480, 8404, 51820,
];

/// Whether spec.CheckTCPPort accepts port.
pub fn tcp_port_ok(port: u64) -> bool {
    (1..=65535).contains(&port) && !RESERVED_TCP_PORTS.contains(&port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spaces() {
        assert_eq!(space_of("web"), Some("default"));
        assert_eq!(space_of("web.shop"), Some("shop"));
        assert_eq!(space_of("web.default"), None);
        assert_eq!(space_of("Web"), None);
        assert_eq!(space_of("web.a.b"), None);
    }
}

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

//! The name rules of internal/spec the resolver applies: which names are
//! app IDs, which are revision labels of one, and which space each belongs
//! to. They must agree with spec.ValidName, spec.SplitAppID, and
//! spec.ValidHostName (compared in the Go parity test).

/// The space of apps whose ID carries no space.
const DEFAULT_SPACE: &str = "default";
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

/// spec.ValidSpace.
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

/// spec.ValidHostName: an app ID, or `<label>--<app ID>` whose first DNS
/// label stays within 63 characters.
pub fn valid_host_name(s: &str) -> bool {
    if valid_app_id(s) {
        return true;
    }
    let Some((label, app)) = s.split_once("--") else {
        return false;
    };
    let first = app.split_once('.').map_or(app, |(n, _)| n);
    valid_name(label) && valid_app_id(app) && label.len() + 2 + first.len() <= 63
}

/// Whether a container of app `caller` may resolve `host`: only names of
/// its own space (ADR 0026).
pub fn same_space(caller: &str, host: &str) -> bool {
    let host = host.split_once("--").map_or(host, |(_, id)| id);
    match (space_of(caller), space_of(host)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in ["web", "a", "shop-api", "a1-b2", &"a".repeat(63)] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in [
            "",
            "1a",
            "-a",
            "a-",
            "a--b",
            "A",
            "a_b",
            "a.b",
            &"a".repeat(64),
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn host_names() {
        for ok in ["web", "api.staging", "canary--web", "canary--api.staging"] {
            assert!(valid_host_name(ok), "{ok}");
        }
        for bad in [
            "",
            "api.default",
            "a.b.c",
            "bad_name",
            "a--b--c",
            "--web",
            "web--",
            "x.api.staging",
            &format!("{}--{}", "a".repeat(30), "b".repeat(32)),
            &format!("web.{}", "s".repeat(31)),
        ] {
            assert!(!valid_host_name(bad), "{bad}");
        }
        assert!(valid_host_name(&format!(
            "{}--{}",
            "a".repeat(30),
            "b".repeat(31)
        )));
    }

    #[test]
    fn spaces() {
        assert_eq!(space_of("web"), Some("default"));
        assert_eq!(space_of("web.shop"), Some("shop"));
        assert_eq!(space_of("web.default"), None);
        assert!(same_space("web.shop", "canary--api.shop"));
        assert!(same_space("api", "web"));
        assert!(!same_space("api", "web.shop"));
        assert!(!same_space("web.shop", "db.blog"));
        assert!(!same_space("bad_", "web"));
    }
}

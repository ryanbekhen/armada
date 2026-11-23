//! Go's path/filepath on Unix: Clean, Join, Dir, and Base, whose results
//! Armada's checks and names depend on.

/// filepath.Clean.
pub fn clean(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let rooted = p.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|l| *l != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            _ => parts.push(part),
        }
    }
    let body = parts.join("/");
    match (rooted, body.is_empty()) {
        (true, _) => format!("/{body}"),
        (false, true) => ".".into(),
        (false, false) => body,
    }
}

/// filepath.Join of two elements.
pub fn join(a: &str, b: &str) -> String {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => String::new(),
        (true, false) => clean(b),
        (false, true) => clean(a),
        (false, false) => clean(&format!("{a}/{b}")),
    }
}

/// filepath.Dir.
pub fn dir(p: &str) -> String {
    let i = p.rfind('/').map_or(0, |i| i + 1);
    clean(&p[..i])
}

/// filepath.Base.
pub fn base(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        return "/".into();
    }
    match t.rfind('/') {
        Some(i) => t[i + 1..].into(),
        None => t.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_go() {
        for (i, want) in [
            ("", "."),
            ("/", "/"),
            ("a//b/./c/..", "a/b"),
            ("/../a", "/a"),
            ("../../a", "../../a"),
            ("a/../..", ".."),
            ("/a/b/", "/a/b"),
        ] {
            assert_eq!(clean(i), want, "{i}");
        }
        assert_eq!(dir("/a/b/c"), "/a/b");
        assert_eq!(dir("c"), ".");
        assert_eq!(dir("/c"), "/");
        assert_eq!(base("/a/b/"), "b");
        assert_eq!(base("///"), "/");
        assert_eq!(join("/usr//bin/", "x"), "/usr/bin/x");
        assert_eq!(join("", "x"), "x");
    }
}

//! Versions of the pinned programs and the ranges advisories give, for
//! `armada-pack outdated`: release numbers of any length ("1.31",
//! "v1.5.3", "3.7.4"), a leading "v" tolerated, pre-releases ordered
//! before their release as semver orders them, build metadata ignored.

use std::cmp::Ordering;

/// A parsed version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// The release numbers; missing ones compare as 0 ("1.31" = "1.31.0").
    pub nums: Vec<u64>,
    /// The pre-release identifiers after '-', empty for a release.
    pub pre: Vec<String>,
}

impl Version {
    /// parse: None when s is not a version (a tag such as "latest").
    pub fn parse(s: &str) -> Option<Version> {
        let s = s.trim();
        let s = s
            .strip_prefix('v')
            .or_else(|| s.strip_prefix('V'))
            .unwrap_or(s);
        let s = s.split_once('+').map_or(s, |(v, _)| v);
        let (core, pre) = match s.split_once('-') {
            Some((_, "")) => return None,
            Some((c, p)) => (c, p),
            None => (s, ""),
        };
        if core.is_empty() {
            return None;
        }
        let nums = core
            .split('.')
            .map(|n| {
                (!n.is_empty() && n.len() <= 19 && n.bytes().all(|c| c.is_ascii_digit()))
                    .then(|| n.parse::<u64>().ok())
                    .flatten()
            })
            .collect::<Option<Vec<u64>>>()?;
        if nums.len() > 4 {
            return None;
        }
        let pre: Vec<String> = if pre.is_empty() {
            Vec::new()
        } else {
            pre.split('.').map(str::to_string).collect()
        };
        if pre
            .iter()
            .any(|p| p.is_empty() || !p.bytes().all(|c| c.is_ascii_alphanumeric()))
        {
            return None;
        }
        Some(Version { nums, pre })
    }

    /// A release, not a pre-release.
    pub fn is_stable(&self) -> bool {
        self.pre.is_empty()
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let n = self.nums.len().max(other.nums.len());
        for i in 0..n {
            let a = self.nums.get(i).copied().unwrap_or(0);
            let b = other.nums.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                Ordering::Equal => {}
                o => return o,
            }
        }
        match (self.pre.is_empty(), other.pre.is_empty()) {
            (true, true) => return Ordering::Equal,
            (true, false) => return Ordering::Greater,
            (false, true) => return Ordering::Less,
            _ => {}
        }
        for (a, b) in self.pre.iter().zip(&other.pre) {
            let o = match (a.parse::<u64>(), b.parse::<u64>()) {
                (Ok(x), Ok(y)) => x.cmp(&y),
                (Ok(_), Err(_)) => Ordering::Less,
                (Err(_), Ok(_)) => Ordering::Greater,
                (Err(_), Err(_)) => a.cmp(b),
            };
            if o != Ordering::Equal {
                return o;
            }
        }
        self.pre.len().cmp(&other.pre.len())
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// One comparison of a range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
}

impl Op {
    fn holds(self, o: Ordering) -> bool {
        match self {
            Op::Lt => o == Ordering::Less,
            Op::Le => o != Ordering::Greater,
            Op::Gt => o == Ordering::Greater,
            Op::Ge => o != Ordering::Less,
            Op::Eq => o == Ordering::Equal,
        }
    }

    /// The comparison seen from the other side ("1.0 <= V" is "V >= 1.0").
    fn flip(self) -> Op {
        match self {
            Op::Lt => Op::Gt,
            Op::Le => Op::Ge,
            Op::Gt => Op::Lt,
            Op::Ge => Op::Le,
            Op::Eq => Op::Eq,
        }
    }
}

/// in_range: whether v lies in a GitHub advisory's vulnerable_version_range,
/// whose comparisons all hold together. The forms repositories write are
/// read: ">= 1.22, < 1.31", ">=1.19, <= 1.26", ">= 1.6.0 < 1.9.0",
/// "< v3.4.26 and < v3.5.9", "0.12.2 <= VERSION <= 1.29.1", "= 1.2.3", a
/// bare version (that one only). None when the range cannot be read, or
/// names a part of the project before the version ("wal <= 3.4.9").
///
/// Several upper bounds ("<=1.2.7, <=1.3.2, <=1.4.0-rc.2") are one per
/// release branch, not all at once: v is checked against the bound of
/// its own branch (the same first two numbers), and when none is its
/// own, against the highest bound. Lower bounds always hold together.
pub fn in_range(v: &Version, range: &str) -> Option<bool> {
    let cons = constraints(range)?;
    let (upper, rest): (Vec<_>, Vec<_>) = cons
        .iter()
        .partition(|(op, _)| matches!(op, Op::Lt | Op::Le));
    if !rest.iter().all(|(op, x)| op.holds(v.cmp(x))) {
        return Some(false);
    }
    if upper.len() < 2 {
        return Some(upper.iter().all(|(op, x)| op.holds(v.cmp(x))));
    }
    let branch = |x: &Version| (num(x, 0), num(x, 1));
    let own: Vec<_> = upper
        .iter()
        .filter(|(_, x)| branch(x) == branch(v))
        .collect();
    if !own.is_empty() {
        return Some(own.iter().all(|(op, x)| op.holds(v.cmp(x))));
    }
    let (op, x) = upper
        .iter()
        .max_by(|a, b| a.1.cmp(&b.1))
        .expect("two bounds");
    Some(op.holds(v.cmp(x)))
}

fn num(v: &Version, i: usize) -> u64 {
    v.nums.get(i).copied().unwrap_or(0)
}

fn constraints(range: &str) -> Option<Vec<(Op, Version)>> {
    let range = range.trim();
    if range.is_empty() {
        return None;
    }
    if let Some((left, right)) = range.split_once("VERSION") {
        let mut out = Vec::new();
        let left = tokens(left)?;
        match left.as_slice() {
            [] => {}
            [Tok::Ver(x), Tok::Op(op)] => out.push((op.flip(), x.clone())),
            _ => return None,
        }
        out.extend(pairs(tokens(right)?)?);
        return (!out.is_empty()).then_some(out);
    }
    let out = pairs(tokens(range)?)?;
    (!out.is_empty()).then_some(out)
}

#[derive(Debug, Clone)]
enum Tok {
    Op(Op),
    Ver(Version),
}

fn tokens(s: &str) -> Option<Vec<Tok>> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() || c == b',' {
            i += 1;
            continue;
        }
        if matches!(c, b'<' | b'>' | b'=') {
            let two = b.get(i + 1) == Some(&b'=');
            let op = match (c, two) {
                (b'<', true) => Op::Le,
                (b'<', false) => Op::Lt,
                (b'>', true) => Op::Ge,
                (b'>', false) => Op::Gt,
                _ => Op::Eq,
            };
            out.push(Tok::Op(op));
            i += if two { 2 } else { 1 };
            continue;
        }
        let start = i;
        while i < b.len()
            && !b[i].is_ascii_whitespace()
            && !matches!(b[i], b',' | b'<' | b'>' | b'=')
        {
            i += 1;
        }
        let word = &s[start..i];
        if word.eq_ignore_ascii_case("and") {
            continue;
        }
        out.push(Tok::Ver(Version::parse(word)?));
    }
    Some(out)
}

fn pairs(toks: Vec<Tok>) -> Option<Vec<(Op, Version)>> {
    let mut out = Vec::new();
    let mut it = toks.into_iter().peekable();
    while let Some(t) = it.next() {
        match t {
            Tok::Op(op) => match it.next()? {
                Tok::Ver(v) => out.push((op, v)),
                Tok::Op(_) => return None,
            },
            // A bare version is the only one affected.
            Tok::Ver(v) => out.push((Op::Eq, v)),
        }
    }
    Some(out)
}

/// An OSV range event (`introduced`, `fixed`, `last_affected`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Introduced(String),
    Fixed(String),
    LastAffected(String),
}

/// osv_fixed: for a version OSV said is affected, the version an
/// ECOSYSTEM or SEMVER range's events name as its fix: the first `fixed`
/// after the last `introduced` at or below v. None when the range says
/// v is not affected or names no fix.
pub fn osv_fixed(v: &Version, events: &[Event]) -> Option<String> {
    let mut affected = false;
    let mut fixed = None;
    for e in events {
        match e {
            Event::Introduced(x) => {
                let from = if x == "0" { None } else { Version::parse(x) };
                if from.as_ref().is_none_or(|f| f <= v) {
                    affected = true;
                    fixed = None;
                }
            }
            Event::Fixed(x) => {
                if affected {
                    match Version::parse(x) {
                        Some(f) if *v < f => {
                            fixed = Some(x.clone());
                            affected = false;
                        }
                        _ => affected = false,
                    }
                }
            }
            Event::LastAffected(x) => {
                if affected && Version::parse(x).is_some_and(|l| *v > l) {
                    affected = false;
                }
            }
        }
    }
    fixed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap_or_else(|| panic!("{s}"))
    }

    #[test]
    fn compares_versions() {
        assert!(v("1.5.3") > v("1.5.2"));
        assert!(v("v1.10.0") > v("1.9.1"));
        assert_eq!(v("1.31").cmp(&v("v1.31.0")), Ordering::Equal);
        assert!(v("1.31") > v("1.30.1"));
        assert!(v("1.6.0-rc.1") < v("1.6.0"));
        assert!(v("1.6.0-rc.2") > v("1.6.0-rc.1"));
        assert!(v("1.6.0-rc.10") > v("1.6.0-rc.9"));
        assert!(v("1.0.0-alpha") < v("1.0.0-alpha.1"));
        assert!(v("1.0.0-1") < v("1.0.0-alpha"));
        assert_eq!(v("3.7.4+build.1").cmp(&v("3.7.4")), Ordering::Equal);
        assert!(!v("1.6.0-rc.1").is_stable());
        assert!(v("0.19.0").is_stable());
        for bad in [
            "",
            "v",
            "latest",
            "1..2",
            "1.2.x",
            "1.2.3-",
            "1.2.3-a..b",
            "1.2.3.4.5",
        ] {
            assert!(Version::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn matches_advisory_ranges() {
        let cases = [
            (">= 1.22, < 1.31", "1.30.1", Some(true)),
            (">= 1.22, < 1.31", "1.31", Some(false)),
            (">= 1.22, < 1.31", "1.21", Some(false)),
            (">=1.19, <= 1.26", "1.26", Some(true)),
            (">= 1.6.0 < 1.9.0", "1.9.1", Some(false)),
            (">= 1.6.0 < 1.9.0", "1.8.0", Some(true)),
            ("< v3.4.26 and < v3.5.9", "3.7.4", Some(false)),
            ("< v3.4.26 and < v3.5.9", "3.4.1", Some(true)),
            ("0.12.2 <= VERSION <= 1.29.1", "1.29.1", Some(true)),
            ("0.12.2 <= VERSION <= 1.29.1", "1.31", Some(false)),
            ("<= 1.29.1", "1.31", Some(false)),
            ("<=3.7.0", "3.7.4", Some(false)),
            ("<=3.6.13", "3.6.13", Some(true)),
            ("= 1.2.3", "1.2.3", Some(true)),
            ("1.2.3", "1.2.4", Some(false)),
            (">= 1.5.0-rc.1, < 1.5.3", "1.5.2", Some(true)),
            (">= 1.5.0-rc.1, < 1.5.3", "1.5.3", Some(false)),
            (">= 1.6.0-rc.1, < 1.6.0-rc.2", "1.5.2", Some(false)),
            ("<=1.2.7, <=1.3.2, <=1.4.0-rc.2", "1.3.1", Some(true)),
            ("<=1.2.7, <=1.3.2, <=1.4.0-rc.2", "1.2.8", Some(false)),
            ("<=1.2.7, <=1.3.2, <=1.4.0-rc.2", "1.4.0", Some(false)),
            ("<=1.2.7, <=1.3.2, <=1.4.0-rc.2", "1.5.2", Some(false)),
            ("<=1.2.7, <=1.3.2, <=1.4.0-rc.2", "1.1.0", Some(true)),
            ("<=1.3.5,<=1.4.2,<=1.5.0-rc.2", "1.4.0", Some(true)),
            (">=v1.0.0-rc3, <=1.2.7, <=1.3.2", "0.9.0", Some(false)),
            ("wal <= 3.4.9", "3.7.4", None),
            ("", "1.0", None),
            ("<", "1.0", None),
            ("< <= 1.0", "1.0", None),
        ];
        for (range, ver, want) in cases {
            assert_eq!(in_range(&v(ver), range), want, "{ver} in {range:?}");
        }
    }

    #[test]
    fn finds_osv_fixes() {
        use Event::*;
        let ev = |l: &[(&str, &str)]| -> Vec<Event> {
            l.iter()
                .map(|(k, x)| match *k {
                    "i" => Introduced(x.to_string()),
                    "f" => Fixed(x.to_string()),
                    _ => LastAffected(x.to_string()),
                })
                .collect()
        };
        let stdlib = ev(&[
            ("i", "0"),
            ("f", "1.25.9"),
            ("i", "1.26.0-0"),
            ("f", "1.26.12"),
        ]);
        assert_eq!(osv_fixed(&v("1.26.11"), &stdlib), Some("1.26.12".into()));
        assert_eq!(osv_fixed(&v("1.25.1"), &stdlib), Some("1.25.9".into()));
        assert_eq!(osv_fixed(&v("1.26.12"), &stdlib), None);
        let last = ev(&[("i", "1.0.0"), ("l", "1.2.0")]);
        assert_eq!(osv_fixed(&v("1.1.0"), &last), None);
        let open = ev(&[("i", "0")]);
        assert_eq!(osv_fixed(&v("9.9.9"), &open), None);
    }
}

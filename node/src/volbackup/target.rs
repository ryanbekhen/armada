//! volbackup.ParseTarget: where a volume's backups go, read from the URL
//! in the app's secret. Errors never repeat the URL, which holds the
//! bucket's credentials, and nothing here prints the keys.

use crate::queue::url;
use std::net::{IpAddr, Ipv6Addr};

/// volbackup.Target.
#[derive(Clone)]
pub struct Target {
    /// host[:port], an IPv6 address in brackets.
    pub endpoint: String,
    pub secure: bool,
    pub bucket: String,
    /// "" or ends with "/".
    pub prefix: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
}

impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.bucket, self.prefix)
    }
}

/// errTarget.
pub fn err_target(msg: &str) -> String {
    format!("backup URL: {msg}")
}

/// netip.ParseAddr: an address, an IPv6 zone left out.
pub fn parse_addr(s: &[u8]) -> Option<IpAddr> {
    let s = std::str::from_utf8(s).ok()?;
    if let Some((a, zone)) = s.split_once('%') {
        // A zone only follows an IPv6 address, and is never empty.
        if zone.is_empty() || !a.contains(':') {
            return None;
        }
        return a.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    s.parse::<IpAddr>().ok()
}

/// Addr.Unmap.
pub fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        v4 => v4,
    }
}

/// nodeOnly: loopback, link-local (cloud metadata), unspecified, and
/// multicast addresses reach the node or its link, never a bucket.
pub fn node_only(ip: IpAddr) -> bool {
    match unmap(ip) {
        IpAddr::V4(v) => {
            v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_multicast()
        }
        IpAddr::V6(v) => {
            v.is_loopback()
                || (v.segments()[0] & 0xffc0) == 0xfe80
                || v.is_unspecified()
                || v.is_multicast()
        }
    }
}

/// Addr.IsPrivate.
pub fn is_private(ip: IpAddr) -> bool {
    match unmap(ip) {
        IpAddr::V4(v) => v.is_private(),
        IpAddr::V6(v) => (v.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$
fn bucket_ok(s: &[u8]) -> bool {
    let n = s.len();
    let edge = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    (3..=63).contains(&n)
        && edge(&s[0])
        && edge(&s[n - 1])
        && s.iter().all(|c| edge(c) || *c == b'.' || *c == b'-')
}

/// ^[A-Za-z0-9._-]+$
fn prefix_ok(s: &[u8]) -> bool {
    !s.is_empty()
        && s.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// ^[a-z0-9-]{1,32}$
fn region_ok(s: &[u8]) -> bool {
    (1..=32).contains(&s.len())
        && s.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// strings.ToValidUTF8(s, "?"): each run of invalid bytes becomes one "?".
fn to_valid_utf8(b: &[u8]) -> String {
    let mut out = String::new();
    let mut in_run = false;
    for chunk in b.utf8_chunks() {
        if !chunk.valid().is_empty() {
            out.push_str(chunk.valid());
            in_run = false;
        }
        if !chunk.invalid().is_empty() {
            if !in_run {
                out.push('?');
            }
            in_run = true;
        }
    }
    out
}

/// ParseTarget. With several unknown parameters, the first in byte order
/// is named (Go's code sorts them the same way).
pub fn parse(raw: &str) -> Result<Target, String> {
    let raw = std::str::from_utf8(crate::gostr::trim_space(raw.as_bytes())).unwrap_or(raw);
    if raw.len() > 2048 {
        return Err(err_target("too long"));
    }
    let u = url::parse(raw).map_err(|()| err_target("not a URL"))?;
    let secure = match u.scheme.as_str() {
        "https" => true,
        "http" => false,
        _ => return Err(err_target("must start with https://")),
    };
    let fragment = raw.split_once('#').map_or("", |(_, f)| f);
    if u.host.is_empty() || !u.opaque.is_empty() || !fragment.is_empty() {
        return Err(err_target("must be https://KEY:SECRET@host/bucket"));
    }
    let host = u.hostname().to_vec();
    let addr = parse_addr(&host);
    if addr.is_some_and(node_only) {
        return Err(err_target(
            "a loopback, link-local, or multicast address cannot hold a bucket",
        ));
    }
    if !secure && !addr.is_some_and(is_private) {
        return Err(err_target(
            "http:// is only allowed for a private IP address; use https://",
        ));
    }
    let host_s = String::from_utf8_lossy(&host).into_owned();
    let port = String::from_utf8_lossy(u.port()).into_owned();
    let endpoint = match (host_s.contains(':'), port.is_empty()) {
        (true, true) => format!("[{host_s}]"),
        (true, false) => format!("[{host_s}]:{port}"),
        (false, true) => host_s,
        (false, false) => format!("{host_s}:{port}"),
    };
    let creds = || err_target("needs the access key and secret key as KEY:SECRET@");
    let Some((user, pass)) = &u.user else {
        return Err(creds());
    };
    let pass = pass.clone().unwrap_or_default();
    if user.is_empty() || pass.is_empty() {
        return Err(creds());
    }
    let path = &u.path[..];
    let mut start = 0;
    let mut end = path.len();
    while start < end && path[start] == b'/' {
        start += 1;
    }
    while end > start && path[end - 1] == b'/' {
        end -= 1;
    }
    let segs: Vec<&[u8]> = path[start..end].split(|c| *c == b'/').collect();
    if segs[0].is_empty() {
        return Err(err_target("needs a bucket: https://KEY:SECRET@host/bucket"));
    }
    if !bucket_ok(segs[0]) || segs[0].windows(2).any(|w| w == b"..") {
        return Err(err_target("invalid bucket name"));
    }
    let mut prefix = String::new();
    for s in &segs[1..] {
        if !prefix_ok(s) || *s == b"." || *s == b".." {
            return Err(err_target(
                "the prefix may only hold letters, digits, '.', '_', and '-' between slashes",
            ));
        }
        prefix.push_str(std::str::from_utf8(s).unwrap_or_default());
        prefix.push('/');
    }
    if prefix.len() > 256 {
        return Err(err_target("prefix too long"));
    }
    let q = u.query();
    // The first unknown parameter in byte order, whatever the URL's order.
    if let Some((k, _)) = q
        .iter()
        .filter(|(k, _)| k != b"region")
        .min_by(|a, b| a.0.cmp(&b.0))
    {
        let cut = &k[..k.len().min(32)];
        return Err(err_target(&format!(
            "unknown parameter {}; only region is known",
            to_valid_utf8(cut)
        )));
    }
    let mut region = String::new();
    if let Some((_, r)) = q.iter().find(|(k, _)| k == b"region")
        && !r.is_empty()
    {
        if !region_ok(r) {
            return Err(err_target("invalid region"));
        }
        region = String::from_utf8_lossy(r).into_owned();
    }
    Ok(Target {
        endpoint,
        secure,
        bucket: String::from_utf8_lossy(segs[0]).into_owned(),
        prefix,
        region,
        access_key: String::from_utf8_lossy(user).into_owned(),
        secret_key: String::from_utf8_lossy(&pass).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_refuses_as_go() {
        let t = parse(" https://AK:se%2Fc@s3.example.com:9000/bk1/a/b?region=eu-1 ").unwrap();
        assert_eq!(
            (
                t.endpoint.as_str(),
                t.secure,
                t.bucket.as_str(),
                t.prefix.as_str()
            ),
            ("s3.example.com:9000", true, "bk1", "a/b/")
        );
        assert_eq!(
            (
                t.region.as_str(),
                t.access_key.as_str(),
                t.secret_key.as_str()
            ),
            ("eu-1", "AK", "se/c")
        );
        assert_eq!(
            parse("http://k:s@[fd00::5]/bk1").unwrap().endpoint,
            "[fd00::5]"
        );
        for (u, e) in [
            ("ftp://k:s@h/bk1", "must start with https://"),
            (
                "http://k:s@s3.example.com/bk1",
                "http:// is only allowed for a private IP address; use https://",
            ),
            (
                "https://k:s@127.0.0.1/bk1",
                "a loopback, link-local, or multicast address cannot hold a bucket",
            ),
            (
                "https://k:s@[::ffff:127.0.0.1]/bk1",
                "a loopback, link-local, or multicast address cannot hold a bucket",
            ),
            (
                "https://k:s@[fe80::1%25eth0]/bk1",
                "a loopback, link-local, or multicast address cannot hold a bucket",
            ),
            (
                "https://h/bk1",
                "needs the access key and secret key as KEY:SECRET@",
            ),
            (
                "https://k:@h/bk1",
                "needs the access key and secret key as KEY:SECRET@",
            ),
            (
                "https://k:s@h/",
                "needs a bucket: https://KEY:SECRET@host/bucket",
            ),
            ("https://k:s@h/Bk", "invalid bucket name"),
            ("https://k:s@h/b..k", "invalid bucket name"),
            (
                "https://k:s@h/bk1//x",
                "the prefix may only hold letters, digits, '.', '_', and '-' between slashes",
            ),
            (
                "https://k:s@h/bk1?x=1",
                "unknown parameter x; only region is known",
            ),
            ("https://k:s@h/bk1?region=EU", "invalid region"),
            (
                "https://k:s@h/bk1?zz=1&region=eu&b=2&a=3",
                "unknown parameter a; only region is known",
            ),
            (
                "https://k:s@h/bk1#f",
                "must be https://KEY:SECRET@host/bucket",
            ),
            ("https:x", "must be https://KEY:SECRET@host/bucket"),
            ("https://k:s@h:x/bk1", "not a URL"),
        ] {
            assert_eq!(parse(u).unwrap_err(), err_target(e), "{u}");
        }
        assert_eq!(to_valid_utf8(b"a\xff\xfeb\xff"), "a?b?");
    }
}

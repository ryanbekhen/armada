//! Go's net/url.Parse as the queue rules use it: which URLs it accepts,
//! and the scheme, user, host, path, and query it reads from them.
//! Strings are bytes as in Go: escapes may make them invalid UTF-8.

use crate::net::addr::Addr;

/// The parts of a url.URL the readings use.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Url {
    pub scheme: String,
    pub opaque: Vec<u8>,
    /// The user name, and the password when the user info had a colon.
    pub user: Option<(Vec<u8>, Option<Vec<u8>>)>,
    /// url.URL.Host, unescaped.
    pub host: Vec<u8>,
    pub path: Vec<u8>,
    pub raw_query: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Path,
    Host,
    Zone,
    UserPassword,
    QueryComponent,
    Fragment,
}

/// shouldEscape for the host and zone modes, the only ones unescape asks.
fn host_should_escape(c: u8) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    !matches!(
        c,
        b'!' | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
            | b':'
            | b'['
            | b']'
            | b'<'
            | b'>'
            | b'"'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
    )
}

fn unhex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => c - b'A' + 10,
    }
}

/// url's unescape: an error for a malformed escape or a byte the host
/// cannot hold.
fn unescape(s: &[u8], mode: Mode) -> Result<Vec<u8>, ()> {
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                if i + 2 >= s.len()
                    || !s[i + 1].is_ascii_hexdigit()
                    || !s[i + 2].is_ascii_hexdigit()
                {
                    return Err(());
                }
                let is25 = &s[i..i + 3] == b"%25";
                if mode == Mode::Host && unhex(s[i + 1]) < 8 && !is25 {
                    return Err(());
                }
                if mode == Mode::Zone {
                    let v = unhex(s[i + 1]) << 4 | unhex(s[i + 2]);
                    if !is25 && v != b' ' && host_should_escape(v) {
                        return Err(());
                    }
                }
                i += 3;
            }
            c => {
                if (mode == Mode::Host || mode == Mode::Zone) && c < 0x80 && host_should_escape(c) {
                    return Err(());
                }
                i += 1;
            }
        }
    }
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                out.push(unhex(s[i + 1]) << 4 | unhex(s[i + 2]));
                i += 3;
            }
            b'+' if mode == Mode::QueryComponent => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

fn get_scheme(raw: &[u8]) -> Result<(&[u8], &[u8]), ()> {
    for (i, &c) in raw.iter().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if i == 0 {
                    return Ok((b"", raw));
                }
            }
            b':' => {
                if i == 0 {
                    return Err(());
                }
                return Ok((&raw[..i], &raw[i + 1..]));
            }
            _ => return Ok((b"", raw)),
        }
    }
    Ok((b"", raw))
}

fn valid_optional_port(p: &[u8]) -> bool {
    p.is_empty() || (p[0] == b':' && p[1..].iter().all(u8::is_ascii_digit))
}

fn valid_userinfo(s: &[u8]) -> bool {
    // Go ranges over runes: any non-ASCII rune fails.
    s.iter().all(|&c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                b'-' | b'.'
                    | b'_'
                    | b':'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b'%'
                    | b'@'
            )
    })
}

fn rfind(s: &[u8], c: u8) -> Option<usize> {
    s.iter().rposition(|&x| x == c)
}

fn find(s: &[u8], c: u8) -> Option<usize> {
    s.iter().position(|&x| x == c)
}

fn parse_host(scheme: &str, host: &[u8]) -> Result<Vec<u8>, ()> {
    match rfind(host, b'[') {
        Some(i) if i > 0 => return Err(()),
        Some(_) => {
            let close = rfind(host, b']').ok_or(())?;
            let colon_port = &host[close + 1..];
            if !valid_optional_port(colon_port) {
                return Err(());
            }
            let colon_port = unescape(colon_port, Mode::Host)?;
            let name = &host[1..close];
            let unescaped = match name.windows(3).position(|w| w == b"%25") {
                Some(z) => {
                    let mut h = unescape(&name[..z], Mode::Host)?;
                    h.extend(unescape(&name[z..], Mode::Zone)?);
                    h
                }
                None => unescape(name, Mode::Host)?,
            };
            let text = std::str::from_utf8(&unescaped).map_err(|_| ())?;
            match Addr::parse(text) {
                Some(a) if !a.is4() => {}
                _ => return Err(()),
            }
            let mut out = b"[".to_vec();
            out.extend(unescaped);
            out.push(b']');
            out.extend(colon_port);
            return Ok(out);
        }
        None => {}
    }
    if let Some(mut i) = find(host, b':') {
        let last = rfind(host, b':').unwrap_or(i);
        // Strict colons apply to http and https only.
        if last != i && scheme != "http" && scheme != "https" {
            i = last;
        }
        if !valid_optional_port(&host[i..]) {
            return Err(());
        }
    }
    unescape(host, Mode::Host)
}

/// url.Parse.
pub fn parse(raw: &str) -> Result<Url, ()> {
    let raw = raw.as_bytes();
    let (u, frag) = match find(raw, b'#') {
        Some(i) => (&raw[..i], &raw[i + 1..]),
        None => (raw, &raw[raw.len()..]),
    };
    let url = parse_rest(u)?;
    if !frag.is_empty() {
        unescape(frag, Mode::Fragment)?;
    }
    Ok(url)
}

fn parse_rest(raw: &[u8]) -> Result<Url, ()> {
    if raw.iter().any(|&b| b < b' ' || b == 0x7f) {
        return Err(());
    }
    let mut url = Url::default();
    if raw == b"*" {
        url.path = b"*".to_vec();
        return Ok(url);
    }
    let (scheme, mut rest) = get_scheme(raw)?;
    url.scheme = String::from_utf8_lossy(scheme).to_ascii_lowercase();
    if rest.last() == Some(&b'?') && rest.iter().filter(|&&c| c == b'?').count() == 1 {
        rest = &rest[..rest.len() - 1];
    } else if let Some(i) = find(rest, b'?') {
        url.raw_query = rest[i + 1..].to_vec();
        rest = &rest[..i];
    }
    if !rest.starts_with(b"/") {
        if !url.scheme.is_empty() {
            url.opaque = rest.to_vec();
            return Ok(url);
        }
        let segment = &rest[..find(rest, b'/').unwrap_or(rest.len())];
        if segment.contains(&b':') {
            return Err(());
        }
    }
    if (!url.scheme.is_empty() || !rest.starts_with(b"///")) && rest.starts_with(b"//") {
        let mut authority = &rest[2..];
        rest = b"";
        if let Some(i) = find(authority, b'/') {
            rest = &authority[i..];
            authority = &authority[..i];
        }
        let at = rfind(authority, b'@');
        url.host = parse_host(
            &url.scheme,
            match at {
                Some(i) => &authority[i + 1..],
                None => authority,
            },
        )?;
        if let Some(i) = at {
            let info = &authority[..i];
            if !valid_userinfo(info) {
                return Err(());
            }
            url.user = Some(match find(info, b':') {
                None => (unescape(info, Mode::UserPassword)?, None),
                Some(c) => (
                    unescape(&info[..c], Mode::UserPassword)?,
                    Some(unescape(&info[c + 1..], Mode::UserPassword)?),
                ),
            });
        }
    }
    url.path = unescape(rest, Mode::Path)?;
    Ok(url)
}

/// splitHostPort of url.URL: Hostname and Port.
fn split_host_port(h: &[u8]) -> (&[u8], &[u8]) {
    let mut host = h;
    let mut port: &[u8] = b"";
    if let Some(c) = rfind(host, b':')
        && valid_optional_port(&host[c..])
    {
        port = &host[c + 1..];
        host = &host[..c];
    }
    if host.starts_with(b"[") && host.ends_with(b"]") && host.len() >= 2 {
        host = &host[1..host.len() - 1];
    }
    (host, port)
}

impl Url {
    pub fn hostname(&self) -> &[u8] {
        split_host_port(&self.host).0
    }

    pub fn port(&self) -> &[u8] {
        split_host_port(&self.host).1
    }

    /// url.URL.Query: the values of each key in order, nothing when the
    /// query has too many parameters.
    pub fn query(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let q = &self.raw_query;
        let mut out = Vec::new();
        if q.iter().filter(|&&c| c == b'&').count() + 1 > 10000 {
            return out;
        }
        for pair in q.split(|&c| c == b'&') {
            if pair.contains(&b';') || pair.is_empty() {
                continue;
            }
            let (k, v) = match find(pair, b'=') {
                Some(i) => (&pair[..i], &pair[i + 1..]),
                None => (pair, &pair[pair.len()..]),
            };
            let (Ok(k), Ok(v)) = (
                unescape(k, Mode::QueryComponent),
                unescape(v, Mode::QueryComponent),
            ) else {
                continue;
            };
            out.push((k, v));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_as_go() {
        let u = parse("redis://us%40er:p%3Ass@[fd00::1]:6380/3?x=1#f").unwrap();
        assert_eq!(u.scheme, "redis");
        assert_eq!(u.user, Some((b"us@er".to_vec(), Some(b"p:ss".to_vec()))));
        assert_eq!(u.hostname(), b"fd00::1");
        assert_eq!(u.port(), b"6380");
        assert_eq!(u.path, b"/3");
        assert_eq!(u.raw_query, b"x=1");
        assert!(parse("redis://h:x/").is_err());
        assert!(parse("redis://[1.2.3.4]/").is_err());
        assert!(parse("redis://h%2f/").is_err());
        assert!(parse("redis://h/%zz").is_err());
        assert!(parse(":x").is_err());
        assert_eq!(parse("redis:h").unwrap().opaque, b"h");
        assert_eq!(parse("redis://a:1:2/").unwrap().port(), b"2");
        let q = parse("amqp://h/?a=1&b=x+y&c;d=2&e=%zz&a=2")
            .unwrap()
            .query();
        assert_eq!(
            q,
            vec![
                (b"a".to_vec(), b"1".to_vec()),
                (b"b".to_vec(), b"x y".to_vec()),
                (b"a".to_vec(), b"2".to_vec())
            ]
        );
    }
}

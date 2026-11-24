//! queuelen.RedisListLength: LLEN of a list on the server a URL names,
//! redis://[user[:password]@]host[:port][/db] or rediss:// for TLS, over
//! the minimal RESP the commands need, with bounded replies. A user given
//! without a password authenticates with an empty password (see auth).

use super::{Answer, Dialer, ERR_AUTH, ERR_DIAL, ERR_REPLY, ERR_URL, MAX_LENGTH, Stream, url};
use crate::gostr;

/// The longest reply line read (bufio.Reader's size in queuelen).
const MAX_REPLY_LINE: usize = 512;

/// A reply line reader like queuelen's bufio.Reader: bytes past one line
/// stay for the next reply.
struct Replies {
    buf: Vec<u8>,
}

impl Replies {
    /// readReply: one simple reply (+, -, :) of at most MAX_REPLY_LINE
    /// bytes; anything else, or a failed read, is errReply.
    fn read(&mut self, s: &mut dyn Stream) -> Result<(u8, Vec<u8>), &'static str> {
        loop {
            if let Some(i) = self.buf.iter().position(|&c| c == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=i).collect();
                if line.len() < 3 || line[line.len() - 2] != b'\r' {
                    return Err(ERR_REPLY);
                }
                return match line[0] {
                    b'+' | b'-' | b':' => Ok((line[0], line[1..line.len() - 2].to_vec())),
                    _ => Err(ERR_REPLY),
                };
            }
            if self.buf.len() >= MAX_REPLY_LINE {
                return Err(ERR_REPLY);
            }
            let mut chunk = vec![0u8; MAX_REPLY_LINE - self.buf.len()];
            match s.read(&mut chunk) {
                Ok(0) | Err(_) => return Err(ERR_REPLY),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
            }
        }
    }
}

/// One command: written as a RESP array, then its reply read.
fn call(
    s: &mut dyn Stream,
    replies: &mut Replies,
    args: &[&[u8]],
) -> Result<(u8, Vec<u8>), &'static str> {
    let mut b = format!("*{}\r\n", args.len()).into_bytes();
    for a in args {
        b.extend(format!("${}\r\n", a.len()).bytes());
        b.extend_from_slice(a);
        b.extend_from_slice(b"\r\n");
    }
    if s.write_all(&b).is_err() {
        return Err(ERR_DIAL);
    }
    replies.read(s)
}

/// The server's host, port, and database, as RedisListLength checks the
/// URL before dialling.
fn parse(raw: &str) -> Option<(url::Url, Vec<u8>, i64)> {
    let u = url::parse(raw).ok()?;
    if (u.scheme != "redis" && u.scheme != "rediss")
        || u.hostname().is_empty()
        || !u.opaque.is_empty()
    {
        return None;
    }
    let mut db = 0;
    let p = u.path.strip_prefix(b"/").unwrap_or(&u.path);
    if !p.is_empty() {
        db = gostr::atoi(std::str::from_utf8(p).ok()?).ok()?;
        if !(0..=1 << 16).contains(&db) {
            return None;
        }
    }
    let port = if u.port().is_empty() {
        b"6379".to_vec()
    } else {
        u.port().to_vec()
    };
    Some((u, port, db))
}

/// The AUTH command the URL's user info asks for, if any:
/// redis://:password@host authenticates as the default user,
/// redis://user:password@host as user (ACLs), and redis://user@host as
/// user with an empty password, as the command-line client and the common
/// client libraries do for a user given alone (an ACL user marked nopass
/// takes any password; any other user is refused, and the reading says the
/// credentials were refused instead of reading the list as the default
/// user).
fn auth(u: &url::Url) -> Option<Vec<&[u8]>> {
    match &u.user {
        Some((name, Some(pass))) if name.is_empty() => Some(vec![b"AUTH", pass]),
        Some((name, Some(pass))) => Some(vec![b"AUTH", name, pass]),
        Some((name, None)) if !name.is_empty() => Some(vec![b"AUTH", name, b""]),
        _ => None,
    }
}

/// RedisListLength.
pub fn list_length(d: &mut Dialer, raw: &str, list: &str) -> Answer {
    let Some((u, port, db)) = parse(raw) else {
        return Answer::Error(ERR_URL);
    };
    let conn = match d.dial(u.hostname(), &port) {
        Ok(c) => c,
        Err(a) => return a,
    };
    let mut s: Box<dyn Stream> = if u.scheme == "rediss" {
        match super::tls(conn, u.hostname()) {
            Some(s) => s,
            None => return Answer::Error(ERR_DIAL),
        }
    } else {
        Box::new(conn)
    };
    let s = s.as_mut();
    let mut replies = Replies { buf: Vec::new() };
    if let Some(args) = auth(&u) {
        match call(s, &mut replies, &args) {
            Ok((b'+', _)) => {}
            _ => return Answer::Error(ERR_AUTH),
        }
    }
    if db != 0 {
        match call(s, &mut replies, &[b"SELECT", db.to_string().as_bytes()]) {
            Ok((b'+', _)) => {}
            _ => return Answer::Error(ERR_REPLY),
        }
    }
    match call(s, &mut replies, &[b"LLEN", list.as_bytes()]) {
        Err(e) => Answer::Error(e),
        // An error reply: the key holds another type, or ACLs refuse it.
        Ok((kind, _)) if kind != b':' => Answer::Error(ERR_REPLY),
        Ok((_, v)) => match gostr::parse_int(&v, 64) {
            Ok(n) if (0..=MAX_LENGTH).contains(&n) => Answer::Length(n),
            _ => Answer::Error(ERR_REPLY),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_as_go() {
        assert!(parse("redis://h").is_some());
        assert_eq!(parse("redis://h:7000/+3").unwrap().2, 3);
        for bad in [
            "http://redis-01",
            "redis://",
            "redis://h/x",
            "redis://h/-1",
            "::",
            "redis://h/65537",
            "redis:h",
        ] {
            assert!(parse(bad).is_none(), "{bad}");
        }
    }

    /// rediss:// reads through TLS verified against the machine's roots
    /// (here the test CA): the server's name checked, AUTH and LLEN sent
    /// inside the session; a server the roots do not vouch for is out of
    /// reach.
    #[test]
    fn rediss_reads_over_tls() {
        use crate::queue::tests::{read_from, serve_tls, trust_test_ca};
        use std::io::{BufRead, BufReader};
        let serve = |s: &mut dyn Stream| {
            let mut r = BufReader::new(s);
            let mut seen = Vec::new();
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let n: usize = line[1..].trim().parse().unwrap();
                let mut args = Vec::new();
                for _ in 0..n {
                    let (mut len, mut arg) = (String::new(), String::new());
                    r.read_line(&mut len).unwrap();
                    r.read_line(&mut arg).unwrap();
                    args.push(arg.trim_end().to_string());
                }
                seen.push(args.join(" "));
                let reply: &[u8] = match args[0].as_str() {
                    "AUTH" if args == ["AUTH", "worker", "s3cret"] => b"+OK\r\n",
                    "AUTH" => b"-WRONGPASS\r\n",
                    _ if seen[0] != "AUTH worker s3cret" => b"-NOAUTH\r\n",
                    _ => b":7\r\n",
                };
                r.get_mut().write_all(reply).unwrap();
            }
        };
        trust_test_ca();
        let port = serve_tls(serve);
        let url = format!("rediss://worker:s3cret@mq.test:{port}");
        assert_eq!(read_from("redis", &url, "jobs", port), Answer::Length(7));
        // The certificate does not name this host.
        let port = serve_tls(serve);
        let url = format!("rediss://worker:s3cret@other.test:{port}");
        assert_eq!(
            read_from("redis", &url, "jobs", port),
            Answer::Error(ERR_DIAL)
        );
        // Roots without the test CA.
        crate::queue::tests::TEST_ROOTS.with(|r| r.borrow_mut().clear());
        let port = serve_tls(serve);
        let url = format!("rediss://worker:s3cret@mq.test:{port}");
        assert_eq!(
            read_from("redis", &url, "jobs", port),
            Answer::Error(ERR_DIAL)
        );
    }

    #[test]
    fn auth_from_user_info() {
        let args = |raw: &str| {
            let (u, _, _) = parse(raw).unwrap();
            auth(&u).map(|a| {
                a.iter()
                    .map(|x| String::from_utf8_lossy(x).into_owned())
                    .collect::<Vec<_>>()
            })
        };
        assert_eq!(args("redis://h"), None);
        assert_eq!(args("redis://@h"), None);
        assert_eq!(args("redis://:pw@h").unwrap(), ["AUTH", "pw"]);
        assert_eq!(args("redis://:@h").unwrap(), ["AUTH", ""]);
        assert_eq!(args("redis://u:pw@h").unwrap(), ["AUTH", "u", "pw"]);
        // A user alone: the user with an empty password, never the default
        // user without AUTH.
        assert_eq!(args("redis://u@h").unwrap(), ["AUTH", "u", ""]);
    }
}

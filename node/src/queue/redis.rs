//! queuelen.RedisListLength: LLEN of a list on the server a URL names,
//! redis://[user[:password]@]host[:port][/db] or rediss:// for TLS, over
//! the minimal RESP the commands need, with bounded replies.

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
    // redis://:password@host authenticates as the default user,
    // redis://user:password@host as user (ACLs).
    if let Some((name, Some(pass))) = &u.user {
        let args: Vec<&[u8]> = if name.is_empty() {
            vec![b"AUTH", pass]
        } else {
            vec![b"AUTH", name, pass]
        };
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
}

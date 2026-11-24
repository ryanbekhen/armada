//! queuelen.RabbitMQQueueLength: the messages ready in a queue, read with
//! a passive Queue.Declare over AMQP 0-9-1 as amqp091-go (v1.17.0) opens a
//! connection for it: ParseURI's reading of the URL, the SASL mechanisms
//! it offers, the handshake's frames and negotiation, and which failure
//! amqp091-go reports as which error, which queuelen turns into its own
//! texts. Only the frames this needs are encoded; every frame read is
//! checked as amqp091-go's reader checks it.

use super::{
    Answer, Dialer, ERR_AUTH, ERR_DIAL, ERR_MISSING, ERR_REPLY, ERR_TIMEOUT, ERR_URL, MAX_LENGTH,
    Stream, url,
};
use crate::gostr;

const FRAME_METHOD: u8 = 1;
const FRAME_HEADER: u8 = 2;
const FRAME_BODY: u8 = 3;
const FRAME_HEARTBEAT: u8 = 8;
const FRAME_END: u8 = 206;
const FRAME_MIN_SIZE: u32 = 4096;
const DEFAULT_FRAME_SIZE: u32 = 131072;
const DEFAULT_CHANNEL_MAX: u16 = 2047;
const DEFAULT_HEARTBEAT: u32 = 10;
const ACCESS_REFUSED: u16 = 403;
const NOT_FOUND: u16 = 404;
const MAX_FIELD_DEPTH: usize = 32;
const MAX_CONTAINER_ELEMENTS: usize = 8192;

/// What ParseURI and DialConfig read from the URL.
#[derive(Debug, PartialEq)]
struct Uri {
    tls: bool,
    host: Vec<u8>,
    port: i64,
    username: Vec<u8>,
    password: Vec<u8>,
    vhost: Vec<u8>,
    mechanisms: Option<Vec<Vec<u8>>>,
    heartbeat: Option<u32>,
    channel_max: u16,
}

/// amqp091.ParseURI; None for every URL it refuses.
fn parse_uri(raw: &str) -> Option<Uri> {
    if raw.contains(' ') {
        return None;
    }
    let u = url::parse(raw).ok()?;
    let (tls, default_port) = match u.scheme.as_str() {
        "amqp" => (false, 5672),
        "amqps" => (true, 5671),
        _ => return None,
    };
    let host = if u.hostname().is_empty() {
        b"localhost".to_vec()
    } else {
        u.hostname().to_vec()
    };
    let port = if u.port().is_empty() {
        default_port
    } else {
        gostr::parse_int(u.port(), 32).ok()?
    };
    let (mut username, mut password) = (b"guest".to_vec(), b"guest".to_vec());
    if let Some((name, pass)) = &u.user {
        username = name.clone();
        if let Some(p) = pass {
            password = p.clone();
        }
    }
    let mut vhost = b"/".to_vec();
    let path = &u.path;
    if !path.is_empty() {
        if path.starts_with(b"/") {
            if u.host.is_empty() && path.starts_with(b"///") {
                if path.len() > 3 {
                    vhost = path[3..].to_vec();
                }
            } else if path.len() > 1 {
                vhost = path[1..].to_vec();
            }
        } else {
            vhost = path.clone();
        }
    }
    let query = u.query();
    let get = |k: &[u8]| query.iter().find(|(qk, _)| qk == k).map(|(_, v)| v.clone());
    let all: Vec<Vec<u8>> = query
        .iter()
        .filter(|(k, _)| k == b"auth_mechanism")
        .map(|(_, v)| v.clone())
        .collect();
    let text = |v: Vec<u8>| String::from_utf8(v).unwrap_or_else(|_| "\u{fffd}".into());
    let heartbeat = match get(b"heartbeat") {
        None => None,
        Some(v) => Some(gostr::parse_uint(&text(v), 16).ok()? as u32),
    };
    if let Some(v) = get(b"connection_timeout") {
        gostr::atoi(&text(v)).ok()?;
    }
    let channel_max = match get(b"channel_max") {
        None => 0,
        Some(v) => gostr::parse_uint(&text(v), 16).ok()? as u16,
    };
    Some(Uri {
        tls,
        host,
        port,
        username,
        password,
        vhost,
        mechanisms: (!all.is_empty()).then_some(all),
        heartbeat,
        channel_max,
    })
}

/// A SASL mechanism and its response.
struct Auth {
    mechanism: &'static str,
    response: Vec<u8>,
}

/// setSASL: the mechanisms the client offers, in order; None for a name
/// it does not know (DialConfig fails before dialling).
fn sasl(uri: &Uri) -> Option<Vec<Auth>> {
    let plain = || {
        let mut r = vec![0u8];
        r.extend_from_slice(&uri.username);
        r.push(0);
        r.extend_from_slice(&uri.password);
        Auth {
            mechanism: "PLAIN",
            response: r,
        }
    };
    let Some(names) = &uri.mechanisms else {
        return Some(vec![plain()]);
    };
    let mut out = Vec::new();
    for n in names {
        match String::from_utf8_lossy(n).to_uppercase().as_str() {
            "PLAIN" => out.push(plain()),
            "AMQPLAIN" => {
                // A table without its length: LOGIN and PASSWORD as long strings.
                let mut r = Vec::new();
                for (k, v) in [(&b"LOGIN"[..], &uri.username), (b"PASSWORD", &uri.password)] {
                    r.push(k.len() as u8);
                    r.extend_from_slice(k);
                    r.push(b'S');
                    r.extend((v.len() as u32).to_be_bytes());
                    r.extend_from_slice(v);
                }
                out.push(Auth {
                    mechanism: "AMQPLAIN",
                    response: r,
                });
            }
            "EXTERNAL" => out.push(Auth {
                mechanism: "EXTERNAL",
                response: b"\0*\0*".to_vec(),
            }),
            _ => return None,
        }
    }
    Some(out)
}

/// A frame's failure: the broker closed the connection or channel with a
/// code, or something else went wrong (an I/O error, a malformed or
/// unexpected frame).
#[derive(Debug, PartialEq)]
enum Fail {
    Server(u16),
    Local,
}

/// A method frame's class, method, and arguments.
struct Method {
    channel: u16,
    class: u16,
    method: u16,
    args: Vec<u8>,
}

/// Reads the arguments of a method in order.
struct Args<'a> {
    b: &'a [u8],
}

impl Args<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], Fail> {
        if self.b.len() < n {
            return Err(Fail::Local);
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }
    fn u8(&mut self) -> Result<u8, Fail> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Fail> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, Fail> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn shortstr(&mut self) -> Result<Vec<u8>, Fail> {
        let n = self.u8()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn longstr(&mut self) -> Result<Vec<u8>, Fail> {
        let n = self.u32()?;
        if n > i32::MAX as u32 {
            return Err(Fail::Local);
        }
        Ok(self.take(n as usize)?.to_vec())
    }
    /// readTable: a table whose every field amqp091-go can read.
    fn table(&mut self, depth: usize) -> Result<(), Fail> {
        if depth > MAX_FIELD_DEPTH {
            return Err(Fail::Local);
        }
        let body = self.longstr()?;
        let mut t = Args { b: &body };
        let mut n = 0;
        while !t.b.is_empty() {
            t.shortstr()?;
            t.field(depth)?;
            if n >= MAX_CONTAINER_ELEMENTS {
                return Err(Fail::Local);
            }
            n += 1;
        }
        Ok(())
    }
    fn array(&mut self, depth: usize) -> Result<(), Fail> {
        if depth > MAX_FIELD_DEPTH {
            return Err(Fail::Local);
        }
        let size = self.u32()?;
        if size > i32::MAX as u32 {
            return Err(Fail::Local);
        }
        // A short array reads what there is (io.LimitedReader).
        let n = (size as usize).min(self.b.len());
        let body = self.take(n)?.to_vec();
        let mut t = Args { b: &body };
        let mut count = 0;
        while !t.b.is_empty() {
            t.field(depth)?;
            if count >= MAX_CONTAINER_ELEMENTS {
                return Err(Fail::Local);
            }
            count += 1;
        }
        Ok(())
    }
    fn field(&mut self, depth: usize) -> Result<(), Fail> {
        match self.u8()? {
            b't' | b'B' | b'b' => self.take(1).map(drop),
            b's' | b'u' => self.take(2).map(drop),
            b'I' | b'i' | b'f' => self.take(4).map(drop),
            b'l' | b'd' | b'T' => self.take(8).map(drop),
            b'D' => self.take(5).map(drop),
            b'S' => self.longstr().map(drop),
            b'A' => self.array(depth + 1),
            b'F' => self.table(depth + 1),
            b'x' => {
                let n = self.u32()? as i32;
                if n < 0 {
                    return Err(Fail::Local);
                }
                self.take(n as usize).map(drop)
            }
            b'V' => Ok(()),
            _ => Err(Fail::Local),
        }
    }
}

/// The connection: frames in and out.
struct Conn<'a> {
    s: &'a mut dyn Stream,
    max_frame: u32,
}

fn method_frame(channel: u16, class: u16, method: u16, args: &[u8]) -> Vec<u8> {
    let mut f = vec![FRAME_METHOD];
    f.extend(channel.to_be_bytes());
    f.extend(((args.len() + 4) as u32).to_be_bytes());
    f.extend(class.to_be_bytes());
    f.extend(method.to_be_bytes());
    f.extend_from_slice(args);
    f.push(FRAME_END);
    f
}

fn shortstr(out: &mut Vec<u8>, s: &[u8]) -> Result<(), Fail> {
    if s.len() > 255 {
        return Err(Fail::Local);
    }
    out.push(s.len() as u8);
    out.extend_from_slice(s);
    Ok(())
}

fn longstr(out: &mut Vec<u8>, s: &[u8]) {
    out.extend((s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// The client properties queuelen sets, with the capabilities amqp091-go
/// adds.
fn client_properties() -> Vec<u8> {
    let mut caps = Vec::new();
    for k in [
        "basic.nack",
        "connection.blocked",
        "consumer_cancel_notify",
        "publisher_confirms",
    ] {
        caps.push(k.len() as u8);
        caps.extend_from_slice(k.as_bytes());
        caps.extend([b't', 1]);
    }
    let mut t = Vec::new();
    t.push(12);
    t.extend_from_slice(b"capabilities");
    t.push(b'F');
    longstr(&mut t, &caps);
    t.push(15);
    t.extend_from_slice(b"connection_name");
    t.push(b'S');
    longstr(&mut t, b"armada-autoscaler");
    let mut out = Vec::new();
    longstr(&mut out, &t);
    out
}

impl Conn<'_> {
    fn send(&mut self, frame: &[u8]) -> Result<(), Fail> {
        self.s.write_all(frame).map_err(|_| Fail::Local)
    }

    /// The next method frame, as amqp091-go's reader and dispatch see it:
    /// heartbeats and Connection.Blocked/Unblocked skipped, a broker's
    /// Connection.Close answered and reported with its code, a channel's
    /// Close (on channel) reported with its code.
    fn next(&mut self, channel: u16) -> Result<Method, Fail> {
        loop {
            let mut head = [0u8; 7];
            self.s.read_exact(&mut head).map_err(|_| Fail::Local)?;
            let typ = head[0];
            let ch = u16::from_be_bytes([head[1], head[2]]);
            let size = u32::from_be_bytes([head[3], head[4], head[5], head[6]]);
            if self.max_frame > 0 && size > self.max_frame - 8 {
                return Err(Fail::Local);
            }
            if !matches!(
                typ,
                FRAME_METHOD | FRAME_HEADER | FRAME_BODY | FRAME_HEARTBEAT
            ) {
                return Err(Fail::Local);
            }
            let mut payload = vec![0u8; size as usize];
            self.s.read_exact(&mut payload).map_err(|_| Fail::Local)?;
            let mut end = [0u8; 1];
            self.s.read_exact(&mut end).map_err(|_| Fail::Local)?;
            if end[0] != FRAME_END {
                return Err(Fail::Local);
            }
            match typ {
                FRAME_HEARTBEAT => continue,
                FRAME_METHOD => {}
                _ => return Err(Fail::Local),
            }
            let mut a = Args { b: &payload };
            let (class, method) = (a.u16()?, a.u16()?);
            let args = a.b.to_vec();
            match (ch, class, method) {
                (0, 10, 50) => {
                    let mut a = Args { b: &args };
                    let code = a.u16()?;
                    let _ = self.send(&method_frame(0, 10, 51, &[]));
                    return Err(Fail::Server(code));
                }
                (0, 10, 60 | 61) => continue,
                (c, 20, 40) if c == channel && c != 0 => {
                    let mut a = Args { b: &args };
                    let code = a.u16()?;
                    let _ = self.send(&method_frame(c, 20, 41, &[]));
                    return Err(Fail::Server(code));
                }
                _ => {
                    return Ok(Method {
                        channel: ch,
                        class,
                        method,
                        args,
                    });
                }
            }
        }
    }

    /// The next method, which must be class.method on channel.
    fn expect(&mut self, channel: u16, class: u16, method: u16) -> Result<Vec<u8>, Fail> {
        let m = self.next(channel)?;
        if m.channel != channel || m.class != class || m.method != method {
            return Err(Fail::Local);
        }
        Ok(m.args)
    }
}

/// pick and pickUInt16 of amqp091-go.
fn pick(client: u32, server: u32) -> u32 {
    if client == 0 || server == 0 {
        client.max(server)
    } else {
        client.min(server)
    }
}

/// connection.open's steps, each failure as queuelen reports it.
fn open(c: &mut Conn, uri: &Uri, auths: &[Auth]) -> Result<(), &'static str> {
    // Before Connection.Tune, a broker's Close counts by its code and any
    // other failure is a dial error (ErrClosed, ErrFrame, ErrSyntax).
    let refused = |f: Fail| match f {
        Fail::Server(ACCESS_REFUSED) => ERR_AUTH,
        _ => ERR_DIAL,
    };
    c.send(b"AMQP\x00\x00\x09\x01").map_err(|_| ERR_DIAL)?;
    let start = c.expect(0, 10, 10).map_err(refused)?;
    let mut a = Args { b: &start };
    let parsed = (|| -> Result<Vec<u8>, Fail> {
        a.u8()?;
        a.u8()?;
        a.table(0)?;
        let mechanisms = a.longstr()?;
        a.longstr()?;
        Ok(mechanisms)
    })();
    let mechanisms = parsed.map_err(refused)?;
    let server: Vec<&[u8]> = mechanisms.split(|&b| b == b' ').collect();
    let Some(auth) = auths
        .iter()
        .find(|a| server.contains(&a.mechanism.as_bytes()))
    else {
        return Err(ERR_AUTH); // ErrSASL
    };
    let mut ok = client_properties();
    shortstr(&mut ok, auth.mechanism.as_bytes()).map_err(|_| ERR_AUTH)?;
    longstr(&mut ok, &auth.response);
    shortstr(&mut ok, b"en_US").map_err(|_| ERR_AUTH)?;
    // After Start-Ok, a failure without the broker's word is taken as
    // refused credentials (ErrCredentials).
    let after_start = |f: Fail| match f {
        Fail::Server(ACCESS_REFUSED) => ERR_AUTH,
        Fail::Server(_) => ERR_DIAL,
        Fail::Local => ERR_AUTH,
    };
    c.send(&method_frame(0, 10, 11, &ok)).map_err(after_start)?;
    let tune = c.expect(0, 10, 30).map_err(after_start)?;
    let mut a = Args { b: &tune };
    let (ch_max, frame_max, heartbeat) =
        (|| -> Result<(u16, u32, u16), Fail> { Ok((a.u16()?, a.u32()?, a.u16()?)) })()
            .map_err(after_start)?;
    let mut channel_max = pick(u32::from(uri.channel_max), u32::from(ch_max)) as u16;
    if channel_max == 0 {
        channel_max = DEFAULT_CHANNEL_MAX;
    }
    let mut frame = pick(DEFAULT_FRAME_SIZE, frame_max);
    if frame > 0 && frame < FRAME_MIN_SIZE {
        frame = FRAME_MIN_SIZE;
    }
    c.max_frame = frame;
    let beat = pick(
        uri.heartbeat.unwrap_or(DEFAULT_HEARTBEAT),
        u32::from(heartbeat),
    );
    let mut tune_ok = Vec::new();
    tune_ok.extend(channel_max.to_be_bytes());
    tune_ok.extend(frame.to_be_bytes());
    tune_ok.extend((beat as u16).to_be_bytes());
    c.send(&method_frame(0, 10, 31, &tune_ok))
        .map_err(|_| ERR_DIAL)?;
    // Connection.Open: a failure without the broker's word is ErrVhost,
    // which is AccessRefused too.
    let mut o = Vec::new();
    shortstr(&mut o, &uri.vhost).map_err(|_| ERR_AUTH)?;
    o.extend([0, 0]);
    c.send(&method_frame(0, 10, 40, &o)).map_err(after_start)?;
    c.expect(0, 10, 41).map_err(after_start)?;
    Ok(())
}

/// Channel.Open and the passive Queue.Declare: the message count.
fn declare(c: &mut Conn, queue: &str) -> Result<u32, &'static str> {
    c.send(&method_frame(1, 20, 10, &[0]))
        .map_err(|_| ERR_REPLY)?;
    c.expect(1, 20, 11).map_err(|_| ERR_REPLY)?;
    let mut d = vec![0, 0];
    shortstr(&mut d, queue.as_bytes()).map_err(|_| ERR_REPLY)?;
    d.push(1); // passive
    d.extend([0, 0, 0, 0]); // no arguments
    let missing = |f: Fail| match f {
        Fail::Server(NOT_FOUND) => ERR_MISSING,
        _ => ERR_REPLY,
    };
    c.send(&method_frame(1, 50, 10, &d)).map_err(missing)?;
    let ok = c.expect(1, 50, 11).map_err(missing)?;
    let mut a = Args { b: &ok };
    (|| -> Result<u32, Fail> {
        a.shortstr()?;
        let n = a.u32()?;
        a.u32()?;
        Ok(n)
    })()
    .map_err(missing)
}

/// RabbitMQQueueLength.
pub fn queue_length(d: &mut Dialer, raw: &str, queue: &str) -> Answer {
    let Some(uri) = parse_uri(raw) else {
        return Answer::Error(ERR_URL);
    };
    let answer = |d: &Dialer, e: &'static str| {
        // queuelen answers "timed out" once its context ends.
        Answer::Error(if d.timed_out() { ERR_TIMEOUT } else { e })
    };
    let Some(auths) = sasl(&uri) else {
        return answer(d, ERR_DIAL);
    };
    let conn = match d.dial(&uri.host, uri.port.to_string().as_bytes()) {
        Ok(c) => c,
        Err(Answer::Error(e)) => return answer(d, e),
        Err(a) => return a,
    };
    let mut s: Box<dyn Stream> = if uri.tls {
        match super::tls(conn, &uri.host) {
            Some(s) => s,
            None => return answer(d, ERR_DIAL),
        }
    } else {
        Box::new(conn)
    };
    let mut c = Conn {
        s: s.as_mut(),
        max_frame: FRAME_MIN_SIZE,
    };
    if let Err(e) = open(&mut c, &uri, &auths) {
        return answer(d, e);
    }
    let n = match declare(&mut c, queue) {
        Ok(n) => n,
        Err(e) => return answer(d, e),
    };
    // Connection.Close, as the connection's Close sends it; the answer does
    // not wait for the broker's Close-Ok.
    let mut close = Vec::new();
    close.extend(200u16.to_be_bytes());
    let _ = shortstr(&mut close, b"kthxbai");
    close.extend([0, 0, 0, 0]);
    let _ = c.send(&method_frame(0, 10, 50, &close));
    Answer::Length(i64::from(n).min(MAX_LENGTH))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uris_as_go() {
        let u = parse_uri("amqps://bob@mq.local:5673/%2Fprod?heartbeat=5&channel_max=9").unwrap();
        assert!(u.tls);
        assert_eq!(u.host, b"mq.local");
        assert_eq!(u.port, 5673);
        assert_eq!(u.username, b"bob");
        assert_eq!(u.password, b"guest");
        assert_eq!(u.vhost, b"/prod");
        assert_eq!(u.heartbeat, Some(5));
        assert_eq!(u.channel_max, 9);
        let u = parse_uri("amqp://").unwrap();
        assert_eq!((u.host.as_slice(), u.port), (&b"localhost"[..], 5672));
        assert_eq!(u.vhost, b"/");
        for bad in [
            "redis://h",
            "amqp://h/ x",
            "amqp://h:99999999999/",
            "amqp://h/?heartbeat=x",
            "amqp://h/?channel_max=70000",
            "amqp://h/?connection_timeout=x",
        ] {
            assert!(parse_uri(bad).is_none(), "{bad}");
        }
        let u = parse_uri("amqp://h/?auth_mechanism=plain&auth_mechanism=nope").unwrap();
        assert!(sasl(&u).is_none());
    }
}

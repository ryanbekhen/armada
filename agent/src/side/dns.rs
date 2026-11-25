//! Resolving a broker's name from a network namespace (Go's resolveIn, a
//! net.Resolver whose Dial dials from the namespace): A and AAAA queries
//! to the nameserver containers use over a socket the runtime connects
//! from the namespace, UDP first and TCP when the answer was truncated.
//! The name is asked as given (absolute); addresses come IPv4 first.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::OwnedFd;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One query's bound.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

/// A query for name of type t with id.
pub fn query(id: u16, name: &str, t: u16) -> Result<Vec<u8>, String> {
    let mut b = Vec::with_capacity(32 + name.len());
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("invalid name".into());
        }
        b.push(label.len() as u8);
        b.extend_from_slice(label.as_bytes());
    }
    b.push(0);
    b.extend_from_slice(&t.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes());
    Ok(b)
}

/// Skips a name at off; the offset after it.
fn skip_name(m: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let l = *m.get(off)? as usize;
        if l == 0 {
            return Some(off + 1);
        }
        if l & 0xc0 == 0xc0 {
            return Some(off + 2);
        }
        off += 1 + l;
    }
}

fn u16_at(m: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*m.get(off)?, *m.get(off + 1)?]))
}

/// What an answer says: the addresses, or that it was truncated.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    Addrs(Vec<IpAddr>),
    Truncated,
}

/// Reads the answer to query id of type t.
pub fn parse(m: &[u8], id: u16, t: u16) -> Result<Answer, String> {
    let bad = || "malformed answer".to_string();
    if m.len() < 12 || u16_at(m, 0) != Some(id) || m[2] & 0x80 == 0 {
        return Err(bad());
    }
    if m[2] & 0x02 != 0 {
        return Ok(Answer::Truncated);
    }
    let rcode = m[3] & 0x0f;
    if rcode != 0 {
        return Err(format!("server answered rcode {rcode}"));
    }
    let qd = u16_at(m, 4).ok_or_else(bad)?;
    let an = u16_at(m, 6).ok_or_else(bad)?;
    let mut off = 12;
    for _ in 0..qd {
        off = skip_name(m, off).ok_or_else(bad)? + 4;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        off = skip_name(m, off).ok_or_else(bad)?;
        let rt = u16_at(m, off).ok_or_else(bad)?;
        let class = u16_at(m, off + 2).ok_or_else(bad)?;
        let len = u16_at(m, off + 8).ok_or_else(bad)? as usize;
        let data = m.get(off + 10..off + 10 + len).ok_or_else(bad)?;
        off += 10 + len;
        if class != 1 || rt != t {
            continue; // a CNAME on the way, among others
        }
        match (rt, data.len()) {
            (TYPE_A, 4) => out.push(IpAddr::V4(Ipv4Addr::new(
                data[0], data[1], data[2], data[3],
            ))),
            (TYPE_AAAA, 16) => {
                let mut a = [0u8; 16];
                a.copy_from_slice(data);
                out.push(IpAddr::V6(Ipv6Addr::from(a)));
            }
            _ => {}
        }
    }
    Ok(Answer::Addrs(out))
}

fn random_id() -> u16 {
    use std::hash::{BuildHasher, RandomState};
    RandomState::new().hash_one(std::time::SystemTime::now()) as u16
}

async fn ask_udp(fd: OwnedFd, q: &[u8]) -> Result<Vec<u8>, String> {
    let s = std::net::UdpSocket::from(fd);
    s.set_nonblocking(true).map_err(|e| e.to_string())?;
    let s = tokio::net::UdpSocket::from_std(s).map_err(|e| e.to_string())?;
    s.send(q).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 1232];
    let n = s.recv(&mut buf).await.map_err(|e| e.to_string())?;
    buf.truncate(n);
    Ok(buf)
}

async fn ask_tcp(fd: OwnedFd, q: &[u8]) -> Result<Vec<u8>, String> {
    let s = std::net::TcpStream::from(fd);
    s.set_nonblocking(true).map_err(|e| e.to_string())?;
    let mut s = tokio::net::TcpStream::from_std(s).map_err(|e| e.to_string())?;
    let mut msg = (q.len() as u16).to_be_bytes().to_vec();
    msg.extend_from_slice(q);
    s.write_all(&msg).await.map_err(|e| e.to_string())?;
    let n = s.read_u16().await.map_err(|e| e.to_string())? as usize;
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    Ok(buf)
}

/// Resolves host through the nameserver ns (host:53), dialled with dial
/// ("udp" or "tcp", address).
pub async fn lookup<F, Fut>(dial: F, ns: &str, host: &str) -> Result<Vec<IpAddr>, String>
where
    F: Fn(&'static str, String) -> Fut,
    Fut: Future<Output = Result<OwnedFd, String>>,
{
    let mut out = Vec::new();
    for t in [TYPE_A, TYPE_AAAA] {
        let id = random_id();
        let q = query(id, host, t)?;
        let ask = async {
            let m = ask_udp(dial("udp", ns.to_string()).await?, &q).await?;
            match parse(&m, id, t)? {
                Answer::Addrs(a) => Ok(a),
                Answer::Truncated => {
                    let m = ask_tcp(dial("tcp", ns.to_string()).await?, &q).await?;
                    match parse(&m, id, t)? {
                        Answer::Addrs(a) => Ok(a),
                        Answer::Truncated => Err("truncated answer".to_string()),
                    }
                }
            }
        };
        if let Ok(Ok(a)) = tokio::time::timeout(QUERY_TIMEOUT, ask).await {
            out.extend(a);
        }
    }
    if out.is_empty() {
        return Err("no such host".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers() {
        let q = query(7, "redis.internal", TYPE_A).unwrap();
        let mut m = q.clone();
        m[2] = 0x81;
        m[3] = 0x80;
        m[7] = 2; // two answers: a CNAME, then an A
        m.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 12]);
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 9]);
        assert_eq!(
            parse(&m, 7, TYPE_A).unwrap(),
            Answer::Addrs(vec!["10.0.0.9".parse().unwrap()])
        );
        assert!(parse(&m, 8, TYPE_A).is_err());
        m[2] |= 0x02;
        assert_eq!(parse(&m, 7, TYPE_A).unwrap(), Answer::Truncated);
        assert!(query(1, "a..b", TYPE_A).is_err());
    }

    #[tokio::test]
    async fn resolves() {
        let srv = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = srv.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for _ in 0..2 {
                let mut b = [0u8; 512];
                let (n, from) = srv.recv_from(&mut b).unwrap();
                let mut m = b[..n].to_vec();
                m[2] = 0x81;
                m[3] = 0x80;
                if m[n - 3] == 1 {
                    m[7] = 1;
                    m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 1, 2, 3]);
                }
                srv.send_to(&m, from).unwrap();
            }
        });
        let dial = |_: &'static str, a: String| async move {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
            s.connect(&a).map_err(|e| e.to_string())?;
            Ok(OwnedFd::from(s))
        };
        let ips = lookup(dial, &addr, "broker.internal").await.unwrap();
        assert_eq!(ips, vec!["10.1.2.3".parse::<IpAddr>().unwrap()]);
    }
}

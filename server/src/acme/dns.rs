//! The DNS lookups of the DNS-01 solver: the zone of a name from its SOA
//! (with an SOA cache), and the
//! propagation check that asks the zone's authoritative nameservers (or,
//! when resolvers are given, those resolvers) for the TXT record. Queries
//! carry EDNS0 with a 1232-byte buffer, go over UDP and again over TCP for
//! a cut answer or a timeout, and wait 10 seconds at most, as miekg/dns
//! does for certmagic.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TIMEOUT: Duration = Duration::from_secs(10);

pub const TYPE_TXT: u16 = 16;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;

/// What an answer's record holds.
#[derive(Clone, Debug)]
pub enum Data {
    Soa { refresh: u32 },
    Ns(String),
    Cname(String),
    Txt(Vec<String>),
    Other,
}

#[derive(Clone, Debug)]
pub struct Record {
    pub name: String,
    pub data: Data,
}

/// A response.
#[derive(Clone, Debug, Default)]
pub struct Msg {
    pub rcode: u16,
    pub truncated: bool,
    pub answer: Vec<Record>,
}

pub fn rcode_string(rc: u16) -> String {
    match rc {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        _ => return String::new(),
    }
    .to_string()
}

/// A query for name (absolute) of type typ, recursion desired when
/// `recursive`, with an EDNS0 OPT record of 1232 bytes.
fn query(id: u16, name: &str, typ: u16, recursive: bool) -> Result<Vec<u8>, String> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[if recursive { 0x01 } else { 0x00 }, 0x00]);
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]);
    let trimmed = name.trim_end_matches('.');
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(format!("dns: bad rdata: {name}"));
            }
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
    }
    q.push(0);
    q.extend_from_slice(&typ.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    // OPT: root name, type 41, class = UDP size, TTL 0, no data.
    q.extend_from_slice(&[0, 0, 41]);
    q.extend_from_slice(&1232u16.to_be_bytes());
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    Ok(q)
}

fn u16_at(b: &[u8], i: usize) -> Result<u16, String> {
    b.get(i..i + 2)
        .map(|x| u16::from_be_bytes([x[0], x[1]]))
        .ok_or_else(|| "dns: overflow unpacking uint16".to_string())
}

fn u32_at(b: &[u8], i: usize) -> Result<u32, String> {
    b.get(i..i + 4)
        .map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]))
        .ok_or_else(|| "dns: overflow unpacking uint32".to_string())
}

/// A possibly compressed name at i: the name (absolute, with its dot)
/// and where the record goes on.
fn read_name(b: &[u8], mut i: usize) -> Result<(String, usize), String> {
    let mut out = String::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let l = *b.get(i).ok_or("dns: buffer size too small")?;
        if l & 0xc0 == 0xc0 {
            let ptr = (usize::from(l & 0x3f) << 8)
                | usize::from(*b.get(i + 1).ok_or("dns: buffer size too small")?);
            end.get_or_insert(i + 2);
            jumps += 1;
            if jumps > 64 {
                return Err("dns: too many compression pointers".to_string());
            }
            i = ptr;
            continue;
        }
        if l == 0 {
            end.get_or_insert(i + 1);
            break;
        }
        let label = b
            .get(i + 1..i + 1 + usize::from(l))
            .ok_or("dns: buffer size too small")?;
        out.push_str(&String::from_utf8_lossy(label));
        out.push('.');
        i += 1 + usize::from(l);
    }
    if out.is_empty() {
        out.push('.');
    }
    Ok((out, end.expect("set before the loop ends")))
}

fn parse(b: &[u8], id: u16) -> Result<Msg, String> {
    if b.len() < 12 {
        return Err("dns: short read".to_string());
    }
    if u16_at(b, 0)? != id {
        return Err("dns: id mismatch".to_string());
    }
    let flags = u16_at(b, 2)?;
    let (qd, an) = (u16_at(b, 4)?, u16_at(b, 6)?);
    let mut msg = Msg {
        rcode: flags & 0x000f,
        truncated: flags & 0x0200 != 0,
        answer: Vec::new(),
    };
    let mut i = 12;
    for _ in 0..qd {
        i = read_name(b, i)?.1 + 4;
    }
    for _ in 0..an {
        let (name, at) = read_name(b, i)?;
        let typ = u16_at(b, at)?;
        let len = usize::from(u16_at(b, at + 8)?);
        let start = at + 10;
        let rdata = b
            .get(start..start + len)
            .ok_or("dns: overflow unpacking rdata")?;
        let data = match typ {
            TYPE_SOA => {
                let (_, j) = read_name(b, start)?;
                let (_, j) = read_name(b, j)?;
                Data::Soa {
                    refresh: u32_at(b, j + 4)?,
                }
            }
            TYPE_NS => Data::Ns(read_name(b, start)?.0),
            TYPE_CNAME => Data::Cname(read_name(b, start)?.0),
            TYPE_TXT => {
                let mut v = Vec::new();
                let mut j = 0;
                while j < rdata.len() {
                    let l = usize::from(rdata[j]);
                    let s = rdata
                        .get(j + 1..j + 1 + l)
                        .ok_or("dns: overflow unpacking txt")?;
                    v.push(String::from_utf8_lossy(s).into_owned());
                    j += 1 + l;
                }
                Data::Txt(v)
            }
            _ => Data::Other,
        };
        msg.answer.push(Record { name, data });
        i = start + len;
    }
    Ok(msg)
}

fn random_id() -> u16 {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 2];
    let _ = ring::rand::SystemRandom::new().fill(&mut b);
    u16::from_be_bytes(b)
}

async fn udp(server: &str, q: &[u8], id: u16) -> Result<Msg, String> {
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(server)
        .await
        .map_err(|e| format!("dial udp {server}: {e}"))?
        .collect();
    let addr = *addrs
        .first()
        .ok_or_else(|| format!("dial udp {server}: no addresses"))?;
    let bind = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|e| e.to_string())?;
    sock.connect(addr)
        .await
        .map_err(|e| format!("dial udp {addr}: {e}"))?;
    sock.send(q).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 65535];
    loop {
        let n = sock.recv(&mut buf).await.map_err(|e| e.to_string())?;
        // miekg/dns ignores answers with another ID and reads on.
        if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) != id {
            continue;
        }
        return parse(&buf[..n], id);
    }
}

async fn tcp(server: &str, q: &[u8], id: u16) -> Result<Msg, String> {
    let mut c = tokio::net::TcpStream::connect(server)
        .await
        .map_err(|e| format!("dial tcp {server}: {e}"))?;
    let mut msg = (q.len() as u16).to_be_bytes().to_vec();
    msg.extend_from_slice(q);
    c.write_all(&msg).await.map_err(|e| e.to_string())?;
    let n = c.read_u16().await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; usize::from(n)];
    c.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    parse(&buf, id)
}

/// UDP, then TCP when the answer is cut short or the UDP
/// exchange timed out.
async fn send_query(name: &str, typ: u16, recursive: bool, ns: &str) -> Result<Msg, String> {
    let id = random_id();
    let q = query(id, name, typ, recursive)?;
    let first = match tokio::time::timeout(TIMEOUT, udp(ns, &q, id)).await {
        Ok(r) => r,
        Err(_) => Err("i/o timeout".to_string()),
    };
    let again = match &first {
        Ok(m) => m.truncated,
        Err(e) => e.contains("timeout"),
    };
    if !again {
        return first;
    }
    match tokio::time::timeout(TIMEOUT, tcp(ns, &q, id)).await {
        Ok(r) => r,
        Err(_) => Err("i/o timeout".to_string()),
    }
}

/// Each nameserver in turn until one answers with records; the
/// last answer and error.
async fn dns_query(
    name: &str,
    typ: u16,
    nameservers: &[String],
    recursive: bool,
) -> (Option<Msg>, Option<String>) {
    let mut last = (None, None);
    for ns in nameservers {
        match send_query(name, typ, recursive, ns).await {
            Ok(m) => {
                let done = !m.answer.is_empty();
                last = (Some(m), None);
                if done {
                    break;
                }
            }
            Err(e) => last = (None, Some(e)),
        }
    }
    last
}

/// RecursiveNameservers: the given resolvers, else the machine's (or
/// public ones when it has none), each with port 53 when it has none.
pub fn recursive_nameservers(custom: &[String]) -> Vec<String> {
    let servers: Vec<String> = if custom.is_empty() {
        let conf = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        let s: Vec<String> = conf
            .lines()
            .filter_map(|l| {
                let mut f = l.split_whitespace();
                (f.next() == Some("nameserver")).then(|| f.next().map(str::to_string))?
            })
            .collect();
        if s.is_empty() {
            ["8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53", "1.0.0.1:53"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            s
        }
    } else {
        custom.to_vec()
    };
    servers.into_iter().map(|s| with_port(&s)).collect()
}

/// s with port 53 added when it has none (an IPv6 address in brackets).
fn with_port(s: &str) -> String {
    let has_port = if let Some(rest) = s.strip_prefix('[') {
        rest.contains("]:")
    } else {
        s.matches(':').count() == 1
    };
    if has_port {
        s.to_string()
    } else if s.contains(':') {
        format!("[{s}]:53")
    } else {
        format!("{s}:53")
    }
}

struct SoaEntry {
    zone: String,
    expires: Instant,
}

static SOA_CACHE: LazyLock<Mutex<HashMap<String, SoaEntry>>> = LazyLock::new(Default::default);

/// FindZoneByFQDN.
pub async fn find_zone(fqdn: &str, nameservers: &[String]) -> Result<String, String> {
    let fqdn = if fqdn.ends_with('.') {
        fqdn.to_string()
    } else {
        format!("{fqdn}.")
    };
    if let Some(e) = SOA_CACHE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&fqdn)
        && e.expires > Instant::now()
    {
        return Ok(e.zone.clone());
    }
    let (zone, refresh) = fetch_soa(&fqdn, nameservers).await?;
    let mut cache = SOA_CACHE.lock().unwrap_or_else(|p| p.into_inner());
    if cache.len() >= 1000
        && let Some(k) = cache.keys().next().cloned()
    {
        cache.remove(&k);
    }
    cache.insert(
        fqdn,
        SoaEntry {
            zone: zone.clone(),
            expires: Instant::now() + Duration::from_secs(u64::from(refresh)),
        },
    );
    Ok(zone)
}

/// Where each label of an absolute name starts.
fn label_starts(fqdn: &str) -> Vec<usize> {
    if fqdn == "." {
        return Vec::new();
    }
    let mut out = vec![0];
    let b = fqdn.as_bytes();
    for (i, c) in b.iter().enumerate() {
        if *c == b'.' && i + 1 < b.len() {
            out.push(i + 1);
        }
    }
    out
}

async fn fetch_soa(fqdn: &str, nameservers: &[String]) -> Result<(String, u32), String> {
    let mut last: (Option<Msg>, Option<String>) = (None, None);
    for start in label_starts(fqdn) {
        let domain = &fqdn[start..];
        last = dns_query(domain, TYPE_SOA, nameservers, true).await;
        if last.1.is_some() {
            continue;
        }
        let Some(m) = &last.0 else { continue };
        match m.rcode {
            0 => {
                if m.answer.is_empty() || m.answer.iter().any(|r| matches!(r.data, Data::Cname(_)))
                {
                    continue;
                }
                for r in &m.answer {
                    if let Data::Soa { refresh } = r.data {
                        return Ok((r.name.clone(), refresh));
                    }
                }
            }
            3 => {}
            rc => {
                return Err(format!(
                    "unexpected response code '{}' for {domain}",
                    rcode_string(rc)
                ));
            }
        }
    }
    let mut parts = Vec::new();
    if let Some(m) = &last.0 {
        parts.push(rcode_string(m.rcode));
    }
    if let Some(e) = &last.1 {
        parts.push(e.clone());
    }
    let detail = if parts.is_empty() {
        String::new()
    } else {
        format!(": {}", parts.join(" "))
    };
    Err(format!(
        "could not find the start of authority for {fqdn}{detail}"
    ))
}

/// Whether a TXT record has propagated.
pub async fn check_propagation(
    fqdn: &str,
    expected: &str,
    check_authoritative: bool,
    resolvers: &[String],
) -> Result<bool, String> {
    let mut fqdn = if fqdn.ends_with('.') {
        fqdn.to_string()
    } else {
        format!("{fqdn}.")
    };
    let (m, err) = dns_query(&fqdn, TYPE_TXT, resolvers, true).await;
    if let Some(e) = err {
        return Err(format!("CNAME dns query: {e}"));
    }
    if let Some(m) = &m
        && m.rcode == 0
    {
        for r in &m.answer {
            if let Data::Cname(t) = &r.data
                && r.name == fqdn
            {
                fqdn = t.clone();
                break;
            }
        }
    }
    let servers = if check_authoritative {
        let ns = lookup_nameservers(&fqdn, resolvers)
            .await
            .map_err(|e| format!("looking up authoritative nameservers: {e}"))?;
        ns.into_iter().map(|s| with_port(&s)).collect()
    } else {
        resolvers.to_vec()
    };
    for ns in &servers {
        let (m, err) = dns_query(&fqdn, TYPE_TXT, std::slice::from_ref(ns), true).await;
        if let Some(e) = err {
            return Err(format!("querying authoritative nameservers: {e}"));
        }
        let Some(m) = m else { return Ok(false) };
        if m.rcode != 0 {
            if m.rcode == 3 || m.rcode == 2 {
                return Ok(false);
            }
            return Err(format!(
                "NS {ns} returned {} for {fqdn}",
                rcode_string(m.rcode)
            ));
        }
        for r in &m.answer {
            if let Data::Txt(t) = &r.data
                && t.concat() == expected
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// The zone's NS names, lowercased.
async fn lookup_nameservers(fqdn: &str, resolvers: &[String]) -> Result<Vec<String>, String> {
    let zone = find_zone(fqdn, resolvers)
        .await
        .map_err(|e| format!("could not determine the zone for '{fqdn}': {e}"))?;
    let (m, err) = dns_query(&zone, TYPE_NS, resolvers, true).await;
    if let Some(e) = err {
        return Err(format!(
            "querying NS resolver for zone '{zone}' recursively: {e}"
        ));
    }
    let ns: Vec<String> = m
        .map(|m| m.answer)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| match r.data {
            Data::Ns(n) => Some(n.to_lowercase()),
            _ => None,
        })
        .collect();
    if ns.is_empty() {
        return Err("could not determine authoritative nameservers".to_string());
    }
    Ok(ns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_and_ports() {
        let f = "_acme-challenge.a.example.com.";
        let starts = label_starts(f);
        let names: Vec<&str> = starts.iter().map(|i| &f[*i..]).collect();
        assert_eq!(
            names,
            vec![
                "_acme-challenge.a.example.com.",
                "a.example.com.",
                "example.com.",
                "com."
            ]
        );
        assert_eq!(with_port("10.0.0.1"), "10.0.0.1:53");
        assert_eq!(with_port("10.0.0.1:5353"), "10.0.0.1:5353");
        assert_eq!(with_port("::1"), "[::1]:53");
        assert_eq!(with_port("ns1.example.com."), "ns1.example.com.:53");
    }

    #[test]
    fn reads_soa_answers() {
        let q = query(9, "example.com.", TYPE_SOA, true).unwrap();
        // The question, then one SOA answer pointing at it.
        let qlen = q.len() - 11;
        let mut a = q[..qlen].to_vec();
        a[2] = 0x81;
        a[3] = 0x80;
        a[7] = 1;
        a[11] = 0;
        a.extend_from_slice(&[0xc0, 12, 0, 6, 0, 1, 0, 0, 0, 60]);
        let mut rdata = vec![2, b'n', b's', 0xc0, 12, 1, b'h', 0xc0, 12];
        rdata.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 77, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]);
        a.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        a.extend_from_slice(&rdata);
        let m = parse(&a, 9).unwrap();
        assert_eq!(m.answer[0].name, "example.com.");
        assert!(matches!(m.answer[0].data, Data::Soa { refresh: 77 }));
    }
}

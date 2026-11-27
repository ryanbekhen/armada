//! What the driver reads back: the node's listening sockets, the running
//! HAProxy's servers, and its counters.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use armada_node::proxy::Layout;

use super::Slot;
use crate::proxy::ServerLoad;

/// The kernel's state of a listening TCP socket in /proc/net/tcp.
const TCP_LISTEN: &str = "0A";

/// The TCP sockets listening on the node.
pub fn proc_listeners() -> Result<Vec<SocketAddr>, String> {
    let mut out = Vec::new();
    for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let b = match std::fs::read(f) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && f == "/proc/net/tcp6" => {
                continue; // IPv6 is off
            }
            Err(e) => return Err(format!("open {f}: {e}")),
            Ok(b) => b,
        };
        out.extend(parse_listeners(&b).map_err(|e| format!("{f}: {e}"))?);
    }
    Ok(out)
}

/// The listening sockets of a /proc/net/tcp{,6} table.
pub fn parse_listeners(b: &[u8]) -> Result<Vec<SocketAddr>, String> {
    let text = String::from_utf8_lossy(b);
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 || fields[3] != TCP_LISTEN {
            continue;
        }
        let Some((host, port)) = fields[1].split_once(':') else {
            return Err(format!("invalid address {:?}", fields[1]));
        };
        let p = u16::from_str_radix(port, 16).map_err(|_| format!("invalid port {port:?}"))?;
        let raw = hex(host).filter(|r| r.len() == 4 || r.len() == 16);
        let Some(mut raw) = raw else {
            return Err(format!("invalid address {host:?}"));
        };
        for w in raw.chunks_mut(4) {
            let v = u32::from_be_bytes([w[0], w[1], w[2], w[3]]);
            w.copy_from_slice(&v.to_ne_bytes());
        }
        let ip = if raw.len() == 4 {
            IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))
        } else {
            let b: [u8; 16] = raw.try_into().expect("16 bytes");
            let v6 = Ipv6Addr::from(b);
            match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            }
        };
        out.push(SocketAddr::new(ip, p));
    }
    Ok(out)
}

fn hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// The ports of the configuration another program holds, on every
/// address, or on the gateway unless the running HAProxy holds it.
pub fn busy_tcp(
    ports: &[i64],
    gateway: IpAddr,
    listeners: &[SocketAddr],
    held: &[i64],
) -> Vec<i64> {
    let mut busy = Vec::new();
    for &port in ports {
        for l in listeners {
            if i64::from(l.port()) != port {
                continue;
            }
            let a = l.ip();
            if a.is_unspecified() || (a == gateway && !held.contains(&port)) {
                busy.push(port);
                break;
            }
        }
    }
    busy
}

/// The ports of a configuration's `frontend tcp_PORT` lines,
/// sorted.
pub fn held_tcp(content: &[u8]) -> Vec<i64> {
    let text = String::from_utf8_lossy(content);
    let mut out: Vec<i64> = text
        .split('\n')
        .filter_map(|l| l.strip_prefix("frontend tcp_"))
        .filter(|d| !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit()))
        .filter_map(|d| d.parse().ok())
        .collect();
    out.sort_unstable();
    out
}

/// One server line of a configuration with its address and weight left
/// out (`    server $1$2`).
fn strip_server(line: &str) -> Option<String> {
    let rest = line.strip_prefix("    server s")?;
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 || rest.as_bytes().get(digits) != Some(&b' ') {
        return None;
    }
    let name = &rest[..digits];
    let after = &rest[digits + 1..];
    let ws = |c: char| matches!(c, '\t' | '\n' | '\x0c' | '\r' | ' ');
    let mut cookie = "";
    let mut from = 0;
    while let Some(i) = after[from..].find(" cookie ") {
        let at = from + i;
        let tail = &after[at + 8..];
        let n = tail.find(ws).unwrap_or(tail.len());
        if n > 0 {
            cookie = &after[at..at + 8 + n];
            break;
        }
        from = at + 1;
    }
    Some(format!("    server s{name}{cookie}"))
}

fn structure(b: &[u8]) -> String {
    let text = String::from_utf8_lossy(b);
    text.split('\n')
        .map(|l| strip_server(l).unwrap_or_else(|| l.to_string()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether two configurations differ only in their servers'
/// addresses and weights.
pub fn same_structure(a: &[u8], b: &[u8]) -> bool {
    structure(a) == structure(b)
}

/// The slots of a live configuration beyond which a server is not a
/// replica's.
const MAX_LIVE_SLOTS: i64 = 1 << 16;
/// srv_admin_state's maintenance bit.
const ADMIN_MAINTENANCE: i64 = 1;

/// What `show servers state` says each backend's slots
/// serve.
pub fn parse_servers_state(out: &str) -> HashMap<String, Vec<Slot>> {
    let mut col: HashMap<String, usize> = HashMap::new();
    let mut slots: HashMap<String, Vec<Slot>> = HashMap::new();
    let need = [
        "be_name",
        "srv_name",
        "srv_addr",
        "srv_admin_state",
        "srv_uweight",
        "srv_port",
    ];
    for line in out.split_inclusive('\n') {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() > 1 && f[0] == "#" {
            for (i, name) in f[1..].iter().enumerate() {
                col.insert(name.to_string(), i);
            }
            continue;
        }
        if !need
            .iter()
            .all(|c| col.get(*c).is_some_and(|&i| i < f.len()))
        {
            continue;
        }
        let at = |c: &str| f[col[c]];
        let n = match go_atoi(at("srv_name").strip_prefix('s').unwrap_or(at("srv_name"))) {
            Some(n) if (1..=MAX_LIVE_SLOTS).contains(&n) => n as usize,
            _ => continue,
        };
        let (Some(admin), Some(weight)) =
            (go_atoi(at("srv_admin_state")), go_atoi(at("srv_uweight")))
        else {
            continue;
        };
        let be = slots.entry(at("be_name").to_string()).or_default();
        while be.len() < n {
            be.push(Slot::default());
        }
        let mut s = Slot {
            addr: String::new(),
            weight,
        };
        if admin & ADMIN_MAINTENANCE == 0 {
            s.addr = format!("{}:{}", at("srv_addr"), at("srv_port"));
        }
        be[n - 1] = s;
    }
    slots
}

/// A decimal integer with an optional sign; None for anything else.
fn go_atoi(s: &str) -> Option<i64> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// The process that answers, from `show info`.
pub fn worker_pid(info: &str) -> String {
    for line in info.split_inclusive('\n') {
        if let Some(v) = line.strip_prefix("Pid:") {
            return v.trim().to_string();
        }
    }
    String::new()
}

/// A CSV record, read leniently: a quote may appear in an unquoted field,
/// and a quote in a quoted field that does not end it is kept.
fn csv_record(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut field = String::new();
    let mut chars = line.chars().peekable();
    let mut quoted = false;
    let mut start = true;
    while let Some(c) = chars.next() {
        if start && c == '"' {
            quoted = true;
            start = false;
            continue;
        }
        start = false;
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else if matches!(chars.peek(), Some(',') | None) {
                    quoted = false;
                } else {
                    field.push('"');
                }
            } else {
                field.push(c);
            }
            continue;
        }
        if c == ',' {
            out.push(std::mem::take(&mut field));
            start = true;
            continue;
        }
        field.push(c);
    }
    out.push(field);
    out
}

/// Requests in progress (scur + qcur) and sent so far (stot)
/// per replica, from `show stat`'s server rows of the `be_` backends.
pub fn parse_load(out: &str, layout: &Layout) -> Result<HashMap<String, ServerLoad>, String> {
    let text = out.strip_prefix("# ").unwrap_or(out);
    let mut lines = text
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .filter(|l| !l.is_empty());
    let Some(header) = lines.next() else {
        return Err("show stat: EOF".into());
    };
    let header = csv_record(header);
    let mut col = HashMap::new();
    for (i, h) in header.iter().enumerate() {
        col.insert(h.as_str(), i);
    }
    for c in ["pxname", "svname", "scur", "qcur", "stot"] {
        if !col.contains_key(c) {
            return Err(format!("show stat: no {c} column"));
        }
    }
    let (px, sv, scur, qcur, stot) = (
        col["pxname"],
        col["svname"],
        col["scur"],
        col["qcur"],
        col["stot"],
    );
    let top = px.max(sv).max(scur).max(qcur).max(stot);
    let mut load: HashMap<String, ServerLoad> = HashMap::new();
    for line in lines {
        let rec = csv_record(line);
        if rec.len() <= top || !rec[px].starts_with("be_") {
            continue;
        }
        let Some(slot) = rec[sv].strip_prefix('s') else {
            continue;
        };
        let Some(slots) = layout.get(&rec[px]) else {
            continue;
        };
        let i = match go_atoi(slot) {
            Some(i) if i >= 1 && (i as usize) <= slots.len() => i as usize,
            _ => continue,
        };
        let name = &slots[i - 1];
        if name.is_empty() {
            continue;
        }
        let num = |s: &str| go_atoi(s).unwrap_or(0).max(0);
        let l = load.entry(name.clone()).or_default();
        l.in_flight += num(&rec[scur]) + num(&rec[qcur]);
        l.total += num(&rec[stot]);
    }
    Ok(load)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listeners_of_proc() {
        let tcp = b"  sl  local_address rem_address   st\n   0: 0100007F:1F90 00000000:0000 0A 0\n   1: 0100780A:0050 00000000:0000 01 0\n   2: 00000000:1538 00000000:0000 0A 0\n";
        let ls = parse_listeners(tcp).unwrap();
        assert_eq!(
            ls,
            vec![
                "127.0.0.1:8080".parse().unwrap(),
                "0.0.0.0:5432".parse().unwrap()
            ]
        );
        let tcp6 = b"h\n 0: 0000000000000000FFFF00000100780A:0050 0:0 0A\n";
        assert_eq!(
            parse_listeners(tcp6).unwrap(),
            vec!["10.120.0.1:80".parse().unwrap()]
        );
        assert!(parse_listeners(b"h\n 0: zz:0050 0:0 0A\n").is_err());
        let gw: IpAddr = "10.120.0.1".parse().unwrap();
        let ls: Vec<SocketAddr> = vec![
            "10.120.0.1:5432".parse().unwrap(),
            "0.0.0.0:6379".parse().unwrap(),
        ];
        assert_eq!(
            busy_tcp(&[5432, 6379, 3306], gw, &ls, &[]),
            vec![5432, 6379]
        );
        assert_eq!(busy_tcp(&[5432, 6379], gw, &ls, &[5432]), vec![6379]);
        assert_eq!(
            held_tcp(b"x\nfrontend tcp_6379\nfrontend tcp_5432\nfrontend tcp_x\n"),
            vec![5432, 6379]
        );
    }

    #[test]
    fn structures() {
        let a = b"backend be_x\n    server s1 10.0.0.2:80 weight 1 cookie r1 check\n    server s2 0.0.0.0:0 disabled\n";
        let b = b"backend be_x\n    server s1 10.0.0.3:81 weight 9 cookie r1 inter 15s\n    server s2 10.0.0.4:80\n";
        assert!(same_structure(a, b));
        let c = b"backend be_x\n    server s1 10.0.0.3:81 cookie r2\n    server s2 10.0.0.4:80\n";
        assert!(!same_structure(a, c));
        assert!(!same_structure(b"backend be_x\n", b"backend be_y\n"));
    }

    #[test]
    fn servers_state() {
        let out = "1\n# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port\n3 be_web 1 s1 10.0.0.2 2 0 7 1 0 0 0 0 0 0 0 0 - 32768\n3 be_web 1 s3 10.0.0.3 2 1 1 1 0 0 0 0 0 0 0 0 - 32769\n3 be_web 1 other 10.0.0.3 2 0 1 1 0 0 0 0 0 0 0 0 - 1\n";
        let s = parse_servers_state(out);
        let web = &s["be_web"];
        assert_eq!(web.len(), 3);
        assert_eq!(web[0].addr, "10.0.0.2:32768");
        assert_eq!(web[0].weight, 7);
        assert_eq!(web[1], Slot::default());
        assert_eq!(web[2].addr, "");
        assert_eq!(web[2].weight, 1);
    }

    #[test]
    fn load_rows() {
        let mut layout = Layout::new();
        layout.insert("be_web".into(), vec!["web-r1".into(), "".into()]);
        let out = "# pxname,svname,qcur,qmax,scur,smax,slim,stot,\nbe_web,s1,1,0,2,0,,40,\nbe_web,s2,0,0,5,0,,9,\nbe_web,BACKEND,0,0,9,0,,99,\nfe,s1,0,0,1,0,,1,\n";
        let l = parse_load(out, &layout).unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!(
            l["web-r1"],
            ServerLoad {
                in_flight: 3,
                total: 40
            }
        );
        assert!(
            parse_load("# a,b\n", &layout)
                .unwrap_err()
                .contains("no pxname")
        );
        assert_eq!(worker_pid("Name: HAProxy\nPid: 42\n"), "42");
    }
}

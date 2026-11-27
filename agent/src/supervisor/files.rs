//! Every app container's own /etc/resolv.conf, /etc/hosts, and
//! /etc/hostname, bind-mounted read-only from <data dir>/containers/<id>/.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use armada_node::net::addr::Addr;

/// Used when the host has no usable nameserver.
const FALLBACK_DNS: [&str; 2] = ["8.8.8.8", "8.8.4.4"];

/// How many search domains a resolv.conf keeps; older C libraries read no
/// more.
const MAX_SEARCH: usize = 6;

/// The files of a container, as their host paths.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContainerFiles {
    pub resolv: String,
    pub hosts: String,
    pub hostname: String,
}

/// The lines of b: split at \n, a trailing \r dropped, the last
/// line kept when it has no newline.
fn lines(b: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = b;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let (line, next) = match rest.iter().position(|&c| c == b'\n') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, &rest[rest.len()..]),
        };
        rest = next;
        Some(line.strip_suffix(b"\r").unwrap_or(line))
    })
}

/// The whitespace-separated fields of a line read as UTF-8 (invalid bytes
/// are no space).
fn fields(line: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(line)
        .split(char::is_whitespace)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// The non-loopback nameservers in a resolv.conf.
pub fn nameservers(conf: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for line in lines(conf) {
        let f = fields(line);
        if f.len() < 2 || f[0] != "nameserver" {
            continue;
        }
        if let Some(a) = Addr::parse(&f[1])
            && !a.is_loopback()
        {
            out.push(f[1].clone());
        }
    }
    out
}

/// A container's resolv.conf: dns (or the host's non-loopback
/// nameservers, or the fallback), one search line with search first and
/// then the host's domains (resolvers use only the last search line), and
/// the host's options lines.
pub fn resolv_conf(host: &[u8], dns: &[String], search: &[String]) -> Vec<u8> {
    let mut servers: Vec<String> = dns.to_vec();
    if servers.is_empty() {
        servers = nameservers(host);
    }
    if servers.is_empty() {
        servers = FALLBACK_DNS.iter().map(|s| s.to_string()).collect();
    }
    let mut b = String::new();
    for s in &servers {
        b.push_str("nameserver ");
        b.push_str(s);
        b.push('\n');
    }
    let mut domains: Vec<String> = search.to_vec();
    let mut options = Vec::new();
    for line in lines(host) {
        let f = fields(line);
        if f.len() >= 2 && f[0] == "search" {
            // The last search line wins, as in the resolver.
            domains = search.to_vec();
            domains.extend(f[1..].iter().cloned());
        } else if f.len() >= 2 && f[0] == "options" {
            options.push(f.join(" "));
        }
    }
    let mut kept: Vec<String> = Vec::new();
    for d in domains {
        if d != "." && !kept.contains(&d) && kept.len() < MAX_SEARCH {
            kept.push(d);
        }
    }
    if !kept.is_empty() {
        b.push_str(&format!("search {}\n", kept.join(" ")));
    }
    for o in options {
        b.push_str(&o);
        b.push('\n');
    }
    b.into_bytes()
}

pub fn hosts_file(ip: &str, hostname: &str) -> Vec<u8> {
    let mut s = String::from("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n");
    if !ip.is_empty() {
        s.push_str(&format!("{ip}\t{hostname}\n"));
    }
    s.into_bytes()
}

/// A valid hostname for container id (the spec's own rule, shared).
pub fn hostname(id: &str) -> String {
    armada_node::runtime::container_hostname(id)
}

/// The host's resolver configuration. A systemd-resolved stub
/// (127.0.0.53) is unreachable from a container's network namespace, so
/// the upstream list is used instead.
pub fn host_resolv_conf(etc: &Path, resolved: &Path) -> Vec<u8> {
    let b = fs::read(etc).unwrap_or_default();
    if nameservers(&b).is_empty()
        && let Ok(up) = fs::read(resolved)
    {
        return up;
    }
    b
}

/// Creates the files under dir/<id>; the hostname is the container's name.
/// They are world-readable (processes in the container may run as any
/// user); the 0700 parent keeps them private on the host.
pub fn write_files(
    dir: &Path,
    id: &str,
    name: &str,
    ip: &str,
    dns: &[String],
    search: &[String],
    host_resolv: &[u8],
) -> Result<ContainerFiles, String> {
    let d = dir.join(id);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&d)
        .map_err(|e| super::os_err("mkdir", &d, &e))?;
    let path = |n: &str| -> PathBuf { d.join(n) };
    let f = ContainerFiles {
        resolv: path("resolv.conf").display().to_string(),
        hosts: path("hosts").display().to_string(),
        hostname: path("hostname").display().to_string(),
    };
    let h = hostname(name);
    for (p, data) in [
        (&f.resolv, resolv_conf(host_resolv, dns, search)),
        (&f.hosts, hosts_file(ip, &h)),
        (&f.hostname, format!("{h}\n").into_bytes()),
    ] {
        let p = Path::new(p);
        fs::write(p, data).map_err(|e| super::os_err("open", p, &e))?;
        // The units run with UMask=0077, which the mode at creation does
        // not override: without this a process that is not root in the
        // container cannot read its resolv.conf.
        fs::set_permissions(p, fs::Permissions::from_mode(0o644))
            .map_err(|e| super::os_err("chmod", p, &e))?;
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn resolv_conf_from_the_host_file() {
        let host = b"nameserver 127.0.0.53\r\nsearch a.example b.example\noptions edns0 trust-ad\nsearch c.example .\n";
        assert_eq!(
            String::from_utf8(resolv_conf(host, &[], &s(&["internal"]))).unwrap(),
            "nameserver 8.8.8.8\nnameserver 8.8.4.4\nsearch internal c.example\noptions edns0 trust-ad\n"
        );
        let host = b"nameserver 10.0.0.2\nnameserver ::1\n";
        assert_eq!(
            String::from_utf8(resolv_conf(host, &[], &[])).unwrap(),
            "nameserver 10.0.0.2\n"
        );
        let many = s(&["a", "b", "a", "c", "d", "e", "f", "g"]);
        assert_eq!(
            String::from_utf8(resolv_conf(b"", &s(&["10.121.0.1"]), &many)).unwrap(),
            "nameserver 10.121.0.1\nsearch a b c d e f\n"
        );
    }

    #[test]
    fn hosts_and_hostnames() {
        assert_eq!(
            String::from_utf8(hosts_file("10.121.0.5", "web")).unwrap(),
            "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n10.121.0.5\tweb\n"
        );
        assert_eq!(hostname("_web_r1."), "web-r1");
    }
}

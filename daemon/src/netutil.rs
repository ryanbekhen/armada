//! The address checks of Go's internal/netutil the machine commands use,
//! and the machine's interfaces as Go's net package lists them.

use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use armada_spec::go::{parse_addr, quote};

/// netutil.IsPrivate: RFC 1918, IPv6 ULA, loopback, or carrier-grade NAT.
pub fn is_private(ip: &IpAddr) -> bool {
    let ip = unmap(ip);
    match ip {
        IpAddr::V4(v) => {
            let b = v.octets();
            v.is_private() || v.is_loopback() || (b[0] == 100 && b[1] & 0xc0 == 64)
        }
        IpAddr::V6(v) => v.octets()[0] & 0xfe == 0xfc || v.is_loopback(),
    }
}

/// Addr.Unmap.
pub fn unmap(ip: &IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => match v.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => *ip,
        },
        _ => *ip,
    }
}

/// Addr.IsGlobalUnicast.
fn is_global_unicast(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !(v.is_unspecified()
                || *v == Ipv4Addr::BROADCAST
                || v.is_loopback()
                || v.is_multicast()
                || v.is_link_local())
        }
        IpAddr::V6(v) => {
            !(v.is_unspecified()
                || v.is_loopback()
                || v.is_multicast()
                || v.segments()[0] & 0xffc0 == 0xfe80)
        }
    }
}

/// netutil.CheckEndpoint.
pub fn check_endpoint(s: &str) -> Result<Ipv4Addr, String> {
    let a = match parse_addr(s) {
        Some(a) if a.is4 && a.string() == s => a,
        _ => {
            return Err(format!(
                "invalid endpoint {}: want an IPv4 address",
                quote(s)
            ));
        }
    };
    let v = Ipv4Addr::new(a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3]);
    let ip = IpAddr::V4(v);
    if !is_global_unicast(&ip) || v.is_loopback() || v == Ipv4Addr::BROADCAST {
        return Err(format!(
            "endpoint {v} is not a unicast address other machines can reach"
        ));
    }
    Ok(v)
}

/// netutil.CheckPrivateIP.
pub fn check_private_ip(s: &str) -> Result<IpAddr, String> {
    let a = match parse_addr(s) {
        Some(a) if a.zone.is_empty() => a,
        _ => return Err(format!("invalid IP address {}", quote(s))),
    };
    let u = a.unmap();
    if u.string() != s {
        return Err(format!(
            "IP address {} is not in canonical form (want {})",
            quote(s),
            u.string()
        ));
    }
    let ip = to_std(&u);
    if !is_private(&ip) {
        return Err(format!(
            "{s}: address is not private; internal services must bind to a private (VPC) or loopback address"
        ));
    }
    Ok(ip)
}

/// The standard library's address of a netip one.
pub fn to_std(a: &armada_spec::go::Addr) -> IpAddr {
    if a.is4 {
        IpAddr::V4(Ipv4Addr::new(
            a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3],
        ))
    } else {
        IpAddr::V6(Ipv6Addr::from(a.bytes))
    }
}

/// One address of an interface.
#[derive(Clone, Debug)]
pub struct IfaceAddr {
    pub name: String,
    pub ip: IpAddr,
}

/// Every address of every interface, in Go's order: interfaces by index,
/// each one's addresses as the kernel lists them (IPv4 first). With up,
/// only interfaces that are up, not loopback, and not container or VM
/// bridges (interfaceAddrs).
pub fn interface_addrs(up_only: bool) -> Vec<IfaceAddr> {
    let mut raw: Vec<(u32, String, IpAddr)> = Vec::new();
    // SAFETY: getifaddrs fills a list freed below; every pointer read is
    // one of its entries.
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return Vec::new();
        }
        let mut p = head;
        while !p.is_null() {
            let e = &*p;
            p = e.ifa_next;
            if e.ifa_addr.is_null() || e.ifa_name.is_null() {
                continue;
            }
            let flags = e.ifa_flags;
            if up_only
                && (flags & libc::IFF_UP as u32 == 0 || flags & libc::IFF_LOOPBACK as u32 != 0)
            {
                continue;
            }
            let name = CStr::from_ptr(e.ifa_name).to_string_lossy().into_owned();
            let ip = match i32::from((*e.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let sa = &*(e.ifa_addr as *const libc::sockaddr_in);
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)))
                }
                libc::AF_INET6 => {
                    let sa = &*(e.ifa_addr as *const libc::sockaddr_in6);
                    IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr))
                }
                _ => continue,
            };
            let index = libc::if_nametoindex(e.ifa_name);
            raw.push((index, name, ip));
        }
        libc::freeifaddrs(head);
    }
    // Stable: the kernel's order within an interface, IPv4 before IPv6.
    raw.sort_by_key(|(i, _, ip)| (*i, ip.is_ipv6()));
    raw.into_iter()
        .filter(|(_, name, _)| !up_only || !virtual_interface(name))
        .map(|(_, name, ip)| IfaceAddr { name, ip })
        .collect()
}

/// virtualInterface.
fn virtual_interface(name: &str) -> bool {
    [
        "docker", "br-", "veth", "cni", "flannel", "virbr", "lxc", "lxd", "podman", "tun", "tap",
        "wg", "armada",
    ]
    .iter()
    .any(|p| name.starts_with(p))
}

/// netutil.DetectEndpoint.
pub fn detect_endpoint() -> Result<Ipv4Addr, String> {
    one_endpoint(&interface_addrs(true))
}

fn one_endpoint(found: &[IfaceAddr]) -> Result<Ipv4Addr, String> {
    let mut ips = Vec::new();
    let mut names = Vec::new();
    for f in found {
        let ip = unmap(&f.ip);
        let IpAddr::V4(v) = ip else { continue };
        if check_endpoint(&v.to_string()).is_err() || is_private(&ip) {
            continue;
        }
        ips.push(v);
        names.push(format!("{v} on {}", f.name));
    }
    match ips.len() {
        0 => Err("no public IPv4 address on this machine's interfaces; pass --endpoint (behind one-to-one NAT, the public address the provider maps to this machine)".to_string()),
        1 => Ok(ips[0]),
        _ => Err(format!(
            "several public addresses ({}); pass --endpoint",
            names.join(", ")
        )),
    }
}

/// The private addresses of the machine's interfaces (etcd's hostAddrs).
pub fn private_host_addrs() -> Vec<IpAddr> {
    interface_addrs(false)
        .into_iter()
        .map(|a| unmap(&a.ip))
        .filter(is_private)
        .collect()
}

/// Whether ip is assigned to an interface (backup's hostHasIP).
pub fn host_has_ip(ip: &IpAddr) -> bool {
    interface_addrs(false).iter().any(|a| unmap(&a.ip) == *ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        assert!(check_endpoint("203.0.113.7").is_ok());
        assert_eq!(
            check_endpoint("10.0.0.1x").unwrap_err(),
            "invalid endpoint \"10.0.0.1x\": want an IPv4 address"
        );
        assert_eq!(
            check_endpoint("127.0.0.1").unwrap_err(),
            "endpoint 127.0.0.1 is not a unicast address other machines can reach"
        );
        let found = |ips: &[&str]| -> Vec<IfaceAddr> {
            ips.iter()
                .map(|s| IfaceAddr {
                    name: "eth0".into(),
                    ip: s.parse().unwrap(),
                })
                .collect()
        };
        assert_eq!(
            one_endpoint(&found(&["10.0.0.5", "203.0.113.7"])).unwrap(),
            Ipv4Addr::new(203, 0, 113, 7)
        );
        assert!(one_endpoint(&found(&["10.0.0.5"])).is_err());
        assert!(is_private(&"100.64.1.1".parse().unwrap()));
    }
}

//! The address checks of Go's internal/netutil the server uses.

use std::net::IpAddr;

use armada_spec::go::{Addr, parse_addr, parse_prefix, quote};

fn std_ip(a: &Addr) -> IpAddr {
    if a.is4 {
        IpAddr::from([a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3]])
    } else {
        IpAddr::from(a.bytes)
    }
}

fn is_loopback(a: &Addr) -> bool {
    std_ip(&a.unmap()).is_loopback()
}

/// netutil.IsPrivate: RFC 1918, IPv6 ULA, loopback, or carrier-grade NAT,
/// never with a zone.
pub fn is_private(a: &Addr) -> bool {
    if !a.zone.is_empty() {
        return false;
    }
    let u = a.unmap();
    let cgnat = parse_prefix("100.64.0.0/10").expect("a valid prefix");
    u.is_private() || is_loopback(&u) || cgnat.contains(&u)
}

/// netutil.CheckPrivateIP.
pub fn check_private_ip(s: &str) -> Result<Addr, String> {
    let addr = match parse_addr(s) {
        Some(a) if a.zone.is_empty() => a,
        _ => return Err(format!("invalid IP address {}", quote(s))),
    };
    let u = addr.unmap();
    if u.string() != s {
        return Err(format!(
            "IP address {} is not in canonical form (want {})",
            quote(s),
            u.string()
        ));
    }
    if !is_private(&addr) {
        return Err(format!(
            "{s}: address is not private; internal services must bind to a private (VPC) or loopback address"
        ));
    }
    Ok(u)
}

/// netutil.CheckNodeIP.
pub fn check_node_ip(s: &str) -> Result<Addr, String> {
    let a = check_private_ip(s)?;
    if is_loopback(&a) {
        return Err(format!("{s}: a node IP must not be a loopback address"));
    }
    Ok(a)
}

/// netutil.CheckEndpoint.
pub fn check_endpoint(s: &str) -> Result<Addr, String> {
    let a = match parse_addr(s) {
        Some(a) if a.is4 && a.string() == s => a,
        _ => {
            return Err(format!(
                "invalid endpoint {}: want an IPv4 address",
                quote(s)
            ));
        }
    };
    let ip = std_ip(&a);
    let global = match ip {
        IpAddr::V4(v) => {
            !(v.is_unspecified()
                || v.is_broadcast()
                || v.is_multicast()
                || v.is_link_local()
                || v.is_loopback())
        }
        IpAddr::V6(_) => false,
    };
    if !global || ip.is_loopback() || a.bytes[..4] == [255; 4] {
        return Err(format!(
            "endpoint {} is not a unicast address other machines can reach",
            a.string()
        ));
    }
    Ok(a)
}

/// The address an [`Addr`] is, for the standard library.
pub fn ip_of(a: &Addr) -> IpAddr {
    std_ip(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks() {
        assert!(check_node_ip("10.0.0.1").is_ok());
        assert!(check_node_ip("127.0.0.1").is_err());
        assert!(check_node_ip("8.8.8.8").is_err());
        assert!(check_node_ip("10.0.0.01").is_err());
        assert!(check_endpoint("8.8.8.8").is_ok());
        assert!(check_endpoint("127.0.0.1").is_err());
        assert!(check_endpoint("224.0.0.1").is_err());
        assert!(check_endpoint("::1").is_err());
    }
}

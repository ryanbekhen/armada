//! The probe of a switch's prepare step (switch_linux.go's ping): an ICMP
//! echo request from this node's tunnel address to every peer's, which the
//! prepare step routes over Next, counting the peers whose reply came in
//! through Next within the wait.

use super::addr::Addr;
use super::plan::{NEXT, Peer};
use super::rules::vtep_addr;
use std::collections::BTreeMap;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

const ICMP_ECHO: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

fn checksum(b: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in b.chunks(2) {
        let w = if c.len() == 2 {
            u16::from_be_bytes([c[0], c[1]])
        } else {
            u16::from_be_bytes([c[0], 0])
        };
        sum += u32::from(w);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An echo request as icmp.Message.Marshal writes it.
pub fn echo(id: u16, seq: u16) -> Vec<u8> {
    let mut b = vec![ICMP_ECHO, 0, 0, 0];
    b.extend(id.to_be_bytes());
    b.extend(seq.to_be_bytes());
    b.extend(b"armada");
    let c = checksum(&b);
    b[2..4].copy_from_slice(&c.to_be_bytes());
    b
}

/// The echo reply's identifier in an IPv4 packet, when it is one.
pub fn reply_id(packet: &[u8]) -> Option<u16> {
    let ihl = usize::from(packet.first()? & 0x0f) * 4;
    let icmp = packet.get(ihl..)?;
    if icmp.len() < 8 || icmp[0] != ICMP_ECHO_REPLY {
        return None;
    }
    Some(u16::from_be_bytes([icmp[4], icmp[5]]))
}

fn random_id() -> u16 {
    let mut b = [0u8; 2];
    // SAFETY: b is valid for its length.
    unsafe {
        libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0);
    }
    (std::process::id() as u16) ^ u16::from_ne_bytes(b)
}

fn sockaddr(ip: [u8; 4]) -> libc::sockaddr_in {
    // SAFETY: a zeroed sockaddr_in is valid.
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_addr.s_addr = u32::from_ne_bytes(ip);
    sa
}

/// ping: the peers whose echo reply came in through Next within wait.
pub fn ping(from: &Addr, peers: &[Peer], wait: Duration) -> Result<BTreeMap<String, bool>, String> {
    let mut reached = BTreeMap::new();
    if peers.is_empty() {
        return Ok(reached);
    }
    let name = std::ffi::CString::new(NEXT).map_err(|e| e.to_string())?;
    // SAFETY: name is a valid C string.
    let next = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if next == 0 {
        return Err(format!("route ip+net: no such network interface {NEXT}"));
    }
    let Addr::V4(self_ip) = from else {
        return Err(format!("open an ICMP socket: {from} is not IPv4"));
    };
    // SAFETY: plain system calls on a descriptor this function owns.
    let fd = unsafe {
        let fd = libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_ICMP,
        );
        if fd < 0 {
            return Err(format!(
                "open an ICMP socket: {}",
                io::Error::last_os_error()
            ));
        }
        OwnedFd::from_raw_fd(fd)
    };
    let raw = fd.as_raw_fd();
    let sa = sockaddr(*self_ip);
    let on: libc::c_int = 1;
    // SAFETY: the arguments are valid for their lengths.
    unsafe {
        if libc::bind(
            raw,
            (&raw const sa).cast(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) < 0
        {
            return Err(format!(
                "open an ICMP socket: {}",
                io::Error::last_os_error()
            ));
        }
        if libc::setsockopt(
            raw,
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            (&raw const on).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        ) < 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
    }
    let id = random_id();
    let mut by_addr = BTreeMap::new();
    for (i, pe) in peers.iter().enumerate() {
        let Addr::V4(to) = vtep_addr(pe.subnet()) else {
            continue;
        };
        by_addr.insert(to, pe.node.clone());
        let b = echo(id, i as u16);
        let dst = sockaddr(to);
        // SAFETY: b and dst are valid for their lengths; a failed send is
        // skipped as Go skips it.
        unsafe {
            libc::sendto(
                raw,
                b.as_ptr().cast(),
                b.len(),
                0,
                (&raw const dst).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
        }
    }
    let deadline = Instant::now() + wait;
    let mut buf = [0u8; 1500];
    let mut cbuf = [0u8; 128];
    while reached.len() < peers.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let tv = libc::timeval {
            tv_sec: left.as_secs() as _,
            tv_usec: left.subsec_micros().max(1) as _,
        };
        // SAFETY: every pointer is valid for its length during the calls.
        let (n, from, ifindex) = unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast(),
                size_of::<libc::timeval>() as libc::socklen_t,
            );
            let mut src: libc::sockaddr_in = std::mem::zeroed();
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            };
            let mut mh: libc::msghdr = std::mem::zeroed();
            mh.msg_name = (&raw mut src).cast();
            mh.msg_namelen = size_of::<libc::sockaddr_in>() as libc::socklen_t;
            mh.msg_iov = &raw mut iov;
            mh.msg_iovlen = 1;
            mh.msg_control = cbuf.as_mut_ptr().cast();
            mh.msg_controllen = cbuf.len() as _;
            let n = libc::recvmsg(raw, &raw mut mh, 0);
            if n < 0 {
                let e = io::Error::last_os_error();
                if matches!(e.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)) {
                    continue;
                }
                return Err(e.to_string());
            }
            let mut ifindex = 0;
            let mut cm = libc::CMSG_FIRSTHDR(&raw const mh);
            while !cm.is_null() {
                if (*cm).cmsg_level == libc::IPPROTO_IP && (*cm).cmsg_type == libc::IP_PKTINFO {
                    let info = libc::CMSG_DATA(cm)
                        .cast::<libc::in_pktinfo>()
                        .read_unaligned();
                    ifindex = info.ipi_ifindex as u32;
                }
                cm = libc::CMSG_NXTHDR(&raw const mh, cm);
            }
            (n as usize, src.sin_addr.s_addr.to_ne_bytes(), ifindex)
        };
        if ifindex != next || reply_id(&buf[..n]) != Some(id) {
            continue;
        }
        if let Some(node) = by_addr.get(&from) {
            reached.insert(node.clone(), true);
        }
    }
    Ok(reached)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_requests_carry_their_checksum() {
        let b = echo(0x1234, 1);
        assert_eq!(b[0], 8);
        assert_eq!(&b[4..8], &[0x12, 0x34, 0, 1]);
        // The checksum of a packet with its checksum in is zero.
        assert_eq!(checksum(&b), 0);
        assert_eq!(&b[8..], b"armada");
    }

    #[test]
    fn replies_are_read_past_the_ip_header() {
        let mut packet = vec![0x45u8];
        packet.extend([0u8; 19]);
        packet.extend([0, 0, 0, 0, 0xab, 0xcd, 0, 1]);
        assert_eq!(reply_id(&packet), Some(0xabcd));
        packet[20] = 8;
        assert_eq!(reply_id(&packet), None);
    }
}

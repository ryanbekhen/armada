//! Dialling from a container's or a sandbox's network namespace: the
//! socket is made on this process's only thread after it switched into
//! the namespace, so it has exactly the namespace's routes and firewall,
//! and the connected socket is handed to the caller over SCM_RIGHTS on the
//! Unix socket it passes as file descriptor 3. Only IP addresses reach
//! here: the caller checked the address and picked the family, and keeps
//! names, zones, and service names.

use super::bundle;
use super::stats::{Located, locate};
use serde::Deserialize;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

/// What `runtime dial` reads.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct DialRequest {
    /// A container: the bundles' and shims' directories and its ID.
    pub dir: String,
    #[serde(rename = "shimDir")]
    pub shim_dir: String,
    pub id: String,
    pub proc: String,
    /// Or a pinned network namespace (a sandbox).
    pub netns: String,
    /// "tcp" or "udp".
    pub kind: String,
    /// The address, family 4 or 6, port, and IPV6_V6ONLY for family 6.
    pub ip: String,
    pub family: u8,
    pub port: u16,
    pub v6only: bool,
    #[serde(rename = "timeoutMs")]
    pub timeout_ms: u64,
}

/// How a dial ended.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    Connected(i32),
    NotFound,
    Redo(String),
    /// Opening the namespace failed with this errno.
    Netns(i32),
    /// Switching into it failed.
    Setns(i32),
    /// A system call of the dial failed (socket, setsockopt, connect,
    /// getsockopt).
    Op(&'static str, i32),
    Timeout,
}

fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn open_ns(path: &str) -> Result<OwnedFd, i32> {
    let c = std::ffi::CString::new(path).map_err(|_| libc::EINVAL)?;
    // SAFETY: a NUL-terminated path; the descriptor is owned below.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(errno());
    }
    // SAFETY: fd was just opened and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Switches this thread into the namespace ns, unless it is already in it.
fn enter(ns: &OwnedFd) -> Result<(), i32> {
    // SAFETY: borrowing a descriptor this function does not close.
    let target = unsafe { File::from_raw_fd(ns.as_raw_fd()) };
    let target = std::mem::ManuallyDrop::new(target);
    let same = match (
        target.metadata(),
        std::fs::metadata("/proc/thread-self/ns/net"),
    ) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    };
    if same {
        return Ok(());
    }
    // SAFETY: setns on a valid descriptor; this process has one thread.
    if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        return Err(errno());
    }
    Ok(())
}

fn setsockopt_int(fd: RawFd, level: i32, opt: i32, v: i32) -> i32 {
    // SAFETY: a pointer to an int and its size.
    unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            (&v as *const i32).cast(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }
}

/// The socket address of ip and port.
fn sockaddr(r: &DialRequest) -> Option<(libc::sockaddr_storage, libc::socklen_t)> {
    // SAFETY: an all-zero sockaddr_storage is valid.
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match r.family {
        4 => {
            let ip: std::net::Ipv4Addr = r.ip.parse().ok()?;
            // SAFETY: sockaddr_storage is large enough and aligned for sockaddr_in.
            let sa = unsafe { &mut *(&raw mut ss).cast::<libc::sockaddr_in>() };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_port = r.port.to_be();
            sa.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
            Some((
                ss,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ))
        }
        6 => {
            let ip: std::net::Ipv6Addr = r.ip.parse().ok()?;
            // SAFETY: as above, for sockaddr_in6.
            let sa = unsafe { &mut *(&raw mut ss).cast::<libc::sockaddr_in6>() };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_port = r.port.to_be();
            sa.sin6_addr.s6_addr = ip.octets();
            Some((
                ss,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            ))
        }
        _ => None,
    }
}

/// Waits until fd is writable or the deadline passes (false).
fn writable(fd: RawFd, deadline: Option<Instant>) -> Result<bool, i32> {
    loop {
        let ms = match deadline {
            None => -1,
            Some(d) => {
                let left = d.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Ok(false);
                }
                left.as_millis().clamp(1, i32::MAX as u128) as i32
            }
        };
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: one pollfd.
        let n = unsafe { libc::poll(&mut p, 1, ms) };
        match n {
            n if n > 0 => return Ok(true),
            0 => {}
            _ if errno() == libc::EINTR => {}
            _ => return Err(errno()),
        }
    }
}

/// The dial itself, in the namespace: a nonblocking socket, the default
/// socket options, and the connect.
pub fn connect(r: &DialRequest, deadline: Option<Instant>) -> Outcome {
    let Some((sa, len)) = sockaddr(r) else {
        return Outcome::Redo(format!("address {} of family {}", r.ip, r.family));
    };
    let ty = match r.kind.as_str() {
        "tcp" => libc::SOCK_STREAM,
        "udp" => libc::SOCK_DGRAM,
        k => return Outcome::Redo(format!("network {k}")),
    };
    let family = if r.family == 4 {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: socket(2) with constant arguments.
    let fd = unsafe { libc::socket(family, ty | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Outcome::Op("socket", errno());
    }
    // SAFETY: fd was just made and nothing else owns it.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    if family == libc::AF_INET6 {
        // This one's error is ignored.
        setsockopt_int(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            i32::from(r.v6only),
        );
    }
    if ty == libc::SOCK_DGRAM && setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_BROADCAST, 1) != 0 {
        return Outcome::Op("setsockopt", errno());
    }
    // SAFETY: a socket address of len bytes.
    let rc = unsafe { libc::connect(fd, (&raw const sa).cast(), len) };
    if rc == 0 {
        return Outcome::Connected(std::os::fd::IntoRawFd::into_raw_fd(sock));
    }
    match errno() {
        libc::EINPROGRESS | libc::EALREADY | libc::EINTR => {}
        libc::EISCONN => return Outcome::Connected(std::os::fd::IntoRawFd::into_raw_fd(sock)),
        e => return Outcome::Op("connect", e),
    }
    loop {
        match writable(fd, deadline) {
            Ok(true) => {}
            Ok(false) => return Outcome::Timeout,
            Err(e) => return Outcome::Op("connect", e),
        }
        let mut v: i32 = 0;
        let mut l = std::mem::size_of::<i32>() as libc::socklen_t;
        // SAFETY: an int and its size.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut v).cast(),
                &mut l,
            )
        } != 0
        {
            return Outcome::Op("getsockopt", errno());
        }
        match v {
            libc::EINPROGRESS | libc::EALREADY | libc::EINTR => continue,
            0 | libc::EISCONN => {
                if v == 0 {
                    // SAFETY: an all-zero sockaddr_storage and its size.
                    let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                    let mut pl = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                    // SAFETY: getpeername into a large enough buffer.
                    if unsafe { libc::getpeername(fd, (&raw mut peer).cast(), &mut pl) } != 0 {
                        continue;
                    }
                }
                return Outcome::Connected(std::os::fd::IntoRawFd::into_raw_fd(sock));
            }
            e => return Outcome::Op("connect", e),
        }
    }
}

/// Switches into the network namespace the request names: the
/// container's (found through its bundle and shim) or a pinned one.
pub fn enter_target(r: &DialRequest, deadline: Option<Instant>) -> Result<(), Outcome> {
    let path = if r.id.is_empty() {
        r.netns.clone()
    } else {
        let (recs, skipped) = bundle::records(&r.dir).map_err(Outcome::Redo)?;
        if let Some(s) = skipped.iter().find(|s| s.id == r.id) {
            return Err(Outcome::Redo(s.error.clone()));
        }
        let Some(rec) = recs.iter().find(|x| x.id == r.id) else {
            return Err(Outcome::NotFound);
        };
        match locate(&r.shim_dir, rec, deadline) {
            Located::Task(pid) => format!("{}/{pid}/ns/net", r.proc.trim_end_matches('/')),
            Located::NotFound => return Err(Outcome::NotFound),
            Located::Redo(why) => return Err(Outcome::Redo(why)),
        }
    };
    let ns = open_ns(&path).map_err(Outcome::Netns)?;
    enter(&ns).map_err(Outcome::Setns)
}

/// Dials from a container (a request with an ID) or a sandbox (with a
/// namespace's path) once the caller checked the address.
pub fn dial(r: &DialRequest) -> Outcome {
    let deadline = (r.timeout_ms > 0).then(|| Instant::now() + Duration::from_millis(r.timeout_ms));
    if let Err(o) = enter_target(r, deadline) {
        return o;
    }
    connect(r, deadline)
}

/// Sends fd over the Unix socket to, with one byte of data.
pub fn send_fd(to: RawFd, fd: RawFd) -> Result<(), String> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // SAFETY: CMSG_SPACE of one descriptor.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut cbuf = vec![0u8; space];
    // SAFETY: an all-zero msghdr is valid; its pointers are set below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    // SAFETY: the control buffer holds one header and one descriptor.
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            (&raw const fd).cast::<u8>(),
            libc::CMSG_DATA(c),
            std::mem::size_of::<RawFd>(),
        );
    }
    // SAFETY: a message built above.
    if unsafe { libc::sendmsg(to, &msg, libc::MSG_NOSIGNAL) } != 1 {
        return Err(format!(
            "send the connection: {}",
            super::errno_text(errno())
        ));
    }
    Ok(())
}

pub fn outcome_json(o: &Outcome) -> serde_json::Value {
    match o {
        Outcome::Connected(_) => serde_json::json!({ "connected": true }),
        Outcome::NotFound => serde_json::json!({ "notFound": true }),
        Outcome::Redo(why) => serde_json::json!({ "redo": why }),
        Outcome::Netns(e) => serde_json::json!({ "netns": e }),
        Outcome::Setns(e) => serde_json::json!({ "setns": e }),
        Outcome::Op(op, e) => serde_json::json!({ "op": op, "errno": e }),
        Outcome::Timeout => serde_json::json!({ "timeout": true }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The namespace the thread is already in is not entered again:
    /// setns needs CAP_SYS_ADMIN even for one's own namespace, so a dial
    /// from it works without the privilege.
    #[test]
    fn stays_in_its_own_namespace() {
        let own = open_ns("/proc/thread-self/ns/net").unwrap();
        assert_eq!(enter(&own), Ok(()));
        assert!(open_ns("/proc/nonexistent/ns/net").is_err());
    }
}

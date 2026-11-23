//! Netlink messages, built as the Go agent's libraries build them
//! (vishvananda/netlink for routing, mdlayher/netlink for generic netlink:
//! both pad every attribute to four bytes and give a nested attribute the
//! length of its padded children), and a socket that sends one request at a
//! time and reads its answer: the messages that answer it, then the
//! acknowledgement, the end of a dump, or an error.
//!
//! Messages are built with sequence number and port ID 0, so tests compare
//! them with what Go's libraries send; the socket numbers them.

use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub const NETLINK_ROUTE: i32 = 0;
pub const NETLINK_GENERIC: i32 = 16;

pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_MULTI: u16 = 0x2;
pub const NLM_F_ACK: u16 = 0x4;
pub const NLM_F_DUMP: u16 = 0x300;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLA_F_NESTED: u16 = 0x8000;
const NLA_TYPE_MASK: u16 = 0x3fff;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const HEADER: usize = 16;

/// An error number, printed as Go prints a syscall.Errno.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Errno(pub i32);

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SAFETY: strerror returns a valid C string for any number; it is
        // copied before anything else can call it on this thread.
        let text = unsafe {
            std::ffi::CStr::from_ptr(libc::strerror(self.0))
                .to_string_lossy()
                .into_owned()
        };
        let mut chars = text.chars();
        match chars.next() {
            Some(c) => write!(f, "{}{}", c.to_lowercase(), chars.as_str()),
            None => write!(f, "errno {}", self.0),
        }
    }
}

impl From<io::Error> for Errno {
    fn from(e: io::Error) -> Errno {
        Errno(e.raw_os_error().unwrap_or(libc::EIO))
    }
}

/// One message before it is numbered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Msg {
    pub ty: u16,
    pub flags: u16,
    pub body: Vec<u8>,
}

impl Msg {
    /// The message as it goes out, numbered seq from port pid.
    pub fn bytes(&self, seq: u32, pid: u32) -> Vec<u8> {
        let mut b = Vec::with_capacity(HEADER + self.body.len());
        b.extend(((HEADER + self.body.len()) as u32).to_ne_bytes());
        b.extend(self.ty.to_ne_bytes());
        b.extend(self.flags.to_ne_bytes());
        b.extend(seq.to_ne_bytes());
        b.extend(pid.to_ne_bytes());
        b.extend(&self.body);
        b
    }

    /// Its text for tests: hex with sequence number and port 0.
    pub fn hex(&self) -> String {
        self.bytes(0, 0)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// Attributes being written.
#[derive(Default)]
pub struct Attrs {
    pub b: Vec<u8>,
}

impl Attrs {
    pub fn new() -> Attrs {
        Attrs::default()
    }

    /// One attribute: its length counts the data, not the padding.
    pub fn put(&mut self, ty: u16, data: &[u8]) -> &mut Attrs {
        self.b.extend(((4 + data.len()) as u16).to_ne_bytes());
        self.b.extend(ty.to_ne_bytes());
        self.b.extend(data);
        while !self.b.len().is_multiple_of(4) {
            self.b.push(0);
        }
        self
    }

    pub fn u8(&mut self, ty: u16, v: u8) -> &mut Attrs {
        self.put(ty, &[v])
    }

    pub fn u16(&mut self, ty: u16, v: u16) -> &mut Attrs {
        self.put(ty, &v.to_ne_bytes())
    }

    pub fn u32(&mut self, ty: u16, v: u32) -> &mut Attrs {
        self.put(ty, &v.to_ne_bytes())
    }

    /// A string with its terminating NUL.
    pub fn cstr(&mut self, ty: u16, s: &str) -> &mut Attrs {
        let mut d = s.as_bytes().to_vec();
        d.push(0);
        self.put(ty, &d)
    }

    /// A nested attribute whose children f writes.
    pub fn nested(&mut self, ty: u16, f: impl FnOnce(&mut Attrs)) -> &mut Attrs {
        let mut inner = Attrs::new();
        f(&mut inner);
        self.b.extend(((4 + inner.b.len()) as u16).to_ne_bytes());
        self.b.extend(ty.to_ne_bytes());
        self.b.extend(inner.b);
        self
    }
}

/// The attributes in b as (type without its flags, data).
pub fn attrs(mut b: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while b.len() >= 4 {
        let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
        let ty = u16::from_ne_bytes([b[2], b[3]]) & NLA_TYPE_MASK;
        if len < 4 || len > b.len() {
            break;
        }
        out.push((ty, &b[4..len]));
        b = &b[len.next_multiple_of(4).min(b.len())..];
    }
    out
}

pub fn ne_u16(b: &[u8]) -> u16 {
    b.get(..2)
        .map(|s| u16::from_ne_bytes([s[0], s[1]]))
        .unwrap_or(0)
}

pub fn ne_u32(b: &[u8]) -> u32 {
    b.get(..4)
        .map(|s| u32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
        .unwrap_or(0)
}

/// A string attribute, up to its NUL.
pub fn cstring(b: &[u8]) -> String {
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// A message received: (type, flags, seq, data).
type Received = (u16, u16, u32, Vec<u8>);

/// A netlink socket of one protocol, talking to the kernel.
pub struct Socket {
    fd: OwnedFd,
    seq: u32,
    pid: u32,
    buf: Vec<u8>,
}

impl Socket {
    pub fn open(protocol: i32) -> Result<Socket, Errno> {
        // SAFETY: plain system calls on a descriptor this function owns.
        unsafe {
            let fd = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                protocol,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error().into());
            }
            let fd = OwnedFd::from_raw_fd(fd);
            let raw = fd.as_raw_fd();
            let timeout = libc::timeval {
                tv_sec: 10,
                tv_usec: 0,
            };
            for opt in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
                libc::setsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    opt,
                    (&raw const timeout).cast(),
                    size_of::<libc::timeval>() as libc::socklen_t,
                );
            }
            let mut addr: libc::sockaddr_nl = std::mem::zeroed();
            addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            let mut len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            if libc::bind(raw, (&raw const addr).cast(), len) < 0
                || libc::getsockname(raw, (&raw mut addr).cast(), &raw mut len) < 0
            {
                return Err(io::Error::last_os_error().into());
            }
            Ok(Socket {
                fd,
                seq: 0,
                pid: addr.nl_pid,
                buf: vec![0; 1 << 20],
            })
        }
    }

    fn send(&self, b: &[u8]) -> Result<(), Errno> {
        // SAFETY: b outlives the call; the kernel's address is zeroed but
        // for its family.
        let n = unsafe {
            let mut to: libc::sockaddr_nl = std::mem::zeroed();
            to.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            libc::sendto(
                self.fd.as_raw_fd(),
                b.as_ptr().cast(),
                b.len(),
                0,
                (&raw const to).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if n as usize != b.len() {
            return Err(Errno(libc::EIO));
        }
        Ok(())
    }

    /// The messages of one datagram from the kernel: (type, flags, seq,
    /// data).
    fn receive(&mut self) -> Result<Vec<Received>, Errno> {
        loop {
            // SAFETY: buf and the address are valid for their lengths.
            let (n, from) = unsafe {
                let mut from: libc::sockaddr_nl = std::mem::zeroed();
                let mut len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
                let n = libc::recvfrom(
                    self.fd.as_raw_fd(),
                    self.buf.as_mut_ptr().cast(),
                    self.buf.len(),
                    libc::MSG_TRUNC,
                    (&raw mut from).cast(),
                    &raw mut len,
                );
                (n, from.nl_pid)
            };
            if n < 0 {
                return Err(io::Error::last_os_error().into());
            }
            let n = n as usize;
            if n > self.buf.len() {
                return Err(Errno(libc::ENOBUFS));
            }
            if from != 0 {
                // Not the kernel.
                continue;
            }
            let mut out = Vec::new();
            let mut b = &self.buf[..n];
            while b.len() >= HEADER {
                let len = ne_u32(b) as usize;
                if len < HEADER || len > b.len() {
                    break;
                }
                out.push((
                    ne_u16(&b[4..]),
                    ne_u16(&b[6..]),
                    ne_u32(&b[8..]),
                    b[HEADER..len].to_vec(),
                ));
                b = &b[len.next_multiple_of(4).min(b.len())..];
            }
            return Ok(out);
        }
    }

    /// Sends m and returns the messages that answer it: a dump's every
    /// part, a lookup's one answer, or nothing for an acknowledged change.
    pub fn request(&mut self, m: &Msg) -> Result<Vec<(u16, Vec<u8>)>, Errno> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        self.send(&m.bytes(seq, self.pid))?;
        let acked = m.flags & NLM_F_ACK != 0;
        let mut out = Vec::new();
        let mut answered = false;
        loop {
            for (ty, flags, s, data) in self.receive()? {
                if s != seq {
                    continue;
                }
                match ty {
                    NLMSG_DONE => return Ok(out),
                    NLMSG_ERROR => {
                        let errno = -(ne_u32(&data) as i32);
                        if errno != 0 {
                            return Err(Errno(errno));
                        }
                        return Ok(out);
                    }
                    _ => {
                        out.push((ty, data));
                        if flags & NLM_F_MULTI == 0 {
                            answered = true;
                        }
                    }
                }
            }
            // A lookup is answered by one message, then (when it asked
            // for one) the acknowledgement.
            if answered && !acked {
                return Ok(out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_pad_and_nest() {
        let mut a = Attrs::new();
        a.cstr(3, "armada-net").nested(18, |l| {
            l.put(1, b"vxlan").u8(5, 0);
        });
        // name: 4 + 11 bytes, padded to 16; nested: 4 + 12 + 8.
        assert_eq!(a.b.len(), 16 + 24);
        assert_eq!(ne_u16(&a.b[16..]), 24);
        let parsed = attrs(&a.b);
        assert_eq!(parsed.len(), 2);
        assert_eq!(cstring(parsed[0].1), "armada-net");
        let inner = attrs(parsed[1].1);
        assert_eq!(inner[0], (1, &b"vxlan"[..]));
        assert_eq!(inner[1], (5, &[0u8][..]));
    }

    #[test]
    fn errors_read_as_go_prints_them() {
        assert_eq!(Errno(libc::EEXIST).to_string(), "file exists");
        assert_eq!(Errno(libc::ENODEV).to_string(), "no such device");
        assert_eq!(
            Errno(libc::EOPNOTSUPP).to_string(),
            "operation not supported"
        );
    }

    #[test]
    fn messages_carry_their_length() {
        let m = Msg {
            ty: 18,
            flags: NLM_F_REQUEST | NLM_F_ACK,
            body: vec![0; 16],
        };
        let b = m.bytes(7, 9);
        assert_eq!(ne_u32(&b), 32);
        assert_eq!(ne_u16(&b[6..]), 5);
        assert_eq!(ne_u32(&b[8..]), 7);
        assert_eq!(ne_u32(&b[12..]), 9);
    }
}

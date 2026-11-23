//! A netfilter netlink socket for nftables batches (what nftables.Conn's
//! Flush does): the batch goes out in one send and every message that asks
//! for an acknowledgement gets one, or an error, back.

use super::nft::{Msg, NLM_F_ACK};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const NETLINK_NETFILTER: libc::c_int = 12;
const NLMSG_ERROR: u16 = 2;
/// The socket buffers (netlinkBuffer): a whole ruleset, and the kernel's
/// answers to it, in one transaction.
const BUFFER: libc::c_int = 32 << 20;

pub struct Socket {
    fd: OwnedFd,
}

fn last_error(what: &str) -> String {
    format!("{what}: {}", io::Error::last_os_error())
}

fn errno_text(errno: i32) -> String {
    io::Error::from_raw_os_error(errno).to_string()
}

impl Socket {
    pub fn open() -> Result<Socket, String> {
        // SAFETY: plain system calls on a descriptor this function owns.
        unsafe {
            let fd = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_NETFILTER,
            );
            if fd < 0 {
                return Err(last_error("netlink socket"));
            }
            let fd = OwnedFd::from_raw_fd(fd);
            let raw = fd.as_raw_fd();
            // The default buffers still work for most clusters, so failing
            // to raise them is not an error (largeSocketBuffers).
            let size = BUFFER;
            for opt in [libc::SO_SNDBUFFORCE, libc::SO_RCVBUFFORCE] {
                libc::setsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    opt,
                    (&raw const size).cast(),
                    size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
            let timeout = libc::timeval {
                tv_sec: 10,
                tv_usec: 0,
            };
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const timeout).cast(),
                size_of::<libc::timeval>() as libc::socklen_t,
            );
            let mut addr: libc::sockaddr_nl = std::mem::zeroed();
            addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            if libc::bind(
                raw,
                (&raw const addr).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            ) < 0
            {
                return Err(last_error("netlink bind"));
            }
            Ok(Socket { fd })
        }
    }

    fn send(&self, msgs: &[Msg], first_seq: u32) -> Result<(), String> {
        let mut buf = Vec::new();
        for (i, m) in msgs.iter().enumerate() {
            buf.extend(m.bytes(first_seq.wrapping_add(i as u32), 0));
        }
        // SAFETY: buf outlives the call; the kernel's address is zeroed but
        // for its family.
        let n = unsafe {
            let mut to: libc::sockaddr_nl = std::mem::zeroed();
            to.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            libc::sendto(
                self.fd.as_raw_fd(),
                buf.as_ptr().cast(),
                buf.len(),
                0,
                (&raw const to).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if n < 0 {
            return Err(last_error("netlink send"));
        }
        if n as usize != buf.len() {
            return Err(format!("netlink send: {n} of {} bytes", buf.len()));
        }
        Ok(())
    }

    /// The messages of one datagram: (type, seq, data).
    fn receive(&self, buf: &mut [u8]) -> Result<Vec<(u16, u32, Vec<u8>)>, io::Error> {
        // SAFETY: buf is valid for its length.
        let n = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_TRUNC,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n > buf.len() {
            return Err(io::Error::other("netlink answer cut short"));
        }
        let mut out = Vec::new();
        let mut b = &buf[..n];
        while b.len() >= 16 {
            let len = u32::from_ne_bytes(b[0..4].try_into().unwrap_or_default()) as usize;
            if len < 16 || len > b.len() {
                break;
            }
            let ty = u16::from_ne_bytes([b[4], b[5]]);
            let seq = u32::from_ne_bytes(b[8..12].try_into().unwrap_or_default());
            out.push((ty, seq, b[16..len].to_vec()));
            b = &b[len.next_multiple_of(4).min(b.len())..];
        }
        Ok(out)
    }

    /// Sends a transaction and waits for an answer to every message that
    /// asked for one, joining the errors as Go's Flush does.
    pub fn transact(&self, msgs: &[Msg]) -> Result<(), String> {
        if msgs.is_empty() {
            return Ok(());
        }
        let first_seq = 1;
        self.send(msgs, first_seq)?;
        let mut waiting: Vec<u32> = msgs
            .iter()
            .enumerate()
            .filter(|(_, m)| m.flags & NLM_F_ACK != 0)
            .map(|(i, _)| first_seq.wrapping_add(i as u32))
            .collect();
        let mut errs = Vec::new();
        let mut buf = vec![0u8; 1 << 20];
        while !waiting.is_empty() {
            let answers = match self.receive(&mut buf) {
                Ok(a) => a,
                Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                    return Err(format!("nftables: {e}"));
                }
                // No more answers: the kernel gave up on the batch as a
                // whole (it answered the errors it had).
                Err(e) if !errs.is_empty() && e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(format!("nftables: conn.Receive: {e}")),
            };
            for (ty, seq, data) in answers {
                if ty != NLMSG_ERROR || data.len() < 4 {
                    // An echo of what was added.
                    continue;
                }
                let errno = -i32::from_ne_bytes(data[0..4].try_into().unwrap_or_default());
                let known = waiting.iter().position(|s| *s == seq);
                if let Some(i) = known {
                    waiting.remove(i);
                }
                if errno != 0 {
                    errs.push(format!("message {seq}: {}", errno_text(errno)));
                    if known.is_none() {
                        // About the batch itself: nothing else comes.
                        waiting.clear();
                    }
                }
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(format!("nftables: conn.Receive: {}", errs.join("\n")))
        }
    }

    /// The kernel's answer to a GETTABLE message as an error number, 0
    /// when the table exists (doctor's hasIsolation, which words the error
    /// as Go's netlink library does).
    pub fn table_errno(&self, get: &Msg) -> Result<(), i32> {
        self.send(std::slice::from_ref(get), 1)
            .map_err(|_| libc::EIO)?;
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let answers = self
                .receive(&mut buf)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            for (ty, seq, data) in answers {
                if seq != 1 {
                    continue;
                }
                if ty != NLMSG_ERROR {
                    return Ok(());
                }
                if data.len() < 4 {
                    return Err(libc::EIO);
                }
                return match -i32::from_ne_bytes(data[0..4].try_into().unwrap_or_default()) {
                    0 => Ok(()),
                    errno => Err(errno),
                };
            }
        }
    }

    /// Whether a table exists, by its GETTABLE message (hasIsolation).
    pub fn has_table(&self, get: &Msg) -> Result<bool, String> {
        self.send(std::slice::from_ref(get), 1)?;
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let answers = self
                .receive(&mut buf)
                .map_err(|e| format!("nftables: {e}"))?;
            for (ty, seq, data) in answers {
                if seq != 1 {
                    continue;
                }
                if ty != NLMSG_ERROR {
                    return Ok(true);
                }
                if data.len() < 4 {
                    return Err("nftables: short answer".into());
                }
                return match -i32::from_ne_bytes(data[0..4].try_into().unwrap_or_default()) {
                    0 => Ok(true),
                    libc::ENOENT => Ok(false),
                    errno => Err(format!("nftables: {}", errno_text(errno))),
                };
            }
        }
    }
}

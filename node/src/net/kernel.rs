//! A netfilter netlink socket for nftables batches (what nftables.Conn's
//! Flush does): the batch goes out in one send, and the kernel answers it.
//!
//! Unlike Go's nftables library, which asks for an acknowledgement of
//! every message and an echo of every rule, a batch goes out asking only
//! for the acknowledgement of its last message (`on_the_wire`): the
//! kernel reports every failed message whether asked or not, processes
//! the whole batch before it answers, and answers in order, so the last
//! message's answer ends the batch's. Tens of thousands of answers to one
//! batch (an app's set and chain each, for thousands of apps) overflowed
//! the socket's receive buffer, failing the transaction with ENOBUFS;
//! now a batch is answered with one message plus one per failure, which
//! carry no copy of the failed message (NETLINK_CAP_ACK).

use super::nft::{Msg, NLM_F_ACK};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const NETLINK_NETFILTER: libc::c_int = 12;
const NLMSG_ERROR: u16 = 2;
const NLM_F_ECHO: u16 = 0x8;
const SOL_NETLINK: libc::c_int = 270;
const NETLINK_CAP_ACK: libc::c_int = 10;
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
            // Error answers without the message they answer.
            let on: libc::c_int = 1;
            libc::setsockopt(
                raw,
                SOL_NETLINK,
                NETLINK_CAP_ACK,
                (&raw const on).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            );
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

    /// Sends a transaction and waits for the kernel's answer to it,
    /// joining the errors as Go's Flush does.
    pub fn transact(&self, msgs: &[Msg]) -> Result<(), String> {
        if msgs.is_empty() {
            return Ok(());
        }
        let first_seq = 1;
        let (wire, answers) = on_the_wire(msgs, first_seq);
        self.send(&wire, first_seq)?;
        let mut answers = answers;
        let mut buf = vec![0u8; 1 << 20];
        while !answers.done() {
            let got = match self.receive(&mut buf) {
                Ok(a) => a,
                Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                    return Err(format!("nftables: {e}"));
                }
                // No more answers: the kernel gave up on the batch as a
                // whole (it answered the errors it had).
                Err(e) if answers.failed() && e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(format!("nftables: conn.Receive: {e}")),
            };
            for (ty, seq, data) in got {
                answers.take(ty, seq, &data);
            }
        }
        answers.result()
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

/// What a transaction goes out as, and what answers it waits for: no
/// message asks for an echo, and only the last message that asked for an
/// acknowledgement keeps asking (the one before the batch's end).
fn on_the_wire(msgs: &[Msg], first_seq: u32) -> (Vec<Msg>, Answers) {
    let last = msgs.iter().rposition(|m| m.flags & NLM_F_ACK != 0);
    let wire = msgs
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let mut m = m.clone();
            m.flags &= !NLM_F_ECHO;
            if Some(i) != last {
                m.flags &= !NLM_F_ACK;
            }
            m
        })
        .collect();
    let seq = |i: usize| first_seq.wrapping_add(i as u32);
    let answers = Answers {
        last: last.map(seq),
        // The messages between the batch's edges: a failure of one of
        // them is reported on its own and the batch goes on; any other
        // sequence number is the batch's (its begin: a failed commit, or
        // a batch the kernel could not read), and nothing else comes.
        messages: if msgs.len() > 2 {
            seq(1)..seq(msgs.len() - 1)
        } else {
            seq(0)..seq(msgs.len())
        },
        errs: Vec::new(),
        over: last.is_none(),
    };
    (wire, answers)
}

/// The kernel's answers to one transaction.
#[derive(Debug)]
struct Answers {
    last: Option<u32>,
    messages: std::ops::Range<u32>,
    errs: Vec<String>,
    over: bool,
}

impl Answers {
    fn take(&mut self, ty: u16, seq: u32, data: &[u8]) {
        if ty != NLMSG_ERROR || data.len() < 4 {
            return;
        }
        let errno = -i32::from_ne_bytes(data[0..4].try_into().unwrap_or_default());
        if errno != 0 {
            self.errs
                .push(format!("message {seq}: {}", errno_text(errno)));
            if !self.messages.contains(&seq) {
                self.over = true;
            }
        }
        if Some(seq) == self.last {
            self.over = true;
        }
    }

    fn done(&self) -> bool {
        self.over
    }

    fn failed(&self) -> bool {
        !self.errs.is_empty()
    }

    fn result(self) -> Result<(), String> {
        if self.errs.is_empty() {
            Ok(())
        } else {
            Err(format!("nftables: conn.Receive: {}", self.errs.join("\n")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::nft;

    fn ack(seq: u32, errno: i32) -> (u16, u32, Vec<u8>) {
        (NLMSG_ERROR, seq, (-errno).to_ne_bytes().to_vec())
    }

    /// Only the last message asks for an acknowledgement, and none for an
    /// echo, however many messages a batch has.
    #[test]
    fn one_acknowledgement_per_batch() {
        let tx = nft::remove_isolation().transaction();
        assert!(tx.len() > 3);
        assert!(tx.iter().filter(|m| m.flags & NLM_F_ACK != 0).count() > 1);
        let (wire, a) = on_the_wire(&tx, 1);
        let acked: Vec<usize> = (0..wire.len())
            .filter(|&i| wire[i].flags & NLM_F_ACK != 0)
            .collect();
        assert_eq!(acked, [tx.len() - 2]);
        assert!(wire.iter().all(|m| m.flags & NLM_F_ECHO == 0));
        assert_eq!(a.last, Some(tx.len() as u32 - 1));
        // Everything else is the same message.
        for (w, m) in wire.iter().zip(&tx) {
            assert_eq!((w.ty, &w.data), (m.ty, &m.data));
        }
    }

    #[test]
    fn answers_end_with_the_last_message() {
        let tx = nft::remove_isolation().transaction();
        let n = tx.len() as u32;
        // Success: one answer.
        let (_, mut a) = on_the_wire(&tx, 1);
        assert!(!a.done());
        let (ty, seq, d) = ack(n - 1, 0);
        a.take(ty, seq, &d);
        assert!(a.done() && a.result().is_ok());
        // A message fails: the batch goes on to its last message, and
        // every failure is reported.
        let (_, mut a) = on_the_wire(&tx, 1);
        for (ty, seq, d) in [ack(2, libc::ENOENT), ack(3, libc::EEXIST)] {
            a.take(ty, seq, &d);
            assert!(!a.done());
        }
        let (ty, seq, d) = ack(n - 1, 0);
        a.take(ty, seq, &d);
        assert!(a.done());
        let err = a.result().unwrap_err();
        assert!(
            err.contains("message 2: ") && err.contains("message 3: "),
            "{err}"
        );
        // The batch itself fails (its begin's number): nothing else comes.
        let (_, mut a) = on_the_wire(&tx, 1);
        let (ty, seq, d) = ack(1, libc::EPERM);
        a.take(ty, seq, &d);
        assert!(a.done() && a.result().is_err());
    }

    /// Tens of thousands of apps in one transaction fit the socket (the
    /// kernel used to answer each message, overflowing it). Needs root and
    /// a network namespace of its own, which the test never leaves:
    ///   cargo test -p armada-node --no-run
    ///   sudo unshare -n env ARMADA_NODE_NETNS_TEST=1 \
    ///     target/debug/deps/armada_node-<hash> many_apps_in_one_transaction
    #[test]
    fn many_apps_in_one_transaction() {
        // SAFETY: geteuid has no preconditions.
        if std::env::var_os("ARMADA_NODE_NETNS_TEST").is_none() || unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root in a network namespace (ARMADA_NODE_NETNS_TEST=1)");
            return;
        }
        use crate::net::addr::{Addr, Prefix};
        use crate::net::policy::Policy;
        let policy = |apps: u32, shift: u32| {
            let mut members = std::collections::BTreeMap::new();
            for i in 0..apps {
                let v = (10u32 << 24 | 96 << 16) + 300 + i + shift;
                let a = Addr::parse(&std::net::Ipv4Addr::from(v).to_string()).unwrap();
                members.insert(format!("app{i}.space{}", i % 50), vec![a]);
            }
            Policy {
                cidr: Prefix::parse("10.96.0.0/11").unwrap(),
                subnet: Prefix::parse("10.96.0.0/24").unwrap(),
                gateway: Addr::parse("10.96.0.1"),
                members,
                open: Vec::new(),
                nodes: vec![Addr::parse("10.1.0.1").unwrap()],
                tcp_ports: vec![5432],
            }
        };
        let s = Socket::open().unwrap();
        let pol = policy(10_000, 0);
        let tx = nft::isolate(&pol, 1).transaction();
        assert!(tx.len() > 20_000, "{} messages", tx.len());
        s.transact(&tx).expect("rebuild with 10,000 apps");
        // In place: every app changes its address.
        let next = policy(10_000, 20_000);
        let tx = nft::update_isolation(&pol, &next, 1).transaction();
        s.transact(&tx).expect("update with 10,000 apps");
        s.transact(&nft::remove_isolation().transaction())
            .expect("remove");
    }
}

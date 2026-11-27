//! The UDP side: one event loop per thread over epoll, reading lookups
//! from the shared listening socket and forwarding the rest to the
//! upstreams without a thread per lookup. Each forwarded lookup goes out
//! on a socket of its own (a fresh source port),
//! waits in the loop, and moves on to the next upstream at its deadline.

use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::Ordering;
use std::time::Instant;

use crate::msg::{self, Request};
use crate::{
    FORWARD_TIMEOUT, MAX_INFLIGHT_PER_CLIENT, Server, Waiting, ZONE, client_of, in_prefix,
};

unsafe extern "C" {
    fn epoll_create1(flags: i32) -> i32;
    fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: *mut EpollEvent) -> i32;
    fn epoll_wait(epfd: i32, events: *mut EpollEvent, max: i32, timeout: i32) -> i32;
}

const EPOLL_CLOEXEC: i32 = 0o2000000;
const EPOLL_CTL_ADD: i32 = 1;
const EPOLL_CTL_DEL: i32 = 2;
const EPOLLIN: u32 = 1;
const EPOLLEXCLUSIVE: u32 = 1 << 28;

/// struct epoll_event: packed on x86-64 only.
#[cfg_attr(target_arch = "x86_64", repr(C, packed))]
#[cfg_attr(not(target_arch = "x86_64"), repr(C))]
#[derive(Clone, Copy)]
struct EpollEvent {
    events: u32,
    data: u64,
}

/// The token of the listening socket; a forward's is its slot + 1.
const LISTEN: u64 = 0;
/// Datagrams read from the listening socket per wakeup, so forwards'
/// answers get their turn.
const BATCH: usize = 64;

struct Epoll(OwnedFd);

impl Epoll {
    fn new() -> io::Result<Self> {
        // SAFETY: epoll_create1 returns a new descriptor or -1.
        let fd = unsafe { epoll_create1(EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a new descriptor this function owns.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    fn add(&self, fd: i32, token: u64, flags: u32) -> io::Result<()> {
        let mut ev = EpollEvent {
            events: EPOLLIN | flags,
            data: token,
        };
        // SAFETY: ev is a valid epoll_event for the call's duration.
        if unsafe { epoll_ctl(self.0.as_raw_fd(), EPOLL_CTL_ADD, fd, &mut ev) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn del(&self, fd: i32) {
        let mut ev = EpollEvent { events: 0, data: 0 };
        // SAFETY: as in add; a failure leaves nothing to undo (closing the
        // descriptor removes it too).
        unsafe { epoll_ctl(self.0.as_raw_fd(), EPOLL_CTL_DEL, fd, &mut ev) };
    }

    fn wait(&self, events: &mut [EpollEvent], timeout_ms: i32) -> io::Result<usize> {
        // SAFETY: events is a writable buffer of events.len() entries.
        let n = unsafe {
            epoll_wait(
                self.0.as_raw_fd(),
                events.as_mut_ptr(),
                events.len() as i32,
                timeout_ms,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::Interrupted {
                Ok(0)
            } else {
                Err(e)
            };
        }
        Ok(n as usize)
    }
}

/// A lookup forwarded and not answered yet.
struct Pending {
    /// The socket of the upstream asked now.
    sock: Option<UdpSocket>,
    pkt: Vec<u8>,
    id: u16,
    client: Ipv4Addr,
    to: SocketAddr,
    /// The upstream asked now.
    upstream: usize,
    /// Bumped for each upstream asked, so a deadline queued for an earlier
    /// one is ignored.
    round: u64,
}

struct Loop<'a> {
    srv: &'a Server,
    listen: UdpSocket,
    ep: Epoll,
    slots: Vec<Option<Pending>>,
    free: Vec<usize>,
    /// Deadlines in the order they fall: every forward waits as long.
    deadlines: VecDeque<(Instant, usize, u64)>,
    rounds: u64,
}

/// Serves lookups from listen (a duplicate of the shared socket) until an
/// error the loop cannot get past.
pub fn serve(srv: &Server, listen: UdpSocket) -> io::Result<()> {
    listen.set_nonblocking(true)?;
    let ep = Epoll::new()?;
    // Exclusive: one of the threads waits on the socket per datagram.
    ep.add(listen.as_raw_fd(), LISTEN, EPOLLEXCLUSIVE)?;
    let mut l = Loop {
        srv,
        listen,
        ep,
        slots: Vec::new(),
        free: Vec::new(),
        deadlines: VecDeque::new(),
        rounds: 0,
    };
    let mut events = [EpollEvent { events: 0, data: 0 }; 64];
    let mut buf = vec![0u8; 65535];
    loop {
        let timeout = l.deadlines.front().map_or(-1, |(d, _, _)| {
            let left = d.saturating_duration_since(Instant::now());
            left.as_millis().min(i32::MAX as u128) as i32 + 1
        });
        let n = l.ep.wait(&mut events, timeout)?;
        for ev in &events[..n] {
            let token = { ev.data };
            if token == LISTEN {
                l.read_lookups(&mut buf);
            } else {
                l.read_answer((token - 1) as usize, &mut buf);
            }
        }
        l.expire();
    }
}

impl Loop<'_> {
    fn reply(&self, pkt: &[u8], to: SocketAddr) {
        let _ = self.listen.send_to(pkt, to);
    }

    fn read_lookups(&mut self, buf: &mut [u8]) {
        for _ in 0..BATCH {
            let (n, from) = match self.listen.recv_from(buf) {
                Ok(r) => r,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            };
            self.lookup(&buf[..n], from);
        }
    }

    fn lookup(&mut self, pkt: &[u8], from: SocketAddr) {
        let srv = self.srv;
        let Some(client) = client_of(from) else {
            return;
        };
        if !in_prefix(client, srv.cfg.clients) {
            // Not a container on this node: no answer at all, so the
            // resolver is never an open resolver or a reflector.
            return;
        }
        match msg::parse(pkt, ZONE) {
            Request::Drop => {}
            Request::Reply(r) => self.reply(&r, from),
            Request::Internal(q, name) => {
                if client == *srv.cfg.listen.ip() || srv.view().answerable(client) {
                    self.reply(&srv.answer(&q, name.as_deref(), client), from);
                } else if Server::take(&srv.per_client, client, MAX_INFLIGHT_PER_CLIENT) {
                    let deadline = Instant::now() + srv.wait_for();
                    let mut room = srv.room.lock().unwrap_or_else(|e| e.into_inner());
                    room.push(Waiting {
                        deadline,
                        client,
                        query: q,
                        name,
                        to: from,
                    });
                    srv.changed.notify_all();
                } else {
                    self.reply(&srv.answer(&q, name.as_deref(), client), from);
                }
            }
            Request::Forward => {
                // The client's own share first, so a client past it never
                // holds a node slot another client could use.
                if !Server::take(&srv.per_client, client, MAX_INFLIGHT_PER_CLIENT) {
                    self.reply(&msg::servfail(pkt), from);
                    return;
                }
                if !srv.take_inflight() {
                    Server::release(&srv.per_client, client);
                    self.reply(&msg::servfail(pkt), from);
                    return;
                }
                let Some(id) = msg::id(pkt) else { return };
                let p = Pending {
                    sock: None,
                    pkt: pkt.to_vec(),
                    id,
                    client,
                    to: from,
                    upstream: 0,
                    round: 0,
                };
                let slot = match self.free.pop() {
                    Some(i) => i,
                    None => {
                        self.slots.push(None);
                        self.slots.len() - 1
                    }
                };
                self.slots[slot] = Some(p);
                self.ask(slot, 0);
            }
        }
    }

    /// Sends slot's lookup to upstream `first` or the next that takes it;
    /// SERVFAIL when none is left.
    fn ask(&mut self, slot: usize, first: usize) {
        let ups = &self.srv.cfg.upstreams;
        for (i, up) in ups.iter().enumerate().skip(first) {
            let Ok(sock) = upstream_socket(*up) else {
                continue;
            };
            let p = self.slots[slot].as_mut().expect("slot in use");
            if sock.send(&p.pkt).is_err()
                || self.ep.add(sock.as_raw_fd(), slot as u64 + 1, 0).is_err()
            {
                continue;
            }
            if let Some(old) = p.sock.replace(sock) {
                self.ep.del(old.as_raw_fd());
            }
            p.upstream = i;
            self.rounds += 1;
            p.round = self.rounds;
            self.deadlines
                .push_back((Instant::now() + FORWARD_TIMEOUT, slot, p.round));
            return;
        }
        let p = self.slots[slot].as_ref().expect("slot in use");
        self.reply(&msg::servfail(&p.pkt), p.to);
        self.finish(slot);
    }

    fn read_answer(&mut self, slot: usize, buf: &mut [u8]) {
        let Some(p) = self.slots.get(slot).and_then(Option::as_ref) else {
            return;
        };
        let Some(sock) = &p.sock else { return };
        loop {
            match sock.recv(buf) {
                Ok(n) if msg::is_response(&buf[..n], p.id) => {
                    self.reply(&buf[..n], p.to);
                    self.finish(slot);
                    return;
                }
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                // Refused (nothing listens there): the next upstream now.
                Err(_) => {
                    let next = p.upstream + 1;
                    self.ask(slot, next);
                    return;
                }
            }
        }
    }

    fn finish(&mut self, slot: usize) {
        if let Some(p) = self.slots[slot].take() {
            if let Some(s) = &p.sock {
                self.ep.del(s.as_raw_fd());
            }
            self.free.push(slot);
            self.srv.inflight.fetch_sub(1, Ordering::AcqRel);
            Server::release(&self.srv.per_client, p.client);
        }
    }

    fn expire(&mut self) {
        let now = Instant::now();
        while let Some(&(deadline, slot, round)) = self.deadlines.front() {
            if deadline > now {
                return;
            }
            self.deadlines.pop_front();
            let next = match &self.slots[slot] {
                Some(p) if p.round == round => p.upstream + 1,
                _ => continue,
            };
            self.ask(slot, next);
        }
    }
}

fn upstream_socket(up: SocketAddr) -> io::Result<UdpSocket> {
    let s = UdpSocket::bind(if up.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
    s.set_nonblocking(true)?;
    s.connect(up)?;
    Ok(s)
}

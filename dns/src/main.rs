//! armada-dns is the node-local resolver of Armada's containers (ADR 0053).
//!
//! It answers `<app>.internal` with the node's internal ingress address
//! (the bridge gateway it listens on) and forwards every other query to the
//! host's resolvers. It answers only addresses of the container bridge, and
//! a container only the names of its own space. The agent runs it as a
//! systemd unit of its own, so it keeps answering while armadad restarts,
//! and tells it the names and the containers over a root-only Unix socket,
//! one request line per connection, answered with one line:
//!
//!   names [NAME...]           the names that resolve (app IDs and
//!                             <label>--<app ID>): `ok EPOCH`
//!   clients [IP=APP...]       the node's containers and their app IDs; from
//!                             then on an address not listed resolves no
//!                             internal name: `ok EPOCH`
//!   epoch                     `ok EPOCH`, which changes when the process does
//!   drain                     stop taking UDP lookups and answer the
//!                             ones held (before the process is stopped)
//!   state                     two lines, `names ...` (or `unnamed`) and
//!                             `clients ...` (or `noclients`), for the next
//!                             process to take over
//!
//! What it knows is saved beside the control socket (`<socket>.state`), so
//! the unit started again after a crash answers at once.
//!
//! A lookup of an internal name from an address the agent has not named
//! yet waits for it (a container runs before the agent hears of it), and
//! before the first `names`, for those (a process that just started).
//!
//! Standard library only, Linux only.

mod msg;
mod names;
mod udp;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use msg::Request;

/// The zone the resolver answers itself.
const ZONE: &str = "internal";
/// The TTL of internal answers: short, so scaling and removals show.
const TTL: u32 = 5;
/// How long each upstream has to answer.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(2);
/// Forwarded queries in flight at once; past it clients get SERVFAIL.
const MAX_INFLIGHT: usize = 128;
/// One client address's share of MAX_INFLIGHT, and of waiting lookups.
const MAX_INFLIGHT_PER_CLIENT: u32 = 16;
/// Open TCP connections per client address, and in all.
const MAX_CONNS_PER_CLIENT: u32 = 16;
const MAX_CONNS: usize = 1024;
/// How long a TCP connection may stay idle, and how long a message may take.
const TCP_IDLE: Duration = Duration::from_secs(8);
const TCP_READ: Duration = Duration::from_secs(5);
/// The longest control request (names and clients of a large node).
const MAX_CONTROL_LINE: u64 = 64 << 20;
/// Thread stacks: buffers live on the heap.
const STACK: usize = 256 << 10;

struct Config {
    listen: SocketAddrV4,
    clients: (Ipv4Addr, u8),
    upstreams: Vec<SocketAddr>,
    control: String,
    /// Control sockets of older processes whose names and clients this
    /// one starts with, before it answers anything.
    take_over: Vec<String>,
    unknown_wait: Duration,
    start_wait: Duration,
}

/// What the agent last said: None until it says it.
#[derive(Default)]
struct View {
    names: Option<HashSet<String>>,
    clients: Option<HashMap<Ipv4Addr, String>>,
}

impl View {
    fn known(&self, client: Ipv4Addr) -> bool {
        self.clients
            .as_ref()
            .is_none_or(|c| c.contains_key(&client))
    }

    fn answerable(&self, client: Ipv4Addr) -> bool {
        self.names.is_some() && self.known(client)
    }

    /// Whether `name` resolves for client: a known name of the client's
    /// space, or any known name while there is no client map.
    fn resolves(&self, client: Ipv4Addr, name: &str) -> bool {
        if !names::valid_host_name(name) || !self.names.as_ref().is_some_and(|n| n.contains(name)) {
            return false;
        }
        match &self.clients {
            None => true,
            Some(c) => c
                .get(&client)
                .is_some_and(|app| names::same_space(app, name)),
        }
    }
}

/// A UDP lookup waiting for its client or the first names.
struct Waiting {
    deadline: Instant,
    client: Ipv4Addr,
    query: msg::Query,
    name: Option<String>,
    to: SocketAddr,
}

struct Server {
    cfg: Config,
    epoch: String,
    view: RwLock<Arc<View>>,
    /// Waiting lookups and the condition that wakes them: a change of the
    /// view, or a new UDP wait.
    room: Mutex<Vec<Waiting>>,
    changed: Condvar,
    per_client: Mutex<HashMap<Ipv4Addr, u32>>,
    per_conn: Mutex<HashMap<Ipv4Addr, u32>>,
    inflight: AtomicUsize,
    conns: AtomicUsize,
    /// The UDP socket, for `drain`.
    udp: OnceLock<Arc<UdpSocket>>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--version") {
        println!("armada-dns {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let cfg = match parse_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("armada-dns: {e}");
            return ExitCode::from(2);
        }
    };
    match run(cfg) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("armada-dns: {e}");
            ExitCode::FAILURE
        }
    }
}

fn parse_args(args: &[String]) -> Result<Config, String> {
    let mut listen = None;
    let mut clients = None;
    let mut upstreams = Vec::new();
    let mut control = None;
    let mut take_over = Vec::new();
    let mut unknown_wait = Duration::from_secs(3);
    let mut start_wait = Duration::from_secs(10);
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it.next().ok_or(format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--listen" => {
                listen = Some(
                    value
                        .parse::<SocketAddrV4>()
                        .map_err(|_| format!("bad --listen {value}"))?,
                )
            }
            "--clients" => {
                clients = Some(parse_prefix(value).ok_or(format!("bad --clients {value}"))?)
            }
            "--upstream" => upstreams.push(
                value
                    .parse::<SocketAddr>()
                    .map_err(|_| format!("bad --upstream {value}"))?,
            ),
            "--control" => control = Some(value.clone()),
            "--take-over" => take_over.push(value.clone()),
            "--unknown-wait-ms" => {
                unknown_wait =
                    Duration::from_millis(value.parse().map_err(|_| "bad --unknown-wait-ms")?)
            }
            "--start-wait-ms" => {
                start_wait =
                    Duration::from_millis(value.parse().map_err(|_| "bad --start-wait-ms")?)
            }
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    let listen = listen.ok_or("--listen is required")?;
    if !private(*listen.ip()) {
        return Err(format!("listen address {} must be private", listen.ip()));
    }
    // Forwarding to ourselves would loop.
    upstreams.retain(|u| *u != SocketAddr::V4(listen));
    Ok(Config {
        listen,
        clients: clients.ok_or("--clients is required")?,
        upstreams,
        control: control.ok_or("--control is required")?,
        take_over,
        unknown_wait,
        start_wait,
    })
}

/// netutil.IsPrivate for IPv4: RFC 1918, shared (100.64/10), and loopback
/// (tests).
fn private(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_private() || ip.is_loopback() || (o[0] == 100 && (o[1] & 0xC0) == 64)
}

fn parse_prefix(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip, bits) = s.split_once('/')?;
    let (ip, bits): (Ipv4Addr, u8) = (ip.parse().ok()?, bits.parse().ok()?);
    (bits <= 32).then_some((ip, bits))
}

fn in_prefix(ip: Ipv4Addr, (net, bits): (Ipv4Addr, u8)) -> bool {
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    u32::from(ip) & mask == u32::from(net) & mask
}

fn client_of(a: SocketAddr) -> Option<Ipv4Addr> {
    match a.ip() {
        IpAddr::V4(v) => Some(v),
        IpAddr::V6(v) => v.to_ipv4_mapped(),
    }
}

fn run(cfg: Config) -> io::Result<()> {
    let control = control_listener(&cfg.control)?;
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let srv = Arc::new(Server {
        epoch: format!("{}-{}", std::process::id(), started.as_nanos()),
        cfg,
        view: RwLock::new(Arc::new(View::default())),
        room: Mutex::new(Vec::new()),
        changed: Condvar::new(),
        per_client: Mutex::new(HashMap::new()),
        per_conn: Mutex::new(HashMap::new()),
        inflight: AtomicUsize::new(0),
        conns: AtomicUsize::new(0),
        udp: OnceLock::new(),
    });
    load_state(&srv);
    // What the process this one replaces knows, before the port is shared
    // with it: from then on the kernel hands this one lookups too.
    for path in &srv.cfg.take_over {
        match take_over(&srv, path) {
            Ok(()) => eprintln!("armada-dns: took over the names and clients of {path}"),
            // Gone once handed over: a restart of this unit finds none.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => eprintln!("armada-dns: take over from {path}: {e}"),
        }
    }
    let udp = Arc::new(UdpSocket::from(reuse_socket(srv.cfg.listen, SOCK_DGRAM)?));
    let _ = srv.udp.set(udp.clone());
    let tcp = TcpListener::from(reuse_socket(srv.cfg.listen, SOCK_STREAM)?);
    {
        let (srv, udp) = (srv.clone(), udp.clone());
        spawn(move || waiter(&srv, &udp))?;
    }
    {
        let srv = srv.clone();
        spawn(move || serve_control(&srv, control))?;
    }
    {
        let srv = srv.clone();
        spawn(move || serve_tcp(&srv, tcp))?;
    }
    eprintln!(
        "armada-dns: listening on {} for {}/{}, upstreams {:?}",
        srv.cfg.listen, srv.cfg.clients.0, srv.cfg.clients.1, srv.cfg.upstreams
    );
    let readers = thread::available_parallelism().map_or(2, |n| n.get().clamp(1, 4));
    let mut handles = Vec::new();
    for _ in 0..readers {
        let (srv, listen) = (srv.clone(), udp.try_clone()?);
        handles.push(spawn(move || {
            if let Err(e) = udp::serve(&srv, listen) {
                eprintln!("armada-dns: udp: {e}");
            }
        })?);
    }
    for h in handles {
        let _ = h.join();
    }
    Err(io::Error::other("UDP readers stopped"))
}

fn spawn<F: FnOnce() + Send + 'static>(f: F) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new().stack_size(STACK).spawn(f)
}

// Socket calls std does not wrap: SO_REUSEPORT must be set before bind,
// so the next process can bind the address while this one still answers.
unsafe extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn setsockopt(fd: i32, level: i32, name: i32, value: *const i32, len: u32) -> i32;
    fn bind(fd: i32, addr: *const SockaddrIn, len: u32) -> i32;
    fn listen(fd: i32, backlog: i32) -> i32;
}

const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;
const SOCK_CLOEXEC: i32 = 0o2000000;
const SOL_SOCKET: i32 = 1;
const SO_REUSEADDR: i32 = 2;
const SO_REUSEPORT: i32 = 15;

#[repr(C)]
struct SockaddrIn {
    family: u16,
    port: [u8; 2],
    addr: [u8; 4],
    zero: [u8; 8],
}

fn reuse_socket(addr: SocketAddrV4, ty: i32) -> io::Result<OwnedFd> {
    // SAFETY: plain system calls on a descriptor this function owns; the
    // OwnedFd closes it on every error path.
    unsafe {
        let fd = socket(AF_INET, ty | SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = OwnedFd::from_raw_fd(fd);
        let one = 1i32;
        for opt in [SO_REUSEADDR, SO_REUSEPORT] {
            if setsockopt(fd, SOL_SOCKET, opt, &one, 4) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let sa = SockaddrIn {
            family: AF_INET as u16,
            port: addr.port().to_be_bytes(),
            addr: addr.ip().octets(),
            zero: [0; 8],
        };
        if bind(fd, &sa, size_of::<SockaddrIn>() as u32) != 0 {
            return Err(io::Error::other(format!(
                "bind {addr}: {}",
                io::Error::last_os_error()
            )));
        }
        if ty == SOCK_STREAM && listen(fd, 1024) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(owned)
    }
}

fn control_listener(path: &str) -> io::Result<UnixListener> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let l = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

impl Server {
    fn view(&self) -> Arc<View> {
        self.view.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_view(&self, f: impl FnOnce(&mut View)) {
        {
            let mut v = self.view.write().unwrap_or_else(|e| e.into_inner());
            let mut next = View {
                names: v.names.clone(),
                clients: v.clients.clone(),
            };
            f(&mut next);
            *v = Arc::new(next);
        }
        // Under the room's lock, so a waiter between its check and its
        // wait cannot miss the change.
        let _room = self.room.lock().unwrap_or_else(|e| e.into_inner());
        self.changed.notify_all();
    }

    fn take(m: &Mutex<HashMap<Ipv4Addr, u32>>, client: Ipv4Addr, limit: u32) -> bool {
        let mut m = m.lock().unwrap_or_else(|e| e.into_inner());
        let n = m.entry(client).or_insert(0);
        if *n >= limit {
            return false;
        }
        *n += 1;
        true
    }

    fn release(m: &Mutex<HashMap<Ipv4Addr, u32>>, client: Ipv4Addr) {
        let mut m = m.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&client) {
            *n -= 1;
            if *n == 0 {
                m.remove(&client);
            }
        }
    }

    fn take_inflight(&self) -> bool {
        self.inflight
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_INFLIGHT).then_some(n + 1)
            })
            .is_ok()
    }

    fn wait_for(&self) -> Duration {
        if self.view().names.is_some() {
            self.cfg.unknown_wait
        } else {
            self.cfg.start_wait
        }
    }

    fn answer(&self, q: &msg::Query, name: Option<&str>, client: Ipv4Addr) -> Vec<u8> {
        let found = name.is_some_and(|n| self.view().resolves(client, n));
        msg::answer(q, found, self.cfg.listen.ip().octets(), TTL)
    }

    /// Blocks until client can be answered or the wait is over (TCP).
    fn await_client(&self, client: Ipv4Addr) {
        if client == *self.cfg.listen.ip() || self.view().answerable(client) {
            return;
        }
        if !Self::take(&self.per_client, client, MAX_INFLIGHT_PER_CLIENT) {
            return;
        }
        let deadline = Instant::now() + self.wait_for();
        let mut room = self.room.lock().unwrap_or_else(|e| e.into_inner());
        while !self.view().answerable(client) {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            room = self
                .changed
                .wait_timeout(room, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        drop(room);
        Self::release(&self.per_client, client);
    }
}

/// Answers waiting UDP lookups once their client is known or their wait
/// is over.
fn waiter(srv: &Server, udp: &UdpSocket) {
    let mut room = srv.room.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        let now = Instant::now();
        let view = srv.view();
        let mut ready = Vec::new();
        let mut i = 0;
        while i < room.len() {
            if room[i].deadline <= now || view.answerable(room[i].client) {
                ready.push(room.swap_remove(i));
            } else {
                i += 1;
            }
        }
        drop(room);
        for w in ready {
            let _ = udp.send_to(&srv.answer(&w.query, w.name.as_deref(), w.client), w.to);
            Server::release(&srv.per_client, w.client);
        }
        room = srv.room.lock().unwrap_or_else(|e| e.into_inner());
        if room
            .iter()
            .any(|w| w.deadline <= Instant::now() || srv.view().answerable(w.client))
        {
            continue;
        }
        let next = room.iter().map(|w| w.deadline).min();
        room = match next {
            Some(d) => {
                let wait = d.saturating_duration_since(Instant::now());
                srv.changed
                    .wait_timeout(room, wait)
                    .unwrap_or_else(|e| e.into_inner())
                    .0
            }
            None => srv.changed.wait(room).unwrap_or_else(|e| e.into_inner()),
        };
    }
}

/// Relays a query over TCP to the first upstream that answers.
fn forward_tcp(upstreams: &[SocketAddr], pkt: &[u8]) -> Option<Vec<u8>> {
    let want = msg::id(pkt)?;
    upstreams
        .iter()
        .filter_map(|up| exchange_tcp(*up, pkt).ok())
        .find(|r| msg::is_response(r, want))
}

fn exchange_tcp(up: SocketAddr, pkt: &[u8]) -> io::Result<Vec<u8>> {
    let mut s = TcpStream::connect_timeout(&up, FORWARD_TIMEOUT)?;
    s.set_read_timeout(Some(FORWARD_TIMEOUT))?;
    s.set_write_timeout(Some(FORWARD_TIMEOUT))?;
    write_frame(&mut s, pkt)?;
    read_frame(&mut s)
}

fn write_frame(s: &mut TcpStream, pkt: &[u8]) -> io::Result<()> {
    let len = u16::try_from(pkt.len()).map_err(|_| io::Error::other("message too long"))?;
    let mut out = Vec::with_capacity(pkt.len() + 2);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(pkt);
    s.write_all(&out)
}

fn read_frame(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    s.read_exact(&mut len)?;
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

fn serve_tcp(srv: &Arc<Server>, l: TcpListener) {
    loop {
        let (conn, from) = match l.accept() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("armada-dns: tcp: {e}");
                thread::sleep(Duration::from_millis(10));
                continue;
            }
        };
        let Some(client) = client_of(from).filter(|c| in_prefix(*c, srv.cfg.clients)) else {
            continue;
        };
        if srv.conns.load(Ordering::Acquire) >= MAX_CONNS
            || !Server::take(&srv.per_conn, client, MAX_CONNS_PER_CLIENT)
        {
            continue;
        }
        srv.conns.fetch_add(1, Ordering::AcqRel);
        let srv2 = srv.clone();
        let started = spawn(move || {
            let _ = serve_conn(&srv2, conn, client);
            srv2.conns.fetch_sub(1, Ordering::AcqRel);
            Server::release(&srv2.per_conn, client);
        });
        if started.is_err() {
            srv.conns.fetch_sub(1, Ordering::AcqRel);
            Server::release(&srv.per_conn, client);
        }
    }
}

fn serve_conn(srv: &Server, mut conn: TcpStream, client: Ipv4Addr) -> io::Result<()> {
    conn.set_write_timeout(Some(TCP_READ))?;
    loop {
        conn.set_read_timeout(Some(TCP_IDLE))?;
        let mut len = [0u8; 2];
        conn.read_exact(&mut len)?;
        conn.set_read_timeout(Some(TCP_READ))?;
        let mut pkt = vec![0u8; u16::from_be_bytes(len) as usize];
        conn.read_exact(&mut pkt)?;
        let resp = match msg::parse(&pkt, ZONE) {
            Request::Drop => continue,
            Request::Reply(r) => r,
            Request::Internal(q, name) => {
                srv.await_client(client);
                srv.answer(&q, name.as_deref(), client)
            }
            Request::Forward => {
                if !Server::take(&srv.per_client, client, MAX_INFLIGHT_PER_CLIENT) {
                    msg::servfail(&pkt)
                } else if !srv.take_inflight() {
                    Server::release(&srv.per_client, client);
                    msg::servfail(&pkt)
                } else {
                    let r = forward_tcp(&srv.cfg.upstreams, &pkt)
                        .unwrap_or_else(|| msg::servfail(&pkt));
                    srv.inflight.fetch_sub(1, Ordering::AcqRel);
                    Server::release(&srv.per_client, client);
                    r
                }
            }
        };
        write_frame(&mut conn, &resp)?;
    }
}

/// Stops taking new UDP lookups and answers the ones it holds, before the
/// process is stopped: connected to a port nobody sends from, the socket
/// leaves the address's other sockets (the next process) every new
/// datagram, while its queue can still be read.
fn drain(srv: &Server) {
    if let Some(u) = srv.udp.get()
        && let Err(e) = u.connect(SocketAddrV4::new(*srv.cfg.listen.ip(), 9))
    {
        eprintln!("armada-dns: drain: {e}");
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    thread::sleep(Duration::from_millis(100));
    while Instant::now() < deadline
        && (srv.inflight.load(Ordering::Acquire) > 0
            || !srv
                .room
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty())
    {
        thread::sleep(Duration::from_millis(20));
    }
}

/// Reads another process's state and applies what it knows that this one
/// does not.
fn take_over(srv: &Server, path: &str) -> io::Result<()> {
    let conn = UnixStream::connect(path)?;
    conn.set_read_timeout(Some(Duration::from_secs(5)))?;
    (&conn).write_all(b"state\n")?;
    let mut state = String::new();
    (&conn).take(MAX_CONTROL_LINE).read_to_string(&mut state)?;
    let view = srv.view();
    for line in state.lines() {
        let known = match line.split(' ').next() {
            Some("names") => view.names.is_some(),
            Some("clients") => view.clients.is_some(),
            _ => continue,
        };
        if !known {
            let reply = command(srv, line);
            if !reply.starts_with("ok") {
                return Err(io::Error::other(reply.trim_end().to_string()));
            }
        }
    }
    Ok(())
}

fn serve_control(srv: &Server, l: UnixListener) {
    for conn in l.incoming() {
        let Ok(conn) = conn else { continue };
        let _ = control(srv, conn);
    }
}

fn control(srv: &Server, conn: UnixStream) -> io::Result<()> {
    conn.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut line = String::new();
    BufReader::new((&conn).take(MAX_CONTROL_LINE)).read_line(&mut line)?;
    let reply = command(srv, line.trim_end_matches('\n'));
    (&conn).write_all(reply.as_bytes())
}

/// The names and clients a process knows, as `state` answers them.
fn state(v: &View) -> String {
    let mut out = match &v.names {
        Some(n) => {
            let mut n: Vec<&str> = n.iter().map(String::as_str).collect();
            n.sort_unstable();
            format!("names {}\n", n.join(" "))
        }
        None => "unnamed\n".to_string(),
    };
    match &v.clients {
        Some(c) => {
            let mut c: Vec<String> = c.iter().map(|(ip, app)| format!("{ip}={app}")).collect();
            c.sort_unstable();
            out.push_str(&format!("clients {}\n", c.join(" ")));
        }
        None => out.push_str("noclients\n"),
    }
    out
}

/// Where the process keeps what it knows, beside its control socket in
/// the root-only run directory (gone after a reboot).
fn state_path(srv: &Server) -> String {
    let c = &srv.cfg.control;
    format!("{}.state", c.strip_suffix(".sock").unwrap_or(c))
}

/// Writes what the process knows, so the same unit started again after a
/// crash answers at once instead of waiting for the agent.
fn save_state(srv: &Server) {
    let path = state_path(srv);
    let tmp = format!("{path}.tmp");
    let saved = fs::write(&tmp, state(&srv.view()))
        .and_then(|()| fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600)))
        .and_then(|()| fs::rename(&tmp, &path));
    if let Err(e) = saved {
        eprintln!("armada-dns: save {path}: {e}");
    }
}

/// Applies the state the same unit saved before it stopped, if any.
fn load_state(srv: &Server) {
    let Ok(saved) = fs::read_to_string(state_path(srv)) else {
        return;
    };
    for line in saved
        .lines()
        .filter(|l| l.starts_with("names") || l.starts_with("clients"))
    {
        let reply = command(srv, line);
        if !reply.starts_with("ok") {
            eprintln!("armada-dns: saved state: {}", reply.trim_end());
        }
    }
    eprintln!("armada-dns: started with the names and clients it saved");
}

fn command(srv: &Server, line: &str) -> String {
    let mut words = line.split(' ').filter(|w| !w.is_empty());
    let ok = || format!("ok {}\n", srv.epoch);
    match words.next() {
        Some("epoch") => ok(),
        Some("drain") => {
            drain(srv);
            ok()
        }
        Some("names") => {
            let mut set = HashSet::new();
            for w in words {
                if !names::valid_host_name(w) {
                    return format!("err invalid name {w:?}\n");
                }
                set.insert(w.to_string());
            }
            srv.set_view(|v| v.names = Some(set));
            save_state(srv);
            ok()
        }
        Some("clients") => {
            let mut map = HashMap::new();
            for w in words {
                let parsed = w
                    .split_once('=')
                    .and_then(|(ip, app)| Some((ip.parse::<Ipv4Addr>().ok()?, app)));
                match parsed {
                    Some((ip, app)) if names::valid_app_id(app) => {
                        map.insert(ip, app.to_string());
                    }
                    _ => return format!("err invalid client {w:?}\n"),
                }
            }
            srv.set_view(|v| v.clients = Some(map));
            save_state(srv);
            ok()
        }
        Some("state") => state(&srv.view()),
        _ => "err unknown request\n".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes() {
        let p = parse_prefix("10.120.3.0/24").unwrap();
        assert!(in_prefix("10.120.3.9".parse().unwrap(), p));
        assert!(!in_prefix("10.120.4.9".parse().unwrap(), p));
        assert!(in_prefix(
            "1.2.3.4".parse().unwrap(),
            parse_prefix("0.0.0.0/0").unwrap()
        ));
        assert!(parse_prefix("10.0.0.0/33").is_none());
        assert!(private("10.1.2.3".parse().unwrap()) && private("100.64.0.1".parse().unwrap()));
        assert!(!private("8.8.8.8".parse().unwrap()) && !private("100.128.0.1".parse().unwrap()));
    }

    #[test]
    fn args() {
        let a = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        let c = parse_args(&a("--listen 10.0.0.1:53 --clients 10.0.0.0/24 --upstream 10.0.0.1:53 --upstream 1.1.1.1:53 --control /x")).unwrap();
        assert_eq!(
            c.upstreams,
            vec!["1.1.1.1:53".parse::<SocketAddr>().unwrap()]
        );
        assert!(parse_args(&a("--listen 8.8.8.8:53 --clients 10.0.0.0/24 --control /x")).is_err());
        assert!(parse_args(&a("--listen 10.0.0.1:53 --control /x")).is_err());
        assert!(parse_args(&a("--bogus 1")).is_err());
    }

    #[test]
    fn views() {
        let c: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let mut v = View::default();
        assert!(!v.answerable(c));
        v.names = Some(
            ["web", "web.shop", "canary--web.shop"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );
        assert!(v.answerable(c) && v.resolves(c, "web.shop"));
        v.clients = Some([(c, "api.shop".to_string())].into());
        assert!(
            v.resolves(c, "canary--web.shop")
                && !v.resolves(c, "web")
                && !v.resolves(c, "ghost.shop")
        );
        let other: Ipv4Addr = "10.0.0.6".parse().unwrap();
        assert!(!v.answerable(other) && !v.resolves(other, "web.shop"));
    }
}

//! What the commands that stream need from the process and its terminal:
//! Ctrl-C and SIGTERM as the end of a followed stream, a terminal's size
//! and raw mode, and window size changes (SIGWINCH). Unix only;
//! Linux and macOS alike.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, OnceLock};

use tokio::sync::Notify;

/// The write end of the pipe signal handlers write to, one per signal set.
static INTERRUPT_FD: AtomicI32 = AtomicI32::new(-1);
static WINCH_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_interrupt(_: libc::c_int) {
    let fd = INTERRUPT_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: write is async-signal-safe; the buffer is static.
        unsafe { libc::write(fd, b"i".as_ptr().cast(), 1) };
    }
}

extern "C" fn on_winch(_: libc::c_int) {
    let fd = WINCH_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: as above.
        unsafe { libc::write(fd, b"w".as_ptr().cast(), 1) };
    }
}

/// A pipe whose read end a thread waits on, calling f for every byte.
fn pipe_thread(slot: &AtomicI32, f: impl Fn() + Send + 'static) -> bool {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: fds has room for the two descriptors pipe writes.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return false;
    }
    slot.store(fds[1], Ordering::Relaxed);
    let rfd = fds[0];
    std::thread::spawn(move || {
        let mut b = [0u8; 1];
        loop {
            // SAFETY: reads one byte into b from the pipe this thread owns.
            let n = unsafe { libc::read(rfd, b.as_mut_ptr().cast(), 1) };
            if n == 1 {
                f();
            } else if n == 0
                || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                return;
            }
        }
    });
    true
}

fn handle(sig: libc::c_int, handler: extern "C" fn(libc::c_int)) {
    // SAFETY: a zeroed sigaction with a handler that only writes to a
    // pipe; SA_RESTART keeps other system calls going.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

static INTERRUPT: OnceLock<Arc<Notify>> = OnceLock::new();

/// From now on, SIGINT and SIGTERM end what waits on the returned Notify
/// (signal.NotifyContext) instead of the process.
pub fn interrupts() -> Arc<Notify> {
    INTERRUPT
        .get_or_init(|| {
            let n = Arc::new(Notify::new());
            let m = n.clone();
            if pipe_thread(&INTERRUPT_FD, move || m.notify_one()) {
                handle(libc::SIGINT, on_interrupt);
                handle(libc::SIGTERM, on_interrupt);
            }
            n
        })
        .clone()
}

/// Calls f on a thread of its own whenever the window size changes.
pub fn on_window_change(f: impl Fn() + Send + 'static) {
    if pipe_thread(&WINCH_FD, f) {
        handle(libc::SIGWINCH, on_winch);
    }
}

/// term.GetSize: the columns and rows of the terminal on fd.
pub fn size(fd: i32) -> Option<(u32, u32)> {
    // SAFETY: TIOCGWINSZ fills the winsize it is given.
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) != 0 {
            return None;
        }
        Some((u32::from(ws.ws_col), u32::from(ws.ws_row)))
    }
}

/// A terminal put in raw mode, restored when dropped.
pub struct Raw {
    fd: i32,
    old: libc::termios,
}

/// term.MakeRaw.
pub fn make_raw(fd: i32) -> std::io::Result<Raw> {
    // SAFETY: tcgetattr fills the termios it is given; the copy changed
    // as x/term does is set back with tcsetattr.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut t) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let old = t;
        t.c_iflag &= !(libc::IGNBRK
            | libc::BRKINT
            | libc::PARMRK
            | libc::ISTRIP
            | libc::INLCR
            | libc::IGNCR
            | libc::ICRNL
            | libc::IXON);
        t.c_oflag &= !libc::OPOST;
        t.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
        t.c_cflag &= !(libc::CSIZE | libc::PARENB);
        t.c_cflag |= libc::CS8;
        t.c_cc[libc::VMIN] = 1;
        t.c_cc[libc::VTIME] = 0;
        if libc::tcsetattr(fd, libc::TCSANOW, &t) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Raw { fd, old })
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        // SAFETY: sets back the termios read before.
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.old) };
    }
}

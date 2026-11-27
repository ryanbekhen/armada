//! SIGINT and SIGTERM end a running server or agent: the first one turns a
//! watch to true; later ones are swallowed while the command stops. A
//! handler that writes to a pipe, so no signal is blocked for the
//! programs the agent starts.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicI32, Ordering};

use tokio::sync::watch;

static WRITE_FD: AtomicI32 = AtomicI32::new(-1);
static STOP: OnceLock<watch::Sender<bool>> = OnceLock::new();

extern "C" fn on_signal(_: libc::c_int) {
    let fd = WRITE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let b = 1u8;
        // SAFETY: write is async-signal-safe; b outlives the call.
        unsafe {
            libc::write(fd, (&b as *const u8).cast(), 1);
        }
    }
}

/// A watch that turns true at the first SIGINT or SIGTERM.
pub fn stop_on_signals() -> watch::Receiver<bool> {
    if let Some(tx) = STOP.get() {
        return tx.subscribe();
    }
    let (tx, rx) = watch::channel(false);
    let tx = STOP.get_or_init(|| tx);
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: fds holds two descriptors for pipe2 to fill.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return rx;
    }
    WRITE_FD.store(fds[1], Ordering::Relaxed);
    for sig in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: sa is plain data set up before sigaction reads it; the
        // handler only writes to the pipe.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as *const () as usize;
            sa.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
    let read = fds[0];
    let tx = tx.clone();
    std::thread::spawn(move || {
        let mut b = 0u8;
        loop {
            // SAFETY: read into one byte of b.
            let n = unsafe { libc::read(read, (&mut b as *mut u8).cast(), 1) };
            if n == 1 {
                let _ = tx.send(true);
            } else if n < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            } else {
                return;
            }
        }
    });
    rx
}

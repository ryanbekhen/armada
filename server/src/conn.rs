//! Accepting connections: TLS over TCP, with bounds (connections in all
//! and per source, the sources a listener accepts, the handshake's time,
//! and the join listener's idle limit), and the peer's address and
//! verified certificate for every request.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use armada_pki::Certificate;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, Sleep};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tonic::transport::server::Connected;

/// What a request knows about its connection: the peer's address and
/// verified certificate.
#[derive(Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    /// The verified client certificate, the chain's leaf; none on the
    /// join listener.
    pub cert: Option<Arc<Certificate>>,
}

/// How long a peer may take to finish the TLS handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounds of one listener's connections.
#[derive(Clone, Default)]
pub struct Limits {
    /// At most total connections, perSource from one address;
    /// zero means none.
    pub total: usize,
    pub per_source: usize,
    /// Closes a connection after this long with nothing read or written.
    pub idle: Option<Duration>,
    /// Connections from addresses it refuses are closed
    /// before TLS.
    pub allow: Option<Arc<dyn Fn(IpAddr) -> bool + Send + Sync>>,
}

#[derive(Default)]
struct Open {
    total: usize,
    by_src: HashMap<IpAddr, usize>,
}

/// Releases one connection's place in its listener's bounds.
struct Slot {
    open: Arc<Mutex<Open>>,
    src: IpAddr,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut o = self.open.lock().unwrap_or_else(|p| p.into_inner());
        o.total = o.total.saturating_sub(1);
        if let Some(n) = o.by_src.get_mut(&self.src) {
            *n -= 1;
            if *n == 0 {
                o.by_src.remove(&self.src);
            }
        }
    }
}

/// One accepted TLS connection.
pub struct Conn {
    inner: TlsStream<TcpStream>,
    info: PeerInfo,
    idle: Option<(Duration, Pin<Box<Sleep>>)>,
    /// Ends the connection when the listener is stopped for good.
    kill: Pin<Box<dyn Future<Output = ()> + Send>>,
    _slot: Option<Slot>,
}

impl Conn {
    fn closing(&mut self, cx: &mut Context<'_>) -> bool {
        if self.kill.as_mut().poll(cx).is_ready() {
            return true;
        }
        if let Some((_, s)) = &mut self.idle {
            return s.as_mut().poll(cx).is_ready();
        }
        false
    }

    fn touch(&mut self) {
        if let Some((d, s)) = &mut self.idle {
            s.as_mut().reset(Instant::now() + *d);
        }
    }
}

impl Connected for Conn {
    type ConnectInfo = PeerInfo;

    fn connect_info(&self) -> PeerInfo {
        self.info.clone()
    }
}

impl AsyncRead for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closing(cx) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection closed",
            )));
        }
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(r, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.touch();
        }
        r
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closing(cx) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection closed",
            )));
        }
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(r, Poll::Ready(Ok(n)) if n > 0) {
            self.touch();
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Accepts connections on l until stop turns true, sending each one that
/// finished its handshake. Connections still open when kill turns true are
/// closed.
pub fn accept(
    l: TcpListener,
    tls: TlsAcceptor,
    limits: Limits,
    mut stop: watch::Receiver<bool>,
    kill: watch::Receiver<bool>,
) -> mpsc::Receiver<io::Result<Conn>> {
    let (tx, rx) = mpsc::channel(16);
    let open = Arc::new(Mutex::new(Open::default()));
    tokio::spawn(async move {
        loop {
            let (tcp, addr) = tokio::select! {
                r = l.accept() => match r {
                    Ok(v) => v,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        continue;
                    }
                },
                _ = crate::stopped(&mut stop) => return,
            };
            let src = addr.ip().to_canonical();
            if let Some(allow) = &limits.allow
                && !allow(src)
            {
                drop(tcp);
                continue;
            }
            let slot = if limits.total > 0 {
                let mut o = open.lock().unwrap_or_else(|p| p.into_inner());
                let n = o.by_src.get(&src).copied().unwrap_or(0);
                if o.total >= limits.total || n >= limits.per_source {
                    drop(o);
                    drop(tcp);
                    continue;
                }
                o.total += 1;
                o.by_src.insert(src, n + 1);
                Some(Slot {
                    open: open.clone(),
                    src,
                })
            } else {
                None
            };
            let _ = tcp.set_nodelay(true);
            let tls = tls.clone();
            let tx = tx.clone();
            let idle = limits.idle;
            let mut kill = kill.clone();
            tokio::spawn(async move {
                let Ok(Ok(s)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, tls.accept(tcp)).await
                else {
                    return;
                };
                let cert = s
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|c| c.first())
                    .and_then(|c| Certificate::from_der(c.as_ref()).ok())
                    .map(Arc::new);
                let conn = Conn {
                    inner: s,
                    info: PeerInfo { addr, cert },
                    idle: idle.map(|d| (d, Box::pin(tokio::time::sleep(d)))),
                    kill: Box::pin(async move {
                        if kill.wait_for(|v| *v).await.is_err() {
                            std::future::pending::<()>().await;
                        }
                    }),
                    _slot: slot,
                };
                let _ = tx.send(Ok(conn)).await;
            });
        }
    });
    rx
}

//! The wake socket (ADR 0021): the node's proxy sends a request for an app
//! scaled to zero here; the agent asks the leader to start the app, holds the
//! request until the applied proxy configuration has a server for it, and
//! forwards it there as a reverse proxy (hop-by-hop headers dropped, the
//! proxy's X-Forwarded-For and X-Forwarded-Proto kept, upgrades such as
//! WebSocket carried through).

use std::collections::HashMap;
use std::convert::Infallible;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use armada_proto::armada::v1 as pb;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;

use crate::agent::{Agent, Inner, lock};
use crate::runtime::Runtime;

/// The requests held on one node for apps that are starting.
pub const MAX_WAITING: usize = 1000;
/// Those of one app, so one app that never starts cannot keep every other
/// app on the node asleep.
pub const MAX_WAITING_PER_APP: usize = 100;
/// How often a waiting app is asked for again.
pub const WAKE_EVERY: Duration = Duration::from_secs(5);
/// How long a request waits for a replica.
pub const WAKE_TIMEOUT: Duration = Duration::from_secs(60);
/// The header naming the app; only the proxy sets it.
pub const WAKE_HEADER: &str = "x-armada-wake";

/// The hop-by-hop headers (RFC 9110), dropped when forwarding.
const HOP_HEADERS: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

type Body = BoxBody<Bytes, hyper::Error>;

/// Holds requests for apps scaled to zero until a replica serves.
#[derive(Default)]
pub(crate) struct Waker {
    next: AtomicU64,
    st: std::sync::Mutex<WakerState>,
}

#[derive(Default)]
struct WakerState {
    held: usize,
    sent: HashMap<String, Instant>,
    waiting: HashMap<String, usize>,
}

impl Waker {
    /// Takes a place for a request of app: one of the node's and one of
    /// the app's own.
    pub(crate) fn hold(&self, app: &str) -> bool {
        let mut st = lock(&self.st);
        if st.waiting.get(app).copied().unwrap_or(0) >= MAX_WAITING_PER_APP
            || st.held >= MAX_WAITING
        {
            return false;
        }
        st.held += 1;
        *st.waiting.entry(app.to_string()).or_default() += 1;
        true
    }

    pub(crate) fn release(&self, app: &str) {
        let mut st = lock(&self.st);
        st.held = st.held.saturating_sub(1);
        if let Some(n) = st.waiting.get_mut(app) {
            *n -= 1;
            if *n == 0 {
                st.waiting.remove(app);
            }
        }
    }

    /// Whether a wake for app may be sent now (at most once per
    /// WAKE_EVERY), noting it.
    fn due(&self, app: &str) -> bool {
        let mut st = lock(&self.st);
        if st.sent.get(app).is_some_and(|t| t.elapsed() < WAKE_EVERY) {
            return false;
        }
        st.sent.insert(app.to_string(), Instant::now());
        if st.sent.len() > MAX_WAITING {
            st.sent.retain(|_, t| t.elapsed() < WAKE_EVERY);
        }
        true
    }
}

/// A place held for a request, given back when dropped.
struct Held<'a> {
    w: &'a Waker,
    app: &'a str,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.w.release(self.app);
    }
}

fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(|n| match n {}).boxed()
}

/// A plain text error answer: msg and a line break, with `nosniff`, and
/// `Retry-After: 5` when retry.
fn error(code: StatusCode, msg: &str, retry: bool) -> Response<Body> {
    let mut r = Response::new(full(format!("{msg}\n")));
    *r.status_mut() = code;
    let h = r.headers_mut();
    h.insert(
        "content-type",
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    if retry {
        h.insert("retry-after", HeaderValue::from_static("5"));
    }
    r
}

/// The value of Upgrade when Connection asks for one.
fn upgrade_type(h: &HeaderMap) -> Option<HeaderValue> {
    let asks = h.get_all("connection").iter().any(|v| {
        v.to_str().is_ok_and(|s| {
            s.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
    });
    if !asks {
        return None;
    }
    h.get("upgrade").cloned()
}

/// Removes the hop-by-hop headers and those Connection names.
fn remove_hop_headers(h: &mut HeaderMap) {
    let named: Vec<String> = h
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    for n in named {
        h.remove(n.as_str());
    }
    for n in HOP_HEADERS {
        // A TE of "trailers" only is kept.
        if n == "te"
            && h.get_all("te")
                .iter()
                .all(|v| v.to_str().is_ok_and(|s| s.trim() == "trailers"))
            && h.contains_key("te")
        {
            continue;
        }
        h.remove(n);
    }
}

/// The request as it goes to addr: the path and query kept, the host
/// kept, the wake header and hop-by-hop headers dropped, and of the
/// forwarding headers only the X-Forwarded-For and X-Forwarded-Proto the
/// node's proxy set.
fn outbound(req: Request<Incoming>) -> Request<Incoming> {
    let (mut parts, body) = req.into_parts();
    let up = upgrade_type(&parts.headers);
    let xff: Vec<HeaderValue> = parts
        .headers
        .get_all("x-forwarded-for")
        .iter()
        .cloned()
        .collect();
    let xfp: Vec<HeaderValue> = parts
        .headers
        .get_all("x-forwarded-proto")
        .iter()
        .cloned()
        .collect();
    let h = &mut parts.headers;
    h.remove(WAKE_HEADER);
    remove_hop_headers(h);
    for n in [
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
    ] {
        h.remove(n);
    }
    for (name, vals) in [("x-forwarded-for", xff), ("x-forwarded-proto", xfp)] {
        for v in vals {
            h.append(HeaderName::from_static(name), v);
        }
    }
    if let Some(up) = up {
        h.insert("connection", HeaderValue::from_static("Upgrade"));
        h.insert("upgrade", up);
    }
    let pq = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    parts.uri = pq.parse().unwrap_or_else(|_| hyper::Uri::from_static("/"));
    parts.version = hyper::Version::HTTP_11;
    Request::from_parts(parts, body)
}

impl<R: Runtime> Agent<R> {
    /// Serves the wake socket at path until the future is dropped.
    pub async fn serve_wake(&self, path: &str) {
        self.inner.clone().serve_wake(path.to_string()).await
    }

    /// One request on the wake socket, held at most `timeout`.
    pub async fn handle_wake(&self, req: Request<Incoming>, timeout: Duration) -> Response<Body> {
        self.inner.handle_wake(req, timeout).await
    }
}

impl<R: Runtime> Inner<R> {
    /// Listens on the wake socket, created with mode 0600 in the proxy's
    /// root-only run directory; no network port is opened.
    pub(crate) async fn serve_wake(self: Arc<Self>, path: String) {
        if let Err(e) = std::fs::remove_file(&path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            self.log.error("wake socket", &[("err", e.to_string())]);
            return;
        }
        let lis = match tokio::net::UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                self.log.error("wake socket", &[("err", e.to_string())]);
                return;
            }
        };
        if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
            self.log.error("wake socket", &[("err", e.to_string())]);
            return;
        }
        loop {
            let Ok((conn, _)) = lis.accept().await else {
                continue;
            };
            let me = self.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req| {
                    let me = me.clone();
                    async move { Ok::<_, Infallible>(me.handle_wake(req, WAKE_TIMEOUT).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .timer(hyper_util::rt::TokioTimer::new())
                    .header_read_timeout(Duration::from_secs(10))
                    .serve_connection(TokioIo::new(conn), svc)
                    .with_upgrades()
                    .await;
            });
        }
    }

    /// Holds a request until its app has a server in the applied proxy
    /// configuration, asking the leader to start one meanwhile, then
    /// forwards it there; after timeout it answers 503.
    pub(crate) async fn handle_wake(
        &self,
        req: Request<Incoming>,
        timeout: Duration,
    ) -> Response<Body> {
        let app = req
            .headers()
            .get(WAKE_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        if !armada_spec::validate::valid_app_id(&app) {
            return error(StatusCode::BAD_REQUEST, "bad request", false);
        }
        if !self.wakes.hold(&app) {
            self.wake(&app); // its app starts all the same
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "too many requests are waiting for apps to start",
                true,
            );
        }
        let _held = Held {
            w: &self.wakes,
            app: &app,
        };
        let Ok(addr) = tokio::time::timeout(timeout, self.await_server(&app)).await else {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!("{app} is starting; try again shortly"),
                true,
            );
        };
        self.forward(req, &addr).await
    }

    /// A server of app from the applied proxy configuration, asking the
    /// leader to start the app every WAKE_EVERY until one appears.
    async fn await_server(&self, app: &str) -> String {
        let mut changed = self.proxy_changed.subscribe();
        loop {
            let cfg = lock(&self.st).proxy_applied.clone();
            if let Some(be) = cfg
                .iter()
                .flat_map(|c| &c.backends)
                .find(|b| b.name == app && !b.servers.is_empty())
            {
                let n = self.wakes.next.fetch_add(1, Ordering::Relaxed) + 1;
                return be.servers[(n % be.servers.len() as u64) as usize]
                    .address
                    .clone();
            }
            self.wake(app);
            tokio::select! {
                _ = changed.changed() => {}
                _ = tokio::time::sleep(WAKE_EVERY) => {}
            }
        }
    }

    /// Asks the leader to start app, at most once per WAKE_EVERY.
    pub(crate) fn wake(&self, app: &str) {
        if !self.wakes.due(app) {
            return;
        }
        let Some(tx) = lock(&self.stream).tx.clone() else {
            return;
        };
        let msg = pb::AgentMessage {
            msg: Some(pb::agent_message::Msg::Wake(pb::Wake {
                app: app.to_string(),
            })),
        };
        if let Err(e) = tx.try_send(msg) {
            self.log.warn(
                "send wake failed",
                &[("app", app.to_string()), ("err", e.to_string())],
            );
        }
    }

    /// Forwards req to addr; an upgrade's streams are copied both ways.
    async fn forward(&self, mut req: Request<Incoming>, addr: &str) -> Response<Body> {
        let inbound_upgrade = hyper::upgrade::on(&mut req);
        let wants_upgrade = upgrade_type(req.headers()).is_some();
        let out = outbound(req);
        let res = async {
            let tcp = tokio::net::TcpStream::connect(addr).await?;
            let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
                .await
                .map_err(std::io::Error::other)?;
            tokio::spawn(conn.with_upgrades());
            send.send_request(out).await.map_err(std::io::Error::other)
        }
        .await;
        let mut res = match res {
            Ok(r) => r,
            Err(e) => {
                self.log
                    .error("http: proxy error", &[("err", e.to_string())]);
                let mut r = Response::new(full(Bytes::new()));
                *r.status_mut() = StatusCode::BAD_GATEWAY;
                return r;
            }
        };
        if res.status() == StatusCode::SWITCHING_PROTOCOLS && wants_upgrade {
            let upstream = hyper::upgrade::on(&mut res);
            let (parts, _) = res.into_parts();
            tokio::spawn(async move {
                if let (Ok(a), Ok(b)) = (inbound_upgrade.await, upstream.await) {
                    let _ =
                        tokio::io::copy_bidirectional(&mut TokioIo::new(a), &mut TokioIo::new(b))
                            .await;
                }
            });
            return Response::from_parts(parts, full(Bytes::new()));
        }
        let (mut parts, body) = res.into_parts();
        remove_hop_headers(&mut parts.headers);
        Response::from_parts(parts, body.boxed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use crate::runtime::{Container, ContainerSpec, Error, Image, RegistryAuth};

    struct NoRuntime;

    impl Runtime for NoRuntime {
        async fn ping(&self) -> crate::runtime::Result<()> {
            Ok(())
        }
        async fn pull(&self, _: &str, _: Option<&RegistryAuth>) -> crate::runtime::Result<Image> {
            Err(Error::other("no"))
        }
        async fn run(&self, _: &ContainerSpec) -> crate::runtime::Result<String> {
            Err(Error::other("no"))
        }
        async fn stop(&self, _: &str, _: Duration) -> crate::runtime::Result<()> {
            Ok(())
        }
        async fn remove(&self, _: &str) -> crate::runtime::Result<()> {
            Ok(())
        }
        async fn list(
            &self,
            _: &BTreeMap<String, String>,
        ) -> crate::runtime::Result<Vec<Container>> {
            Ok(Vec::new())
        }
        async fn inspect(&self, _: &str) -> crate::runtime::Result<Container> {
            Err(Error::NotFound)
        }
    }

    fn agent() -> Agent<NoRuntime> {
        let cfg = crate::Config {
            cpu_millis: 1,
            memory_bytes: 1,
            boot_time: Some(std::time::SystemTime::UNIX_EPOCH),
            ..Default::default()
        };
        Agent::new(cfg, NoRuntime)
    }

    fn socket_path(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("armada-wake-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("wake.sock").to_string_lossy().into_owned()
    }

    async fn wait_for(path: &str) {
        for _ in 0..200 {
            if std::path::Path::new(path).exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no socket");
    }

    /// Sends one request over the wake socket.
    async fn send(path: &str, app: &str) -> (StatusCode, HeaderMap, String) {
        let io = tokio::net::UnixStream::connect(path).await.unwrap();
        let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
            .await
            .unwrap();
        tokio::spawn(conn);
        let req = Request::post("/api/x?q=1")
            .header("host", "web.internal")
            .header("x-armada-wake", app)
            .header("x-forwarded-for", "203.0.113.9")
            .header("x-forwarded-host", "spoofed")
            .body(full("body"))
            .unwrap();
        let res = tx.send_request(req).await.unwrap();
        let (parts, body) = res.into_parts();
        let b = body.collect().await.unwrap().to_bytes();
        (
            parts.status,
            parts.headers,
            String::from_utf8_lossy(&b).into_owned(),
        )
    }

    /// A request for an app with no replica waits until the proxy
    /// configuration has one, then reaches it with its path, host, and
    /// forwarding headers, and without the wake header.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn holds_then_forwards() {
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap().to_string();
        let (got_tx, mut got_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            let (c, _) = backend.accept().await.unwrap();
            let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                let got = got_tx.clone();
                async move {
                    let h = req.headers();
                    let v = |n: &str| {
                        h.get(n)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string()
                    };
                    let line = format!(
                        "{} {} host={} wake={} xff={} xfh={}",
                        req.method(),
                        req.uri(),
                        v("host"),
                        v("x-armada-wake"),
                        v("x-forwarded-for"),
                        v("x-forwarded-host"),
                    );
                    let body = req.into_body().collect().await.unwrap().to_bytes();
                    let _ = got.send(format!("{line} body={}", String::from_utf8_lossy(&body)));
                    Ok::<_, Infallible>(Response::new(full("hello")))
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(c), svc)
                .await;
        });
        let a = agent();
        let path = socket_path("forward");
        let srv = a.clone();
        let p = path.clone();
        tokio::spawn(async move { srv.serve_wake(&p).await });
        wait_for(&path).await;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let inner = a.inner.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            lock(&inner.st).proxy_applied = Some(pb::ProxyConfig {
                backends: vec![pb::ProxyBackend {
                    name: "web".into(),
                    wake: true,
                    servers: vec![pb::ProxyServer {
                        name: "web-1".into(),
                        address: backend_addr,
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            });
            inner.proxy_changed.send_modify(|n| *n += 1);
        });
        let (code, _, body) = send(&path, "web").await;
        assert_eq!((code, body.as_str()), (StatusCode::OK, "hello"));
        assert_eq!(
            got_rx.recv().await.unwrap(),
            "POST /api/x?q=1 host=web.internal wake= xff=203.0.113.9 xfh= body=body"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refuses() {
        let a = agent();
        let path = socket_path("refuse");
        let srv = a.clone();
        let p = path.clone();
        tokio::spawn(async move { srv.serve_wake(&p).await });
        wait_for(&path).await;
        for app in ["", "Bad Name", "../x"] {
            let (code, h, body) = send(&path, app).await;
            assert_eq!(code, StatusCode::BAD_REQUEST, "app {app:?}");
            assert_eq!(body, "bad request\n");
            assert_eq!(h["content-type"], "text/plain; charset=utf-8");
        }
        for i in 0..MAX_WAITING {
            assert!(a.inner.wakes.hold(&format!("a{}", i % 20)));
        }
        let (code, h, body) = send(&path, "web").await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(h["retry-after"], "5");
        assert_eq!(body, "too many requests are waiting for apps to start\n");
    }

    #[test]
    fn places_per_node_and_per_app() {
        let w = Waker::default();
        for _ in 0..MAX_WAITING_PER_APP {
            assert!(w.hold("stuck"));
        }
        assert!(!w.hold("stuck"), "over the app's share");
        assert!(w.hold("shop"), "another app refused");
        w.release("stuck");
        assert!(w.hold("stuck"), "a released place not given back");
        let w = Waker::default();
        for i in 0..MAX_WAITING {
            assert!(w.hold(&format!("a{}", i % 20)));
        }
        assert!(!w.hold("other"), "over the node's places");
    }

    #[test]
    fn wakes_at_most_every_interval() {
        let w = Waker::default();
        assert!(w.due("web"));
        assert!(!w.due("web"));
        assert!(w.due("api"));
    }

    #[test]
    fn hop_headers() {
        let mut h = HeaderMap::new();
        h.insert(
            "connection",
            HeaderValue::from_static("keep-alive, X-Secret"),
        );
        h.insert("x-secret", HeaderValue::from_static("1"));
        h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        h.insert("te", HeaderValue::from_static("trailers"));
        h.insert("x-kept", HeaderValue::from_static("1"));
        remove_hop_headers(&mut h);
        let mut names: Vec<_> = h.keys().map(|k| k.as_str().to_string()).collect();
        names.sort();
        assert_eq!(names, ["te", "x-kept"]);
        let mut h = HeaderMap::new();
        h.insert("connection", HeaderValue::from_static("Upgrade"));
        h.insert("upgrade", HeaderValue::from_static("websocket"));
        assert_eq!(upgrade_type(&h).unwrap(), "websocket");
        h.insert("connection", HeaderValue::from_static("close"));
        assert!(upgrade_type(&h).is_none());
    }
}

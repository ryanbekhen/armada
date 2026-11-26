//! Calls of the API by method path with messages as bytes (encoded and
//! decoded by methods.rs), over TLS 1.3 as Armada's clients dial.

use std::sync::Arc;

use prost::bytes::{Buf, BufMut};
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Code, Status};

/// A client's TLS: the CA as the only root, the client certificate when
/// given (none for the join listener).
pub fn tls(ca: &[u8], client: Option<(&[u8], &[u8])>) -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(ca).flatten() {
        roots.add(c).map_err(|e| e.to_string())?;
    }
    let b = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots);
    let mut cfg = match client {
        Some((cert, key)) => {
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert)
                .filter_map(Result::ok)
                .collect();
            let key = PrivateKeyDer::from_pem_slice(key).map_err(|e| e.to_string())?;
            b.with_client_auth_cert(certs, key)
                .map_err(|e| e.to_string())?
        }
        None => b.with_no_client_auth(),
    };
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(cfg)
}

/// A lazy channel to addr.
pub fn channel(addr: &str, tls: rustls::ClientConfig) -> Channel {
    let tls = tokio_rustls::TlsConnector::from(Arc::new(tls));
    let name: ServerName<'static> =
        ServerName::try_from(armada_pki::SERVER_NAME).expect("a DNS name");
    let addr = addr.to_string();
    let connector = tower::service_fn(move |_: Uri| {
        let tls = tls.clone();
        let name = name.clone();
        let addr = addr.clone();
        async move {
            let tcp = tokio::net::TcpStream::connect(addr.as_str()).await?;
            tcp.set_nodelay(true)?;
            let s = tls.connect(name, tcp).await?;
            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(s))
        }
    });
    Endpoint::from_static("http://control-plane").connect_with_connector_lazy(connector)
}

/// Messages as their bytes.
#[derive(Clone, Copy, Default)]
pub struct Raw;

impl Codec for Raw {
    type Encode = Vec<u8>;
    type Decode = Vec<u8>;
    type Encoder = Raw;
    type Decoder = Raw;
    fn encoder(&mut self) -> Raw {
        Raw
    }
    fn decoder(&mut self) -> Raw {
        Raw
    }
}

impl Encoder for Raw {
    type Item = Vec<u8>;
    type Error = Status;
    fn encode(&mut self, item: Vec<u8>, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        dst.put_slice(&item);
        Ok(())
    }
}

impl Decoder for Raw {
    type Item = Vec<u8>;
    type Error = Status;
    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Vec<u8>>, Status> {
        let n = src.remaining();
        let mut out = vec![0; n];
        src.copy_to_slice(&mut out);
        Ok(Some(out))
    }
}

/// What sees a stream's messages before they are read.
pub type Tap = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// What a stream gave.
pub enum Item {
    Msg(Vec<u8>),
    Err(Status),
    /// Its end without an error (io.EOF to grpc-go).
    Eof,
}

/// An open call: what the scenario sends, and what came back in order.
pub struct Stream {
    send: Option<mpsc::UnboundedSender<Vec<u8>>>,
    recv: mpsc::UnboundedReceiver<Item>,
    header: Option<oneshot::Receiver<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
    ended: bool,
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Stream {
    /// Opens a call of path on ch.
    pub fn open(ch: Channel, path: &str) -> Stream {
        Stream::open_tapped(ch, path, None)
    }

    /// Opens a call whose messages tap sees first: those it takes are not
    /// read in order (a fake agent's volume requests, answered at once).
    pub fn open_tapped(ch: Channel, path: &str, tap: Option<Tap>) -> Stream {
        let (stx, srx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (rtx, rrx) = mpsc::unbounded_channel();
        let (htx, hrx) = oneshot::channel();
        let path: tonic::codegen::http::uri::PathAndQuery = path.parse().expect("a method path");
        let task = tokio::spawn(async move {
            let mut g = tonic::client::Grpc::new(ch);
            if let Err(e) = g.ready().await {
                let _ = htx.send(Vec::new());
                let _ = rtx.send(Item::Err(Status::unavailable(e.to_string())));
                return;
            }
            let req = tonic::Request::new(UnboundedReceiverStream::new(srx));
            match g.streaming(req, path, Raw).await {
                Err(s) => {
                    let _ = htx.send(Vec::new());
                    let _ = rtx.send(Item::Err(s));
                }
                Ok(resp) => {
                    let servers = resp
                        .metadata()
                        .get_all("armada-servers")
                        .iter()
                        .filter_map(|v| v.to_str().ok().map(str::to_string))
                        .collect();
                    let _ = htx.send(servers);
                    let mut body = resp.into_inner();
                    loop {
                        match body.message().await {
                            Ok(Some(m)) => {
                                if tap.as_ref().is_some_and(|t| t(&m)) {
                                    continue;
                                }
                                if rtx.send(Item::Msg(m)).is_err() {
                                    return;
                                }
                            }
                            Ok(None) => {
                                let _ = rtx.send(Item::Eof);
                                return;
                            }
                            Err(s) => {
                                let _ = rtx.send(Item::Err(s));
                                return;
                            }
                        }
                    }
                }
            }
        });
        Stream {
            send: Some(stx),
            recv: rrx,
            header: Some(hrx),
            task,
            ended: false,
        }
    }

    pub fn send(&self, m: Vec<u8>) {
        if let Some(s) = &self.send {
            let _ = s.send(m);
        }
    }

    pub fn close_send(&mut self) {
        self.send = None;
    }

    /// The next item; once the stream ended, its end again (grpc-go
    /// returns the same error to every later read).
    pub async fn recv(&mut self) -> Item {
        if self.ended {
            return Item::Eof;
        }
        match self.recv.recv().await {
            Some(Item::Msg(m)) => Item::Msg(m),
            Some(other) => {
                self.ended = true;
                other
            }
            None => {
                self.ended = true;
                Item::Eof
            }
        }
    }

    /// The next item if one comes within d.
    pub async fn recv_within(&mut self, d: std::time::Duration) -> Option<Item> {
        if self.ended {
            return Some(Item::Eof);
        }
        tokio::time::timeout(d, self.recv()).await.ok()
    }

    /// The response's armada-servers header (empty when the call failed
    /// before it).
    pub async fn header(&mut self) -> Vec<String> {
        match self.header.take() {
            Some(h) => h.await.unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Ends the call as a cancelled context does.
    pub fn cancel(&mut self) {
        self.task.abort();
        self.send = None;
    }
}

/// grpc-go's name of a code.
pub fn code_name(c: Code) -> &'static str {
    match c {
        Code::Ok => "OK",
        Code::Cancelled => "Canceled",
        Code::Unknown => "Unknown",
        Code::InvalidArgument => "InvalidArgument",
        Code::DeadlineExceeded => "DeadlineExceeded",
        Code::NotFound => "NotFound",
        Code::AlreadyExists => "AlreadyExists",
        Code::PermissionDenied => "PermissionDenied",
        Code::ResourceExhausted => "ResourceExhausted",
        Code::FailedPrecondition => "FailedPrecondition",
        Code::Aborted => "Aborted",
        Code::OutOfRange => "OutOfRange",
        Code::Unimplemented => "Unimplemented",
        Code::Internal => "Internal",
        Code::Unavailable => "Unavailable",
        Code::DataLoss => "DataLoss",
        Code::Unauthenticated => "Unauthenticated",
    }
}

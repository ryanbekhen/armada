//! This server's armada-kv member (ADR 0057) as `armadad kv` runs it, and
//! as `armadad init --state kv` and the commands that need the state while
//! no server runs start it in process: its name, directory, addresses,
//! certificate, and its listeners.
//!
//! A server whose state is in armada-kv has the member's directory
//! `<data dir>/kv` (and no `etcd`): the CA (`ca.crt`), the member
//! certificate and key (`member.crt`, `member.key`, the `etcd:member`
//! identity as etcd's), the database (`kv.db`), and, on a server that
//! joined until it votes, the members it joins through (`initial-cluster`).
//! The member listens on the server's private address only: the client API
//! on 7445 and the peer service on 7446, over mutual TLS (armada_kv::tls).

use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use armada_kv::{Node, Options, Start, TlsConnector, tls};
use armada_pki::{Ca, parse_cert_pem};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::agentconfig::{DIR_KV, FILE_CA_CERT, FILE_CA_KEY, FILE_KV_INITIAL, FILE_SERVER_CERT};
use crate::netutil;

pub const DEFAULT_CLIENT_PORT: u16 = 7445;
pub const DEFAULT_PEER_PORT: u16 = 7446;

/// What `armadad etcd` exits with on a server whose state is in armada-kv,
/// and `armadad kv` on one whose state is in etcd (EX_CONFIG): the unit
/// stays stopped (RestartPreventExitStatus in armada-etcd.service and
/// armada-kv.service), since the server runs the other store.
pub const EXIT_OTHER_STORE: i32 = 78;

/// Whether data_dir's server keeps the state in armada-kv: it has the
/// member's directory.
pub fn is_kv(data_dir: &str) -> bool {
    fs::symlink_metadata(Path::new(data_dir).join(DIR_KV)).is_ok_and(|m| m.is_dir())
}

/// The member's settings.
pub struct Config {
    pub dir: PathBuf,
    pub name: String,
    /// None when the server certificate names no address.
    pub addr: Option<IpAddr>,
    pub client_port: u16,
    pub peer_port: u16,
    pub ca: Option<Ca>,
    /// The peer URLs of the members a joining member asks for its ID
    /// (initial-cluster, its own left out).
    pub join: Vec<String>,
}

impl Config {
    pub fn client_url(&self) -> Option<String> {
        self.addr
            .map(|a| crate::etcdmember::member_url(&a, self.client_port))
    }

    pub fn peer_url(&self) -> Option<String> {
        self.addr
            .map(|a| crate::etcdmember::member_url(&a, self.peer_port))
    }
}

/// The peer URLs an initial cluster ("name=url,...") names.
fn initial_peers(text: &str) -> Vec<String> {
    text.split(',')
        .filter_map(|p| p.split_once('=').map(|(_, u)| u.trim().to_string()))
        .filter(|u| !u.is_empty())
        .collect()
}

/// Where data_dir's member lives and listens.
pub fn member_config(data_dir: &str) -> Config {
    let dd = Path::new(data_dir);
    let mut cfg = Config {
        dir: dd.join(DIR_KV),
        name: String::new(),
        addr: None,
        client_port: DEFAULT_CLIENT_PORT,
        peer_port: DEFAULT_PEER_PORT,
        ca: None,
        join: Vec::new(),
    };
    // A member on loopback ports of its own (test hooks only).
    if let Some((c, p)) = crate::hooks::get("KV_PORTS").and_then(|v| {
        let (c, p) = v.split_once(',')?;
        Some((c.parse().ok()?, p.parse().ok()?))
    }) {
        cfg.client_port = c;
        cfg.peer_port = p;
    }
    if let Ok(b) = armada_fsutil::read_private_file(&dd.join(FILE_SERVER_CERT))
        && let Ok(c) = parse_cert_pem(&b)
    {
        cfg.addr = c.ip_addresses.first().map(netutil::unmap);
    }
    if let Ok(b) = armada_fsutil::read_private_file(&dd.join(FILE_KV_INITIAL)) {
        let own = cfg.peer_url();
        cfg.join = initial_peers(&String::from_utf8_lossy(&b))
            .into_iter()
            .filter(|u| Some(u) != own.as_ref())
            .collect();
    }
    cfg
}

/// The member described from the data directory, named by the server
/// certificate's identity.
pub fn kv_config(data_dir: &str) -> Result<Config, String> {
    let dd = Path::new(data_dir);
    let mut pem = Vec::new();
    for n in [FILE_CA_CERT, FILE_CA_KEY, FILE_SERVER_CERT] {
        pem.push(armada_fsutil::read_private_file(&dd.join(n)).map_err(|e| e.to_string())?);
    }
    let ca = Ca::load(&pem[0], &pem[1]).map_err(|e| e.to_string())?;
    let cert = parse_cert_pem(&pem[2]).map_err(|e| e.to_string())?;
    match cert.identity() {
        Ok(id) if id.kind == armada_pki::KIND_SERVER => {
            let mut cfg = member_config(data_dir);
            cfg.name = id.name;
            cfg.ca = Some(ca);
            Ok(cfg)
        }
        _ => Err(format!("{FILE_SERVER_CERT} is not a server certificate")),
    }
}

/// Whether the member has state of its own: a database with something in
/// it.
fn has_state(dir: &Path) -> bool {
    fs::metadata(dir.join(armada_kv::node::DB_FILE)).is_ok_and(|m| m.len() > 0)
}

/// A running member: its listeners and Raft, until [`Member::shutdown`].
pub struct Member {
    pub node: Node,
    pub client_url: String,
    pub peer_url: String,
    pub dir: PathBuf,
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<Result<(), String>>>,
}

impl Member {
    /// Waits for stop, or for a listener to fail (its error).
    pub async fn wait(&mut self, stop: &mut watch::Receiver<bool>) -> Result<(), String> {
        use std::future::Future;
        use std::pin::Pin;
        use std::task::Poll;
        let ended = {
            let tasks = &mut self.tasks;
            let first = std::future::poll_fn(|cx| {
                for (i, t) in tasks.iter_mut().enumerate() {
                    if let Poll::Ready(r) = Pin::new(t).poll(cx) {
                        return Poll::Ready((i, r));
                    }
                }
                Poll::Pending
            });
            tokio::select! {
                _ = crate::stopped(stop) => None,
                v = first => Some(v),
            }
        };
        let Some((i, r)) = ended else { return Ok(()) };
        // An ended task is never polled again.
        drop(self.tasks.remove(i));
        match r {
            Ok(Ok(())) => Err("a listener of the member stopped".to_string()),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Stops serving (calls in flight get a grace) and closes the member.
    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        for t in std::mem::take(&mut self.tasks) {
            let _ = t.await;
        }
        self.node.close().await;
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

/// How [`start`] starts a member with no state of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fresh {
    /// A new cluster with this member alone (`armadad init --state kv`).
    New,
    /// Refused, unless the member joins (initial-cluster): a member that
    /// lost its database must not start a cluster of its own.
    Refuse,
}

/// The member checked, its directory and certificate made, its database
/// held, its listeners bound on the private address, and the member
/// opened and served.
pub async fn start(cfg: &mut Config, fresh: Fresh) -> Result<Member, String> {
    let Some(ca) = cfg.ca.as_ref().filter(|_| !cfg.name.is_empty()) else {
        return Err("armada-kv: Name and CA are required".to_string());
    };
    let addr = match cfg.addr {
        Some(a) if netutil::is_private(&a) => a,
        Some(a) => return Err(format!("armada-kv: listen address {a} must be private")),
        None => return Err("armada-kv: the server certificate names no address".to_string()),
    };
    let abs = std::path::absolute(&cfg.dir).map_err(|e| e.to_string())?;
    cfg.dir = PathBuf::from(crate::gopath::clean(&abs.to_string_lossy()));
    let dir = cfg.dir.clone();
    armada_fsutil::mkdir_private(&dir).map_err(|e| e.to_string())?;
    let existing = has_state(&dir);
    let start = if existing {
        // A member with state restarts from it; Start is not read.
        Start::New
    } else if !cfg.join.is_empty() {
        Start::Join(cfg.join.clone())
    } else if fresh == Fresh::New {
        Start::New
    } else {
        return Err(format!(
            "no armada-kv member in {}: `armadad init --state kv` or `armadad server join` makes one",
            dir.display()
        ));
    };
    crate::etcdmember::ensure_member_cert(&dir, ca, &addr)?;
    let server_cfg = tls::server_config(&dir).map_err(|e| e.to_string())?;
    let connector = TlsConnector::new(&dir).map_err(|e| e.to_string())?;
    let client_url = cfg.client_url().unwrap_or_default();
    let peer_url = cfg.peer_url().unwrap_or_default();
    let opts = Options {
        name: cfg.name.clone(),
        peer_urls: vec![peer_url.clone()],
        client_urls: vec![client_url.clone()],
        start,
        connector: Some(std::sync::Arc::new(connector)),
        ..Options::default()
    };
    // The database first: it is locked while it is open, so a second
    // process running the same member is refused here, before it binds
    // the member's ports.
    let node = Node::open(&dir, opts).await.map_err(|e| match e {
        armada_kv::Error::Storage(t) if t.ends_with("another process holds the database") => {
            format!(
                "another process runs the armada-kv member in {}; stop it first",
                dir.display()
            )
        }
        e => e.to_string(),
    })?;
    let bound = async {
        let api = tls::bind(SocketAddr::new(addr, cfg.client_port)).await?;
        let peer = tls::bind(SocketAddr::new(addr, cfg.peer_port)).await?;
        Ok::<_, armada_kv::Error>((api, peer))
    }
    .await;
    let (api, peer) = match bound {
        Ok(v) => v,
        Err(e) => {
            node.close().await;
            return Err(e.to_string());
        }
    };
    let (stop, rx) = watch::channel(false);
    let mut tasks = Vec::new();
    for (lis, is_peer) in [(api, false), (peer, true)] {
        let n = node.clone();
        let c = server_cfg.clone();
        let mut rx = rx.clone();
        tasks.push(tokio::spawn(async move {
            let shutdown = async move {
                let _ = rx.wait_for(|v| *v).await;
            };
            let r = if is_peer {
                tls::serve_peer_tls(n, lis, c, shutdown).await
            } else {
                tls::serve_api_tls(n, lis, c, shutdown).await
            };
            r.map_err(|e| e.to_string())
        }));
    }
    Ok(Member {
        node,
        client_url,
        peer_url,
        dir,
        stop,
        tasks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_cluster_names_peers() {
        assert_eq!(
            initial_peers("s1=https://10.0.0.4:7446,s2=https://10.0.0.5:7446\n"),
            vec!["https://10.0.0.4:7446", "https://10.0.0.5:7446"]
        );
        assert!(initial_peers("").is_empty());
        assert!(initial_peers("junk").is_empty());
    }
}

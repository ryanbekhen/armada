//! The move of the control plane's state from etcd to armada-kv (ADR 0057),
//! checked in process with no recording: clusters of the pinned etcd (one
//! member, or three on loopback ports), each server's armada-kv member in
//! this process on Unix sockets (a MoveHost of the test's own, as the
//! daemon's runs its member until the switch), the leader's pass of a term's
//! server, and every server's follower.
//!
//! - One server and three: the state moved, armada-kv's key space equal to
//!   etcd's at the move's revision (the election and the ACME locks left
//!   out), every member voting, every server told to switch, writes refused
//!   on etcd and working on armada-kv, StateMoved recorded there.
//! - A member that does not join: the move is given up, the cluster stays
//!   on etcd with writes working, StateMoveFailed recorded, the next try
//!   ten minutes away, every member's data removed.
//! - While the key space is copied, writes are refused (transactions,
//!   events, the ACME storage) and reads work.
//! - A leader that stops in the middle: the next term gives the move up
//!   before anything else.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use armada_kv::{Node, Options, Start, UnixConnector};
use armada_pki::{Ca, Identity, IssueRequest, SERVER_NAME};
use armada_proto::etcd::mvccpb::KeyValue;
use armada_server::cluster::{Cluster, MemberInfo, STATE_KV};
use armada_server::statemove::{self, Followed, MoveHost};
use armada_server::{Config, Server, lifecycle};
use armada_store::election::Leadership;
use armada_store::statemove::{self as sm, META_STATE_MOVE_MODE, STEP_MOVED};
use armada_store::{Client, Etcd, Kind};
use tokio::sync::{Notify, watch};
use tonic::codegen::async_trait;

const PREFIX: &str = "/armada/";

/// etcd members m0, m1, ... of one cluster: peers on loopback ports,
/// clients on Unix sockets in each member's directory.
struct Etcds {
    children: Vec<Child>,
    dirs: Vec<PathBuf>,
}

impl Drop for Etcds {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// A directory only its owner reaches, as a member's must be.
fn mkdir_private(p: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(p)
        .map_err(|e| format!("{}: {e}", p.display()))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("a loopback port")
}

impl Etcds {
    fn start(etcd: &Path, base: &Path, n: usize) -> Result<Etcds, String> {
        let _ = std::fs::remove_dir_all(base);
        let peers: Vec<String> = (0..n)
            .map(|_| format!("http://127.0.0.1:{}", free_port()))
            .collect();
        let initial: Vec<String> = peers
            .iter()
            .enumerate()
            .map(|(i, p)| format!("m{i}={p}"))
            .collect();
        let mut out = Etcds {
            children: Vec::new(),
            dirs: Vec::new(),
        };
        for (i, peer) in peers.iter().enumerate() {
            let dir = base.join(format!("e{i}"));
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let child = Command::new(etcd)
                .current_dir(&dir)
                .args(["--name", &format!("m{i}"), "--data-dir", "data"])
                .args(["--listen-client-urls", "unix://client.sock"])
                .args(["--advertise-client-urls", "unix://client.sock"])
                .args(["--listen-peer-urls", peer])
                .args(["--initial-advertise-peer-urls", peer])
                .arg("--initial-cluster")
                .arg(initial.join(","))
                .args(["--initial-cluster-token", "statemove"])
                .args(["--initial-cluster-state", "new"])
                .args(["--max-txn-ops", "4096", "--unsafe-no-fsync"])
                .args(["--enable-grpc-gateway=false", "--log-level", "error"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| format!("start {}: {e}", etcd.display()))?;
            out.children.push(child);
            out.dirs.push(dir);
        }
        Ok(out)
    }

    async fn client(&self, i: usize) -> Result<Client, String> {
        let sock = self.dirs[i].join("client.sock");
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if sock.exists() {
                let c = Client::connect_unix(&sock).map_err(|e| e.to_string())?;
                if let Ok(Ok(st)) = tokio::time::timeout(Duration::from_secs(3), c.status()).await
                    && st.leader != 0
                {
                    return Ok(c);
                }
            }
            if Instant::now() > deadline {
                return Err(format!("etcd m{i} did not become ready within a minute"));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// A server's member of the new store, in this process.
struct Running {
    id: String,
    node: Node,
    client: Client,
    halt: watch::Sender<bool>,
    served: Vec<tokio::task::JoinHandle<()>>,
}

/// The test's MoveHost: the member in `<dir>/kv.moving` on Unix sockets.
struct Host {
    name: String,
    dir: PathBuf,
    run: tokio::sync::Mutex<Option<Running>>,
    current: Mutex<Option<(String, Option<Client>)>>,
    leading: AtomicBool,
    /// Joining fails (the injected failure).
    fail_join: AtomicBool,
    /// start_new waits for this, when set.
    gate: Mutex<Option<Arc<Notify>>>,
    /// start_new reached the gate.
    at_gate: Notify,
}

impl Host {
    fn new(name: &str, dir: PathBuf) -> Arc<Host> {
        Arc::new(Host {
            name: name.to_string(),
            dir,
            run: tokio::sync::Mutex::new(None),
            current: Mutex::new(None),
            leading: AtomicBool::new(false),
            fail_join: AtomicBool::new(false),
            gate: Mutex::new(None),
            at_gate: Notify::new(),
        })
    }

    fn moving(&self) -> PathBuf {
        self.dir.join("kv.moving")
    }

    /// The peer URL its member takes: what its server record says.
    fn peer_url(&self) -> String {
        format!("unix://{}", self.moving().join("peer.sock").display())
    }

    async fn open(&self, id: &str, start: Start) -> Result<Client, String> {
        let dir = self.moving();
        let opts = Options {
            name: self.name.clone(),
            peer_urls: vec![self.peer_url()],
            client_urls: vec![format!("unix://{}", dir.join("client.sock").display())],
            start,
            connector: Some(Arc::new(UnixConnector)),
            ..Options::default()
        };
        let node = Node::open(&dir, opts).await.map_err(|e| e.to_string())?;
        let (halt, rx) = watch::channel(false);
        let mut served = Vec::new();
        for peer in [false, true] {
            let (n, mut rx) = (node.clone(), rx.clone());
            let sock = dir.join(if peer { "peer.sock" } else { "client.sock" });
            served.push(tokio::spawn(async move {
                let stop = async move {
                    let _ = rx.wait_for(|v| *v).await;
                };
                let _ = if peer {
                    armada_kv::serve_peer_unix(n, &sock, stop).await
                } else {
                    armada_kv::serve_unix(n, &sock, stop).await
                };
            }));
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        while !dir.join("client.sock").exists() {
            if Instant::now() > deadline {
                return Err("the member's socket did not appear".into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let client = Client::connect_unix(&dir.join("client.sock")).map_err(|e| e.to_string())?;
        *self.run.lock().await = Some(Running {
            id: id.to_string(),
            node,
            client: client.clone(),
            halt,
            served,
        });
        *self.current.lock().unwrap() = Some((id.to_string(), Some(client.clone())));
        Ok(client)
    }

    async fn stop(&self) {
        if let Some(r) = self.run.lock().await.take() {
            let _ = r.halt.send(true);
            for t in r.served {
                let _ = t.await;
            }
            r.node.close().await;
        }
    }

    /// The running member's client.
    async fn client(&self) -> Option<Client> {
        self.run.lock().await.as_ref().map(|r| r.client.clone())
    }

    async fn running_id(&self) -> Option<String> {
        self.run.lock().await.as_ref().map(|r| r.id.clone())
    }
}

#[async_trait]
impl MoveHost for Host {
    async fn start_new(
        &self,
        id: &str,
        revision: i64,
        kvs: Vec<KeyValue>,
        leases: Vec<(i64, i64)>,
    ) -> Result<Client, String> {
        let gate = self.gate.lock().unwrap().clone();
        if let Some(g) = gate {
            self.at_gate.notify_one();
            g.notified().await;
        }
        self.discard().await;
        mkdir_private(&self.moving())?;
        let mut w = armada_kv::snapshot::Writer::new(revision);
        for (l, ttl) in leases {
            w.lease(l, ttl);
        }
        for kv in &kvs {
            w.kv(kv);
        }
        let db = self.moving().join(armada_kv::node::DB_FILE);
        drop(
            armada_kv::mvcc::Store::restore(&w.finish(), &db, Default::default())
                .map_err(|e| e.to_string())?,
        );
        *self.current.lock().unwrap() = Some((id.to_string(), None));
        let c = self.open(id, Start::New).await?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(Ok(st)) = tokio::time::timeout(Duration::from_secs(3), c.status()).await
                && st.leader != 0
            {
                return Ok(c);
            }
            if Instant::now() > deadline {
                return Err("the new member did not lead".into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn join(&self, id: &str, peers: &[String]) -> Result<(), String> {
        if self.fail_join.load(Ordering::SeqCst) {
            return Err("injected: this member cannot start".into());
        }
        if self.member(id).is_some() {
            return Ok(());
        }
        self.discard().await;
        mkdir_private(&self.moving())?;
        *self.current.lock().unwrap() = Some((id.to_string(), None));
        self.open(id, Start::Join(peers.to_vec())).await.map(drop)
    }

    fn current(&self) -> Option<String> {
        self.current
            .lock()
            .unwrap()
            .as_ref()
            .map(|(i, _)| i.clone())
    }

    fn member(&self, id: &str) -> Option<Client> {
        match self.current.lock().unwrap().as_ref() {
            Some((i, Some(c))) if i == id => Some(c.clone()),
            _ => None,
        }
    }

    async fn discard(&self) {
        self.stop().await;
        let _ = std::fs::remove_dir_all(self.moving());
        *self.current.lock().unwrap() = None;
    }

    fn set_leading(&self, on: bool) {
        self.leading.store(on, Ordering::SeqCst);
    }

    fn leading(&self) -> bool {
        self.leading.load(Ordering::SeqCst)
    }
}

/// The etcd membership, every member answering; on armada-kv once moved.
struct Members {
    c: Client,
    kv: bool,
}

#[async_trait]
impl Cluster for Members {
    fn state(&self) -> &'static str {
        if self.kv { STATE_KV } else { "" }
    }

    async fn members(&self) -> Result<Vec<MemberInfo>, String> {
        let ms = self.c.member_list().await.map_err(|e| e.to_string())?;
        Ok(ms
            .into_iter()
            .map(|m| MemberInfo {
                id: m.id,
                name: m.name,
                learner: m.is_learner,
                client_url: m.client_ur_ls.first().cloned().unwrap_or_default(),
            })
            .collect())
    }

    async fn add_learner(
        &self,
        _: &str,
        _: std::net::IpAddr,
        _: u16,
    ) -> Result<(u64, String), String> {
        Err("not in this test".into())
    }

    async fn promote(&self) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }

    async fn reachable(&self, _: &MemberInfo) -> bool {
        true
    }

    async fn remove_member(&self, _: u64) -> Result<(), String> {
        Err("not in this test".into())
    }
}

/// A cluster of n servers on etcd with state worth moving.
struct Fixture {
    _etcds: Etcds,
    clients: Vec<Client>,
    hosts: Vec<Arc<Host>>,
    names: Vec<String>,
    ca: Ca,
    cert: (Vec<u8>, Vec<u8>),
}

fn check(ok: bool, what: impl Into<String>) -> Result<(), String> {
    if ok { Ok(()) } else { Err(what.into()) }
}

fn es(e: armada_store::Error) -> String {
    e.to_string()
}

impl Fixture {
    async fn new(etcd: &Path, case: &str, n: usize) -> Result<Fixture, String> {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("statemove-{case}"));
        let etcds = Etcds::start(etcd, &base, n)?;
        let mut clients = Vec::new();
        for i in 0..n {
            clients.push(etcds.client(i).await?);
        }
        let names: Vec<String> = (0..n).map(|i| format!("s{i}")).collect();
        let hosts: Vec<Arc<Host>> = names
            .iter()
            .enumerate()
            .map(|(i, nm)| Host::new(nm, base.join(format!("h{i}"))))
            .collect();
        for h in &hosts {
            std::fs::create_dir_all(&h.dir).map_err(|e| e.to_string())?;
        }
        let c = &clients[0];
        let st = Etcd::new(c.clone(), PREFIX).await.map_err(es)?;
        let members = c.member_list().await.map_err(es)?;
        for (i, nm) in names.iter().enumerate() {
            let id = members
                .iter()
                .find(|m| m.name == format!("m{i}"))
                .map(|m| m.id)
                .unwrap_or_default();
            st.upsert_server(&armada_store::Server {
                name: nm.clone(),
                private_ip: "10.0.0.5".into(),
                api_addr: format!("10.0.0.{}:7443", 5 + i),
                join_addr: String::new(),
                member_id: id,
                schema: armada_store::SCHEMA,
                version: "test".into(),
                created_at: armada_spec::gotime::Time::zero(),
                kv_peer_url: hosts[i].peer_url(),
            })
            .await
            .map_err(es)?;
        }
        // Records, an event on a lease, more keys than one read's page,
        // a key outside the store's prefix, ACME data and a lock.
        st.know_user("ryan").await.map_err(es)?;
        st.set_meta("root_domain", "apps.example.com")
            .await
            .map_err(es)?;
        let mut ev = armada_store::Event {
            key: String::new(),
            kind: "cluster".into(),
            object: "x".into(),
            app: String::new(),
            node: String::new(),
            reason: "Tested".into(),
            message: "before the move".into(),
            count: 1,
            first: armada_store::gojson::now(),
            last: armada_store::gojson::now(),
        };
        st.put_event(&ev, "").await.map_err(es)?;
        ev.reason = "Tested2".into();
        st.put_event(&ev, "").await.map_err(es)?;
        for chunk in (0..1500).collect::<Vec<_>>().chunks(500) {
            let ops = chunk
                .iter()
                .map(|i| armada_store::client::op::put(&format!("{PREFIX}test/k{i:04}"), b"v", 0))
                .collect();
            c.txn(armada_proto::etcd::etcdserverpb::TxnRequest {
                compare: Vec::new(),
                success: ops,
                failure: Vec::new(),
            })
            .await
            .map_err(es)?;
        }
        c.put("/elsewhere/key", b"kept").await.map_err(es)?;
        c.put("/armada-acme/data/certificates/a.example.com", b"cert")
            .await
            .map_err(es)?;
        let lease = c.grant(60).await.map_err(es)?;
        c.txn(armada_proto::etcd::etcdserverpb::TxnRequest {
            compare: Vec::new(),
            success: vec![armada_store::client::op::put(
                "/armada-acme/locks/issue/1",
                b"",
                lease,
            )],
            failure: Vec::new(),
        })
        .await
        .map_err(es)?;
        let ca = Ca::new("test").map_err(|e| e.to_string())?;
        let (cert, key) = ca
            .issue(&IssueRequest {
                identity: Identity::new("server", "s0"),
                dns_names: vec![SERVER_NAME.to_string()],
                ips: Vec::new(),
                server: true,
                client: false,
                validity: Duration::ZERO,
            })
            .map_err(|e| e.to_string())?;
        Ok(Fixture {
            _etcds: etcds,
            clients,
            hosts,
            names,
            cert: (cert, key.expose().to_vec()),
            ca,
        })
    }

    /// The term's server of leader i on store st (fenced on its term), on
    /// etcd or armada-kv.
    fn server(&self, i: usize, st: Etcd, members: Client, kv: bool) -> Result<Server, String> {
        let sc =
            armada_server::tls::ServerCert::new(&self.ca.cert_pem, &self.cert.0, &self.cert.1)?;
        let mut cfg = Config::new(st, sc);
        cfg.name = self.names[i].clone();
        cfg.manual_passes = true;
        cfg.cluster = Some(Arc::new(Members { c: members, kv }));
        cfg.state_mover = Some(self.hosts[i].clone() as Arc<dyn MoveHost>);
        cfg.state_move_timing = statemove::Timing {
            stable: Duration::from_secs(600),
            every: Duration::from_millis(200),
            join_wait: Duration::from_secs(4),
            limit: Duration::from_secs(60),
        };
        if std::env::var_os("ARMADA_SERVER_VERBOSE").is_some() {
            cfg.log = armada_server::log::Logger::stderr(true);
        }
        Server::new(cfg)
    }

    /// Every server's follower, as each daemon runs it.
    fn follow(&self, stop: &watch::Receiver<bool>) -> Vec<tokio::task::JoinHandle<Followed>> {
        (0..self.names.len())
            .map(|i| {
                tokio::spawn(statemove::follow(
                    self.clients[i].clone(),
                    PREFIX.to_string(),
                    self.names[i].clone(),
                    self.hosts[i].clone() as Arc<dyn MoveHost>,
                    armada_server::log::Logger::discard(),
                    Duration::from_millis(100),
                    stop.clone(),
                ))
            })
            .collect()
    }
}

/// A store fenced on a new term of leader name.
async fn term(c: &Client, name: &str) -> Result<(Leadership, Etcd), String> {
    let l = Leadership::campaign(c, Duration::from_secs(5), name)
        .await
        .map_err(es)?;
    let st = Etcd::new(c.clone(), PREFIX).await.map_err(es)?;
    let (k, rev) = l.fence();
    let fenced = st.fenced(&k, rev);
    Ok((l, fenced))
}

async fn events(st: &Etcd) -> Result<Vec<String>, String> {
    Ok(st
        .list_events(&armada_spec::gotime::Time::zero())
        .await
        .map_err(es)?
        .into_iter()
        .map(|e| e.reason)
        .collect())
}

/// One server, or three: the whole move.
pub async fn moved(etcd: &Path, n: usize) -> Result<(), String> {
    let fx = Fixture::new(etcd, &format!("moved{n}"), n).await?;
    let (stop_tx, stop) = watch::channel(false);
    let followers = fx.follow(&stop);
    let (lead, fenced) = term(&fx.clients[0], "s0").await?;
    let srv = fx.server(0, fenced.clone(), fx.clients[0].clone(), false)?;
    // Auto waits ten minutes; now moves at the next pass.
    fenced
        .set_meta(META_STATE_MOVE_MODE, "now")
        .await
        .map_err(es)?;
    srv.state_move_pass().await?;
    let (m, _) = fenced
        .state_move()
        .await
        .map_err(es)?
        .ok_or("no move record in etcd")?;
    check(
        m.step == STEP_MOVED,
        format!("etcd's record says {}", m.step),
    )?;
    check(
        fenced.get_meta(META_STATE_MOVE_MODE).await.map_err(es)? == "auto",
        "now was not used up",
    )?;
    // Every server is told to switch.
    for (i, f) in followers.into_iter().enumerate() {
        let r = tokio::time::timeout(Duration::from_secs(20), f)
            .await
            .map_err(|_| format!("s{i} was not told the state moved"))?
            .map_err(|e| e.to_string())?;
        check(
            r == Followed::Moved(m.id.clone()),
            format!("s{i} followed to {r:?}"),
        )?;
    }
    // armada-kv holds etcd's key space at the move's revision, the
    // election's keys and the ACME locks left out.
    let kc = fx.hosts[0].client().await.ok_or("no armada-kv member")?;
    let (_, want) = sm::read_key_space(&fx.clients[0], m.revision, PREFIX)
        .await
        .map_err(es)?;
    let (_, got) = sm::read_key_space(&kc, 0, PREFIX).await.map_err(es)?;
    check(
        sm::key_space_difference(&want, &got).is_none(),
        format!("{:?}", sm::key_space_difference(&want, &got)),
    )?;
    check(
        want.len() > 1500,
        format!("only {} keys copied", want.len()),
    )?;
    for (k, kept) in [
        ("/elsewhere/key", true),
        ("/armada-acme/data/certificates/a.example.com", true),
        ("/armada-acme/locks/issue/1", false),
    ] {
        let r = kc
            .range(armada_store::client::op::get(k, 0))
            .await
            .map_err(es)?;
        check(r.kvs.is_empty() != kept, format!("{k} kept: {}", !kept))?;
    }
    let r = kc
        .range(armada_store::client::op::get_prefix("/armada-leader/", 0))
        .await
        .map_err(es)?;
    check(r.kvs.is_empty(), "the election's keys were copied")?;
    let members = kc.member_list().await.map_err(es)?;
    check(
        members.len() == n && members.iter().all(|m| !m.is_learner),
        format!("{} armada-kv members", members.len()),
    )?;
    for (i, h) in fx.hosts.iter().enumerate() {
        check(
            h.running_id().await.as_deref() == Some(m.id.as_str()),
            format!("s{i}'s member does not run"),
        )?;
    }
    // Writes: refused on etcd for good, working on armada-kv.
    let plain = Etcd::new(fx.clients[n - 1].clone(), PREFIX)
        .await
        .map_err(es)?;
    match plain.set_meta("after", "x").await {
        Err(e) if e.kind == Kind::Moving => {}
        r => return Err(format!("a write to etcd after the move: {r:?}")),
    }
    let ks = Etcd::new(kc.clone(), PREFIX).await.map_err(es)?;
    check(
        ks.get_meta("root_domain").await.map_err(es)? == "apps.example.com",
        "root domain on armada-kv",
    )?;
    ks.set_meta("after", "x").await.map_err(es)?;
    // The new leader on armada-kv records StateMoved once.
    drop(srv);
    let _ = lead.resign().await;
    let (_kl, kfenced) = term(&kc, "s0").await?;
    let ksrv = fx.server(0, kfenced.clone(), kc.clone(), true)?;
    ksrv.state_move_pass().await?;
    ksrv.state_move_pass().await?;
    let evs = events(&kfenced).await?;
    check(
        evs.iter().filter(|r| *r == statemove::EVENT_MOVED).count() == 1
            && evs.iter().any(|r| r == statemove::EVENT_STARTED),
        format!("events on armada-kv: {evs:?}"),
    )?;
    let (m2, _) = kfenced
        .state_move()
        .await
        .map_err(es)?
        .ok_or("no record on armada-kv")?;
    check(m2.told && m2.step == STEP_MOVED, format!("{m2:?}"))?;
    let _ = stop_tx.send(true);
    for h in &fx.hosts {
        h.discard().await;
    }
    Ok(())
}

/// A member that does not join: given up, writes work again on etcd.
pub async fn failed(etcd: &Path) -> Result<(), String> {
    let fx = Fixture::new(etcd, "failed", 2).await?;
    fx.hosts[1].fail_join.store(true, Ordering::SeqCst);
    let (stop_tx, stop) = watch::channel(false);
    let followers = fx.follow(&stop);
    let (_lead, fenced) = term(&fx.clients[0], "s0").await?;
    let srv = fx.server(0, fenced.clone(), fx.clients[0].clone(), false)?;
    fenced
        .set_meta(META_STATE_MOVE_MODE, "now")
        .await
        .map_err(es)?;
    let err = srv.state_move_pass().await.err().unwrap_or_default();
    check(
        err.contains("did not join"),
        format!("the move's error: {err:?}"),
    )?;
    check(
        fenced.state_move().await.map_err(es)?.is_none(),
        "the record stayed",
    )?;
    let plain = Etcd::new(fx.clients[1].clone(), PREFIX).await.map_err(es)?;
    plain.set_meta("after", "x").await.map_err(es)?;
    let evs = events(&fenced).await?;
    check(
        evs.iter().any(|r| r == statemove::EVENT_FAILED),
        format!("events: {evs:?}"),
    )?;
    let retry = fenced
        .get_meta(armada_store::statemove::META_STATE_MOVE_RETRY)
        .await
        .map_err(es)?;
    check(
        retry.contains("\"failures\":1"),
        format!("retry record {retry}"),
    )?;
    // The next try waits: auto again, and within the backoff.
    srv.state_move_pass().await?;
    check(
        fenced.state_move().await.map_err(es)?.is_none(),
        "a move started within the backoff",
    )?;
    // Every member's data is removed.
    let deadline = Instant::now() + Duration::from_secs(10);
    while fx
        .hosts
        .iter()
        .any(|h| h.moving().exists() || h.current().is_some())
    {
        if Instant::now() > deadline {
            return Err("a member's data stayed".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = stop_tx.send(true);
    for f in followers {
        let r = f.await.map_err(|e| e.to_string())?;
        check(r == Followed::Stopped, format!("{r:?}"))?;
    }
    Ok(())
}

/// While the key space is copied: writes refused, reads working.
pub async fn copying(etcd: &Path) -> Result<(), String> {
    let fx = Fixture::new(etcd, "copying", 1).await?;
    let gate = Arc::new(Notify::new());
    *fx.hosts[0].gate.lock().unwrap() = Some(gate.clone());
    let (stop_tx, stop) = watch::channel(false);
    let followers = fx.follow(&stop);
    let (_lead, fenced) = term(&fx.clients[0], "s0").await?;
    let srv = fx.server(0, fenced.clone(), fx.clients[0].clone(), false)?;
    fenced
        .set_meta(META_STATE_MOVE_MODE, "now")
        .await
        .map_err(es)?;
    let pass = {
        let srv = srv.clone();
        tokio::spawn(async move { srv.state_move_pass().await })
    };
    tokio::time::timeout(Duration::from_secs(20), fx.hosts[0].at_gate.notified())
        .await
        .map_err(|_| "the move did not start")?;
    let plain = Etcd::new(fx.clients[0].clone(), PREFIX).await.map_err(es)?;
    match plain.set_meta("during", "x").await {
        Err(e) if e.kind == Kind::Moving && e.to_string().contains("state is moving") => {}
        r => return Err(format!("a transaction while copying: {r:?}")),
    }
    match fenced.set_meta("during", "x").await {
        Err(e) if e.kind == Kind::Moving => {}
        r => return Err(format!("the leader's transaction while copying: {r:?}")),
    }
    let ev = armada_store::Event {
        key: String::new(),
        kind: "cluster".into(),
        object: "x".into(),
        app: String::new(),
        node: String::new(),
        reason: "During".into(),
        message: String::new(),
        count: 1,
        first: armada_store::gojson::now(),
        last: armada_store::gojson::now(),
    };
    match fenced.put_event(&ev, "").await {
        Err(e) if e.kind == Kind::Moving => {}
        r => return Err(format!("an event while copying: {r:?}")),
    }
    let acme = armada_server::certs::EtcdStorage::new(fx.clients[0].clone(), "/armada-acme/")
        .map_err(es)?
        .frozen_by(&plain.moving_key());
    match acme.store("certificates/b", b"x").await {
        Err(e) if e.kind == Kind::Moving => {}
        r => return Err(format!("an ACME write while copying: {r:?}")),
    }
    check(
        plain.get_meta("root_domain").await.map_err(es)? == "apps.example.com",
        "a read while copying",
    )?;
    check(
        !plain.list_servers().await.map_err(es)?.is_empty(),
        "a list while copying",
    )?;
    gate.notify_one();
    pass.await.map_err(|e| e.to_string())??;
    match acme.store("certificates/b", b"x").await {
        Err(e) if e.kind == Kind::Moving => {}
        r => return Err(format!("an ACME write after the move: {r:?}")),
    }
    let _ = stop_tx.send(true);
    for f in followers {
        let _ = f.await;
    }
    for h in &fx.hosts {
        h.discard().await;
    }
    Ok(())
}

/// A leader stopped while copying: the next term gives the move up first.
pub async fn interrupted(etcd: &Path) -> Result<(), String> {
    let fx = Fixture::new(etcd, "interrupted", 1).await?;
    let (lead, fenced) = term(&fx.clients[0], "s0").await?;
    let rec = sm::StateMove {
        id: "0123456789abcdef".into(),
        step: sm::STEP_COPYING.into(),
        leader: "s0".into(),
        servers: vec!["s0".into()],
        started_at: 1,
        ..Default::default()
    };
    fenced.begin_state_move(&rec).await.map_err(es)?;
    match fenced.set_meta("during", "x").await {
        Err(e) if e.kind == Kind::Moving => {}
        r => return Err(format!("a write while copying: {r:?}")),
    }
    // The leader stops.
    lead.resign().await.map_err(es)?;
    let st = Etcd::new(fx.clients[0].clone(), PREFIX).await.map_err(es)?;
    let l2 = Leadership::campaign(&fx.clients[0], Duration::from_secs(5), "s0")
        .await
        .map_err(es)?;
    let (stop_tx, stop) = watch::channel(false);
    let stop_tx = Arc::new(stop_tx);
    let seen: Arc<Mutex<Option<Result<(), String>>>> = Arc::default();
    let res = {
        let (seen, stop_tx) = (seen.clone(), stop_tx.clone());
        lifecycle::term(
            &st,
            &l2,
            &armada_server::log::Logger::discard(),
            stop,
            move |fenced, _, _| {
                let (seen, stop_tx) = (seen.clone(), stop_tx.clone());
                async move {
                    let r = async {
                        check(
                            fenced.state_move().await.map_err(es)?.is_none(),
                            "the record stayed",
                        )?;
                        fenced.set_meta("after", "x").await.map_err(es)
                    }
                    .await;
                    *seen.lock().unwrap() = Some(r);
                    let _ = stop_tx.send(true);
                    Ok(())
                }
            },
        )
        .await
    };
    res.map_err(|e| format!("the term: {e:?}"))?;
    seen.lock()
        .unwrap()
        .take()
        .ok_or("the term's server did not run")??;
    let evs = events(&st).await?;
    check(
        evs.iter().any(|r| r == statemove::EVENT_FAILED),
        format!("events: {evs:?}"),
    )?;
    Ok(())
}

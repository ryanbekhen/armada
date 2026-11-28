//! Raft between armada-kv members (ADR 0057), in one process: three members
//! on Unix sockets whose connections a test can cut, killed and restarted
//! from their own databases. Every acknowledged write must survive, no
//! read may see the revision go back, and leases must neither outlive
//! their TTL by more than one TTL nor expire early, whatever the leader
//! does.

use std::collections::{BTreeMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use armada_kv::command::{Command, Op};
use armada_kv::peer::{BoxFuture, BoxIo, Connector, connect_unix};
use armada_kv::{Error, Node, Options, Start, Timing};
use armada_proto::etcd::etcdserverpb as pb;
use openraft::async_runtime::WatchReceiver;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;

/// Connections cut between members, by name.
#[derive(Default)]
struct Faults {
    cut: Mutex<HashSet<(String, String)>>,
}

impl Faults {
    fn blocked(&self, from: &str, to: &str) -> bool {
        self.cut
            .lock()
            .unwrap()
            .contains(&(from.to_string(), to.to_string()))
    }
}

/// A member's connector: Unix sockets, refused or broken while the test
/// cuts the pair.
struct FaultConnector {
    from: String,
    faults: Arc<Faults>,
}

/// The member a peer URL (unix://<dir>/<name>/peer.sock) names.
fn name_of(url: &str) -> String {
    Path::new(url.trim_start_matches("unix://"))
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

impl Connector for FaultConnector {
    fn connect(&self, url: &str) -> BoxFuture<io::Result<BoxIo>> {
        let from = self.from.clone();
        let to = name_of(url);
        let faults = self.faults.clone();
        let path = PathBuf::from(url.trim_start_matches("unix://"));
        Box::pin(async move {
            if faults.blocked(&from, &to) {
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "cut"));
            }
            let s = connect_unix(&path).await?;
            Ok(Box::new(FaultIo {
                inner: s,
                from,
                to,
                faults,
            }) as BoxIo)
        })
    }
}

struct FaultIo {
    inner: tokio::net::UnixStream,
    from: String,
    to: String,
    faults: Arc<Faults>,
}

impl FaultIo {
    fn cut(&self) -> bool {
        self.faults.blocked(&self.from, &self.to)
    }
}

fn broken() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "cut")
}

impl AsyncRead for FaultIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.cut() {
            return Poll::Ready(Err(broken()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FaultIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.cut() {
            return Poll::Ready(Err(broken()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.cut() {
            return Poll::Ready(Err(broken()));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct Running {
    node: Node,
    halt: watch::Sender<bool>,
    served: tokio::task::JoinHandle<()>,
}

/// Members a, b, c, ... in one directory.
struct Cluster {
    dir: PathBuf,
    faults: Arc<Faults>,
    timing: Timing,
    names: Vec<String>,
    running: Vec<Option<Running>>,
}

fn dir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("kvr-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn fast() -> Timing {
    Timing {
        heartbeat: Duration::from_millis(50),
        election_min: Duration::from_millis(300),
        election_max: Duration::from_millis(600),
        ..Timing::default()
    }
}

impl Cluster {
    fn peer(&self, name: &str) -> String {
        format!("unix://{}", self.dir.join(name).join("peer.sock").display())
    }

    fn options(&self, name: &str, start: Start) -> Options {
        Options {
            name: name.to_string(),
            peer_urls: vec![self.peer(name)],
            client_urls: vec![format!("unix://{name}.client")],
            start,
            timing: self.timing.clone(),
            connector: Some(Arc::new(FaultConnector {
                from: name.to_string(),
                faults: self.faults.clone(),
            })),
            request_timeout: Duration::from_secs(3),
            ..Default::default()
        }
    }

    /// Opens member i (again: a member with a database restarts from it)
    /// and serves its peer service.
    async fn open(&mut self, i: usize, start: Start) {
        let name = self.names[i].clone();
        std::fs::create_dir_all(self.dir.join(&name)).unwrap();
        let data = self.dir.join(&name).join("data");
        let deadline = Instant::now() + Duration::from_secs(15);
        // The database of a member just stopped closes once its last
        // task lets go of it.
        let node = loop {
            match Node::open(&data, self.options(&name, start.clone())).await {
                Ok(n) => break n,
                Err(e) if Instant::now() < deadline && e.to_string().contains("holds") => {
                    tokio::time::sleep(Duration::from_millis(50)).await
                }
                Err(e) => panic!("open {name}: {e}"),
            }
        };
        let (halt, mut h) = watch::channel(false);
        let sock = self.dir.join(&name).join("peer.sock");
        let _ = std::fs::remove_file(&sock);
        let served_node = node.clone();
        let served = tokio::spawn(async move {
            armada_kv::serve_peer_unix(served_node, &sock, async move {
                let _ = h.wait_for(|s| *s).await;
            })
            .await
            .unwrap();
        });
        self.running[i] = Some(Running { node, halt, served });
    }

    /// A cluster of n members: the first bootstraps it, the others are
    /// added as learners, join, and are promoted.
    async fn start(name: &str, n: usize, timing: Timing) -> Cluster {
        let mut c = Cluster {
            dir: dir(name),
            faults: Arc::default(),
            timing,
            names: (0..n)
                .map(|i| ((b'a' + i as u8) as char).to_string())
                .collect(),
            running: (0..n).map(|_| None).collect(),
        };
        c.open(0, Start::New).await;
        for i in 1..n {
            c.add(i).await;
            c.promote(i).await;
        }
        c
    }

    /// Adds member i as a learner and starts it.
    async fn add(&mut self, i: usize) {
        let peer = self.peer(&self.names[i]);
        let r = retry(|| {
            let n = self.any();
            let peer = peer.clone();
            async move {
                n.member_add(pb::MemberAddRequest {
                    peer_ur_ls: vec![peer],
                    is_learner: true,
                })
                .await
            }
        })
        .await;
        let added = r.member.unwrap();
        assert!(added.is_learner);
        let peers = self
            .running
            .iter()
            .flatten()
            .map(|r| r.node.options().peer_urls[0].clone())
            .collect();
        self.open(i, Start::Join(peers)).await;
        assert_eq!(self.node(i).id(), added.id, "the joined member took its ID");
    }

    async fn promote(&self, i: usize) {
        let id = self.node(i).id();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match self
                .any()
                .member_promote(pb::MemberPromoteRequest { id })
                .await
            {
                Ok(_) => return,
                Err(e) => assert!(Instant::now() < deadline, "promote: {e}"),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn node(&self, i: usize) -> &Node {
        &self.running[i].as_ref().expect("running").node
    }

    /// A running member.
    fn any(&self) -> Node {
        self.running.iter().flatten().next().unwrap().node.clone()
    }

    fn index_of(&self, id: u64) -> Option<usize> {
        (0..self.names.len()).find(|&i| self.running[i].as_ref().is_some_and(|r| r.node.id() == id))
    }

    /// The leader every member of among agrees on, once there is one.
    async fn leader(&self, among: &[usize]) -> usize {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let seen: Vec<u64> = among
                .iter()
                .map(|&i| self.node(i).raft_status().0)
                .collect();
            if let Some(l) = self.index_of(seen[0])
                && seen.iter().all(|s| *s == seen[0])
                && among.contains(&l)
                && self.node(l).raft_status().0 == self.node(l).id()
            {
                return l;
            }
            assert!(
                Instant::now() < deadline,
                "no leader among {among:?}: {seen:x?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Stops member i: its peer service, its Raft, its tasks.
    async fn kill(&mut self, i: usize) {
        let r = self.running[i].take().expect("running");
        let _ = r.halt.send(true);
        let _ = r.served.await;
        r.node.close().await;
    }

    /// Cuts member i off from every other member, both ways.
    fn partition(&self, i: usize) {
        let mut cut = self.faults.cut.lock().unwrap();
        for (j, other) in self.names.iter().enumerate() {
            if j != i {
                cut.insert((self.names[i].clone(), other.clone()));
                cut.insert((other.clone(), self.names[i].clone()));
            }
        }
    }

    fn heal(&self) {
        self.faults.cut.lock().unwrap().clear();
    }

    async fn stop(mut self) {
        for i in 0..self.names.len() {
            if self.running[i].is_some() {
                self.kill(i).await;
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Retries f while the cluster has no leader or moves it, at most 20 s.
async fn retry<T, F, Fut>(mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = armada_kv::Result<T>>,
{
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match f().await {
            Ok(v) => return v,
            Err(e) => assert!(Instant::now() < deadline, "{e}"),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn put_cmd(k: &str, v: &str, lease: i64) -> Command {
    Command::new(Op::Put(pb::PutRequest {
        key: k.as_bytes().to_vec(),
        value: v.as_bytes().to_vec(),
        lease,
        ..Default::default()
    }))
}

/// A put through member n: the revision it made.
fn put<'n>(
    n: &'n Node,
    k: &str,
    v: &str,
) -> impl Future<Output = armada_kv::Result<i64>> + use<'n> {
    let cmd = put_cmd(k, v, 0);
    async move { Ok(n.propose(cmd).await?.revision) }
}

/// A linearizable read of k on member n: the revision it saw and the
/// value.
async fn get(n: &Node, k: &str) -> armada_kv::Result<(i64, Option<String>)> {
    n.linearize().await?;
    let r = n.store().range(&pb::RangeRequest {
        key: k.as_bytes().to_vec(),
        ..Default::default()
    })?;
    Ok((
        r.header.unwrap().revision,
        r.kvs
            .first()
            .map(|kv| String::from_utf8_lossy(&kv.value).into_owned()),
    ))
}

/// The whole key space of member n as it has applied it.
fn dump(n: &Node) -> BTreeMap<String, (String, i64, i64)> {
    let r = n
        .store()
        .range(&pb::RangeRequest {
            key: vec![0],
            range_end: vec![0],
            ..Default::default()
        })
        .unwrap();
    r.kvs
        .into_iter()
        .map(|kv| {
            (
                String::from_utf8_lossy(&kv.key).into_owned(),
                (
                    String::from_utf8_lossy(&kv.value).into_owned(),
                    kv.mod_revision,
                    kv.version,
                ),
            )
        })
        .collect()
}

/// Waits until member n has applied as far as member of.
async fn caught_up(n: &Node, of: &Node) {
    let want = *of.applied().borrow();
    let mut a = n.applied();
    tokio::time::timeout(Duration::from_secs(20), a.wait_for(|a| *a >= want))
        .await
        .expect("caught up in time")
        .unwrap();
}

/// Writers through every member while the leader is killed: every
/// acknowledged write is on every member afterwards (the killed one too,
/// once restarted), and no reader sees the revision go back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leader_killed_mid_write() {
    let mut c = Cluster::start("kill", 3, fast()).await;
    let leader = c.leader(&[0, 1, 2]).await;
    let acked = Arc::new(Mutex::new(Vec::<(String, i64)>::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut tasks = Vec::new();
    for w in 0..3 {
        let n = c.node(w).clone();
        let acked = acked.clone();
        let stop = stop.clone();
        tasks.push(tokio::spawn(async move {
            let mut j = 0;
            while !stop.load(Ordering::Relaxed) {
                let k = format!("w{w}/{j}");
                match put(&n, &k, "v").await {
                    Ok(rev) => acked.lock().unwrap().push((k, rev)),
                    Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
                }
                j += 1;
            }
        }));
    }
    // Readers on the followers: revisions never go back, and a read after
    // a write was acknowledged sees at least its revision.
    let mut readers = Vec::new();
    for r in (0..3).filter(|&r| r != leader) {
        let n = c.node(r).clone();
        let stop = stop.clone();
        let acked = acked.clone();
        readers.push(tokio::spawn(async move {
            let mut last = 0;
            let mut reads = 0;
            while !stop.load(Ordering::Relaxed) {
                let floor = acked.lock().unwrap().iter().map(|a| a.1).max().unwrap_or(0);
                match get(&n, "w0/0").await {
                    Ok((rev, _)) => {
                        assert!(rev >= last, "the revision went back: {last} then {rev}");
                        assert!(
                            rev >= floor,
                            "a read saw {rev} after {floor} was acknowledged"
                        );
                        last = rev;
                        reads += 1;
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
                }
            }
            reads
        }));
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    let before = acked.lock().unwrap().len();
    c.kill(leader).await;
    let rest: Vec<usize> = (0..3).filter(|&i| i != leader).collect();
    let new = c.leader(&rest).await;
    assert_ne!(new, leader);
    // Writes go on through the new leader.
    tokio::time::sleep(Duration::from_millis(400)).await;
    stop.store(true, Ordering::Relaxed);
    for t in tasks {
        t.await.unwrap();
    }
    for r in readers {
        assert!(r.await.unwrap() > 0, "the reader read");
    }
    let acked = acked.lock().unwrap().clone();
    assert!(acked.len() > before, "writes after the leader died");
    for &i in &rest {
        let n = c.node(i).clone();
        n.linearize().await.unwrap();
        let d = dump(&n);
        for (k, rev) in &acked {
            let got = d
                .get(k)
                .unwrap_or_else(|| panic!("{k} lost on {}", c.names[i]));
            assert_eq!(got.1, *rev, "{k}'s revision");
        }
    }
    // The old leader, restarted from its log, catches up with the same
    // key space.
    c.open(leader, Start::New).await;
    let l = c.node(new).clone();
    put(&l, "after", "restart").await.unwrap();
    caught_up(c.node(leader), &l).await;
    assert_eq!(dump(c.node(leader)), dump(&l));
    c.stop().await;
}

/// A leader cut off from the others: its writes fail and are lost, the
/// majority elects another leader and keeps every acknowledged write, and
/// the old leader follows it once the cut heals.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partitioned_leader() {
    let c = Cluster::start("part", 3, fast()).await;
    let old = c.leader(&[0, 1, 2]).await;
    let before = put(c.node(old), "before", "1").await.unwrap();
    c.partition(old);
    let e = put(c.node(old), "cut-off", "x").await.unwrap_err();
    assert!(
        matches!(
            e,
            Error::Timeout | Error::LeaderChanged | Error::NoLeader | Error::Unavailable(_)
        ),
        "{e}"
    );
    // Reads on it fail too: it cannot confirm it leads.
    assert!(get(c.node(old), "before").await.is_err());
    let rest: Vec<usize> = (0..3).filter(|&i| i != old).collect();
    let new = c.leader(&rest).await;
    let after = retry(|| put(c.node(rest[0]), "after", "2")).await;
    assert!(after > before);
    c.heal();
    let l = c.node(new).clone();
    put(&l, "healed", "3").await.unwrap();
    caught_up(c.node(old), &l).await;
    let d = dump(c.node(old));
    assert_eq!(d, dump(&l));
    assert!(d.contains_key("before") && d.contains_key("after") && d.contains_key("healed"));
    assert!(
        !d.contains_key("cut-off"),
        "a write the minority took is gone"
    );
    let (_, v) = retry(|| get(c.node(old), "after")).await;
    assert_eq!(v.as_deref(), Some("2"));
    c.stop().await;
}

/// Members restarted from their logs: a follower that missed writes
/// catches up, and the cluster survives each member restarting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_from_log() {
    let mut c = Cluster::start("restart", 3, fast()).await;
    let leader = c.leader(&[0, 1, 2]).await;
    let f = (leader + 1) % 3;
    for i in 0..20 {
        put(c.node(leader), &format!("k{i}"), "a").await.unwrap();
    }
    c.kill(f).await;
    for i in 20..40 {
        retry(|| put(c.node(leader), &format!("k{i}"), "b")).await;
    }
    c.open(f, Start::New).await;
    caught_up(c.node(f), c.node(leader)).await;
    assert_eq!(dump(c.node(f)), dump(c.node(leader)));
    // Every member restarted in turn, leader included.
    for i in 0..3 {
        c.kill(i).await;
        c.open(i, Start::New).await;
        let l = c.leader(&[0, 1, 2]).await;
        retry(|| put(c.node(l), &format!("r{i}"), "c")).await;
    }
    let l = c.leader(&[0, 1, 2]).await;
    for i in 0..3 {
        caught_up(c.node(i), c.node(l)).await;
        assert_eq!(dump(c.node(i)), dump(c.node(l)));
        assert_eq!(dump(c.node(i)).len(), 43);
    }
    c.stop().await;
}

/// etcd's membership calls: a learner added, started, promoted, its peer
/// URL updated, and removed; and what they refuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn learner_add_promote_remove() {
    let mut c = Cluster::start("members", 3, fast()).await;
    c.names.push("d".into());
    c.running.push(None);
    put(&c.any(), "x", "1").await.unwrap();
    c.add(3).await;
    let d = c.node(3).clone();
    let list = c.node(0).members();
    let m = list.iter().find(|m| m.id == d.id()).unwrap();
    assert!(m.is_learner);
    // The learner reads (through the leader) and is shown as one.
    let (_, v) = retry(|| get(&d, "x")).await;
    assert_eq!(v.as_deref(), Some("1"));
    assert!(d.raft_status().4, "Status says learner");
    // It tells the cluster its name and client URLs once started.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let m = c
            .node(1)
            .members()
            .into_iter()
            .find(|m| m.id == d.id())
            .unwrap();
        if m.name == "d" && m.client_ur_ls == vec!["unix://d.client".to_string()] {
            break;
        }
        assert!(Instant::now() < deadline, "{m:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Refusals keep etcd's errors.
    let dup = c
        .any()
        .member_add(pb::MemberAddRequest {
            peer_ur_ls: vec![c.peer("d")],
            is_learner: true,
        })
        .await
        .unwrap_err();
    assert_eq!(dup, Error::PeerUrlExists);
    let voter = c.node(0).id();
    assert_eq!(
        c.any()
            .member_promote(pb::MemberPromoteRequest { id: voter })
            .await
            .unwrap_err(),
        Error::NotLearner
    );
    assert_eq!(
        c.any()
            .member_remove(pb::MemberRemoveRequest { id: 42 })
            .await
            .unwrap_err(),
        Error::MemberNotFound
    );
    c.promote(3).await;
    assert!(c.node(2).members().iter().all(|m| !m.is_learner));
    assert_eq!(c.node(2).members().len(), 4);
    assert!(!c.node(3).raft_status().4);
    // A peer URL updated keeps the member's name.
    let moved = format!("{}-moved", c.peer("d"));
    let r = c
        .node(3)
        .member_update(pb::MemberUpdateRequest {
            id: d.id(),
            peer_ur_ls: vec![moved.clone()],
        })
        .await
        .unwrap();
    let m = r.members.iter().find(|m| m.id == d.id()).unwrap();
    assert_eq!((m.name.as_str(), m.peer_ur_ls.clone()), ("d", vec![moved]));
    // Removed: three voters again, and they still write.
    c.node(1)
        .member_remove(pb::MemberRemoveRequest { id: d.id() })
        .await
        .unwrap();
    c.kill(3).await;
    let list = c.node(0).members();
    assert_eq!(list.len(), 3, "{list:?}");
    retry(|| put(c.node(2), "y", "2")).await;
    c.stop().await;
}

/// A member far behind (its entries purged from every log) and a new
/// member: both get a snapshot, keep their IDs, and end with the leader's
/// key space.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_install() {
    let timing = Timing {
        snapshot_every: 20,
        keep_behind: 5,
        ..fast()
    };
    let mut c = Cluster::start("snap", 3, timing).await;
    let leader = c.leader(&[0, 1, 2]).await;
    let f = (leader + 1) % 3;
    let (id, cluster) = (c.node(f).id(), c.node(f).store().ids().cluster);
    c.kill(f).await;
    for i in 0..150 {
        retry(|| put(c.node(leader), &format!("s{:03}", i % 100), &i.to_string())).await;
    }
    let lease = c
        .node(leader)
        .grant(pb::LeaseGrantRequest { ttl: 600, id: 0 })
        .await
        .unwrap();
    c.node(leader)
        .propose(put_cmd("leased", "l", lease.id))
        .await
        .unwrap();
    let purged = c.node(leader).raft().metrics().borrow_watched().purged;
    assert!(
        purged.is_some_and(|p| p.index > 100),
        "the leader purged its log: {purged:?}"
    );
    c.open(f, Start::New).await;
    caught_up(c.node(f), c.node(leader)).await;
    assert_eq!(c.node(f).id(), id);
    assert_eq!(c.node(f).store().ids().cluster, cluster);
    assert_eq!(dump(c.node(f)), dump(c.node(leader)));
    assert_eq!(
        c.node(f).store().leases().unwrap(),
        c.node(leader).store().leases().unwrap()
    );
    assert_eq!(
        c.node(f).store().state().unwrap().revision,
        c.node(leader).store().state().unwrap().revision
    );
    // It goes on applying after the snapshot.
    put(c.node(leader), "next", "1").await.unwrap();
    caught_up(c.node(f), c.node(leader)).await;
    assert_eq!(dump(c.node(f)), dump(c.node(leader)));
    // A new member starts from a snapshot too.
    c.names.push("d".into());
    c.running.push(None);
    c.add(3).await;
    caught_up(c.node(3), c.node(leader)).await;
    assert_eq!(dump(c.node(3)), dump(c.node(leader)));
    assert_eq!(c.node(3).store().ids().cluster, cluster);
    c.stop().await;
}

/// Leases across a change of leader: a lease no longer kept alive expires
/// after its TTL and at most one more TTL plus an election, never before;
/// a lease kept alive through the change stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lease_expiry_across_leader_change() {
    const TTL: i64 = 3;
    let mut c = Cluster::start("lease", 3, fast()).await;
    let leader = c.leader(&[0, 1, 2]).await;
    let f = (leader + 1) % 3;
    let n = c.node(f).clone();
    let dropped = n
        .grant(pb::LeaseGrantRequest { ttl: TTL, id: 0 })
        .await
        .unwrap()
        .id;
    let kept = n
        .grant(pb::LeaseGrantRequest { ttl: TTL, id: 0 })
        .await
        .unwrap()
        .id;
    n.propose(put_cmd("dropped", "x", dropped)).await.unwrap();
    n.propose(put_cmd("kept", "x", kept)).await.unwrap();
    // Kept alive through the follower for a while, then no more.
    for _ in 0..4 {
        assert_eq!(n.keep_alive(dropped).await.unwrap(), TTL);
        assert_eq!(n.keep_alive(kept).await.unwrap(), TTL);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(n.keep_alive(dropped).await.unwrap(), TTL);
    let last = Instant::now();
    let keeping = Arc::new(AtomicBool::new(true));
    let kept_until = Arc::new(AtomicI64::new(0));
    let k = {
        let n = n.clone();
        let keeping = keeping.clone();
        let kept_until = kept_until.clone();
        tokio::spawn(async move {
            while keeping.load(Ordering::Relaxed) {
                if let Ok(t) = n.keep_alive(kept).await {
                    assert_eq!(t, TTL, "the kept lease is alive");
                    kept_until.fetch_add(1, Ordering::Relaxed);
                }
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
        })
    };
    // The leader dies right after the last keep-alive of `dropped`.
    c.kill(leader).await;
    let rest: Vec<usize> = (0..3).filter(|&i| i != leader).collect();
    c.leader(&rest).await;
    let early = last + Duration::from_secs(TTL as u64) - Duration::from_millis(200);
    let late = last + Duration::from_secs(2 * TTL as u64) + c.timing.election_max * 2;
    let gone_at = loop {
        let present = retry(|| get(&n, "dropped")).await.1.is_some();
        let now = Instant::now();
        if !present {
            break now;
        }
        assert!(now < late, "the key outlived its lease by more than a TTL");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(gone_at >= early, "the lease expired early");
    // The lease kept alive through the change is still there, a TTL later.
    tokio::time::sleep(Duration::from_secs(TTL as u64)).await;
    assert_eq!(retry(|| get(&n, "kept")).await.1.as_deref(), Some("x"));
    keeping.store(false, Ordering::Relaxed);
    k.await.unwrap();
    assert!(kept_until.load(Ordering::Relaxed) > 0);
    c.stop().await;
}

/// A store restored from a snapshot (`armadad restore`, the move of the
/// state from etcd) holds a key space no log entry made: members added to
/// its cluster get all of it (a Raft snapshot of it, sealed before the
/// first member serves), the same on every member, and a member alone
/// still has it once the first one is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restored_key_space_reaches_new_members() {
    let mut c = Cluster {
        dir: dir("restored"),
        faults: Arc::default(),
        timing: fast(),
        names: vec!["a".into(), "b".into(), "c".into()],
        running: vec![None, None, None],
    };
    let mut w = armada_kv::snapshot::Writer::new(500);
    w.lease(77, 3600);
    for i in 0..300 {
        w.kv(&armada_proto::etcd::mvccpb::KeyValue {
            key: format!("/armada/r{i:03}").into_bytes(),
            value: format!("v{i}").into_bytes(),
            create_revision: 10 + i,
            mod_revision: 100 + i,
            version: 1 + i % 3,
            lease: if i == 7 { 77 } else { 0 },
        });
    }
    let data = c.dir.join("a").join("data");
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&data)
            .unwrap();
    }
    let st = armada_kv::mvcc::Store::restore(
        &w.finish(),
        &data.join(armada_kv::node::DB_FILE),
        Default::default(),
    )
    .unwrap();
    assert!(st.unsealed_base().unwrap());
    drop(st);
    c.open(0, Start::New).await;
    assert!(!c.node(0).store().unsealed_base().unwrap(), "sealed");
    assert_eq!(dump(c.node(0)).len(), 300);
    for i in 1..3 {
        c.add(i).await;
        c.promote(i).await;
    }
    put(c.node(0), "/armada/after", "1").await.unwrap();
    for i in 1..3 {
        caught_up(c.node(i), c.node(0)).await;
        assert_eq!(dump(c.node(i)), dump(c.node(0)), "member {i}");
        assert_eq!(
            c.node(i).store().leases().unwrap(),
            c.node(0).store().leases().unwrap()
        );
    }
    assert_eq!(dump(c.node(1)).len(), 301);
    // The first member gone: the others elect a leader and hold it all.
    c.kill(0).await;
    let l = c.leader(&[1, 2]).await;
    let (_, v) = retry(|| get(c.node(l), "/armada/r123")).await;
    assert_eq!(v.as_deref(), Some("v123"));
    assert_eq!(dump(c.node(l)).len(), 301);
    // Restarting a sealed member does not seal again.
    c.open(0, Start::New).await;
    caught_up(c.node(0), c.node(l)).await;
    assert_eq!(dump(c.node(0)), dump(c.node(l)));
    c.stop().await;
}

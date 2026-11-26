//! The move of runc's containers to crun (ADR 0056) against a runtime in
//! memory whose new containers are created with the runtime the test sets.

use std::collections::{BTreeMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use super::*;
use crate::agent::{Agent, Config, REPLICA_STARTING};
use crate::clock::{Clock, TestClock};
use crate::proxy::{BoxFut, Proxy};
use crate::runtime::{
    ContainerSpec, Error, Image, LABEL_REPLICA, OCI_RUNC, RegistryAuth, STATE_EXITED,
};

/// Containers in memory, each with the OCI runtime set when it was run.
struct Fake {
    clock: Arc<TestClock>,
    cs: Mutex<Vec<Container>>,
    /// "run REPLICA" and "remove ID", in order.
    calls: Mutex<Vec<String>>,
    next: Mutex<String>,
    n: AtomicU32,
}

impl Fake {
    fn calls(&self) -> Vec<String> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }

    fn of(&self, replica: &str) -> Container {
        self.cs
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.label(LABEL_REPLICA) == replica)
            .cloned()
            .unwrap()
    }

    fn on_runc(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .cs
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.on_runc())
            .map(|c| c.label(LABEL_REPLICA).to_string())
            .collect();
        v.sort();
        v
    }
}

impl Runtime for Fake {
    async fn ping(&self) -> crate::runtime::Result<()> {
        Ok(())
    }
    async fn pull(&self, _: &str, _: Option<&RegistryAuth>) -> crate::runtime::Result<Image> {
        Ok(Image::default())
    }
    async fn run(&self, s: &ContainerSpec) -> crate::runtime::Result<String> {
        let n = self.n.fetch_add(1, Ordering::SeqCst) + 1;
        let id = format!("{}-c{n}", s.name);
        self.calls
            .lock()
            .unwrap()
            .push(format!("run {}", s.labels[LABEL_REPLICA]));
        self.cs.lock().unwrap().push(Container {
            id: id.clone(),
            name: s.name.clone(),
            labels: s.labels.clone(),
            state: STATE_RUNNING.into(),
            ip: format!("10.0.0.{n}"),
            started_at: Some(self.clock.now()),
            oci_runtime: self.next.lock().unwrap().clone(),
            ..Default::default()
        });
        Ok(id)
    }
    async fn stop(&self, id: &str, _: Duration) -> crate::runtime::Result<()> {
        for c in self.cs.lock().unwrap().iter_mut().filter(|c| c.id == id) {
            c.state = STATE_EXITED.into();
        }
        Ok(())
    }
    async fn remove(&self, id: &str) -> crate::runtime::Result<()> {
        self.calls.lock().unwrap().push(format!("remove {id}"));
        self.cs.lock().unwrap().retain(|c| c.id != id);
        Ok(())
    }
    async fn list(
        &self,
        want: &BTreeMap<String, String>,
    ) -> crate::runtime::Result<Vec<Container>> {
        Ok(self
            .cs
            .lock()
            .unwrap()
            .iter()
            .filter(|c| want.iter().all(|(k, v)| c.label(k) == v))
            .cloned()
            .collect())
    }
    async fn inspect(&self, id: &str) -> crate::runtime::Result<Container> {
        self.cs
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.id == id)
            .cloned()
            .ok_or(Error::NotFound)
    }
}

/// The node's proxy, in a container runc created until moved.
#[derive(Default)]
struct FakeProxy {
    runc: AtomicBool,
    moves: AtomicU32,
    fail: AtomicBool,
}

impl Proxy for FakeProxy {
    fn apply<'a>(&'a self, _: &'a pb::ProxyConfig) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn health(&self) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn moves_to_crun(&self) -> bool {
        true
    }
    fn on_runc(&self) -> BoxFut<'_, Result<bool, String>> {
        Box::pin(async { Ok(self.runc.load(Ordering::SeqCst)) })
    }
    fn move_to_crun(&self) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async {
            self.moves.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err("haproxy exited".to_string());
            }
            self.runc.store(false, Ordering::SeqCst);
            Ok(())
        })
    }
}

struct Lab {
    clock: Arc<TestClock>,
    agent: Agent<Fake>,
    /// Container addresses whose port does not answer.
    sick: Arc<Mutex<HashSet<String>>>,
    proxy: Arc<FakeProxy>,
}

fn t0() -> SystemTime {
    clock::from_unix_nanos(1_790_000_000_000_000_000)
}

fn lab(with_proxy: bool) -> Lab {
    let clock = Arc::new(TestClock::new(t0()));
    let sick: Arc<Mutex<HashSet<String>>> = Arc::default();
    let s = sick.clone();
    let check: crate::check::CheckFn = Arc::new(move |addr: String, _path, _timeout| {
        let bad = s
            .lock()
            .unwrap()
            .contains(addr.split(':').next().unwrap_or(""));
        Box::pin(async move {
            if bad {
                Err("connection refused".to_string())
            } else {
                Ok(())
            }
        })
    });
    let proxy = Arc::new(FakeProxy::default());
    let cfg = Config {
        node_id: "n1".into(),
        private_ip: "10.1.0.1".into(),
        cpu_millis: 1000,
        memory_bytes: 1 << 30,
        boot_time: Some(SystemTime::UNIX_EPOCH),
        image_prune: None,
        check: Some(check),
        clock: clock.clone(),
        proxy: with_proxy.then(|| proxy.clone() as Arc<dyn Proxy>),
        ..Default::default()
    };
    let fake = Fake {
        clock: clock.clone(),
        cs: Mutex::default(),
        calls: Mutex::default(),
        next: Mutex::new(OCI_RUNC.into()),
        n: AtomicU32::default(),
    };
    Lab {
        agent: Agent::new(cfg, fake),
        clock,
        sick,
        proxy,
    }
}

fn spec(id: &str, app: &str) -> pb::ReplicaSpec {
    pb::ReplicaSpec {
        id: id.into(),
        app: app.into(),
        revision: format!("{app}-r1"),
        image: "img".into(),
        port: 8080,
        ..Default::default()
    }
}

/// The proxy configuration: each app's backend with its servers.
fn backends(apps: &[(&str, &[&str])]) -> pb::ProxyConfig {
    pb::ProxyConfig {
        backends: apps
            .iter()
            .map(|(app, servers)| pb::ProxyBackend {
                name: app.to_string(),
                servers: servers
                    .iter()
                    .map(|s| pb::ProxyServer {
                        name: s.to_string(),
                        address: "10.1.0.1:1".into(),
                        weight: 1,
                    })
                    .collect(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

impl Lab {
    fn rt(&self) -> &Fake {
        self.agent.runtime()
    }

    fn assign(&self, replicas: &[pb::ReplicaSpec], px: pb::ProxyConfig) {
        self.agent.set_assignment(&pb::Assignment {
            replicas: replicas.to_vec(),
            proxy: Some(px),
            ..Default::default()
        });
    }

    async fn pass(&self) -> pb::ReplicaReport {
        let r = self.agent.reconcile().await.unwrap().unwrap();
        // The probes of new containers check once.
        tokio::time::sleep(Duration::from_millis(30)).await;
        r
    }

    /// The next container created does not answer on its port.
    fn sick_next(&self) {
        let n = self.rt().n.load(Ordering::SeqCst) + 1;
        self.sick.lock().unwrap().insert(format!("10.0.0.{n}"));
    }

    /// No replica is being moved.
    fn idle(&self) {
        assert!(lock(&self.agent.inner.st).crun.current.is_none());
    }

    fn advance(&self, d: Duration) {
        self.clock.set(later(self.clock.now(), d));
    }

    /// Replicas created on runc and ready, then crun for what comes next.
    async fn on_runc(&self, replicas: &[pb::ReplicaSpec], px: pb::ProxyConfig) {
        self.assign(replicas, px);
        self.pass().await;
        self.pass().await;
        assert_eq!(self.rt().on_runc().len(), replicas.len());
        *self.rt().next.lock().unwrap() = OCI_CRUN.into();
        self.rt().calls();
        // Later than the containers' start, as on an upgraded node.
        self.advance(READY_WAIT);
        self.agent.set_contact(true);
    }

    fn state<'a>(r: &'a pb::ReplicaReport, id: &str) -> &'a pb::ReplicaState {
        r.replicas.iter().find(|s| s.id == id).unwrap()
    }

    /// One replica's move: taken out of service, then recreated on crun.
    async fn moves(&self, id: &str) {
        let old = self.rt().of(id).id;
        let r = self.pass().await;
        let st = Self::state(&r, id);
        assert_eq!(
            (st.state.as_str(), st.container_id.as_str(), st.ready),
            (REPLICA_STARTING, old.as_str(), false),
            "{id} drains first"
        );
        assert!(st.message.contains(MOVED_NOTE));
        assert!(st.address.is_empty());
        assert!(
            self.rt().calls().is_empty(),
            "nothing removed while draining"
        );
        self.advance(DRAIN);
        self.pass().await;
        assert_eq!(
            self.rt().calls(),
            [format!("remove {old}"), format!("run {id}")]
        );
        assert!(!self.rt().of(id).on_runc());
    }
}

/// Every replica on runc is recreated on crun, one at a time, the next
/// only once the one before is ready again; crun's containers stay.
#[tokio::test]
async fn moves_replicas_one_at_a_time() {
    let lab = lab(false);
    let rs = [
        spec("web-r1", "web"),
        spec("web-r2", "web"),
        spec("api-r1", "api"),
    ];
    let px = backends(&[("web", &["web-r1", "web-r2"]), ("api", &[])]);
    lab.on_runc(&rs[..2], px.clone()).await;
    // api-r1 is created now, on crun: never moved.
    lab.agent.set_contact(false);
    lab.assign(&rs, px.clone());
    lab.pass().await;
    assert_eq!(lab.rt().calls(), ["run api-r1"]);
    lab.advance(READY_WAIT);
    lab.agent.set_contact(true);

    // web-r1's new container does not answer yet: web-r2 waits.
    lab.sick_next();
    lab.moves("web-r1").await;
    assert_eq!(lab.rt().on_runc(), ["web-r2"]);
    for _ in 0..3 {
        let r = lab.pass().await;
        assert!(!Lab::state(&r, "web-r1").ready);
        assert_eq!(
            Lab::state(&r, "web-r2").state,
            crate::agent::REPLICA_RUNNING
        );
    }
    assert!(lab.rt().calls().is_empty());
    // Ready again: the next one moves.
    lab.sick.lock().unwrap().clear();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    lab.moves("web-r2").await;
    lab.pass().await;
    lab.pass().await;
    assert!(lab.rt().on_runc().is_empty());
    assert!(lab.rt().calls().is_empty());
    assert!(lock(&lab.agent.inner.st).crun.current.is_none());
}

/// A move whose replica does not get ready again holds the next one back,
/// longer after each failure, and does not loop.
#[tokio::test]
async fn backs_off_after_a_failed_move() {
    let lab = lab(false);
    let rs = [spec("a-r1", "a"), spec("b-r1", "b"), spec("c-r1", "c")];
    lab.on_runc(&rs, backends(&[])).await;
    lab.sick_next();
    lab.moves("a-r1").await;
    lab.pass().await;
    lab.advance(READY_WAIT);
    lab.pass().await;
    assert!(lab.rt().calls().is_empty());
    lab.idle();
    assert!(lab.rt().calls().is_empty());
    lab.idle();
    assert_eq!(lab.rt().on_runc(), ["b-r1", "c-r1"]);
    lab.advance(BACKOFF - Duration::from_secs(1));
    lab.pass().await;
    assert!(lab.rt().calls().is_empty());
    lab.idle();
    lab.advance(Duration::from_secs(1));
    // b-r1 does not come up either: the wait doubles.
    lab.sick_next();
    lab.moves("b-r1").await;
    lab.advance(READY_WAIT);
    lab.pass().await;
    lab.advance(BACKOFF);
    lab.pass().await;
    assert!(lab.rt().calls().is_empty());
    lab.idle();
    lab.advance(BACKOFF);
    lab.moves("c-r1").await;
    assert_eq!(backoff(1), BACKOFF);
    assert_eq!(backoff(2), BACKOFF * 2);
    assert_eq!(backoff(20), MAX_BACKOFF);
}

/// A replica alone in its app's backends waits ALONE_WAIT, as another
/// node may be moving the app's other replica; one listed with another
/// moves at once.
#[tokio::test]
async fn waits_for_an_app_served_by_one_replica() {
    let lab = lab(false);
    let rs = [spec("web-r1", "web")];
    lab.on_runc(&rs, backends(&[("web", &["web-r1"])])).await;
    lab.pass().await;
    assert!(lab.rt().calls().is_empty());
    lab.idle();
    lab.advance(ALONE_WAIT - Duration::from_secs(1));
    lab.pass().await;
    assert!(lab.rt().calls().is_empty());
    lab.idle();
    // The other replica is back on another node: no more waiting.
    lab.assign(&rs, backends(&[("web", &["web-r1", "web-r9"])]));
    lab.moves("web-r1").await;

    assert!(alone(Some(&backends(&[("x--web", &["r"])])), "web", "r"));
    assert!(!alone(Some(&backends(&[("web", &[])])), "web", "r"));
    assert!(!alone(None, "web", "r"));
}

/// Without a session the agent moves nothing: the leader would not hear
/// of it. Job attempts and held replicas stay.
#[tokio::test]
async fn moves_nothing_cut_off_or_for_jobs() {
    let lab = lab(false);
    let mut job = spec("j-j1-x", "j");
    job.job = Some(pb::JobAttempt::default());
    job.port = 0;
    lab.on_runc(&[spec("web-r1", "web"), job.clone()], backends(&[]))
        .await;
    lab.agent.set_contact(false);
    lab.pass().await;
    lab.advance(DRAIN);
    lab.pass().await;
    assert!(lab.rt().calls().is_empty());
    lab.idle();
    lab.agent.set_contact(true);
    lab.moves("web-r1").await;
    lab.pass().await;
    lab.advance(READY_WAIT);
    lab.pass().await;
    assert_eq!(lab.rt().on_runc(), ["j-j1-x"]);
    assert!(lab.rt().calls().is_empty());
    lab.idle();
}

/// An agent started again while a moved replica is not ready yet waits
/// for it before moving the next.
#[tokio::test]
async fn an_agent_restarted_mid_move_waits() {
    let lab = lab(false);
    let rs = [spec("a-r1", "a"), spec("b-r1", "b")];
    lab.on_runc(&rs, backends(&[])).await;
    lab.sick_next();
    lab.moves("a-r1").await;
    // The same node's containers, a new agent with no memory of the move.
    let again = lab_from(&lab);
    again.assign(&rs, backends(&[]));
    again.agent.set_contact(true);
    for _ in 0..3 {
        let r = again.pass().await;
        assert_eq!(Lab::state(&r, "b-r1").state, crate::agent::REPLICA_RUNNING);
        again.advance(DRAIN);
    }
    assert!(again.rt().calls().is_empty());
    again.sick.lock().unwrap().clear();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    again.pass().await;
    again.moves("b-r1").await;
}

/// A new agent over lab's containers, clock, and checks.
fn lab_from(lab: &Lab) -> Lab {
    let fresh = self::lab(false);
    let cs = lab.rt().cs.lock().unwrap().clone();
    let n = lab.rt().n.load(Ordering::SeqCst);
    fresh.clock.set(lab.clock.now());
    *fresh.rt().cs.lock().unwrap() = cs;
    fresh.rt().n.store(n, Ordering::SeqCst);
    *fresh.rt().next.lock().unwrap() = OCI_CRUN.into();
    *fresh.sick.lock().unwrap() = lab.sick.lock().unwrap().clone();
    fresh
}

/// The proxy moves last, once no replica is left on runc, and a failed
/// move of it is tried again later, not at once.
#[tokio::test]
async fn moves_the_proxy_last() {
    let lab = lab(true);
    lab.proxy.runc.store(true, Ordering::SeqCst);
    lab.proxy.fail.store(true, Ordering::SeqCst);
    let rs = [spec("web-r1", "web")];
    lab.on_runc(&rs, backends(&[])).await;
    lab.pass().await;
    assert_eq!(lab.proxy.moves.load(Ordering::SeqCst), 0);
    lab.moves("web-r1").await;
    // Ready again: the proxy's turn.
    lab.pass().await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(lab.proxy.moves.load(Ordering::SeqCst), 1);
    lab.pass().await;
    lab.pass().await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(lab.proxy.moves.load(Ordering::SeqCst), 1, "backs off");
    lab.proxy.fail.store(false, Ordering::SeqCst);
    lab.advance(BACKOFF);
    lab.pass().await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(lab.proxy.moves.load(Ordering::SeqCst), 2);
    assert!(!lab.proxy.runc.load(Ordering::SeqCst));
    lab.advance(MAX_BACKOFF);
    lab.pass().await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(lab.proxy.moves.load(Ordering::SeqCst), 2, "done");
}

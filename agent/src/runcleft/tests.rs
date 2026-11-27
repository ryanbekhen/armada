//! Containers runc created (ADR 0056) against a runtime in memory whose
//! new containers are created with the runtime the test sets.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use armada_proto::armada::v1 as pb;

use super::*;
use crate::agent::{Agent, Config, REPLICA_STARTING, RESTART_NOTE};
use crate::clock::{Clock, TestClock};
use crate::proxy::{BoxFut, Proxy};
use crate::runtime::{
    ContainerSpec, Error, Image, LABEL_REPLICA, OCI_CRUN, OCI_RUNC, RegistryAuth, STATE_EXITED,
    STATE_RUNNING,
};

/// Containers in memory, each with the OCI runtime set when it was run.
struct Fake {
    clock: Arc<TestClock>,
    cs: Mutex<Vec<Container>>,
    /// "run REPLICA", "stop ID GRACE", and "remove ID", in order.
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
    async fn stop(&self, id: &str, grace: Duration) -> crate::runtime::Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("stop {id} {}", grace.as_secs()));
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
    proxy: Arc<FakeProxy>,
    /// Addresses whose checks fail (replicas never ready).
    bad: Arc<Mutex<std::collections::HashSet<String>>>,
}

fn t0() -> SystemTime {
    clock::from_unix_nanos(1_790_000_000_000_000_000)
}

fn lab(with_proxy: bool) -> Lab {
    let clock = Arc::new(TestClock::new(t0()));
    let bad: Arc<Mutex<std::collections::HashSet<String>>> = Arc::default();
    let b = bad.clone();
    let check: crate::check::CheckFn = Arc::new(move |addr: String, _path, _timeout| {
        let fails = b.lock().unwrap().contains(&addr);
        Box::pin(async move {
            if fails {
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
        proxy,
        bad,
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

impl Lab {
    fn rt(&self) -> &Fake {
        self.agent.runtime()
    }

    fn assign(&self, replicas: &[pb::ReplicaSpec]) {
        self.assign_with(replicas, pb::ProxyConfig::default());
    }

    fn assign_with(&self, replicas: &[pb::ReplicaSpec], proxy: pb::ProxyConfig) {
        self.agent.set_assignment(&pb::Assignment {
            replicas: replicas.to_vec(),
            proxy: Some(proxy),
            ..Default::default()
        });
    }

    /// The next container run never gets ready.
    fn next_never_ready(&self) {
        let n = self.rt().n.load(Ordering::SeqCst) + 1;
        self.bad.lock().unwrap().insert(format!("10.0.0.{n}:8080"));
    }

    /// The calls of the last pass, sorted.
    fn sorted_calls(&self) -> Vec<String> {
        let mut v = self.rt().calls();
        v.sort();
        v
    }

    async fn pass(&self) -> pb::ReplicaReport {
        let r = self.agent.reconcile().await.unwrap().unwrap();
        // The probes of new containers check once.
        tokio::time::sleep(Duration::from_millis(30)).await;
        r
    }

    fn advance(&self, d: Duration) {
        self.clock.set(later(self.clock.now(), d));
    }

    /// Replicas created on runc (by an older release), then crun for
    /// what comes next: the node after its upgrade.
    async fn on_runc(&self, replicas: &[pb::ReplicaSpec]) {
        self.assign(replicas);
        self.pass().await;
        assert_eq!(self.rt().on_runc().len(), replicas.len());
        *self.rt().next.lock().unwrap() = OCI_CRUN.into();
        self.rt().calls();
    }
}

/// The calls that end a runc container and create its replica again,
/// sorted.
fn recreated(replica: &str, old: &str) -> Vec<String> {
    let mut v = vec![
        format!("remove {old}"),
        format!("run {replica}"),
        format!("stop {old} 0"),
    ];
    v.sort();
    v
}

/// Two replicas of one app on the node: one at a time, each reported
/// starting (out of the proxies) for DRAIN before it is ended, the second
/// only once the first runs on crun and is ready. A replica crun created
/// stays.
#[tokio::test]
async fn one_replica_of_an_app_at_a_time_with_a_drain() {
    let lab = lab(false);
    let rs = [spec("web-r1", "web"), spec("web-r2", "web")];
    lab.on_runc(&rs).await;
    let (old1, old2) = (lab.rt().of("web-r1").id, lab.rt().of("web-r2").id);
    let all = [rs[0].clone(), rs[1].clone(), spec("api-r1", "api")];
    lab.assign(&all);
    *lab.rt().next.lock().unwrap() = OCI_CRUN.into();

    // web-r2 is ready: web-r1 drains, its runc container left running.
    let r = lab.pass().await;
    assert_eq!(lab.sorted_calls(), ["run api-r1"]);
    let st = r.replicas.iter().find(|s| s.id == "web-r1").unwrap();
    assert_eq!(
        (st.state.as_str(), st.container_id.as_str()),
        (REPLICA_STARTING, old1.as_str())
    );
    assert!(st.address.is_empty());
    assert_eq!(st.message, format!("{RESTART_NOTE}{RUNC_NOTE}"));
    lab.pass().await;
    assert!(lab.rt().calls().is_empty(), "drains for DRAIN");

    lab.advance(DRAIN);
    lab.pass().await;
    assert_eq!(lab.sorted_calls(), recreated("web-r1", &old1));
    assert_eq!(lab.rt().on_runc(), ["web-r2"]);

    // web-r1 runs on crun and is ready: web-r2's turn, drained too.
    lab.pass().await;
    assert!(lab.rt().calls().is_empty());
    lab.advance(DRAIN);
    lab.pass().await;
    assert_eq!(lab.sorted_calls(), recreated("web-r2", &old2));
    assert!(lab.rt().on_runc().is_empty());

    // Every one on crun now: the next passes change nothing.
    lab.pass().await;
    lab.pass().await;
    assert!(lab.rt().calls().is_empty());
    let st = lock(&lab.agent.inner.st);
    assert!(st.runc.ended.is_empty(), "forgotten once gone");
    assert!(st.runc.recovering.is_empty());
}

/// A replica that is its app's only one (on the node and in the proxy
/// configuration) is ended at once: there is nothing to drain to.
#[tokio::test]
async fn ends_an_only_replica_at_once() {
    let lab = lab(false);
    let rs = [spec("web-r1", "web")];
    lab.on_runc(&rs).await;
    let old = lab.rt().of("web-r1").id;
    lab.pass().await;
    assert_eq!(lab.sorted_calls(), recreated("web-r1", &old));
    assert!(lab.rt().on_runc().is_empty());
}

/// A replica alone on the node whose app has a ready replica elsewhere
/// (a server of its backends) is drained first.
#[tokio::test]
async fn drains_when_the_app_serves_from_another_node() {
    let lab = lab(false);
    let rs = [spec("web-r1", "web")];
    lab.on_runc(&rs).await;
    let old = lab.rt().of("web-r1").id;
    let px = pb::ProxyConfig {
        backends: vec![pb::ProxyBackend {
            name: "web".into(),
            servers: vec![
                pb::ProxyServer {
                    name: "web-r1".into(),
                    address: "10.0.0.1:8080".into(),
                    ..Default::default()
                },
                pb::ProxyServer {
                    name: "web-r9".into(),
                    address: "10.2.0.9:8080".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }],
        ..Default::default()
    };
    lab.assign_with(&rs, px);
    let r = lab.pass().await;
    assert!(lab.rt().calls().is_empty());
    assert_eq!(r.replicas[0].state, REPLICA_STARTING);
    lab.advance(DRAIN);
    lab.pass().await;
    assert_eq!(lab.sorted_calls(), recreated("web-r1", &old));
}

/// Apps go in parallel, one replica each.
#[tokio::test]
async fn apps_in_parallel() {
    let lab = lab(false);
    let rs = [
        spec("a-r1", "a"),
        spec("a-r2", "a"),
        spec("b-r1", "b"),
        spec("b-r2", "b"),
        spec("c-r1", "c"),
    ];
    lab.on_runc(&rs).await;
    let old: Vec<String> = ["a-r1", "b-r1", "c-r1"]
        .iter()
        .map(|r| lab.rt().of(r).id)
        .collect();
    // c's only replica at once; a-r1 and b-r1 drain together.
    lab.pass().await;
    assert_eq!(lab.sorted_calls(), recreated("c-r1", &old[2]));
    lab.advance(DRAIN);
    lab.pass().await;
    let mut want = recreated("a-r1", &old[0]);
    want.extend(recreated("b-r1", &old[1]));
    want.sort();
    assert_eq!(lab.sorted_calls(), want);
    assert_eq!(lab.rt().on_runc(), ["a-r2", "b-r2"]);
}

/// A recreated replica that never gets ready holds its app's next one
/// back READY_WAIT, then the next goes on (with nothing ready to drain
/// to, at once).
#[tokio::test]
async fn goes_on_after_a_bound_when_never_ready() {
    let lab = lab(false);
    let rs = [spec("web-r1", "web"), spec("web-r2", "web")];
    lab.on_runc(&rs).await;
    let old2 = lab.rt().of("web-r2").id;
    lab.next_never_ready();
    lab.pass().await;
    lab.advance(DRAIN);
    lab.pass().await;
    assert_eq!(lab.rt().on_runc(), ["web-r2"]);
    lab.rt().calls();
    lab.pass().await;
    lab.advance(READY_WAIT - Duration::from_secs(1));
    lab.pass().await;
    assert!(lab.rt().calls().is_empty(), "waits for web-r1");
    lab.advance(Duration::from_secs(1));
    lab.pass().await;
    assert_eq!(lab.sorted_calls(), recreated("web-r2", &old2));
    assert!(lab.rt().on_runc().is_empty());
}

/// An agent restarted in the middle (its memory gone) waits for the
/// replica it recreated, found from the containers, before the next.
#[tokio::test]
async fn rebuilt_after_a_restart() {
    let lab = lab(false);
    let rs = [spec("web-r1", "web"), spec("web-r2", "web")];
    lab.on_runc(&rs).await;
    let old2 = lab.rt().of("web-r2").id;
    lab.next_never_ready();
    lab.pass().await;
    lab.advance(DRAIN);
    lab.pass().await;
    lab.rt().calls();
    {
        let mut st = lock(&lab.agent.inner.st);
        st.runc = RuncLeft::default();
        for (_, w) in st.probes.drain() {
            w.cancel();
        }
    }
    lab.pass().await;
    lab.pass().await;
    assert!(lab.rt().calls().is_empty(), "waits for web-r1");
    assert_eq!(lab.rt().on_runc(), ["web-r2"]);
    // web-r1 gets ready: web-r2 drains, then is recreated.
    lab.bad.lock().unwrap().clear();
    lock(&lab.agent.inner.st)
        .probes
        .drain()
        .for_each(|(_, w)| w.cancel());
    lab.pass().await;
    lab.pass().await;
    assert!(lab.rt().calls().is_empty(), "drains");
    lab.advance(DRAIN);
    lab.pass().await;
    assert_eq!(lab.sorted_calls(), recreated("web-r2", &old2));
}

/// While its new container starts, the replica is reported starting with
/// its old container and no address, so the leader takes it out of the
/// proxies.
#[tokio::test]
async fn reported_starting_while_recreated() {
    let lab = lab(false);
    let rs = [spec("web-r1", "web")];
    lab.on_runc(&rs).await;
    let c = lab.rt().of("web-r1");
    let old = c.id.clone();
    lab.agent.inner.end_runc_replica("web-r1", &c).await;
    assert_eq!(
        lab.rt().calls(),
        [format!("stop {old} 0"), format!("remove {old}")]
    );
    let st = lab.agent.inner.recreating(&crate::agent::PendingStart {
        id: "web-r1".into(),
        spec: rs[0].clone(),
        hash: String::new(),
        replaced: old.clone(),
    });
    assert_eq!(
        (st.state.as_str(), st.container_id.as_str()),
        (REPLICA_STARTING, old.as_str())
    );
    assert!(st.address.is_empty());
    assert_eq!(st.message, format!("{RESTART_NOTE}{RUNC_NOTE}"));
}

/// A job attempt runc created runs to its end: it needs nothing from runc
/// while it runs, and an attempt runs once.
#[tokio::test]
async fn leaves_running_job_attempts() {
    let lab = lab(false);
    let mut job = spec("j-j1-x", "j");
    job.job = Some(pb::JobAttempt::default());
    job.port = 0;
    lab.on_runc(std::slice::from_ref(&job)).await;
    lab.pass().await;
    lab.pass().await;
    assert!(lab.rt().calls().is_empty());
    assert_eq!(lab.rt().on_runc(), ["j-j1-x"]);
}

/// The proxy's container moves in the background as soon as runc is seen
/// to hold it, and a failed move is tried again later, not at once.
#[tokio::test]
async fn moves_the_proxy_and_backs_off() {
    let lab = lab(true);
    lab.proxy.runc.store(true, Ordering::SeqCst);
    lab.proxy.fail.store(true, Ordering::SeqCst);
    lab.assign(&[]);
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
    assert_eq!(backoff(1), BACKOFF);
    assert_eq!(backoff(2), BACKOFF * 2);
    assert_eq!(backoff(20), MAX_BACKOFF);
}

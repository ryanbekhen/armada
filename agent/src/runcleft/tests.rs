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
}

fn t0() -> SystemTime {
    clock::from_unix_nanos(1_790_000_000_000_000_000)
}

fn lab(with_proxy: bool) -> Lab {
    let clock = Arc::new(TestClock::new(t0()));
    let check: crate::check::CheckFn =
        Arc::new(|_addr: String, _path, _timeout| Box::pin(async { Ok(()) }));
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
        self.agent.set_assignment(&pb::Assignment {
            replicas: replicas.to_vec(),
            proxy: Some(pb::ProxyConfig::default()),
            ..Default::default()
        });
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

/// Every replica runc created is ended at once (no grace) and created
/// again on crun in the same pass, reported starting with its old
/// container meanwhile; a replica crun created stays.
#[tokio::test]
async fn ends_and_recreates_every_replica_runc_created() {
    let lab = lab(false);
    let rs = [spec("web-r1", "web"), spec("web-r2", "web")];
    lab.on_runc(&rs).await;
    let (old1, old2) = (lab.rt().of("web-r1").id, lab.rt().of("web-r2").id);
    let all = [rs[0].clone(), rs[1].clone(), spec("api-r1", "api")];
    lab.assign(&all);
    lab.pass().await;
    let mut calls = lab.rt().calls();
    calls.sort();
    let mut want = vec![
        format!("remove {old1}"),
        format!("remove {old2}"),
        "run api-r1".to_string(),
        "run web-r1".to_string(),
        "run web-r2".to_string(),
        format!("stop {old1} 0"),
        format!("stop {old2} 0"),
    ];
    want.sort();
    assert_eq!(calls, want);
    assert!(lab.rt().on_runc().is_empty());
    // Every one on crun now: the next passes change nothing.
    lab.pass().await;
    lab.pass().await;
    assert!(lab.rt().calls().is_empty());
    assert!(
        lock(&lab.agent.inner.st).runc.ended.is_empty(),
        "forgotten once gone"
    );
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

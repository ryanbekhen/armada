//! The cluster network behind the agent's [`Network`] seam: armada-node's
//! network code (`net apply`, `net up`, `net unreachable`, `net key
//! rotate`, `net remove`) called in process, with the state kept between
//! passes here and handed to every pass. The switch's probe runs as
//! `armada-node net probe` beside the agent: a pass that starts one marks
//! the switch probing; the probe records who answered and clears probing
//! `PROBE_EVERY` after its start.
//!
//! A pass armada-node fails is the pass's error, retried on the next one (a
//! full, idempotent sync of the node). The agent has no userspace WireGuard
//! device: a pass that needs one fails with what to install.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use armada_node::net::apply::{self as netapply, Answer, Request, SeenState, State};
use armada_node::net::config::NetworkConfig;
use armada_node::net::{key, probe};
use armada_proto::armada::v1 as pb;
use tokio::sync::Mutex;

use crate::log::Logger;
use crate::network::Network;
use crate::proxy::{BoxFut, Clients};

/// How often a switch's probe may start, and how long one
/// waits for answers (armada-node's PROBE_WAIT).
pub const PROBE_EVERY: Duration = Duration::from_secs(5);
pub const PROBE_WAIT: Duration = Duration::from_secs(2);

/// What a pass fails with when it needs the userspace WireGuard device.
pub const ERR_NO_KERNEL_WIREGUARD: &str = "the kernel has no WireGuard, which this node's cluster network needs; use a kernel with WireGuard (Linux 5.6 or later)";

/// The kernel side of the cluster network, a seam so the agent's side runs
/// in tests without root.
pub trait NetKernel: Send + Sync + 'static {
    /// One pass of `net apply` (op "apply") or `net up` ("up").
    fn pass(&self, op: &str, req: Request) -> Answer;
    /// The stale WireGuard peers among since at now (Unix seconds); None
    /// when since is empty.
    fn unreachable(&self, since: &[SeenState], now: i64) -> Option<Vec<String>>;
    /// Writes a new key at path and returns its private half as text.
    fn rotate_key(&self, path: &std::path::Path) -> Result<String, String>;
    /// Pings what req names; the peers that answered and the error, if
    /// any. Runs on a blocking thread.
    fn probe(&self, req: &probe::Request) -> (BTreeSet<String>, Option<String>);
}

/// armada-node's library in process, and its program for the probe.
pub struct Kernel {
    /// The runtime pack's armada-node, which runs the switch's probe.
    pub program: Option<PathBuf>,
}

impl NetKernel for Kernel {
    fn pass(&self, op: &str, req: Request) -> Answer {
        netapply::pass(op, req)
    }

    fn unreachable(&self, since: &[SeenState], now: i64) -> Option<Vec<String>> {
        netapply::unreachable(since, now)
    }

    fn rotate_key(&self, path: &std::path::Path) -> Result<String, String> {
        key::rotate(path).map(|k| k.to_string())
    }

    fn probe(&self, req: &probe::Request) -> (BTreeSet<String>, Option<String>) {
        let Some(bin) = &self.program else {
            return (
                BTreeSet::new(),
                Some("no armada-node to probe the target transport with".into()),
            );
        };
        run_probe(bin, req)
    }
}

/// Runs `armada-node net probe` with req on stdin.
pub fn run_probe(
    bin: &std::path::Path,
    req: &probe::Request,
) -> (BTreeSet<String>, Option<String>) {
    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct ProbeAnswer {
        reached: Option<Vec<String>>,
        error: String,
    }
    let fail = |e: String| (BTreeSet::new(), Some(format!("armada-node net probe: {e}")));
    let input = match serde_json::to_vec(req) {
        Ok(b) => b,
        Err(e) => return fail(e.to_string()),
    };
    let mut child = match Command::new(bin)
        .args(["net", "probe"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return fail(e.to_string()),
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(&input);
    }
    let out = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => return fail(e.to_string()),
    };
    let answer: ProbeAnswer = match serde_json::from_slice(&out.stdout) {
        Ok(a) if out.status.success() => a,
        Ok(_) | Err(_) => {
            let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return fail(if msg.is_empty() {
                out.status.to_string()
            } else {
                format!("{}: {msg}", out.status)
            });
        }
    };
    let reached = answer.reached.unwrap_or_default().into_iter().collect();
    let err = (!answer.error.is_empty()).then_some(answer.error);
    (reached, err)
}

/// What the node's cluster network is set up with.
#[derive(Clone, Debug, Default)]
pub struct NetConfig {
    pub node: String,
    pub private_ip: String,
    /// The node's public address; "" for none.
    pub endpoint: String,
    /// mesh.json, where the peer list of a mesh or of other sites is kept;
    /// "" for none.
    pub mesh_cache: String,
    /// Caps the uplink's MTU (join --mtu); 0 for none.
    pub uplink_mtu: i64,
    /// network.key.
    pub key_path: PathBuf,
}

/// The node's cluster network.
pub struct ClusterNet {
    cfg: NetConfig,
    kernel: Arc<dyn NetKernel>,
    log: Logger,
    /// The private key as text, "" for none.
    key: StdMutex<String>,
    /// What every pass reads and gives back; held across a pass, so a
    /// probe's result waits for the pass to end.
    st: Arc<Mutex<State>>,
    /// The last error of each call, to log a failure once.
    errs: StdMutex<std::collections::HashMap<&'static str, String>>,
    clock: fn() -> SystemTime,
}

fn unix(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The NetworkConfig as armada-node reads it: the protobuf JSON mapping.
pub fn node_config(cfg: &pb::NetworkConfig) -> Result<NetworkConfig, String> {
    let v = serde_json::to_value(cfg).map_err(|e| e.to_string())?;
    serde_json::from_value(v).map_err(|e| e.to_string())
}

impl ClusterNet {
    /// A network with the key at cfg.key_path, made when there is none.
    pub fn new(
        cfg: NetConfig,
        kernel: Arc<dyn NetKernel>,
        log: Logger,
    ) -> Result<ClusterNet, String> {
        let k = if cfg.key_path.as_os_str().is_empty() {
            String::new()
        } else {
            key::load_or_create(&cfg.key_path)?.to_string()
        };
        Ok(ClusterNet {
            cfg,
            kernel,
            log: log.with("component", "clusternet"),
            key: StdMutex::new(k),
            st: Arc::new(Mutex::new(State::default())),
            errs: StdMutex::new(Default::default()),
            clock: SystemTime::now,
        })
    }

    /// The node's public key, "" without a key.
    pub fn public_key(&self) -> String {
        let k = crate::agent::lock(&self.key).clone();
        key::Key::parse(&k)
            .map(|k| k.public().to_string())
            .unwrap_or_default()
    }

    /// Logs what a call ended in, once per change, in the words
    /// operators and the end-to-end test read in the journal.
    fn note(&self, op: &'static str, err: Option<&str>) {
        let msg = err.unwrap_or("").to_string();
        let mut errs = crate::agent::lock(&self.errs);
        let prev = errs.insert(op, msg.clone());
        if prev.as_deref() == Some(msg.as_str()) {
            return;
        }
        if msg.is_empty() {
            if op == "apply" {
                self.log
                    .info("armada-node applies the cluster network", &[]);
            }
        } else {
            self.log
                .warn("armada-node failed", &[("op", op.into()), ("err", msg)]);
        }
    }

    /// One pass; local maps this node's containers to their apps.
    async fn run(
        &self,
        op: &'static str,
        cfg: Option<&pb::NetworkConfig>,
        local: Option<&Clients>,
    ) -> Result<(), String> {
        let config = cfg.map(node_config).transpose()?;
        let mut st = self.st.clone().lock_owned().await;
        let req = Request {
            config,
            node: self.cfg.node.clone(),
            private_ip: self.cfg.private_ip.clone(),
            endpoint: self.cfg.endpoint.clone(),
            mesh_cache: self.cfg.mesh_cache.clone(),
            uplink_mtu: self.cfg.uplink_mtu,
            key: crate::agent::lock(&self.key).clone(),
            local: local.map(|l| {
                l.iter()
                    .map(|(a, app)| (a.to_string(), app.clone()))
                    .collect()
            }),
            userspace: false,
            state: std::mem::take(&mut *st),
        };
        let kernel = self.kernel.clone();
        let answer = tokio::task::spawn_blocking(move || kernel.pass(op, req)).await;
        let a = match answer {
            Ok(a) => a,
            Err(e) => {
                // Nothing is known of what it did: the next pass builds the
                // isolation tables again and checks every firewall rule.
                let err = format!("armada-node net {op}: {e}");
                self.note(op, Some(&err));
                return Err(err);
            }
        };
        *st = a.state;
        for l in &a.log {
            if l.level == "warn" {
                self.log.warn(&l.msg, &[]);
            } else {
                self.log.info(&l.msg, &[]);
            }
        }
        let res = if a.needs_userspace {
            Err(ERR_NO_KERNEL_WIREGUARD.to_string())
        } else if !a.error.is_empty() {
            Err(a.error)
        } else {
            Ok(())
        };
        self.note(op, res.as_ref().err().map(String::as_str));
        if res.is_ok()
            && let Some(p) = a.probe
        {
            self.start_probe(st.switch.to.clone(), st.switch.step.clone(), p);
        }
        res
    }

    /// Runs the probe beside the agent; st.switch.probing is already set.
    fn start_probe(&self, to: String, step: String, req: probe::Request) {
        let kernel = self.kernel.clone();
        let st = self.st.clone();
        let log = self.log.clone();
        tokio::spawn(async move {
            let (reached, err) = tokio::task::spawn_blocking(move || kernel.probe(&req))
                .await
                .unwrap_or_else(|e| (BTreeSet::new(), Some(e.to_string())));
            if let Some(e) = err {
                log.warn(
                    "probe the cluster network's target transport",
                    &[("err", e)],
                );
            }
            {
                let mut s = st.lock().await;
                if s.switch.to == to && s.switch.step == step {
                    s.switch.reached = reached.into_iter().collect();
                    s.switch.probed = true;
                }
            }
            tokio::time::sleep(PROBE_EVERY - PROBE_WAIT).await;
            st.lock().await.switch.probing = false;
        });
    }

    /// Brings the tunnels up before the control plane: from cfg,
    /// or from the peer list kept in mesh.json when cfg is None.
    pub async fn up(&self, cfg: Option<&pb::NetworkConfig>) -> Result<(), String> {
        self.run("up", cfg, None).await
    }

    /// What a switch's probe and passes left, for the tests.
    #[cfg(test)]
    async fn state_for_test(&self) -> (armada_node::net::apply::SwitchState, Vec<SeenState>) {
        let st = self.st.lock().await;
        (st.switch.clone(), st.since.clone())
    }

    #[cfg(test)]
    fn with_clock(mut self, clock: fn() -> SystemTime) -> ClusterNet {
        self.clock = clock;
        self
    }
}

/// Removes the node's tunnels, isolation tables, and firewall chains
/// (`armadad runtime reset`).
pub fn remove() -> Result<(), String> {
    netapply::remove()
}

impl Network for ClusterNet {
    fn apply<'a>(
        &'a self,
        cfg: &'a pb::NetworkConfig,
        local: Option<&'a Clients>,
    ) -> BoxFut<'a, Result<(), String>> {
        Box::pin(self.run("apply", Some(cfg), local))
    }

    fn switches(&self) -> bool {
        true
    }

    fn switch_status(&self) -> BoxFut<'_, Option<pb::NetworkSwitchStatus>> {
        Box::pin(async move {
            let st = self.st.lock().await;
            netapply::switch_status(&st.switch).map(|s| pb::NetworkSwitchStatus {
                to: s.to,
                step: s.step,
                ready: s.ready,
                unreached: s.unreached,
                error: s.error,
            })
        })
    }

    fn checks_peers(&self) -> bool {
        true
    }

    fn unreachable_peers(&self) -> BoxFut<'_, Vec<String>> {
        Box::pin(async move {
            let since = {
                let st = self.st.lock().await;
                if !st.switch.to.is_empty() || st.since.is_empty() {
                    return Vec::new();
                }
                st.since.clone()
            };
            let kernel = self.kernel.clone();
            let now = unix((self.clock)());
            tokio::task::spawn_blocking(move || kernel.unreachable(&since, now))
                .await
                .ok()
                .flatten()
                .unwrap_or_default()
        })
    }

    fn reports_wireguard(&self) -> bool {
        true
    }

    fn wireguard_userspace(&self) -> BoxFut<'_, bool> {
        // The kernel's device or none: never the userspace one.
        Box::pin(async { false })
    }

    fn rotates_keys(&self) -> bool {
        true
    }

    fn rotate_key(&self) -> BoxFut<'_, Result<String, String>> {
        Box::pin(async move {
            if self.cfg.key_path.as_os_str().is_empty() {
                return Err("the node's key file is unknown".to_string());
            }
            // Between passes.
            let _st = self.st.lock().await;
            let kernel = self.kernel.clone();
            let path = self.cfg.key_path.clone();
            let res = tokio::task::spawn_blocking(move || kernel.rotate_key(&path))
                .await
                .map_err(|e| e.to_string())
                .and_then(|r| r);
            self.note("rotate-key", res.as_ref().err().map(String::as_str));
            let k = res?;
            let public = key::Key::parse(&k)
                .map(|k| k.public().to_string())
                .ok_or_else(|| "the key file does not hold a key".to_string())?;
            *crate::agent::lock(&self.key) = k;
            self.log.info("made a new network key", &[]);
            Ok(public)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    type AnswerFn = Box<dyn Fn(&Request) -> Answer + Send>;

    /// Records each pass's request and answers what the test set.
    #[derive(Default)]
    struct Fake {
        reqs: StdMutex<Vec<(String, serde_json::Value)>>,
        answer: StdMutex<Option<AnswerFn>>,
        probes: StdMutex<Vec<probe::Request>>,
        reached: Vec<String>,
        since_asked: StdMutex<Vec<Vec<SeenState>>>,
    }

    fn empty(state: State) -> Answer {
        Answer {
            error: String::new(),
            needs_userspace: false,
            state,
            switch: None,
            probe: None,
            done: Vec::new(),
            log: Vec::new(),
        }
    }

    impl NetKernel for Fake {
        fn pass(&self, op: &str, mut req: Request) -> Answer {
            let state = std::mem::take(&mut req.state);
            let v = serde_json::json!({
                "config": req.config.as_ref().map(|c| serde_json::to_value(c).unwrap()),
                "node": req.node, "ip": req.private_ip, "key": req.key,
                "local": req.local, "state": serde_json::to_value(&state).unwrap(),
            });
            self.reqs.lock().unwrap().push((op.to_string(), v));
            match &*self.answer.lock().unwrap() {
                Some(f) => {
                    req.state = state;
                    f(&req)
                }
                None => empty(state),
            }
        }
        fn unreachable(&self, since: &[SeenState], _now: i64) -> Option<Vec<String>> {
            self.since_asked.lock().unwrap().push(since.to_vec());
            Some(vec!["b".into()])
        }
        fn rotate_key(&self, path: &std::path::Path) -> Result<String, String> {
            key::rotate(path).map(|k| k.to_string())
        }
        fn probe(&self, req: &probe::Request) -> (BTreeSet<String>, Option<String>) {
            self.probes.lock().unwrap().push(req.clone());
            (self.reached.iter().cloned().collect(), None)
        }
    }

    fn net(fake: Arc<Fake>, dir: &std::path::Path) -> ClusterNet {
        ClusterNet::new(
            NetConfig {
                node: "a".into(),
                private_ip: "10.0.0.1".into(),
                key_path: dir.join("network.key"),
                ..NetConfig::default()
            },
            fake,
            Logger::discard(),
        )
        .unwrap()
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "armada-agent-clusternet-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn passes_send_the_request_and_keep_the_state() {
        let dir = tmp("state");
        let fake = Arc::new(Fake::default());
        *fake.answer.lock().unwrap() = Some(Box::new(|req: &Request| {
            empty(State {
                last: format!("{}+", req.state.last),
                since: vec![SeenState {
                    key: "k".into(),
                    node: "b".into(),
                    since: 7,
                }],
                ..State::default()
            })
        }));
        let n = net(fake.clone(), &dir);
        let cfg = pb::NetworkConfig {
            mode: "wireguard".into(),
            cluster_cidr: "10.120.0.0/16".into(),
            tcp_ports: vec![5432],
            peers: vec![pb::NetworkPeer {
                node: "b".into(),
                private_ip: "10.0.0.2".into(),
                subnet: "10.120.1.0/24".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut local = Clients::new();
        local.insert("10.120.0.5".parse::<IpAddr>().unwrap(), "web".into());
        n.apply(&cfg, Some(&local)).await.unwrap();
        n.apply(&cfg, None).await.unwrap();
        let reqs = fake.reqs.lock().unwrap().clone();
        assert_eq!(reqs.len(), 2);
        let (op, first) = &reqs[0];
        assert_eq!(op, "apply");
        assert_eq!(first["node"], "a");
        assert_eq!(first["ip"], "10.0.0.1");
        assert_eq!(first["local"]["10.120.0.5"], "web");
        assert_eq!(first["config"]["mode"], "wireguard");
        assert_eq!(first["config"]["tcpPorts"][0], 5432);
        assert_eq!(first["config"]["peers"][0]["privateIp"], "10.0.0.2");
        // The key made at start goes with every pass.
        assert_eq!(first["key"].as_str().unwrap().len(), 44);
        assert!(!n.public_key().is_empty());
        // What the first pass gave back is what the second one gets.
        assert_eq!(reqs[1].1["state"]["Last"], "+");
        assert!(reqs[1].1["local"].is_null());
        assert_eq!(n.unreachable_peers().await, vec!["b".to_string()]);
        assert_eq!(fake.since_asked.lock().unwrap()[0][0].key, "k");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn failures_and_the_userspace_device() {
        let dir = tmp("fail");
        let fake = Arc::new(Fake::default());
        *fake.answer.lock().unwrap() = Some(Box::new(|req: &Request| {
            let mut a = empty(State::default());
            if req.state.last.is_empty() {
                a.error = "firewall: boom".into();
                a.state.last = "x".into();
            } else {
                a.needs_userspace = true;
                a.error = "the kernel has no WireGuard".into();
            }
            a
        }));
        let n = net(fake, &dir);
        let cfg = pb::NetworkConfig::default();
        assert_eq!(n.apply(&cfg, None).await.unwrap_err(), "firewall: boom");
        assert_eq!(
            n.apply(&cfg, None).await.unwrap_err(),
            ERR_NO_KERNEL_WIREGUARD
        );
        assert!(!n.wireguard_userspace().await);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(start_paused = true)]
    async fn a_switch_probes_beside_the_agent() {
        let dir = tmp("probe");
        let fake = Arc::new(Fake {
            reached: vec!["b".into()],
            ..Fake::default()
        });
        *fake.answer.lock().unwrap() = Some(Box::new(|req: &Request| {
            let mut st = State {
                switch: req.state.switch.clone(),
                ..State::default()
            };
            st.switch.to = "wireguard".into();
            st.switch.step = "prepare".into();
            st.switch.peers = vec!["b".into(), "c".into()];
            let mut a = empty(State::default());
            if !st.switch.probing {
                st.switch.probing = true;
                a.probe = Some(probe::Request {
                    from: "10.120.0.0".into(),
                    peers: vec![probe::Target {
                        node: "b".into(),
                        address: "10.120.1.0".into(),
                    }],
                });
            }
            a.state = st;
            a
        }));
        let n = net(fake.clone(), &dir);
        n.apply(&pb::NetworkConfig::default(), None).await.unwrap();
        // The probe's blocking thread runs in real time.
        for _ in 0..200 {
            if n.state_for_test().await.0.probed {
                break;
            }
            tokio::task::yield_now().await;
            std::thread::sleep(Duration::from_millis(5));
        }
        let (sw, _) = n.state_for_test().await;
        assert!(sw.probed && sw.probing);
        assert_eq!(sw.reached, vec!["b"]);
        let st = n.switch_status().await.unwrap();
        assert!(!st.ready);
        assert_eq!(st.unreached, vec!["c"]);
        // No probe while one ran less than PROBE_EVERY ago.
        n.apply(&pb::NetworkConfig::default(), None).await.unwrap();
        assert_eq!(fake.probes.lock().unwrap().len(), 1);
        // Peers are not checked while a switch runs.
        assert!(n.unreachable_peers().await.is_empty());
        tokio::time::sleep(PROBE_EVERY).await;
        for _ in 0..100 {
            if !n.state_for_test().await.0.probing {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!n.state_for_test().await.0.probing);
        n.apply(&pb::NetworkConfig::default(), None).await.unwrap();
        for _ in 0..200 {
            if fake.probes.lock().unwrap().len() == 2 {
                break;
            }
            tokio::task::yield_now().await;
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(fake.probes.lock().unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn rotates_the_key_file() {
        let dir = tmp("rotate");
        let n = net(Arc::new(Fake::default()), &dir).with_clock(SystemTime::now);
        let before = n.public_key();
        let public = n.rotate_key().await.unwrap();
        assert_ne!(public, before);
        assert_eq!(public, n.public_key());
        let again = key::load_or_create(&dir.join("network.key")).unwrap();
        assert_eq!(again.public().to_string(), public);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn reads_the_config_as_armada_node_does() {
        let c = node_config(&pb::NetworkConfig {
            mode: "plain".into(),
            isolate_default: true,
            endpoints: vec![pb::NetworkEndpoint {
                address: "10.120.0.2".into(),
                app: "web".into(),
            }],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(c.mode, "plain");
        assert!(c.isolate_default);
        assert_eq!(c.endpoints[0].app, "web");
    }
}

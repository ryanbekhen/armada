//! The member of the state the replay's scenarios share: an armada-kv
//! member in the test's process (ADR 0057; the store of new clusters), or,
//! with ARMADA_SCENARIO_STORE=etcd, the pinned etcd (scripts/etcd-cache.sh
//! puts it in .cache/etcd) as a cluster not moved yet keeps it, either on
//! a Unix socket in a directory of the build's, without TLS, as `armadad
//! backup` runs a scratch member.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use armada_store::Client;

enum Backend {
    Etcd(Child),
    Kv {
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    },
}

pub struct Member {
    backend: Backend,
    pub dir: PathBuf,
}

impl Drop for Member {
    fn drop(&mut self) {
        match &mut self.backend {
            Backend::Etcd(child) => {
                let _ = child.kill();
                let _ = child.wait();
            }
            Backend::Kv { stop, thread } => {
                if let Some(s) = stop.take() {
                    let _ = s.send(());
                }
                if let Some(t) = thread.take() {
                    let _ = t.join();
                }
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The pinned etcd: ARMADA_ETCD_DIR's, else the repository's .cache/etcd.
pub fn program() -> Option<PathBuf> {
    let dir = match std::env::var_os("ARMADA_ETCD_DIR") {
        Some(d) => PathBuf::from(d),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../.cache/etcd"),
    };
    let p = dir.join("etcd");
    p.is_file().then_some(p)
}

/// Which store the scenarios and terms run on: armada-kv unless
/// ARMADA_SCENARIO_STORE says etcd.
pub fn on_etcd() -> bool {
    match std::env::var("ARMADA_SCENARIO_STORE").as_deref() {
        Err(_) | Ok("") | Ok("kv") => false,
        Ok("etcd") => true,
        Ok(other) => panic!("ARMADA_SCENARIO_STORE={other}: kv or etcd"),
    }
}

/// The store's name for messages.
pub fn store_name() -> &'static str {
    if on_etcd() { "etcd" } else { "armada-kv" }
}

impl Member {
    /// Starts the member of the chosen store in dir (made afresh); etcd is
    /// the program found by `program`, refused when there is none.
    pub fn start_chosen(dir: PathBuf) -> Result<Member, String> {
        if !on_etcd() {
            return Member::start_kv(dir);
        }
        let prog = program().ok_or("no etcd in .cache/etcd or ARMADA_ETCD_DIR")?;
        Member::start(&prog, dir)
    }

    /// Starts an etcd member in dir (made afresh).
    pub fn start(etcd: &Path, dir: PathBuf) -> Result<Member, String> {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let peer = "https://127.0.0.1:2380";
        // Relative paths: a socket's address holds at most 108 bytes.
        let child = Command::new(etcd)
            .current_dir(&dir)
            .args(["--name", "replay", "--data-dir", "data"])
            .args(["--listen-client-urls", "unix://client.sock"])
            .args(["--advertise-client-urls", "unix://client.sock"])
            .args(["--listen-peer-urls", "unix://peer.sock"])
            .args(["--initial-advertise-peer-urls", peer])
            .arg("--initial-cluster")
            .arg(format!("replay={peer}"))
            .args(["--initial-cluster-token", "armada"])
            // The store's transactions hold up to 4096 operations.
            .args(["--max-txn-ops", "4096", "--unsafe-no-fsync"])
            .args(["--enable-grpc-gateway=false", "--log-level", "error"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("start {}: {e}", etcd.display()))?;
        Ok(Member {
            backend: Backend::Etcd(child),
            dir,
        })
    }

    /// Starts an armada-kv member in dir/data (made afresh), served on
    /// dir/client.sock from a thread of its own until it is dropped.
    pub fn start_kv(dir: PathBuf) -> Result<Member, String> {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let d = dir.clone();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("a runtime");
            rt.block_on(async move {
                let opts = armada_kv::Options {
                    name: "replay".to_string(),
                    ..Default::default()
                };
                let node = armada_kv::Node::open(&d.join("data"), opts)
                    .await
                    .expect("open armada-kv");
                armada_kv::serve_unix(node.clone(), &d.join("client.sock"), async {
                    let _ = stopped.await;
                })
                .await
                .expect("serve armada-kv");
                node.close().await;
            });
        });
        Ok(Member {
            backend: Backend::Kv {
                stop: Some(stop),
                thread: Some(thread),
            },
            dir,
        })
    }

    pub fn socket(&self) -> PathBuf {
        self.dir.join("client.sock")
    }

    /// Waits until the member answers.
    pub async fn ready(&mut self) -> Result<Client, String> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match &mut self.backend {
                Backend::Etcd(child) => {
                    if let Ok(Some(st)) = child.try_wait() {
                        return Err(format!("etcd exited: {st}"));
                    }
                }
                Backend::Kv { thread, .. } => {
                    if thread.as_ref().is_some_and(|t| t.is_finished()) {
                        return Err("armada-kv stopped".into());
                    }
                }
            }
            if self.socket().exists() {
                let c = Client::connect_unix(&self.socket()).map_err(|e| e.to_string())?;
                if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_secs(3), c.status()).await {
                    return Ok(c);
                }
            }
            if Instant::now() > deadline {
                return Err("the member did not become ready within a minute".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

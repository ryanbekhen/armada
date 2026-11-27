//! The etcd member the replay's scenarios share: the pinned etcd
//! (scripts/etcd-cache.sh puts it in .cache/etcd) on Unix sockets in a
//! directory of the build's, without TLS, as `armadad backup` runs a
//! scratch member.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use armada_store::Client;

pub struct Member {
    child: Child,
    pub dir: PathBuf,
}

impl Drop for Member {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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

impl Member {
    /// Starts a member in dir (made afresh).
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
        Ok(Member { child, dir })
    }

    pub fn socket(&self) -> PathBuf {
        self.dir.join("client.sock")
    }

    /// Waits until the member answers.
    pub async fn ready(&mut self) -> Result<Client, String> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Ok(Some(st)) = self.child.try_wait() {
                return Err(format!("etcd exited: {st}"));
            }
            if self.socket().exists() {
                let c = Client::connect_unix(&self.socket()).map_err(|e| e.to_string())?;
                if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_secs(3), c.status()).await {
                    return Ok(c);
                }
            }
            if Instant::now() > deadline {
                return Err("etcd did not become ready within a minute".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

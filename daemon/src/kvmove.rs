//! This server's part in the move of the control plane's state from etcd
//! to armada-kv (ADR 0057): the MoveHost the control plane's move and
//! follower ask (armada_server::statemove).
//!
//! During the move the server's new member runs inside `armadad server`,
//! from `<data dir>/kv.moving` (the member's directory as `kv/` will be,
//! and `move`, the move's ID), listening where armada-kv.service will: the
//! leader's starts as a new store from the copied key space, the others
//! join it. A move given up removes the directory. Once the state moved,
//! [`Host::switch`] stops the member, renames `kv.moving` to `kv` (from
//! then on the server's store is armada-kv) and `etcd` to `etcd.moved`
//! (kept for a manual return during this release), enables and starts
//! armada-kv.service, and stops and disables armada-etcd.service.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use armada_proto::etcd::mvccpb::KeyValue;
use armada_server::log::Logger;
use armada_server::statemove::MoveHost;
use armada_store::Client;
use tonic::codegen::async_trait;

use crate::agentconfig::{DIR_ETCD, DIR_KV, FILE_ETCD_INITIAL};
use crate::kvmember::{self, Fresh};

/// The new member's directory until the switch.
pub const DIR_KV_MOVING: &str = "kv.moving";
/// The move a `kv.moving` belongs to.
const FILE_MOVE: &str = "move";
/// etcd's member directory after the switch, kept during this release.
pub const DIR_ETCD_MOVED: &str = "etcd.moved";

struct Running {
    id: String,
    member: kvmember::Member,
}

/// A server's MoveHost.
pub struct Host {
    data_dir: PathBuf,
    data_dir_text: String,
    running: tokio::sync::Mutex<Option<Running>>,
    /// The move of kv.moving (running or on disk), and a client of its
    /// running member.
    current: Mutex<Option<(String, Option<Client>)>>,
    leading: AtomicBool,
    log: Logger,
}

fn io(op: &str, p: &Path, e: &std::io::Error) -> String {
    format!("{op} {}: {}", p.display(), armada_fsutil::errno_text(e))
}

impl Host {
    /// The host of data_dir's server; a `kv.moving` left by a move this
    /// server took part in is picked up again.
    pub fn new(data_dir: &str, log: Logger) -> Host {
        let dd = PathBuf::from(data_dir);
        let id = fs::read_to_string(dd.join(DIR_KV_MOVING).join(FILE_MOVE))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Host {
            data_dir: dd,
            data_dir_text: data_dir.to_string(),
            running: tokio::sync::Mutex::new(None),
            current: Mutex::new(id.map(|i| (i, None))),
            leading: AtomicBool::new(false),
            log,
        }
    }

    fn moving_dir(&self) -> PathBuf {
        self.data_dir.join(DIR_KV_MOVING)
    }

    /// The peer URL this server's member takes in a move (its server
    /// record's KvPeerURL), empty when the server certificate names no
    /// address.
    pub fn peer_url(data_dir: &str) -> String {
        kvmember::member_config(data_dir)
            .peer_url()
            .unwrap_or_default()
    }

    /// A fresh kv.moving for move id.
    fn prepare_dir(&self, id: &str) -> Result<PathBuf, String> {
        let dir = self.moving_dir();
        if let Err(e) = fs::remove_dir_all(&dir)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            return Err(io("remove", &dir, &e));
        }
        armada_fsutil::mkdir_private(&dir).map_err(|e| e.to_string())?;
        armada_fsutil::write_file_exclusive(&dir.join(FILE_MOVE), id.as_bytes(), 0o600)
            .map_err(|e| e.to_string())?;
        Ok(dir)
    }

    /// The member of kv.moving started in this process, joining through
    /// join (none: from its own state, or alone when it has none).
    async fn run(&self, id: &str, join: Vec<String>, fresh: Fresh) -> Result<Client, String> {
        let mut cfg = kvmember::kv_config(&self.data_dir_text)?;
        cfg.dir = self.moving_dir();
        cfg.join = join;
        let m = kvmember::start(&mut cfg, fresh).await?;
        let client = Client::connect(&m.client_url, &m.dir).map_err(|e| e.to_string())?;
        *self.running.lock().await = Some(Running {
            id: id.to_string(),
            member: m,
        });
        *self.current.lock().expect("current") = Some((id.to_string(), Some(client.clone())));
        Ok(client)
    }

    /// Stops the member running in this process.
    async fn stop_member(&self) {
        let r = self.running.lock().await.take();
        if let Some(r) = r {
            r.member.shutdown().await;
        }
        if let Some((_, c)) = self.current.lock().expect("current").as_mut() {
            *c = None;
        }
    }

    /// After the state moved (move id): the member stopped, `kv.moving`
    /// made `kv` and `etcd` made `etcd.moved`, then, under systemd as root,
    /// armada-kv.service enabled and started and armada-etcd.service
    /// stopped and disabled. Each step is safe to run again.
    pub async fn switch(&self, id: &str) -> Result<(), String> {
        self.stop_member().await;
        let dd = &self.data_dir;
        let moving = self.moving_dir();
        let kv = dd.join(DIR_KV);
        if moving.is_dir() {
            if kv.exists() {
                return Err(format!(
                    "{} exists already; the state moved (move {id}) but this server cannot switch to it",
                    kv.display()
                ));
            }
            let _ = fs::remove_file(moving.join(FILE_MOVE));
            fs::rename(&moving, &kv).map_err(|e| io("rename", &moving, &e))?;
        } else if !kv.is_dir() {
            return Err(format!(
                "the state moved to armada-kv (move {id}), but this server has no member of it in {}",
                moving.display()
            ));
        }
        let etcd = dd.join(DIR_ETCD);
        let moved = dd.join(DIR_ETCD_MOVED);
        if etcd.is_dir() && !moved.exists() {
            let _ = fs::remove_file(dd.join(FILE_ETCD_INITIAL));
            fs::rename(&etcd, &moved).map_err(|e| io("rename", &etcd, &e))?;
        }
        if let Ok(d) = fs::File::open(dd) {
            let _ = d.sync_all();
        }
        *self.current.lock().expect("current") = None;
        self.log.info(
            "the state moved to armada-kv; this server's store is now armada-kv",
            &[("move", id.to_string())],
        );
        if crate::machine::euid() == 0 && std::env::var_os("INVOCATION_ID").is_some() {
            // Under systemd: armada-kv.service runs the member from now on;
            // armada-etcd.service has nothing left to run (it would exit
            // 78) and stays off.
            crate::systemd::systemctl(&["enable", "--now", "armada-kv.service"])?;
            if let Err(e) = crate::systemd::systemctl(&["disable", "--now", "armada-etcd.service"])
            {
                self.log
                    .warn("stop armada-etcd after the move", &[("err", e)]);
            }
        } else {
            self.log.warn(
                "not under systemd: start this server's armada-kv member now",
                &[(
                    "command",
                    format!("armadad kv --data-dir {}", self.data_dir_text),
                )],
            );
        }
        Ok(())
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
        self.discard().await;
        let dir = self.prepare_dir(id)?;
        let mut w = armada_kv::snapshot::Writer::new(revision);
        for (l, ttl) in leases {
            w.lease(l, ttl);
        }
        for kv in &kvs {
            w.kv(kv);
        }
        let snap = w.finish();
        drop(kvs);
        let db = dir.join(armada_kv::node::DB_FILE);
        let store = armada_kv::mvcc::Store::restore(&snap, &db, armada_kv::mvcc::Limits::default())
            .map_err(|e| e.to_string())?;
        drop(store);
        *self.current.lock().expect("current") = Some((id.to_string(), None));
        let c = self.run(id, Vec::new(), Fresh::New).await?;
        // It answers once it leads.
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Ok(Ok(st)) = tokio::time::timeout(Duration::from_secs(3), c.status()).await
                && st.leader != 0
            {
                return Ok(c);
            }
            if Instant::now() > deadline {
                return Err("the new armada-kv member did not lead within a minute".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn join(&self, id: &str, peers: &[String]) -> Result<(), String> {
        if self.member(id).is_some() {
            return Ok(());
        }
        let on_disk = self.current();
        if on_disk.as_deref() != Some(id) {
            self.discard().await;
            self.prepare_dir(id)?;
            *self.current.lock().expect("current") = Some((id.to_string(), None));
        }
        self.run(id, peers.to_vec(), Fresh::Refuse)
            .await
            .map(|_| ())
    }

    fn current(&self) -> Option<String> {
        self.current
            .lock()
            .expect("current")
            .as_ref()
            .map(|(i, _)| i.clone())
    }

    fn member(&self, id: &str) -> Option<Client> {
        match self.current.lock().expect("current").as_ref() {
            Some((i, Some(c))) if i == id => Some(c.clone()),
            _ => None,
        }
    }

    fn member_client(&self, client_url: &str) -> Result<Client, String> {
        // This server's member certificate (the cluster CA's etcd:member
        // identity, which every member accepts).
        Client::connect(client_url, &self.moving_dir()).map_err(|e| e.to_string())
    }

    async fn discard(&self) {
        self.stop_member().await;
        let dir = self.moving_dir();
        if let Err(e) = fs::remove_dir_all(&dir)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            self.log.warn(
                "remove the armada-kv member of a state move",
                &[("err", io("remove", &dir, &e))],
            );
        }
        *self.current.lock().expect("current") = None;
    }

    fn set_leading(&self, on: bool) {
        self.leading.store(on, Ordering::SeqCst);
    }

    fn leading(&self) -> bool {
        self.leading.load(Ordering::SeqCst)
    }
}

impl Host {
    /// The move whose member runs in this process.
    pub async fn running(&self) -> Option<String> {
        self.running.lock().await.as_ref().map(|r| r.id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(name: &str) -> PathBuf {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/tmp")
            .join(name);
        let _ = fs::remove_dir_all(&p);
        armada_fsutil::mkdir_private(&p).unwrap();
        p
    }

    #[tokio::test]
    async fn the_switch_makes_the_moved_member_the_servers() {
        let dd = base("kvmove-switch");
        let moving = dd.join(DIR_KV_MOVING);
        armada_fsutil::mkdir_private(&moving).unwrap();
        fs::write(moving.join(FILE_MOVE), "abc").unwrap();
        fs::write(moving.join("kv.db"), "x").unwrap();
        armada_fsutil::mkdir_private(&dd.join(DIR_ETCD)).unwrap();
        fs::write(dd.join(FILE_ETCD_INITIAL), "s1=https://10.0.0.5:2380").unwrap();
        let text = dd.to_string_lossy().into_owned();
        // A server that restarts in the middle of a move knows its member.
        let h = Host::new(&text, Logger::discard());
        assert_eq!(h.current().as_deref(), Some("abc"));
        assert_eq!(crate::state::Store::of(&text), crate::state::Store::Etcd);
        h.switch("abc").await.unwrap();
        assert_eq!(crate::state::Store::of(&text), crate::state::Store::Kv);
        assert!(dd.join(DIR_KV).join("kv.db").is_file());
        assert!(!dd.join(DIR_KV).join(FILE_MOVE).exists());
        assert!(dd.join(DIR_ETCD_MOVED).is_dir() && !dd.join(DIR_ETCD).exists());
        assert!(h.current().is_none());
        // Again: nothing left to do.
        h.switch("abc").await.unwrap();
        // A server with no member of the move cannot switch.
        let other = base("kvmove-none");
        let h = Host::new(&other.to_string_lossy(), Logger::discard());
        assert!(h.switch("abc").await.unwrap_err().contains("no member"));
    }

    #[tokio::test]
    async fn a_given_up_move_leaves_nothing() {
        let dd = base("kvmove-discard");
        let moving = dd.join(DIR_KV_MOVING);
        armada_fsutil::mkdir_private(&moving).unwrap();
        fs::write(moving.join(FILE_MOVE), "abc").unwrap();
        let h = Host::new(&dd.to_string_lossy(), Logger::discard());
        h.set_leading(true);
        assert!(h.leading());
        h.discard().await;
        assert!(!moving.exists() && h.current().is_none());
    }
}

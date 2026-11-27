//! The cluster's state for the machine commands that need it but not the
//! running server: armadad embeds no etcd, it runs the runtime pack's
//! pinned `etcd` and `etcdutl` (ADR 0055).
//!
//! - A server's member that runs is reached at
//!   its client URL, TLS 1.3 with the member certificate, a status within
//!   3 seconds.
//! - One that does not run is started from the pack for the command's
//!   length, from the configuration file `armadad etcd` writes (in a
//!   private directory removed again), and stopped afterwards.
//! - A snapshot is turned into a member's data with `etcdutl snapshot
//!   restore`, and checked in a scratch
//!   member, the pack's etcd in a private directory listening on Unix
//!   sockets only (no TLS: nothing outside the directory reaches it).
//!
//! A server whose state is in armada-kv (ADR 0057, `<data dir>/kv`) is
//! reached the same way at its member's client URL; one that does not run
//! is opened in this process for the command's length (crate::kvmember).
//!
//! The programs come from the pack this armadad carries, extracted into a
//! private directory each time and checked against the pack's manifest
//! (the test hook ARMADA_DAEMON_TEST_ETCD_DIR names a directory holding
//! them instead).

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use armada_store::client::Client;

use crate::agentconfig::{FILE_ETCD_INITIAL, FILE_KV_INITIAL};
use crate::etcdmember::{self, CLUSTER_TOKEN, DIR_DATA};
use crate::{kvmember, pack};

/// Where a server keeps the cluster's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Store {
    /// The pack's etcd (armada-etcd.service, ADR 0055).
    Etcd,
    /// armada-kv (armada-kv.service, ADR 0057): the data directory has
    /// `kv`.
    Kv,
}

impl Store {
    /// The store of data_dir's server.
    pub fn of(data_dir: &str) -> Store {
        if kvmember::is_kv(data_dir) {
            Store::Kv
        } else {
            Store::Etcd
        }
    }

    /// The systemd unit that runs the member.
    pub fn unit(self) -> &'static str {
        match self {
            Store::Etcd => "armada-etcd",
            Store::Kv => "armada-kv",
        }
    }

    /// The member, as messages name it.
    pub fn member(self) -> &'static str {
        match self {
            Store::Etcd => "etcd member",
            Store::Kv => "armada-kv member",
        }
    }

    /// The file naming the members a joining server starts with.
    fn initial_file(self) -> &'static str {
        match self {
            Store::Etcd => FILE_ETCD_INITIAL,
            Store::Kv => FILE_KV_INITIAL,
        }
    }
}

/// The client URL of data_dir's member, its peer URL, and its directory
/// (whose certificate the client presents).
pub fn endpoint(data_dir: &str) -> Result<(String, String, PathBuf), String> {
    match Store::of(data_dir) {
        Store::Etcd => {
            let cfg = etcdmember::etcd_config(data_dir)?;
            let Some(addr) = cfg.addr else {
                return Err("etcd: no listen address".to_string());
            };
            Ok((
                etcdmember::member_url(&addr, cfg.client_port),
                etcdmember::member_url(&addr, cfg.peer_port),
                cfg.dir,
            ))
        }
        Store::Kv => {
            let cfg = kvmember::kv_config(data_dir)?;
            match (cfg.client_url(), cfg.peer_url()) {
                (Some(c), Some(p)) => Ok((c, p, cfg.dir)),
                _ => Err("armada-kv: no listen address".to_string()),
            }
        }
    }
}

/// How long a member may take to answer.
const READY_LIMIT: Duration = Duration::from_secs(60);
/// How long a member may take to stop before it is killed.
const STOP_LIMIT: Duration = Duration::from_secs(10);

/// The pinned etcd and etcdutl.
pub struct Programs {
    dir: PathBuf,
    /// The private directory the pack's programs were extracted into.
    tmp: Option<PathBuf>,
}

impl Programs {
    /// The programs, extracted from the pack into a private directory
    /// below base (which exists) unless the test hook names them.
    pub fn find(base: &Path) -> Result<Programs, String> {
        if let Some(d) = crate::hooks::get("ETCD_DIR") {
            return Ok(Programs {
                dir: PathBuf::from(d),
                tmp: None,
            });
        }
        if pack::bundled().is_empty() {
            return Err(
                "no etcd program: this armadad carries no runtime pack with etcd and etcdutl"
                    .to_string(),
            );
        }
        let tmp = pack::temp_dir(base, ".etcd-")?;
        let p = Programs {
            dir: tmp.clone(),
            tmp: Some(tmp),
        };
        pack::extract_programs(
            pack::bundled(),
            &p.dir,
            &[pack::BIN_ETCD, pack::BIN_ETCDUTL],
        )
        .map_err(|e| format!("runtime pack: {e}"))?;
        Ok(p)
    }

    pub fn etcd(&self) -> PathBuf {
        self.dir.join(pack::BIN_ETCD)
    }

    pub fn etcdutl(&self) -> PathBuf {
        self.dir.join(pack::BIN_ETCDUTL)
    }
}

impl Drop for Programs {
    fn drop(&mut self) {
        if let Some(t) = self.tmp.take() {
            let _ = fs::remove_dir_all(t);
        }
    }
}

/// A command for one of the programs, without etcd's own variables in its
/// environment (they would override its flags and file).
fn program(path: &Path) -> Command {
    let mut c = Command::new(path);
    c.env_clear()
        .envs(std::env::vars_os().filter(|(k, _)| !k.to_string_lossy().starts_with("ETCD_")))
        .stdin(Stdio::null());
    c
}

/// An etcd process this command started, stopped when dropped.
pub struct Process {
    child: Child,
    /// etcd's last lines of error output.
    errors: Arc<Mutex<Vec<String>>>,
    /// Directories removed once it stopped.
    remove: Vec<PathBuf>,
    _programs: Option<Programs>,
}

impl Process {
    fn spawn(
        mut cmd: Command,
        programs: Option<Programs>,
        remove: Vec<PathBuf>,
    ) -> Result<Process, String> {
        cmd.stdout(Stdio::null()).stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                for d in &remove {
                    let _ = fs::remove_dir_all(d);
                }
                return Err(format!("start etcd: {}", armada_fsutil::errno_text(&e)));
            }
        };
        let errors = Arc::new(Mutex::new(Vec::new()));
        if let Some(err) = child.stderr.take() {
            let keep = errors.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(err).lines().map_while(Result::ok) {
                    let mut k = keep.lock().expect("etcd output");
                    if k.len() == 16 {
                        k.remove(0);
                    }
                    k.push(line);
                }
            });
        }
        Ok(Process {
            child,
            errors,
            remove,
            _programs: programs,
        })
    }

    /// Why etcd ended: its last error, from its log line's "error" or
    /// "msg".
    fn ended(&mut self) -> Option<String> {
        let status = self.child.try_wait().ok().flatten()?;
        // The output's reader may still be reading the last lines.
        std::thread::sleep(Duration::from_millis(100));
        let lines = self.errors.lock().expect("etcd output").clone();
        let why = lines.iter().rev().find_map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).ok()?;
            let level = v.get("level")?.as_str()?;
            if level != "error" && level != "fatal" && level != "panic" {
                return None;
            }
            let msg = v.get("msg")?.as_str()?.to_string();
            Some(match v.get("error").and_then(|e| e.as_str()) {
                Some(e) => format!("{msg}: {e}"),
                None => msg,
            })
        });
        Some(why.unwrap_or_else(|| format!("etcd exited ({status})")))
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            // SAFETY: a signal to the child this process started and has not
            // reaped yet.
            unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
            let deadline = Instant::now() + STOP_LIMIT;
            while Instant::now() < deadline {
                if let Ok(Some(_)) = self.child.try_wait() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        for d in &self.remove {
            let _ = fs::remove_dir_all(d);
        }
    }
}

/// Waits for a member to answer, at most a minute.
/// The member's ID and whether it is a learner.
async fn wait_ready(p: &mut Process, client: &Client) -> Result<(u64, bool), String> {
    let deadline = Instant::now() + READY_LIMIT;
    loop {
        if let Some(why) = p.ended() {
            return Err(format!("etcd: {why}"));
        }
        if let Ok(Ok(st)) = tokio::time::timeout(Duration::from_secs(3), client.status()).await {
            return Ok((st.header.as_ref().map_or(0, |h| h.member_id), st.is_learner));
        }
        if Instant::now() > deadline {
            return Err("etcd did not become ready within a minute".to_string());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// A connection to this server's member, and the member when this command
/// started it.
pub struct State {
    pub client: Client,
    /// The member's ID in the cluster.
    pub member_id: u64,
    _member: Option<Process>,
    /// The armada-kv member this command opened.
    kv: Option<kvmember::Member>,
}

impl State {
    /// Closes a member this command started: an armada-kv member shuts
    /// down in order, an etcd process stops when dropped.
    pub async fn close(mut self) {
        if let Some(m) = self.kv.take() {
            m.shutdown().await;
        }
    }
}

/// The running member at url (with the certificates in dir), or an error.
async fn dial(url: &str, dir: &Path) -> Result<(Client, u64), String> {
    let c = Client::connect(url, dir).map_err(|e| e.to_string())?;
    match tokio::time::timeout(Duration::from_secs(3), c.status()).await {
        Ok(Ok(st)) => Ok((c, st.header.as_ref().map_or(0, |h| h.member_id))),
        Ok(Err(e)) => Err(format!("member at {url}: {e}")),
        Err(_) => Err(format!("member at {url}: context deadline exceeded")),
    }
}

/// The member started from the pack, its peer
/// URL brought up to date, and, on a server that joined, a voting member.
async fn start_member(data_dir: &str, cfg: &mut etcdmember::Config) -> Result<State, String> {
    let prepared = etcdmember::prepare_start(cfg)?;
    let dd = Path::new(data_dir);
    let programs = Programs::find(dd)?;
    let tmp = pack::temp_dir(dd, ".etcd-start-")?;
    let file = tmp.join(etcdmember::FILE_CONFIG);
    if let Err(e) = armada_fsutil::write_file_exclusive(&file, &prepared.file, 0o600) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(e.to_string());
    }
    let mut cmd = program(&programs.etcd());
    cmd.arg("--config-file").arg(&file);
    let mut p = Process::spawn(cmd, Some(programs), vec![tmp])?;
    let client = Client::connect(&prepared.client_url, &prepared.dir).map_err(|e| e.to_string())?;
    let (id, mut learner) = wait_ready(&mut p, &client).await?;
    if !learner {
        update_peer_url(&client, id, &prepared.peer_url).await?;
    }
    while learner {
        tokio::time::sleep(Duration::from_millis(500)).await;
        learner = match client.status().await {
            Ok(s) => s.is_learner,
            Err(_) => true,
        };
    }
    // Joined: later starts use the member's own data.
    let initial = dd.join(FILE_ETCD_INITIAL);
    if let Err(e) = fs::remove_file(&initial)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(format!(
            "remove {}: {}",
            initial.display(),
            armada_fsutil::errno_text(&e)
        ));
    }
    Ok(State {
        client,
        member_id: id,
        _member: Some(p),
        kv: None,
    })
}

/// data_dir's armada-kv member opened in this process for the command's
/// length, as start_member starts etcd's: its peer URL brought up to date,
/// and, on a server that joined, a voting member. fresh says whether a
/// member with no state starts a new cluster.
async fn start_kv(data_dir: &str, fresh: kvmember::Fresh) -> Result<State, String> {
    let mut cfg = kvmember::kv_config(data_dir)?;
    let m = kvmember::start(&mut cfg, fresh).await?;
    let client = Client::connect(&m.client_url, &m.dir).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + READY_LIMIT;
    let (id, mut learner) = loop {
        if let Ok(Ok(st)) = tokio::time::timeout(Duration::from_secs(3), client.status()).await
            && st.leader != 0
        {
            break (st.header.as_ref().map_or(0, |h| h.member_id), st.is_learner);
        }
        if Instant::now() > deadline {
            m.shutdown().await;
            return Err("armada-kv did not become ready within a minute".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    if !learner {
        update_peer_url(&client, id, &m.peer_url).await?;
    }
    while learner {
        tokio::time::sleep(Duration::from_millis(500)).await;
        learner = match client.status().await {
            Ok(s) => s.is_learner,
            Err(_) => true,
        };
    }
    remove_initial(data_dir, Store::Kv)?;
    Ok(State {
        client,
        member_id: id,
        _member: None,
        kv: Some(m),
    })
}

/// The initial cluster of a server that joined, once its member votes:
/// later starts use the member's own data.
fn remove_initial(data_dir: &str, store: Store) -> Result<(), String> {
    let initial = Path::new(data_dir).join(store.initial_file());
    if let Err(e) = fs::remove_file(&initial)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(format!(
            "remove {}: {}",
            initial.display(),
            armada_fsutil::errno_text(&e)
        ));
    }
    Ok(())
}

/// The member of a data directory started for the command's length
/// (`armadad init`): the pack's etcd, joined as start_member joins it, or,
/// for a cluster on armada-kv, a new armada-kv cluster with this member
/// alone, opened in this process.
pub async fn start(data_dir: &str, store: Store) -> Result<State, String> {
    if store == Store::Kv {
        return start_kv(data_dir, kvmember::Fresh::New).await;
    }
    let mut cfg = etcdmember::etcd_config(data_dir)?;
    start_member(data_dir, &mut cfg).await
}

async fn update_peer_url(c: &Client, id: u64, peer: &str) -> Result<(), String> {
    let members = tokio::time::timeout(Duration::from_secs(10), c.member_list())
        .await
        .map_err(|_| "etcd member list: context deadline exceeded".to_string())?
        .map_err(|e| format!("etcd member list: {e}"))?;
    for m in members {
        if m.id != id {
            continue;
        }
        if m.peer_ur_ls.len() == 1 && m.peer_ur_ls[0] == peer {
            return Ok(());
        }
        c.member_update(m.id, vec![peer.to_string()])
            .await
            .map_err(|e| format!("etcd: update peer URL to {peer}: {e}"))?;
    }
    Ok(())
}

/// The member of a running server in data_dir, or the member
/// started for the command when no server runs.
pub async fn state_client(data_dir: &str) -> Result<State, String> {
    let store = Store::of(data_dir);
    let (url, _, dir) = endpoint(data_dir)?;
    if let Ok((c, id)) = dial(&url, &dir).await {
        return Ok(State {
            client: c,
            member_id: id,
            _member: None,
            kv: None,
        });
    }
    let started = match store {
        Store::Etcd => {
            let mut cfg = etcdmember::etcd_config(data_dir)?;
            start_member(data_dir, &mut cfg).await
        }
        Store::Kv => start_kv(data_dir, kvmember::Fresh::Refuse).await,
    };
    started.map_err(|e| format!("the server's state is not reachable (is it starting?): {e}"))
}

/// The snapshot turned into the data of a new single-member
/// cluster of member name below dir, whose peer URL is on addr:peer_port.
pub fn restore(
    programs: &Programs,
    snapshot: &Path,
    dir: &Path,
    name: &str,
    addr: Option<IpAddr>,
    peer_port: u16,
) -> Result<(), String> {
    if name.is_empty() {
        return Err("etcd: Name is required".to_string());
    }
    armada_fsutil::mkdir_private(dir).map_err(|e| e.to_string())?;
    let data = dir.join(DIR_DATA);
    match fs::symlink_metadata(&data) {
        Ok(_) => return Err(format!("{} already exists", data.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!(
                "lstat {}: {}",
                data.display(),
                armada_fsutil::errno_text(&e)
            ));
        }
    }
    let peer = match addr {
        Some(a) => etcdmember::member_url(&a, peer_port),
        None => format!("https://invalid%20IP:{peer_port}"),
    };
    let out = program(&programs.etcdutl())
        .arg("snapshot")
        .arg("restore")
        .arg(snapshot)
        .arg("--name")
        .arg(name)
        .arg("--data-dir")
        .arg(&data)
        .arg("--initial-cluster")
        .arg(format!("{name}={peer}"))
        .arg("--initial-cluster-token")
        .arg(CLUSTER_TOKEN)
        .arg("--initial-advertise-peer-urls")
        .arg(&peer)
        .output();
    let failed = match out {
        Err(e) => Some(format!("run etcdutl: {}", armada_fsutil::errno_text(&e))),
        Ok(o) if o.status.success() => None,
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stderr);
            let why = text
                .lines()
                .rev()
                .find_map(|l| l.strip_prefix("Error: "))
                .map(str::to_string)
                .unwrap_or_else(|| text.trim().to_string());
            Some(why)
        }
    };
    if let Some(why) = failed {
        let _ = fs::remove_dir_all(&data);
        return Err(format!("restore etcd snapshot: {why}"));
    }
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).map_err(|e| {
        format!(
            "chmod {}: {}",
            data.display(),
            armada_fsutil::errno_text(&e)
        )
    })
}

/// What a snapshot holds that a backup records.
pub struct StateInfo {
    pub schema: i64,
    pub master_key_id: String,
    /// The API address recorded for the backed-up server.
    pub listen: String,
}

/// inspect: the snapshot restored into a scratch member below scratch,
/// its state opened (which checks the schema), and the cluster's records
/// read. The scratch member is removed again.
pub async fn inspect(
    programs: &Programs,
    snapshot: &Path,
    scratch: &Path,
    server: &str,
) -> Result<StateInfo, String> {
    let dir = pack::temp_dir(scratch, ".inspect-")?;
    struct Remove(PathBuf);
    impl Drop for Remove {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _remove = Remove(dir.clone());
    restore(
        programs,
        snapshot,
        &dir.join("etcd"),
        "inspect",
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        etcdmember::DEFAULT_PEER_PORT,
    )?;
    let peer = etcdmember::member_url(
        &IpAddr::V4(Ipv4Addr::LOCALHOST),
        etcdmember::DEFAULT_PEER_PORT,
    );
    let mut cmd = program(&programs.etcd());
    // Relative paths: a socket's address holds at most 108 bytes.
    cmd.current_dir(&dir)
        .args(["--name", "inspect", "--data-dir", "etcd/data"])
        .args(["--listen-client-urls", "unix://client.sock"])
        .args(["--advertise-client-urls", "unix://client.sock"])
        .args(["--listen-peer-urls", "unix://peer.sock"])
        .arg("--initial-advertise-peer-urls")
        .arg(&peer)
        .arg("--initial-cluster")
        .arg(format!("inspect={peer}"))
        .args(["--initial-cluster-token", CLUSTER_TOKEN])
        .args(["--enable-grpc-gateway=false", "--log-level", "error"]);
    let mut p = Process::spawn(cmd, None, Vec::new())?;
    let client = Client::connect_unix(&dir.join("client.sock")).map_err(|e| e.to_string())?;
    wait_ready(&mut p, &client).await?;
    let st = armada_store::Etcd::new(client, crate::backup::ETCD_PREFIX)
        .await
        .map_err(|e| e.to_string())?;
    let master_key_id = match st.get_meta(crate::backup::META_MASTER_KEY).await {
        Ok(v) => v,
        Err(e) if e.is(armada_store::error::Kind::NotFound) => String::new(),
        Err(e) => return Err(e.to_string()),
    };
    let mut listen = String::new();
    for srv in st.list_servers().await.map_err(|e| e.to_string())? {
        if srv.name == server {
            listen = srv.api_addr;
        }
    }
    drop(p);
    Ok(StateInfo {
        schema: armada_store::SCHEMA,
        master_key_id,
        listen,
    })
}

/// The status of the member at url within 3 seconds:
/// its ID and whether it is a learner.
async fn member_status(c: &Client, host: &str) -> Result<(u64, bool), String> {
    match tokio::time::timeout(Duration::from_secs(3), c.status()).await {
        Ok(Ok(st)) => match st.header {
            Some(h) => Ok((h.member_id, st.is_learner)),
            None => Err(format!("etcd at {host}: status without a header")),
        },
        Ok(Err(e)) => Err(format!("etcd at {host}: {e}")),
        Err(_) => Err(format!("etcd at {host}: context deadline exceeded")),
    }
}

/// What the member of data_dir's server says of itself (armadad doctor's
/// etcd check, ADR 0055): its client address and its status, asked once
/// within 3 seconds.
pub async fn member_health(
    data_dir: &str,
) -> Result<(String, armada_proto::etcd::etcdserverpb::StatusResponse), String> {
    let (url, _, dir) = endpoint(data_dir)?;
    let what = match Store::of(data_dir) {
        Store::Etcd => "etcd",
        Store::Kv => "armada-kv",
    };
    let host = url.trim_start_matches("https://").to_string();
    let c = Client::connect(&url, &dir).map_err(|e| e.to_string())?;
    match tokio::time::timeout(Duration::from_secs(3), c.status()).await {
        Ok(Ok(st)) => Ok((host, st)),
        Ok(Err(e)) => Err(format!("{what} at {host}: {e}")),
        Err(_) => Err(format!("{what} at {host}: context deadline exceeded")),
    }
}

/// The member armada-etcd.service runs
/// (`armadad etcd`, ADR 0055), or armada-kv.service on a server whose state
/// is in armada-kv (ADR 0057), waited for up to a minute, its peer URL
/// brought up to date, and, on a server that joined, a voting member
/// before the state is used. wait is told once that the member does not
/// answer yet, and learner once that it waits for its promotion.
pub async fn connect(
    data_dir: &str,
    wait: &(dyn Fn(&str, &str) + Send + Sync),
    learner: &(dyn Fn() + Send + Sync),
) -> Result<State, String> {
    let store = Store::of(data_dir);
    let (url, peer, dir) = endpoint(data_dir)?;
    let host = url.trim_start_matches("https://").to_string();
    let deadline = Instant::now() + READY_LIMIT;
    let mut logged = false;
    let (client, id, is_learner) = loop {
        let res = match Client::connect(&url, &dir) {
            Ok(c) => member_status(&c, &host).await.map(|(id, l)| (c, id, l)),
            Err(e) => Err(e.to_string()),
        };
        match res {
            Ok(v) => break v,
            Err(e) => {
                if Instant::now() > deadline {
                    return Err(format!(
                        "the {} at {host} did not answer within a minute (is {} running?): {e}",
                        store.member(),
                        store.unit()
                    ));
                }
                if !logged {
                    wait(&host, &e);
                    logged = true;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    };
    if !is_learner {
        update_peer_url(&client, id, &peer).await?;
    }
    let mut is_learner = is_learner;
    if is_learner {
        learner();
    }
    while is_learner {
        tokio::time::sleep(Duration::from_millis(500)).await;
        is_learner = member_status(&client, &host).await.map_or(true, |(_, l)| l);
    }
    remove_initial(data_dir, store)?;
    Ok(State {
        client,
        member_id: id,
        _member: None,
        kv: None,
    })
}

/// What [`inspect_kv`] reads of armada-kv's snapshots: at most this much.
pub const MAX_KV_SNAPSHOT: u64 = 2 << 30;

/// An armada-kv snapshot read from a file and checked (its format, its
/// SHA-256, its revision, and its keys' order and revisions).
pub fn read_kv_snapshot(snapshot: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let f = fs::File::open(snapshot).map_err(|e| {
        format!(
            "open {}: {}",
            snapshot.display(),
            armada_fsutil::errno_text(&e)
        )
    })?;
    let mut b = Vec::new();
    f.take(MAX_KV_SNAPSHOT + 1)
        .read_to_end(&mut b)
        .map_err(|e| format!("read {}: {e}", snapshot.display()))?;
    if b.len() as u64 > MAX_KV_SNAPSHOT {
        return Err("the armada-kv snapshot is too large".to_string());
    }
    armada_kv::snapshot::read(&b).map_err(|e| e.to_string())?;
    Ok(b)
}

/// The snapshot turned into a new single-member armada-kv store in dir
/// (the member's directory of a kv server, created 0700): its database,
/// whose member starts a cluster of its own on its first start.
pub fn restore_kv(snapshot: &Path, dir: &Path) -> Result<(), String> {
    let b = read_kv_snapshot(snapshot)?;
    armada_fsutil::mkdir_private(dir).map_err(|e| e.to_string())?;
    let db = dir.join(armada_kv::node::DB_FILE);
    armada_kv::mvcc::Store::restore(&b, &db, armada_kv::mvcc::Limits::default())
        .map(drop)
        .map_err(|e| format!("restore armada-kv snapshot: {e}"))
}

/// inspect for an armada-kv snapshot: restored into a scratch member
/// below scratch, opened in this process on a Unix socket of its
/// directory, its state opened (which checks the schema), and the
/// cluster's records read. The scratch member is removed again.
pub async fn inspect_kv(
    snapshot: &Path,
    scratch: &Path,
    server: &str,
) -> Result<StateInfo, String> {
    let dir = pack::temp_dir(scratch, ".inspect-")?;
    struct Remove(PathBuf);
    impl Drop for Remove {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _remove = Remove(dir.clone());
    let kv = dir.join("kv");
    restore_kv(snapshot, &kv)?;
    let node = armada_kv::Node::open(
        &kv,
        armada_kv::Options {
            name: "inspect".to_string(),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    let sock = dir.join("client.sock");
    let (tx, mut rx) = tokio::sync::watch::channel(false);
    let served = {
        let (node, sock) = (node.clone(), sock.clone());
        tokio::spawn(async move {
            let _ = armada_kv::serve_unix(node, &sock, async move {
                let _ = rx.wait_for(|v| *v).await;
            })
            .await;
        })
    };
    let read = async {
        let client = Client::connect_unix(&sock).map_err(|e| e.to_string())?;
        let deadline = Instant::now() + READY_LIMIT;
        loop {
            if let Ok(Ok(st)) = tokio::time::timeout(Duration::from_secs(3), client.status()).await
                && st.leader != 0
            {
                break;
            }
            if Instant::now() > deadline {
                return Err("armada-kv did not become ready within a minute".to_string());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let st = armada_store::Etcd::new(client, crate::backup::ETCD_PREFIX)
            .await
            .map_err(|e| e.to_string())?;
        let master_key_id = match st.get_meta(crate::backup::META_MASTER_KEY).await {
            Ok(v) => v,
            Err(e) if e.is(armada_store::error::Kind::NotFound) => String::new(),
            Err(e) => return Err(e.to_string()),
        };
        let mut listen = String::new();
        for srv in st.list_servers().await.map_err(|e| e.to_string())? {
            if srv.name == server {
                listen = srv.api_addr;
            }
        }
        Ok(StateInfo {
            schema: armada_store::SCHEMA,
            master_key_id,
            listen,
        })
    }
    .await;
    let _ = tx.send(true);
    let _ = served.await;
    node.close().await;
    read
}

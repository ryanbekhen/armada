//! The supervisor runtime behind the agent's [`Runtime`] (ADR 0055, item
//! 16e; ADR 0046, ADR 0054): Go's internal/runtime/containerd driver on
//! its supervisor backend through armada-node, with armada-node's code
//! called in process. Images are pulled into and pruned from armada-node's
//! store, root filesystems prepared on its unpacked layers, specs built by
//! its `runtime spec` code, bundles written and listed, shims started and
//! asked, and containers sampled as its commands do; exec runs
//! `armada-node runtime exec` as a process of its own. The network is
//! the pack's CNI plugins run as libcni runs them, logs go through
//! armada-log on the shim's descriptors, and init containers and sidecars
//! start in order as Go's driver starts them.
//!
//! Every file is where and as the Go agent keeps it (bundles, records,
//! config.json, armada-node's image store and root filesystems, the CNI
//! cache, the container files, log history), so either agent adopts the
//! containers the other made. What needs root or the kernel goes through
//! [`host::Host`].

pub mod cni;
#[cfg(test)]
mod conformance;
pub mod exec;
pub mod files;
pub mod host;
pub mod logs;
#[cfg(test)]
mod parity;
pub mod shim;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use armada_node::runtime::container::bundle::{self, Record};
use armada_node::runtime::container::mount::Mount;
use armada_node::runtime::container::shim::CallError;
use armada_node::runtime::container::stats as nstats;
use armada_node::runtime::image::store::{ImageRecord, Store};
use armada_node::runtime::image::{pull as npull, reference, snapshot};
use serde_json::value::RawValue;
use tokio::sync::watch;

use crate::haproxy::engine::{SystemRunner, SystemSpec};
use crate::log::Logger;
use crate::runtime::{
    self, AgentStatus, Container, ContainerSpec, Error, Image, LABEL_APP, LABEL_CONTAINER,
    LABEL_REPLICA, LABEL_REVISION, LABEL_ROLE, LABEL_SYSTEM, Member, MemberSpec, ROLE_INIT,
    ROLE_SIDECAR, RegistryAuth, Runtime, STATE_CREATED, STATE_DEAD, STATE_EXITED, STATE_RUNNING,
    STATE_STARTING, Stats,
};
use host::Host;
use shim::{Shims, TaskState};

/// The driver's own labels.
const LABEL_PREFIX: &str = "armada.runtime/";
const LABEL_KIND: &str = "armada.runtime/kind";
const LABEL_NAME: &str = "armada.runtime/name";
const LABEL_HOST_IP: &str = "armada.runtime/host-ip";
const LABEL_HOST_PORT: &str = "armada.runtime/host-port";
const LABEL_PORT: &str = "armada.runtime/port";
const LABEL_IP: &str = "armada.runtime/ip";
const LABEL_NETNS: &str = "armada.runtime/netns";
const LABEL_STARTED: &str = "armada.runtime/started";
/// The replica's container an init container or sidecar belongs to.
const LABEL_POD: &str = "armada.runtime/pod";
/// On a replica's container: why its start was given up.
const LABEL_FAILED: &str = "armada.runtime/failed";
const KIND_APP: &str = "app";
const KIND_SYSTEM: &str = "system";
const KIND_MEMBER: &str = "member";
/// Bounds the reason a start was given up, kept in a label.
const MAX_FAILED: usize = 512;

/// Groups Armada's containers in the cgroup v2 hierarchy.
const CGROUP_PARENT: &str = "/armada";
/// Armada's AppArmor profile.
const APPARMOR_PROFILE: &str = "armada-default";
/// Host ports for published container ports.
const PORT_MIN: u16 = 20000;
const PORT_MAX: u16 = 32767;

/// Where the runtime's files are, and how it reaches the machine.
#[derive(Clone)]
pub struct Config {
    /// Armada's data directory (/var/lib/armada).
    pub data_dir: PathBuf,
    /// Its run directory (/run/armada).
    pub run_dir: PathBuf,
    /// The node's container subnet; "" for the default.
    pub subnet: String,
    /// The bridge's and containers' MTU; 0 leaves the kernel's.
    pub mtu: u32,
    /// The runtime pack's programs; None for <data dir>/runtime/current/bin.
    pub bin_dir: Option<PathBuf>,
    /// systemd's programs; "" for systemd-run and systemctl.
    pub systemd_run: String,
    pub systemctl: String,
    /// Where cgroup v2 and procfs are mounted; empty for the usual.
    pub cgroup_root: PathBuf,
    pub proc_root: PathBuf,
    pub host: Arc<dyn Host>,
    pub log: Logger,
}

impl Config {
    /// The machine's runtime under data_dir and run_dir.
    pub fn new(data_dir: PathBuf, run_dir: PathBuf, log: Logger) -> Config {
        Config {
            data_dir,
            run_dir,
            subnet: String::new(),
            mtu: 0,
            bin_dir: None,
            systemd_run: String::new(),
            systemctl: String::new(),
            cgroup_root: PathBuf::new(),
            proc_root: PathBuf::new(),
            host: Arc::new(host::LinuxHost),
            log,
        }
    }
}

/// The supervisor runtime.
#[derive(Clone)]
pub struct Supervisor {
    inner: Arc<Inner>,
}

struct Inner {
    cfg: Config,
    bin: PathBuf,
    bundles: PathBuf,
    images: PathBuf,
    net: cni::Network,
    shims: Shims,
    /// Picking a host port and recording it must not interleave.
    ports: tokio::sync::Mutex<()>,
    /// The AppArmor profile was loaded by this process.
    apparmor: Mutex<bool>,
    /// Replicas whose init containers or sidecars are starting.
    starts: Mutex<HashMap<String, Arc<Start>>>,
    /// Records a listing left out, logged once while they stay so.
    skipped: Mutex<BTreeMap<String, String>>,
}

/// A replica's bring-up in progress.
struct Start {
    cancel: watch::Sender<bool>,
    done: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// "op path: errno", as Go's *PathError prints.
pub(crate) fn os_err(op: &str, p: &Path, e: &std::io::Error) -> String {
    format!("{op} {}: {}", p.display(), errno(e))
}

/// Go's text for an OS error.
pub(crate) fn errno(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(n) => armada_node::runtime::container::errno_text(n),
        None => e.to_string(),
    }
}

/// exec.ExitError's text.
pub(crate) fn exit_text(s: &std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    if let Some(c) = s.code() {
        return format!("exit status {c}");
    }
    let sig = s.signal().unwrap_or(0);
    let name = match sig {
        libc::SIGKILL => "killed".to_string(),
        libc::SIGTERM => "terminated".to_string(),
        libc::SIGINT => "interrupt".to_string(),
        libc::SIGSEGV => "segmentation fault".to_string(),
        libc::SIGABRT => "aborted".to_string(),
        n => format!("signal {n}"),
    };
    format!("signal: {name}")
}

fn other(e: impl Into<String>) -> Error {
    Error::Other(e.into())
}

/// Random bytes as hex.
fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    let mut got = 0;
    while got < n {
        // SAFETY: the buffer is valid for its remaining length.
        let r = unsafe { libc::getrandom(b[got..].as_mut_ptr().cast(), n - got, 0) };
        if r > 0 {
            got += r as usize;
        }
    }
    b.iter().map(|c| format!("{c:02x}")).collect()
}

/// newID: a fresh container ID for name, unique per creation.
pub fn new_id(name: &str) -> Result<String, String> {
    let id = format!("{name}-{}", random_hex(4));
    if !logs::valid_id(&id) {
        return Err(format!(
            "invalid container name {}",
            armada_pki::go_quote(name)
        ));
    }
    Ok(id)
}

/// time.Now().UTC().Format(time.RFC3339Nano).
fn now_text() -> String {
    crate::clock::rfc3339_nano(SystemTime::now())
}

/// time.Parse(time.RFC3339Nano, s); None when it is not one.
pub fn parse_time(s: &str) -> Option<SystemTime> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        t.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| t.parse().ok())?
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    let mut i = 19;
    let mut nanos: i64 = 0;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let frac = &s[start..i];
        if frac.is_empty() || frac.len() > 9 {
            return None;
        }
        nanos = format!("{frac:0<9}").parse().ok()?;
    }
    let offset = match &s[i..] {
        "Z" => 0,
        z if z.len() == 6 && (z.starts_with('+') || z.starts_with('-')) && &z[3..4] == ":" => {
            let oh: i64 = z[1..3].parse().ok()?;
            let om: i64 = z[4..6].parse().ok()?;
            let o = oh * 3600 + om * 60;
            if z.starts_with('-') { -o } else { o }
        }
        _ => return None,
    };
    // Days from the civil date (Howard Hinnant's algorithm).
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 + sec - offset;
    if secs >= 0 {
        Some(UNIX_EPOCH + Duration::new(secs as u64, nanos as u32))
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs((-secs) as u64))?
            .checked_add(Duration::from_nanos(nanos as u64))
    }
}

/// netutil.CheckPrivateIP's acceptance: a private address in canonical
/// form.
fn private_ip(s: &str) -> bool {
    let Some(a) = armada_node::net::addr::Addr::parse(s) else {
        return false;
    };
    if !a.zone().is_empty() || a.unmap().to_string() != s {
        return false;
    }
    let u = a.unmap();
    let cgnat =
        matches!(u, armada_node::net::addr::Addr::V4(b) if b[0] == 100 && b[1] & 0xc0 == 64);
    u.is_private() || u.is_loopback() || cgnat
}

fn label<'a>(l: &'a BTreeMap<String, String>, k: &str) -> &'a str {
    l.get(k).map(String::as_str).unwrap_or("")
}

/// The node's spec of a container as armada-node's spec code reads it.
fn node_spec(s: &ContainerSpec) -> armada_node::runtime::ContainerSpec {
    use armada_node::runtime as n;
    let files = |f: &[runtime::FileMount]| -> Vec<n::FileMount> {
        f.iter()
            .map(|f| n::FileMount {
                source: f.source.clone(),
                target: f.target.clone(),
            })
            .collect()
    };
    let vols = |v: &[runtime::VolumeMount]| -> Vec<n::VolumeMount> {
        v.iter()
            .map(|v| n::VolumeMount {
                source: v.source.clone(),
                target: v.target.clone(),
                shared: v.shared,
                read_only: v.read_only,
            })
            .collect()
    };
    let member = |m: &MemberSpec| n::MemberSpec {
        name: m.name.clone(),
        image: m.image.clone(),
        entrypoint: m.entrypoint.clone(),
        cmd: m.cmd.clone(),
        env: m.env.clone(),
        memory_bytes: m.memory_bytes,
        nano_cpus: m.nano_cpus,
        cpu_reserve_millis: m.cpu_reserve_millis,
        pids_limit: m.pids_limit,
        files: files(&m.files),
        volumes: vols(&m.volumes),
    };
    n::ContainerSpec {
        name: s.name.clone(),
        image: s.image.clone(),
        entrypoint: s.entrypoint.clone(),
        cmd: s.cmd.clone(),
        env: s.env.clone(),
        labels: s.labels.clone(),
        port: s.port,
        host_ip: s.host_ip.clone(),
        memory_bytes: s.memory_bytes,
        nano_cpus: s.nano_cpus,
        cpu_reserve_millis: s.cpu_reserve_millis,
        pids_limit: s.pids_limit,
        files: files(&s.files),
        dns: s.dns.clone(),
        dns_search: s.dns_search.clone(),
        volumes: vols(&s.volumes),
        init: s.init.iter().map(member).collect(),
        sidecars: s.sidecars.iter().map(member).collect(),
    }
}

/// What a container's spec is built from besides the image.
#[derive(Clone)]
enum Kind {
    App {
        spec: Box<ContainerSpec>,
        member: Option<Box<MemberSpec>>,
        netns: String,
        files: files::ContainerFiles,
        tini: String,
    },
    System(Box<SystemSpec>),
}

/// What a replica's containers share (podEnv).
#[derive(Clone)]
struct Pod {
    spec: ContainerSpec,
    netns: String,
    files: files::ContainerFiles,
    tini: String,
    images: BTreeMap<String, ImageRecord>,
}

/// The cleanups of a creation that failed, newest first.
#[derive(Default)]
struct Undo(Vec<UndoStep>);

enum UndoStep {
    Network(String, String, Option<cni::PortMapping>),
    Files(String),
    Container(Record),
    Task(Record),
}

/// A port mapping from a container's labels.
fn mapping(l: &BTreeMap<String, String>) -> Option<cni::PortMapping> {
    let hp = shim::atoi(label(l, LABEL_HOST_PORT))?;
    let cp = shim::atoi(label(l, LABEL_PORT))?;
    Some(cni::PortMapping {
        host_ip: label(l, LABEL_HOST_IP).to_string(),
        host_port: u16::try_from(hp).ok()?,
        container_port: u16::try_from(cp).ok()?,
    })
}

fn truncate(s: &str, n: usize) -> String {
    let b = s.as_bytes();
    String::from_utf8_lossy(&b[..b.len().min(n)]).into_owned()
}

/// sortMembers: init containers first, then by when they started.
fn sort_members(ms: &mut [Member]) {
    let rank = |m: &Member| if m.role == ROLE_INIT { 0 } else { 1 };
    for i in 1..ms.len() {
        let mut j = i;
        while j > 0 {
            let (a, b) = (&ms[j - 1], &ms[j]);
            if rank(a) < rank(b) || (rank(a) == rank(b) && b.started_at >= a.started_at) {
                break;
            }
            ms.swap(j - 1, j);
            j -= 1;
        }
    }
}

fn member_of(c: &Container) -> Member {
    Member {
        id: c.id.clone(),
        name: c.label(LABEL_CONTAINER).to_string(),
        role: c.label(LABEL_ROLE).to_string(),
        state: c.state.clone(),
        exit_code: c.exit_code,
        started_at: c.started_at,
    }
}

/// A shim's error from a kill, as taskProc.Kill words it.
enum KillError {
    NotFound,
    /// "is not running": nothing to signal (errdefs.ErrFailedPrecondition).
    Precondition(String),
    Other(String),
}

impl Supervisor {
    pub fn new(cfg: Config) -> Result<Supervisor, String> {
        let bin = cfg
            .bin_dir
            .clone()
            .unwrap_or_else(|| cfg.data_dir.join("runtime").join("current").join("bin"));
        let subnet = if cfg.subnet.is_empty() {
            cni::DEFAULT_SUBNET
        } else {
            &cfg.subnet
        };
        let subnet = cni::Prefix4::parse(subnet)
            .ok_or_else(|| format!("container subnet {subnet}: not an IPv4 prefix"))?;
        let net = cni::Network::new(
            subnet,
            cfg.mtu,
            &cfg.run_dir.join("cni"),
            bin.join("cni"),
            cfg.run_dir.join("netns"),
            cfg.host.clone(),
            cfg.log.clone(),
        )?;
        let logger = {
            let l = bin.join("armada-log");
            if fs::metadata(&l).is_ok_and(|m| m.is_file()) {
                l
            } else {
                std::env::current_exe().unwrap_or(l)
            }
        };
        let shims = Shims {
            dir: cfg.run_dir.join("shim"),
            bin: bin.join("armada-shim").display().to_string(),
            runc: bin.join("runc").display().to_string(),
            logger: logger.display().to_string(),
            systemd_run: cfg.systemd_run.clone(),
            systemctl: cfg.systemctl.clone(),
        };
        Ok(Supervisor {
            inner: Arc::new(Inner {
                bundles: cfg.data_dir.join("supervisor").join("containers"),
                images: cfg.data_dir.join("node").join("images"),
                bin,
                net,
                shims,
                ports: tokio::sync::Mutex::new(()),
                apparmor: Mutex::new(false),
                starts: Mutex::new(HashMap::new()),
                skipped: Mutex::new(BTreeMap::new()),
                cfg,
            }),
        })
    }

    /// The bridge network.
    pub fn bridge(&self) -> cni::Bridge {
        self.inner.net.bridge
    }
}

impl Inner {
    fn logs(&self) -> PathBuf {
        self.cfg.data_dir.join("logs")
    }

    fn containers(&self) -> PathBuf {
        self.cfg.data_dir.join("containers")
    }

    fn cgroup_root(&self) -> PathBuf {
        if self.cfg.cgroup_root.as_os_str().is_empty() {
            PathBuf::from("/sys/fs/cgroup")
        } else {
            self.cfg.cgroup_root.clone()
        }
    }

    fn proc_root(&self) -> PathBuf {
        if self.cfg.proc_root.as_os_str().is_empty() {
            PathBuf::from("/proc")
        } else {
            self.cfg.proc_root.clone()
        }
    }

    fn bundle_dir(&self, id: &str) -> PathBuf {
        self.bundles.join(id)
    }

    async fn blocking<T: Send + 'static>(
        &self,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, Error> {
        tokio::task::spawn_blocking(f)
            .await
            .map_err(|e| other(e.to_string()))
    }

    /// Bundles.Records through armada-node's code: a record that cannot
    /// be read is left out and logged once while it stays so.
    async fn records(&self) -> Result<Vec<Record>, Error> {
        let dir = self.bundles.display().to_string();
        let (recs, skipped) = self
            .blocking(move || bundle::records(&dir))
            .await?
            .map_err(other)?;
        let mut known = self.skipped.lock().unwrap_or_else(|p| p.into_inner());
        let mut now = BTreeMap::new();
        for s in skipped {
            if known.get(&s.id) != Some(&s.error) {
                self.cfg.log.warn(
                    "container record left out",
                    &[("container", s.id.clone()), ("err", s.error.clone())],
                );
            }
            now.insert(s.id, s.error);
        }
        *known = now;
        Ok(recs)
    }

    async fn load(&self, id: &str) -> Result<Record, Error> {
        self.records()
            .await?
            .into_iter()
            .find(|r| r.id == id)
            .ok_or(Error::NotFound)
    }

    fn store(&self) -> Result<Store, String> {
        Store::open(&self.images)
    }

    /// Driver.image: a pulled image's record.
    async fn image(&self, image: &str) -> Result<ImageRecord, String> {
        let r = reference::parse_docker_ref(image).map_err(|e| {
            format!(
                "invalid image reference {}: {e}",
                armada_pki::go_quote(image)
            )
        })?;
        let name = r.to_string();
        let images = self.images.clone();
        let idx = tokio::task::spawn_blocking(move || Store::open(&images)?.index())
            .await
            .map_err(|e| e.to_string())??;
        idx.images
            .get(&name)
            .cloned()
            .ok_or_else(|| format!("image {image}: image {name}: not found"))
    }

    fn tini(&self) -> Result<String, String> {
        let p = self.bin.join("tini");
        fs::canonicalize(&p)
            .map(|p| p.display().to_string())
            .map_err(|e| format!("tini: {}", os_err("lstat", &p, &e)))
    }

    /// The AppArmor profile, loaded once per process; None where the host
    /// has no AppArmor.
    fn apparmor(&self) -> Result<Option<&'static str>, String> {
        let host = &self.cfg.host;
        if !host.apparmor_supported() {
            return Ok(None);
        }
        let mut loaded = self.apparmor.lock().unwrap_or_else(|p| p.into_inner());
        if !*loaded {
            let text = armada_node::runtime::apparmor::armada_profile(
                APPARMOR_PROFILE,
                &armada_node::runtime::apparmor::Facts::read(),
            )?;
            host.load_apparmor(APPARMOR_PROFILE, &text)?;
            *loaded = true;
        }
        Ok(Some(APPARMOR_PROFILE))
    }

    /// The spec request of a container from image rec.
    fn spec_request(
        &self,
        id: &str,
        rec: &ImageRecord,
        kind: &Kind,
    ) -> Result<armada_node::runtime::SpecRequest, String> {
        let store = self.store()?;
        let blob = store.read_blob(&rec.config, 64 << 20)?;
        let image: armada_node::runtime::ImageConfig =
            serde_json::from_slice(&blob).map_err(|e| e.to_string())?;
        let mut r = armada_node::runtime::SpecRequest {
            image,
            image_media_type: rec.config.media_type.clone(),
            cgroup: format!("{CGROUP_PARENT}/{id}"),
            seccomp: true,
            namespace: "armada".into(),
            id: id.into(),
            ..Default::default()
        };
        match kind {
            Kind::App {
                spec,
                member,
                netns,
                files,
                tini,
            } => {
                r.spec = node_spec(spec);
                r.member = member.as_ref().map(|m| {
                    node_spec(&ContainerSpec {
                        init: vec![(**m).clone()],
                        ..Default::default()
                    })
                    .init
                    .remove(0)
                });
                r.netns = netns.clone();
                r.files = armada_node::runtime::Files {
                    resolv: files.resolv.clone(),
                    hosts: files.hosts.clone(),
                    hostname: files.hostname.clone(),
                };
                r.tini = tini.clone();
                r.apparmor = self.apparmor()?.unwrap_or_default().to_string();
            }
            Kind::System(s) => {
                r.system = Some(armada_node::runtime::SystemSpec {
                    name: s.name.clone(),
                    image: s.image.clone(),
                    cmd: Vec::new(),
                    mounts: s
                        .mounts
                        .iter()
                        .map(|m| armada_node::runtime::SystemMount {
                            source: m.source.clone(),
                            target: m.target.clone(),
                            read_only: m.read_only,
                        })
                        .collect(),
                    cap_add: s.cap_add.clone(),
                    user: s.user.clone(),
                });
            }
        }
        Ok(r)
    }

    /// Store.NewContainer on armada-node: the root filesystem, the spec
    /// built on it, and the bundle.
    async fn new_container(
        self: &Arc<Self>,
        id: &str,
        rec: &ImageRecord,
        labels: &BTreeMap<String, String>,
        kind: &Kind,
    ) -> Result<Record, String> {
        if self.bundle_dir(id).exists() {
            return Err(format!("container {id}: already exists"));
        }
        let me = self.clone();
        let (id, rec, labels, kind) = (id.to_string(), rec.clone(), labels.clone(), kind.clone());
        tokio::task::spawn_blocking(move || me.new_container_now(&id, &rec, &labels, &kind))
            .await
            .map_err(|e| e.to_string())?
    }

    fn new_container_now(
        &self,
        id: &str,
        rec: &ImageRecord,
        labels: &BTreeMap<String, String>,
        kind: &Kind,
    ) -> Result<Record, String> {
        let store = self.store()?;
        let mounts = snapshot::prepare(&store, id, &rec.name)
            .map_err(|e| format!("root filesystem: {e}"))?;
        let spec = self.spec_request(id, rec, kind).and_then(|mut req| {
            self.cfg.host.with_rootfs(&mounts, &mut |root| {
                req.rootfs = root.to_string();
                armada_node::runtime::build(&req)
            })
        });
        let spec = match spec {
            Ok(s) => s,
            Err(e) => {
                let _ = snapshot::release(&store, id);
                return Err(e);
            }
        };
        let raw = RawValue::from_string(String::from_utf8_lossy(&spec).into_owned())
            .map_err(|e| e.to_string())?;
        let req = bundle::CreateRequest {
            dir: self.bundles.display().to_string(),
            id: id.to_string(),
            image: rec.name.clone(),
            labels: labels.clone(),
            spec: raw,
            mounts,
        };
        let host = self.cfg.host.clone();
        match bundle::create_with(&req, &|m: &[Mount], t: &Path| host.mount_all(m, t)) {
            Ok(r) => Ok(r),
            Err(e) => {
                // The root filesystem goes only once its bundle is unmounted.
                if self.remove_bundle_now(id).is_ok() {
                    let _ = snapshot::release(&store, id);
                }
                Err(e)
            }
        }
    }

    fn remove_bundle_now(&self, id: &str) -> Result<(), String> {
        let host = self.cfg.host.clone();
        bundle::remove_with(&self.bundles.display().to_string(), id, &|t: &Path| {
            host.unmount_all(t)
        })
    }

    /// container.Delete: the bundle, then the root filesystem.
    async fn delete_container(self: &Arc<Self>, id: &str) -> Result<(), String> {
        let me = self.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || {
            me.remove_bundle_now(&id)?;
            let store = me.store()?;
            snapshot::release(&store, &id)
        })
        .await
        .map_err(|e| e.to_string())?
    }

    /// logMeta: whose container id is, so its output is kept in the log
    /// history. System containers keep none.
    fn log_meta(&self, id: &str, labels: &BTreeMap<String, String>) {
        let app = label(labels, LABEL_APP);
        if app.is_empty() {
            return;
        }
        let m = logs::LogMeta {
            app: app.into(),
            replica: label(labels, LABEL_REPLICA).into(),
            revision: label(labels, LABEL_REVISION).into(),
            container: label(labels, LABEL_CONTAINER).into(),
            created: now_text(),
        };
        if let Err(e) = logs::write_log_meta(&self.logs(), id, &m) {
            self.cfg.log.warn(
                "log history: record container",
                &[("id", id.to_string()), ("err", e)],
            );
        }
    }

    /// container.NewTask: the process created in the group's shim, not
    /// started.
    async fn new_task(&self, rec: &Record) -> Result<i64, String> {
        self.shims.start(&rec.group).await?;
        self.shims
            .create(
                &rec.group,
                &rec.id,
                &self.bundle_dir(&rec.id).display().to_string(),
                &self.logs().display().to_string(),
            )
            .await
            .map_err(|e| format!("create task: {e}"))
    }

    /// container.Task: the shim's state of the container; None when it has
    /// no task. A shim that is gone took its containers with it: they are
    /// ended, and the task is not found. A shim that runs but does not
    /// answer keeps them: the error is returned.
    async fn task(&self, rec: &Record) -> Result<Option<TaskState>, String> {
        let (g, id) = (&rec.group, &rec.id);
        let err = match self.shims.state(g, id).await {
            Ok(st) => return Ok(Some(st)),
            Err(e) if shim::not_found(&e) => return Ok(None),
            Err(CallError::Shim(t)) => return Err(t),
            Err(e) => e,
        };
        let (gone, aerr) = self.shims.abandon(g).await;
        let refused = matches!(err, CallError::Conn(_, Some(n)) if n == libc::ENOENT || n == libc::ECONNREFUSED);
        match aerr {
            Some(a) => Err(format!("shim of {id}: {}; {a}", err.text())),
            None if !gone && refused => match self.shims.state(g, id).await {
                Ok(st) => Ok(Some(st)),
                Err(e) if shim::not_found(&e) => Ok(None),
                Err(e) => Err(format!("shim of {id} does not answer: {}", e.text())),
            },
            None if !gone => Err(format!("shim of {id} does not answer: {}", err.text())),
            None => Ok(None),
        }
    }

    async fn kill(&self, rec: &Record, sig: i32, all: bool) -> Result<(), KillError> {
        let sig = sig.to_string();
        let mut words = vec!["kill", rec.id.as_str(), sig.as_str()];
        if all {
            words.push("all");
        }
        match self.shims.call(&rec.group, &words).await {
            Ok(_) => Ok(()),
            Err(e) if shim::not_found(&e) => Err(KillError::NotFound),
            Err(CallError::Shim(t)) => {
                Err(KillError::Precondition(format!("{t}: failed precondition")))
            }
            Err(e) => Err(KillError::Other(e.text().to_string())),
        }
    }

    /// containerd's WithProcessKill: SIGKILL to every process, then the
    /// exit awaited.
    async fn kill_and_wait(&self, rec: &Record) -> Result<(), String> {
        let wait = self.shims.wait(&rec.group, &rec.id);
        tokio::pin!(wait);
        // The wait is asked before the kill, as Go's.
        let first = tokio::time::timeout(Duration::from_millis(1), &mut wait).await;
        if first.is_ok() {
            return Ok(());
        }
        match self.kill(rec, libc::SIGKILL, true).await {
            Ok(()) | Err(KillError::NotFound) => {
                let _ = wait.await;
                Ok(())
            }
            Err(KillError::Precondition(_)) => Ok(()),
            Err(KillError::Other(e)) => Err(e),
        }
    }

    /// taskProc.Delete: the process removed from its shim (killed first
    /// with kill); NotFound when the shim has no such container.
    async fn delete_task(&self, rec: &Record, kill: bool, pid: i64) -> Result<(), Option<String>> {
        if kill && pid != 0 {
            self.kill_and_wait(rec).await.map_err(Some)?;
        }
        match self.shims.call(&rec.group, &["delete", &rec.id]).await {
            Ok(_) => Ok(()),
            Err(e) if shim::not_found(&e) => Err(None),
            Err(e) => Err(Some(e.text().to_string())),
        }
    }

    async fn undo(self: &Arc<Self>, undo: Undo) {
        for step in undo.0.into_iter().rev() {
            match step {
                UndoStep::Task(rec) => {
                    let pid = self.task(&rec).await.ok().flatten().map_or(0, |s| s.pid);
                    let _ = self.delete_task(&rec, true, pid).await;
                }
                UndoStep::Container(rec) => {
                    let _ = self.delete_container(&rec.id).await;
                }
                UndoStep::Files(id) => {
                    let _ = fs::remove_dir_all(self.containers().join(id));
                }
                UndoStep::Network(id, netns, pm) => {
                    let _ = self.net.teardown(&id, &netns, pm.as_ref()).await;
                }
            }
        }
    }

    /// Driver.create: the container made and its task started.
    async fn create(
        self: &Arc<Self>,
        id: &str,
        rec: &ImageRecord,
        labels: &BTreeMap<String, String>,
        kind: &Kind,
        undo: &mut Undo,
    ) -> Result<String, String> {
        let c = self
            .new_container(id, rec, labels, kind)
            .await
            .map_err(|e| format!("create container: {e}"))?;
        undo.0.push(UndoStep::Container(c.clone()));
        self.log_meta(id, labels);
        self.new_task(&c)
            .await
            .map_err(|e| format!("create task: {e}"))?;
        undo.0.push(UndoStep::Task(c.clone()));
        self.shims
            .call(&c.group, &["start", id])
            .await
            .map_err(|e| format!("start container: {}", e.text()))?;
        Ok(id.to_string())
    }

    /// The host ports containers hold.
    async fn used_ports(&self) -> Result<Vec<i64>, Error> {
        Ok(self
            .records()
            .await?
            .iter()
            .filter_map(|r| shim::atoi(label(&r.labels, LABEL_HOST_PORT)))
            .collect())
    }

    /// pickPort: a free port on host_ip, not used by another container nor
    /// bound by a host process, from a random start.
    fn pick_port(&self, host_ip: &str, used: &[i64]) -> Result<u16, String> {
        let n = u32::from(PORT_MAX - PORT_MIN) + 1;
        let start = u32::from_str_radix(&random_hex(4), 16).unwrap_or(0) % n;
        for i in 0..n {
            let p = PORT_MIN + ((start + i) % n) as u16;
            if !used.contains(&i64::from(p)) && self.cfg.host.port_free(host_ip, p) {
                return Ok(p);
            }
        }
        Err("no free host port".into())
    }

    async fn run(self: &Arc<Self>, s: &ContainerSpec) -> Result<String, String> {
        armada_node::runtime::check::check_container_spec(&node_spec(s))?;
        let id = new_id(&s.name)?;
        let img = self.image(&s.image).await?;
        let mut images = BTreeMap::new();
        for m in s.init.iter().chain(&s.sidecars) {
            if !images.contains_key(&m.image) {
                let r = self
                    .image(&m.image)
                    .await
                    .map_err(|e| format!("container {}: {e}", m.name))?;
                images.insert(m.image.clone(), r);
            }
        }
        let tini = self.tini()?;
        // Picking a host port and taking it must not interleave.
        let mut ports = if s.port != 0 {
            Some(self.ports.lock().await)
        } else {
            None
        };
        let mut undo = Undo::default();
        let res = self
            .run_locked(s, &id, &img, images, tini, &mut ports, &mut undo)
            .await;
        if res.is_err() {
            self.undo(undo).await;
        }
        res
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_locked(
        self: &Arc<Self>,
        s: &ContainerSpec,
        id: &str,
        img: &ImageRecord,
        images: BTreeMap<String, ImageRecord>,
        tini: String,
        ports: &mut Option<tokio::sync::MutexGuard<'_, ()>>,
        undo: &mut Undo,
    ) -> Result<String, String> {
        let mut labels = s.labels.clone();
        labels.insert(LABEL_KIND.into(), KIND_APP.into());
        labels.insert(LABEL_NAME.into(), s.name.clone());
        let mut pm = None;
        if s.port != 0 {
            let used = self.used_ports().await.map_err(|e| e.to_string())?;
            let hp = self.pick_port(&s.host_ip, &used)?;
            let p = cni::PortMapping {
                host_ip: s.host_ip.clone(),
                host_port: hp,
                container_port: u16::try_from(s.port).map_err(|e| e.to_string())?,
            };
            labels.insert(LABEL_HOST_IP.into(), s.host_ip.clone());
            labels.insert(LABEL_HOST_PORT.into(), hp.to_string());
            labels.insert(LABEL_PORT.into(), s.port.to_string());
            pm = Some(p);
        }
        self.net.ensure().await?;
        let (netns, ip) = self
            .net
            .setup(id, pm.as_ref())
            .await
            .map_err(|e| format!("container network: {e}"))?;
        undo.0
            .push(UndoStep::Network(id.into(), netns.clone(), pm.clone()));
        labels.insert(LABEL_NETNS.into(), netns.clone());
        labels.insert(LABEL_IP.into(), ip.clone());
        let host_resolv = {
            let h = self.cfg.host.clone();
            tokio::task::spawn_blocking(move || h.resolv_conf())
                .await
                .unwrap_or_default()
        };
        let files = files::write_files(
            &self.containers(),
            id,
            &s.name,
            &ip,
            &s.dns,
            &s.dns_search,
            &host_resolv,
        )?;
        undo.0.push(UndoStep::Files(id.into()));
        let kind = Kind::App {
            spec: Box::new(s.clone()),
            member: None,
            netns: netns.clone(),
            files: files.clone(),
            tini: tini.clone(),
        };
        if !s.init.is_empty() || !s.sidecars.is_empty() {
            let pod = Pod {
                spec: s.clone(),
                netns,
                files,
                tini,
                images,
            };
            return self.run_pod(id, img, labels, &kind, pod, undo, ports).await;
        }
        labels.insert(LABEL_STARTED.into(), now_text());
        self.create(id, img, &labels, &kind, undo).await
    }

    /// runPod: the replica's container and its task, unstarted; the rest
    /// is bring_up's, which outlives Run.
    #[allow(clippy::too_many_arguments)]
    async fn run_pod(
        self: &Arc<Self>,
        id: &str,
        img: &ImageRecord,
        mut labels: BTreeMap<String, String>,
        kind: &Kind,
        pod: Pod,
        undo: &mut Undo,
        ports: &mut Option<tokio::sync::MutexGuard<'_, ()>>,
    ) -> Result<String, String> {
        labels.insert(LABEL_STARTED.into(), now_text());
        let c = self
            .new_container(id, img, &labels, kind)
            .await
            .map_err(|e| format!("create container: {e}"))?;
        undo.0.push(UndoStep::Container(c.clone()));
        // The container records its port: other starts may pick now.
        ports.take();
        self.log_meta(id, &labels);
        self.new_task(&c)
            .await
            .map_err(|e| format!("create task: {e}"))?;
        undo.0.push(UndoStep::Task(c.clone()));
        let (cancel, cancelled) = watch::channel(false);
        let start = Arc::new(Start {
            cancel,
            done: tokio::sync::Mutex::new(None),
        });
        let mut done = start.done.lock().await;
        self.starts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id.to_string(), start.clone());
        let me = self.clone();
        let id_owned = id.to_string();
        *done = Some(tokio::spawn(async move {
            let (why, gave_up) = me.bring_up(&c, &pod, cancelled.clone()).await;
            let was_cancelled = *cancelled.borrow();
            if gave_up && !was_cancelled {
                // Never started: the task goes, so the container lists as
                // exited, and the reason stays on it unless a failed init
                // container tells it.
                let pid = me.task(&c).await.ok().flatten().map_or(0, |s| s.pid);
                let _ = me.delete_task(&c, true, pid).await;
                if !why.is_empty() {
                    let mut l = BTreeMap::new();
                    l.insert(LABEL_FAILED.to_string(), truncate(&why, MAX_FAILED));
                    let _ = me.set_labels(&id_owned, l).await;
                }
            }
            me.starts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&id_owned);
        }));
        Ok(id.to_string())
    }

    async fn set_labels(
        &self,
        id: &str,
        labels: BTreeMap<String, String>,
    ) -> Result<Record, Error> {
        let (dir, id) = (self.bundles.display().to_string(), id.to_string());
        self.blocking(move || bundle::set_labels(&dir, &id, &labels))
            .await?
            .map_err(other)
    }

    /// bringUp: the init containers in order, each to its end, then the
    /// sidecars, then the replica's task. Whether it gave up, and why
    /// unless a failed init container tells it; a cancel stops it without
    /// giving up (Stop or Remove take over).
    async fn bring_up(
        self: &Arc<Self>,
        c: &Record,
        pod: &Pod,
        mut cancelled: watch::Receiver<bool>,
    ) -> (String, bool) {
        for m in &pod.spec.init {
            let (mrec, exited) = match self.start_member(&c.id, m, ROLE_INIT, pod).await {
                Ok(x) => x,
                Err(e) => return (format!("init container {}: {e}", m.name), true),
            };
            tokio::select! {
                code = exited => {
                    if code.unwrap_or(Ok(-1)).unwrap_or(-1) != 0 {
                        return (String::new(), true);
                    }
                }
                _ = async { cancelled.wait_for(|c| *c).await.map(|_| ()) } => {
                    let _ = self.kill(&mrec, libc::SIGKILL, true).await;
                    return (String::new(), false);
                }
            }
        }
        for m in &pod.spec.sidecars {
            if let Err(e) = self.start_member(&c.id, m, ROLE_SIDECAR, pod).await {
                return (format!("sidecar {}: {e}", m.name), true);
            }
        }
        if *cancelled.borrow() {
            return (String::new(), false);
        }
        if let Err(e) = self.shims.call(&c.group, &["start", &c.id]).await {
            return (format!("start container: {}", e.text()), true);
        }
        let mut l = BTreeMap::new();
        l.insert(LABEL_STARTED.to_string(), now_text());
        let _ = self.set_labels(&c.id, l).await;
        (String::new(), false)
    }

    /// startMember: an init container or sidecar of pod, created and
    /// started in its network namespace; its record and its exit.
    async fn start_member(
        self: &Arc<Self>,
        pod_id: &str,
        m: &MemberSpec,
        role: &str,
        pod: &Pod,
    ) -> Result<(Record, tokio::sync::oneshot::Receiver<Result<i64, String>>), String> {
        let mid = new_id(&format!("armada-{}", m.name))?;
        let img = pod
            .images
            .get(&m.image)
            .ok_or_else(|| format!("image {} was not resolved", m.image))?;
        let mut labels = pod.spec.labels.clone();
        labels.insert(LABEL_ROLE.into(), role.into());
        labels.insert(LABEL_CONTAINER.into(), m.name.clone());
        labels.insert(LABEL_KIND.into(), KIND_MEMBER.into());
        labels.insert(LABEL_NAME.into(), m.name.clone());
        labels.insert(LABEL_POD.into(), pod_id.into());
        labels.insert(LABEL_STARTED.into(), now_text());
        let kind = Kind::App {
            spec: Box::new(pod.spec.clone()),
            member: Some(Box::new(m.clone())),
            netns: pod.netns.clone(),
            files: pod.files.clone(),
            tini: pod.tini.clone(),
        };
        let mut undo = Undo::default();
        let res = async {
            let c = self
                .new_container(&mid, img, &labels, &kind)
                .await
                .map_err(|e| format!("create container: {e}"))?;
            undo.0.push(UndoStep::Container(c.clone()));
            self.log_meta(&mid, &labels);
            self.new_task(&c)
                .await
                .map_err(|e| format!("create task: {e}"))?;
            undo.0.push(UndoStep::Task(c.clone()));
            let (tx, rx) = tokio::sync::oneshot::channel();
            let me = self.clone();
            let w = c.clone();
            let waiting = tokio::spawn(async move {
                let code = me.shims.wait(&w.group, &w.id).await;
                let _ = tx.send(code);
            });
            if let Err(e) = self.shims.call(&c.group, &["start", &mid]).await {
                waiting.abort();
                return Err(format!("start: {}", e.text()));
            }
            Ok((c, rx))
        }
        .await;
        if res.is_err() {
            self.undo(undo).await;
        }
        res
    }

    fn starting(&self, id: &str) -> bool {
        self.starts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(id)
    }

    /// endStart: stops bringing up id, if that still goes on, and waits
    /// for it to have stopped.
    async fn end_start(&self, id: &str) {
        let s = self
            .starts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(id)
            .cloned();
        if let Some(s) = s {
            let _ = s.cancel.send(true);
            if let Some(h) = s.done.lock().await.take() {
                let _ = h.await;
            }
        }
    }

    /// describeTask: a record as a container, with its task's state when
    /// known already; and its pod when it is a member.
    async fn describe(
        &self,
        rec: &Record,
        known: Option<Option<TaskState>>,
    ) -> Result<(Container, String), Error> {
        let l = &rec.labels;
        let pod = if label(l, LABEL_KIND) == KIND_MEMBER {
            label(l, LABEL_POD).to_string()
        } else {
            String::new()
        };
        let mut c = Container {
            id: rec.id.clone(),
            name: label(l, LABEL_NAME).to_string(),
            image: rec.image.clone(),
            labels: l
                .iter()
                .filter(|(k, _)| !k.starts_with(LABEL_PREFIX))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            start_error: label(l, LABEL_FAILED).to_string(),
            ip: label(l, LABEL_IP).to_string(),
            started_at: parse_time(label(l, LABEL_STARTED)),
            ..Default::default()
        };
        if c.name.is_empty() {
            c.name = rec.id.clone();
        }
        if let Some(p) = shim::atoi(label(l, LABEL_HOST_PORT))
            && private_ip(label(l, LABEL_HOST_IP))
        {
            c.host_ip = label(l, LABEL_HOST_IP).to_string();
            c.host_port = p;
        }
        let st = match known {
            Some(Some(st)) => Some(st),
            // Not in its shim's list: asked by itself, as only that can say
            // it is gone.
            _ => match self.task(rec).await {
                Ok(st) => st,
                Err(e) => return Err(other(e)),
            },
        };
        match st {
            None => {
                // No task: the node rebooted or the shim went; the agent
                // recreates the container.
                c.state = STATE_EXITED.into();
                c.exit_code = 255;
            }
            Some(st) => match st.status {
                "running" => c.state = STATE_RUNNING.into(),
                "created" => c.state = STATE_CREATED.into(),
                "exited" => {
                    c.state = STATE_EXITED.into();
                    c.exit_code = st.exit;
                }
                _ => c.state = STATE_DEAD.into(),
            },
        }
        if pod.is_empty() && self.starting(&c.id) {
            c.state = STATE_STARTING.into();
        }
        Ok((c, pod))
    }

    /// The states of every container, asking each group's shim once;
    /// containers of a shim that does not answer are left out.
    async fn tasks(&self, recs: &[Record]) -> BTreeMap<String, TaskState> {
        let mut groups: Vec<&str> = recs.iter().map(|r| r.group.as_str()).collect();
        groups.sort_unstable();
        groups.dedup();
        let mut out = BTreeMap::new();
        for g in groups {
            if let Ok(states) = self.shims.list(g).await {
                out.extend(states);
            }
        }
        out
    }

    async fn list(&self, want: &BTreeMap<String, String>) -> Result<Vec<Container>, Error> {
        let recs = self.records().await?;
        let known = self.tasks(&recs).await;
        let ids: std::collections::HashSet<&str> = recs.iter().map(|r| r.id.as_str()).collect();
        let mut out = Vec::new();
        let mut members: HashMap<String, Vec<Container>> = HashMap::new();
        for rec in &recs {
            let (c, pod) = match self.describe(rec, Some(known.get(&rec.id).copied())).await {
                Ok(x) => x,
                Err(Error::NotFound) => continue,
                Err(e) => return Err(e),
            };
            if !pod.is_empty() && ids.contains(pod.as_str()) {
                members.entry(pod).or_default().push(c);
                continue;
            }
            if want.iter().all(|(k, v)| c.label(k) == v) {
                out.push(c);
            }
        }
        for c in &mut out {
            if let Some(ms) = members.get(&c.id) {
                c.members = ms.iter().map(member_of).collect();
            }
            sort_members(&mut c.members);
        }
        Ok(out)
    }

    async fn inspect(&self, id: &str) -> Result<Container, Error> {
        let rec = self.load(id).await?;
        let (mut c, pod) = self.describe(&rec, None).await?;
        if pod.is_empty() {
            for m in self.members_of(id).await? {
                match self.describe(&m, None).await {
                    Ok((mc, _)) => c.members.push(member_of(&mc)),
                    Err(Error::NotFound) => {}
                    Err(e) => return Err(e),
                }
            }
            sort_members(&mut c.members);
        }
        Ok(c)
    }

    async fn members_of(&self, pod: &str) -> Result<Vec<Record>, Error> {
        Ok(self
            .records()
            .await?
            .into_iter()
            .filter(|r| label(&r.labels, LABEL_POD) == pod)
            .collect())
    }

    /// stopContainer: SIGTERM, SIGKILL after grace; a task created but
    /// never started is deleted.
    async fn stop_container(&self, rec: &Record, grace: Duration) -> Result<(), String> {
        let Some(st) = self.task(rec).await? else {
            return Ok(());
        };
        match st.status {
            "exited" => return Ok(()),
            "created" => {
                return match self.delete_task(rec, true, st.pid).await {
                    Ok(()) | Err(None) => Ok(()),
                    Err(Some(e)) => Err(e),
                };
            }
            _ => {}
        }
        let wait = self.shims.wait(&rec.group, &rec.id);
        tokio::pin!(wait);
        match self.kill(rec, libc::SIGTERM, false).await {
            Ok(()) | Err(KillError::NotFound) => {}
            Err(KillError::Precondition(e) | KillError::Other(e)) => return Err(e),
        }
        if tokio::time::timeout(grace, &mut wait).await.is_ok() {
            return Ok(());
        }
        match self.kill(rec, libc::SIGKILL, true).await {
            Ok(()) | Err(KillError::NotFound) => {}
            Err(KillError::Precondition(e) | KillError::Other(e)) => return Err(e),
        }
        let _ = wait.await;
        Ok(())
    }

    async fn stop(&self, id: &str, grace: Duration) -> Result<(), Error> {
        let rec = self.load(id).await?;
        self.end_start(id).await;
        self.stop_container(&rec, grace).await.map_err(other)?;
        if label(&rec.labels, LABEL_KIND) != KIND_APP {
            return Ok(());
        }
        // A replica's sidecars stop after it, at once, each with grace.
        let ms = self.members_of(id).await?;
        let mut errs = Vec::new();
        let stops = ms
            .iter()
            .filter(|m| label(&m.labels, LABEL_ROLE) == ROLE_SIDECAR)
            .map(|m| self.stop_container(m, grace));
        for r in futures_join(stops).await {
            if let Err(e) = r {
                errs.push(e);
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(other(errs.join("\n")))
        }
    }

    /// removeContainer: its task, network, bundle, root filesystem, files,
    /// and logs.
    async fn remove_container(self: &Arc<Self>, rec: &Record) -> Result<(), Error> {
        let id = &rec.id;
        if let Some(st) = self.task(rec).await.map_err(other)? {
            let kill = st.status != "exited";
            let mut res = self.delete_task(rec, kill, st.pid).await;
            if kill
                && matches!(res, Err(Some(_)))
                && let Ok(Some(now)) = self.task(rec).await
                && now.status == "exited"
            {
                res = self.delete_task(rec, false, 0).await;
            }
            if let Err(Some(e)) = res {
                return Err(other(format!("delete task: {e}")));
            }
        }
        if label(&rec.labels, LABEL_KIND) == KIND_APP {
            self.net
                .teardown(
                    id,
                    label(&rec.labels, LABEL_NETNS),
                    mapping(&rec.labels).as_ref(),
                )
                .await
                .map_err(|e| other(format!("container network: {e}")))?;
        }
        self.delete_container(id).await.map_err(other)?;
        let mut errs = Vec::new();
        match fs::remove_dir_all(self.containers().join(id)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                errs.push(os_err("unlinkat", &self.containers().join(id), &e));
            }
            _ => {}
        }
        if let Err(e) = logs::remove_logs(&self.logs(), id) {
            errs.push(e);
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(other(errs.join("\n")))
        }
    }

    async fn remove(self: &Arc<Self>, id: &str) -> Result<(), Error> {
        let rec = self.load(id).await?;
        self.end_start(id).await;
        if label(&rec.labels, LABEL_KIND) == KIND_APP {
            let mut errs = Vec::new();
            for m in self.members_of(id).await? {
                match self.remove_container(&m).await {
                    Ok(()) | Err(Error::NotFound) => {}
                    Err(e) => errs.push(e.to_string()),
                }
            }
            if !errs.is_empty() {
                return Err(other(format!(
                    "init containers and sidecars: {}",
                    errs.join("\n")
                )));
            }
        }
        self.remove_container(&rec).await
    }

    async fn release_network(&self, id: &str) -> Result<(), Error> {
        let rec = self.load(id).await?;
        if label(&rec.labels, LABEL_KIND) != KIND_APP {
            return Ok(());
        }
        let ns = label(&rec.labels, LABEL_NETNS);
        if fs::metadata(ns).is_err() {
            // Already released, or gone with a reboot.
            return Ok(());
        }
        self.net
            .teardown(id, ns, mapping(&rec.labels).as_ref())
            .await
            .map_err(other)
    }

    /// StatsBatch: armada-node's sampling of every container in process;
    /// a container it leaves ("redo") is looked up through its task, which
    /// ends the containers of a shim that is gone.
    async fn stats_batch(&self, ids: &[String]) -> Vec<Result<Stats, Error>> {
        let r = nstats::StatsRequest {
            dir: self.bundles.display().to_string(),
            shim_dir: self.shims.dir.display().to_string(),
            cgroup_root: self.cgroup_root().display().to_string(),
            proc: self.proc_root().display().to_string(),
            ids: ids.to_vec(),
            timeout_ms: 0,
        };
        let samples = match self.blocking(move || nstats::stats(&r)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) | Err(Error::Other(e)) => {
                return ids.iter().map(|_| Err(other(e.clone()))).collect();
            }
            Err(e) => return ids.iter().map(|_| Err(e.clone())).collect(),
        };
        let mut out = Vec::with_capacity(ids.len());
        for (id, s) in ids.iter().zip(samples) {
            out.push(match s {
                nstats::Sample::Stats(st) => Ok(Stats {
                    cpu: Duration::from_nanos(st.cpu.max(0) as u64),
                    memory_bytes: st.memory,
                    egress_bytes: st.egress,
                    network_lost: st.network_lost,
                    oom_kills: st.oom_kills,
                }),
                nstats::Sample::NotFound => Err(Error::NotFound),
                nstats::Sample::Redo(why) => match self.load(id).await {
                    Err(e) => Err(e),
                    Ok(rec) => match self.task(&rec).await {
                        Ok(None) => Err(Error::NotFound),
                        Ok(Some(_)) => Err(other(why)),
                        Err(e) => Err(other(e)),
                    },
                },
            });
        }
        out
    }

    async fn pull(&self, image: &str, auth: Option<&RegistryAuth>) -> Result<Image, Error> {
        let req = npull::PullRequest {
            image: image.to_string(),
            auth: auth.map(|a| reference::RegistryAuth {
                username: a.username.clone(),
                password: a.password.clone(),
                server_address: a.server_address.clone(),
            }),
        };
        let images = self.images.clone();
        let res = self
            .blocking(move || -> Result<npull::Pulled, npull::PullError> {
                let store = Store::open(&images).map_err(npull::PullError::Other)?;
                let client =
                    armada_node::http::Client::new(None, armada_node::http::Proxy::from_env())
                        .map_err(npull::PullError::Other)?;
                npull::pull(&store, &client, &req)
            })
            .await?;
        match res {
            Ok(p) => Ok(Image {
                reference: p.reference,
                platforms: p.platforms,
            }),
            Err(npull::PullError::Platform(p)) => Err(Error::Platform {
                image: p.image,
                want: p.want,
                have: p.have,
            }),
            Err(npull::PullError::Other(e)) => Err(other(e)),
        }
    }

    async fn prune(&self, keep: &[String], grace: Duration) -> Result<Vec<String>, Error> {
        let in_use: Vec<String> = self.records().await?.into_iter().map(|r| r.image).collect();
        let req = npull::PruneRequest {
            keep: keep.to_vec(),
            in_use,
            grace_seconds: grace.as_secs(),
        };
        let images = self.images.clone();
        self.blocking(move || Store::open(&images).and_then(|s| npull::prune(&s, &req)))
            .await?
            .map_err(other)
    }

    /// A command in a running container through armada-node runtime exec.
    async fn exec(
        &self,
        rec: &Record,
        cmd: &[String],
        output: bool,
        drain: Duration,
    ) -> Result<(i64, Vec<u8>), Error> {
        if self.task(rec).await.map_err(other)?.is_none() {
            return Err(Error::NotFound);
        }
        let dir = self
            .shims
            .dir
            .join(armada_node::runtime::container::shim::shim_name(&rec.group))
            .join(format!("exec-{}-exec-{}", rec.id, random_hex(6)));
        let node = self.bin.join("armada-node");
        let (bundle, dir, root, runc, id, args) = (
            self.bundle_dir(&rec.id).display().to_string(),
            dir.display().to_string(),
            self.shims.root(&rec.group).display().to_string(),
            self.shims.runc.clone(),
            rec.id.clone(),
            cmd.to_vec(),
        );
        self.blocking(move || {
            exec::run(
                &node,
                &exec::ExecRequest {
                    bundle: &bundle,
                    dir: &dir,
                    root: &root,
                    runc: &runc,
                    id: &id,
                    args: &args,
                    output,
                    drain_grace: drain,
                },
            )
        })
        .await?
        .map_err(other)
    }

    async fn run_system(self: &Arc<Self>, s: &SystemSpec) -> Result<String, String> {
        for m in &s.mounts {
            if !m.source.starts_with('/')
                || !m.target.starts_with('/')
                || format!("{}{}", m.source, m.target).contains([':', ',', '\n'])
            {
                return Err(format!("invalid mount {} -> {}", m.source, m.target));
            }
        }
        let id = new_id(&s.name)?;
        let img = self.image(&s.image).await?;
        let mut labels = s.labels.clone();
        labels.insert(LABEL_KIND.into(), KIND_SYSTEM.into());
        labels.insert(LABEL_NAME.into(), s.name.clone());
        let mut undo = Undo::default();
        let res = self
            .create(
                &id,
                &img,
                &labels,
                &Kind::System(Box::new(s.clone())),
                &mut undo,
            )
            .await;
        if res.is_err() {
            self.undo(undo).await;
        }
        res
    }
}

/// Runs futures at once and returns their results in order.
async fn futures_join<F: std::future::Future>(fs: impl Iterator<Item = F>) -> Vec<F::Output> {
    let mut pinned: Vec<std::pin::Pin<Box<F>>> = fs.map(Box::pin).collect();
    let mut out: Vec<Option<F::Output>> = pinned.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (f, o) in pinned.iter_mut().zip(out.iter_mut()) {
            if o.is_none() {
                match f.as_mut().poll(cx) {
                    std::task::Poll::Ready(v) => *o = Some(v),
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    out.into_iter()
        .map(|o| o.expect("every future ended"))
        .collect()
}

impl Runtime for Supervisor {
    async fn ping(&self) -> runtime::Result<()> {
        let i = &self.inner;
        for (what, p) in [
            ("armada-shim", PathBuf::from(&i.shims.bin)),
            ("armada-node", i.bin.join("armada-node")),
        ] {
            if let Err(e) = fs::metadata(&p) {
                return Err(other(format!(
                    "container runtime: {what}: {}",
                    os_err("stat", &p, &e)
                )));
            }
        }
        if i.cfg.host.selinux_enabled() {
            return Err(other(
                "container runtime: SELinux is on, and this agent does not label containers yet: run the Go agent on this machine",
            ));
        }
        i.net.ensure().await.map_err(other)
    }

    async fn agent_start(&self) -> runtime::Result<()> {
        let i = self.inner.clone();
        i.blocking({
            let i = i.clone();
            move || i.apparmor().map(|_| ())
        })
        .await?
        .map_err(|e| other(format!("apparmor profile not loaded yet: {e}")))
    }

    async fn pull(&self, image: &str, auth: Option<&RegistryAuth>) -> runtime::Result<Image> {
        self.inner.pull(image, auth).await
    }

    async fn run(&self, spec: &ContainerSpec) -> runtime::Result<String> {
        self.inner.run(spec).await.map_err(other)
    }

    async fn stop(&self, id: &str, grace: Duration) -> runtime::Result<()> {
        self.inner.stop(id, grace).await
    }

    async fn remove(&self, id: &str) -> runtime::Result<()> {
        self.inner.remove(id).await
    }

    async fn list(&self, labels: &BTreeMap<String, String>) -> runtime::Result<Vec<Container>> {
        self.inner.list(labels).await
    }

    async fn inspect(&self, id: &str) -> runtime::Result<Container> {
        self.inner.inspect(id).await
    }

    fn can_run_members(&self) -> bool {
        true
    }

    fn can_mount_volumes(&self) -> bool {
        true
    }

    fn can_exec(&self) -> bool {
        true
    }

    async fn exec_app(&self, id: &str, cmd: &[String]) -> runtime::Result<i64> {
        check_exec_command(cmd).map_err(other)?;
        let rec = self.inner.load(id).await?;
        if !label(&rec.labels, LABEL_SYSTEM).is_empty() {
            return Err(other(format!("container {id} is a system container")));
        }
        let (code, _) = self.inner.exec(&rec, cmd, false, exec::DRAIN_GRACE).await?;
        Ok(code)
    }

    fn can_stats(&self) -> bool {
        true
    }

    async fn stats(&self, id: &str) -> runtime::Result<Stats> {
        self.inner
            .stats_batch(&[id.to_string()])
            .await
            .pop()
            .unwrap_or(Err(Error::NotFound))
    }

    async fn stats_batch(&self, ids: &[String]) -> Option<Vec<runtime::Result<Stats>>> {
        if ids.is_empty() {
            return Some(Vec::new());
        }
        Some(self.inner.stats_batch(ids).await)
    }

    async fn release_network(&self, id: &str) -> Option<runtime::Result<()>> {
        Some(self.inner.release_network(id).await)
    }

    async fn prune_images(
        &self,
        keep: &[String],
        grace: Duration,
    ) -> Option<runtime::Result<Vec<String>>> {
        Some(self.inner.prune(keep, grace).await)
    }

    async fn runtime_agent(&self) -> Option<AgentStatus> {
        let d = &self.inner.cfg.data_dir;
        Some(AgentStatus {
            agent: runtime::AGENT_SUPERVISOR_RUST.into(),
            go_images: d.join("supervisor").join("images").exists(),
            converted: d.join("node").join("converted.json").exists(),
            images_to_pull: 0,
            error: String::new(),
        })
    }
}

/// runtime.CheckExecCommand: errors never repeat the arguments.
pub fn check_exec_command(cmd: &[String]) -> Result<(), String> {
    if cmd.is_empty() || cmd[0].is_empty() {
        return Err("command is empty".into());
    }
    if cmd.len() > 64 {
        return Err("command has more than 64 arguments".into());
    }
    for (i, a) in cmd.iter().enumerate() {
        if a.len() > 4096 {
            return Err(format!("argument {i} is longer than 4096 bytes"));
        }
        if a.contains('\0') {
            return Err(format!("argument {i} contains a NUL byte"));
        }
    }
    Ok(())
}

/// The signals a system container is sent.
fn signal_number(name: &str) -> Option<i32> {
    Some(match name {
        "SIGHUP" => libc::SIGHUP,
        "SIGINT" => libc::SIGINT,
        "SIGQUIT" => libc::SIGQUIT,
        "SIGKILL" => libc::SIGKILL,
        "SIGTERM" => libc::SIGTERM,
        "SIGUSR1" => libc::SIGUSR1,
        "SIGUSR2" => libc::SIGUSR2,
        _ => return None,
    })
}

impl SystemRunner for Supervisor {
    async fn run_system(&self, spec: &SystemSpec) -> runtime::Result<String> {
        self.inner.run_system(spec).await.map_err(other)
    }

    async fn exec_system(&self, id: &str, cmd: &[String]) -> runtime::Result<(String, i64)> {
        let rec = self.inner.load(id).await?;
        let (code, out) = self.inner.exec(&rec, cmd, true, Duration::ZERO).await?;
        Ok((String::from_utf8_lossy(&out).into_owned(), code))
    }

    async fn signal(&self, id: &str, signal: &str) -> runtime::Result<()> {
        let sig = signal_number(signal).ok_or_else(|| {
            other(format!(
                "unsupported signal {}",
                armada_pki::go_quote(signal)
            ))
        })?;
        let rec = self.inner.load(id).await?;
        if self.inner.task(&rec).await.map_err(other)?.is_none() {
            return Err(Error::NotFound);
        }
        match self.inner.kill(&rec, sig, false).await {
            Ok(()) => Ok(()),
            Err(KillError::NotFound) => Err(Error::NotFound),
            Err(KillError::Precondition(e) | KillError::Other(e)) => Err(other(e)),
        }
    }

    async fn log_tail(&self, id: &str, lines: usize) -> runtime::Result<String> {
        let dir = self.inner.logs();
        let id = id.to_string();
        match self
            .inner
            .blocking(move || logs::tail(&dir, &id, lines))
            .await?
        {
            Ok(Some(t)) => Ok(t),
            Ok(None) => Err(Error::NotFound),
            Err(e) => Err(other(e)),
        }
    }
}

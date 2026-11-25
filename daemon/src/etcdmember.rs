//! This server's etcd member as `armadad etcd` works it out (Go's
//! etcdConfig and memberConfig in internal/daemon/state.go, and prepare,
//! ensureCert, fileConfig, and WriteConfigFile in internal/etcd): its name,
//! data, addresses, certificate, and the configuration file the pack's
//! etcd runs with (ADR 0055).

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use armada_pki::{Ca, ExtKeyUsage, IssueRequest, parse_cert_pem};
use armada_spec::yaml::encode::Encoder;

use crate::agentconfig::{
    DIR_ETCD, FILE_CA_CERT, FILE_CA_KEY, FILE_ETCD_INITIAL, FILE_SERVER_CERT,
};
use crate::netutil;

/// FileConfig.
pub const FILE_CONFIG: &str = "etcd.yaml";
pub const DEFAULT_CLIENT_PORT: u16 = 2379;
pub const DEFAULT_PEER_PORT: u16 = 2380;

pub const DIR_DATA: &str = "data";
const FILE_CERT: &str = "member.crt";
const FILE_KEY: &str = "member.key";
const FILE_CA: &str = "ca.crt";
pub const CLUSTER_TOKEN: &str = "armada";
const CERT_RENEW: Duration = Duration::from_secs(30 * 24 * 3600);
const MAX_TXN_OPS: u64 = 4096;

/// etcd.Config, the parts the file needs.
pub struct Config {
    pub dir: PathBuf,
    pub name: String,
    /// None when the server certificate names no address.
    pub addr: Option<IpAddr>,
    pub client_port: u16,
    pub peer_port: u16,
    pub ca: Option<Ca>,
    pub initial_cluster: String,
}

/// memberConfig: where data_dir's member lives and listens.
pub fn member_config(data_dir: &str) -> Config {
    let dd = Path::new(data_dir);
    let mut cfg = Config {
        dir: dd.join(DIR_ETCD),
        name: String::new(),
        addr: None,
        client_port: DEFAULT_CLIENT_PORT,
        peer_port: DEFAULT_PEER_PORT,
        ca: None,
        initial_cluster: String::new(),
    };
    // The parity tests' etcdAddrOverride and etcdPorts: a member on
    // loopback ports of their own (test hooks only).
    let addr_override: Option<IpAddr> = crate::hooks::get("ETCD_ADDR").and_then(|a| a.parse().ok());
    if let Some((c, p)) = crate::hooks::get("ETCD_PORTS").and_then(|v| {
        let (c, p) = v.split_once(',')?;
        Some((c.parse().ok()?, p.parse().ok()?))
    }) {
        cfg.client_port = c;
        cfg.peer_port = p;
    }
    cfg.addr = addr_override;
    if cfg.addr.is_none()
        && let Ok(b) = armada_fsutil::read_private_file(&dd.join(FILE_SERVER_CERT))
        && let Ok(c) = parse_cert_pem(&b)
    {
        cfg.addr = c.ip_addresses.first().map(netutil::unmap);
    }
    if let Ok(b) = armada_fsutil::read_private_file(&dd.join(FILE_ETCD_INITIAL)) {
        cfg.initial_cluster = String::from_utf8_lossy(&b).trim().to_string();
    }
    cfg
}

/// etcdConfig: the member described from the data directory, named by the
/// server certificate's identity.
pub fn etcd_config(data_dir: &str) -> Result<Config, String> {
    let dd = Path::new(data_dir);
    let mut pem = Vec::new();
    for n in [FILE_CA_CERT, FILE_CA_KEY, FILE_SERVER_CERT] {
        pem.push(armada_fsutil::read_private_file(&dd.join(n)).map_err(|e| e.to_string())?);
    }
    let ca = Ca::load(&pem[0], &pem[1]).map_err(|e| e.to_string())?;
    let cert = parse_cert_pem(&pem[2]).map_err(|e| e.to_string())?;
    let id = cert.identity();
    match id {
        Ok(id) if id.kind == armada_pki::KIND_SERVER => {
            let mut cfg = member_config(data_dir);
            cfg.name = id.name;
            cfg.ca = Some(ca);
            Ok(cfg)
        }
        _ => Err(format!("{FILE_SERVER_CERT} is not a server certificate")),
    }
}

/// What etcd is told about the member.
struct MemberSpec {
    name: String,
    data_dir: String,
    client_url: String,
    peer_url: String,
    initial_cluster: String,
    cluster_state: &'static str,
    cert_file: String,
    key_file: String,
    ca_file: String,
    allowed_cn: String,
}

pub fn member_url(addr: &IpAddr, port: u16) -> String {
    match addr {
        IpAddr::V4(v) => format!("https://{v}:{port}"),
        IpAddr::V6(v) => format!("https://[{v}]:{port}"),
    }
}

/// netip.Addr.Compare: IPv4 first, then by bytes.
fn addr_key(a: &IpAddr) -> (u8, [u8; 16]) {
    match a {
        IpAddr::V4(v) => {
            let mut b = [0u8; 16];
            b[..4].copy_from_slice(&v.octets());
            (0, b)
        }
        IpAddr::V6(v) => (1, v.octets()),
    }
}

/// certAddrs: the listen address and every other private address of the
/// machine, sorted, once each.
fn cert_addrs(addr: &IpAddr) -> Vec<IpAddr> {
    let mut v = vec![*addr];
    v.extend(netutil::private_host_addrs());
    v.sort_by_key(addr_key);
    v.dedup();
    v
}

fn write_ca(cfg: &Config, ca: &Ca) -> Result<(), String> {
    armada_fsutil::write_file_atomic(&cfg.dir.join(FILE_CA), &ca.cert_pem, 0o600)
        .map_err(|e| e.to_string())
}

/// certFits.
fn cert_fits(c: &armada_pki::Certificate, ca: &Ca, addr: &IpAddr) -> bool {
    let now = SystemTime::now();
    let left = c.not_after - unix(now);
    if c.common_name != armada_pki::etcd_member().to_string() || left < CERT_RENEW.as_secs() as i64
    {
        return false;
    }
    if c.verify(&ca.cert, None, ExtKeyUsage::Any, now).is_err() {
        return false;
    }
    let have: Vec<IpAddr> = c.ip_addresses.iter().map(netutil::unmap).collect();
    cert_addrs(addr).iter().all(|a| have.contains(a))
}

fn unix(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// ensureCert: the member certificate issued when missing, for another
/// identity or addresses, or within a month of its end.
fn ensure_cert(cfg: &Config, ca: &Ca, addr: &IpAddr) -> Result<(), String> {
    let cert_path = cfg.dir.join(FILE_CERT);
    match armada_fsutil::read_private_file(&cert_path) {
        Ok(b) => {
            if let Ok(c) = parse_cert_pem(&b)
                && cert_fits(&c, ca, addr)
            {
                return write_ca(cfg, ca);
            }
        }
        Err(e) if e.kind() == armada_fsutil::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    let (cert_pem, key_pem) = ca
        .issue(&IssueRequest {
            identity: armada_pki::etcd_member(),
            ips: cert_addrs(addr),
            server: true,
            client: true,
            ..Default::default()
        })
        .map_err(|e| format!("etcd member certificate: {e}"))?;
    armada_fsutil::write_file_atomic(&cfg.dir.join(FILE_KEY), key_pem.expose(), 0o600)
        .map_err(|e| e.to_string())?;
    armada_fsutil::write_file_atomic(&cert_path, &cert_pem, 0o600).map_err(|e| e.to_string())?;
    write_ca(cfg, ca)
}

/// wal.Exist: a directory holding a file named *.wal.
fn wal_exists(dir: &Path) -> bool {
    fs::read_dir(dir).is_ok_and(|rd| {
        rd.flatten()
            .any(|e| e.file_name().to_string_lossy().ends_with(".wal"))
    })
}

/// prepare: cfg checked, the member's directory and certificate made, a
/// data directory that never started removed.
fn prepare(cfg: &mut Config) -> Result<MemberSpec, String> {
    let Some(ca) = cfg.ca.as_ref().filter(|_| !cfg.name.is_empty()) else {
        return Err("etcd: Name and CA are required".to_string());
    };
    let addr = match cfg.addr {
        Some(a) if netutil::is_private(&a) => a,
        Some(a) => return Err(format!("etcd: listen address {a} must be private")),
        None => return Err("etcd: listen address invalid IP must be private".to_string()),
    };
    let abs = std::path::absolute(&cfg.dir).map_err(|e| e.to_string())?;
    cfg.dir = PathBuf::from(crate::gopath::clean(&abs.to_string_lossy()));
    armada_fsutil::mkdir_private(&cfg.dir).map_err(|e| e.to_string())?;
    ensure_cert(cfg, ca, &addr)?;
    let data = cfg.dir.join(DIR_DATA);
    let fresh = !wal_exists(&data.join("member").join("wal"));
    if fresh
        && let Err(e) = fs::remove_dir_all(&data)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(format!(
            "unlinkat {}: {}",
            data.display(),
            armada_fsutil::errno_text(&e)
        ));
    }
    let peer_url = member_url(&addr, cfg.peer_port);
    let mut s = MemberSpec {
        name: cfg.name.clone(),
        data_dir: data.to_string_lossy().into_owned(),
        client_url: member_url(&addr, cfg.client_port),
        peer_url: peer_url.clone(),
        initial_cluster: format!("{}={peer_url}", cfg.name),
        cluster_state: "new",
        cert_file: cfg.dir.join(FILE_CERT).to_string_lossy().into_owned(),
        key_file: cfg.dir.join(FILE_KEY).to_string_lossy().into_owned(),
        ca_file: cfg.dir.join(FILE_CA).to_string_lossy().into_owned(),
        allowed_cn: armada_pki::etcd_member().to_string(),
    };
    if !cfg.initial_cluster.is_empty() && fresh {
        s.initial_cluster = cfg.initial_cluster.clone();
        s.cluster_state = "existing";
    }
    Ok(s)
}

/// fileConfig: etcdFile as go-yaml's Marshal writes it.
fn file_config(s: &MemberSpec) -> Result<Vec<u8>, String> {
    let mut e = Encoder::new();
    e.document_start()?;
    e.mapping_start("")?;
    let kv = |e: &mut Encoder, k: &str, v: &str| -> Result<(), String> {
        e.stringv("", k)?;
        e.stringv("", v)
    };
    kv(&mut e, "name", &s.name)?;
    kv(&mut e, "data-dir", &s.data_dir)?;
    kv(&mut e, "listen-client-urls", &s.client_url)?;
    kv(&mut e, "advertise-client-urls", &s.client_url)?;
    kv(&mut e, "listen-peer-urls", &s.peer_url)?;
    kv(&mut e, "initial-advertise-peer-urls", &s.peer_url)?;
    kv(&mut e, "initial-cluster", &s.initial_cluster)?;
    kv(&mut e, "initial-cluster-token", CLUSTER_TOKEN)?;
    kv(&mut e, "initial-cluster-state", s.cluster_state)?;
    e.stringv("", "enable-grpc-gateway")?;
    e.boolv("", false)?;
    kv(&mut e, "tls-min-version", "TLS1.3")?;
    e.stringv("", "max-txn-ops")?;
    e.uintv("", MAX_TXN_OPS)?;
    kv(&mut e, "auto-compaction-mode", "periodic")?;
    kv(&mut e, "auto-compaction-retention", "1h")?;
    kv(&mut e, "logger", "zap")?;
    kv(&mut e, "log-level", "warn")?;
    e.stringv("", "log-outputs")?;
    e.sequence_start("")?;
    e.stringv("", "stderr")?;
    e.sequence_end()?;
    for key in ["client-transport-security", "peer-transport-security"] {
        e.stringv("", key)?;
        e.mapping_start("")?;
        kv(&mut e, "cert-file", &s.cert_file)?;
        kv(&mut e, "key-file", &s.key_file)?;
        kv(&mut e, "trusted-ca-file", &s.ca_file)?;
        e.stringv("", "client-cert-auth")?;
        e.boolv("", true)?;
        e.stringv("", "allowed-cn")?;
        e.sequence_start("")?;
        e.stringv("", &s.allowed_cn)?;
        e.sequence_end()?;
        e.mapping_end()?;
    }
    e.mapping_end()?;
    e.document_end()?;
    e.finish()?;
    let mut out = b"# Written by armadad etcd at every start; changes are overwritten.\n".to_vec();
    out.extend_from_slice(&e.into_bytes());
    Ok(out)
}

/// A member to start: its client URL and the configuration file's
/// content, the member prepared (Go's Start begins with prepare too).
pub struct Prepared {
    pub dir: PathBuf,
    pub client_url: String,
    pub peer_url: String,
    pub file: Vec<u8>,
}

/// prepare and fileConfig, for a member this process starts and stops
/// (Go's Start, which embeds one).
pub fn prepare_start(cfg: &mut Config) -> Result<Prepared, String> {
    let s = prepare(cfg)?;
    Ok(Prepared {
        dir: cfg.dir.clone(),
        client_url: s.client_url.clone(),
        peer_url: s.peer_url.clone(),
        file: file_config(&s)?,
    })
}

/// WriteConfigFile: the member prepared and its file written (0600); the
/// file's path.
pub fn write_config_file(cfg: &mut Config) -> Result<PathBuf, String> {
    let s = prepare(cfg)?;
    let b = file_config(&s)?;
    let path = cfg.dir.join(FILE_CONFIG);
    armada_fsutil::write_file_atomic(&path, &b, 0o600).map_err(|e| e.to_string())?;
    Ok(path)
}

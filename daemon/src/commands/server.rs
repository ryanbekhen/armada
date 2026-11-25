//! armadad server (Go's newServerCommand, lead, term, runTerm, and
//! resolveSettings in internal/daemon): the control plane of this
//! machine. It connects to the etcd member armada-etcd.service runs (ADR
//! 0055: Rust runs no member inside the server), campaigns for leadership,
//! and runs a term's server while it leads (armada-server's lifecycle).
//!
//! The node's agent runs as a unit of its own on a server machine too
//! (ADR 0055, "The agent on a server machine"): `--agent` is kept for the
//! units of before and logged, never acted on; the unit that runs it
//! comes with the switch (pull request 19).

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use armada_client::cli::{Ctx, Error, Result};
use armada_pki::{Ca, KIND_SERVER, parse_cert_pem};
use armada_server::acme::{self, Acme, Event, Options};
use armada_server::certs::{Certs, Dns, EtcdStorage};
use armada_server::log::Logger;
use armada_server::renew::Renewer;
use armada_server::tls::ServerCert;
use armada_server::{Cluster, MemberInfo, Server, lifecycle};
use armada_store::{Client, Etcd, Kind, SCHEMA};
use tokio::sync::watch;
use tonic::codegen::async_trait;

use crate::agentconfig::{
    self, AgentConfig, FILE_CA_CERT, FILE_CA_KEY, FILE_SERVER_CERT, NETWORK_MESH,
};
use crate::machine::{self, FILE_MASTER_KEY, FILE_SERVER_KEY, META_MASTER_KEY};
use crate::{backup, netutil, signals, state};

fn msg(s: impl Into<String>) -> Error {
    Error::Msg(s.into())
}

/// The ETCD member choices of the hidden --etcd-member flag.
const ETCD_EMBEDDED: &str = "embedded";
const ETCD_UNIT: &str = "unit";
/// defaultACMEPort.
const DEFAULT_ACME_PORT: u16 = 7480;
/// acmePrefix: where certificates and the ACME account live in etcd.
const ACME_PREFIX: &str = "/armada-acme/";

/// The loggers of --log-format and --verbose: the control plane's and the
/// tunnels' (armada-agent's), writing the same lines.
pub fn loggers(ctx: &Ctx<'_>) -> std::result::Result<(Logger, armada_agent::log::Logger), Error> {
    let verbose = ctx.bool("verbose");
    match ctx.str("log-format").as_str() {
        "text" => Ok((
            Logger::stderr(verbose),
            armada_agent::log::Logger::stderr(verbose),
        )),
        "json" => Ok((
            Logger::stderr_json(verbose),
            armada_agent::log::Logger::stderr_json(verbose),
        )),
        other => Err(msg(format!(
            "unsupported --log-format {} (want text or json)",
            armada_spec::go::quote(other)
        ))),
    }
}

/// A multi-threaded runtime for a long-running command.
pub fn runtime() -> std::result::Result<tokio::runtime::Runtime, Error> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| msg(e.to_string()))
}

/// The certificate flags (Go's tlsFlags).
#[derive(Clone)]
struct TlsFlags {
    enabled: bool,
    ca: String,
    email: String,
    listen: String,
    dns_provider: String,
    dns_token_file: String,
}

/// readTokenFile: --dns-token-file, a private file.
fn read_token_file(path: &str) -> std::result::Result<String, String> {
    let b =
        armada_fsutil::read_private_file(Path::new(path)).map_err(|e| format!("DNS token: {e}"))?;
    let t = armada_spec::go::trim_space(&String::from_utf8_lossy(&b)).to_string();
    if t.is_empty() {
        return Err("DNS token file is empty".to_string());
    }
    Ok(t)
}

/// serverIdentity: the name of a server certificate.
fn server_identity(pem: &[u8]) -> std::result::Result<String, String> {
    let bad = || format!("{FILE_SERVER_CERT} is not a server certificate");
    let c = parse_cert_pem(pem).map_err(|e| e.to_string())?;
    match c.identity() {
        Ok(id) if id.kind == KIND_SERVER => Ok(id.name),
        _ => Err(bad()),
    }
}

/// serverIP: the private IP a server certificate was issued for.
pub fn server_ip(pem: &[u8]) -> std::result::Result<IpAddr, String> {
    let c = parse_cert_pem(pem).map_err(|e| e.to_string())?;
    c.ip_addresses
        .first()
        .map(netutil::unmap)
        .ok_or_else(|| format!("{FILE_SERVER_CERT} has no IP address"))
}

fn read_private(data_dir: &str, names: &[&str]) -> std::result::Result<Vec<Vec<u8>>, String> {
    names
        .iter()
        .map(|n| {
            armada_fsutil::read_private_file(&Path::new(data_dir).join(n))
                .map_err(|e| e.to_string())
        })
        .collect()
}

/// resolveJoinListen.
fn resolve_join_listen(flag: &str, api: &str) -> std::result::Result<String, String> {
    match flag {
        "off" => Ok(String::new()),
        "" => {
            let Some((host, port)) = api.rsplit_once(':') else {
                return Err(format!("address {api}: missing port in address"));
            };
            match port.parse::<u32>() {
                Ok(p) if p < 65535 => Ok(format!("{host}:{}", p + 1)),
                _ => Err(format!(
                    "cannot derive a join port from {api}; set --join-listen"
                )),
            }
        }
        _ => {
            netutil::check_private_listen(flag).map_err(|e| format!("--join-listen: {e}"))?;
            Ok(flag.to_string())
        }
    }
}

/// acmeListen: --acme-listen, by default the server's IP and port 7480.
fn acme_listen(flag: &str, server_listen: &str) -> std::result::Result<String, String> {
    let mut listen = flag.to_string();
    if listen.is_empty() {
        let Some((a, _)) = armada_client::config::parse_addr_port(server_listen) else {
            return Err(format!(
                "invalid AddrPort {}",
                armada_spec::go::quote(server_listen)
            ));
        };
        let ip = netutil::to_std(&a);
        listen = match ip {
            IpAddr::V4(v) => format!("{v}:{DEFAULT_ACME_PORT}"),
            IpAddr::V6(v) => format!("[{v}]:{DEFAULT_ACME_PORT}"),
        };
    }
    netutil::check_private_listen(&listen).map_err(|e| format!("ACME responder: {e}"))?;
    if armada_client::config::parse_addr_port(&listen).is_some_and(|(_, p)| p == 0) {
        return Err("ACME responder needs a fixed port".to_string());
    }
    Ok(listen)
}

/// loadMasterKey: the secrets master key, made for a cluster from before
/// secrets, else the key the state records.
async fn load_master_key(
    st: &Etcd,
    data_dir: &str,
    log: &Logger,
) -> std::result::Result<armada_secrets::Keyring, String> {
    let path = Path::new(data_dir).join(FILE_MASTER_KEY);
    let recorded = match st.get_meta(META_MASTER_KEY).await {
        Ok(v) => v,
        Err(e) if e.kind == Kind::NotFound => String::new(),
        Err(e) => return Err(e.to_string()),
    };
    let missing = matches!(std::fs::symlink_metadata(&path), Err(e) if e.kind() == std::io::ErrorKind::NotFound);
    if missing && recorded.is_empty() {
        armada_secrets::generate_key_file(&path).map_err(|e| format!("master key: {e}"))?;
        log.warn(
            "created a new secrets master key; back it up with the state database",
            &[("path", path.display().to_string())],
        );
    } else if missing {
        return Err(format!(
            "master key {} is missing; restore it from a backup (key id {recorded})",
            path.display()
        ));
    }
    let keys = armada_secrets::load_key_file(&path).map_err(|e| format!("master key: {e}"))?;
    if recorded.is_empty() {
        st.set_meta(META_MASTER_KEY, keys.id())
            .await
            .map_err(|e| e.to_string())?;
    } else if recorded != keys.id() {
        return Err(format!(
            "master key {} (id {}) is not the key this cluster's secrets use (id {recorded}); restore the right key",
            path.display(),
            keys.id()
        ));
    }
    Ok(keys)
}

/// The etcd membership of the control plane over this server's member
/// (Go's etcd.Cluster).
struct EtcdCluster {
    c: Client,
    /// The member's directory, whose certificate reaches other members.
    dir: PathBuf,
}

fn member_info(m: &armada_proto::etcd::etcdserverpb::Member) -> (MemberInfo, String) {
    (
        MemberInfo {
            id: m.id,
            name: m.name.clone(),
            learner: m.is_learner,
            client_url: m.client_ur_ls.first().cloned().unwrap_or_default(),
        },
        m.peer_ur_ls.first().cloned().unwrap_or_default(),
    )
}

impl EtcdCluster {
    async fn list(&self) -> std::result::Result<Vec<(MemberInfo, String)>, String> {
        let ms = self
            .c
            .member_list()
            .await
            .map_err(|e| format!("etcd member list: {e}"))?;
        Ok(ms.iter().map(member_info).collect())
    }
}

#[async_trait]
impl Cluster for EtcdCluster {
    async fn members(&self) -> std::result::Result<Vec<MemberInfo>, String> {
        Ok(self.list().await?.into_iter().map(|(m, _)| m).collect())
    }

    async fn add_learner(
        &self,
        name: &str,
        addr: IpAddr,
        peer_port: u16,
    ) -> std::result::Result<(u64, String), String> {
        let members = self.list().await?;
        let peer = crate::etcdmember::member_url(&addr, peer_port);
        let mut parts = Vec::new();
        for (m, purl) in &members {
            if m.name == name {
                return Err(format!("etcd member {name} already exists"));
            }
            if *purl == peer {
                return Err(format!("etcd member at {peer} already exists"));
            }
            if m.name.is_empty() {
                return Err(format!(
                    "a control plane node added at {purl} has not started yet; start it or remove it first"
                ));
            }
            parts.push(format!("{}={purl}", m.name));
        }
        // etcd refuses changes until every voting member has been
        // connected for a few seconds, e.g. right after a promotion.
        let mut tries = 0;
        let id = loop {
            match self.c.member_add_learner(vec![peer.clone()]).await {
                Ok(id) => break id,
                Err(e) if e.to_string().contains("unhealthy cluster") && tries < 60 => {
                    tries += 1;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => return Err(format!("etcd add member: {e}")),
            }
        };
        parts.push(format!("{name}={peer}"));
        Ok((id, parts.join(",")))
    }

    async fn promote(&self) -> std::result::Result<Vec<String>, String> {
        let mut promoted = Vec::new();
        for (m, _) in self.list().await? {
            if !m.learner || m.name.is_empty() {
                continue;
            }
            if let Err(e) = self.c.member_promote(m.id).await {
                if e.to_string().contains("not in sync") {
                    continue;
                }
                return Err(format!("etcd promote {}: {e}", m.name));
            }
            promoted.push(m.name);
        }
        Ok(promoted)
    }

    async fn reachable(&self, m: &MemberInfo) -> bool {
        let Some(host) = m
            .client_url
            .strip_prefix("https://")
            .filter(|h| !h.is_empty())
        else {
            return false;
        };
        let Ok(c) = Client::connect(&format!("https://{host}"), &self.dir) else {
            return false;
        };
        matches!(
            tokio::time::timeout(Duration::from_secs(1), c.status()).await,
            Ok(Ok(_))
        )
    }

    async fn remove_member(&self, id: u64) -> std::result::Result<(), String> {
        self.c
            .member_remove(id)
            .await
            .map_err(|e| format!("etcd remove member: {e}"))
    }
}

/// What one term of the control plane uses (Go's termSettings).
struct TermSettings {
    enabled: bool,
    ca: String,
    email: String,
    dns_provider: String,
    token: String,
    metrics: String,
    lost_timeout: Duration,
}

/// The flags resolveSettings reads, and which were given.
#[derive(Clone)]
struct SettingFlags {
    tls: TlsFlags,
    metrics: String,
    lost: Duration,
    given: Vec<&'static str>,
}

/// resolveSettings: the cluster's settings over this server's flags, the
/// flags over the defaults; a setting the cluster lacks is taken from the
/// flags given here and stored.
async fn resolve_settings(
    st: &Etcd,
    keys: &armada_secrets::Keyring,
    f: &SettingFlags,
    ip: &str,
    log: &Logger,
) -> std::result::Result<TermSettings, String> {
    let mut set = armada_server::load_settings(st)
        .await
        .map_err(|e| e.to_string())?;
    let given = |n: &str| f.given.contains(&n);
    let mut adopted: Vec<&str> = Vec::new();
    let disagree = |flag: &str| {
        log.warn(
            "a flag in server.env differs from the cluster setting, which wins; change it with `armada cluster update`",
            &[("flag", format!("--{flag}"))],
        )
    };
    let tf = &f.tls;
    if set.tls.is_none() && given("tls") {
        set.tls = Some(tf.enabled);
        adopted.push("tls");
    } else if set.tls.is_some_and(|v| v != tf.enabled) && given("tls") {
        disagree("tls");
    }
    if set.acme_ca.is_empty() && given("acme-ca") {
        set.acme_ca = tf.ca.clone();
        adopted.push("acme-ca");
    } else if !set.acme_ca.is_empty() && given("acme-ca") && set.acme_ca != tf.ca {
        disagree("acme-ca");
    }
    if set.acme_email.is_empty() && given("acme-email") {
        set.acme_email = tf.email.clone();
        adopted.push("acme-email");
    } else if !set.acme_email.is_empty() && given("acme-email") && set.acme_email != tf.email {
        disagree("acme-email");
    }
    if !set.dns_provider_set && given("dns-provider") {
        let mut token = String::new();
        if !tf.dns_token_file.is_empty() {
            token = read_token_file(&tf.dns_token_file)?;
        }
        if !token.is_empty() {
            set.seal_token(keys, token.as_bytes())?;
        }
        set.dns_provider = tf.dns_provider.clone();
        set.dns_provider_set = true;
        adopted.push("dns-provider");
    } else if set.dns_provider_set && given("dns-provider") && set.dns_provider != tf.dns_provider {
        disagree("dns-provider");
    }
    if set.metrics_port.is_none()
        && given("metrics-listen")
        && let Some((_, p)) = f.metrics.rsplit_once(':')
        && let Ok(port) = armada_spec::go::atoi(p)
    {
        set.metrics_port = Some(port);
        adopted.push("metrics-listen");
    }
    let lost_secs = f.lost.as_secs() as i64;
    if set.node_lost_seconds == 0 && given("node-lost-timeout") {
        set.node_lost_seconds = lost_secs;
        adopted.push("node-lost-timeout");
    } else if set.node_lost_seconds != 0
        && given("node-lost-timeout")
        && set.node_lost_seconds != lost_secs
    {
        disagree("node-lost-timeout");
    }
    if !adopted.is_empty() {
        armada_server::save_settings(st, &set)
            .await
            .map_err(|e| e.to_string())?;
        st.record_audit(
            "server",
            "cluster.settings",
            "cluster",
            &format!("from server flags: {}", adopted.join(" ")),
        )
        .await
        .map_err(|e| e.to_string())?;
        log.info(
            "cluster settings taken from this server's flags",
            &[("flags", adopted.join(","))],
        );
    }
    let mut out = TermSettings {
        enabled: tf.enabled,
        ca: tf.ca.clone(),
        email: tf.email.clone(),
        dns_provider: tf.dns_provider.clone(),
        token: String::new(),
        metrics: f.metrics.clone(),
        lost_timeout: f.lost,
    };
    if let Some(v) = set.tls {
        out.enabled = v;
    }
    if !set.acme_ca.is_empty() {
        out.ca = set.acme_ca.clone();
    }
    if !set.acme_email.is_empty() {
        out.email = set.acme_email.clone();
    }
    if set.dns_provider_set {
        out.dns_provider = set.dns_provider.clone();
    }
    if let Some(v) = set.token(keys)? {
        out.token = String::from_utf8_lossy(v.bytes()).into_owned();
    } else if !set.dns_provider_set && !tf.dns_token_file.is_empty() {
        out.token = read_token_file(&tf.dns_token_file)?;
    }
    if let Some(p) = set.metrics_port
        && !given("metrics-listen")
    {
        out.metrics = if p > 0 {
            if ip.contains(':') {
                format!("[{ip}]:{p}")
            } else {
                format!("{ip}:{p}")
            }
        } else {
            String::new()
        };
    }
    if set.node_lost_seconds > 0 {
        out.lost_timeout = Duration::from_secs(set.node_lost_seconds as u64);
    }
    Ok(out)
}

/// What every term of this server shares.
struct Setup {
    data_dir: String,
    name: String,
    listen: String,
    join_addr: String,
    join_public: bool,
    join_site_addr: String,
    acme_flag: String,
    ip: String,
    flags: SettingFlags,
    ca: Arc<Ca>,
    cert: Arc<ServerCert>,
    keys: Arc<armada_secrets::Keyring>,
    client: Client,
    member_dir: PathBuf,
    log: Logger,
    /// The term's server, for the certificate manager's events.
    current: Arc<Mutex<Option<Server>>>,
}

/// One run of a term's server (Go's runTerm).
async fn run_term(
    s: Arc<Setup>,
    fenced: Etcd,
    restart: lifecycle::Restart,
    stop: watch::Receiver<bool>,
) -> std::result::Result<(), String> {
    let ts = resolve_settings(&fenced, &s.keys, &s.flags, &s.ip, &s.log)
        .await
        .map_err(|e| format!("cluster settings: {e}"))?;
    if !ts.metrics.is_empty() {
        netutil::check_private_listen(&ts.metrics).map_err(|e| format!("metrics: {e}"))?;
    }
    let mut cfg = armada_server::Config::new(fenced, s.cert.clone());
    cfg.log = s.log.clone();
    cfg.keys = Some(s.keys.clone());
    cfg.ca = Some(s.ca.clone());
    cfg.join_addr = s.join_addr.clone();
    cfg.join_public = s.join_public;
    cfg.join_site_addr = s.join_site_addr.clone();
    cfg.api_addr = s.listen.clone();
    cfg.node_lost_timeout = ts.lost_timeout;
    cfg.metrics_addr = ts.metrics.clone();
    cfg.on_settings_changed = Some(restart);
    cfg.name = s.name.clone();
    cfg.cluster = Some(Arc::new(EtcdCluster {
        c: s.client.clone(),
        dir: s.member_dir.clone(),
    }));
    // The scheduled backups to a bucket (ADR 0051) hold what armadad
    // backup writes.
    {
        let data_dir = s.data_dir.clone();
        let client = s.client.clone();
        cfg.control_plane_backup = Some(Arc::new(move || {
            let data_dir = data_dir.clone();
            let client = client.clone();
            Box::pin(async move {
                let (dir, staged) = backup::stage(&data_dir, &client).await?;
                Ok(armada_server::cpbackup::Staged {
                    dir,
                    cleanup: Some(Box::new(move || drop(staged))),
                })
            })
        }));
    }
    // certOptions: none without TLS.
    let mut acme_mgr: Option<(Acme, Arc<EtcdStorage>)> = None;
    if ts.enabled {
        let directory = acme::directory(&ts.ca)?;
        let listen = acme_listen(&s.acme_flag, &s.listen)?;
        let dns = match ts.dns_provider.as_str() {
            "" => None,
            "cloudflare" => {
                if ts.token.is_empty() {
                    return Err("DNS provider cloudflare needs a token (armada cluster update --dns-token - < FILE)".to_string());
                }
                Some(Dns {
                    provider: "cloudflare".to_string(),
                    token: ts.token.clone(),
                })
            }
            other => {
                return Err(format!(
                    "unsupported DNS provider {} (want cloudflare)",
                    armada_spec::go::quote(other)
                ));
            }
        };
        let storage =
            Arc::new(EtcdStorage::new(s.client.clone(), ACME_PREFIX).map_err(|e| e.to_string())?);
        let mut opts = Options::new(storage.clone(), &directory);
        opts.email = ts.email.clone();
        opts.dns = dns;
        opts.log = s.log.clone();
        let current = s.current.clone();
        let log = s.log.clone();
        opts.on_event = Some(Arc::new(move |ev: Event| {
            let (name, err) = match ev {
                Event::Obtained { name, .. } => {
                    log.info("certificate obtained", &[("name", name.clone())]);
                    (name, None)
                }
                Event::Failed {
                    name,
                    renewal,
                    error,
                } => {
                    log.warn(
                        "certificate request failed; retrying with backoff",
                        &[
                            ("name", name.clone()),
                            ("renewal", renewal.to_string()),
                            ("err", error.clone()),
                        ],
                    );
                    let e = if error.is_empty() {
                        "certificate request failed".to_string()
                    } else {
                        error
                    };
                    (name, Some(e))
                }
            };
            let srv = current.lock().unwrap_or_else(|p| p.into_inner()).clone();
            if let Some(srv) = srv {
                tokio::spawn(async move {
                    let ok = err.is_none();
                    srv.certificate_event(&name, err).await;
                    if ok {
                        srv.trigger();
                    }
                });
            }
        }));
        let m = Acme::new(opts)?;
        cfg.certs = Some(Arc::new(m.clone()) as Arc<dyn Certs>);
        cfg.acme_addr = listen;
        cfg.acme_email = ts.email.clone();
        cfg.acme_ca = ts.ca.clone();
        cfg.dns_provider = ts.dns_provider.clone();
        cfg.tls_on = true;
        acme_mgr = Some((m, storage));
    }
    // Without certificates the apps are served over plain HTTP.
    cfg.plain_http = !ts.enabled;
    let res = async {
        let srv = Server::new(cfg)?;
        *s.current.lock().unwrap_or_else(|p| p.into_inner()) = Some(srv.clone());
        let lis = tokio::net::TcpListener::bind(&s.listen)
            .await
            .map_err(|e| format!("listen tcp {}: {e}", s.listen))?;
        srv.serve(lis, stop).await
    }
    .await;
    *s.current.lock().unwrap_or_else(|p| p.into_inner()) = None;
    if let Some((m, storage)) = acme_mgr {
        m.close().await;
        let _ = storage.close().await;
    }
    res
}

pub fn run(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let (log, net_log) = loggers(ctx)?;
    let data_dir = ctx.str("data-dir");
    let etcd_member = ctx.str("etcd-member");
    if etcd_member != ETCD_EMBEDDED && etcd_member != ETCD_UNIT {
        return Err(msg(format!(
            "invalid --etcd-member {}: use {ETCD_EMBEDDED} or {ETCD_UNIT}",
            armada_spec::go::quote(&etcd_member)
        )));
    }
    let lost = Duration::from_nanos(ctx.duration("node-lost-timeout").max(0) as u64);
    armada_server::check_node_lost_timeout(lost)
        .map_err(|e| msg(format!("--node-lost-timeout: {e}")))?;
    let tls = TlsFlags {
        enabled: ctx.bool("tls"),
        ca: ctx.str("acme-ca"),
        email: ctx.str("acme-email"),
        listen: ctx.str("acme-listen"),
        dns_provider: ctx.str("dns-provider"),
        dns_token_file: ctx.str("dns-token-file"),
    };
    if tls.enabled {
        armada_server::check_acme_ca(&tls.ca).map_err(|e| msg(format!("--acme-ca: {e}")))?;
    }
    if armada_server::check_dns_provider(&tls.dns_provider).is_err() {
        return Err(msg(format!(
            "unsupported --dns-provider {} (want cloudflare)",
            armada_spec::go::quote(&tls.dns_provider)
        )));
    }
    if !tls.dns_provider.is_empty() && !tls.enabled {
        return Err(msg("--dns-provider needs --tls"));
    }
    if tls.dns_provider.is_empty() != tls.dns_token_file.is_empty() {
        return Err(msg("--dns-provider and --dns-token-file go together"));
    }
    if !tls.dns_token_file.is_empty() {
        // A bad token file should fail at startup, not when this server
        // first leads.
        read_token_file(&tls.dns_token_file).map_err(msg)?;
    }
    let mut given = Vec::new();
    for f in [
        "tls",
        "acme-ca",
        "acme-email",
        "dns-provider",
        "dns-token-file",
        "metrics-listen",
        "node-lost-timeout",
    ] {
        if ctx.changed(f) {
            given.push(f);
        }
    }
    let flags = SettingFlags {
        tls: tls.clone(),
        metrics: ctx.str("metrics-listen"),
        lost,
        given,
    };
    let join_flag = ctx.str("join-listen");
    let with_agent = ctx.bool("agent");
    let rt = runtime()?;
    let stop = signals::stop_on_signals();
    rt.block_on(serve(
        data_dir,
        etcd_member == ETCD_UNIT,
        tls,
        flags,
        join_flag,
        with_agent,
        log,
        net_log,
        stop,
    ))
    .map_err(msg)
}

#[allow(clippy::too_many_arguments)]
async fn serve(
    data_dir: String,
    unit: bool,
    tls: TlsFlags,
    flags: SettingFlags,
    join_flag: String,
    with_agent: bool,
    log: Logger,
    net_log: armada_agent::log::Logger,
    stop: watch::Receiver<bool>,
) -> std::result::Result<(), String> {
    // A mesh server's etcd member and API listen on its mesh address,
    // which exists once the tunnel is up (ADR 0049).
    let ac = match agentconfig::load(&data_dir) {
        Ok(ac) => ac,
        // Not initialized: the state says so.
        Err(e) if e.not_found => AgentConfig::default(),
        Err(e) => return Err(e.text),
    };
    machine::up_mesh(&data_dir, &ac, None, &net_log).await?;
    if matches!(std::fs::metadata(Path::new(&data_dir).join(FILE_SERVER_CERT)), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        return Err(format!("{data_dir} is not initialized; run `armadad init`"));
    }
    // Rust runs no etcd member inside the server (ADR 0055): the member
    // is armada-etcd.service's.
    if !unit {
        return Err("this armadad runs no embedded etcd member: run this server's member as armada-etcd.service (`armadad etcd`) and start the server with --etcd-member unit (ADR 0055)".to_string());
    }
    let wait_log = log.clone();
    let learner_log = log.clone();
    let member = state::connect(
        &data_dir,
        &move |addr, err| {
            wait_log.info(
                "waiting for the etcd member",
                &[
                    ("component", "etcd".into()),
                    ("addr", addr.into()),
                    ("err", err.into()),
                ],
            )
        },
        &move || {
            learner_log.info(
                "waiting for the leader to promote this server to a voting etcd member",
                &[],
            )
        },
    )
    .await?;
    let st = Etcd::new(member.client.clone(), backup::ETCD_PREFIX)
        .await
        .map_err(|e| e.to_string())?;
    let pem = read_private(&data_dir, &[FILE_CA_CERT, FILE_CA_KEY])?;
    let ca = Arc::new(Ca::load(&pem[0], &pem[1]).map_err(|e| e.to_string())?);
    // Renew before loading, so a server that was down past the renewal
    // point, or past expiry, starts with a valid certificate.
    let shared = machine::euid() == 0 && data_dir == machine::DEFAULT_DATA_DIR;
    let member_dir = Path::new(&data_dir).join(crate::agentconfig::DIR_ETCD);
    let mut renewer = Renewer {
        data_dir: PathBuf::from(&data_dir),
        ca: ca.clone(),
        server: None,
        member_dir: Some(member_dir.clone()),
        st: shared.then(|| st.clone()),
        admin_config: shared.then(|| PathBuf::from(armada_client::config::SYSTEM_PATH)),
        log: log.clone(),
        now: Arc::new(SystemTime::now),
    };
    renewer.check();
    let pem = read_private(
        &data_dir,
        &[FILE_CA_CERT, FILE_SERVER_CERT, FILE_SERVER_KEY],
    )?;
    let name = server_identity(&pem[1])?;
    let ip = server_ip(&pem[1])?;
    let servers = st.list_servers().await.map_err(|e| e.to_string())?;
    let Some(me) = servers.into_iter().find(|s| s.name == name) else {
        return Err(format!(
            "server {name} is not part of this cluster (it was removed, or the state is from another cluster)"
        ));
    };
    let listen = me.api_addr.clone();
    netutil::check_private_listen(&listen)?;
    let cert = ServerCert::new(&pem[0], &pem[1], &pem[2])?;
    renewer.server = Some(cert.clone());
    let mut join_addr = resolve_join_listen(&join_flag, &listen)?;
    // A mesh cluster's machines join over the leader's public endpoint,
    // while a join token is open (ADR 0049).
    let join_public = ac.network == NETWORK_MESH && !join_addr.is_empty();
    if join_public {
        join_addr = machine::mesh_join_listen(&join_addr, ac.endpoint.parse().ok())?;
    }
    // Machines of another site join over the leader's endpoint, while a
    // token for one is open (ADR 0050).
    let mut join_site_addr = String::new();
    if let Ok(ep) = crate::commands::endpoint::announced(&ac).parse::<IpAddr>()
        && !join_public
        && !join_addr.is_empty()
    {
        join_site_addr = machine::mesh_join_listen(&join_addr, Some(ep))?;
    }
    if !flags.metrics.is_empty() {
        netutil::check_private_listen(&flags.metrics)
            .map_err(|e| format!("--metrics-listen: {e}"))?;
    }
    let keys = Arc::new(load_master_key(&st, &data_dir, &log).await?);
    acme_listen(&tls.listen, &listen)?;
    st.upsert_server(&armada_store::Server {
        name: name.clone(),
        private_ip: ip.to_string(),
        api_addr: listen.clone(),
        join_addr: join_addr.clone(),
        member_id: member.member_id,
        schema: SCHEMA,
        version: armada_client::commands::version::get().version.to_string(),
        created_at: armada_spec::gotime::Time::zero(),
    })
    .await
    .map_err(|e| e.to_string())?;
    if with_agent {
        // The node's agent is a unit of its own on server machines too
        // (ADR 0055); a node certificate that expired while the machine
        // was down is signed again for it, as Go does before its embedded
        // agent starts.
        renewer.renew_node(&st).await;
        log.info(
            "this machine's agent runs as armada-agent.service, not inside the server (ADR 0055)",
            &[],
        );
    }
    let setup = Arc::new(Setup {
        data_dir: data_dir.clone(),
        name: name.clone(),
        listen,
        join_addr,
        join_public,
        join_site_addr,
        acme_flag: tls.listen.clone(),
        ip: ip.to_string(),
        flags,
        ca,
        cert,
        keys,
        client: member.client.clone(),
        member_dir,
        log: log.clone(),
        current: Arc::new(Mutex::new(None)),
    });
    let renewer = Arc::new(renewer);
    let renew = {
        let r = renewer.clone();
        let stop = stop.clone();
        tokio::spawn(async move { r.run(stop).await })
    };
    let res = lifecycle::lead(
        &member.client,
        &name,
        lifecycle::LEADER_LEASE,
        &log,
        stop.clone(),
        || {
            let st = st.clone();
            let log = log.clone();
            let mut stop = stop.clone();
            async move { lifecycle::wait_lead_ready(&st, &log, &mut stop).await }
        },
        |lead, tstop| {
            let st = st.clone();
            let log = log.clone();
            let setup = setup.clone();
            async move {
                lifecycle::term(&st, &lead, &log, tstop, |fenced, restart, run_stop| {
                    run_term(setup.clone(), fenced, restart, run_stop)
                })
                .await
            }
        },
    )
    .await;
    renew.abort();
    drop(member);
    res
}

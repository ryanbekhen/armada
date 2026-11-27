//! The cluster's server settings (ADR 0031) and the
//! cluster configuration RPCs. SetClusterConfig sets the root domain and
//! the server settings here, and calls on the others: the trusted proxies
//! and PROXY protocol sources (`ingress`), the log settings (`logs`), the
//! control plane backups (`cpbackup`), the network mode, the mesh range,
//! and the runtime move.

use std::sync::Arc;
use std::time::Duration;

use armada_pki::encoding::{base64_decode, base64_encode};
use armada_proto::armada::v1::{BackupKeep, ClusterConfig, SetClusterConfigRequest};
use armada_secrets::{Keyring, Sealed, Value};
use armada_store::{Etcd, Kind};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use tonic::{Code, Status};

use crate::grpc::Auth;
use crate::{Server, store_err};

const META_SETTINGS: &str = "settings";
const META_ROOT_DOMAIN: &str = "root_domain";
use crate::ingress::{META_PROXY_PROTOCOL, META_TRUSTED_PROXIES};
pub(crate) const META_LOGS: &str = "logs";
const META_CP_BACKUP: &str = "control-plane-backup";

/// The DNS token is sealed like an app secret, bound to this scope.
pub(crate) const TOKEN_SCOPE: &str = "cluster";
const TOKEN_NAME: &str = "dns-token";
pub(crate) const LOG_TOKEN_NAME: &str = "log-token";

pub const MIN_NODE_LOST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_NODE_LOST_TIMEOUT: Duration = Duration::from_secs(24 * 3600);
const MAX_EMAIL_LEN: usize = 254;
const MAX_TOKEN_LEN: usize = 4096;

/// A sealed secret as JSON.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SealedJson {
    #[serde(rename = "KeyID", default)]
    key_id: String,
    #[serde(rename = "WrappedKey", default, with = "b64")]
    wrapped_key: Vec<u8>,
    #[serde(rename = "Ciphertext", default, with = "b64")]
    ciphertext: Vec<u8>,
}

impl SealedJson {
    pub(crate) fn sealed(&self) -> Sealed {
        Sealed {
            key_id: self.key_id.clone(),
            wrapped_key: self.wrapped_key.clone(),
            ciphertext: self.ciphertext.clone(),
        }
    }

    pub(crate) fn of(s: &Sealed) -> SealedJson {
        SealedJson {
            key_id: s.key_id.clone(),
            wrapped_key: s.wrapped_key.clone(),
            ciphertext: s.ciphertext.clone(),
        }
    }
}

mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::base64_encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let t = Option::<String>::deserialize(d)?.unwrap_or_default();
        super::base64_decode(t.as_bytes())
            .ok_or_else(|| serde::de::Error::custom("illegal base64 data"))
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}
fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// The server settings that must be the same on every server. Unset
/// fields fall back to each server's flags, then the defaults.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Settings {
    #[serde(rename = "tls", skip_serializing_if = "Option::is_none", default)]
    pub tls: Option<bool>,
    #[serde(rename = "acmeCa", skip_serializing_if = "String::is_empty", default)]
    pub acme_ca: String,
    #[serde(
        rename = "acmeEmail",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub acme_email: String,
    #[serde(
        rename = "dnsProvider",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub dns_provider: String,
    #[serde(rename = "dnsProviderSet", skip_serializing_if = "is_false", default)]
    pub dns_provider_set: bool,
    #[serde(rename = "dnsToken", skip_serializing_if = "Option::is_none", default)]
    dns_token: Option<SealedJson>,
    #[serde(rename = "dnsTokenVersion", skip_serializing_if = "is_zero", default)]
    pub dns_token_version: i64,
    #[serde(
        rename = "metricsPort",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub metrics_port: Option<i64>,
    #[serde(rename = "nodeLostSeconds", skip_serializing_if = "is_zero", default)]
    pub node_lost_seconds: i64,
}

impl Settings {
    /// Whether a DNS token is stored.
    pub fn has_token(&self) -> bool {
        self.dns_token.is_some()
    }

    /// Stores token as the DNS token, a new version of it.
    pub fn seal_token(&mut self, keys: &Keyring, token: &[u8]) -> Result<(), String> {
        if token.is_empty() {
            self.dns_token = None;
            return Ok(());
        }
        let sealed = keys
            .seal(
                TOKEN_SCOPE,
                TOKEN_NAME,
                self.dns_token_version + 1,
                &Value::new(token),
            )
            .map_err(|e| e.to_string())?;
        self.dns_token_version += 1;
        self.dns_token = Some(SealedJson::of(&sealed));
        Ok(())
    }

    /// Opens the DNS token; none when none is stored.
    pub fn token(&self, keys: &Keyring) -> Result<Option<Value>, String> {
        let Some(t) = &self.dns_token else {
            return Ok(None);
        };
        keys.open(&t.sealed(), TOKEN_SCOPE, TOKEN_NAME, self.dns_token_version)
            .map(Some)
            .map_err(|e| e.to_string())
    }
}

/// Reads the cluster's settings; none stored yields zero.
pub async fn load_settings(st: &Etcd) -> Result<Settings, armada_store::Error> {
    match st.get_meta(META_SETTINGS).await {
        Err(e) if e.kind == Kind::NotFound => Ok(Settings::default()),
        Err(e) => Err(e),
        Ok(v) if v.is_empty() => Ok(Settings::default()),
        Ok(v) => serde_json::from_str(&v)
            .map_err(|e| armada_store::Error::other(format!("cluster settings: {e}"))),
    }
}

/// Stores the cluster's settings.
pub async fn save_settings(st: &Etcd, s: &Settings) -> Result<(), armada_store::Error> {
    let b = serde_json::to_string(s).map_err(|e| armada_store::Error::other(e.to_string()))?;
    st.set_meta(META_SETTINGS, &b).await
}

/// CheckACMECA: letsencrypt, letsencrypt-staging, or an https:// URL.
pub fn check_acme_ca(v: &str) -> Result<(), String> {
    if v == "letsencrypt" || v == "letsencrypt-staging" {
        return Ok(());
    }
    let bad = || "ACME CA must be letsencrypt, letsencrypt-staging, or an https:// URL".to_string();
    if v.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f) {
        return Err(bad());
    }
    let Some((scheme, rest)) = v.split_once("://") else {
        return Err(bad());
    };
    if !scheme.eq_ignore_ascii_case("https") {
        return Err(bad());
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') || authority.contains(' ') {
        return Err(bad());
    }
    if let Some((host, port)) = authority.rsplit_once(':')
        && !authority.starts_with('[')
        && (host.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(bad());
    }
    Ok(())
}

/// CheckDNSProvider: the providers Armada supports, or none.
pub fn check_dns_provider(v: &str) -> Result<(), String> {
    if !v.is_empty() && v != "cloudflare" {
        return Err(format!(
            "unsupported DNS provider {} (want cloudflare or none)",
            armada_spec::go::quote(v)
        ));
    }
    Ok(())
}

/// CheckDNSToken: bounded, one line of printable characters.
pub fn check_dns_token(token: &[u8]) -> Result<(), String> {
    let s = String::from_utf8_lossy(token);
    let t = armada_spec::go::trim_space(&s);
    if t.len() > MAX_TOKEN_LEN {
        return Err(format!("DNS token is longer than {MAX_TOKEN_LEN} bytes"));
    }
    if t.chars().any(|r| (r as u32) < 0x20 || r as u32 == 0x7f) {
        return Err("DNS token must be one line of printable characters".to_string());
    }
    Ok(())
}

/// CheckEmail: bounded; ACME checks the rest.
pub fn check_email(v: &str) -> Result<(), String> {
    if v.len() > MAX_EMAIL_LEN
        || v.contains([' ', '\t', '\r', '\n', '<', '>'])
        || (!v.is_empty() && !v.contains('@'))
    {
        return Err("invalid ACME email".to_string());
    }
    Ok(())
}

/// CheckNodeLostTimeout.
pub fn check_node_lost_timeout(d: Duration) -> Result<(), String> {
    if d < MIN_NODE_LOST_TIMEOUT || d > MAX_NODE_LOST_TIMEOUT {
        return Err("node-lost timeout must be between 10s and 24h0m0s (a short network blip must not move every replica)".to_string());
    }
    Ok(())
}

/// A meta record read as JSON; none when missing or empty.
pub(crate) async fn read_meta(st: &Etcd, key: &str) -> Result<Option<Json>, armada_store::Error> {
    match st.get_meta(key).await {
        Err(e) if e.kind == Kind::NotFound => Ok(None),
        Err(e) => Err(e),
        Ok(v) if v.is_empty() => Ok(None),
        Ok(v) => serde_json::from_str(&v)
            .map(Some)
            .map_err(|e| armada_store::Error::other(format!("{key}: {e}"))),
    }
}

fn int(v: &Json, k: &str) -> i64 {
    v.get(k).and_then(Json::as_i64).unwrap_or_default()
}
fn text(v: &Json, k: &str) -> String {
    v.get(k)
        .and_then(Json::as_str)
        .unwrap_or_default()
        .to_string()
}

impl Server {
    /// The root domain for what only shows it (URLs, messages): "" when
    /// none is set or it cannot be read.
    pub(crate) async fn root_domain(&self) -> String {
        self.read_root_domain().await.unwrap_or_default()
    }

    /// The root domain, "" when none is set; a failed read is an error,
    /// so a proxy configuration is never built without the root domain's
    /// hosts because etcd did not answer once.
    pub(crate) async fn read_root_domain(&self) -> Result<String, armada_store::Error> {
        match self.store().get_meta(META_ROOT_DOMAIN).await {
            Err(e) if e.kind == Kind::NotFound => Ok(String::new()),
            r => r,
        }
    }

    /// GetClusterConfig.
    pub(crate) async fn get_cluster_config(
        &self,
        _a: &Auth,
        _req: armada_proto::armada::v1::GetClusterConfigRequest,
    ) -> Result<ClusterConfig, Status> {
        self.cluster_config().await
    }

    async fn cluster_config(&self) -> Result<ClusterConfig, Status> {
        let e = |e: armada_store::Error| store_err(&e);
        // A record that no longer parses is an error (storeErr of it).
        let internal = |_| Status::new(Code::Internal, "internal error");
        let trusted = self.trusted_proxies().await.map_err(internal)?;
        let sources = self.proxy_protocol().await.map_err(internal)?;
        let set = load_settings(self.store()).await.map_err(e)?;
        let mut cc = ClusterConfig {
            root_domain: self.root_domain().await,
            acme_email: self.0.acme_email.clone(),
            trusted_proxies: trusted,
            proxy_protocol: sources,
            tls: self.0.tls_on,
            acme_ca: self.0.acme_ca.clone(),
            dns_provider: self.0.dns_provider.clone(),
            dns_token_set: set.has_token(),
            node_lost_timeout_seconds: self.0.node_lost_timeout.as_secs() as i64,
            ..Default::default()
        };
        if let Ok(ap) = self.0.metrics_addr.parse::<std::net::SocketAddr>() {
            cc.metrics_port = i32::from(ap.port());
        }
        if let Some(ls) = read_meta(self.store(), META_LOGS).await.map_err(e)? {
            cc.log_retention_seconds = int(&ls, "retentionSeconds");
            cc.log_max_bytes = int(&ls, "maxBytes");
            cc.log_export = text(&ls, "export");
            cc.log_endpoint = text(&ls, "endpoint");
            cc.log_export_user = text(&ls, "user");
            cc.log_export_tenant = text(&ls, "tenant");
            cc.log_token_set = ls.get("token").is_some_and(|t| !t.is_null());
        }
        if let Some(b) = read_meta(self.store(), META_CP_BACKUP).await.map_err(e)?
            && b.get("url").is_some_and(|t| !t.is_null())
            && b.get("key").is_some_and(|t| !t.is_null())
        {
            cc.backup_every_seconds = int(&b, "everySeconds");
            cc.backup_schedule = text(&b, "schedule");
            cc.backup_time_zone = text(&b, "timeZone");
            cc.backup_bucket = text(&b, "bucket");
            let k = b.get("keep").cloned().unwrap_or(Json::Null);
            cc.backup_keep = Some(BackupKeep {
                last: int(&k, "last") as i32,
                hourly: int(&k, "hourly") as i32,
                daily: int(&k, "daily") as i32,
                weekly: int(&k, "weekly") as i32,
                monthly: int(&k, "monthly") as i32,
            });
        }
        match self.store().get_network().await {
            Err(err) if err.kind == Kind::NotFound => {}
            Err(err) => return Err(store_err(&err)),
            Ok(n) => {
                cc.network = n.mode.clone();
                if let Some(p) = &n.mesh_cidr {
                    cc.mesh_cidr = p.string();
                }
                if let Some(sw) = &n.switch {
                    cc.network_switch_to = sw.to.clone();
                }
            }
        }
        Ok(cc)
    }

    /// SetClusterConfig: the root domain and the server settings (ADR
    /// 0031); the leader restarts its term to apply the server settings.
    pub(crate) async fn set_cluster_config(
        &self,
        a: &Auth,
        req: SetClusterConfigRequest,
    ) -> Result<ClusterConfig, Status> {
        let c = req.config.clone().unwrap_or_default();
        if req.set_root_domain {
            let root = c.root_domain.trim().to_lowercase();
            if !root.is_empty()
                && let Err(e) = armada_spec::validate::validate_domain(&root)
            {
                return Err(Status::new(
                    Code::InvalidArgument,
                    format!("root domain: {e}"),
                ));
            }
            self.store()
                .set_meta(META_ROOT_DOMAIN, &root)
                .await
                .map_err(|e| store_err(&e))?;
            self.store()
                .record_audit(&a.actor(), "cluster.root_domain", "cluster", &root)
                .await
                .map_err(|e| store_err(&e))?;
            self.0.log.info(
                "root domain changed",
                &[("root_domain", root), ("by", a.actor())],
            );
        }
        if req.set_trusted_proxies {
            let trusted = crate::ingress::parse_trusted_proxies(&c.trusted_proxies)
                .map_err(|e| Status::new(Code::InvalidArgument, e))?;
            self.check_proxy_prefixes(&trusted, "trusted proxy", "trusted proxies")
                .await?;
            let list = trusted.join(",");
            self.store()
                .set_meta(META_TRUSTED_PROXIES, &list)
                .await
                .map_err(|e| store_err(&e))?;
            self.store()
                .record_audit(&a.actor(), "cluster.trusted_proxies", "cluster", &list)
                .await
                .map_err(|e| store_err(&e))?;
            self.0.log.info(
                "trusted proxies changed",
                &[("trusted_proxies", list), ("by", a.actor())],
            );
        }
        if req.set_proxy_protocol {
            let sources = crate::ingress::parse_proxy_protocol(&c.proxy_protocol)
                .map_err(|e| Status::new(Code::InvalidArgument, e))?;
            self.check_proxy_prefixes(&sources, "PROXY protocol source", "PROXY protocol sources")
                .await?;
            let list = sources.join(",");
            self.store()
                .set_meta(META_PROXY_PROTOCOL, &list)
                .await
                .map_err(|e| store_err(&e))?;
            self.store()
                .record_audit(&a.actor(), "cluster.proxy_protocol", "cluster", &list)
                .await
                .map_err(|e| store_err(&e))?;
            self.0.log.info(
                "PROXY protocol sources changed",
                &[("proxy_protocol", list), ("by", a.actor())],
            );
        }
        self.set_log_settings(a, &req).await?;
        self.set_control_plane_backup(a, &req).await?;
        if req.set_network {
            self.set_network(a, &c.network).await?;
        }
        if req.set_mesh_cidr {
            let Some(p) = armada_spec::go::parse_prefix(&c.mesh_cidr) else {
                return Err(Status::new(
                    Code::InvalidArgument,
                    format!(
                        "mesh CIDR {}: want a prefix like {}",
                        armada_spec::go::quote(&c.mesh_cidr),
                        armada_store::network::DEFAULT_MESH_CIDR
                    ),
                ));
            };
            self.store()
                .set_mesh_cidr(&Some(p.clone()), &a.actor())
                .await
                .map_err(|e| store_err(&e))?;
            self.0.log.info(
                "mesh CIDR set",
                &[("mesh_cidr", p.string()), ("by", a.actor())],
            );
        }
        let changed = self.set_settings(a, &req, &c).await?;
        self.trigger();
        let cc = self.cluster_config().await;
        if cc.is_ok()
            && changed
            && let Some(f) = self.0.on_settings.clone()
        {
            // After this answer: the term ends with the API it serves.
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                f();
            });
        }
        cc
    }

    async fn set_settings(
        &self,
        a: &Auth,
        req: &SetClusterConfigRequest,
        c: &ClusterConfig,
    ) -> Result<bool, Status> {
        let any = req.set_tls
            || req.set_acme_email
            || req.set_acme_ca
            || req.set_dns_provider
            || req.set_metrics_port
            || req.set_node_lost_timeout
            || req.set_dns_token;
        if !any {
            return Ok(false);
        }
        let mut set = load_settings(self.store())
            .await
            .map_err(|e| store_err(&e))?;
        let invalid = |e: String| Status::new(Code::InvalidArgument, e);
        let mut what: Vec<String> = Vec::new();
        if req.set_tls {
            set.tls = Some(c.tls);
            what.push(format!("tls={}", c.tls));
        }
        if req.set_acme_email {
            let email = armada_spec::go::trim_space(&c.acme_email).to_string();
            check_email(&email).map_err(invalid)?;
            what.push(format!("acme_email={email}"));
            set.acme_email = email;
        }
        if req.set_acme_ca {
            check_acme_ca(&c.acme_ca).map_err(invalid)?;
            set.acme_ca = c.acme_ca.clone();
            what.push(format!("acme_ca={}", c.acme_ca));
        }
        if req.set_dns_provider {
            let p = if c.dns_provider == "none" {
                ""
            } else {
                c.dns_provider.as_str()
            };
            check_dns_provider(p).map_err(invalid)?;
            set.dns_provider = p.to_string();
            set.dns_provider_set = true;
            what.push(format!(
                "dns_provider={}",
                if p.is_empty() { "none" } else { p }
            ));
        }
        if req.set_dns_token {
            let Some(keys) = &self.0.keys else {
                return Err(Status::new(
                    Code::FailedPrecondition,
                    "this server has no master key to encrypt the token with",
                ));
            };
            let raw = String::from_utf8_lossy(&req.dns_token).into_owned();
            let token = armada_spec::go::trim_space(&raw).as_bytes().to_vec();
            check_dns_token(&token).map_err(invalid)?;
            set.seal_token(keys, &token)
                .map_err(|_| Status::new(Code::Internal, "seal the DNS token"))?;
            what.push("dns_token".to_string());
        }
        if req.set_metrics_port {
            let port = c.metrics_port;
            if !(0..=65535).contains(&port) {
                return Err(invalid(
                    "metrics port must be between 0 (off) and 65535".to_string(),
                ));
            }
            set.metrics_port = Some(i64::from(port));
            what.push(format!("metrics_port={port}"));
        }
        if req.set_node_lost_timeout {
            let secs = c.node_lost_timeout_seconds;
            let d = Duration::from_secs(secs.max(0) as u64);
            if secs < 0 {
                check_node_lost_timeout(Duration::ZERO).map_err(invalid)?;
            }
            check_node_lost_timeout(d).map_err(invalid)?;
            set.node_lost_seconds = secs;
            what.push(format!(
                "node_lost_timeout={}",
                armada_spec::go::format_duration(secs * 1_000_000_000)
            ));
        }
        if !set.dns_provider.is_empty() && !set.has_token() {
            return Err(Status::new(
                Code::FailedPrecondition,
                format!(
                    "DNS provider {} needs a token: armada cluster update --dns-token - < FILE",
                    set.dns_provider
                ),
            ));
        }
        save_settings(self.store(), &set)
            .await
            .map_err(|e| store_err(&e))?;
        let detail = what.join(" ");
        self.store()
            .record_audit(&a.actor(), "cluster.settings", "cluster", &detail)
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "cluster settings changed",
            &[("changed", detail), ("by", a.actor())],
        );
        Ok(true)
    }
}

/// The log settings every assignment carries,
/// the export token opened with the master key.
pub(crate) fn log_settings_proto(
    ls: Option<&Json>,
    keys: Option<&Arc<Keyring>>,
    log: &crate::log::Logger,
) -> armada_proto::armada::v1::LogSettings {
    use armada_proto::armada::v1::{LogExport, LogSettings};
    let Some(ls) = ls else {
        return LogSettings::default();
    };
    let mut p = LogSettings {
        retention_seconds: int(ls, "retentionSeconds"),
        max_bytes: int(ls, "maxBytes"),
        export: None,
    };
    let export = text(ls, "export");
    if export.is_empty() {
        return p;
    }
    let mut e = LogExport {
        format: export,
        endpoint: text(ls, "endpoint"),
        user: text(ls, "user"),
        tenant: text(ls, "tenant"),
        set_at: int(ls, "setAt"),
        token: Vec::new(),
    };
    if let Some(t) = ls.get("token").filter(|t| !t.is_null()) {
        let Some(keys) = keys else {
            log.warn(
                "log export: no master key to open the token with; logs are not sent",
                &[],
            );
            return p;
        };
        let sealed: Option<SealedJson> = serde_json::from_value(t.clone()).ok();
        let opened = sealed
            .ok_or_else(|| "invalid token".to_string())
            .and_then(|s| {
                keys.open(
                    &s.sealed(),
                    TOKEN_SCOPE,
                    LOG_TOKEN_NAME,
                    int(ls, "tokenVersion"),
                )
                .map_err(|e| e.to_string())
            });
        match opened {
            Ok(v) => e.token = v.bytes().to_vec(),
            Err(err) => {
                log.warn("log export: open the token", &[("err", err)]);
                return p;
            }
        }
    }
    p.export = Some(e);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks() {
        assert!(check_acme_ca("letsencrypt").is_ok());
        assert!(check_acme_ca("https://acme.example/dir").is_ok());
        assert!(check_acme_ca("http://acme.example").is_err());
        assert!(check_acme_ca("https://u@acme.example").is_err());
        assert!(check_acme_ca("https://").is_err());
        assert!(check_email("a@b").is_ok());
        assert!(check_email("ab").is_err());
        assert!(check_dns_provider("route53").is_err());
        assert!(check_node_lost_timeout(Duration::from_secs(5)).is_err());
        assert!(check_dns_token(b"a\x01b").is_err());
    }

    #[test]
    fn settings_json() {
        let s = Settings {
            tls: Some(false),
            metrics_port: Some(0),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            r#"{"tls":false,"metricsPort":0}"#
        );
    }
}

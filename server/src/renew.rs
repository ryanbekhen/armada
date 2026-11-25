//! A server's own certificates (Go's certRenewer in internal/daemon's
//! renew.go): the API's, the etcd member's, the user certificate in the
//! machine's shared admin config, and an expired node certificate, each
//! renewed for the key it already has once pki::renew_due says so. Every
//! server holds the CA, so it signs them itself; nothing restarts.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use armada_fsutil::{read_private_file, write_file_atomic};
use armada_pki::{Ca, KIND_NODE, KIND_USER, parse_cert_pem};
use armada_store::Etcd;
use serde::{Deserialize, Serialize};

use crate::log::Logger;
use crate::tls::ServerCert;

/// certRenewInterval: how often a server checks its own certificates.
pub const RENEW_INTERVAL: Duration = Duration::from_secs(12 * 3600);

pub const FILE_SERVER_CERT: &str = "server.crt";
pub const FILE_SERVER_KEY: &str = "server.key";
pub const FILE_NODE_CERT: &str = "node.crt";
/// The etcd member's certificate in its directory.
pub const FILE_MEMBER_CERT: &str = "member.crt";

/// The renewer of one server's certificates.
pub struct Renewer {
    pub data_dir: PathBuf,
    pub ca: Arc<Ca>,
    /// Takes the renewed certificate for the next handshake.
    pub server: Option<Arc<ServerCert>>,
    /// The etcd member's directory, when this server has one.
    pub member_dir: Option<PathBuf>,
    /// The store and the machine's shared admin config, when this server
    /// owns it.
    pub st: Option<Etcd>,
    pub admin_config: Option<PathBuf>,
    pub log: Logger,
    pub now: Arc<dyn Fn() -> SystemTime + Send + Sync>,
}

fn secs(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// The client config of a machine (clientconfig.Config), written as Go's
/// json.MarshalIndent writes it.
#[derive(Serialize, Deserialize)]
struct ClientConfig {
    #[serde(default)]
    servers: Option<Vec<String>>,
    #[serde(default)]
    ca: String,
    #[serde(default)]
    cert: String,
    #[serde(default)]
    key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    ssh: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    space: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    project: String,
}

impl Renewer {
    /// Checks the server's and the member's certificates (Go's check).
    pub fn check(&self) {
        if let Err(e) = self.renew_server() {
            self.log
                .warn("server certificate renewal failed; retrying", &[("err", e)]);
        }
        let Some(dir) = &self.member_dir else { return };
        match self.renew_member(dir) {
            Err(e) => self.log.warn(
                "etcd member certificate renewal failed; retrying",
                &[("err", e)],
            ),
            Ok(true) => self.log.info("etcd member certificate renewed", &[]),
            Ok(false) => {}
        }
    }

    /// Checks every RENEW_INTERVAL until stop.
    pub async fn run(&self, mut stop: tokio::sync::watch::Receiver<bool>) {
        self.renew_admin().await;
        loop {
            tokio::select! {
                _ = crate::stopped(&mut stop) => return,
                _ = tokio::time::sleep(RENEW_INTERVAL) => {
                    self.check();
                    self.renew_admin().await;
                }
            }
        }
    }

    fn renew_server(&self) -> Result<(), String> {
        let path = self.data_dir.join(FILE_SERVER_CERT);
        let b = read_private_file(&path).map_err(|e| e.to_string())?;
        let leaf = parse_cert_pem(&b).map_err(|e| e.to_string())?;
        if !armada_pki::renew_due(&leaf, (self.now)()) {
            return Ok(());
        }
        let cert_pem = self
            .ca
            .reissue(&leaf, Duration::ZERO)
            .map_err(|e| e.to_string())?;
        let key_pem =
            read_private_file(&self.data_dir.join(FILE_SERVER_KEY)).map_err(|e| e.to_string())?;
        // Check the pair before it replaces the file.
        let renewed = ServerCert::new(&self.ca.cert_pem, &cert_pem, &key_pem)?;
        write_file_atomic(&path, &cert_pem, 0o600).map_err(|e| e.to_string())?;
        if let Some(s) = &self.server {
            s.set(&cert_pem, &key_pem)?;
        }
        self.log.info(
            "server certificate renewed",
            &[("expires", renewed.leaf().not_after.to_string())],
        );
        Ok(())
    }

    /// The etcd member's certificate (Go's Member.RenewCert).
    fn renew_member(&self, dir: &Path) -> Result<bool, String> {
        let path = dir.join(FILE_MEMBER_CERT);
        let b = read_private_file(&path).map_err(|e| e.to_string())?;
        let c = parse_cert_pem(&b).map_err(|e| e.to_string())?;
        if !armada_pki::renew_due(&c, (self.now)()) {
            return Ok(false);
        }
        let pem = self
            .ca
            .reissue(&c, Duration::ZERO)
            .map_err(|e| format!("etcd member certificate: {e}"))?;
        write_file_atomic(&path, &pem, 0o600).map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// Renews the user certificate in the machine's shared admin config
    /// once a third of its life is left, or after it expired; the cluster
    /// must still accept the certificate being replaced.
    pub async fn renew_admin(&self) {
        let (Some(st), Some(path)) = (&self.st, &self.admin_config) else {
            return;
        };
        if std::fs::metadata(path).is_err() {
            return; // no shared config on this machine
        }
        match self.renew_admin_config(st, path).await {
            Err(e) => self.log.warn(
                "admin config not renewed; renew it with `sudo armadad user renew`",
                &[("file", path.display().to_string()), ("err", e)],
            ),
            Ok(Some(t)) => self.log.info(
                "admin config renewed",
                &[
                    ("file", path.display().to_string()),
                    ("expires", t.to_string()),
                ],
            ),
            Ok(None) => {}
        }
    }

    async fn renew_admin_config(&self, st: &Etcd, path: &Path) -> Result<Option<i64>, String> {
        let old_meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
        let b = std::fs::read(path).map_err(|e| e.to_string())?;
        let mut cc: ClientConfig =
            serde_json::from_slice(&b).map_err(|e| format!("parse {}: {e}", path.display()))?;
        if cc.servers.as_ref().is_none_or(|s| s.is_empty())
            || cc.ca.is_empty()
            || cc.cert.is_empty()
            || cc.key.is_empty()
        {
            return Err(format!("{} is incomplete", path.display()));
        }
        if cc.space.is_empty() {
            cc.space = std::mem::take(&mut cc.project);
        }
        cc.project.clear();
        let old = parse_cert_pem(cc.cert.as_bytes()).map_err(|e| e.to_string())?;
        if !armada_pki::renew_due(&old, (self.now)()) {
            return Ok(None);
        }
        old.check_signature_from(&self.ca.cert)
            .map_err(|e| format!("its certificate is not from this cluster's CA: {e}"))?;
        let id = old
            .identity()
            .ok()
            .and_then(|i| i.principal())
            .filter(|i| i.kind == KIND_USER)
            .ok_or_else(|| "it holds no user certificate".to_string())?;
        let (key_pem, csr) = armada_pki::new_csr(&id).map_err(|e| e.to_string())?;
        let c = self
            .ca
            .sign_user_csr(&csr, &id.name)
            .map_err(|e| e.to_string())?;
        let renewed = tokio::time::timeout(
            Duration::from_secs(60),
            st.renewed_user(
                &id.name,
                &armada_store::gojson::from_unix(old.not_before),
                &old.serial_string(),
                &c.serial,
            ),
        )
        .await
        .unwrap_or_else(|_| Err(armada_store::Error::other("context deadline exceeded")));
        renewed
            .map_err(|e| format!("the cluster no longer accepts the certificate of {id}: {e}"))?;
        cc.cert = String::from_utf8_lossy(&c.pem).into_owned();
        cc.key = String::from_utf8_lossy(key_pem.expose()).into_owned();
        cc.ca = String::from_utf8_lossy(&self.ca.cert_pem).into_owned();
        let mut out = serde_json::to_vec_pretty(&cc).map_err(|e| e.to_string())?;
        out.push(b'\n');
        write_file_atomic(path, &out, 0o600).map_err(|e| e.to_string())?;
        // A shared config keeps its owner, group, and mode.
        let mode = old_meta.permissions().mode() & 0o777;
        if old_meta.uid() == 0 && mode == 0o640 {
            std::os::unix::fs::chown(path, Some(old_meta.uid()), Some(old_meta.gid()))
                .map_err(|e| e.to_string())?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640))
                .map_err(|e| e.to_string())?;
        }
        Ok(Some(c.not_after))
    }

    /// Re-signs this machine's node certificate, for the same key, if it
    /// has expired; the new serial is recorded first, so a node removed
    /// meanwhile stays out. Call it before the agent starts.
    pub async fn renew_node(&self, st: &Etcd) {
        let path = self.data_dir.join(FILE_NODE_CERT);
        let Ok(b) = read_private_file(&path) else {
            return;
        };
        let Ok(leaf) = parse_cert_pem(&b) else { return };
        if secs((self.now)()) < leaf.not_after {
            return;
        }
        let Ok(id) = leaf.identity() else { return };
        if id.kind != KIND_NODE {
            return;
        }
        let cert_pem = match self.ca.reissue(&leaf, armada_pki::NODE_VALIDITY) {
            Ok(p) => p,
            Err(e) => {
                self.log
                    .warn("node certificate renewal failed", &[("err", e.to_string())]);
                return;
            }
        };
        let Ok(c) = parse_cert_pem(&cert_pem) else {
            return;
        };
        if let Err(e) = st
            .record_node_cert(
                &id.name,
                &armada_store::NodeCert {
                    serial: c.serial_string(),
                    not_after: armada_store::gojson::from_unix(c.not_after),
                },
                "",
            )
            .await
        {
            self.log.warn(
                "expired node certificate not renewed: the node may have been removed; join it again",
                &[("node", id.name.clone()), ("err", e.to_string())],
            );
            return;
        }
        if let Err(e) = write_file_atomic(&path, &cert_pem, 0o600) {
            self.log
                .warn("node certificate renewal failed", &[("err", e.to_string())]);
            return;
        }
        self.log.info(
            "expired node certificate renewed",
            &[("node", id.name), ("expires", c.not_after.to_string())],
        );
    }
}

//! armadad user renew: a user certificate
//! signed with the cluster CA on this server, the name recorded in the
//! cluster's state first.

use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use armada_client::cli::{Ctx, Error, Result};
use armada_client::config;
use armada_pki::{Ca, Identity, KIND_USER, new_csr, parse_cert_pem};

use crate::agentconfig::{FILE_CA_CERT, FILE_CA_KEY};
use crate::state;

fn msg(s: impl Into<String>) -> Error {
    Error::Msg(s.into())
}

/// name recorded with cluster-admin when the cluster has no
/// record of it, within a minute.
async fn record_user(data_dir: &str, name: &str) -> std::result::Result<(), String> {
    let work = async {
        let st = state::state_client(data_dir).await?;
        let s = armada_store::Etcd::new(st.client.clone(), crate::backup::ETCD_PREFIX)
            .await
            .map_err(|e| e.to_string())?;
        s.know_user(name).await.map_err(|e| e.to_string())
    };
    match tokio::time::timeout(Duration::from_secs(60), work).await {
        Ok(r) => r,
        Err(_) => Err("context deadline exceeded".to_string()),
    }
}

pub fn renew(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let path = ctx.g.config_path.clone();
    let data_dir = ctx.str("data-dir");
    let mut cc = config::load(&path).map_err(msg)?;
    let cert = parse_cert_pem(cc.cert.as_bytes()).map_err(|e| msg(format!("{path}: {e}")))?;
    let id: Option<Identity> = cert.identity().ok().and_then(|id| id.principal());
    let id = match id {
        Some(id) if id.kind == KIND_USER => id,
        _ => return Err(msg(format!("{path} does not hold a user certificate"))),
    };
    let (key_pem, csr) = new_csr(&id).map_err(|e| msg(e.to_string()))?;
    let dd = Path::new(&data_dir);
    let ca_pem =
        armada_fsutil::read_private_file(&dd.join(FILE_CA_CERT)).map_err(|e| msg(e.to_string()))?;
    let ca_key =
        armada_fsutil::read_private_file(&dd.join(FILE_CA_KEY)).map_err(|e| msg(e.to_string()))?;
    let ca = Ca::load(&ca_pem, &ca_key).map_err(|e| msg(e.to_string()))?;
    ctx.block_on(record_user(&data_dir, &id.name))
        .map_err(|e| msg(format!("record {id} in the cluster state: {e}")))?;
    let c = ca
        .sign_user_csr(&csr, &id.name)
        .map_err(|e| msg(e.to_string()))?;
    // The config may be another user's copy: keep it theirs.
    let owner = std::fs::metadata(&path)
        .map_err(|e| msg(format!("stat {path}: {}", armada_fsutil::errno_text(&e))))?;
    cc.cert = String::from_utf8_lossy(&c.pem).into_owned();
    cc.key = String::from_utf8_lossy(key_pem.expose()).into_owned();
    cc.ca = String::from_utf8_lossy(&ca.cert_pem).into_owned();
    cc.save_file(&path).map_err(msg)?;
    // SAFETY: geteuid only reads the process's credentials.
    if owner.uid() != unsafe { libc::geteuid() } {
        std::os::unix::fs::chown(&path, Some(owner.uid()), Some(owner.gid())).map_err(|e| {
            msg(format!(
                "give {path} back to its owner: chown {path}: {}",
                armada_fsutil::errno_text(&e)
            ))
        })?;
    }
    let (y, m, d) = armada_node::volbackup::gotime::civil_from_days(c.not_after.div_euclid(86_400));
    ctx.print(&format!(
        "Renewed {id} (valid until {y:04}-{m:02}-{d:02}).\n"
    ));
    Ok(())
}

//! armadad runtime reset: every container Armada runs on the node removed,
//! on the supervisor runtime; a node still on containerd is refused.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use armada_agent::runtime::{Error as RtError, LABEL_MANAGED, LABEL_SYSTEM, Runtime};
use armada_agent::supervisor::{self, Supervisor};
use armada_client::cli::{Ctx, Error, Result};

use crate::agentconfig::{self, RUNTIME_SUPERVISOR};

fn msg(s: impl Into<String>) -> Error {
    Error::Msg(s.into())
}

/// runtimeHint.
fn runtime_hint(rt: &str) -> &'static str {
    if rt == RUNTIME_SUPERVISOR {
        "the runtime pack is installed by armada-server or armada-agent; check sudo armadad doctor"
    } else {
        "systemctl start armada-runtime"
    }
}

/// removeContainers: every container with Armada's labels, then the
/// network sandboxes; the errors of those left.
async fn remove_containers(
    rt: &Supervisor,
    out: &mut String,
) -> std::result::Result<Vec<String>, String> {
    let all = rt.list(&BTreeMap::new()).await.map_err(|e| e.to_string())?;
    let cs: Vec<_> = all
        .into_iter()
        .filter(|c| {
            c.labels.get(LABEL_MANAGED).map(String::as_str) == Some("true")
                || c.labels.get(LABEL_SYSTEM).is_some_and(|v| !v.is_empty())
        })
        .collect();
    let mut errs = Vec::new();
    for c in &cs {
        let _ = rt.stop(&c.id, Duration::from_secs(10)).await;
        match rt.remove(&c.id).await {
            Ok(()) | Err(RtError::NotFound) => {}
            Err(e) => errs.push(format!("{}: {e}", c.name)),
        }
    }
    out.push_str(&format!(
        "Removed {} container(s).\n",
        cs.len() - errs.len()
    ));
    match rt.list_sandboxes().await {
        Err(e) => errs.push(format!("network sandboxes: {e}")),
        Ok(sbs) => {
            let mut removed = 0;
            for s in sbs {
                match rt.remove_sandbox(&s.id).await {
                    Ok(()) => removed += 1,
                    Err(e) => errs.push(format!("network sandbox {}: {e}", s.id)),
                }
            }
            if removed > 0 {
                out.push_str(&format!("Removed {removed} network sandbox(es).\n"));
            }
        }
    }
    Ok(errs)
}

/// The node's supervisor runtime, the pack installed first.
fn open_supervisor(
    data_dir: &str,
    ac: &agentconfig::AgentConfig,
) -> std::result::Result<Supervisor, String> {
    crate::pack::install_pack(&crate::paths(data_dir))?;
    let mut cfg = supervisor::Config::new(
        PathBuf::from(data_dir),
        PathBuf::from(crate::run_dir()),
        armada_agent::log::Logger::discard(),
    );
    cfg.subnet = ac.container_subnet.clone();
    Supervisor::new(cfg)
}

/// armadad runtime reset.
pub fn reset(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let data_dir = ctx.str("data-dir");
    let ac = agentconfig::load(&data_dir)?;
    ac.check_runtime().map_err(msg)?;
    if ac.runtime != RUNTIME_SUPERVISOR {
        return Err(msg(agentconfig::CONTAINERD_NODE));
    }
    let rt = open_supervisor(&data_dir, &ac).map_err(msg)?;
    let mut out = String::new();
    let res = ctx.block_on(async {
        match tokio::time::timeout(Duration::from_secs(10), rt.ping()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return Err(format!(
                    "container runtime: {e} ({})",
                    runtime_hint(&ac.runtime)
                ));
            }
            Err(_) => {
                return Err(format!(
                    "container runtime: context deadline exceeded ({})",
                    runtime_hint(&ac.runtime)
                ));
            }
        }
        let mut errs = remove_containers(&rt, &mut out).await?;
        if let Err(e) = armada_agent::dnsprocess::stop_units().await {
            errs.push(format!("armada-dns: {e}"));
        }
        Ok(errs)
    });
    let mut errs = match res {
        Ok(e) => e,
        Err(e) => {
            ctx.print(&out);
            return Err(msg(e));
        }
    };
    if !ac.network.is_empty() {
        match armada_agent::clusternet::remove() {
            Err(e) => errs.push(format!("cluster network: {e}")),
            Ok(()) => out.push_str(
                "Removed the cluster network interface armada-net and its firewall rules.\n",
            ),
        }
    }
    ctx.print(&out);
    if errs.is_empty() {
        Ok(())
    } else {
        Err(msg(errs.join("\n")))
    }
}

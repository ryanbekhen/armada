//! armadad endpoint show|set (Go's endpoint.go, ADR 0050).

use std::path::Path;

use armada_client::cli::{Ctx, Error, Result};

use crate::agentconfig::{self, AgentConfig, FILE_SERVER_CERT, NETWORK_MESH};
use crate::{netutil, systemd};

/// endpointNone: `set none`, behind NAT.
const ENDPOINT_NONE: &str = "none";

/// announcedEndpoint.
pub fn announced(ac: &AgentConfig) -> String {
    if ac.behind_nat {
        return String::new();
    }
    if !ac.endpoint.is_empty() || ac.network.is_empty() {
        return ac.endpoint.clone();
    }
    match netutil::detect_endpoint() {
        Ok(ep) => ep.to_string(),
        Err(_) => String::new(),
    }
}

/// restartService: the machine's active Armada service, restarted; the
/// unit, or "" when none runs.
fn restart_service() -> std::result::Result<String, (String, String)> {
    for unit in ["armada-server", "armada-agent"] {
        if systemd::unit_active(unit) {
            return match systemd::systemctl(&["restart", unit]) {
                Ok(()) => Ok(unit.to_string()),
                Err(e) => Err((unit.to_string(), e)),
            };
        }
    }
    Ok(String::new())
}

pub fn show(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let data_dir = ctx.str("data-dir");
    let ac = agentconfig::load(&data_dir)?;
    let ep = announced(&ac);
    let line = if ac.behind_nat {
        "none: behind NAT (set); this machine starts every connection to other sites".to_string()
    } else if !ac.endpoint.is_empty() {
        format!("{} (set)", ac.endpoint)
    } else if !ep.is_empty() {
        format!("{ep} (found on this machine's interfaces)")
    } else if ac.network.is_empty() {
        "none: this cluster has no cluster network".to_string()
    } else {
        "none: no single public IPv4 address on this machine's interfaces; set one with `armadad endpoint set IP`".to_string()
    };
    ctx.print(&format!("{line}\n"));
    Ok(())
}

pub fn set(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let data_dir = ctx.str("data-dir");
    let nat = args[0] == ENDPOINT_NONE;
    let mut ep = String::new();
    if !nat {
        ep = netutil::check_endpoint(&args[0])?.to_string();
    }
    let ac = agentconfig::load(&data_dir)?;
    if nat && std::fs::metadata(Path::new(&data_dir).join(FILE_SERVER_CERT)).is_ok() {
        return Err(Error::Msg(
            "this machine is a control plane server, which needs an endpoint other sites reach it at".into(),
        ));
    }
    if ac.network.is_empty() {
        return Err(Error::Msg("this cluster has no cluster network: its nodes reach each other only over the private network".into()));
    }
    if ac.network == NETWORK_MESH && ac.endpoint.is_empty() && !ac.behind_nat {
        return Err(Error::Msg("agent.json records no endpoint for this mesh node; it is not a node of this Armada's mesh".into()));
    }
    let (endpoint, behind_nat) = if nat {
        ctx.print("This machine is behind NAT: it announces no endpoint.\n");
        (String::new(), true)
    } else {
        ctx.print(&format!("Endpoint set to {ep}.\n"));
        (ep, false)
    };
    agentconfig::update(&data_dir, |c| {
        c.endpoint = endpoint;
        c.behind_nat = behind_nat;
        Ok(())
    })?;
    if ctx.bool("no-restart") {
        ctx.print("Restart armada-server or armada-agent to announce it.\n");
        return Ok(());
    }
    match restart_service() {
        Err((unit, e)) => Err(Error::Msg(format!("restart {unit}: {e}"))),
        Ok(unit) if unit.is_empty() => {
            ctx.print("No Armada service runs; it announces the endpoint when it starts.\n");
            Ok(())
        }
        Ok(unit) => {
            ctx.print(&format!("Restarted {unit}: it announces the endpoint, and the other nodes follow within seconds.\n"));
            Ok(())
        }
    }
}

//! armadad runtime: the runtime pack installed. It runs nothing: nodes
//! run their containers on the supervisor runtime, through armada-shim and
//! armada-node (ADR 0046).

use armada_client::cli::{Ctx, Error, Result};

use crate::agentconfig::{self, RUNTIME_SUPERVISOR};
use crate::pack;

pub fn run(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let data_dir = ctx.str("data-dir");
    let bin_dir = ctx.str("bin-dir");
    let ac = match agentconfig::load(&data_dir) {
        Err(e) if e.not_found => {
            let _ = writeln!(ctx.err, "{data_dir} is not initialized; nothing to run");
            return Ok(());
        }
        r => r?,
    };
    ac.check_runtime()?;
    let p = crate::paths(&data_dir);
    if !bin_dir.is_empty() {
        pack::use_bin_dir(&p.bundle(), &bin_dir)?;
    }
    pack::install_pack(&p)?;
    if ac.runtime != RUNTIME_SUPERVISOR {
        return Err(Error::Msg(agentconfig::CONTAINERD_NODE.to_string()));
    }
    let _ = writeln!(
        ctx.err,
        "this node runs containers on the supervisor runtime; the runtime pack is installed, nothing to run"
    );
    Ok(())
}

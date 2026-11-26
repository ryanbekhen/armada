//! armadad runtime: the runtime pack installed (Go's runtime.go). It runs
//! nothing: supervisor nodes run their containers through armada-shim and
//! armada-node, and containerd, which nodes set up before ran here, is no
//! longer in the pack (ADR 0046, ADR 0055).

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
        return Err(Error::Msg(containerd_gone()));
    }
    let _ = writeln!(
        ctx.err,
        "this node runs containers without containerd (runtime: supervisor); the runtime pack is installed, nothing to run"
    );
    Ok(())
}

/// What armada-runtime says on a node set up on containerd.
pub fn containerd_gone() -> String {
    "this node runs containers on containerd, which this armadad no longer carries (ADR 0055): move the node to the supervisor runtime with v0.1.0-alpha.42 first (armada node drain, armadad runtime migrate --to supervisor, armada node resume), or remove the node and join it again".to_string()
}

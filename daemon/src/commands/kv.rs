//! armadad kv: this server's armada-kv member (armada-kv.service, ADR
//! 0057), on a server of a cluster whose state is in armada-kv (`armadad
//! init`, the state's move from etcd, or `armadad server join` to such a
//! cluster). It works
//! the member out as `armadad etcd` does (name, directory, addresses,
//! certificate), refuses while another process holds the member's
//! database, serves until SIGTERM or SIGINT, then stops in order.

use std::path::Path;

use armada_client::cli::{Ctx, Error, Result};
use armada_server::log::Logger;

use crate::agentconfig::FILE_SERVER_CERT;
use crate::kvmember::{self, EXIT_OTHER_STORE, Fresh};
use crate::{signals, state};

pub fn run(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let data_dir = ctx.str("data-dir");
    if let Err(e) = std::fs::metadata(Path::new(&data_dir).join(FILE_SERVER_CERT))
        && e.kind() == std::io::ErrorKind::NotFound
    {
        return Err(Error::Msg(format!(
            "{data_dir} is not a server's data directory; run `armadad init` or `armadad server join`"
        )));
    }
    if state::Store::of(&data_dir) != state::Store::Kv {
        // The server's member is etcd's (armada-etcd.service): this unit
        // has nothing to run and stays stopped.
        let _ = writeln!(
            ctx.err,
            "this server keeps the cluster's state in etcd (armada-etcd); armada-kv has nothing to run"
        );
        return Err(Error::Exit(EXIT_OTHER_STORE));
    }
    let log = Logger::stderr(false);
    let rt = crate::commands::server::runtime()?;
    let mut stop = signals::stop_on_signals();
    rt.block_on(async {
        let mut cfg = kvmember::kv_config(&data_dir)?;
        let mut m = kvmember::start(&mut cfg, Fresh::Refuse).await?;
        log.info(
            "armada-kv member serving",
            &[
                ("name", cfg.name.clone()),
                ("client", m.client_url.clone()),
                ("peer", m.peer_url.clone()),
            ],
        );
        let r = m.wait(&mut stop).await;
        m.shutdown().await;
        match &r {
            Ok(()) => log.info("armada-kv member stopped", &[]),
            Err(e) => log.warn("armada-kv member failed", &[("err", e.clone())]),
        }
        r
    })
    .map_err(Error::Msg)
}

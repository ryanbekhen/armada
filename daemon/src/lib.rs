//! armadad (ADR 0027, ADR 0055): every command that runs on a machine, on
//! the client's command framework (armada_client::cli). Some need neither
//! the running server or agent, nor the cluster's state, nor the container
//! runtime: version, endpoint, etcd, upgrade, and runtime. Some need the
//! cluster's state but not the running server or agent: backup, backup
//! list, restore, user renew, and runtime-log. The rest set a machine up
//! and run it: init, join, server join, server (armada-server's terms on
//! the member armada-etcd.service runs), agent (armada-agent on the
//! supervisor runtime), runtime reset, and doctor.

pub mod agentconfig;
pub mod backup;
pub mod commands;
pub mod download;
pub mod etcdmember;
pub mod gofs;
pub mod gopath;
pub mod hooks;
pub mod joinclient;
pub mod machine;
pub mod manifest;
pub mod netutil;
pub mod pack;
pub mod signals;
pub mod state;
pub mod systemd;
pub mod tar;
pub mod tree;

use std::io::{Read, Write};

/// Resolves once the signal turns true; never when its sender is gone
/// without turning it.
pub async fn stopped(rx: &mut tokio::sync::watch::Receiver<bool>) {
    if rx.wait_for(|v| *v).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// The node's runtime state on tmpfs.
pub fn run_dir() -> String {
    hooks::get("RUN_DIR").unwrap_or_else(|| "/run/armada".to_string())
}

pub fn paths(data_dir: &str) -> pack::Paths {
    pack::Paths {
        data_dir: data_dir.into(),
        run_dir: run_dir().into(),
    }
}

/// The --config default.
pub fn config_default() -> String {
    armada_client::config::default_path()
}

/// Execute: the tree run with args; the exit code.
pub fn execute(args: &[String]) -> i32 {
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let code = run(args, &mut stdin, &mut stdout, &mut stderr);
    let _ = stdout.flush();
    code
}

/// Run: the command tree with args.
pub fn run(args: &[String], stdin: &mut dyn Read, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let mut t = tree::root();
    if args.iter().any(|a| a == "__completeNoDesc") {
        armada_client::cli::complete::CALLED_NO_DESC.with(|c| c.set(true));
    }
    armada_client::cli::run(&mut t, args, |_| Ok(()), stdin, out, err)
}

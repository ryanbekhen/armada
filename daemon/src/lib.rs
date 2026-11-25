//! armadad in Rust (ADR 0055, pull request 18): the command tree of Go's
//! internal/daemon with the same names, flags, help, examples, output,
//! and exit codes, on the client's command framework (armada_client::cli,
//! as Go's daemon runs cli.Run). This first part (18a) has the commands
//! that need neither the running server or agent, nor the cluster's state,
//! nor the container runtime's driver: version, endpoint, etcd, upgrade,
//! and runtime; the others say they come with 18b.

pub mod agentconfig;
pub mod commands;
pub mod download;
pub mod etcdmember;
pub mod gofs;
pub mod gopath;
pub mod hooks;
pub mod netutil;
pub mod pack;
pub mod systemd;
pub mod tar;
pub mod tree;

use std::io::{Read, Write};

/// runDir: the node's runtime state on tmpfs.
pub fn run_dir() -> String {
    hooks::get("RUN_DIR").unwrap_or_else(|| "/run/armada".to_string())
}

/// runtimePaths.
pub fn paths(data_dir: &str) -> pack::Paths {
    pack::Paths {
        data_dir: data_dir.into(),
        run_dir: run_dir().into(),
    }
}

/// The --config default (clientconfig.DefaultPath).
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

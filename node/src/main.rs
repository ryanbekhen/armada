//! `armada-node` is Armada's node agent moving to Rust in steps (ADR 0054).
//! It runs as subcommands the Go agent hands work to, each one checked
//! against the Go code it replaces:
//!
//!   armada-node proxy render   HAProxy's configuration (src/proxy)
//!   armada-node net ...        the cluster network's plan, key, peer list, firewall, tunnels,
//!                              and routes (src/net)
//!   armada-node runtime ...    containers' OCI runtime specs and their checks (src/runtime)

mod names;
mod net;
mod proxy;
mod runtime;

use std::process::ExitCode;

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["proxy", "render"] => proxy::render_command(),
        ["net", "plan"] => net::plan_command(),
        ["net", "key", path] => net::key_command(path, false),
        ["net", "key", "rotate", path] => net::key_command(path, true),
        ["net", "cache", op, path] => net::cache_command(op, path),
        ["net", "firewall", op] => net::firewall::command(op),
        ["net", op @ ("apply" | "up")] => net::apply::command(op),
        ["net", "remove"] => net::apply::remove_command(),
        ["net", "probe"] => net::probe::command(),
        ["net", "unreachable"] => net::apply::unreachable_command(),
        ["net", "diagnose"] => net::diagnose::command(),
        ["net", "netlink", op] => net::nlcheck::command(op),
        ["runtime", "spec"] => runtime::spec_command(),
        ["runtime", "check"] => runtime::check_command(),
        ["runtime", "seccomp"] => runtime::seccomp_command(),
        ["runtime", "apparmor", name] => runtime::apparmor_command(name),
        _ => Err(format!(
            "unknown command {args:?}; try: proxy render, net plan, net key [rotate] PATH, net cache save|load PATH, net firewall nft|iptables|apply|remove, net apply|up|remove, net probe, net unreachable, net diagnose, net netlink encode|show|wg-parse, runtime spec|check|seccomp, runtime apparmor NAME"
        )),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("armada-node: {e}");
            ExitCode::FAILURE
        }
    }
}

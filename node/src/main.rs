//! `armada-node` is Armada's node agent moving to Rust in steps (ADR 0054).
//! It runs as subcommands the Go agent hands work to, each one checked
//! against the Go code it replaces:
//!
//!   armada-node proxy render   HAProxy's configuration (src/proxy)
//!   armada-node net ...        the cluster network's plan, key, peer list, firewall, tunnels,
//!                              and routes (src/net)
//!   armada-node runtime ...    containers' OCI runtime specs and their checks, image pulls and
//!                              the image store, containers' root filesystems, bundles,
//!                              shims, statistics, dials from containers, and runc exec
//!                              (src/runtime)

mod names;
mod net;
mod proxy;
mod runtime;
mod volume;

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
        ["runtime", "pull", rest @ ..] => runtime::image::pull_command(rest),
        ["runtime", "images", root] => runtime::image::images_command(root),
        ["runtime", "prune", root] => runtime::image::prune_command(root),
        ["runtime", "mounts", root, image] => runtime::image::mounts_command(root, image),
        ["runtime", "apply", rest @ ..] => runtime::image::apply_command(rest),
        ["runtime", "prepare", root] => runtime::container::prepare_command(root),
        ["runtime", "release", root, key] => runtime::container::release_command(root, key),
        ["runtime", "snapshots", root] => runtime::container::snapshots_command(root),
        ["runtime", "bundle", rest @ ..] => runtime::container::bundle_command(rest),
        ["runtime", "shim", op] => runtime::container::shim_command(op),
        ["runtime", "stats"] => runtime::container::stats_command(),
        ["runtime", "dial"] => runtime::container::dial_command(),
        ["runtime", "exec"] => runtime::container::exec::exec_command(),
        ["runtime", "reference"] => runtime::image::reference_command(),
        ["runtime", "platforms"] => runtime::image::platforms_command(),
        ["runtime", "proxy", url] => runtime::image::proxy_command(url),
        ["volume", rest @ ..] => volume::command(rest),
        _ => Err(format!(
            "unknown command {args:?}; try: proxy render, net plan, net key [rotate] PATH, net cache save|load PATH, net firewall nft|iptables|apply|remove, net apply|up|remove, net probe, net unreachable, net diagnose, net netlink encode|show|wg-parse, runtime spec|check|seccomp, runtime apparmor NAME, runtime pull ROOT [--extra-ca FILE], runtime images|prune ROOT, runtime mounts ROOT IMAGE, runtime apply DIR [--media-type MT] [--lower DIR]..., runtime prepare ROOT, runtime release ROOT KEY, runtime snapshots ROOT, runtime bundle create|remove|records|labels, runtime shim call|start|abandon, runtime stats, runtime dial, runtime exec, runtime reference|platforms, runtime proxy URL"
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

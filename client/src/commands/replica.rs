//! armada replica.

use armada_proto::armada::v1::{AppStatus, ReplicaStatus, StatusRequest, StatusResponse};
use armada_spec as spec;

use super::app::replica_state;
use super::{Output, ago, dash, now_nanos, output_flag, print_json, round_second, rpc_err, since};
use crate::cli::tabwriter::TabWriter;
use crate::cli::{Args, Ctx, Node, Result, Tree};
use crate::rpc;

pub fn add(t: &mut Tree) -> usize {
    let n = t.add(
        0,
        Node::new("replica", "List the replicas of apps")
            .aliases(&["replicas"])
            .long("A replica is one running copy of an app, with its containers, on one node.\n`armada replica list` names them the way --replica takes them.")
            .noun(),
    );
    t.add(
        n,
        Node::new("list [APP]", "List an app's replicas, or every app's")
            .aliases(&["ls"])
            .long("List replicas with their short name, node, state, revision, and\ncontainers. The short name is what `--replica` takes in `armada app exec`\nand `armada app logs`, and the containers what `--container` takes.")
            .example("  armada replica list api\n  armada app exec api --replica k3p9x --container log-ship")
            .args(Args::Max(1))
            .flag(output_flag(false))
            .run(list),
    );
    n
}

fn list(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    let o = Output::of(ctx, false);
    o.check()?;
    let mut admin = ctx.admin()?;
    let mut req = StatusRequest::default();
    if args.len() == 1 {
        req.app = args[0].clone();
    }
    let resp = rpc!(ctx, admin, status, req).map_err(rpc_err)?;
    let apps: Vec<AppStatus> = resp
        .apps
        .into_iter()
        .filter(|a| args.len() == 1 || ctx.listed(&a.name))
        .collect();
    if o.json() {
        return print_json(
            ctx,
            &StatusResponse {
                apps,
                ..Default::default()
            },
        );
    }
    let text = print_replicas(&apps, args.is_empty(), ctx.g.all_spaces, now_nanos());
    ctx.print(&text);
    Ok(())
}

fn print_replicas(apps: &[AppStatus], with_app: bool, with_space: bool, now: i128) -> String {
    let mut tw = TabWriter::new(0, 2);
    let mut head = "REPLICA\tNODE\tSTATE\tREVISION\tCONTAINERS\tRESTARTS\tAGE".to_string();
    if with_app {
        head = format!("APP\t{head}");
    }
    if with_space {
        head = format!("SPACE\t{head}");
    }
    tw.write(&format!("{head}\n"));
    for a in apps {
        let (space, name) = spec::validate::split_app_id(&a.name).unwrap_or_default();
        for r in &a.replicas {
            let age = ago(r.created_at.as_ref(), now);
            let mut line = format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                short_replica(&r.id),
                dash(&r.node_id),
                replica_state(r),
                short_revision(&r.revision),
                container_list(r),
                restarts(r, now),
                age.strip_suffix(" ago").unwrap_or(&age)
            );
            if with_app {
                line = format!("{name}\t{line}");
            }
            if with_space {
                line = format!("{space}\t{line}");
            }
            tw.write(&format!("{line}\n"));
        }
    }
    tw.finish()
}

fn restarts(r: &ReplicaStatus, now: i128) -> String {
    let mut n = r.restarts.to_string();
    if let Some(t) = &r.last_restart_at
        && r.restarts > 0
    {
        n.push_str(&format!(
            " ({} ago)",
            armada_spec::go::format_duration(round_second(since(t, now)))
        ));
    }
    n
}

/// The ID after its last hyphen.
pub fn short_replica(id: &str) -> &str {
    match id.rfind('-') {
        Some(i) => &id[i + 1..],
        None => id,
    }
}

/// r12 for api--r12.
pub fn short_revision(rev: &str) -> &str {
    match rev.rfind("--") {
        Some(i) => &rev[i + 2..],
        None => rev,
    }
}

/// a replica's containers, init containers last.
fn container_list(r: &ReplicaStatus) -> String {
    if r.containers.is_empty() {
        return "-".to_string();
    }
    let mut s = r.containers.join(", ");
    if !r.init_containers.is_empty() {
        s.push_str(&format!(" (init: {})", r.init_containers.join(", ")));
    }
    s
}

//! armada space (Go's spaces.go).

use armada_proto::armada::v1::{
    CreateSpaceRequest, DeleteSpaceRequest, ListSpacesRequest, ListSpacesResponse, SpaceInfo,
    UpdateSpaceRequest,
};
use armada_spec as spec;
use armada_spec::go;

use super::{Output, ago, dash, now_nanos, output_flag, print_json, rpc_err};
use crate::cli::flags::Flag;
use crate::cli::tabwriter::TabWriter;
use crate::cli::{Args, Ctx, Error, Node, Result, Tree};
use crate::rpc;

const SPACE_LONG: &str =
    "Spaces hold apps, jobs, secrets, domains, and volumes (ADR 0026). Names only
need to be unique within a space. Every cluster has the space default,
which holds everything deployed without --space.

Commands work in the space `armada space use` saved, or the one --space
(or ARMADA_SPACE) names, else default. An app of another space can also
be named NAME.SPACE, which is how events and the internal host name
(NAME.SPACE.internal) show it. Lists take -A for every space.

On a cluster with a cluster network, containers reach other apps only
through their internal names, resolve only their own space's names, and
the containers of every space but default are kept away from the nodes,
the private network, and the cloud's metadata service (network isolation;
for default, turn it on with `armada space update default --network-isolation`).";

pub fn add(t: &mut Tree) -> usize {
    let n = t.add(
        0,
        Node::new("space", "Manage spaces")
            .aliases(&["spaces"])
            .long(SPACE_LONG)
            .noun(),
    );
    t.add(
        n,
        Node::new("create NAME", "Create a space")
            .args(Args::Exact(1))
            .example("  armada space create shop")
            .run(create),
    );
    t.add(
        n,
        Node::new("list", "List spaces")
            .aliases(&["ls"])
            .args(Args::No)
            .example("  armada space list")
            .flag(output_flag(false))
            .run(list),
    );
    t.add(
        n,
        Node::new("update SPACE --network-isolation[=false]", "Change a space's settings")
            .long("Change a space's settings (cluster-admin only).\n\n--network-isolation keeps the space's containers away from the nodes, the\ncontrol plane, the private network, and the cloud's metadata service: they\nreach the internet, their node's DNS server, and internal and public\ningress (ADR 0026). Every space but default always has it; turn it on for\ndefault once its apps no longer need the private network. It needs the\ncluster network.")
            .args(Args::Exact(1))
            .example("  armada space update default --network-isolation")
            .flag(Flag::bool(
                "network-isolation",
                None,
                false,
                "keep the space's containers away from the platform and the private network",
            ))
            .run(update),
    );
    t.add(
        n,
        Node::new("show NAME", "Show a space's settings")
            .args(Args::Exact(1))
            .example("  armada space show shop")
            .flag(output_flag(false))
            .run(show),
    );
    t.add(
        n,
        Node::new("use NAME", "Work in a space: commands without --space use it")
            .long("Save NAME in the client config (--config) as the space commands work in when\nneither --space nor ARMADA_SPACE names one. `armada space use default`\ngoes back to the default space.")
            .args(Args::Exact(1))
            .example("  armada space use shop      # later commands work in shop\n  armada space use default")
            .run(use_space),
    );
    t.add(
        n,
        Node::new("delete NAME", "Delete an empty space")
            .aliases(&["rm"])
            .long("Delete a space. It must be empty: delete its apps, jobs, secrets, and\nvolumes first. The default space cannot be deleted.")
            .args(Args::Exact(1))
            .example("  armada space delete shop   # once its apps, jobs, and volumes are gone")
            .run(delete),
    );
    n
}

fn create(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut admin = ctx.admin()?;
    let req = CreateSpaceRequest {
        name: args[0].clone(),
    };
    let p = rpc!(ctx, admin, create_space, req).map_err(rpc_err)?;
    ctx.print(&format!("Created space {}.\n", p.name));
    Ok(())
}

fn update(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut req = UpdateSpaceRequest {
        name: args[0].clone(),
        ..Default::default()
    };
    if ctx.changed("network-isolation") {
        req.network_isolation = Some(ctx.bool("network-isolation"));
    }
    if req.network_isolation.is_none() {
        return Err("nothing to change: give --network-isolation".into());
    }
    let mut admin = ctx.admin()?;
    let p = rpc!(ctx, admin, update_space, req).map_err(rpc_err)?;
    let state = if p.network_isolation { "on" } else { "off" };
    ctx.print(&format!("Space {}: network isolation {state}.\n", p.name));
    Ok(())
}

fn list_spaces(ctx: &mut Ctx<'_>) -> Result<ListSpacesResponse> {
    let mut admin = ctx.admin()?;
    rpc!(ctx, admin, list_spaces, ListSpacesRequest {}).map_err(rpc_err)
}

fn space_network(p: &SpaceInfo) -> &'static str {
    if p.network_isolation {
        "isolated"
    } else {
        "open"
    }
}

fn list(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let resp = list_spaces(ctx)?;
    if o.json() {
        return print_json(ctx, &resp);
    }
    let now = now_nanos();
    let mut tw = TabWriter::new(0, 2);
    tw.write("SPACE\tAPPS\tNETWORK\tCREATED\tBY\n");
    for p in &resp.spaces {
        tw.write(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            p.name,
            p.apps,
            space_network(p),
            ago(p.created_at.as_ref(), now),
            dash(&p.created_by)
        ));
    }
    let out = tw.finish();
    ctx.print(&out);
    Ok(())
}

fn use_space(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let name = args[0].clone();
    if !spec::validate::valid_space(&name) {
        return Err(Error::Msg(format!("invalid space {}", go::quote(&name))));
    }
    if name != spec::validate::DEFAULT_SPACE {
        let resp = list_spaces(ctx)?;
        if !resp.spaces.iter().any(|p| p.name == name) {
            return Err(Error::Msg(format!("space {name} not found")));
        }
    }
    let mut cc = crate::config::load(&ctx.g.config_path).map_err(Error::Msg)?;
    cc.space = if name == spec::validate::DEFAULT_SPACE {
        String::new()
    } else {
        name.clone()
    };
    cc.save_file(&ctx.g.config_path).map_err(Error::Msg)?;
    ctx.print(&format!("Using space {name}.\n"));
    Ok(())
}

fn show(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let resp = list_spaces(ctx)?;
    for p in &resp.spaces {
        if p.name != args[0] {
            continue;
        }
        if o.json() {
            return print_json(ctx, p);
        }
        let mut tw = TabWriter::new(0, 2);
        tw.write(&format!(
            "Space:\t{}\nApps:\t{}\nNetwork:\t{}\nCreated:\t{} by {}\n",
            p.name,
            p.apps,
            space_network(p),
            ago(p.created_at.as_ref(), now_nanos()),
            dash(&p.created_by)
        ));
        let out = tw.finish();
        ctx.print(&out);
        return Ok(());
    }
    Err(Error::Msg(format!("space {} not found", args[0])))
}

fn delete(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut admin = ctx.admin()?;
    let req = DeleteSpaceRequest {
        name: args[0].clone(),
    };
    rpc!(ctx, admin, delete_space, req).map_err(rpc_err)?;
    ctx.print(&format!("Deleted space {}.\n", args[0]));
    Ok(())
}

//! armada node and armada server.

use std::collections::BTreeMap;

use armada_proto::armada::v1::{
    CordonNodeRequest, CreateJoinTokenRequest, LabelNodeRequest, ListServersRequest,
    ListServersResponse, ListVolumesRequest, NodeStatus, RemoveNodeRequest, RemoveServerRequest,
    RestrictNodeRequest, RotateNodeKeyRequest, SetNodeRelayRequest, SetNodeSiteRequest,
    StatusRequest, StatusResponse,
};
use armada_spec as spec;
use armada_spec::go;

use super::{
    Output, dash, date_only, go_time, human_bytes, now_nanos, output_flag, print_json, rfc3339,
    round_second, rpc_err, since,
};
use crate::cli::flags::Flag;
use crate::cli::tabwriter::TabWriter;
use crate::cli::{Args, Ctx, Error, Node, Result, Tree};
use crate::rpc;

/// How often `node delete` checks for remaining replicas.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// InstallURL: where the installer is published.
const INSTALL_URL: &str = "https://raw.githubusercontent.com/ryanbekhen/armada/main/install.sh";

const JOIN_LONG: &str =
    "Create a single-use join token and print the command to run on the new node.

The token is a credential: anyone holding it before it expires can add a node.
Send it over a trusted channel. Only a hash is stored on the server.

In a mesh cluster (armadad init --network mesh), and for a machine of another
site than the leader's (--site, ADR 0050), the join listener faces the public
on the leader's endpoint, open only while such a token is unused and
unexpired: these tokens last 10 minutes by default and at most an hour, and
--from makes the listener answer only the address the machine joins from.";

/// Node join-token and server join-token.
fn join_token_node(server: bool) -> Node {
    let mut long = JOIN_LONG.to_string();
    let (short, ttl, example, run): (&str, &str, &str, crate::cli::Run) = if server {
        long.push_str("\n\nA server token hands the new server the cluster CA key and the secrets master\nkey: it lasts 15 minutes by default (10 over the leader's public address) and\nat most an hour.\n\nA server may join another site than the leader's (--site): its etcd member and\nAPI are reached over WireGuard between the sites. Every write waits for a\nmajority of servers, so keep the servers in one site, or in sites close\ntogether.");
        (
            "Create a single-use token that adds a control plane server, and print the join command",
            "token lifetime (1m to 1h; default 15m, 10m over the leader's public address)",
            "  armada server join-token          # prints the armadad server join command\n  armada server join-token --ttl 30m",
            |ctx, args| join_token(ctx, args, true),
        )
    } else {
        (
            "Create a single-use token that adds a node, and print the join command",
            "token lifetime (1m to 24h, joins over the leader's public address 1h; default 1h, 10m for those)",
            "  armada node join-token                       # prints the armadad join command\n  armada node join-token --label disk=ssd      # the node joins with a label\n  armada node join-token --ttl 30m",
            |ctx, args| join_token(ctx, args, false),
        )
    };
    Node::new("join-token", short)
        .long(&long)
        .args(Args::No)
        .example(example)
        .flag(Flag::duration("ttl", None, 0, ttl))
        .flag(Flag::string("from", None, "", "joins over the leader's public address (mesh clusters, other sites): the IP address the machine joins from; the join listener answers no other"))
        .flag(Flag::string_array("label", None, "label KEY=VALUE for the node that joins with the token (repeatable)"))
        .flag(Flag::string("site", None, "", "the site the machine joins (ADR 0050); default: the cluster's first site"))
        .run(run)
}

/// `^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`.
fn release_tag(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('v') else {
        return false;
    };
    let (core, pre) = match rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (rest, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()))
        && pre.is_none_or(|p| {
            !p.is_empty() && p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.')
        })
}

/// The line that installs Armada, pinned to the server's
/// release when it is one.
fn install_command(version: &str) -> String {
    let env = if release_tag(version) {
        format!("ARMADA_VERSION={version} ")
    } else {
        String::new()
    };
    format!("curl -fsSL {INSTALL_URL} | sudo {env}sh")
}

/// KEY=VALUE, both checked.
fn parse_label(s: &str) -> std::result::Result<(String, String), String> {
    let Some((k, v)) = s.split_once('=') else {
        return Err(format!(
            "label {}: want KEY=VALUE (or KEY- to remove)",
            go::quote(s)
        ));
    };
    spec::validate::check_admin_label(k, v)?;
    Ok((k.to_string(), v.to_string()))
}

/// k=v,k2=v2 sorted by key.
fn format_labels(labels: &BTreeMap<String, String>) -> String {
    let mut keys: Vec<&String> = labels.keys().collect();
    keys.sort();
    keys.iter()
        .map(|k| format!("{k}={}", labels[*k]))
        .collect::<Vec<_>>()
        .join(",")
}

fn join_token(ctx: &mut Ctx<'_>, _: &[String], server: bool) -> Result {
    let mut admin = ctx.admin()?;
    let site = ctx.str("site");
    let mut req = CreateJoinTokenRequest {
        ttl_seconds: ctx.duration("ttl") / go::SECOND,
        server,
        from: ctx.str("from"),
        site: site.clone(),
        ..Default::default()
    };
    for l in ctx.strs("label") {
        let (k, v) = parse_label(&l)?;
        req.labels.insert(k, v);
    }
    let resp = rpc!(ctx, admin, create_join_token, req).map_err(rpc_err)?;
    let (sub, unit) = if server {
        ("server join", "armada-server")
    } else {
        ("join", "armada-agent")
    };
    let mut out = format!(
        "Token (works once, expires {}, shown once): {}\n\n",
        rfc3339(&go_time(resp.expires_at.as_ref(), true)),
        resp.token
    );
    let mut where_ = "same private network".to_string();
    if let Some((a, _)) = crate::config::parse_addr_port(&resp.join_addr)
        && !a.is_private()
    {
        where_ = "reaching the leader over the internet: the machine needs a public IPv4 address"
            .to_string();
        if !site.is_empty() {
            where_ = format!(
                "in site {site}, reaching the leader over the internet: the machine needs a public IPv4 address"
            );
        }
    }
    out.push_str(&format!("On the new machine ({where_}), install Armada if needed, then join\nand paste the token when asked:\n\n"));
    out.push_str(&format!("  {}\n", install_command(&resp.version)));
    if server {
        out.push_str("  # copy /etc/armada/server.env from this server, if it has one\n");
    }
    out.push_str(&format!(
        "  sudo armadad {sub} {} --ca-hash {}\n",
        resp.join_addr, resp.ca_hash
    ));
    out.push_str(&format!("  sudo systemctl enable --now {unit}\n"));
    ctx.print(&out);
    Ok(())
}

pub fn add_node(t: &mut Tree) -> usize {
    let n = t.add(
        0,
        Node::new("node", "List, label, drain, and delete nodes")
            .aliases(&["nodes"])
            .noun(),
    );
    t.add(
        n,
        Node::new("list", "List nodes")
            .aliases(&["ls"])
            .args(Args::No)
            .example("  armada node list")
            .flag(output_flag(false))
            .run(list),
    );
    t.add(
        n,
        Node::new("show NODE", "Show a node")
            .args(Args::Exact(1))
            .example("  armada node show node1")
            .flag(output_flag(false))
            .run(show),
    );
    t.add(n, super::streams::node_top_node());
    t.add(
        n,
        Node::new("label NODE KEY=VALUE... | KEY-...", "Set or remove a node's labels")
            .long("Set labels with KEY=VALUE and remove them with KEY-. Apps choose nodes by\nlabel with placement.require (see the spec reference). Replicas whose node no\nlonger matches their app's placement move to other nodes, without dropping\nbelow the serving count.\n\nKeys are lowercase letters, digits, '.', '-', '_', and '/'; values the same\nwithout '/'. Keys starting with \"armada.\" are set by Armada (armada.os,\narmada.arch, and armada.site from armada node site) and cannot be changed here.")
            .example("  armada node label raspi-1 region=sulawesi kind=raspi\n  armada node label raspi-1 kind-")
            .args(Args::Min(2))
            .run(label),
    );
    t.add(
        n,
        Node::new("site NODE [SITE] | NODE --clear", "Move a node to another site")
            .long("Move a node to another site (ADR 0050). Within a site, nodes reach each other\nover their private network in the cluster's mode; between sites, over\nWireGuard between their public addresses. --clear moves the node back to the\ncluster's first site, which has no name.\n\nA node carries its site as the label armada.site, so placement.require and\nspreadBy can name it. Nodes of the first site have no armada.site label.")
            .example("  armada node site office-1 office\n  armada node site office-1 --clear")
            .args(Args::Range(1, 2))
            .flag(Flag::bool("clear", None, false, "move the node back to the cluster's first site"))
            .run(site),
    );
    t.add(
        n,
        Node::new("relay NODE [--clear]", "Choose the node that relays its site's traffic between nodes behind NAT")
            .long("Choose the node that relays its site's traffic between nodes behind NAT (ADR\n0050). Two nodes behind NAT in different sites cannot reach each other, so\ntheir traffic goes through the relay of one of their sites: a node of that\nsite with a public address. The leader picks one itself; this command pins\nNODE as its site's relay while it is ready and not drained, and --clear lets\nthe leader pick again. A site has one chosen relay: choosing another node of\nthe site moves the choice to it, and the output names the node that had it.\nThe relay carries that traffic, so choose a node with room for it.")
            .example("  armada node relay cloud-1\n  armada node relay cloud-1 --clear")
            .args(Args::Exact(1))
            .flag(Flag::bool("clear", None, false, "let the leader pick the relay of the node's site again"))
            .run(relay),
    );
    t.add(
        n,
        Node::new("rotate-key NODE", "Give a node a new WireGuard key")
            .long("Give a node a new WireGuard key (ADR 0025). The node's agent writes a new\nnetwork.key and announces the public half; every other node takes it within\nseconds, with a short gap in the node's traffic to them. Do it when the key\nmay have leaked, after you have dealt with how. The node must be connected.")
            .example("  armada node rotate-key n2\n  armada cluster events --node n2   # NetworkKeyRotated")
            .args(Args::Exact(1))
            .run(rotate_key),
    );
    t.add(
        n,
        Node::new(
            "drain NODE",
            "Stop placing replicas on a node and move its replicas away",
        )
        .args(Args::Exact(1))
        .example(
            "  armada node drain node1    # before maintenance; armada node resume node1 after",
        )
        .run(|ctx, args| cordon(ctx, args, true)),
    );
    t.add(
        n,
        Node::new("resume NODE", "Let a drained node take replicas again")
            .args(Args::Exact(1))
            .example("  armada node resume node1")
            .run(|ctx, args| cordon(ctx, args, false)),
    );
    t.add(
        n,
        Node::new(
            "restrict NODE",
            "Run only apps whose placement selects one of the node's labels",
        )
        .args(Args::Exact(1))
        .example("  armada node restrict node1   # only apps whose placement selects its labels")
        .run(|ctx, args| restrict(ctx, args, true)),
    );
    t.add(
        n,
        Node::new(
            "unrestrict NODE",
            "Let any app run on a restricted node again",
        )
        .args(Args::Exact(1))
        .example("  armada node unrestrict node1")
        .run(|ctx, args| restrict(ctx, args, false)),
    );
    t.add(n, join_token_node(false));
    t.add(
        n,
        Node::new("delete NODE", "Move a node's replicas away, then delete it and revoke its certificate")
            .aliases(&["rm"])
            .long("Drain the node, wait until its replicas run elsewhere (moved like a rolling\nupdate), then delete it from the cluster and revoke its certificate.\n\n--force deletes the node at once and its replicas without draining; use it\nonly for a node that is gone for good. A node holding volumes is only deleted\nwith --force; their records stay so a backup can be restored elsewhere.")
            .args(Args::Exact(1))
            .example("  armada node delete node1           # moves its replicas away first\n  armada node delete node1 --force   # a machine that is gone for good")
            .flag(Flag::bool("force", None, false, "delete now, with its replicas, without draining"))
            .flag(Flag::duration("wait", None, 10 * go::MINUTE, "how long to wait for replicas to move"))
            .run(delete),
    );
    n
}

/// The nodes.
fn node_status(ctx: &mut Ctx<'_>) -> Result<StatusResponse> {
    let mut admin = ctx.admin()?;
    let req = StatusRequest {
        nodes_only: true,
        ..Default::default()
    };
    rpc!(ctx, admin, status, req).map_err(rpc_err)
}

fn node_state(n: &NodeStatus) -> String {
    let mut s = n.state.clone();
    if n.cordoned {
        s.push_str(",drained");
    }
    if n.restricted {
        s.push_str(",restricted");
    }
    if n.behind_nat {
        s.push_str(",behind-nat");
    }
    if n.relay {
        s.push_str(",relay");
    }
    s
}

fn node_endpoint(n: &NodeStatus) -> String {
    if n.behind_nat {
        return "none (behind NAT)".to_string();
    }
    dash(&n.endpoint)
}

fn node_relay(n: &NodeStatus) -> &'static str {
    match (n.relay, n.relay_pinned) {
        (true, true) => "yes (chosen)",
        (true, false) => "yes (picked by the leader)",
        (false, true) => "chosen, but not ready to relay",
        _ => "no",
    }
}

fn list(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let resp = node_status(ctx)?;
    if o.json() {
        let only = StatusResponse {
            nodes: resp.nodes,
            ..Default::default()
        };
        return print_json(ctx, &only);
    }
    let mut tw = TabWriter::new(0, 2);
    tw.write("NODE\tPRIVATE IP\tSTATE\tREPLICAS\tVERSION\tCERT EXPIRES\tLABELS\n");
    for n in &resp.nodes {
        let exp = n
            .cert_expires_at
            .as_ref()
            .map_or("-".to_string(), |t| date_only(&go_time(Some(t), true)));
        tw.write(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            n.id,
            n.private_ip,
            node_state(n),
            n.replicas,
            dash(&n.version),
            exp,
            dash(&format_labels(&n.labels))
        ));
    }
    let out = tw.finish();
    ctx.print(&out);
    Ok(())
}

fn show(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let resp = node_status(ctx)?;
    let Some(n) = resp.nodes.iter().find(|n| n.id == args[0]) else {
        return Err(Error::Msg(format!("node {} not found", args[0])));
    };
    if o.json() {
        return print_json(ctx, n);
    }
    let seen = n.last_seen.as_ref().map_or("never".to_string(), |t| {
        format!(
            "{} ago",
            go::format_duration(round_second(since(t, now_nanos())))
        )
    });
    let exp = n
        .cert_expires_at
        .as_ref()
        .map_or("-".to_string(), |t| date_only(&go_time(Some(t), true)));
    let site = if n.site.is_empty() {
        "(the first site)".to_string()
    } else {
        n.site.clone()
    };
    let mut tw = TabWriter::new(0, 2);
    tw.write(&format!(
        "Node:\t{}\nPrivate IP:\t{}\nSite:\t{}\nEndpoint:\t{}\nRelay:\t{}\nState:\t{}\nReplicas:\t{}\nCPU:\t{:.1}\nMemory:\t{}\nVersion:\t{}\nLast seen:\t{}\nCert expires:\t{}\nLabels:\t{}\n",
        n.id,
        n.private_ip,
        site,
        node_endpoint(n),
        node_relay(n),
        node_state(n),
        n.replicas,
        n.cpu_millis as f64 / 1000.0,
        human_bytes(n.memory_bytes),
        dash(&n.version),
        seen,
        exp,
        dash(&format_labels(&n.labels))
    ));
    let out = tw.finish();
    ctx.print(&out);
    Ok(())
}

fn cordon(ctx: &mut Ctx<'_>, args: &[String], on: bool) -> Result {
    let mut admin = ctx.admin()?;
    let req = CordonNodeRequest {
        node: args[0].clone(),
        cordoned: on,
    };
    rpc!(ctx, admin, cordon_node, req).map_err(rpc_err)?;
    if on {
        ctx.print(&format!(
            "Node {} is drained: it takes no new replicas, and its replicas move to other nodes.\n",
            args[0]
        ));
    } else {
        ctx.print(&format!("Node {} takes new replicas again.\n", args[0]));
    }
    Ok(())
}

fn restrict(ctx: &mut Ctx<'_>, args: &[String], on: bool) -> Result {
    let mut admin = ctx.admin()?;
    let req = RestrictNodeRequest {
        node: args[0].clone(),
        restricted: on,
    };
    rpc!(ctx, admin, restrict_node, req).map_err(rpc_err)?;
    if on {
        ctx.print(&format!("Node {} is restricted: only apps whose placement.require names one of its labels run there.\n", args[0]));
    } else {
        ctx.print(&format!(
            "Node {} is unrestricted: any app may run there.\n",
            args[0]
        ));
    }
    Ok(())
}

fn label(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut req = LabelNodeRequest {
        node: args[0].clone(),
        ..Default::default()
    };
    for a in &args[1..] {
        if let Some(k) = a.strip_suffix('-')
            && !a.contains('=')
        {
            req.remove.push(k.to_string());
            continue;
        }
        let (k, v) = parse_label(a)?;
        req.set.insert(k, v);
    }
    let mut admin = ctx.admin()?;
    let resp = rpc!(ctx, admin, label_node, req).map_err(rpc_err)?;
    ctx.print(&format!(
        "Labels of {}: {}\n",
        args[0],
        dash(&format_labels(&resp.labels))
    ));
    Ok(())
}

fn site_name(site: &str) -> String {
    if site.is_empty() {
        "the first site".to_string()
    } else {
        format!("site {site}")
    }
}

fn site(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let clear = ctx.bool("clear");
    let site = match (args.len(), clear) {
        (2, true) => return Err("give a SITE or --clear, not both".into()),
        (2, false) => args[1].clone(),
        (_, false) => {
            return Err("give a SITE, or --clear for the cluster's first site".into());
        }
        _ => String::new(),
    };
    let mut admin = ctx.admin()?;
    let req = SetNodeSiteRequest {
        node: args[0].clone(),
        site: site.clone(),
    };
    rpc!(ctx, admin, set_node_site, req).map_err(rpc_err)?;
    ctx.print(&format!("Node {} is in {}.\n", args[0], site_name(&site)));
    Ok(())
}

fn relay(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let clear = ctx.bool("clear");
    let mut admin = ctx.admin()?;
    let req = SetNodeRelayRequest {
        node: args[0].clone(),
        clear,
    };
    let resp = rpc!(ctx, admin, set_node_relay, req).map_err(rpc_err)?;
    if clear {
        ctx.print(&format!(
            "The leader picks the relay of {}'s site again.\n",
            args[0]
        ));
    } else if !resp.replaced.is_empty() {
        ctx.print(&format!(
            "Node {} relays its site's traffic between nodes behind NAT, in place of {}.\n",
            args[0],
            resp.replaced.join(", ")
        ));
    } else {
        ctx.print(&format!(
            "Node {} relays its site's traffic between nodes behind NAT.\n",
            args[0]
        ));
    }
    Ok(())
}

fn rotate_key(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut admin = ctx.admin()?;
    let req = RotateNodeKeyRequest {
        node: args[0].clone(),
    };
    rpc!(ctx, admin, rotate_node_key, req).map_err(rpc_err)?;
    ctx.print(&format!("Asked node {} for a new network key; its NetworkKeyRotated event says when the other nodes have it.\n", args[0]));
    Ok(())
}

fn delete(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let node = args[0].clone();
    let force = ctx.bool("force");
    let wait = ctx.duration("wait");
    let mut admin = ctx.admin()?;
    if !force {
        // Apps with volumes never move off their node (ADR 0023).
        let vols =
            rpc!(ctx, admin, list_volumes, ListVolumesRequest::default()).map_err(rpc_err)?;
        let held: Vec<String> = vols
            .volumes
            .iter()
            .filter(|v| v.node == node)
            .map(|v| format!("{}/{}", v.app, v.name))
            .collect();
        if !held.is_empty() {
            return Err(Error::Msg(format!(
                "{node} holds volumes {}, whose apps never move; back them up (armada volume backup) and restore them on another node (armada volume restore --node), or use --force",
                held.join(", ")
            )));
        }
        let req = CordonNodeRequest {
            node: node.clone(),
            cordoned: true,
        };
        rpc!(ctx, admin, cordon_node, req).map_err(rpc_err)?;
        let _ = writeln!(ctx.err, "Drained {node}; waiting for its replicas to move.");
        let deadline = now_nanos() + i128::from(wait);
        loop {
            let req = StatusRequest {
                nodes_only: true,
                ..Default::default()
            };
            let resp = rpc!(ctx, admin, status, req).map_err(rpc_err)?;
            let left = resp
                .nodes
                .iter()
                .filter(|n| n.id == node)
                .map(|n| n.replicas)
                .next_back()
                .unwrap_or(0);
            if left == 0 {
                break;
            }
            if now_nanos() > deadline {
                return Err(Error::Msg(format!(
                    "{left} replica(s) still on {node} after {}; the node stays drained. Is there capacity elsewhere? Retry, or use --force",
                    go::format_duration(wait)
                )));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
    let req = RemoveNodeRequest {
        node: node.clone(),
        force,
    };
    rpc!(ctx, admin, remove_node, req).map_err(rpc_err)?;
    ctx.print(&format!(
        "Deleted node {node}; its certificate is revoked.\n"
    ));
    let _ = write!(
        ctx.err,
        "On that machine, stop armada-agent (or armada-server) and run `armadad runtime reset`:\nits proxy keeps serving its last configuration until then.\n"
    );
    Ok(())
}

// ---- server ----

pub fn add_server(t: &mut Tree) -> usize {
    let mut noun = Node::new("server", "List, add, and delete control plane servers")
        .aliases(&["servers"])
        .long("List and delete control plane servers, and create tokens that add them.\nA server runs on its machine with `armadad server`, and joins with\n`armadad server join`.")
        .noun();
    noun.args = Args::No;
    let n = t.add(0, noun);
    t.add(
        n,
        Node::new(
            "list",
            "List control plane servers and update the client config with them",
        )
        .aliases(&["ls"])
        .args(Args::No)
        .example("  armada server list    # and update the client config with them")
        .flag(output_flag(false))
        .run(server_list),
    );
    t.add(n, join_token_node(true));
    t.add(
        n,
        Node::new("delete NAME", "Delete a control plane server")
            .aliases(&["rm"])
            .long("Delete a control plane server from the cluster. Stop `armadad server` on it first.\nIts agent stays a node; delete that with `armada node delete`. The leader cannot\ndelete itself: stop it, and run this once another server leads.\n\nA removed server still holds copies of the cluster CA key and master key: wipe\nits data directory.")
            .args(Args::Exact(1))
            .example("  armada server delete server3")
            .run(server_delete),
    );
    n
}

/// The members' API addresses, the leader first.
pub fn server_addrs(resp: &ListServersResponse) -> Vec<String> {
    let mut addrs = Vec::new();
    for s in &resp.servers {
        if s.member && s.leader {
            addrs.insert(0, s.api_addr.clone());
        } else if s.member {
            addrs.push(s.api_addr.clone());
        }
    }
    addrs
}

/// a pending state migration (ADR 0012).
fn schema_note(resp: &ListServersResponse) -> String {
    let newest = resp
        .servers
        .iter()
        .map(|s| s.schema)
        .fold(resp.state_schema, i32::max);
    if newest == resp.state_schema {
        return String::new();
    }
    let old: Vec<&str> = resp
        .servers
        .iter()
        .filter(|s| s.schema < newest)
        .map(|s| s.name.as_str())
        .collect();
    format!(
        "The state uses schema {}; upgraded servers know {newest}. The migration runs, and upgraded\nservers can lead, once these servers are upgraded too: {}.",
        resp.state_schema,
        old.join(", ")
    )
}

fn server_list(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let mut admin = ctx.admin()?;
    let resp = rpc!(ctx, admin, list_servers, ListServersRequest::default()).map_err(rpc_err)?;
    if o.json() {
        print_json(ctx, &resp)?;
        return sync_client_servers(ctx, &server_addrs(&resp));
    }
    let mut tw = TabWriter::new(0, 2);
    tw.write("NAME\tADDRESS\tROLE\tSTATUS\tVERSION\n");
    for s in &resp.servers {
        let mut role = if s.leader { "leader" } else { "standby" };
        let mut st = "voting";
        if !s.member {
            (st, role) = ("not a member", "-");
        } else if !s.voting {
            st = "catching up";
        } else if !s.reachable {
            (st, role) = ("unreachable", "-");
        }
        tw.write(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            s.name,
            s.api_addr,
            role,
            st,
            dash(&s.version)
        ));
    }
    let out = tw.finish();
    ctx.print(&out);
    let note = schema_note(&resp);
    if !note.is_empty() {
        let _ = writeln!(ctx.err, "{note}");
    }
    sync_client_servers(ctx, &server_addrs(&resp))
}

/// CheckServers' error.
fn check_servers(addrs: &[String]) -> std::result::Result<(), String> {
    for a in addrs {
        crate::config::check_private_listen(a).map_err(|e| format!("server address: {e}"))?;
    }
    Ok(())
}

/// The control plane's addresses kept in the client
/// config.
fn sync_client_servers(ctx: &mut Ctx<'_>, addrs: &[String]) -> Result {
    if addrs.is_empty() {
        return Ok(());
    }
    check_servers(addrs)?;
    let path = ctx.g.config_path.clone();
    let mut cc = crate::config::load(&path).map_err(Error::Msg)?;
    // A config that reaches the servers through a tunnel keeps its list.
    if cc.servers == addrs || crate::rpc::tunnelled(&cc.servers, addrs) {
        return Ok(());
    }
    cc.servers = addrs.to_vec();
    match cc.save(&path) {
        Err(e) if e.contains("permission denied") => {
            let _ = writeln!(
                ctx.err,
                "{path} lists other control plane addresses; update it with sudo armada server list."
            );
            Ok(())
        }
        Err(e) => Err(Error::Msg(e)),
        Ok(()) => {
            let _ = writeln!(
                ctx.err,
                "Updated {path} with {} control plane addresses.",
                addrs.len()
            );
            Ok(())
        }
    }
}

fn server_delete(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut admin = ctx.admin()?;
    let req = RemoveServerRequest {
        name: args[0].clone(),
    };
    rpc!(ctx, admin, remove_server, req).map_err(rpc_err)?;
    ctx.print(&format!(
        "Deleted server {}. Wipe its data directory: it holds the cluster keys.\n",
        args[0]
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_tags() {
        for ok in ["v0.1.0", "v0.1.0-alpha.41", "v10.20.30-rc1"] {
            assert!(release_tag(ok), "{ok}");
        }
        for bad in ["0.1.0", "v0.1", "v0.1.0-", "v0.1.0-a_b", "dev", "v0.1.0+x"] {
            assert!(!release_tag(bad), "{bad}");
        }
        assert_eq!(
            install_command("v0.1.0"),
            "curl -fsSL https://raw.githubusercontent.com/ryanbekhen/armada/main/install.sh | sudo ARMADA_VERSION=v0.1.0 sh"
        );
    }
}

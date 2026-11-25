//! The nouns and verbs the second part of the client's port (ADR 0055,
//! pull request 17b) brings. Until then they are listed with Go's names and
//! descriptions, so help and suggestions read as Go's, and running one
//! says it is not here yet. Nothing ships this crate before then.

use crate::cli::{Ctx, Error, Node, Result, Tree};

fn not_yet(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    Err(Error::Msg(format!(
        "{} is not in this client yet (ADR 0055, pull request 17b)",
        ctx.path()
    )))
}

/// A command of 17b: any flags and arguments, then the error above.
pub fn stub(use_: &str, short: &str, aliases: &[&str]) -> Node {
    let mut n = Node::new(use_, short).aliases(aliases).run(not_yet);
    n.disable_flag_parsing = true;
    n.explain = false;
    n
}

fn add(t: &mut Tree, use_: &str, short: &str, aliases: &[&str]) -> usize {
    t.add(0, stub(use_, short, aliases))
}

pub fn volume(t: &mut Tree) -> usize {
    add(
        t,
        "volume",
        "List, back up, restore, and delete persistent volumes",
        &["volumes"],
    )
}

pub fn snapshot(t: &mut Tree) -> usize {
    add(
        t,
        "snapshot",
        "List a volume's backups in its bucket, or take one now",
        &["snapshots"],
    )
}

pub fn domain(t: &mut Tree) -> usize {
    add(t, "domain", "List and verify custom domains", &["domains"])
}

pub fn cluster(t: &mut Tree) -> usize {
    add(
        t,
        "cluster",
        "The cluster's status, settings, and events",
        &[],
    )
}

pub fn node(t: &mut Tree) -> usize {
    add(
        t,
        "node",
        "List, label, drain, and delete nodes",
        &["nodes"],
    )
}

pub fn server(t: &mut Tree) -> usize {
    add(
        t,
        "server",
        "List, add, and delete control plane servers",
        &["servers"],
    )
}

pub fn user(t: &mut Tree) -> usize {
    add(
        t,
        "user",
        "People, each with a certificate of their own",
        &["users"],
    )
}

pub fn service(t: &mut Tree) -> usize {
    add(
        t,
        "service",
        "Programs such as a CI system, each with a certificate of their own",
        &["services"],
    )
}

pub fn role(t: &mut Tree) -> usize {
    add(
        t,
        "role",
        "List the roles and who holds them; grant and revoke them",
        &["roles"],
    )
}

pub fn alert(t: &mut Tree) -> usize {
    add(
        t,
        "alert",
        "Where notices about events go: Slack, Discord, Telegram, email, or a webhook",
        &["alerts"],
    )
}

pub fn metrics(t: &mut Tree) -> usize {
    add(
        t,
        "metrics",
        "Credentials for the Prometheus metrics endpoint",
        &[],
    )
}

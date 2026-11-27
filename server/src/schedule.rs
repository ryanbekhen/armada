//! Scheduling: what each node holds and can take,
//! which nodes an app's revision may use (ADR 0014), where a new replica
//! goes, which replica goes first, and the messages that explain why an
//! app waits for a node.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use armada_spec::Placement;
use armada_store::{App, NODE_READY, Node, REPLICA_RUNNING, Replica, Revision};

/// What Armada keeps for itself on every node (the agent, the runtime,
/// and HAProxy), and on server machines for the control plane.
const SYSTEM_CPU_MILLIS: i64 = 100;
const SYSTEM_MEMORY_BYTES: i64 = 128 << 20;
const SERVER_CPU_MILLIS: i64 = 100;

/// How many replicas a node with its own container
/// subnet takes.
pub(crate) const MAX_SUBNET_REPLICAS: i64 = 250;

/// What a replica reserves on its node, or what a node has.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Res {
    pub cpu: i64,
    pub mem: i64,
}

impl fmt::Display for Res {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} of CPU and {} of memory",
            human_cpu(self.cpu),
            human_memory(self.mem)
        )
    }
}

pub(crate) fn human_cpu(m: i64) -> String {
    if m % 1000 == 0 {
        format!("{}", m / 1000)
    } else {
        format!("{m}m")
    }
}

pub(crate) fn human_memory(b: i64) -> String {
    if b >= 1 << 30 && b % (1 << 30) == 0 {
        format!("{}Gi", b >> 30)
    } else if b >= 1 << 20 {
        format!("{}Mi", b >> 20)
    } else {
        format!("{b} bytes")
    }
}

/// reservation: what one replica of rev reserves on its node.
pub(crate) fn reservation(rev: &Revision) -> Res {
    Res {
        cpu: rev.spec().reserved_cpu_millis(),
        mem: rev.spec().reserved_memory_bytes(),
    }
}

/// allocatable: copies of nodes with the capacity left for replicas.
pub(crate) fn allocatable(nodes: &[Node], servers: &[armada_store::Server]) -> Vec<Node> {
    let is_server: BTreeSet<&str> = servers.iter().map(|s| s.private_ip.as_str()).collect();
    nodes
        .iter()
        .map(|n| {
            let mut n = n.clone();
            let mut cpu = SYSTEM_CPU_MILLIS;
            if is_server.contains(n.private_ip.as_str()) {
                cpu += SERVER_CPU_MILLIS;
            }
            if n.cpu_millis > 0 {
                n.cpu_millis = (n.cpu_millis - cpu).max(1);
            }
            if n.memory_bytes > 0 {
                n.memory_bytes = (n.memory_bytes - SYSTEM_MEMORY_BYTES).max(1);
            }
            n
        })
        .collect()
}

/// n's container subnet has no address for another replica.
pub(crate) fn replicas_full(n: &Node, replicas: &[Replica]) -> bool {
    if n.subnet.is_empty() {
        return false;
    }
    let used = replicas
        .iter()
        .filter(|r| r.node_id == n.id && !r.done)
        .count() as i64;
    used >= MAX_SUBNET_REPLICAS
}

/// What the replicas on one node add up to.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Placed {
    pub total: i64,
    pub holding: i64,
    pub reserved: Res,
}

/// The use of each node, by node ID.
pub(crate) type Use = HashMap<String, Placed>;

/// What each revision's replicas reserve, by revision name; a revision
/// missing from it reserves nothing (it could not be read).
pub(crate) type Reserved = HashMap<String, Res>;

pub(crate) fn reserved_of(r: &Replica, res: &Reserved) -> Res {
    if r.done {
        return Res::default();
    }
    res.get(&r.revision).copied().unwrap_or_default()
}

pub(crate) fn usage_of(replicas: &[Replica], res: &Reserved) -> Use {
    let mut use_: Use = HashMap::new();
    for r in replicas {
        let u = use_.entry(r.node_id.clone()).or_default();
        u.total += 1;
        if !r.done {
            u.holding += 1;
        }
        let x = reserved_of(r, res);
        u.reserved.cpu += x.cpu;
        u.reserved.mem += x.mem;
    }
    use_
}

fn labels(n: &Node) -> HashMap<String, String> {
    n.all_labels().into_iter().collect()
}

/// Replicas of rev may run on n.
pub(crate) fn placement_allows(n: &Node, rev: &Revision) -> bool {
    let sp = rev.spec();
    if sp.has_local_volumes() && !n.volumes {
        return false;
    }
    if sp.has_nfs_volumes() && !n.nfs {
        return false;
    }
    if sp.has_containers() && !n.containers {
        return false;
    }
    let pl = sp.placement.as_ref();
    if !Placement::matches(pl, &labels(n)) {
        return false;
    }
    let own: HashMap<String, String> = n.labels.clone().unwrap_or_default().into_iter().collect();
    if n.restricted && !Placement::selects(pl, &own) {
        return false;
    }
    rev.platforms.is_empty()
        || n.os.is_empty()
        || n.arch.is_empty()
        || rev.platforms.contains(&format!("{}/{}", n.os, n.arch))
}

/// eligible: the nodes that may take new replicas of rev.
pub(crate) fn eligible(nodes: &[Node], rev: &Revision) -> Vec<Node> {
    nodes
        .iter()
        .filter(|n| n.state == NODE_READY && !n.cordoned && placement_allows(n, rev))
        .cloned()
        .collect()
}

/// The nodes that have label key, mapped to its value; none
/// when key is empty.
pub(crate) fn spread_groups(nodes: &[Node], key: &str) -> Option<HashMap<String, String>> {
    if key.is_empty() {
        return None;
    }
    let mut out = HashMap::new();
    for n in nodes {
        if let Some(v) = n.all_labels().get(key) {
            out.insert(n.id.clone(), v.clone());
        }
    }
    Some(out)
}

/// The first of the smallest.
pub(crate) fn min_first<T>(xs: &[T], cmp: impl Fn(&T, &T) -> Ordering) -> Option<&T> {
    let mut best: Option<&T> = None;
    for x in xs {
        match best {
            Some(b) if cmp(x, b) != Ordering::Less => {}
            _ => best = Some(x),
        }
    }
    best
}

/// The first of the largest.
pub(crate) fn max_first<T>(xs: &[T], cmp: impl Fn(&T, &T) -> Ordering) -> Option<&T> {
    let mut best: Option<&T> = None;
    for x in xs {
        match best {
            Some(b) if cmp(x, b) != Ordering::Greater => {}
            _ => best = Some(x),
        }
    }
    best
}

fn group<'a>(g: &'a Option<HashMap<String, String>>, node: &str) -> Option<&'a String> {
    g.as_ref().and_then(|m| m.get(node))
}

pub(crate) fn pick_node(
    nodes: &[Node],
    replicas: &[Replica],
    spread: &[Replica],
    spread_by: &str,
    want: Res,
    res: &Reserved,
) -> Option<Node> {
    pick_node_by(nodes, &usage_of(replicas, res), spread, spread_by, want)
}

pub(crate) fn pick_node_by(
    nodes: &[Node],
    use_: &Use,
    spread: &[Replica],
    spread_by: &str,
    want: Res,
) -> Option<Node> {
    let group_of = spread_groups(nodes, spread_by);
    let mut same_app: HashMap<&str, i64> = HashMap::new();
    let mut same_group: HashMap<&str, i64> = HashMap::new();
    for r in spread {
        *same_app.entry(r.node_id.as_str()).or_default() += 1;
        if let Some(g) = group(&group_of, &r.node_id) {
            *same_group.entry(g.as_str()).or_default() += 1;
        }
    }
    struct Cand<'a> {
        node: &'a Node,
        same_group: i64,
        same_app: i64,
        total: i64,
        free: Res,
    }
    let mut cands = Vec::new();
    for n in nodes {
        let u = use_.get(&n.id).copied().unwrap_or_default();
        if n.state != NODE_READY
            || n.cordoned
            || (!n.subnet.is_empty() && u.holding >= MAX_SUBNET_REPLICAS)
        {
            continue;
        }
        let mut c = Cand {
            node: n,
            same_group: 0,
            same_app: same_app.get(n.id.as_str()).copied().unwrap_or(0),
            total: u.total,
            free: Res {
                cpu: n.cpu_millis - u.reserved.cpu,
                mem: n.memory_bytes - u.reserved.mem,
            },
        };
        if let Some(g) = group(&group_of, &n.id) {
            c.same_group = same_group.get(g.as_str()).copied().unwrap_or(0);
        }
        if (n.memory_bytes > 0 && c.free.mem < want.mem)
            || (n.cpu_millis > 0 && c.free.cpu < want.cpu)
        {
            continue;
        }
        cands.push(c);
    }
    min_first(&cands, |a, b| {
        a.same_group
            .cmp(&b.same_group)
            .then(a.same_app.cmp(&b.same_app))
            .then(a.total.cmp(&b.total))
            .then(b.free.mem.cmp(&a.free.mem))
            .then(b.free.cpu.cmp(&a.free.cpu))
            .then(a.node.id.cmp(&b.node.id))
    })
    .map(|c| c.node.clone())
}

/// The replica to remove when scaling down.
pub(crate) fn pick_victim(rs: &[Replica], group_of: &Option<HashMap<String, String>>) -> Replica {
    let mut per_node: HashMap<&str, i64> = HashMap::new();
    let mut per_group: HashMap<&str, i64> = HashMap::new();
    for r in rs {
        *per_node.entry(r.node_id.as_str()).or_default() += 1;
        if let Some(g) = group(group_of, &r.node_id) {
            *per_group.entry(g.as_str()).or_default() += 1;
        }
    }
    let in_group = |r: &Replica| -> i64 {
        group(group_of, &r.node_id)
            .map(|g| per_group.get(g.as_str()).copied().unwrap_or(0))
            .unwrap_or(0)
    };
    let pn = |r: &Replica| per_node.get(r.node_id.as_str()).copied().unwrap_or(0);
    min_first(rs, |a, b| {
        let (ha, hb) = (a.state == REPLICA_RUNNING, b.state == REPLICA_RUNNING);
        if ha != hb {
            return if ha {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        in_group(b)
            .cmp(&in_group(a))
            .then(pn(b).cmp(&pn(a)))
            .then(b.id.cmp(&a.id))
    })
    .cloned()
    .expect("pick_victim of no replicas")
}

/// The replica of rs on the node with the most of them (the
/// highest ID among those). rs is not empty.
pub(crate) fn most_loaded(rs: &[Replica]) -> Replica {
    let mut per_node: HashMap<&str, i64> = HashMap::new();
    for r in rs {
        *per_node.entry(r.node_id.as_str()).or_default() += 1;
    }
    let pn = |r: &Replica| per_node.get(r.node_id.as_str()).copied().unwrap_or(0);
    max_first(rs, |a, b| pn(a).cmp(&pn(b)).then(a.id.cmp(&b.id)))
        .cloned()
        .expect("most_loaded of no replicas")
}

pub(crate) fn node_victim(
    nodes: &[Node],
    use_: &Use,
    current: &[Replica],
    want: Res,
) -> Option<(Replica, String)> {
    if current.is_empty() {
        return None;
    }
    let to = pick_node_by(nodes, use_, current, "", want)?;
    let mut per_node: HashMap<&str, i64> = HashMap::new();
    for r in current {
        *per_node.entry(r.node_id.as_str()).or_default() += 1;
    }
    let victim = most_loaded(current);
    let from = per_node.get(victim.node_id.as_str()).copied().unwrap_or(0);
    let at = per_node.get(to.id.as_str()).copied().unwrap_or(0);
    if from - at < 2 {
        return None;
    }
    Some((victim, to.id))
}

pub(crate) fn rebalance_victim(
    nodes: &[Node],
    use_: &Use,
    current: &[Replica],
    spread_by: &str,
    want: Res,
) -> Option<(Replica, String)> {
    if spread_by.is_empty() {
        return node_victim(nodes, use_, current, want);
    }
    let group_of = spread_groups(nodes, spread_by);
    let gm = group_of.clone().unwrap_or_default();
    let mut per_group: HashMap<String, i64> = HashMap::new();
    let mut placed = Vec::new();
    for r in current {
        if let Some(g) = gm.get(&r.node_id) {
            *per_group.entry(g.clone()).or_default() += 1;
            placed.push(r.clone());
        }
    }
    let pg = |g: &str| per_group.get(g).copied().unwrap_or(0);
    if let Some(to) = pick_node_by(nodes, use_, current, spread_by, want)
        && !placed.is_empty()
    {
        let top = max_first(&placed, |a, b| {
            let (ga, gb) = (&gm[&a.node_id], &gm[&b.node_id]);
            pg(ga).cmp(&pg(gb)).then(gb.cmp(ga))
        })
        .expect("placed is not empty");
        let from = gm[&top.node_id].clone();
        let to_group = gm.get(&to.id).cloned().unwrap_or_default();
        if pg(&from) - pg(&to_group) >= 2 {
            let inside: Vec<Replica> = placed
                .iter()
                .filter(|r| gm[&r.node_id] == from)
                .cloned()
                .collect();
            return Some((most_loaded(&inside), to.id));
        }
    }
    let mut groups: BTreeMap<String, Vec<Node>> = BTreeMap::new();
    for n in nodes {
        if let Some(g) = gm.get(&n.id) {
            groups.entry(g.clone()).or_default().push(n.clone());
        }
    }
    for (g, ns) in &groups {
        let inside: Vec<Replica> = placed
            .iter()
            .filter(|r| &gm[&r.node_id] == g)
            .cloned()
            .collect();
        if let Some(v) = node_victim(ns, use_, &inside, want) {
            return Some(v);
        }
    }
    None
}

/// The nodes that may run target, how many replicas of
/// app's target revision are not draining, and how many of those are on
/// nodes outside that set.
pub(crate) fn target_placement(
    nodes: &[Node],
    replicas: &[Replica],
    app: &App,
    target: &Revision,
) -> (Vec<Node>, i64, i64) {
    let fit = eligible(nodes, target);
    let allowed: BTreeSet<&str> = fit.iter().map(|n| n.id.as_str()).collect();
    let (mut live, mut stuck) = (0, 0);
    for r in replicas {
        if r.app == app.name && r.revision == app.target_revision && !r.draining() {
            live += 1;
            if !allowed.contains(r.node_id.as_str()) {
                stuck += 1;
            }
        }
    }
    (fit, live, stuck)
}

pub(crate) fn placement_needs_cluster(
    target: Option<&Revision>,
    nodes: &[Node],
    own: &[Replica],
    app: &App,
) -> bool {
    if app.removing {
        return false;
    }
    let Some(target) = target else {
        return true;
    };
    let (_, live, stuck) = target_placement(nodes, own, app, target);
    live < app.replicas
        || stuck > 0
        || !Placement::spread_key(target.spec().placement.as_ref()).is_empty()
}

/// Why app waits for a node, or "".
pub(crate) fn placement_message(
    target: Option<&Revision>,
    nodes: &[Node],
    all: &[Replica],
    app: &App,
    res: &Reserved,
) -> String {
    if app.removing {
        return "being removed: its replicas are draining".to_string();
    }
    let Some(target) = target else {
        return String::new();
    };
    let (fit, live, stuck) = target_placement(nodes, all, app, target);
    if live >= app.replicas && stuck == 0 {
        return spread_message(&fit, all, app, target, res);
    }
    let why = if fit.is_empty() {
        no_node_reason(nodes, target)
    } else {
        let want = reservation(target);
        if pick_node(&fit, all, &[], "", want, res).is_some() {
            return String::new();
        }
        if !fit.iter().any(|n| !replicas_full(n, all)) {
            format!(
                "{} node(s) may run the app, each already runs {} replicas",
                fit.len(),
                MAX_SUBNET_REPLICAS
            )
        } else {
            let mut short = want.to_string();
            if pick_node(
                &fit,
                all,
                &[],
                "",
                Res {
                    cpu: 0,
                    mem: want.mem,
                },
                res,
            )
            .is_none()
            {
                short = format!("{} of memory", human_memory(want.mem));
            } else if pick_node(
                &fit,
                all,
                &[],
                "",
                Res {
                    cpu: want.cpu,
                    mem: 0,
                },
                res,
            )
            .is_none()
            {
                short = format!("{} of CPU", human_cpu(want.cpu));
            }
            format!(
                "{} node(s) may run the app, none has {short} free",
                fit.len()
            )
        }
    };
    if live < app.replicas {
        return format!("waiting for a node: {why}");
    }
    format!("{stuck} replica(s) stay on nodes the app may no longer use until one is free: {why}")
}

fn spread_message(
    fit: &[Node],
    all: &[Replica],
    app: &App,
    target: &Revision,
    res: &Reserved,
) -> String {
    let key = Placement::spread_key(target.spec().placement.as_ref());
    if key.is_empty() {
        return String::new();
    }
    let gm = spread_groups(fit, &key).unwrap_or_default();
    // Every fit node has a group: one without the label is in the group
    // "".
    let mut groups: BTreeMap<String, Vec<Node>> = BTreeMap::new();
    for n in fit {
        groups
            .entry(gm.get(&n.id).cloned().unwrap_or_default())
            .or_default()
            .push(n.clone());
    }
    let mut count: HashMap<String, i64> = HashMap::new();
    for r in all {
        if let Some(g) = gm.get(&r.node_id)
            && r.app == app.name
            && r.revision == app.target_revision
            && !r.draining()
        {
            *count.entry(g.clone()).or_default() += 1;
        }
    }
    let c = |g: &str| count.get(g).copied().unwrap_or(0);
    let most = groups.keys().map(|g| c(g)).max().unwrap_or(0).max(0);
    let mut full = Vec::new();
    for (g, ns) in &groups {
        if most - c(g) < 2 {
            continue;
        }
        if pick_node(ns, all, &[], "", reservation(target), res).is_none() {
            full.push(g.clone());
        }
    }
    if full.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = groups.keys().map(|g| format!("{g}={}", c(g))).collect();
    format!(
        "replicas spread unevenly over {key} ({}): no node with {key}={} has {} free",
        parts.join(", "),
        full.join("|"),
        reservation(target)
    )
}

/// Why no node is eligible for rev.
fn no_node_reason(nodes: &[Node], rev: &Revision) -> String {
    let bare = Revision {
        platforms: Vec::new(),
        ..rev.clone()
    };
    let labelled = nodes
        .iter()
        .filter(|n| n.state == NODE_READY && !n.cordoned && placement_allows(n, &bare))
        .count();
    let pl = Placement::string(rev.spec().placement.as_ref());
    if labelled > 0 {
        format!(
            "no ready node can run the image, which is built for {}",
            rev.platforms.join(", ")
        )
    } else if !pl.is_empty() {
        format!("no ready node matches the placement ({pl})")
    } else {
        "no ready node accepts the app (every ready node is cordoned or restricted)".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, ready: bool, cpu: i64, mem: i64) -> Node {
        Node {
            id: id.to_string(),
            state: if ready { NODE_READY } else { "unknown" }.to_string(),
            cpu_millis: cpu,
            memory_bytes: mem,
            ..Node::default()
        }
    }

    fn on(app: &str, node: &str) -> Replica {
        Replica {
            app: app.to_string(),
            node_id: node.to_string(),
            ..Replica::default()
        }
    }

    /// Every replica (of revision "") reserves r.
    fn each(r: Res) -> Reserved {
        Reserved::from([(String::new(), r)])
    }

    const MI: i64 = 1 << 20;

    fn id(n: Option<Node>) -> Option<String> {
        n.map(|n| n.id)
    }

    // Picking a node.
    #[test]
    fn picks_nodes() {
        let nodes = [
            node("a", true, 0, 1 << 30),
            node("b", true, 0, 2 << 30),
            node("c", false, 0, 8 << 30),
        ];
        let half = Res {
            cpu: 0,
            mem: 512 * MI,
        };
        let pick = |all: &[Replica], spread: &[Replica], want: Res, res: &Reserved| {
            id(pick_node(&nodes, all, spread, "", want, res))
        };
        assert_eq!(pick(&[], &[], half, &each(half)).as_deref(), Some("b"));
        let web_b = [on("web", "b")];
        assert_eq!(
            pick(&web_b, &web_b, half, &each(half)).as_deref(),
            Some("a")
        );
        let full = [on("x", "a"), on("x", "a"), on("web", "b")];
        assert_eq!(
            pick(&full, &full[2..], half, &each(half)).as_deref(),
            Some("b")
        );
        let huge = Res {
            cpu: 0,
            mem: 4 << 30,
        };
        assert_eq!(pick(&[], &[], huge, &each(half)), None);
        let unknown = [node("u", true, 0, 0)];
        let any = Res {
            cpu: 0,
            mem: 1 << 40,
        };
        assert!(pick_node(&unknown, &[], &[], "", any, &each(half)).is_some());
        let greedy = [
            node("honest", true, 0, 2 << 30),
            node("liar", true, 0, 16 << 40),
        ];
        let n = pick_node(&greedy, &[on("x", "liar")], &[], "", half, &each(half));
        assert_eq!(id(n).as_deref(), Some("honest"));
        let quarter = Res {
            cpu: 0,
            mem: 256 * MI,
        };
        let all = [on("web", "a"), on("web", "a"), on("web", "b")];
        assert_eq!(
            pick(&all, &all[2..], quarter, &each(quarter)).as_deref(),
            Some("a")
        );
    }

    // Picking a node reserves CPU.
    #[test]
    fn reserves_cpu() {
        let nodes = [
            node("a", true, 1000, 8 << 30),
            node("b", true, 500, 8 << 30),
        ];
        let small = each(Res {
            cpu: 100,
            mem: 256 * MI,
        });
        let mut all: Vec<Replica> = (0..6).map(|_| on("x", "a")).collect();
        all.extend((0..5).map(|_| on("y", "b")));
        let want = |cpu| Res { cpu, mem: 256 * MI };
        let n = pick_node(&nodes, &all, &[], "", want(100), &small);
        assert_eq!(id(n).as_deref(), Some("a"));
        assert!(pick_node(&nodes, &all, &[], "", want(500), &small).is_none());
        let n = pick_node(&nodes, &[], &[], "", Res { cpu: 100, mem: 0 }, &small);
        assert_eq!(id(n).as_deref(), Some("a"));
    }

    // Picking a node skips a full subnet.
    #[test]
    fn skips_full_subnets() {
        let mut a = node("a", true, 0, 0);
        a.subnet = "10.120.0.0/24".to_string();
        let mut b = node("b", true, 0, 0);
        b.subnet = "10.120.1.0/24".to_string();
        let nodes = [a, b];
        let many = |n: &str, k: i64, done: bool| -> Vec<Replica> {
            (0..k).map(|_| Replica { done, ..on("x", n) }).collect()
        };
        let none = Reserved::new();
        let zero = Res::default();
        let spread = [on("web", "b")];
        let mut all = many("a", MAX_SUBNET_REPLICAS, false);
        all.extend(spread.iter().cloned());
        let n = pick_node(&nodes, &all, &spread, "", zero, &none);
        assert_eq!(id(n).as_deref(), Some("b"));
        let mut all = many("a", MAX_SUBNET_REPLICAS, false);
        all.extend(many("b", MAX_SUBNET_REPLICAS, false));
        assert!(pick_node(&nodes, &all, &[], "", zero, &none).is_none());
        let mut all = many("a", MAX_SUBNET_REPLICAS - 1, false);
        all.extend(many("b", MAX_SUBNET_REPLICAS, false));
        all.extend(many("a", 5, true));
        let n = pick_node(&nodes, &all, &[], "", zero, &none);
        assert_eq!(id(n).as_deref(), Some("a"));
        assert!(replicas_full(&nodes[1], &all));
        assert!(!replicas_full(&nodes[0], &all));
    }

    // Picking the replica that goes first.
    #[test]
    fn picks_victims() {
        let r = |id: &str, n: &str, state: &str| Replica {
            id: id.to_string(),
            state: state.to_string(),
            ..on("web", n)
        };
        let mut rs = vec![
            r("1", "a", REPLICA_RUNNING),
            r("2", "b", REPLICA_RUNNING),
            r("3", "b", REPLICA_RUNNING),
        ];
        assert_eq!(pick_victim(&rs, &None).node_id, "b");
        rs.push(r("4", "a", "failed"));
        assert_eq!(pick_victim(&rs, &None).id, "4");
    }

    #[test]
    fn first_of_equals() {
        let xs = [(1, 'a'), (0, 'b'), (0, 'c'), (2, 'd'), (2, 'e')];
        assert_eq!(min_first(&xs, |a, b| a.0.cmp(&b.0)).map(|x| x.1), Some('b'));
        assert_eq!(max_first(&xs, |a, b| a.0.cmp(&b.0)).map(|x| x.1), Some('d'));
        assert_eq!(human_memory(2 << 30), "2Gi");
        assert_eq!(human_memory(1536 * MI), "1536Mi");
        assert_eq!(human_cpu(2000), "2");
        assert_eq!(human_cpu(250), "250m");
    }
}

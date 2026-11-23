//! The node's firewall (ADR 0054 step 3): the nftables isolation tables
//! (nft.rs) and the iptables chains (iptables.rs), written but not yet used
//! by nodes. Two commands print what would be done, for the parity test
//! against Go; two do it.
//!
//!   armada-node net firewall nft       stdin: {Policy, Previous, HasTables, FirstSetID,
//!                                      UpdateSetID}
//!                                      stdout: {action, isolate, update, remove}, each
//!                                      batch as the hex of its messages (seq and port 0)
//!   armada-node net firewall iptables  stdin: a plan request (Config, Node, PrivateIP,
//!                                      Key) with Clean, Tables (iptables' state), Fail
//!                                      stdout: {calls, error, clean, removeCalls, removeErrors}
//!   armada-node net firewall apply     stdin: a plan request with Local, Previous, Clean;
//!                                      sets up both; stdout: {policy, clean}
//!   armada-node net firewall remove    takes both away
//!
//! A policy is written as `net plan` writes it (cidr, subnet, gateway,
//! members, open, nodes, tcpPorts).

use super::addr::{Addr, Prefix};
use super::config::NetworkConfig;
use super::iptables::{self, Clean, Iptables, Sim, SimChain};
use super::kernel::Socket;
use super::key::Key;
use super::nft::{self, Action};
use super::plan::{self, MODE_WIREGUARD, Plan, encrypted};
use super::policy::{Policy, build_policy};
use super::{read_stdin, write_stdout};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct MembersJson {
    app: String,
    addresses: Vec<String>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PolicyJson {
    cidr: String,
    subnet: String,
    gateway: String,
    apps: Vec<String>,
    members: Vec<MembersJson>,
    open: Vec<String>,
    nodes: Vec<String>,
    tcp_ports: Vec<u16>,
}

fn texts(v: &[Addr]) -> Vec<String> {
    v.iter().map(Addr::to_string).collect()
}

fn addrs(v: &[String]) -> Result<Vec<Addr>, String> {
    v.iter()
        .map(|s| Addr::parse(s).ok_or_else(|| format!("invalid address {s:?}")))
        .collect()
}

impl PolicyJson {
    pub fn of(p: &Policy) -> PolicyJson {
        PolicyJson {
            cidr: p.cidr.to_string(),
            subnet: p.subnet.to_string(),
            gateway: p.gateway.as_ref().map(Addr::to_string).unwrap_or_default(),
            apps: p.members.keys().cloned().collect(),
            members: p
                .members
                .iter()
                .map(|(app, a)| MembersJson {
                    app: app.clone(),
                    addresses: texts(a),
                })
                .collect(),
            open: texts(&p.open),
            nodes: texts(&p.nodes),
            tcp_ports: p.tcp_ports.clone(),
        }
    }

    fn policy(&self) -> Result<Policy, String> {
        let prefix = |s: &str| Prefix::parse(s).ok_or_else(|| format!("invalid prefix {s:?}"));
        let mut members = BTreeMap::new();
        for m in &self.members {
            members.insert(m.app.clone(), addrs(&m.addresses)?);
        }
        Ok(Policy {
            cidr: prefix(&self.cidr)?,
            subnet: prefix(&self.subnet)?,
            gateway: Addr::parse(&self.gateway),
            members,
            open: addrs(&self.open)?,
            nodes: addrs(&self.nodes)?,
            tcp_ports: self.tcp_ports.clone(),
        })
    }
}

fn hex(msgs: &[nft::Msg]) -> Vec<String> {
    msgs.iter()
        .map(|m| m.bytes(0, 0).iter().map(|b| format!("{b:02x}")).collect())
        .collect()
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct NftRequest {
    policy: PolicyJson,
    previous: Option<PolicyJson>,
    has_tables: bool,
    /// The first set ID of the rebuild's batch, and of the update's.
    #[serde(rename = "FirstSetID")]
    first_set_id: u32,
    #[serde(rename = "UpdateSetID")]
    update_set_id: u32,
}

#[derive(Serialize)]
struct NftAnswer {
    action: &'static str,
    isolate: Vec<String>,
    update: Option<Vec<String>>,
    remove: Vec<String>,
}

/// armada-node net firewall nft.
fn nft_command() -> Result<(), String> {
    let req: NftRequest = serde_json::from_slice(&read_stdin()?).map_err(|e| e.to_string())?;
    let pol = req.policy.policy()?;
    let prev = req.previous.as_ref().map(PolicyJson::policy).transpose()?;
    let action = nft::decide(prev.as_ref(), &pol, &mut || req.has_tables);
    let answer = NftAnswer {
        action: action.name(),
        isolate: hex(&nft::isolate(&pol, req.first_set_id).transaction()),
        update: prev
            .as_ref()
            .map(|old| hex(&nft::update_isolation(old, &pol, req.update_set_id).transaction())),
        remove: hex(&nft::remove_isolation().transaction()),
    };
    write_stdout(&serde_json::to_vec(&answer).map_err(|e| e.to_string())?)
}

/// What every firewall command but nft reads: the network configuration
/// seen from this node, as `net plan` reads it.
#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Request {
    config: NetworkConfig,
    node: String,
    #[serde(rename = "PrivateIP")]
    private_ip: String,
    key: String,
    local: Option<HashMap<String, String>>,
    previous: Option<PolicyJson>,
    clean: CleanJson,
    tables: BTreeMap<String, Vec<ChainJson>>,
    fail: Vec<String>,
}

#[derive(Serialize, Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "PascalCase", default)]
struct CleanJson {
    next: bool,
    site: bool,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct ChainJson {
    name: String,
    builtin: bool,
    rules: Vec<String>,
}

impl Request {
    /// Net.plan: the plan, refused in an encrypted mode without a key.
    fn plan(&self) -> Result<(Plan, Addr), String> {
        let ip = Addr::parse(&self.private_ip);
        let p = plan::parse(&self.config, &self.node, &ip)?;
        let key = Key::parse(&self.key).unwrap_or_default();
        if (encrypted(&p.mode) || encrypted(&p.switch_to)) && key.is_zero() {
            return Err(format!("the {MODE_WIREGUARD} mode needs the node's key"));
        }
        Ok((p, ip.unwrap_or(Addr::V4([0; 4]))))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IptablesAnswer {
    plan_error: String,
    calls: Vec<Vec<String>>,
    error: String,
    clean: CleanJson,
    remove_calls: Vec<Vec<String>>,
    remove_errors: Vec<String>,
}

/// armada-node net firewall iptables: Net.firewall and removeFirewall on a
/// model of iptables holding Tables.
fn iptables_command() -> Result<(), String> {
    let req: Request = serde_json::from_slice(&read_stdin()?).map_err(|e| e.to_string())?;
    let sim = || {
        let mut sim = Sim::new();
        for (table, chains) in &req.tables {
            sim.tables.insert(
                table.clone(),
                chains
                    .iter()
                    .map(|c| {
                        (
                            c.name.clone(),
                            SimChain {
                                builtin: c.builtin,
                                rules: c.rules.clone(),
                            },
                        )
                    })
                    .collect(),
            );
        }
        sim.fail = req.fail.clone();
        sim
    };
    let mut answer = IptablesAnswer {
        plan_error: String::new(),
        calls: Vec::new(),
        error: String::new(),
        clean: req.clean,
        remove_calls: Vec::new(),
        remove_errors: Vec::new(),
    };
    match req.plan() {
        Err(e) => answer.plan_error = e,
        Ok((p, ip)) => {
            let mut s = sim();
            let mut clean = Clean {
                next: req.clean.next,
                site: req.clean.site,
            };
            let res = iptables::firewall(&mut Iptables { tool: &mut s }, &p, &ip, &mut clean);
            answer.error = res.err().unwrap_or_default();
            answer.clean = CleanJson {
                next: clean.next,
                site: clean.site,
            };
            answer.calls = s.calls;
        }
    }
    let mut s = sim();
    answer.remove_errors = iptables::remove_firewall(&mut Iptables { tool: &mut s });
    answer.remove_calls = s.calls;
    write_stdout(&serde_json::to_vec(&answer).map_err(|e| e.to_string())?)
}

/// Net.isolate for real: keep, update (rebuilding when that fails), or
/// rebuild the tables; returns which it did.
fn isolate(prev: Option<&Policy>, pol: &Policy) -> Result<&'static str, String> {
    let mut has = || {
        nft::FAMILIES.iter().all(|fam| {
            Socket::open()
                .and_then(|s| s.has_table(&nft::get_table(*fam)))
                .unwrap_or(false)
        })
    };
    let action = nft::decide(prev, pol, &mut has);
    if action == Action::Keep {
        return Ok("keep");
    }
    if let (Action::Update, Some(old)) = (action, prev) {
        let tx = nft::update_isolation(old, pol, 1).transaction();
        match Socket::open().and_then(|s| s.transact(&tx)) {
            Ok(()) => return Ok("update"),
            Err(e) => eprintln!("armada-node: update the isolation rules; rebuilding them: {e}"),
        }
    }
    let tx = nft::isolate(pol, 1).transaction();
    Socket::open()?.transact(&tx)?;
    Ok("rebuild")
}

#[derive(Serialize)]
struct ApplyAnswer {
    policy: PolicyJson,
    clean: CleanJson,
    /// What was done to the isolation tables: keep, update, or rebuild.
    action: &'static str,
}

/// armada-node net firewall apply: Net.Apply's firewall and isolation.
fn apply_command() -> Result<(), String> {
    let req: Request = serde_json::from_slice(&read_stdin()?).map_err(|e| e.to_string())?;
    let (p, ip) = req.plan()?;
    let mut clean = Clean {
        next: req.clean.next,
        site: req.clean.site,
    };
    iptables::firewall(
        &mut Iptables {
            tool: &mut iptables::Program,
        },
        &p,
        &ip,
        &mut clean,
    )
    .map_err(|e| format!("firewall: {e}"))?;
    let local: Option<HashMap<Addr, String>> = req.local.as_ref().map(|m| {
        m.iter()
            .filter_map(|(a, app)| Addr::parse(a).map(|a| (a, app.clone())))
            .collect()
    });
    let pol = build_policy(&p, local.as_ref());
    let prev = req.previous.as_ref().map(PolicyJson::policy).transpose()?;
    let action = isolate(prev.as_ref(), &pol).map_err(|e| format!("isolation: {e}"))?;
    let answer = ApplyAnswer {
        policy: PolicyJson::of(&pol),
        clean: CleanJson {
            next: clean.next,
            site: clean.site,
        },
        action,
    };
    write_stdout(&serde_json::to_vec(&answer).map_err(|e| e.to_string())?)
}

/// armada-node net firewall remove: the isolation tables and the iptables
/// chains taken away (Remove's firewall part).
fn remove_command() -> Result<(), String> {
    let mut errs = Vec::new();
    let tx = nft::remove_isolation().transaction();
    if let Err(e) = Socket::open().and_then(|s| s.transact(&tx)) {
        errs.push(format!("remove the isolation tables: {e}"));
    }
    errs.extend(iptables::remove_firewall(&mut Iptables {
        tool: &mut iptables::Program,
    }));
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("\n"))
    }
}

/// armada-node net firewall OP.
pub fn command(op: &str) -> Result<(), String> {
    match op {
        "nft" => nft_command(),
        "iptables" => iptables_command(),
        "apply" => apply_command(),
        "remove" => remove_command(),
        _ => Err(format!(
            "unknown firewall operation {op:?}; try: nft, iptables, apply, remove"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policies_round_trip() {
        let json = r#"{"cidr":"10.120.0.0/16","subnet":"10.120.0.0/24","gateway":"10.120.0.1",
            "members":[{"app":"web","addresses":["10.120.0.5"]}],"open":[],"nodes":["10.0.0.1"],"tcpPorts":[5432]}"#;
        let p: PolicyJson = serde_json::from_str(json).unwrap();
        let pol = p.policy().unwrap();
        assert_eq!(PolicyJson::of(&pol).policy().unwrap(), pol);
        assert_eq!(pol.members["web"], vec![Addr::parse("10.120.0.5").unwrap()]);
    }

    #[test]
    fn plans_need_a_key_in_the_wireguard_mode() {
        let req: Request = serde_json::from_str(
            r#"{"Config":{"mode":"wireguard","clusterCidr":"10.120.0.0/16","peers":[
                {"node":"a","privateIp":"10.0.0.1","subnet":"10.120.0.0/24"}]},
            "Node":"a","PrivateIP":"10.0.0.1"}"#,
        )
        .unwrap();
        assert_eq!(
            req.plan().err().unwrap(),
            "the wireguard mode needs the node's key"
        );
    }

    #[test]
    fn batches_number_set_ids_from_the_first() {
        let pol = PolicyJson {
            cidr: "10.120.0.0/16".into(),
            subnet: "10.120.0.0/24".into(),
            gateway: "10.120.0.1".into(),
            ..Default::default()
        }
        .policy()
        .unwrap();
        let a = hex(&nft::isolate(&pol, 1).transaction());
        let b = hex(&nft::isolate(&pol, 7).transaction());
        assert_eq!(a.len(), b.len());
        assert_ne!(a, b);
    }
}

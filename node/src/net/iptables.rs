//! The cluster network's iptables chains (clusternet_linux.go: Net.firewall,
//! iptablesCmd, and the iptables part of Remove): which iptables commands
//! run, in which order, decided from what earlier commands answered. The
//! rules themselves come from rules.rs. The tool runs through `Tool`: the
//! real program, or `Sim`, a model of it the parity test drives with the
//! same state as Go's.

use super::addr::Addr;
use super::plan::{INTERFACE, MODE_MESH, NEXT, Plan, SITE_INTERFACE};
use super::rules::{self, CHAIN_IN, CHAIN_MESH, Rule};
use std::collections::BTreeMap;
use std::process::Command;

pub const CHAIN_FWD: &str = "ARMADA-NET-FWD";
pub const CHAIN_PRE: &str = "ARMADA-NET-PRE";
pub const CHAIN_MSS: &str = "ARMADA-NET-MSS";

/// What iptablesCmd.exec does: runs the tool with args and returns its
/// output (with combined, standard error too), or the error Go reports
/// for it, with that output.
pub trait Tool {
    fn exec(&mut self, combined: bool, args: &[String]) -> Result<String, (String, String)>;
}

/// The iptables program.
pub struct Program;

impl Tool for Program {
    fn exec(&mut self, combined: bool, args: &[String]) -> Result<String, (String, String)> {
        let out = Command::new("iptables")
            .args(args)
            .output()
            .map_err(|e| (e.to_string(), String::new()))?;
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        if combined {
            text.push_str(&String::from_utf8_lossy(&out.stderr));
        }
        if out.status.success() {
            return Ok(text);
        }
        // Go's exec.ExitError text.
        let status = match out.status.code() {
            Some(code) => format!("exit status {code}"),
            None => {
                use std::os::unix::process::ExitStatusExt;
                format!("signal: {}", out.status.signal().unwrap_or(0))
            }
        };
        Err((status, text))
    }
}

fn strings(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// iptablesCmd's methods over a tool.
pub struct Iptables<'a> {
    pub tool: &'a mut dyn Tool,
}

impl Iptables<'_> {
    /// run: the tool with -w 5 and args; the error names the arguments.
    pub fn run(&mut self, args: &[String]) -> Result<(), String> {
        let mut full = strings(&["-w", "5"]);
        full.extend_from_slice(args);
        self.tool
            .exec(true, &full)
            .map(|_| ())
            .map_err(|(e, out)| format!("iptables {}: {e}: {}", args.join(" "), out.trim()))
    }

    fn run_with(&mut self, head: &[&str], rule: &[String]) -> Result<(), String> {
        let mut args = strings(head);
        args.extend_from_slice(rule);
        self.run(&args)
    }

    /// chain: create a chain if it does not exist.
    pub fn chain(&mut self, table: &str, name: &str) -> Result<(), String> {
        if self.run(&strings(&["-t", table, "-L", name, "-n"])).is_ok() {
            return Ok(());
        }
        self.run(&strings(&["-t", table, "-N", name]))
    }

    /// fill: replace a chain's rules, unless they already match.
    pub fn fill(&mut self, table: &str, name: &str, rules: &[Rule]) -> Result<(), String> {
        let listed = self
            .tool
            .exec(false, &strings(&["-w", "5", "-t", table, "-S", name]));
        if let Ok(out) = listed {
            let mut want = vec![format!("-N {name}")];
            for r in rules {
                want.push(format!("-A {name} {}", r.join(" ")));
            }
            if out.trim().split('\n').eq(want.iter().map(String::as_str)) {
                return Ok(());
            }
        }
        self.run(&strings(&["-t", table, "-F", name]))?;
        for r in rules {
            self.run_with(&["-t", table, "-A", name], r)?;
        }
        Ok(())
    }

    /// first: make sure a rule is in a built-in chain, at the top when it
    /// was missing.
    pub fn first(&mut self, table: &str, chain: &str, rule: &[String]) -> Result<(), String> {
        if self.run_with(&["-t", table, "-C", chain], rule).is_ok() {
            return Ok(());
        }
        self.run_with(&["-t", table, "-I", chain, "1"], rule)
    }

    /// jumps: the rules of a built-in filter chain that jump to target, as
    /// arguments for -D.
    pub fn jumps(&mut self, chain: &str, target: &str) -> Vec<Rule> {
        let Ok(out) = self.tool.exec(false, &strings(&["-w", "5", "-S", chain])) else {
            return Vec::new();
        };
        let head = format!("-A {chain} ");
        let tail = format!("-j {target}");
        out.split('\n')
            .filter(|line| line.starts_with(&head) && line.ends_with(&tail))
            .map(|line| {
                line[head.len()..]
                    .split_whitespace()
                    .map(String::from)
                    .collect()
            })
            .collect()
    }

    /// only: make rule the one rule of a built-in filter chain that jumps to
    /// target, at the top.
    pub fn only(&mut self, chain: &str, target: &str, rule: &[String]) -> Result<(), String> {
        for r in self.jumps(chain, target) {
            if r != rule {
                self.run_with(&["-D", chain], &r)?;
            }
        }
        self.first("filter", chain, rule)
    }

    /// Delete a rule from a built-in chain for as long as that succeeds.
    fn delete_all(&mut self, table: &str, chain: &str, rule: &[&str]) {
        while self
            .run_with(&["-t", table, "-D", chain], &strings(rule))
            .is_ok()
        {}
    }
}

/// What the firewall remembers between passes (Net.nextClean, siteClean).
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Clean {
    pub next: bool,
    pub site: bool,
}

/// Net.firewall: the cluster network's chains and jumps for plan p of a
/// node at private_ip.
pub fn firewall(
    ipt: &mut Iptables,
    p: &Plan,
    private_ip: &Addr,
    clean: &mut Clean,
) -> Result<(), String> {
    ipt.chain("filter", CHAIN_IN)?;
    let remote = p.has_remote();
    ipt.fill("filter", CHAIN_IN, &rules::input_rules(p, private_ip))?;
    ipt.only("INPUT", CHAIN_IN, &rules::input_jump(p))?;
    if p.mode == MODE_MESH || remote {
        ipt.chain("filter", CHAIN_MESH)?;
        ipt.fill("filter", CHAIN_MESH, &rules::mesh_rules(p))?;
        let jump = strings(&["-i", rules::wg_interface(p), "-j", CHAIN_MESH]);
        ipt.only("INPUT", CHAIN_MESH, &jump)?;
    } else {
        for r in ipt.jumps("INPUT", CHAIN_MESH) {
            ipt.run_with(&["-D", "INPUT"], &r)?;
        }
    }
    let tunnels = rules::tunnels(p);
    ipt.chain("filter", CHAIN_FWD)?;
    ipt.fill(
        "filter",
        CHAIN_FWD,
        &rules::forward_rules(&tunnels, &p.relaying),
    )?;
    ipt.first("filter", "FORWARD", &strings(&["-j", CHAIN_FWD]))?;
    ipt.chain("raw", CHAIN_PRE)?;
    ipt.fill("raw", CHAIN_PRE, &rules::spoof_rules(p))?;
    ipt.first("raw", "PREROUTING", &strings(&["-j", CHAIN_PRE]))?;
    ipt.chain("mangle", CHAIN_MSS)?;
    ipt.fill("mangle", CHAIN_MSS, &rules::mss_rules(&tunnels))?;
    ipt.first("mangle", "FORWARD", &strings(&["-j", CHAIN_MSS]))?;
    // Ahead of the container runtime's masquerading.
    for name in &tunnels {
        ipt.first(
            "nat",
            "POSTROUTING",
            &strings(&["-o", name, "-j", "RETURN"]),
        )?;
    }
    if p.switching() {
        clean.next = false;
    } else if !clean.next {
        ipt.delete_all("nat", "POSTROUTING", &["-o", NEXT, "-j", "RETURN"]);
        clean.next = true;
    }
    if tunnels.contains(&SITE_INTERFACE) {
        clean.site = false;
    } else if !clean.site {
        ipt.delete_all(
            "nat",
            "POSTROUTING",
            &["-o", SITE_INTERFACE, "-j", "RETURN"],
        );
        clean.site = true;
    }
    Ok(())
}

/// removeFirewall: the chains and jumps taken away, with what failed.
pub fn remove_firewall(ipt: &mut Iptables) -> Vec<String> {
    let mut errs = Vec::new();
    for r in [
        ["filter", "FORWARD", "-j", CHAIN_FWD].as_slice(),
        &["raw", "PREROUTING", "-j", CHAIN_PRE],
        &["nat", "POSTROUTING", "-o", INTERFACE, "-j", "RETURN"],
        &["nat", "POSTROUTING", "-o", NEXT, "-j", "RETURN"],
        &["nat", "POSTROUTING", "-o", SITE_INTERFACE, "-j", "RETURN"],
        &["mangle", "FORWARD", "-j", CHAIN_MSS],
    ] {
        ipt.delete_all(r[0], r[1], &r[2..]);
    }
    let mut keep = |res: Result<(), String>| {
        if let Err(e) = res {
            errs.push(e);
        }
    };
    for c in [CHAIN_IN, CHAIN_MESH] {
        for r in ipt.jumps("INPUT", c) {
            keep(ipt.run_with(&["-D", "INPUT"], &r));
        }
    }
    for c in [CHAIN_IN, CHAIN_MESH, CHAIN_FWD] {
        if ipt.run(&strings(&["-L", c, "-n"])).is_ok() {
            keep(ipt.run(&strings(&["-F", c])));
            keep(ipt.run(&strings(&["-X", c])));
        }
    }
    for (table, c) in [("raw", CHAIN_PRE), ("mangle", CHAIN_MSS)] {
        if ipt.run(&strings(&["-t", table, "-L", c, "-n"])).is_ok() {
            keep(ipt.run(&strings(&["-t", table, "-F", c])));
            keep(ipt.run(&strings(&["-t", table, "-X", c])));
        }
    }
    errs
}

/// A chain of the model: built in or not, with its rules as -S prints them
/// after "-A NAME ".
#[derive(Clone, Default, Debug)]
pub struct SimChain {
    pub builtin: bool,
    pub rules: Vec<String>,
}

/// Sim: a model of iptables for tests, recording every call. It keeps the
/// rules as their argument text: the rules Armada writes are already in
/// the form -S prints. Calls whose arguments (after -w 5) are in fail fail.
#[derive(Default, Debug)]
pub struct Sim {
    /// Tables by name, chains by name in the order they were made.
    pub tables: BTreeMap<String, Vec<(String, SimChain)>>,
    pub fail: Vec<String>,
    pub calls: Vec<Vec<String>>,
}

/// The built-in chains of each table.
pub const BUILTIN: [(&str, &[&str]); 4] = [
    ("filter", &["INPUT", "FORWARD", "OUTPUT"]),
    ("raw", &["PREROUTING", "OUTPUT"]),
    (
        "mangle",
        &["PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"],
    ),
    ("nat", &["PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"]),
];

impl Sim {
    /// A model with only the built-in chains, empty.
    pub fn new() -> Sim {
        let mut s = Sim::default();
        for (table, chains) in BUILTIN {
            s.tables.insert(
                table.to_string(),
                chains
                    .iter()
                    .map(|c| {
                        (
                            c.to_string(),
                            SimChain {
                                builtin: true,
                                rules: Vec::new(),
                            },
                        )
                    })
                    .collect(),
            );
        }
        s
    }

    fn chain_mut(&mut self, table: &str, name: &str) -> Option<&mut SimChain> {
        self.tables
            .get_mut(table)?
            .iter_mut()
            .find(|(n, _)| n == name)
            .map(|(_, c)| c)
    }

    fn call(&mut self, args: &[String]) -> Result<String, ()> {
        let mut a: &[String] = args;
        if a.len() >= 2 && a[0] == "-w" {
            a = &a[2..];
        }
        if self.fail.iter().any(|f| *f == a.join(" ")) {
            return Err(());
        }
        let mut table = "filter";
        if a.len() >= 2 && a[0] == "-t" {
            table = &a[1];
            a = &a[2..];
        }
        let table = table.to_string();
        let (Some(op), Some(name)) = (a.first(), a.get(1)) else {
            return Err(());
        };
        let rest = a[2..].join(" ");
        if op == "-N" {
            if self.chain_mut(&table, name).is_some() {
                return Err(());
            }
            let chains = self.tables.entry(table).or_default();
            chains.push((name.clone(), SimChain::default()));
            return Ok(String::new());
        }
        if op == "-X" {
            let chains = self.tables.get_mut(&table).ok_or(())?;
            let i = chains.iter().position(|(n, _)| n == name).ok_or(())?;
            chains.remove(i);
            return Ok(String::new());
        }
        let c = self.chain_mut(&table, name).ok_or(())?;
        match op.as_str() {
            "-L" => Ok(String::new()),
            "-S" => {
                let mut out = if c.builtin {
                    format!("-P {name} ACCEPT\n")
                } else {
                    format!("-N {name}\n")
                };
                for r in &c.rules {
                    out.push_str(&format!("-A {name} {r}\n"));
                }
                Ok(out)
            }
            "-F" => {
                c.rules.clear();
                Ok(String::new())
            }
            "-A" => {
                c.rules.push(rest);
                Ok(String::new())
            }
            "-I" => {
                let r = a[3..].join(" ");
                c.rules.insert(0, r);
                Ok(String::new())
            }
            "-C" => c.rules.contains(&rest).then(String::new).ok_or(()),
            "-D" => {
                let i = c.rules.iter().position(|r| *r == rest).ok_or(())?;
                c.rules.remove(i);
                Ok(String::new())
            }
            _ => Err(()),
        }
    }
}

impl Tool for Sim {
    fn exec(&mut self, _combined: bool, args: &[String]) -> Result<String, (String, String)> {
        self.calls.push(args.to_vec());
        self.call(args)
            .map_err(|()| ("exit status 1".to_string(), "simulated failure".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::config::NetworkConfig;
    use crate::net::plan;

    fn plan_of(json: &str) -> Plan {
        let cfg: NetworkConfig = serde_json::from_str(json).unwrap();
        plan::parse(&cfg, "a", &Addr::parse("10.0.0.1")).unwrap()
    }

    const TWO: &str = r#"{"mode":"plain","clusterCidr":"10.120.0.0/16","peers":[
        {"node":"a","privateIp":"10.0.0.1","subnet":"10.120.0.0/24"},
        {"node":"b","privateIp":"10.0.0.2","subnet":"10.120.1.0/24"}]}"#;

    #[test]
    fn a_second_pass_changes_nothing() {
        let p = plan_of(TWO);
        let ip = Addr::parse("10.0.0.1").unwrap();
        let mut sim = Sim::new();
        let mut clean = Clean::default();
        firewall(&mut Iptables { tool: &mut sim }, &p, &ip, &mut clean).unwrap();
        assert!(clean.next && clean.site);
        let first = sim.calls.len();
        firewall(&mut Iptables { tool: &mut sim }, &p, &ip, &mut clean).unwrap();
        let second = &sim.calls[first..];
        // Only checks and listings: no -A, -I, -F, -D, -N.
        assert!(second.iter().all(|c| {
            !c.iter()
                .any(|a| ["-A", "-I", "-F", "-D", "-N"].contains(&a.as_str()))
        }));
        let fwd = sim.chain_mut("filter", "FORWARD").unwrap();
        assert_eq!(fwd.rules, vec![format!("-j {CHAIN_FWD}")]);
    }

    #[test]
    fn removal_leaves_the_builtin_chains() {
        let p = plan_of(TWO);
        let ip = Addr::parse("10.0.0.1").unwrap();
        let mut sim = Sim::new();
        firewall(
            &mut Iptables { tool: &mut sim },
            &p,
            &ip,
            &mut Clean::default(),
        )
        .unwrap();
        let errs = remove_firewall(&mut Iptables { tool: &mut sim });
        assert!(errs.is_empty(), "{errs:?}");
        for (table, chains) in &sim.tables {
            for (name, c) in chains {
                assert!(c.builtin, "{table} {name} left");
                assert!(c.rules.is_empty(), "{table} {name}: {:?}", c.rules);
            }
        }
    }

    #[test]
    fn errors_name_the_arguments() {
        let mut sim = Sim::new();
        sim.fail.push("-t filter -N X".into());
        let err = Iptables { tool: &mut sim }
            .chain("filter", "X")
            .unwrap_err();
        assert_eq!(
            err,
            "iptables -t filter -N X: exit status 1: simulated failure"
        );
    }
}

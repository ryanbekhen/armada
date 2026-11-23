//! The kernel side of the cluster network (clusternet_linux.go's Net.Apply,
//! Net.Up, and Remove, with vxlan_linux.go, wireguard_linux.go, and
//! switch_linux.go): the firewall and isolation tables first, then the
//! tunnel interfaces (VXLAN, or kernel WireGuard), their addresses, peers,
//! forwarding and neighbour entries, and routes, in the order Go sets them
//! up. The userspace WireGuard device stays in the Go agent: where Go would
//! start it, this answers that the pass needs it.
//!
//!   armada-node net apply    stdin: a request (below); stdout: the answer
//!   armada-node net up       stdin: a request whose Config may be null
//!                            (the peer list kept in MeshCache)
//!   armada-node net remove   the tunnels, isolation tables, firewall
//!                            chains, and the userspace device's socket
//!
//! A request is one JSON object: Config (a NetworkConfig in protojson, or
//! null), Node, PrivateIP, Endpoint ("" for none), MeshCache, UplinkMTU,
//! Key (the private key, "" for none), Local (the node's containers, null
//! when they are not in its subnet), Userspace (the Go agent holds the
//! userspace device), and State: what Go's Net keeps between passes
//! (Previous: the isolation policy last applied, Clean, Switch, Since,
//! Last). The answer: {error, needsUserspace, state, switch (the
//! SwitchStatus, or null), done (what changed), log}.

use super::addr::{Addr, Prefix};
use super::config::NetworkConfig;
use super::firewall::PolicyJson;
use super::iptables::{self, Clean, Iptables, Program};
use super::kernel::Socket as NftSocket;
use super::key::Key;
use super::netlink::Errno;
use super::nft::{self, Action};
use super::plan::{
    self, INTERFACE, MODE_MESH, MODE_PLAIN, MODE_WIREGUARD, NEXT, Peer, Plan, SITE_INTERFACE,
    SWITCH_MOVE, VXLAN_PORT, encrypted,
};
use super::policy::{Policy, build_policy};
use super::rtnl::{self, AF_BRIDGE, AF_INET, Handle, IfAddr, Link, Neigh, Route};
use super::rules::{self, RouteSet};
use super::wgnl::{self, WgError};
use super::wireguard;
use super::{mesh, probe, read_stdin, write_stdout};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The VXLAN network identifier of Armada's tunnel.
pub const VNI: u32 = 7027;
/// MinUplinkMTU.
pub const MIN_UPLINK_MTU: i64 = 1280;
/// Where the userspace WireGuard device serves its control socket.
pub const USER_SOCKET: &str = "/var/run/wireguard/armada-net.sock";
/// probeEvery and probeWait, in milliseconds.
const PROBE_EVERY: i64 = 5000;
const PROBE_WAIT: u64 = 2000;
const MAX_UNREACHED: usize = 32;

/// Why a pass stopped: an error as Go words it, or the userspace device
/// the Go agent holds.
#[derive(Debug)]
pub enum Fail {
    Err(String),
    Userspace,
}

impl From<String> for Fail {
    fn from(s: String) -> Fail {
        Fail::Err(s)
    }
}

impl Fail {
    fn text(&self) -> String {
        match self {
            Fail::Err(s) => s.clone(),
            Fail::Userspace => {
                "the kernel has no WireGuard; the Go agent runs it in userspace".to_string()
            }
        }
    }
}

type Res<T> = Result<T, Fail>;

fn errno(e: Errno) -> Fail {
    Fail::Err(e.to_string())
}

fn ctx(what: impl std::fmt::Display) -> impl FnOnce(Errno) -> Fail {
    move |e| Fail::Err(format!("{what}: {e}"))
}

#[derive(Serialize, Deserialize, Default, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "PascalCase", default)]
pub struct CleanState {
    pub next: bool,
    pub site: bool,
}

/// switchState.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "PascalCase", default)]
pub struct SwitchState {
    pub to: String,
    pub step: String,
    pub error: String,
    pub peers: Vec<String>,
    pub reached: Vec<String>,
    pub probed: bool,
    /// When the last probe started, Unix milliseconds (0: none yet).
    pub probe_at: i64,
    pub moved: bool,
}

/// wgPeerSeen, by key.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "PascalCase", default)]
pub struct SeenState {
    pub key: String,
    pub node: String,
    /// Unix seconds.
    pub since: i64,
}

/// What Go's Net keeps between passes.
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct State {
    pub previous: Option<PolicyJson>,
    pub clean: CleanState,
    pub switch: SwitchState,
    #[serde(deserialize_with = "super::config::nullable")]
    pub since: Vec<SeenState>,
    /// The summary of the last plan applied, to log changes once.
    pub last: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Request {
    config: Option<NetworkConfig>,
    node: String,
    #[serde(rename = "PrivateIP")]
    private_ip: String,
    endpoint: String,
    mesh_cache: String,
    #[serde(rename = "UplinkMTU")]
    uplink_mtu: i64,
    key: String,
    local: Option<HashMap<String, String>>,
    userspace: bool,
    // Go sends null before the first pass.
    #[serde(deserialize_with = "super::config::nullable")]
    state: State,
}

/// SwitchStatus, as protojson writes a NetworkSwitchStatus.
#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SwitchStatus {
    pub to: String,
    pub step: String,
    pub ready: bool,
    pub unreached: Vec<String>,
    pub error: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Answer {
    error: String,
    needs_userspace: bool,
    state: State,
    switch: Option<SwitchStatus>,
    done: Vec<String>,
    log: Vec<String>,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn bytes(a: &Addr) -> Vec<u8> {
    rtnl::v4(a)
}

fn same_ip(a: &[u8], b: &[u8]) -> bool {
    rtnl::addr_of(a) == rtnl::addr_of(b)
}

fn ip_text(b: &[u8]) -> String {
    rtnl::addr_of(b).map_or_else(|| "<nil>".to_string(), |a| a.to_string())
}

/// tunnelName.
fn tunnel_name(name: &str) -> bool {
    name == INTERFACE || name == NEXT || name == SITE_INTERFACE
}

/// UplinkOf's failures: no interface holds the address (errNoUplink), or
/// anything else.
enum Uplink {
    None(String),
    Other(Fail),
}

/// The node's cluster network on this machine, for one command.
pub struct Net {
    node: String,
    ip: Addr,
    endpoint: Option<Addr>,
    mesh_cache: String,
    uplink_mtu: i64,
    key: Key,
    pub st: State,
    pub done: Vec<String>,
    pub log: Vec<String>,
    rt: Handle,
}

impl Net {
    fn new(req: &Request, st: State) -> Result<Net, String> {
        let ip = Addr::parse(&req.private_ip)
            .filter(Addr::is4)
            .ok_or_else(|| {
                format!(
                    "cluster network: private IP {} is not IPv4",
                    if req.private_ip.is_empty() {
                        "invalid IP"
                    } else {
                        &req.private_ip
                    }
                )
            })?;
        Ok(Net {
            node: req.node.clone(),
            ip,
            endpoint: Addr::parse(&req.endpoint),
            mesh_cache: req.mesh_cache.clone(),
            uplink_mtu: req.uplink_mtu,
            key: Key::parse(&req.key).unwrap_or_default(),
            st,
            done: Vec::new(),
            log: Vec::new(),
            rt: Handle::open().map_err(|e| e.to_string())?,
        })
    }

    fn info(&mut self, s: String) {
        self.log.push(s);
    }

    fn did(&mut self, s: String) {
        self.done.push(s);
    }

    /// Net.plan.
    fn plan(&self, cfg: &NetworkConfig) -> Result<Plan, String> {
        let p = plan::parse(cfg, &self.node, &Some(self.ip.clone()))?;
        if (encrypted(&p.mode) || encrypted(&p.switch_to)) && self.key.is_zero() {
            return Err(format!("the {MODE_WIREGUARD} mode needs the node's key"));
        }
        Ok(p)
    }

    /// Net.firewall.
    fn firewall(&mut self, p: &Plan) -> Res<()> {
        let mut clean = Clean {
            next: self.st.clean.next,
            site: self.st.clean.site,
        };
        let res = iptables::firewall(
            &mut Iptables { tool: &mut Program },
            p,
            &self.ip,
            &mut clean,
        );
        self.st.clean = CleanState {
            next: clean.next,
            site: clean.site,
        };
        res.map_err(|e| Fail::Err(format!("firewall: {e}")))
    }

    /// Net.isolate.
    fn isolate(&mut self, pol: &Policy) -> Result<(), String> {
        let prev = self
            .st
            .previous
            .as_ref()
            .map(PolicyJson::policy)
            .transpose()?;
        let mut has = || {
            nft::FAMILIES.iter().all(|fam| {
                NftSocket::open()
                    .and_then(|s| s.has_table(&nft::get_table(*fam)))
                    .unwrap_or(false)
            })
        };
        let action = nft::decide(prev.as_ref(), pol, &mut has);
        if action == Action::Keep {
            return Ok(());
        }
        if let (Action::Update, Some(old)) = (action, prev.as_ref()) {
            let tx = nft::update_isolation(old, pol, 1).transaction();
            match NftSocket::open().and_then(|s| s.transact(&tx)) {
                Ok(()) => {
                    self.st.previous = Some(PolicyJson::of(pol));
                    self.did("isolation updated".into());
                    return Ok(());
                }
                Err(e) => self.info(format!("update the isolation rules; rebuilding them: {e}")),
            }
        }
        let tx = nft::isolate(pol, 1).transaction();
        if let Err(e) = NftSocket::open().and_then(|s| s.transact(&tx)) {
            self.st.previous = None;
            return Err(e);
        }
        self.st.previous = Some(PolicyJson::of(pol));
        self.did("isolation rebuilt".into());
        Ok(())
    }

    /// Net.Apply.
    pub fn apply(&mut self, cfg: &NetworkConfig, local: Option<&HashMap<Addr, String>>) -> Res<()> {
        let p = self.plan(cfg)?;
        self.firewall(&p)?;
        self.isolate(&build_policy(&p, local))
            .map_err(|e| Fail::Err(format!("isolation: {e}")))?;
        let res = self.tunnel(&p);
        self.track(&p, res.as_ref().err());
        res?;
        self.see_peers(&p, now_ms() / 1000);
        if self.mesh_cache.is_empty() {
            return Ok(());
        }
        let path = self.mesh_cache.clone();
        if p.mode == MODE_MESH || p.has_remote() {
            if let Err(e) = mesh::save(Path::new(&path), cfg) {
                self.info(format!("keep the peer list: {e}"));
            }
        } else if let Err(e) = remove_mesh_cache(&path) {
            self.info(format!("remove the peer list: {e}"));
        }
        Ok(())
    }

    /// Net.Up.
    pub fn up(&mut self, cfg: Option<NetworkConfig>) -> Res<()> {
        if self.mesh_cache.is_empty() {
            return Err(Fail::Err(
                "the mesh mode needs a place to keep its peer list".into(),
            ));
        }
        let path = self.mesh_cache.clone();
        let given = cfg.is_some();
        let cfg = match cfg {
            Some(c) => c,
            None => match mesh::load(Path::new(&path))? {
                Some(c) => c,
                None => return Ok(()),
            },
        };
        let p = self
            .plan(&cfg)
            .map_err(|e| Fail::Err(format!("peer list: {e}")))?;
        self.firewall(&p)?;
        self.tunnel(&p)?;
        if given {
            mesh::save(Path::new(&path), &cfg)?;
        }
        Ok(())
    }

    /// Net.tunnel.
    fn tunnel(&mut self, p: &Plan) -> Res<()> {
        if !p.switching() {
            self.finish_switch(&p.mode)?;
            let all = if p.mode == MODE_PLAIN {
                self.sites(p)?;
                if p.meshed {
                    return self.drop_vxlan(p);
                }
                p.only(p.local())
            } else {
                self.sites(&p.only(Vec::new()))?;
                p.clone()
            };
            let mtu = self.transport(&all, &p.mode, INTERFACE, RouteSet::All)?;
            let remote = p.remote().len();
            let subnet = p.self_.subnet().to_string();
            let summary = format!("{} {} {} {}", p.mode, subnet, p.peers.len(), remote);
            if summary != self.st.last {
                self.info(format!(
                    "cluster network applied mode={} subnet={} peers={} other_sites={} mtu={}",
                    p.mode,
                    subnet,
                    p.peers.len(),
                    remote,
                    mtu
                ));
                self.st.last = summary;
            }
            return Ok(());
        }
        if p.step == SWITCH_MOVE {
            self.transport(p, &p.switch_to, NEXT, RouteSet::All)?;
            self.transport(p, &p.mode, INTERFACE, RouteSet::None)?;
            return Ok(());
        }
        self.transport(p, &p.mode, INTERFACE, RouteSet::All)?;
        self.transport(p, &p.switch_to, NEXT, RouteSet::Probe)?;
        Ok(())
    }

    /// Net.dropVXLAN.
    fn drop_vxlan(&mut self, p: &Plan) -> Res<()> {
        let subnet = p.self_.subnet().to_string();
        let summary = format!("{} {} meshed {}", p.mode, subnet, p.peers.len());
        if summary != self.st.last {
            self.info(format!(
                "cluster network applied mode={} subnet={} peers={} mesh_address={}",
                p.mode,
                subnet,
                p.peers.len(),
                p.self_.ip()
            ));
            self.st.last = summary;
        }
        match self.rt.link_named(INTERFACE).map_err(errno)? {
            Some(l) => self.del_link(&l),
            None => Ok(()),
        }
    }

    /// Net.sites.
    fn sites(&mut self, p: &Plan) -> Res<()> {
        let remote = p.remote();
        if remote.is_empty() {
            let Some(l) = self.rt.link_named(SITE_INTERFACE).map_err(errno)? else {
                return Ok(());
            };
            self.info(format!(
                "no node in another site; removing their interface interface={SITE_INTERFACE}"
            ));
            return self.del_link(&l);
        }
        self.transport(
            &p.only(remote),
            MODE_WIREGUARD,
            SITE_INTERFACE,
            RouteSet::All,
        )?;
        Ok(())
    }

    /// Net.transport: the MTU it set.
    fn transport(&mut self, p: &Plan, mode: &str, name: &str, r: RouteSet) -> Res<i64> {
        let (uplink, mut uplink_mtu, _) = self.uplink_for(mode)?;
        if encrypted(mode) {
            uplink_mtu = uplink_mtu.min(self.remote_uplink_mtu(&p.remote(), uplink_mtu));
        }
        if self.uplink_mtu > 0 {
            uplink_mtu = uplink_mtu.min(self.uplink_mtu);
        }
        let mtu = plan::tunnel_mtu(mode, uplink_mtu);
        if encrypted(mode) {
            self.wireguard(p, mode, name, mtu, r)?;
        } else {
            self.vxlan(p, name, &uplink, mtu, r)?;
        }
        Ok(mtu)
    }

    /// Net.finishSwitch.
    fn finish_switch(&mut self, mode: &str) -> Res<()> {
        let Some(next) = self.rt.link_named(NEXT).map_err(errno)? else {
            return Ok(());
        };
        let cur = self.rt.link_named(INTERFACE).map_err(errno)?;
        if !carries(&next, mode) || cur.as_ref().is_some_and(|c| carries(c, mode)) {
            self.info(format!(
                "removing the interface of a switch that did not happen interface={NEXT}"
            ));
            return self.del_link(&next);
        }
        if let Some(cur) = cur {
            self.del_link(&cur)?;
        }
        self.rt
            .exec(&rtnl::set_down(next.index))
            .map_err(ctx(format!("take {NEXT} down")))?;
        self.rt
            .exec(&rtnl::set_name(next.index, INTERFACE))
            .map_err(ctx(format!("rename {NEXT} to {INTERFACE}")))?;
        self.did(format!("renamed {NEXT} to {INTERFACE}"));
        self.info(format!("cluster network switched mode={mode}"));
        Ok(())
    }

    /// Net.delLink (the kernel's interfaces only: the userspace device is
    /// the Go agent's).
    fn del_link(&mut self, l: &Link) -> Res<()> {
        self.rt
            .exec(&rtnl::del_link(l.index))
            .map_err(ctx(format!("remove {}", l.name)))?;
        self.did(format!("removed {}", l.name));
        Ok(())
    }

    /// remoteUplinkMTU. A peer behind NAT has no endpoint: Go asks for the
    /// route to the empty address, which the kernel refuses, and skips it.
    fn remote_uplink_mtu(&mut self, peers: &[Peer], def: i64) -> i64 {
        let mut mtu = def;
        for pe in peers {
            let Some(ep) = &pe.endpoint else { continue };
            let Ok(routes) = self.rt.route_get(&bytes(ep)) else {
                continue;
            };
            let Some(r) = routes.first() else { continue };
            let Ok(l) = self.rt.link_by_index(r.oif) else {
                continue;
            };
            if tunnel_name(&l.name) || l.name == "lo" {
                continue;
            }
            if i64::from(l.mtu) >= MIN_UPLINK_MTU {
                mtu = mtu.min(i64::from(l.mtu));
            }
        }
        mtu
    }

    /// UplinkOf.
    fn uplink_of(&mut self, ip: &Addr) -> Result<(Link, i64), Uplink> {
        let addrs = self
            .rt
            .addrs(0, AF_INET)
            .map_err(|e| Uplink::Other(errno(e)))?;
        for a in addrs {
            if rtnl::addr_of(&a.ip).as_ref() == Some(ip) {
                let l = self
                    .rt
                    .link_by_index(a.index)
                    .map_err(|e| Uplink::Other(errno(e)))?;
                let mtu = i64::from(l.mtu);
                if mtu < MIN_UPLINK_MTU {
                    return Err(Uplink::Other(Fail::Err(format!(
                        "the interface of {ip} ({}) has MTU {mtu}, below {MIN_UPLINK_MTU}",
                        l.name
                    ))));
                }
                return Ok((l, mtu));
            }
        }
        Err(Uplink::None(format!(
            "no interface holds the private IP {ip}"
        )))
    }

    /// uplinkFor: the uplink, its MTU, and whether the node is meshed.
    fn uplink_for(&mut self, mode: &str) -> Res<(Link, i64, bool)> {
        if mode != MODE_MESH {
            let ip = self.ip.clone();
            let res = self.uplink_of(&ip);
            let tunnel = matches!(&res, Ok((l, _)) if tunnel_name(&l.name));
            if self.endpoint.is_none() || (res.is_ok() && !tunnel) {
                return match res {
                    Ok((l, mtu)) => Ok((l, mtu, false)),
                    Err(Uplink::None(s)) => Err(Fail::Err(s)),
                    Err(Uplink::Other(f)) => Err(f),
                };
            }
            return match res {
                Ok(_) | Err(Uplink::None(_)) => {
                    let (l, mtu) = self.endpoint_uplink()?;
                    Ok((l, mtu, true))
                }
                Err(Uplink::Other(f)) => Err(f),
            };
        }
        let (l, mtu) = self.endpoint_uplink()?;
        Ok((l, mtu, false))
    }

    /// endpointUplink.
    fn endpoint_uplink(&mut self) -> Res<(Link, i64)> {
        let Some(ep) = self.endpoint.clone() else {
            return Err(Fail::Err("the mesh mode needs the node's endpoint".into()));
        };
        if let Ok(found) = self.uplink_of(&ep) {
            return Ok(found);
        }
        let routes = self
            .rt
            .route_get(&bytes(&ep))
            .map_err(ctx(format!("no route towards the endpoint {ep}")))?;
        let Some(r) = routes.first() else {
            return Err(Fail::Err(format!("no route towards the endpoint {ep}")));
        };
        let l = self.rt.link_by_index(r.oif).map_err(errno)?;
        let mtu = i64::from(l.mtu);
        if tunnel_name(&l.name) || l.name == "lo" {
            return Err(Fail::Err(format!(
                "the route towards the endpoint {ep} leaves by {}, not an uplink",
                l.name
            )));
        }
        if mtu < MIN_UPLINK_MTU {
            return Err(Fail::Err(format!(
                "the uplink {} has MTU {mtu}, below {MIN_UPLINK_MTU}",
                l.name
            )));
        }
        Ok((l, mtu))
    }

    /// Net.vxlan.
    fn vxlan(&mut self, p: &Plan, name: &str, uplink: &Link, mtu: i64, r: RouteSet) -> Res<()> {
        let link = self.vxlan_device(p, name, uplink, mtu)?;
        self.vxlan_peers(p, &link)?;
        self.sync_routes(&link, p, true, r)
    }

    /// Net.vxlanDevice.
    fn vxlan_device(&mut self, p: &Plan, name: &str, uplink: &Link, mtu: i64) -> Res<Link> {
        let mac = rtnl::parse_mac(&rules::vtep_mac(p.self_.subnet()));
        let want = rtnl::Vxlan {
            id: VNI,
            link: uplink.index as u32,
            local: bytes(&self.ip),
            port: VXLAN_PORT,
            learning: false,
        };
        let mut link = self.rt.link_named(name).map_err(errno)?;
        if let Some(l) = &link {
            let ok = l.vxlan.as_ref().is_some_and(|v| {
                v.id == want.id
                    && v.port == want.port
                    && !v.learning
                    && v.link == want.link
                    && same_ip(&v.local, &want.local)
            });
            if !ok {
                self.info(format!(
                    "replacing the cluster network interface interface={name}"
                ));
                let l = l.clone();
                self.del_link(&l)?;
                link = None;
            }
        }
        let link = match link {
            Some(l) => l,
            None => {
                match self
                    .rt
                    .exec(&rtnl::add_vxlan(name, mtu as u32, &mac, &want))
                {
                    Ok(()) => self.did(format!("created {name} (vxlan)")),
                    Err(Errno(libc::EEXIST)) => {}
                    Err(e) => return Err(Fail::Err(format!("create {name}: {e}"))),
                }
                self.link_by_name(name)?
            }
        };
        if link.mac != mac {
            self.rt
                .exec(&rtnl::set_mac(link.index, &mac))
                .map_err(ctx(format!("set address of {name}")))?;
            self.did(format!(
                "set the address of {name} to {}",
                rtnl::mac_text(&mac)
            ));
        }
        self.set_up(&link, p, mtu)?;
        Ok(link)
    }

    /// LinkByName where the interface must exist.
    fn link_by_name(&mut self, name: &str) -> Res<Link> {
        self.rt
            .link_named(name)
            .map_err(errno)?
            .ok_or_else(|| Fail::Err("Link not found".into()))
    }

    /// setUp.
    fn set_up(&mut self, link: &Link, p: &Plan, mtu: i64) -> Res<()> {
        let name = link.name.clone();
        if i64::from(link.mtu) != mtu {
            self.rt
                .exec(&rtnl::set_mtu(link.index, mtu as u32))
                .map_err(ctx(format!("set MTU of {name}")))?;
            self.did(format!("set the MTU of {name} to {mtu}"));
        }
        let want: Vec<Vec<u8>> = rules::tunnel_addresses(p)
            .iter()
            .map(|a| bytes(&a.addr))
            .collect();
        for a in self.rt.addrs(link.index, AF_INET).map_err(errno)? {
            if !want.iter().any(|w| same_ip(&a.ip, w)) {
                self.rt
                    .exec(&rtnl::addr(false, link.index, &a))
                    .map_err(errno)?;
                self.did(format!("removed address {} from {name}", ip_text(&a.ip)));
            }
        }
        for w in want {
            let a = IfAddr {
                ip: w,
                prefixlen: 32,
                ..IfAddr::default()
            };
            self.rt
                .exec(&rtnl::addr(true, link.index, &a))
                .map_err(ctx(format!("address {name}")))?;
        }
        self.rt.exec(&rtnl::set_up(link.index)).map_err(errno)
    }

    /// vxlanPeers.
    fn vxlan_peers(&mut self, p: &Plan, link: &Link) -> Res<()> {
        let idx = link.index;
        let mut want_neigh = HashSet::new();
        let mut want_fdb = HashSet::new();
        for pe in &p.peers {
            let (mac, gw) = rules::vxlan_entry(pe);
            let mac = rtnl::parse_mac(&mac);
            self.rt
                .exec(&rtnl::neigh(
                    true,
                    &Neigh {
                        index: idx,
                        family: AF_BRIDGE,
                        flags: rtnl::NTF_SELF,
                        state: rtnl::NUD_PERMANENT,
                        ip: bytes(pe.ip()),
                        mac: Some(mac.clone()),
                        ..Neigh::default()
                    },
                ))
                .map_err(ctx(format!("forwarding entry for {}", pe.node)))?;
            self.rt
                .exec(&rtnl::neigh(
                    true,
                    &Neigh {
                        index: idx,
                        family: AF_INET,
                        state: rtnl::NUD_PERMANENT,
                        ip: bytes(&gw),
                        mac: Some(mac.clone()),
                        ..Neigh::default()
                    },
                ))
                .map_err(ctx(format!("neighbour entry for {}", pe.node)))?;
            want_neigh.insert(gw.to_string());
            want_fdb.insert(rtnl::mac_text(&mac));
        }
        for ne in self.rt.neighs(idx, AF_INET).map_err(errno)? {
            let ip = ip_text(&ne.ip);
            if !want_neigh.contains(&ip) {
                self.rt
                    .exec(&rtnl::neigh(false, &ne))
                    .map_err(ctx(format!("remove neighbour {ip}")))?;
                self.did(format!("removed neighbour {ip} from {}", link.name));
            }
        }
        for ne in self.rt.neighs(idx, AF_BRIDGE).map_err(errno)? {
            let Some(mac) = ne.mac.as_ref().map(|m| rtnl::mac_text(m)) else {
                continue;
            };
            if !want_fdb.contains(&mac) && ne.state & rtnl::NUD_PERMANENT != 0 {
                self.rt
                    .exec(&rtnl::neigh(false, &ne))
                    .map_err(ctx(format!("remove forwarding entry {mac}")))?;
                self.did(format!("removed forwarding entry {mac} from {}", link.name));
            }
        }
        Ok(())
    }

    /// syncRoutes.
    fn sync_routes(&mut self, link: &Link, p: &Plan, via: bool, set: RouteSet) -> Res<()> {
        let idx = link.index;
        let mut want = HashSet::new();
        for w in rules::want_routes(p, via, set) {
            let mut r = Route {
                oif: idx,
                dst: Some((bytes(&w.dst.addr), w.dst.bits)),
                scope: rtnl::RT_SCOPE_LINK,
                src: w.src.as_ref().map(bytes),
                ..Route::default()
            };
            if let Some(gw) = &w.via {
                r.scope = rtnl::RT_SCOPE_UNIVERSE;
                r.gw = Some(bytes(gw));
                r.flags = rtnl::RTNH_F_ONLINK;
            }
            let what = match &w.src {
                Some(_) => w.dst.addr.to_string(),
                None => w.dst.to_string(),
            };
            self.rt
                .exec(&rtnl::replace_route(&r))
                .map_err(ctx(format!("route to {} ({what})", w.node)))?;
            want.insert(w.dst.clone());
        }
        for r in self.rt.routes(idx, AF_INET).map_err(errno)? {
            let Some((ip, bits)) = &r.dst else { continue };
            let Some(addr) = rtnl::addr_of(ip) else {
                continue;
            };
            let dst = Prefix::from(&addr, *bits);
            if !want.contains(&dst) && r.protocol != rtnl::RTPROT_KERNEL {
                self.rt
                    .exec(&rtnl::del_route(&r))
                    .map_err(ctx(format!("remove route {dst}")))?;
                self.did(format!("removed the route to {dst} from {}", link.name));
            }
        }
        Ok(())
    }

    /// Net.wireguard.
    fn wireguard(&mut self, p: &Plan, mode: &str, name: &str, mtu: i64, r: RouteSet) -> Res<()> {
        let link = self.wg_device(name, mtu, mode == MODE_WIREGUARD && name == INTERFACE)?;
        self.set_up(&link, p, mtu)?;
        self.wg_peers(name, mode, &p.peers)?;
        self.sync_routes(&link, p, false, r)
    }

    /// Net.wgDevice: user is whether Go would fall back to the userspace
    /// device, which this answers with Fail::Userspace.
    fn wg_device(&mut self, name: &str, mtu: i64, user: bool) -> Res<Link> {
        if let Some(l) = self.rt.link_named(name).map_err(errno)? {
            if l.kind == "wireguard" {
                return Ok(l);
            }
            self.info(format!(
                "replacing the cluster network interface interface={name}"
            ));
            self.del_link(&l)?;
        }
        match self.rt.exec(&rtnl::add_wireguard(name, mtu as u32)) {
            Ok(()) => self.did(format!("created {name} (wireguard)")),
            Err(Errno(libc::EOPNOTSUPP)) if name == NEXT => {
                return Err(Fail::Err(ERR_SWITCH_NEEDS_KERNEL.into()));
            }
            Err(Errno(libc::EOPNOTSUPP)) if name == SITE_INTERFACE => {
                return Err(Fail::Err(ERR_SITES_NEED_KERNEL.into()));
            }
            Err(Errno(libc::EOPNOTSUPP)) if !user => {
                return Err(Fail::Err(ERR_NO_KERNEL_WIREGUARD.into()));
            }
            Err(Errno(libc::EOPNOTSUPP)) => return Err(Fail::Userspace),
            Err(e) => return Err(Fail::Err(format!("create {name}: {e}"))),
        }
        self.link_by_name(name)
    }

    /// Net.wgPeers.
    fn wg_peers(&mut self, name: &str, mode: &str, peers: &[Peer]) -> Res<()> {
        let read = |e: WgError| Fail::Err(format!("read {name}: {e}"));
        let mut c = match wgnl::Client::open() {
            Ok(c) => c,
            Err(e @ WgError::NotExist) => return Err(read(e)),
            Err(e) => return Err(Fail::Err(e.to_string())),
        };
        let d = c.device(name).map_err(read)?;
        let keyed: Vec<Peer> = peers
            .iter()
            .filter(|pe| !pe.key.is_zero())
            .cloned()
            .collect();
        let Some(cfg) = wireguard::peer_changes(&d, &self.key, mode, &keyed, now_ms() / 1000)
        else {
            return Ok(());
        };
        let set = wgnl::device_set(&cfg, &self.key)?;
        c.configure(name, &set)
            .map_err(|e| Fail::Err(format!("configure {name}: {e}")))?;
        self.did(format!(
            "configured {name}: {} peer change(s){}{}",
            set.peers.len(),
            if set.private_key.is_some() {
                ", key"
            } else {
                ""
            },
            if set.listen_port.is_some() {
                ", port"
            } else {
                ""
            }
        ));
        Ok(())
    }

    /// Net.track, with the probe run here and now: the next pass reads its
    /// result, where Go's probe runs beside the agent.
    fn track(&mut self, p: &Plan, err: Option<&Fail>) {
        if !p.switching() {
            self.st.switch = SwitchState::default();
            return;
        }
        let sw = &mut self.st.switch;
        if sw.to != p.switch_to || sw.step != p.step {
            *sw = SwitchState {
                to: p.switch_to.clone(),
                step: p.step.clone(),
                ..SwitchState::default()
            };
        }
        sw.error = err.map(Fail::text).unwrap_or_default();
        sw.peers = p.peers.iter().map(|pe| pe.node.clone()).collect();
        if p.step == SWITCH_MOVE {
            sw.moved = err.is_none();
            return;
        }
        let now = now_ms();
        if err.is_some() || (sw.probe_at != 0 && now - sw.probe_at < PROBE_EVERY) {
            return;
        }
        sw.probe_at = now;
        let from = rules::vtep_addr(p.self_.subnet());
        match probe::ping(&from, &p.peers, Duration::from_millis(PROBE_WAIT)) {
            Ok(reached) => {
                self.st.switch.reached = reached.into_keys().collect();
            }
            Err(e) => {
                self.st.switch.reached = Vec::new();
                self.info(format!("probe the cluster network's target transport: {e}"));
            }
        }
        self.st.switch.probed = true;
    }

    /// Net.seePeers.
    fn see_peers(&mut self, p: &Plan, now: i64) {
        let old: HashMap<String, SeenState> = self
            .st
            .since
            .drain(..)
            .map(|s| (s.key.clone(), s))
            .collect();
        let mut next = BTreeMap::new();
        for pe in &p.peers {
            if pe.key.is_zero() || (!encrypted(&p.mode) && !pe.remote) {
                continue;
            }
            let key = pe.key.to_string();
            let seen = match old.get(&key) {
                Some(s) if s.node == pe.node => s.clone(),
                _ => SeenState {
                    key: key.clone(),
                    node: pe.node.clone(),
                    since: now,
                },
            };
            next.insert(key, seen);
        }
        self.st.since = next.into_values().collect();
    }
}

/// carries: whether link is the transport of mode.
fn carries(link: &Link, mode: &str) -> bool {
    match link.kind.as_str() {
        "wireguard" => encrypted(mode),
        "vxlan" => !encrypted(mode),
        _ => false,
    }
}

const ERR_NO_KERNEL_WIREGUARD: &str = "the kernel has no WireGuard, which the mesh network mode needs (the userspace device lives inside the agent, and the mesh must be up before it starts); use a kernel with WireGuard (Linux 5.6 or later)";
const ERR_SWITCH_NEEDS_KERNEL: &str = "the kernel has no WireGuard, which switching a running cluster to the wireguard mode needs; use a kernel with WireGuard (Linux 5.6 or later), or remove this node first";
const ERR_SITES_NEED_KERNEL: &str = "the kernel has no WireGuard, which reaching nodes of other sites needs; use a kernel with WireGuard (Linux 5.6 or later)";

/// RemoveMeshCache.
fn remove_mesh_cache(path: &str) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
        _ => Ok(()),
    }
}

/// SwitchStatus.
pub fn switch_status(sw: &SwitchState) -> Option<SwitchStatus> {
    if sw.to.is_empty() {
        return None;
    }
    let mut st = SwitchStatus {
        to: sw.to.clone(),
        step: sw.step.clone(),
        ready: false,
        unreached: Vec::new(),
        error: sw.error.clone(),
    };
    if sw.step == SWITCH_MOVE {
        st.ready = sw.moved && sw.error.is_empty();
        return Some(st);
    }
    let reached: HashSet<&String> = sw.reached.iter().collect();
    let mut unreached: Vec<String> = sw
        .peers
        .iter()
        .filter(|p| !reached.contains(p))
        .cloned()
        .collect();
    unreached.sort();
    st.ready = sw.error.is_empty() && sw.probed && unreached.is_empty();
    unreached.truncate(MAX_UNREACHED);
    st.unreached = unreached;
    Some(st)
}

/// Remove.
pub fn remove() -> Result<(), String> {
    let mut errs = Vec::new();
    match Handle::open() {
        Ok(mut rt) => {
            for name in [INTERFACE, NEXT, SITE_INTERFACE] {
                if let Ok(Some(l)) = rt.link_named(name)
                    && let Err(e) = rt.exec(&rtnl::del_link(l.index))
                {
                    errs.push(format!("remove {name}: {e}"));
                }
            }
        }
        Err(e) => errs.push(e.to_string()),
    }
    let tx = nft::remove_isolation().transaction();
    if let Err(e) = NftSocket::open().and_then(|s| s.transact(&tx)) {
        errs.push(format!("remove the isolation tables: {e}"));
    }
    errs.extend(iptables::remove_firewall(&mut Iptables {
        tool: &mut Program,
    }));
    if let Err(e) = std::fs::remove_file(USER_SOCKET)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        errs.push(format!("remove {USER_SOCKET}: {e}"));
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("\n"))
    }
}

/// armada-node net apply | up.
pub fn command(op: &str) -> Result<(), String> {
    let mut req: Request = serde_json::from_slice(&read_stdin()?).map_err(|e| e.to_string())?;
    let state = std::mem::take(&mut req.state);
    let mut answer = Answer {
        error: String::new(),
        needs_userspace: false,
        state: State::default(),
        switch: None,
        done: Vec::new(),
        log: Vec::new(),
    };
    let mut net = match Net::new(&req, state) {
        Ok(n) => n,
        Err(e) => {
            answer.error = e;
            return finish(answer);
        }
    };
    let res = if req.userspace {
        Err(Fail::Userspace)
    } else if op == "up" {
        net.up(req.config.take())
    } else {
        let local: Option<HashMap<Addr, String>> = req.local.as_ref().map(|m| {
            m.iter()
                .filter_map(|(a, app)| Addr::parse(a).map(|a| (a, app.clone())))
                .collect()
        });
        match &req.config {
            Some(cfg) => net.apply(cfg, local.as_ref()),
            None => Err(Fail::Err("no network configuration".into())),
        }
    };
    if let Err(f) = res {
        answer.needs_userspace = matches!(f, Fail::Userspace);
        answer.error = f.text();
    }
    answer.switch = switch_status(&net.st.switch);
    answer.state = net.st;
    answer.done = net.done;
    answer.log = net.log;
    finish(answer)
}

fn finish(answer: Answer) -> Result<(), String> {
    let failed = !answer.error.is_empty() && !answer.needs_userspace;
    let text = answer.error.clone();
    write_stdout(&serde_json::to_vec(&answer).map_err(|e| e.to_string())?)?;
    if failed {
        // The answer, with the state, is on stdout either way.
        return Err(text);
    }
    Ok(())
}

/// armada-node net remove.
pub fn remove_command() -> Result<(), String> {
    remove()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switch_status_follows_go() {
        assert_eq!(switch_status(&SwitchState::default()), None);
        let mut sw = SwitchState {
            to: "wireguard".into(),
            step: "prepare".into(),
            peers: vec!["c".into(), "b".into()],
            reached: vec!["b".into()],
            probed: true,
            ..SwitchState::default()
        };
        let st = switch_status(&sw).unwrap();
        assert!(!st.ready);
        assert_eq!(st.unreached, vec!["c"]);
        sw.reached.push("c".into());
        assert!(switch_status(&sw).unwrap().ready);
        sw.error = "boom".into();
        assert!(!switch_status(&sw).unwrap().ready);
        let mv = SwitchState {
            to: "wireguard".into(),
            step: "move".into(),
            moved: true,
            ..SwitchState::default()
        };
        assert!(switch_status(&mv).unwrap().ready);
    }

    #[test]
    fn links_carry_their_mode() {
        let l = |kind: &str| Link {
            kind: kind.into(),
            ..Link::default()
        };
        assert!(carries(&l("wireguard"), "mesh"));
        assert!(!carries(&l("wireguard"), "plain"));
        assert!(carries(&l("vxlan"), "plain"));
        assert!(!carries(&l("tun"), "wireguard"));
    }

    #[test]
    fn state_reads_what_it_writes() {
        let st = State {
            clean: CleanState {
                next: true,
                site: false,
            },
            switch: SwitchState {
                to: "plain".into(),
                ..SwitchState::default()
            },
            since: vec![SeenState {
                key: "k".into(),
                node: "a".into(),
                since: 5,
            }],
            last: "x".into(),
            ..State::default()
        };
        let back: State = serde_json::from_slice(&serde_json::to_vec(&st).unwrap()).unwrap();
        assert_eq!(back.clean, st.clean);
        assert_eq!(back.switch, st.switch);
        assert_eq!(back.since, st.since);
        assert_eq!(back.last, "x");
    }
}

//! The cluster network (ADR 0054 step 3): internal/clusternet in Rust,
//! which stays the reference. The pure logic (plan, policy, rules, peer
//! changes) is compared by a Go test on the package's test cases and random
//! configurations; the firewall and the kernel side (apply.rs: interfaces,
//! addresses, routes, neighbour and forwarding entries, kernel WireGuard)
//! by the netlink messages Go's libraries send and, as root, by the
//! integration tests in network namespaces.
//!
//!   armada-node net plan             stdin: a request (below); stdout: the plan
//!   armada-node net key PATH         network.key: load or create; prints the public key
//!   armada-node net key rotate PATH  network.key: a new key; prints its public key
//!   armada-node net cache save PATH  stdin: a NetworkConfig (protojson); keeps mesh.json
//!   armada-node net cache load PATH  prints the kept NetworkConfig, or null
//!   armada-node net firewall ...     the nftables isolation tables and the
//!                                    iptables chains (firewall.rs)
//!   armada-node net apply|up|remove  Net.Apply, Net.Up, and Remove (apply.rs)
//!   armada-node net netlink ...      the netlink messages and readings the
//!                                    parity tests compare (nlcheck.rs)
//!
//! A plan request is one JSON object as Go's encoding/json writes it:
//! Config (a NetworkConfig in protojson), Node and PrivateIP (this node),
//! Key (its private key, "" for none), Local (its own containers'
//! addresses, null when they are not in its subnet), Locals (the machine's
//! interface networks), UplinkMTU, LineMTU, and RemoteMTU (what the kernel
//! says of the uplinks), Now (Unix seconds), Devices (the WireGuard devices
//! by name, as the kernel reports them), and Stale (peers to check for
//! handshakes). The answer is one JSON object: {"error"} with the text Go
//! returns, or the plan, its isolation policy, the firewall rules per chain,
//! and what each transport (interface) carries.

pub mod addr;
pub mod apply;
pub mod config;
pub mod firewall;
pub mod iptables;
pub mod kernel;
pub mod key;
pub mod mesh;
pub mod netlink;
pub mod nft;
pub mod nlcheck;
pub mod plan;
pub mod policy;
pub mod probe;
pub mod rtnl;
pub mod rules;
pub mod wgnl;
pub mod wireguard;

use addr::{Addr, Prefix};
use config::NetworkConfig;
use key::Key;
use plan::{
    INTERFACE, LocalPrefix, MODE_PLAIN, MODE_WIREGUARD, NEXT, Peer, Plan, SITE_INTERFACE,
    SWITCH_MOVE, encrypted,
};
use rules::{Route, RouteSet, Rule};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::Path;

fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Request {
    config: NetworkConfig,
    node: String,
    #[serde(rename = "PrivateIP")]
    private_ip: String,
    key: String,
    local: Option<HashMap<String, String>>,
    #[serde(deserialize_with = "nullable")]
    locals: Vec<LocalIn>,
    #[serde(rename = "UplinkMTU")]
    uplink_mtu: i64,
    #[serde(rename = "LineMTU")]
    line_mtu: i64,
    #[serde(rename = "RemoteMTU")]
    remote_mtu: i64,
    now: i64,
    #[serde(deserialize_with = "nullable")]
    devices: HashMap<String, DeviceIn>,
    stale: Option<StaleIn>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct LocalIn {
    dev: String,
    prefix: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct DeviceIn {
    private_key: String,
    listen_port: i64,
    #[serde(deserialize_with = "nullable")]
    peers: Vec<DevicePeerIn>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct DevicePeerIn {
    public_key: String,
    endpoint: String,
    #[serde(rename = "AllowedIPs", deserialize_with = "nullable")]
    allowed_ips: Vec<String>,
    keepalive: i64,
    last_handshake: i64,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct StaleIn {
    #[serde(deserialize_with = "nullable")]
    since: Vec<SeenIn>,
    #[serde(deserialize_with = "nullable")]
    devices: Vec<Option<Vec<DevicePeerIn>>>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct SeenIn {
    key: String,
    node: String,
    since: i64,
}

fn key_of(s: &str) -> Key {
    Key::parse(s).unwrap_or_default()
}

impl DevicePeerIn {
    fn device_peer(&self) -> wireguard::DevicePeer {
        wireguard::DevicePeer {
            public_key: key_of(&self.public_key),
            endpoint: (!self.endpoint.is_empty()).then(|| self.endpoint.clone()),
            allowed_ips: self.allowed_ips.clone(),
            keepalive: self.keepalive,
            last_handshake: (self.last_handshake != 0).then_some(self.last_handshake),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerOut {
    node: String,
    ip: String,
    subnet: String,
    key: String,
    endpoint: String,
    site: String,
    remote: bool,
    nat: bool,
    relay: bool,
    carried: Vec<String>,
}

fn opt_text(a: &Option<Addr>) -> String {
    a.as_ref().map(Addr::to_string).unwrap_or_default()
}

fn key_text(k: &Key) -> String {
    if k.is_zero() {
        String::new()
    } else {
        k.to_string()
    }
}

fn texts<T: ToString>(v: &[T]) -> Vec<String> {
    v.iter().map(ToString::to_string).collect()
}

impl PeerOut {
    fn of(pe: &Peer) -> PeerOut {
        PeerOut {
            node: pe.node.clone(),
            ip: opt_text(&pe.ip),
            subnet: pe
                .subnet
                .as_ref()
                .map(Prefix::to_string)
                .unwrap_or_default(),
            key: key_text(&pe.key),
            endpoint: opt_text(&pe.endpoint),
            site: pe.site.clone(),
            remote: pe.remote,
            nat: pe.nat,
            relay: pe.relay,
            carried: texts(&pe.carried),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EndpointOut {
    address: String,
    app: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlanOut {
    mode: String,
    cidr: String,
    mesh: String,
    meshed: bool,
    switch_to: String,
    step: String,
    #[serde(rename = "self")]
    self_: PeerOut,
    peers: Vec<PeerOut>,
    relayed: Vec<PeerOut>,
    unreachable: Vec<String>,
    relaying: Vec<[String; 2]>,
    endpoints: Vec<EndpointOut>,
    isolate_default: bool,
    tcp_ports: Vec<u16>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MembersOut {
    app: String,
    addresses: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyOut {
    cidr: String,
    subnet: String,
    gateway: String,
    apps: Vec<String>,
    members: Vec<MembersOut>,
    open: Vec<String>,
    nodes: Vec<String>,
    tcp_ports: Vec<u16>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RulesOut {
    #[serde(rename = "in")]
    input: Vec<Rule>,
    in_jump: Rule,
    mesh: Option<Vec<Rule>>,
    mesh_jump: Option<Rule>,
    forward: Vec<Rule>,
    spoof: Vec<Rule>,
    mss: Vec<Rule>,
    nat: Vec<Rule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RouteOut {
    node: String,
    dst: String,
    via: String,
    src: String,
}

impl RouteOut {
    fn of(r: &Route) -> RouteOut {
        RouteOut {
            node: r.node.clone(),
            dst: r.dst.to_string(),
            via: opt_text(&r.via),
            src: opt_text(&r.src),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NeighbourOut {
    node: String,
    ip: String,
    mac: String,
    tunnel: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerConfigOut {
    public_key: String,
    remove: bool,
    endpoint: String,
    replace_allowed_ips: bool,
    allowed_ips: Vec<String>,
    keepalive: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WireGuardOut {
    private_key: bool,
    listen_port: Option<u16>,
    peers: Vec<PeerConfigOut>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransportOut {
    name: String,
    mode: String,
    routes: String,
    mtu: i64,
    addresses: Vec<String>,
    route_list: Vec<RouteOut>,
    neighbours: Vec<NeighbourOut>,
    wireguard: Option<WireGuardOut>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckOut {
    level: i64,
    detail: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Answer {
    plan: PlanOut,
    local: Vec<String>,
    remote: Vec<String>,
    tunnels: Vec<String>,
    wg_interface: String,
    policy: PolicyOut,
    rules: RulesOut,
    transports: Vec<TransportOut>,
    remove: Vec<String>,
    relay: Option<CheckOut>,
    shadowed: Vec<String>,
    stale: Option<Vec<String>>,
    public_key: String,
}

#[derive(Serialize)]
struct ErrorOut {
    error: String,
}

fn names_of(peers: &[Peer]) -> Vec<String> {
    peers.iter().map(|p| p.node.clone()).collect()
}

/// One transport tunnel() sets up: mode's on interface name, with the given
/// peers and routes.
fn transport(
    req: &Request,
    key: &Key,
    p: &Plan,
    mode: &str,
    name: &str,
    set: RouteSet,
) -> TransportOut {
    let mut uplink = req.uplink_mtu;
    if encrypted(mode) && p.has_remote() && req.remote_mtu > 0 {
        uplink = uplink.min(req.remote_mtu);
    }
    if req.line_mtu > 0 {
        uplink = uplink.min(req.line_mtu);
    }
    let wg = encrypted(mode);
    let mut out = TransportOut {
        name: name.to_string(),
        mode: mode.to_string(),
        routes: set.name().to_string(),
        mtu: plan::tunnel_mtu(mode, uplink),
        addresses: texts(&rules::tunnel_addresses(p)),
        route_list: rules::want_routes(p, !wg, set)
            .iter()
            .map(RouteOut::of)
            .collect(),
        neighbours: Vec::new(),
        wireguard: None,
    };
    if wg {
        let keyed: Vec<Peer> = p
            .peers
            .iter()
            .filter(|pe| !pe.key.is_zero())
            .cloned()
            .collect();
        let dev = req.devices.get(name).map(|d| wireguard::Device {
            private_key: key_of(&d.private_key),
            listen_port: d.listen_port,
            peers: d.peers.iter().map(DevicePeerIn::device_peer).collect(),
        });
        out.wireguard =
            wireguard::peer_changes(&dev.unwrap_or_default(), key, mode, &keyed, req.now).map(
                |c| WireGuardOut {
                    private_key: c.private_key,
                    listen_port: c.listen_port,
                    peers: c
                        .peers
                        .into_iter()
                        .map(|pc| PeerConfigOut {
                            public_key: pc.public_key.to_string(),
                            remove: pc.remove,
                            endpoint: pc.endpoint.unwrap_or_default(),
                            replace_allowed_ips: pc.replace_allowed_ips,
                            allowed_ips: pc.allowed_ips,
                            keepalive: pc.keepalive.unwrap_or_default(),
                        })
                        .collect(),
                },
            );
    } else {
        out.neighbours = p
            .peers
            .iter()
            .map(|pe| {
                let (mac, tunnel) = rules::vxlan_entry(pe);
                NeighbourOut {
                    node: pe.node.clone(),
                    ip: pe.ip().to_string(),
                    mac,
                    tunnel: tunnel.to_string(),
                }
            })
            .collect();
    }
    out
}

/// What tunnel() sets up and removes for p.
fn transports(req: &Request, key: &Key, p: &Plan) -> (Vec<TransportOut>, Vec<String>) {
    let (mut out, mut remove) = (Vec::new(), Vec::new());
    if p.switching() {
        let to = p.switch_to.as_str();
        if p.step == SWITCH_MOVE {
            out.push(transport(req, key, p, to, NEXT, RouteSet::All));
            out.push(transport(req, key, p, &p.mode, INTERFACE, RouteSet::None));
        } else {
            out.push(transport(req, key, p, &p.mode, INTERFACE, RouteSet::All));
            out.push(transport(req, key, p, to, NEXT, RouteSet::Probe));
        }
        return (out, remove);
    }
    if p.mode != MODE_PLAIN {
        remove.push(SITE_INTERFACE.to_string());
        out.push(transport(req, key, p, &p.mode, INTERFACE, RouteSet::All));
        return (out, remove);
    }
    let remote = p.remote();
    if remote.is_empty() {
        remove.push(SITE_INTERFACE.to_string());
    } else {
        out.push(transport(
            req,
            key,
            &p.only(remote),
            MODE_WIREGUARD,
            SITE_INTERFACE,
            RouteSet::All,
        ));
    }
    if p.meshed {
        remove.push(INTERFACE.to_string());
    } else {
        out.push(transport(
            req,
            key,
            &p.only(p.local()),
            &p.mode,
            INTERFACE,
            RouteSet::All,
        ));
    }
    (out, remove)
}

fn answer(req: &Request) -> Result<Answer, String> {
    let self_ip = Addr::parse(&req.private_ip);
    let key = key_of(&req.key);
    let p = plan::parse(&req.config, &req.node, &self_ip)?;
    if (encrypted(&p.mode) || encrypted(&p.switch_to)) && key.is_zero() {
        return Err(format!("the {MODE_WIREGUARD} mode needs the node's key"));
    }
    let local: Option<HashMap<Addr, String>> = req.local.as_ref().map(|m| {
        m.iter()
            .filter_map(|(a, app)| Addr::parse(a).map(|a| (a, app.clone())))
            .collect()
    });
    let pol = policy::build_policy(&p, local.as_ref());
    let tunnels = rules::tunnels(&p);
    let meshes = p.mode == plan::MODE_MESH || p.has_remote();
    let private_ip = self_ip.clone().unwrap_or(Addr::V4([0; 4]));
    let rules_out = RulesOut {
        input: rules::input_rules(&p, &private_ip),
        in_jump: rules::input_jump(&p),
        mesh: meshes.then(|| rules::mesh_rules(&p)),
        mesh_jump: meshes.then(|| {
            vec![
                "-i".to_string(),
                rules::wg_interface(&p).to_string(),
                "-j".to_string(),
                rules::CHAIN_MESH.to_string(),
            ]
        }),
        forward: rules::forward_rules(&tunnels, &p.relaying),
        spoof: rules::spoof_rules(&p),
        mss: rules::mss_rules(&tunnels),
        nat: tunnels
            .iter()
            .map(|t| vec!["-o".into(), t.to_string(), "-j".into(), "RETURN".into()])
            .collect(),
    };
    let locals: Vec<LocalPrefix> = req
        .locals
        .iter()
        .filter_map(|l| {
            Prefix::parse(&l.prefix).map(|prefix| LocalPrefix {
                dev: l.dev.clone(),
                prefix,
            })
        })
        .collect();
    let stale = req.stale.as_ref().map(|s| {
        let since = s
            .since
            .iter()
            .map(|e| {
                (
                    key_of(&e.key),
                    wireguard::Seen {
                        node: e.node.clone(),
                        since: e.since,
                    },
                )
            })
            .collect();
        let devices: Vec<Vec<wireguard::DevicePeer>> = s
            .devices
            .iter()
            .map(|d| d.iter().flatten().map(DevicePeerIn::device_peer).collect())
            .collect();
        wireguard::stale_peers(&devices, &since, req.now)
    });
    let (transports, remove) = transports(req, &key, &p);
    Ok(Answer {
        plan: PlanOut {
            mode: p.mode.clone(),
            cidr: p.cidr().to_string(),
            mesh: p.mesh.as_ref().map(Prefix::to_string).unwrap_or_default(),
            meshed: p.meshed,
            switch_to: p.switch_to.clone(),
            step: p.step.clone(),
            self_: PeerOut::of(&p.self_),
            peers: p.peers.iter().map(PeerOut::of).collect(),
            relayed: p.relayed.iter().map(PeerOut::of).collect(),
            unreachable: p.unreachable.clone(),
            relaying: p
                .relaying
                .iter()
                .map(|[a, b]| [a.to_string(), b.to_string()])
                .collect(),
            endpoints: p
                .endpoints
                .iter()
                .map(|(a, app)| EndpointOut {
                    address: a.to_string(),
                    app: app.clone(),
                })
                .collect(),
            isolate_default: p.isolate_default,
            tcp_ports: p.tcp_ports.clone(),
        },
        local: names_of(&p.local()),
        remote: names_of(&p.remote()),
        tunnels: tunnels.iter().map(|t| t.to_string()).collect(),
        wg_interface: rules::wg_interface(&p).to_string(),
        policy: PolicyOut {
            cidr: pol.cidr.to_string(),
            subnet: pol.subnet.to_string(),
            gateway: opt_text(&pol.gateway),
            apps: pol.members.keys().cloned().collect(),
            members: pol
                .members
                .iter()
                .map(|(app, addrs)| MembersOut {
                    app: app.clone(),
                    addresses: texts(addrs),
                })
                .collect(),
            open: texts(&pol.open),
            nodes: texts(&pol.nodes),
            tcp_ports: pol.tcp_ports,
        },
        rules: rules_out,
        transports,
        remove,
        relay: plan::relay_check(&p).map(|(level, detail)| CheckOut { level, detail }),
        shadowed: plan::shadowed(&p, &locals),
        stale,
        public_key: key_text(&if key.is_zero() { key } else { key.public() }),
    })
}

fn read_stdin() -> Result<Vec<u8>, String> {
    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .map_err(|e| e.to_string())?;
    Ok(input)
}

fn write_stdout(b: &[u8]) -> Result<(), String> {
    let mut out = io::stdout().lock();
    out.write_all(b)
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush())
        .map_err(|e| e.to_string())
}

/// armada-node net plan.
pub fn plan_command() -> Result<(), String> {
    let req: Request = serde_json::from_slice(&read_stdin()?).map_err(|e| e.to_string())?;
    let out = match answer(&req) {
        Ok(a) => serde_json::to_vec(&a),
        Err(error) => serde_json::to_vec(&ErrorOut { error }),
    }
    .map_err(|e| e.to_string())?;
    write_stdout(&out)
}

/// armada-node net key [rotate] PATH.
pub fn key_command(path: &str, rotate: bool) -> Result<(), String> {
    let k = if rotate {
        key::rotate(Path::new(path))?
    } else {
        key::load_or_create(Path::new(path))?
    };
    write_stdout(k.public().to_string().as_bytes())
}

/// armada-node net cache save|load PATH.
pub fn cache_command(op: &str, path: &str) -> Result<(), String> {
    let path = Path::new(path);
    match op {
        "save" => {
            let cfg: NetworkConfig =
                serde_json::from_slice(&read_stdin()?).map_err(|e| e.to_string())?;
            mesh::save(path, &cfg)
        }
        "load" => {
            let cfg = mesh::load(path)?;
            write_stdout(&serde_json::to_vec(&cfg).map_err(|e| e.to_string())?)
        }
        _ => Err(format!("unknown cache operation {op:?}; try: save, load")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_a_request() {
        let req: Request = serde_json::from_str(
            r#"{"Config":{"mode":"plain","clusterCidr":"10.120.0.0/16","peers":[
                {"node":"a","privateIp":"10.0.0.1","subnet":"10.120.0.0/24"},
                {"node":"b","privateIp":"10.0.0.2","subnet":"10.120.1.0/24"}]},
            "Node":"a","PrivateIP":"10.0.0.1","Key":"","Local":null,"Locals":null,
            "UplinkMTU":1500,"LineMTU":0,"RemoteMTU":0,"Now":0,"Devices":null,"Stale":null}"#,
        )
        .unwrap();
        let a = answer(&req).unwrap();
        assert_eq!(a.plan.peers[0].node, "b");
        assert_eq!(a.transports[0].mtu, 1450);
        assert_eq!(a.transports[0].route_list[0].via, "10.120.1.0");
        assert_eq!(a.remove, vec!["armada-wg"]);
        assert!(a.rules.spoof.contains(&vec![
            "-s".to_string(),
            "10.120.0.0/24".into(),
            "!".into(),
            "-i".into(),
            "armada0".into(),
            "-j".into(),
            "DROP".into()
        ]));
    }
}

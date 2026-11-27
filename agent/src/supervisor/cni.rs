//! The container network: the node's bridge `armada0` and the CNI plugin chain
//! of the runtime pack (bridge with host-local addresses on tmpfs,
//! portmap, firewall, loopback), run as libcni v1.3 runs them. The
//! plugins' input, environment, and cache files are what libcni makes, so
//! a container attached by an earlier release is released from its cache
//! like any other.

use std::collections::BTreeMap;
use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::host::Host;
use crate::log::Logger;

/// The per-node container bridge.
pub const BRIDGE_NAME: &str = "armada0";
/// The network's name, and the name of its cache files.
const NETWORK_NAME: &str = "armada";
const CNI_VERSION: &str = "1.0.0";
const IFNAME: &str = "eth0";
/// libcni's cache kind.
const CACHE_KIND: &str = "cniCacheV1";

/// An IPv4 prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix4 {
    pub addr: Ipv4Addr,
    pub bits: u8,
}

impl Prefix4 {
    /// Parses an IPv4 prefix (no leading zeros in the length).
    pub fn parse(s: &str) -> Option<Prefix4> {
        let (a, b) = s.split_once('/')?;
        let addr = match armada_node::net::addr::Addr::parse(a)? {
            armada_node::net::addr::Addr::V4(b) => Ipv4Addr::from(b),
            _ => return None,
        };
        if b.is_empty() || b.len() > 2 || !b.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if b.len() > 1 && b.starts_with('0') {
            return None;
        }
        let bits: u8 = b.parse().ok()?;
        (bits <= 32).then_some(Prefix4 { addr, bits })
    }

    pub fn masked(self) -> Prefix4 {
        let m = u32::MAX.checked_shl(32 - u32::from(self.bits)).unwrap_or(0);
        Prefix4 {
            addr: Ipv4Addr::from(u32::from(self.addr) & m),
            bits: self.bits,
        }
    }

    pub fn contains(self, a: Ipv4Addr) -> bool {
        Prefix4 { addr: a, ..self }.masked().addr == self.masked().addr
    }
}

impl std::fmt::Display for Prefix4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.bits)
    }
}

/// The default container subnet.
pub const DEFAULT_SUBNET: &str = "10.121.0.0/24";

/// The bridge network: the gateway is the subnet's first address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bridge {
    pub gateway: Ipv4Addr,
    pub subnet: Prefix4,
}

/// Whether an IPv4 address is private: RFC 1918, loopback, or shared
/// (100.64.0.0/10).
fn private4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_private() || o[0] == 127 || (o[0] == 100 && o[1] & 0xc0 == 64)
}

/// BridgeOf.
pub fn bridge_of(subnet: Prefix4) -> Result<Bridge, String> {
    let subnet = subnet.masked();
    if subnet.bits > 28 || subnet.bits < 8 {
        return Err(format!(
            "container subnet {subnet}: need an IPv4 prefix between /8 and /28"
        ));
    }
    let gateway = Ipv4Addr::from(u32::from(subnet.addr).wrapping_add(1));
    if !private4(gateway) {
        return Err(format!("container subnet {subnet} is not private"));
    }
    Ok(Bridge { gateway, subnet })
}

/// A locally administered unicast address holding the gateway's
/// bytes, so the bridge keeps it across restarts.
pub fn bridge_mac(gw: Ipv4Addr) -> [u8; 6] {
    let b = gw.octets();
    [0x02, 0x41, b[0], b[1], b[2], b[3]]
}

fn obj(pairs: Vec<(&str, Value)>) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// The plugin chain as compact JSON, every object's keys sorted.
pub fn cni_config(b: &Bridge, ipam_dir: &str, mtu: u32) -> Vec<u8> {
    let mut bridge = vec![
        ("type", Value::from("bridge")),
        ("bridge", Value::from(BRIDGE_NAME)),
        ("isGateway", Value::from(true)),
        ("ipMasq", Value::from(true)),
        ("hairpinMode", Value::from(true)),
        (
            "ipam",
            obj(vec![
                ("type", Value::from("host-local")),
                (
                    "ranges",
                    Value::Array(vec![Value::Array(vec![obj(vec![
                        ("subnet", Value::from(b.subnet.to_string())),
                        ("gateway", Value::from(b.gateway.to_string())),
                    ])])]),
                ),
                (
                    "routes",
                    Value::Array(vec![obj(vec![("dst", Value::from("0.0.0.0/0"))])]),
                ),
                ("dataDir", Value::from(ipam_dir)),
            ]),
        ),
    ];
    if mtu > 0 {
        bridge.push(("mtu", Value::from(mtu)));
    }
    let plugins = vec![
        obj(bridge),
        obj(vec![
            ("type", Value::from("portmap")),
            (
                "capabilities",
                obj(vec![("portMappings", Value::from(true))]),
            ),
            ("snat", Value::from(true)),
        ]),
        obj(vec![("type", Value::from("firewall"))]),
        // A new network namespace has its loopback down: localhost, and
        // the container's own address, would reach nothing.
        obj(vec![("type", Value::from("loopback"))]),
    ];
    go_json(&obj(vec![
        ("cniVersion", Value::from(CNI_VERSION)),
        ("name", Value::from(NETWORK_NAME)),
        ("plugins", Value::Array(plugins)),
    ]))
}

/// Compact JSON of v, `<`, `>`, `&`, U+2028, and U+2029 as `\u` escapes.
fn go_json<T: Serialize>(v: &T) -> Vec<u8> {
    armada_node::runtime::spec::to_go_json(v)
}

/// A published port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortMapping {
    pub host_ip: String,
    pub host_port: u16,
    pub container_port: u16,
}

/// The portmap plugin's capability argument.
fn capability_args(pm: Option<&PortMapping>) -> Map<String, Value> {
    let mut m = Map::new();
    if let Some(pm) = pm {
        m.insert(
            "portMappings".into(),
            Value::Array(vec![obj(vec![
                ("hostPort", Value::from(pm.host_port)),
                ("containerPort", Value::from(pm.container_port)),
                ("protocol", Value::from("tcp")),
                ("hostIP", Value::from(pm.host_ip.clone())),
            ])]),
        );
    }
    m
}

/// A plugin chain's result (CNI 1.0.0) as libcni caches it (an empty dns
/// left out).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CniResult {
    #[serde(
        rename = "cniVersion",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub cni_version: String,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "null_list"
    )]
    pub interfaces: Vec<Interface>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "null_list"
    )]
    pub ips: Vec<IpConfig>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "null_list"
    )]
    pub routes: Vec<Route>,
    #[serde(default, skip_serializing_if = "Dns::is_empty")]
    pub dns: Dns,
}

fn null_list<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<Option<T>>>::deserialize(d)?
        .unwrap_or_default()
        .into_iter()
        .flatten()
        .collect())
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Interface {
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mac: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub mtu: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sandbox: String,
    #[serde(
        rename = "socketPath",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub socket_path: String,
    #[serde(rename = "pciID", default, skip_serializing_if = "String::is_empty")]
    pub pci_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct IpConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<i64>,
    #[serde(default)]
    pub address: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gateway: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Route {
    #[serde(default)]
    pub dst: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gw: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub mtu: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub advmss: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub priority: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<i64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Dns {
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "null_list"
    )]
    pub nameservers: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "null_list"
    )]
    pub search: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "null_list"
    )]
    pub options: Vec<String>,
}

impl Dns {
    fn is_empty(&self) -> bool {
        self.nameservers.is_empty()
            && self.domain.is_empty()
            && self.search.is_empty()
            && self.options.is_empty()
    }
}

impl CniResult {
    /// The first address, without its prefix length.
    pub fn first_ip(&self) -> Result<String, String> {
        let ip = self
            .ips
            .first()
            .ok_or_else(|| "no IP address assigned".to_string())?;
        Ok(ip
            .address
            .split_once('/')
            .map_or(ip.address.as_str(), |(a, _)| a)
            .to_string())
    }
}

/// The CNI error object a plugin prints when it fails.
#[derive(Deserialize, Default)]
struct PluginError {
    #[serde(default)]
    msg: String,
    #[serde(default)]
    details: String,
}

/// The CNI runtime configuration of one call.
struct Rt<'a> {
    id: &'a str,
    netns: &'a str,
    caps: Map<String, Value>,
}

/// A cache file's contents, as libcni writes them.
#[derive(Serialize, Deserialize)]
struct Cached {
    kind: String,
    #[serde(rename = "containerId")]
    container_id: String,
    config: String,
    #[serde(rename = "ifName")]
    if_name: String,
    #[serde(rename = "networkName")]
    network_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    netns: String,
    #[serde(
        rename = "capabilityArgs",
        default,
        skip_serializing_if = "Map::is_empty"
    )]
    capability_args: Map<String, Value>,
    #[serde(rename = "result", default, skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
}

/// The node's container network.
pub struct Network {
    pub bridge: Bridge,
    mtu: u32,
    conf: Vec<u8>,
    plugins: Vec<Map<String, Value>>,
    /// Where the plugins are found (CNI_PATH).
    plugin_path: Vec<PathBuf>,
    cache_dir: PathBuf,
    netns_dir: PathBuf,
    host: Arc<dyn Host>,
    log: Logger,
    ready: tokio::sync::Mutex<bool>,
}

/// The plugins have no names of their own.
fn describe(plugin: &Map<String, Value>) -> String {
    let ty = plugin.get("type").and_then(Value::as_str).unwrap_or("");
    format!("type={}", armada_pki::go_quote(ty))
}

/// ^[a-zA-Z0-9][a-zA-Z0-9_.\-]*$.
fn cni_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

impl Network {
    /// The chain for subnet; ipam addresses under <cni>/ipam,
    /// libcni's cache under <cni>/cache, plugins from <bin>/cni.
    pub fn new(
        subnet: Prefix4,
        mtu: u32,
        cni_dir: &Path,
        plugin_dir: PathBuf,
        netns_dir: PathBuf,
        host: Arc<dyn Host>,
        log: Logger,
    ) -> Result<Network, String> {
        let bridge = bridge_of(subnet)?;
        let conf = cni_config(&bridge, &cni_dir.join("ipam").display().to_string(), mtu);
        let list: Value = serde_json::from_slice(&conf).map_err(|e| e.to_string())?;
        let plugins = list["plugins"]
            .as_array()
            .map(|a| a.iter().filter_map(|p| p.as_object().cloned()).collect())
            .unwrap_or_default();
        Ok(Network {
            bridge,
            mtu,
            conf,
            plugins,
            plugin_path: vec![plugin_dir],
            cache_dir: cni_dir.join("cache"),
            netns_dir,
            host,
            log,
            ready: tokio::sync::Mutex::new(false),
        })
    }

    /// The configuration list's bytes.
    pub fn conf(&self) -> &[u8] {
        &self.conf
    }

    /// Ensure: the bridge with the gateway's address, made before the
    /// first container (the resolver and ingress bind to it).
    pub async fn ensure(&self) -> Result<(), String> {
        let mut ready = self.ready.lock().await;
        if *ready {
            return Ok(());
        }
        let (host, b, mtu) = (self.host.clone(), self.bridge, self.mtu);
        tokio::task::spawn_blocking(move || host.ensure_bridge(&b, mtu))
            .await
            .map_err(|e| e.to_string())??;
        *ready = true;
        Ok(())
    }

    fn cache_file(&self, id: &str) -> PathBuf {
        self.cache_dir
            .join("results")
            .join(format!("{NETWORK_NAME}-{id}-{IFNAME}"))
    }

    /// The plugin's map with name, cniVersion, the previous
    /// result, and runtimeConfig with the capabilities the plugin declares.
    fn plugin_input(
        &self,
        plugin: &Map<String, Value>,
        prev: Option<&CniResult>,
        caps: &Map<String, Value>,
    ) -> Vec<u8> {
        let mut rc = Map::new();
        if let Some(Value::Object(declared)) = plugin.get("capabilities") {
            for (k, v) in declared {
                if v.as_bool() == Some(true)
                    && let Some(arg) = caps.get(k)
                {
                    rc.insert(k.clone(), arg.clone());
                }
            }
        }
        // libcni writes every key sorted, the previous result's too.
        let mut m = plugin.clone();
        m.insert("name".into(), Value::from(NETWORK_NAME));
        m.insert("cniVersion".into(), Value::from(CNI_VERSION));
        if let Some(p) = prev {
            let v: Value = serde_json::from_slice(&go_json(p)).unwrap_or(Value::Null);
            m.insert("prevResult".into(), v);
        }
        if !rc.is_empty() {
            m.insert("runtimeConfig".into(), Value::Object(rc));
        }
        go_json(&m)
    }

    /// FindInPath.
    fn find(&self, plugin: &Map<String, Value>) -> Result<PathBuf, String> {
        let ty = plugin.get("type").and_then(Value::as_str).unwrap_or("");
        if ty.is_empty() {
            return Err("no plugin name provided".into());
        }
        if ty.contains('/') {
            return Err(format!("invalid plugin name: {ty}"));
        }
        for dir in &self.plugin_path {
            let p = dir.join(ty);
            if fs::metadata(&p).is_ok_and(|m| m.is_file()) {
                return Ok(p);
            }
        }
        let dirs: Vec<String> = self
            .plugin_path
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        Err(format!(
            "failed to find plugin {} in path [{}]",
            armada_pki::go_quote(ty),
            dirs.join(" ")
        ))
    }

    /// Runs the plugin with the CNI variables, its input on stdin; a
    /// failure is its CNI error.
    async fn exec(
        &self,
        path: &Path,
        command: &str,
        rt: &Rt<'_>,
        input: &[u8],
    ) -> Result<Vec<u8>, String> {
        let cni_path: Vec<String> = self
            .plugin_path
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let (path, command, id, netns, input) = (
            path.to_path_buf(),
            command.to_string(),
            rt.id.to_string(),
            rt.netns.to_string(),
            input.to_vec(),
        );
        tokio::task::spawn_blocking(move || {
            run_plugin(&path, &command, &id, &netns, &cni_path.join(":"), &input)
        })
        .await
        .map_err(|e| e.to_string())?
    }

    /// Adds the container to every plugin of the chain, then caches the
    /// result.
    async fn add(&self, rt: &Rt<'_>) -> Result<CniResult, String> {
        let mut result: Option<CniResult> = None;
        for p in &self.plugins {
            let r = async {
                let path = self.find(p)?;
                if !cni_name(rt.id) {
                    return Err("invalid characters in containerID".to_string());
                }
                let input = self.plugin_input(p, result.as_ref(), &rt.caps);
                let out = self.exec(&path, "ADD", rt, &input).await?;
                let mut r: CniResult = serde_json::from_slice(&out)
                    .map_err(|e| format!("decoding version from network config: {e}"))?;
                r.cni_version = CNI_VERSION.into();
                Ok(r)
            }
            .await
            .map_err(|e| format!("plugin {} failed (add): {e}", describe(p)))?;
            result = Some(r);
        }
        let result = result.unwrap_or_default();
        self.cache_add(&result, rt).map_err(|e| {
            format!(
                "failed to set network {} cached result: {e}",
                armada_pki::go_quote(NETWORK_NAME)
            )
        })?;
        Ok(result)
    }

    fn cache_add(&self, result: &CniResult, rt: &Rt<'_>) -> Result<(), String> {
        let raw: Value = serde_json::from_slice(&go_json(result)).map_err(|e| e.to_string())?;
        let c = Cached {
            kind: CACHE_KIND.into(),
            container_id: rt.id.into(),
            config: armada_node::net::key::b64_encode(&self.conf),
            if_name: IFNAME.into(),
            network_name: NETWORK_NAME.into(),
            netns: rt.netns.into(),
            capability_args: rt.caps.clone(),
            result: Some(raw),
        };
        let f = self.cache_file(rt.id);
        let dir = f.parent().expect("a cache file has a directory");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| super::os_err("mkdir", dir, &e))?;
        let mut w = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&f)
            .map_err(|e| super::os_err("open", &f, &e))?;
        std::io::Write::write_all(&mut w, &go_json(&c)).map_err(|e| super::os_err("write", &f, &e))
    }

    /// The cached result of id, None when there is none;
    /// an unreadable file is an error.
    fn cached(&self, id: &str) -> Result<Option<CniResult>, String> {
        let Ok(data) = fs::read(self.cache_file(id)) else {
            return Ok(None);
        };
        let c: Cached = match serde_json::from_slice::<Cached>(&data) {
            Ok(c) if c.kind == CACHE_KIND => c,
            // libcni then reads the legacy cache, which Armada never wrote.
            _ => return Ok(None),
        };
        let Some(v) = c.result else {
            return Err("cached result has no result".into());
        };
        let mut r: CniResult = serde_json::from_value(v).map_err(|e| e.to_string())?;
        r.cni_version = CNI_VERSION.into();
        Ok(Some(r))
    }

    /// Every plugin in reverse order with the cached
    /// result, then the cache file goes.
    async fn del(&self, rt: &Rt<'_>) -> Result<(), String> {
        let prev = match self.cached(rt.id) {
            Ok(r) => r,
            Err(_) => {
                let _ = fs::remove_file(self.cache_file(rt.id));
                None
            }
        };
        for p in self.plugins.iter().rev() {
            async {
                let path = self.find(p)?;
                let input = self.plugin_input(p, prev.as_ref(), &rt.caps);
                self.exec(&path, "DEL", rt, &input).await.map(|_| ())
            }
            .await
            .map_err(|e| format!("plugin {} failed (delete): {e}", describe(p)))?;
        }
        let _ = fs::remove_file(self.cache_file(rt.id));
        Ok(())
    }

    /// Setup: a network namespace for id, attached, its port published;
    /// the namespace's path and the container's address.
    pub async fn setup(
        &self,
        id: &str,
        pm: Option<&PortMapping>,
    ) -> Result<(String, String), String> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.netns_dir)
            .map_err(|e| super::os_err("mkdir", &self.netns_dir, &e))?;
        let (host, dir) = (self.host.clone(), self.netns_dir.clone());
        let ns = tokio::task::spawn_blocking(move || host.new_netns(&dir))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| format!("network namespace: {e}"))?;
        let rt = Rt {
            id,
            netns: &ns,
            caps: capability_args(pm),
        };
        let res = match self.add(&rt).await {
            Ok(r) => r,
            Err(e) => {
                let _ = self.del(&rt).await;
                let _ = self.remove_netns(&ns).await;
                return Err(e);
            }
        };
        match res.first_ip() {
            Ok(ip) => Ok((ns, ip)),
            Err(e) => {
                let _ = self.teardown(id, &ns, pm).await;
                Err(format!("network result: {e}"))
            }
        }
    }

    /// Attaches the namespace at path, which the caller made, as
    /// id with no port; its address.
    pub async fn setup_at(&self, id: &str, path: &str) -> Result<String, String> {
        let rt = Rt {
            id,
            netns: path,
            caps: Map::new(),
        };
        match self.add(&rt).await {
            Ok(r) => r.first_ip().map_err(|e| format!("network result: {e}")),
            Err(e) => {
                let _ = self.del(&rt).await;
                Err(e)
            }
        }
    }

    /// AddNetworkList of id at path with pm, as Setup makes it (tests).
    #[cfg(test)]
    pub(crate) async fn attach(
        &self,
        id: &str,
        path: &str,
        pm: Option<&PortMapping>,
    ) -> Result<CniResult, String> {
        self.add(&Rt {
            id,
            netns: path,
            caps: capability_args(pm),
        })
        .await
    }

    /// Address: the address SetupAt gave id, from the plugins' cache.
    pub fn address(&self, id: &str) -> Result<String, String> {
        match self.cached(id)? {
            None => Err("no cached network result".into()),
            Some(r) => r.first_ip().map_err(|e| format!("network result: {e}")),
        }
    }

    async fn remove_netns(&self, path: &str) -> Result<(), String> {
        let (host, p) = (self.host.clone(), path.to_string());
        tokio::task::spawn_blocking(move || host.remove_netns(&p))
            .await
            .map_err(|e| e.to_string())?
    }

    /// Teardown: undoes Setup, also when the namespace is gone (the
    /// plugins still release the address and NAT rules); the address's
    /// connection tracking entries are deleted once it is given back.
    pub async fn teardown(
        &self,
        id: &str,
        path: &str,
        pm: Option<&PortMapping>,
    ) -> Result<(), String> {
        let ns_path = if path.is_empty() || fs::metadata(path).is_err() {
            ""
        } else {
            path
        };
        let addr = self
            .cached(id)
            .ok()
            .flatten()
            .and_then(|r| r.first_ip().ok())
            .and_then(|ip| ip.parse::<Ipv4Addr>().ok());
        let rt = Rt {
            id,
            netns: ns_path,
            caps: capability_args(pm),
        };
        self.del(&rt).await?;
        if let Some(a) = addr {
            let host = self.host.clone();
            let res = tokio::task::spawn_blocking(move || host.forget_connections(a))
                .await
                .map_err(|e| e.to_string())
                .and_then(|r| r);
            if let Err(e) = res {
                self.log.warn(
                    "connection tracking entries of a released container address were not all deleted",
                    &[("container", id.to_string()), ("address", a.to_string()), ("err", e)],
                );
            }
        }
        if !ns_path.is_empty() {
            self.remove_netns(ns_path).await?;
        }
        Ok(())
    }
}

/// One plugin call: the CNI variables, the input on stdin; a plugin
/// that is being written ("text file busy") is tried again for up to five
/// seconds.
fn run_plugin(
    path: &Path,
    command: &str,
    id: &str,
    netns: &str,
    cni_path: &str,
    input: &[u8],
) -> Result<Vec<u8>, String> {
    use std::io::Write;
    let mut tries = 0;
    loop {
        let child = std::process::Command::new(path)
            .env("CNI_COMMAND", command)
            .env("CNI_CONTAINERID", id)
            .env("CNI_NETNS", netns)
            .env("CNI_ARGS", "")
            .env("CNI_IFNAME", IFNAME)
            .env("CNI_PATH", cni_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && tries < 5 => {
                tries += 1;
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            Err(e) => {
                return Err(plugin_error(
                    &format!("fork/exec {}: {}", path.display(), super::errno(&e)),
                    b"",
                    b"",
                ));
            }
        };
        let stdin = child.stdin.take();
        let input = input.to_vec();
        let writer = std::thread::spawn(move || {
            if let Some(mut w) = stdin {
                let _ = w.write_all(&input);
            }
        });
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        let _ = writer.join();
        if out.status.success() {
            return Ok(out.stdout);
        }
        return Err(plugin_error(
            &super::exit_text(&out.status),
            &out.stdout,
            &out.stderr,
        ));
    }
}

/// The plugin's CNI error, or what it printed.
fn plugin_error(exit: &str, stdout: &[u8], stderr: &[u8]) -> String {
    let e = if stdout.is_empty() {
        if stderr.is_empty() {
            PluginError {
                msg: format!("netplugin failed with no error message: {exit}"),
                ..Default::default()
            }
        } else {
            PluginError {
                msg: format!(
                    "netplugin failed: {}: {exit}",
                    armada_pki::go_quote(&String::from_utf8_lossy(stderr))
                ),
                ..Default::default()
            }
        }
    } else {
        match serde_json::from_slice::<PluginError>(stdout) {
            Ok(e) => e,
            Err(perr) => PluginError {
                msg: format!(
                    "netplugin failed but error parsing its diagnostic message {}: {perr}",
                    armada_pki::go_quote(&String::from_utf8_lossy(stdout))
                ),
                ..Default::default()
            },
        }
    };
    if e.details.is_empty() {
        e.msg
    } else {
        format!("{}; {}", e.msg, e.details)
    }
}

/// The CNI files' layout, for the tests that compare them with recordings.
pub fn cache_file_name(id: &str) -> String {
    format!("{NETWORK_NAME}-{id}-{IFNAME}")
}

/// The keys of a cache file, sorted, for the tests.
pub fn sorted_keys(v: &Value) -> Vec<String> {
    let m: BTreeMap<_, _> = v
        .as_object()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .collect();
    m.into_keys().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridges_of_subnets() {
        let b = bridge_of(Prefix4::parse("10.120.3.7/24").unwrap()).unwrap();
        assert_eq!(b.gateway.to_string(), "10.120.3.1");
        assert_eq!(b.subnet.to_string(), "10.120.3.0/24");
        assert_eq!(bridge_mac(b.gateway), [0x02, 0x41, 10, 120, 3, 1]);
        assert_eq!(
            bridge_of(Prefix4::parse("10.0.0.0/30").unwrap()).unwrap_err(),
            "container subnet 10.0.0.0/30: need an IPv4 prefix between /8 and /28"
        );
        assert_eq!(
            bridge_of(Prefix4::parse("8.8.8.0/24").unwrap()).unwrap_err(),
            "container subnet 8.8.8.0/24 is not private"
        );
        assert!(Prefix4::parse("10.0.0.0/033").is_none());
    }

    #[test]
    fn config_with_sorted_keys() {
        let b = bridge_of(Prefix4::parse("10.121.0.0/24").unwrap()).unwrap();
        assert_eq!(
            String::from_utf8(cni_config(&b, "/run/armada/cni/ipam", 1450)).unwrap(),
            r#"{"cniVersion":"1.0.0","name":"armada","plugins":[{"bridge":"armada0","hairpinMode":true,"ipMasq":true,"ipam":{"dataDir":"/run/armada/cni/ipam","ranges":[[{"gateway":"10.121.0.1","subnet":"10.121.0.0/24"}]],"routes":[{"dst":"0.0.0.0/0"}],"type":"host-local"},"isGateway":true,"mtu":1450,"type":"bridge"},{"capabilities":{"portMappings":true},"snat":true,"type":"portmap"},{"type":"firewall"},{"type":"loopback"}]}"#
        );
    }

    #[test]
    fn plugin_errors() {
        assert_eq!(
            plugin_error(
                "exit status 1",
                br#"{"code":7,"msg":"no","details":"why"}"#,
                b""
            ),
            "no; why"
        );
        assert_eq!(
            plugin_error("exit status 1", b"", b"bad\n"),
            "netplugin failed: \"bad\\n\": exit status 1"
        );
        assert_eq!(
            plugin_error("exit status 2", b"", b""),
            "netplugin failed with no error message: exit status 2"
        );
    }
}

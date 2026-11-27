//! agent.json: what a node's agent needs besides its certificate, read and
//! written in a fixed form: the fields in a fixed order, empty ones left
//! out, two spaces of indent, a new line at the end, mode 0600.

use std::path::Path;
use std::sync::Mutex;

use armada_client::config::json_string;
use serde_json::Value;

/// The data directory's files.
pub const FILE_AGENT: &str = "agent.json";
pub const FILE_SERVER_CERT: &str = "server.crt";
pub const FILE_CA_CERT: &str = "ca.crt";
pub const FILE_CA_KEY: &str = "ca.key";
pub const FILE_ETCD_INITIAL: &str = "etcd/initial-cluster";
pub const DIR_ETCD: &str = "etcd";
/// The armada-kv member's directory (ADR 0057): a server of a cluster
/// whose state is in armada-kv has it, and no etcd directory.
pub const DIR_KV: &str = "kv";
/// The members a server that joined such a cluster asks for its ID
/// (removed once it votes).
pub const FILE_KV_INITIAL: &str = "kv/initial-cluster";

/// Container runtimes recorded in agent.json.
pub const RUNTIME_EMBEDDED: &str = "embedded";
pub const RUNTIME_SUPERVISOR: &str = "supervisor";

/// What a node still on containerd (agent.json runtime "embedded", or
/// none) is told: this release runs containers on the supervisor runtime
/// only.
pub const CONTAINERD_NODE: &str = "this node runs containers on containerd, which this release does not run: upgrade it through v0.1.0-alpha.44 first";

/// Network modes.
pub const NETWORK_MESH: &str = "mesh";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct AgentConfig {
    pub node_id: String,
    pub private_ip: String,
    /// None is JSON null (a nil slice).
    pub servers: Option<Vec<String>>,
    pub runtime: String,
    pub container_subnet: String,
    pub network: String,
    pub endpoint: String,
    pub cluster_cidr: String,
    pub mesh_cidr: String,
    pub behind_nat: bool,
    pub mtu: i64,
}

/// The fields by their JSON keys, in the order they are written.
const KEYS: [&str; 11] = [
    "nodeId",
    "privateIp",
    "servers",
    "runtime",
    "containerSubnet",
    "network",
    "endpoint",
    "clusterCidr",
    "meshCidr",
    "behindNat",
    "mtu",
];

impl AgentConfig {
    /// The JSON indented by two spaces, and a new line.
    pub fn encode(&self) -> Vec<u8> {
        let mut fields: Vec<String> = Vec::new();
        let mut s = |k: &str, v: &str, omit: bool| {
            if !(omit && v.is_empty()) {
                fields.push(format!("  \"{k}\": {}", json_string(v)));
            }
        };
        s("nodeId", &self.node_id, false);
        s("privateIp", &self.private_ip, false);
        let servers = match &self.servers {
            None => "null".to_string(),
            Some(v) if v.is_empty() => "[]".to_string(),
            Some(v) => {
                let items: Vec<String> = v
                    .iter()
                    .map(|x| format!("    {}", json_string(x)))
                    .collect();
                format!("[\n{}\n  ]", items.join(",\n"))
            }
        };
        fields.push(format!("  \"servers\": {servers}"));
        let mut s = |k: &str, v: &str| {
            if !v.is_empty() {
                fields.push(format!("  \"{k}\": {}", json_string(v)));
            }
        };
        s("runtime", &self.runtime);
        s("containerSubnet", &self.container_subnet);
        s("network", &self.network);
        s("endpoint", &self.endpoint);
        s("clusterCidr", &self.cluster_cidr);
        s("meshCidr", &self.mesh_cidr);
        if self.behind_nat {
            fields.push("  \"behindNat\": true".to_string());
        }
        if self.mtu != 0 {
            fields.push(format!("  \"mtu\": {}", self.mtu));
        }
        format!("{{\n{}\n}}\n", fields.join(",\n")).into_bytes()
    }

    /// agent.json decoded: keys matched exactly, else without
    /// regard to case; unknown keys ignored; null leaves a field as it is.
    pub fn decode(b: &[u8]) -> Result<AgentConfig, String> {
        let v: Value = serde_json::from_slice(b).map_err(|e| syntax_text(&e))?;
        let Value::Object(map) = v else {
            return Err(format!(
                "json: cannot unmarshal {} into value of type daemon.agentConfig",
                kind(&v)
            ));
        };
        let mut c = AgentConfig::default();
        for (k, v) in &map {
            let Some(key) = KEYS
                .iter()
                .find(|f| **f == k.as_str())
                .or_else(|| KEYS.iter().find(|f| f.eq_ignore_ascii_case(k)))
            else {
                continue;
            };
            if v.is_null() {
                continue;
            }
            let mismatch = |want: &str| {
                format!(
                    "json: cannot unmarshal {} into struct field agentConfig.{key} of type {want}",
                    kind(v)
                )
            };
            match *key {
                "servers" => {
                    let Value::Array(items) = v else {
                        return Err(mismatch("[]string"));
                    };
                    let mut out = Vec::new();
                    for item in items {
                        match item {
                            Value::String(s) => out.push(s.clone()),
                            Value::Null => out.push(String::new()),
                            _ => {
                                return Err(format!(
                                    "json: cannot unmarshal {} into struct field agentConfig.servers of type string",
                                    kind(item)
                                ));
                            }
                        }
                    }
                    c.servers = Some(out);
                }
                "behindNat" => match v {
                    Value::Bool(b) => c.behind_nat = *b,
                    _ => return Err(mismatch("bool")),
                },
                "mtu" => match v.as_i64() {
                    Some(n) if n == n as isize as i64 => c.mtu = n,
                    _ if v.is_number() => {
                        return Err(format!(
                            "json: cannot unmarshal number {v} into struct field agentConfig.mtu of type int"
                        ));
                    }
                    _ => return Err(mismatch("int")),
                },
                other => {
                    let Value::String(s) = v else {
                        return Err(mismatch("string"));
                    };
                    let s = s.clone();
                    match other {
                        "nodeId" => c.node_id = s,
                        "privateIp" => c.private_ip = s,
                        "runtime" => c.runtime = s,
                        "containerSubnet" => c.container_subnet = s,
                        "network" => c.network = s,
                        "endpoint" => c.endpoint = s,
                        "clusterCidr" => c.cluster_cidr = s,
                        "meshCidr" => c.mesh_cidr = s,
                        _ => {}
                    }
                }
            }
        }
        Ok(c)
    }

    /// An agent.json naming a runtime this Armada does not
    /// know is refused.
    pub fn check_runtime(&self) -> Result<(), String> {
        match self.runtime.as_str() {
            RUNTIME_EMBEDDED | RUNTIME_SUPERVISOR | "" => Ok(()),
            other => Err(format!(
                "{FILE_AGENT} names container runtime {}, which this Armada does not know ({RUNTIME_EMBEDDED} or {RUNTIME_SUPERVISOR}); remove the node and join it again",
                armada_spec::go::quote(other)
            )),
        }
    }
}

/// The kind of a JSON value, as a type error names it.
fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// A syntax error, worded by the character met where it can be.
fn syntax_text(e: &serde_json::Error) -> String {
    if e.is_eof() {
        return "unexpected end of JSON input".to_string();
    }
    format!("invalid JSON: {e}")
}

/// An error loading agent.json: whether the file is missing, and its text.
#[derive(Debug)]
pub struct LoadError {
    pub not_found: bool,
    pub text: String,
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

impl From<LoadError> for armada_client::cli::Error {
    fn from(e: LoadError) -> Self {
        armada_client::cli::Error::Msg(e.text)
    }
}

pub fn load(data_dir: &str) -> Result<AgentConfig, LoadError> {
    let path = Path::new(data_dir).join(FILE_AGENT);
    let b = armada_fsutil::read_private_file(&path).map_err(|e| LoadError {
        not_found: e.kind() == armada_fsutil::ErrorKind::NotFound,
        text: e.to_string(),
    })?;
    let c = AgentConfig::decode(&b).map_err(|e| LoadError {
        not_found: false,
        text: format!("parse {FILE_AGENT}: {e}"),
    })?;
    if c.servers.as_ref().is_none_or(|s| s.is_empty()) {
        return Err(LoadError {
            not_found: false,
            text: format!("{FILE_AGENT} lists no control plane address"),
        });
    }
    Ok(c)
}

pub fn save(data_dir: &str, c: &AgentConfig) -> Result<(), String> {
    armada_fsutil::write_file_atomic(&Path::new(data_dir).join(FILE_AGENT), &c.encode(), 0o600)
        .map_err(|e| e.to_string())
}

static AGENT_CONFIG_MU: Mutex<()> = Mutex::new(());

/// agent.json as it is on disk now, with the fields
/// change owns set, written back.
pub fn update(
    data_dir: &str,
    change: impl FnOnce(&mut AgentConfig) -> Result<(), String>,
) -> Result<AgentConfig, String> {
    let _held = AGENT_CONFIG_MU.lock().unwrap_or_else(|e| e.into_inner());
    let mut c = load(data_dir).map_err(|e| e.text)?;
    change(&mut c)?;
    save(data_dir, &c)?;
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let c = AgentConfig {
            node_id: "n1".into(),
            private_ip: "10.0.0.5".into(),
            servers: Some(vec!["10.0.0.2:7443".into()]),
            runtime: "supervisor".into(),
            behind_nat: true,
            mtu: 1492,
            ..Default::default()
        };
        let b = c.encode();
        assert_eq!(
            String::from_utf8(b.clone()).unwrap(),
            "{\n  \"nodeId\": \"n1\",\n  \"privateIp\": \"10.0.0.5\",\n  \"servers\": [\n    \"10.0.0.2:7443\"\n  ],\n  \"runtime\": \"supervisor\",\n  \"behindNat\": true,\n  \"mtu\": 1492\n}\n"
        );
        assert_eq!(AgentConfig::decode(&b).unwrap(), c);
        let folded = AgentConfig::decode(br#"{"NODEID": "x", "unknown": 1}"#).unwrap();
        assert_eq!(folded.node_id, "x");
        assert_eq!(
            AgentConfig::decode(br#"{"mtu": "x"}"#).unwrap_err(),
            "json: cannot unmarshal string into struct field agentConfig.mtu of type int"
        );
    }
}

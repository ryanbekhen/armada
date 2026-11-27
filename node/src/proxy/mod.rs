//! HAProxy's configuration: `armada-node proxy render` renders haproxy.cfg,
//! the route maps, and local.map (checked against recorded cases,
//! tests/render.rs).
//!
//! Standard input is one JSON object, {"Config", "Layout", "Options"}: a
//! proxy configuration (certificates by name), the
//! server slots per backend, and the node's options. The output is each
//! file as `file NAME LENGTH` and LENGTH bytes (haproxy.cfg, the route maps,
//! local.map), or `unsafe` when a value is not a single token, then `end`.

pub mod render;

use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::io::{self, Read, Write};

/// A missing slice or map may come as null.
fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Config {
    #[serde(deserialize_with = "nullable")]
    pub backends: Vec<Backend>,
    #[serde(deserialize_with = "nullable")]
    pub rules: Vec<Rule>,
    #[serde(deserialize_with = "nullable")]
    pub certificates: Vec<Certificate>,
    #[serde(rename = "ACMEAddress")]
    pub acme_address: String,
    #[serde(deserialize_with = "nullable")]
    pub trusted_proxies: Vec<String>,
    #[serde(rename = "TCP", deserialize_with = "nullable")]
    pub tcp: Vec<TcpRoute>,
    #[serde(rename = "PlainHTTP")]
    pub plain_http: bool,
    #[serde(deserialize_with = "nullable")]
    pub proxy_protocol: Vec<String>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "PascalCase", default)]
pub struct Backend {
    pub name: String,
    #[serde(deserialize_with = "nullable")]
    pub servers: Vec<Server>,
    pub health_path: String,
    pub wake: bool,
    pub local_first: bool,
    pub timeout_seconds: i64,
    #[serde(rename = "IPAllow", deserialize_with = "nullable")]
    pub ip_allow: Vec<String>,
    #[serde(rename = "IPDeny", deserialize_with = "nullable")]
    pub ip_deny: Vec<String>,
    pub sticky: bool,
    #[serde(rename = "CORS")]
    pub cors: Option<Cors>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "PascalCase", default)]
pub struct Cors {
    #[serde(deserialize_with = "nullable")]
    pub origins: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub methods: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub headers: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub expose: Vec<String>,
    pub max_age_seconds: i64,
    pub credentials: bool,
}

#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "PascalCase", default)]
pub struct Server {
    pub name: String,
    pub address: String,
    pub weight: i64,
}

impl Server {
    /// proxy.Server.EffectiveWeight: 0 means 1.
    pub fn effective_weight(&self) -> i64 {
        if self.weight == 0 { 1 } else { self.weight }
    }
}

#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "PascalCase", default)]
pub struct Rule {
    pub host: String,
    pub path_prefix: String,
    pub strip_prefix: bool,
    pub backend: String,
    pub internal: bool,
    #[serde(deserialize_with = "nullable")]
    pub allow: Vec<String>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "PascalCase", default)]
pub struct Certificate {
    pub name: String,
}

#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "PascalCase", default)]
pub struct TcpRoute {
    pub port: i64,
    pub backend: String,
    #[serde(deserialize_with = "nullable")]
    pub allow: Vec<String>,
}

/// The node's parts of the configuration.
#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Options {
    #[serde(rename = "PrivateIP")]
    pub private_ip: String,
    #[serde(rename = "InternalIP")]
    pub internal_ip: String,
    pub subnet: String,
    #[serde(rename = "BusyTCP", deserialize_with = "nullable")]
    pub busy_tcp: Vec<i64>,
}

/// Server slots per HAProxy backend; "" is a free slot.
pub type Layout = HashMap<String, Vec<String>>;

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Request {
    config: Config,
    #[serde(deserialize_with = "nullable")]
    layout: Layout,
    options: Options,
}

/// proxy.BackendSpace: the space of the app a backend serves, or "".
pub fn backend_space(backend: &str) -> &str {
    let id = backend.split_once("--").map_or(backend, |(_, id)| id);
    crate::names::space_of(id).unwrap_or("")
}

pub fn render_command() -> Result<(), String> {
    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .map_err(|e| e.to_string())?;
    let req: Request = serde_json::from_slice(&input).map_err(|e| e.to_string())?;
    let out = io::stdout();
    let mut w = io::BufWriter::new(out.lock());
    let file = |w: &mut io::BufWriter<_>, name: &str, b: &[u8]| -> io::Result<()> {
        writeln!(w, "file {name} {}", b.len())?;
        w.write_all(b)
    };
    let result = (|| -> io::Result<()> {
        match render::render(&req.config, &req.layout, &req.options) {
            None => writeln!(w, "unsafe")?,
            Some(cfg) => {
                file(&mut w, "haproxy.cfg", cfg.as_bytes())?;
                for (name, b) in render::route_files(&req.config, &req.options) {
                    file(&mut w, &name, &b)?;
                }
                let local = render::local_map(&req.config, &req.layout, &req.options.node());
                file(&mut w, "local.map", &local)?;
            }
        }
        writeln!(w, "end")?;
        w.flush()
    })();
    result.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_go_json() {
        let req: Request = serde_json::from_str(
            r#"{"Config":{"Backends":[{"Name":"web","Servers":null,"CORS":null}],"Rules":null,
            "Certificates":[{"Name":"a.test","PEM":null}],"ACMEAddress":"","TrustedProxies":null,
            "TCP":null,"PlainHTTP":true,"ProxyProtocol":null},"Layout":null,
            "Options":{"PrivateIP":"10.0.0.1","InternalIP":"","Subnet":"","BusyTCP":null}}"#,
        )
        .unwrap();
        assert_eq!(req.config.backends[0].name, "web");
        assert!(req.config.plain_http);
        assert_eq!(req.options.private_ip, "10.0.0.1");
    }

    #[test]
    fn spaces_of_backends() {
        assert_eq!(backend_space("web"), "default");
        assert_eq!(backend_space("canary--web.shop"), "shop");
        assert_eq!(backend_space("Bad"), "");
    }
}

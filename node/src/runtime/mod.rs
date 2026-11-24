//! Containers' OCI runtime specs (ADR 0054 step 4, first part; not used by
//! nodes yet): what internal/runtime/containerd builds before it hands a
//! spec to its backend, and runtime.CheckContainerSpec.
//!
//!   armada-node runtime spec       stdin: a SpecRequest (below) as Go's
//!                                  encoding/json writes it; stdout: the
//!                                  config.json bytes Go writes, or
//!                                  {"error": TEXT} with Go's error text
//!   armada-node runtime check      stdin: a runtime.ContainerSpec; stdout:
//!                                  {} or {"error": TEXT}
//!   armada-node runtime seccomp    stdin: {"Arch", "Bounding", "Kernel48"};
//!                                  stdout: the default seccomp profile
//!   armada-node runtime apparmor NAME
//!                                  Armada's AppArmor profile for NAME as
//!                                  this machine makes it (appArmorProfile)
//!
//! Go's TestArmadaNodeSpecMatchesGo, TestArmadaNodeCheckMatchesGo,
//! TestArmadaNodeSeccompMatchesGo, and TestArmadaNodeAppArmorMatchesGo
//! (internal/runtime/containerd) compare them with Go. Image pulls and the
//! image store are in image/ (runtime pull, images, prune).

mod apparmor;
mod check;
pub mod container;
pub(crate) mod gopath;
pub mod image;
mod oci;
mod seccomp;
pub(crate) mod spec;
mod user;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};

/// Go writes a nil slice or map as null.
fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// runtime.ContainerSpec.
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct ContainerSpec {
    pub name: String,
    pub image: String,
    #[serde(deserialize_with = "nullable")]
    pub entrypoint: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub cmd: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub env: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub labels: BTreeMap<String, String>,
    pub port: i64,
    #[serde(rename = "HostIP")]
    pub host_ip: String,
    pub memory_bytes: i64,
    #[serde(rename = "NanoCPUs")]
    pub nano_cpus: i64,
    #[serde(rename = "CPUReserveMillis")]
    pub cpu_reserve_millis: i64,
    pub pids_limit: i64,
    #[serde(deserialize_with = "nullable")]
    pub files: Vec<FileMount>,
    #[serde(rename = "DNS", deserialize_with = "nullable")]
    pub dns: Vec<String>,
    #[serde(rename = "DNSSearch", deserialize_with = "nullable")]
    pub dns_search: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub volumes: Vec<VolumeMount>,
    #[serde(deserialize_with = "nullable")]
    pub init: Vec<MemberSpec>,
    #[serde(deserialize_with = "nullable")]
    pub sidecars: Vec<MemberSpec>,
}

/// runtime.MemberSpec.
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct MemberSpec {
    pub name: String,
    pub image: String,
    #[serde(deserialize_with = "nullable")]
    pub entrypoint: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub cmd: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub env: Vec<String>,
    pub memory_bytes: i64,
    #[serde(rename = "NanoCPUs")]
    pub nano_cpus: i64,
    #[serde(rename = "CPUReserveMillis")]
    pub cpu_reserve_millis: i64,
    pub pids_limit: i64,
    #[serde(deserialize_with = "nullable")]
    pub files: Vec<FileMount>,
    #[serde(deserialize_with = "nullable")]
    pub volumes: Vec<VolumeMount>,
}

/// runtime.FileMount.
#[derive(Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub struct FileMount {
    pub source: String,
    pub target: String,
}

/// runtime.VolumeMount.
#[derive(Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub struct VolumeMount {
    pub source: String,
    pub target: String,
    pub shared: bool,
    pub read_only: bool,
}

/// runtime.SystemSpec (what its spec reads).
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct SystemSpec {
    pub name: String,
    pub image: String,
    #[serde(deserialize_with = "nullable")]
    pub cmd: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub mounts: Vec<SystemMount>,
    #[serde(deserialize_with = "nullable")]
    pub cap_add: Vec<String>,
    pub user: String,
}

/// runtime.Mount.
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct SystemMount {
    pub source: String,
    pub target: String,
    pub read_only: bool,
}

/// containerFiles: the container's resolv.conf, hosts, and hostname.
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct Files {
    pub resolv: String,
    pub hosts: String,
    pub hostname: String,
}

/// selinuxLabels; empty when the container is not confined.
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct Labels {
    pub process: String,
    pub mount: String,
}

fn yes() -> bool {
    true
}

/// What the driver has when it builds a spec. App containers: Spec (and
/// Member for one of its init containers or sidecars), NetNS, Files,
/// Tini; system containers: System. Every spec: the image's config blob
/// (and its descriptor's media type when known), the root filesystem its
/// users and groups are read from, the cgroup, the SELinux labels, and
/// whether seccomp and which AppArmor profile apply. Arch is Go's GOARCH
/// name, this program's own when empty.
#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct SpecRequest {
    pub spec: ContainerSpec,
    pub member: Option<MemberSpec>,
    pub system: Option<SystemSpec>,
    pub image: ImageConfig,
    pub image_media_type: String,
    #[serde(rename = "NetNS")]
    pub netns: String,
    pub files: Files,
    pub tini: String,
    pub cgroup: String,
    #[serde(rename = "SELinux")]
    pub selinux: Labels,
    #[serde(default = "yes")]
    pub seccomp: bool,
    #[serde(rename = "AppArmor")]
    pub apparmor: String,
    pub rootfs: String,
    pub arch: String,
    pub namespace: String,
    #[serde(rename = "ID")]
    pub id: String,
}

impl SpecRequest {
    /// populateDefaultUnixSpec's cgroup path, path.Join("/", ns, id),
    /// which WithCgroup replaces.
    fn default_cgroups_path(&self) -> String {
        gopath::clean(&format!("/{}/{}", self.namespace, self.id))
    }
}

/// What WithImageConfigArgs reads of an image's config blob (v1.Image's
/// config), parsed as encoding/json does: field names matched exactly or
/// case-insensitively, the last of repeated keys kept, null as nothing.
#[derive(Default, Clone, Debug)]
pub struct ImageConfig {
    pub user: String,
    pub env: Vec<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub working_dir: String,
}

/// encoding/json's key match: equal under simple case folding, where
/// only ASCII letters, U+017F (s), and U+212A (k) fold to the ASCII
/// letters of the names read here.
fn key_is(key: &str, field: &str) -> bool {
    let fold = |c: char| match c {
        '\u{17f}' => 's',
        '\u{212a}' => 'k',
        c => c.to_ascii_lowercase(),
    };
    key.chars().map(fold).eq(field.chars().map(fold))
}

impl<'de> Deserialize<'de> for ImageConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Blob;
        impl<'de> Visitor<'de> for Blob {
            type Value = ImageConfig;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an image configuration")
            }
            fn visit_unit<E: de::Error>(self) -> Result<ImageConfig, E> {
                Ok(ImageConfig::default())
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<ImageConfig, A::Error> {
                let mut out = ImageConfig::default();
                while let Some(k) = m.next_key::<String>()? {
                    if key_is(&k, "config") {
                        if let Some(c) = m.next_value::<Option<Config>>()? {
                            c.apply(&mut out);
                        }
                    } else {
                        m.next_value::<de::IgnoredAny>()?;
                    }
                }
                Ok(out)
            }
        }
        d.deserialize_any(Blob)
    }
}

/// v1.ImageConfig's fields the spec reads, each as it was last set.
#[derive(Default)]
struct Config(Vec<(Field, Option<Value>)>);

enum Field {
    User,
    Env,
    Entrypoint,
    Cmd,
    WorkingDir,
}

enum Value {
    Str(String),
    List(Vec<String>),
}

impl Config {
    fn apply(self, out: &mut ImageConfig) {
        for (f, v) in self.0 {
            match (f, v) {
                (Field::User, Some(Value::Str(s))) => out.user = s,
                (Field::WorkingDir, Some(Value::Str(s))) => out.working_dir = s,
                (Field::Env, v) => out.env = list(v),
                (Field::Entrypoint, v) => out.entrypoint = list(v),
                (Field::Cmd, v) => out.cmd = list(v),
                _ => {}
            }
        }
    }
}

fn list(v: Option<Value>) -> Vec<String> {
    match v {
        Some(Value::List(l)) => l,
        _ => Vec::new(),
    }
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Config;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an image's config")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Config, A::Error> {
                let mut c = Config::default();
                while let Some(k) = m.next_key::<String>()? {
                    let field = [
                        ("User", Field::User),
                        ("Env", Field::Env),
                        ("Entrypoint", Field::Entrypoint),
                        ("Cmd", Field::Cmd),
                        ("WorkingDir", Field::WorkingDir),
                    ]
                    .into_iter()
                    .find(|(n, _)| key_is(&k, n));
                    match field {
                        Some((_, f @ (Field::User | Field::WorkingDir))) => {
                            // null leaves a string as it was.
                            if let Some(s) = m.next_value::<Option<String>>()? {
                                c.0.push((f, Some(Value::Str(s))));
                            }
                        }
                        Some((_, f)) => {
                            let l = m.next_value::<Option<Vec<Option<String>>>>()?;
                            let v = l.map(|l| {
                                Value::List(l.into_iter().map(Option::unwrap_or_default).collect())
                            });
                            c.0.push((f, v));
                        }
                        None => {
                            m.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(c)
            }
        }
        d.deserialize_map(V)
    }
}

/// images.IsConfigType.
fn is_config_type(mt: &str) -> bool {
    matches!(
        mt,
        "application/vnd.docker.container.image.v1+json"
            | "application/vnd.oci.image.config.v1+json"
    )
}

/// The member's own spec as startMember builds it: the replica's name,
/// the member's image, command, environment, limits, files, and volumes.
fn member_container_spec(replica: &ContainerSpec, m: &MemberSpec) -> ContainerSpec {
    ContainerSpec {
        name: replica.name.clone(),
        image: m.image.clone(),
        entrypoint: m.entrypoint.clone(),
        cmd: m.cmd.clone(),
        env: m.env.clone(),
        memory_bytes: m.memory_bytes,
        nano_cpus: m.nano_cpus,
        cpu_reserve_millis: m.cpu_reserve_millis,
        pids_limit: m.pids_limit,
        files: m.files.clone(),
        volumes: m.volumes.clone(),
        ..Default::default()
    }
}

/// Go's GOARCH name for this program's architecture.
fn own_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "amd64"
    } else {
        std::env::consts::ARCH
    }
}

/// The config.json bytes of a request, or Go's error text.
pub fn build(r: &SpecRequest) -> Result<Vec<u8>, String> {
    if !r.image_media_type.is_empty() && !is_config_type(&r.image_media_type) {
        return Err(format!(
            "unknown image config media type {}",
            r.image_media_type
        ));
    }
    let host = oci::Host {
        masked: oci::default_masked_paths(),
        goarch: if r.arch.is_empty() {
            own_arch().to_string()
        } else {
            r.arch.clone()
        },
        kernel_4_8: seccomp::kernel_at_least_4_8(),
    };
    let spec = match (&r.system, &r.member) {
        (Some(s), _) => oci::system_spec(r, s, &host)?,
        (None, Some(m)) => oci::app_spec(r, &member_container_spec(&r.spec, m), &host)?,
        (None, None) => oci::app_spec(r, &r.spec, &host)?,
    };
    Ok(spec::to_go_json(&spec))
}

#[derive(Serialize)]
struct ErrorOut {
    error: String,
}

pub(crate) fn read_stdin() -> Result<Vec<u8>, String> {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .map_err(|e| format!("read input: {e}"))?;
    Ok(input)
}

pub(crate) fn write_out(b: &[u8]) -> Result<(), String> {
    let mut out = std::io::stdout().lock();
    out.write_all(b)
        .and_then(|()| out.flush())
        .map_err(|e| format!("write output: {e}"))
}

fn error_json(e: String) -> Vec<u8> {
    spec::to_go_json(&ErrorOut { error: e })
}

/// armada-node runtime spec.
pub fn spec_command() -> Result<(), String> {
    let r: SpecRequest =
        serde_json::from_slice(&read_stdin()?).map_err(|e| format!("read request: {e}"))?;
    write_out(&build(&r).unwrap_or_else(error_json))
}

/// armada-node runtime check.
pub fn check_command() -> Result<(), String> {
    let s: ContainerSpec =
        serde_json::from_slice(&read_stdin()?).map_err(|e| format!("read spec: {e}"))?;
    match check::check_container_spec(&s) {
        Ok(()) => write_out(b"{}"),
        Err(e) => write_out(&error_json(e)),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SeccompRequest {
    arch: String,
    #[serde(deserialize_with = "nullable", default)]
    bounding: Vec<String>,
    #[serde(rename = "Kernel48")]
    kernel_4_8: Option<bool>,
}

/// armada-node runtime seccomp.
pub fn seccomp_command() -> Result<(), String> {
    let r: SeccompRequest =
        serde_json::from_slice(&read_stdin()?).map_err(|e| format!("read request: {e}"))?;
    let k = r.kernel_4_8.unwrap_or_else(seccomp::kernel_at_least_4_8);
    write_out(&spec::to_go_json(&seccomp::default_profile(
        &r.bounding,
        &r.arch,
        k,
    )))
}

/// armada-node runtime apparmor NAME.
pub fn apparmor_command(name: &str) -> Result<(), String> {
    let text = apparmor::armada_profile(name, &apparmor::Facts::read())?;
    write_out(text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_config_as_encoding_json() {
        let c: ImageConfig = serde_json::from_str(
            r#"{"architecture":"amd64","CONFIG":{"user":"app","Env":["A=1",null],"cmd":null,"Cmd":["x"],"WorkingDir":null,"Entrypoint":["/e"],"entrypoint":null}}"#,
        )
        .unwrap();
        assert_eq!(c.user, "app");
        assert_eq!(c.env, ["A=1", ""]);
        assert_eq!(c.cmd, ["x"]);
        assert!(c.entrypoint.is_empty());
        assert_eq!(c.working_dir, "");
        assert!(key_is("\u{212a}", "k"));
    }
}

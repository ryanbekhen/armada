//! The parts of the OCI runtime spec (opencontainers/runtime-spec v1.3.0,
//! specs-go) Armada's containers use, in specs-go's field order and with
//! its omitempty rules, so serialising one writes the bytes Go's
//! encoding/json writes (see `to_go_json`).

use serde::Serialize;
use std::collections::BTreeMap;

/// specs.Version.
pub const OCI_VERSION: &str = "1.3.0";

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

#[derive(Serialize, Default, Clone, Debug)]
pub struct Spec {
    #[serde(rename = "ociVersion")]
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<Process>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<Root>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<Mount>,
    /// None is Go's nil map; an empty map is omitted all the same.
    #[serde(skip_serializing_if = "map_empty")]
    pub annotations: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux: Option<Linux>,
}

fn map_empty(m: &Option<BTreeMap<String, String>>) -> bool {
    m.as_ref().is_none_or(BTreeMap::is_empty)
}

#[derive(Serialize, Default, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    #[serde(skip_serializing_if = "is_false")]
    pub terminal: bool,
    pub user: User,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    pub cwd: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capabilities>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rlimits: Vec<Rlimit>,
    #[serde(skip_serializing_if = "is_false")]
    pub no_new_privileges: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub apparmor_profile: String,
    #[serde(rename = "oomScoreAdj", skip_serializing_if = "Option::is_none")]
    pub oom_score_adj: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub selinux_label: String,
}

#[derive(Serialize, Default, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub additional_gids: Vec<u32>,
}

#[derive(Serialize, Default, Clone, Debug)]
pub struct Capabilities {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bounding: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub effective: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub inheritable: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub permitted: Vec<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Rlimit {
    #[serde(rename = "type")]
    pub kind: String,
    pub hard: u64,
    pub soft: u64,
}

#[derive(Serialize, Default, Clone, Debug)]
pub struct Root {
    pub path: String,
    #[serde(skip_serializing_if = "is_false")]
    pub readonly: bool,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Mount {
    pub destination: String,
    #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
    pub kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

impl Mount {
    pub fn new(destination: &str, kind: &str, source: &str, options: &[&str]) -> Mount {
        Mount {
            destination: destination.into(),
            kind: kind.into(),
            source: source.into(),
            options: options.iter().map(|s| s.to_string()).collect(),
        }
    }
}

#[derive(Serialize, Default, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Linux {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Resources>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cgroups_path: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<Namespace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<Seccomp>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub masked_paths: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub readonly_paths: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mount_label: String,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Namespace {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
}

#[derive(Serialize, Default, Clone, Debug)]
pub struct Resources {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<DeviceCgroup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<Memory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<Cpu>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pids: Option<Pids>,
}

#[derive(Serialize, Clone, Debug)]
pub struct DeviceCgroup {
    pub allow: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub access: String,
}

#[derive(Serialize, Default, Clone, Debug)]
pub struct Memory {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap: Option<i64>,
}

#[derive(Serialize, Default, Clone, Debug)]
pub struct Cpu {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shares: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<u64>,
}

#[derive(Serialize, Default, Clone, Debug)]
pub struct Pids {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Seccomp {
    pub default_action: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub architectures: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub syscalls: Vec<Syscall>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Syscall {
    pub names: Vec<String>,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errno_ret: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<SeccompArg>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SeccompArg {
    pub index: u64,
    pub value: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub value_two: u64,
    pub op: String,
}

/// Writes v as Go's json.Marshal does: compact, with <, >, &, U+2028, and
/// U+2029 escaped (serde_json already writes \b, \f, \n, \r, \t and the
/// other control characters as \u00xx, as Go does since 1.22).
pub fn to_go_json<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut out, GoFormatter);
    v.serialize(&mut ser).expect("serialising to memory");
    out
}

struct GoFormatter;

impl serde_json::ser::Formatter for GoFormatter {
    fn write_string_fragment<W: ?Sized + std::io::Write>(
        &mut self,
        w: &mut W,
        fragment: &str,
    ) -> std::io::Result<()> {
        let mut start = 0;
        for (i, c) in fragment.char_indices() {
            let esc = match c {
                '<' => "\\u003c",
                '>' => "\\u003e",
                '&' => "\\u0026",
                '\u{2028}' => "\\u2028",
                '\u{2029}' => "\\u2029",
                _ => continue,
            };
            w.write_all(&fragment.as_bytes()[start..i])?;
            w.write_all(esc.as_bytes())?;
            start = i + c.len_utf8();
        }
        w.write_all(&fragment.as_bytes()[start..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_as_go() {
        let m = Mount::new("/a<b>&\u{2028}", "", "x\u{8}\u{c}\u{1}", &[]);
        assert_eq!(
            String::from_utf8(to_go_json(&m)).unwrap(),
            r#"{"destination":"/a~u003cb~u003e~u0026~u2028","source":"x~b~f~u0001"}"#
                .replace('~', "\\")
        );
    }
}

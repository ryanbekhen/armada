//! The client config (Go's internal/clientconfig): where it is, the
//! permissions it may have (private to its owner, or shared on purpose by
//! root with the armada group, ADR 0027), reading and writing it as Go's
//! encoding/json does, and the machine's list of servers
//! (/etc/armada/servers).

use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use armada_spec::go;

/// Overrides the default config location.
pub const ENV_PATH: &str = "ARMADA_CONFIG";

/// The admin config `armadad init` writes on the first server.
pub const SYSTEM_PATH: &str = "/etc/armada/admin.config";

/// The group whose members may read SYSTEM_PATH.
pub const GROUP: &str = "armada";

/// The control plane's API addresses on every Armada machine.
pub const SERVERS_PATH: &str = "/etc/armada/servers";

/// The header the leader sends the control plane's addresses in.
pub const SERVERS_HEADER: &str = "armada-servers";

const SHARED_MODE: u32 = 0o640;
const MAX_SERVERS_FILE: u64 = 64 << 10;

/// A client config: the control plane's addresses and the user's mTLS
/// credentials.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Config {
    pub servers: Vec<String>,
    pub ca: String,
    pub cert: String,
    pub key: String,
    pub ssh: String,
    pub space: String,
    pub project: String,
}

/// DefaultPath: $ARMADA_CONFIG, else ~/.armada/config when it exists,
/// else SYSTEM_PATH when it exists, else ~/.armada/config.
pub fn default_path() -> String {
    if let Ok(p) = std::env::var(ENV_PATH)
        && !p.is_empty()
    {
        return p;
    }
    let own = match std::env::var("HOME") {
        Ok(h) if !h.is_empty() => join(&h, ".armada/config"),
        _ => ".armada/config".to_string(),
    };
    if fs::metadata(&own).is_ok() {
        return own;
    }
    if fs::metadata(SYSTEM_PATH).is_ok() {
        return SYSTEM_PATH.to_string();
    }
    own
}

/// filepath.Join for an absolute or relative base and a clean relative path.
fn join(base: &str, rel: &str) -> String {
    let b = base.trim_end_matches('/');
    let joined = if b.is_empty() && base.starts_with('/') {
        format!("/{rel}")
    } else {
        format!("{b}/{rel}")
    };
    go::clean_path(&joined)
}

/// Go's text for an errno as os.PathError shows it.
fn path_error(op: &str, path: &str, e: &io::Error) -> String {
    format!("{op} {path}: {}", armada_fsutil::errno_text(e))
}

/// Load reads a config, refusing files readable by group or others unless
/// root shares them with the armada group.
pub fn load(path: &str) -> Result<Config, String> {
    let b = match read_config(path) {
        Ok(b) => b,
        Err(ReadError::NotExist) => {
            return Err(format!(
                "no client config at {path}; run `armadad init` on the server or set {ENV_PATH}"
            ));
        }
        Err(ReadError::Permission(_)) if path == SYSTEM_PATH => {
            return Err(format!("{path}: permission denied: {}", group_advice()));
        }
        Err(ReadError::Permission(t) | ReadError::Other(t)) => return Err(t),
    };
    let mut c = decode(&b).map_err(|e| format!("parse {path}: {e}"))?;
    if c.servers.is_empty() || c.ca.is_empty() || c.cert.is_empty() || c.key.is_empty() {
        return Err(format!("{path} is incomplete"));
    }
    if !c.ssh.is_empty() {
        check_ssh(&c.ssh).map_err(|e| format!("{path}: {e}"))?;
    }
    if c.space.is_empty() {
        c.space = c.project.clone();
    }
    c.project.clear();
    Ok(c)
}

enum ReadError {
    NotExist,
    Permission(String),
    Other(String),
}

fn read_error(op: &str, path: &str, e: &io::Error) -> ReadError {
    match e.kind() {
        io::ErrorKind::NotFound => ReadError::NotExist,
        io::ErrorKind::PermissionDenied => ReadError::Permission(path_error(op, path, e)),
        _ => ReadError::Other(path_error(op, path, e)),
    }
}

fn read_config(path: &str) -> Result<Vec<u8>, ReadError> {
    let meta = fs::metadata(path).map_err(|e| read_error("stat", path, &e))?;
    let perm = meta.permissions().mode() & 0o777;
    if perm & 0o077 != 0 && !shared_ok(&meta) {
        return Err(ReadError::Other(format!(
            "{path} has mode {perm:04o}, want 0600 (or 0640, owned by root, group {GROUP}): {}",
            armada_fsutil::INSECURE_PERMISSIONS
        )));
    }
    fs::read(path).map_err(|e| {
        let op = if e.raw_os_error() == Some(libc::EISDIR) {
            "read"
        } else {
            "open"
        };
        read_error(op, path, &e)
    })
}

/// sharedOK: root's, mode 0640, group armada.
fn shared_ok(meta: &fs::Metadata) -> bool {
    if meta.permissions().mode() & 0o777 != SHARED_MODE || meta.uid() != 0 {
        return false;
    }
    group_id(GROUP).is_some_and(|g| g == meta.gid())
}

/// user.LookupGroup through /etc/group, as Go without cgo reads it.
fn group_id(name: &str) -> Option<u32> {
    let text = fs::read_to_string("/etc/group").ok()?;
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 3 && f[0] == name {
            return f[2].parse().ok();
        }
    }
    None
}

/// The groups of this process (os.Getgroups).
fn session_groups() -> Vec<u32> {
    // SAFETY: getgroups with a zero size only counts; the second call
    // fills a buffer of the size it returned.
    unsafe {
        let n = libc::getgroups(0, std::ptr::null_mut());
        if n <= 0 {
            return Vec::new();
        }
        let mut v = vec![0 as libc::gid_t; n as usize];
        let n = libc::getgroups(n, v.as_mut_ptr());
        if n < 0 {
            return Vec::new();
        }
        v.truncate(n as usize);
        v
    }
}

/// The groups the account is listed in (user.Current().GroupIds() through
/// /etc/passwd and /etc/group).
fn account_groups() -> Vec<u32> {
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    let Ok(passwd) = fs::read_to_string("/etc/passwd") else {
        return Vec::new();
    };
    let mut user = None;
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 4 && f[2].parse::<u32>().ok() == Some(uid as u32) {
            user = Some((f[0].to_string(), f[3].parse::<u32>().ok()));
            break;
        }
    }
    let Some((name, primary)) = user else {
        return Vec::new();
    };
    let mut out: Vec<u32> = primary.into_iter().collect();
    if let Ok(group) = fs::read_to_string("/etc/group") {
        for line in group.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() >= 4
                && f[3].split(',').any(|m| m == name)
                && let Ok(g) = f[2].parse::<u32>()
                && !out.contains(&g)
            {
                out.push(g);
            }
        }
    }
    out
}

/// groupAdvice: why SYSTEM_PATH could not be read.
fn group_advice() -> String {
    let Some(gid) = group_id(GROUP) else {
        return "use sudo".to_string();
    };
    if session_groups().contains(&gid) {
        return format!("the file is not shared with the {GROUP} group; use sudo");
    }
    if account_groups().contains(&gid) {
        return format!("this session started before you joined the {GROUP} group; log in again");
    }
    format!("you are not in the {GROUP} group; use sudo")
}

/// json.Unmarshal into Config: field names matched without case, other
/// fields ignored.
fn decode(b: &[u8]) -> Result<Config, String> {
    let v: serde_json::Value = serde_json::from_slice(b).map_err(|e| json_error(&e))?;
    let obj = match v {
        serde_json::Value::Object(o) => o,
        serde_json::Value::Null => return Ok(Config::default()),
        other => {
            return Err(format!(
                "json: cannot unmarshal {} into Go value of type clientconfig.Config",
                json_kind(&other)
            ));
        }
    };
    let mut c = Config::default();
    for (k, val) in obj {
        let field = match k.to_lowercase().as_str() {
            "servers" => "servers",
            "ca" => "ca",
            "cert" => "cert",
            "key" => "key",
            "ssh" => "ssh",
            "space" => "space",
            "project" => "project",
            _ => continue,
        };
        if field == "servers" {
            match val {
                serde_json::Value::Null => c.servers = Vec::new(),
                serde_json::Value::Array(a) => {
                    let mut out = Vec::new();
                    for e in a {
                        match e {
                            serde_json::Value::String(s) => out.push(s),
                            serde_json::Value::Null => out.push(String::new()),
                            other => {
                                return Err(format!(
                                    "json: cannot unmarshal {} into Go struct field Config.servers of type string",
                                    json_kind(&other)
                                ));
                            }
                        }
                    }
                    c.servers = out;
                }
                other => {
                    return Err(format!(
                        "json: cannot unmarshal {} into Go struct field Config.servers of type []string",
                        json_kind(&other)
                    ));
                }
            }
            continue;
        }
        let s = match val {
            serde_json::Value::String(s) => s,
            serde_json::Value::Null => continue,
            other => {
                return Err(format!(
                    "json: cannot unmarshal {} into Go struct field Config.{field} of type string",
                    json_kind(&other)
                ));
            }
        };
        match field {
            "ca" => c.ca = s,
            "cert" => c.cert = s,
            "key" => c.key = s,
            "ssh" => c.ssh = s,
            "space" => c.space = s,
            _ => c.project = s,
        }
    }
    Ok(c)
}

fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn json_error(e: &serde_json::Error) -> String {
    if e.is_eof() {
        return "unexpected end of JSON input".to_string();
    }
    format!("invalid JSON: {e}")
}

/// A string as Go's encoding/json writes it.
pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl Config {
    /// json.MarshalIndent(c, "", "  ") and a new line.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = String::from("{\n  \"servers\": ");
        if self.servers.is_empty() {
            out.push_str("null");
        } else {
            out.push_str("[\n");
            let items: Vec<String> = self
                .servers
                .iter()
                .map(|s| format!("    {}", json_string(s)))
                .collect();
            out.push_str(&items.join(",\n"));
            out.push_str("\n  ]");
        }
        for (k, v, omit) in [
            ("ca", &self.ca, false),
            ("cert", &self.cert, false),
            ("key", &self.key, false),
            ("ssh", &self.ssh, true),
            ("space", &self.space, true),
            ("project", &self.project, true),
        ] {
            if omit && v.is_empty() {
                continue;
            }
            out.push_str(&format!(",\n  \"{k}\": {}", json_string(v)));
        }
        out.push_str("\n}\n");
        out.into_bytes()
    }

    /// SaveFile: written with mode 0600 into an existing directory; a
    /// config root shared with the group stays shared.
    pub fn save_file(&self, path: &str) -> Result<(), String> {
        let old = fs::metadata(path).ok();
        if let Err(e) = armada_fsutil::write_file_atomic(Path::new(path), &self.encode(), 0o600) {
            let text = e.to_string();
            if text.ends_with("permission denied") {
                return Err(format!(
                    "{text} (a shared config is changed as root: run the command with sudo)"
                ));
            }
            return Err(text);
        }
        if let Some(old) = old
            && shared_ok(&old)
        {
            std::os::unix::fs::chown(path, Some(old.uid()), Some(old.gid()))
                .map_err(|e| path_error("chown", path, &e))?;
            fs::set_permissions(path, fs::Permissions::from_mode(SHARED_MODE))
                .map_err(|e| path_error("chmod", path, &e))?;
        }
        Ok(())
    }
}

impl Config {
    /// Save: SaveFile, making the file's directory (0700) when the file
    /// does not exist yet.
    pub fn save(&self, path: &str) -> Result<(), String> {
        if fs::metadata(path).is_err() {
            let dir = Path::new(path)
                .parent()
                .filter(|d| !d.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            armada_fsutil::mkdir_private(dir).map_err(|e| e.to_string())?;
        }
        self.save_file(path)
    }
}

/// netip.ParseAddrPort's errors, for CheckPrivateListen.
fn addr_port_error(s: &str) -> Option<String> {
    let Some(i) = s.rfind(':') else {
        return Some("not an ip:port".to_string());
    };
    let (mut ip, port) = (&s[..i], &s[i + 1..]);
    if ip.is_empty() {
        return Some("no IP".to_string());
    }
    if port.is_empty() {
        return Some("no port".to_string());
    }
    let mut v6 = false;
    if ip.starts_with('[') {
        if ip.len() < 2 || !ip.ends_with(']') {
            return Some("missing ]".to_string());
        }
        ip = &ip[1..ip.len() - 1];
        v6 = true;
    }
    if !port.bytes().all(|c| c.is_ascii_digit()) || port.parse::<u16>().is_err() {
        return Some(format!(
            "invalid port {} parsing {}",
            go::quote(port),
            go::quote(s)
        ));
    }
    let Some(a) = go::parse_addr(ip) else {
        return Some(format!("ParseAddr({}): unable to parse IP", go::quote(ip)));
    };
    if v6 && a.is4 {
        return Some(format!(
            "invalid ip:port {}, square brackets can only be used with IPv6 addresses",
            go::quote(s)
        ));
    }
    if !v6 && !a.is4 {
        return Some(format!(
            "invalid ip:port {}, IPv6 addresses must be surrounded by square brackets",
            go::quote(s)
        ));
    }
    None
}

/// netutil.CheckPrivateListen with its errors.
pub fn check_private_listen(s: &str) -> Result<(), String> {
    if let Some(e) = addr_port_error(s) {
        return Err(format!(
            "listen address {} must be ip:port: {e}",
            go::quote(s)
        ));
    }
    let (a, _) =
        parse_addr_port(s).ok_or_else(|| format!("invalid IP address {}", go::quote(s)))?;
    let text = a.string();
    if !a.zone.is_empty() {
        return Err(format!("invalid IP address {}", go::quote(&text)));
    }
    let u = a.unmap();
    if u.string() != text {
        return Err(format!(
            "IP address {} is not in canonical form (want {})",
            go::quote(&text),
            u.string()
        ));
    }
    if !private_listen(s) {
        return Err(format!(
            "{text}: address is not private; internal services must bind to a private (VPC) or loopback address"
        ));
    }
    Ok(())
}

/// CheckSSH: an ssh(1) destination that never reads as an option:
/// `^(ssh://)?([A-Za-z0-9._][A-Za-z0-9._-]*@)?[A-Za-z0-9._\[][A-Za-z0-9._:\[\]-]*$`.
pub fn check_ssh(dest: &str) -> Result<(), String> {
    if dest.len() > 255 || !ssh_dest(dest) {
        return Err(format!(
            "ssh destination {}: want [user@]host, a host alias from ~/.ssh/config, or ssh://[user@]host[:port]",
            go::quote(dest)
        ));
    }
    Ok(())
}

fn ssh_dest(s: &str) -> bool {
    let host_ok = |h: &str| {
        let b = h.as_bytes();
        !b.is_empty()
            && (b[0].is_ascii_alphanumeric() || matches!(b[0], b'.' | b'_' | b'['))
            && b[1..].iter().all(|&c| {
                c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'[' | b']' | b'-')
            })
    };
    let user_ok = |u: &str| {
        let b = u.as_bytes();
        !b.is_empty()
            && (b[0].is_ascii_alphanumeric() || matches!(b[0], b'.' | b'_'))
            && b[1..]
                .iter()
                .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
    };
    let check = |rest: &str| {
        // The host part has no "@", so a user part ends at the first one.
        match rest.split_once('@') {
            Some((u, h)) => user_ok(u) && host_ok(h),
            None => host_ok(rest),
        }
    };
    check(s) || s.strip_prefix("ssh://").is_some_and(check)
}

/// ParseServers: addresses separated by commas or new lines, empty
/// entries and repeats skipped.
pub fn parse_servers(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for a in s.split([',', '\n', '\r']) {
        let a = go::trim_space(a);
        if !a.is_empty() && !out.iter().any(|o| o == a) {
            out.push(a.to_string());
        }
    }
    out
}

/// netip.ParseAddrPort.
pub fn parse_addr_port(s: &str) -> Option<(go::Addr, u16)> {
    let i = s.rfind(':')?;
    let (ip, port) = (&s[..i], &s[i + 1..]);
    if port.is_empty() || !port.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    let addr = if let Some(inner) = ip.strip_prefix('[') {
        let inner = inner.strip_suffix(']')?;
        let a = go::parse_addr(inner)?;
        if a.is4 {
            return None;
        }
        a
    } else {
        let a = go::parse_addr(ip)?;
        if !a.is4 {
            return None;
        }
        a
    };
    Some((addr, port))
}

/// Addr.IsLoopback.
pub fn is_loopback(a: &go::Addr) -> bool {
    if a.is4 {
        return a.bytes[0] == 127;
    }
    a.bytes[..15].iter().all(|&b| b == 0) && a.bytes[15] == 1
}

/// CheckPrivateListen, as CheckServers uses it.
fn private_listen(s: &str) -> bool {
    let Some((a, _)) = parse_addr_port(s) else {
        return false;
    };
    if !a.zone.is_empty() {
        return false;
    }
    let text = a.string();
    // CheckPrivateIP of the address's own text: canonical once unmapped.
    let u = a.unmap();
    if u.string() != text {
        return false;
    }
    let cgnat = u.is4 && u.bytes[0] == 100 && u.bytes[1] & 0xc0 == 64;
    u.is_private() || is_loopback(&u) || cgnat
}

/// CheckServers: every address a private ip:port.
pub fn check_servers(addrs: &[String]) -> bool {
    !addrs.is_empty() && addrs.iter().all(|a| private_listen(a))
}

/// MachineServers: the addresses in SERVERS_PATH, or none when the file
/// is missing, not root's, writable by others, or holds an invalid one.
pub fn machine_servers() -> Vec<String> {
    let Ok(meta) = fs::metadata(SERVERS_PATH) else {
        return Vec::new();
    };
    if !meta.is_file()
        || meta.len() > MAX_SERVERS_FILE
        || meta.uid() != 0
        || meta.permissions().mode() & 0o022 != 0
    {
        return Vec::new();
    }
    let Ok(b) = fs::read(SERVERS_PATH) else {
        return Vec::new();
    };
    let addrs = parse_servers(&String::from_utf8_lossy(&b));
    if !check_servers(&addrs) {
        return Vec::new();
    }
    addrs
}

/// SameServers: the same addresses in any order.
pub fn same_servers(a: &[String], b: &[String]) -> bool {
    let mut x = a.to_vec();
    let mut y = b.to_vec();
    x.sort();
    x.dedup();
    y.sort();
    y.dedup();
    x == y
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_destinations() {
        for ok in [
            "bastion.test",
            "ops@bastion.test",
            "ssh://ops@host:2222",
            "[::1]",
            "alias",
        ] {
            assert!(check_ssh(ok).is_ok(), "{ok}");
        }
        for bad in ["-oProxyCommand=x", "a b", "", "@host", "a;b", "ssh://-x"] {
            assert!(check_ssh(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn servers() {
        assert_eq!(parse_servers(" a, b\nb,,c\r\n"), ["a", "b", "c"]);
        assert!(check_servers(&[
            "10.0.0.1:7443".into(),
            "127.0.0.1:1".into(),
            "[fd00::1]:7443".into()
        ]));
        assert!(!check_servers(&["8.8.8.8:443".into()]));
        assert!(!check_servers(&["10.0.0.1".into()]));
        assert!(!check_servers(&["[::ffff:10.0.0.1]:1".into()]));
        assert!(check_servers(&["100.64.0.1:1".into()]));
        assert!(!check_servers(&[]));
    }

    #[test]
    fn encode_round_trip() {
        let c = Config {
            servers: vec!["10.0.0.1:7443".into()],
            ca: "a\n<b>".into(),
            cert: "c".into(),
            key: "k".into(),
            space: "shop".into(),
            ..Config::default()
        };
        let text = String::from_utf8(c.encode()).unwrap();
        assert_eq!(
            text,
            "{\n  \"servers\": [\n    \"10.0.0.1:7443\"\n  ],\n  \"ca\": \"a\\n\\u003cb\\u003e\",\n  \"cert\": \"c\",\n  \"key\": \"k\",\n  \"space\": \"shop\"\n}\n"
        );
        assert_eq!(decode(text.as_bytes()).unwrap(), c);
    }
}

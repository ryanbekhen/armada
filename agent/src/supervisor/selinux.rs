//! SELinux confinement of containers (ADR 0011; Go's internal/runtime/
//! containerd selinux.go and selinux_linux.go over go-selinux v1.15.1):
//! on SELinux hosts every container runs as the policy's container
//! process type with categories of its own, its spec carries the matching
//! mount label, and the files Armada bind-mounts into it are relabelled,
//! so a container reaches neither the host's files nor another
//! container's. The kernel's side (the policy's contexts, the context
//! check, extended attributes) goes through [`Host`].

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use super::host::Host;

/// The policy's type for files every container may read; policies
/// without it get the plain container file type.
pub const RO_FILE_TYPE: &str = "container_ro_file_t";
/// go-selinux's maxCategory and its default category range.
const MAX_CATEGORY: u32 = 1024;
/// The extended attribute holding a file's label.
pub const XATTR: &str = "security.selinux";

/// How containers are confined on this host (SELinuxState).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// SELinux is off; there is nothing to label.
    Disabled,
    /// Containers run as container_t with their own categories.
    Confined,
    /// SELinux is on but the policy has no container types, so containers
    /// run with the runtime's own label.
    NoPolicy,
}

/// A container's labels (selinuxLabels); empty when it is not confined.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Labels {
    /// e.g. system_u:system_r:container_t:s0:c1,c2
    pub process: String,
    /// e.g. system_u:object_r:container_file_t:s0:c1,c2
    pub mount: String,
}

/// A label's parts (go-selinux's Context).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Context {
    pub user: String,
    pub role: String,
    pub typ: String,
    pub level: String,
}

impl Context {
    /// NewContext: "" is an empty context; fewer than three parts is
    /// ErrInvalidLabel.
    pub fn new(label: &str) -> Result<Context, String> {
        if label.is_empty() {
            return Ok(Context::default());
        }
        let p: Vec<&str> = label.splitn(4, ':').collect();
        if p.len() < 3 {
            return Err("invalid Label".into());
        }
        Ok(Context {
            user: p[0].into(),
            role: p[1].into(),
            typ: p[2].into(),
            level: p.get(3).copied().unwrap_or_default().into(),
        })
    }

    /// Context.Get.
    pub fn get(&self) -> String {
        if self.level.is_empty() {
            format!("{}:{}:{}", self.user, self.role, self.typ)
        } else {
            format!("{}:{}:{}:{}", self.user, self.role, self.typ, self.level)
        }
    }
}

/// The level of a label: what follows its third colon.
fn level_of(label: &str) -> Option<&str> {
    let p: Vec<&str> = label.splitn(4, ':').collect();
    (p.len() > 3).then(|| p[3])
}

/// go-selinux's state in this process: whether SELinux is on, the
/// policy's container contexts, and the categories handed out.
pub struct Selinux {
    host: Arc<dyn Host>,
    enabled: OnceLock<bool>,
    contexts: OnceLock<HashMap<String, String>>,
    mcs: Mutex<HashSet<String>>,
    /// The categories of existing containers were reserved
    /// (Driver.labelsReserved), under the driver's labelsMu.
    pub(crate) reserved: tokio::sync::Mutex<bool>,
}

/// A random number below n from the kernel's generator.
fn random_below(n: u32) -> u32 {
    let mut b = [0u8; 4];
    // SAFETY: the buffer is valid for its length.
    let r = unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) };
    if r != 4 {
        return 0;
    }
    u32::from_ne_bytes(b) % n
}

/// parseContexts: lxc_contexts' "key = value" lines, quotes trimmed,
/// blank lines and comments (';' or '#') skipped.
pub fn parse_contexts(b: &[u8]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in b.split(|&c| c == b'\n') {
        let line = line.trim_ascii();
        if line.is_empty() || line[0] == b';' || line[0] == b'#' {
            continue;
        }
        if let Some(i) = line.iter().position(|&c| c == b'=') {
            let k = line[..i].trim_ascii();
            let v = line[i + 1..].trim_ascii();
            let v = trim_quotes(v);
            out.insert(
                String::from_utf8_lossy(k).into_owned(),
                String::from_utf8_lossy(v).into_owned(),
            );
        }
    }
    out
}

/// bytes.Trim(v, `"`).
fn trim_quotes(mut v: &[u8]) -> &[u8] {
    while let [b'"', rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b'"'] = v {
        v = rest;
    }
    v
}

impl Selinux {
    pub fn new(host: Arc<dyn Host>) -> Selinux {
        Selinux {
            host,
            enabled: OnceLock::new(),
            contexts: OnceLock::new(),
            mcs: Mutex::new(HashSet::new()),
            reserved: tokio::sync::Mutex::new(false),
        }
    }

    /// selinux.GetEnabled, asked once per process as go-selinux does.
    pub fn enabled(&self) -> bool {
        *self.enabled.get_or_init(|| self.host.selinux_enabled())
    }

    /// loadLabels: the policy's container contexts, read once; the
    /// privileged mount label's categories are reserved then.
    fn label(&self, key: &str) -> String {
        self.contexts
            .get_or_init(|| {
                let labels = self
                    .host
                    .selinux_contexts()
                    .map(|b| parse_contexts(&b))
                    .unwrap_or_default();
                let mut con =
                    Context::new(labels.get("file").map_or("", String::as_str)).unwrap_or_default();
                con.level = format!("s0:c{},c{}", MAX_CATEGORY - 2, MAX_CATEGORY - 1);
                self.reserve(&con.get());
                labels
            })
            .get(key)
            .cloned()
            .unwrap_or_default()
    }

    /// mcsAdd: false when mcs is taken; a level without categories is
    /// not recorded.
    fn mcs_add(&self, mcs: &str) -> bool {
        if !mcs.contains(":c") {
            return true;
        }
        self.mcs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(mcs.to_string())
    }

    /// uniqMcs: two distinct categories, lower first, not handed out yet.
    fn uniq_mcs(&self) -> String {
        loop {
            let (mut c1, mut c2) = (random_below(MAX_CATEGORY), random_below(MAX_CATEGORY));
            if c1 == c2 {
                continue;
            }
            if c1 > c2 {
                std::mem::swap(&mut c1, &mut c2);
            }
            let mcs = format!("s0:c{c1},c{c2}");
            if self.mcs_add(&mcs) {
                return mcs;
            }
        }
    }

    /// containerLabels (addMcs): the policy's process and file labels with
    /// fresh categories; ("", file) when the policy has no container
    /// types.
    fn container_labels(&self) -> (String, String) {
        if !self.enabled() {
            return (String::new(), String::new());
        }
        let (process, file) = (self.label("process"), self.label("file"));
        if process.is_empty() || file.is_empty() {
            return (String::new(), file);
        }
        let Ok(mut scon) = Context::new(&process) else {
            return (String::new(), file);
        };
        if scon.level.is_empty() {
            return (process, file);
        }
        let mcs = self.uniq_mcs();
        scon.level = mcs.clone();
        let mut fcon = Context::new(&file).unwrap_or_default();
        fcon.level = mcs;
        (scon.get(), fcon.get())
    }

    /// The SELinux support of this host (SELinux()).
    pub fn state(&self) -> State {
        if !self.enabled() {
            return State::Disabled;
        }
        let (p, _) = self.container_labels();
        if p.is_empty() {
            return State::NoPolicy;
        }
        self.release(&p);
        if self.host.selinux_check_context(&p).is_err() {
            return State::NoPolicy;
        }
        State::Confined
    }

    /// newLabels: a process and mount label with categories no other
    /// container of this process holds, or empty labels when containers
    /// cannot be confined.
    pub fn new_labels(&self) -> Labels {
        let (p, m) = self.container_labels();
        if p.is_empty() {
            return Labels::default();
        }
        if self.host.selinux_check_context(&p).is_err() {
            self.release(&p);
            return Labels::default();
        }
        Labels {
            process: p,
            mount: m,
        }
    }

    /// reserveLabel (ReserveLabelV2): an existing container's categories
    /// are not handed out again; already reserved is fine.
    pub fn reserve(&self, process: &str) {
        if let Some(l) = level_of(process) {
            self.mcs_add(l);
        }
    }

    /// releaseLabel.
    pub fn release(&self, process: &str) {
        if let Some(l) = level_of(process)
            && !l.is_empty()
        {
            self.mcs.lock().unwrap_or_else(|p| p.into_inner()).remove(l);
        }
    }

    /// The levels handed out or reserved (tests).
    #[cfg(test)]
    pub fn reserved_levels(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .mcs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .cloned()
            .collect();
        v.sort();
        v
    }

    /// relabel: path, recursively, gets the container's mount label, so
    /// only that container can use it (selinux.Chcon with recurse).
    pub fn relabel(&self, path: &Path, l: &Labels) -> Result<(), String> {
        if l.mount.is_empty() {
            return Ok(());
        }
        chcon(&*self.host, path, &l.mount, &excluded_homes())
    }

    /// relabelShared: path gets the label every container may read but
    /// not write (level s0, the read-only type where the policy has it).
    pub fn relabel_shared(&self, path: &Path, l: &Labels) -> Result<(), String> {
        if l.mount.is_empty() {
            return Ok(());
        }
        let mut c = Context::new(&l.mount)?;
        c.level = "s0".into();
        let plain = c.get();
        c.typ = RO_FILE_TYPE.into();
        let ro = c.get();
        let label = if self.host.selinux_check_context(&ro).is_ok() {
            ro
        } else {
            plain
        };
        self.host
            .set_file_label(path, &label)
            .map_err(|e| super::os_err(&format!("setxattr(label={label})"), path, &e))
    }
}

/// The process label of a container's config.json (processLabel): only a
/// label with a colon.
pub fn process_label(spec: &[u8]) -> String {
    let v: serde_json::Value = serde_json::from_slice(spec).unwrap_or_default();
    let l = v["process"]["selinuxLabel"].as_str().unwrap_or_default();
    if l.contains(':') {
        l.to_string()
    } else {
        String::new()
    }
}

/// The home directories chcon refuses besides its fixed list: $HOME and
/// $SUDO_USER's.
fn excluded_homes() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(h) = std::env::var("HOME")
        && !h.is_empty()
    {
        out.push(h);
    }
    if let Ok(u) = std::env::var("SUDO_USER")
        && !u.is_empty()
        && let Some(h) = home_of(&u)
    {
        out.push(h);
    }
    out
}

/// user.Lookup's home directory, from the password database.
fn home_of(user: &str) -> Option<String> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 6 && f[0] == user).then(|| f[5].to_string())
    })
}

/// The paths chcon never relabels.
const EXCLUDED: &[&str] = &[
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/etc/passwd",
    "/etc/pki",
    "/etc/shadow",
    "/home",
    "/lib",
    "/lib64",
    "/media",
    "/opt",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/srv",
    "/sys",
    "/tmp",
    "/usr",
    "/var",
    "/var/lib",
    "/var/log",
];

fn not_exist(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound
}

/// chcon with recurse (rchcon): every entry under path, path last, gets
/// label; an entry removed meanwhile is skipped. When path has the label
/// already, entries with it are left alone.
pub fn chcon(host: &dyn Host, path: &Path, label: &str, homes: &[String]) -> Result<(), String> {
    let s = path.to_string_lossy();
    if s.is_empty() {
        return Err("empty path".into());
    }
    let trimmed = if s == "/" {
        s.to_string()
    } else {
        s.trim_end_matches('/').to_string()
    };
    if EXCLUDED.contains(&trimmed.as_str()) || homes.contains(&trimmed) {
        return Err(format!("SELinux relabeling of {trimmed} is not allowed"));
    }
    let root = Path::new(&trimmed);
    let fast = host.lfile_label(root).is_ok_and(|l| l == label);
    let set = |p: &Path| -> Result<(), String> {
        if fast && host.lfile_label(p).is_ok_and(|l| l == label) {
            return Ok(());
        }
        match host.lset_file_label(p, label) {
            Err(e) if !not_exist(&e) => {
                Err(super::os_err(&format!("lsetxattr(label={label})"), p, &e))
            }
            _ => Ok(()),
        }
    };
    let meta = std::fs::symlink_metadata(root).map_err(|e| super::os_err("lstat", root, &e))?;
    if meta.is_dir() {
        walk(root, &set)?;
    }
    set(root)
}

/// filepath.WalkDir below dir in lexical order (dir itself left to the
/// caller); entries gone meanwhile are skipped.
fn walk(dir: &Path, f: &dyn Fn(&Path) -> Result<(), String>) -> Result<(), String> {
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) if not_exist(&e) => return Ok(()),
        Err(e) => return Err(super::os_err("open", dir, &e)),
    };
    let mut names: Vec<_> = rd.filter_map(|e| e.ok()).collect();
    names.sort_by_key(|e| e.file_name());
    for e in names {
        let p = e.path();
        f(&p)?;
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            walk(&p, f)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contexts_and_levels() {
        let c = parse_contexts(
            b"# comment\n; too\n\nprocess = \"system_u:system_r:container_t:s0\"\nfile=\"system_u:object_r:container_file_t:s0\"\nro_file=\"system_u:object_r:container_ro_file_t:s0\"\n",
        );
        assert_eq!(c["process"], "system_u:system_r:container_t:s0");
        assert_eq!(c["file"], "system_u:object_r:container_file_t:s0");
        let x = Context::new("u:r:t:s0:c1,c2").unwrap();
        assert_eq!(x.level, "s0:c1,c2");
        assert_eq!(x.get(), "u:r:t:s0:c1,c2");
        assert_eq!(Context::new("u:r").unwrap_err(), "invalid Label");
        assert_eq!(Context::new("u:r:t").unwrap().get(), "u:r:t");
        assert_eq!(level_of("u:r:t:s0:c3,c4"), Some("s0:c3,c4"));
        assert_eq!(level_of("u:r:t"), None);
        assert_eq!(
            process_label(br#"{"process":{"selinuxLabel":"u:r:t:s0:c1,c2"}}"#),
            "u:r:t:s0:c1,c2"
        );
        assert_eq!(process_label(br#"{"process":{"selinuxLabel":"x"}}"#), "");
    }
}

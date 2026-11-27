//! The spec of a container: containerd's default Unix spec
//! (oci.populateDefaultUnixSpec), then Armada's options in order (the
//! command's, then an app container's or a system container's), each
//! applied as the containerd option of the same purpose applies it.

use super::gopath;
use super::seccomp;
use super::spec::*;
use super::user::{self, FsError, Rootfs};
use super::{ContainerSpec, ImageConfig, SpecRequest, SystemSpec};

/// initPath: where tini is mounted in app containers.
const INIT_PATH: &str = "/sbin/armada-init";
/// cpuPeriod: the CFS period of CPU limits (100ms).
const CPU_PERIOD: i64 = 100_000;
/// nofile: every container's open-file limit.
const NOFILE: u64 = 1_048_576;
/// appOOMScoreAdj.
const APP_OOM_SCORE_ADJ: i64 = 0;
/// shimGroupAnnotation.
const SHIM_GROUP_ANNOTATION: &str = "io.containerd.runc.v2.group";
/// runtime.DroppedCaps.
const DROPPED_CAPS: [&str; 3] = ["NET_RAW", "MKNOD", "AUDIT_WRITE"];
/// runtime.LabelApp.
const LABEL_APP: &str = "armada.app";

/// cpuShares: 1024 per core, at least 2, at most 262144, in wrapping
/// 64-bit arithmetic.
pub fn cpu_shares(millis: i64) -> u64 {
    (millis.wrapping_mul(1024) / 1000).clamp(2, 262_144) as u64
}

/// shimGroup: one shim per app and runtime pack, none without an app.
pub fn shim_group(app: &str, tini: &str) -> String {
    if app.is_empty() {
        return String::new();
    }
    format!("{app}@{}", gopath::base(&gopath::dir(&gopath::dir(tini))))
}

/// hostname: at most 63 bytes, underscores as hyphens, no dots or hyphens
/// at either end. Bytes a cut leaves of a character become U+FFFD one
/// each, as encoding/json writes them.
pub fn hostname(id: &str) -> String {
    let b = id.as_bytes();
    let b = &b[..b.len().min(63)];
    let s = go_string(b).replace('_', "-");
    s.trim_matches(['.', '-']).to_string()
}

/// Bytes as a JSON string holding them: each byte of an invalid UTF-8
/// sequence as U+FFFD.
fn go_string(mut b: &[u8]) -> String {
    let mut out = String::new();
    loop {
        match std::str::from_utf8(b) {
            Ok(s) => {
                out.push_str(s);
                return out;
            }
            Err(e) => {
                let good = e.valid_up_to();
                out.push_str(std::str::from_utf8(&b[..good]).expect("valid prefix"));
                let bad = e.error_len().unwrap_or(b.len() - good);
                for _ in 0..bad {
                    out.push('\u{fffd}');
                }
                b = &b[good + bad..];
            }
        }
    }
}

fn cap_names(caps: &[String]) -> Vec<String> {
    caps.iter().map(|c| format!("CAP_{c}")).collect()
}

fn default_caps() -> Vec<String> {
    [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FSETID",
        "CAP_FOWNER",
        "CAP_MKNOD",
        "CAP_NET_RAW",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETFCAP",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_SYS_CHROOT",
        "CAP_KILL",
        "CAP_AUDIT_WRITE",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// defaultLinuxMaskedPaths on this machine: the fixed list, then each
/// possible CPU's thermal_throttle directory that exists.
pub fn default_masked_paths() -> Vec<String> {
    let mut paths: Vec<String> = [
        "/proc/acpi",
        "/proc/asound",
        "/proc/interrupts",
        "/proc/kcore",
        "/proc/keys",
        "/proc/latency_stats",
        "/proc/timer_list",
        "/proc/timer_stats",
        "/proc/sched_debug",
        "/sys/firmware",
        "/sys/devices/virtual/powercap",
        "/proc/scsi",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for cpu in possible_cpus() {
        let p = format!("/sys/devices/system/cpu/cpu{cpu}/thermal_throttle");
        if std::fs::metadata(&p).is_ok() {
            paths.push(p);
        }
    }
    paths
}

/// possibleCPUs: /sys/devices/system/cpu/possible, else 0..NumCPU.
fn possible_cpus() -> Vec<i64> {
    if let Ok(s) = std::fs::read_to_string("/sys/devices/system/cpu/possible")
        && let Some(cpus) = parse_possible_cpus(s.trim_matches(char::is_whitespace))
        && !cpus.is_empty()
    {
        return cpus;
    }
    (0..num_cpu()).collect()
}

/// parsePossibleCPUs, None for its errors.
fn parse_possible_cpus(content: &str) -> Option<Vec<i64>> {
    if content.is_empty() {
        return None;
    }
    let num = |s: &str| -> Option<i64> {
        match user::atoi(s.as_bytes()) {
            (v, Ok(())) if v >= 0 => Some(v),
            _ => None,
        }
    };
    let mut cpus = Vec::new();
    for r in content.split(',') {
        if let Some((a, b)) = r.split_once('-') {
            let (start, end) = (num(a)?, num(b)?);
            if start > end {
                return None;
            }
            cpus.extend(start..=end);
        } else {
            cpus.push(num(r)?);
        }
    }
    Some(cpus)
}

/// runtime.NumCPU: the CPUs this process may run on.
fn num_cpu() -> i64 {
    // SAFETY: a zeroed set sched_getaffinity fills.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let n =
        if unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) }
            == 0
        {
            // SAFETY: the set was filled above.
            unsafe { libc::CPU_COUNT(&set) as i64 }
        } else {
            0
        };
    n.max(1)
}

/// populateDefaultUnixSpec, with the cgroup path the namespace and ID give.
fn default_spec(cgroups_path: String, masked: Vec<String>) -> Spec {
    let m = |d: &str, t: &str, s: &str, o: &[&str]| Mount::new(d, t, s, o);
    Spec {
        version: OCI_VERSION.into(),
        root: Some(Root {
            path: "rootfs".into(),
            readonly: false,
        }),
        process: Some(Process {
            cwd: "/".into(),
            no_new_privileges: true,
            capabilities: Some(Capabilities {
                bounding: default_caps(),
                permitted: default_caps(),
                effective: default_caps(),
                inheritable: Vec::new(),
            }),
            rlimits: vec![Rlimit {
                kind: "RLIMIT_NOFILE".into(),
                hard: 1024,
                soft: 1024,
            }],
            ..Default::default()
        }),
        linux: Some(Linux {
            masked_paths: masked,
            readonly_paths: [
                "/proc/bus",
                "/proc/fs",
                "/proc/irq",
                "/proc/sys",
                "/proc/sysrq-trigger",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            cgroups_path,
            resources: Some(Resources {
                devices: vec![DeviceCgroup {
                    allow: false,
                    access: "rwm".into(),
                }],
                ..Default::default()
            }),
            namespaces: ["pid", "ipc", "uts", "mount", "network"]
                .iter()
                .map(|t| Namespace {
                    kind: t.to_string(),
                    path: String::new(),
                })
                .collect(),
            ..Default::default()
        }),
        mounts: vec![
            m("/proc", "proc", "proc", &["nosuid", "noexec", "nodev"]),
            m(
                "/dev",
                "tmpfs",
                "tmpfs",
                &["nosuid", "strictatime", "mode=755", "size=65536k"],
            ),
            m(
                "/dev/pts",
                "devpts",
                "devpts",
                &[
                    "nosuid",
                    "noexec",
                    "newinstance",
                    "ptmxmode=0666",
                    "mode=0620",
                    "gid=5",
                ],
            ),
            m(
                "/dev/shm",
                "tmpfs",
                "shm",
                &["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"],
            ),
            m(
                "/dev/mqueue",
                "mqueue",
                "mqueue",
                &["nosuid", "noexec", "nodev"],
            ),
            m(
                "/sys",
                "sysfs",
                "sysfs",
                &["nosuid", "noexec", "nodev", "ro"],
            ),
            m(
                "/run",
                "tmpfs",
                "tmpfs",
                &["nosuid", "strictatime", "mode=755", "size=65536k"],
            ),
        ],
        ..Default::default()
    }
}

/// The spec under construction with what options read: the root
/// filesystem (opened when an option first needs it) and the image.
struct Builder<'a> {
    s: Spec,
    rootfs_path: &'a str,
    rootfs: Option<Rootfs>,
}

type Res = Result<(), String>;

impl<'a> Builder<'a> {
    fn process(&mut self) -> &mut Process {
        self.s.process.get_or_insert_with(Default::default)
    }

    fn linux(&mut self) -> &mut Linux {
        self.s.linux.get_or_insert_with(Default::default)
    }

    fn caps(&mut self) -> &mut Capabilities {
        self.process()
            .capabilities
            .get_or_insert_with(Default::default)
    }

    fn resources(&mut self) -> Option<&mut Resources> {
        self.s
            .linux
            .as_mut()
            .map(|l| l.resources.get_or_insert_with(Default::default))
    }

    fn root(&mut self) -> Result<&Rootfs, FsError> {
        if self.rootfs.is_none() {
            self.rootfs = Some(Rootfs::open(self.rootfs_path)?);
        }
        Ok(self.rootfs.as_ref().expect("opened"))
    }

    /// WithEnv.
    fn env(&mut self, env: &[String]) {
        if !env.is_empty() {
            let p = self.process();
            p.env = replace_or_append_env(&p.env, env);
        }
    }

    /// WithProcessArgs.
    fn args(&mut self, args: Vec<String>) {
        self.process().args = args;
    }

    /// WithLinuxNamespace.
    fn namespace(&mut self, kind: &str, path: &str) {
        let ns = Namespace {
            kind: kind.into(),
            path: path.into(),
        };
        let l = self.linux();
        match l.namespaces.iter_mut().find(|n| n.kind == kind) {
            Some(n) => *n = ns,
            None => l.namespaces.push(ns),
        }
    }

    /// WithHostNamespace.
    fn host_namespace(&mut self, kind: &str) {
        let l = self.linux();
        if let Some(i) = l.namespaces.iter().position(|n| n.kind == kind) {
            l.namespaces.remove(i);
        }
    }

    /// WithRlimit.
    fn rlimit(&mut self, r: Rlimit) {
        let p = self.process();
        match p.rlimits.iter_mut().find(|x| x.kind == r.kind) {
            Some(x) => *x = r,
            None => p.rlimits.push(r),
        }
    }

    /// WithDroppedCapabilities.
    fn drop_caps(&mut self, caps: &[String]) {
        let c = self.caps();
        for cap in caps {
            for l in [
                &mut c.bounding,
                &mut c.effective,
                &mut c.permitted,
                &mut c.inheritable,
            ] {
                l.retain(|x| x != cap);
            }
        }
    }

    /// WithCapabilities.
    fn set_caps(&mut self, caps: Vec<String>) {
        let c = self.caps();
        c.bounding = caps.clone();
        c.effective = caps.clone();
        c.permitted = caps.clone();
        if caps.is_empty() {
            c.inheritable = Vec::new();
        } else if !c.inheritable.is_empty() {
            c.inheritable.retain(|x| caps.contains(x));
        }
    }

    /// withSELinux.
    fn selinux(&mut self, process: &str, mount: &str) {
        if process.is_empty() {
            return;
        }
        if let Some(p) = self.s.process.as_mut() {
            p.selinux_label = process.into();
        }
        if let Some(l) = self.s.linux.as_mut() {
            l.mount_label = mount.into();
        }
    }

    /// seccomp.WithDefaultProfile, from the bounding set at this point.
    fn seccomp(&mut self, goarch: &str, kernel_4_8: bool) {
        let bounding = self
            .s
            .process
            .as_ref()
            .and_then(|p| p.capabilities.as_ref())
            .map(|c| c.bounding.clone())
            .unwrap_or_default();
        self.linux().seccomp = Some(seccomp::default_profile(&bounding, goarch, kernel_4_8));
    }

    /// WithImageConfigArgs (WithImageConfig with no args).
    fn image_config(&mut self, img: &ImageConfig, args: Option<&[String]>) -> Res {
        self.process();
        if self.s.linux.is_none() {
            return Err("spec does not contain Linux or Windows section".into());
        }
        let defaults: Vec<String> = if img.env.is_empty() {
            vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()]
        } else {
            img.env.clone()
        };
        let p = self.process();
        p.env = replace_or_append_env(&defaults, &p.env);
        let cmd = match args {
            Some(a) if !a.is_empty() => a.to_vec(),
            _ => img.cmd.clone(),
        };
        let mut a = img.entrypoint.clone();
        a.extend(cmd);
        p.args = a;
        p.cwd = if img.working_dir.is_empty() {
            "/".into()
        } else {
            img.working_dir.clone()
        };
        if !img.user.is_empty() {
            self.with_user(&img.user)?;
            let uid = self.process().user.uid.to_string();
            return self.additional_gids(&uid);
        }
        self.additional_gids("root")
    }

    /// ensureAdditionalGids.
    fn ensure_additional_gids(&mut self) {
        let u = &mut self.process().user;
        if !u.additional_gids.contains(&u.gid) {
            u.additional_gids.insert(0, u.gid);
        }
    }

    /// WithUser: uid, user, uid:gid, user:group, uid:group, user:gid.
    fn with_user(&mut self, userstr: &str) -> Res {
        self.process().user.additional_gids.clear();
        let r = self.with_user_inner(userstr);
        self.ensure_additional_gids();
        r
    }

    fn with_user_inner(&mut self, userstr: &str) -> Res {
        const MAX_ID: i64 = i32::MAX as i64;
        let parts: Vec<&str> = userstr.split(':').collect();
        let range = |what: &str| {
            format!(
                "invalid USER value {}: {what} out of range",
                user_quote(userstr)
            )
        };
        match parts.len() {
            1 => match user::atoi(parts[0].as_bytes()) {
                (_, Err(user::AtoiError::Range)) => Err(range("uid")),
                (_, Err(user::AtoiError::Syntax)) => self.with_username(userstr),
                (v, Ok(())) if !(0..=MAX_ID).contains(&v) => Err(range("uid")),
                (v, Ok(())) => self.with_user_id(v as u32),
            },
            2 => {
                let (mut uid, mut gid) = (0u32, 0u32);
                let mut username = "";
                let mut groupname = "";
                match user::atoi(parts[0].as_bytes()) {
                    (_, Err(user::AtoiError::Range)) => return Err(range("uid")),
                    (_, Err(user::AtoiError::Syntax)) => username = parts[0],
                    (v, Ok(())) if !(0..=MAX_ID).contains(&v) => return Err(range("uid")),
                    (v, Ok(())) => uid = v as u32,
                }
                match user::atoi(parts[1].as_bytes()) {
                    (_, Err(user::AtoiError::Range)) => return Err(range("gid")),
                    (_, Err(user::AtoiError::Syntax)) => groupname = parts[1],
                    (v, Ok(())) if !(0..=MAX_ID).contains(&v) => return Err(range("gid")),
                    (v, Ok(())) => gid = v as u32,
                }
                if username.is_empty() && groupname.is_empty() {
                    let u = &mut self.process().user;
                    (u.uid, u.gid) = (uid, gid);
                    return Ok(());
                }
                let root = self.root().map_err(|e| e.text)?;
                if !username.is_empty() {
                    let users = read_passwd(root).map_err(|e| e.text)?;
                    match users.iter().find(|u| u.name == username.as_bytes()) {
                        Some(u) => uid = u.uid as u32,
                        None => return Err("no users found".into()),
                    }
                }
                if !groupname.is_empty() {
                    let groups = read_group(root).map_err(|e| e.text)?;
                    match groups.iter().find(|g| g.name == groupname.as_bytes()) {
                        Some(g) => gid = g.gid as u32,
                        None => return Err("no groups found".into()),
                    }
                }
                let u = &mut self.process().user;
                (u.uid, u.gid) = (uid, gid);
                Ok(())
            }
            _ => Err(format!("invalid USER value {userstr}")),
        }
    }

    /// WithUserID: the user's group from /etc/passwd, 0 when the file or
    /// the user is missing.
    fn with_user_id(&mut self, uid: u32) -> Res {
        self.process().user.additional_gids.clear();
        let r = (|| {
            let root = self.root().map_err(|e| e.text)?;
            let found = match read_passwd(root) {
                Ok(users) => users.into_iter().find(|u| u.uid == i64::from(uid)),
                Err(e) if e.not_exist => None,
                Err(e) => return Err(e.text),
            };
            let u = &mut self.process().user;
            match found {
                Some(f) => (u.uid, u.gid) = (f.uid as u32, f.gid as u32),
                None => (u.uid, u.gid) = (uid, 0),
            }
            Ok(())
        })();
        self.ensure_additional_gids();
        r
    }

    /// WithUsername: the user must be in /etc/passwd.
    fn with_username(&mut self, name: &str) -> Res {
        self.process().user.additional_gids.clear();
        let r = (|| {
            let root = self.root().map_err(|e| e.text)?;
            let users = read_passwd(root).map_err(|e| e.text)?;
            let f = users
                .into_iter()
                .find(|u| u.name == name.as_bytes())
                .ok_or_else(|| "no users found".to_string())?;
            let u = &mut self.process().user;
            (u.uid, u.gid) = (f.uid as u32, f.gid as u32);
            Ok(())
        })();
        self.ensure_additional_gids();
        r
    }

    /// WithAdditionalGIDs: the groups of /etc/group that list the user.
    fn additional_gids(&mut self, userstr: &str) -> Res {
        self.process().user.additional_gids.clear();
        let root = self.root().map_err(|e| e.text)?;
        let username: Vec<u8> = match user::atoi(userstr.as_bytes()) {
            (uid, Ok(())) => match read_passwd(root) {
                Ok(users) => match users.into_iter().find(|u| u.uid == uid) {
                    Some(u) => u.name,
                    None => {
                        self.ensure_additional_gids();
                        return Ok(());
                    }
                },
                Err(e) if e.not_exist => {
                    self.ensure_additional_gids();
                    return Ok(());
                }
                Err(e) => {
                    self.ensure_additional_gids();
                    return Err(e.text);
                }
            },
            _ => userstr.as_bytes().to_vec(),
        };
        let gids = match read_group(root) {
            Ok(groups) => groups
                .into_iter()
                .filter(|g| g.name != username && g.list.contains(&username))
                .map(|g| g.gid as u32)
                .collect(),
            Err(e) if e.not_exist => {
                self.ensure_additional_gids();
                return Ok(());
            }
            Err(e) => {
                self.ensure_additional_gids();
                return Err(e.text);
            }
        };
        self.process().user.additional_gids = gids;
        self.ensure_additional_gids();
        Ok(())
    }

    /// withInit: tini runs the process.
    fn init(&mut self) -> Res {
        match self.s.process.as_mut() {
            Some(p) if !p.args.is_empty() => {
                let mut a = vec![INIT_PATH.to_string(), "--".into()];
                a.append(&mut p.args);
                p.args = a;
                Ok(())
            }
            _ => Err("image has no command; set one in the spec".into()),
        }
    }
}

/// %q of a USER value.
fn user_quote(s: &str) -> String {
    crate::net::addr::quote(s)
}

fn read_passwd(root: &Rootfs) -> Result<Vec<user::PasswdUser>, FsError> {
    user::parse_passwd(&root.read_user_file("etc/passwd")?)
}

fn read_group(root: &Rootfs) -> Result<Vec<user::Group>, FsError> {
    user::parse_group(&root.read_user_file("etc/group")?)
}

/// replaceOrAppendEnvValues.
pub fn replace_or_append_env(defaults: &[String], overrides: &[String]) -> Vec<String> {
    let mut cache: std::collections::HashMap<String, usize> = Default::default();
    let mut results: Vec<String> = Vec::with_capacity(defaults.len());
    for (i, e) in defaults.iter().enumerate() {
        let k = e.split_once('=').map_or(e.as_str(), |(k, _)| k);
        results.push(e.clone());
        cache.insert(k.to_string(), i);
    }
    for value in overrides {
        match value.split_once('=') {
            None => {
                if let Some(&i) = cache.get(value.as_str()) {
                    results[i] = String::new();
                }
            }
            Some((k, _)) => match cache.get(k) {
                Some(&i) => results[i] = value.clone(),
                None => results.push(value.clone()),
            },
        }
    }
    results.retain(|e| !e.is_empty());
    results
}

/// The spec of an app container (or an init container or sidecar):
/// The command's options, then an app container's, on the default spec.
pub fn app_spec(r: &SpecRequest, s: &ContainerSpec, host: &Host) -> Result<Spec, String> {
    let mut b = Builder {
        s: default_spec(r.default_cgroups_path(), host.masked.clone()),
        rootfs_path: &r.rootfs,
        rootfs: None,
    };
    // The command's options.
    if !s.entrypoint.is_empty() {
        b.image_config(&r.image, None)?;
        let mut a = s.entrypoint.clone();
        a.extend(s.cmd.iter().cloned());
        b.args(a);
    } else if !s.cmd.is_empty() {
        b.image_config(&r.image, Some(&s.cmd))?;
    } else {
        b.image_config(&r.image, None)?;
    }
    // An app container's options.
    let ro = ["rbind", "ro", "nosuid", "nodev", "noexec"];
    let mut mounts = vec![
        Mount::new("/etc/resolv.conf", "bind", &r.files.resolv, &ro),
        Mount::new("/etc/hosts", "bind", &r.files.hosts, &ro),
        Mount::new("/etc/hostname", "bind", &r.files.hostname, &ro),
        Mount::new(
            INIT_PATH,
            "bind",
            &r.tini,
            &["rbind", "ro", "nosuid", "nodev"],
        ),
        Mount::new(
            "/sys/fs/cgroup",
            "cgroup",
            "cgroup",
            &["ro", "nosuid", "noexec", "nodev", "relatime"],
        ),
    ];
    for f in &s.files {
        mounts.push(Mount::new(&f.target, "bind", &f.source, &ro));
    }
    for v in &s.volumes {
        let rw = if v.read_only { "ro" } else { "rw" };
        mounts.push(Mount::new(
            &v.target,
            "bind",
            &v.source,
            &["rbind", rw, "nosuid", "nodev"],
        ));
    }
    let h = hostname(&s.name);
    b.env(&s.env);
    b.env(&[format!("HOSTNAME={h}")]);
    b.s.hostname = h;
    b.namespace("network", &r.netns);
    b.namespace("cgroup", "");
    b.s.mounts.extend(mounts);
    b.drop_caps(&cap_names(&DROPPED_CAPS.map(String::from)));
    b.process().no_new_privileges = true;
    b.linux().cgroups_path = r.cgroup.clone();
    b.rlimit(Rlimit {
        kind: "RLIMIT_NOFILE".into(),
        hard: NOFILE,
        soft: NOFILE,
    });
    b.init()?;
    b.selinux(&r.selinux.process, &r.selinux.mount);
    b.process().oom_score_adj = Some(APP_OOM_SCORE_ADJ);
    if r.seccomp {
        b.seccomp(&host.goarch, host.kernel_4_8);
    }
    let group = shim_group(
        r.spec.labels.get(LABEL_APP).map_or("", String::as_str),
        &r.tini,
    );
    if !group.is_empty() {
        b.s.annotations
            .get_or_insert_with(Default::default)
            .insert(SHIM_GROUP_ANNOTATION.into(), group);
    }
    if !r.apparmor.is_empty() {
        b.process().apparmor_profile = r.apparmor.clone();
    }
    if s.memory_bytes > 0 {
        if let Some(res) = b.resources() {
            res.memory.get_or_insert_with(Default::default).limit = Some(s.memory_bytes);
        }
        if let Some(res) = b.resources() {
            res.memory.get_or_insert_with(Default::default).swap = Some(s.memory_bytes);
        }
    }
    if s.pids_limit > 0
        && let Some(res) = b.resources()
    {
        res.pids.get_or_insert_with(Default::default).limit = Some(s.pids_limit);
    }
    if s.nano_cpus > 0
        && let Some(res) = b.resources()
    {
        let cpu = res.cpu.get_or_insert_with(Default::default);
        cpu.quota = Some(s.nano_cpus.wrapping_mul(CPU_PERIOD) / 1_000_000_000);
        cpu.period = Some(CPU_PERIOD as u64);
    }
    if s.cpu_reserve_millis > 0
        && let Some(res) = b.resources()
    {
        res.cpu.get_or_insert_with(Default::default).shares =
            Some(cpu_shares(s.cpu_reserve_millis));
    }
    Ok(b.s)
}

/// The spec of a system container: the command's options with the command
/// alone, then a system container's.
pub fn system_spec(r: &SpecRequest, s: &SystemSpec, host: &Host) -> Result<Spec, String> {
    let mut b = Builder {
        s: default_spec(r.default_cgroups_path(), host.masked.clone()),
        rootfs_path: &r.rootfs,
        rootfs: None,
    };
    if !s.cmd.is_empty() {
        b.image_config(&r.image, Some(&s.cmd))?;
    } else {
        b.image_config(&r.image, None)?;
    }
    let mut mounts = Vec::new();
    for f in ["/etc/resolv.conf", "/etc/hosts"] {
        mounts.push(Mount::new(
            f,
            "bind",
            f,
            &["rbind", "ro", "nosuid", "nodev", "noexec"],
        ));
    }
    for m in &s.mounts {
        let mut o = vec!["rbind", "nosuid", "nodev", "noexec"];
        o.push(if m.read_only { "ro" } else { "rw" });
        mounts.push(Mount::new(&m.target, "bind", &m.source, &o));
    }
    b.host_namespace("network");
    b.namespace("cgroup", "");
    b.s.mounts.extend(mounts);
    b.set_caps(cap_names(&s.cap_add));
    b.process().no_new_privileges = true;
    b.s.root.get_or_insert_with(Default::default).readonly = true;
    b.linux().cgroups_path = r.cgroup.clone();
    b.rlimit(Rlimit {
        kind: "RLIMIT_NOFILE".into(),
        hard: NOFILE,
        soft: NOFILE,
    });
    b.selinux(&r.selinux.process, &r.selinux.mount);
    if !s.cmd.is_empty() {
        b.args(s.cmd.clone());
    }
    if !s.user.is_empty() {
        b.with_user(&s.user)?;
    }
    if r.seccomp {
        b.seccomp(&host.goarch, host.kernel_4_8);
    }
    Ok(b.s)
}

/// What the spec takes from the machine.
pub struct Host {
    pub masked: Vec<String>,
    pub goarch: String,
    pub kernel_4_8: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_as_containerd() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            replace_or_append_env(&s(&["A=1", "B=2", "A=3"]), &s(&["A=9", "B", "C=4"])),
            s(&["A=1", "A=9", "C=4"])
        );
    }

    #[test]
    fn shares_and_groups() {
        assert_eq!(cpu_shares(0), 2);
        assert_eq!(cpu_shares(1000), 1024);
        assert_eq!(cpu_shares(10_000_000), 262_144);
        assert_eq!(
            shim_group("web", "/var/lib/armada/runtime/abc/bin/tini"),
            "web@abc"
        );
        assert_eq!(shim_group("", "/x"), "");
    }

    #[test]
    fn hostnames() {
        assert_eq!(hostname("_web_1."), "web-1");
        assert_eq!(hostname(&"a".repeat(70)).len(), 63);
    }

    #[test]
    fn possible_cpus_ranges() {
        assert_eq!(parse_possible_cpus("0-3,8"), Some(vec![0, 1, 2, 3, 8]));
        assert_eq!(parse_possible_cpus("3-1"), None);
        assert_eq!(parse_possible_cpus(""), None);
    }
}

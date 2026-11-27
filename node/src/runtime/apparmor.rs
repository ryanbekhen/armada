//! Armada's AppArmor profile: containerd's default profile template
//! (contrib/apparmor's defaultTemplate and loadData) with Armada's
//! changes. Loading it stays with apparmor_parser.

/// What loadData reads of the machine.
pub struct Facts {
    /// /etc/apparmor.d/abi/3.0 exists.
    pub abi: bool,
    /// /etc/apparmor.d/tunables/global exists.
    pub tunables: bool,
    /// /etc/apparmor.d/abstractions/base exists.
    pub base: bool,
    /// /proc/self/attr/current, None when unreadable.
    pub current: Option<Vec<u8>>,
    /// exec.LookPath("rootlesskit"), "" when not found.
    pub rootlesskit: String,
}

impl Facts {
    /// The machine's, as loadData reads them.
    pub fn read() -> Facts {
        let exists = |m: &str| std::fs::metadata(format!("/etc/apparmor.d/{m}")).is_ok();
        Facts {
            abi: exists("abi/3.0"),
            tunables: exists("tunables/global"),
            base: exists("abstractions/base"),
            current: std::fs::read("/proc/self/attr/current").ok(),
            rootlesskit: look_path("rootlesskit"),
        }
    }
}

/// cleanProfileName: up to the first space, "unconfined" when empty. The
/// file's newline stays, as upstream keeps it.
fn clean_profile_name(p: &[u8]) -> String {
    let cut = match p.iter().position(|&c| c == b' ') {
        Some(i) => &p[..i],
        None => p,
    };
    if cut.is_empty() {
        "unconfined".into()
    } else {
        String::from_utf8_lossy(cut).into_owned()
    }
}

/// The text defaultTemplate renders for name (DumpDefaultProfile).
pub fn default_profile(name: &str, f: &Facts) -> String {
    let mut imports = Vec::new();
    if f.tunables {
        imports.push("#include <tunables/global>");
    } else {
        imports.push("@{PROC}=/proc/");
    }
    let mut inner = Vec::new();
    if f.base {
        inner.push("#include <abstractions/base>");
    }
    let daemon = clean_profile_name(f.current.as_deref().unwrap_or_default());
    let mut s = String::from("\n");
    if f.abi {
        s.push_str("abi <abi/3.0>,\n");
    }
    s.push('\n');
    for v in &imports {
        s.push('\n');
        s.push_str(v);
        s.push('\n');
    }
    s.push_str("\n\nprofile ");
    s.push_str(name);
    s.push_str(" flags=(attach_disconnected,mediate_deleted) {\n");
    for v in &inner {
        s.push_str("\n  ");
        s.push_str(v);
        s.push('\n');
    }
    s.push_str(
        "\n\n  network,\n  capability,\n  file,\n  umount,\n  # Host (privileged) processes may send signals to container processes.\n  signal (receive) peer=unconfined,\n  # runc may send signals to container processes.\n  signal (receive) peer=runc,\n  # crun may send signals to container processes.\n  signal (receive) peer=crun,\n  # Manager may send signals to container processes.\n  signal (receive) peer=",
    );
    s.push_str(&daemon);
    s.push_str(",\n  # Container processes may send signals amongst themselves.\n  signal (send,receive) peer=");
    s.push_str(name);
    s.push_str(",\n");
    if !f.rootlesskit.is_empty() {
        s.push_str(
            "\n  # https://github.com/containerd/nerdctl/issues/2730\n  signal (receive) peer=",
        );
        s.push_str(&f.rootlesskit);
        s.push_str(",\n");
    }
    s.push_str(
        "\n\n  deny @{PROC}/* w,   # deny write for all files directly in /proc (not in a subdir)\n  # deny write to files not in /proc/<number>/** or /proc/sys/**\n  deny @{PROC}/{[^1-9/],[^1-9/][^0-9/],[^1-9s/][^0-9y/][^0-9s/],[^1-9/][^0-9/][^0-9/][^0-9/]*}/** w,\n  deny @{PROC}/sys/[^k]** w,  # deny /proc/sys except /proc/sys/k* (effectively /proc/sys/kernel)\n  deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,  # deny everything except shm* in /proc/sys/kernel/\n  deny @{PROC}/sysrq-trigger rwklx,\n  deny @{PROC}/kcore rwklx,\n\n  deny mount,\n\n  deny /sys/[^f]*/** wklx,\n  deny /sys/f[^s]*/** wklx,\n  deny /sys/fs/[^c]*/** wklx,\n  deny /sys/fs/c[^g]*/** wklx,\n  deny /sys/fs/cg[^r]*/** wklx,\n  deny /sys/firmware/** rwklx,\n  deny /sys/devices/virtual/powercap/** rwklx,\n  deny /sys/kernel/security/** rwklx,\n\n  # allow processes within the container to trace each other,\n  # provided all other LSM and yama setting allow it.\n  ptrace (trace,tracedby,read,readby) peer=",
    );
    s.push_str(name);
    s.push_str(",\n}\n");
    s
}

/// appArmorProfile: the default profile with each signal and ptrace rule
/// for the container's own processes repeated for the label they carry on
/// kernels that stack a profile entered under no_new_privileges.
pub fn armada_profile(name: &str, f: &Facts) -> Result<String, String> {
    let text = default_profile(name, f);
    let stacked = format!("\"{name}//&unconfined\"");
    let own = format!(" peer={name},");
    let mut out = String::with_capacity(text.len() + 128);
    let mut added = 0;
    for line in text.split_inclusive('\n') {
        out.push_str(line);
        let trimmed = line.trim_matches(go_space);
        if (trimmed.starts_with("signal (send,receive) ") || trimmed.starts_with("ptrace ("))
            && trimmed.ends_with(&own)
        {
            let indent_len = line.len() - line.trim_start_matches([' ', '\t']).len();
            out.push_str(&line[..indent_len]);
            out.push_str(&trimmed[..trimmed.len() - (own.len() - 1)]);
            out.push_str("peer=");
            out.push_str(&stacked);
            out.push_str(",\n");
            added += 1;
        }
    }
    if added != 2 {
        return Err(format!(
            "apparmor profile {name}: expected a signal and a ptrace rule for its own processes, found {added}"
        ));
    }
    Ok(out)
}

/// unicode.IsSpace, which strings.TrimSpace trims.
fn go_space(c: char) -> bool {
    c.is_whitespace()
}

/// The path of a program named without a slash: the first executable file
/// in $PATH, "" when none or when the directory is not absolute.
fn look_path(file: &str) -> String {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let path = path.to_string_lossy();
    for dir in path.split(':') {
        let dir = if dir.is_empty() { "." } else { dir };
        let p = super::gopath::join(dir, file);
        if executable(&p) {
            return if p.starts_with('/') { p } else { String::new() };
        }
    }
    String::new()
}

/// findExecutable: not a directory, and eaccess(X_OK), or any execute bit
/// where eaccess is not available.
fn executable(p: &str) -> bool {
    let Ok(m) = std::fs::metadata(p) else {
        return false;
    };
    if m.is_dir() {
        return false;
    }
    let Ok(c) = std::ffi::CString::new(p) else {
        return false;
    };
    // SAFETY: a valid C string.
    let r = unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::X_OK, libc::AT_EACCESS) };
    if r == 0 {
        return true;
    }
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if e != libc::ENOSYS && e != libc::EPERM {
        return false;
    }
    use std::os::unix::fs::PermissionsExt;
    m.permissions().mode() & 0o111 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        Facts {
            abi: true,
            tunables: true,
            base: true,
            current: Some(b"unconfined\n".to_vec()),
            rootlesskit: String::new(),
        }
    }

    #[test]
    fn adds_the_stacked_peers() {
        let p = armada_profile("armada-default", &facts()).unwrap();
        assert!(p.contains("  signal (send,receive) peer=\"armada-default//&unconfined\",\n"));
        assert!(p.contains(
            "  ptrace (trace,tracedby,read,readby) peer=\"armada-default//&unconfined\",\n"
        ));
        assert!(p.starts_with("\nabi <abi/3.0>,\n\n\n#include <tunables/global>\n"));
    }

    #[test]
    fn daemon_profile_names() {
        assert_eq!(clean_profile_name(b""), "unconfined");
        assert_eq!(clean_profile_name(b"x (enforce)\n"), "x");
    }
}

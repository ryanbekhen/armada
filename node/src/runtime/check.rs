//! The container spec check: what every driver refuses before running an
//! app container, with its error texts.

use super::gopath::clean;
use super::user::errno_text;
use super::{ContainerSpec, FileMount, VolumeMount};
use crate::names::{DEFAULT_SPACE, INTERNAL_SUFFIX, valid_name};
use crate::net::addr::{Addr, Prefix, quote};

/// spec.MaxVolumes.
const MAX_VOLUMES: usize = 8;
/// spec.MaxInitContainers and spec.MaxSidecars.
const MAX_INIT: usize = 4;
const MAX_SIDECARS: usize = 4;
/// spec.MainContainer.
const MAIN_CONTAINER: &str = "app";
/// spec.maxPathLen.
const MAX_PATH_LEN: usize = 256;

pub fn check_container_spec(s: &ContainerSpec) -> Result<(), String> {
    for f in &s.files {
        check_file_mount(f)?;
    }
    if s.volumes.len() > MAX_VOLUMES {
        return Err(format!("at most {MAX_VOLUMES} volumes"));
    }
    let mut targets: Vec<&str> = s.files.iter().map(|f| f.target.as_str()).collect();
    for v in &s.volumes {
        check_volume_mount(v)?;
        if targets.contains(&v.target.as_str()) {
            return Err(format!("volume target {} is used twice", v.target));
        }
        targets.push(&v.target);
    }
    for d in &s.dns {
        check_private_ip(d).map_err(|e| format!("DNS server: {e}"))?;
    }
    if s.dns_search.len() > 1 {
        return Err("at most one DNS search domain".into());
    }
    for d in &s.dns_search {
        if !valid_search_domain(d) {
            return Err(format!(
                "DNS search domain {}: not an internal zone",
                quote(d)
            ));
        }
    }
    if s.port != 0 {
        if s.port < 1 || s.port > 65535 {
            return Err(format!("invalid port {}", s.port));
        }
        check_private_ip(&s.host_ip).map_err(|e| format!("publish address: {e}"))?;
    }
    check_members(s)
}

fn check_members(s: &ContainerSpec) -> Result<(), String> {
    if s.init.len() > MAX_INIT || s.sidecars.len() > MAX_SIDECARS {
        return Err(format!(
            "at most {MAX_INIT} init containers and {MAX_SIDECARS} sidecars"
        ));
    }
    let mut names = vec![MAIN_CONTAINER.to_string()];
    for m in s.init.iter().chain(&s.sidecars) {
        if !valid_member_name(&m.name) || names.contains(&m.name) {
            return Err(format!(
                "invalid or repeated container name {}",
                quote(&m.name)
            ));
        }
        names.push(m.name.clone());
        if m.image.is_empty() {
            return Err(format!("container {}: no image", m.name));
        }
        for f in &m.files {
            if !s.files.contains(f) {
                return Err(format!(
                    "container {}: file {} is not one of the replica's",
                    m.name, f.target
                ));
            }
        }
        for v in &m.volumes {
            if !s.volumes.contains(v) {
                return Err(format!(
                    "container {}: volume {} is not one of the replica's",
                    m.name, v.target
                ));
            }
        }
    }
    Ok(())
}

/// runtime.ValidMemberName.
pub fn valid_member_name(name: &str) -> bool {
    valid_name(name) && name.len() <= 30 && name != MAIN_CONTAINER
}

fn abs_clean(p: &str) -> bool {
    p.starts_with('/') && clean(p) == p && p != "/"
}

/// lstat's file type bits (S_IFMT), or the error's text ("lstat PATH: ERRNO TEXT").
fn lstat(p: &str) -> Result<u32, String> {
    let c = std::ffi::CString::new(p)
        .map_err(|_| format!("lstat {p}: {}", errno_text(libc::EINVAL)))?;
    // SAFETY: a valid C string and a zeroed stat lstat fills.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(c.as_ptr(), &mut st) } != 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        return Err(format!("lstat {p}: {}", errno_text(e)));
    }
    Ok(st.st_mode & libc::S_IFMT)
}

/// runtime.CheckFileMount.
pub fn check_file_mount(f: &FileMount) -> Result<(), String> {
    for p in [&f.source, &f.target] {
        if !abs_clean(p) {
            return Err(format!(
                "file mount {}: path must be absolute and clean",
                quote(p)
            ));
        }
    }
    let mode = lstat(&f.source).map_err(|e| format!("file mount: {e}"))?;
    if mode != libc::S_IFREG {
        return Err(format!("file mount {}: not a regular file", f.source));
    }
    Ok(())
}

/// runtime.CheckVolumeMount.
pub fn check_volume_mount(v: &VolumeMount) -> Result<(), String> {
    if !abs_clean(&v.source) || v.source.contains([':', ',', '\n']) {
        return Err(format!(
            "volume source {}: path must be absolute and clean",
            quote(&v.source)
        ));
    }
    if let Some(msg) = check_secret_file_path(&v.target) {
        return Err(format!("volume target {}: {msg}", quote(&v.target)));
    }
    let mode = lstat(&v.source).map_err(|e| format!("volume: {e}"))?;
    if mode != libc::S_IFDIR {
        return Err(format!("volume {}: not a directory", v.source));
    }
    Ok(())
}

/// spec.checkSecretFilePath (spec.ValidateVolumePath's message).
fn check_secret_file_path(p: &str) -> Option<String> {
    if p.is_empty() {
        return Some("is required".into());
    }
    if p.len() > MAX_PATH_LEN {
        return Some(format!("must be at most {MAX_PATH_LEN} characters"));
    }
    // ^(/[A-Za-z0-9._-]+)+$
    let ok_char = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-');
    let b = p.as_bytes();
    let shape = b[0] == b'/'
        && b.iter().all(|&c| c == b'/' || ok_char(c))
        && !p[1..].split('/').any(str::is_empty);
    if !shape {
        return Some("must be an absolute path of letters, digits, '.', '_', '-', and '/'".into());
    }
    if p[1..].split('/').any(|part| part == "." || part == "..") {
        return Some("must not contain . or .. components".into());
    }
    if ["/etc/hosts", "/etc/hostname", "/etc/resolv.conf"].contains(&p) {
        return Some(format!("{p} is managed by the container runtime"));
    }
    for d in ["/proc", "/sys", "/dev"] {
        if p == d || p.starts_with(&format!("{d}/")) {
            return Some(format!("must not be under {d}"));
        }
    }
    None
}

/// spec.ValidSearchDomain.
fn valid_search_domain(s: &str) -> bool {
    if s == &INTERNAL_SUFFIX[1..] {
        return true;
    }
    match s.strip_suffix(INTERNAL_SUFFIX) {
        Some(space) => space != DEFAULT_SPACE && space.len() <= 30 && valid_name(space),
        None => false,
    }
}

/// netutil.CheckPrivateIP's error.
fn check_private_ip(s: &str) -> Result<(), String> {
    let addr = match Addr::parse(s) {
        Some(a) if a.zone().is_empty() => a,
        _ => return Err(format!("invalid IP address {}", quote(s))),
    };
    let unmapped = addr.unmap();
    if unmapped.to_string() != s {
        return Err(format!(
            "IP address {} is not in canonical form (want {unmapped})",
            quote(s)
        ));
    }
    let cgnat = Prefix::parse("100.64.0.0/10").expect("a prefix");
    if !(unmapped.is_private() || unmapped.is_loopback() || cgnat.contains(&unmapped)) {
        return Err(format!(
            "{s}: address is not private; internal services must bind to a private (VPC) or loopback address"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_targets() {
        assert_eq!(check_secret_file_path("/data"), None);
        assert!(check_secret_file_path("/data/").is_some());
        assert!(check_secret_file_path("//a").is_some());
        assert_eq!(
            check_secret_file_path("/a/../b").as_deref(),
            Some("must not contain . or .. components")
        );
        assert_eq!(
            check_secret_file_path("/proc/x").as_deref(),
            Some("must not be under /proc")
        );
    }

    #[test]
    fn private_addresses() {
        assert!(check_private_ip("10.0.0.1").is_ok());
        assert!(check_private_ip("100.64.0.1").is_ok());
        assert!(check_private_ip("8.8.8.8").is_err());
        assert_eq!(
            check_private_ip("::ffff:10.0.0.1").unwrap_err(),
            "IP address \"::ffff:10.0.0.1\" is not in canonical form (want 10.0.0.1)"
        );
    }
}

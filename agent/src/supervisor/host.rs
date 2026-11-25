//! What the supervisor runtime needs root or the kernel for, behind one
//! narrow seam so the runtime's tests run without either: network
//! namespaces, the bridge, connection tracking, mounts, AppArmor, SELinux's
//! state, and free host ports. [`LinuxHost`] is the machine; the tests
//! give a stand-in.

use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use armada_node::net::netlink::{self, Msg, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, Socket};
use armada_node::net::rtnl::{self, Handle, IfAddr};
use armada_node::runtime::container::mount::{self, Mount};

use super::cni::{BRIDGE_NAME, Bridge, bridge_mac};

/// The machine as the supervisor runtime uses it. Every call blocks; the
/// runtime makes them off its async tasks.
pub trait Host: Send + Sync + 'static {
    /// A new network namespace bind-mounted on a new file in dir
    /// (containerd's netns.NewNetNS); its path.
    fn new_netns(&self, dir: &Path) -> Result<String, String>;
    /// Unmounts and removes a namespace; one that is gone is no error.
    fn remove_netns(&self, path: &str) -> Result<(), String>;
    /// The bridge with the gateway's address, its fixed hardware address,
    /// the MTU (0 leaves it), IPv6 off, and up.
    fn ensure_bridge(&self, b: &Bridge, mtu: u32) -> Result<(), String>;
    /// Deletes the connection tracking entries any of whose addresses is
    /// addr.
    fn forget_connections(&self, addr: Ipv4Addr) -> Result<(), String>;
    /// mount.All of a bundle's root filesystem.
    fn mount_all(&self, mounts: &[Mount], target: &Path) -> Result<(), String>;
    /// UnmountAll, with the errno of a failure.
    fn unmount_all(&self, target: &Path) -> Result<(), (String, i32)>;
    /// Runs f with the root filesystem mounts give, read-only, mounted
    /// somewhere for the moment (containerd's WithReadonlyTempMount): the
    /// spec reads the image's users and groups from it.
    fn with_rootfs(
        &self,
        mounts: &[Mount],
        f: &mut dyn FnMut(&str) -> Result<Vec<u8>, String>,
    ) -> Result<Vec<u8>, String>;
    /// Whether AppArmor confines containers here (aa.HostSupports).
    fn apparmor_supported(&self) -> bool;
    /// Loads (or replaces) a profile with apparmor_parser.
    fn load_apparmor(&self, name: &str, text: &str) -> Result<(), String>;
    /// selinux.GetEnabled.
    fn selinux_enabled(&self) -> bool;
    /// Whether nothing on the host listens on ip:port.
    fn port_free(&self, ip: &str, port: u16) -> bool;
    /// The host's resolver configuration for containers.
    fn resolv_conf(&self) -> Vec<u8>;
}

/// The machine.
pub struct LinuxHost;

fn errno_text(e: &std::io::Error) -> String {
    super::errno(e)
}

fn random(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    let mut got = 0;
    while got < n {
        // SAFETY: the buffer is valid for its remaining length.
        let r = unsafe { libc::getrandom(b[got..].as_mut_ptr().cast(), n - got, 0) };
        if r > 0 {
            got += r as usize;
        }
    }
    b
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

/// containerd's netns name: cni- and 16 random bytes in five groups.
pub fn netns_name(b: &[u8]) -> String {
    format!(
        "cni-{}-{}-{}-{}-{}",
        hex(&b[0..4]),
        hex(&b[4..6]),
        hex(&b[6..8]),
        hex(&b[8..10]),
        hex(&b[10..16])
    )
}

fn sys_mount(src: &str, target: &str, flags: libc::c_ulong) -> std::io::Result<()> {
    let s = CString::new(src)?;
    let t = CString::new(target)?;
    let none = CString::new("none")?;
    // SAFETY: valid C strings; no data.
    let r = unsafe {
        libc::mount(
            s.as_ptr(),
            t.as_ptr(),
            none.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// readonlyMounts: an overlay keeps its upper directory as a lower one;
/// anything else gets "ro".
pub fn readonly_mounts(mounts: &[Mount]) -> Vec<Mount> {
    mounts
        .iter()
        .map(|m| {
            let mut m = m.clone();
            if m.kind == "overlay" {
                let mut upper = String::new();
                let mut out: Vec<String> = Vec::new();
                for o in &m.options {
                    if let Some(u) = o.strip_prefix("upperdir=") {
                        upper = u.to_string();
                    } else if !o.starts_with("workdir=") {
                        out.push(o.clone());
                    }
                }
                if !upper.is_empty() {
                    for o in &mut out {
                        if let Some(l) = o.strip_prefix("lowerdir=") {
                            *o = format!("lowerdir={upper}:{l}");
                        }
                    }
                }
                m.options = out;
            } else {
                m.options.retain(|o| o != "rw" && o != "ro");
                m.options.push("ro".into());
            }
            m
        })
        .collect()
}

impl Host for LinuxHost {
    fn new_netns(&self, dir: &Path) -> Result<String, String> {
        fs::create_dir_all(dir).map_err(|e| super::os_err("mkdir", dir, &e))?;
        let path = dir.join(netns_name(&random(16)));
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o666)
            .open(&path)
            .map_err(|e| super::os_err("open", &path, &e))?;
        let p = path.display().to_string();
        let target = p.clone();
        let made = std::thread::spawn(move || -> Result<(), String> {
            // The thread enters a namespace of its own and ends with it,
            // which the bind mount keeps.
            // SAFETY: plain system calls on this thread alone.
            if unsafe { libc::unshare(libc::CLONE_NEWNET) } < 0 {
                return Err(errno_text(&std::io::Error::last_os_error()));
            }
            // SAFETY: plain system calls.
            let (pid, tid) = unsafe { (libc::getpid(), libc::gettid()) };
            let src = format!("/proc/{pid}/task/{tid}/ns/net");
            sys_mount(&src, &target, libc::MS_BIND)
                .map_err(|e| format!("failed to bind mount ns at {target}: {}", errno_text(&e)))
        })
        .join()
        .map_err(|_| "the namespace thread panicked".to_string())
        .and_then(|r| r);
        if let Err(e) = made {
            let _ = fs::remove_file(&path);
            return Err(format!("failed to setup netns: {e}"));
        }
        Ok(p)
    }

    fn remove_netns(&self, path: &str) -> Result<(), String> {
        match fs::metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("failed to stat netns: {}", errno_text(&e))),
            Ok(_) => {}
        }
        let c = CString::new(path).map_err(|e| e.to_string())?;
        // SAFETY: a valid C string.
        if unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) } < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::ENOENT) && e.raw_os_error() != Some(libc::EINVAL) {
                return Err(format!(
                    "failed to unmount NS: at {path}: {}",
                    errno_text(&e)
                ));
            }
        }
        fs::remove_file(path).map_err(|e| format!("failed to remove ns: {}", errno_text(&e)))
    }

    fn ensure_bridge(&self, b: &Bridge, mtu: u32) -> Result<(), String> {
        let mut h = Handle::open().map_err(|e| format!("bridge {BRIDGE_NAME}: {e}"))?;
        let mut link = h
            .link_named(BRIDGE_NAME)
            .map_err(|e| format!("bridge {BRIDGE_NAME}: {e}"))?;
        if link.is_none() {
            match h.exec(&rtnl::add_bridge(BRIDGE_NAME)) {
                Ok(()) | Err(netlink::Errno(libc::EEXIST)) => {}
                Err(e) => return Err(format!("create bridge {BRIDGE_NAME}: {e}")),
            }
            link = h
                .link_named(BRIDGE_NAME)
                .map_err(|e| format!("bridge {BRIDGE_NAME}: {e}"))?;
        }
        let link = link.ok_or_else(|| format!("bridge {BRIDGE_NAME}: Link not found"))?;
        if link.kind != "bridge" {
            return Err(format!("{BRIDGE_NAME} exists and is not a bridge"));
        }
        let want = format!("{}/{}", b.gateway, b.subnet.bits);
        let mut have = false;
        for a in h
            .addrs(link.index, libc::AF_INET as u8)
            .map_err(|e| e.to_string())?
        {
            let ip =
                a.ip.get(..4)
                    .map(|o| Ipv4Addr::new(o[0], o[1], o[2], o[3]))
                    .unwrap_or(Ipv4Addr::UNSPECIFIED);
            let got = format!("{ip}/{}", a.prefixlen);
            if got == want {
                have = true;
                continue;
            }
            return Err(format!(
                "bridge {BRIDGE_NAME} has address {got}, want {want}; remove it with `ip link delete {BRIDGE_NAME}`"
            ));
        }
        if !have {
            let a = IfAddr {
                index: link.index,
                family: libc::AF_INET as u8,
                ip: b.gateway.octets().to_vec(),
                prefixlen: b.subnet.bits,
                ..IfAddr::default()
            };
            match h.exec(&rtnl::addr(false, link.index, &a)) {
                Ok(()) | Err(netlink::Errno(libc::EEXIST)) => {}
                Err(e) => return Err(format!("address bridge {BRIDGE_NAME}: {e}")),
            }
        }
        let mac = bridge_mac(b.gateway);
        let assigned = fs::read_to_string(format!("/sys/class/net/{BRIDGE_NAME}/addr_assign_type"))
            .unwrap_or_default();
        if link.mac != mac || assigned.trim() != "3" {
            h.exec(&rtnl::set_mac(link.index, &mac))
                .map_err(|e| format!("set address of bridge {BRIDGE_NAME}: {e}"))?;
        }
        if mtu > 0 && link.mtu != mtu {
            h.exec(&rtnl::set_mtu(link.index, mtu))
                .map_err(|e| format!("set MTU of bridge {BRIDGE_NAME}: {e}"))?;
        }
        // Before the link is up, so it never gets a link-local address.
        disable_ipv6(Path::new("/proc/sys/net/ipv6/conf"), BRIDGE_NAME)?;
        h.exec(&rtnl::set_up(link.index)).map_err(|e| e.to_string())
    }

    fn forget_connections(&self, addr: Ipv4Addr) -> Result<(), String> {
        forget_connections(addr)
    }

    fn mount_all(&self, mounts: &[Mount], target: &Path) -> Result<(), String> {
        mount::mount_all(mounts, target)
    }

    fn unmount_all(&self, target: &Path) -> Result<(), (String, i32)> {
        mount::unmount_all(target)
    }

    fn with_rootfs(
        &self,
        mounts: &[Mount],
        f: &mut dyn FnMut(&str) -> Result<Vec<u8>, String>,
    ) -> Result<Vec<u8>, String> {
        let root = std::env::temp_dir().join(format!(
            "containerd-mount{}",
            u32::from_ne_bytes(random(4).try_into().unwrap_or([0; 4]))
        ));
        fs::create_dir(&root).map_err(|e| super::os_err("mkdir", &root, &e))?;
        let res = mount::mount_all(&readonly_mounts(mounts), &root)
            .map_err(|e| format!("mount callback failed on {}: {e}", root.display()))
            .and_then(|()| {
                let out = f(&root.display().to_string());
                let _ = mount::unmount_all(&root);
                out
            });
        let _ = fs::remove_dir(&root);
        res
    }

    fn apparmor_supported(&self) -> bool {
        Path::new("/sys/kernel/security/apparmor").exists()
            && std::env::var_os("container").is_none_or(|v| v.is_empty())
            && Path::new("/sbin/apparmor_parser").exists()
            && fs::read("/sys/module/apparmor/parameters/enabled")
                .is_ok_and(|b| b.len() > 1 && b[0] == b'Y')
    }

    fn load_apparmor(&self, name: &str, text: &str) -> Result<(), String> {
        let path = std::env::temp_dir().join(format!("armada-apparmor-{}", hex(&random(6))));
        let res = (|| {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| super::os_err("open", &path, &e))?;
            f.write_all(text.as_bytes())
                .map_err(|e| super::os_err("write", &path, &e))?;
            drop(f);
            let out = std::process::Command::new("apparmor_parser")
                .arg("-Kr")
                .arg(&path)
                .output()
                .map_err(|e| format!("load apparmor profile {name}: {}", errno_text(&e)))?;
            if !out.status.success() {
                let mut both = out.stdout.clone();
                both.extend(&out.stderr);
                return Err(format!(
                    "load apparmor profile {name}: {}: {}",
                    super::exit_text(&out.status),
                    String::from_utf8_lossy(&both).trim()
                ));
            }
            Ok(())
        })();
        let _ = fs::remove_file(&path);
        res
    }

    fn selinux_enabled(&self) -> bool {
        armada_node::nfs::selinux_enabled()
    }

    fn port_free(&self, ip: &str, port: u16) -> bool {
        std::net::TcpListener::bind(format!("{}:{port}", bracket(ip))).is_ok()
    }

    fn resolv_conf(&self) -> Vec<u8> {
        super::files::host_resolv_conf(
            Path::new("/etc/resolv.conf"),
            Path::new("/run/systemd/resolve/resolv.conf"),
        )
    }
}

fn bracket(ip: &str) -> String {
    if ip.contains(':') {
        format!("[{ip}]")
    } else {
        ip.to_string()
    }
}

/// DisableIPv6: IPv6 off on link; a kernel without IPv6 has nothing to
/// turn off.
pub fn disable_ipv6(conf: &Path, link: &str) -> Result<(), String> {
    let p: PathBuf = conf.join(link).join("disable_ipv6");
    if !p.exists() {
        return Ok(());
    }
    fs::write(&p, b"1\n").map_err(|e| {
        format!(
            "turn IPv6 off on {link}: open {}: {}",
            p.display(),
            errno_text(&e)
        )
    })
}

const NETLINK_NETFILTER: i32 = 12;
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_GET: u16 = 1;
const IPCTNL_MSG_CT_DELETE: u16 = 2;
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_TUPLE_IP: u16 = 1;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;

/// The nfgenmsg of an IPv4 request.
fn nfgen() -> Vec<u8> {
    vec![libc::AF_INET as u8, 0, 0, 0]
}

/// A tuple's source and destination.
fn tuple(b: &[u8]) -> (Option<[u8; 4]>, Option<[u8; 4]>) {
    let mut out = (None, None);
    for (t, d) in netlink::attrs(b) {
        if t != CTA_TUPLE_IP {
            continue;
        }
        for (k, v) in netlink::attrs(d) {
            let a = v.get(..4).map(|x| [x[0], x[1], x[2], x[3]]);
            match k {
                CTA_IP_V4_SRC => out.0 = a,
                CTA_IP_V4_DST => out.1 = a,
                _ => {}
            }
        }
    }
    out
}

/// Whether a dumped flow (its attributes after the nfgenmsg) has addr as
/// its original source or destination, or either reply address: the
/// filters forgetConnections gives ConntrackDeleteFilters.
pub fn flow_matches(attrs: &[u8], addr: Ipv4Addr) -> bool {
    let want = Some(addr.octets());
    for (t, d) in netlink::attrs(attrs) {
        let (s, dst) = tuple(d);
        match t {
            CTA_TUPLE_ORIG if s == want || dst == want => return true,
            CTA_TUPLE_REPLY if s == want || dst == want => return true,
            _ => {}
        }
    }
    false
}

/// forgetConnections: the IPv4 table dumped, each matching flow deleted by
/// sending its attributes back, as vishvananda's ConntrackDeleteFilters
/// does.
pub fn forget_connections(addr: Ipv4Addr) -> Result<(), String> {
    let mut dump = Socket::open(NETLINK_NETFILTER).map_err(|e| e.to_string())?;
    let flows = dump
        .request(&Msg {
            ty: (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET,
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            body: nfgen(),
        })
        .map_err(|e| e.to_string())?;
    let mut del = Socket::open(NETLINK_NETFILTER).map_err(|e| e.to_string())?;
    let mut errs = Vec::new();
    for (_, data) in flows {
        let Some(attrs) = data.get(4..) else { continue };
        if !flow_matches(attrs, addr) {
            continue;
        }
        let mut body = nfgen();
        body.extend(attrs);
        match del.request(&Msg {
            ty: (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE,
            flags: NLM_F_REQUEST | NLM_F_ACK,
            body,
        }) {
            Ok(_) | Err(netlink::Errno(libc::ENOENT)) => {}
            Err(e) => errs.push(format!("error deleting conntrack flow: {e}")),
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_readonly_mounts() {
        assert_eq!(
            netns_name(&(0u8..16).collect::<Vec<_>>()),
            "cni-00010203-0405-0607-0809-0a0b0c0d0e0f"
        );
        let m = |kind: &str, opts: &[&str]| Mount {
            kind: kind.into(),
            source: "s".into(),
            target: String::new(),
            options: opts.iter().map(|s| s.to_string()).collect(),
        };
        assert_eq!(
            readonly_mounts(&[
                m(
                    "overlay",
                    &["workdir=/w", "upperdir=/u", "lowerdir=/a:/b", "index=off"]
                ),
                m("bind", &["rw", "rbind"])
            ]),
            vec![
                m("overlay", &["lowerdir=/u:/a:/b", "index=off"]),
                m("bind", &["rbind", "ro"])
            ]
        );
    }

    #[test]
    fn flows_matched_by_any_address() {
        // CTA_TUPLE_ORIG { CTA_TUPLE_IP { src 10.0.0.1, dst 10.121.0.5 } }
        let mut ip = netlink::Attrs::new();
        ip.put(CTA_IP_V4_SRC, &[10, 0, 0, 1])
            .put(CTA_IP_V4_DST, &[10, 121, 0, 5]);
        let mut t = netlink::Attrs::new();
        t.nested(CTA_TUPLE_IP, |x| x.b.extend(ip.b.clone()));
        let mut f = netlink::Attrs::new();
        f.nested(CTA_TUPLE_ORIG, |x| x.b.extend(t.b.clone()));
        assert!(flow_matches(&f.b, Ipv4Addr::new(10, 121, 0, 5)));
        assert!(flow_matches(&f.b, Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!flow_matches(&f.b, Ipv4Addr::new(10, 121, 0, 6)));
    }

    #[test]
    fn ipv6_off() {
        let dir = std::env::temp_dir().join(format!("armada-ipv6-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("armada0")).unwrap();
        disable_ipv6(&dir, "nope").unwrap();
        fs::write(dir.join("armada0/disable_ipv6"), "0\n").unwrap();
        disable_ipv6(&dir, "armada0").unwrap();
        assert_eq!(
            fs::read_to_string(dir.join("armada0/disable_ipv6")).unwrap(),
            "1\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}

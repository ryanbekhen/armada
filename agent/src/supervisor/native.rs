//! Dials and queue readings from containers' and sandboxes' network
//! namespaces, and the sandboxes themselves (ADR 0034, ADR 0040).
//! armada-node's
//! `runtime dial` and `queue redis|rabbitmq` run as processes: they enter
//! the namespace on their only thread, which this process never does
//! (its threads run every task). A dial's socket comes back over
//! SCM_RIGHTS on descriptor 3.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::runtime::{Error, Result};
use crate::side::nodeprog;

/// The network plugins' container ID of a sandbox.
pub const SANDBOX_PREFIX: &str = "sandbox-";

fn other(e: impl Into<String>) -> Error {
    Error::Other(e.into())
}

/// Where a dial or reading happens: a container's task, or a pinned
/// namespace.
pub enum Target<'a> {
    Container {
        dir: &'a Path,
        shim_dir: &'a Path,
        id: &'a str,
        proc: &'a Path,
    },
    Netns(&'a Path),
}

impl Target<'_> {
    fn fill(&self, req: &mut serde_json::Map<String, Value>) {
        match self {
            Target::Container {
                dir,
                shim_dir,
                id,
                proc,
            } => {
                req.insert("dir".into(), json!(dir.display().to_string()));
                req.insert("shimDir".into(), json!(shim_dir.display().to_string()));
                req.insert("id".into(), json!(id));
                req.insert("proc".into(), json!(proc.display().to_string()));
            }
            Target::Netns(p) => {
                req.insert("netns".into(), json!(p.display().to_string()));
            }
        }
    }

    fn ns_text(&self) -> &'static str {
        match self {
            Target::Container { .. } => "container network namespace",
            Target::Netns(_) => "sandbox namespace",
        }
    }
}

/// Only an IP address and port over TCP or UDP.
pub fn check_dial(network: &str, address: &str) -> std::result::Result<(), String> {
    let (host, _) = split_host_port(address)?;
    if armada_node::net::addr::Addr::parse(host).is_none() {
        return Err(format!(
            "dial from a namespace: {} is not an IP address",
            armada_pki::go_quote(host)
        ));
    }
    match network {
        "tcp" | "tcp4" | "tcp6" | "udp" | "udp4" | "udp6" => Ok(()),
        _ => Err(format!(
            "dial from a namespace: network {}",
            armada_pki::go_quote(network)
        )),
    }
}

/// Splits `host:port` or `[host]:port`, with texts such as "address HP:
/// missing port in address".
fn split_host_port(hp: &str) -> std::result::Result<(&str, &str), String> {
    let err = |why: &str| format!("address {hp}: {why}");
    let i = hp
        .rfind(':')
        .ok_or_else(|| err("missing port in address"))?;
    let (host, port) = (&hp[..i], &hp[i + 1..]);
    let host = if let Some(h) = host.strip_prefix('[') {
        h.strip_suffix(']')
            .ok_or_else(|| err("missing ']' in address"))?
    } else {
        if host.contains(':') {
            return Err(err("too many colons in address"));
        }
        host
    };
    Ok((host, port))
}

/// The dial's request; None for what armada-node does not dial: a zone, a
/// service name, or a family the network refuses.
fn dial_plan(network: &str, address: &str) -> Option<serde_json::Map<String, Value>> {
    let (host, port) = split_host_port(address).ok()?;
    let port: u16 = port.parse().ok()?;
    let a = armada_node::net::addr::Addr::parse(host)?;
    if !a.zone().is_empty() {
        return None;
    }
    let kind = match network {
        "tcp" | "tcp4" | "tcp6" => "tcp",
        "udp" | "udp4" | "udp6" => "udp",
        _ => return None,
    };
    let is4 = a.unmap().to_string().parse::<std::net::Ipv4Addr>().is_ok();
    let (family, v6only) = match network.as_bytes()[network.len() - 1] {
        b'4' if !is4 => return None,
        b'4' => (4, false),
        b'6' if is4 => return None,
        b'6' => (6, true),
        _ => (if is4 { 4 } else { 6 }, false),
    };
    let ip = if family == 4 {
        a.unmap().to_string()
    } else {
        a.to_string()
    };
    let mut m = serde_json::Map::new();
    m.insert("kind".into(), json!(kind));
    m.insert("ip".into(), json!(ip));
    m.insert("family".into(), json!(family));
    m.insert("port".into(), json!(port));
    m.insert("v6only".into(), json!(v6only));
    Some(m)
}

#[derive(Deserialize, Default)]
struct DialAnswer {
    #[serde(default)]
    connected: bool,
    #[serde(rename = "notFound", default)]
    not_found: bool,
    #[serde(default)]
    redo: Option<String>,
    #[serde(default)]
    netns: Option<i32>,
    #[serde(default)]
    setns: Option<i32>,
    #[serde(default)]
    op: String,
    #[serde(default)]
    errno: i32,
    #[serde(default)]
    timeout: bool,
}

/// A connected socket from armada-node's runtime dial, with errors such as
/// "dial NETWORK ADDRESS: TEXT" for a failed connect, NotFound for a
/// container with no task, the namespace's errno otherwise.
pub async fn dial(
    node: &Path,
    target: Target<'_>,
    network: &str,
    address: &str,
) -> Result<OwnedFd> {
    check_dial(network, address).map_err(other)?;
    let Some(mut req) = dial_plan(network, address) else {
        return Err(other(format!(
            "dial {network} {address}: this node dials no such address from a namespace"
        )));
    };
    target.fill(&mut req);
    let (mine, theirs) = std::os::unix::net::UnixStream::pair()
        .map_err(|e| other(format!("socketpair: {}", super::errno(&e))))?;
    let out = nodeprog::run_files(
        &node.display().to_string(),
        &["runtime", "dial"],
        &Value::Object(req),
        None,
        vec![OwnedFd::from(theirs)],
    )
    .await
    .map_err(other)?;
    let a: DialAnswer = serde_json::from_slice(&out)
        .map_err(|e| other(format!("armada-node: unreadable answer: {e}")))?;
    let op_err = |why: String| other(format!("dial {network} {address}: {why}"));
    if a.connected {
        return receive_fd(&mine).map_err(other);
    }
    if let Some(r) = a.redo {
        return Err(other(format!("dial {network} {address}: {r}")));
    }
    if a.not_found {
        return Err(Error::NotFound);
    }
    if let Some(n) = a.netns {
        return Err(other(format!(
            "{}: {}",
            target.ns_text(),
            armada_node::runtime::container::errno_text(n)
        )));
    }
    if let Some(n) = a.setns {
        return Err(other(armada_node::runtime::container::errno_text(n)));
    }
    if !a.op.is_empty() {
        return Err(op_err(format!(
            "{}: {}",
            a.op,
            armada_node::runtime::container::errno_text(a.errno)
        )));
    }
    if a.timeout {
        return Err(op_err("i/o timeout".into()));
    }
    Err(other(format!(
        "armada-node: unreadable answer: {}",
        String::from_utf8_lossy(&out)
    )))
}

/// The one descriptor sent over c.
fn receive_fd(c: &std::os::unix::net::UnixStream) -> std::result::Result<OwnedFd, String> {
    let mut buf = [0u8; 1];
    // Room for one descriptor's control message.
    let mut cmsg = [0u64; 4];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: an all-zero msghdr is valid; its pointers are set below to
    // buffers that outlive the call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&cmsg) as _;
    // SAFETY: recvmsg on a descriptor this process owns, into msg.
    let n = unsafe {
        libc::recvmsg(
            c.as_raw_fd(),
            &mut msg,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if n < 0 {
        return Err(format!(
            "receive the connection: {}",
            super::errno(&std::io::Error::last_os_error())
        ));
    }
    // SAFETY: walking the control messages recvmsg filled in.
    unsafe {
        let h = libc::CMSG_FIRSTHDR(&msg);
        if h.is_null()
            || (*h).cmsg_level != libc::SOL_SOCKET
            || (*h).cmsg_type != libc::SCM_RIGHTS
            || (*h).cmsg_len as usize != libc::CMSG_LEN(4) as usize
        {
            return Err("receive the connection: no descriptor".into());
        }
        let fd = std::ptr::read_unaligned(libc::CMSG_DATA(h).cast::<i32>());
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

#[derive(Deserialize, Default)]
struct QueueAnswer {
    #[serde(default)]
    length: Option<i64>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    redo: Option<String>,
}

/// A queue's length through armada-node's queue readers: the readings'
/// fixed texts on failure. A reading armada-node does not take (a broker
/// named by a name with no addresses, a zone) cannot reach the broker
/// here.
pub async fn read_queue(
    node: &Path,
    target: Target<'_>,
    q: &crate::side::QueueRead,
    timeout: Duration,
) -> Result<i64> {
    if q.kind != "redis" && q.kind != "rabbitmq" {
        return Err(other(crate::side::queue::ERR_DIAL));
    }
    let mut req = serde_json::Map::new();
    req.insert("url".into(), json!(q.url));
    req.insert("name".into(), json!(q.name));
    if !q.addresses.is_empty() {
        req.insert(
            "addresses".into(),
            json!(
                q.addresses
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
            ),
        );
    }
    req.insert("timeoutMs".into(), json!(timeout.as_millis() as u64));
    target.fill(&mut req);
    // The request holds the URL: never logged or repeated.
    let out = nodeprog::run(
        &node.display().to_string(),
        &["queue", &q.kind],
        &Value::Object(req),
        Some(timeout),
    )
    .await
    .map_err(|e| other(format!("queue {}: {e}", q.kind)))?;
    let a: QueueAnswer = serde_json::from_slice(&out)
        .map_err(|_| other(format!("queue {}: armada-node: unreadable answer", q.kind)))?;
    match (a.length, a.error, a.redo) {
        (Some(n), ..) => Ok(n),
        (_, Some(e), _) => Err(other(e)),
        (_, _, Some(_)) => Err(other(crate::side::queue::ERR_DIAL)),
        _ => Err(other(format!(
            "queue {}: armada-node: unreadable answer",
            q.kind
        ))),
    }
}

/// A sandbox's pinned namespace: <run dir>/sandboxes/<id>.
pub fn sandbox_path(run_dir: &Path, id: &str) -> PathBuf {
    run_dir.join("sandboxes").join(id)
}

/// An error unless id may name a sandbox.
pub fn check_sandbox_id(id: &str) -> Result<()> {
    if crate::side::sandbox::check_sandbox_id(id) {
        Ok(())
    } else {
        Err(other(format!(
            "invalid sandbox ID {}",
            armada_pki::go_quote(id)
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_and_checks() {
        let p = dial_plan("tcp", "10.0.0.1:6379").unwrap();
        assert_eq!(
            Value::Object(p),
            json!({"kind":"tcp","ip":"10.0.0.1","family":4,"port":6379,"v6only":false})
        );
        let p = dial_plan("udp6", "[fd00::1]:53").unwrap();
        assert_eq!(p["family"], 6);
        assert_eq!(p["v6only"], true);
        assert!(dial_plan("tcp4", "[fd00::1]:53").is_none());
        assert!(dial_plan("tcp6", "10.0.0.1:53").is_none());
        assert!(dial_plan("tcp", "[fe80::1%eth0]:53").is_none());
        assert_eq!(
            dial_plan("tcp", "[::ffff:10.0.0.1]:5").unwrap()["ip"],
            "10.0.0.1"
        );
        assert_eq!(
            check_dial("tcp", "redis:6379").unwrap_err(),
            "dial from a namespace: \"redis\" is not an IP address"
        );
        assert_eq!(
            check_dial("unix", "10.0.0.1:1").unwrap_err(),
            "dial from a namespace: network \"unix\""
        );
        assert_eq!(
            check_dial("tcp", "10.0.0.1").unwrap_err(),
            "address 10.0.0.1: missing port in address"
        );
    }
}

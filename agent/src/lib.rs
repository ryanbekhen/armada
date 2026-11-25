//! The node agent's loop in Rust (ADR 0055, item 16, first part): a port
//! of Go's `internal/agent` that the Rust `armadad agent` links. It
//! receives the node's assignment over the Connect stream and reconciles
//! the node's containers through a [`runtime::Runtime`]: starts at most
//! eight at a time with each image pulled once, reports while it starts,
//! probes (HTTP, TCP, and commands), crash backoff, liveness, lost
//! networks, job attempts, held replicas, fencing, init containers and
//! sidecars, secret files on tmpfs, strays, image pruning, and usage
//! samples. Its parity tests (`internal/agent/parity_test.go`) drive it
//! and Go's agent through the same scenarios against one fake runtime.
//!
//! The second part (16b) adds the proxy and network passes over seams of
//! their own ([`proxy::Proxy`], [`network::Network`],
//! [`proxy::InternalDns`], [`proxy::CertificateSource`]), the wake socket,
//! key rotation, the runtime move, and the usage reports' load, switch,
//! and peers. The third part (16c, [`side`]) adds exec, log, and volume
//! sessions, queue readings and sandboxes, NFS volumes, the log export
//! and the log history's prune, and the usage reports' volumes,
//! connection tracking, queues, sandboxes, and export. The fourth part
//! (16d) adds the seams' real drivers over armada-node's library: HAProxy
//! ([`haproxy::Driver`]), the cluster network
//! ([`clusternet::ClusterNet`]), and armada-dns
//! ([`dnsprocess::DnsProcess`]). The fifth part (16e) adds the supervisor
//! runtime ([`supervisor::Supervisor`]) behind the runtime trait and
//! HAProxy's system containers; SELinux labels, the conversion of Go's
//! image store, 16c's runtime calls, and the volume and connection
//! tracking seams moved in process come in its second pull request.

pub mod agent;
pub mod boot;
pub mod check;
pub mod clock;
pub mod clusternet;
mod containers;
pub mod creds;
pub mod dnsprocess;
pub mod fence;
mod files;
pub mod haproxy;
pub mod hold;
mod job;
pub mod log;
pub mod network;
mod probe;
pub mod proxy;
pub mod runtime;
pub mod runtimemove;
pub mod session;
pub mod side;
pub mod spec;
pub mod supervisor;
pub mod usage;
pub mod wake;

pub use agent::{Agent, Config};
pub use files::NO_SECRETS_DIR;

/// This agent's version (Hello.version, the probes' User-Agent).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

//! The node agent that `armadad agent` links. It receives the node's
//! assignment over the Connect stream and reconciles the node's containers
//! through a [`runtime::Runtime`]: starts at most eight at a time with each
//! image pulled once, reports while it starts, probes (HTTP, TCP, and
//! commands), crash backoff, liveness, lost networks, job attempts, held
//! replicas, fencing, init containers and sidecars, secret files on tmpfs,
//! strays, image pruning, and usage samples. The replays
//! (`tests/scenarios.rs`) drive it through recorded scenarios against a
//! fake runtime.
//!
//! The proxy and network passes run over seams of their own
//! ([`proxy::Proxy`], [`network::Network`], [`proxy::InternalDns`],
//! [`proxy::CertificateSource`]), with the wake socket, key rotation, the
//! runtime move, and the usage reports' load, switch, and peers. [`side`]
//! holds the exec, log, and volume sessions, queue readings and sandboxes,
//! NFS volumes, the log export and the log history's prune, and the usage
//! reports' volumes, connection tracking, queues, sandboxes, and export.
//! The seams' real drivers run over armada-node's library: HAProxy
//! ([`haproxy::Driver`]), the cluster network
//! ([`clusternet::ClusterNet`]), and armada-dns
//! ([`dnsprocess::DnsProcess`]). The supervisor runtime
//! ([`supervisor::Supervisor`]) runs containers behind the runtime trait,
//! HAProxy's system containers among them, with SELinux labels, the
//! sessions' runtime calls, and the volume and connection tracking seams in
//! process.

pub mod agent;
pub mod boot;
pub mod check;
pub mod clock;
pub mod clusternet;
mod containers;
pub mod creds;
pub mod crunmove;
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

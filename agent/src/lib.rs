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
//! and peers. Left for later parts: exec, log, and volume sessions, queue
//! readings and sandboxes, NFS, log export and prune (16c), and the
//! supervisor runtime and the seams' real implementations over
//! armada-node's library (16d).

pub mod agent;
pub mod boot;
pub mod check;
pub mod clock;
mod containers;
pub mod creds;
pub mod fence;
mod files;
pub mod hold;
mod job;
pub mod log;
pub mod network;
mod probe;
pub mod proxy;
pub mod runtime;
pub mod runtimemove;
pub mod session;
pub mod spec;
pub mod usage;
pub mod wake;

pub use agent::{Agent, Config};
pub use files::NO_SECRETS_DIR;

/// This agent's version (Hello.version, the probes' User-Agent).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

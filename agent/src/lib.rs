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
//! Left for the second part: the proxy and network passes, the wake
//! socket, exec, log, and volume sessions, queue readings and sandboxes,
//! NFS, proxy certificates by reference, log export, the runtime move,
//! and the supervisor runtime over armada-node's library.

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
mod probe;
pub mod runtime;
pub mod session;
pub mod spec;
pub mod usage;

pub use agent::{Agent, Config};
pub use files::NO_SECRETS_DIR;

/// This agent's version (Hello.version, the probes' User-Agent).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

//! armada-kv: Armada's own state store (ADR 0057), in place of etcd.
//!
//! A member serves the subset of etcd's v3 gRPC API armada-store uses,
//! with etcd's messages (armada-proto's servers), so the store's client,
//! its transactions, and its election and lock recipes work unchanged:
//!
//! - [`mvcc`]: the multi-version key space in one redb database (revisions,
//!   versions, leases, history until compaction), changed only by applying
//!   [`command::Command`]s, every commit durable before it is answered.
//! - [`node`]: a member: the writer applying proposals in batches, the
//!   lease clock, and the periodic compaction.
//! - [`service`]: the gRPC services, and serving them on a Unix socket.
//! - [`snapshot`]: the store's snapshot format.
//!
//! This is a single member: there is no replication yet. Commands are
//! deterministic and carry every decision made outside the state machine
//! (lease IDs, expiries), so a replicated log can carry them as they are.

pub mod command;
pub mod error;
pub mod mvcc;
pub mod node;
pub mod service;
pub mod snapshot;

pub use error::{Error, Result};
pub use node::{Node, Options};
pub use service::{Dispatch, serve_unix};

//! armada-kv: Armada's own state store (ADR 0057), in place of etcd.
//!
//! A member serves the subset of etcd's v3 gRPC API armada-store uses,
//! with etcd's messages (armada-proto's servers), so the store's client,
//! its transactions, and its election and lock recipes work unchanged:
//!
//! - [`mvcc`]: the multi-version key space in one redb database (revisions,
//!   versions, leases, history until compaction), changed only by applying
//!   [`command::Command`]s, every commit durable before it is answered.
//! - [`node`]: a member: Raft in front of the key space, forwarding to the
//!   leader, linearizable reads, the lease clock, and the periodic
//!   compaction.
//! - [`raft`], [`log`], [`sm`]: openraft's types and their encoding, the
//!   Raft log and vote, and the state machine, all in the member's one
//!   database.
//! - [`peer`]: what members say to each other (Raft's messages, forwarded
//!   requests, snapshots), and how they reach each other.
//! - [`service`]: etcd's gRPC services, and serving them on a Unix socket.
//! - [`tls`]: the client and peer listeners on the network (TLS 1.3, the
//!   cluster CA's `etcd:member` certificates on both sides), and the
//!   connector that reaches other members over the same mutual TLS.
//! - [`snapshot`]: the store's snapshot format.
//!
//! Commands are deterministic and carry every decision made outside the
//! state machine (lease IDs, expiries), so every member applies the same
//! log to the same key space.

pub mod command;
pub mod error;
pub mod log;
pub mod mvcc;
pub mod node;
pub mod peer;
pub mod raft;
pub mod service;
pub mod sm;
pub mod snapshot;
pub mod tls;

pub use error::{Error, Result};
pub use node::{Node, Options, Start, Timing};
pub use peer::{Connector, PeerDispatch, UnixConnector, serve_peer_unix};
pub use service::{Dispatch, serve_unix};
pub use tls::{TlsConnector, serve_api_tls, serve_peer_tls};

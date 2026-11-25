//! The cluster state in etcd (ADR 0009, ADR 0010, ADR 0055): a port of
//! Go's `internal/store` and of the client side of `internal/etcd`.
//!
//! The keys, the JSON records (field names, omitempty, time encodings),
//! the schema number, the commit key, the optimistic transactions, the
//! fencing on the election key, the range deletes, the event leases, and
//! the election and mutex recipes are Go's, so a Go server and a Rust
//! server share one keyspace and campaign in one election. Go's tests
//! drive this crate through the `armada-store-parity` program on one etcd
//! member and compare the keyspace and every answer
//! (internal/store/nativestore_test.go).

pub mod client;
pub mod election;
pub mod error;
pub mod gojson;
mod records;
mod tx;
pub mod types;

mod access;
mod apps;
mod events;
pub mod jobs;
mod metrics;
mod migrate;
pub mod network;
mod nodes;
#[cfg(feature = "parity")]
pub mod parity;
mod placements;
mod remove;
mod secrets;
mod spaces;
mod volumes;

pub use access::{
    KIND_SERVICE, KIND_USER, MAX_GRANTS, MAX_SERVICE_CERTS, ROLE_ADMIN, ROLE_CLUSTER_ADMIN,
    ROLE_DEPLOYER, ROLE_SPACE_CREATOR, ROLE_VIEWER, ROLES, check_grant, check_labels,
};
pub use client::Client;
pub use error::{Error, Kind, Result};
pub use events::EVENT_TTL_SECONDS;
pub use network::{Network, NetworkSwitch};
pub use tx::{Clock, Etcd, Random, SCHEMA};
pub use types::*;

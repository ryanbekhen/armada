//! The membership of the control plane's state store: etcd's, or
//! armada-kv's (ADR 0057), which serves the same API.

use std::net::IpAddr;

use tonic::codegen::async_trait;

/// One etcd member.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemberInfo {
    pub id: u64,
    pub name: String,
    pub learner: bool,
    pub client_url: String,
}

/// What [`Cluster::state`] says of a cluster whose servers keep the state
/// in armada-kv (ADR 0057); etcd's is "".
pub const STATE_KV: &str = "kv";

/// Manages the etcd membership of the control plane nodes. Errors are
/// their texts.
#[async_trait]
pub trait Cluster: Send + Sync {
    /// Where the servers keep the state: "" for etcd, [`STATE_KV`] for
    /// armada-kv. A joining server runs the same.
    fn state(&self) -> &'static str {
        ""
    }
    async fn members(&self) -> Result<Vec<MemberInfo>, String>;
    /// Adds a non-voting member and returns its ID and the initial cluster
    /// for its first start.
    async fn add_learner(
        &self,
        name: &str,
        addr: IpAddr,
        peer_port: u16,
    ) -> Result<(u64, String), String>;
    /// Turns caught-up learners into voting members.
    async fn promote(&self) -> Result<Vec<String>, String>;
    /// Whether a member answers.
    async fn reachable(&self, m: &MemberInfo) -> bool;
    async fn remove_member(&self, id: u64) -> Result<(), String>;
}

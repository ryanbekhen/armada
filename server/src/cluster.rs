//! The etcd membership of the control plane (Go's server.Cluster).

use std::net::IpAddr;

use tonic::codegen::async_trait;

/// One etcd member (Go's etcd.MemberInfo).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemberInfo {
    pub id: u64,
    pub name: String,
    pub learner: bool,
    pub client_url: String,
}

/// Manages the etcd membership of the control plane nodes. Errors are
/// their texts, as Go's handlers print them with %v.
#[async_trait]
pub trait Cluster: Send + Sync {
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

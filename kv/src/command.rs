//! The commands of the state machine: every change of the key space is one
//! command, applied in order, each at most one revision. They are protobuf
//! messages built from etcd's requests, so a replicated log (ADR 0057,
//! Raft) carries them as they are and every member applies the same bytes.
//!
//! What is not deterministic is decided before a command is made: a new
//! lease's ID, and which leases expired (the member that keeps the time
//! proposes `LeaseExpire`).

use armada_proto::etcd::etcdserverpb as pb;
use prost::Message;

/// One change of the key space.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Command {
    #[prost(oneof = "Op", tags = "1, 2, 3, 4, 5, 6, 7")]
    pub op: Option<Op>,
}

/// What a command does.
#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Op {
    /// KV.Put.
    #[prost(message, tag = "1")]
    Put(pb::PutRequest),
    /// KV.DeleteRange.
    #[prost(message, tag = "2")]
    DeleteRange(pb::DeleteRangeRequest),
    /// KV.Txn (its ranges are read where it is applied).
    #[prost(message, tag = "3")]
    Txn(pb::TxnRequest),
    /// Lease.LeaseGrant, with the ID already chosen.
    #[prost(message, tag = "4")]
    LeaseGrant(pb::LeaseGrantRequest),
    /// Lease.LeaseRevoke.
    #[prost(message, tag = "5")]
    LeaseRevoke(pb::LeaseRevokeRequest),
    /// A lease that was not kept alive: revoked when it still exists.
    #[prost(message, tag = "6")]
    LeaseExpire(pb::LeaseRevokeRequest),
    /// KV.Compact, or the periodic compaction.
    #[prost(message, tag = "7")]
    Compact(pb::CompactionRequest),
}

impl Command {
    pub fn new(op: Op) -> Command {
        Command { op: Some(op) }
    }

    /// The command as a log entry carries it.
    pub fn encode(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// A command from a log entry.
    pub fn decode_entry(b: &[u8]) -> Result<Command, prost::DecodeError> {
        Command::decode(b)
    }

    /// Whether the command can only make the database larger: refused
    /// while it is past its quota.
    pub fn grows(&self) -> bool {
        match &self.op {
            Some(Op::Put(_)) | Some(Op::LeaseGrant(_)) => true,
            Some(Op::Txn(t)) => t.success.iter().chain(&t.failure).any(|o| {
                matches!(
                    o.request,
                    Some(pb::request_op::Request::RequestPut(_))
                        | Some(pb::request_op::Request::RequestTxn(_))
                )
            }),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let c = Command::new(Op::Put(pb::PutRequest {
            key: b"a".to_vec(),
            value: b"1".to_vec(),
            lease: 7,
            ..Default::default()
        }));
        assert_eq!(Command::decode_entry(&c.encode()).unwrap(), c);
        assert!(c.grows());
        let d = Command::new(Op::Compact(pb::CompactionRequest {
            revision: 3,
            physical: false,
        }));
        assert_eq!(Command::decode_entry(&d.encode()).unwrap(), d);
        assert!(!d.grows());
    }
}

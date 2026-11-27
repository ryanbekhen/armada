//! Raft's types for armada-kv (ADR 0057) and their encoding: the log's
//! entries on disk, and the messages members send each other.
//!
//! openraft is built without serde: every type that is stored or sent is
//! turned into one of the protobuf messages below, so what is on disk and
//! on the wire is armada-kv's own and changes only on purpose.
//!
//! A member's Raft node ID is its etcd member ID. A member's node in the
//! Raft membership holds what the member list shows (name, peer and client
//! URLs), so a membership change carries it to every member.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use armada_proto::etcd::etcdserverpb as pb;
use openraft::vote::leader_id_std::{CommittedLeaderId, LeaderId};
use prost::Message;

use crate::command::Command;
use crate::error::{Error, Result};
use crate::mvcc::Applied;

/// A member as the Raft membership holds it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Peer {
    /// Empty until the member started and told the cluster.
    pub name: String,
    pub peer_urls: Vec<String>,
    /// Empty until the member started and told the cluster.
    pub client_urls: Vec<String>,
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.peer_urls.join(","))
    }
}

/// What applying an entry answers: a command's result, or nothing for the
/// entries Raft itself writes (blank and membership entries).
#[derive(Clone, Debug, PartialEq)]
pub struct Reply(pub Option<Result<Applied>>);

openraft::declare_raft_types!(
    /// armada-kv's Raft: one leader per term, commands as entries.
    pub Tc:
        D = Command,
        R = Reply,
        NodeId = u64,
        Node = Peer,
        Term = u64,
        LeaderId = LeaderId<u64, u64>,
);

pub type LogId = openraft::LogId<CommittedLeaderId<u64>>;
pub type Vote = openraft::Vote<LeaderId<u64, u64>>;
pub type Membership = openraft::Membership<u64, Peer>;
pub type StoredMembership = openraft::StoredMembership<CommittedLeaderId<u64>, Membership>;
pub type Entry =
    openraft::Entry<CommittedLeaderId<u64>, openraft::EntryPayload<Command, Membership>>;
pub type Payload = openraft::EntryPayload<Command, Membership>;
pub type SnapshotMeta = openraft::SnapshotMeta<CommittedLeaderId<u64>, Membership>;
pub type Snapshot = openraft::Snapshot<CommittedLeaderId<u64>, Membership, Vec<u8>>;
pub type Raft = openraft::Raft<Tc, crate::sm::StateMachine>;

pub fn log_id(term: u64, index: u64) -> LogId {
    openraft::LogId::new(CommittedLeaderId::new(term), index)
}

/// A log ID.
#[derive(Clone, Copy, PartialEq, Eq, prost::Message)]
pub struct WLogId {
    #[prost(uint64, tag = "1")]
    pub term: u64,
    #[prost(uint64, tag = "2")]
    pub index: u64,
}

impl From<&LogId> for WLogId {
    fn from(l: &LogId) -> WLogId {
        WLogId {
            term: l.leader_id.term,
            index: l.index,
        }
    }
}

impl From<WLogId> for LogId {
    fn from(w: WLogId) -> LogId {
        log_id(w.term, w.index)
    }
}

fn opt_log_id(l: &Option<LogId>) -> Option<WLogId> {
    l.as_ref().map(WLogId::from)
}

/// A vote.
#[derive(Clone, Copy, PartialEq, Eq, prost::Message)]
pub struct WVote {
    #[prost(uint64, tag = "1")]
    pub term: u64,
    #[prost(uint64, tag = "2")]
    pub node: u64,
    #[prost(bool, tag = "3")]
    pub committed: bool,
}

impl From<&Vote> for WVote {
    fn from(v: &Vote) -> WVote {
        WVote {
            term: v.leader_id.term,
            node: v.leader_id.voted_for,
            committed: v.committed,
        }
    }
}

impl From<WVote> for Vote {
    fn from(w: WVote) -> Vote {
        if w.committed {
            openraft::Vote::new_committed(w.term, w.node)
        } else {
            openraft::Vote::new(w.term, w.node)
        }
    }
}

/// A member of a membership.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WPeer {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, repeated, tag = "3")]
    pub peer_urls: Vec<String>,
    #[prost(string, repeated, tag = "4")]
    pub client_urls: Vec<String>,
}

/// One configuration of a (joint) membership: its voters.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WConfig {
    #[prost(uint64, repeated, tag = "1")]
    pub voters: Vec<u64>,
}

/// A membership: its configurations (two while joint) and every member,
/// voters and learners.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WMembership {
    #[prost(message, repeated, tag = "1")]
    pub configs: Vec<WConfig>,
    #[prost(message, repeated, tag = "2")]
    pub nodes: Vec<WPeer>,
}

impl From<&Membership> for WMembership {
    fn from(m: &Membership) -> WMembership {
        WMembership {
            configs: m
                .get_joint_config()
                .iter()
                .map(|c| WConfig {
                    voters: c.iter().copied().collect(),
                })
                .collect(),
            nodes: m
                .nodes()
                .map(|(id, p)| WPeer {
                    id: *id,
                    name: p.name.clone(),
                    peer_urls: p.peer_urls.clone(),
                    client_urls: p.client_urls.clone(),
                })
                .collect(),
        }
    }
}

impl TryFrom<WMembership> for Membership {
    type Error = Error;
    fn try_from(w: WMembership) -> Result<Membership> {
        let configs: Vec<BTreeSet<u64>> = w
            .configs
            .into_iter()
            .map(|c| c.voters.into_iter().collect())
            .collect();
        let nodes: BTreeMap<u64, Peer> = w
            .nodes
            .into_iter()
            .map(|p| {
                (
                    p.id,
                    Peer {
                        name: p.name,
                        peer_urls: p.peer_urls,
                        client_urls: p.client_urls,
                    },
                )
            })
            .collect();
        openraft::Membership::new(configs, nodes)
            .map_err(|e| Error::Storage(format!("a membership: {e}")))
    }
}

/// A membership with the log ID of the entry that holds it.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WStoredMembership {
    #[prost(message, optional, tag = "1")]
    pub log_id: Option<WLogId>,
    #[prost(message, optional, tag = "2")]
    pub membership: Option<WMembership>,
}

impl From<&StoredMembership> for WStoredMembership {
    fn from(m: &StoredMembership) -> WStoredMembership {
        WStoredMembership {
            log_id: opt_log_id(m.log_id()),
            membership: Some(m.membership().into()),
        }
    }
}

impl TryFrom<WStoredMembership> for StoredMembership {
    type Error = Error;
    fn try_from(w: WStoredMembership) -> Result<StoredMembership> {
        let m = match w.membership {
            Some(m) => m.try_into()?,
            None => Membership::default(),
        };
        Ok(openraft::StoredMembership::new(w.log_id.map(Into::into), m))
    }
}

/// A log entry: blank (a new leader's first), a command, or a membership.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WEntry {
    #[prost(message, optional, tag = "1")]
    pub log_id: Option<WLogId>,
    #[prost(message, optional, tag = "2")]
    pub command: Option<Command>,
    #[prost(message, optional, tag = "3")]
    pub membership: Option<WMembership>,
}

impl From<&Entry> for WEntry {
    fn from(e: &Entry) -> WEntry {
        let mut w = WEntry {
            log_id: Some((&e.log_id).into()),
            command: None,
            membership: None,
        };
        match &e.payload {
            Payload::Blank => {}
            Payload::Normal(c) => w.command = Some(c.clone()),
            Payload::Membership(m) => w.membership = Some(m.into()),
        }
        w
    }
}

impl TryFrom<WEntry> for Entry {
    type Error = Error;
    fn try_from(w: WEntry) -> Result<Entry> {
        let log_id = w
            .log_id
            .ok_or_else(|| Error::Storage("a log entry without its ID".into()))?
            .into();
        let payload = match (w.command, w.membership) {
            (None, None) => Payload::Blank,
            (Some(c), None) => Payload::Normal(c),
            (None, Some(m)) => Payload::Membership(m.try_into()?),
            (Some(_), Some(_)) => {
                return Err(Error::Storage(
                    "a log entry with a command and a membership".into(),
                ));
            }
        };
        Ok(openraft::Entry { log_id, payload })
    }
}

/// Encodes an entry as the log keeps it.
pub fn encode_entry(e: &Entry) -> Vec<u8> {
    WEntry::from(e).encode_to_vec()
}

/// An entry the log kept.
pub fn decode_entry(b: &[u8]) -> Result<Entry> {
    WEntry::decode(b)
        .map_err(|e| Error::Storage(format!("a log entry: {e}")))?
        .try_into()
}

pub fn encode<M: Message>(m: &M) -> Vec<u8> {
    m.encode_to_vec()
}

pub fn decode<M: Message + Default>(b: &[u8], what: &str) -> Result<M> {
    M::decode(b).map_err(|e| Error::Storage(format!("{what}: {e}")))
}

// The messages between members (crate::peer).

/// AppendEntries.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WAppend {
    #[prost(message, optional, tag = "1")]
    pub vote: Option<WVote>,
    #[prost(message, optional, tag = "2")]
    pub prev_log_id: Option<WLogId>,
    #[prost(message, repeated, tag = "3")]
    pub entries: Vec<WEntry>,
    #[prost(message, optional, tag = "4")]
    pub leader_commit: Option<WLogId>,
}

impl From<&openraft::raft::AppendEntriesRequest<Tc>> for WAppend {
    fn from(r: &openraft::raft::AppendEntriesRequest<Tc>) -> WAppend {
        WAppend {
            vote: Some((&r.vote).into()),
            prev_log_id: opt_log_id(&r.prev_log_id),
            entries: r.entries.iter().map(WEntry::from).collect(),
            leader_commit: opt_log_id(&r.leader_commit),
        }
    }
}

impl TryFrom<WAppend> for openraft::raft::AppendEntriesRequest<Tc> {
    type Error = Error;
    fn try_from(w: WAppend) -> Result<Self> {
        Ok(openraft::raft::AppendEntriesRequest {
            vote: w.vote.unwrap_or_default().into(),
            prev_log_id: w.prev_log_id.map(Into::into),
            entries: w
                .entries
                .into_iter()
                .map(Entry::try_from)
                .collect::<Result<_>>()?,
            leader_commit: w.leader_commit.map(Into::into),
        })
    }
}

/// AppendEntries' answer: the last log ID accepted, a conflict (with the
/// follower's hint), or a higher vote.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WAppendReply {
    #[prost(bool, tag = "1")]
    pub ok: bool,
    #[prost(message, optional, tag = "2")]
    pub accepted: Option<WLogId>,
    #[prost(message, optional, tag = "3")]
    pub conflict: Option<WLogId>,
    #[prost(bool, tag = "4")]
    pub has_hint: bool,
    #[prost(message, repeated, tag = "5")]
    pub hint: Vec<WLogId>,
    #[prost(message, optional, tag = "6")]
    pub higher_vote: Option<WVote>,
}

impl From<&openraft::raft::AppendResult<Tc>> for WAppendReply {
    fn from(r: &openraft::raft::AppendResult<Tc>) -> WAppendReply {
        use openraft::raft::AppendError;
        let mut w = WAppendReply::default();
        match r {
            Ok(a) => {
                w.ok = true;
                w.accepted = opt_log_id(a);
            }
            Err(AppendError::Conflict { log_id, hint }) => {
                w.conflict = Some(log_id.into());
                if let Some(h) = hint {
                    w.has_hint = true;
                    w.hint = h.log_ids.iter().map(WLogId::from).collect();
                }
            }
            Err(AppendError::HigherVote(v)) => w.higher_vote = Some(v.into()),
        }
        w
    }
}

impl TryFrom<WAppendReply> for openraft::raft::AppendResult<Tc> {
    type Error = Error;
    fn try_from(w: WAppendReply) -> Result<Self> {
        use openraft::raft::{AppendError, ConflictHint};
        if w.ok {
            return Ok(Ok(w.accepted.map(Into::into)));
        }
        if let Some(v) = w.higher_vote {
            return Ok(Err(AppendError::HigherVote(v.into())));
        }
        let Some(c) = w.conflict else {
            return Err(Error::Unavailable("an empty AppendEntries answer".into()));
        };
        Ok(Err(AppendError::Conflict {
            log_id: c.into(),
            hint: w
                .has_hint
                .then(|| ConflictHint::new(w.hint.into_iter().map(Into::into).collect())),
        }))
    }
}

/// RequestVote (and PreVote).
#[derive(Clone, PartialEq, prost::Message)]
pub struct WVoteRequest {
    #[prost(message, optional, tag = "1")]
    pub vote: Option<WVote>,
    #[prost(message, optional, tag = "2")]
    pub last_log_id: Option<WLogId>,
    #[prost(message, optional, tag = "3")]
    pub transfer_from: Option<WVote>,
}

impl From<&openraft::raft::VoteRequest<Tc>> for WVoteRequest {
    fn from(r: &openraft::raft::VoteRequest<Tc>) -> WVoteRequest {
        WVoteRequest {
            vote: Some((&r.vote).into()),
            last_log_id: opt_log_id(&r.last_log_id),
            transfer_from: r.leadership_transfer_from.as_ref().map(WVote::from),
        }
    }
}

impl From<WVoteRequest> for openraft::raft::VoteRequest<Tc> {
    fn from(w: WVoteRequest) -> Self {
        let mut r = openraft::raft::VoteRequest::new(
            w.vote.unwrap_or_default().into(),
            w.last_log_id.map(Into::into),
        );
        r.leadership_transfer_from = w.transfer_from.map(Into::into);
        r
    }
}

/// RequestVote's answer.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WVoteReply {
    #[prost(message, optional, tag = "1")]
    pub vote: Option<WVote>,
    #[prost(bool, tag = "2")]
    pub granted: bool,
    #[prost(message, optional, tag = "3")]
    pub last_log_id: Option<WLogId>,
}

impl From<&openraft::raft::VoteResponse<Tc>> for WVoteReply {
    fn from(r: &openraft::raft::VoteResponse<Tc>) -> WVoteReply {
        WVoteReply {
            vote: Some((&r.vote).into()),
            granted: r.vote_granted,
            last_log_id: opt_log_id(&r.last_log_id),
        }
    }
}

impl From<WVoteReply> for openraft::raft::VoteResponse<Tc> {
    fn from(w: WVoteReply) -> Self {
        let vote: Vote = w.vote.unwrap_or_default().into();
        openraft::raft::VoteResponse::new(vote, w.last_log_id.map(Into::into), w.granted)
    }
}

/// A snapshot's metadata.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WSnapshotMeta {
    #[prost(message, optional, tag = "1")]
    pub last_log_id: Option<WLogId>,
    #[prost(message, optional, tag = "2")]
    pub membership: Option<WStoredMembership>,
}

impl From<&SnapshotMeta> for WSnapshotMeta {
    fn from(m: &SnapshotMeta) -> WSnapshotMeta {
        WSnapshotMeta {
            last_log_id: opt_log_id(&m.last_log_id),
            membership: Some((&m.last_membership).into()),
        }
    }
}

impl TryFrom<WSnapshotMeta> for SnapshotMeta {
    type Error = Error;
    fn try_from(w: WSnapshotMeta) -> Result<SnapshotMeta> {
        Ok(openraft::SnapshotMeta {
            last_log_id: w.last_log_id.map(Into::into),
            last_membership: w.membership.unwrap_or_default().try_into()?,
        })
    }
}

/// An error as members send it (crate::error::Error::to_wire).
#[derive(Clone, PartialEq, prost::Message)]
pub struct WError {
    #[prost(uint32, tag = "1")]
    pub code: u32,
    #[prost(string, tag = "2")]
    pub text: String,
}

impl From<&Error> for WError {
    fn from(e: &Error) -> WError {
        let (code, text) = e.to_wire();
        WError { code, text }
    }
}

impl From<WError> for Error {
    fn from(w: WError) -> Error {
        Error::from_wire(w.code, w.text)
    }
}

/// A command's answer as the leader sends it to the member that forwarded
/// the command.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WApplied {
    #[prost(int64, tag = "1")]
    pub revision: i64,
    #[prost(oneof = "WResponse", tags = "2, 3, 4, 5, 6, 7")]
    pub response: Option<WResponse>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum WResponse {
    #[prost(message, tag = "2")]
    Put(pb::PutResponse),
    #[prost(message, tag = "3")]
    DeleteRange(pb::DeleteRangeResponse),
    #[prost(message, tag = "4")]
    Txn(pb::TxnResponse),
    #[prost(message, tag = "5")]
    LeaseGrant(pb::LeaseGrantResponse),
    #[prost(message, tag = "6")]
    LeaseRevoke(pb::LeaseRevokeResponse),
    #[prost(message, tag = "7")]
    Compact(pb::CompactionResponse),
}

impl From<&Applied> for WApplied {
    fn from(a: &Applied) -> WApplied {
        use crate::mvcc::Response as R;
        WApplied {
            revision: a.revision,
            response: Some(match &a.response {
                R::Put(r) => WResponse::Put(r.clone()),
                R::DeleteRange(r) => WResponse::DeleteRange(r.clone()),
                R::Txn(r) => WResponse::Txn(r.clone()),
                R::LeaseGrant(r) => WResponse::LeaseGrant(r.clone()),
                R::LeaseRevoke(r) => WResponse::LeaseRevoke(*r),
                R::Compact(r) => WResponse::Compact(*r),
            }),
        }
    }
}

impl TryFrom<WApplied> for Applied {
    type Error = Error;
    fn try_from(w: WApplied) -> Result<Applied> {
        use crate::mvcc::Response as R;
        let response = match w.response {
            Some(WResponse::Put(r)) => R::Put(r),
            Some(WResponse::DeleteRange(r)) => R::DeleteRange(r),
            Some(WResponse::Txn(r)) => R::Txn(r),
            Some(WResponse::LeaseGrant(r)) => R::LeaseGrant(r),
            Some(WResponse::LeaseRevoke(r)) => R::LeaseRevoke(r),
            Some(WResponse::Compact(r)) => R::Compact(r),
            None => return Err(Error::Unavailable("an empty answer".into())),
        };
        // What the lease clock follows comes from each member's own apply.
        Ok(Applied {
            revision: w.revision,
            response,
            granted: None,
            revoked: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::Op;

    fn membership() -> Membership {
        let nodes: BTreeMap<u64, Peer> = [
            (
                1,
                Peer {
                    name: "a".into(),
                    peer_urls: vec!["unix://a".into()],
                    client_urls: vec!["unix://ca".into()],
                },
            ),
            (2, Peer::default()),
            (3, Peer::default()),
        ]
        .into_iter()
        .collect();
        openraft::Membership::new(vec![[1, 2].into(), [1].into()], nodes).unwrap()
    }

    #[test]
    fn entries_round_trip() {
        for payload in [
            Payload::Blank,
            Payload::Normal(Command::new(Op::Put(pb::PutRequest {
                key: b"k".to_vec(),
                value: b"v".to_vec(),
                ..Default::default()
            }))),
            Payload::Membership(membership()),
        ] {
            let e = openraft::Entry {
                log_id: log_id(3, 9),
                payload,
            };
            assert_eq!(decode_entry(&encode_entry(&e)).unwrap(), e);
        }
        assert!(decode_entry(b"\xff").is_err());
    }

    #[test]
    fn messages_round_trip() {
        let v: Vote = openraft::Vote::new_committed(4, 2);
        assert_eq!(Vote::from(WVote::from(&v)), v);
        let v: Vote = openraft::Vote::new(5, 3);
        assert_eq!(Vote::from(WVote::from(&v)), v);
        let sm = openraft::StoredMembership::new(Some(log_id(2, 7)), membership());
        let back: StoredMembership = WStoredMembership::from(&sm).try_into().unwrap();
        assert_eq!(back, sm);
        let conflict: openraft::raft::AppendResult<Tc> =
            Err(openraft::raft::AppendError::Conflict {
                log_id: log_id(1, 4),
                hint: Some(openraft::raft::ConflictHint::new(vec![log_id(1, 2)])),
            });
        let back: openraft::raft::AppendResult<Tc> =
            WAppendReply::from(&conflict).try_into().unwrap();
        assert_eq!(back, conflict);
        let ok: openraft::raft::AppendResult<Tc> = Ok(None);
        let back: openraft::raft::AppendResult<Tc> = WAppendReply::from(&ok).try_into().unwrap();
        assert_eq!(back, ok);
    }
}

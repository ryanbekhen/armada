//! The store's errors, each answered with the gRPC code and the text etcd
//! gives for it (etcd's `rpctypes`), since armada-store shows and matches
//! etcd's texts.

use std::fmt;

/// An error of the key space or of its storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A request without a key.
    EmptyKey,
    /// A put that keeps the value or the lease of a key that does not
    /// exist.
    KeyNotFound,
    /// A put that keeps the value but gives one.
    ValueProvided,
    /// A put that keeps the lease but gives one.
    LeaseProvided,
    /// A transaction with more operations than the store takes.
    TooManyOps,
    /// A transaction that changes one key twice.
    DuplicateKey,
    /// A read or watch below the compacted revision.
    Compacted,
    /// A read at a revision the store has not reached.
    FutureRev,
    /// The database is past its quota.
    NoSpace,
    /// A lease that does not exist.
    LeaseNotFound,
    /// A lease ID that is taken.
    LeaseExists,
    /// A lease longer than the store grants.
    LeaseTtlTooLarge,
    /// A request larger than the store takes.
    RequestTooLarge,
    /// A request outside the subset of etcd's API the store serves.
    Unimplemented(String),
    /// The member is closing.
    Stopped,
    /// No leader is known (an election is under way, or the member is cut
    /// off from a majority).
    NoLeader,
    /// The leader changed before a proposal was committed: it may or may
    /// not have been applied.
    LeaderChanged,
    /// A proposal or a read was not answered in time.
    Timeout,
    /// The leader could not be reached; a forwarded proposal may or may
    /// not have been applied.
    Unavailable(String),
    /// A peer answered that it is not the leader (between members only).
    NotLeader,
    /// A member that is not in the cluster.
    MemberNotFound,
    /// A member added or updated with a peer URL another member has.
    PeerUrlExists,
    /// A promotion of a voting member.
    NotLearner,
    /// A promotion of a learner whose log is behind the leader's.
    LearnerNotReady,
    /// The database failed.
    Storage(String),
    /// A snapshot that is not one of the store's own.
    Snapshot(String),
}

impl Error {
    /// The answer to a gRPC call.
    pub fn status(&self) -> tonic::Status {
        use tonic::Code;
        let code = match self {
            Error::EmptyKey
            | Error::KeyNotFound
            | Error::ValueProvided
            | Error::LeaseProvided
            | Error::TooManyOps
            | Error::DuplicateKey
            | Error::RequestTooLarge
            | Error::Snapshot(_) => Code::InvalidArgument,
            Error::Compacted | Error::FutureRev | Error::LeaseTtlTooLarge => Code::OutOfRange,
            Error::NoSpace => Code::ResourceExhausted,
            Error::LeaseNotFound => Code::NotFound,
            Error::LeaseExists => Code::FailedPrecondition,
            Error::Unimplemented(_) => Code::Unimplemented,
            Error::Stopped
            | Error::NoLeader
            | Error::LeaderChanged
            | Error::Timeout
            | Error::Unavailable(_)
            | Error::NotLeader => Code::Unavailable,
            Error::MemberNotFound => Code::NotFound,
            Error::PeerUrlExists | Error::NotLearner | Error::LearnerNotReady => {
                Code::FailedPrecondition
            }
            Error::Storage(_) => Code::Internal,
        };
        tonic::Status::new(code, self.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Error::EmptyKey => "etcdserver: key is not provided",
            Error::KeyNotFound => "etcdserver: key not found",
            Error::ValueProvided => "etcdserver: value is provided",
            Error::LeaseProvided => "etcdserver: lease is provided",
            Error::TooManyOps => "etcdserver: too many operations in txn request",
            Error::DuplicateKey => "etcdserver: duplicate key given in txn request",
            Error::Compacted => "etcdserver: mvcc: required revision has been compacted",
            Error::FutureRev => "etcdserver: mvcc: required revision is a future revision",
            Error::NoSpace => "etcdserver: mvcc: database space exceeded",
            Error::LeaseNotFound => "etcdserver: requested lease not found",
            Error::LeaseExists => "etcdserver: lease already exists",
            Error::LeaseTtlTooLarge => "etcdserver: too large lease TTL",
            Error::RequestTooLarge => "etcdserver: request is too large",
            Error::Stopped => "etcdserver: server stopped",
            Error::NoLeader => "etcdserver: no leader",
            Error::LeaderChanged => "etcdserver: leader changed",
            Error::Timeout => "etcdserver: request timed out",
            Error::NotLeader => "armada-kv: not the leader",
            Error::MemberNotFound => "etcdserver: member not found",
            Error::PeerUrlExists => "etcdserver: Peer URLs already exists",
            Error::NotLearner => "etcdserver: can only promote a learner member",
            Error::LearnerNotReady => {
                "etcdserver: can only promote a learner member which is in sync with leader"
            }
            Error::Unavailable(e) => return write!(f, "armada-kv: {e}"),
            Error::Unimplemented(what) => return write!(f, "armada-kv: {what} is not served"),
            Error::Storage(e) => return write!(f, "armada-kv: storage: {e}"),
            Error::Snapshot(e) => return write!(f, "armada-kv: snapshot: {e}"),
        };
        f.write_str(s)
    }
}

impl std::error::Error for Error {}

impl Error {
    /// The error as members send it to each other: a number and, for the
    /// errors that carry one, a text.
    pub(crate) fn to_wire(&self) -> (u32, String) {
        let (n, t) = match self {
            Error::EmptyKey => (1, ""),
            Error::KeyNotFound => (2, ""),
            Error::ValueProvided => (3, ""),
            Error::LeaseProvided => (4, ""),
            Error::TooManyOps => (5, ""),
            Error::DuplicateKey => (6, ""),
            Error::Compacted => (7, ""),
            Error::FutureRev => (8, ""),
            Error::NoSpace => (9, ""),
            Error::LeaseNotFound => (10, ""),
            Error::LeaseExists => (11, ""),
            Error::LeaseTtlTooLarge => (12, ""),
            Error::RequestTooLarge => (13, ""),
            Error::Unimplemented(t) => (14, t.as_str()),
            Error::Stopped => (15, ""),
            Error::Storage(t) => (16, t.as_str()),
            Error::Snapshot(t) => (17, t.as_str()),
            Error::NoLeader => (18, ""),
            Error::LeaderChanged => (19, ""),
            Error::Timeout => (20, ""),
            Error::Unavailable(t) => (21, t.as_str()),
            Error::NotLeader => (22, ""),
            Error::MemberNotFound => (23, ""),
            Error::PeerUrlExists => (24, ""),
            Error::NotLearner => (25, ""),
            Error::LearnerNotReady => (26, ""),
        };
        (n, t.to_string())
    }

    /// An error a member sent.
    pub(crate) fn from_wire(n: u32, t: String) -> Error {
        match n {
            1 => Error::EmptyKey,
            2 => Error::KeyNotFound,
            3 => Error::ValueProvided,
            4 => Error::LeaseProvided,
            5 => Error::TooManyOps,
            6 => Error::DuplicateKey,
            7 => Error::Compacted,
            8 => Error::FutureRev,
            9 => Error::NoSpace,
            10 => Error::LeaseNotFound,
            11 => Error::LeaseExists,
            12 => Error::LeaseTtlTooLarge,
            13 => Error::RequestTooLarge,
            14 => Error::Unimplemented(t),
            15 => Error::Stopped,
            16 => Error::Storage(t),
            17 => Error::Snapshot(t),
            18 => Error::NoLeader,
            19 => Error::LeaderChanged,
            20 => Error::Timeout,
            21 => Error::Unavailable(t),
            22 => Error::NotLeader,
            23 => Error::MemberNotFound,
            24 => Error::PeerUrlExists,
            25 => Error::NotLearner,
            26 => Error::LearnerNotReady,
            n => Error::Unavailable(format!("a peer answered error {n}: {t}")),
        }
    }
}

/// A storage error of redb's.
pub(crate) fn storage(e: impl fmt::Display) -> Error {
    Error::Storage(e.to_string())
}

/// The store's results.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_are_etcds() {
        let s = Error::Compacted.status();
        assert_eq!(s.code(), tonic::Code::OutOfRange);
        assert_eq!(
            s.message(),
            "etcdserver: mvcc: required revision has been compacted"
        );
        assert_eq!(Error::LeaseNotFound.status().code(), tonic::Code::NotFound);
        for e in [
            Error::Compacted,
            Error::Unimplemented("x".into()),
            Error::Unavailable("y".into()),
            Error::LearnerNotReady,
        ] {
            let (n, t) = e.to_wire();
            assert_eq!(Error::from_wire(n, t), e);
        }

        assert_eq!(
            Error::Unimplemented("KV.RangeStream".into())
                .status()
                .code(),
            tonic::Code::Unimplemented
        );
    }
}

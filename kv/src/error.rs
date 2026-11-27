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
            Error::Stopped => Code::Unavailable,
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
            Error::Unimplemented(what) => return write!(f, "armada-kv: {what} is not served"),
            Error::Storage(e) => return write!(f, "armada-kv: storage: {e}"),
            Error::Snapshot(e) => return write!(f, "armada-kv: snapshot: {e}"),
        };
        f.write_str(s)
    }
}

impl std::error::Error for Error {}

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
        assert_eq!(
            Error::Unimplemented("KV.RangeStream".into())
                .status()
                .code(),
            tonic::Code::Unimplemented
        );
    }
}

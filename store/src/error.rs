//! The store's errors: Go's sentinel errors (ErrNotFound, ErrConflict,
//! ErrPrecondition, ErrNotLeader) as kinds, each error carrying the whole
//! text Go's wrapped error prints.

use std::fmt;

/// What an error is, as errors.Is tells Go's sentinels apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// store.ErrNotFound: a record does not exist (or, for scoped updates,
    /// does not belong to the caller).
    NotFound,
    /// store.ErrConflict: a change collides with another.
    Conflict,
    /// store.ErrPrecondition: the operation needs some other state first.
    Precondition,
    /// store.ErrNotLeader: a fenced store's term is over.
    NotLeader,
    /// Anything else: etcd, decoding, invalid arguments.
    Other,
}

impl Kind {
    /// The sentinel's own text.
    pub fn text(self) -> &'static str {
        match self {
            Kind::NotFound => "not found",
            Kind::Conflict => "conflict",
            Kind::Precondition => "failed precondition",
            Kind::NotLeader => "this server is no longer the leader",
            Kind::Other => "",
        }
    }

    /// The name the parity program answers with.
    pub fn name(self) -> &'static str {
        match self {
            Kind::NotFound => "notFound",
            Kind::Conflict => "conflict",
            Kind::Precondition => "precondition",
            Kind::NotLeader => "notLeader",
            Kind::Other => "other",
        }
    }
}

/// An error of the store: its kind and the text Go's error prints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: Kind,
    pub msg: String,
}

impl Error {
    /// An error of no sentinel kind.
    pub fn other(msg: impl Into<String>) -> Error {
        Error {
            kind: Kind::Other,
            msg: msg.into(),
        }
    }

    /// fmt.Errorf("<msg>: %w", sentinel).
    pub fn wrap(kind: Kind, msg: impl fmt::Display) -> Error {
        Error {
            kind,
            msg: format!("{msg}: {}", kind.text()),
        }
    }

    /// The sentinel itself (ErrNotLeader is returned unwrapped).
    pub fn bare(kind: Kind) -> Error {
        Error {
            kind,
            msg: kind.text().to_string(),
        }
    }

    /// fmt.Errorf("<prefix>: %w", err): the kind is kept.
    pub fn context(self, prefix: impl fmt::Display) -> Error {
        Error {
            kind: self.kind,
            msg: format!("{prefix}: {}", self.msg),
        }
    }

    pub fn is(&self, kind: Kind) -> bool {
        self.kind == kind
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Error {}

impl From<tonic::Status> for Error {
    fn from(s: tonic::Status) -> Error {
        Error::other(etcd_text(&s))
    }
}

/// The text of an etcd error as clientv3 shows it: etcd's own message for
/// its errors (rpctypes), gRPC's form for the others.
pub(crate) fn etcd_text(s: &tonic::Status) -> String {
    let m = s.message();
    if m.starts_with("etcdserver: ") || m.starts_with("mvcc: ") {
        return m.to_string();
    }
    format!("rpc error: code = {:?} desc = {m}", s.code())
}

/// notFoundf: fmt.Errorf(format+": %w", ErrNotFound).
macro_rules! not_found {
    ($($arg:tt)*) => {
        $crate::error::Error::wrap($crate::error::Kind::NotFound, format!($($arg)*))
    };
}

/// fmt.Errorf(format+": %w", ErrConflict).
macro_rules! conflict {
    ($($arg:tt)*) => {
        $crate::error::Error::wrap($crate::error::Kind::Conflict, format!($($arg)*))
    };
}

/// fmt.Errorf(format+": %w", ErrPrecondition).
macro_rules! precondition {
    ($($arg:tt)*) => {
        $crate::error::Error::wrap($crate::error::Kind::Precondition, format!($($arg)*))
    };
}

/// fmt.Errorf(format) or errors.New.
macro_rules! other {
    ($($arg:tt)*) => {
        $crate::error::Error::other(format!($($arg)*))
    };
}

pub(crate) use {conflict, not_found, other, precondition};

/// The store's results.
pub type Result<T> = std::result::Result<T, Error>;

//! The parts of armada-node other crates of the workspace reuse (ADR
//! 0055): the control plane (armada-server) reads volume backup URLs with
//! the same ParseTarget the node uses, so their checks and texts agree.
//! The control plane's ACME client and DNS provider send their requests
//! through the same guarded HTTPS client image pulls use (`http`), and
//! back the control plane up to a bucket with the repository volume
//! backups use (`volbackup`). The program (main.rs) compiles these files
//! as its own modules too.

pub mod gostr;

pub mod net {
    pub mod addr;
}

pub mod queue {
    // Go's url.Parse fails with no detail: the callers word the error.
    #[allow(clippy::result_unit_err)]
    pub mod url;
}

// The repository of volume backups (ADR 0041), which the control plane
// also backs itself up to (ADR 0051), with what it walks, reads, and
// restores through.
#[allow(dead_code)]
#[path = "volbackup/mod.rs"]
pub mod volbackup;

#[allow(dead_code)]
pub mod hooks;

#[allow(dead_code)]
#[path = "volume/mod.rs"]
pub mod volume;

// What the program alone names lints there, not here.
#[allow(dead_code, clippy::should_implement_trait)]
pub mod runtime {
    pub mod image {
        pub mod check;
        pub mod digest;
        // The library uses part of what the program does with it.
        pub mod http;
        pub mod tar;
        pub mod unpack;
    }
}

pub use runtime::image::http;

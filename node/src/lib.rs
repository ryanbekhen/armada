//! The parts of armada-node other crates of the workspace reuse (ADR
//! 0055): the control plane (armada-server) reads volume backup URLs with
//! the same ParseTarget the node uses, so their checks and texts agree.
//! The control plane's ACME client and DNS provider send their requests
//! through the same guarded HTTPS client image pulls use (`http`). The
//! Rust agent (armada-agent) runs the cluster network (`net`) and renders
//! HAProxy's configuration (`proxy`) in process. The program (main.rs)
//! compiles these files as its own modules too.

pub mod gostr;

// The library uses part of what the program does with them.
#[allow(dead_code)]
pub mod net;

#[allow(dead_code)]
pub mod proxy;

#[allow(dead_code)]
mod names;

pub mod queue {
    // Go's url.Parse fails with no detail: the callers word the error.
    #[allow(clippy::result_unit_err)]
    pub mod url;
}

pub mod volbackup {
    pub mod target;
}

// The library uses part of what the program does with it.
#[allow(dead_code)]
#[path = "runtime/image/http.rs"]
pub mod http;

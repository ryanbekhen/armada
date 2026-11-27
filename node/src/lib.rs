//! The parts of armada-node other crates of the workspace reuse: the
//! control plane (armada-server) reads volume backup URLs with the same
//! parser the node uses, so their checks and texts agree.
//! The control plane's ACME client and DNS provider send their requests
//! through the same guarded HTTPS client image pulls use (`http`), and
//! back the control plane up to a bucket with the repository volume
//! backups use (`volbackup`). The agent (armada-agent) runs the
//! cluster network (`net`) and renders HAProxy's configuration (`proxy`)
//! in process, and the supervisor runtime's pulls, bundles, specs,
//! shims, and statistics (`runtime`). The program (main.rs) compiles
//! these files as its own modules too.

pub mod textutil;

// The library uses part of what the program does with them.
#[allow(dead_code)]
pub mod net;

#[allow(dead_code)]
pub mod proxy;

#[allow(dead_code)]
mod names;

pub mod queue {
    // A URL that does not parse fails with no detail: the callers word
    // the error.
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

// The connection tracking table's numbers, which the agent reads
// and raises in process.
#[allow(dead_code)]
pub mod conntrack;

// SELinux's state (selinux_enabled), which the agent reads too.
#[allow(dead_code)]
pub mod nfs;

// What the program alone names lints there, not here. The agent runs
// the supervisor runtime on the same code:
// pulls, root filesystems, bundles, shims, specs, and statistics in
// process.
#[allow(dead_code, clippy::should_implement_trait)]
#[path = "runtime/mod.rs"]
pub mod runtime;

pub use runtime::image::http;

//! The OCI runtime a container runs on (ADR 0056). New containers are
//! created with crun; containers created before it with runc stay on runc
//! until they are recreated, since neither runtime reads the other's
//! state. A container's bundle record names its runtime (no name: runc),
//! and every call for it (start, kill, delete, exec, and the cleanup of a
//! shim that is gone) goes to that runtime, with its own state directory
//! beside the other's in the shim's state.

use std::path::{Path, PathBuf};

/// The OCI runtime of a container.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OciRuntime {
    /// Containers created before ADR 0056, until they are recreated.
    Runc,
    /// Every container created since.
    Crun,
}

impl OciRuntime {
    /// What new containers are created with (the agent's choice, through
    /// the library: the program creates what its request names).
    #[allow(dead_code)]
    pub const NEW: OciRuntime = OciRuntime::Crun;

    /// Both, in the order a shim's state is cleaned up.
    pub const ALL: [OciRuntime; 2] = [OciRuntime::Runc, OciRuntime::Crun];

    /// The runtime a bundle record names: none is runc, which records
    /// written before ADR 0056 never name.
    pub fn of_record(name: &str) -> Result<OciRuntime, String> {
        match name {
            "" | "runc" => Ok(OciRuntime::Runc),
            "crun" => Ok(OciRuntime::Crun),
            other => Err(format!(
                "unknown OCI runtime {}",
                crate::net::addr::quote(other)
            )),
        }
    }

    /// Its program's name in the runtime pack, and the word the shim and
    /// the records use.
    pub fn name(self) -> &'static str {
        match self {
            OciRuntime::Runc => "runc",
            OciRuntime::Crun => "crun",
        }
    }

    /// What a new bundle record holds: crun named, runc left out (as
    /// every record before ADR 0056).
    pub fn record_value(self) -> String {
        match self {
            OciRuntime::Runc => String::new(),
            OciRuntime::Crun => self.name().to_string(),
        }
    }

    /// Its state directory under a shim's state directory (`--root`):
    /// runc's and crun's never share one.
    pub fn root(self, state: &Path) -> PathBuf {
        state.join(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_name_their_runtime() {
        assert_eq!(OciRuntime::of_record(""), Ok(OciRuntime::Runc));
        assert_eq!(OciRuntime::of_record("runc"), Ok(OciRuntime::Runc));
        assert_eq!(OciRuntime::of_record("crun"), Ok(OciRuntime::Crun));
        assert_eq!(
            OciRuntime::of_record("youki"),
            Err("unknown OCI runtime \"youki\"".to_string())
        );
        assert_eq!(OciRuntime::NEW, OciRuntime::Crun);
        assert_eq!(OciRuntime::Crun.record_value(), "crun");
        assert_eq!(OciRuntime::Runc.record_value(), "");
        let s = Path::new("/run/armada/shim/s0");
        assert_eq!(OciRuntime::Runc.root(s), s.join("runc"));
        assert_eq!(OciRuntime::Crun.root(s), s.join("crun"));
    }
}

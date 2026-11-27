//! The OCI runtime (ADR 0056): crun creates and runs every container. A
//! container's bundle record names it ("crun"). A record that names runc,
//! or no runtime at all, is a container runc created under a release
//! that still carried runc; neither runtime reads the other's state, and
//! the runtime pack no longer carries runc, so such a container is only
//! recognized to be ended without runc and created again on crun
//! (cgroup.rs, and the agent's supervisor runtime).

use std::path::{Path, PathBuf};

/// What a bundle record says created a container.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OciRuntime {
    /// runc, under a release that carried it: to be ended and recreated.
    Runc,
    /// crun: every container created now.
    Crun,
}

impl OciRuntime {
    /// The runtime a bundle record names: none is runc, which records
    /// written before crun never name (the agent's, through the library).
    #[allow(dead_code)]
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

    /// The runtime a new bundle is created for: crun, which a request may
    /// name or leave out; anything else is refused.
    pub fn for_create(name: &str) -> Result<OciRuntime, String> {
        match name {
            "" | "crun" => Ok(OciRuntime::Crun),
            "runc" => Err("OCI runtime \"runc\": containers are created with crun".into()),
            other => Err(format!(
                "unknown OCI runtime {}",
                crate::net::addr::quote(other)
            )),
        }
    }

    /// Its program's name, the word the shim and the records use.
    pub fn name(self) -> &'static str {
        match self {
            OciRuntime::Runc => "runc",
            OciRuntime::Crun => "crun",
        }
    }

    /// Its state directory under a shim's state directory (`--root`):
    /// crun's, and runc's as a release that carried runc left it.
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
        assert_eq!(OciRuntime::for_create(""), Ok(OciRuntime::Crun));
        assert_eq!(OciRuntime::for_create("crun"), Ok(OciRuntime::Crun));
        assert!(OciRuntime::for_create("runc").is_err());
        assert!(OciRuntime::for_create("youki").is_err());
        let s = Path::new("/run/armada/shim/s0");
        assert_eq!(OciRuntime::Runc.root(s), s.join("runc"));
        assert_eq!(OciRuntime::Crun.root(s), s.join("crun"));
    }
}

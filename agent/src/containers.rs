//! Init containers and sidecars (ADR 0038, Go's containers.go): the runtime
//! runs them with the replica's own container; the agent pulls their
//! images, gives them the files and volumes they name, and reads their
//! state to tell a crash from a running replica.

use std::collections::HashMap;
use std::sync::Arc;

use armada_proto::armada::v1 as pb;

use crate::agent::{Inner, PullOnce, lock};
use crate::runtime::{
    self, Container, ContainerSpec, Error, MemberSpec, Runtime, STATE_EXITED, STATE_STARTING,
};
use crate::spec::{member_images, registry_auth};

/// Gives each init container and sidecar of cs the secret files and
/// volumes of the replica it names, at the same paths.
pub(crate) fn with_member_mounts(
    s: &pb::ReplicaSpec,
    cs: &mut ContainerSpec,
) -> Result<(), String> {
    let volume_path: HashMap<&str, &str> = s
        .volumes
        .iter()
        .map(|v| (v.name.as_str(), v.path.as_str()))
        .collect();
    let fill = |members: &mut [MemberSpec],
                specs: &[pb::ContainerSpec],
                files: &[runtime::FileMount],
                volumes: &[runtime::VolumeMount]|
     -> Result<(), String> {
        for (m, spec) in members.iter_mut().zip(specs) {
            for path in &spec.secret_files {
                let Some(f) = files.iter().find(|f| &f.target == path) else {
                    return Err(format!(
                        "container {}: secret file {path} is not the replica's",
                        m.name
                    ));
                };
                m.files.push(f.clone());
            }
            for name in &spec.volumes {
                let p = volume_path.get(name.as_str()).copied().unwrap_or("");
                let found = volumes.iter().find(|v| v.target == p);
                match found {
                    Some(v) if !p.is_empty() => m.volumes.push(v.clone()),
                    _ => {
                        return Err(format!(
                            "container {}: volume {name} is not the replica's",
                            m.name
                        ));
                    }
                }
            }
        }
        Ok(())
    };
    let (files, volumes) = (cs.files.clone(), cs.volumes.clone());
    let a = fill(&mut cs.init, &s.init_containers, &files, &volumes);
    let b = fill(&mut cs.sidecars, &s.sidecars, &files, &volumes);
    // errors.Join: the texts one per line.
    match (a, b) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(a), Ok(())) => Err(a),
        (Ok(()), Err(b)) => Err(b),
        (Err(a), Err(b)) => Err(format!("{a}\n{b}")),
    }
}

/// What of c's other containers stops its replica: an init container that
/// failed, a start the runtime gave up, or, outside jobs, a sidecar that no
/// longer runs. Empty when nothing does.
pub(crate) fn member_down(s: &pb::ReplicaSpec, c: &Container) -> String {
    if c.state == STATE_STARTING {
        return String::new();
    }
    if let Some(m) = c.failed_init() {
        return format!("init container {} exited with code {}", m.name, m.exit_code);
    }
    if !c.start_error.is_empty() {
        return c.start_error.clone();
    }
    if s.job.is_some() {
        // A job's sidecars serve its container; the attempt ends with it.
        return String::new();
    }
    if let Some(m) = c.stopped_sidecar() {
        if m.state == STATE_EXITED {
            return format!("sidecar {} exited with code {}", m.name, m.exit_code);
        }
        return format!("sidecar {} is {}", m.name, m.state);
    }
    String::new()
}

impl<R: Runtime> Inner<R> {
    /// Pulls the images of s's init containers and sidecars. An image with
    /// no variant for the node is a plain error: the platforms the server
    /// learns are the replica's own image's.
    pub(crate) async fn pull_members(
        self: &Arc<Self>,
        s: &pb::ReplicaSpec,
        pull: Option<&PullOnce>,
    ) -> runtime::Result<()> {
        let auth = registry_auth(s);
        for image in member_images(s) {
            let img = match self.pull_with(pull, &image, auth.as_ref()).await {
                Err(e @ Error::Platform { .. }) => return Err(Error::Other(e.to_string())),
                r => r?,
            };
            if !img.reference.is_empty() {
                lock(&self.st).digests.insert(image, img.reference);
            }
        }
        Ok(())
    }
}

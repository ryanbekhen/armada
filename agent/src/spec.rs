//! A replica's assignment as the runtime's container spec, and its spec
//! hash.

use std::collections::BTreeMap;

use armada_proto::armada::v1 as pb;
use prost::Message;
use sha2::{Digest, Sha256};

use crate::runtime::{
    ContainerSpec, LABEL_APP, LABEL_FENCE_AFTER, LABEL_MANAGED, LABEL_REPLICA, LABEL_REVISION,
    LABEL_SPEC_HASH, MemberSpec, RegistryAuth,
};

/// The container spec of replica `s`, published on `host_ip`, labelled
/// with its spec hash.
pub fn container_spec(s: &pb::ReplicaSpec, host_ip: &str, hash: &str) -> ContainerSpec {
    let mut labels = BTreeMap::from([
        (LABEL_MANAGED.to_string(), "true".to_string()),
        (LABEL_APP.to_string(), s.app.clone()),
        (LABEL_REVISION.to_string(), s.revision.clone()),
        (LABEL_REPLICA.to_string(), s.id.clone()),
        (LABEL_SPEC_HASH.to_string(), hash.to_string()),
    ]);
    if s.fence_after_seconds > 0 {
        labels.insert(
            LABEL_FENCE_AFTER.to_string(),
            s.fence_after_seconds.to_string(),
        );
    }
    ContainerSpec {
        name: format!("armada-{}", s.id),
        image: s.image.clone(),
        entrypoint: s.command.clone(),
        cmd: s.args.clone(),
        env: s
            .env
            .iter()
            .map(|e| format!("{}={}", e.name, e.value))
            .collect(),
        labels,
        port: i64::from(s.port),
        host_ip: host_ip.to_string(),
        memory_bytes: s.memory_bytes,
        nano_cpus: s.nano_cpus,
        cpu_reserve_millis: s.cpu_reserve_millis,
        pids_limit: s.pids_limit,
        init: member_specs(&s.init_containers),
        sidecars: member_specs(&s.sidecars),
        ..ContainerSpec::default()
    }
}

/// Init containers or sidecars as the runtime's specs; their files and
/// volumes are filled in by `with_member_mounts`.
pub fn member_specs(cs: &[pb::ContainerSpec]) -> Vec<MemberSpec> {
    cs.iter()
        .map(|c| MemberSpec {
            name: c.name.clone(),
            image: c.image.clone(),
            entrypoint: c.command.clone(),
            cmd: c.args.clone(),
            env: c
                .env
                .iter()
                .map(|e| format!("{}={}", e.name, e.value))
                .collect(),
            memory_bytes: c.memory_bytes,
            nano_cpus: c.nano_cpus,
            cpu_reserve_millis: c.cpu_reserve_millis,
            pids_limit: c.pids_limit,
            ..MemberSpec::default()
        })
        .collect()
}

/// A replica's pull credentials, if any.
pub fn registry_auth(s: &pb::ReplicaSpec) -> Option<RegistryAuth> {
    s.registry.as_ref().map(|r| RegistryAuth {
        username: r.username.clone(),
        password: r.password.clone(),
        server_address: r.server.clone(),
    })
}

/// Fingerprints everything about a replica except its image (the protobuf
/// encoding of the cleaned spec, fields in number order, then the first 16
/// bytes of its SHA-256), the same bytes every release hashes, so an
/// upgraded agent adopts the containers of the one before. Secret values are
/// left out: the hash sits in a container label.
pub fn spec_hash(s: &pb::ReplicaSpec) -> String {
    let mut c = s.clone();
    c.image.clear();
    c.cpu_reserve_millis = 0;
    c.queues.clear();
    c.hold = false;
    c.fence_after_seconds = 0;
    if let Some(j) = c.job.as_mut() {
        j.done = false;
    }
    for e in &mut c.env {
        if !e.r#ref.is_empty() {
            e.value.clear();
        }
    }
    for f in &mut c.secret_files {
        f.data.clear();
    }
    for m in c.init_containers.iter_mut().chain(c.sidecars.iter_mut()) {
        for e in &mut m.env {
            if !e.r#ref.is_empty() {
                e.value.clear();
            }
        }
    }
    if let Some(r) = c.registry.as_mut() {
        r.password.clear();
    }
    let sum = Sha256::digest(c.encode_to_vec());
    sum[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether s runs init containers or sidecars.
pub fn has_members(s: &pb::ReplicaSpec) -> bool {
    !s.init_containers.is_empty() || !s.sidecars.is_empty()
}

/// The images of s's init containers and sidecars.
pub fn member_images(s: &pb::ReplicaSpec) -> Vec<String> {
    s.init_containers
        .iter()
        .chain(s.sidecars.iter())
        .map(|c| c.image.clone())
        .collect()
}

//! The client links nothing a machine runs (ADR 0027): every crate it is
//! built with, read from the workspace's Cargo.lock, is outside the
//! control plane, the store, and the node agent.

use std::collections::{BTreeMap, BTreeSet};

const FORBIDDEN: [&str; 4] = [
    "armada-server",
    "armada-store",
    "armada-node",
    "armada-secrets",
];
const ARMADA_ALLOWED: [&str; 5] = [
    "armada-client",
    "armada-proto",
    "armada-spec",
    "armada-fsutil",
    "armada-pki",
];

/// Each package of Cargo.lock with the names of its dependencies.
fn lock() -> BTreeMap<String, Vec<String>> {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.lock"))
        .expect("the workspace's Cargo.lock");
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for block in text.split("[[package]]").skip(1) {
        let mut name = String::new();
        let mut deps = Vec::new();
        let mut in_deps = false;
        for line in block.lines() {
            let line = line.trim();
            if let Some(n) = line.strip_prefix("name = ") {
                name = n.trim_matches('"').to_string();
            } else if line.starts_with("dependencies = [") {
                in_deps = true;
            } else if in_deps && line == "]" {
                in_deps = false;
            } else if in_deps {
                // "name", or "name version" when two versions are locked.
                let d = line.trim_end_matches(',').trim_matches('"');
                deps.push(d.split(' ').next().unwrap_or(d).to_string());
            }
        }
        out.entry(name).or_default().extend(deps);
    }
    out
}

#[test]
fn the_client_links_no_machine_code() {
    let lock = lock();
    let mut seen = BTreeSet::new();
    let mut todo = vec!["armada-client".to_string()];
    while let Some(p) = todo.pop() {
        if !seen.insert(p.clone()) {
            continue;
        }
        todo.extend(lock.get(&p).cloned().unwrap_or_default());
    }
    for f in FORBIDDEN {
        assert!(!seen.contains(f), "armada-client is built with {f}");
    }
    for p in &seen {
        if p.starts_with("armada-") {
            assert!(
                ARMADA_ALLOWED.contains(&p.as_str()),
                "armada-client is built with {p}"
            );
        }
    }
    assert!(
        seen.contains("armada-proto"),
        "the walk found the client's crates"
    );
}

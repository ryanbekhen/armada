//! The render cases recorded from Go (ADR 0055, item 20): before the Go
//! code was removed, Go's TestArmadaNodeRenderMatchesGo rendered every configuration that test compares (the
//! named ones on every node's options, one with a value that is not a
//! single token, and the valid ones of 400 random configurations) with the
//! Go renderer and wrote testdata/render.jsonl.gz: each request as
//! `armada-node proxy render` reads it, and Go's haproxy.cfg, route maps,
//! and local.map, or that it rendered nothing. armada-node's renderer must
//! write the same bytes.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;

use armada_node::proxy::{Config, Options, render};
use serde_json::Value;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/testdata/render.jsonl.gz"
);

#[test]
fn renders_what_go_rendered() {
    let mut text = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(FIXTURE).expect("the recording"))
        .read_to_string(&mut text)
        .unwrap();
    let (mut n, mut failed) = (0, Vec::new());
    for line in text.lines() {
        let case: Value = serde_json::from_str(line).unwrap();
        let name = case["name"].as_str().unwrap().to_string();
        let req = &case["request"];
        let cfg: Config = serde_json::from_value(req["Config"].clone()).unwrap();
        let layout: HashMap<String, Vec<String>> =
            serde_json::from_value(req["Layout"].clone()).unwrap_or_default();
        let opts: Options = serde_json::from_value(req["Options"].clone()).unwrap();
        n += 1;
        let got = render::render(&cfg, &layout, &opts);
        if case["unsafe"].as_bool().unwrap() {
            if got.is_some() {
                failed.push(format!("{name}: rendered what Go refused"));
            }
            continue;
        }
        let Some(got) = got else {
            failed.push(format!("{name}: rendered nothing"));
            continue;
        };
        if got != case["config"].as_str().unwrap() {
            failed.push(format!(
                "{name}: haproxy.cfg differs:\n armada-node:\n{got}\n Go:\n{}",
                case["config"].as_str().unwrap()
            ));
            continue;
        }
        let routes: BTreeMap<String, String> = render::route_files(&cfg, &opts)
            .into_iter()
            .map(|(k, v)| (k, String::from_utf8(v).unwrap()))
            .collect();
        let want: BTreeMap<String, String> =
            serde_json::from_value(case["routes"].clone()).unwrap();
        if routes != want {
            failed.push(format!(
                "{name}: route maps differ: {routes:?}, Go {want:?}"
            ));
        }
        let local = render::local_map(&cfg, &layout, &opts.node());
        if local != case["local"].as_str().unwrap().as_bytes() {
            failed.push(format!(
                "{name}: local.map differs:\n{}\n Go:\n{}",
                String::from_utf8_lossy(&local),
                case["local"].as_str().unwrap()
            ));
        }
    }
    assert!(n > 250, "only {n} recorded renders");
    assert!(failed.is_empty(), "{}", failed.join("\n"));
}

/// Writes what armada-node renders for the recorded named cases (not the
/// random ones) into ARMADA_HAPROXY_CHECK_DIR, one directory per distinct
/// configuration with its haproxy.cfg, route maps, local.map, an empty
/// clients.map, and an empty certs/, laid out as the proxy's configuration
/// directory: scripts/haproxy-check.sh (CI job haproxy) adds a test
/// certificate and runs `haproxy -c` on each with the pinned image.
/// Does nothing without the variable.
#[test]
fn writes_configs_for_haproxy_check() {
    let Some(out) = std::env::var_os("ARMADA_HAPROXY_CHECK_DIR") else {
        return;
    };
    let out = std::path::PathBuf::from(out);
    let mut text = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(FIXTURE).expect("the recording"))
        .read_to_string(&mut text)
        .unwrap();
    let mut seen = std::collections::HashSet::new();
    for line in text.lines() {
        let case: Value = serde_json::from_str(line).unwrap();
        let name = case["name"].as_str().unwrap();
        if name.starts_with("random") || case["unsafe"].as_bool().unwrap() {
            continue;
        }
        let req = &case["request"];
        let cfg: Config = serde_json::from_value(req["Config"].clone()).unwrap();
        let layout: HashMap<String, Vec<String>> =
            serde_json::from_value(req["Layout"].clone()).unwrap_or_default();
        let opts: Options = serde_json::from_value(req["Options"].clone()).unwrap();
        let config = render::render(&cfg, &layout, &opts).expect("rendered");
        if !seen.insert(config.clone()) {
            continue;
        }
        let dir = out.join(format!("{:03}", seen.len()));
        std::fs::create_dir_all(dir.join("certs")).unwrap();
        std::fs::write(dir.join("haproxy.cfg"), &config).unwrap();
        std::fs::write(dir.join("clients.map"), b"").unwrap();
        std::fs::write(
            dir.join("local.map"),
            render::local_map(&cfg, &layout, &opts.node()),
        )
        .unwrap();
        for (file, body) in render::route_files(&cfg, &opts) {
            std::fs::write(dir.join(file), body).unwrap();
        }
        std::fs::write(dir.join("case.txt"), format!("{name}\n")).unwrap();
    }
    assert!(seen.len() >= 5, "only {} configurations", seen.len());
}

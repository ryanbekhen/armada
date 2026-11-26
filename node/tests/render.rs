//! The render cases recorded from Go (ADR 0055, item 20): `go test
//! ./internal/proxy/haproxy -run TestArmadaNodeRenderMatchesGo
//! -record-fixtures` rendered every configuration that test compares (the
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

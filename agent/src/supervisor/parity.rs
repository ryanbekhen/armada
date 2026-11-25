//! The supervisor runtime against Go's driver: what Go's
//! TestRustSupervisorCNI, TestRustSupervisorFiles, and
//! TestRustSupervisorContainers (internal/runtime/containerd
//! rustsupervisor_linux_test.go) kept in testdata/rust, replayed here.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Value, json};

use super::tests::{FakeHost, cni_plugins, plugin_calls};
use super::*;

fn golden(name: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../internal/runtime/containerd/testdata/rust")
        .join(name);
    serde_json::from_slice(&fs::read(&p).unwrap()).unwrap()
}

fn root(name: &str) -> PathBuf {
    let r = std::env::temp_dir().join(format!("armada-parity-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&r);
    fs::create_dir_all(&r).unwrap();
    r
}

/// A cache file with root replaced, also in the configuration it holds as
/// base64 (rsCache).
fn cache(path: &Path, conf: &[u8], root: &str) -> String {
    use armada_node::net::key::b64_encode;
    let s = fs::read_to_string(path).unwrap();
    let norm = String::from_utf8_lossy(conf).replace(root, "ROOT");
    s.replace(&b64_encode(conf), &b64_encode(norm.as_bytes()))
        .replace(root, "ROOT")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cni_as_go() {
    let want = golden("cni.json");
    let dir = root("cni");
    let r = dir.display().to_string();
    let plugins = dir.join("data/runtime/current/bin/cni");
    cni_plugins(&plugins, &dir.join("cni-log"));
    let host = Arc::new(FakeHost::new(dir.join("rootfs")));
    let net = cni::Network::new(
        cni::Prefix4::parse("10.121.0.0/24").unwrap(),
        1450,
        &dir.join("run/cni"),
        plugins,
        dir.join("run/netns"),
        host.clone(),
        Logger::discard(),
    )
    .unwrap();
    let results = dir.join("run/cni/cache/results");
    let (id, ns) = ("web-r1-0a0b0c0d", format!("{r}/run/netns/cni-fake-0"));
    let pm = cni::PortMapping {
        host_ip: "10.0.0.5".into(),
        host_port: 20001,
        container_port: 8080,
    };
    net.attach(id, &ns, Some(&pm)).await.unwrap();
    let got_cache = cache(&results.join(format!("armada-{id}-eth0")), net.conf(), &r);
    net.teardown(id, &ns, Some(&pm)).await.unwrap();
    let (id2, ns2) = ("sandbox-q1", format!("{r}/sandboxes/q1"));
    net.setup_at(id2, &ns2).await.unwrap();
    let got_cache_at = cache(&results.join(format!("armada-{id2}-eth0")), net.conf(), &r);
    let address = net.address(id2).unwrap();
    net.teardown(id2, "", None).await.unwrap();
    let calls: Vec<Value> = plugin_calls(&dir.join("cni-log"))
        .into_iter()
        .map(|(h, i)| json!({"head": h.replace(&r, "ROOT"), "input": i.replace(&r, "ROOT")}))
        .collect();
    let forgot: Vec<String> = host
        .calls()
        .iter()
        .filter_map(|c| c.strip_prefix("forget ").map(String::from))
        .collect();
    let got = json!({
        "calls": calls, "cache": got_cache, "cacheAt": got_cache_at, "address": address,
        "forgot": forgot, "released": !results.join(format!("armada-{id2}-eth0")).exists(),
    });
    for k in ["calls", "cache", "cacheAt", "address", "forgot", "released"] {
        assert_eq!(got[k], want[k], "{k}");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn files_as_go() {
    let want = golden("files.json");
    let strs = |v: &Value| -> Vec<String> {
        v.as_array()
            .map(|a| a.iter().map(|s| s.as_str().unwrap().to_string()).collect())
            .unwrap_or_default()
    };
    for c in want["resolv"].as_array().unwrap() {
        let got = files::resolv_conf(
            c["host"].as_str().unwrap().as_bytes(),
            &strs(&c["dns"]),
            &strs(&c["search"]),
        );
        assert_eq!(
            String::from_utf8(got).unwrap(),
            c["want"].as_str().unwrap(),
            "{c}"
        );
    }
    for (name, h) in want["hostnames"].as_object().unwrap() {
        assert_eq!(files::hostname(name), h.as_str().unwrap(), "{name}");
        assert_eq!(
            String::from_utf8(files::hosts_file("10.121.0.7", h.as_str().unwrap())).unwrap(),
            want["hosts"][name].as_str().unwrap()
        );
    }
    assert_eq!(
        String::from_utf8(files::hosts_file("", "web")).unwrap(),
        want["hosts"][""].as_str().unwrap()
    );
}

fn time_text(t: Option<std::time::SystemTime>) -> String {
    t.map(crate::clock::rfc3339_nano).unwrap_or_default()
}

fn container_json(c: &Container) -> Value {
    json!({
        "id": c.id, "name": c.name, "image": c.image, "labels": c.labels, "state": c.state,
        "exitCode": c.exit_code, "hostIP": c.host_ip, "hostPort": c.host_port, "ip": c.ip,
        "startedAt": time_text(c.started_at), "startError": c.start_error,
        "members": c.members.iter().map(|m| json!({
            "id": m.id, "name": m.name, "role": m.role, "state": m.state,
            "exitCode": m.exit_code, "startedAt": time_text(m.started_at),
        })).collect::<Vec<_>>(),
    })
}

/// Shims answering from Go's table.
fn serve_shims(dir: &Path, table: &serde_json::Map<String, Value>) {
    fs::create_dir_all(dir).unwrap();
    for (group, answers) in table {
        let sock = dir.join(format!(
            "{}.sock",
            armada_node::runtime::container::shim::shim_name(group)
        ));
        let answers: BTreeMap<String, String> = answers
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect();
        let l = UnixListener::bind(&sock).unwrap();
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(c) = c else { break };
                let mut line = String::new();
                if BufReader::new(&c).read_line(&mut line).is_err() {
                    continue;
                }
                let a = answers
                    .get(line.trim_end_matches('\n'))
                    .cloned()
                    .unwrap_or_else(|| "err unknown request".into());
                let _ = (&c).write_all(format!("{a}\n").as_bytes());
            }
        });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn containers_as_go() {
    let want = golden("containers.json");
    let dir = root("containers");
    let bundles = dir.join("data/supervisor/containers");
    for (rel, content) in want["files"].as_object().unwrap() {
        let p = bundles.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content.as_str().unwrap()).unwrap();
    }
    serve_shims(&dir.join("run/shim"), want["shims"].as_object().unwrap());
    let mut cfg = Config::new(dir.join("data"), dir.join("run"), Logger::discard());
    cfg.host = Arc::new(FakeHost::new(dir.join("rootfs")));
    let rt = Supervisor::new(cfg).unwrap();

    let sorted = |mut cs: Vec<Container>| -> Value {
        cs.sort_by(|a, b| a.id.cmp(&b.id));
        Value::Array(cs.iter().map(container_json).collect())
    };
    assert_eq!(
        sorted(rt.list(&BTreeMap::new()).await.unwrap()),
        want["list"]
    );
    let mut web = BTreeMap::new();
    web.insert("armada.app".to_string(), "web".to_string());
    assert_eq!(sorted(rt.list(&web).await.unwrap()), want["web"]);
    for (id, w) in want["inspect"].as_object().unwrap() {
        let got = match rt.inspect(id).await {
            Ok(c) => container_json(&c),
            Err(e) => {
                assert_eq!(e.to_string(), w["state"].as_str().unwrap(), "{id}");
                continue;
            }
        };
        assert_eq!(&got, w, "{id}");
    }
    let _ = fs::remove_dir_all(&dir);
}

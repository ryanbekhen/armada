//! The supervisor runtime against its recordings
//! (tests/testdata/supervisor), replayed here.

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
        .join("tests/testdata/supervisor")
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
/// base64.
fn cache(path: &Path, conf: &[u8], root: &str) -> String {
    use armada_node::net::key::b64_encode;
    let s = fs::read_to_string(path).unwrap();
    let norm = String::from_utf8_lossy(conf).replace(root, "ROOT");
    s.replace(&b64_encode(conf), &b64_encode(norm.as_bytes()))
        .replace(root, "ROOT")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cni_as_recorded() {
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
fn files_as_recorded() {
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

/// Shims answering from the recorded table.
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
async fn containers_as_recorded() {
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

/// Writes (or appends) the files logs.json describes, with their times.
fn write_log_files(dir: &Path, files: &Value, append: bool) {
    for f in files.as_array().into_iter().flatten() {
        let p = dir.join(f["path"].as_str().unwrap());
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        let mut w = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .append(append)
            .truncate(!append)
            .open(&p)
            .unwrap();
        w.write_all(f["data"].as_str().unwrap().as_bytes()).unwrap();
        let t = std::time::UNIX_EPOCH + Duration::from_secs(f["mod"].as_u64().unwrap());
        w.set_times(fs::FileTimes::new().set_modified(t).set_accessed(t))
            .unwrap();
    }
}

fn records_json(recs: &[crate::side::LogRecord]) -> Value {
    Value::Array(
        recs.iter()
            .map(|r| {
                let mut o = json!({
                    "time": time_text(Some(r.time)),
                    "stderr": r.stderr,
                    "data": String::from_utf8_lossy(&r.data),
                    "replica": r.replica,
                    "container": r.container,
                });
                if !r.app.is_empty() {
                    o["app"] = json!(r.app);
                }
                if !r.revision.is_empty() {
                    o["revision"] = json!(r.revision);
                }
                o
            })
            .collect(),
    )
}

fn regular_files(dir: &Path) -> Vec<(PathBuf, fs::Metadata)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let md = fs::symlink_metadata(e.path()).unwrap();
            if md.is_dir() {
                stack.push(e.path());
            } else if md.is_file() {
                out.push((e.path(), md));
            }
        }
    }
    out
}

/// export.json with each inode replaced by its file's name.
fn state_text(dir: &Path) -> String {
    use std::os::unix::fs::MetadataExt;
    let Ok(mut s) = fs::read_to_string(dir.join("history/export.json")) else {
        return String::new();
    };
    let v: Value = serde_json::from_str(&s).unwrap();
    for (p, md) in regular_files(dir) {
        let rel = p.strip_prefix(dir).unwrap().display().to_string();
        if v["files"]
            .as_object()
            .is_some_and(|f| f.values().any(|c| c["ino"].as_u64() == Some(md.ino())))
        {
            s = s.replace(
                &format!("\"ino\":{}", md.ino()),
                &format!("\"ino\":{rel:?}"),
            );
        }
    }
    s
}

fn time_of(v: &Value) -> Option<std::time::SystemTime> {
    v.as_str().filter(|s| !s.is_empty()).and_then(parse_time)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logs_as_recorded() {
    let want = golden("logs.json");
    let dir = root("logs");
    write_log_files(&dir, &want["files"], false);
    for s in want["searches"].as_array().unwrap() {
        let q = crate::side::LogQuery {
            app: s["app"].as_str().unwrap().into(),
            replica: s["replica"].as_str().unwrap().into(),
            container: s["container"].as_str().unwrap().into(),
            since: time_of(&s["since"]).unwrap_or_else(history::zero_time),
            until: time_of(&s["until"]),
            grep: s["grep"].as_str().unwrap().into(),
            limit: s["limit"].as_i64().unwrap(),
            max_bytes: s["maxBytes"].as_i64().unwrap(),
        };
        let (recs, notice) = history::search_logs(&dir, None, &q, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(records_json(&recs), s["records"], "{s}");
        assert_eq!(notice, s["notice"].as_str().unwrap(), "{s}");
    }
    for t in want["tails"].as_array().unwrap() {
        write_log_files(&dir, &t["append"], true);
        let tail = history::tail_logs(
            &dir,
            None,
            t["target"].as_str().unwrap(),
            t["maxBytes"].as_i64().unwrap(),
            time_of(&t["now"]).unwrap(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(records_json(&tail.records), t["records"], "{t}");
        (tail.commit.unwrap())().await.unwrap();
        assert_eq!(state_text(&dir), t["state"].as_str().unwrap());
    }
    for p in want["prunes"].as_array().unwrap() {
        history::prune_logs(
            &dir,
            Duration::from_secs(p["retention"].as_u64().unwrap()),
            p["maxBytes"].as_i64().unwrap(),
            time_of(&p["now"]).unwrap(),
        )
        .unwrap();
        let mut left: Vec<String> = regular_files(&dir)
            .into_iter()
            .map(|(p, _)| p.strip_prefix(&dir).unwrap().display().to_string())
            .collect();
        left.sort();
        assert_eq!(json!(left), p["left"]);
    }
    let _ = fs::remove_dir_all(&dir);
}

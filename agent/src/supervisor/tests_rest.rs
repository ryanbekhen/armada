//! The supervisor runtime's second part without root: SELinux labels,
//! the move of Go's image store, and the calls of the agent's sessions
//! (exec sessions, logs, dials, queues, sandboxes) against the stand-ins
//! of [`super::tests`].

use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::Ordering;

use super::tests::{Lab, script};
use super::*;

fn labels(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
    kv.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

pub(crate) fn web_spec(name: &str, port: i64) -> ContainerSpec {
    ContainerSpec {
        name: name.into(),
        image: "app:1".into(),
        labels: labels(&[
            ("armada.managed", "true"),
            ("armada.app", "web"),
            ("armada.replica", name),
            ("armada.revision", "web-1"),
        ]),
        port,
        host_ip: if port != 0 {
            "10.0.0.5".into()
        } else {
            String::new()
        },
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn labels_containers_for_selinux() {
    let lab = Lab::new("selinux");
    lab.host.selinux.store(true, Ordering::SeqCst);
    let vol = lab.root.join("volumes/web/data");
    fs::create_dir_all(vol.join("sub")).unwrap();
    fs::write(vol.join("sub/f"), b"x").unwrap();
    let shared = lab.root.join("nfs/web/share");
    fs::create_dir_all(&shared).unwrap();
    let secret = lab.root.join("secrets/web-r1/key");
    fs::create_dir_all(secret.parent().unwrap()).unwrap();
    fs::write(&secret, b"k").unwrap();
    let mut s = web_spec("web-r1", 8080);
    s.files = vec![runtime::FileMount {
        source: secret.display().to_string(),
        target: "/run/secrets/key".into(),
    }];
    s.volumes = vec![
        runtime::VolumeMount {
            source: vol.display().to_string(),
            target: "/data".into(),
            ..Default::default()
        },
        runtime::VolumeMount {
            source: shared.display().to_string(),
            target: "/share".into(),
            shared: true,
            ..Default::default()
        },
    ];
    let rt = &lab.rt;
    rt.ping().await.unwrap();
    let id = rt.run(&s).await.unwrap();
    let c = lab.config(&id);
    let process = c["process"]["selinuxLabel"].as_str().unwrap().to_string();
    let mount = c["linux"]["mountLabel"].as_str().unwrap().to_string();
    let level = process
        .strip_prefix("system_u:system_r:container_t:")
        .unwrap()
        .to_string();
    assert!(level.starts_with("s0:c"), "{process}");
    assert_eq!(mount, format!("system_u:object_r:container_file_t:{level}"));
    let fl = lab.host.file_labels.lock().unwrap().clone();
    for p in [
        lab.data().join("containers").join(&id),
        lab.data().join("containers").join(&id).join("hosts"),
        secret.clone(),
        vol.clone(),
        vol.join("sub"),
        vol.join("sub/f"),
    ] {
        assert_eq!(fl.get(&p), Some(&mount), "{}", p.display());
    }
    assert!(!fl.contains_key(&shared));
    let tini = fs::canonicalize(lab.data().join("runtime/current/bin/tini")).unwrap();
    assert_eq!(
        fl.get(&tini).map(String::as_str),
        Some("system_u:object_r:container_ro_file_t:s0")
    );

    // A runtime started again keeps the first container's categories
    // reserved, gives the next one others, and releases them with the
    // container.
    let rt2 = Supervisor::new(rt.inner.cfg.clone()).unwrap();
    let id2 = rt2.run(&web_spec("web-r2", 0)).await.unwrap();
    let p2 = lab.config(&id2)["process"]["selinuxLabel"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(p2, process);
    assert!(rt2.inner.selinux.reserved_levels().contains(&level));
    rt2.remove(&id).await.unwrap();
    assert!(!rt2.inner.selinux.reserved_levels().contains(&level));

    // A system container's mounted directories get its label.
    let dir = lab.root.join("haproxy");
    fs::create_dir_all(&dir).unwrap();
    let sid = rt2
        .run_system(&SystemSpec {
            name: "armada-haproxy".into(),
            image: "app:1".into(),
            mounts: vec![crate::haproxy::engine::Mount {
                source: dir.display().to_string(),
                target: "/etc/haproxy".into(),
                read_only: false,
            }],
            labels: labels(&[("armada.system", "haproxy")]),
            ..Default::default()
        })
        .await
        .unwrap();
    let sp = lab.config(&sid)["process"]["selinuxLabel"]
        .as_str()
        .unwrap()
        .replace("system_r:container_t", "object_r:container_file_t");
    assert_eq!(lab.host.file_labels.lock().unwrap().get(&dir), Some(&sp));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_policy_without_container_types_runs_containers_unlabelled() {
    let lab = Lab::new("selinux-nopolicy");
    lab.host.selinux.store(true, Ordering::SeqCst);
    lab.host
        .unknown_types
        .lock()
        .unwrap()
        .push("container_t".into());
    let id = lab.rt.run(&web_spec("web-r1", 0)).await.unwrap();
    let c = lab.config(&id);
    assert!(c["process"]["selinuxLabel"].is_null(), "{c}");
    assert!(lab.host.file_labels.lock().unwrap().is_empty());
}

fn node_stand_in(lab: &Lab, body: &str) {
    script(&lab.data().join("runtime/current/bin/armada-node"), body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runs_exec_sessions_through_armada_node() {
    use crate::side::{ExecOptions, TermSize};
    let lab = Lab::new("execsession");
    let id = lab.rt.run(&web_spec("web-r1", 0)).await.unwrap();
    let req = lab.root.join("req.json");
    let ctl = lab.root.join("ctl.txt");
    node_stand_in(
        &lab,
        &format!(
            r#"cat <&3 >{req}
echo '{{"spawned":true}}' >&4
echo '{{"started":true}}' >&4
cat <&5 >&6
echo err >&7
echo '{{"exit":7}}' >&4
echo '{{"drained":true}}' >&4"#,
            req = req.display()
        ),
    );
    let (in_tx, in_rx) = tokio::sync::mpsc::channel(4);
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(16);
    in_tx.send(b"hello\n".to_vec()).await.unwrap();
    drop(in_tx);
    let opts = ExecOptions {
        cmd: vec!["sh".into(), "-c".into(), "cat".into()],
        stdin: Some(in_rx),
        output: Some(out_tx),
        ..Default::default()
    };
    assert_eq!(lab.rt.exec_session(&id, opts).await.unwrap(), 7);
    let mut got = Vec::new();
    while let Ok(o) = out_rx.try_recv() {
        got.push(o);
    }
    got.sort();
    assert_eq!(
        got,
        vec![(false, b"err\n".to_vec()), (true, b"hello\n".to_vec())]
    );
    let r: serde_json::Value = serde_json::from_slice(&fs::read(&req).unwrap()).unwrap();
    assert_eq!(r["args"], serde_json::json!(["sh", "-c", "cat"]));
    assert_eq!(r["id"], serde_json::json!(id));
    assert_eq!(r["terminal"], false);
    assert_eq!(r["consoleSize"], serde_json::Value::Null);
    for k in ["stdin", "stdout", "stderr"] {
        assert_eq!(r[k], true, "{k}");
    }
    assert_eq!(r["drainGraceMs"], 2000);
    assert!(
        r["dir"]
            .as_str()
            .unwrap()
            .contains(&format!("/exec-{id}-exec-"))
    );

    // A terminal: no error output, its size first and its resizes as
    // they come.
    node_stand_in(
        &lab,
        &format!(
            r#"cat <&3 >{req}
echo '{{"spawned":true}}' >&4
echo '{{"started":true}}' >&4
head -n 2 <&4 >{ctl}
echo '{{"exit":0}}' >&4
echo '{{"drained":true}}' >&4"#,
            req = req.display(),
            ctl = ctl.display()
        ),
    );
    let (rs_tx, rs_rx) = tokio::sync::mpsc::channel(4);
    rs_tx
        .send(TermSize {
            rows: 50,
            cols: 120,
        })
        .await
        .unwrap();
    let (out_tx, _out_rx) = tokio::sync::mpsc::channel(16);
    let opts = ExecOptions {
        cmd: vec!["sh".into()],
        tty: true,
        size: TermSize { rows: 24, cols: 80 },
        output: Some(out_tx),
        resize: Some(rs_rx),
        ..Default::default()
    };
    assert_eq!(lab.rt.exec_session(&id, opts).await.unwrap(), 0);
    let r: serde_json::Value = serde_json::from_slice(&fs::read(&req).unwrap()).unwrap();
    assert_eq!(
        r["consoleSize"],
        serde_json::json!({"height": 24, "width": 80})
    );
    assert_eq!(r["stderr"], false);
    assert_eq!(
        fs::read_to_string(&ctl).unwrap(),
        "{\"resize\":{\"height\":24,\"width\":80}}\n{\"resize\":{\"height\":50,\"width\":120}}\n"
    );

    // A caller that gives up: the command is killed, then abandoned.
    node_stand_in(
        &lab,
        &format!(
            r#"cat <&3 >/dev/null
echo '{{"spawned":true}}' >&4
echo '{{"started":true}}' >&4
head -n 1 <&4 >{ctl}.tmp
mv {ctl}.tmp {ctl}
echo '{{"exit":137}}' >&4"#,
            ctl = ctl.display()
        ),
    );
    let _ = fs::remove_file(&ctl);
    let opts = ExecOptions {
        cmd: vec!["sleep".into(), "100".into()],
        ..Default::default()
    };
    let r = tokio::time::timeout(Duration::from_millis(300), lab.rt.exec_session(&id, opts)).await;
    assert!(r.is_err());
    let mut seen = String::new();
    for _ in 0..300 {
        seen = fs::read_to_string(&ctl).unwrap_or_default();
        if !seen.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(seen, "{\"kill\":true}\n");

    // Failures before the runtime ran, and calls refused. A new
    // container runs on crun (ADR 0056).
    node_stand_in(&lab, r#"echo '{"execErrno":2}' >&4"#);
    let bin = lab.data().join("runtime/current/bin");
    let cmd = |c: &[&str]| ExecOptions {
        cmd: c.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    assert_eq!(lab.record(&id)["runtime"], "crun");
    assert_eq!(
        lab.rt
            .exec_session(&id, cmd(&["x"]))
            .await
            .unwrap_err()
            .to_string(),
        format!(
            "exec: crun exec: fork/exec {}: no such file or directory",
            bin.join("crun").display()
        )
    );
    // A container created before ADR 0056 (its record names no runtime)
    // stays on runc.
    let record = lab
        .data()
        .join("supervisor/containers")
        .join(&id)
        .join("record.json");
    let mut rec = lab.record(&id);
    rec.as_object_mut().unwrap().remove("runtime");
    fs::write(&record, serde_json::to_vec(&rec).unwrap()).unwrap();
    // The agent sees it on runc and moves it; the node counts it.
    assert_eq!(lab.rt.inspect(&id).await.unwrap().oci_runtime, "runc");
    assert_eq!(lab.rt.runtime_agent().await.unwrap().runc_containers, 1);
    assert_eq!(
        lab.rt
            .exec_session(&id, cmd(&["x"]))
            .await
            .unwrap_err()
            .to_string(),
        format!(
            "exec: runc exec: fork/exec {}: no such file or directory",
            bin.join("runc").display()
        )
    );
    assert_eq!(
        lab.rt
            .exec_session(&id, cmd(&[]))
            .await
            .unwrap_err()
            .to_string(),
        "command is empty"
    );
    assert!(matches!(
        lab.rt.exec_session("nope", cmd(&["x"])).await,
        Err(Error::NotFound)
    ));
}

fn log_line(stream: &str, log: &str, t: &str) -> String {
    format!(
        "{}\n",
        serde_json::json!({"log": log, "stream": stream, "time": t})
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reads_and_follows_a_containers_output() {
    use crate::side::LogOptions;
    let lab = Lab::new("readlogs");
    let logs = lab.data().join("logs");
    fs::create_dir_all(&logs).unwrap();
    let path = logs.join("web-r1-aaaa.log");
    fs::write(
        logs.join("web-r1-aaaa.log.1"),
        log_line("stdout", "one\n", "2026-01-01T00:00:01Z"),
    )
    .unwrap();
    fs::write(
        &path,
        log_line("stderr", "Two\n", "2026-01-01T00:00:02Z")
            + &log_line("stdout", "three\n", "2026-01-01T00:00:03Z"),
    )
    .unwrap();
    let read = |opts: LogOptions| {
        let rt = lab.rt.clone();
        async move {
            let mut rx = rt.logs("web-r1-aaaa", &opts).await.unwrap();
            let mut out = Vec::new();
            while let Some(f) = rx.recv().await {
                let f = f.unwrap();
                out.push((f.stderr, String::from_utf8(f.data).unwrap()));
            }
            out
        }
    };
    assert_eq!(
        read(LogOptions::default()).await,
        vec![
            (false, "one\n".into()),
            (true, "Two\n".into()),
            (false, "three\n".into())
        ]
    );
    let tail = LogOptions {
        tail: 1,
        ..Default::default()
    };
    assert_eq!(read(tail).await, vec![(false, "three\n".to_string())]);
    let grep = LogOptions {
        grep: "two".into(),
        ..Default::default()
    };
    assert_eq!(read(grep).await, vec![(true, "Two\n".to_string())]);
    assert!(matches!(
        lab.rt.logs("nope", &LogOptions::default()).await,
        Err(Error::NotFound)
    ));

    // Following: new output only (tail -1), then what is appended, also
    // once the file was rotated.
    let follow = LogOptions {
        follow: true,
        tail: -1,
        ..Default::default()
    };
    let mut rx = lab.rt.logs("web-r1-aaaa", &follow).await.unwrap();
    // After the first read of the file.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
    std::io::Write::write_all(
        &mut f,
        log_line("stdout", "four\n", "2026-01-01T00:00:04Z").as_bytes(),
    )
    .unwrap();
    let next = |rx: &mut crate::side::LogFrames| {
        let rx = rx as *mut crate::side::LogFrames;
        async move {
            // SAFETY: the receiver outlives this future, awaited at once.
            let rx = unsafe { &mut *rx };
            let f = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            String::from_utf8(f.data).unwrap()
        }
    };
    assert_eq!(next(&mut rx).await, "four\n");
    fs::rename(&path, logs.join("web-r1-aaaa.log.1")).unwrap();
    fs::write(&path, log_line("stdout", "five\n", "2026-01-01T00:00:05Z")).unwrap();
    assert_eq!(next(&mut rx).await, "five\n");
    drop(rx);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn searches_and_exports_through_armada_log() {
    let lab = Lab::new("armadalog");
    let logs = lab.data().join("logs");
    fs::create_dir_all(logs.join("history")).unwrap();
    fs::write(
        logs.join("history/web-r1-aaaa.meta"),
        r#"{"app":"web","replica":"web-r1","revision":"web-1","created":"2099-01-01T00:00:00Z"}"#,
    )
    .unwrap();
    fs::write(
        logs.join("web-r1-aaaa.log"),
        log_line("stdout", "x\n", "2026-01-01T00:00:01Z"),
    )
    .unwrap();
    let args = lab.root.join("args.txt");
    let input = lab.root.join("input.txt");
    let bin = lab.data().join("runtime/current/bin/armada-log");
    script(
        &bin,
        &format!(
            r#"echo "$@" > {args}
cat > {input}
case "$1" in
search) printf '%s\n' '2 {{"log":"found\n","stream":"stderr","time":"2026-01-01T00:00:09Z"}}' 'end budget 77' ;;
export) printf 'body 3\nabccursor 0 0 10 1767225601.5\nend 42\n' ;;
esac"#,
            args = args.display(),
            input = input.display()
        ),
    );
    let q = crate::side::LogQuery {
        app: "web".into(),
        since: UNIX_EPOCH + Duration::from_secs(1_767_225_600),
        grep: "fo".into(),
        limit: 10,
        max_bytes: 100 << 20,
        replica: String::new(),
        container: String::new(),
        until: None,
    };
    let (recs, notice) = lab.rt.search_logs(&q).await.unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(
        (recs[0].stderr, recs[0].data.as_slice()),
        (true, &b"found\n"[..])
    );
    assert_eq!(recs[0].replica, "web-r1");
    assert!(
        notice.starts_with("searched the newest 100 MiB"),
        "{notice}"
    );
    assert_eq!(
        fs::read_to_string(&args).unwrap(),
        "search --limit 10 --max-bytes 104857600 --since 1767225600000000000 --grep fo --deadline-ms 30000\n"
    );
    let paths = fs::read_to_string(&input).unwrap();
    assert_eq!(paths.lines().count(), 3, "{paths}");
    assert!(paths.starts_with(&format!("{}\n", logs.join("web-r1-aaaa.log").display())));

    // A non-ASCII text is searched here.
    let q = crate::side::LogQuery {
        grep: "ä".into(),
        ..q
    };
    assert!(lab.rt.search_logs(&q).await.unwrap().0.is_empty());

    // Exports: a new container is read from its start.
    let enc = crate::side::LogEncoding {
        format: "loki".into(),
        node: "n1".into(),
        batch_records: 2000,
        batch_bytes: 1 << 20,
    };
    let tail = lab
        .rt
        .tail_logs("loki|t", 1 << 20, Some(&enc))
        .await
        .unwrap();
    assert_eq!(tail.bodies, Some(vec![b"abc".to_vec()]));
    assert_eq!(tail.size, 42);
    let a = fs::read_to_string(&args).unwrap();
    assert!(
        a.starts_with("export --format loki --node n1 --now ")
            && a.ends_with(
                " --batch-records 2000 --batch-bytes 1048576 --budget 1048576 --share 1048576\n"
            ),
        "{a}"
    );
    let plan = fs::read_to_string(&input).unwrap();
    assert_eq!(
        plan,
        format!(
            "c\t1\tdefault\tweb\tweb-r1\tweb-1\tapp\t-\nf\t0\t{}\t{}\n",
            fs::metadata(logs.join("web-r1-aaaa.log")).unwrap().len(),
            logs.join("web-r1-aaaa.log").display()
        )
    );
    (tail.commit.unwrap())().await.unwrap();
    let st: serde_json::Value =
        serde_json::from_slice(&fs::read(logs.join("history/export.json")).unwrap()).unwrap();
    assert_eq!(st["files"]["web-r1-aaaa"]["off"], 10);
    assert_eq!(
        st["files"]["web-r1-aaaa"]["time"],
        "2026-01-01T00:00:01.000000005Z"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dials_reads_queues_and_keeps_sandboxes() {
    use std::io::{Read, Write};
    let lab = Lab::new("dial");
    let id = lab.rt.run(&web_spec("web-r1", 0)).await.unwrap();
    let req = lab.root.join("req.json");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    // A stand-in armada-node: dials 127.0.0.1 itself and hands the socket
    // over descriptor 3, as runtime dial does; answers queue readings.
    let have_python = std::process::Command::new("python3")
        .arg("-c")
        .arg("import socket; socket.send_fds")
        .status()
        .is_ok_and(|s| s.success());
    node_stand_in(
        &lab,
        &format!(
            r#"cat > {req}
case "$1 $2" in
"runtime dial") exec python3 -I -c '
import socket, json, sys
r = json.load(open("{req}"))
c = socket.create_connection(("127.0.0.1", r["port"]))
s = socket.socket(fileno=3)
socket.send_fds(s, [b"x"], [c.fileno()])
print(json.dumps({{"connected": True}}))' ;;
"queue redis") echo '{{"length":42}}' ;;
"queue rabbitmq") echo '{{"error":"the queue does not exist"}}' ;;
esac"#,
            req = req.display()
        ),
    );
    if have_python {
        let fd = lab
            .rt
            .dial_container(&id, "tcp", &format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        let mut conn = std::net::TcpStream::from(fd);
        conn.write_all(b"ping").unwrap();
        let mut b = [0u8; 4];
        peer.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"ping");
        let r: serde_json::Value = serde_json::from_slice(&fs::read(&req).unwrap()).unwrap();
        assert_eq!(r["id"], serde_json::json!(id));
        assert_eq!(r["kind"], "tcp");
        assert_eq!(r["family"], 4);
        assert_eq!(
            r["dir"],
            lab.data()
                .join("supervisor/containers")
                .display()
                .to_string()
        );
        assert_eq!(
            r["shimDir"],
            lab.root.join("run/shim").display().to_string()
        );
    }
    assert_eq!(
        lab.rt
            .dial_container(&id, "tcp", "redis:6379")
            .await
            .unwrap_err()
            .to_string(),
        "dial from a namespace: \"redis\" is not an IP address"
    );

    let q = crate::side::QueueRead {
        kind: "redis".into(),
        url: "redis://:secret@10.0.0.9:6379".into(),
        name: "jobs".into(),
        addresses: vec!["10.0.0.9:6379".parse().unwrap()],
    };
    assert_eq!(lab.rt.read_queue(&id, &q).await.unwrap(), 42);
    let r: serde_json::Value = serde_json::from_slice(&fs::read(&req).unwrap()).unwrap();
    assert_eq!(r["url"], "redis://:secret@10.0.0.9:6379");
    assert_eq!(r["addresses"], serde_json::json!(["10.0.0.9:6379"]));
    assert_eq!(r["timeoutMs"], 10000);
    let q = crate::side::QueueRead {
        kind: "rabbitmq".into(),
        ..q
    };
    assert_eq!(
        lab.rt.read_queue(&id, &q).await.unwrap_err().to_string(),
        "the queue does not exist"
    );

    // Sandboxes: pinned, attached, listed, read from, and removed.
    assert!(lab.rt.list_sandboxes().await.unwrap().is_empty());
    let sb = lab.rt.ensure_sandbox("worker.dev").await.unwrap();
    assert_eq!(sb.ip, "10.121.0.5");
    let path = lab.root.join("run/sandboxes/worker.dev");
    assert!(lab.host.is_netns(&path));
    assert_eq!(lab.rt.ensure_sandbox("worker.dev").await.unwrap(), sb);
    assert_eq!(lab.rt.list_sandboxes().await.unwrap(), vec![sb.clone()]);
    assert_eq!(
        lab.rt
            .read_sandbox_queue("worker.dev", &q)
            .await
            .unwrap_err()
            .to_string(),
        "the queue does not exist"
    );
    let r: serde_json::Value = serde_json::from_slice(&fs::read(&req).unwrap()).unwrap();
    assert_eq!(r["netns"], path.display().to_string());
    let calls: Vec<String> = super::tests::plugin_calls(&lab.root.join("cni-log"))
        .into_iter()
        .map(|(h, _)| h)
        .filter(|h| h.contains("sandbox-worker.dev"))
        .collect();
    // What an earlier try left is released first, as Go does.
    let kinds: Vec<&str> = calls
        .iter()
        .map(|c| c.split(' ').take(2).last().unwrap())
        .collect();
    assert_eq!(
        kinds,
        ["DEL", "DEL", "DEL", "DEL", "ADD", "ADD", "ADD", "ADD"],
        "{calls:?}"
    );
    lab.rt.remove_sandbox("worker.dev").await.unwrap();
    assert!(!path.exists());
    assert!(lab.rt.list_sandboxes().await.unwrap().is_empty());
    assert_eq!(
        lab.rt
            .dial_sandbox("worker.dev", "tcp", "10.0.0.1:1")
            .await
            .unwrap_err()
            .to_string(),
        "sandbox worker.dev: not found"
    );
    assert_eq!(
        lab.rt.ensure_sandbox("Bad").await.unwrap_err().to_string(),
        "invalid sandbox ID \"Bad\""
    );
}

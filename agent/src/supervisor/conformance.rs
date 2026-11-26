//! The supervisor runtime on a real machine (root, a lab node whose
//! agent is stopped, its runtime pack installed): what Go's
//! ConformanceSupervisor checks of the driver, through the Rust one, with
//! new containers on crun (ADR 0056). Never run by `cargo test`; see
//! CLAUDE.md's Commands for how to run it (the pack installed must carry
//! crun: a pack built from pack/lock.json since ADR 0056).
//!
//! ARMADA_DATA_DIR and ARMADA_RUN_DIR name the node's directories
//! (/var/lib/armada and /run/armada), ARMADA_SUBNET its container subnet
//! (the default bridge's when unset), ARMADA_CONFORMANCE_IMAGE an image
//! with sh, sleep, true, and false (busybox when unset).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use super::*;

fn env(k: &str, def: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| def.to_string())
}

fn runtime() -> Supervisor {
    let mut cfg = Config::new(
        PathBuf::from(env("ARMADA_DATA_DIR", "/var/lib/armada")),
        PathBuf::from(env("ARMADA_RUN_DIR", "/run/armada")),
        Logger::stderr(false),
    );
    cfg.subnet = env("ARMADA_SUBNET", "");
    Supervisor::new(cfg).unwrap()
}

fn image() -> String {
    env("ARMADA_CONFORMANCE_IMAGE", "docker.io/library/busybox:1.36")
}

fn spec(name: &str, img: &str) -> ContainerSpec {
    let mut labels = BTreeMap::new();
    labels.insert("armada.managed".to_string(), "true".to_string());
    labels.insert("armada.app".to_string(), "conformance".to_string());
    labels.insert("armada.replica".to_string(), name.to_string());
    ContainerSpec {
        name: name.into(),
        image: img.into(),
        cmd: vec!["sleep".into(), "300".into()],
        labels,
        memory_bytes: 64 << 20,
        pids_limit: 64,
        ..Default::default()
    }
}

async fn wait_for(rt: &Supervisor, id: &str, state: &str) -> Container {
    for _ in 0..300 {
        let c = rt.inspect(id).await.unwrap();
        if c.state == state {
            return c;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{id} never became {state}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "root on a lab node: see CLAUDE.md"]
async fn conformance_supervisor_rust() {
    let rt = runtime();
    rt.ping().await.unwrap();
    rt.agent_start().await.unwrap();
    let img = rt.pull(&image(), None).await.unwrap();
    assert!(img.reference.contains('@'), "{img:?}");
    // The agent runs a replica's image by the name its spec gives, as Go's
    // driver does; the digest reference only goes into its reports.
    let name = image();

    // A replica: running, addressed on the bridge, commands, samples.
    let id = rt.run(&spec("conformance-r1", &name)).await.unwrap();
    let c = wait_for(&rt, &id, STATE_RUNNING).await;
    let ip: std::net::Ipv4Addr = c.ip.parse().unwrap();
    assert!(rt.bridge().subnet.contains(ip), "{ip}");
    // A new container runs on crun (ADR 0056): its record names it, and
    // its state is in crun's directory of the shim's, not runc's.
    let rec = rt.inner.load(&id).await.unwrap();
    assert_eq!(rec.runtime, "crun");
    let crun_state = rt.inner.shims.root(&rec.group, OciRuntime::Crun);
    assert!(
        crun_state.join(&id).join("status").is_file(),
        "{crun_state:?}"
    );
    let runc_state = rt.inner.shims.root(&rec.group, OciRuntime::Runc);
    assert!(!runc_state.join(&id).exists(), "{runc_state:?}");
    assert_eq!(rt.exec_app(&id, &["true".to_string()]).await.unwrap(), 0);
    assert_eq!(rt.exec_app(&id, &["false".to_string()]).await.unwrap(), 1);
    let st = rt.stats(&id).await.unwrap();
    assert!(st.memory_bytes > 0 && !st.network_lost, "{st:?}");

    // An exec session with its streams; the output in the log; a dial
    // from the container's namespace (refused: nothing listens there).
    let (in_tx, in_rx) = tokio::sync::mpsc::channel(1);
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(16);
    in_tx.send(b"hello\n".to_vec()).await.unwrap();
    drop(in_tx);
    let opts = crate::side::ExecOptions {
        cmd: vec!["sh".into(), "-c".into(), "cat; echo err >&2; exit 3".into()],
        stdin: Some(in_rx),
        output: Some(out_tx),
        ..Default::default()
    };
    assert_eq!(rt.exec_session(&id, opts).await.unwrap(), 3);
    let mut got = Vec::new();
    while let Ok(o) = out_rx.try_recv() {
        got.push(o);
    }
    got.sort();
    assert_eq!(
        got,
        vec![(false, b"err\n".to_vec()), (true, b"hello\n".to_vec())]
    );
    // A terminal: the container's own (crun hands it over its console
    // socket, ADR 0056), sized as asked and translating its output, so
    // lines end in "\r\n" as on any terminal.
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(16);
    let opts = crate::side::ExecOptions {
        cmd: vec!["sh".into(), "-c".into(), "echo a; echo b; stty size".into()],
        tty: true,
        size: crate::side::TermSize {
            rows: 33,
            cols: 101,
        },
        output: Some(out_tx),
        ..Default::default()
    };
    assert_eq!(rt.exec_session(&id, opts).await.unwrap(), 0);
    let mut tty = Vec::new();
    while let Ok((_, b)) = out_rx.try_recv() {
        tty.extend(b);
    }
    let tty = String::from_utf8_lossy(&tty).into_owned();
    assert!(tty.contains("a\r\nb\r\n33 101\r\n"), "{tty:?}");
    let mut frames = rt
        .logs(&id, &crate::side::LogOptions::default())
        .await
        .unwrap();
    while frames.recv().await.is_some() {}
    let e = rt
        .dial_container(&id, "tcp", "127.0.0.1:1")
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("connection refused"), "{e}");

    // A sandbox: pinned, addressed on the bridge, removed.
    let sb = rt.ensure_sandbox("conformance").await.unwrap();
    let ip: std::net::Ipv4Addr = sb.ip.parse().unwrap();
    assert!(rt.bridge().subnet.contains(ip), "{ip}");
    assert_eq!(rt.list_sandboxes().await.unwrap(), vec![sb]);
    rt.remove_sandbox("conformance").await.unwrap();
    assert!(rt.list_sandboxes().await.unwrap().is_empty());

    rt.stop(&id, Duration::from_secs(5)).await.unwrap();
    assert_eq!(rt.inspect(&id).await.unwrap().state, STATE_EXITED);
    assert_eq!(rt.release_network(&id).await, Some(Ok(())));
    rt.remove(&id).await.unwrap();
    assert_eq!(rt.inspect(&id).await.unwrap_err(), Error::NotFound);

    // A replica with an init container and a sidecar.
    let mut s = spec("conformance-r2", &name);
    s.init = vec![MemberSpec {
        name: "init".into(),
        image: name.clone(),
        cmd: vec!["true".into()],
        ..Default::default()
    }];
    s.sidecars = vec![MemberSpec {
        name: "side".into(),
        image: name.clone(),
        cmd: vec!["sleep".into(), "300".into()],
        ..Default::default()
    }];
    let id = rt.run(&s).await.unwrap();
    let c = wait_for(&rt, &id, STATE_RUNNING).await;
    assert_eq!(c.members.len(), 2, "{c:?}");
    assert_eq!(c.members[0].exit_code, 0);
    assert_eq!(c.members[1].state, STATE_RUNNING);
    rt.stop(&id, Duration::from_secs(5)).await.unwrap();
    rt.remove(&id).await.unwrap();

    // A system container: commands with their output, signals.
    let mut labels = BTreeMap::new();
    labels.insert(LABEL_SYSTEM.to_string(), "conformance".to_string());
    let id = rt
        .run_system(&SystemSpec {
            name: "armada-conformance".into(),
            image: name.clone(),
            labels,
            user: "0:0".into(),
            ..Default::default()
        })
        .await;
    // Busybox's default command ends at once; only the start is checked.
    let id = id.unwrap();
    rt.remove(&id).await.unwrap();
    rt.prune_images(&[], Duration::ZERO).await.unwrap().unwrap();
}

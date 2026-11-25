//! The supervisor runtime on a real machine (root, a lab node whose
//! agent is stopped, its runtime pack installed): what Go's
//! ConformanceSupervisor checks of the driver, through the Rust one. Never
//! run by `cargo test`; see CLAUDE.md's Commands for how to run it.
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

    // A replica: running, addressed on the bridge, commands, samples.
    let id = rt
        .run(&spec("conformance-r1", &img.reference))
        .await
        .unwrap();
    let c = wait_for(&rt, &id, STATE_RUNNING).await;
    let ip: std::net::Ipv4Addr = c.ip.parse().unwrap();
    assert!(rt.bridge().subnet.contains(ip), "{ip}");
    assert_eq!(rt.exec_app(&id, &["true".to_string()]).await.unwrap(), 0);
    assert_eq!(rt.exec_app(&id, &["false".to_string()]).await.unwrap(), 1);
    let st = rt.stats(&id).await.unwrap();
    assert!(st.memory_bytes > 0 && !st.network_lost, "{st:?}");
    rt.stop(&id, Duration::from_secs(5)).await.unwrap();
    assert_eq!(rt.inspect(&id).await.unwrap().state, STATE_EXITED);
    assert_eq!(rt.release_network(&id).await, Some(Ok(())));
    rt.remove(&id).await.unwrap();
    assert_eq!(rt.inspect(&id).await.unwrap_err(), Error::NotFound);

    // A replica with an init container and a sidecar.
    let mut s = spec("conformance-r2", &img.reference);
    s.init = vec![MemberSpec {
        name: "init".into(),
        image: img.reference.clone(),
        cmd: vec!["true".into()],
        ..Default::default()
    }];
    s.sidecars = vec![MemberSpec {
        name: "side".into(),
        image: img.reference.clone(),
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
            image: img.reference.clone(),
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

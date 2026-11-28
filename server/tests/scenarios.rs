//! The control plane's recorded scenarios replayed against the server.
//! tests/testdata/scenarios holds every step a scenario took at the
//! server's boundaries (calls of the API, fake agents' sessions, the
//! store's methods, clock moves, passes, the fake etcd membership) and
//! the recorded answer to each. Each recording is replayed here against
//! armada-server-parity on a member of the state of the test's own: an
//! armada-kv member in the test's process (ADR 0057, the store of new
//! clusters), or with ARMADA_SCENARIO_STORE=etcd the pinned etcd that
//! scripts/etcd-cache.sh puts in .cache/etcd (or ARMADA_ETCD_DIR), the
//! store of clusters not moved yet; every answer, normalized as the
//! transcripts were, must equal the recorded one. ARMADA_SCENARIO=NAME
//! replays only the recordings whose names contain NAME. The state's
//! moves (replay/statemove.rs) always start on the pinned etcd.

mod replay;

use std::path::Path;

use replay::etcd::{self, Member};
use replay::run::{Fixture, Shared, replay};

/// Whether the chosen store can run here: armada-kv always, etcd only
/// with the pinned program (CI fails without it).
fn store_ready(name: &str) -> bool {
    if !etcd::on_etcd() || etcd::program().is_some() {
        return true;
    }
    eprintln!(
        "{name}: skipped, no etcd in .cache/etcd or ARMADA_ETCD_DIR (run sh scripts/etcd-cache.sh)"
    );
    if std::env::var_os("CI").is_some() {
        panic!("CI runs the {name} on etcd: the pinned etcd is missing");
    }
    false
}

#[test]
fn scenarios() {
    if !store_ready("scenarios") {
        return;
    }
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/scenarios");
    let mut fixtures = Vec::new();
    for e in std::fs::read_dir(&dir).expect("the recordings") {
        let p = e.expect("a recording").path();
        if p.extension().is_some_and(|x| x == "json") {
            let f = Fixture::parse(&std::fs::read(&p).expect("read a recording"))
                .unwrap_or_else(|e| panic!("{}: {e}", p.display()));
            fixtures.push(f);
        }
    }
    fixtures.sort_by(|a, b| a.name.cmp(&b.name));
    assert!(!fixtures.is_empty(), "no recordings in {}", dir.display());
    let only = std::env::var("ARMADA_SCENARIO").unwrap_or_default();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime");
    rt.block_on(async {
        let mut member =
            Member::start_chosen(Path::new(env!("CARGO_TARGET_TMPDIR")).join("scenarios-state"))
                .expect("start the state's member");
        let client = member.ready().await.expect("the state's member ready");
        eprintln!("scenarios: on {}", etcd::store_name());
        let shared = Shared {
            client,
            socket: member.socket(),
            n: Default::default(),
        };
        let (mut failed, mut ran, mut skipped) = (Vec::new(), 0, Vec::new());
        for f in &fixtures {
            if !only.is_empty() && !f.name.contains(&only) {
                continue;
            }
            if let Some(why) = &f.skip {
                skipped.push(format!("{} ({why})", f.name));
                continue;
            }
            ran += 1;
            match replay(&shared, f).await {
                Ok(d) if d.is_empty() => eprintln!("scenarios: {} ok", f.name),
                Ok(d) => {
                    eprintln!(
                        "scenarios: {} differs from the recording:\n{}",
                        f.name,
                        d.join("\n")
                    );
                    failed.push(f.name.clone());
                }
                Err(e) => {
                    eprintln!("scenarios: {} failed: {e}", f.name);
                    failed.push(f.name.clone());
                }
            }
        }
        for s in &skipped {
            eprintln!("scenarios: skipped {s}");
        }
        drop(member);
        assert!(
            failed.is_empty(),
            "{} of {ran} scenarios differ from their recordings: {}",
            failed.len(),
            failed.join(", ")
        );
    });
}

/// The server's terms on a member of the test's own (replay/terms.rs).
#[test]
fn terms() {
    if !store_ready("terms") {
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    rt.block_on(async {
        let mut member =
            Member::start_chosen(Path::new(env!("CARGO_TARGET_TMPDIR")).join("terms-state"))
                .expect("start the state's member");
        let client = member.ready().await.expect("the state's member ready");
        let res = replay::terms::terms(client, &member.socket()).await;
        drop(member);
        if let Err(e) = res {
            panic!("terms: {e}");
        }
    });
}

/// Runs a check of the state's move to armada-kv (replay/statemove.rs) on
/// clusters of the pinned etcd.
fn state_move(name: &str, f: impl AsyncFnOnce(&Path) -> Result<(), String>) {
    let Some(prog) = etcd::program() else {
        eprintln!("{name}: skipped, no etcd in .cache/etcd or ARMADA_ETCD_DIR");
        if std::env::var_os("CI").is_some() {
            panic!("CI runs the state moves: the pinned etcd is missing");
        }
        return;
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime");
    if let Err(e) = rt.block_on(f(&prog)) {
        panic!("{name}: {e}");
    }
}

/// One server on etcd moved to armada-kv.
#[test]
fn state_move_one_server() {
    state_move("state_move_one_server", async |p| {
        replay::statemove::moved(p, 1).await
    });
}

/// Three servers on etcd moved to armada-kv.
#[test]
fn state_move_three_servers() {
    state_move("state_move_three_servers", async |p| {
        replay::statemove::moved(p, 3).await
    });
}

/// A move that fails in the middle leaves the cluster on etcd.
#[test]
fn state_move_failed() {
    state_move("state_move_failed", async |p| {
        replay::statemove::failed(p).await
    });
}

/// Writes are refused while the key space is copied.
#[test]
fn state_move_copying() {
    state_move("state_move_copying", async |p| {
        replay::statemove::copying(p).await
    });
}

/// A new leader gives up a move its predecessor left half done.
#[test]
fn state_move_interrupted() {
    state_move("state_move_interrupted", async |p| {
        replay::statemove::interrupted(p).await
    });
}

//! The control plane's scenarios replayed against the Rust server (ADR
//! 0055, item 20): Go's scenario parity tests (internal/server/parity_*)
//! recorded once against Go's server, with -record-scenarios, into
//! tests/testdata/scenarios: every step a scenario took at the server's
//! boundaries (calls of the API, fake agents' sessions, the store's
//! methods, clock moves, passes, the fake etcd membership) and Go's
//! answer to each. Each recording is replayed here against
//! armada-server-parity on an etcd member of the test's own (the pinned
//! etcd that scripts/etcd-cache.sh puts in .cache/etcd, or
//! ARMADA_ETCD_DIR), and every answer, normalized as the transcripts
//! were, must equal Go's. ARMADA_SCENARIO=NAME replays only the
//! recordings whose names contain NAME.

mod replay;

use std::path::Path;

use replay::etcd::{self, Member};
use replay::run::{Fixture, Shared, replay};

#[test]
fn scenarios() {
    let Some(prog) = etcd::program() else {
        eprintln!(
            "scenarios: skipped, no etcd in .cache/etcd or ARMADA_ETCD_DIR (run sh scripts/etcd-cache.sh)"
        );
        if std::env::var_os("CI").is_some() {
            panic!("CI runs the scenarios: the pinned etcd is missing");
        }
        return;
    };
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
        let mut member = Member::start(
            &prog,
            Path::new(env!("CARGO_TARGET_TMPDIR")).join("scenarios-etcd"),
        )
        .expect("start etcd");
        let client = member.ready().await.expect("etcd ready");
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
                    eprintln!("scenarios: {} differs from Go:\n{}", f.name, d.join("\n"));
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
            "{} of {ran} scenarios differ from Go's: {}",
            failed.len(),
            failed.join(", ")
        );
    });
}

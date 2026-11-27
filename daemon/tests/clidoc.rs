//! The command line reference written from armadad's commands equals
//! docs/cli: armadad's pages there are the daemon's (`make docs` writes
//! them from these commands). With ARMADA_CLIDOC_UPDATE=1 the test
//! writes the daemon's pages into docs/cli instead, removing armadad's
//! pages no command has. armada's pages are the client's
//! (client/tests/clidoc.rs).

use std::path::Path;

#[test]
fn reference_equals_docs_cli() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/cli");
    let tree = armada_daemon::tree::root();
    let pages = armada_client::cli::clidoc::pages(&tree);
    let ours = |name: &str| name == "armadad.md" || name.starts_with("armadad-");
    if std::env::var_os("ARMADA_CLIDOC_UPDATE").is_some_and(|v| v == "1") {
        for e in std::fs::read_dir(&dir).expect("docs/cli") {
            let name = e.expect("entry").file_name().to_string_lossy().into_owned();
            if ours(&name) && !pages.contains_key(&name) {
                std::fs::remove_file(dir.join(&name)).expect("remove a stale page");
            }
        }
        for (name, page) in &pages {
            std::fs::write(dir.join(name), page).expect("write a page");
        }
        return;
    }
    let mut bad = Vec::new();
    for (name, page) in &pages {
        let want = std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        if &want != page {
            bad.push(name.clone());
            let (w, g): (Vec<&str>, Vec<&str>) = (want.lines().collect(), page.lines().collect());
            if let Some(i) = (0..w.len().max(g.len())).find(|&i| w.get(i) != g.get(i)) {
                eprintln!(
                    "docs/cli/{name}:{}:\n  docs: {:?}\n  got: {:?}",
                    i + 1,
                    w.get(i),
                    g.get(i)
                );
            }
        }
    }
    // Every page of armadad in docs/cli is one the daemon writes.
    for e in std::fs::read_dir(&dir).expect("docs/cli") {
        let name = e.expect("entry").file_name().to_string_lossy().into_owned();
        if ours(&name) && !pages.contains_key(&name) {
            bad.push(format!("{name} (no command)"));
        }
    }
    assert!(pages.len() > 10, "{} pages", pages.len());
    assert!(
        bad.is_empty(),
        "pages differ from docs/cli (run make docs): {bad:?}"
    );
}

//! The command line reference written from the Rust client's commands
//! equals docs/cli: armada's pages there are the client's (ADR 0055,
//! item 20: `make docs` writes them from these commands, as Go's
//! TestReferenceIsCurrent wrote them from Go's, which still checks them
//! while Go is in the repository). With ARMADA_CLIDOC_UPDATE=1 the test
//! writes the client's pages into docs/cli instead, removing armada's
//! pages no command has. armadad's pages are the daemon's
//! (daemon/tests/clidoc.rs).

use std::path::Path;

#[test]
fn reference_equals_docs_cli() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/cli");
    let tree = armada_client::commands::root();
    let pages = armada_client::cli::clidoc::pages(&tree);
    let ours = |name: &str| name == "armada.md" || name.starts_with("armada-");
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
                    "docs/cli/{name}:{}:\n  docs: {:?}\n  Rust: {:?}",
                    i + 1,
                    w.get(i),
                    g.get(i)
                );
            }
        }
    }
    // Every page of armada in docs/cli is one the client writes.
    for e in std::fs::read_dir(&dir).expect("docs/cli") {
        let name = e.expect("entry").file_name().to_string_lossy().into_owned();
        if ours(&name) && !pages.contains_key(&name) {
            bad.push(format!("{name} (no command)"));
        }
    }
    assert!(pages.len() > 19, "{} pages", pages.len());
    assert!(
        bad.is_empty(),
        "pages differ from docs/cli (run make docs): {bad:?}"
    );
}

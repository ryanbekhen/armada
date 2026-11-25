//! armadad: runs on every machine of an Armada cluster (ADR 0027). A
//! program of its own: never a link to armada, and never choosing what it
//! is from its name.

fn main() {
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    std::process::exit(armada_daemon::execute(&args));
}

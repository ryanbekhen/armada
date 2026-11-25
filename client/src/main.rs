//! armada: the client, which manages apps on an Armada cluster through the
//! control plane's API (ADR 0027). A program of its own: never a link to
//! armadad, and never choosing what it is from its name.

fn main() {
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    std::process::exit(armada_client::execute(&args));
}

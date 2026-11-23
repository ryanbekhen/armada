//! `armada-node` is Armada's node agent moving to Rust in steps (ADR 0054).
//! It runs as subcommands the Go agent hands work to, each one checked
//! against the Go code it replaces:
//!
//!   armada-node proxy render   HAProxy's configuration (src/proxy)

mod names;
mod proxy;

use std::process::ExitCode;

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["proxy", "render"] => proxy::render_command(),
        _ => Err(format!("unknown command {args:?}; try: proxy render")),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("armada-node: {e}");
            ExitCode::FAILURE
        }
    }
}

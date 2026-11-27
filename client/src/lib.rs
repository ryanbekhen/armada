//! The armada client (ADR 0027): commands that only talk to the control
//! plane's API, with their flags, help, output, exit codes, completion,
//! and configuration files. It never links what a machine runs.
//!
//! `cli::clidoc` writes the command line reference (docs/cli) from these
//! commands.

pub mod cli;
pub mod commands;
pub mod config;
pub mod dial;
pub mod release;
pub mod rpc;
pub mod term;

use std::io::{IsTerminal, Read, Write};
use std::time::Duration;

/// How far the client's clock is moved from the machine's: always zero,
/// except in builds with the test-hooks feature (never released), where
/// ARMADA_CLIENT_TEST_NOW (Unix nanoseconds) is the time the program
/// starts at, so the recorded parity cases (tests/parity.rs) see the
/// answers' times as recorded.
pub(crate) fn clock_offset() -> i128 {
    #[cfg(feature = "test-hooks")]
    {
        static OFFSET: std::sync::OnceLock<i128> = std::sync::OnceLock::new();
        *OFFSET.get_or_init(|| {
            std::env::var("ARMADA_CLIENT_TEST_NOW")
                .ok()
                .and_then(|v| v.parse::<i128>().ok())
                .map_or(0, |t| t - commands::wall_nanos())
        })
    }
    #[cfg(not(feature = "test-hooks"))]
    {
        0
    }
}

/// Execute: the tree run with args, and on a terminal, at most once a
/// day, a line saying a newer release exists.
pub fn execute(args: &[String]) -> i32 {
    let notice = start_notice(args);
    let mut stdin = std::io::stdin().lock();
    let mut stdout = Unbuffered(std::io::stdout());
    let mut stderr = std::io::stderr();
    let code = run(args, &mut stdin, &mut stdout, &mut stderr);
    let line = notice(Duration::from_secs(1));
    if !line.is_empty() {
        let _ = writeln!(stderr, "{line}");
    }
    code
}

/// stdout, flushed after every write so lines a waiting command prints
/// show at once.
struct Unbuffered(std::io::Stdout);

impl Write for Unbuffered {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let mut l = self.0.lock();
        let n = l.write(b)?;
        l.flush()?;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// Only when a person reads stderr, and not for commands that
/// need no cluster.
fn start_notice(args: &[String]) -> Box<dyn FnOnce(Duration) -> String> {
    let none: Box<dyn FnOnce(Duration) -> String> = Box::new(|_| String::new());
    if !std::io::stderr().is_terminal() {
        return none;
    }
    if let Some(first) = args.first()
        && ["version", "help", "completion", "__complete"].contains(&first.as_str())
    {
        return none;
    }
    release::start_notice(commands::version::get().version)
}

/// Run: the command tree with args, returning the exit code.
pub fn run(args: &[String], stdin: &mut dyn Read, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let mut tree = commands::root();
    if args.iter().any(|a| a == "__completeNoDesc") {
        cli::complete::CALLED_NO_DESC.with(|c| c.set(true));
    }
    cli::run(&mut tree, args, commands::pre_run, stdin, out, err)
}

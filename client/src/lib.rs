//! The armada client (ADR 0027, ADR 0055): commands that only talk to the
//! control plane's API, ported from Go's internal/cli and
//! internal/clientconfig with the same names, flags, help, output, exit
//! codes, completion, and configuration files. It never links what a
//! machine runs.
//!
//! This is the first part of the port (ADR 0055, pull request 17a): the
//! command framework, the client config, dialing (mTLS and SSH), the
//! release notice, and the app, revision, replica, job, run, secret, space,
//! version, and completion commands. The other nouns are listed and say
//! they are not here yet.

pub mod cli;
pub mod commands;
pub mod config;
pub mod dial;
pub mod release;
pub mod rpc;

use std::io::{IsTerminal, Read, Write};
use std::time::Duration;

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

/// startNotice: only when a person reads stderr, and not for commands that
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

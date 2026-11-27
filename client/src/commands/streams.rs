//! The app and job commands that stream or sample: app logs and job logs
//! app events and cluster events, app exec, and app top and node top.

use std::io::Write;
use std::os::fd::FromRawFd;

use armada_proto::armada::v1::{
    EventInfo, EventsRequest, ExecClientMessage, ExecInput, ExecStart, LogsRequest, Stream,
    TermSize, TopRequest, TopResponse, exec_client_message, exec_input, exec_server_message,
};
use armada_spec::go;

use super::{
    Output, clock, dash, go_time, human_bytes, is_terminal, month_day_clock, now_nanos,
    output_flag, print_json, rfc3339_millis, rpc_err, used_bytes,
};
use crate::cli::flags::Flag;
use crate::cli::tabwriter::TabWriter;
use crate::cli::{ArgError, Args, Ctx, Error, Node, Result, arg_error};
use crate::rpc::printable;

// ---- logs ----

/// App logs, or job logs.
pub fn logs_node(job: bool) -> Node {
    let mut flags = vec![
        Flag::bool(
            "follow",
            Some('f'),
            false,
            "stream new log lines, also from replicas that start later",
        ),
        Flag::int("tail", None, 100, "lines per replica to show"),
        Flag::string(
            "container",
            None,
            "",
            "show an init container or sidecar instead of the app's own container",
        ),
        Flag::string(
            "since",
            None,
            "",
            "search the log history from this long ago (2h, 3d) or this time (RFC 3339), across every node, including replicas that are gone",
        ),
        Flag::string(
            "until",
            None,
            "",
            "with --since: up to this long ago or this time (default now)",
        ),
        Flag::string(
            "grep",
            None,
            "",
            "only lines containing this text, ignoring case (plain text, not a pattern); also while following",
        ),
        Flag::int(
            "limit",
            None,
            0,
            "with --since: the newest lines to show (default 500, at most 5000)",
        ),
        Flag::bool("timestamps", None, false, "show when each line was written"),
    ];
    let n = if job {
        flags.push(Flag::int64(
            "run",
            None,
            0,
            "the run to show (default: the newest)",
        ));
        flags.push(Flag::int(
            "task",
            None,
            0,
            "the task to show, for a job with tasks (default: the latest attempt of any task)",
        ));
        Node::new("logs JOB", "Print the logs of a job's run")
            .long("Print the logs of the latest attempt of a job's newest run (--run N for another\nrun, --task I for one task of a run that has several). A finished run's logs are\nkept for 24 hours; --since searches the log history of every run (ADR 0043).")
            .example("  armada job logs migrate               # the newest run\n  armada job logs migrate --run 12      # one run (armada run list migrate)\n  armada job logs migrate -f")
            .run(job_logs)
    } else {
        flags.push(Flag::string(
            "replica",
            None,
            "",
            "only show this replica: its short name from armada replica list, or its ID",
        ));
        Node::new("logs APP", "Print logs from an app's replicas")
            .example("  armada app logs api                     # the last 100 lines of each replica\n  armada app logs api -f --grep error     # follow, only lines with \"error\"\n  armada app logs api --since 2h          # search the history, replicas that are gone included\n  armada app logs api --replica k3p9x --container log-ship")
            .run(app_logs)
    };
    n.args(Args::Exact(1)).flags(flags)
}

fn app_logs(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    logs(ctx, args, false)
}

fn job_logs(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    logs(ctx, args, true)
}

/// A time as a protobuf timestamp.
fn ts_of(unix: i64, nsec: i64) -> armada_proto::google::protobuf::Timestamp {
    armada_proto::google::protobuf::Timestamp {
        seconds: unix,
        nanos: nsec as i32,
    }
}

/// A Unix time in nanoseconds as a timestamp.
fn ts_nanos(n: i128) -> armada_proto::google::protobuf::Timestamp {
    ts_of(
        n.div_euclid(1_000_000_000) as i64,
        n.rem_euclid(1_000_000_000) as i64,
    )
}

/// a duration before now ("2h", "3d") or an RFC 3339 time.
pub fn parse_when(
    s: &str,
    now: i128,
) -> std::result::Result<armada_proto::google::protobuf::Timestamp, String> {
    if let Some(d) = s.strip_suffix('d') {
        return match d.parse::<i64>() {
            Ok(n) if (0..=3650).contains(&n) => {
                Ok(ts_nanos(now - i128::from(n) * 24 * i128::from(go::HOUR)))
            }
            _ => Err(format!("{} is not a number of days", go::quote(s))),
        };
    }
    if let Ok(d) = go::parse_duration(s) {
        if d < 0 {
            return Err(format!("{} is negative", go::quote(s)));
        }
        return Ok(ts_nanos(now - i128::from(d)));
    }
    parse_rfc3339(s).ok_or_else(|| {
        format!(
            "{} is neither a duration such as 2h or 3d nor a time such as 2026-11-13T09:00:00+07:00",
            go::quote(s)
        )
    })
}

/// An RFC 3339 time: 2006-01-02T15:04:05, an optional
/// fraction, then Z or an offset.
fn parse_rfc3339(s: &str) -> Option<armada_proto::google::protobuf::Timestamp> {
    let b = s.as_bytes();
    let num = |from: usize, len: usize| -> Option<i64> {
        let part = b.get(from..from + len)?;
        part.iter()
            .all(u8::is_ascii_digit)
            .then(|| part.iter().fold(0i64, |n, &c| n * 10 + i64::from(c - b'0')))
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (y, mo, d) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    let (h, mi, sec) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&mo)
        || d < 1
        || d > days[(mo - 1) as usize]
        || h > 23
        || mi > 59
        || sec > 59
    {
        return None;
    }
    let mut i = 19;
    let mut nsec = 0i64;
    if b[i] == b'.' || b[i] == b',' {
        let start = i + 1;
        let mut j = start;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j == start {
            return None;
        }
        let digits = &s[start..j.min(start + 9)];
        nsec = format!("{digits:0<9}").parse().ok()?;
        i = j;
    }
    let off = match b.get(i)? {
        b'Z' if i + 1 == b.len() => 0,
        c @ (b'+' | b'-') if i + 6 == b.len() && b[i + 3] == b':' => {
            let (oh, om) = (num(i + 1, 2)?, num(i + 4, 2)?);
            if oh > 23 || om > 59 {
                return None;
            }
            let o = oh * 3600 + om * 60;
            if *c == b'-' { -o } else { o }
        }
        _ => return None,
    };
    let t = armada_spec::gotime::Time::date(
        y,
        mo,
        d,
        h,
        mi,
        sec,
        0,
        &armada_spec::gotime::Location::utc(),
    );
    Some(ts_of(t.unix - off, nsec))
}

fn logs(ctx: &mut Ctx<'_>, args: &[String], job: bool) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    let mut admin = ctx.admin()?;
    let since = ctx.str("since");
    let until = ctx.str("until");
    let limit = ctx.int("limit");
    let replica = if job {
        String::new()
    } else {
        ctx.str("replica")
    };
    let mut req = LogsRequest {
        app: args[0].clone(),
        follow: ctx.bool("follow"),
        tail: ctx.int("tail").clamp(0, 10000) as i32,
        replica: replica.clone(),
        run: if job { ctx.int("run") } else { 0 },
        container: ctx.str("container"),
        grep: ctx.str("grep"),
        limit: limit.clamp(0, 100_000) as i32,
        ..Default::default()
    };
    let now = now_nanos();
    if !since.is_empty() {
        req.since = Some(parse_when(&since, now).map_err(|e| format!("--since: {e}"))?);
    }
    if !until.is_empty() {
        req.until = Some(parse_when(&until, now).map_err(|e| format!("--until: {e}"))?);
    }
    if since.is_empty() && (!until.is_empty() || limit != 0) {
        return Err(
            "--until and --limit search the log history: give --since too, e.g. --since 1h".into(),
        );
    }
    if job && ctx.changed("task") {
        req.task = Some(ctx.int("task").clamp(-1, 1 << 20) as i32);
    }
    let stamps = ctx.bool("timestamps");
    let interrupt = crate::term::interrupts();
    let mut stream = crate::rpc!(ctx, admin, logs, req).map_err(rpc_err)?;
    loop {
        let next = ctx.block_on(async {
            tokio::select! {
                m = stream.message() => Some(m),
                () = interrupt.notified() => None,
            }
        });
        let e = match next {
            None => return Ok(()),
            Some(Ok(None)) => return Ok(()),
            Some(Err(s)) => return Err(rpc_err(s)),
            Some(Ok(Some(e))) => e,
        };
        let mut line = Vec::new();
        if stamps && let Some(t) = &e.time {
            line.extend(format!("{} ", rfc3339_millis(&go_time(Some(t), true))).into_bytes());
        }
        if replica.is_empty() && (!job || !since.is_empty()) && !e.replica.is_empty() {
            line.extend(format!("{} | ", e.replica).into_bytes());
        }
        line.extend(&e.data);
        let w: &mut dyn Write = if e.stream == Stream::Stderr as i32 {
            &mut *ctx.err
        } else {
            &mut *ctx.out
        };
        let _ = w.write_all(&line);
    }
}

// ---- events ----

/// How long the control plane keeps events.
const MAX_EVENTS_SINCE: i64 = 24 * go::HOUR;

/// App events [APP], or cluster events.
pub fn events_node(cluster: bool) -> Node {
    let mut o = output_flag(false);
    o.usage = "output format: text or json (one event per line)".to_string();
    let mut flags = vec![
        o,
        Flag::duration(
            "since",
            None,
            go::HOUR,
            "how far back to start (at most 24h)",
        ),
        Flag::bool("follow", Some('f'), false, "keep printing new events"),
    ];
    if cluster {
        flags.push(Flag::string(
            "node",
            None,
            "",
            "only events about this node and its replicas",
        ));
        Node::new("events", "Show what the cluster did: crashes, rollouts, lost nodes")
            .long("Show every event from the last hour (or --since, at most 24h), oldest first: replicas\nscheduled, started, crashed, moved, or removed; rollouts; nodes connected, lost,\ndrained, or removed; apps that cannot be placed; domains and certificates. With\n--node, only that node and its replicas. An event that repeats within 10 minutes is\ncounted rather than shown again.")
            .args(Args::No)
            .example("  armada cluster events                   # the last day\n  armada cluster events --node node1 -f   # one node, as it happens")
            .flags(flags)
            .run(cluster_events)
    } else {
        Node::new("events [APP]", "Show what happened to apps: crashes, rollouts, placement")
            .long("Show events from the last hour (or --since, at most 24h), oldest first: replicas scheduled,\nstarted, crashed, moved, or removed; rollouts started, completed, failed, or rolled back;\napps that cannot be placed. Without APP, the events of the space's apps (every\nspace's with -A). An event that repeats within 10 minutes is counted rather than\nshown again.")
            .args(Args::Max(1))
            .example("  armada app events              # what happened to the space's apps\n  armada app events api -f       # one app, as it happens\n  armada app events --since 2h")
            .flags(flags)
            .run(app_events)
    }
}

fn app_events(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    events(ctx, args, false)
}

fn cluster_events(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    events(ctx, args, true)
}

/// The time of day for today's events, with the date for older
/// ones.
fn event_time(t: Option<&armada_proto::google::protobuf::Timestamp>) -> String {
    let t = go_time(t, true);
    let now = go_time(Some(&ts_nanos(now_nanos())), true);
    let (a, b) = (t.civil(), now.civil());
    if (a.year, a.month, a.day) == (b.year, b.month, b.day) {
        clock(&t)
    } else {
        month_day_clock(&t)
    }
}

fn event_line(cols: [&str; 6]) -> String {
    format!(
        "{:<14}  {:<11}  {:<28}  {:<15}  {:>5}  {}\n",
        cols[0], cols[1], cols[2], cols[3], cols[4], cols[5]
    )
}

fn events(ctx: &mut Ctx<'_>, args: &[String], cluster: bool) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    let o = Output::of(ctx, false);
    o.check()?;
    let since = ctx.duration("since");
    if !(go::SECOND..=MAX_EVENTS_SINCE).contains(&since) {
        return Err(Error::Msg(format!(
            "--since must be between 1s and {}",
            go::format_duration(MAX_EVENTS_SINCE)
        )));
    }
    let req = EventsRequest {
        app: args.first().cloned().unwrap_or_default(),
        node: if cluster {
            ctx.str("node")
        } else {
            String::new()
        },
        since_seconds: since / go::SECOND,
        follow: ctx.bool("follow"),
    };
    let only_listed = !cluster && req.app.is_empty();
    let keep =
        |ctx: &Ctx<'_>, e: &EventInfo| !only_listed || (!e.app.is_empty() && ctx.listed(&e.app));
    let mut admin = ctx.admin()?;
    let interrupt = crate::term::interrupts();
    let res = crate::rpc!(ctx, admin, events, req);
    // The stream opens before the server answers, so the header shows
    // above an error the server sends (one with its headers), not above a
    // failure to reach it.
    let answered = match &res {
        Ok(_) => true,
        Err(s) => s.metadata().contains_key("content-type"),
    };
    if answered && !o.json() {
        ctx.print(&event_line([
            "TIME", "KIND", "OBJECT", "REASON", "COUNT", "MESSAGE",
        ]));
    }
    let mut stream = res.map_err(rpc_err)?;
    loop {
        let next = ctx.block_on(async {
            tokio::select! {
                m = stream.message() => Some(m),
                () = interrupt.notified() => None,
            }
        });
        let e = match next {
            None | Some(Ok(None)) => return Ok(()),
            Some(Err(s)) => return Err(rpc_err(s)),
            Some(Ok(Some(e))) => e,
        };
        if !keep(ctx, &e) {
            continue;
        }
        if o.json() {
            let s = serde_json::to_string(&e).map_err(|e| Error::Msg(e.to_string()))?;
            ctx.print(&format!("{s}\n"));
            continue;
        }
        let line = event_line([
            &event_time(e.last.as_ref()),
            &e.kind,
            &printable(&e.object),
            &printable(&e.reason),
            &e.count.to_string(),
            &printable(&e.message),
        ]);
        ctx.print(&line);
    }
}

// ---- exec ----

/// What exec runs without a command.
const DEFAULT_SHELL: &str = "/bin/sh";
const MAX_EXEC_ARGS: usize = 64;
const MAX_EXEC_ARG_LEN: usize = 4096;
/// runtime.MaxExecChunk: the most data one exec message carries.
const MAX_EXEC_CHUNK: usize = 32 << 10;

pub fn exec_node() -> Node {
    Node::new("exec APP [--replica R] [--container C] [-- COMMAND...]", "Run a command, or a shell, in one of an app's replicas")
        .long("Run a command in one of an app's replicas and exit with its exit code.\nWithout a command it opens a shell (/bin/sh).\n\nRuns in a ready replica of the serving revision unless --replica picks one;\n`armada replica list APP` shows the replicas and their containers. --container\nruns it in one of the replica's sidecars instead of the app's own container.\nWhen standard input is a terminal the command gets it and a terminal of its\nown; -i and -t (or -i=false, -t=false) say otherwise. The command runs with\nthe container's own user and security settings.\n\nExec is for diagnosis: changes made inside a container are lost when its\nreplica is replaced. Each session is recorded in the audit log with the\ncommand's name, not its arguments.")
        .example("  armada app exec api                        # a shell in one of api's replicas\n  armada app exec api -- env                 # run one command\n  armada app exec api --container log-ship   # a shell in a sidecar\n  armada app exec api --replica k3p9x -- ps  # in one replica (armada replica list api)")
        .args(Args::Custom(exec_args))
        .flag(Flag::string("replica", None, "", "run in this replica: its short name from armada replica list, or its ID"))
        .flag(Flag::string("container", None, "", "run in this sidecar instead of the app's own container"))
        .flag(Flag::bool("stdin", Some('i'), false, "pass standard input to the command (default: when it is a terminal)"))
        .flag(Flag::bool("tty", Some('t'), false, "allocate a terminal (default: when standard input and output are terminals)"))
        .run(exec)
}

/// runtime.CheckExecCommand: errors never repeat the arguments.
fn check_exec_command(cmd: &[String]) -> std::result::Result<(), String> {
    if cmd.is_empty() || cmd[0].is_empty() {
        return Err("command is empty".to_string());
    }
    if cmd.len() > MAX_EXEC_ARGS {
        return Err(format!("command has more than {MAX_EXEC_ARGS} arguments"));
    }
    for (i, a) in cmd.iter().enumerate() {
        if a.len() > MAX_EXEC_ARG_LEN {
            return Err(format!(
                "argument {i} is longer than {MAX_EXEC_ARG_LEN} bytes"
            ));
        }
        if a.contains('\0') {
            return Err(format!("argument {i} contains a NUL byte"));
        }
    }
    Ok(())
}

fn exec_args(ctx: &Ctx<'_>, args: &[String]) -> std::result::Result<(), ArgError> {
    let dash = ctx.flags.args_len_at_dash;
    if args.is_empty() {
        return Err(ArgError::Own(arg_error(ctx.tree, ctx.cmd, args)));
    }
    if dash == -1 && args.len() > 1 {
        // Never repeat the command: its arguments may hold a secret.
        return Err(ArgError::Own(
            "put -- before the command: armada app exec APP -- COMMAND".into(),
        ));
    }
    if dash > 1 {
        return Err(ArgError::Own("give one app before --".into()));
    }
    if dash == 0 {
        return Err(ArgError::Own("missing APP before --".into()));
    }
    if args.len() == 1 {
        return Ok(());
    }
    check_exec_command(&args[1..]).map_err(ArgError::Own)
}

fn input(i: exec_input::Input) -> ExecClientMessage {
    ExecClientMessage {
        msg: Some(exec_client_message::Msg::Input(ExecInput {
            input: Some(i),
        })),
    }
}

fn term_size(fd: i32) -> Option<TermSize> {
    crate::term::size(fd).map(|(cols, rows)| TermSize { rows, cols })
}

fn exec(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    let mut command: Vec<String> = args[1..].to_vec();
    if command.is_empty() {
        command = vec![DEFAULT_SHELL.to_string()];
    }
    let in_term = is_terminal(0);
    let out_term = is_terminal(1);
    // A person at a terminal gets an interactive session unless a flag
    // says otherwise (ADR 0052).
    let stdin = if ctx.changed("stdin") {
        ctx.bool("stdin")
    } else {
        in_term
    };
    let tty = if ctx.changed("tty") {
        ctx.bool("tty")
    } else {
        in_term && out_term
    };
    if tty && (!in_term || !out_term) {
        return Err(
            "-t needs a terminal on standard input and output; leave it out to run without one"
                .into(),
        );
    }
    let mut admin = ctx.admin()?;
    let (tx, rx) = tokio::sync::mpsc::channel::<ExecClientMessage>(16);
    let mut start = ExecStart {
        app: args[0].clone(),
        replica: ctx.str("replica"),
        cmd: command,
        tty,
        stdin,
        size: None,
        container: ctx.str("container"),
    };
    if tty {
        start.size = term_size(0);
    }
    let first_msg = ExecClientMessage {
        msg: Some(exec_client_message::Msg::Start(start)),
    };
    if tx.try_send(first_msg).is_err() {
        return Err("server did not start the command".into());
    }
    let interrupt = crate::term::interrupts();
    let rx = tokio_stream::wrappers::ReceiverStream::new(rx);
    let mut stream = crate::rpc!(ctx, admin, exec, rx).map_err(rpc_err)?;
    let canceled = || Error::Msg("context canceled".to_string());
    // The first message names the replica, or the error that kept the
    // command from starting.
    let first = ctx.block_on(async {
        tokio::select! {
            m = stream.message() => Some(m),
            () = interrupt.notified() => None,
        }
    });
    let first = match first {
        None => return Err(canceled()),
        Some(Err(s)) => return Err(rpc_err(s)),
        Some(Ok(None)) => return Err("EOF".into()),
        Some(Ok(Some(m))) => m,
    };
    match first.msg {
        Some(exec_server_message::Msg::Replica(r)) if !r.is_empty() => {}
        _ => return Err("server did not start the command".into()),
    }
    let _raw = if tty {
        let raw = crate::term::make_raw(0).map_err(|e| {
            Error::Msg(format!(
                "terminal raw mode: {}",
                armada_fsutil::errno_text(&e)
            ))
        })?;
        let resize = tx.clone();
        crate::term::on_window_change(move || {
            if let Some(size) = term_size(0) {
                let _ = resize.blocking_send(input(exec_input::Input::Resize(size)));
            }
        });
        Some(raw)
    } else {
        None
    };
    if stdin {
        let feed = tx.clone();
        std::thread::spawn(move || {
            // fd 0 itself: the process's stdin, which nothing else reads.
            // SAFETY: the File is never dropped, so fd 0 stays open.
            let mut f = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(0) });
            let mut buf = vec![0u8; MAX_EXEC_CHUNK];
            loop {
                match std::io::Read::read(&mut *f, &mut buf) {
                    Ok(0) => {
                        let _ = feed.blocking_send(input(exec_input::Input::CloseStdin(true)));
                        return;
                    }
                    Ok(n) => {
                        if feed
                            .blocking_send(input(exec_input::Input::Stdin(buf[..n].to_vec())))
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => return,
                }
            }
        });
    }
    drop(tx);
    loop {
        let next = ctx.block_on(async {
            tokio::select! {
                m = stream.message() => Some(m),
                () = interrupt.notified() => None,
            }
        });
        let m = match next {
            None => return Err(canceled()),
            Some(Err(s)) => return Err(rpc_err(s)),
            Some(Ok(None)) => {
                return Err("server ended the session without an exit code".into());
            }
            Some(Ok(Some(m))) => m,
        };
        match m.msg {
            Some(exec_server_message::Msg::Stdout(b)) => {
                let _ = ctx.out.write_all(&b);
            }
            Some(exec_server_message::Msg::Stderr(b)) => {
                let _ = ctx.err.write_all(&b);
            }
            Some(exec_server_message::Msg::ExitCode(c)) => {
                if c != 0 {
                    return Err(Error::Exit(c));
                }
                return Ok(());
            }
            _ => {}
        }
    }
}

// ---- top ----

pub fn app_top_node() -> Node {
    Node::new("top [APP]", "Show the CPU and memory apps and their replicas use")
        .long("Show the CPU and memory replicas use, from samples their nodes take every 10 seconds.\n\nWithout arguments it lists the space's apps (every space's with -A); with APP, that\napp's replicas; with --spaces, every space, with the requests it received and the\nbytes it sent since the control plane's leader started counting.\nCPU is shown as used/reserved and memory as used/limit; \"-\" means no recent sample\n(the replica is not running, or its node's runtime cannot measure containers).")
        .args(Args::Max(1))
        .example("  armada app top              # every app of the space\n  armada app top api          # one app, per replica\n  armada app top --spaces     # per space, with volumes, requests, and egress")
        .flag(output_flag(false))
        .flag(Flag::bool("spaces", None, false, "list spaces instead of apps"))
        .run(app_top)
}

pub fn node_top_node() -> Node {
    Node::new(
        "top",
        "Show the CPU and memory each node's replicas use and reserve",
    )
    .args(Args::No)
    .example("  armada node top     # CPU and memory used and reserved per node")
    .flag(output_flag(false))
    .run(node_top)
}

fn top(ctx: &mut Ctx<'_>, req: TopRequest) -> Result<TopResponse> {
    let mut admin = ctx.admin()?;
    crate::rpc!(ctx, admin, top, req).map_err(rpc_err)
}

fn millis(m: i64) -> String {
    format!("{m}m")
}

fn app_top(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let mut args = args.to_vec();
    ctx.qualify(&mut args)?;
    let o = Output::of(ctx, false);
    o.check()?;
    let spaces = ctx.bool("spaces");
    if spaces && args.len() == 1 {
        return Err("--spaces lists every space; leave out APP".into());
    }
    let req = TopRequest {
        app: args.first().cloned().unwrap_or_default(),
    };
    let app = req.app.clone();
    let mut resp = top(ctx, req)?;
    resp.nodes.clear();
    if spaces {
        resp.replicas.clear();
    } else {
        resp.spaces.clear();
        resp.counted_since = None;
        if app.is_empty() {
            resp.replicas.retain(|r| ctx.listed(&r.app));
        }
    }
    if o.json() {
        return print_json(ctx, &resp);
    }
    let mut tw = TabWriter::new(0, 2);
    if spaces {
        tw.write("SPACE\tREPLICAS\tCPU\tMEMORY\tVOLUMES\tREQUESTS\tEGRESS\n");
        for p in &resp.spaces {
            let (cpu, mem) = if p.measured > 0 {
                (millis(p.cpu_millis), used_bytes(p.memory_bytes))
            } else {
                ("-".to_string(), "-".to_string())
            };
            tw.write(&format!(
                "{}\t{}\t{}/{}\t{}/{}\t{}\t{}\t{}\n",
                p.name,
                p.replicas,
                cpu,
                millis(p.cpu_reserved_millis),
                mem,
                human_bytes(p.memory_reserved_bytes),
                used_bytes(p.volume_bytes),
                p.requests,
                used_bytes(p.egress_bytes)
            ));
        }
    } else if !app.is_empty() {
        tw.write("REPLICA\tNODE\tSTATE\tCPU\tMEMORY\n");
        for r in &resp.replicas {
            let (cpu, mem) = if r.measured {
                (millis(r.cpu_millis), used_bytes(r.memory_bytes))
            } else {
                ("-".to_string(), "-".to_string())
            };
            tw.write(&format!(
                "{}\t{}\t{}\t{}/{}\t{}/{}\n",
                r.id,
                dash(&r.node_id),
                dash(&r.state),
                cpu,
                millis(r.cpu_reserved_millis),
                mem,
                human_bytes(r.memory_limit_bytes)
            ));
        }
    } else {
        // Each app's replicas summed, in the order they come.
        struct AppTop {
            name: String,
            replicas: i64,
            measured: i64,
            cpu: i64,
            cpu_reserved: i64,
            memory: i64,
            memory_limit: i64,
        }
        let mut apps: Vec<AppTop> = Vec::new();
        for r in &resp.replicas {
            let i = match apps.iter().position(|a| a.name == r.app) {
                Some(i) => i,
                None => {
                    apps.push(AppTop {
                        name: r.app.clone(),
                        replicas: 0,
                        measured: 0,
                        cpu: 0,
                        cpu_reserved: 0,
                        memory: 0,
                        memory_limit: 0,
                    });
                    apps.len() - 1
                }
            };
            let a = &mut apps[i];
            a.replicas += 1;
            a.cpu_reserved += r.cpu_reserved_millis;
            a.memory_limit += r.memory_limit_bytes;
            if r.measured {
                a.measured += 1;
                a.cpu += r.cpu_millis;
                a.memory += r.memory_bytes;
            }
        }
        tw.write("APP\tMEASURED\tCPU\tMEMORY\n");
        for a in &apps {
            let (cpu, mem) = if a.measured > 0 {
                (millis(a.cpu), used_bytes(a.memory))
            } else {
                ("-".to_string(), "-".to_string())
            };
            tw.write(&format!(
                "{}\t{}/{}\t{}/{}\t{}/{}\n",
                a.name,
                a.measured,
                a.replicas,
                cpu,
                millis(a.cpu_reserved),
                mem,
                human_bytes(a.memory_limit)
            ));
        }
    }
    let out = tw.finish();
    ctx.print(&out);
    Ok(())
}

fn node_top(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let resp = top(ctx, TopRequest::default())?;
    if o.json() {
        let only = TopResponse {
            nodes: resp.nodes,
            ..Default::default()
        };
        return print_json(ctx, &only);
    }
    let mut tw = TabWriter::new(0, 2);
    tw.write("NODE\tREPLICAS\tCPU USED\tCPU RESERVED\tMEMORY USED\tMEMORY RESERVED\n");
    for n in &resp.nodes {
        let (cpu, mem) = if n.measured {
            (millis(n.cpu_millis), used_bytes(n.memory_bytes))
        } else {
            ("-".to_string(), "-".to_string())
        };
        tw.write(&format!(
            "{}\t{}\t{}\t{}/{}\t{}\t{}/{}\n",
            n.id,
            n.replicas,
            cpu,
            millis(n.cpu_reserved_millis),
            millis(n.cpu_allocatable_millis),
            mem,
            used_bytes(n.memory_reserved_bytes),
            human_bytes(n.memory_allocatable_bytes)
        ));
    }
    let out = tw.finish();
    ctx.print(&out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn when() {
        let now: i128 = 1_800_000_000 * 1_000_000_000;
        let secs = |s: &str| parse_when(s, now).map(|t| t.seconds);
        assert_eq!(secs("2h"), Ok(1_800_000_000 - 7200));
        assert_eq!(secs("3d"), Ok(1_800_000_000 - 3 * 86400));
        assert_eq!(
            secs("2026-11-13T09:00:00+07:00"),
            secs("2026-11-13T02:00:00Z")
        );
        assert_eq!(secs("1970-01-02T00:00:00Z"), Ok(86400));
        assert!(
            parse_when("9999d", now)
                .unwrap_err()
                .contains("not a number of days")
        );
        assert!(parse_when("-1h", now).unwrap_err().contains("is negative"));
        assert!(parse_when("2026-02-30T00:00:00Z", now).is_err());
        let t = parse_when("2026-11-13T10:00:00.5Z", now).unwrap();
        assert_eq!(t.nanos, 500_000_000);
    }

    #[test]
    fn exec_commands() {
        let v =
            |a: &[&str]| check_exec_command(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert!(v(&["ls"]).is_ok());
        assert_eq!(v(&[""]).unwrap_err(), "command is empty");
        assert_eq!(
            v(&["echo", "a\0b"]).unwrap_err(),
            "argument 1 contains a NUL byte"
        );
    }
}

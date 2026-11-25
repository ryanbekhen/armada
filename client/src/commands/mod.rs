//! The armada command tree (Go's NewRootCommand) and what its commands
//! share: the space they work in, output formats, and the texts tables use.

pub mod access;
pub mod app;
pub mod cluster;
pub mod deploy;
pub mod jobs;
pub mod node;
pub mod replica;
pub mod secret;
pub mod space;
pub mod streams;
pub mod version;
pub mod volume;

use armada_spec as spec;
use armada_spec::go;
use serde::Serialize;

use crate::cli::flags::Flag;
use crate::cli::{Ctx, Error, Group, Node, Result, Tree};
use crate::rpc::{Admin, printable};

const ROOT_LONG: &str = "armada manages apps, jobs, and the cluster they run on. Every command is
`armada NOUN VERB`, such as `armada app deploy` or `armada secret set`. It
talks to the control plane with the credentials in --config and needs no
root. Machines run `armadad`. Tab completes names from the cluster:
see `armada completion bash --help` (or zsh, fish).";

/// NewRootCommand.
pub fn root() -> Tree {
    let mut root = Node::new("armada", "Manage apps on an Armada cluster")
        .long(ROOT_LONG)
        .noun();
    root.persistent = vec![
        Flag::string(
            "config",
            None,
            &crate::config::default_path(),
            "client config file",
        ),
        Flag::string(
            "space",
            None,
            &std::env::var("ARMADA_SPACE").unwrap_or_default(),
            "space to work in",
        ),
        Flag::bool("all-spaces", Some('A'), false, "every space"),
    ];
    let mut t = Tree::new(root);
    t.verb_hints = verb_hint;
    t.groups = vec![
        Group {
            id: "apps",
            title: "Apps:",
        },
        Group {
            id: "cluster",
            title: "Cluster:",
        },
        Group {
            id: "access",
            title: "Access:",
        },
        Group {
            id: "monitoring",
            title: "Monitoring:",
        },
    ];
    type Add = fn(&mut Tree) -> usize;
    let groups: [(&str, Vec<Add>); 4] = [
        (
            "apps",
            vec![
                app::add_app,
                app::add_revision,
                replica::add,
                jobs::add_job,
                jobs::add_run,
                secret::add,
                volume::add_volume,
                volume::add_snapshot,
                cluster::add_domain,
            ],
        ),
        (
            "cluster",
            vec![
                cluster::add_cluster,
                node::add_node,
                node::add_server,
                space::add,
            ],
        ),
        (
            "access",
            vec![access::add_user, access::add_service, access::add_role],
        ),
        (
            "monitoring",
            vec![access::add_alert, access::add_metrics, version::add],
        ),
    ];
    for (id, adds) in groups {
        for add in adds {
            let i = add(&mut t);
            t.nodes[i].group = id.to_string();
        }
    }
    t
}

/// The root's persistent pre-run: resolveSpace.
pub fn pre_run(ctx: &mut Ctx<'_>) -> Result {
    resolve_space(ctx).map_err(Error::Msg)
}

/// resolveSpace: the client config's space when neither --space nor
/// ARMADA_SPACE named one.
pub fn resolve_space(ctx: &mut Ctx<'_>) -> std::result::Result<(), String> {
    if ctx.g.space.is_empty()
        && let Ok(cc) = crate::config::load(&ctx.g.config_path)
    {
        ctx.g.space = cc.space;
    }
    if ctx.g.space == spec::validate::DEFAULT_SPACE {
        ctx.g.space.clear();
    }
    if !ctx.g.space.is_empty() && !spec::validate::valid_space(&ctx.g.space) {
        return Err(format!("invalid space {}", go::quote(&ctx.g.space)));
    }
    Ok(())
}

/// verbHints: what to type for verbs Armada has not got.
pub fn verb_hint(key: &str) -> Option<&'static str> {
    Some(match key {
        "app scale" => "The replica count is part of the spec: armada app deploy APP --min N",
        "app create" => "armada app deploy APP creates an app (--new refuses one that exists)",
        "app update" => "armada app deploy APP changes an app",
        "app revision" => "armada revision list APP",
        "app replica" => "armada replica list APP",
        "job create" => "armada job deploy JOB creates a job",
        "job update" => "armada job deploy JOB changes a job",
        "job run" => "armada job start JOB",
        "secret import" => {
            "armada secret create SECRET --from-env-file FILE, or secret set SECRET --from-env-file FILE"
        }
        "secret get" => {
            "Armada never prints a secret's value; armada secret show SECRET lists its keys"
        }
        _ => return None,
    })
}

impl Ctx<'_> {
    /// scope: the space a command works in.
    pub fn scope(&self) -> String {
        if self.g.space.is_empty() {
            spec::validate::DEFAULT_SPACE.to_string()
        } else {
            self.g.space.clone()
        }
    }

    /// app: the ID of an app or job named name in the space.
    pub fn app_id(&self, name: &str) -> std::result::Result<String, String> {
        if name.contains('.') {
            let Some((p, _)) = spec::validate::split_app_id(name) else {
                return Err(format!(
                    "invalid name {}: want NAME, or NAME.SPACE for one of another space",
                    go::quote(name)
                ));
            };
            if !self.g.space.is_empty() && self.g.space != p {
                return Err(format!("{name} belongs to space {p}, not {}", self.g.space));
            }
            return Ok(name.to_string());
        }
        Ok(spec::validate::app_id(&self.g.space, name))
    }

    /// qualify: args[0] replaced with its ID.
    pub fn qualify(&self, args: &mut [String]) -> Result {
        if let Some(a) = args.first_mut() {
            *a = self.app_id(a).map_err(Error::Msg)?;
        }
        Ok(())
    }

    /// listed: whether a listing shows the app with ID id.
    pub fn listed(&self, id: &str) -> bool {
        if self.g.all_spaces {
            return true;
        }
        spec::validate::split_app_id(id).is_some_and(|(p, _)| p == self.scope())
    }

    /// dialAdmin.
    pub fn admin(&self) -> Result<Admin> {
        let _rt = self.runtime().enter();
        Admin::dial(&self.g.config_path).map_err(Error::Msg)
    }
}

/// -o of a command that prints data.
pub struct Output {
    pub format: String,
    pub yaml: bool,
}

pub const OUTPUT_TEXT: &str = "text";
pub const OUTPUT_JSON: &str = "json";
pub const OUTPUT_YAML: &str = "yaml";

/// addOutput's flag.
pub fn output_flag(yaml: bool) -> Flag {
    let usage = if yaml {
        "output format: text, json, or yaml (the spec, as a file holds it)"
    } else {
        "output format: text or json"
    };
    Flag::string("output", Some('o'), OUTPUT_TEXT, usage)
}

impl Output {
    pub fn of(ctx: &Ctx<'_>, yaml: bool) -> Output {
        Output {
            format: ctx.str("output"),
            yaml,
        }
    }

    pub fn check(&self) -> Result {
        let f = self.format.as_str();
        if f == OUTPUT_TEXT || f == OUTPUT_JSON || (self.yaml && f == OUTPUT_YAML) {
            return Ok(());
        }
        if self.yaml {
            return Err(Error::Msg(format!(
                "unsupported output format {} (want \"text\", \"json\", or \"yaml\")",
                go::quote(f)
            )));
        }
        check_output(f)
    }

    pub fn json(&self) -> bool {
        self.format == OUTPUT_JSON
    }
}

/// checkOutput.
pub fn check_output(f: &str) -> Result {
    if f != OUTPUT_TEXT && f != OUTPUT_JSON {
        return Err(Error::Msg(format!(
            "unsupported output format {} (want \"text\" or \"json\")",
            go::quote(f)
        )));
    }
    Ok(())
}

/// printJSON: protojson, indented by two spaces.
pub fn print_json<T: Serialize>(ctx: &mut Ctx<'_>, m: &T) -> Result {
    let s = serde_json::to_string_pretty(m).map_err(|e| Error::Msg(e.to_string()))?;
    ctx.print(&s);
    ctx.print("\n");
    Ok(())
}

/// The status of a failed call, as the command prints it.
pub fn rpc_err(s: tonic::Status) -> Error {
    Error::Msg(crate::rpc::rpc_error(&s))
}

pub fn dash(s: &str) -> String {
    if s.is_empty() {
        "-".to_string()
    } else {
        s.to_string()
    }
}

/// The time now, in Unix nanoseconds.
pub fn now_nanos() -> i128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0)
}

fn ts_nanos(t: &armada_proto::google::protobuf::Timestamp) -> i128 {
    i128::from(t.seconds) * 1_000_000_000 + i128::from(t.nanos)
}

/// The nanoseconds from t to now, as Go's Sub saturates them.
pub fn since(t: &armada_proto::google::protobuf::Timestamp, now: i128) -> i64 {
    clamp(now - ts_nanos(t))
}

/// The nanoseconds from now to t.
pub fn until(t: &armada_proto::google::protobuf::Timestamp, now: i128) -> i64 {
    clamp(ts_nanos(t) - now)
}

fn clamp(d: i128) -> i64 {
    d.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

/// humanDuration: 42s, 5m, 3h, 2d.
pub fn human_duration(d: i64) -> String {
    let d = d.max(0);
    if d < go::MINUTE {
        return format!("{}s", d / go::SECOND);
    }
    if d < go::HOUR {
        return format!("{}m", d / go::MINUTE);
    }
    if d < 48 * go::HOUR {
        return format!("{}h", d / go::HOUR);
    }
    format!("{}d", d / (24 * go::HOUR))
}

/// ago: how long ago t was, or "-".
pub fn ago(t: Option<&armada_proto::google::protobuf::Timestamp>, now: i128) -> String {
    match t {
        None => "-".to_string(),
        Some(t) => format!("{} ago", human_duration(since(t, now))),
    }
}

/// Duration.Round(time.Second).
pub fn round_second(d: i64) -> i64 {
    let m = go::SECOND;
    let r = d % m;
    if d < 0 {
        let r = -r;
        if r + r < m {
            return d + r;
        }
        return d.checked_sub(m - r).unwrap_or(i64::MIN);
    }
    if r + r < m {
        return d - r;
    }
    d.checked_add(m - r).unwrap_or(i64::MAX)
}

/// A timestamp in the local zone.
pub fn local_civil(t: &armada_proto::google::protobuf::Timestamp) -> spec::gotime::Civil {
    let loc = spec::gotime::load_location("Local").unwrap_or_else(spec::gotime::Location::utc);
    spec::gotime::Time {
        unix: t.seconds,
        nsec: i64::from(t.nanos),
        loc,
    }
    .civil()
}

/// Format(time.DateTime) in the local zone.
pub fn date_time(t: Option<&armada_proto::google::protobuf::Timestamp>) -> String {
    let zero = armada_proto::google::protobuf::Timestamp {
        seconds: 0,
        nanos: 0,
    };
    let c = local_civil(t.unwrap_or(&zero));
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    )
}

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/// Format("Mon 15:04") in the local zone.
pub fn day_clock(t: &armada_proto::google::protobuf::Timestamp) -> String {
    let c = local_civil(t);
    format!(
        "{} {:02}:{:02}",
        WEEKDAYS[c.weekday.rem_euclid(7) as usize],
        c.hour,
        c.minute
    )
}

/// choiceList: names for an error, at most 20.
pub fn choice_list(names: &[String]) -> String {
    let mut names = names.to_vec();
    names.sort();
    names.dedup();
    if names.len() > 20 {
        return format!("{}, and {} more", names[..20].join(", "), names.len() - 20);
    }
    names.join(", ")
}

/// The text of a message for a table: printable, else "-".
pub fn dash_printable(s: &str) -> String {
    dash(&printable(s))
}

/// A protobuf timestamp as a time.Time, in the local zone or UTC
/// (AsTime().Local() or AsTime()); none reads as the Unix epoch.
pub fn go_time(
    t: Option<&armada_proto::google::protobuf::Timestamp>,
    local: bool,
) -> spec::gotime::Time {
    let (unix, nsec) = t.map_or((0, 0), |t| (t.seconds, i64::from(t.nanos)));
    let loc = if local {
        spec::gotime::load_location("Local").unwrap_or_else(spec::gotime::Location::utc)
    } else {
        spec::gotime::Location::utc()
    };
    spec::gotime::Time { unix, nsec, loc }
}

/// The timestamp of Unix seconds.
pub fn unix_ts(seconds: i64) -> armada_proto::google::protobuf::Timestamp {
    armada_proto::google::protobuf::Timestamp { seconds, nanos: 0 }
}

/// Z07:00 of a layout: Z for UTC, else the offset.
fn zone_colon(t: &spec::gotime::Time) -> String {
    let off = t.loc.offset(t.unix);
    if off == 0 {
        return "Z".to_string();
    }
    let (sign, a) = if off < 0 { ('-', -off) } else { ('+', off) };
    format!("{sign}{:02}:{:02}", a / 3600, a % 3600 / 60)
}

/// Format(time.RFC3339).
pub fn rfc3339(t: &spec::gotime::Time) -> String {
    let c = t.civil();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{}",
        c.year,
        c.month,
        c.day,
        c.hour,
        c.minute,
        c.second,
        zone_colon(t)
    )
}

/// Format("2006-01-02T15:04:05.000Z07:00").
pub fn rfc3339_millis(t: &spec::gotime::Time) -> String {
    let c = t.civil();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}{}",
        c.year,
        c.month,
        c.day,
        c.hour,
        c.minute,
        c.second,
        t.nsec / 1_000_000,
        zone_colon(t)
    )
}

/// Format(time.DateOnly).
pub fn date_only(t: &spec::gotime::Time) -> String {
    let c = t.civil();
    format!("{:04}-{:02}-{:02}", c.year, c.month, c.day)
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Format("Jan 02 15:04:05").
pub fn month_day_clock(t: &spec::gotime::Time) -> String {
    let c = t.civil();
    format!(
        "{} {:02} {:02}:{:02}:{:02}",
        MONTHS[(c.month - 1).clamp(0, 11) as usize],
        c.day,
        c.hour,
        c.minute,
        c.second
    )
}

/// Format("15:04:05").
pub fn clock(t: &spec::gotime::Time) -> String {
    let c = t.civil();
    format!("{:02}:{:02}:{:02}", c.hour, c.minute, c.second)
}

/// humanBytes: 512Mi, 1.5Gi, or "-" for none.
pub fn human_bytes(b: i64) -> String {
    if b <= 0 {
        return "-".to_string();
    }
    if b >= 1 << 30 {
        return format!("{:.1}Gi", b as f64 / f64::from(1u32 << 30));
    }
    format!("{}Mi", b >> 20)
}

/// usedBytes: memory in use, where 0 is a value rather than unknown.
pub fn used_bytes(b: i64) -> String {
    if b <= 0 {
        return "0Mi".to_string();
    }
    human_bytes(b)
}

/// diskBytes: 512B, 4.0Ki, 1.2Gi.
pub fn disk_bytes(b: i64) -> String {
    const UNIT: f64 = 1024.0;
    if b < 1024 {
        return format!("{b}B");
    }
    let mut v = b as f64 / UNIT;
    let mut i = 0;
    while v >= UNIT && i < 4 {
        v /= UNIT;
        i += 1;
    }
    format!("{v:.1}{}i", ["K", "M", "G", "T", "P"][i])
}

/// The text of an error reading or writing a file, as Go's os package
/// words it.
pub fn path_error(op: &str, path: &str, e: &std::io::Error) -> String {
    format!("{op} {path}: {}", armada_fsutil::errno_text(e))
}

/// readTokenArg and readSecretArg: a file (mode 0600), or "-" for at most
/// 64 KiB of stdin; trimmed.
pub fn read_token_arg(ctx: &mut Ctx<'_>, flag: &str, arg: &str) -> Result<Vec<u8>> {
    let b = if arg == "-" {
        let mut b = Vec::new();
        std::io::Read::read_to_end(&mut std::io::Read::take(&mut *ctx.stdin, 64 << 10), &mut b)
            .map_err(|e| Error::Msg(format!("{flag}: {}", armada_fsutil::errno_text(&e))))?;
        b
    } else {
        armada_fsutil::read_private_file(std::path::Path::new(arg))
            .map_err(|e| Error::Msg(format!("{flag}: {e}")))?
    };
    let space = |c: &u8| matches!(c, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ');
    let start = b.iter().position(|c| !space(c)).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !space(c)).map_or(start, |i| i + 1);
    Ok(b[start..end].to_vec())
}

/// Whether file descriptor fd is a terminal (term.IsTerminal).
pub fn is_terminal(fd: i32) -> bool {
    // SAFETY: isatty only reads the descriptor's state.
    unsafe { libc::isatty(fd) == 1 }
}

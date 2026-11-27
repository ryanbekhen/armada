//! app deploy and job deploy: a
//! spec from flags or a file, created or changed, with --diff and --new.

use std::collections::HashMap;
use std::io::Read;

use armada_proto::armada::v1::{DeployRequest, GetAppSpecRequest};
use armada_spec as spec;
use armada_spec::go;
use spec::{
    App, Duration, EnvFrom, EnvFromSecret, EnvVar, IPRule, Ingress, Probe, Probes, Scale, ScaleRule,
};
use tonic::Code;

use super::app::{WaitFlags, wait_flags, wait_rollout};
use super::rpc_err;
use crate::cli::flags::Flag;
use crate::cli::{Ctx, Error, Result};
use crate::rpc;

/// Flags that change an app's spec, and a job's.
const APP_SPEC_FLAGS: [&str; 33] = [
    "image",
    "command",
    "args",
    "env",
    "secret-env",
    "remove-env",
    "env-from-secrets",
    "env-from",
    "cpu",
    "memory",
    "registry-user",
    "registry-secret",
    "port",
    "ingress",
    "protocol",
    "domain",
    "remove-domain",
    "ip-allow",
    "ip-deny",
    "no-ip-rules",
    "sticky",
    "cors-origin",
    "no-cors",
    "dns-token-secret",
    "no-dns",
    "min",
    "max",
    "no-autoscale",
    "idle-after",
    "scale-cpu",
    "scale-memory",
    "scale-http",
    "health-path",
];
const JOB_SPEC_FLAGS: [&str; 19] = [
    "image",
    "command",
    "args",
    "env",
    "secret-env",
    "remove-env",
    "env-from-secrets",
    "env-from",
    "cpu",
    "memory",
    "registry-user",
    "registry-secret",
    "schedule",
    "time-zone",
    "timeout",
    "retries",
    "concurrency",
    "tasks",
    "parallelism",
];

fn kind_word(job: bool) -> &'static str {
    if job { "job" } else { "app" }
}

/// The flags of app deploy or job deploy (specFlags.register and
/// registerDeploy).
pub fn flags(job: bool) -> (Vec<Flag>, Vec<Vec<&'static str>>) {
    let k = kind_word(job);
    let mut f = vec![
        Flag::string("file", Some('f'), "", "spec file, or - for stdin"),
        Flag::string(
            "vars",
            None,
            "",
            "with --file: file of NAME=VALUE lines for ${NAME} in the spec",
        ),
        Flag::string_array(
            "var",
            None,
            "with --file: NAME=VALUE for ${NAME} in the spec (repeatable; wins over --vars)",
        ),
        Flag::string("image", None, "", "container image"),
        Flag::string_array(
            "command",
            None,
            "command, replacing the image's entrypoint: one word per flag, kept as written (repeat it; \"\" clears)",
        ),
        Flag::string_array(
            "args",
            None,
            "argument of the command: one per flag, kept as written (repeat it; \"\" clears)",
        ),
        Flag::string_array("env", None, "environment variable NAME=VALUE (repeatable)"),
        Flag::string_array(
            "secret-env",
            None,
            &format!(
                "environment variable from a secret: NAME=SECRET/KEY, or NAME=KEY of the {k}'s own secret (repeatable)"
            ),
        ),
        Flag::string_array(
            "remove-env",
            None,
            "remove an environment variable (repeatable)",
        ),
        Flag::bool(
            "env-from-secrets",
            None,
            false,
            &format!(
                "give every key of the {k}'s own secret as a variable (database-url becomes DATABASE_URL)"
            ),
        ),
        Flag::string_array(
            "env-from",
            None,
            "give every key of a secret of the space as a variable (repeatable; replaces the list; \"\" clears)",
        ),
        Flag::string(
            "cpu",
            None,
            "",
            "CPU reserved and its limit, e.g. 250m or 1",
        ),
        Flag::string("memory", None, "", "memory limit, e.g. 256Mi"),
        Flag::string(
            "registry-user",
            None,
            "",
            "user name for a private registry (the image's)",
        ),
        Flag::string(
            "registry-secret",
            None,
            "",
            "secret holding the private registry's password",
        ),
    ];
    let mut exclusive = Vec::new();
    if job {
        f.extend([
            Flag::string("schedule", None, "", "cron schedule that starts runs, e.g. \"0 3 * * *\" (empty to clear)"),
            Flag::string("time-zone", None, "", "time zone of the schedule, e.g. Asia/Jakarta"),
            Flag::duration("timeout", None, 0, "how long one attempt may run"),
            Flag::int("retries", None, 0, "attempts after a failed one"),
            Flag::string("concurrency", None, "", "when a run is due while one runs: forbid or replace"),
            Flag::int("tasks", None, 0, "split each run into this many tasks, each told its index in ARMADA_JOB_TASK (0 or 1 for one)"),
            Flag::int("parallelism", None, 0, "how many tasks of a run run at once (0 for all)"),
        ]);
    } else {
        f.extend([
            Flag::int("port", None, 0, "port the app listens on"),
            Flag::string("ingress", None, "", "who reaches the app: external, internal, or none"),
            Flag::string("protocol", None, "", "http (default) or tcp: a tcp app is internal only, reached by apps of its space at <app>.internal:<port>"),
            Flag::string_array("domain", None, "custom domain (repeatable)"),
            Flag::string_array("remove-domain", None, "remove a custom domain (repeatable)"),
            Flag::string_array("ip-allow", None, "RANGE[,name=NAME][,description=TEXT]: only clients from this address or prefix reach the app from outside (repeatable; replaces the list)"),
            Flag::string_array("ip-deny", None, "RANGE[,name=NAME][,description=TEXT]: clients from this address or prefix cannot reach the app from outside (repeatable; replaces the list)"),
            Flag::bool("no-ip-rules", None, false, "let every client reach the app again"),
            Flag::bool("sticky", None, false, "keep each client on the replica that answered it first (--sticky=false to stop)"),
            Flag::string_array("cors-origin", None, "origin browsers may call the app from, such as https://app.example.com, or * (repeatable; replaces the origins; methods, headers, and the rest in the spec file)"),
            Flag::bool("no-cors", None, false, "remove the app's CORS policy"),
            Flag::string("dns-token-secret", None, "", "app secret holding a Cloudflare API token: the custom domains get certificates through DNS-01 with it instead of HTTP-01"),
            Flag::bool("no-dns", None, false, "custom domains get certificates through HTTP-01 again"),
            Flag::int("min", None, 0, "replicas to run: a fixed count, or the fewest with a --scale rule"),
            Flag::int("max", None, 0, "most replicas, with a --scale rule"),
            Flag::bool("no-autoscale", None, false, "stop autoscaling: drop the scale rules and run --min (or the current minimum) replicas"),
            Flag::duration("idle-after", None, 0, "with --min 0: stop the last replica after this long without a request, 1m to 24h (0 for the default, 15m)"),
            Flag::int("scale-cpu", None, 0, "autoscale to this percent of reserved CPU"),
            Flag::int("scale-memory", None, 0, "autoscale to this percent of the memory limit"),
            Flag::int("scale-http", None, 0, "autoscale to this many concurrent requests per replica"),
            Flag::string("health-path", None, "", "HTTP path that answers when the app is ready (empty to clear)"),
        ]);
        exclusive = vec![
            vec!["ip-allow", "ip-deny", "no-ip-rules"],
            vec!["cors-origin", "no-cors"],
            vec!["dns-token-secret", "no-dns"],
        ];
        f.extend(wait_flags());
    }
    f.push(Flag::bool(
        "diff",
        None,
        false,
        "print what would change and change nothing",
    ));
    f.push(Flag::bool(
        "new",
        None,
        false,
        &format!("refuse a {k} that exists"),
    ));
    (f, exclusive)
}

/// What the flags of one run say.
struct SpecFlags<'c, 'a> {
    ctx: &'c Ctx<'a>,
    job: bool,
}

impl SpecFlags<'_, '_> {
    fn ch(&self, n: &str) -> bool {
        self.ctx.changed(n)
    }

    fn file(&self) -> String {
        self.ctx.str("file")
    }

    fn spec_changed(&self) -> bool {
        if self.job {
            JOB_SPEC_FLAGS.iter().any(|n| self.ch(n))
        } else {
            APP_SPEC_FLAGS.iter().any(|n| self.ch(n))
        }
    }

    fn check(&self) -> Result {
        if !self.file().is_empty() && self.spec_changed() {
            return Err("give either --file or flags that change the spec, not both".into());
        }
        if self.file().is_empty() && (self.ch("vars") || self.ch("var")) {
            return Err("--vars and --var fill in a spec file: use them with --file".into());
        }
        Ok(())
    }

    fn apply(&self, a: &mut App) -> Result {
        let c = self.ctx;
        if self.ch("image") {
            a.image = c.str("image");
            if let Some(r) = &mut a.registry {
                r.server = spec::validate::registry_host(&a.image);
            }
        }
        if self.ch("command") {
            a.command = non_empty(c.strs("command"));
        }
        if self.ch("args") {
            a.args = non_empty(c.strs("args"));
        }
        self.apply_env(a)?;
        if self.ch("env-from-secrets") && self.ch("env-from") {
            return Err("--env-from-secrets and --env-from: use one (--env-from SECRET lists secrets of the space)".into());
        }
        if self.ch("env-from-secrets") {
            a.env_from = EnvFrom {
                own: c.bool("env-from-secrets"),
                secrets: None,
            };
        }
        if self.ch("env-from") {
            let names = non_empty(c.strs("env-from"));
            a.env_from = EnvFrom {
                own: false,
                secrets: if names.is_empty() {
                    None
                } else {
                    Some(
                        names
                            .into_iter()
                            .map(|secret| EnvFromSecret { secret })
                            .collect(),
                    )
                },
            };
        }
        if self.ch("cpu") || self.ch("memory") {
            let r = a.resources.get_or_insert_with(Default::default);
            if self.ch("cpu") {
                r.cpu = c.str("cpu");
            }
            if self.ch("memory") {
                r.memory = c.str("memory");
            }
        }
        if self.ch("registry-user") || self.ch("registry-secret") {
            let mut r = a.registry.clone().unwrap_or_default();
            if self.ch("registry-user") {
                r.username = c.str("registry-user");
            }
            if self.ch("registry-secret") {
                r.password_secret_ref = c.str("registry-secret");
            }
            r.server = spec::validate::registry_host(&a.image);
            a.registry = if r.username.is_empty() && r.password_secret_ref.is_empty() {
                None
            } else {
                Some(r)
            };
        }
        if self.job {
            self.apply_job(a);
            return Ok(());
        }
        self.apply_ingress(a)?;
        if self.ch("health-path") {
            self.apply_health_path(a);
        }
        self.apply_scale(a)
    }

    fn apply_env(&self, a: &mut App) -> Result {
        let c = self.ctx;
        for k in c.strs("remove-env") {
            if !a.env.iter().any(|e| e.name == k) {
                return Err(Error::Msg(format!(
                    "--remove-env {k}: the {} has no such variable",
                    kind_word(self.job)
                )));
            }
            a.env.retain(|e| e.name != k);
        }
        let set = |a: &mut App, e: EnvVar| {
            if let Some(o) = a.env.iter_mut().find(|o| o.name == e.name) {
                *o = e;
            } else {
                a.env.push(e);
            }
        };
        for kv in c.strs("env") {
            match kv.split_once('=') {
                Some((k, v)) if !k.is_empty() => set(
                    a,
                    EnvVar {
                        name: k.to_string(),
                        value: v.to_string(),
                        secret_ref: String::new(),
                    },
                ),
                _ => return Err("--env: want NAME=VALUE".into()),
            }
        }
        for kv in c.strs("secret-env") {
            match kv.split_once('=') {
                Some((k, s)) if !k.is_empty() && !s.is_empty() => set(
                    a,
                    EnvVar {
                        name: k.to_string(),
                        value: String::new(),
                        secret_ref: s.to_string(),
                    },
                ),
                _ => {
                    return Err("--secret-env: want NAME=SECRET/KEY or NAME=KEY, where a secret's key is (never its value)".into());
                }
            }
        }
        Ok(())
    }

    fn apply_job(&self, a: &mut App) {
        let c = self.ctx;
        if self.ch("schedule") {
            a.schedule = c.str("schedule");
        }
        if self.ch("time-zone") {
            a.time_zone = c.str("time-zone");
        }
        if self.ch("timeout") {
            a.timeout = Duration(c.duration("timeout"));
        }
        if self.ch("retries") {
            a.retries = c.int("retries");
        }
        if self.ch("concurrency") {
            a.concurrency = c.str("concurrency");
        }
        if self.ch("tasks") {
            a.tasks = c.int("tasks");
            if a.tasks == 1 {
                a.tasks = 0;
            }
        }
        if self.ch("parallelism") {
            a.parallelism = c.int("parallelism");
        }
    }

    fn apply_ingress(&self, a: &mut App) -> Result {
        let c = self.ctx;
        let names = [
            "ingress",
            "protocol",
            "port",
            "domain",
            "remove-domain",
            "ip-allow",
            "ip-deny",
            "no-ip-rules",
            "sticky",
            "cors-origin",
            "no-cors",
            "dns-token-secret",
            "no-dns",
        ];
        if !names.iter().any(|n| self.ch(n)) {
            return Ok(());
        }
        let mut inn = a.ingress.clone().unwrap_or_else(|| Ingress {
            typ: spec::INGRESS_NONE.to_string(),
            ..Default::default()
        });
        let old_port = inn.port;
        if self.ch("ingress") {
            inn.typ = c.str("ingress");
            if inn.typ == spec::INGRESS_NONE {
                inn = Ingress {
                    typ: spec::INGRESS_NONE.to_string(),
                    ..Default::default()
                };
            }
        }
        if self.ch("protocol") {
            inn.protocol = c.str("protocol");
            if inn.protocol == spec::PROTOCOL_HTTP {
                inn.protocol.clear();
            }
        }
        if self.ch("port") {
            inn.port = c.int("port");
        }
        let remove = c.strs("remove-domain");
        inn.domains.retain(|d| !remove.contains(d));
        for d in c.strs("domain") {
            if !inn.domains.contains(&d) {
                inn.domains.push(d);
            }
        }
        if self.ch("sticky") {
            inn.sticky = c.bool("sticky");
        }
        if c.bool("no-cors") {
            inn.cors = None;
        } else if self.ch("cors-origin") {
            let mut cors = inn.cors.clone().unwrap_or_default();
            cors.allow_origins = Some(c.strs("cors-origin"));
            inn.cors = Some(cors);
        }
        if c.bool("no-dns") {
            inn.dns = None;
        } else if self.ch("dns-token-secret") {
            inn.dns = Some(spec::IngressDns {
                provider: spec::DNS_PROVIDER_CLOUDFLARE.to_string(),
                token_secret_ref: c.str("dns-token-secret"),
            });
        }
        if c.bool("no-ip-rules") {
            inn.ip_allow.clear();
            inn.ip_deny.clear();
        } else if self.ch("ip-allow") {
            inn.ip_allow = ip_rule_flags("--ip-allow", &c.strs("ip-allow"))?;
            inn.ip_deny.clear();
        } else if self.ch("ip-deny") {
            inn.ip_deny = ip_rule_flags("--ip-deny", &c.strs("ip-deny"))?;
            inn.ip_allow.clear();
        }
        let new_port = inn.port;
        a.ingress = Some(inn);
        if new_port != old_port
            && let Some(p) = &mut a.probes
        {
            for probe in [&mut p.startup, &mut p.readiness, &mut p.liveness]
                .into_iter()
                .flatten()
            {
                if probe.command.is_empty() && probe.port == old_port {
                    probe.port = new_port;
                }
            }
        }
        Ok(())
    }

    fn apply_health_path(&self, a: &mut App) {
        let path = self.ctx.str("health-path");
        if path.is_empty() {
            if let Some(p) = &mut a.probes {
                p.readiness = None;
                if p.startup.is_none() && p.liveness.is_none() {
                    a.probes = None;
                }
            }
            return;
        }
        let port = a.ingress.as_ref().map(|i| i.port);
        let probes = a.probes.get_or_insert_with(Probes::default);
        let mut p = match probes.readiness.take() {
            Some(p) if p.command.is_empty() => p,
            _ => Probe::default(),
        };
        p.path = path;
        if let Some(port) = port
            && p.port == 0
        {
            p.port = port;
        }
        probes.readiness = Some(p);
    }

    fn apply_scale(&self, a: &mut App) -> Result {
        let c = self.ctx;
        let mut rules = Vec::new();
        if self.ch("scale-cpu") {
            rules.push(ScaleRule {
                typ: spec::SCALE_CPU.to_string(),
                utilization: c.int("scale-cpu"),
                ..Default::default()
            });
        }
        if self.ch("scale-memory") {
            rules.push(ScaleRule {
                typ: spec::SCALE_MEMORY.to_string(),
                utilization: c.int("scale-memory"),
                ..Default::default()
            });
        }
        if self.ch("scale-http") {
            rules.push(ScaleRule {
                typ: spec::SCALE_HTTP.to_string(),
                concurrent: c.int("scale-http"),
                ..Default::default()
            });
        }
        if rules.len() > 1 {
            return Err("give one of --scale-cpu, --scale-memory, and --scale-http".into());
        }
        let no_autoscale = c.bool("no-autoscale");
        if !self.ch("min")
            && !self.ch("max")
            && rules.is_empty()
            && !no_autoscale
            && !self.ch("idle-after")
        {
            return Ok(());
        }
        let mut s = a.scale.clone().unwrap_or_default();
        if self.ch("min") {
            s.min = Some(c.int("min"));
        }
        if self.ch("max") {
            s.max = Some(c.int("max"));
        }
        let have_rules = !rules.is_empty();
        if have_rules {
            s.rules = rules;
        }
        if self.ch("idle-after") {
            s.idle_after = Duration(c.duration("idle-after"));
        }
        if no_autoscale {
            if have_rules || self.ch("max") || self.ch("idle-after") {
                return Err("--no-autoscale runs a fixed count: give --min N alone, or leave it out to keep the current minimum".into());
            }
            s.rules.clear();
            s.idle_after = Duration(0);
        }
        if self.ch("min") && c.int("min") > 0 && !self.ch("idle-after") {
            s.idle_after = Duration(0);
        }
        if s.rules.is_empty() {
            if self.ch("max") {
                return Err("--max bounds autoscaling: add one of --scale-cpu, --scale-memory, and --scale-http (--min N alone runs a fixed N)".into());
            }
            s.max = None;
        }
        a.scale = Some(Scale { ..s });
        Ok(())
    }
}

/// --file with its variables filled in.
fn read_file(ctx: &mut Ctx<'_>) -> Result<Vec<u8>> {
    {
        let file = ctx.str("file");
        let mut data = Vec::new();
        let limit = (spec::MAX_SPEC_BYTES + 1) as u64;
        if file == "-" {
            ctx.stdin
                .take(limit)
                .read_to_end(&mut data)
                .map_err(|e| Error::Msg(e.to_string()))?;
        } else {
            let f = std::fs::File::open(&file)
                .map_err(|e| Error::Msg(path_error("open", &file, &e)))?;
            f.take(limit)
                .read_to_end(&mut data)
                .map_err(|e| Error::Msg(path_error("read", &file, &e)))?;
        }
        let vars_file = ctx.str("vars");
        let list = ctx.strs("var");
        if !vars_file.is_empty() || !list.is_empty() {
            let vars = load_vars(&vars_file, &list).map_err(Error::Msg)?;
            data = spec::vars::substitute(&data, &vars).map_err(Error::Msg)?;
        }
        Ok(data)
    }
}

fn non_empty(s: Vec<String>) -> Vec<String> {
    if s.len() == 1 && s[0].is_empty() {
        return Vec::new();
    }
    s
}

/// A failed file operation's text: "OP PATH: ERRNO TEXT".
pub fn path_error(op: &str, path: &str, e: &std::io::Error) -> String {
    format!("{op} {path}: {}", armada_fsutil::errno_text(e))
}

/// RANGE[,name=NAME][,description=TEXT].
fn ip_rule_flags(flag: &str, vals: &[String]) -> Result<Vec<IPRule>> {
    let mut out = Vec::new();
    for v in vals {
        let (rest, desc) = match v.split_once(",description=") {
            Some((r, d)) => (r, Some(d)),
            None => (v.as_str(), None),
        };
        let mut parts = rest.split(',');
        let mut r = IPRule {
            range: parts.next().unwrap_or("").to_string(),
            ..Default::default()
        };
        if let Some(d) = desc {
            r.description = d.to_string();
        }
        for p in parts {
            match p.strip_prefix("name=") {
                Some(name) if r.name.is_empty() => r.name = name.to_string(),
                _ => {
                    return Err(Error::Msg(format!(
                        "{flag} {}: want RANGE[,name=NAME][,description=TEXT]",
                        go::quote(v)
                    )));
                }
            }
        }
        out.push(r);
    }
    Ok(out)
}

/// NAME=VALUE lines of file, then each of list, which wins.
fn load_vars(file: &str, list: &[String]) -> std::result::Result<HashMap<String, String>, String> {
    const MAX: usize = 1 << 20;
    let mut vars = HashMap::new();
    if !file.is_empty() {
        let f = std::fs::File::open(file).map_err(|e| path_error("open", file, &e))?;
        let mut b = Vec::new();
        f.take(MAX as u64 + 1)
            .read_to_end(&mut b)
            .map_err(|e| path_error("read", file, &e))?;
        if b.len() > MAX {
            return Err(format!("{file} is larger than {MAX} bytes"));
        }
        let mut seen: HashMap<String, usize> = HashMap::new();
        for (i, line) in scan_lines(&b).into_iter().enumerate() {
            let n = i + 1;
            let line = String::from_utf8_lossy(line);
            let line = line.strip_suffix('\r').unwrap_or(&line);
            let t = go::trim_space(line);
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let (name, value) = split_var(line).map_err(|e| format!("{file} line {n}: {e}"))?;
            if let Some(first) = seen.get(&name) {
                return Err(format!(
                    "{file} line {n}: {name} was already set on line {first}"
                ));
            }
            seen.insert(name.clone(), n);
            vars.insert(name, value);
        }
    }
    for v in list {
        let (name, value) = split_var(v).map_err(|e| format!("--var: {e}"))?;
        vars.insert(name, value);
    }
    Ok(vars)
}

/// bufio.ScanLines: lines without their "\n" or "\r\n", the last one
/// without a new line included.
pub fn scan_lines(b: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = b;
    while !rest.is_empty() {
        let (line, next) = match rest.iter().position(|&c| c == b'\n') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, &rest[rest.len()..]),
        };
        out.push(line.strip_suffix(b"\r").unwrap_or(line));
        rest = next;
    }
    out
}

fn split_var(s: &str) -> std::result::Result<(String, String), String> {
    match s.split_once('=') {
        Some((name, value)) if spec::vars::valid_var_name(name) => {
            if value.contains('\0') {
                return Err(format!("{name} contains a NUL byte"));
            }
            Ok((name.to_string(), value.to_string()))
        }
        _ => Err("want NAME=VALUE with NAME of letters, digits, and _".to_string()),
    }
}

/// An app spec refused for a job command and the other way.
pub fn check_kind(sp: &App, job: bool, verb: &str) -> Result {
    if sp.is_job() && !job {
        return Err(Error::Msg(format!(
            "{} is a job (kind: job); use armada job {verb}",
            sp.name
        )));
    }
    if !sp.is_job() && job {
        return Err(Error::Msg(format!(
            "{} is an app, not a job; use armada app {verb}",
            sp.name
        )));
    }
    Ok(())
}

/// The space and name of an ID, "" for the default space.
pub fn app_target(id: &str) -> (String, String) {
    let (p, n) = spec::validate::split_app_id(id).unwrap_or_default();
    if p == spec::validate::DEFAULT_SPACE {
        return (String::new(), n);
    }
    (p, n)
}

/// The spec from --file or from the flags.
fn create_spec(ctx: &mut Ctx<'_>, job: bool, id: &str, space: &str) -> Result<(Vec<u8>, App)> {
    if !ctx.str("file").is_empty() {
        let data = read_file(ctx)?;
        let sp = spec::parse_in(&data, space).map_err(Error::Msg)?;
        check_kind(&sp, job, "deploy")?;
        if !id.is_empty() {
            let (_, name) = app_target(id);
            if sp.name != name {
                return Err(Error::Msg(format!(
                    "the file names {}, not {name}",
                    sp.name
                )));
            }
        }
        return Ok((data, sp));
    }
    if id.is_empty() {
        return Err(Error::Msg(format!(
            "give the {}'s name, or --file",
            kind_word(job)
        )));
    }
    let f = SpecFlags { ctx: &*ctx, job };
    if !f.ch("image") {
        return Err("--image is required (or give --file)".into());
    }
    let (_, name) = app_target(id);
    let mut a = App {
        name,
        ..Default::default()
    };
    if job {
        a.kind = spec::KIND_JOB.to_string();
    }
    f.apply(&mut a)?;
    spec_data(&a, space)
}

/// The spec as a file holds it, validated here first.
fn spec_data(a: &App, space: &str) -> Result<(Vec<u8>, App)> {
    let data = a.export().map_err(Error::Msg)?;
    let sp = spec::parse_in(&data, space).map_err(Error::Msg)?;
    Ok((data, sp))
}

/// App deploy and job deploy.
pub fn run_deploy(ctx: &mut Ctx<'_>, args: &[String], job: bool) -> Result {
    if ctx.bool("new") {
        if ctx.bool("diff") {
            return Err("--new and --diff do not go together".into());
        }
        return run_create(ctx, args, job);
    }
    run_update(ctx, args, job)
}

fn run_create(ctx: &mut Ctx<'_>, args: &[String], job: bool) -> Result {
    SpecFlags { ctx: &*ctx, job }.check()?;
    let mut id = String::new();
    if args.len() == 1 {
        id = ctx.app_id(&args[0]).map_err(Error::Msg)?;
    }
    let mut space = ctx.g.space.clone();
    if !id.is_empty() {
        space = app_target(&id).0;
    }
    let (data, _) = create_spec(ctx, job, &id, &space)?;
    let mut admin = ctx.admin()?;
    let resp = rpc!(
        ctx,
        admin,
        deploy,
        DeployRequest {
            spec: data,
            space,
            must_create: true,
            ..Default::default()
        }
    )
    .map_err(rpc_err)?;
    ctx.print(&format!(
        "Created {} (revision {}).\n",
        resp.app, resp.revision
    ));
    let w = WaitFlags::of(ctx);
    if job || !w.wait {
        return Ok(());
    }
    wait_rollout(ctx, &mut admin, &resp.app, &resp.revision, w.timeout)
}

fn run_update(ctx: &mut Ctx<'_>, args: &[String], job: bool) -> Result {
    let f = SpecFlags { ctx: &*ctx, job };
    f.check()?;
    let file = f.file();
    if file.is_empty() && !f.spec_changed() {
        return Err("nothing to change: give flags that change the spec, or --file".into());
    }
    let mut id = String::new();
    if args.len() == 1 {
        id = ctx.app_id(&args[0]).map_err(Error::Msg)?;
    } else if file.is_empty() {
        return Err(Error::Msg(format!("give the {}'s name", kind_word(job))));
    }
    let mut space = ctx.g.space.clone();
    if !id.is_empty() {
        space = app_target(&id).0;
    }
    let mut admin = ctx.admin()?;
    let diff = ctx.bool("diff");
    let mut data;
    let mut current = Vec::new();
    let mut base = String::new();
    let mut prev = String::new();
    let mut exists = true;
    if !file.is_empty() {
        let (d, sp) = create_spec(ctx, job, &id, &space)?;
        data = d;
        id = spec::validate::app_id(&space, &sp.name);
        let req = GetAppSpecRequest { app: id.clone() };
        match rpc!(ctx, admin, get_app_spec, req) {
            Err(s) if s.code() == Code::NotFound => exists = false,
            Err(s) => return Err(rpc_err(s)),
            Ok(cur) => {
                current = cur.spec;
                prev = cur.revision;
                check_current_kind(&id, &current, job)?;
            }
        }
        if diff {
            data = sp.export().map_err(Error::Msg)?;
        }
    } else {
        let req = GetAppSpecRequest { app: id.clone() };
        let mut a = match rpc!(ctx, admin, get_app_spec, req) {
            Err(s) if s.code() == Code::NotFound => {
                exists = false;
                let (_, name) = app_target(&id);
                let mut a = App {
                    name,
                    ..Default::default()
                };
                if job {
                    a.kind = spec::KIND_JOB.to_string();
                }
                a
            }
            Err(s) => return Err(rpc_err(s)),
            Ok(cur) => {
                current = cur.spec;
                base = cur.revision.clone();
                prev = cur.revision;
                let a = spec::parse_in(&current, &space)
                    .map_err(|e| Error::Msg(format!("the spec of {id}: {e}")))?;
                check_kind(&a, job, "deploy")?;
                a
            }
        };
        let f = SpecFlags { ctx: &*ctx, job };
        if !exists && !f.ch("image") {
            return Err(Error::Msg(format!(
                "{id} does not exist; creating it needs --image"
            )));
        }
        f.apply(&mut a)?;
        data = spec_data(&a, &space)?.0;
    }
    if diff {
        let text = print_diff(&current, &data);
        ctx.print(&text);
        return Ok(());
    }
    let req = DeployRequest {
        spec: data,
        space,
        base_revision: base,
        must_create: !exists,
        must_exist: exists,
    };
    let resp = match rpc!(ctx, admin, deploy, req) {
        Ok(r) => r,
        Err(s) if s.code() == Code::NotFound && exists => {
            return Err(Error::Msg(format!(
                "{id} was deleted while this deploy ran; run armada {} deploy again to create it",
                kind_word(job)
            )));
        }
        Err(s) => return Err(rpc_err(s)),
    };
    let line = if !exists {
        format!("Created {} (revision {}).", resp.app, resp.revision)
    } else if resp.revision == prev {
        format!("{} is unchanged (revision {}).", resp.app, resp.revision)
    } else {
        format!("Updated {} (revision {}).", resp.app, resp.revision)
    };
    ctx.print(&format!("{line}\n"));
    let w = WaitFlags::of(ctx);
    if job || !w.wait {
        return Ok(());
    }
    wait_rollout(ctx, &mut admin, &resp.app, &resp.revision, w.timeout)
}

/// Never replace a job with an app or the other way.
fn check_current_kind(id: &str, current: &[u8], job: bool) -> Result {
    let (p, _) = app_target(id);
    match spec::parse_in(current, &p) {
        Ok(sp) => check_kind(&sp, job, "deploy"),
        Err(_) => Ok(()),
    }
}

const MAX_DIFF_CELLS: usize = 4 << 20;

/// "-" for a line removed, "+" for one added, three lines of
/// context, "@@" between hunks.
pub fn print_diff(before: &[u8], after: &[u8]) -> String {
    let a_text = String::from_utf8_lossy(before);
    let b_text = String::from_utf8_lossy(after);
    let ops = line_diff(&split_lines(&a_text), &split_lines(&b_text));
    if ops.iter().all(|(k, _)| *k == ' ') {
        return "No changes.\n".to_string();
    }
    let mut out = String::new();
    let around = 3usize;
    let mut shown: Option<usize> = None;
    for (i, (kind, line)) in ops.iter().enumerate() {
        let lo = i.saturating_sub(around);
        let hi = (i + around).min(ops.len() - 1);
        if !(lo..=hi).any(|j| ops[j].0 != ' ') {
            continue;
        }
        if let Some(s) = shown
            && i > s + 1
        {
            out.push_str("@@\n");
        }
        shown = Some(i);
        out.push_str(&format!("{kind} {line}\n"));
    }
    out
}

fn split_lines(s: &str) -> Vec<String> {
    let s = s.strip_suffix('\n').unwrap_or(s);
    if s.is_empty() {
        return Vec::new();
    }
    s.split('\n').map(str::to_string).collect()
}

fn line_diff(a: &[String], b: &[String]) -> Vec<(char, String)> {
    let mut ops = Vec::new();
    if a.len() * b.len() > MAX_DIFF_CELLS {
        ops.extend(a.iter().map(|l| ('-', l.clone())));
        ops.extend(b.iter().map(|l| ('+', l.clone())));
        return ops;
    }
    let mut lcs = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            ops.push((' ', a[i].clone()));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            ops.push(('-', a[i].clone()));
            i += 1;
        } else {
            ops.push(('+', b[j].clone()));
            j += 1;
        }
    }
    ops.extend(a[i..].iter().map(|l| ('-', l.clone())));
    ops.extend(b[j..].iter().map(|l| ('+', l.clone())));
    ops
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff() {
        assert_eq!(print_diff(b"a\nb\n", b"a\nb\n"), "No changes.\n");
        assert_eq!(
            print_diff(b"a\nb\nc\n", b"a\nx\nc\n"),
            "  a\n- b\n+ x\n  c\n"
        );
        let before = b"1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n";
        let after = b"0\n1\n2\n3\n4\n5\n6\n7\n8\n9\n11\n";
        assert_eq!(
            print_diff(before, after),
            "+ 0\n  1\n  2\n  3\n@@\n  7\n  8\n  9\n- 10\n+ 11\n"
        );
    }

    #[test]
    fn ip_rules() {
        let r = ip_rule_flags(
            "--ip-allow",
            &["10.0.0.0/8,name=office,description=a, b".into()],
        )
        .unwrap();
        assert_eq!(r[0].range, "10.0.0.0/8");
        assert_eq!(r[0].name, "office");
        assert_eq!(r[0].description, "a, b");
        assert!(ip_rule_flags("--ip-allow", &["10.0.0.0/8,x=y".into()]).is_err());
    }
}

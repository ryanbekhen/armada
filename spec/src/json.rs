//! The spec as JSON, as the control plane stores revisions: field names,
//! fields left out when empty or zero, Duration and EnvFrom's own forms,
//! and the `json: cannot unmarshal ...` error texts.

use std::collections::BTreeMap;

use crate::go;
use crate::spec::*;

/// A JSON writer whose strings escape HTML characters, U+2028, and
/// U+2029 escaped).
struct W {
    out: String,
    first: Vec<bool>,
}

fn escape(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' | '>' | '&' => out.push_str(&format!("\\u00{:02x}", c as u32)),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u00{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

impl W {
    fn open(&mut self) {
        self.out.push('{');
        self.first.push(true);
    }
    fn close(&mut self) {
        self.out.push('}');
        self.first.pop();
    }
    fn key(&mut self, k: &str) {
        let first = self.first.last_mut().expect("inside an object");
        if !*first {
            self.out.push(',');
        }
        *first = false;
        escape(&mut self.out, k);
        self.out.push(':');
    }
    fn s(&mut self, v: &str) {
        escape(&mut self.out, v);
    }
    fn str(&mut self, k: &str, v: &str, omit: bool) {
        if omit && v.is_empty() {
            return;
        }
        self.key(k);
        self.s(v);
    }
    fn int(&mut self, k: &str, v: i64, omit: bool) {
        if omit && v == 0 {
            return;
        }
        self.key(k);
        self.out.push_str(&v.to_string());
    }
    fn bool(&mut self, k: &str, v: bool) {
        if !v {
            return;
        }
        self.key(k);
        self.out.push_str("true");
    }
    fn dur(&mut self, k: &str, v: Duration) {
        if v.0 == 0 {
            return;
        }
        self.key(k);
        self.s(&v.string());
    }
    fn strings(&mut self, v: Option<&[String]>) {
        let Some(v) = v else {
            self.out.push_str("null");
            return;
        };
        self.out.push('[');
        for (i, s) in v.iter().enumerate() {
            if i > 0 {
                self.out.push(',');
            }
            self.s(s);
        }
        self.out.push(']');
    }
    fn list(&mut self, k: &str, v: &[String]) {
        if v.is_empty() {
            return;
        }
        self.key(k);
        self.strings(Some(v));
    }
    fn seq<T>(&mut self, k: &str, v: &[T], f: fn(&mut W, &T)) {
        if v.is_empty() {
            return;
        }
        self.key(k);
        self.out.push('[');
        for (i, x) in v.iter().enumerate() {
            if i > 0 {
                self.out.push(',');
            }
            f(self, x);
        }
        self.out.push(']');
    }
    fn opt<T>(&mut self, k: &str, v: &Option<T>, f: fn(&mut W, &T)) {
        if let Some(x) = v {
            self.key(k);
            f(self, x);
        }
    }
}

fn env_var(w: &mut W, v: &EnvVar) {
    w.open();
    w.str("name", &v.name, false);
    w.str("value", &v.value, true);
    w.str("secretRef", &v.secret_ref, true);
    w.close();
}

fn secret_file(w: &mut W, v: &SecretFile) {
    w.open();
    w.str("secretRef", &v.secret_ref, false);
    w.str("path", &v.path, false);
    w.close();
}

fn registry(w: &mut W, v: &Registry) {
    w.open();
    w.str("server", &v.server, false);
    w.str("username", &v.username, false);
    w.str("passwordSecretRef", &v.password_secret_ref, false);
    w.close();
}

fn route(w: &mut W, v: &Route) {
    w.open();
    w.str("path", &v.path, false);
    w.bool("stripPrefix", v.strip_prefix);
    w.close();
}

fn ip_rule(w: &mut W, v: &IPRule) {
    w.open();
    w.str("range", &v.range, false);
    w.str("name", &v.name, true);
    w.str("description", &v.description, true);
    w.close();
}

fn cors(w: &mut W, v: &Cors) {
    w.open();
    w.key("allowOrigins");
    w.strings(v.allow_origins.as_deref());
    w.list("allowMethods", &v.allow_methods);
    w.list("allowHeaders", &v.allow_headers);
    w.list("exposeHeaders", &v.expose_headers);
    w.dur("maxAge", v.max_age);
    w.bool("allowCredentials", v.allow_credentials);
    w.close();
}

fn ingress_dns(w: &mut W, v: &IngressDns) {
    w.open();
    w.str("provider", &v.provider, false);
    w.str("tokenSecretRef", &v.token_secret_ref, false);
    w.close();
}

fn ingress(w: &mut W, v: &Ingress) {
    w.open();
    w.str("type", &v.typ, false);
    w.str("protocol", &v.protocol, true);
    w.int("port", v.port, true);
    w.list("domains", &v.domains);
    w.seq("routes", &v.routes, route);
    w.list("allow", &v.allow);
    w.seq("ipAllow", &v.ip_allow, ip_rule);
    w.seq("ipDeny", &v.ip_deny, ip_rule);
    w.bool("sticky", v.sticky);
    w.opt("cors", &v.cors, cors);
    w.dur("timeout", v.timeout);
    w.opt("dns", &v.dns, ingress_dns);
    w.close();
}

fn traffic_target(w: &mut W, v: &TrafficTarget) {
    w.open();
    w.str("revision", &v.revision, false);
    w.int("weight", v.weight, false);
    w.str("label", &v.label, true);
    w.close();
}

fn revisions(w: &mut W, v: &Revisions) {
    w.open();
    w.str("mode", &v.mode, true);
    w.seq("traffic", &v.traffic, traffic_target);
    w.close();
}

fn probe(w: &mut W, v: &Probe) {
    w.open();
    w.str("path", &v.path, true);
    w.list("command", &v.command);
    w.int("port", v.port, true);
    w.dur("initialDelay", v.initial_delay);
    w.dur("period", v.period);
    w.dur("timeout", v.timeout);
    w.int("failureThreshold", v.failure_threshold, true);
    w.close();
}

fn probes(w: &mut W, v: &Probes) {
    w.open();
    w.opt("startup", &v.startup, probe);
    w.opt("readiness", &v.readiness, probe);
    w.opt("liveness", &v.liveness, probe);
    w.close();
}

fn scale_rule(w: &mut W, v: &ScaleRule) {
    w.open();
    w.str("type", &v.typ, false);
    w.int("concurrent", v.concurrent, true);
    w.int("utilization", v.utilization, true);
    w.list("command", &v.command);
    w.str("urlSecretRef", &v.url_secret_ref, true);
    w.str("list", &v.list, true);
    w.str("queue", &v.queue, true);
    w.int("length", v.length, true);
    w.str("schedule", &v.schedule, true);
    w.str("timeZone", &v.time_zone, true);
    w.dur("duration", v.duration);
    w.int("replicas", v.replicas, true);
    w.close();
}

fn scale(w: &mut W, v: &Scale) {
    w.open();
    if let Some(m) = v.min {
        w.int("min", m, false);
    }
    if let Some(m) = v.max {
        w.int("max", m, false);
    }
    w.seq("rules", &v.rules, scale_rule);
    w.dur("idleAfter", v.idle_after);
    w.close();
}

fn resources(w: &mut W, v: &Resources) {
    w.open();
    w.str("cpu", &v.cpu, true);
    w.str("memory", &v.memory, true);
    w.close();
}

fn placement(w: &mut W, v: &Placement) {
    w.open();
    if !v.require.is_empty() {
        w.key("require");
        w.open();
        // Map keys sorted, as a BTreeMap holds them.
        for (k, vals) in &v.require {
            w.key(k);
            w.strings(vals.as_deref());
        }
        w.close();
    }
    w.str("spreadBy", &v.spread_by, true);
    w.close();
}

fn keep(w: &mut W, k: &BackupKeep) {
    w.open();
    w.int("last", k.last, true);
    w.int("hourly", k.hourly, true);
    w.int("daily", k.daily, true);
    w.int("weekly", k.weekly, true);
    w.int("monthly", k.monthly, true);
    w.close();
}

fn volume_backup(w: &mut W, v: &VolumeBackup) {
    w.open();
    w.dur("every", v.every);
    w.str("schedule", &v.schedule, true);
    w.str("timeZone", &v.time_zone, true);
    w.key("keep");
    keep(w, &v.keep);
    w.str("urlSecretRef", &v.url_secret_ref, false);
    w.str("keySecretRef", &v.key_secret_ref, false);
    w.bool("stop", v.stop);
    w.close();
}

fn nfs(w: &mut W, v: &NfsSource) {
    w.open();
    w.str("server", &v.server, false);
    w.str("path", &v.path, false);
    w.bool("readOnly", v.read_only);
    w.close();
}

fn volume(w: &mut W, v: &Volume) {
    w.open();
    w.str("name", &v.name, false);
    w.str("path", &v.path, false);
    w.str("owner", &v.owner, true);
    w.opt("backup", &v.backup, volume_backup);
    w.str("failover", &v.failover, true);
    w.opt("nfs", &v.nfs, nfs);
    w.close();
}

fn container(w: &mut W, v: &Container) {
    w.open();
    w.str("name", &v.name, false);
    w.str("image", &v.image, false);
    w.list("command", &v.command);
    w.list("args", &v.args);
    w.seq("env", &v.env, env_var);
    w.opt("resources", &v.resources, resources);
    w.list("volumes", &v.volumes);
    w.list("secretFiles", &v.secret_files);
    w.close();
}

fn queue_trigger(w: &mut W, v: &QueueTrigger) {
    w.open();
    w.str("type", &v.typ, false);
    w.str("urlSecretRef", &v.url_secret_ref, true);
    w.str("list", &v.list, true);
    w.str("queue", &v.queue, true);
    w.int("perRun", v.per_run, true);
    w.close();
}

fn trigger(w: &mut W, v: &Trigger) {
    w.open();
    w.opt("queue", &v.queue, queue_trigger);
    w.dur("pollingInterval", v.polling_interval);
    w.int("parallelism", v.parallelism, true);
    w.close();
}

/// EnvFrom.MarshalJSON: "secrets", or the list.
fn env_from(w: &mut W, v: &EnvFrom) {
    if v.own {
        w.s(crate::validate::ENV_FROM_SECRETS);
        return;
    }
    let Some(list) = &v.secrets else {
        w.out.push_str("null");
        return;
    };
    w.out.push('[');
    for (i, s) in list.iter().enumerate() {
        if i > 0 {
            w.out.push(',');
        }
        w.open();
        w.str("secret", &s.secret, false);
        w.close();
    }
    w.out.push(']');
}

impl App {
    /// json.Marshal of the spec.
    pub fn to_json(&self) -> String {
        let mut w = W {
            out: String::new(),
            first: Vec::new(),
        };
        let a = self;
        w.open();
        w.str("apiVersion", &a.api_version, true);
        w.str("kind", &a.kind, true);
        w.str("name", &a.name, false);
        w.str("image", &a.image, false);
        w.list("command", &a.command);
        w.list("args", &a.args);
        w.seq("env", &a.env, env_var);
        if !a.env_from.is_zero() {
            w.key("envFrom");
            env_from(&mut w, &a.env_from);
        }
        w.list("envFromAdded", &a.env_from_added);
        w.seq("secretFiles", &a.secret_files, secret_file);
        w.opt("registry", &a.registry, registry);
        w.opt("ingress", &a.ingress, ingress);
        w.opt("revisions", &a.revisions, revisions);
        w.opt("probes", &a.probes, probes);
        w.opt("scale", &a.scale, scale);
        w.opt("resources", &a.resources, resources);
        w.opt("placement", &a.placement, placement);
        w.seq("volumes", &a.volumes, volume);
        w.seq("initContainers", &a.init_containers, container);
        w.seq("sidecars", &a.sidecars, container);
        w.dur("drain", a.drain);
        w.str("space", &a.space, true);
        w.str("schedule", &a.schedule, true);
        w.str("timeZone", &a.time_zone, true);
        w.dur("timeout", a.timeout);
        w.int("retries", a.retries, true);
        w.str("concurrency", &a.concurrency, true);
        if let Some(h) = a.history {
            w.int("history", h, false);
        }
        w.int("tasks", a.tasks, true);
        w.int("parallelism", a.parallelism, true);
        w.opt("trigger", &a.trigger, trigger);
        w.close();
        w.out
    }

    /// json.Unmarshal into a zero App.
    pub fn from_json(data: &[u8]) -> Result<App, String> {
        let v = parse(data)?;
        let mut a = App::default();
        let mut r = Reader { first: None };
        r.app(&v, &mut a, "");
        match r.first {
            Some(e) => Err(e),
            None => Ok(a),
        }
    }
}

/// A JSON value that keeps the order of object keys and number literals.
#[derive(Clone, Debug)]
enum Json {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn kind(&self) -> String {
        match self {
            Json::Null => "null".to_string(),
            Json::Bool(_) => "bool".to_string(),
            Json::Num(n) => format!("number {n}"),
            Json::Str(_) => "string".to_string(),
            Json::Arr(_) => "array".to_string(),
            Json::Obj(_) => "object".to_string(),
        }
    }
}

/// Parses JSON (RFC 8259) with serde_json's checks, keeping key order.
fn parse(data: &[u8]) -> Result<Json, String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| format!("json: {e}"))?;
    let mut p = P { b: data, i: 0 };
    let _ = v;
    Ok(p.value())
}

/// A small reader for JSON serde_json has already checked.
struct P<'a> {
    b: &'a [u8],
    i: usize,
}

impl P<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn value(&mut self) -> Json {
        self.ws();
        match self.b[self.i] {
            b'n' => {
                self.i += 4;
                Json::Null
            }
            b't' => {
                self.i += 4;
                Json::Bool(true)
            }
            b'f' => {
                self.i += 5;
                Json::Bool(false)
            }
            b'"' => Json::Str(self.string()),
            b'[' => {
                self.i += 1;
                let mut out = Vec::new();
                self.ws();
                if self.b[self.i] == b']' {
                    self.i += 1;
                    return Json::Arr(out);
                }
                loop {
                    out.push(self.value());
                    self.ws();
                    let c = self.b[self.i];
                    self.i += 1;
                    if c == b']' {
                        return Json::Arr(out);
                    }
                }
            }
            b'{' => {
                self.i += 1;
                let mut out = Vec::new();
                self.ws();
                if self.b[self.i] == b'}' {
                    self.i += 1;
                    return Json::Obj(out);
                }
                loop {
                    self.ws();
                    let k = self.string();
                    self.ws();
                    self.i += 1; // ':'
                    let v = self.value();
                    out.push((k, v));
                    self.ws();
                    let c = self.b[self.i];
                    self.i += 1;
                    if c == b'}' {
                        return Json::Obj(out);
                    }
                }
            }
            _ => {
                let start = self.i;
                while self.i < self.b.len()
                    && matches!(
                        self.b[self.i],
                        b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'
                    )
                {
                    self.i += 1;
                }
                Json::Num(String::from_utf8_lossy(&self.b[start..self.i]).into_owned())
            }
        }
    }
    fn string(&mut self) -> String {
        let start = self.i;
        self.i += 1;
        while self.b[self.i] != b'"' {
            if self.b[self.i] == b'\\' {
                self.i += 1;
            }
            self.i += 1;
        }
        self.i += 1;
        serde_json::from_slice::<String>(&self.b[start..self.i]).unwrap_or_default()
    }
}

/// encoding/json's field name matching: exact, else case-insensitive.
fn fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\u{212a}' => 'k',
            '\u{17f}' => 's',
            c => c.to_lowercase().next().unwrap_or(c),
        })
        .collect()
}

struct Reader {
    first: Option<String>,
}

impl Reader {
    fn fail(&mut self, v: &Json, field: &str, typ: &str, strukt: &str) {
        if self.first.is_none() {
            self.first = Some(format!(
                "json: cannot unmarshal {} into struct field {strukt}.{field} of type {typ}",
                match v {
                    Json::Num(_) => "number".to_string(),
                    other => other.kind(),
                }
            ));
        }
    }

    /// The object's fields, each matched to one of keys (ignoring case), the
    /// last value winning.
    fn fields<'j>(
        &mut self,
        v: &'j Json,
        keys: &[&str],
        path: &str,
        strukt: &str,
        typ: &str,
    ) -> Vec<Option<&'j Json>> {
        let mut out = vec![None; keys.len()];
        match v {
            Json::Obj(pairs) => {
                for (k, val) in pairs {
                    let idx = keys.iter().position(|n| n == k).or_else(|| {
                        let f = fold(k);
                        keys.iter().position(|n| fold(n) == f)
                    });
                    if let Some(i) = idx {
                        out[i] = Some(val);
                    }
                }
            }
            Json::Null => {}
            other => {
                let field = path.trim_end_matches('.');
                if field.is_empty() {
                    if self.first.is_none() {
                        self.first = Some(format!(
                            "json: cannot unmarshal {} into value of type {typ}",
                            other.kind()
                        ));
                    }
                } else {
                    self.fail(other, field, typ, strukt);
                }
            }
        }
        out
    }

    fn string(&mut self, v: Option<&Json>, out: &mut String, field: &str, strukt: &str) {
        match v {
            None | Some(Json::Null) => {}
            Some(Json::Str(s)) => *out = s.clone(),
            Some(o) => self.fail(o, field, "string", strukt),
        }
    }

    /// A string in a list: its errors name the element without "struct field".
    fn element(&mut self, v: &Json, out: &mut String, path: &str, strukt: &str) {
        match v {
            Json::Null => {}
            Json::Str(s) => *out = s.clone(),
            o => {
                if self.first.is_none() {
                    let kind = if let Json::Num(_) = o {
                        "number".to_string()
                    } else {
                        o.kind()
                    };
                    self.first = Some(format!(
                        "json: cannot unmarshal {kind} into {strukt}.{path} of type string"
                    ));
                }
            }
        }
    }

    fn int(&mut self, v: Option<&Json>, out: &mut i64, field: &str, strukt: &str, typ: &str) {
        match v {
            None | Some(Json::Null) => {}
            Some(Json::Num(n)) => match go::parse_int(n) {
                Ok(i) => *out = i,
                Err(_) => {
                    if self.first.is_none() {
                        self.first = Some(format!(
                            "json: cannot unmarshal number {n} into struct field {strukt}.{field} of type {typ}"
                        ));
                    }
                }
            },
            Some(o) => self.fail(o, field, typ, strukt),
        }
    }

    fn opt_int(&mut self, v: Option<&Json>, out: &mut Option<i64>, field: &str, strukt: &str) {
        match v {
            None => {}
            Some(Json::Null) => *out = None,
            Some(j) => {
                let mut i = out.unwrap_or(0);
                self.int(Some(j), &mut i, field, strukt, "int");
                *out = Some(i);
            }
        }
    }

    fn bool(&mut self, v: Option<&Json>, out: &mut bool, field: &str, strukt: &str) {
        match v {
            None | Some(Json::Null) => {}
            Some(Json::Bool(b)) => *out = *b,
            Some(o) => self.fail(o, field, "bool", strukt),
        }
    }

    fn dur(&mut self, v: Option<&Json>, out: &mut Duration) {
        match v {
            None | Some(Json::Null) => {}
            Some(Json::Str(s)) => match go::parse_duration(s) {
                Ok(d) => *out = Duration(d),
                Err(e) => {
                    self.first.get_or_insert(e);
                }
            },
            Some(_) => {
                self.first
                    .get_or_insert("duration must be a JSON string".to_string());
            }
        }
    }

    fn strings(&mut self, v: Option<&Json>, out: &mut Vec<String>, field: &str, strukt: &str) {
        let mut o = Some(std::mem::take(out));
        self.nil_strings(v, &mut o, field, strukt, "[]string");
        *out = o.unwrap_or_default();
    }

    fn nil_strings(
        &mut self,
        v: Option<&Json>,
        out: &mut Option<Vec<String>>,
        field: &str,
        strukt: &str,
        typ: &str,
    ) {
        match v {
            None => {}
            Some(Json::Null) => *out = None,
            Some(Json::Arr(items)) => {
                let mut list = Vec::new();
                for (i, it) in items.iter().enumerate() {
                    let mut s = String::new();
                    self.element(it, &mut s, &format!("{field}.{i}"), strukt);
                    list.push(s);
                }
                *out = Some(list);
            }
            Some(o) => self.fail(o, field, typ, strukt),
        }
    }

    fn list<T: Default>(
        &mut self,
        v: Option<&Json>,
        out: &mut Vec<T>,
        path: &str,
        strukt: &str,
        typ: &str,
        f: fn(&mut Reader, &Json, &mut T, &str),
    ) {
        match v {
            None => {}
            Some(Json::Null) => out.clear(),
            Some(Json::Arr(items)) => {
                out.clear();
                for (i, it) in items.iter().enumerate() {
                    let mut x = T::default();
                    f(self, it, &mut x, &format!("{path}{i}."));
                    out.push(x);
                }
            }
            Some(o) => self.fail(o, path.trim_end_matches('.'), typ, strukt),
        }
    }

    fn ptr<T: Default>(
        &mut self,
        v: Option<&Json>,
        out: &mut Option<T>,
        path: &str,
        f: fn(&mut Reader, &Json, &mut T, &str),
    ) {
        match v {
            None => {}
            Some(Json::Null) => *out = None,
            Some(j) => f(self, j, out.get_or_insert_with(T::default), path),
        }
    }

    fn app(&mut self, v: &Json, a: &mut App, p: &str) {
        const K: &[&str] = &[
            "apiVersion",
            "kind",
            "name",
            "image",
            "command",
            "args",
            "env",
            "envFrom",
            "envFromAdded",
            "secretFiles",
            "registry",
            "ingress",
            "revisions",
            "probes",
            "scale",
            "resources",
            "placement",
            "volumes",
            "initContainers",
            "sidecars",
            "drain",
            "space",
            "schedule",
            "timeZone",
            "timeout",
            "retries",
            "concurrency",
            "history",
            "tasks",
            "parallelism",
            "trigger",
        ];
        let s = "App";
        let f = self.fields(v, K, p, s, "spec.App");
        self.string(f[0], &mut a.api_version, &format!("{p}apiVersion"), s);
        self.string(f[1], &mut a.kind, &format!("{p}kind"), s);
        self.string(f[2], &mut a.name, &format!("{p}name"), s);
        self.string(f[3], &mut a.image, &format!("{p}image"), s);
        self.strings(f[4], &mut a.command, &format!("{p}command"), s);
        self.strings(f[5], &mut a.args, &format!("{p}args"), s);
        self.list(
            f[6],
            &mut a.env,
            &format!("{p}env."),
            s,
            "[]spec.EnvVar",
            Reader::env_var,
        );
        if let Some(j) = f[7] {
            self.env_from(j, &mut a.env_from);
        }
        self.strings(f[8], &mut a.env_from_added, &format!("{p}envFromAdded"), s);
        self.list(
            f[9],
            &mut a.secret_files,
            &format!("{p}secretFiles."),
            s,
            "[]spec.SecretFile",
            Reader::secret_file,
        );
        self.ptr(
            f[10],
            &mut a.registry,
            &format!("{p}registry."),
            Reader::registry,
        );
        self.ptr(
            f[11],
            &mut a.ingress,
            &format!("{p}ingress."),
            Reader::ingress,
        );
        self.ptr(
            f[12],
            &mut a.revisions,
            &format!("{p}revisions."),
            Reader::revisions,
        );
        self.ptr(f[13], &mut a.probes, &format!("{p}probes."), Reader::probes);
        self.ptr(f[14], &mut a.scale, &format!("{p}scale."), Reader::scale);
        self.ptr(
            f[15],
            &mut a.resources,
            &format!("{p}resources."),
            Reader::resources,
        );
        self.ptr(
            f[16],
            &mut a.placement,
            &format!("{p}placement."),
            Reader::placement,
        );
        self.list(
            f[17],
            &mut a.volumes,
            &format!("{p}volumes."),
            s,
            "[]spec.Volume",
            Reader::volume,
        );
        self.list(
            f[18],
            &mut a.init_containers,
            &format!("{p}initContainers."),
            s,
            "[]spec.Container",
            Reader::container,
        );
        self.list(
            f[19],
            &mut a.sidecars,
            &format!("{p}sidecars."),
            s,
            "[]spec.Container",
            Reader::container,
        );
        self.dur(f[20], &mut a.drain);
        self.string(f[21], &mut a.space, &format!("{p}space"), s);
        self.string(f[22], &mut a.schedule, &format!("{p}schedule"), s);
        self.string(f[23], &mut a.time_zone, &format!("{p}timeZone"), s);
        self.dur(f[24], &mut a.timeout);
        self.int(f[25], &mut a.retries, &format!("{p}retries"), s, "int");
        self.string(f[26], &mut a.concurrency, &format!("{p}concurrency"), s);
        self.opt_int(f[27], &mut a.history, &format!("{p}history"), s);
        self.int(f[28], &mut a.tasks, &format!("{p}tasks"), s, "int");
        self.int(
            f[29],
            &mut a.parallelism,
            &format!("{p}parallelism"),
            s,
            "int",
        );
        self.ptr(
            f[30],
            &mut a.trigger,
            &format!("{p}trigger."),
            Reader::trigger,
        );
    }

    fn env_from(&mut self, j: &Json, out: &mut EnvFrom) {
        match j {
            Json::Str(w) => {
                if w != crate::validate::ENV_FROM_SECRETS {
                    self.first.get_or_insert(format!(
                        "envFrom must be {} or a list of secrets",
                        go::quote(crate::validate::ENV_FROM_SECRETS)
                    ));
                    return;
                }
                *out = EnvFrom {
                    own: true,
                    secrets: None,
                };
            }
            Json::Null => *out = EnvFrom::default(),
            Json::Arr(items) => {
                let mut list = Vec::new();
                for it in items {
                    let mut x = EnvFromSecret::default();
                    let f = self.fields(it, &["secret"], "", "EnvFromSecret", "spec.EnvFromSecret");
                    self.string(f[0], &mut x.secret, "secret", "EnvFromSecret");
                    list.push(x);
                }
                *out = EnvFrom {
                    own: false,
                    secrets: Some(list),
                };
            }
            other => {
                self.first.get_or_insert(format!(
                    "json: cannot unmarshal {} into value of type []spec.EnvFromSecret",
                    other.kind()
                ));
            }
        }
    }

    fn env_var(&mut self, j: &Json, e: &mut EnvVar, p: &str) {
        let s = "App";
        let f = self.fields(j, &["name", "value", "secretRef"], p, s, "spec.EnvVar");
        self.string(f[0], &mut e.name, &format!("{p}name"), s);
        self.string(f[1], &mut e.value, &format!("{p}value"), s);
        self.string(f[2], &mut e.secret_ref, &format!("{p}secretRef"), s);
    }

    fn secret_file(&mut self, j: &Json, e: &mut SecretFile, p: &str) {
        let s = "App";
        let f = self.fields(j, &["secretRef", "path"], p, s, "spec.SecretFile");
        self.string(f[0], &mut e.secret_ref, &format!("{p}secretRef"), s);
        self.string(f[1], &mut e.path, &format!("{p}path"), s);
    }

    fn registry(&mut self, j: &Json, e: &mut Registry, p: &str) {
        let s = "App";
        let f = self.fields(
            j,
            &["server", "username", "passwordSecretRef"],
            p,
            s,
            "spec.Registry",
        );
        self.string(f[0], &mut e.server, &format!("{p}server"), s);
        self.string(f[1], &mut e.username, &format!("{p}username"), s);
        self.string(
            f[2],
            &mut e.password_secret_ref,
            &format!("{p}passwordSecretRef"),
            s,
        );
    }

    fn ingress(&mut self, j: &Json, e: &mut Ingress, p: &str) {
        let s = "App";
        let k = &[
            "type", "protocol", "port", "domains", "routes", "allow", "ipAllow", "ipDeny",
            "sticky", "cors", "timeout", "dns",
        ];
        let f = self.fields(j, k, p, s, "spec.Ingress");
        self.string(f[0], &mut e.typ, &format!("{p}type"), s);
        self.string(f[1], &mut e.protocol, &format!("{p}protocol"), s);
        self.int(f[2], &mut e.port, &format!("{p}port"), s, "int");
        self.strings(f[3], &mut e.domains, &format!("{p}domains"), s);
        self.list(
            f[4],
            &mut e.routes,
            &format!("{p}routes."),
            s,
            "[]spec.Route",
            |r, j, x, p| {
                let s = "App";
                let f = r.fields(j, &["path", "stripPrefix"], p, s, "spec.Route");
                r.string(f[0], &mut x.path, &format!("{p}path"), s);
                r.bool(f[1], &mut x.strip_prefix, &format!("{p}stripPrefix"), s);
            },
        );
        self.strings(f[5], &mut e.allow, &format!("{p}allow"), s);
        self.list(
            f[6],
            &mut e.ip_allow,
            &format!("{p}ipAllow."),
            s,
            "[]spec.IPRule",
            Reader::ip_rule,
        );
        self.list(
            f[7],
            &mut e.ip_deny,
            &format!("{p}ipDeny."),
            s,
            "[]spec.IPRule",
            Reader::ip_rule,
        );
        self.bool(f[8], &mut e.sticky, &format!("{p}sticky"), s);
        self.ptr(f[9], &mut e.cors, &format!("{p}cors."), |r, j, c, p| {
            let s = "App";
            let k = &[
                "allowOrigins",
                "allowMethods",
                "allowHeaders",
                "exposeHeaders",
                "maxAge",
                "allowCredentials",
            ];
            let f = r.fields(j, k, p, s, "spec.CORS");
            r.nil_strings(
                f[0],
                &mut c.allow_origins,
                &format!("{p}allowOrigins"),
                s,
                "[]string",
            );
            r.strings(f[1], &mut c.allow_methods, &format!("{p}allowMethods"), s);
            r.strings(f[2], &mut c.allow_headers, &format!("{p}allowHeaders"), s);
            r.strings(f[3], &mut c.expose_headers, &format!("{p}exposeHeaders"), s);
            r.dur(f[4], &mut c.max_age);
            r.bool(
                f[5],
                &mut c.allow_credentials,
                &format!("{p}allowCredentials"),
                s,
            );
        });
        self.dur(f[10], &mut e.timeout);
        self.ptr(f[11], &mut e.dns, &format!("{p}dns."), |r, j, d, p| {
            let s = "App";
            let f = r.fields(j, &["provider", "tokenSecretRef"], p, s, "spec.IngressDNS");
            r.string(f[0], &mut d.provider, &format!("{p}provider"), s);
            r.string(
                f[1],
                &mut d.token_secret_ref,
                &format!("{p}tokenSecretRef"),
                s,
            );
        });
    }

    fn ip_rule(&mut self, j: &Json, e: &mut IPRule, p: &str) {
        let s = "App";
        let f = self.fields(j, &["range", "name", "description"], p, s, "spec.IPRule");
        self.string(f[0], &mut e.range, &format!("{p}range"), s);
        self.string(f[1], &mut e.name, &format!("{p}name"), s);
        self.string(f[2], &mut e.description, &format!("{p}description"), s);
    }

    fn revisions(&mut self, j: &Json, e: &mut Revisions, p: &str) {
        let s = "App";
        let f = self.fields(j, &["mode", "traffic"], p, s, "spec.Revisions");
        self.string(f[0], &mut e.mode, &format!("{p}mode"), s);
        self.list(
            f[1],
            &mut e.traffic,
            &format!("{p}traffic."),
            s,
            "[]spec.TrafficTarget",
            |r, j, t, p| {
                let s = "App";
                let f = r.fields(
                    j,
                    &["revision", "weight", "label"],
                    p,
                    s,
                    "spec.TrafficTarget",
                );
                r.string(f[0], &mut t.revision, &format!("{p}revision"), s);
                r.int(f[1], &mut t.weight, &format!("{p}weight"), s, "int");
                r.string(f[2], &mut t.label, &format!("{p}label"), s);
            },
        );
    }

    fn probe(&mut self, j: &Json, e: &mut Probe, p: &str) {
        let s = "App";
        let k = &[
            "path",
            "command",
            "port",
            "initialDelay",
            "period",
            "timeout",
            "failureThreshold",
        ];
        let f = self.fields(j, k, p, s, "spec.Probe");
        self.string(f[0], &mut e.path, &format!("{p}path"), s);
        self.strings(f[1], &mut e.command, &format!("{p}command"), s);
        self.int(f[2], &mut e.port, &format!("{p}port"), s, "int");
        self.dur(f[3], &mut e.initial_delay);
        self.dur(f[4], &mut e.period);
        self.dur(f[5], &mut e.timeout);
        self.int(
            f[6],
            &mut e.failure_threshold,
            &format!("{p}failureThreshold"),
            s,
            "int",
        );
    }

    fn probes(&mut self, j: &Json, e: &mut Probes, p: &str) {
        let f = self.fields(
            j,
            &["startup", "readiness", "liveness"],
            p,
            "App",
            "spec.Probes",
        );
        self.ptr(f[0], &mut e.startup, &format!("{p}startup."), Reader::probe);
        self.ptr(
            f[1],
            &mut e.readiness,
            &format!("{p}readiness."),
            Reader::probe,
        );
        self.ptr(
            f[2],
            &mut e.liveness,
            &format!("{p}liveness."),
            Reader::probe,
        );
    }

    fn scale(&mut self, j: &Json, e: &mut Scale, p: &str) {
        let s = "App";
        let f = self.fields(j, &["min", "max", "rules", "idleAfter"], p, s, "spec.Scale");
        self.opt_int(f[0], &mut e.min, &format!("{p}min"), s);
        self.opt_int(f[1], &mut e.max, &format!("{p}max"), s);
        self.list(
            f[2],
            &mut e.rules,
            &format!("{p}rules."),
            s,
            "[]spec.ScaleRule",
            |r, j, x, p| {
                let s = "App";
                let k = &[
                    "type",
                    "concurrent",
                    "utilization",
                    "command",
                    "urlSecretRef",
                    "list",
                    "queue",
                    "length",
                    "schedule",
                    "timeZone",
                    "duration",
                    "replicas",
                ];
                let f = r.fields(j, k, p, s, "spec.ScaleRule");
                r.string(f[0], &mut x.typ, &format!("{p}type"), s);
                r.int(f[1], &mut x.concurrent, &format!("{p}concurrent"), s, "int");
                r.int(
                    f[2],
                    &mut x.utilization,
                    &format!("{p}utilization"),
                    s,
                    "int",
                );
                r.strings(f[3], &mut x.command, &format!("{p}command"), s);
                r.string(f[4], &mut x.url_secret_ref, &format!("{p}urlSecretRef"), s);
                r.string(f[5], &mut x.list, &format!("{p}list"), s);
                r.string(f[6], &mut x.queue, &format!("{p}queue"), s);
                r.int(f[7], &mut x.length, &format!("{p}length"), s, "int");
                r.string(f[8], &mut x.schedule, &format!("{p}schedule"), s);
                r.string(f[9], &mut x.time_zone, &format!("{p}timeZone"), s);
                r.dur(f[10], &mut x.duration);
                r.int(f[11], &mut x.replicas, &format!("{p}replicas"), s, "int");
            },
        );
        self.dur(f[3], &mut e.idle_after);
    }

    fn resources(&mut self, j: &Json, e: &mut Resources, p: &str) {
        let s = "App";
        let f = self.fields(j, &["cpu", "memory"], p, s, "spec.Resources");
        self.string(f[0], &mut e.cpu, &format!("{p}cpu"), s);
        self.string(f[1], &mut e.memory, &format!("{p}memory"), s);
    }

    fn placement(&mut self, j: &Json, e: &mut Placement, p: &str) {
        let s = "App";
        let f = self.fields(j, &["require", "spreadBy"], p, s, "spec.Placement");
        match f[0] {
            None => {}
            Some(Json::Null) => e.require = BTreeMap::new(),
            Some(Json::Obj(pairs)) => {
                for (k, v) in pairs {
                    let mut vals = e.require.remove(k).flatten();
                    self.nil_strings(
                        Some(v),
                        &mut vals,
                        &format!("{p}require.{k}"),
                        s,
                        "spec.LabelValues",
                    );
                    e.require.insert(k.clone(), vals);
                }
            }
            Some(o) => self.fail(o, &format!("{p}require"), "map[string]spec.LabelValues", s),
        }
        self.string(f[1], &mut e.spread_by, &format!("{p}spreadBy"), s);
    }

    fn volume(&mut self, j: &Json, e: &mut Volume, p: &str) {
        let s = "App";
        let f = self.fields(
            j,
            &["name", "path", "owner", "backup", "failover", "nfs"],
            p,
            s,
            "spec.Volume",
        );
        self.string(f[0], &mut e.name, &format!("{p}name"), s);
        self.string(f[1], &mut e.path, &format!("{p}path"), s);
        self.string(f[2], &mut e.owner, &format!("{p}owner"), s);
        self.ptr(f[3], &mut e.backup, &format!("{p}backup."), |r, j, b, p| {
            let s = "App";
            let k = &[
                "every",
                "schedule",
                "timeZone",
                "keep",
                "urlSecretRef",
                "keySecretRef",
                "stop",
            ];
            let f = r.fields(j, k, p, s, "spec.VolumeBackup");
            r.dur(f[0], &mut b.every);
            r.string(f[1], &mut b.schedule, &format!("{p}schedule"), s);
            r.string(f[2], &mut b.time_zone, &format!("{p}timeZone"), s);
            if let Some(kj) = f[3] {
                let kp = format!("{p}keep.");
                let f = r.fields(
                    kj,
                    &["last", "hourly", "daily", "weekly", "monthly"],
                    &kp,
                    s,
                    "spec.BackupKeep",
                );
                let k = &mut b.keep;
                r.int(f[0], &mut k.last, &format!("{kp}last"), s, "int");
                r.int(f[1], &mut k.hourly, &format!("{kp}hourly"), s, "int");
                r.int(f[2], &mut k.daily, &format!("{kp}daily"), s, "int");
                r.int(f[3], &mut k.weekly, &format!("{kp}weekly"), s, "int");
                r.int(f[4], &mut k.monthly, &format!("{kp}monthly"), s, "int");
            }
            r.string(f[4], &mut b.url_secret_ref, &format!("{p}urlSecretRef"), s);
            r.string(f[5], &mut b.key_secret_ref, &format!("{p}keySecretRef"), s);
            r.bool(f[6], &mut b.stop, &format!("{p}stop"), s);
        });
        self.string(f[4], &mut e.failover, &format!("{p}failover"), s);
        self.ptr(f[5], &mut e.nfs, &format!("{p}nfs."), |r, j, n, p| {
            let s = "App";
            let f = r.fields(j, &["server", "path", "readOnly"], p, s, "spec.NFSSource");
            r.string(f[0], &mut n.server, &format!("{p}server"), s);
            r.string(f[1], &mut n.path, &format!("{p}path"), s);
            r.bool(f[2], &mut n.read_only, &format!("{p}readOnly"), s);
        });
    }

    fn container(&mut self, j: &Json, e: &mut Container, p: &str) {
        let s = "App";
        let k = &[
            "name",
            "image",
            "command",
            "args",
            "env",
            "resources",
            "volumes",
            "secretFiles",
        ];
        let f = self.fields(j, k, p, s, "spec.Container");
        self.string(f[0], &mut e.name, &format!("{p}name"), s);
        self.string(f[1], &mut e.image, &format!("{p}image"), s);
        self.strings(f[2], &mut e.command, &format!("{p}command"), s);
        self.strings(f[3], &mut e.args, &format!("{p}args"), s);
        self.list(
            f[4],
            &mut e.env,
            &format!("{p}env."),
            s,
            "[]spec.EnvVar",
            Reader::env_var,
        );
        self.ptr(
            f[5],
            &mut e.resources,
            &format!("{p}resources."),
            Reader::resources,
        );
        self.strings(f[6], &mut e.volumes, &format!("{p}volumes"), s);
        self.strings(f[7], &mut e.secret_files, &format!("{p}secretFiles"), s);
    }

    fn trigger(&mut self, j: &Json, e: &mut Trigger, p: &str) {
        let s = "App";
        let f = self.fields(
            j,
            &["queue", "pollingInterval", "parallelism"],
            p,
            s,
            "spec.Trigger",
        );
        self.ptr(f[0], &mut e.queue, &format!("{p}queue."), |r, j, q, p| {
            let s = "App";
            let f = r.fields(
                j,
                &["type", "urlSecretRef", "list", "queue", "perRun"],
                p,
                s,
                "spec.QueueTrigger",
            );
            r.string(f[0], &mut q.typ, &format!("{p}type"), s);
            r.string(f[1], &mut q.url_secret_ref, &format!("{p}urlSecretRef"), s);
            r.string(f[2], &mut q.list, &format!("{p}list"), s);
            r.string(f[3], &mut q.queue, &format!("{p}queue"), s);
            r.int(f[4], &mut q.per_run, &format!("{p}perRun"), s, "int64");
        });
        self.dur(f[1], &mut e.polling_interval);
        self.int(
            f[2],
            &mut e.parallelism,
            &format!("{p}parallelism"),
            s,
            "int",
        );
    }
}

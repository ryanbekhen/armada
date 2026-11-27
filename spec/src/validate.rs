//! Validation, with fixed messages. The name rules are written out as byte
//! checks: every character class in them is ASCII.

use std::collections::{HashMap, HashSet};

use crate::go::{self, quote};
use crate::gotime::load_location;
use crate::spec::*;

/// One invalid field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldError {
    pub field: String,
    pub msg: String,
}

impl std::fmt::Display for FieldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.msg)
    }
}

/// errors.Join of field errors: one per line.
pub fn join(errs: &[FieldError]) -> String {
    errs.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

const MAX_IMAGE_LEN: usize = 512;
const MAX_ARGS: usize = 256;
const MAX_ARG_LEN: usize = 4096;
const MAX_ENV: usize = 512;
const MAX_ENV_VALUE_LEN: usize = 32 << 10;
const MAX_DOMAINS: usize = 32;
const MAX_ROUTES: usize = 32;
const MAX_PATH_LEN: usize = 256;
const MAX_DOMAIN_LEN: usize = 253;
const RESERVED_ENV_PFX: &str = "ARMADA_";
pub const MAX_ALLOW: usize = 32;
pub const MAX_TRAFFIC_TARGETS: usize = 10;
pub const LATEST_REVISION: &str = "latest";
pub const MAX_IP_RANGES: usize = 64;
pub const MAX_CORS_ORIGINS: usize = 32;
pub const MAX_CORS_HEADERS: usize = 32;
pub const MAX_CORS_MAX_AGE: i64 = 24 * go::HOUR;
pub const CORS_METHOD_NAMES: [&str; 7] =
    ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
pub const MAX_IP_RULE_NAME: usize = 64;
pub const MAX_IP_RULE_DESCRIPTION: usize = 256;
pub const RESERVED_TCP_PORTS: [i64; 14] = [
    22, 53, 80, 443, 2379, 2380, 4789, 7443, 7444, 7445, 7446, 7480, 8404, 51820,
];
pub const INTERNAL_SUFFIX: &str = ".internal";
pub const DEFAULT_SPACE: &str = "default";
const MAX_SPACE_LEN: usize = 30;
const MAX_PROBE_ARGS: usize = 64;
const MAX_PROBE_ARG_LEN: usize = 4096;
const MAX_SCHEDULE_LEN: usize = 128;
const MAX_TIME_ZONE_LEN: usize = 64;
pub const MAX_SECRET_NAME_LEN: usize = 63;
const MAX_SECRET_FILES: usize = 64;
const MAX_USERNAME_LEN: usize = 256;
const DEFAULT_REGISTRY: &str = "docker.io";
pub const ENV_FROM_SECRETS: &str = "secrets";
const MAX_ENV_FROM: usize = 16;
const MAX_CONTAINER_NAME: usize = 30;
const MAX_NFS_PATH: usize = 256;
const MAX_OWNER_ID: i64 = (1 << 31) - 1;
pub const RESERVED_LABEL_PREFIX: &str = "armada.";
pub const LABEL_OS: &str = "armada.os";
pub const LABEL_ARCH: &str = "armada.arch";
pub const LABEL_SITE: &str = "armada.site";
const MAX_LABEL_LEN: usize = 63;
pub const MAX_NODE_LABELS: usize = 32;
const MAX_REQUIRE: usize = 16;

const NAME_RULE: &str = "must be lowercase letters, digits, and single hyphens, starting with a letter and not ending with a hyphen";
pub const ENV_NAME_RE: &str = "^[A-Za-z_][A-Za-z0-9_]*$";

fn lower_alnum(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit()
}

fn alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

/// `^E([M]*E)?$` with E a subset of M.
fn edged(s: &str, edge: fn(u8) -> bool, mid: fn(u8) -> bool) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && edge(b[0]) && edge(b[b.len() - 1]) && b.iter().all(|&c| mid(c))
}

/// `^[a-z]([a-z0-9]|-[a-z0-9])*$`
pub(crate) fn name_re(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || !b[0].is_ascii_lowercase() || b[b.len() - 1] == b'-' {
        return false;
    }
    b.iter().all(|&c| lower_alnum(c) || c == b'-') && !s.contains("--")
}

/// `^[A-Za-z_][A-Za-z0-9_]*$`
pub fn env_name_re(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|&c| alnum(c) || c == b'_')
}

/// `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`
pub(crate) fn label_re(s: &str) -> bool {
    edged(s, lower_alnum, |c| lower_alnum(c) || c == b'-')
}

fn route_char(c: u8) -> bool {
    alnum(c) || matches!(c, b'.' | b'_' | b'~' | b'-')
}

/// `^/([A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+)*)?$`
fn route_path_re(s: &str) -> bool {
    if s == "/" {
        return true;
    }
    let Some(rest) = s.strip_prefix('/') else {
        return false;
    };
    rest.split('/')
        .all(|seg| !seg.is_empty() && seg.bytes().all(route_char))
}

/// `^/[A-Za-z0-9._~/-]*(\?[A-Za-z0-9._~=&%-]*)?$`
fn probe_path_re(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('/') else {
        return false;
    };
    let (path, query) = match rest.find('?') {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None => (rest, None),
    };
    path.bytes().all(|c| route_char(c) || c == b'/')
        && query.is_none_or(|q| {
            q.bytes()
                .all(|c| route_char(c) || matches!(c, b'=' | b'&' | b'%'))
        })
}

/// One path component of an image reference:
/// `[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*`
fn image_component(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || !lower_alnum(b[0]) || !lower_alnum(b[b.len() - 1]) {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        if lower_alnum(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && !lower_alnum(b[i]) {
            i += 1;
        }
        let sep = &s[start..i];
        if !(sep == "." || sep == "_" || sep == "__" || sep.bytes().all(|c| c == b'-')) {
            return false;
        }
    }
    true
}

/// `[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.…)*(?::[0-9]+)?`
fn image_domain(s: &str) -> bool {
    let (host, port) = match s.find(':') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    host.split('.')
        .all(|l| edged(l, alnum, |c| alnum(c) || c == b'-'))
        && port.is_none_or(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()))
}

/// The image reference after its optional domain: path components, an
/// optional tag, and an optional sha256 digest.
fn image_rest(s: &str) -> bool {
    let (s, digest) = match s.find('@') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    if let Some(d) = digest {
        let Some(hex) = d.strip_prefix("sha256:") else {
            return false;
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return false;
        }
    }
    let (path, tag) = match s.find(':') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    if let Some(t) = tag {
        let b = t.as_bytes();
        if b.is_empty()
            || b.len() > 128
            || !(alnum(b[0]) || b[0] == b'_')
            || !b
                .iter()
                .all(|&c| alnum(c) || matches!(c, b'.' | b'_' | b'-'))
        {
            return false;
        }
    }
    path.split('/').all(image_component)
}

fn image_re(s: &str) -> bool {
    if image_rest(s) {
        return true;
    }
    match s.find('/') {
        Some(i) => image_domain(&s[..i]) && image_rest(&s[i + 1..]),
        None => false,
    }
}

/// `^[a-z0-9]([a-z0-9._/-]*[a-z0-9])?$`
fn label_key_re(s: &str) -> bool {
    edged(s, lower_alnum, |c| {
        lower_alnum(c) || matches!(c, b'.' | b'_' | b'/' | b'-')
    })
}

/// `^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`
fn label_value_re(s: &str) -> bool {
    edged(s, lower_alnum, |c| {
        lower_alnum(c) || matches!(c, b'.' | b'_' | b'-')
    })
}

/// `^(/[A-Za-z0-9._-]+)+$`
fn secret_file_path_re(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('/') else {
        return false;
    };
    rest.split('/').all(|p| {
        !p.is_empty()
            && p.bytes()
                .all(|c| alnum(c) || matches!(c, b'.' | b'_' | b'-'))
    })
}

/// `^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?$`
fn registry_host_re(s: &str) -> bool {
    let (host, port) = match s.find(':') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    host.split('.').all(label_re)
        && port.is_none_or(|p| (1..=5).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_digit()))
}

/// `^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`
fn cors_header_re(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 64 && alnum(b[0]) && b.iter().all(|&c| alnum(c) || c == b'-')
}

/// `^/[A-Za-z0-9._/-]*$`
fn nfs_path_re(s: &str) -> bool {
    s.starts_with('/')
        && s.bytes()
            .all(|c| alnum(c) || matches!(c, b'.' | b'_' | b'/' | b'-'))
}

/// `^([0-9]+)(Ki|Mi|Gi|K|M|G)?$`, the digits and the suffix.
fn memory_re(s: &str) -> Option<(&str, &str)> {
    let i = s
        .bytes()
        .position(|c| !c.is_ascii_digit())
        .unwrap_or(s.len());
    if i == 0 {
        return None;
    }
    let suffix = &s[i..];
    matches!(suffix, "" | "Ki" | "Mi" | "Gi" | "K" | "M" | "G").then_some((&s[..i], suffix))
}

#[derive(Default)]
pub(crate) struct Validator {
    pub errs: Vec<FieldError>,
}

impl Validator {
    pub(crate) fn add(&mut self, field: impl Into<String>, msg: impl Into<String>) {
        self.errs.push(FieldError {
            field: field.into(),
            msg: msg.into(),
        });
    }

    fn name(&mut self, field: &str, s: &str) {
        if s.is_empty() {
            self.add(field, "is required");
        } else if s.len() > 63 {
            self.add(field, "must be at most 63 characters");
        } else if !name_re(s) {
            self.add(field, NAME_RULE);
        }
    }

    fn space(&mut self, s: &str) {
        if s.is_empty() || s == DEFAULT_SPACE {
        } else if s.len() > MAX_SPACE_LEN {
            self.add(
                "space",
                format!("must be at most {MAX_SPACE_LEN} characters"),
            );
        } else if !name_re(s) {
            self.add("space", NAME_RULE);
        }
    }

    fn image(&mut self, field: &str, s: &str) {
        if s.is_empty() {
            self.add(field, "is required");
        } else if s.len() > MAX_IMAGE_LEN {
            self.add(field, format!("must be at most {MAX_IMAGE_LEN} characters"));
        } else if !image_re(s) {
            self.add(field, "is not a valid image reference");
        }
    }

    fn args(&mut self, field: &str, args: &[String]) {
        if args.len() > MAX_ARGS {
            self.add(field, format!("must have at most {MAX_ARGS} entries"));
            return;
        }
        for (i, a) in args.iter().enumerate() {
            if a.len() > MAX_ARG_LEN {
                self.add(
                    format!("{field}[{i}]"),
                    format!("must be at most {MAX_ARG_LEN} bytes"),
                );
            }
            if a.contains('\0') {
                self.add(format!("{field}[{i}]"), "must not contain NUL bytes");
            }
        }
    }

    fn env_in(&mut self, field: &str, env: &[EnvVar]) {
        if env.len() > MAX_ENV {
            self.add(field, format!("must have at most {MAX_ENV} entries"));
            return;
        }
        let mut seen = HashSet::new();
        for (i, e) in env.iter().enumerate() {
            let f = format!("{field}[{i}]");
            if !env_name_re(&e.name) {
                self.add(format!("{f}.name"), format!("must match {ENV_NAME_RE}"));
            } else if e.name.starts_with(RESERVED_ENV_PFX) || e.name == "PORT" {
                self.add(
                    format!("{f}.name"),
                    format!("{} is reserved for Armada", quote(&e.name)),
                );
            } else if seen.contains(&e.name) {
                self.add(
                    format!("{f}.name"),
                    format!("duplicate variable {}", quote(&e.name)),
                );
            }
            seen.insert(e.name.clone());
            if !e.secret_ref.is_empty() {
                if !e.value.is_empty() {
                    self.add(f.clone(), "set either value or secretRef, not both");
                }
                self.secret_name(&format!("{f}.secretRef"), &e.secret_ref);
            }
            if e.value.len() > MAX_ENV_VALUE_LEN {
                self.add(
                    format!("{f}.value"),
                    format!("must be at most {MAX_ENV_VALUE_LEN} bytes"),
                );
            }
            if e.value.contains('\0') {
                self.add(format!("{f}.value"), "must not contain NUL bytes");
            }
        }
    }

    fn ingress(&mut self, ing: Option<&Ingress>, this: &str) {
        let Some(i) = ing else { return };
        if i.timeout.0 != 0 && (i.timeout.0 < go::SECOND || i.timeout.0 > MAX_INGRESS_TIMEOUT) {
            self.add(
                "ingress.timeout",
                format!(
                    "must be between 1s and {}",
                    go::format_duration(MAX_INGRESS_TIMEOUT)
                ),
            );
        }
        match i.typ.as_str() {
            INGRESS_EXTERNAL => {}
            INGRESS_INTERNAL => {
                if !i.domains.is_empty() {
                    self.add(
                        "ingress.domains",
                        format!("custom domains require type external; internal apps are reachable at http://<app>{INTERNAL_SUFFIX}"),
                    );
                }
                if !i.ip_allow.is_empty() || !i.ip_deny.is_empty() {
                    self.add("ingress", "ipAllow and ipDeny require type external: internal callers are chosen with allow");
                }
                if i.dns.is_some() {
                    self.add(
                        "ingress.dns",
                        "is for the certificates of custom domains, which require type external",
                    );
                }
            }
            INGRESS_NONE => {
                if i.port != 0
                    || !i.protocol.is_empty()
                    || !i.domains.is_empty()
                    || !i.routes.is_empty()
                    || !i.allow.is_empty()
                    || !i.ip_allow.is_empty()
                    || !i.ip_deny.is_empty()
                    || i.sticky
                    || i.cors.is_some()
                    || i.dns.is_some()
                {
                    self.add(
                        "ingress",
                        "port, domains, routes, and allow require type external or internal",
                    );
                }
                return;
            }
            "" => {
                self.add("ingress.type", "is required (external, internal, or none)");
                return;
            }
            _ => {
                self.add("ingress.type", "must be external, internal, or none");
                return;
            }
        }
        if i.port < 1 || i.port > 65535 {
            self.add("ingress.port", "must be between 1 and 65535");
        }
        self.protocol(i);
        if i.domains.len() > MAX_DOMAINS {
            self.add(
                "ingress.domains",
                format!("must have at most {MAX_DOMAINS} entries"),
            );
        }
        let mut seen = HashSet::new();
        for (n, d) in i.domains.iter().enumerate() {
            let f = format!("ingress.domains[{n}]");
            if let Err(e) = validate_domain(d) {
                self.add(f, e);
            } else if seen.contains(d) {
                self.add(f, format!("duplicate domain {}", quote(d)));
            }
            seen.insert(d.clone());
        }
        if let Some(d) = &i.dns
            && i.typ == INGRESS_EXTERNAL
        {
            if d.provider != DNS_PROVIDER_CLOUDFLARE {
                self.add(
                    "ingress.dns.provider",
                    format!("must be {DNS_PROVIDER_CLOUDFLARE}"),
                );
            }
            self.secret_name("ingress.dns.tokenSecretRef", &d.token_secret_ref);
            if i.domains.is_empty() {
                self.add(
                    "ingress.dns",
                    "is for the certificates of custom domains; list them in ingress.domains (<app>.<root domain> uses the cluster's DNS provider)",
                );
            }
        }
        if !i.ip_allow.is_empty() && !i.ip_deny.is_empty() {
            self.add("ingress", "set ipAllow or ipDeny, not both");
        }
        self.ip_ranges("ingress.ipAllow", &i.ip_allow);
        self.ip_ranges("ingress.ipDeny", &i.ip_deny);
        self.cors(i.cors.as_ref());
        if i.allow.len() > MAX_ALLOW {
            self.add(
                "ingress.allow",
                format!("must have at most {MAX_ALLOW} entries"),
            );
        }
        let mut allowed = HashSet::new();
        for (n, a) in i.allow.iter().enumerate() {
            let f = format!("ingress.allow[{n}]");
            if !valid_name(a) {
                self.add(
                    f,
                    format!(
                        "{} is not an app name of this space (lowercase letters, digits, and single hyphens)",
                        quote(a)
                    ),
                );
            } else if a == this {
                self.add(f, "the app itself may always call itself; leave it out");
            } else if allowed.contains(a) {
                self.add(f, format!("duplicate app {}", quote(a)));
            }
            allowed.insert(a.clone());
        }
        if i.routes.len() > MAX_ROUTES {
            self.add(
                "ingress.routes",
                format!("must have at most {MAX_ROUTES} entries"),
            );
        }
        let mut paths = HashSet::new();
        for (n, r) in i.routes.iter().enumerate() {
            let f = format!("ingress.routes[{n}].path");
            if let Err(e) = validate_route_path(&r.path) {
                self.add(f, e);
                continue;
            }
            if paths.contains(&r.path) {
                self.add(f, format!("duplicate path {}", quote(&r.path)));
            }
            paths.insert(r.path.clone());
            if r.path == "/" && r.strip_prefix {
                self.add(
                    format!("ingress.routes[{n}].stripPrefix"),
                    "cannot strip the root path",
                );
            }
        }
    }

    fn protocol(&mut self, i: &Ingress) {
        match i.protocol.as_str() {
            "" | PROTOCOL_HTTP => return,
            PROTOCOL_TCP => {}
            _ => {
                self.add("ingress.protocol", "must be http or tcp");
                return;
            }
        }
        if i.typ != INGRESS_INTERNAL {
            self.add(
                "ingress.protocol",
                format!(
                    "tcp is internal only: set type internal; apps of the space then connect to <app>{INTERNAL_SUFFIX}:<port>, and nothing outside the cluster can"
                ),
            );
        }
        if (1..=65535).contains(&i.port)
            && let Err(e) = check_tcp_port(i.port)
        {
            self.add("ingress.port", e);
        }
        for (name, set) in [
            ("routes", !i.routes.is_empty()),
            ("sticky", i.sticky),
            ("cors", i.cors.is_some()),
            ("timeout", i.timeout.0 != 0),
        ] {
            if set {
                self.add(
                    format!("ingress.{name}"),
                    "is HTTP only; not with protocol tcp",
                );
            }
        }
    }

    fn revisions(&mut self, a: &App) {
        let Some(r) = &a.revisions else { return };
        if a.is_job() {
            return;
        }
        match r.mode.as_str() {
            REVISIONS_SINGLE => {
                if !r.traffic.is_empty() {
                    self.add("revisions.traffic", "is only allowed in multiple mode");
                }
            }
            REVISIONS_MULTIPLE => {
                let ing = a.ingress.as_ref();
                if ing.is_none_or(|i| i.typ == INGRESS_NONE || i.typ.is_empty()) {
                    self.add(
                        "revisions.mode",
                        "multiple needs ingress (external or internal): traffic is split at the proxy",
                    );
                }
                if a.scale.as_ref().is_some_and(|s| s.min == Some(0)) {
                    self.add(
                        "revisions.mode",
                        "multiple cannot be combined with scale.min: 0",
                    );
                }
                // A missing ingress is not TCP.
                if Ingress::tcp(ing) {
                    self.add(
                        "revisions.mode",
                        "multiple needs HTTP ingress: revision labels are host names",
                    );
                }
                for e in check_traffic(&a.id(), &r.traffic, true) {
                    self.errs.push(e);
                }
            }
            _ => self.add("revisions.mode", "must be single or multiple"),
        }
    }

    fn probes(&mut self, p: Option<&Probes>) {
        let Some(p) = p else { return };
        for (name, probe) in [
            ("startup", &p.startup),
            ("readiness", &p.readiness),
            ("liveness", &p.liveness),
        ] {
            let Some(pr) = probe else { continue };
            let f = format!("probes.{name}");
            if !pr.command.is_empty() {
                self.probe_command(&f, pr);
            } else {
                if pr.path.len() > MAX_PATH_LEN || !probe_path_re(&pr.path) {
                    self.add(
                        format!("{f}.path"),
                        "must start with \"/\" and contain only URL-safe characters",
                    );
                }
                if pr.port < 1 || pr.port > 65535 {
                    self.add(
                        format!("{f}.port"),
                        "must be between 1 and 65535 (defaults to ingress.port)",
                    );
                }
            }
            if pr.initial_delay.0 < 0 || pr.initial_delay.0 > 10 * go::MINUTE {
                self.add(format!("{f}.initialDelay"), "must be between 0 and 10m");
            }
            if pr.period.0 < go::SECOND || pr.period.0 > 5 * go::MINUTE {
                self.add(format!("{f}.period"), "must be between 1s and 5m");
            }
            if pr.timeout.0 < go::SECOND || pr.timeout > pr.period {
                self.add(
                    format!("{f}.timeout"),
                    "must be at least 1s and not longer than period",
                );
            }
            if pr.failure_threshold < 1 || pr.failure_threshold > 100 {
                self.add(format!("{f}.failureThreshold"), "must be between 1 and 100");
            }
        }
    }

    fn probe_command(&mut self, f: &str, pr: &Probe) {
        if !pr.path.is_empty() || pr.port != 0 {
            self.add(
                format!("{f}.command"),
                "cannot be combined with path or port",
            );
        }
        if pr.command.len() > MAX_PROBE_ARGS {
            self.add(
                format!("{f}.command"),
                format!("must have at most {MAX_PROBE_ARGS} entries"),
            );
        }
        if pr.command[0].is_empty() {
            self.add(format!("{f}.command"), "must start with the program to run");
        }
        if pr
            .command
            .iter()
            .any(|a| a.len() > MAX_PROBE_ARG_LEN || a.contains('\0'))
        {
            self.add(
                format!("{f}.command"),
                format!("entries must be at most {MAX_PROBE_ARG_LEN} bytes, with no NUL"),
            );
        }
    }

    fn scale(&mut self, s: Option<&Scale>, ing: Option<&Ingress>) {
        let Some(s) = s else { return };
        let (Some(min_r), Some(max_r)) = (s.min, s.max) else {
            return;
        };
        if min_r == 0 {
            if s.rules.is_empty() {
                self.add(
                    "scale.min",
                    "can be 0 only with scale.rules, which take over once the app has woken up",
                );
            }
            if ing.is_none_or(|i| i.typ == INGRESS_NONE || i.typ.is_empty()) {
                self.add(
                    "scale.min",
                    "can be 0 only with ingress (external or internal): a request wakes the app",
                );
            } else if Ingress::tcp(ing) {
                self.add(
                    "scale.min",
                    "can be 0 only with HTTP ingress: a request wakes the app",
                );
            }
        } else if !(0..=MAX_REPLICAS).contains(&min_r) {
            self.add("scale.min", format!("must be between 0 and {MAX_REPLICAS}"));
        }
        let idle = s.idle_after.0;
        if idle == 0 {
        } else if min_r != 0 {
            self.add("scale.idleAfter", "is only valid with scale.min: 0");
        } else if !(MIN_IDLE_AFTER..=MAX_IDLE_AFTER).contains(&idle) {
            self.add(
                "scale.idleAfter",
                format!(
                    "must be between {} and {}",
                    go::format_duration(MIN_IDLE_AFTER),
                    go::format_duration(MAX_IDLE_AFTER)
                ),
            );
        }
        if max_r < min_r || max_r > MAX_REPLICAS {
            self.add(
                "scale.max",
                format!("must be between scale.min and {MAX_REPLICAS}"),
            );
        }
        self.scale_rules(s, min_r, max_r, ing);
    }

    fn scale_rules(&mut self, s: &Scale, min_r: i64, max_r: i64, ing: Option<&Ingress>) {
        if s.rules.is_empty() {
            return;
        }
        if max_r <= min_r {
            self.add(
                "scale.max",
                "must be greater than scale.min when scale.rules are set",
            );
        }
        let mut seen = HashSet::new();
        let mut schedules = 0;
        for (i, r) in s.rules.iter().enumerate() {
            let f = format!("scale.rules[{i}]");
            if r.typ == SCALE_SCHEDULE {
                schedules += 1;
                if schedules == MAX_SCHEDULE_RULES + 1 {
                    self.add(
                        f.clone(),
                        format!("an app takes at most {MAX_SCHEDULE_RULES} schedule rules"),
                    );
                }
            } else if seen.contains(&r.typ) {
                self.add(
                    format!("{f}.type"),
                    format!("{} is used more than once", quote(&r.typ)),
                );
            }
            seen.insert(r.typ.clone());
            // Sorted by name.
            let set = [
                ("command", !r.command.is_empty()),
                ("concurrent", r.concurrent != 0),
                ("duration", r.duration.0 != 0),
                ("length", r.length != 0),
                ("list", !r.list.is_empty()),
                ("queue", !r.queue.is_empty()),
                ("replicas", r.replicas != 0),
                ("schedule", !r.schedule.is_empty()),
                ("timeZone", !r.time_zone.is_empty()),
                ("urlSecretRef", !r.url_secret_ref.is_empty()),
                ("utilization", r.utilization != 0),
            ];
            let allowed: Option<&[&str]> = match r.typ.as_str() {
                SCALE_HTTP => Some(&["concurrent"]),
                SCALE_CPU | SCALE_MEMORY => Some(&["utilization"]),
                SCALE_QUEUE => Some(&["command", "length"]),
                SCALE_REDIS => Some(&["urlSecretRef", "list", "length"]),
                SCALE_RABBITMQ => Some(&["urlSecretRef", "queue", "length"]),
                SCALE_SCHEDULE => Some(&["schedule", "timeZone", "duration", "replicas"]),
                _ => None,
            };
            if let Some(fields) = allowed {
                for (name, on) in set {
                    if on && !fields.contains(&name) {
                        self.add(
                            format!("{f}.{name}"),
                            format!("is not valid for {} rules", r.typ),
                        );
                    }
                }
            }
            match r.typ.as_str() {
                SCALE_HTTP => {
                    if r.concurrent < 1 || r.concurrent > MAX_CONCURRENT {
                        self.add(
                            format!("{f}.concurrent"),
                            format!("must be between 1 and {MAX_CONCURRENT}"),
                        );
                    }
                    if ing.is_none_or(|i| i.typ == INGRESS_NONE || i.typ.is_empty()) {
                        self.add(
                            format!("{f}.type"),
                            "http rules need ingress (external or internal): requests are counted at the proxy",
                        );
                    } else if Ingress::tcp(ing) {
                        self.add(
                            format!("{f}.type"),
                            "http rules need HTTP ingress; scale a TCP app with cpu or memory rules",
                        );
                    }
                }
                SCALE_CPU | SCALE_MEMORY => {
                    if r.utilization < 1 || r.utilization > 100 {
                        self.add(
                            format!("{f}.utilization"),
                            format!("must be between 1 and 100 (percent of resources.{})", r.typ),
                        );
                    }
                }
                SCALE_QUEUE | SCALE_REDIS | SCALE_RABBITMQ => {
                    match r.typ.as_str() {
                        SCALE_QUEUE => {
                            if r.command.is_empty() {
                                self.add(
                                    format!("{f}.command"),
                                    "is required: a command run in a replica that prints the queue's length",
                                );
                            } else {
                                self.probe_command(
                                    &f,
                                    &Probe {
                                        command: r.command.clone(),
                                        ..Probe::default()
                                    },
                                );
                            }
                        }
                        SCALE_REDIS => {
                            self.secret_name(&format!("{f}.urlSecretRef"), &r.url_secret_ref);
                            self.broker_name(&format!("{f}.list"), &r.list, MAX_REDIS_LIST_LEN);
                        }
                        _ => {
                            self.secret_name(&format!("{f}.urlSecretRef"), &r.url_secret_ref);
                            self.broker_name(
                                &format!("{f}.queue"),
                                &r.queue,
                                MAX_RABBITMQ_QUEUE_LEN,
                            );
                        }
                    }
                    if r.length < 1 || r.length > MAX_QUEUE_LENGTH {
                        self.add(
                            format!("{f}.length"),
                            format!("must be between 1 and {MAX_QUEUE_LENGTH} (items per replica)"),
                        );
                    }
                    if min_r < 1 {
                        self.add(
                            format!("{f}.type"),
                            format!(
                                "{} rules need scale.min of at least 1: the length is read from a running replica",
                                r.typ
                            ),
                        );
                    }
                }
                SCALE_SCHEDULE => {
                    if r.schedule.is_empty() {
                        self.add(
                            format!("{f}.schedule"),
                            "is required: when the window starts (minute hour day-of-month month day-of-week)",
                        );
                    } else if r.schedule.len() > MAX_SCHEDULE_LEN {
                        self.add(
                            format!("{f}.schedule"),
                            format!("must be at most {MAX_SCHEDULE_LEN} characters"),
                        );
                    } else if r.time_zone.len() > MAX_TIME_ZONE_LEN {
                        self.add(
                            format!("{f}.timeZone"),
                            format!("must be at most {MAX_TIME_ZONE_LEN} characters"),
                        );
                    } else if let Err(e) = parse_schedule(&r.schedule, &r.time_zone) {
                        self.add(format!("{f}.schedule"), e);
                    }
                    let d = r.duration.0;
                    if !(MIN_SCHEDULE_DURATION..=MAX_SCHEDULE_DURATION).contains(&d) {
                        self.add(
                            format!("{f}.duration"),
                            format!(
                                "must be between {} and {}",
                                go::format_duration(MIN_SCHEDULE_DURATION),
                                go::format_duration(MAX_SCHEDULE_DURATION)
                            ),
                        );
                    }
                    if r.replicas < 1 || r.replicas > max_r {
                        self.add(format!("{f}.replicas"), "must be between 1 and scale.max");
                    }
                }
                _ => self.add(
                    format!("{f}.type"),
                    format!(
                        "must be {}, {}, {}, {}, {}, {}, or {}",
                        quote(SCALE_HTTP),
                        quote(SCALE_CPU),
                        quote(SCALE_MEMORY),
                        quote(SCALE_QUEUE),
                        quote(SCALE_REDIS),
                        quote(SCALE_RABBITMQ),
                        quote(SCALE_SCHEDULE)
                    ),
                ),
            }
        }
    }

    fn cors(&mut self, c: Option<&Cors>) {
        let Some(c) = c else { return };
        let origins = c.origins();
        if origins.is_empty() {
            self.add(
                "ingress.cors.allowOrigins",
                "is required: the origins browsers may call from, such as https://app.example.com, or \"*\"",
            );
        } else if origins.len() > MAX_CORS_ORIGINS {
            self.add(
                "ingress.cors.allowOrigins",
                format!("must have at most {MAX_CORS_ORIGINS} entries"),
            );
        }
        let mut seen = HashSet::new();
        for (i, o) in origins.iter().enumerate() {
            let f = format!("ingress.cors.allowOrigins[{i}]");
            if o == "*" {
                if origins.len() > 1 {
                    self.add(f.clone(), "\"*\" allows every origin; leave the others out");
                }
                if c.allow_credentials {
                    self.add(
                        f,
                        "\"*\" cannot be combined with allowCredentials: name the origins",
                    );
                }
            } else if !valid_cors_origin(o) {
                self.add(
                    f,
                    format!("{} is not an origin such as https://app.example.com or http://localhost:3000", quote(o)),
                );
            } else if seen.contains(o) {
                self.add(f, format!("duplicate origin {}", quote(o)));
            }
            seen.insert(o.clone());
        }
        for (i, m) in c.allow_methods.iter().enumerate() {
            if !CORS_METHOD_NAMES.contains(&m.as_str()) {
                self.add(
                    format!("ingress.cors.allowMethods[{i}]"),
                    format!("must be one of {}", CORS_METHOD_NAMES.join(", ")),
                );
            }
        }
        // In the order the fields are written in.
        for (field, list) in [
            ("allowHeaders", &c.allow_headers),
            ("exposeHeaders", &c.expose_headers),
        ] {
            if list.len() > MAX_CORS_HEADERS {
                self.add(
                    format!("ingress.cors.{field}"),
                    format!("must have at most {MAX_CORS_HEADERS} entries"),
                );
                continue;
            }
            for (i, h) in list.iter().enumerate() {
                if !cors_header_re(h) {
                    self.add(
                        format!("ingress.cors.{field}[{i}]"),
                        format!(
                            "{} is not a header name (letters, digits, and hyphens)",
                            quote(h)
                        ),
                    );
                }
            }
        }
        let d = c.max_age.0;
        if !(0..=MAX_CORS_MAX_AGE).contains(&d) {
            self.add(
                "ingress.cors.maxAge",
                format!(
                    "must be between 0 and {}",
                    go::format_duration(MAX_CORS_MAX_AGE)
                ),
            );
        }
    }

    fn ip_ranges(&mut self, field: &str, rules: &[IPRule]) {
        if rules.len() > MAX_IP_RANGES {
            self.add(field, format!("must have at most {MAX_IP_RANGES} entries"));
            return;
        }
        let mut seen: HashSet<Option<go::Prefix>> = HashSet::new();
        let mut names = HashSet::new();
        for (i, r) in rules.iter().enumerate() {
            let f = format!("{field}[{i}]");
            let p = parse_ip_range(&r.range);
            if r.range.is_empty() {
                self.add(
                    format!("{f}.range"),
                    "is required: an address or prefix such as 203.0.113.0/24",
                );
            } else if let Err(e) = &p {
                self.add(format!("{f}.range"), e.clone());
            } else if seen.contains(&p.clone().ok()) {
                self.add(
                    format!("{f}.range"),
                    format!(
                        "duplicate range {}",
                        p.as_ref().map(go::Prefix::string).unwrap_or_default()
                    ),
                );
            }
            seen.insert(p.ok());
            if !r.name.is_empty() {
                if !printable_text(&r.name, MAX_IP_RULE_NAME) {
                    self.add(
                        format!("{f}.name"),
                        format!("must be at most {MAX_IP_RULE_NAME} characters of printable text"),
                    );
                } else if names.contains(&r.name) {
                    self.add(
                        format!("{f}.name"),
                        format!("duplicate name {}", quote(&r.name)),
                    );
                }
                names.insert(r.name.clone());
            }
            if !printable_text(&r.description, MAX_IP_RULE_DESCRIPTION) {
                self.add(
                    format!("{f}.description"),
                    format!(
                        "must be at most {MAX_IP_RULE_DESCRIPTION} characters of printable text"
                    ),
                );
            }
        }
    }

    fn broker_name(&mut self, field: &str, s: &str, max: usize) {
        if s.is_empty() {
            self.add(field, "is required");
        } else if s.len() > max {
            self.add(field, format!("must be at most {max} bytes"));
        } else if s.chars().any(|r| (r as u32) < 0x20 || r as u32 == 0x7f) {
            self.add(field, "must be printable UTF-8");
        }
    }

    fn resources_in(&mut self, field: &str, r: Option<&Resources>) {
        let Some(r) = r else { return };
        if !r.memory.is_empty() {
            match parse_memory(&r.memory) {
                Err(e) => self.add(format!("{field}.memory"), e),
                Ok(m) if !(MIN_MEMORY_BYTES..=MAX_MEMORY_BYTES).contains(&m) => {
                    self.add(format!("{field}.memory"), "must be between 16Mi and 64Gi")
                }
                Ok(_) => {}
            }
        }
        if !r.cpu.is_empty() {
            match parse_cpu(&r.cpu) {
                Err(e) => self.add(format!("{field}.cpu"), e),
                Ok(c) if !(MIN_NANO_CPUS..=MAX_NANO_CPUS).contains(&c) => {
                    self.add(format!("{field}.cpu"), "must be between 10m and 64")
                }
                Ok(_) => {}
            }
        }
    }

    fn placement(&mut self, p: Option<&Placement>) {
        let Some(p) = p else { return };
        if !p.spread_by.is_empty()
            && let Err(e) = check_label_key(&p.spread_by)
        {
            self.add("placement.spreadBy", e);
        }
        if p.require.is_empty() {
            if p.spread_by.is_empty() {
                self.add("placement", "must set require or spreadBy");
            }
            return;
        }
        if p.require.len() > MAX_REQUIRE {
            self.add(
                "placement.require",
                format!("must have at most {MAX_REQUIRE} labels"),
            );
            return;
        }
        // Keys in sorted order.
        for (k, vals) in &p.require {
            let f = format!("placement.require.{k}");
            if let Err(e) = check_label_key(k) {
                self.add("placement.require", e);
                continue;
            }
            let vals = vals.as_deref().unwrap_or(&[]);
            if vals.is_empty() || vals.len() > MAX_REQUIRE {
                self.add(f, format!("must list between 1 and {MAX_REQUIRE} values"));
                continue;
            }
            for v in vals {
                if let Err(e) = check_label_value(v) {
                    self.add(f.clone(), e);
                }
            }
        }
    }

    fn volumes(&mut self, a: &App) {
        if a.volumes.is_empty() {
            return;
        }
        if a.is_job() {
            self.add("volumes", "jobs cannot have volumes yet");
            return;
        }
        if a.volumes.len() > MAX_VOLUMES {
            self.add(
                "volumes",
                format!("must have at most {MAX_VOLUMES} entries"),
            );
            return;
        }
        let mut names = HashSet::new();
        let mut paths: Vec<String> = a.secret_files.iter().map(|f| f.path.clone()).collect();
        let first = a.volumes.iter().position(Volume::local);
        for (i, vol) in a.volumes.iter().enumerate() {
            let field = format!("volumes[{i}]");
            self.name(&format!("{field}.name"), &vol.name);
            if names.contains(&vol.name) {
                self.add(
                    format!("{field}.name"),
                    format!("{} is used more than once", quote(&vol.name)),
                );
            }
            names.insert(vol.name.clone());
            if let Some(msg) = check_secret_file_path(&vol.path) {
                self.add(format!("{field}.path"), msg);
            } else {
                for p in &paths {
                    if *p == vol.path
                        || vol.path.starts_with(&format!("{p}/"))
                        || p.starts_with(&format!("{}/", vol.path))
                    {
                        self.add(
                            format!("{field}.path"),
                            format!("{} and {} overlap", quote(p), quote(&vol.path)),
                        );
                    }
                }
                paths.push(vol.path.clone());
            }
            if !vol.owner.is_empty()
                && let Err(e) = parse_owner(&vol.owner)
            {
                self.add(format!("{field}.owner"), e);
            }
            if let Some(n) = &vol.nfs {
                if let Err(e) = check_nfs_server(&n.server) {
                    self.add(format!("{field}.nfs.server"), e);
                }
                if let Err(e) = check_nfs_path(&n.path) {
                    self.add(format!("{field}.nfs.path"), e);
                }
                if !vol.owner.is_empty() {
                    self.add(
                        format!("{field}.owner"),
                        "is set on the NFS server for an NFS volume",
                    );
                }
                if vol.backup.is_some() || !vol.failover.is_empty() {
                    self.add(
                        format!("{field}.backup"),
                        "an NFS volume is backed up by its server; leave backup and failover out",
                    );
                }
            }
            if let Some(b) = &vol.backup {
                self.volume_backup(&format!("{field}.backup"), b);
            }
            if vol.failover.is_empty() {
            } else if vol.failover != FAILOVER_RESTORE {
                self.add(
                    format!("{field}.failover"),
                    format!("must be {} or left out", quote(FAILOVER_RESTORE)),
                );
            } else if vol.backup.is_none() {
                self.add(
                    format!("{field}.failover"),
                    "restores the latest backup, so the volume needs backup",
                );
            }
            // With no local volume first is None, and vol.local() is
            // false first.
            if vol.local()
                && let Some(first) = first
                && vol.failover.is_empty() != a.volumes[first].failover.is_empty()
            {
                self.add(
                    format!("{field}.failover"),
                    "must be set on every volume of the app on its node, or on none: the app moves with all of them",
                );
            }
        }
        if !a.has_local_volumes() {
            return;
        }
        if let Some(s) = &a.scale
            && (s.min.is_some_and(|m| m != 1)
                || s.max.is_some_and(|m| m != 1)
                || !s.rules.is_empty())
        {
            self.add(
                "scale",
                "an app with volumes runs exactly one replica (min and max 1, no rules)",
            );
        }
        if a.multiple_revisions() {
            self.add(
                "revisions.mode",
                "an app with volumes runs one revision at a time; use single mode",
            );
        }
    }

    fn volume_backup(&mut self, field: &str, b: &VolumeBackup) {
        self.backup_plan(field, b);
        self.secret_name(&format!("{field}.urlSecretRef"), &b.url_secret_ref);
        self.secret_name(&format!("{field}.keySecretRef"), &b.key_secret_ref);
        if !b.url_secret_ref.is_empty() && b.url_secret_ref == b.key_secret_ref {
            self.add(
                format!("{field}.keySecretRef"),
                "must be another secret than urlSecretRef",
            );
        }
    }

    fn backup_plan(&mut self, field: &str, b: &VolumeBackup) {
        let every = b.every.0;
        if every == 0 && b.schedule.is_empty() {
            self.add(field, "needs every or schedule");
        } else if every != 0 && !b.schedule.is_empty() {
            self.add(field, "takes every or schedule, not both");
        } else if every != 0 && !(MIN_BACKUP_EVERY..=MAX_BACKUP_EVERY).contains(&every) {
            self.add(
                format!("{field}.every"),
                format!(
                    "must be from {} to 168h",
                    go::format_duration(MIN_BACKUP_EVERY)
                ),
            );
        } else if every != 0 && !b.time_zone.is_empty() {
            if b.time_zone.len() > MAX_TIME_ZONE_LEN {
                self.add(
                    format!("{field}.timeZone"),
                    format!("must be at most {MAX_TIME_ZONE_LEN} characters"),
                );
            } else if load_location(&b.time_zone).is_none() {
                self.add(
                    format!("{field}.timeZone"),
                    format!("unknown time zone {}", quote(&b.time_zone)),
                );
            }
        } else if !b.schedule.is_empty() {
            if b.schedule.len() > MAX_SCHEDULE_LEN {
                self.add(
                    format!("{field}.schedule"),
                    format!("must be at most {MAX_SCHEDULE_LEN} characters"),
                );
            } else if b.time_zone.len() > MAX_TIME_ZONE_LEN {
                self.add(
                    format!("{field}.timeZone"),
                    format!("must be at most {MAX_TIME_ZONE_LEN} characters"),
                );
            } else if let Err(e) = parse_schedule(&b.schedule, &b.time_zone) {
                self.add(format!("{field}.schedule"), e);
            }
        }
        let k = b.keep;
        let mut total = 0i64;
        for n in [k.last, k.hourly, k.daily, k.weekly, k.monthly] {
            if !(0..=MAX_BACKUP_KEEP).contains(&n) {
                self.add(
                    format!("{field}.keep"),
                    format!("each count must be from 0 to {MAX_BACKUP_KEEP}"),
                );
                total = -1;
                break;
            }
            total += n;
        }
        if total == 0 {
            self.add(format!("{field}.keep"), "must keep at least one backup");
        }
    }

    fn containers(&mut self, a: &App) {
        if a.init_containers.len() > MAX_INIT_CONTAINERS {
            self.add(
                "initContainers",
                format!("must have at most {MAX_INIT_CONTAINERS} entries"),
            );
            return;
        }
        if a.sidecars.len() > MAX_SIDECARS {
            self.add(
                "sidecars",
                format!("must have at most {MAX_SIDECARS} entries"),
            );
            return;
        }
        let mut names: HashSet<String> = HashSet::from([MAIN_CONTAINER.to_string()]);
        let volumes: HashSet<&str> = a.volumes.iter().map(|v| v.name.as_str()).collect();
        let files: HashSet<&str> = a.secret_files.iter().map(|f| f.path.as_str()).collect();
        let list = a
            .init_containers
            .iter()
            .enumerate()
            .map(|(i, c)| (format!("initContainers[{i}]"), c))
            .chain(
                a.sidecars
                    .iter()
                    .enumerate()
                    .map(|(i, c)| (format!("sidecars[{i}]"), c)),
            );
        for (field, c) in list {
            self.name(&format!("{field}.name"), &c.name);
            if c.name.len() > MAX_CONTAINER_NAME {
                self.add(
                    format!("{field}.name"),
                    format!("must be at most {MAX_CONTAINER_NAME} characters"),
                );
            } else if c.name == MAIN_CONTAINER {
                self.add(
                    format!("{field}.name"),
                    format!("{} is the app's own container", quote(MAIN_CONTAINER)),
                );
            } else if names.contains(&c.name) {
                self.add(
                    format!("{field}.name"),
                    format!("{} is used more than once", quote(&c.name)),
                );
            }
            names.insert(c.name.clone());
            self.image(&format!("{field}.image"), &c.image);
            self.args(&format!("{field}.command"), &c.command);
            self.args(&format!("{field}.args"), &c.args);
            self.env_in(&format!("{field}.env"), &c.env);
            self.resources_in(&format!("{field}.resources"), c.resources.as_ref());
            for (i, name) in c.volumes.iter().enumerate() {
                let f = format!("{field}.volumes[{i}]");
                if !volumes.contains(name.as_str()) {
                    self.add(
                        f,
                        format!("{} is not one of the app's volumes", quote(name)),
                    );
                } else if c.volumes.iter().position(|v| v == name) != Some(i) {
                    self.add(f, format!("{} is listed twice", quote(name)));
                }
            }
            for (i, path) in c.secret_files.iter().enumerate() {
                let f = format!("{field}.secretFiles[{i}]");
                if !files.contains(path.as_str()) {
                    self.add(
                        f,
                        format!(
                            "{} is not the path of one of the app's secret files",
                            quote(path)
                        ),
                    );
                } else if c.secret_files.iter().position(|v| v == path) != Some(i) {
                    self.add(f, format!("{} is listed twice", quote(path)));
                }
            }
        }
    }

    fn job(&mut self, a: &App) {
        if !a.is_job() {
            // In the order the fields are written in.
            for (field, set) in [
                ("schedule", !a.schedule.is_empty()),
                ("timeZone", !a.time_zone.is_empty()),
                ("timeout", a.timeout.0 != 0),
                ("retries", a.retries != 0),
                ("concurrency", !a.concurrency.is_empty()),
                ("history", a.history.is_some()),
                ("trigger", a.trigger.is_some()),
                ("tasks", a.tasks != 0),
                ("parallelism", a.parallelism != 0),
            ] {
                if set {
                    self.add(field, "is only valid for kind: job");
                }
            }
            return;
        }
        if a.ingress.as_ref().is_some_and(|i| i.typ != INGRESS_NONE) {
            self.add("ingress", "jobs take no traffic; leave ingress out");
        }
        if a.probes.is_some() {
            self.add("probes", "jobs have no health checks; leave probes out");
        }
        if a.drain.0 != 0 {
            self.add("drain", "jobs take no requests; leave drain out");
        }
        if a.scale.is_some() {
            self.add(
                "scale",
                "a job runs one container per run, or per task with tasks; leave scale out",
            );
        }
        if a.revisions
            .as_ref()
            .is_some_and(|r| r.mode != REVISIONS_SINGLE || !r.traffic.is_empty())
        {
            self.add(
                "revisions",
                "jobs have no traffic to split; leave revisions out",
            );
        }
        if a.schedule.len() > MAX_SCHEDULE_LEN {
            self.add(
                "schedule",
                format!("must be at most {MAX_SCHEDULE_LEN} characters"),
            );
        } else if a.time_zone.len() > MAX_TIME_ZONE_LEN {
            self.add(
                "timeZone",
                format!("must be at most {MAX_TIME_ZONE_LEN} characters"),
            );
        } else if a.schedule.is_empty() && !a.time_zone.is_empty() {
            self.add("timeZone", "needs a schedule");
        } else if !a.schedule.is_empty()
            && let Err(e) = parse_schedule(&a.schedule, &a.time_zone)
        {
            self.add("schedule", e);
        }
        if a.timeout.0 != 0 && (a.timeout.0 < MIN_JOB_TIMEOUT || a.timeout.0 > MAX_JOB_TIMEOUT) {
            self.add(
                "timeout",
                format!(
                    "must be between {} and {}",
                    go::format_duration(MIN_JOB_TIMEOUT),
                    go::format_duration(MAX_JOB_TIMEOUT)
                ),
            );
        }
        if a.retries < 0 || a.retries > MAX_JOB_RETRIES {
            self.add(
                "retries",
                format!("must be between 0 and {MAX_JOB_RETRIES}"),
            );
        }
        match a.concurrency.as_str() {
            "" | CONCURRENCY_FORBID | CONCURRENCY_REPLACE => {}
            _ => self.add(
                "concurrency",
                format!(
                    "must be {} or {}",
                    quote(CONCURRENCY_FORBID),
                    quote(CONCURRENCY_REPLACE)
                ),
            ),
        }
        if a.history
            .is_some_and(|h| !(1..=MAX_JOB_HISTORY).contains(&h))
        {
            self.add(
                "history",
                format!("must be between 1 and {MAX_JOB_HISTORY}"),
            );
        }
        if a.tasks < 0 || a.tasks > MAX_JOB_TASKS {
            self.add("tasks", format!("must be between 1 and {MAX_JOB_TASKS}"));
        } else if a.parallelism < 0 || a.parallelism > a.job_tasks() {
            self.add(
                "parallelism",
                format!("must be between 1 and tasks ({})", a.job_tasks()),
            );
        } else if a.tasks > 1 && a.trigger.is_some() {
            self.add(
                "tasks",
                "a job its queue starts runs one task per run; set trigger.parallelism and trigger.perRun instead",
            );
        }
        self.trigger(a);
    }

    fn trigger(&mut self, a: &App) {
        let Some(t) = &a.trigger else { return };
        let Some(q) = &t.queue else {
            self.add(
                "trigger.queue",
                "is required: the queue whose messages start runs",
            );
            return;
        };
        if !a.schedule.is_empty() {
            self.add(
                "trigger",
                "a job starts runs on a schedule or from a queue, not both; leave schedule out",
            );
        }
        if !a.concurrency.is_empty() {
            self.add(
                "concurrency",
                "jobs with a trigger keep up to trigger.parallelism runs at once; leave concurrency out",
            );
        }
        let allowed: Option<&[&str]> = match q.typ.as_str() {
            SCALE_REDIS => {
                self.secret_name("trigger.queue.urlSecretRef", &q.url_secret_ref);
                self.broker_name("trigger.queue.list", &q.list, MAX_REDIS_LIST_LEN);
                Some(&["urlSecretRef", "list"])
            }
            SCALE_RABBITMQ => {
                self.secret_name("trigger.queue.urlSecretRef", &q.url_secret_ref);
                self.broker_name("trigger.queue.queue", &q.queue, MAX_RABBITMQ_QUEUE_LEN);
                Some(&["urlSecretRef", "queue"])
            }
            _ => {
                self.add(
                    "trigger.queue.type",
                    format!(
                        "must be {} or {}",
                        quote(SCALE_REDIS),
                        quote(SCALE_RABBITMQ)
                    ),
                );
                None
            }
        };
        if let Some(fields) = allowed {
            for (name, set) in [
                ("list", !q.list.is_empty()),
                ("queue", !q.queue.is_empty()),
                ("urlSecretRef", !q.url_secret_ref.is_empty()),
            ] {
                if set && !fields.contains(&name) {
                    self.add(
                        format!("trigger.queue.{name}"),
                        format!("is not valid for {} queues", q.typ),
                    );
                }
            }
        }
        if q.per_run < 1 || q.per_run > MAX_QUEUE_LENGTH {
            self.add(
                "trigger.queue.perRun",
                format!("must be between 1 and {MAX_QUEUE_LENGTH} (messages one run handles)"),
            );
        }
        let d = t.polling_interval.0;
        if d != 0 && !(MIN_POLLING_INTERVAL..=MAX_POLLING_INTERVAL).contains(&d) {
            self.add(
                "trigger.pollingInterval",
                format!(
                    "must be between {} and {}",
                    go::format_duration(MIN_POLLING_INTERVAL),
                    go::format_duration(MAX_POLLING_INTERVAL)
                ),
            );
        }
        if t.parallelism != 0 && !(1..=MAX_JOB_PARALLELISM).contains(&t.parallelism) {
            self.add(
                "trigger.parallelism",
                format!("must be between 1 and {MAX_JOB_PARALLELISM}"),
            );
        }
    }

    pub(crate) fn secret_name(&mut self, field: &str, r: &str) {
        if let Err(e) = validate_secret_ref(r) {
            let msg = e.strip_prefix("secret name ").unwrap_or(&e);
            let msg = msg.strip_prefix("key ").unwrap_or(msg);
            self.add(field, msg.to_string());
        }
    }

    fn secret_files(&mut self, files: &[SecretFile]) {
        if files.len() > MAX_SECRET_FILES {
            self.add(
                "secretFiles",
                format!("must have at most {MAX_SECRET_FILES} entries"),
            );
            return;
        }
        let mut paths: Vec<&str> = Vec::new();
        for (i, f) in files.iter().enumerate() {
            let field = format!("secretFiles[{i}]");
            self.secret_name(&format!("{field}.secretRef"), &f.secret_ref);
            if let Some(msg) = check_secret_file_path(&f.path) {
                self.add(format!("{field}.path"), msg);
                continue;
            }
            for p in &paths {
                if *p == f.path {
                    self.add(
                        format!("{field}.path"),
                        format!("duplicate path {}", quote(&f.path)),
                    );
                } else if f.path.starts_with(&format!("{p}/"))
                    || p.starts_with(&format!("{}/", f.path))
                {
                    self.add(
                        format!("{field}.path"),
                        format!("{} and {} overlap", quote(p), quote(&f.path)),
                    );
                }
            }
            paths.push(&f.path);
        }
    }

    fn registry(&mut self, r: Option<&Registry>, image: &str) {
        let Some(r) = r else { return };
        if r.server.is_empty() {
            self.add("registry.server", "is required");
        } else if r.server.len() > MAX_DOMAIN_LEN || !registry_host_re(&r.server) {
            self.add(
                "registry.server",
                "must be a lowercase host name with an optional port, e.g. ghcr.io",
            );
        } else if r.server != registry_host(image) {
            self.add(
                "registry.server",
                format!(
                    "must match the registry of image ({})",
                    registry_host(image)
                ),
            );
        }
        if r.username.is_empty() {
            self.add("registry.username", "is required");
        } else if r.username.len() > MAX_USERNAME_LEN {
            self.add(
                "registry.username",
                format!("must be at most {MAX_USERNAME_LEN} characters"),
            );
        } else if r
            .username
            .chars()
            .any(|c| (c as u32) < 0x21 || c as u32 == 0x7f)
        {
            self.add(
                "registry.username",
                "must not contain spaces or control characters",
            );
        }
        self.secret_name("registry.passwordSecretRef", &r.password_secret_ref);
    }

    fn env_from(&mut self, e: &EnvFrom) {
        let list = e.list();
        if e.own && !list.is_empty() {
            self.add(
                "envFrom",
                format!(
                    "must be {} or a list of secrets, not both",
                    quote(ENV_FROM_SECRETS)
                ),
            );
        } else if list.len() > MAX_ENV_FROM {
            self.add(
                "envFrom",
                format!("must list at most {MAX_ENV_FROM} secrets"),
            );
        }
        let mut seen = HashSet::new();
        for (i, s) in list.iter().enumerate() {
            let f = format!("envFrom[{i}].secret");
            if let Err(e) = validate_secret_name(&s.secret) {
                self.add(f, e.strip_prefix("secret name ").unwrap_or(&e).to_string());
            } else if seen.contains(&s.secret) {
                self.add(f, format!("secret {} is listed twice", quote(&s.secret)));
            }
            seen.insert(s.secret.clone());
        }
    }
}

impl App {
    /// Validate checks the spec and returns every problem.
    pub fn validate(&self) -> Result<(), Vec<FieldError>> {
        let mut v = Validator::default();
        if !self.api_version.is_empty() && self.api_version != API_VERSION {
            v.add("apiVersion", format!("must be {}", quote(API_VERSION)));
        }
        if self.kind != KIND_APP && self.kind != KIND_JOB {
            v.add(
                "kind",
                format!("must be {} or {}", quote(KIND_APP), quote(KIND_JOB)),
            );
        }
        v.name("name", &self.name);
        v.space(&self.space);
        v.image("image", &self.image);
        v.args("command", &self.command);
        v.args("args", &self.args);
        v.env_in("env", &self.env);
        v.env_from(&self.env_from);
        v.secret_files(&self.secret_files);
        v.registry(self.registry.as_ref(), &self.image);
        v.ingress(self.ingress.as_ref(), &self.name);
        if self.drain.0 != 0 && (self.drain.0 < go::SECOND || self.drain.0 > MAX_DRAIN) {
            v.add(
                "drain",
                format!("must be between 1s and {}", go::format_duration(MAX_DRAIN)),
            );
        }
        v.revisions(self);
        v.probes(self.probes.as_ref());
        v.scale(self.scale.as_ref(), self.ingress.as_ref());
        v.resources_in("resources", self.resources.as_ref());
        v.placement(self.placement.as_ref());
        v.volumes(self);
        v.containers(self);
        v.job(self);
        if v.errs.is_empty() {
            Ok(())
        } else {
            Err(v.errs)
        }
    }
}

/// ValidName: a valid app, job, or secret name.
pub fn valid_name(s: &str) -> bool {
    s.len() <= 63 && name_re(s)
}

/// ValidateName checks an app name.
pub fn validate_name(s: &str) -> Result<(), String> {
    let mut v = Validator::default();
    v.name("name", s);
    if v.errs.is_empty() {
        Ok(())
    } else {
        Err(join(&v.errs))
    }
}

/// ValidSpace: an app name of at most 30 characters.
pub fn valid_space(s: &str) -> bool {
    s.len() <= MAX_SPACE_LEN && name_re(s)
}

/// AppID: the name in the default space, <name>.<space> in any other.
pub fn app_id(space: &str, name: &str) -> String {
    if space.is_empty() || space == DEFAULT_SPACE {
        return name.to_string();
    }
    format!("{name}.{space}")
}

/// SplitAppID returns the space and name of a valid app ID.
pub fn split_app_id(id: &str) -> Option<(String, String)> {
    let (name, space) = match id.split_once('.') {
        None => (id, DEFAULT_SPACE),
        Some((n, s)) => {
            if s == DEFAULT_SPACE || !valid_space(s) {
                return None;
            }
            (n, s)
        }
    };
    if !valid_name(name) {
        return None;
    }
    Some((space.to_string(), name.to_string()))
}

pub fn valid_app_id(id: &str) -> bool {
    split_app_id(id).is_some()
}

/// CheckTCPPort reports why port cannot be a TCP app's port.
pub fn check_tcp_port(port: i64) -> Result<(), String> {
    if !(1..=65535).contains(&port) {
        return Err("must be between 1 and 65535".to_string());
    }
    if RESERVED_TCP_PORTS.contains(&port) {
        let list: Vec<String> = RESERVED_TCP_PORTS.iter().map(ToString::to_string).collect();
        return Err(format!(
            "{port} is reserved for Armada (reserved: {})",
            list.join(", ")
        ));
    }
    Ok(())
}

/// ValidateDomain: a lowercase, fully qualified host name.
pub fn validate_domain(d: &str) -> Result<(), String> {
    if d.is_empty() {
        return Err("must not be empty".to_string());
    }
    if d.len() > MAX_DOMAIN_LEN {
        return Err(format!("must be at most {MAX_DOMAIN_LEN} characters"));
    }
    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() < 2 {
        return Err("must be a fully qualified domain name".to_string());
    }
    for l in &labels {
        if l.is_empty() || l.len() > 63 || !label_re(l) {
            return Err(format!("{} is not a valid lowercase domain name", quote(d)));
        }
    }
    let last = labels[labels.len() - 1];
    if go::atoi(last).is_ok() {
        return Err("must be a domain name, not an IP address".to_string());
    }
    if format!(".{last}") == INTERNAL_SUFFIX {
        return Err(format!(
            "the {INTERNAL_SUFFIX} zone is reserved for names inside the cluster"
        ));
    }
    Ok(())
}

pub fn internal_host(app: &str) -> String {
    format!("{app}{INTERNAL_SUFFIX}")
}

/// InternalSearchDomain of an app ID.
pub fn internal_search_domain(id: &str) -> String {
    match split_app_id(id) {
        None => String::new(),
        Some((space, _)) if space == DEFAULT_SPACE => "internal".to_string(),
        Some((space, _)) => format!("{space}{INTERNAL_SUFFIX}"),
    }
}

pub fn valid_search_domain(s: &str) -> bool {
    if s == "internal" {
        return true;
    }
    match s.strip_suffix(INTERNAL_SUFFIX) {
        Some(space) => space != DEFAULT_SPACE && valid_space(space),
        None => false,
    }
}

pub fn label_host(label: &str, app: &str) -> String {
    format!("{label}--{app}")
}

fn host_label(id: &str) -> &str {
    id.split_once('.').map_or(id, |(n, _)| n)
}

/// ValidHostName: an app ID or a LabelHost of one.
pub fn valid_host_name(s: &str) -> bool {
    if valid_app_id(s) {
        return true;
    }
    match s.split_once("--") {
        Some((label, app)) => {
            valid_name(label) && valid_app_id(app) && label.len() + 2 + host_label(app).len() <= 63
        }
        None => false,
    }
}

/// ValidateRoutePath checks a route path prefix.
pub fn validate_route_path(p: &str) -> Result<(), String> {
    if p.len() > MAX_PATH_LEN {
        return Err(format!("must be at most {MAX_PATH_LEN} characters"));
    }
    if !route_path_re(p) {
        return Err(
            "must start with \"/\" and contain only letters, digits, and . _ ~ - separated by single \"/\", without a trailing \"/\""
                .to_string(),
        );
    }
    if p.split('/').any(|s| s == "." || s == "..") {
        return Err("must not contain \".\" or \"..\" segments".to_string());
    }
    Ok(())
}

/// ValidateProbePath checks an HTTP health check path.
pub fn validate_probe_path(p: &str) -> Result<(), String> {
    if p.len() > MAX_PATH_LEN || !probe_path_re(p) {
        return Err("must start with \"/\" and contain only URL-safe characters".to_string());
    }
    Ok(())
}

/// CheckTraffic validates the traffic targets of app.
pub fn check_traffic(app: &str, traffic: &[TrafficTarget], allow_latest: bool) -> Vec<FieldError> {
    let mut v = Validator::default();
    if traffic.is_empty() || traffic.len() > MAX_TRAFFIC_TARGETS {
        v.add(
            "revisions.traffic",
            format!("needs 1 to {MAX_TRAFFIC_TARGETS} targets"),
        );
        return v.errs;
    }
    let mut sum = 0i64;
    let mut revs = HashSet::new();
    let mut labels = HashSet::new();
    for (i, t) in traffic.iter().enumerate() {
        let f = format!("revisions.traffic[{i}]");
        if t.revision == LATEST_REVISION && allow_latest {
        } else if !valid_revision_name(app, &t.revision) {
            if allow_latest {
                v.add(
                    format!("{f}.revision"),
                    format!(
                        "must be {} or a revision of {app} such as {app}--r3",
                        quote(LATEST_REVISION)
                    ),
                );
            } else {
                v.add(
                    format!("{f}.revision"),
                    format!("must be a revision of {app} such as {app}--r3"),
                );
            }
        }
        if revs.contains(&t.revision) {
            v.add(
                format!("{f}.revision"),
                format!("{} is listed more than once", t.revision),
            );
        }
        revs.insert(t.revision.clone());
        if t.weight < 0 || t.weight > 100 {
            v.add(format!("{f}.weight"), "must be between 0 and 100");
        }
        sum = sum.wrapping_add(t.weight);
        if t.label.is_empty() {
            if t.weight == 0 {
                v.add(
                    format!("{f}.label"),
                    "is required for weight 0 (the revision is then reached only through its label)",
                );
            }
        } else if !valid_name(&t.label) {
            v.add(
                format!("{f}.label"),
                "must be lowercase letters, digits, and single hyphens, starting with a letter",
            );
        } else if t.label.len() + 2 + host_label(app).len() > 63 {
            v.add(
                format!("{f}.label"),
                format!(
                    "{}--{} must be at most 63 characters",
                    t.label,
                    host_label(app)
                ),
            );
        } else if labels.contains(&t.label) {
            v.add(
                format!("{f}.label"),
                format!("{} is used more than once", quote(&t.label)),
            );
        }
        labels.insert(t.label.clone());
    }
    if sum != 100 {
        v.add(
            "revisions.traffic",
            format!("weights must add up to 100, not {sum}"),
        );
    }
    v.errs
}

/// ValidRevisionName: rev is <app>--r<number>.
pub fn valid_revision_name(app: &str, rev: &str) -> bool {
    let Some(seq) = rev.strip_prefix(&format!("{app}--r")) else {
        return false;
    };
    !seq.is_empty()
        && !seq.starts_with('0')
        && seq.len() <= 9
        && seq.bytes().all(|c| c.is_ascii_digit())
}

/// ValidCORSHeader.
pub fn valid_cors_header(h: &str) -> bool {
    cors_header_re(h)
}

/// ValidCORSOrigin: http or https, a lowercase host name or localhost,
/// and an optional port.
pub fn valid_cors_origin(o: &str) -> bool {
    let rest = match o
        .strip_prefix("https://")
        .or_else(|| o.strip_prefix("http://"))
    {
        Some(r) => r,
        None => return false,
    };
    let (host, port) = match rest.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    if let Some(port) = port {
        match go::atoi(port) {
            Ok(n) if (1..=65535).contains(&n) && n.to_string() == port => {}
            _ => return false,
        }
    }
    host == "localhost" || validate_domain(host).is_ok()
}

/// printableText: UTF-8 of at most n characters with no control characters.
fn printable_text(s: &str, n: usize) -> bool {
    s.chars().count() <= n
        && !s
            .chars()
            .any(|r| go::is_control(r) || r == '\u{2028}' || r == '\u{2029}')
}

/// ParseIPRange reads an address or a prefix as a masked prefix.
pub fn parse_ip_range(s: &str) -> Result<go::Prefix, String> {
    let p = if let Some(a) = go::parse_addr(s) {
        if !a.zone.is_empty() {
            return Err(format!("{} has a zone", quote(s)));
        }
        go::Prefix::from(&a, a.bit_len())
    } else {
        go::parse_prefix(s).ok_or_else(|| {
            format!(
                "{} is not an IP address or prefix such as 203.0.113.0/24",
                quote(s)
            )
        })?
    };
    if p.addr.is4in6() {
        return Err(format!("{}: write IPv4 addresses as IPv4", quote(s)));
    }
    if p.bits == 0 {
        return Err(format!(
            "{} matches every address; leave the rule out instead",
            quote(s)
        ));
    }
    Ok(p.masked())
}

/// IPRanges: the rules' ranges as sorted canonical prefixes.
pub fn ip_ranges(rules: &[IPRule]) -> Vec<String> {
    let mut out: Vec<String> = rules
        .iter()
        .filter_map(|r| parse_ip_range(&r.range).ok())
        .map(|p| p.string())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// ParseMemory parses quantities like "512Mi", "1G", or "1048576".
pub fn parse_memory(s: &str) -> Result<i64, String> {
    let Some((digits, suffix)) = memory_re(s) else {
        return Err(format!(
            "invalid memory quantity {} (use e.g. 256Mi or 1Gi)",
            quote(s)
        ));
    };
    let n = go::parse_int(digits).map_err(|_| format!("invalid memory quantity {}", quote(s)))?;
    let mult: i64 = match suffix {
        "" => 1,
        "K" => 1000,
        "M" => 1_000_000,
        "G" => 1_000_000_000,
        "Ki" => 1 << 10,
        "Mi" => 1 << 20,
        _ => 1 << 30,
    };
    if n > i64::MAX / mult {
        return Err(format!("memory quantity {} is too large", quote(s)));
    }
    Ok(n * mult)
}

/// ParseCPU parses "500m" or "0.5" into nano-CPUs.
pub fn parse_cpu(s: &str) -> Result<i64, String> {
    if let Some(d) = s.strip_suffix('m')
        && !d.is_empty()
        && d.bytes().all(|c| c.is_ascii_digit())
    {
        return match go::parse_int(d) {
            Ok(n) if n <= i64::MAX / 1_000_000 => Ok(n * 1_000_000),
            _ => Err(format!("invalid cpu quantity {}", quote(s))),
        };
    }
    let (int, frac) = match s.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (s, None),
    };
    let core = !int.is_empty()
        && int.bytes().all(|c| c.is_ascii_digit())
        && frac.is_none_or(|f| (1..=3).contains(&f.len()) && f.bytes().all(|c| c.is_ascii_digit()));
    if core {
        return match s.parse::<f64>() {
            Ok(f) if f <= 1e6 => Ok((f * 1e9).round() as i64),
            _ => Err(format!("invalid cpu quantity {}", quote(s))),
        };
    }
    Err(format!(
        "invalid cpu quantity {} (use e.g. 0.5 or 500m)",
        quote(s)
    ))
}

/// CheckLabelKey.
pub fn check_label_key(k: &str) -> Result<(), String> {
    if k.is_empty() {
        return Err("label key is empty".to_string());
    }
    if k.len() > MAX_LABEL_LEN {
        return Err(format!(
            "label key {} is longer than {MAX_LABEL_LEN} characters",
            quote(k)
        ));
    }
    if !label_key_re(k) || k.contains("//") {
        return Err(format!(
            "label key {} must be lowercase letters, digits, '.', '-', '_', or '/', starting and ending with a letter or digit",
            quote(k)
        ));
    }
    Ok(())
}

/// CheckLabelValue.
pub fn check_label_value(v: &str) -> Result<(), String> {
    if v.is_empty() {
        return Err("label value is empty".to_string());
    }
    if v.len() > MAX_LABEL_LEN {
        return Err(format!(
            "label value {} is longer than {MAX_LABEL_LEN} characters",
            quote(v)
        ));
    }
    if !label_value_re(v) {
        return Err(format!(
            "label value {} must be lowercase letters, digits, '.', '-', or '_', starting and ending with a letter or digit",
            quote(v)
        ));
    }
    Ok(())
}

/// CheckAdminLabel.
pub fn check_admin_label(k: &str, v: &str) -> Result<(), String> {
    check_label_key(k)?;
    if k.starts_with(RESERVED_LABEL_PREFIX) {
        return Err(format!(
            "label key {}: the {} prefix is reserved for labels Armada sets",
            quote(k),
            quote(RESERVED_LABEL_PREFIX)
        ));
    }
    check_label_value(v)
}

impl Placement {
    /// Matches on a possibly nil placement.
    pub fn matches(p: Option<&Placement>, labels: &HashMap<String, String>) -> bool {
        let Some(p) = p else { return true };
        for (k, vals) in &p.require {
            match labels.get(k) {
                Some(v) if vals.as_deref().unwrap_or(&[]).contains(v) => {}
                _ => return false,
            }
        }
        p.spread_by.is_empty() || labels.contains_key(&p.spread_by)
    }

    pub fn spread_key(p: Option<&Placement>) -> String {
        p.map_or(String::new(), |p| p.spread_by.clone())
    }

    pub fn selects(p: Option<&Placement>, labels: &HashMap<String, String>) -> bool {
        let Some(p) = p else { return false };
        p.require
            .keys()
            .any(|k| !k.starts_with(RESERVED_LABEL_PREFIX) && labels.contains_key(k))
    }

    /// Placement.String.
    pub fn string(p: Option<&Placement>) -> String {
        let Some(p) = p else { return String::new() };
        let mut values: std::collections::BTreeMap<String, String> = p
            .require
            .iter()
            .map(|(k, v)| (k.clone(), v.as_deref().unwrap_or(&[]).join("|")))
            .collect();
        if !p.spread_by.is_empty() && !values.contains_key(&p.spread_by) {
            values.insert(p.spread_by.clone(), "*".to_string());
        }
        values
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// CheckNFSServer: a private IP address.
pub fn check_nfs_server(s: &str) -> Result<(), String> {
    let ip = match go::parse_addr(s) {
        Some(ip) if ip.zone.is_empty() => ip.unmap(),
        _ => return Err("must be an IP address".to_string()),
    };
    let shared = go::parse_prefix("100.64.0.0/10").expect("shared range");
    if !ip.is_private() && !shared.contains(&ip) {
        return Err(
            "must be a private address (10/8, 172.16/12, 192.168/16, 100.64/10, or fc00::/7)"
                .to_string(),
        );
    }
    Ok(())
}

/// CheckNFSPath: absolute, clean, of safe characters.
pub fn check_nfs_path(p: &str) -> Result<(), String> {
    if p.len() > MAX_NFS_PATH || !nfs_path_re(p) || go::clean_path(p) != p {
        return Err(format!(
            "must be an absolute, clean path of letters, digits, '.', '_', '-', and '/', at most {MAX_NFS_PATH} characters"
        ));
    }
    Ok(())
}

/// ParseOwner reads a volume's "uid:gid".
pub fn parse_owner(s: &str) -> Result<(i64, i64), String> {
    let Some((u, g)) = s.split_once(':') else {
        return Err("must be uid:gid, e.g. 999:999".to_string());
    };
    let mut ids = [0i64; 2];
    for (i, part) in [u, g].into_iter().enumerate() {
        match go::atoi(part) {
            Ok(n) if (0..=MAX_OWNER_ID).contains(&n) && n.to_string() == part => ids[i] = n,
            _ => {
                return Err(format!(
                    "must be uid:gid with numbers from 0 to {MAX_OWNER_ID}"
                ));
            }
        }
    }
    Ok((ids[0], ids[1]))
}

/// ValidateVolumePath.
pub fn validate_volume_path(p: &str) -> Result<(), String> {
    check_secret_file_path(p).map_or(Ok(()), Err)
}

/// CheckBackupPlan: when backups run and which are kept.
pub fn check_backup_plan(b: &VolumeBackup) -> Result<(), String> {
    let mut v = Validator::default();
    v.backup_plan("backup", b);
    match v.errs.first() {
        None => Ok(()),
        Some(e) => Err(e.to_string()),
    }
}

/// ValidateSecretName.
pub fn validate_secret_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("secret name is required".to_string());
    }
    if name.len() > MAX_SECRET_NAME_LEN {
        return Err(format!(
            "secret name must be at most {MAX_SECRET_NAME_LEN} characters"
        ));
    }
    if !label_re(name) {
        return Err(format!(
            "secret name {} must be lowercase letters, digits, and hyphens, not starting or ending with a hyphen",
            quote(name)
        ));
    }
    Ok(())
}

/// ValidateSecretKey.
pub fn validate_secret_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("key is required".to_string());
    }
    if key.len() > MAX_SECRET_NAME_LEN {
        return Err(format!(
            "key must be at most {MAX_SECRET_NAME_LEN} characters"
        ));
    }
    if !label_re(key) && !env_name_re(key) {
        return Err(format!(
            "key {} must be lowercase letters, digits, and hyphens (database-url), or a variable name (DATABASE_URL)",
            quote(key)
        ));
    }
    Ok(())
}

/// SplitSecretRef: SECRET/KEY, or a key of the app's own secret ("").
pub fn split_secret_ref(r: &str) -> (String, String) {
    match r.split_once('/') {
        Some((s, k)) => (s.to_string(), k.to_string()),
        None => (String::new(), r.to_string()),
    }
}

/// ValidateSecretRef: KEY or SECRET/KEY.
pub fn validate_secret_ref(r: &str) -> Result<(), String> {
    let (secret, key) = split_secret_ref(r);
    if r.matches('/').count() > 1 {
        return Err(format!("{} must be KEY or SECRET/KEY", quote(r)));
    }
    if r.contains('/') {
        validate_secret_name(&secret)?;
    }
    validate_secret_key(&key)
}

/// SecretSource: the ID of the secret ref names for the app appID, and the
/// key.
pub fn secret_source(app_id_: &str, r: &str) -> (String, String) {
    let (secret, key) = split_secret_ref(r);
    if secret.is_empty() {
        return (app_id_.to_string(), key);
    }
    let space = split_app_id(app_id_).map_or(String::new(), |(s, _)| s);
    (app_id(&space, &secret), key)
}

/// RegistryHost: the registry an image reference pulls from.
pub fn registry_host(image: &str) -> String {
    if let Some((first, _)) = image.split_once('/')
        && (first.contains(['.', ':']) || first == "localhost")
    {
        return first.to_lowercase();
    }
    DEFAULT_REGISTRY.to_string()
}

/// SecretEnvName: database-url becomes DATABASE_URL; other keys are kept.
pub fn secret_env_name(key: &str) -> String {
    if !label_re(key) {
        return key.to_string();
    }
    key.replace('-', "_").to_uppercase()
}

pub(crate) fn check_secret_file_path(p: &str) -> Option<String> {
    if p.is_empty() {
        return Some("is required".to_string());
    }
    if p.len() > MAX_PATH_LEN {
        return Some(format!("must be at most {MAX_PATH_LEN} characters"));
    }
    if !secret_file_path_re(p) {
        return Some(
            "must be an absolute path of letters, digits, '.', '_', '-', and '/'".to_string(),
        );
    }
    if p[1..].split('/').any(|part| part == "." || part == "..") {
        return Some("must not contain . or .. components".to_string());
    }
    if ["/etc/hosts", "/etc/hostname", "/etc/resolv.conf"].contains(&p) {
        return Some(format!("{p} is managed by the container runtime"));
    }
    for d in ["/proc", "/sys", "/dev"] {
        if p == d || p.starts_with(&format!("{d}/")) {
            return Some(format!("must not be under {d}"));
        }
    }
    None
}

impl App {
    /// SecretRefs: every secret reference, sorted, without duplicates.
    pub fn secret_refs(&self) -> Vec<String> {
        let mut refs: Vec<String> = Vec::new();
        refs.extend(
            self.env
                .iter()
                .filter(|e| !e.secret_ref.is_empty())
                .map(|e| e.secret_ref.clone()),
        );
        refs.extend(self.secret_files.iter().map(|f| f.secret_ref.clone()));
        for c in self.init_containers.iter().chain(&self.sidecars) {
            refs.extend(
                c.env
                    .iter()
                    .filter(|e| !e.secret_ref.is_empty())
                    .map(|e| e.secret_ref.clone()),
            );
        }
        if let Some(r) = &self.registry {
            refs.push(r.password_secret_ref.clone());
        }
        if let Some(s) = &self.scale {
            refs.extend(
                s.rules
                    .iter()
                    .filter(|r| !r.url_secret_ref.is_empty())
                    .map(|r| r.url_secret_ref.clone()),
            );
        }
        if let Some(q) = self.queue_trigger() {
            refs.push(q.url_secret_ref.clone());
        }
        refs.extend(self.backup_secret_refs());
        if let Some(d) = self.ingress.as_ref().and_then(|i| i.dns.as_ref()) {
            refs.push(d.token_secret_ref.clone());
        }
        refs.sort();
        refs.dedup();
        refs
    }

    /// BackupSecretRefs: the secrets the volumes' backups use.
    pub fn backup_secret_refs(&self) -> Vec<String> {
        let mut refs = Vec::new();
        for v in &self.volumes {
            if let Some(b) = &v.backup {
                refs.push(b.url_secret_ref.clone());
                refs.push(b.key_secret_ref.clone());
            }
        }
        refs
    }

    /// UsesSpaceSecrets: the spec names a secret other than its own.
    pub fn uses_space_secrets(&self) -> bool {
        !self.env_from.list().is_empty() || self.secret_refs().iter().any(|r| r.contains('/'))
    }

    /// WithSecretEnv: a copy whose env holds a variable for each key of the
    /// secrets envFrom names; keys maps a secret's name ("" for the app's
    /// own) to its keys.
    pub fn with_secret_env(
        &self,
        keys: &HashMap<String, Vec<String>>,
    ) -> Result<App, Vec<FieldError>> {
        if self.env_from.is_zero() {
            return Ok(self.clone());
        }
        let source = |r: &str| {
            let (secret, key) = split_secret_ref(r);
            let secret = if secret.is_empty() {
                self.name.clone()
            } else {
                secret
            };
            format!("{secret}/{key}")
        };
        let mut used = HashSet::new();
        for f in &self.secret_files {
            used.insert(source(&f.secret_ref));
        }
        if let Some(r) = &self.registry {
            used.insert(source(&r.password_secret_ref));
        }
        for s in self.backup_secret_refs() {
            used.insert(source(&s));
        }
        if let Some(d) = self.ingress.as_ref().and_then(|i| i.dns.as_ref()) {
            used.insert(source(&d.token_secret_ref));
        }
        let mut set: HashSet<String> = self.env.iter().map(|e| e.name.clone()).collect();
        let mut c = self.clone();
        c.env_from_added = Vec::new();
        let mut add = |r: String, c: &mut App| {
            let (_, key) = split_secret_ref(&r);
            let name = secret_env_name(&key);
            if used.contains(&source(&r))
                || set.contains(&name)
                || !env_name_re(&name)
                || name == "PORT"
                || name.starts_with(RESERVED_ENV_PFX)
            {
                return;
            }
            set.insert(name.clone());
            c.env.push(EnvVar {
                name: name.clone(),
                value: String::new(),
                secret_ref: r,
            });
            c.env_from_added.push(name);
        };
        if self.env_from.own {
            let mut own = keys.get("").cloned().unwrap_or_default();
            own.sort();
            for k in own {
                add(k, &mut c);
            }
        }
        for s in self.env_from.list() {
            let mut ks = keys.get(&s.secret).cloned().unwrap_or_default();
            ks.sort();
            for k in ks {
                add(format!("{}/{k}", s.secret), &mut c);
            }
        }
        c.validate()?;
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn armada_kv_ports_are_reserved() {
        // armada-kv's client and peer ports (ADR 0057), like etcd's.
        for p in [7445, 7446, 2379, 2380] {
            let e = check_tcp_port(p).unwrap_err();
            assert_eq!(
                e,
                format!(
                    "{p} is reserved for Armada (reserved: 22, 53, 80, 443, 2379, 2380, 4789, 7443, 7444, 7445, 7446, 7480, 8404, 51820)"
                )
            );
        }
        assert!(check_tcp_port(7447).is_ok());
    }

    #[test]
    fn patterns() {
        assert!(name_re("web-api"));
        assert!(!name_re("web--api"));
        assert!(!name_re("web-"));
        assert!(image_re("nginx:1.27"));
        assert!(image_re(
            "ghcr.io/org/app:1@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(image_re("localhost:5000/foo"));
        assert!(!image_re("Nginx"));
        assert!(!image_re("a._b"));
        assert!(image_re("a__b-----c.d"));
        assert!(route_path_re("/"));
        assert!(route_path_re("/a/b"));
        assert!(!route_path_re("/a/"));
        assert!(probe_path_re("/healthz?x=1"));
        assert_eq!(parse_memory("256Mi"), Ok(256 << 20));
        assert_eq!(parse_cpu("0.5"), Ok(500_000_000));
        assert_eq!(parse_cpu("500m"), Ok(500_000_000));
    }
}

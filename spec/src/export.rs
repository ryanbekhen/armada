//! App.Export: the spec as go-yaml's Encoder writes the App struct (field
//! order, omitempty, the MarshalYAML methods, map keys in keyList order),
//! with an indent of 2.

use crate::go;
use crate::spec::*;
use crate::yaml::encode::Encoder;

type R = Result<(), String>;

struct Out {
    e: Encoder,
}

impl Out {
    fn key(&mut self, k: &str) -> R {
        self.e.stringv("", k)
    }
    fn str(&mut self, k: &str, v: &str, omit: bool) -> R {
        if omit && v.is_empty() {
            return Ok(());
        }
        self.key(k)?;
        self.e.stringv("", v)
    }
    fn int(&mut self, k: &str, v: i64, omit: bool) -> R {
        if omit && v == 0 {
            return Ok(());
        }
        self.key(k)?;
        self.e.intv("", v)
    }
    fn bool(&mut self, k: &str, v: bool) -> R {
        if !v {
            return Ok(());
        }
        self.key(k)?;
        self.e.boolv("", v)
    }
    fn dur(&mut self, k: &str, v: Duration) -> R {
        if v.0 == 0 {
            return Ok(());
        }
        self.key(k)?;
        self.e.stringv("", &v.string())
    }
    fn strings(&mut self, v: &[String]) -> R {
        self.e.sequence_start("")?;
        for s in v {
            self.e.stringv("", s)?;
        }
        self.e.sequence_end()
    }
    fn list(&mut self, k: &str, v: &[String]) -> R {
        if v.is_empty() {
            return Ok(());
        }
        self.key(k)?;
        self.strings(v)
    }
    fn seq<T>(&mut self, k: &str, v: &[T], f: fn(&mut Out, &T) -> R) -> R {
        if v.is_empty() {
            return Ok(());
        }
        self.key(k)?;
        self.e.sequence_start("")?;
        for x in v {
            f(self, x)?;
        }
        self.e.sequence_end()
    }
    fn opt<T>(&mut self, k: &str, v: &Option<T>, f: fn(&mut Out, &T) -> R) -> R {
        let Some(x) = v else { return Ok(()) };
        self.key(k)?;
        f(self, x)
    }
    fn map(&mut self, f: impl FnOnce(&mut Out) -> R) -> R {
        self.e.mapping_start("")?;
        f(self)?;
        self.e.mapping_end()
    }
}

fn env_var(o: &mut Out, v: &EnvVar) -> R {
    o.map(|o| {
        o.str("name", &v.name, false)?;
        o.str("value", &v.value, true)?;
        o.str("secretRef", &v.secret_ref, true)
    })
}

fn secret_file(o: &mut Out, v: &SecretFile) -> R {
    o.map(|o| {
        o.str("secretRef", &v.secret_ref, false)?;
        o.str("path", &v.path, false)
    })
}

fn registry(o: &mut Out, v: &Registry) -> R {
    o.map(|o| {
        o.str("server", &v.server, false)?;
        o.str("username", &v.username, false)?;
        o.str("passwordSecretRef", &v.password_secret_ref, false)
    })
}

fn route(o: &mut Out, v: &Route) -> R {
    o.map(|o| {
        o.str("path", &v.path, false)?;
        o.bool("stripPrefix", v.strip_prefix)
    })
}

/// IPRule.MarshalYAML: the range alone when it has no name or description.
fn ip_rule(o: &mut Out, v: &IPRule) -> R {
    if v.name.is_empty() && v.description.is_empty() {
        return o.e.stringv("", &v.range);
    }
    o.map(|o| {
        o.str("range", &v.range, false)?;
        o.str("name", &v.name, true)?;
        o.str("description", &v.description, true)
    })
}

fn cors(o: &mut Out, v: &Cors) -> R {
    o.map(|o| {
        o.key("allowOrigins")?;
        o.strings(v.origins())?;
        o.list("allowMethods", &v.allow_methods)?;
        o.list("allowHeaders", &v.allow_headers)?;
        o.list("exposeHeaders", &v.expose_headers)?;
        o.dur("maxAge", v.max_age)?;
        o.bool("allowCredentials", v.allow_credentials)
    })
}

fn ingress_dns(o: &mut Out, v: &IngressDns) -> R {
    o.map(|o| {
        o.str("provider", &v.provider, false)?;
        o.str("tokenSecretRef", &v.token_secret_ref, false)
    })
}

fn ingress(o: &mut Out, v: &Ingress) -> R {
    o.map(|o| {
        o.str("type", &v.typ, false)?;
        o.str("protocol", &v.protocol, true)?;
        o.int("port", v.port, true)?;
        o.list("domains", &v.domains)?;
        o.seq("routes", &v.routes, route)?;
        o.list("allow", &v.allow)?;
        o.seq("ipAllow", &v.ip_allow, ip_rule)?;
        o.seq("ipDeny", &v.ip_deny, ip_rule)?;
        o.bool("sticky", v.sticky)?;
        o.opt("cors", &v.cors, cors)?;
        o.dur("timeout", v.timeout)?;
        o.opt("dns", &v.dns, ingress_dns)
    })
}

fn traffic_target(o: &mut Out, v: &TrafficTarget) -> R {
    o.map(|o| {
        o.str("revision", &v.revision, false)?;
        o.int("weight", v.weight, false)?;
        o.str("label", &v.label, true)
    })
}

fn revisions(o: &mut Out, v: &Revisions) -> R {
    o.map(|o| {
        o.str("mode", &v.mode, true)?;
        o.seq("traffic", &v.traffic, traffic_target)
    })
}

fn probe(o: &mut Out, v: &Probe) -> R {
    o.map(|o| {
        o.str("path", &v.path, true)?;
        o.list("command", &v.command)?;
        o.int("port", v.port, true)?;
        o.dur("initialDelay", v.initial_delay)?;
        o.dur("period", v.period)?;
        o.dur("timeout", v.timeout)?;
        o.int("failureThreshold", v.failure_threshold, true)
    })
}

fn probes(o: &mut Out, v: &Probes) -> R {
    o.map(|o| {
        o.opt("startup", &v.startup, probe)?;
        o.opt("readiness", &v.readiness, probe)?;
        o.opt("liveness", &v.liveness, probe)
    })
}

fn scale_rule(o: &mut Out, v: &ScaleRule) -> R {
    o.map(|o| {
        o.str("type", &v.typ, false)?;
        o.int("concurrent", v.concurrent, true)?;
        o.int("utilization", v.utilization, true)?;
        o.list("command", &v.command)?;
        o.str("urlSecretRef", &v.url_secret_ref, true)?;
        o.str("list", &v.list, true)?;
        o.str("queue", &v.queue, true)?;
        o.int("length", v.length, true)?;
        o.str("schedule", &v.schedule, true)?;
        o.str("timeZone", &v.time_zone, true)?;
        o.dur("duration", v.duration)?;
        o.int("replicas", v.replicas, true)
    })
}

fn scale(o: &mut Out, v: &Scale) -> R {
    o.map(|o| {
        if let Some(m) = v.min {
            o.int("min", m, false)?;
        }
        if let Some(m) = v.max {
            o.int("max", m, false)?;
        }
        o.seq("rules", &v.rules, scale_rule)?;
        o.dur("idleAfter", v.idle_after)
    })
}

fn resources(o: &mut Out, v: &Resources) -> R {
    o.map(|o| {
        o.str("cpu", &v.cpu, true)?;
        o.str("memory", &v.memory, true)
    })
}

/// sorter.go's keyList.Less for two string keys.
fn key_less(a: &str, b: &str) -> bool {
    let ar: Vec<char> = a.chars().collect();
    let br: Vec<char> = b.chars().collect();
    let mut digits = false;
    let mut i = 0;
    while i < ar.len() && i < br.len() {
        if ar[i] == br[i] {
            digits = go::is_digit(ar[i]);
            i += 1;
            continue;
        }
        let al = go::is_letter(ar[i]);
        let bl = go::is_letter(br[i]);
        if al && bl {
            return ar[i] < br[i];
        }
        if al || bl {
            return if digits { al } else { bl };
        }
        let (mut an, mut bn) = (0i64, 0i64);
        if ar[i] == '0' || br[i] == '0' {
            let mut j = i as isize - 1;
            while j >= 0 && go::is_digit(ar[j as usize]) {
                if ar[j as usize] != '0' {
                    an = 1;
                    bn = 1;
                    break;
                }
                j -= 1;
            }
        }
        let mut ai = i;
        while ai < ar.len() && go::is_digit(ar[ai]) {
            an = an
                .wrapping_mul(10)
                .wrapping_add(i64::from(ar[ai] as u32) - i64::from('0' as u32));
            ai += 1;
        }
        let mut bi = i;
        while bi < br.len() && go::is_digit(br[bi]) {
            bn = bn
                .wrapping_mul(10)
                .wrapping_add(i64::from(br[bi] as u32) - i64::from('0' as u32));
            bi += 1;
        }
        if an != bn {
            return an < bn;
        }
        if ai != bi {
            return ai < bi;
        }
        return ar[i] < br[i];
    }
    ar.len() < br.len()
}

fn placement(o: &mut Out, v: &Placement) -> R {
    o.map(|o| {
        if !v.require.is_empty() {
            o.key("require")?;
            let mut keys: Vec<&String> = v.require.keys().collect();
            // sort.Sort is not stable, but keys are distinct.
            keys.sort_by(|a, b| {
                if key_less(a, b) {
                    std::cmp::Ordering::Less
                } else if key_less(b, a) {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Equal
                }
            });
            o.map(|o| {
                for k in keys {
                    o.key(k)?;
                    o.strings(v.require[k].as_deref().unwrap_or(&[]))?;
                }
                Ok(())
            })?;
        }
        o.str("spreadBy", &v.spread_by, true)
    })
}

/// BackupKeep.MarshalYAML: a policy of Last alone is its number.
fn keep(o: &mut Out, k: &BackupKeep) -> R {
    if *k
        == (BackupKeep {
            last: k.last,
            ..BackupKeep::default()
        })
    {
        return o.e.intv("", k.last);
    }
    o.map(|o| {
        o.int("last", k.last, true)?;
        o.int("hourly", k.hourly, true)?;
        o.int("daily", k.daily, true)?;
        o.int("weekly", k.weekly, true)?;
        o.int("monthly", k.monthly, true)
    })
}

fn volume_backup(o: &mut Out, v: &VolumeBackup) -> R {
    o.map(|o| {
        o.dur("every", v.every)?;
        o.str("schedule", &v.schedule, true)?;
        o.str("timeZone", &v.time_zone, true)?;
        o.key("keep")?;
        keep(o, &v.keep)?;
        o.str("urlSecretRef", &v.url_secret_ref, false)?;
        o.str("keySecretRef", &v.key_secret_ref, false)?;
        o.bool("stop", v.stop)
    })
}

fn nfs(o: &mut Out, v: &NfsSource) -> R {
    o.map(|o| {
        o.str("server", &v.server, false)?;
        o.str("path", &v.path, false)?;
        o.bool("readOnly", v.read_only)
    })
}

fn volume(o: &mut Out, v: &Volume) -> R {
    o.map(|o| {
        o.str("name", &v.name, false)?;
        o.str("path", &v.path, false)?;
        o.str("owner", &v.owner, true)?;
        o.opt("backup", &v.backup, volume_backup)?;
        o.str("failover", &v.failover, true)?;
        o.opt("nfs", &v.nfs, nfs)
    })
}

fn container(o: &mut Out, v: &Container) -> R {
    o.map(|o| {
        o.str("name", &v.name, false)?;
        o.str("image", &v.image, false)?;
        o.list("command", &v.command)?;
        o.list("args", &v.args)?;
        o.seq("env", &v.env, env_var)?;
        o.opt("resources", &v.resources, resources)?;
        o.list("volumes", &v.volumes)?;
        o.list("secretFiles", &v.secret_files)
    })
}

fn queue_trigger(o: &mut Out, v: &QueueTrigger) -> R {
    o.map(|o| {
        o.str("type", &v.typ, false)?;
        o.str("urlSecretRef", &v.url_secret_ref, true)?;
        o.str("list", &v.list, true)?;
        o.str("queue", &v.queue, true)?;
        o.int("perRun", v.per_run, true)
    })
}

fn trigger(o: &mut Out, v: &Trigger) -> R {
    o.map(|o| {
        o.opt("queue", &v.queue, queue_trigger)?;
        o.dur("pollingInterval", v.polling_interval)?;
        o.int("parallelism", v.parallelism, true)
    })
}

/// EnvFrom.MarshalYAML: the form the spec was written in.
fn env_from(o: &mut Out, v: &EnvFrom) -> R {
    if v.own {
        return o.e.stringv("", crate::validate::ENV_FROM_SECRETS);
    }
    o.e.sequence_start("")?;
    for s in v.list() {
        o.map(|o| o.str("secret", &s.secret, false))?;
    }
    o.e.sequence_end()
}

fn app(o: &mut Out, a: &App) -> R {
    o.map(|o| {
        o.str("apiVersion", &a.api_version, true)?;
        o.str("kind", &a.kind, true)?;
        o.str("name", &a.name, false)?;
        o.str("image", &a.image, false)?;
        o.list("command", &a.command)?;
        o.list("args", &a.args)?;
        o.seq("env", &a.env, env_var)?;
        if !a.env_from.is_zero() {
            o.key("envFrom")?;
            env_from(o, &a.env_from)?;
        }
        o.seq("secretFiles", &a.secret_files, secret_file)?;
        o.opt("registry", &a.registry, registry)?;
        o.opt("ingress", &a.ingress, ingress)?;
        o.opt("revisions", &a.revisions, revisions)?;
        o.opt("probes", &a.probes, probes)?;
        o.opt("scale", &a.scale, scale)?;
        o.opt("resources", &a.resources, resources)?;
        o.opt("placement", &a.placement, placement)?;
        o.seq("volumes", &a.volumes, volume)?;
        o.seq("initContainers", &a.init_containers, container)?;
        o.seq("sidecars", &a.sidecars, container)?;
        o.dur("drain", a.drain)?;
        o.str("schedule", &a.schedule, true)?;
        o.str("timeZone", &a.time_zone, true)?;
        o.dur("timeout", a.timeout)?;
        o.int("retries", a.retries, true)?;
        o.str("concurrency", &a.concurrency, true)?;
        if let Some(h) = a.history {
            o.int("history", h, false)?;
        }
        o.int("tasks", a.tasks, true)?;
        o.int("parallelism", a.parallelism, true)?;
        o.opt("trigger", &a.trigger, trigger)
    })
}

impl App {
    /// Export writes the spec the way a file holds it (ADR 0032): what
    /// envFrom added and the space are left out.
    pub fn export(&self) -> Result<Vec<u8>, String> {
        let mut c = self.clone();
        c.space.clear();
        if !c.env_from_added.is_empty() {
            let added = std::mem::take(&mut c.env_from_added);
            c.env.retain(|e| !added.contains(&e.name));
        }
        let mut e = Encoder::new_with_writer();
        e.indent = 2;
        let mut o = Out { e };
        o.e.document_start()?;
        app(&mut o, &c)?;
        o.e.document_end()?;
        Ok(o.e.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::key_less;

    #[test]
    fn keys_sort_as_go() {
        assert!(key_less("a2", "a10"));
        assert!(key_less("rack", "zone"));
        assert!(!key_less("b", "a"));
    }
}

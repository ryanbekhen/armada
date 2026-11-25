//! Queue readings (ADR 0034; Go's queue.go): every queue rule of the apps
//! on the node is read from one ready replica of each app, every interval,
//! and the lengths go out with the next usage report. A `queue` rule runs
//! its command in the container; `redis` and `rabbitmq` rules are read by
//! the runtime from the container's network namespace (armada-node as a
//! process), a broker named by a name resolved first from there.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use armada_proto::armada::v1 as pb;
use tokio::sync::{Semaphore, mpsc};

use super::{ExecOptions, QueueRead};
use crate::agent::{Inner, lock, managed};
use crate::runtime::{LABEL_REPLICA, Runtime, STATE_RUNNING};

/// How often queue rules are read.
pub const DEFAULT_QUEUE_INTERVAL: Duration = Duration::from_secs(15);
/// Bounds one reading.
pub const QUEUE_TIMEOUT: Duration = Duration::from_secs(10);
/// The most a queue command may print: a number.
pub const MAX_QUEUE_OUTPUT: usize = 64;
/// The longest length an agent reports.
pub const MAX_QUEUE_LENGTH: i64 = 1 << 40;
/// The queue rules one pass reads, and at once.
pub const MAX_QUEUE_APPS: usize = 32;
pub const MAX_QUEUE_READS: usize = 4;

/// The readings' own errors (queuelen's), which never hold the URL or
/// anything the broker sent.
pub const ERR_URL: &str = "the URL in the secret is not valid for this rule";
pub const ERR_DIAL: &str = "cannot reach the broker from the replica";
pub const ERR_AUTH: &str = "the broker refused the URL's credentials";
pub const ERR_REPLY: &str = "the broker answered something unexpected";
pub const ERR_MISSING: &str = "the queue does not exist";
pub const ERR_TIMEOUT: &str = "timed out";
pub const ERR_VHOST: &str = "the broker refused the URL's virtual host";
pub const ERR_MECHANISM: &str =
    "the URL names an authentication mechanism other than PLAIN, AMQPLAIN, or EXTERNAL";
pub const ERR_NO_MECHANISM: &str = "the broker offers none of the URL's authentication mechanisms";

/// queuelen.Reason: the error's text when it is a reading's own, a fixed
/// text otherwise.
pub fn reason(err: &str) -> String {
    if err.is_empty() {
        return String::new();
    }
    for e in [
        ERR_URL,
        ERR_DIAL,
        ERR_AUTH,
        ERR_REPLY,
        ERR_MISSING,
        ERR_TIMEOUT,
        ERR_VHOST,
        ERR_MECHANISM,
        ERR_NO_MECHANISM,
    ] {
        if err == e {
            return e.to_string();
        }
    }
    "the queue could not be read".into()
}

/// One queue rule: an app has at most one of each type.
type QueueKey = (String, String);

#[derive(Clone)]
struct Reading {
    replica: String,
    length: i64,
    at: SystemTime,
}

/// The latest length read for each queue rule of the apps on the node
/// (queueLengths).
#[derive(Default)]
pub struct QueueLengths {
    m: Mutex<(HashMap<QueueKey, Reading>, HashMap<QueueKey, String>)>,
}

impl QueueLengths {
    fn set(&self, k: QueueKey, r: Reading) {
        lock(&self.m).0.insert(k, r);
    }

    /// Notes why rule k was not read; whether that is new.
    fn fail(&self, k: QueueKey, why: &str) -> bool {
        let mut m = lock(&self.m);
        if m.1.get(&k).map(String::as_str) == Some(why) {
            return false;
        }
        m.1.insert(k, why.to_string());
        true
    }

    /// Forgets rule k's failure; whether there was one.
    fn recovered(&self, k: &QueueKey) -> bool {
        lock(&self.m).1.remove(k).is_some()
    }

    /// Drops readings of rules no app on the node has any more.
    fn keep(&self, rules: &HashSet<QueueKey>) {
        let mut m = lock(&self.m);
        m.0.retain(|k, _| rules.contains(k));
        m.1.retain(|k, _| rules.contains(k));
    }

    /// The readings taken within max_age of now, for a usage report.
    pub fn fresh(&self, now: SystemTime, max_age: Duration) -> Vec<pb::QueueLength> {
        let m = lock(&self.m);
        let mut out: Vec<pb::QueueLength> =
            m.0.iter()
                .filter(|(_, l)| crate::clock::sub(now, l.at) <= max_age.as_nanos() as i64)
                .map(|((_, t), l)| pb::QueueLength {
                    id: l.replica.clone(),
                    length: l.length,
                    r#type: t.clone(),
                })
                .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id).then(a.r#type.cmp(&b.r#type)));
        out
    }
}

/// The replica a queue rule is read from.
struct Target {
    app: String,
    replica: String,
    container: String,
    probe: pb::QueueProbe,
}

/// The host and port a reading dials for a URL (queuelen.Broker), when
/// the URL has them; armada-node checks the rest.
pub fn broker(kind: &str, url: &str) -> Option<(String, u16)> {
    let u = armada_node::queue::url::parse(url).ok()?;
    let host = String::from_utf8(u.hostname().to_vec()).ok()?;
    if host.is_empty() {
        return None;
    }
    let default = match (kind, u.scheme.as_str()) {
        ("redis", "redis" | "rediss") => 6379,
        ("rabbitmq", "amqp") => 5672,
        ("rabbitmq", "amqps") => 5671,
        _ => return None,
    };
    let port = match std::str::from_utf8(u.port()).ok()? {
        "" => default,
        p => p.parse().ok()?,
    };
    Some((host, port))
}

/// The resolver containers use: the node's internal DNS, else the host's
/// first nameserver that is not loopback (containerNameserver).
fn nameserver_from(dns: Option<String>, resolv: Option<String>) -> String {
    if let Some(a) = dns.filter(|a| !a.is_empty()) {
        return crate::agent::join_host_port(&a, 53);
    }
    for line in resolv.unwrap_or_default().lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 2
            && f[0] == "nameserver"
            && let Ok(ip) = f[1].parse::<IpAddr>()
            && !ip.is_loopback()
        {
            return crate::agent::join_host_port(&ip.to_string(), 53);
        }
    }
    String::new()
}

impl<R: Runtime> Inner<R> {
    pub(crate) fn container_nameserver(&self) -> String {
        nameserver_from(
            self.cfg.dns.as_ref().map(|d| d.address()),
            std::fs::read_to_string("/etc/resolv.conf").ok(),
        )
    }

    /// A reading for p with the broker's addresses resolved through dial
    /// when the URL names it by a name (nativeQueue).
    pub(crate) async fn queue_read<F, Fut>(
        &self,
        p: &pb::QueueProbe,
        dial: F,
    ) -> Result<QueueRead, String>
    where
        F: Fn(&'static str, String) -> Fut,
        Fut: Future<Output = Result<OwnedFd, String>>,
    {
        let mut q = QueueRead {
            kind: p.r#type.clone(),
            url: p.url.clone(),
            name: p.name.clone(),
            addresses: Vec::new(),
        };
        if let Some((host, port)) = broker(&q.kind, &q.url)
            && host.parse::<IpAddr>().is_err()
        {
            let ns = self.container_nameserver();
            if ns.is_empty() {
                return Err(ERR_DIAL.into());
            }
            let ips = super::dns::lookup(dial, &ns, &host)
                .await
                .map_err(|_| ERR_DIAL.to_string())?;
            q.addresses = ips
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect();
        }
        Ok(q)
    }

    /// Reads every queue rule once (measureQueues).
    pub(crate) async fn measure_queues(self: &Arc<Self>) {
        let targets = self.queue_targets().await;
        let rules: HashSet<QueueKey> = targets
            .iter()
            .map(|t| (t.app.clone(), t.probe.r#type.clone()))
            .collect();
        self.side.queues.keep(&rules);
        // A few at once, so one slow rule does not hold back the others.
        let sem = Arc::new(Semaphore::new(MAX_QUEUE_READS));
        let mut tasks = tokio::task::JoinSet::new();
        for t in targets {
            let Ok(permit) = sem.clone().acquire_owned().await else {
                break;
            };
            let me = self.clone();
            tasks.spawn(async move {
                let _permit = permit;
                let k = (t.app.clone(), t.probe.r#type.clone());
                match me.read_queue(&t.container, &t.probe).await {
                    Err(e) => {
                        // The command's arguments and the broker's URL stay
                        // out of logs: the errors name only the kind of
                        // failure. Each failure is a warning once.
                        let kv = [
                            ("app", t.app.clone()),
                            ("type", t.probe.r#type.clone()),
                            ("replica", t.replica.clone()),
                            ("err", e.clone()),
                        ];
                        if me.side.queues.fail(k, &e) {
                            me.log.warn("queue rule not read", &kv);
                        } else {
                            me.log.debug("queue rule not read", &kv);
                        }
                    }
                    Ok(n) => {
                        if me.side.queues.recovered(&k) {
                            me.log.info(
                                "queue rule read again",
                                &[("app", t.app.clone()), ("type", t.probe.r#type.clone())],
                            );
                        }
                        me.side.queues.set(
                            k,
                            Reading {
                                replica: t.replica,
                                length: n,
                                at: SystemTime::now(),
                            },
                        );
                    }
                }
            });
        }
        while tasks.join_next().await.is_some() {}
    }

    /// For every app with queue rules, the ready replica on this node with
    /// the lowest ID, once per rule (queueTargets).
    async fn queue_targets(&self) -> Vec<Target> {
        let specs: BTreeMap<String, pb::ReplicaSpec> = lock(&self.st)
            .desired
            .as_ref()
            .map(|d| {
                d.iter()
                    .filter(|(_, s)| !s.queues.is_empty() && s.job.is_none())
                    .map(|(k, s)| (k.clone(), s.clone()))
                    .collect()
            })
            .unwrap_or_default();
        if specs.is_empty() {
            return Vec::new();
        }
        let Ok(cs) = self.rt.list(&managed()).await else {
            return Vec::new();
        };
        let mut best: BTreeMap<String, (String, String, pb::ReplicaSpec)> = BTreeMap::new();
        for c in cs {
            let id = c.label(LABEL_REPLICA).to_string();
            let Some(s) = specs.get(&id) else { continue };
            if c.state != STATE_RUNNING || !self.replica_ready(&id, &c.id) {
                continue;
            }
            if best.get(&s.app).is_none_or(|cur| id < cur.0) {
                best.insert(s.app.clone(), (id, c.id.clone(), s.clone()));
            }
        }
        let mut out = Vec::new();
        for (app, (replica, container, s)) in best {
            for q in s.queues {
                out.push(Target {
                    app: app.clone(),
                    replica: replica.clone(),
                    container: container.clone(),
                    probe: q,
                });
            }
        }
        out.sort_by(|x, y| x.app.cmp(&y.app).then(x.probe.r#type.cmp(&y.probe.r#type)));
        out.truncate(MAX_QUEUE_APPS);
        out
    }

    /// Whether the probes of replica's container passed.
    fn replica_ready(&self, replica: &str, container: &str) -> bool {
        let w = lock(&self.st).probes.get(replica).cloned();
        w.is_some_and(|w| w.container_id == container && w.status().0)
    }

    /// Reads one queue rule from the container (readQueue).
    pub(crate) async fn read_queue(
        &self,
        container: &str,
        p: &pb::QueueProbe,
    ) -> Result<i64, String> {
        match p.r#type.as_str() {
            "redis" | "rabbitmq" => {
                let read = async {
                    // A broker named by an address needs no dial here.
                    let dial = |net: &'static str, addr: String| async move {
                        self.rt
                            .dial_container(container, net, &addr)
                            .await
                            .map_err(|e| e.to_string())
                    };
                    let q = self.queue_read(p, dial).await?;
                    self.rt
                        .read_queue(container, &q)
                        .await
                        .map_err(|e| e.to_string())
                };
                tokio::time::timeout(QUEUE_TIMEOUT, read)
                    .await
                    .unwrap_or_else(|_| Err(ERR_TIMEOUT.into()))
            }
            "queue" => self.run_queue_command(container, &p.command).await,
            t => Err(format!("unknown queue rule {}", super::quote(t))),
        }
    }

    /// Runs cmd in the container with its own security settings and reads
    /// the number it prints; its error output is dropped
    /// (runQueueCommand).
    async fn run_queue_command(&self, container: &str, cmd: &[String]) -> Result<i64, String> {
        if !self.rt.can_exec() {
            return Err("this node's runtime cannot run commands in containers".into());
        }
        super::exec::check_exec_command(cmd)?;
        let (tx, mut rx) = mpsc::channel::<super::Output>(16);
        let collect = tokio::spawn(async move {
            let (mut out, mut over) = (Vec::new(), false);
            while let Some((stdout, b)) = rx.recv().await {
                if !stdout {
                    continue;
                }
                let room = MAX_QUEUE_OUTPUT.saturating_sub(out.len());
                if b.len() > room {
                    over = true;
                }
                out.extend_from_slice(&b[..b.len().min(room)]);
            }
            (out, over)
        });
        let opts = ExecOptions {
            cmd: cmd.to_vec(),
            output: Some(tx),
            ..Default::default()
        };
        let r = tokio::time::timeout(QUEUE_TIMEOUT, self.rt.exec_session(container, opts)).await;
        let (out, over) = collect.await.unwrap_or_default();
        let code = match r {
            Err(_) => return Err("command timed out".into()),
            Ok(Err(_)) => {
                return Err("could not run the command; is the program in the image?".into());
            }
            Ok(Ok(c)) => c,
        };
        if code != 0 {
            return Err(format!("command exited with code {code}"));
        }
        if over {
            return Err("command printed more than a number".into());
        }
        let text = String::from_utf8_lossy(&out);
        match text.trim().parse::<i64>() {
            Ok(n) if (0..=MAX_QUEUE_LENGTH).contains(&n) => Ok(n),
            _ => Err("command did not print a whole number between 0 and 2^40".into()),
        }
    }

    /// Reads queue rules every interval (queueLoop).
    pub(crate) async fn queue_loop(self: Arc<Self>) {
        if !self.rt.can_exec() && !self.rt.can_dial() {
            return;
        }
        let every = self.cfg.side.queue_interval;
        let mut t = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        loop {
            t.tick().await;
            self.measure_queues().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brokers() {
        assert_eq!(
            broker("redis", "redis://:p@cache.internal/0"),
            Some(("cache.internal".into(), 6379))
        );
        assert_eq!(
            broker("redis", "rediss://10.0.0.1:7000"),
            Some(("10.0.0.1".into(), 7000))
        );
        assert_eq!(
            broker("rabbitmq", "amqps://u:p@mq"),
            Some(("mq".into(), 5671))
        );
        assert_eq!(
            broker("rabbitmq", "amqp://mq:5673/v"),
            Some(("mq".into(), 5673))
        );
        assert_eq!(broker("redis", "http://x"), None);
        assert_eq!(broker("redis", "redis:///0"), None);
    }

    #[test]
    fn nameservers() {
        assert_eq!(
            nameserver_from(Some("10.120.0.1".into()), None),
            "10.120.0.1:53"
        );
        assert_eq!(
            nameserver_from(
                None,
                Some("# x\nnameserver 127.0.0.53\nnameserver 10.0.0.2\n".into())
            ),
            "10.0.0.2:53"
        );
        assert_eq!(nameserver_from(None, None), "");
        assert_eq!(reason(ERR_AUTH), ERR_AUTH);
        assert_eq!(
            reason("dial tcp 10.0.0.1: refused"),
            "the queue could not be read"
        );
    }
}

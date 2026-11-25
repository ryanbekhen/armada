//! Assignments (Go's pushAssignments and replicaSpec in reconciler.go):
//! what each connected node runs, built from the store's replicas and the
//! secret versions their revisions pin, opened only while the assignment
//! is built and never logged, with the queue sandboxes each node keeps
//! (ADR 0040), the cluster network, and each containerd node's plan of
//! the runtime move (ADR 0054). The proxy configuration (pull request 14)
//! is left out until its pull request.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;

use armada_proto::armada::v1::*;
use armada_secrets::Value;
use armada_spec::validate::secret_source;
use armada_spec::{App as Spec, DEFAULT_PIDS, INGRESS_NONE, SCALE_RABBITMQ, SCALE_REDIS};
use armada_store::{App, Kind, Replica, Revision};

use crate::Server;
use crate::schedule::{Res, Reserved, reservation};
use crate::settings::{META_LOGS, log_settings_proto, read_meta};

/// The secret versions the leader decrypted, kept across passes; versions
/// no pass used are dropped by sweep (Go's openedSecrets).
#[derive(Default)]
pub struct Opened {
    st: Mutex<OpenedState>,
}

#[derive(Default)]
struct OpenedState {
    vals: HashMap<(String, String, i64), Value>,
    used: HashMap<(String, String, i64), bool>,
}

impl Opened {
    fn get(&self, app: &str, name: &str, version: i64) -> Option<Value> {
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        let k = (app.to_string(), name.to_string(), version);
        let v = st.vals.get(&k).cloned();
        if v.is_some() {
            st.used.insert(k, true);
        }
        v
    }

    fn put(&self, app: &str, name: &str, version: i64, v: Value) {
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        let k = (app.to_string(), name.to_string(), version);
        st.vals.insert(k.clone(), v);
        st.used.insert(k, true);
    }

    /// Drops every cached version of a secret's key, or with name "" of
    /// every key (Go's forget).
    pub fn forget(&self, app: &str, name: &str) {
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        let gone = |k: &(String, String, i64)| k.0 == app && (name.is_empty() || k.1 == name);
        st.vals.retain(|k, _| !gone(k));
        st.used.retain(|k, _| !gone(k));
    }

    /// Drops what no lookup since the last sweep used.
    pub fn sweep(&self) {
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        let used = std::mem::take(&mut st.used);
        st.vals.retain(|k, _| used.contains_key(k));
    }
}

/// The revisions and secrets one pass reads (Go's revisionCache).
pub(crate) struct Revisions<'a> {
    srv: &'a Server,
    m: HashMap<String, Revision>,
    vals: HashMap<String, BTreeMap<String, Value>>,
    /// What a replica of each revision reserves.
    res: HashMap<String, Res>,
}

impl<'a> Revisions<'a> {
    pub(crate) fn new(srv: &'a Server) -> Revisions<'a> {
        Revisions {
            srv,
            m: HashMap::new(),
            vals: HashMap::new(),
            res: HashMap::new(),
        }
    }

    /// preload: reads the revisions a pass over apps and replicas needs at
    /// once. A failure costs nothing but speed.
    pub(crate) async fn preload(&mut self, apps: &[App], replicas: &[Replica]) {
        let mut seen = BTreeSet::new();
        let mut names = Vec::new();
        let mut add = |n: &str| {
            if !n.is_empty() && seen.insert(n.to_string()) {
                names.push(n.to_string());
            }
        };
        for a in apps {
            add(&a.active_revision);
            add(&a.target_revision);
        }
        for r in replicas {
            add(&r.revision);
        }
        if let Ok(m) = self.srv.store().get_revisions(&names).await {
            self.m.extend(m);
        }
    }

    pub(crate) async fn get(&mut self, name: &str) -> Result<Revision, armada_store::Error> {
        if let Some(r) = self.m.get(name) {
            return Ok(r.clone());
        }
        let r = self.srv.store().get_revision(name).await?;
        self.m.insert(name.to_string(), r.clone());
        Ok(r)
    }

    /// What each revision of replicas reserves (Go's reserved): a revision
    /// that cannot be read reserves nothing.
    pub(crate) async fn reserved(&mut self, replicas: &[Replica]) -> Reserved {
        let mut out = Reserved::new();
        for r in replicas {
            if r.done || out.contains_key(&r.revision) {
                continue;
            }
            if let Some(x) = self.res.get(&r.revision) {
                out.insert(r.revision.clone(), *x);
                continue;
            }
            if let Ok(rev) = self.get(&r.revision).await {
                let x = reservation(&rev);
                self.res.insert(r.revision.clone(), x);
                out.insert(r.revision.clone(), x);
            }
        }
        out
    }

    /// Decrypts the secret versions rev pins.
    pub(crate) async fn secrets(
        &mut self,
        rev: &Revision,
    ) -> Result<BTreeMap<String, Value>, armada_store::Error> {
        if rev.secrets.is_empty() {
            return Ok(BTreeMap::new());
        }
        if let Some(v) = self.vals.get(&rev.name) {
            return Ok(v.clone());
        }
        let Some(keys) = &self.srv.0.keys else {
            return Err(armada_store::Error::other(format!(
                "revision {} uses secrets, but no master key is loaded",
                rev.name
            )));
        };
        let mut vals = BTreeMap::new();
        for (r, version) in &rev.secrets {
            let (secret, key) = secret_source(&rev.app, r);
            if let Some(v) = self.srv.0.opened.get(&secret, &key, *version) {
                vals.insert(r.clone(), v);
                continue;
            }
            let sealed = self.srv.store().get_secret(&secret, &key, *version).await?;
            let v = keys
                .open(&sealed, &secret, &key, *version)
                .map_err(|e| armada_store::Error::other(e.to_string()))?;
            self.srv.0.opened.put(&secret, &key, *version, v.clone());
            vals.insert(r.clone(), v);
        }
        self.vals.insert(rev.name.clone(), vals.clone());
        Ok(vals)
    }
}

/// Empty values for every secret rev pins (Go's unresolvedSecrets).
fn unresolved(rev: &Revision) -> BTreeMap<String, Value> {
    rev.secrets
        .keys()
        .map(|k| (k.clone(), Value::new(&[])))
        .collect()
}

fn text(v: &Value) -> String {
    String::from_utf8_lossy(v.bytes()).into_owned()
}

fn probe(p: &Option<armada_spec::Probe>) -> Option<Probe> {
    p.as_ref().map(|p| Probe {
        path: p.path.clone(),
        command: p.command.clone(),
        port: p.port as i32,
        initial_delay_ms: p.initial_delay.0 / 1_000_000,
        period_ms: p.period.0 / 1_000_000,
        timeout_ms: p.timeout.0 / 1_000_000,
        failure_threshold: p.failure_threshold as i32,
    })
}

/// What an agent needs to run one replica (Go's replicaSpec). vals holds
/// the plaintext of the secret versions rev pins.
pub(crate) fn replica_spec(
    r: &Replica,
    rev: &Revision,
    vals: &BTreeMap<String, Value>,
) -> Result<ReplicaSpec, String> {
    let sp: &Spec = rev.spec();
    let secret = |name: &str| -> Result<(String, String, Vec<u8>), String> {
        let Some(v) = vals.get(name) else {
            return Err(format!(
                "revision {}: secret {name} is not resolved",
                rev.name
            ));
        };
        let version = rev.secrets.get(name).copied().unwrap_or_default();
        Ok((text(v), format!("{name}@v{version}"), v.bytes().to_vec()))
    };
    let mut env = Vec::with_capacity(sp.env.len() + 4);
    for e in &sp.env {
        if e.secret_ref.is_empty() {
            env.push(EnvVar {
                name: e.name.clone(),
                value: e.value.clone(),
                r#ref: String::new(),
            });
            continue;
        }
        let (v, rf, _) = secret(&e.secret_ref)?;
        env.push(EnvVar {
            name: e.name.clone(),
            value: v,
            r#ref: rf,
        });
    }
    let plain = |n: &str, v: String| EnvVar {
        name: n.to_string(),
        value: v,
        r#ref: String::new(),
    };
    env.push(plain("ARMADA_APP", r.app.clone()));
    env.push(plain("ARMADA_REVISION", r.revision.clone()));
    env.push(plain("ARMADA_REPLICA", r.id.clone()));
    if r.run != 0 {
        env.push(plain("ARMADA_JOB_RUN", r.run.to_string()));
        let n = sp.job_tasks();
        if n > 1 {
            env.push(plain("ARMADA_JOB_TASK", r.task.to_string()));
            env.push(plain("ARMADA_JOB_TASKS", n.to_string()));
        }
    }
    let mut port = 0;
    if let Some(ing) = &sp.ingress
        && ing.typ != INGRESS_NONE
    {
        port = ing.port as i32;
        env.push(plain("PORT", ing.port.to_string()));
    }
    let mut rs = ReplicaSpec {
        id: r.id.clone(),
        app: r.app.clone(),
        revision: r.revision.clone(),
        image: rev.image(),
        command: sp.command.clone(),
        args: sp.args.clone(),
        env: env.clone(),
        port,
        memory_bytes: sp.memory_bytes(),
        nano_cpus: sp.nano_cpus(),
        cpu_reserve_millis: sp.cpu_millis(),
        pids_limit: DEFAULT_PIDS,
        ..Default::default()
    };
    if r.run != 0 {
        rs.job = Some(JobAttempt {
            job: r.app.clone(),
            run: r.run,
            done: r.done,
        });
    }
    if let Some(p) = &sp.probes {
        rs.startup = probe(&p.startup);
        rs.readiness = probe(&p.readiness);
        rs.liveness = probe(&p.liveness);
    }
    for v in &sp.volumes {
        rs.volumes.push(VolumeSpec {
            name: v.name.clone(),
            path: v.path.clone(),
            owner: v.owner.clone(),
            nfs: v.nfs.as_ref().map(|n| NfsSource {
                server: n.server.clone(),
                path: n.path.clone(),
                read_only: n.read_only,
            }),
        });
    }
    if r.run == 0 {
        for q in sp.queue_rules() {
            let mut p = QueueProbe {
                r#type: q.typ.clone(),
                command: q.command.clone(),
                ..Default::default()
            };
            if q.typ == SCALE_REDIS {
                p.name = q.list.clone();
            } else if q.typ == SCALE_RABBITMQ {
                p.name = q.queue.clone();
            }
            if !q.url_secret_ref.is_empty() {
                let (v, rf, _) = secret(&q.url_secret_ref)?;
                p.url = v;
                p.url_ref = rf;
            }
            rs.queues.push(p);
        }
    }
    for f in &sp.secret_files {
        let (_, rf, data) = secret(&f.secret_ref)?;
        rs.secret_files.push(SecretFile {
            path: f.path.clone(),
            data,
            r#ref: rf,
        });
    }
    if let Some(reg) = &sp.registry {
        let (v, rf, _) = secret(&reg.password_secret_ref)?;
        rs.registry = Some(RegistryAuth {
            server: reg.server.clone(),
            username: reg.username.clone(),
            password: v,
            r#ref: rf,
        });
    }
    // Init containers and sidecars (ADR 0038): their own env, with the
    // replica's identity, never the app's variables or PORT.
    let member = |c: &armada_spec::Container| -> Result<ContainerSpec, String> {
        let mut cs = ContainerSpec {
            name: c.name.clone(),
            image: c.image.clone(),
            command: c.command.clone(),
            args: c.args.clone(),
            memory_bytes: c.memory_bytes(),
            nano_cpus: c.nano_cpus(),
            cpu_reserve_millis: c.cpu_millis(),
            pids_limit: DEFAULT_PIDS,
            volumes: c.volumes.clone(),
            secret_files: c.secret_files.clone(),
            env: Vec::new(),
        };
        for e in &c.env {
            if e.secret_ref.is_empty() {
                cs.env.push(plain(&e.name, e.value.clone()));
                continue;
            }
            let (v, rf, _) = secret(&e.secret_ref)?;
            cs.env.push(EnvVar {
                name: e.name.clone(),
                value: v,
                r#ref: rf,
            });
        }
        for e in &env {
            if e.name.starts_with("ARMADA_") {
                cs.env.push(plain(&e.name, e.value.clone()));
            }
        }
        cs.env.push(plain("ARMADA_CONTAINER", c.name.clone()));
        Ok(cs)
    };
    for c in &sp.init_containers {
        rs.init_containers.push(member(c)?);
    }
    for c in &sp.sidecars {
        rs.sidecars.push(member(c)?);
    }
    Ok(rs)
}

impl Server {
    /// fenceAfter: half the node-lost timeout, at least a second.
    fn fence_after(&self) -> i64 {
        ((self.0.node_lost_timeout / 2).as_secs() as i64).max(1)
    }

    /// Sends every connected node its assignment (Go's pushAssignments).
    pub(crate) async fn push_assignments(
        &self,
        replicas: &[Replica],
        revs: &mut Revisions<'_>,
        servers: &[String],
        network: Option<&NetworkConfig>,
        sandboxes: &HashMap<String, Vec<QueueSandbox>>,
        move_plans: &HashMap<String, RuntimeMovePlan>,
    ) -> Result<(), armada_store::Error> {
        let mut by_node: HashMap<&str, Vec<&Replica>> = HashMap::new();
        for r in replicas {
            by_node.entry(r.node_id.as_str()).or_default().push(r);
        }
        let ls = read_meta(self.store(), META_LOGS).await?;
        let logs = log_settings_proto(ls.as_ref(), self.0.keys.as_ref(), &self.0.log);
        for sess in self.sessions() {
            let mut a = Assignment {
                servers: servers.to_vec(),
                logs: Some(logs.clone()),
                network: network.cloned(),
                queue_sandboxes: sandboxes.get(&sess.node_id).cloned().unwrap_or_default(),
                ..Default::default()
            };
            if sess.caps.runtime_move {
                a.runtime_move = move_plans.get(&sess.node_id).cloned();
            }
            for r in by_node.get(sess.node_id.as_str()).into_iter().flatten() {
                if r.held && !sess.caps.holds {
                    // An agent that does not know holds would start it
                    // next to the replica still using its volume.
                    continue;
                }
                let rev = revs.get(&r.revision).await?;
                let vals = match revs.secrets(&rev).await {
                    Err(e) if e.kind == Kind::NotFound && (r.done || r.draining()) => {
                        // A finished attempt never starts again, and a
                        // draining replica is on its way out: a deleted
                        // version only needs its reference.
                        unresolved(&rev)
                    }
                    Err(e) => return Err(e),
                    Ok(v) => v,
                };
                let mut rs = replica_spec(r, &rev, &vals).map_err(armada_store::Error::other)?;
                rs.hold = r.held;
                if rev.spec().fails_over() {
                    rs.fence_after_seconds = self.fence_after();
                }
                a.replicas.push(rs);
            }
            a.replicas.sort_by(|x, y| x.id.cmp(&y.id));
            sess.offer_assignment(a);
        }
        Ok(())
    }
}

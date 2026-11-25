//! Apps, revisions, rollouts, replicas, and domains (etcd.go).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use armada_spec::App as Spec;
use armada_spec::TrafficTarget;
use armada_spec::go::{atoi, quote};
use armada_spec::gotime::Time;
use armada_spec::validate::{DEFAULT_SPACE, LATEST_REVISION, check_traffic, join, split_app_id};
use armada_spec::{INGRESS_EXTERNAL, Ingress, MAX_REPLICAS};
use serde_json::value::RawValue;

use crate::client::op;
use crate::error::{Error, Kind, Result, conflict, not_found, other, precondition};
use crate::gojson::{decode, from_ms, unix_milli};
use crate::jobs::{RUN_PENDING, RUN_RUNNING};
use crate::records::*;
use crate::tx::*;
use crate::types::*;

/// seqKey: a sequence number as ten digits.
pub(crate) fn seq_key(n: i64) -> String {
    format!("{n:010}")
}

pub(crate) fn rev_key(app: &str, seq: i64) -> String {
    format!("{PFX_REVS}{app}/{}", seq_key(seq))
}

/// parseRevisionName splits "<app>--r<seq>".
pub(crate) fn parse_revision_name(name: &str) -> Option<(String, i64)> {
    let i = name.rfind("--r")?;
    if i == 0 {
        return None;
    }
    let seq = atoi(&name[i + 3..]).ok()?;
    if seq < 1 {
        return None;
    }
    Some((name[..i].to_string(), seq))
}

/// replicaPrefix: what the ID of every replica of app starts with.
pub(crate) fn replica_prefix(app: &str) -> String {
    format!("{app}-")
}

/// spaceOf: the space of an app ID, "" for an invalid one.
pub(crate) fn space_of(id: &str) -> String {
    split_app_id(id).map(|(s, _)| s).unwrap_or_default()
}

/// routeKeys: the host+path pairs an app routes on its custom domains.
fn route_keys(sp: &Spec) -> Vec<String> {
    let Some(i) = sp.ingress.as_ref().filter(|i| i.typ == INGRESS_EXTERNAL) else {
        return Vec::new();
    };
    let paths: Vec<String> = if i.routes.is_empty() {
        vec!["/".to_string()]
    } else {
        i.routes.iter().map(|r| r.path.clone()).collect()
    };
    let mut keys = Vec::new();
    for d in &i.domains {
        for p in &paths {
            keys.push(format!("{d}{p}"));
        }
    }
    keys
}

/// trafficString: "web--r3=90,web--r4=10".
fn traffic_string(traffic: &[TrafficTarget]) -> String {
    traffic
        .iter()
        .map(|t| format!("{}={}", t.revision, t.weight))
        .collect::<Vec<_>>()
        .join(",")
}

/// keptReplicas: the count an app keeps when sp becomes its target.
pub(crate) fn kept_replicas(sp: &Spec, cur: i64) -> i64 {
    if sp.has_local_volumes() {
        return 1;
    }
    if !sp.autoscaled() {
        return cur;
    }
    let (lo, hi) = sp.scale_bounds();
    cur.max(lo).min(hi)
}

pub(crate) fn decode_rev(r: RevRec) -> Result<Revision> {
    let spec = match r.spec.get() {
        "null" => Spec::default(),
        s => {
            Spec::from_json(s.as_bytes()).map_err(|e| other!("decode revision {}: {e}", r.name))?
        }
    };
    Ok(Revision {
        name: r.name,
        app: r.app,
        seq: r.seq,
        spec: Some(Arc::new(spec)),
        image_digest: r.image_digest,
        platforms: r.platforms,
        secrets: r.secrets.unwrap_or_default(),
        created_at: from_ms(r.created_at),
    })
}

fn app_from(a: &AppRec, rev: &Revision) -> App {
    App {
        name: a.name.clone(),
        active_revision: a.active_revision.clone(),
        target_revision: a.target_revision.clone(),
        replicas: a.replicas,
        spec: rev.spec.clone(),
        rollout_state: a.rollout_state.clone(),
        rollout_message: a.rollout_message.clone(),
        rollout_progress_at: from_ms(a.rollout_progress_at),
        created_at: from_ms(a.created_at),
        updated_at: from_ms(a.updated_at),
        last_scheduled: from_ms(a.last_scheduled),
        traffic: a.traffic.iter().map(TrafficRec::to_spec).collect(),
        removing: a.removing,
        scaled_at: from_ms(a.scaled_at),
    }
}

fn replica_of(r: ReplicaRec) -> Replica {
    Replica {
        id: r.id,
        app: r.app,
        revision: r.revision,
        node_id: r.node_id,
        state: r.state,
        container_id: r.container_id,
        address: r.address,
        ip: r.ip,
        message: r.message,
        ready: r.ready,
        ready_since: from_ms(r.ready_since),
        draining_since: from_ms(r.draining_since),
        moving_since: from_ms(r.moving_since),
        updated_at: from_ms(r.updated_at),
        created_at: from_ms(r.created_at),
        restarts: r.restarts,
        last_restart_at: from_ms(r.last_restart_at),
        last_restart: r.last_restart,
        run: r.run,
        done: r.done,
        finished: r.finished,
        exit_code: r.exit_code,
        task: r.task,
        held: r.held,
    }
}

fn to_domain(d: DomainRec) -> Domain {
    Domain {
        name: d.name,
        token: d.token,
        verified: d.verified,
        verified_at: from_ms(d.verified_at),
        message: d.message,
        created_at: from_ms(d.created_at),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Etx<'_> {
    pub(crate) async fn app(&self, name: &str) -> Result<Option<AppRec>> {
        self.get(&format!("{PFX_APPS}{name}")).await
    }

    pub(crate) async fn need_app(&self, name: &str) -> Result<AppRec> {
        self.app(name)
            .await?
            .ok_or_else(|| not_found!("app {name}"))
    }

    pub(crate) async fn revision(&self, name: &str) -> Result<Revision> {
        let Some((app, seq)) = parse_revision_name(name) else {
            return Err(not_found!("revision {name}"));
        };
        match self.get::<RevRec>(&rev_key(&app, seq)).await? {
            None => Err(not_found!("revision {name}")),
            Some(r) => decode_rev(r),
        }
    }

    /// revisions: the revisions that exist among names, by name.
    pub(crate) async fn revisions(&self, names: &[String]) -> Result<HashMap<String, Revision>> {
        let mut keys = Vec::new();
        let mut by_key: HashMap<String, String> = HashMap::new();
        for name in names {
            let Some((app, seq)) = parse_revision_name(name) else {
                continue;
            };
            let k = rev_key(&app, seq);
            if !by_key.contains_key(&k) {
                by_key.insert(k.clone(), name.clone());
                keys.push(k);
            }
        }
        let raw = self.get_many(&keys).await?;
        let mut out = HashMap::with_capacity(raw.len());
        for (k, b) in raw {
            let r: RevRec = decode(&k, &b)?;
            out.insert(by_key[&k].clone(), decode_rev(r)?);
        }
        Ok(out)
    }

    async fn to_app(&self, a: &AppRec) -> Result<App> {
        let rev = self.revision(&a.active_revision).await?;
        Ok(app_from(a, &rev))
    }

    /// appReplicas: every replica of app, read by its ID prefix.
    pub(crate) async fn app_replicas(&self, app: &str) -> Result<Vec<(String, ReplicaRec)>> {
        Ok(self
            .list_into::<ReplicaRec>(&format!("{PFX_REPLICAS}{}", replica_prefix(app)))
            .await?
            .into_iter()
            .filter(|(_, r)| r.app == app)
            .collect())
    }

    /// liveSpecs: the active and (if different) target spec of every app.
    pub(crate) async fn live_specs(&self) -> Result<Vec<(String, Arc<Spec>)>> {
        let apps: Vec<AppRec> = self
            .list_into::<AppRec>(PFX_APPS)
            .await?
            .into_iter()
            .map(|(_, a)| a)
            .collect();
        let names: Vec<String> = apps
            .iter()
            .flat_map(|a| [a.active_revision.clone(), a.target_revision.clone()])
            .collect();
        let revs = self.revisions(&names).await?;
        let mut out = Vec::new();
        for a in &apps {
            let mut list = vec![a.active_revision.clone()];
            if a.target_revision != a.active_revision {
                list.push(a.target_revision.clone());
            }
            for name in list {
                let Some(rev) = revs.get(&name) else {
                    return Err(not_found!("revision {name}"));
                };
                out.push((a.name.clone(), rev.spec.clone().expect("decoded")));
            }
        }
        Ok(out)
    }

    /// claimDomains rejects host+path collisions with other apps and
    /// registers sp's new domains with a fresh verification token.
    pub(crate) async fn claim_domains(&mut self, sp: &Spec, now: &Time) -> Result<()> {
        let id = sp.id();
        let space = space_of(&id);
        let mut taken: HashMap<String, String> = HashMap::new();
        let mut foreign: HashMap<String, String> = HashMap::new();
        let mut ports: HashMap<i64, String> = HashMap::new();
        for (app, other) in self.live_specs().await? {
            if app == id {
                continue;
            }
            for k in route_keys(&other) {
                taken.insert(k, app.clone());
            }
            if Ingress::tcp(other.ingress.as_ref()) && space_of(&app) == space {
                ports.insert(other.ingress.as_ref().map_or(0, |i| i.port), app.clone());
            }
            let p = space_of(&app);
            if p != space
                && let Some(i) = &other.ingress
            {
                for d in &i.domains {
                    foreign.insert(d.clone(), p.clone());
                }
            }
        }
        for k in route_keys(sp) {
            if let Some(owner) = taken.get(&k) {
                return Err(conflict!("{k} is already routed to app {owner}"));
            }
        }
        if Ingress::tcp(sp.ingress.as_ref()) {
            let port = sp.ingress.as_ref().map_or(0, |i| i.port);
            if let Some(owner) = ports.get(&port) {
                return Err(conflict!(
                    "TCP port {port} is already used by app {owner} of this space"
                ));
            }
        }
        let Some(ing) = &sp.ingress else {
            return Ok(());
        };
        for d in &ing.domains {
            if let Some(p) = foreign.get(d) {
                return Err(conflict!("domain {d} is used by space {p}"));
            }
            let k = format!("{PFX_DOMAINS}{d}");
            let r = self.get::<DomainRec>(&k).await?;
            if let Some(r) = &r {
                let owner = if r.space.is_empty() {
                    DEFAULT_SPACE
                } else {
                    r.space.as_str()
                };
                if owner == space {
                    continue;
                }
            }
            let mut b = [0u8; 16];
            self.s.random(&mut b);
            let mut rec = DomainRec {
                name: d.clone(),
                token: hex(&b),
                created_at: unix_milli(now),
                ..Default::default()
            };
            if space != DEFAULT_SPACE {
                rec.space = space.clone();
            }
            self.put(&k, &rec)?;
        }
        Ok(())
    }

    /// pruneDomains deletes domains no live spec references any more.
    pub(crate) async fn prune_domains(&mut self) -> Result<()> {
        let mut in_use = HashSet::new();
        for (_, sp) in self.live_specs().await? {
            if let Some(i) = &sp.ingress {
                in_use.extend(i.domains.iter().cloned());
            }
        }
        for (k, d) in self.list_into::<DomainRec>(PFX_DOMAINS).await? {
            if !in_use.contains(&d.name) {
                self.delete(&k);
            }
        }
        Ok(())
    }

    /// setTarget points a at target and resets the rollout state.
    async fn set_target(
        &mut self,
        mut a: AppRec,
        target: &str,
        replicas: i64,
        now: &Time,
    ) -> Result<()> {
        a.rollout_state = if target != a.active_revision {
            ROLLOUT_PROGRESSING.to_string()
        } else {
            ROLLOUT_NONE.to_string()
        };
        a.target_revision = target.to_string();
        a.replicas = replicas;
        a.rollout_message.clear();
        a.rollout_progress_at = unix_milli(now);
        a.updated_at = unix_milli(now);
        self.put(&format!("{PFX_APPS}{}", a.name), &a)
    }

    /// pruneRevisions deletes old revisions beyond RevisionsToKeep that are
    /// neither active, targeted, nor still running, then secret versions
    /// nothing pins any more.
    pub(crate) async fn prune_revisions(&mut self, app: &str) -> Result<()> {
        let Some(a) = self.app(app).await? else {
            return Ok(());
        };
        let mut running = HashSet::new();
        for (_, r) in self.app_replicas(app).await? {
            running.insert(r.revision);
        }
        for (_, r) in self
            .list_into::<JobRunRec>(&format!("{PFX_RUNS}{app}/"))
            .await?
        {
            if r.state == RUN_PENDING || r.state == RUN_RUNNING {
                running.insert(r.revision);
            }
        }
        let recs: Vec<RevRec> = self
            .list_into::<RevRec>(&format!("{PFX_REVS}{app}/"))
            .await?
            .into_iter()
            .map(|(_, r)| r)
            .collect();
        let Some(last) = recs.last() else {
            return Ok(());
        };
        for t in &a.traffic {
            running.insert(t.revision.clone());
        }
        let max_seq = last.seq;
        for r in &recs {
            if r.name == a.active_revision
                || r.name == a.target_revision
                || running.contains(&r.name)
                || r.seq > max_seq - REVISIONS_TO_KEEP
            {
                continue;
            }
            self.delete(&rev_key(app, r.seq));
        }
        self.prune_secrets(app).await
    }

    /// resolveTraffic replaces "latest" with latest and checks every
    /// revision exists, belongs to app, and is listed once.
    async fn resolve_traffic(
        &self,
        app: &str,
        latest: &str,
        traffic: &[TrafficTarget],
    ) -> Result<Vec<TrafficTarget>> {
        let mut out = Vec::with_capacity(traffic.len());
        let mut seen = HashSet::new();
        for tt in traffic {
            let mut tt = tt.clone();
            if tt.revision == LATEST_REVISION {
                tt.revision = latest.to_string();
            }
            if !seen.insert(tt.revision.clone()) {
                return Err(precondition!(
                    "revisions.traffic lists {} twice (latest is {latest})",
                    tt.revision
                ));
            }
            match self.revision(&tt.revision).await {
                Err(e) if e.is(Kind::NotFound) => {
                    return Err(precondition!(
                        "revisions.traffic: {} is not a revision of {app} (see armada revision list {app})",
                        tt.revision
                    ));
                }
                Ok(rev) if rev.app != app => {
                    return Err(precondition!(
                        "revisions.traffic: {} is not a revision of {app} (see armada revision list {app})",
                        tt.revision
                    ));
                }
                Err(e) => return Err(e),
                Ok(_) => {}
            }
            out.push(tt);
        }
        Ok(out)
    }

    /// activateTraffic makes latest the app's current revision in multiple
    /// revision mode, with no rollout.
    #[allow(clippy::too_many_arguments)]
    async fn activate_traffic(
        &mut self,
        mut a: AppRec,
        latest: &str,
        traffic: &[TrafficTarget],
        replicas: i64,
        now: &Time,
        actor: &str,
        action: &str,
    ) -> Result<()> {
        let resolved = self.resolve_traffic(&a.name, latest, traffic).await?;
        a.active_revision = latest.to_string();
        a.target_revision = latest.to_string();
        a.traffic = resolved.iter().map(TrafficRec::from_spec).collect();
        a.rollout_state = ROLLOUT_NONE.to_string();
        a.rollout_message.clear();
        a.replicas = replicas;
        a.rollout_progress_at = unix_milli(now);
        a.updated_at = unix_milli(now);
        self.put(&format!("{PFX_APPS}{}", a.name), &a)?;
        self.prune_revisions(&a.name).await?;
        self.prune_domains().await?;
        self.audit(now, actor, action, &a.name, &traffic_string(&resolved))
            .await
    }
}

/// sameRevision: r runs exactly spec body with secret pins.
fn same_revision(r: &Revision, body: &str, pins: &BTreeMap<String, i64>) -> bool {
    r.spec().to_json() == body && &r.secrets == pins
}

impl Etcd {
    /// Deploy records spec as a new revision (see DeployWith).
    pub async fn deploy(&self, sp: &Spec, actor: &str) -> Result<(Revision, bool)> {
        self.deploy_with(sp, actor, &DeployOptions::default()).await
    }

    /// DeployWith is Deploy with the checks of opts, in the same
    /// transaction.
    pub async fn deploy_with(
        &self,
        sp: &Spec,
        actor: &str,
        opts: &DeployOptions,
    ) -> Result<(Revision, bool)> {
        let mut out = None;
        let id = sp.id();
        tx!(self, |t| {
            let a = t.app(&id).await?;
            if opts.must_create && a.is_some() {
                return Err(conflict!(
                    "{id} exists; deploy it without --new to change it"
                ));
            }
            if opts.must_exist && a.is_none() {
                return Err(Error::wrap(Kind::NotFound, format!("app {id}")));
            }
            if let Some(a) = &a
                && !opts.base_revision.is_empty()
                && a.target_revision != opts.base_revision
            {
                return Err(precondition!(
                    "{id} changed since {} (now {}); run the command again",
                    opts.base_revision,
                    a.target_revision
                ));
            }
            if sp.uses_space_secrets() {
                t.need_schema(
                    15,
                    "secrets of the space (SECRET/KEY references and envFrom lists)",
                )
                .await?;
            }
            let full = t.secret_env(sp).await?;
            let replicas = full.replicas();
            out = Some(
                self.deploy_revision(t, &full, replicas, actor, "deploy", false)
                    .await?,
            );
            Ok(())
        })?;
        Ok(out.expect("set by the transaction"))
    }

    /// deployRevision is deploy; force makes a new revision even when sp and
    /// its secret versions are those of the app's target or active revision.
    pub(crate) async fn deploy_revision(
        &self,
        t: &mut Etx<'_>,
        sp: &Spec,
        mut replicas: i64,
        actor: &str,
        action: &str,
        force: bool,
    ) -> Result<(Revision, bool)> {
        let multiple = sp.multiple_revisions();
        let mut traffic = Vec::new();
        let mut owned = sp.clone();
        if multiple && let Some(r) = owned.revisions.as_mut() {
            traffic = std::mem::take(&mut r.traffic);
        }
        let sp = Arc::new(owned);
        let body = sp.to_json();
        let pins = t.pin_secrets(&sp).await?;
        let id = sp.id();
        t.note_secret_users(&id, &pins).await?;
        let now = self.now();
        t.space_exists(&sp.space).await?;
        let same = |r: &Revision| !force && same_revision(r, &body, &pins);
        let a = t.app(&id).await?;
        if let Some(a) = &a {
            if a.removing {
                return Err(precondition!(
                    "{id} is being removed; deploy again once it is gone"
                ));
            }
            if sp.autoscaled() {
                replicas = kept_replicas(&sp, a.replicas);
            }
            let cur = t.revision(&a.active_revision).await?;
            if cur.spec().is_job() != sp.is_job() {
                let what = if cur.spec().is_job() {
                    "a job"
                } else {
                    "an app"
                };
                return Err(conflict!("{id} is {what}; choose another name"));
            }
            let tgt = if a.target_revision != a.active_revision {
                t.revision(&a.target_revision).await?
            } else {
                cur.clone()
            };
            if multiple && same(&tgt) {
                t.activate_traffic(
                    a.clone(),
                    &tgt.name,
                    &traffic,
                    replicas,
                    &now,
                    actor,
                    &format!("{action}.unchanged"),
                )
                .await?;
                return Ok((tgt, false));
            }
            if multiple && same(&cur) {
                t.activate_traffic(
                    a.clone(),
                    &cur.name,
                    &traffic,
                    replicas,
                    &now,
                    actor,
                    &format!("{action}.unchanged"),
                )
                .await?;
                return Ok((cur, false));
            }
            if same(&tgt) {
                let mut a = a.clone();
                a.replicas = replicas;
                a.updated_at = unix_milli(&now);
                t.put(&format!("{PFX_APPS}{}", a.name), &a)?;
                t.audit(&now, actor, &format!("{action}.unchanged"), &id, &tgt.name)
                    .await?;
                return Ok((tgt, false));
            }
            if same(&cur) {
                // Deploying what is already serving cancels the rollout.
                let target = a.target_revision.clone();
                t.set_target(a.clone(), &cur.name, replicas, &now).await?;
                t.prune_domains().await?;
                t.audit(&now, actor, &format!("{action}.cancel"), &id, &target)
                    .await?;
                return Ok((cur, false));
            }
        }
        t.claim_domains(&sp, &now).await?;
        let mut seq = 1;
        let revs = t.list(&format!("{PFX_REVS}{id}/")).await?;
        if let Some((last, _)) = revs.last() {
            let n = last
                .rsplit_once('/')
                .and_then(|(_, s)| atoi(s).ok())
                .ok_or_else(|| other!("bad revision key {last}"))?;
            seq = n + 1;
        }
        let rev = Revision {
            name: format!("{id}--r{seq}"),
            app: id.clone(),
            seq,
            spec: Some(sp.clone()),
            image_digest: String::new(),
            platforms: Vec::new(),
            secrets: pins.clone(),
            created_at: now.clone(),
        };
        let mut a = a.unwrap_or_else(|| AppRec {
            name: id.clone(),
            active_revision: rev.name.clone(),
            target_revision: rev.name.clone(),
            created_at: unix_milli(&now),
            ..Default::default()
        });
        t.put(
            &rev_key(&id, seq),
            &RevRec {
                name: rev.name.clone(),
                app: rev.app.clone(),
                seq,
                spec: RawValue::from_string(body.clone()).map_err(|e| other!("{e}"))?,
                image_digest: String::new(),
                platforms: Vec::new(),
                secrets: Some(pins.clone()),
                created_at: unix_milli(&now),
            },
        )?;
        if multiple {
            t.activate_traffic(a, &rev.name, &traffic, replicas, &now, actor, action)
                .await?;
            return Ok((rev, true));
        }
        if sp.is_job() {
            // Jobs have no rollouts: new runs use the new revision.
            a.active_revision = rev.name.clone();
        }
        t.set_target(a, &rev.name, replicas, &now).await?;
        t.prune_revisions(&id).await?;
        t.prune_domains().await?;
        t.audit(&now, actor, action, &id, &rev.name).await?;
        Ok((rev, true))
    }

    /// SetTraffic changes the weights of an app in multiple revision mode
    /// until its next deploy (ADR 0022).
    pub async fn set_traffic(
        &self,
        app: &str,
        weights: &[TrafficTarget],
        actor: &str,
    ) -> Result<Vec<TrafficTarget>> {
        let now = self.now();
        let mut out = Vec::new();
        tx!(self, |t| {
            let mut a = t.need_app(app).await?;
            let cur = t.revision(&a.active_revision).await?;
            if !cur.spec().multiple_revisions() || a.target_revision != a.active_revision {
                return Err(precondition!(
                    "{app} does not split traffic; set revisions.mode: multiple in its spec"
                ));
            }
            let labels: HashMap<String, String> = a
                .traffic
                .iter()
                .map(|t| (t.revision.clone(), t.label.clone()))
                .collect();
            let next: Vec<TrafficTarget> = weights
                .iter()
                .map(|w| TrafficTarget {
                    revision: w.revision.clone(),
                    weight: w.weight,
                    label: labels.get(&w.revision).cloned().unwrap_or_default(),
                })
                .collect();
            let errs = check_traffic(app, &next, false);
            if !errs.is_empty() {
                return Err(precondition!("{}", join(&errs)));
            }
            out = t.resolve_traffic(app, &a.active_revision, &next).await?;
            a.traffic = out.iter().map(TrafficRec::from_spec).collect();
            a.updated_at = unix_milli(&now);
            t.put(&format!("{PFX_APPS}{app}"), &a)?;
            t.prune_revisions(app).await?;
            t.audit(&now, actor, "traffic", app, &traffic_string(&out))
                .await
        })?;
        Ok(out)
    }

    /// Rollback makes an existing revision of app the rollout target.
    pub async fn rollback(&self, app: &str, revision: &str, actor: &str) -> Result<Revision> {
        let now = self.now();
        let mut out = None;
        tx!(self, |t| {
            let a = t.need_app(app).await?;
            let rev = t.revision(revision).await?;
            if rev.app != app {
                return Err(not_found!("revision {revision} of app {app}"));
            }
            if rev.spec().is_job() {
                return Err(precondition!(
                    "{app} is a job; jobs have no rollouts (deploy the spec you want its next runs to use)"
                ));
            }
            if !a.traffic.is_empty() || rev.spec().multiple_revisions() {
                return Err(precondition!(
                    "{app} splits traffic between revisions; change the weights with armada app traffic {app} or in its spec"
                ));
            }
            t.check_pins(&rev).await?;
            let kept = kept_replicas(rev.spec(), a.replicas);
            t.claim_domains(rev.spec(), &now).await?;
            t.set_target(a, revision, kept, &now).await?;
            t.prune_domains().await?;
            t.audit(&now, actor, "rollback", app, revision).await?;
            out = Some(rev);
            Ok(())
        })?;
        Ok(out.expect("set by the transaction"))
    }

    /// RestartApp makes a new revision of app's target spec with the latest
    /// version of every secret it uses and rolls it out.
    pub async fn restart_app(&self, app: &str, actor: &str) -> Result<Revision> {
        let mut out = None;
        tx!(self, |t| {
            let a = t.need_app(app).await?;
            if a.removing {
                return Err(precondition!("{app} is being removed"));
            }
            let cur = t.revision(&a.target_revision).await?;
            if cur.spec().is_job() {
                return Err(precondition!(
                    "{app} is a job; each run starts with the latest secrets (armada job start {app})"
                ));
            }
            if !a.traffic.is_empty() || cur.spec().multiple_revisions() {
                return Err(precondition!(
                    "{app} splits traffic between revisions; deploy its spec to make a new revision"
                ));
            }
            let (rev, _) = self
                .deploy_revision(t, cur.spec(), a.replicas, actor, "app.restart", true)
                .await?;
            out = Some(rev);
            Ok(())
        })?;
        Ok(out.expect("set by the transaction"))
    }

    /// CompleteRollout makes revision active if it is still the target.
    pub async fn complete_rollout(&self, app: &str, revision: &str) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            let Some(mut a) = t.app(app).await?.filter(|a| a.target_revision == revision) else {
                return Err(not_found!("rollout of {app} to {revision}"));
            };
            a.active_revision = a.target_revision.clone();
            a.rollout_state = ROLLOUT_NONE.to_string();
            a.rollout_message.clear();
            a.updated_at = unix_milli(&now);
            if let Ok(cur) = t.revision(revision).await
                && !cur.spec().multiple_revisions()
            {
                a.traffic.clear(); // the app has left multiple revision mode
            }
            t.put(&format!("{PFX_APPS}{app}"), &a)?;
            t.prune_revisions(app).await?;
            t.prune_domains().await?;
            t.audit(&now, "system", "rollout.complete", app, revision)
                .await
        })
    }

    /// FailRollout aborts the rollout to revision, if it is still the
    /// target, and keeps the active revision.
    pub async fn fail_rollout(&self, app: &str, revision: &str, message: &str) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            let Some(mut a) = t.app(app).await?.filter(|a| {
                a.target_revision == revision && a.target_revision != a.active_revision
            }) else {
                return Err(not_found!("rollout of {app} to {revision}"));
            };
            a.target_revision = a.active_revision.clone();
            a.rollout_state = ROLLOUT_FAILED.to_string();
            a.rollout_message = message.to_string();
            a.updated_at = unix_milli(&now);
            t.put(&format!("{PFX_APPS}{app}"), &a)?;
            t.prune_domains().await?;
            t.audit(
                &now,
                "system",
                "rollout.fail",
                app,
                &format!("{revision}: {message}"),
            )
            .await
        })
    }

    /// MarkRolloutProgress restarts the progress deadline.
    pub async fn mark_rollout_progress(&self, app: &str) -> Result<()> {
        tx!(self, |t| {
            let mut a = t.need_app(app).await?;
            a.rollout_progress_at = unix_milli(&self.now());
            t.put(&format!("{PFX_APPS}{app}"), &a)
        })
    }

    /// GetApp returns an app with its active spec.
    pub async fn get_app(&self, name: &str) -> Result<App> {
        let mut out = None;
        view!(self, |t| {
            let a = t.need_app(name).await?;
            out = Some(t.to_app(&a).await?);
            Ok(())
        })?;
        Ok(out.expect("set by the view"))
    }

    /// ListApps returns all apps ordered by name.
    pub async fn list_apps(&self) -> Result<Vec<App>> {
        let mut out = Vec::new();
        view!(self, |t| {
            out.clear();
            let recs: Vec<AppRec> = t
                .list_into::<AppRec>(PFX_APPS)
                .await?
                .into_iter()
                .map(|(_, a)| a)
                .collect();
            let names: Vec<String> = recs.iter().map(|a| a.active_revision.clone()).collect();
            let revs = t.revisions(&names).await?;
            for a in &recs {
                let Some(rev) = revs.get(&a.active_revision) else {
                    return Err(not_found!("revision {}", a.active_revision));
                };
                out.push(app_from(a, rev));
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// GetApps returns the apps that exist among names, with their active
    /// specs.
    pub async fn get_apps(&self, names: &[String]) -> Result<HashMap<String, App>> {
        let mut out = HashMap::new();
        view!(self, |t| {
            out.clear();
            let keys: Vec<String> = names.iter().map(|n| format!("{PFX_APPS}{n}")).collect();
            let raw = t.get_many(&keys).await?;
            let mut recs = Vec::with_capacity(raw.len());
            for (k, b) in &raw {
                recs.push(decode::<AppRec>(k, b)?);
            }
            let active: Vec<String> = recs.iter().map(|a| a.active_revision.clone()).collect();
            let revs = t.revisions(&active).await?;
            for a in &recs {
                let Some(rev) = revs.get(&a.active_revision) else {
                    return Err(not_found!("revision {}", a.active_revision));
                };
                out.insert(a.name.clone(), app_from(a, rev));
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// ListAppIDs returns every app's ID from the keys alone.
    pub async fn list_app_ids(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        view!(self, |t| {
            let pfx = t.full(PFX_APPS);
            let mut r = op::get_prefix(&pfx, t.rev);
            r.keys_only = true;
            let resp = self.c.range(r).await?;
            out = resp
                .kvs
                .iter()
                .map(|kv| {
                    let k = String::from_utf8_lossy(&kv.key);
                    k.strip_prefix(pfx.as_str()).unwrap_or(&k).to_string()
                })
                .collect();
            Ok(())
        })?;
        Ok(out)
    }

    /// SetReplicas changes the desired replica count until the next deploy.
    pub async fn set_replicas(&self, app: &str, n: i64, actor: &str) -> Result<()> {
        if !(1..=MAX_REPLICAS).contains(&n) {
            return Err(other!("replicas must be between 1 and {MAX_REPLICAS}"));
        }
        let now = self.now();
        tx!(self, |t| {
            let mut a = t.need_app(app).await?;
            let cur = t.revision(&a.active_revision).await?;
            if cur.spec().is_job() {
                return Err(precondition!(
                    "{app} is a job; it runs one container per run"
                ));
            }
            if cur.spec().autoscaled() {
                let (lo, hi) = cur.spec().scale_bounds();
                return Err(precondition!(
                    "{app} scales itself between {lo} and {hi} replicas: keep more running with `armada app deploy {app} --min N`, or run a fixed count with `armada app deploy {app} --no-autoscale --min N`"
                ));
            }
            let tgt = t.revision(&a.target_revision).await?;
            if tgt.spec().has_local_volumes() && n != 1 {
                return Err(precondition!(
                    "{app} has volumes and runs exactly one replica (ADR 0023)"
                ));
            }
            a.replicas = n;
            a.updated_at = unix_milli(&now);
            t.put(&format!("{PFX_APPS}{app}"), &a)?;
            t.audit(&now, actor, "scale", app, &n.to_string()).await
        })
    }

    /// AutoscaleReplicas sets an autoscaled app's count from from to n.
    pub async fn autoscale_replicas(
        &self,
        app: &str,
        from: i64,
        n: i64,
        actor: &str,
    ) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            let mut a = t.need_app(app).await?;
            let cur = t.revision(&a.active_revision).await?;
            let (lo, hi) = cur.spec().scale_bounds();
            if !cur.spec().autoscaled()
                || a.replicas != from
                || a.target_revision != a.active_revision
                || n < lo
                || n > hi
            {
                return Err(conflict!("app {app} changed since the autoscaler looked"));
            }
            a.replicas = n;
            a.updated_at = unix_milli(&now);
            a.scaled_at = unix_milli(&now);
            t.put(&format!("{PFX_APPS}{app}"), &a)?;
            t.audit(&now, actor, "autoscale", app, &format!("{from}->{n}"))
                .await
        })
    }

    /// GetRevision returns one revision.
    pub async fn get_revision(&self, name: &str) -> Result<Revision> {
        let mut out = None;
        view!(self, |t| {
            out = Some(t.revision(name).await?);
            Ok(())
        })?;
        Ok(out.expect("set by the view"))
    }

    /// GetRevisions returns the revisions that exist among names, by name.
    pub async fn get_revisions(&self, names: &[String]) -> Result<HashMap<String, Revision>> {
        let mut out = HashMap::new();
        view!(self, |t| {
            out = t.revisions(names).await?;
            Ok(())
        })?;
        Ok(out)
    }

    /// ListRevisions returns an app's revisions, newest first.
    pub async fn list_revisions(&self, app: &str) -> Result<Vec<Revision>> {
        let mut out = Vec::new();
        view!(self, |t| {
            out.clear();
            for (_, r) in t.list_into::<RevRec>(&format!("{PFX_REVS}{app}/")).await? {
                out.push(decode_rev(r)?);
            }
            Ok(())
        })?;
        out.reverse();
        Ok(out)
    }

    /// SetRevisionDigest records the pinned image once.
    pub async fn set_revision_digest(&self, revision: &str, digest: &str) -> Result<()> {
        tx!(self, |t| {
            let Some((app, seq)) = parse_revision_name(revision) else {
                return Ok(());
            };
            let k = rev_key(&app, seq);
            let Some(mut r) = t.get::<RevRec>(&k).await? else {
                return Ok(());
            };
            if !r.image_digest.is_empty() {
                return Ok(());
            }
            r.image_digest = digest.to_string();
            t.put(&k, &r)
        })
    }

    /// SetRevisionPlatforms records the image's platforms once.
    pub async fn set_revision_platforms(&self, revision: &str, platforms: &[String]) -> Result<()> {
        tx!(self, |t| {
            let Some((app, seq)) = parse_revision_name(revision) else {
                return Ok(());
            };
            let k = rev_key(&app, seq);
            let Some(mut r) = t.get::<RevRec>(&k).await? else {
                return Ok(());
            };
            if !r.platforms.is_empty() {
                return Ok(());
            }
            r.platforms = platforms.to_vec();
            t.put(&k, &r)
        })
    }

    /// CreateReplica schedules a replica.
    pub async fn create_replica(&self, r: &Replica) -> Result<()> {
        let mut r = r.clone();
        if r.state.is_empty() {
            r.state = REPLICA_PENDING.to_string();
        }
        let pfx = replica_prefix(&r.app);
        if !r.id.starts_with(&pfx) {
            return Err(precondition!(
                "replica ID {} does not start with {}",
                quote(&r.id),
                quote(&pfx)
            ));
        }
        let r = &r;
        tx!(self, |t| {
            let k = format!("{PFX_REPLICAS}{}", r.id);
            if t.get_raw(&k).await?.is_some() {
                return Err(conflict!("replica {} exists", r.id));
            }
            t.need_app(&r.app).await?;
            let rev = t.revision(&r.revision).await?;
            if t.node(&r.node_id).await?.is_none() {
                return Err(not_found!("node {}", r.node_id));
            }
            let now = self.now();
            t.bind_volumes(&rev, &r.node_id, &now).await?;
            t.put_placement(r, &now)?;
            t.put(
                &k,
                &ReplicaRec {
                    id: r.id.clone(),
                    app: r.app.clone(),
                    revision: r.revision.clone(),
                    node_id: r.node_id.clone(),
                    state: r.state.clone(),
                    updated_at: unix_milli(&now),
                    created_at: unix_milli(&now),
                    run: r.run,
                    task: r.task,
                    held: r.held,
                    ..Default::default()
                },
            )
        })
    }

    /// DeleteReplica removes a replica from desired state.
    pub async fn delete_replica(&self, id: &str) -> Result<()> {
        tx!(self, |t| {
            let k = format!("{PFX_REPLICAS}{id}");
            if t.get_raw(&k).await?.is_none() {
                return Err(not_found!("replica {id}"));
            }
            t.delete(&k);
            Ok(())
        })
    }

    async fn update_replica(
        &self,
        id: &str,
        f: impl Fn(&mut ReplicaRec, &Time) -> bool,
    ) -> Result<()> {
        tx!(self, |t| {
            let k = format!("{PFX_REPLICAS}{id}");
            let Some(mut r) = t.get::<ReplicaRec>(&k).await? else {
                return Err(not_found!("replica {id}"));
            };
            if !f(&mut r, &self.now()) {
                return Ok(());
            }
            t.put(&k, &r)
        })
    }

    /// DrainReplica marks a replica as draining (idempotent).
    pub async fn drain_replica(&self, id: &str) -> Result<()> {
        self.update_replica(id, |r, now| {
            if r.draining_since != 0 {
                return false;
            }
            r.draining_since = unix_milli(now);
            true
        })
        .await
    }

    /// SetReplicaMoving marks a replica as being moved, or clears the mark.
    pub async fn set_replica_moving(&self, id: &str, moving: bool) -> Result<()> {
        self.update_replica(id, |r, now| {
            if moving && r.moving_since == 0 {
                r.moving_since = unix_milli(now);
            } else if !moving && r.moving_since != 0 {
                r.moving_since = 0;
            } else {
                return false;
            }
            true
        })
        .await
    }

    /// ReleaseReplica lifts a replica's hold (idempotent).
    pub async fn release_replica(&self, id: &str) -> Result<()> {
        self.update_replica(id, |r, _| {
            if !r.held {
                return false;
            }
            r.held = false;
            true
        })
        .await
    }

    /// SetReplicaDone marks a job attempt as over.
    pub async fn set_replica_done(&self, id: &str) -> Result<()> {
        self.update_replica(id, |r, _| {
            if r.done {
                return false;
            }
            r.done = true;
            true
        })
        .await
    }

    /// ListReplicas returns replicas matching f ordered by ID.
    pub async fn list_replicas(&self, f: &ReplicaFilter) -> Result<Vec<Replica>> {
        let mut out = Vec::new();
        view!(self, |t| {
            out.clear();
            let recs = if f.app.is_empty() {
                t.list_into::<ReplicaRec>(PFX_REPLICAS).await?
            } else {
                t.app_replicas(&f.app).await?
            };
            for (_, r) in recs {
                if (f.app.is_empty() || r.app == f.app)
                    && (f.node_id.is_empty() || r.node_id == f.node_id)
                {
                    out.push(replica_of(r));
                }
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// UpdateReplicaStatus applies a status report from node_id.
    pub async fn update_replica_status(&self, node_id: &str, st: &ReplicaStatus) -> Result<()> {
        let now = unix_milli(&self.now());
        tx!(self, |t| {
            let k = format!("{PFX_REPLICAS}{}", st.id);
            let Some(mut r) = t
                .get::<ReplicaRec>(&k)
                .await?
                .filter(|r| r.node_id == node_id)
            else {
                return Err(not_found!("replica {} on node {node_id}", st.id));
            };
            let ready = st.ready && st.state == REPLICA_RUNNING;
            if !ready {
                r.ready_since = 0;
            } else if !(r.ready && r.ready_since != 0) {
                r.ready_since = now;
            }
            if r.run == 0
                && !r.container_id.is_empty()
                && !st.container_id.is_empty()
                && st.container_id != r.container_id
            {
                r.restarts += 1;
                r.last_restart_at = now;
                r.last_restart.clear();
            }
            if r.restarts > 0
                && r.last_restart.is_empty()
                && let Some(why) = st.message.strip_prefix(RESTART_NOTE)
            {
                r.last_restart = why.to_string();
            }
            r.state = st.state.clone();
            r.container_id = st.container_id.clone();
            r.address = st.address.clone();
            r.ip = st.ip.clone();
            r.message = st.message.clone();
            r.updated_at = now;
            r.ready = ready;
            if r.run != 0 && !r.finished {
                r.finished = st.finished;
                r.exit_code = st.exit_code;
            }
            t.put(&k, &r)
        })
    }

    /// ListDomains returns all registered custom domains ordered by name.
    pub async fn list_domains(&self) -> Result<Vec<Domain>> {
        let mut out = Vec::new();
        view!(self, |t| {
            out = t
                .list_into::<DomainRec>(PFX_DOMAINS)
                .await?
                .into_iter()
                .map(|(_, d)| to_domain(d))
                .collect();
            Ok(())
        })?;
        Ok(out)
    }

    /// GetDomain returns one domain.
    pub async fn get_domain(&self, name: &str) -> Result<Domain> {
        let mut out = None;
        view!(self, |t| {
            let Some(d) = t.get::<DomainRec>(&format!("{PFX_DOMAINS}{name}")).await? else {
                return Err(not_found!("domain {name}"));
            };
            out = Some(to_domain(d));
            Ok(())
        })?;
        Ok(out.expect("set by the view"))
    }

    /// SetDomainVerification records the outcome of an ownership check; a
    /// domain verified once stays verified.
    pub async fn set_domain_verification(
        &self,
        name: &str,
        verified: bool,
        message: &str,
    ) -> Result<()> {
        tx!(self, |t| {
            let k = format!("{PFX_DOMAINS}{name}");
            let Some(mut d) = t.get::<DomainRec>(&k).await? else {
                return Err(not_found!("domain {name}"));
            };
            if verified {
                if !d.verified {
                    d.verified_at = unix_milli(&self.now());
                }
                d.verified = true;
                d.message.clear();
            } else if d.verified {
                return Ok(());
            } else {
                d.message = message.to_string();
            }
            t.put(&k, &d)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revision_names() {
        assert_eq!(parse_revision_name("web--r3"), Some(("web".to_string(), 3)));
        assert_eq!(
            parse_revision_name("web.shop--r12"),
            Some(("web.shop".to_string(), 12))
        );
        assert_eq!(
            parse_revision_name("a--r1--r2"),
            Some(("a--r1".to_string(), 2))
        );
        for bad in ["web", "--r1", "web--r0", "web--rx", "web--r-1"] {
            assert_eq!(parse_revision_name(bad), None, "{bad}");
        }
        assert_eq!(rev_key("web", 7), "revs/web/0000000007");
    }

    #[test]
    fn routes_and_counts() {
        let sp = armada_spec::parse(
            b"name: web\nimage: nginx\ningress:\n  type: external\n  port: 80\n  domains: [a.example.com]\n  routes:\n    - path: /\n    - path: /api\n",
        )
        .unwrap();
        assert_eq!(route_keys(&sp), ["a.example.com/", "a.example.com/api"]);
        assert_eq!(kept_replicas(&sp, 4), 4);
        let auto = armada_spec::parse(
            b"name: a\nimage: nginx\ningress:\n  type: internal\n  port: 80\nscale:\n  min: 2\n  max: 3\n  rules:\n    - type: cpu\n      utilization: 50\n",
        )
        .unwrap();
        assert_eq!(kept_replicas(&auto, 9), 3);
        assert_eq!(kept_replicas(&auto, 1), 2);
        assert_eq!(space_of("web.shop"), "shop");
        assert_eq!(space_of("web"), "default");
        assert_eq!(space_of("Bad!"), "");
    }
}

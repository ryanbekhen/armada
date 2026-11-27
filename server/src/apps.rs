//! Apps through the API (Go's admin.go, apps.go, remove.go, nfs.go, and
//! the URL helpers of ingress.go): deploys, traffic, revisions,
//! rollbacks, restarts, removal, and what `armada app list|show` and
//! `armada node list` read.
//!
//! Deploys, rollbacks, and restarts check volume backup buckets
//! (`backups`, Go's checkBackupTargets, ADR 0041). Node status leaves out the usage samples
//! (the last sample's time and runtime) until watching (15); an
//! autoscaled app shows the autoscaler's last evaluation, or its bounds
//! until the first.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use armada_proto::armada::v1::*;
use armada_spec::validate::{
    DEFAULT_SPACE, LATEST_REVISION, MAX_TRAFFIC_TARGETS, internal_host, label_host, validate_domain,
};
use armada_spec::{
    App as Spec, INGRESS_EXTERNAL, INGRESS_INTERNAL, INGRESS_NONE, Ingress, MAIN_CONTAINER,
};
use armada_store::{App, DeployOptions, Kind, Node, Replica, ReplicaFilter};
use tonic::{Code, Status};

use crate::assign::Revisions;
use crate::backups::UrlSource;
use crate::events::timestamp;
use crate::grpc::Auth;
use crate::reconcile::{APP, ROLLOUT, app_event, nanos, node_lost, traffic_shares};
use crate::schedule::{allocatable, placement_message, placement_needs_cluster};
use crate::{Server, store_err};

/// Bounds and states of the app listings (ADR 0032).
const MAX_APPS_PAGE: usize = 500;
pub(crate) const APP_READY: &str = "ready";
pub(crate) const APP_PROGRESS: &str = "progressing";
pub(crate) const APP_FAILING: &str = "failing";
pub(crate) const APP_IDLE: &str = "idle";
const JOB: &str = "job";
/// nodeStateLost is shown for nodes whose replicas are being rescheduled.
const NODE_STATE_LOST: &str = "lost";

fn spec_of(a: &App) -> &Spec {
    a.spec.as_deref().expect("a stored app has a spec")
}

fn ingress_type(sp: &Spec) -> String {
    sp.ingress
        .as_ref()
        .map(|i| i.typ.clone())
        .unwrap_or_default()
}

fn optional_time(
    t: &armada_spec::gotime::Time,
) -> Option<armada_proto::google::protobuf::Timestamp> {
    (!t.is_zero()).then(|| timestamp(t))
}

fn ip_rules(rules: &[armada_spec::IPRule]) -> Vec<IpRule> {
    rules
        .iter()
        .map(|r| IpRule {
            range: r.range.clone(),
            name: r.name.clone(),
            description: r.description.clone(),
        })
        .collect()
}

/// trafficMessage: "web--r3 90%, web--r4 10%".
fn traffic_message(t: &[armada_spec::TrafficTarget]) -> String {
    t.iter()
        .map(|t| format!("{} {}%", t.revision, t.weight))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The routes an app serves (Go's appRoutes).
fn app_routes(sp: &Spec) -> Vec<String> {
    match &sp.ingress {
        Some(i) if !i.routes.is_empty() => i.routes.iter().map(|r| r.path.clone()).collect(),
        _ => vec!["/".to_string()],
    }
}

/// rootHost: the host Armada gives a name under the root domain, or "".
fn root_host(name: &str, root: &str) -> String {
    if root.is_empty() {
        return String::new();
    }
    let h = format!("{name}.{root}");
    if validate_domain(&h).is_err() {
        return String::new();
    }
    h
}

/// What app URLs are made of (Go's urlSources).
#[derive(Default)]
pub(crate) struct UrlSources {
    root: String,
    verified: HashMap<String, bool>,
    scheme: String,
}

/// appURLsFrom.
fn app_urls(app: &App, src: &UrlSources) -> Vec<String> {
    let sp = spec_of(app);
    let Some(ing) = &sp.ingress else {
        return Vec::new();
    };
    if ing.typ == INGRESS_NONE {
        return Vec::new();
    }
    if Ingress::tcp(Some(ing)) {
        return vec![format!("tcp://{}:{}", internal_host(&app.name), ing.port)];
    }
    if ing.typ == INGRESS_INTERNAL {
        return app_routes(sp)
            .iter()
            .map(|p| format!("http://{}{p}", internal_host(&app.name)))
            .collect();
    }
    let scheme = if src.scheme.is_empty() {
        "https"
    } else {
        &src.scheme
    };
    let mut hosts = Vec::new();
    let h = root_host(&app.name, &src.root);
    if !h.is_empty() {
        hosts.push(h);
    }
    for d in &ing.domains {
        if src.verified.get(d).copied().unwrap_or(false) && !hosts.contains(d) {
            hosts.push(d.clone());
        }
    }
    let mut urls = Vec::new();
    for h in hosts {
        for p in app_routes(sp) {
            urls.push(format!("{scheme}://{h}{p}"));
        }
    }
    urls
}

/// specContainers: "app" and its sidecars, then its init containers.
pub(crate) fn spec_containers(sp: &Spec) -> (Vec<String>, Vec<String>) {
    let mut running = vec![MAIN_CONTAINER.to_string()];
    running.extend(sp.sidecars.iter().map(|c| c.name.clone()));
    let inits = sp.init_containers.iter().map(|c| c.name.clone()).collect();
    (running, inits)
}

impl Server {
    fn public_scheme(&self) -> &'static str {
        if self.0.plain_http { "http" } else { "https" }
    }

    /// urlSource: the root domain and the verified domains.
    async fn url_source(&self) -> UrlSources {
        let mut src = UrlSources {
            root: self.root_domain().await,
            verified: HashMap::new(),
            scheme: self.public_scheme().to_string(),
        };
        if let Ok(ds) = self.store().list_domains().await {
            for d in ds {
                src.verified.insert(d.name, d.verified);
            }
        }
        src
    }

    /// appURLSource: urlSource reading only the domains app names.
    async fn app_url_source(&self, app: &App) -> UrlSources {
        let sp = spec_of(app);
        let Some(ing) = sp.ingress.as_ref().filter(|i| i.typ == INGRESS_EXTERNAL) else {
            return UrlSources::default();
        };
        let mut src = UrlSources {
            root: self.root_domain().await,
            verified: HashMap::new(),
            scheme: self.public_scheme().to_string(),
        };
        for name in &ing.domains {
            if let Ok(d) = self.store().get_domain(name).await {
                src.verified.insert(d.name, d.verified);
            }
        }
        src
    }

    /// labelURLs: the URLs a revision label serves under (ADR 0022).
    async fn label_urls(&self, app: &App, label: &str) -> Vec<String> {
        let sp = spec_of(app);
        let Some(ing) = &sp.ingress else {
            return Vec::new();
        };
        if label.is_empty() || app.rolling() {
            return Vec::new();
        }
        let name = label_host(label, &app.name);
        let mut prefix = format!("http://{}", internal_host(&name));
        if ing.typ == INGRESS_EXTERNAL {
            let root = self.root_domain().await;
            if root.is_empty() || validate_domain(&format!("{name}.{root}")).is_err() {
                return Vec::new();
            }
            prefix = format!("{}://{name}.{root}", self.public_scheme());
        }
        app_routes(sp)
            .iter()
            .map(|p| format!("{prefix}{p}"))
            .collect()
    }

    /// checkNFSExports: only cluster-admins add an NFS export to an app,
    /// or make one writable (ADR 0042).
    pub(crate) async fn check_nfs_exports(&self, a: &Auth, sp: &Spec) -> Result<(), Status> {
        if a.acc.admin() || !sp.has_nfs_volumes() {
            return Ok(());
        }
        let mut allowed: Vec<armada_spec::NfsSource> = Vec::new();
        match self.store().get_app(&sp.id()).await {
            Err(e) if e.kind == Kind::NotFound => {}
            Err(e) => return Err(store_err(&e)),
            Ok(app) => {
                let rn = if app.target_revision.is_empty() {
                    app.active_revision.clone()
                } else {
                    app.target_revision.clone()
                };
                if !rn.is_empty() {
                    let rev = self
                        .store()
                        .get_revision(&rn)
                        .await
                        .map_err(|e| store_err(&e))?;
                    for v in &rev.spec().volumes {
                        if let Some(n) = &v.nfs {
                            allowed.push(n.clone());
                            let mut ro = n.clone();
                            ro.read_only = true;
                            allowed.push(ro);
                        }
                    }
                }
            }
        }
        for v in &sp.volumes {
            if let Some(n) = &v.nfs
                && !allowed.contains(n)
            {
                return Err(Status::new(
                    Code::PermissionDenied,
                    format!(
                        "volume {}: adding an NFS export ({}:{}) or making one writable needs cluster-admin, since it reaches storage outside the cluster",
                        v.name, n.server, n.path
                    ),
                ));
            }
        }
        Ok(())
    }

    /// checkStoredRevision: Deploy's placement and NFS checks on the
    /// stored spec of a revision a non-cluster-admin makes serve again.
    async fn check_stored_revision(&self, a: &Auth, app: &str, name: &str) -> Result<(), Status> {
        if a.acc.admin() {
            return Ok(());
        }
        let rev = match self.store().get_revision(name).await {
            Err(e) if e.kind == Kind::NotFound => return Ok(()),
            Err(e) => return Err(store_err(&e)),
            Ok(r) => r,
        };
        let Some(sp) = &rev.spec else { return Ok(()) };
        if rev.app != app {
            return Ok(());
        }
        a.acc.placement(sp)?;
        self.check_nfs_exports(a, sp).await
    }

    /// checkTrafficRevisions: checkStoredRevision on every revision traffic
    /// names other than latest and those already in the app's traffic.
    async fn check_traffic_revisions(
        &self,
        a: &Auth,
        app: &str,
        traffic: &[armada_spec::TrafficTarget],
    ) -> Result<(), Status> {
        if a.acc.admin() {
            return Ok(());
        }
        let mut serving = BTreeSet::new();
        match self.store().get_app(app).await {
            Err(e) if e.kind == Kind::NotFound => {}
            Err(e) => return Err(store_err(&e)),
            Ok(x) => serving.extend(x.traffic.into_iter().map(|t| t.revision)),
        }
        for t in traffic {
            if t.revision == LATEST_REVISION || serving.contains(&t.revision) {
                continue;
            }
            self.check_stored_revision(a, app, &t.revision).await?;
        }
        Ok(())
    }

    /// Deploy validates a spec and records it as the app's revision.
    pub(crate) async fn deploy(
        &self,
        a: &Auth,
        req: DeployRequest,
    ) -> Result<DeployResponse, Status> {
        a.acc.space(&req.space)?;
        let app = armada_spec::parse_in(&req.spec, &req.space)
            .map_err(|e| Status::new(Code::InvalidArgument, e))?;
        a.acc.placement(&app)?;
        self.check_nfs_exports(a, &app).await?;
        if let Some(r) = &app.revisions
            && !r.traffic.is_empty()
        {
            self.check_traffic_revisions(a, &app.id(), &r.traffic)
                .await?;
        }
        self.check_backup_targets(
            &a.acc,
            &app.id(),
            &app,
            &mut UrlSource::Latest {
                app: &app.id(),
                infos: Default::default(),
            },
        )
        .await?;
        if Ingress::tcp(app.ingress.as_ref()) {
            match self.store().get_network().await {
                Err(e) if e.kind == Kind::NotFound => {
                    return Err(Status::new(
                        Code::FailedPrecondition,
                        "TCP ingress needs the cluster network (armadad init --cluster-cidr), which this cluster was created without",
                    ));
                }
                Err(e) => return Err(store_err(&e)),
                Ok(_) => {}
            }
        }
        if app.queue_trigger().is_some() {
            let mode = match self.store().get_network().await {
                Err(e) if e.kind == Kind::NotFound => String::new(),
                Err(e) => return Err(store_err(&e)),
                Ok(n) => n.mode,
            };
            if mode.is_empty() {
                return Err(Status::new(
                    Code::FailedPrecondition,
                    "trigger.queue needs a cluster network (armadad init --network): the queue is read from the job's own network, which a cluster without one does not have",
                ));
            }
        }
        let id = app.id();
        let opts = DeployOptions {
            must_create: req.must_create,
            must_exist: req.must_exist,
            base_revision: req.base_revision.clone(),
        };
        let (rev, created) = match self.store().deploy_with(&app, &a.actor(), &opts).await {
            Ok(x) => x,
            Err(e) => {
                self.0.log.error(
                    "deploy failed",
                    &[("app", id.clone()), ("err", e.to_string())],
                );
                return Err(store_err(&e));
            }
        };
        self.0.log.info(
            "deployed",
            &[
                ("app", id.clone()),
                ("revision", rev.name.clone()),
                ("new_revision", created.to_string()),
                ("by", a.actor()),
            ],
        );
        if app.multiple_revisions() {
            // No rollout: the traffic applies at once (ADR 0022).
            let mut msg = format!("image {}", app.image);
            if let Ok(x) = self.store().get_app(&id).await {
                msg = traffic_message(&x.traffic);
            }
            if created {
                msg += &format!("; new revision {}", rev.name);
            }
            self.record(app_event(APP, &id, &id, "TrafficChanged", &msg))
                .await;
        } else if created && app.is_job() {
            self.record(app_event(
                JOB,
                &id,
                &id,
                "Deployed",
                &format!("new runs use {} (image {})", rev.name, app.image),
            ))
            .await;
        } else if created {
            self.record(app_event(
                ROLLOUT,
                &rev.name,
                &id,
                "Started",
                &format!("rolling out {} (image {})", rev.name, app.image),
            ))
            .await;
        }
        self.trigger();
        Ok(DeployResponse {
            app: id,
            revision: rev.name,
        })
    }

    /// SetTraffic changes how an app in multiple revision mode splits
    /// requests until its next deploy (ADR 0022).
    pub(crate) async fn set_traffic(
        &self,
        a: &Auth,
        req: SetTrafficRequest,
    ) -> Result<SetTrafficResponse, Status> {
        a.acc.app(&req.app)?;
        if req.traffic.len() > MAX_TRAFFIC_TARGETS {
            return Err(Status::new(
                Code::InvalidArgument,
                format!("at most {MAX_TRAFFIC_TARGETS} revisions"),
            ));
        }
        let want: Vec<armada_spec::TrafficTarget> = req
            .traffic
            .iter()
            .map(|t| armada_spec::TrafficTarget {
                revision: t.revision.clone(),
                weight: i64::from(t.weight),
                label: String::new(),
            })
            .collect();
        self.check_traffic_revisions(a, &req.app, &want).await?;
        let got = self
            .store()
            .set_traffic(&req.app, &want, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "traffic changed",
            &[("app", req.app.clone()), ("by", a.actor())],
        );
        self.record(app_event(
            APP,
            &req.app,
            &req.app,
            "TrafficChanged",
            &traffic_message(&got),
        ))
        .await;
        self.trigger();
        Ok(SetTrafficResponse {
            traffic: got
                .iter()
                .map(|t| TrafficTarget {
                    revision: t.revision.clone(),
                    weight: t.weight as i32,
                    label: t.label.clone(),
                    ..Default::default()
                })
                .collect(),
        })
    }

    /// ListRevisions: an app's retained revisions, newest first.
    pub(crate) async fn list_revisions(
        &self,
        a: &Auth,
        req: ListRevisionsRequest,
    ) -> Result<ListRevisionsResponse, Status> {
        a.acc.app(&req.app)?;
        let app = self
            .store()
            .get_app(&req.app)
            .await
            .map_err(|e| store_err(&e))?;
        let revs = self
            .store()
            .list_revisions(&app.name)
            .await
            .map_err(|e| store_err(&e))?;
        Ok(ListRevisionsResponse {
            revisions: revs
                .iter()
                .map(|r| RevisionInfo {
                    name: r.name.clone(),
                    image: r.spec().image.clone(),
                    image_digest: r.image_digest.clone(),
                    created_at: Some(timestamp(&r.created_at)),
                    active: r.name == app.active_revision,
                    target: r.name == app.target_revision,
                    platforms: r.platforms.clone(),
                })
                .collect(),
        })
    }

    async fn previous_revision(&self, app: &App) -> Result<String, Status> {
        if app.rolling() {
            return Ok(app.active_revision.clone());
        }
        let revs = self
            .store()
            .list_revisions(&app.name)
            .await
            .map_err(|e| store_err(&e))?;
        let active = revs
            .iter()
            .filter(|r| r.name == app.active_revision)
            .map(|r| r.seq)
            .next_back()
            .unwrap_or(0);
        if let Some(r) = revs.iter().find(|r| r.seq < active) {
            return Ok(r.name.clone());
        }
        Err(Status::new(
            Code::FailedPrecondition,
            format!("app {} has no earlier revision to roll back to", app.name),
        ))
    }

    /// Rollback rolls an app out to an earlier revision.
    pub(crate) async fn rollback(
        &self,
        a: &Auth,
        req: RollbackRequest,
    ) -> Result<RollbackResponse, Status> {
        a.acc.app(&req.app)?;
        let app = self
            .store()
            .get_app(&req.app)
            .await
            .map_err(|e| store_err(&e))?;
        let target = if req.revision.is_empty() {
            self.previous_revision(&app).await?
        } else {
            req.revision.clone()
        };
        self.check_stored_revision(a, &app.name, &target).await?;
        self.check_rollback_backups(&a.acc, &app.name, &target)
            .await?;
        let rev = self
            .store()
            .rollback(&app.name, &target, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "rollback",
            &[
                ("app", app.name.clone()),
                ("revision", rev.name.clone()),
                ("by", a.actor()),
            ],
        );
        self.record(app_event(
            ROLLOUT,
            &rev.name,
            &app.name,
            "RolledBack",
            &format!("rolling back to {}", rev.name),
        ))
        .await;
        self.trigger();
        Ok(RollbackResponse { revision: rev.name })
    }

    /// RestartApp makes a new revision of an app's spec with the latest
    /// secret values and rolls it out (ADR 0052).
    pub(crate) async fn restart_app(
        &self,
        a: &Auth,
        req: RestartAppRequest,
    ) -> Result<RestartAppResponse, Status> {
        a.acc.app(&req.app)?;
        let app = self
            .store()
            .get_app(&req.app)
            .await
            .map_err(|e| store_err(&e))?;
        self.check_stored_revision(a, &app.name, &app.target_revision)
            .await?;
        let target = self
            .store()
            .get_revision(&app.target_revision)
            .await
            .map_err(|e| store_err(&e))?;
        self.check_backup_targets(
            &a.acc,
            &app.name,
            target.spec(),
            &mut UrlSource::Latest {
                app: &app.name,
                infos: Default::default(),
            },
        )
        .await?;
        let rev = self
            .store()
            .restart_app(&app.name, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "restart",
            &[
                ("app", app.name.clone()),
                ("revision", rev.name.clone()),
                ("by", a.actor()),
            ],
        );
        self.record(app_event(
            ROLLOUT,
            &rev.name,
            &app.name,
            "Restarted",
            &format!("restarting as {}", rev.name),
        ))
        .await;
        self.trigger();
        Ok(RestartAppResponse { revision: rev.name })
    }

    /// RemoveApp starts removing an app: the reconciler drains its
    /// replicas, then removes it.
    pub(crate) async fn remove_app(
        &self,
        a: &Auth,
        req: RemoveAppRequest,
    ) -> Result<RemoveAppResponse, Status> {
        a.acc.app(&req.app)?;
        self.store()
            .mark_app_removing(&req.app, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "removing app",
            &[("app", req.app.clone()), ("by", a.actor())],
        );
        self.record(app_event(
            APP,
            &req.app,
            &req.app,
            "Removing",
            &format!("by {}", a.actor()),
        ))
        .await;
        self.trigger();
        Ok(RemoveAppResponse {})
    }

    /// GetAppSpec: the spec an app or job runs (its target revision) as a
    /// file holds it (ADR 0032).
    pub(crate) async fn get_app_spec(
        &self,
        a: &Auth,
        req: GetAppSpecRequest,
    ) -> Result<GetAppSpecResponse, Status> {
        a.acc.app(&req.app)?;
        let app = self
            .store()
            .get_app(&req.app)
            .await
            .map_err(|e| store_err(&e))?;
        let rev = self
            .store()
            .get_revision(&app.target_revision)
            .await
            .map_err(|e| store_err(&e))?;
        let spec = rev
            .spec()
            .export()
            .map_err(|_| Status::new(Code::Internal, "export the spec"))?;
        Ok(GetAppSpecResponse {
            spec,
            revision: rev.name,
        })
    }

    /// appSummaries: a summary of each app (not job) the caller sees.
    pub(crate) async fn app_summaries(
        &self,
        a: &Auth,
        keep: impl Fn(&App) -> bool,
    ) -> Result<Vec<AppSummary>, Status> {
        let apps = self.store().list_apps().await.map_err(|e| store_err(&e))?;
        let reps = self
            .store()
            .list_replicas(&ReplicaFilter::default())
            .await
            .map_err(|e| store_err(&e))?;
        let mut ready: HashMap<&str, i64> = HashMap::new();
        for r in &reps {
            if r.ready && !r.draining() && !r.done {
                *ready.entry(r.app.as_str()).or_default() += 1;
            }
        }
        let src = self.url_source().await;
        let mut out = Vec::new();
        for x in &apps {
            let sp = spec_of(x);
            if sp.is_job() || !a.acc.sees(&x.name) || !keep(x) {
                continue;
            }
            let n = ready.get(x.name.as_str()).copied().unwrap_or(0);
            let mut sum = AppSummary {
                name: x.name.clone(),
                space: if sp.space.is_empty() {
                    DEFAULT_SPACE.to_string()
                } else {
                    sp.space.clone()
                },
                image: sp.image.clone(),
                revision: x.active_revision.clone(),
                ready: n.min(1 << 30) as i32,
                desired: x.replicas as i32,
                ..Default::default()
            };
            if let Some(i) = &sp.ingress {
                sum.ingress = i.typ.clone();
            }
            if let Some(u) = app_urls(x, &src).into_iter().next() {
                sum.url = u;
            }
            if x.removing {
                sum.state = APP_PROGRESS.to_string();
                sum.message = "being removed".to_string();
            } else if x.rollout_state == armada_store::ROLLOUT_FAILED {
                sum.state = APP_FAILING.to_string();
                sum.message = x.rollout_message.clone();
            } else if x.rolling() {
                sum.state = APP_PROGRESS.to_string();
                sum.message = format!("rolling out {}", x.target_revision);
                sum.target_revision = x.target_revision.clone();
                if let Ok(rev) = self.store().get_revision(&x.target_revision).await
                    && let Some(s) = &rev.spec
                {
                    sum.target_image = s.image.clone();
                }
            } else if x.replicas == 0 {
                sum.state = APP_IDLE.to_string();
            } else if i64::from(sum.ready) < x.replicas {
                sum.state = APP_FAILING.to_string();
                sum.message = "not every replica is ready".to_string();
            } else {
                sum.state = APP_READY.to_string();
            }
            out.push(sum);
        }
        out.sort_by(|x, y| x.name.cmp(&y.name));
        Ok(out)
    }

    /// ListApps: one summary per app, a page at a time.
    pub(crate) async fn list_apps(
        &self,
        a: &Auth,
        req: ListAppsRequest,
    ) -> Result<ListAppsResponse, Status> {
        let space = if req.space.is_empty() {
            DEFAULT_SPACE.to_string()
        } else {
            req.space.clone()
        };
        if !req.all_spaces {
            a.acc.space(&req.space)?;
        }
        let size = if req.page_size <= 0 || req.page_size as usize > MAX_APPS_PAGE {
            MAX_APPS_PAGE
        } else {
            req.page_size as usize
        };
        let all = self
            .app_summaries(a, |x| {
                let sp = spec_of(x);
                let s = if sp.space.is_empty() {
                    DEFAULT_SPACE
                } else {
                    sp.space.as_str()
                };
                req.all_spaces || s == space
            })
            .await?;
        let start = if req.page_token.is_empty() {
            0
        } else {
            all.iter()
                .position(|x| x.name > req.page_token)
                .unwrap_or(all.len())
        };
        let end = (start + size).min(all.len());
        let mut resp = ListAppsResponse {
            apps: all[start..end].to_vec(),
            next_page_token: String::new(),
        };
        if end < all.len() {
            resp.next_page_token = all[end - 1].name.clone();
        }
        Ok(resp)
    }

    /// Status: apps, replicas, and nodes; with an app, that app alone.
    pub(crate) async fn status(
        &self,
        a: &Auth,
        req: StatusRequest,
    ) -> Result<StatusResponse, Status> {
        if !req.app.is_empty() {
            return self.app_status(a, &req.app).await;
        }
        let mut apps = Vec::new();
        if !req.nodes_only {
            apps = self.store().list_apps().await.map_err(|e| store_err(&e))?;
            apps.retain(|x| a.acc.sees(&x.name));
        }
        let nodes = self.store().list_nodes().await.map_err(|e| store_err(&e))?;
        let all = self
            .store()
            .list_replicas(&ReplicaFilter::default())
            .await
            .map_err(|e| store_err(&e))?;
        let mut per_node: HashMap<&str, i32> = HashMap::new();
        for r in &all {
            if !r.done {
                *per_node.entry(r.node_id.as_str()).or_default() += 1;
            }
        }
        let mut resp = StatusResponse::default();
        if !apps.is_empty() {
            let mut revs = Revisions::new(self);
            revs.preload(&apps, &all).await;
            let servers = self
                .store()
                .list_servers()
                .await
                .map_err(|e| store_err(&e))?;
            let sched = allocatable(&nodes, &servers);
            let src = self.url_source().await;
            let mut by_app: HashMap<&str, Vec<Replica>> = HashMap::new();
            for r in &all {
                by_app.entry(r.app.as_str()).or_default().push(r.clone());
            }
            let res = revs.reserved(&all).await;
            for x in &apps {
                if spec_of(x).is_job() {
                    continue; // `armada job list`
                }
                let target = revs.get(&x.target_revision).await.ok();
                let pm = placement_message(target.as_ref(), &sched, &all, x, &res);
                let own = by_app.get(x.name.as_str()).cloned().unwrap_or_default();
                let st = self.app_status_proto(x, &own, &mut revs, pm, &src).await;
                resp.apps.push(st);
            }
        }
        let relays = self.site_relays(&nodes);
        let now = self.now();
        let lost = nanos(self.0.node_lost_timeout);
        for n in &nodes {
            let state = if node_lost(n, &now, lost) {
                NODE_STATE_LOST.to_string()
            } else {
                n.state.clone()
            };
            let relay = relays.get(&n.site);
            // The node's record changes only with its status; its usage
            // samples say when it was last heard, every few seconds.
            let mut last_seen = n.last_seen.clone();
            let mut runtime = None;
            if let Some(sample) = self.0.usage.node(&n.id, &now) {
                if sample.at.after(&last_seen) {
                    last_seen = sample.at.clone();
                }
                runtime = sample.runtime;
            }
            resp.nodes.push(NodeStatus {
                id: n.id.clone(),
                private_ip: n.private_ip.clone(),
                state,
                cpu_millis: n.cpu_millis,
                memory_bytes: n.memory_bytes,
                cordoned: n.cordoned,
                version: n.version.clone(),
                labels: n.all_labels(),
                restricted: n.restricted,
                replicas: per_node.get(n.id.as_str()).copied().unwrap_or(0),
                site: n.site.clone(),
                endpoint: n.endpoint.clone(),
                behind_nat: n.behind_nat,
                relay: relay.is_some_and(|r| *r == n.id && !r.is_empty()),
                relay_pinned: n.relay,
                last_seen: optional_time(&last_seen),
                cert_expires_at: optional_time(&n.cert_not_after),
                runtime,
            });
        }
        if !a.acc.admin() {
            // Nodes are the cluster's, not a space's.
            resp.nodes.clear();
        }
        Ok(resp)
    }

    /// appStatus: Status for one app.
    async fn app_status(&self, a: &Auth, name: &str) -> Result<StatusResponse, Status> {
        a.acc.app(name)?;
        let x = self
            .store()
            .get_app(name)
            .await
            .map_err(|e| store_err(&e))?;
        if spec_of(&x).is_job() {
            return Err(Status::new(
                Code::FailedPrecondition,
                format!("{} is a job; see `armada run list {}`", x.name, x.name),
            ));
        }
        let nodes = self.store().list_nodes().await.map_err(|e| store_err(&e))?;
        let own = self
            .store()
            .list_replicas(&ReplicaFilter {
                app: x.name.clone(),
                ..Default::default()
            })
            .await
            .map_err(|e| store_err(&e))?;
        let mut revs = Revisions::new(self);
        revs.preload(std::slice::from_ref(&x), &own).await;
        let target = revs.get(&x.target_revision).await.ok();
        let (mut sched, mut all) = (nodes.clone(), own.clone());
        if placement_needs_cluster(target.as_ref(), &nodes, &own, &x) {
            all = self
                .store()
                .list_replicas(&ReplicaFilter::default())
                .await
                .map_err(|e| store_err(&e))?;
            let servers = self
                .store()
                .list_servers()
                .await
                .map_err(|e| store_err(&e))?;
            sched = allocatable(&nodes, &servers);
        }
        let res = revs.reserved(&all).await;
        let pm = placement_message(target.as_ref(), &sched, &all, &x, &res);
        let src = self.app_url_source(&x).await;
        let st = self.app_status_proto(&x, &own, &mut revs, pm, &src).await;
        Ok(StatusResponse {
            apps: vec![st],
            nodes: Vec::new(),
        })
    }

    /// appStatusProto: app with its replicas.
    async fn app_status_proto(
        &self,
        x: &App,
        reps: &[Replica],
        revs: &mut Revisions<'_>,
        placement: String,
        src: &UrlSources,
    ) -> AppStatus {
        let sp = spec_of(x);
        let mut st = AppStatus {
            name: x.name.clone(),
            image: sp.image.clone(),
            active_revision: x.active_revision.clone(),
            desired_replicas: x.replicas as i32,
            ingress: ingress_type(sp),
            urls: app_urls(x, src),
            target_revision: x.target_revision.clone(),
            rollout_state: x.rollout_state.clone(),
            rollout_message: x.rollout_message.clone(),
            placement_message: placement,
            ..Default::default()
        };
        if let Some(i) = &sp.ingress {
            st.ip_allow = ip_rules(&i.ip_allow);
            st.ip_deny = ip_rules(&i.ip_deny);
        }
        if !x.rolling() {
            let shares = traffic_shares(x.replicas, &x.traffic);
            let mut total = 0;
            for (i, t) in x.traffic.iter().enumerate() {
                st.traffic.push(TrafficTarget {
                    revision: t.revision.clone(),
                    weight: t.weight as i32,
                    label: t.label.clone(),
                    urls: self.label_urls(x, &t.label).await,
                    replicas: shares[i] as i32,
                });
                total += shares[i];
            }
            if total > 0 {
                st.desired_replicas = total as i32;
            }
        }
        if sp.autoscaled() {
            let mut a = self.autoscale_status(&x.name).unwrap_or_else(|| {
                let (lo, hi) = sp.scale_bounds();
                Autoscale {
                    min: lo as i32,
                    max: hi as i32,
                    message: "waiting for the first evaluation".to_string(),
                    ..Default::default()
                }
            });
            a.last_scaled_at = optional_time(&x.scaled_at);
            st.autoscale = Some(a);
        }
        for r in reps {
            let mut rs = ReplicaStatus {
                id: r.id.clone(),
                revision: r.revision.clone(),
                node_id: r.node_id.clone(),
                state: r.state.clone(),
                message: r.message.clone(),
                address: r.address.clone(),
                updated_at: Some(timestamp(&r.updated_at)),
                ready: r.ready,
                draining: r.draining(),
                restarts: r.restarts.min(i64::from(i32::MAX)) as i32,
                last_restart: r.last_restart.clone(),
                created_at: optional_time(&r.created_at),
                last_restart_at: optional_time(&r.last_restart_at),
                ..Default::default()
            };
            if let Ok(rev) = revs.get(&r.revision).await {
                let (c, i) = spec_containers(rev.spec());
                rs.containers = c;
                rs.init_containers = i;
            }
            st.replicas.push(rs);
        }
        st
    }

    /// siteRelays: each site's relay between nodes behind NAT (ADR 0050).
    pub(crate) fn site_relays(&self, nodes: &[Node]) -> BTreeMap<String, String> {
        if !nodes.iter().any(|n| n.behind_nat && !n.subnet.is_empty()) {
            return BTreeMap::new();
        }
        let mut out: BTreeMap<String, String> = BTreeMap::new();
        let mut best: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut pinned: BTreeSet<String> = BTreeSet::new();
        let now = self.now();
        let lost = nanos(self.0.node_lost_timeout);
        for n in nodes {
            let candidate = !n.subnet.is_empty()
                && !n.network_key.is_empty()
                && !n.endpoint.is_empty()
                && !n.behind_nat
                && !n.cordoned
                && n.state == armada_store::NODE_READY
                && !node_lost(n, &now, lost);
            if !candidate {
                continue;
            }
            let h = ring::digest::digest(
                &ring::digest::SHA256,
                format!("{}\x00{}", n.site, n.id).as_bytes(),
            );
            let h = h.as_ref().to_vec();
            let is_pinned = pinned.contains(&n.site);
            if n.relay && (!is_pinned || n.id < *out.get(&n.site).unwrap_or(&String::new())) {
                out.insert(n.site.clone(), n.id.clone());
                pinned.insert(n.site.clone());
            } else if is_pinned {
            } else if best.get(&n.site).is_none_or(|b| h > *b) {
                out.insert(n.site.clone(), n.id.clone());
                best.insert(n.site.clone(), h);
            }
        }
        out
    }
}

//! Obtaining and renewing certificates with ACME (Go's internal/certs
//! ACME manager on certmagic, ADR 0055 pull request 14): [`Acme`]
//! implements [`Certs`] the way certmagic does for Armada's options, so a
//! Go server and a Rust server share one ACME account, obtain and renew
//! each other's certificates, answer each other's HTTP-01 challenges, and
//! wait for each other's locks, all in certmagic's storage in etcd
//! ([`EtcdStorage`]).
//!
//! What it keeps of certmagic: the account per CA and email
//! (`acme/<CA>/users/<email>/...`, registered once under the
//! `register_acme_account_<email>` lock), certificates under
//! `certificates/<CA>/<name>/` with their `.json` metadata (the ACME
//! certificate's URL, CA, account, and renewal information), the
//! `issue_cert_<name>` lock held through every try of an obtain or a
//! renewal, HTTP-01 challenges written to storage
//! (`acme/<CA>/challenge_tokens/<name>.json`) so whichever server leads
//! answers them on the responder the proxies forward
//! `/.well-known/acme-challenge/` to, DNS-01 through Cloudflare with one
//! provider per credentials (an app's own token for its custom domains,
//! the cluster's for the root domain, the names under it, and wildcards;
//! every other name HTTP-01), new P-256 keys for every certificate, the
//! renewal checks (ARI first, then a third of the lifetime left, then the
//! emergency windows) every 10 minutes with ARI updated under the
//! `ari_<ID>` lock, retries with certmagic's backoff for up to 30 days,
//! and its internal rate limit (10 orders per 10 seconds per CA and
//! account). OCSP stapling is left out: the proxies get the chain and the
//! key only (`load_bundle`).

pub mod cloudflare;
pub mod dns;
mod issue;
pub mod keys;
pub mod protocol;
pub mod responder;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use armada_node::http::{Client as HttpClient, Proxy};
use tokio::sync::watch;
use tonic::codegen::async_trait;

use crate::certs::{Certs, Dns, EtcdStorage, issuer_key, load_bundle};
use crate::log::Logger;
use protocol::{Challenge, Fail, Leaf, RenewalInfo};

/// Let's Encrypt's directories (certmagic's constants).
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// DefaultRenewCheckInterval.
pub const DEFAULT_RENEW_CHECK_INTERVAL: Duration = Duration::from_secs(600);

/// Unpadded base64url.
pub fn b64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        s.push(A[(n >> 18) as usize & 63] as char);
        s.push(A[(n >> 12) as usize & 63] as char);
        if c.len() > 1 {
            s.push(A[(n >> 6) as usize & 63] as char);
        }
        if c.len() > 2 {
            s.push(A[n as usize & 63] as char);
        }
    }
    s
}

/// acmeDirectory: --acme-ca (or the cluster's ACME CA) as a directory URL.
pub fn directory(v: &str) -> Result<String, String> {
    match v {
        "letsencrypt" => return Ok(LETS_ENCRYPT.to_string()),
        "letsencrypt-staging" => return Ok(LETS_ENCRYPT_STAGING.to_string()),
        _ => {}
    }
    crate::check_acme_ca(v).map(|_| v.to_string()).map_err(|_| {
        "--acme-ca must be letsencrypt, letsencrypt-staging, or an https:// URL".to_string()
    })
}

/// What the manager tells its caller (certmagic's cert_obtained and
/// cert_failed events, which Go's Options.OnObtained and OnFailed hear).
#[derive(Clone, Debug)]
pub enum Event {
    Obtained {
        name: String,
        renewal: bool,
    },
    Failed {
        name: String,
        renewal: bool,
        error: String,
    },
}

/// The manager's options (certs.Options and what Go's daemon sets).
#[derive(Clone)]
pub struct Options {
    pub storage: Arc<EtcdStorage>,
    /// The directory URL.
    pub ca: String,
    pub email: String,
    /// The cluster's DNS provider credentials (DNS-01 for wildcards, the
    /// root domain, and the names under it).
    pub dns: Option<Dns>,
    /// Providers for credentials Manage is given for a name (Go's
    /// NewProvider, which the daemon always sets).
    pub named_dns: bool,
    pub on_event: Option<Arc<dyn Fn(Event) + Send + Sync>>,
    pub log: Logger,
    /// Tests only: Cloudflare's API address, the resolvers DNS-01 asks
    /// (DNSManager.Resolvers: then no authoritative nameservers are
    /// looked up), and how often renewals are checked.
    pub cloudflare_api: String,
    pub resolvers: Vec<String>,
    pub renew_check_interval: Duration,
}

impl Options {
    pub fn new(storage: Arc<EtcdStorage>, ca: &str) -> Options {
        Options {
            storage,
            ca: ca.to_string(),
            email: String::new(),
            dns: None,
            named_dns: true,
            on_event: None,
            log: Logger::discard(),
            cloudflare_api: cloudflare::API.to_string(),
            resolvers: Vec::new(),
            renew_check_interval: DEFAULT_RENEW_CHECK_INTERVAL,
        }
    }
}

/// Cancellation of a name's work (the context Go's Manage cancels when a
/// name is dropped, or Close).
#[derive(Clone)]
pub(crate) struct Cancel(watch::Receiver<bool>);

impl Cancel {
    pub(crate) fn never() -> Cancel {
        let (tx, rx) = watch::channel(false);
        std::mem::forget(tx);
        Cancel(rx)
    }

    pub(crate) fn is(&self) -> bool {
        *self.0.borrow()
    }

    /// Resolves once cancelled.
    pub(crate) async fn done(&self) {
        let mut rx = self.0.clone();
        while !*rx.borrow_and_update() {
            if rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }

    pub(crate) fn check(&self) -> Result<(), Fail> {
        if self.is() {
            Err(Fail::new("context canceled"))
        } else {
            Ok(())
        }
    }

    pub(crate) async fn sleep(&self, d: Duration) -> Result<(), Fail> {
        tokio::select! {
            _ = tokio::time::sleep(d) => Ok(()),
            _ = self.done() => Err(Fail::new("context canceled")),
        }
    }
}

/// How a name's challenges are solved: HTTP-01 through storage, or
/// DNS-01 with a provider (a certmagic Config with its issuer).
pub(crate) enum Solver {
    Http,
    Dns(issue::DnsSolver),
}

/// Which credentials a certificate is obtained with: VIA_HTTP for
/// HTTP-01, VIA_ROOT for the cluster's DNS provider, else a Dns::key.
const VIA_HTTP: &str = "";
const VIA_ROOT: &str = "root";

#[derive(Default)]
struct Named {
    keys: HashMap<String, String>,
    solvers: HashMap<String, Arc<Solver>>,
}

/// A certificate certmagic's cache holds: its names, leaf, renewal
/// information, and the issuer whose storage holds it.
#[derive(Clone)]
pub(crate) struct Cached {
    pub names: Vec<String>,
    pub leaf: Leaf,
    pub ari: RenewalInfo,
    pub issuer: String,
}

/// renewalBackoffState.
struct Backoff {
    next: Instant,
    idx: Option<usize>,
    first: Instant,
}

pub(crate) struct Inner {
    pub(crate) storage: Arc<EtcdStorage>,
    pub(crate) ca: String,
    pub(crate) issuer: String,
    pub(crate) http: Arc<HttpClient>,
    opts_email: String,
    /// The email PreCheck settled on (setEmail).
    pub(crate) email: Mutex<Option<String>>,
    root_solver: Option<Arc<Solver>>,
    http_solver: Arc<Solver>,
    named: RwLock<Arc<Named>>,
    root: RwLock<String>,
    named_dns: bool,
    cloudflare_api: String,
    pub(crate) resolvers: Vec<String>,
    pub(crate) interval: Duration,
    pub(crate) log: Logger,
    on_event: Option<Arc<dyn Fn(Event) + Send + Sync>>,
    /// Manage's names: each one's cancel and the challenge it uses.
    managed: tokio::sync::Mutex<HashMap<String, (watch::Sender<bool>, String)>>,
    pub(crate) cache: Mutex<HashMap<String, Cached>>,
    /// Challenges this manager presents (certmagic's activeChallenges).
    pub(crate) active: Mutex<HashMap<String, Challenge>>,
    /// Running renewal jobs by name (jobManager's names).
    jobs: Mutex<HashSet<String>>,
    backoff: Mutex<HashMap<String, Backoff>>,
    /// The internal rate limiter's recent events per CA and email.
    pub(crate) limiter: tokio::sync::Mutex<HashMap<String, VecDeque<Instant>>>,
    stop: watch::Sender<bool>,
}

/// The ACME certificate manager.
#[derive(Clone)]
pub struct Acme(pub(crate) Arc<Inner>);

impl Acme {
    /// NewACME: nothing is requested until manage. The renewal checks
    /// start now and stop with close.
    pub fn new(opts: Options) -> Result<Acme, String> {
        if opts.ca.is_empty() {
            return Err("certs: Storage and CA are required".to_string());
        }
        let http = Arc::new(HttpClient::new(None, Proxy::from_env())?);
        let root_solver = match &opts.dns {
            None => None,
            Some(d) => Some(Arc::new(Solver::Dns(issue::DnsSolver::new(Arc::new(
                cloudflare::Provider::new(&d.token, &opts.cloudflare_api, http.clone()),
            ))))),
        };
        let (stop, _) = watch::channel(false);
        let inner = Arc::new(Inner {
            storage: opts.storage,
            issuer: issuer_key(&opts.ca),
            ca: opts.ca,
            http,
            opts_email: opts.email,
            email: Mutex::new(None),
            root_solver,
            http_solver: Arc::new(Solver::Http),
            named: RwLock::new(Arc::new(Named::default())),
            root: RwLock::new(String::new()),
            named_dns: opts.named_dns,
            cloudflare_api: opts.cloudflare_api,
            resolvers: opts.resolvers,
            interval: if opts.renew_check_interval.is_zero() {
                DEFAULT_RENEW_CHECK_INTERVAL
            } else {
                opts.renew_check_interval
            },
            log: opts.log,
            on_event: opts.on_event,
            managed: Default::default(),
            cache: Default::default(),
            active: Default::default(),
            jobs: Default::default(),
            backoff: Default::default(),
            limiter: Default::default(),
            stop,
        });
        let me = Acme(inner);
        let m = me.clone();
        let mut stop = me.0.stop.subscribe();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(m.0.interval);
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = tick.tick() => m.0.clone().renew_managed().await,
                    r = stop.changed() => if r.is_err() || *stop.borrow() { return },
                }
            }
        });
        Ok(me)
    }

    /// The storage key of this CA's certificates.
    pub fn issuer_key(&self) -> &str {
        &self.0.issuer
    }

    /// Close: stops the renewal checks and every name's work. A control
    /// plane node that loses leadership closes its manager.
    pub async fn close(&self) {
        let _ = self.0.stop.send(true);
        for (_, (c, _)) in self.0.managed.lock().await.drain() {
            let _ = c.send(true);
        }
    }

    /// The names managed now, sorted.
    pub async fn managed_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.0.managed.lock().await.keys().cloned().collect();
        v.sort();
        v
    }
}

impl Inner {
    /// via: which credentials name's certificate is obtained with.
    pub(crate) fn via(&self, name: &str) -> String {
        if let Some(k) = self
            .named
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .keys
            .get(name)
        {
            return k.clone();
        }
        if self.root_solver.is_none() {
            return VIA_HTTP.to_string();
        }
        if name.starts_with("*.") {
            return VIA_ROOT.to_string();
        }
        let root = self.root.read().unwrap_or_else(|p| p.into_inner()).clone();
        if !root.is_empty() && (name == root || name.ends_with(&format!(".{root}"))) {
            return VIA_ROOT.to_string();
        }
        VIA_HTTP.to_string()
    }

    /// config: the solver for credentials via picked.
    pub(crate) fn solver(&self, via: &str) -> Arc<Solver> {
        match via {
            VIA_HTTP => self.http_solver.clone(),
            VIA_ROOT => self
                .root_solver
                .clone()
                .unwrap_or_else(|| self.http_solver.clone()),
            k => self
                .named
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .solvers
                .get(k)
                .cloned()
                .unwrap_or_else(|| self.http_solver.clone()),
        }
    }

    /// setNamed: the names with credentials of their own, keeping the
    /// solvers of credentials still in use. A name whose provider cannot
    /// be made keeps HTTP-01 and is reported.
    fn set_named(&self, names: &[String], dns: &BTreeMap<String, Dns>) -> Result<(), String> {
        let old = self.named.read().unwrap_or_else(|p| p.into_inner()).clone();
        let mut next = Named::default();
        let mut errs = Vec::new();
        for n in names {
            let Some(d) = dns.get(n) else { continue };
            let k = d.key();
            if !next.solvers.contains_key(&k) {
                if let Some(s) = old.solvers.get(&k) {
                    next.solvers.insert(k.clone(), s.clone());
                } else if !self.named_dns {
                    errs.push(format!("{n}: no DNS providers"));
                    continue;
                } else if d.provider != "cloudflare" {
                    errs.push(format!(
                        "{n}: unsupported DNS provider {} (want cloudflare)",
                        armada_spec::go::quote(&d.provider)
                    ));
                    continue;
                } else {
                    let p = cloudflare::Provider::new(
                        &d.token,
                        &self.cloudflare_api,
                        self.http.clone(),
                    );
                    next.solvers.insert(
                        k.clone(),
                        Arc::new(Solver::Dns(issue::DnsSolver::new(Arc::new(p)))),
                    );
                }
            }
            next.keys.insert(n.clone(), k);
        }
        *self.named.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(next);
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("\n"))
        }
    }

    pub(crate) fn emit(&self, e: Event) {
        if let Some(f) = &self.on_event {
            f(e);
        }
    }

    /// The email setEmail settles on, once.
    pub(crate) fn opts_email(&self) -> &str {
        &self.opts_email
    }

    /// getConfigForCert: the solver for a cached certificate's names.
    fn solver_for(&self, names: &[String]) -> Arc<Solver> {
        for n in names {
            let v = self.via(n);
            if v != VIA_HTTP {
                return self.solver(&v);
            }
        }
        self.http_solver.clone()
    }

    /// RenewManagedCertificates: one round of the renewal checks.
    async fn renew_managed(self: Arc<Self>) {
        let certs: Vec<Cached> = self
            .cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .cloned()
            .collect();
        let now = armada_store::gojson::now();
        let mut renew = Vec::new();
        let mut ari_queue = Vec::new();
        for cert in certs {
            if cert.ari.needs_refresh(&now) {
                ari_queue.push(cert.clone());
            }
            if issue::needs_renewal(&cert.leaf, Some(&cert.ari), self.interval) {
                match self.stored_needs_renewal(&cert.names[0]).await {
                    Err(e) => self.log.warn(
                        "error while checking if stored certificate is also expiring soon",
                        &[("identifiers", cert.names.join(",")), ("err", e)],
                    ),
                    Ok(false) => {
                        // Renewed in storage already: reload it.
                        let _ = self.reload(&cert.names[0]).await;
                        continue;
                    }
                    Ok(true) => {}
                }
                if !renew.iter().any(|c: &Cached| c.names == cert.names) {
                    renew.push(cert);
                }
            }
        }
        for cert in ari_queue {
            match self.update_ari(&cert).await {
                Err(e) => self.log.error("updating ARI", &[("err", e)]),
                Ok((updated, changed)) => {
                    if changed
                        && issue::needs_renewal(&updated.leaf, Some(&updated.ari), self.interval)
                        && !renew.iter().any(|c: &Cached| c.names == updated.names)
                    {
                        renew.push(updated);
                    }
                }
            }
        }
        for cert in renew {
            self.clone().queue_renewal(cert);
        }
    }

    /// queueRenewalTask: one renewal try, backed off after failures.
    fn queue_renewal(self: Arc<Self>, cert: Cached) {
        let name = cert.names[0].clone();
        let job = format!("renew_{name}");
        {
            let b = self.backoff.lock().unwrap_or_else(|p| p.into_inner());
            if b.get(&job).is_some_and(|s| Instant::now() < s.next) {
                return;
            }
        }
        if !self
            .jobs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(job.clone())
        {
            return;
        }
        tokio::spawn(async move {
            let solver = self.solver_for(&cert.names);
            let r = self
                .renew_cert(&name, false, false, &solver, &Cancel::never())
                .await;
            match r {
                Err(e) => {
                    self.record_failure(&job);
                    self.log.error(
                        "job failed",
                        &[("err", format!("[{}] {}", cert.names.join(" "), e.msg))],
                    );
                }
                Ok(()) => {
                    self.backoff
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .remove(&job);
                    let _ = self.reload(&name).await;
                }
            }
            self.jobs
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&job);
        });
    }

    /// renewalBackoff.recordFailure.
    fn record_failure(&self, job: &str) {
        let now = Instant::now();
        let mut b = self.backoff.lock().unwrap_or_else(|p| p.into_inner());
        let st = b.entry(job.to_string()).or_insert(Backoff {
            next: now,
            idx: None,
            first: now,
        });
        if now.duration_since(st.first) >= issue::MAX_RETRY_DURATION {
            b.remove(job);
            return;
        }
        let idx = match st.idx {
            None => 0,
            Some(i) if i + 1 < issue::RETRY_INTERVALS.len() => i + 1,
            Some(i) => i,
        };
        st.idx = Some(idx);
        st.next = now + issue::RETRY_INTERVALS[idx];
    }

    /// manageOne: a name's certificate from storage (renewed when due), or
    /// obtained when storage has none.
    async fn manage_one(self: Arc<Self>, name: String, via: String, cancel: Cancel) {
        if self
            .cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(&name)
        {
            return;
        }
        let solver = self.solver(&via);
        match self.cache_managed(&name).await {
            Err(e) if e.is_empty() => {
                // None in storage: obtain it, with retries.
                if let Err(e) = self.obtain_cert(&name, true, &solver, &cancel).await {
                    if e.msg != "context canceled" {
                        self.log.error(
                            "job failed",
                            &[("err", format!("{name}: obtaining certificate: {}", e.msg))],
                        );
                    }
                    return;
                }
                if let Err(e) = self.cache_managed(&name).await {
                    self.log.error(
                        "job failed",
                        &[(
                            "err",
                            format!("{name}: caching certificate after obtaining it: {e}"),
                        )],
                    );
                }
            }
            Err(e) => self.log.error(
                "initiating certificate management",
                &[
                    ("subject", name.clone()),
                    ("err", format!("{name}: caching certificate: {e}")),
                ],
            ),
            Ok(mut cert) => {
                let now = armada_store::gojson::now();
                if cert.ari.needs_refresh(&now) {
                    match self.update_ari(&cert).await {
                        Ok((c, _)) => cert = c,
                        Err(e) => self.log.error("updating ARI upon managing", &[("err", e)]),
                    }
                }
                if !issue::needs_renewal(&cert.leaf, Some(&cert.ari), self.interval) {
                    return;
                }
                let job = format!("renew_{name}");
                if !self
                    .jobs
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(job.clone())
                {
                    return;
                }
                let r = self.renew_cert(&name, false, true, &solver, &cancel).await;
                match r {
                    Err(e) if e.msg != "context canceled" => self.log.error(
                        "job failed",
                        &[("err", format!("{name}: renewing certificate: {}", e.msg))],
                    ),
                    Err(_) => {}
                    Ok(()) => {
                        if let Err(e) = self.reload(&name).await {
                            self.log.error(
                                "job failed",
                                &[(
                                    "err",
                                    format!(
                                        "{name}: reloading renewed certificate into memory: {e}"
                                    ),
                                )],
                            );
                        }
                    }
                }
                self.jobs
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&job);
            }
        }
    }

    /// CacheManagedCertificate: the certificate in storage, now in the
    /// cache; Err("") when storage has none.
    async fn cache_managed(&self, name: &str) -> Result<Cached, String> {
        let res = self.load_resource(name).await?.ok_or_else(String::new)?;
        let cert = res.cached(name, &self.issuer)?;
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(name.to_string(), cert.clone());
        Ok(cert)
    }

    /// reloadManagedCertificate.
    async fn reload(&self, name: &str) -> Result<Cached, String> {
        let r = self.cache_managed(name).await;
        r.map_err(|e| {
            let e = if e.is_empty() {
                "file does not exist".to_string()
            } else {
                e
            };
            format!("loading managed certificate for [{name}] from storage: {e}")
        })
    }

    /// managedCertInStorageNeedsRenewal.
    async fn stored_needs_renewal(&self, name: &str) -> Result<bool, String> {
        let res = self
            .load_resource(name)
            .await?
            .ok_or_else(|| "file does not exist".to_string())?;
        Ok(res.needs_renewal(self.interval).2)
    }
}

#[async_trait]
impl Certs for Acme {
    async fn manage(
        &self,
        names: &[String],
        root: &str,
        dns: &BTreeMap<String, Dns>,
    ) -> Result<(), String> {
        let inner = &self.0;
        let mut managed = inner.managed.lock().await;
        let mut want = HashSet::new();
        for n in names {
            if n.starts_with("*.") && inner.root_solver.is_none() {
                return Err(format!("wildcard certificate {n} needs a DNS provider"));
            }
            want.insert(n.clone());
        }
        *inner.root.write().unwrap_or_else(|p| p.into_inner()) = root.to_string();
        let named_err = inner.set_named(names, dns);
        let current: Vec<(String, String)> = managed
            .iter()
            .map(|(n, (_, v))| (n.clone(), v.clone()))
            .collect();
        for (n, via) in current {
            // A name whose challenge changed starts over with the new one.
            if !want.contains(&n) || via != inner.via(&n) {
                if let Some((c, _)) = managed.remove(&n) {
                    let _ = c.send(true);
                }
                // Stops renewal; the certificate stays in storage.
                inner
                    .cache
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&n);
            }
        }
        for n in names {
            if managed.contains_key(n) {
                continue;
            }
            let via = inner.via(n);
            let (tx, rx) = watch::channel(false);
            managed.insert(n.clone(), (tx, via.clone()));
            // manageAll lowercases and trims each name.
            let name = n.trim().to_lowercase();
            tokio::spawn(inner.clone().manage_one(name, via, Cancel(rx)));
        }
        named_err
    }

    async fn certificate(&self, name: &str) -> Option<Vec<u8>> {
        load_bundle(&self.0.storage, &self.0.issuer, name).await
    }

    fn supports_wildcard(&self) -> bool {
        self.0.root_solver.is_some()
    }

    async fn http_challenge(&self, method: &str, host: &str, path: &str) -> Option<Vec<u8>> {
        self.0.http_challenge(method, host, path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_without_padding() {
        assert_eq!(b64url(b""), "");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn directories() {
        assert_eq!(directory("letsencrypt").unwrap(), LETS_ENCRYPT);
        assert_eq!(
            directory("letsencrypt-staging").unwrap(),
            LETS_ENCRYPT_STAGING
        );
        assert_eq!(
            directory("https://localhost:14000/dir").unwrap(),
            "https://localhost:14000/dir"
        );
        assert!(directory("http://localhost:14000/dir").is_err());
    }
}

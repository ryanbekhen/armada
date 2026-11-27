//! Obtaining and renewing one certificate (certmagic's Config.obtainCert
//! and renewCert with its ACMEIssuer, and acmez's ObtainCertificate): the
//! account, the order, the challenges with their solvers, finalization,
//! the certificate resource in storage, renewal information, and the
//! HTTP-01 answers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::cloudflare::{Provider, TxtRecord, absolute_name, relative_name};
use super::keys::EcKey;
use super::protocol::{
    Account, Authorization, CertChain, Challenge, Client, Fail, Identifier, Leaf, Order,
    RenewalInfo, go_marshal,
};
use super::{Cached, Cancel, Event, Inner, Solver, dns};
use crate::certs::{safe, site_cert, site_private_key};

/// The waits between tries, and how long tries go on.
pub(crate) const RETRY_INTERVALS: [Duration; 25] = {
    const M: u64 = 60;
    const H: u64 = 3600;
    [
        Duration::from_secs(M),
        Duration::from_secs(2 * M),
        Duration::from_secs(2 * M),
        Duration::from_secs(5 * M),
        Duration::from_secs(10 * M),
        Duration::from_secs(10 * M),
        Duration::from_secs(10 * M),
        Duration::from_secs(20 * M),
        Duration::from_secs(20 * M),
        Duration::from_secs(20 * M),
        Duration::from_secs(20 * M),
        Duration::from_secs(30 * M),
        Duration::from_secs(30 * M),
        Duration::from_secs(30 * M),
        Duration::from_secs(30 * M),
        Duration::from_secs(30 * M),
        Duration::from_secs(30 * M),
        Duration::from_secs(H),
        Duration::from_secs(H),
        Duration::from_secs(H),
        Duration::from_secs(2 * H),
        Duration::from_secs(2 * H),
        Duration::from_secs(3 * H),
        Duration::from_secs(3 * H),
        Duration::from_secs(6 * H),
    ]
};
pub(crate) const MAX_RETRY_DURATION: Duration = Duration::from_secs(30 * 24 * 3600);

/// The internal rate limit: RateLimitEvents per RateLimitEventsWindow.
const RATE_EVENTS: usize = 10;
const RATE_WINDOW: Duration = Duration::from_secs(10);

const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(120);

/// The Unix seconds of 0001-01-01T00:00:00Z, which a missing time reads
/// as.
const ZERO_UNIX: i128 = -62_135_596_800;

fn now_ns() -> i128 {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    d.as_nanos() as i128
}

fn ns(t: &armada_spec::gotime::Time) -> i128 {
    t.unix as i128 * 1_000_000_000 + t.nsec as i128
}

fn in_window(not_before: i128, not_after: i128, ratio: f64) -> bool {
    let lifetime = not_after - not_before;
    let window = (lifetime as f64 * ratio) as i128;
    now_ns() > not_after - window
}

/// ARI's selected time first (and an emergency window
/// of a twentieth of the lifetime), then a third of the lifetime left,
/// then a fiftieth or less than five renewal checks.
pub(crate) fn needs_renewal(leaf: &Leaf, ari: Option<&RenewalInfo>, interval: Duration) -> bool {
    let interval = interval.as_nanos() as i128;
    let not_before = leaf.not_before as i128 * 1_000_000_000;
    let expires = leaf.expires() as i128 * 1_000_000_000;
    if let Some(ari) = ari {
        let selected = ari.selected.clone().or_else(|| {
            let (s, e) = (ari.start.as_ref()?, ari.end.as_ref()?);
            let (start, end) = (s.unix + 1, e.unix);
            Some(armada_spec::gotime::Time {
                unix: super::protocol::random_below((end - start).max(1) as u64) as i64 + start,
                nsec: 0,
                loc: armada_spec::gotime::Location::utc(),
            })
        });
        if selected.is_some() {
            // certmagic takes the cutoff from the stored selected time,
            // not the one it improvised: with no time stored the cutoff
            // is the zero time, so a window alone renews at once.
            let base = ari
                .selected
                .as_ref()
                .map(ns)
                .unwrap_or(ZERO_UNIX * 1_000_000_000);
            if now_ns() > base - interval {
                return true;
            }
            if in_window(not_before, expires, 1.0 / 20.0) {
                return true;
            }
        }
    }
    if in_window(not_before, expires, 1.0 / 3.0) {
        return true;
    }
    in_window(not_before, expires, 1.0 / 50.0) || expires - now_ns() < interval * 5
}

/// A certificate resource in storage (CertificateResource).
/// The key is read (a resource without one is missing) but not kept:
/// every certificate gets a new key.
pub(crate) struct Resource {
    pub cert_pem: Vec<u8>,
    pub issuer_data: Value,
}

impl Resource {
    fn acme(&self) -> CertChain {
        CertChain::from_metadata(&self.issuer_data)
    }

    /// (left in ns, the leaf, whether due).
    pub(crate) fn needs_renewal(&self, interval: Duration) -> (i128, Option<Leaf>, bool) {
        match Leaf::from_bundle(&self.cert_pem) {
            Err(_) => (0, None, true),
            Ok(leaf) => {
                let ari = self.acme().renewal_info;
                let left = leaf.expires() as i128 * 1_000_000_000 - now_ns();
                let due = needs_renewal(&leaf, ari.as_ref(), interval);
                (left, Some(leaf), due)
            }
        }
    }

    pub(crate) fn cached(&self, name: &str, issuer: &str) -> Result<Cached, String> {
        let leaf = Leaf::from_bundle(&self.cert_pem)?;
        let mut names = leaf.dns_names.clone();
        if names.is_empty() {
            names.push(name.to_string());
        }
        Ok(Cached {
            names,
            leaf,
            ari: self.acme().renewal_info.unwrap_or_default(),
            issuer: issuer.to_string(),
        })
    }
}

/// A certificate's metadata (its names and the issuer's data) as JSON
/// indented by tabs.
fn resource_json(sans: &[String], issuer_data: &str) -> Vec<u8> {
    let mut compact = String::from("{");
    if !sans.is_empty() {
        compact.push_str(r#""sans":"#);
        compact.push_str(&String::from_utf8_lossy(&go_marshal(sans)));
    }
    if !issuer_data.is_empty() {
        if compact.len() > 1 {
            compact.push(',');
        }
        compact.push_str(r#""issuer_data":"#);
        compact.push_str(issuer_data);
    }
    compact.push('}');
    go_indent_bytes(compact.as_bytes())
}

/// Compact JSON indented by tabs.
pub(crate) fn go_indent_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len() * 2);
    let mut depth = 0usize;
    let mut in_str = false;
    let mut esc = false;
    let mut i = 0;
    let nl = |out: &mut Vec<u8>, d: usize| {
        out.push(b'\n');
        out.extend(std::iter::repeat_n(b'\t', d));
    };
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c);
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' => {
                in_str = true;
                out.push(c);
            }
            b'{' | b'[' => {
                out.push(c);
                let close = if c == b'{' { b'}' } else { b']' };
                if b.get(i + 1) == Some(&close) {
                    out.push(close);
                    i += 2;
                    continue;
                }
                depth += 1;
                nl(&mut out, depth);
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                nl(&mut out, depth);
                out.push(c);
            }
            b',' => {
                out.push(c);
                nl(&mut out, depth);
            }
            b':' => out.extend_from_slice(b": "),
            b' ' | b'\t' | b'\n' | b'\r' => {}
            _ => out.push(c),
        }
        i += 1;
    }
    out
}

/// StorageKeys.SiteMeta.
fn site_meta(issuer: &str, name: &str) -> String {
    let n = safe(name);
    format!("certificates/{}/{n}/{n}.json", safe(issuer))
}

fn ca_prefix(issuer: &str) -> String {
    format!("acme/{}", safe(issuer))
}

fn email_username(email: &str) -> &str {
    match email.find('@') {
        None => email,
        Some(0) => &email[1..],
        Some(i) => &email[..i],
    }
}

fn user_key(issuer: &str, email: &str, default_name: &str, ext: &str) -> String {
    let email = if email.is_empty() { "default" } else { email }.to_lowercase();
    let mut file = email_username(&email).to_string();
    if file.is_empty() {
        file = default_name.to_string();
    }
    format!(
        "{}/users/{}/{}{ext}",
        ca_prefix(issuer),
        safe(&email),
        safe(&file)
    )
}

fn primary_contact(a: &Account) -> String {
    match a.contact.first() {
        None => String::new(),
        Some(c) => match c.find(':') {
            Some(i) => c[i + 1..].to_string(),
            None => c.clone(),
        },
    }
}

/// SubjectQualifiesForPublicCert.
fn qualifies_for_public_cert(s: &str) -> bool {
    let qualifies = !s.trim().is_empty()
        && !s.starts_with('.')
        && !s.ends_with('.')
        && (!s.contains('*') || s.starts_with("*.") || s == "*")
        && !s.contains(|c: char| "()[]{}<> \t\n\"\\!@#$%^&|;'+=".contains(c));
    let host = s.trim_end_matches('.').to_lowercase();
    let internal_ip = host.parse::<std::net::IpAddr>().is_ok_and(|ip| match ip {
        std::net::IpAddr::V4(v) => {
            v.is_loopback()
                || (v.octets()[0] == 0 && v.octets()[1] == 0)
                || v.is_private()
                || v.is_link_local()
        }
        std::net::IpAddr::V6(v) => {
            let s0 = v.segments()[0];
            v.is_loopback()
                || (s0 & 0xfe00) == 0
                || (s0 & 0xffc0) == 0xfe80
                || (s0 & 0xfe00) == 0xfc00
        }
    });
    let internal = host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".home.arpa")
        || internal_ip;
    qualifies
        && !internal
        && (!s.contains('*')
            || (s.matches('*').count() == 1
                && s.matches('.').count() > 1
                && s.len() > 2
                && s.starts_with("*.")))
}

/// The DNS-01 solver: DNS01Solver with a Cloudflare provider, its
/// records remembered per name.
pub(crate) struct DnsSolver {
    provider: Arc<Provider>,
    memory: Mutex<HashMap<String, Vec<(String, TxtRecord)>>>,
}

impl DnsSolver {
    pub(crate) fn new(provider: Arc<Provider>) -> DnsSolver {
        DnsSolver {
            provider,
            memory: Mutex::default(),
        }
    }

    fn recall(&self, dns_name: &str, value: &str) -> Result<(String, TxtRecord), Fail> {
        self.memory
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(dns_name)
            .and_then(|v| v.iter().find(|(_, r)| r.text == value).cloned())
            .ok_or_else(|| {
                Fail::new(format!(
                    "no memory of presenting a DNS record for {} (usually OK if presenting also failed)",
                    armada_spec::go::quote(dns_name)
                ))
            })
    }

    async fn present(&self, inner: &Inner, chal: &Challenge) -> Result<(), Fail> {
        let dns_name = format!("_acme-challenge.{}", chal.identifier.value);
        let value = chal.dns01_key_authorization();
        let servers = dns::recursive_nameservers(&inner.resolvers);
        let zone = dns::find_zone(&dns_name, &servers).await.map_err(|e| {
            Fail::new(format!(
                "could not determine zone for domain {}: {e}",
                armada_spec::go::quote(&dns_name)
            ))
        })?;
        let rel = relative_name(&format!("{dns_name}."), &zone);
        let rec = self
            .provider
            .append_txt(&zone, &rel, &value)
            .await
            .map_err(|e| {
                Fail::new(format!(
                    "adding temporary record for zone {}: {e}",
                    armada_spec::go::quote(&zone)
                ))
            })?;
        self.memory
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(dns_name)
            .or_default()
            .push((zone, rec));
        Ok(())
    }

    /// Wait: until the zone's nameservers (or the given resolvers) answer
    /// the record, checked every 2 seconds for 2 minutes.
    async fn wait(&self, inner: &Inner, chal: &Challenge, cancel: &Cancel) -> Result<(), Fail> {
        let dns_name = format!("_acme-challenge.{}", chal.identifier.value);
        let (zone, rec) = self.recall(&dns_name, &chal.dns01_key_authorization())?;
        let authoritative = inner.resolvers.is_empty();
        let resolvers = dns::recursive_nameservers(&inner.resolvers);
        let abs = absolute_name(&rec.name, &zone);
        let start = Instant::now();
        let mut last: Option<String> = None;
        while start.elapsed() < PROPAGATION_TIMEOUT {
            cancel.sleep(Duration::from_secs(2)).await?;
            match dns::check_propagation(&abs, &rec.text, authoritative, &resolvers).await {
                Ok(true) => return Ok(()),
                Ok(false) => last = None,
                Err(e) => {
                    return Err(Fail::new(format!(
                        "checking DNS propagation of {} (relative={} zone={zone} resolvers=[{}]): {e}",
                        armada_spec::go::quote(&abs),
                        rec.name,
                        resolvers.join(" ")
                    )));
                }
            }
        }
        Err(Fail::new(format!(
            "timed out waiting for record to fully propagate; verify DNS provider configuration is correct - last error: {}",
            last.unwrap_or_else(|| "<nil>".to_string())
        )))
    }

    async fn cleanup(&self, chal: &Challenge) -> Result<(), Fail> {
        let dns_name = format!("_acme-challenge.{}", chal.identifier.value);
        let value = chal.dns01_key_authorization();
        let found = self.recall(&dns_name, &value);
        {
            let mut m = self.memory.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(v) = m.get_mut(&dns_name)
                && let Some(i) = v.iter().position(|(_, r)| r.text == value)
            {
                v.remove(i);
            }
        }
        let (zone, rec) = found?;
        let del = self.provider.delete_txt(&zone, &rec);
        match tokio::time::timeout(PROPAGATION_TIMEOUT, del).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(Fail::new(format!(
                "deleting temporary record for name {} in zone {}: {e}",
                armada_spec::go::quote(&zone),
                armada_spec::go::quote(&rec.name)
            ))),
            Err(_) => Err(Fail::new("context deadline exceeded")),
        }
    }
}

/// An authorization being solved (acmez's authzState).
struct AuthzState {
    authz: Authorization,
    /// The challenge presented, until cleaned up.
    current: Option<Challenge>,
}

impl Inner {
    /// distributedSolver.challengeTokensKey.
    fn token_key(&self, identifier: &str) -> String {
        format!(
            "{}/challenge_tokens/{}.json",
            ca_prefix(&self.issuer),
            safe(identifier)
        )
    }

    /// solverWrapper.Present with the config's solver.
    async fn present(&self, solver: &Solver, chal: &Challenge) -> Result<(), Fail> {
        self.active
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(chal.identifier.value.clone(), chal.clone());
        match solver {
            Solver::Http => {
                // The challenge in storage, so whichever
                // control plane node leads answers it.
                let b = go_marshal(chal);
                self.storage
                    .store(&self.token_key(&chal.identifier.value), &b)
                    .await
                    .map_err(|e| Fail::new(e.to_string()))
            }
            Solver::Dns(d) => d.present(self, chal).await,
        }
    }

    async fn wait(&self, solver: &Solver, chal: &Challenge, cancel: &Cancel) -> Result<(), Fail> {
        match solver {
            Solver::Http => Ok(()),
            Solver::Dns(d) => d.wait(self, chal, cancel).await,
        }
    }

    /// solverWrapper.CleanUp, which ignores the caller's cancellation.
    async fn cleanup(&self, solver: &Solver, chal: &Challenge) {
        self.active
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&chal.identifier.value);
        let r = match solver {
            Solver::Http => self
                .storage
                .delete(&self.token_key(&chal.identifier.value))
                .await
                .map_err(|e| Fail::new(e.to_string())),
            Solver::Dns(d) => d.cleanup(chal).await,
        };
        if let Err(e) = r {
            self.log.error(
                "cleaning up solver",
                &[
                    ("identifier", chal.identifier.value.clone()),
                    ("challenge_type", chal.typ.clone()),
                    ("err", e.msg),
                ],
            );
        }
    }

    /// The HTTP-01 answer for a request (HTTPChallengeHandler): a
    /// challenge this manager presents for the host, else one in storage
    /// (distributed solving), answered only on its own path and host.
    pub(crate) async fn http_challenge(
        &self,
        method: &str,
        host: &str,
        path: &str,
    ) -> Option<Vec<u8>> {
        if method != "GET" || !path.starts_with("/.well-known/acme-challenge/") {
            return None;
        }
        let host = host_only(host);
        let mem = self
            .active
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&host)
            .cloned();
        let chal = match mem {
            Some(c) => c,
            None => {
                let b = self.storage.load(&self.token_key(&host)).await.ok()??;
                if b.is_empty() {
                    return None;
                }
                serde_json::from_slice::<Challenge>(&b).ok()?
            }
        };
        if path == format!("/.well-known/acme-challenge/{}", chal.token)
            && host.eq_ignore_ascii_case(&chal.identifier.value)
        {
            return Some(chal.key_authorization.into_bytes());
        }
        None
    }

    /// A random value written, read back, and deleted.
    async fn check_storage(&self) -> Result<(), String> {
        let key = format!("rw_test_{}", super::protocol::random_below(i64::MAX as u64));
        let mut contents = vec![0u8; 10 * 1024];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut contents)
            .map_err(|_| "random".to_string())?;
        self.storage
            .store(&key, &contents)
            .await
            .map_err(|e| e.to_string())?;
        let loaded = self.storage.load(&key).await;
        let del = self.storage.delete(&key).await;
        let loaded = loaded
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "file does not exist".to_string())?;
        if loaded != contents {
            return Err(format!(
                "load yielded different value than was stored; expected {} bytes, got {} bytes of differing elements",
                contents.len(),
                loaded.len()
            ));
        }
        del.map_err(|e| e.to_string())
    }

    async fn has_resources(&self, name: &str) -> bool {
        self.storage.exists(&site_cert(&self.issuer, name)).await
            && self
                .storage
                .exists(&site_private_key(&self.issuer, name))
                .await
            && self.storage.exists(&site_meta(&self.issuer, name)).await
    }

    /// None when a part is missing.
    pub(crate) async fn load_resource(&self, name: &str) -> Result<Option<Resource>, String> {
        let load =
            |k: String| async move { self.storage.load(&k).await.map_err(|e| e.to_string()) };
        let Some(key) = load(site_private_key(&self.issuer, name)).await? else {
            return Ok(None);
        };
        drop(armada_pki::SecretBytes::new(key));
        let Some(cert) = load(site_cert(&self.issuer, name)).await? else {
            return Ok(None);
        };
        let Some(meta) = load(site_meta(&self.issuer, name)).await? else {
            return Ok(None);
        };
        let v: Value = serde_json::from_slice(&meta)
            .map_err(|e| format!("decoding certificate metadata: {e}"))?;
        Ok(Some(Resource {
            cert_pem: cert,
            issuer_data: v.get("issuer_data").cloned().unwrap_or(Value::Null),
        }))
    }

    /// Key, certificate, then metadata, all or none.
    async fn save_resource(
        &self,
        name: &str,
        cert_pem: &[u8],
        key_pem: &[u8],
        meta: &str,
    ) -> Result<(), String> {
        let all = [
            (site_private_key(&self.issuer, name), key_pem.to_vec()),
            (site_cert(&self.issuer, name), cert_pem.to_vec()),
            (
                site_meta(&self.issuer, name),
                resource_json(&[name.to_string()], meta),
            ),
        ];
        store_all(&self.storage, &all).await
    }

    /// The configured email, else the most recent account's in
    /// storage, lowercased.
    async fn set_email(&self) -> String {
        if let Some(e) = self.email.lock().unwrap_or_else(|p| p.into_inner()).clone() {
            return e;
        }
        let mut email = self.opts_email().to_string();
        if email.is_empty() {
            email = self.most_recent_account_email().await.unwrap_or_default();
        }
        let email = email.trim().to_lowercase();
        *self.email.lock().unwrap_or_else(|p| p.into_inner()) = Some(email.clone());
        email
    }

    async fn most_recent_account_email(&self) -> Option<String> {
        let users = format!("{}/users", ca_prefix(&self.issuer));
        let list = self.storage.list(&users, false).await.ok()??;
        let mut dirs = Vec::new();
        for u in list {
            if let Ok(Some(info)) = self.storage.stat(&u).await
                && !info.terminal
            {
                dirs.push((u, info.modified));
            }
        }
        // Newest first; certmagic's directories carry no time, so the
        // listing's order stands.
        dirs.sort_by_key(|a| std::cmp::Reverse(a.1));
        let (first, _) = dirs.first()?;
        let base = first.rsplit('/').next().unwrap_or(first);
        let acct = self.load_or_create_account(base).await.ok()?;
        Some(primary_contact(&acct))
    }

    /// None when it is not in storage.
    async fn load_account(&self, email: &str) -> Result<Option<Account>, String> {
        let reg = self
            .storage
            .load(&user_key(&self.issuer, email, "registration", ".json"))
            .await
            .map_err(|e| e.to_string())?;
        let Some(reg) = reg else { return Ok(None) };
        let key = self
            .storage
            .load(&user_key(&self.issuer, email, "private", ".key"))
            .await
            .map_err(|e| e.to_string())?;
        let Some(key) = key else { return Ok(None) };
        let key = armada_pki::SecretBytes::new(key);
        let v: Value = serde_json::from_slice(&reg).map_err(|e| e.to_string())?;
        let mut a = Account::default();
        a.merge(&v);
        let k = EcKey::from_pem(key.expose())
            .map_err(|e| format!("could not decode account's private key: {e}"))?;
        a.key = Some(Arc::new(k));
        Ok(Some(a))
    }

    /// The stored account, or a new one with a new
    /// P-256 key (status empty until registered).
    async fn load_or_create_account(&self, email: &str) -> Result<Account, String> {
        if let Some(a) = self.load_account(email).await? {
            return Ok(a);
        }
        let mut a = Account::default();
        if !email.is_empty() {
            a.contact = vec![format!("mailto:{email}")];
        }
        a.key = Some(Arc::new(
            EcKey::generate().map_err(|e| format!("generating private key: {e}"))?,
        ));
        Ok(a)
    }

    async fn save_account(&self, a: &Account) -> Result<(), String> {
        let contact = primary_contact(a);
        let key = a.key.as_ref().ok_or("account has no private key")?.to_pem();
        let all = [
            (
                user_key(&self.issuer, &contact, "registration", ".json"),
                a.to_json(true),
            ),
            (
                user_key(&self.issuer, &contact, "private", ".key"),
                key.expose().to_vec(),
            ),
        ];
        store_all(&self.storage, &all).await
    }

    async fn delete_account(&self, a: &Account) -> Result<(), String> {
        let contact = primary_contact(a);
        self.storage
            .delete(&user_key(&self.issuer, &contact, "registration", ".json"))
            .await
            .map_err(|e| e.to_string())?;
        self.storage
            .delete(&user_key(&self.issuer, &contact, "private", ".key"))
            .await
            .map_err(|e| e.to_string())
    }

    /// The account, registered under the
    /// account lock when it is new.
    async fn client_with_account(
        &self,
        email: &str,
        cancel: &Cancel,
    ) -> Result<(Client, Account), Fail> {
        let client = Client::new(&self.ca, self.http.clone(), cancel.clone());
        let get = || async {
            self.load_or_create_account(email)
                .await
                .map_err(|e| Fail::new(format!("getting ACME account: {e}")))
        };
        let mut account = get().await?;
        if account.status.is_empty() {
            let lock = match account.contact.is_empty() {
                true => "register_acme_account".to_string(),
                false => format!("register_acme_account_{}", primary_contact(&account)),
            };
            let guard = Lock::take(&self.storage, &lock, cancel)
                .await
                .map_err(|e| Fail::new(format!("locking account registration: {e}")))?;
            let res = async {
                account = get().await?;
                if account.status.is_empty() {
                    account.terms_agreed = true;
                    let contact = format!("[{}]", account.contact.join(" "));
                    account = client.new_account(&account).await.map_err(|e| {
                        e.map(|m| format!("registering account {contact} with server: {m}"))
                    })?;
                    self.save_account(&account).await.map_err(|e| {
                        Fail::new(format!(
                            "could not save account [{}]: {e}",
                            account.contact.join(" ")
                        ))
                    })?;
                }
                Ok::<(), Fail>(())
            }
            .await;
            guard.release(&self.log).await;
            res?;
        }
        Ok((client, account))
    }

    /// throttle: at most 10 orders in any 10 seconds per CA and email.
    async fn throttle(&self, email: &str, cancel: &Cancel) -> Result<(), Fail> {
        let key = format!("{},{email}", self.ca);
        loop {
            let wait = {
                let mut all = self.limiter.lock().await;
                let q = all.entry(key.clone()).or_default();
                let now = Instant::now();
                while q
                    .front()
                    .is_some_and(|t| now.duration_since(*t) >= RATE_WINDOW)
                {
                    q.pop_front();
                }
                if q.len() < RATE_EVENTS {
                    q.push_back(now);
                    return Ok(());
                }
                RATE_WINDOW - now.duration_since(*q.front().expect("full"))
            };
            cancel.sleep(wait).await?;
        }
    }

    /// PreCheck: public CAs only issue for public names; the email.
    async fn precheck(&self, name: &str) -> Result<String, Fail> {
        const PUBLIC: [(&str, bool); 5] = [
            ("api.letsencrypt.org", true),
            ("acme.zerossl.com", false),
            ("api.pki.goog", true),
            ("api.buypass.com", false),
            ("acme.ssl.com", false),
        ];
        if let Some((_, ip_ok)) = PUBLIC.iter().find(|(s, _)| self.ca.contains(s)) {
            if !qualifies_for_public_cert(name) {
                return Err(Fail::new(format!(
                    "subject '{name}' does not qualify for a public certificate"
                )));
            }
            if !ip_ok && name.parse::<std::net::IpAddr>().is_ok() {
                return Err(Fail::new(format!(
                    "subject '{name}' cannot have public IP certificate from {} (if CA's policy has changed, please notify the developers in an issue)",
                    self.ca
                )));
            }
        }
        Ok(self.set_email().await)
    }

    /// Issues a certificate: the chain and its metadata.
    #[allow(clippy::too_many_arguments)]
    async fn issue(
        &self,
        name: &str,
        email: &str,
        csr: &[u8],
        replaces: Option<&Leaf>,
        attempts: usize,
        solver: &Solver,
        cancel: &Cancel,
    ) -> Result<CertChain, Fail> {
        let (mut client, mut account) = self.client_with_account(email, cancel).await?;
        self.throttle(email, cancel).await?;
        let typ = if name.parse::<std::net::IpAddr>().is_ok() {
            "ip"
        } else {
            "dns"
        };
        let mut order = Order {
            identifiers: vec![Identifier {
                typ: typ.into(),
                value: name.into(),
            }],
            ..Default::default()
        };
        if attempts != 2
            && let Some(leaf) = replaces
        {
            order.replaces = leaf.ari_id()?;
        }
        let mut chains = Vec::new();
        for _ in 0..2 {
            match self
                .obtain_certificate(&client, &account, order.clone(), csr, solver, cancel)
                .await
            {
                Ok(c) => {
                    chains = c;
                    break;
                }
                Err(e) if e.is("accountDoesNotExist") => {
                    self.delete_account(&account).await.map_err(|d| {
                        Fail::new(format!(
                            "[{name}] ACME account no longer exists on CA, but resetting our local copy of the account info failed: {d}"
                        ))
                    })?;
                    (client, account) = self.client_with_account(email, cancel).await?;
                }
                Err(e) => {
                    let dir = client.directory.clone();
                    return Err(e.map(|m| format!("[{name}] {m} (ca={dir})")));
                }
            }
        }
        chains
            .into_iter()
            .next()
            .ok_or_else(|| Fail::new("no certificate chains"))
    }

    /// acmez's ObtainCertificate for one order.
    async fn obtain_certificate(
        &self,
        client: &Client,
        account: &Account,
        mut order: Order,
        csr: &[u8],
        solver: &Solver,
        cancel: &Cancel,
    ) -> Result<Vec<CertChain>, Fail> {
        if account.status != "valid" {
            return Err(Fail::new(format!(
                "account status is not valid: {}",
                account.status
            )));
        }
        let want = order.identifiers.clone();
        let mut attempt = 1;
        loop {
            if attempt > 1 {
                cancel.sleep(Duration::from_secs(1)).await?;
            }
            match client.new_order(account, &order).await {
                Ok(o) => order = o,
                Err(e) if e.is("alreadyReplaced") && !order.replaces.is_empty() && attempt < 3 => {
                    order.replaces.clear();
                    attempt += 1;
                    continue;
                }
                Err(e) => return Err(e.wrap("creating new order")),
            }
            match self
                .solve_challenges(client, account, &order, solver, cancel)
                .await
            {
                Ok(()) => break,
                Err(e) => {
                    if let Some(p) = &e.problem {
                        let mut s = "solving challenge".to_string();
                        if let Some(id) = &p.authz {
                            s.push_str(": ");
                            s.push_str(id);
                        }
                        return Err(e.wrap(&s));
                    }
                    let loc = order.location.clone();
                    return Err(e.map(|m| format!("solving challenges: {m} (order={loc})")));
                }
            }
        }
        // The CSR's names are the order's.
        let mut left: Vec<&Identifier> = want.iter().collect();
        if left.len() != order.identifiers.len() {
            return Err(Fail::new(format!(
                "validating order identifiers: number of identifiers in Order {} ({}) does not match the number of identifiers extracted from CSR {} ({})",
                ids(&order.identifiers),
                order.identifiers.len(),
                ids(&want),
                want.len()
            )));
        }
        for id in &order.identifiers {
            match left.iter().position(|w| *w == id) {
                Some(i) => {
                    left.remove(i);
                }
                None => {
                    return Err(Fail::new(format!(
                        "validating order identifiers: identifiers in Order {} do not match the identifiers extracted from CSR {}",
                        ids(&order.identifiers),
                        ids(&want)
                    )));
                }
            }
        }
        client
            .finalize_order(account, &mut order, csr)
            .await
            .map_err(|e| {
                let loc = order.location.clone();
                e.map(|m| format!("finalizing order {loc}: {m}"))
            })?;
        let url = order.certificate.clone();
        client
            .get_certificate_chain(account, &url)
            .await
            .map_err(|e| {
                let loc = order.location.clone();
                e.map(|m| format!("downloading certificate chain from {url}: {m} (order={loc})"))
            })
    }

    /// Present each pending authorization's challenge,
    /// tell the server, and poll; on failure every solver is cleaned up
    /// and the authorizations deactivated.
    async fn solve_challenges(
        &self,
        client: &Client,
        account: &Account,
        order: &Order,
        solver: &Solver,
        cancel: &Cancel,
    ) -> Result<(), Fail> {
        let mut states = Vec::new();
        for url in &order.authorizations {
            let authz = client
                .get_authorization(account, url)
                .await
                .map_err(|e| e.wrap(&format!("getting authorization at {url}")))?;
            states.push(AuthzState {
                authz,
                current: None,
            });
        }
        let res = self
            .solve(client, account, &mut states, solver, cancel)
            .await;
        for st in &mut states {
            if let Some(c) = st.current.take() {
                self.cleanup(solver, &c).await;
            }
        }
        if res.is_err() {
            for st in &states {
                if st.authz.status != "pending" && st.authz.status != "valid" {
                    continue;
                }
                if let Err(e) = client
                    .deactivate_authorization(account, &st.authz.location)
                    .await
                {
                    self.log.error(
                        "deactivating authorization",
                        &[
                            ("identifier", st.authz.identifier_value()),
                            ("authz", st.authz.location.clone()),
                            ("err", e.msg),
                        ],
                    );
                }
            }
        }
        res
    }

    async fn solve(
        &self,
        client: &Client,
        account: &Account,
        states: &mut [AuthzState],
        solver: &Solver,
        cancel: &Cancel,
    ) -> Result<(), Fail> {
        let solver_type = match solver {
            Solver::Http => "http-01",
            Solver::Dns(_) => "dns-01",
        };
        for st in states.iter_mut() {
            match st.authz.status.as_str() {
                "valid" => continue,
                "pending" => {}
                s => {
                    return Err(Fail::new(format!(
                        "authz {} has unexpected status; order will fail: {s}",
                        st.authz.location
                    )));
                }
            }
            let Some(chal) = st
                .authz
                .challenges
                .iter()
                .find(|c| c.typ == solver_type)
                .cloned()
            else {
                let offered: Vec<&str> =
                    st.authz.challenges.iter().map(|c| c.typ.as_str()).collect();
                return Err(Fail::new(format!(
                    "{}: no solvers available for remaining challenges (configured=[{solver_type}] offered=[{}] remaining=[{}])",
                    st.authz.identifier_value(),
                    offered.join(" "),
                    offered.join(" ")
                )));
            };
            st.current = Some(chal.clone());
            self.present(solver, &chal)
                .await
                .map_err(|e| e.wrap("presenting for challenge"))?;
        }
        for st in states.iter_mut() {
            if st.authz.status != "pending" {
                continue;
            }
            let chal = st.current.clone().expect("presented above");
            cancel.check()?;
            self.wait(solver, &chal, cancel)
                .await
                .map_err(|e| e.wrap("waiting for solver certmagic.solverWrapper to be ready"))?;
            client
                .initiate_challenge(account, &chal)
                .await
                .map_err(|e| e.wrap("initiating challenge with server"))?;
        }
        for st in states.iter_mut() {
            let r = client.poll_authorization(account, &mut st.authz).await;
            if let Some(c) = st.current.take() {
                self.cleanup(solver, &c).await;
            }
            if let Err(e) = r {
                let id = st.authz.identifier_value();
                return Err(e.map(|m| format!("[{id}] {m}")));
            }
        }
        Ok(())
    }

    /// The obtain or renewal of one certificate, after its lock: a new key,
    /// the issuer, the resource saved, the events.
    #[allow(clippy::too_many_arguments)]
    async fn issue_and_save(
        &self,
        name: &str,
        renewal: bool,
        replaces: Option<&Leaf>,
        attempts: usize,
        solver: &Solver,
        cancel: &Cancel,
    ) -> Result<(), Fail> {
        let key = EcKey::generate().map_err(Fail::new)?;
        let key_pem = key.to_pem();
        let csr = key.csr(name).map_err(Fail::new)?;
        let op = if renewal { "Renew" } else { "Obtain" };
        let res = match self.precheck(name).await {
            Err(e) => Err(e),
            Ok(email) => {
                self.issue(name, &email, &csr, replaces, attempts, solver, cancel)
                    .await
            }
        };
        let chain = match res {
            Ok(c) => c,
            Err(e) => {
                self.emit(Event::Failed {
                    name: name.to_string(),
                    renewal,
                    error: e.msg.clone(),
                });
                return Err(e.map(|m| format!("[{name}] {op}: {m}")));
            }
        };
        self.save_resource(
            name,
            &chain.chain_pem,
            key_pem.expose(),
            &chain.metadata_json(),
        )
        .await
        .map_err(|e| Fail::new(format!("[{name}] {op}: saving assets: {e}")))?;
        self.log.info(
            if renewal {
                "certificate renewed successfully"
            } else {
                "certificate obtained successfully"
            },
            &[
                ("identifier", name.to_string()),
                ("issuer", self.issuer.clone()),
            ],
        );
        self.emit(Event::Obtained {
            name: name.to_string(),
            renewal,
        });
        Ok(())
    }

    /// f until it succeeds, is cancelled, or 30 days passed,
    /// waiting certmagic's intervals between tries.
    async fn with_retry<F, Fut>(&self, cancel: &Cancel, mut f: F) -> Result<(), Fail>
    where
        F: FnMut(usize) -> Fut,
        Fut: std::future::Future<Output = Result<(), Fail>>,
    {
        let start = Instant::now();
        let mut idx: Option<usize> = None;
        let mut attempts = 0;
        let mut last = Fail::new("no attempt");
        while start.elapsed() < MAX_RETRY_DURATION {
            let wait = idx.map(|i| RETRY_INTERVALS[i]).unwrap_or_default();
            cancel.sleep(wait).await?;
            let r = f(attempts).await;
            attempts += 1;
            match r {
                Ok(()) => return Ok(()),
                Err(e) if e.msg == "context canceled" || e.no_retry => return Err(e),
                Err(e) => {
                    idx = Some(match idx {
                        None => 0,
                        Some(i) if i + 1 < RETRY_INTERVALS.len() => i + 1,
                        Some(i) => i,
                    });
                    if start.elapsed() < MAX_RETRY_DURATION {
                        self.log.error(
                            "will retry",
                            &[
                                ("err", e.msg.clone()),
                                ("attempt", attempts.to_string()),
                                (
                                    "retrying_in",
                                    format!("{:?}", RETRY_INTERVALS[idx.unwrap_or(0)]),
                                ),
                            ],
                        );
                    } else {
                        return Err(e);
                    }
                    last = e;
                }
            }
        }
        Err(last)
    }

    pub(crate) async fn obtain_cert(
        &self,
        name: &str,
        retry: bool,
        solver: &Solver,
        cancel: &Cancel,
    ) -> Result<(), Fail> {
        if self.has_resources(name).await {
            return Ok(());
        }
        self.check_storage().await.map_err(|e| {
            Fail::new(format!(
                "failed storage check: {e} - storage is probably misconfigured"
            ))
        })?;
        let lock = format!("issue_cert_{name}");
        self.log
            .info("acquiring lock", &[("identifier", name.to_string())]);
        let guard = Lock::take(&self.storage, &lock, cancel)
            .await
            .map_err(|e| Fail::new(format!("unable to acquire lock '{lock}': {e}")))?;
        self.log
            .info("lock acquired", &[("identifier", name.to_string())]);
        let f = |attempts: usize| async move {
            // Another node may have obtained it while we waited.
            if self.has_resources(name).await {
                self.log.info(
                    "certificate already exists in storage",
                    &[("identifier", name.to_string())],
                );
                return Ok(());
            }
            self.issue_and_save(name, false, None, attempts, solver, cancel)
                .await
        };
        let r = if retry {
            self.with_retry(cancel, f).await
        } else {
            f(0).await
        };
        self.log
            .info("releasing lock", &[("identifier", name.to_string())]);
        guard.release(&self.log).await;
        r
    }

    pub(crate) async fn renew_cert(
        &self,
        name: &str,
        force: bool,
        retry: bool,
        solver: &Solver,
        cancel: &Cancel,
    ) -> Result<(), Fail> {
        if !self.has_resources(name).await {
            return self.obtain_cert(name, true, solver, cancel).await;
        }
        self.check_storage().await.map_err(|e| {
            Fail::new(format!(
                "failed storage check: {e} - storage is probably misconfigured"
            ))
        })?;
        let lock = format!("issue_cert_{name}");
        let guard = Lock::take(&self.storage, &lock, cancel)
            .await
            .map_err(|e| Fail::new(format!("unable to acquire lock '{lock}': {e}")))?;
        let f = |attempts: usize| async move {
            // Another node may have renewed it while we waited.
            let res = self
                .load_resource(name)
                .await
                .map_err(Fail::new)?
                .ok_or_else(|| Fail::new("file does not exist"))?;
            let (_, leaf, due) = res.needs_renewal(self.interval);
            if !due && !force {
                self.log.info(
                    "certificate appears to have been renewed already",
                    &[("identifier", name.to_string())],
                );
                return Ok(());
            }
            // Tell the CA what this replaces when it issued the old one.
            let replaces = match &leaf {
                Some(l) if res.acme().ca == self.ca => Some(l),
                _ => None,
            };
            self.issue_and_save(name, true, replaces, attempts, solver, cancel)
                .await
        };
        let r = if retry {
            self.with_retry(cancel, f).await
        } else {
            f(0).await
        };
        guard.release(&self.log).await;
        r
    }

    /// The certificate's renewal information, from storage when
    /// another node stored newer, else from the CA (stored with the
    /// metadata), under the `ari_<ID>` lock.
    pub(crate) async fn update_ari(&self, cert: &Cached) -> Result<(Cached, bool), String> {
        let old = cert.ari.clone();
        let lock = format!("ari_{}", old.unique_identifier);
        let guard = Lock::take(&self.storage, &lock, &Cancel::never())
            .await
            .map_err(|e| format!("unable to obtain ARI lock: {e}"))?;
        let r = self.update_ari_locked(cert).await;
        guard.release(&self.log).await;
        let (updated, err) = r;
        let changed = !updated.ari.same_window(&old);
        match err {
            Some(e) => Err(e),
            None => Ok((updated, changed)),
        }
    }

    async fn update_ari_locked(&self, cert: &Cached) -> (Cached, Option<String>) {
        let name = cert.names[0].clone();
        let meta_key = site_meta(&cert.issuer, &name);
        let stored = match self.storage.load(&meta_key).await {
            Ok(Some(b)) => serde_json::from_slice::<Value>(&b).ok(),
            _ => None,
        };
        let stored_acme = stored
            .as_ref()
            .map(|v| CertChain::from_metadata(v.get("issuer_data").unwrap_or(&Value::Null)));
        if let Some(s) = &stored_acme
            && let Some(ri) = &s.renewal_info
            && let Some(ra) = &ri.retry_after
            && ((!cert.ari.has_window() && ri.has_window())
                || cert.ari.retry_after.as_ref().is_none_or(|c| ra.after(c)))
        {
            let mut updated = cert.clone();
            updated.ari = ri.clone();
            self.cache_set(&name, &updated);
            return (updated, None);
        }
        if cert.issuer != self.issuer {
            return (
                cert.clone(),
                Some("could not fully update ACME renewal info: either no issuer supporting ARI is configured for certificate, or all such failed (make sure the ACME CA that issued the certificate is configured)".to_string()),
            );
        }
        let client = Client::new(&self.ca, self.http.clone(), Cancel::never());
        let mut ari = match client.get_renewal_info(&cert.leaf).await {
            Ok(a) => a,
            Err(e) => {
                self.log.error(
                    "failed updating renewal info from ACME CA",
                    &[("issuer", self.issuer.clone()), ("err", e.msg)],
                );
                return (
                    cert.clone(),
                    Some("could not fully update ACME renewal info: either no issuer supporting ARI is configured for certificate, or all such failed (make sure the ACME CA that issued the certificate is configured)".to_string()),
                );
            }
        };
        if ari.same_window(&cert.ari) && cert.ari.selected.is_some() {
            ari.selected = cert.ari.selected.clone();
        }
        let mut updated = cert.clone();
        updated.ari = ari.clone();
        self.cache_set(&name, &updated);
        let Some(mut data) = stored_acme else {
            return (
                updated,
                Some(format!(
                    "got new ARI from {}, but failed loading stored certificate metadata: loading cert metadata: file does not exist",
                    self.issuer
                )),
            );
        };
        data.renewal_info = Some(ari);
        let meta = resource_json(&cert.names, &data.metadata_json());
        if let Err(e) = self.storage.store(&meta_key, &meta).await {
            return (
                updated,
                Some(format!(
                    "got new ARI from {}, but could not store it with certificate metadata: {e}",
                    self.issuer
                )),
            );
        }
        (updated, None)
    }

    fn cache_set(&self, name: &str, c: &Cached) {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(e) = cache.get_mut(name) {
            *e = c.clone();
        }
    }
}

/// Identifiers as text: [{dns a.test}].
fn ids(v: &[Identifier]) -> String {
    let parts: Vec<String> = v
        .iter()
        .map(|i| format!("{{{} {}}}", i.typ, i.value))
        .collect();
    format!("[{}]", parts.join(" "))
}

/// Every value or none.
async fn store_all(
    storage: &crate::certs::EtcdStorage,
    all: &[(String, Vec<u8>)],
) -> Result<(), String> {
    for (i, (k, v)) in all.iter().enumerate() {
        if let Err(e) = storage.store(k, v).await {
            for (k, _) in all[..i].iter().rev() {
                let _ = storage.delete(k).await;
            }
            return Err(e.to_string());
        }
    }
    Ok(())
}

fn host_only(hostport: &str) -> String {
    if let Some(rest) = hostport.strip_prefix('[') {
        if let Some((h, port)) = rest.split_once("]:")
            && !port.contains(':')
        {
            return h.to_string();
        }
        if let Some(h) = rest.strip_suffix(']') {
            return h.to_string();
        }
        return hostport.to_string();
    }
    match hostport.rsplit_once(':') {
        Some((h, _)) if !h.contains(':') => h.to_string(),
        _ => hostport.to_string(),
    }
}

/// A storage lock held by this manager (acquireLock/releaseLock).
struct Lock {
    storage: Arc<crate::certs::EtcdStorage>,
    name: String,
}

impl Lock {
    async fn take(
        storage: &Arc<crate::certs::EtcdStorage>,
        name: &str,
        cancel: &Cancel,
    ) -> Result<Lock, String> {
        match storage.lock_unless(name, cancel.done()).await {
            Ok(true) => Ok(Lock {
                storage: storage.clone(),
                name: name.to_string(),
            }),
            Ok(false) => Err("context canceled".to_string()),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn release(self, log: &crate::log::Logger) {
        if let Err(e) = self.storage.unlock(&self.name).await {
            log.error(
                "unable to unlock",
                &[("lock_key", self.name.clone()), ("err", e.to_string())],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indents_as_encoding_json() {
        let b = resource_json(
            &["a.test".to_string()],
            r#"{"url":"https://x/c","ca":"https://x/dir","renewal_info":{"suggestedWindow":{"start":"0001-01-01T00:00:00Z"},"e":[]}}"#,
        );
        assert_eq!(
            String::from_utf8(b).unwrap(),
            "{\n\t\"sans\": [\n\t\t\"a.test\"\n\t],\n\t\"issuer_data\": {\n\t\t\"url\": \"https://x/c\",\n\t\t\"ca\": \"https://x/dir\",\n\t\t\"renewal_info\": {\n\t\t\t\"suggestedWindow\": {\n\t\t\t\t\"start\": \"0001-01-01T00:00:00Z\"\n\t\t\t},\n\t\t\t\"e\": []\n\t\t}\n\t}\n}"
        );
    }

    #[test]
    fn account_keys_as_certmagic_names_them() {
        assert_eq!(
            user_key(
                "localhost:14000-dir",
                "Me@Example.org",
                "registration",
                ".json"
            ),
            "acme/localhost-14000-dir/users/me@example.org/me.json"
        );
        assert_eq!(
            user_key("localhost:14000-dir", "", "private", ".key"),
            "acme/localhost-14000-dir/users/default/default.key"
        );
        assert_eq!(host_only("a.test:80"), "a.test");
        assert_eq!(host_only("[::1]:80"), "::1");
        assert_eq!(host_only("a.test"), "a.test");
        assert!(qualifies_for_public_cert("a.example.org"));
        assert!(!qualifies_for_public_cert("a.local"));
        assert!(!qualifies_for_public_cert("10.0.0.1"));
    }

    #[test]
    fn renewal_windows() {
        let now = (now_ns() / 1_000_000_000) as i64;
        let leaf = |nb: i64, na: i64| Leaf {
            not_before: nb,
            not_after: na,
            serial: vec![1],
            aki: vec![],
            dns_names: vec![],
        };
        let day = 86_400;
        let iv = Duration::from_secs(600);
        // 90 days, 10 used: not due.
        assert!(!needs_renewal(
            &leaf(now - 10 * day, now + 80 * day),
            None,
            iv
        ));
        // 90 days, 70 used: within the last third.
        assert!(needs_renewal(
            &leaf(now - 70 * day, now + 20 * day),
            None,
            iv
        ));
        // Less than five checks left.
        assert!(needs_renewal(&leaf(now - 60, now + 2000), None, iv));
        // An ARI window with no selected time renews at once.
        let ari = RenewalInfo {
            start: Some(armada_store::gojson::from_unix(now + day)),
            end: Some(armada_store::gojson::from_unix(now + 2 * day)),
            ..Default::default()
        };
        assert!(needs_renewal(
            &leaf(now - day, now + 80 * day),
            Some(&ari),
            iv
        ));
    }
}

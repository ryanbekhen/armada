//! Certificates of the public frontends, the parts the leader reads: the
//! manager's interface the
//! server builds the proxy configuration with, the DNS credentials of an
//! app's custom domains (ADR 0047), and certmagic's storage in etcd
//! ([`EtcdStorage`], `/armada-acme/`) with its key layout, so every
//! server serves what another's certificate manager obtained. Obtaining and
//! renewing certificates is [`crate::acme`]'s.

use std::collections::BTreeMap;
use std::sync::Arc;

use armada_store::client::op;
use armada_store::election::{Mutex as EtcdMutex, Session};
use armada_store::{Client, Error, Result};
use tonic::codegen::async_trait;

/// DNS are a DNS provider's credentials for a name's certificate. They
/// redact themselves when printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Dns {
    pub provider: String,
    pub token: String,
}

impl std::fmt::Debug for Dns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (token redacted)", self.provider)
    }
}

impl Dns {
    /// DNS.Key: names the credentials without holding the token.
    pub fn key(&self) -> String {
        let mut b = self.provider.as_bytes().to_vec();
        b.push(0);
        b.extend_from_slice(self.token.as_bytes());
        format!(
            "dns:{}",
            hex(ring::digest::digest(&ring::digest::SHA256, &b).as_ref())
        )
    }
}

/// What the server needs from certificate management.
#[async_trait]
pub trait Certs: Send + Sync {
    /// Makes names the set of managed certificates; a name in dns uses
    /// DNS-01 with those credentials. It returns without waiting for
    /// issuance.
    async fn manage(
        &self,
        names: &[String],
        root: &str,
        dns: &BTreeMap<String, Dns>,
    ) -> std::result::Result<(), String>;
    /// The chain followed by the private key, if issued.
    async fn certificate(&self, name: &str) -> Option<Vec<u8>>;
    /// Whether DNS-01, and so wildcards, is available.
    fn supports_wildcard(&self) -> bool;
    /// HTTPHandler: the answer to an HTTP-01 challenge request (method,
    /// Host header, path), or None for anything else (404).
    async fn http_challenge(&self, _method: &str, _host: &str, _path: &str) -> Option<Vec<u8>> {
        None
    }
}

/// Looks up DNS TXT records.
#[async_trait]
pub trait TxtResolver: Send + Sync {
    async fn lookup_txt(&self, name: &str) -> std::result::Result<Vec<String>, String>;
}

/// Resolves nothing (the tests' noTXT).
pub struct NoTxt;

#[async_trait]
impl TxtResolver for NoTxt {
    async fn lookup_txt(&self, _name: &str) -> std::result::Result<Vec<String>, String> {
        Err("no such host".to_string())
    }
}

/// The machine's resolvers: a TXT
/// query to each nameserver of /etc/resolv.conf in turn over UDP, again
/// over TCP when the answer is cut short; each record's strings joined
/// into one.
pub struct SystemTxt;

#[async_trait]
impl TxtResolver for SystemTxt {
    async fn lookup_txt(&self, name: &str) -> std::result::Result<Vec<String>, String> {
        let conf = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        let mut servers: Vec<String> = conf
            .lines()
            .filter_map(|l| l.trim().strip_prefix("nameserver"))
            .map(|s| s.trim().to_string())
            .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
            .map(|ip| std::net::SocketAddr::new(ip, 53).to_string())
            .collect();
        if servers.is_empty() {
            servers.push("127.0.0.1:53".to_string());
        }
        let mut last = format!("lookup {name}: no such host");
        for s in servers {
            match dns::lookup_txt(&s, name).await {
                Ok(v) => return Ok(v),
                Err(dns::Fail::NoSuchHost) => return Err(format!("lookup {name}: no such host")),
                Err(dns::Fail::Other(e)) => last = format!("lookup {name} on {s}: {e}"),
            }
        }
        Err(last)
    }
}

/// A minimal DNS client for TXT records (RFC 1035).
mod dns {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub enum Fail {
        NoSuchHost,
        Other(String),
    }

    const TIMEOUT: Duration = Duration::from_secs(5);
    const TXT: u16 = 16;

    fn query(id: u16, name: &str) -> Result<Vec<u8>, Fail> {
        let mut q = Vec::with_capacity(32 + name.len());
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name.trim_end_matches('.').split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(Fail::NoSuchHost);
            }
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&TXT.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        Ok(q)
    }

    fn other(e: impl std::fmt::Display) -> Fail {
        Fail::Other(e.to_string())
    }

    fn u16_at(b: &[u8], i: usize) -> Result<u16, Fail> {
        b.get(i..i + 2)
            .map(|x| u16::from_be_bytes([x[0], x[1]]))
            .ok_or_else(|| other("short answer"))
    }

    /// Skips a possibly compressed name at i.
    fn skip_name(b: &[u8], mut i: usize) -> Result<usize, Fail> {
        loop {
            let l = *b.get(i).ok_or_else(|| other("short answer"))?;
            if l & 0xc0 == 0xc0 {
                return Ok(i + 2);
            }
            if l == 0 {
                return Ok(i + 1);
            }
            i += 1 + usize::from(l);
        }
    }

    /// The TXT records of an answer; None when it was cut short.
    fn parse(b: &[u8], id: u16) -> Result<Option<Vec<String>>, Fail> {
        if b.len() < 12 || u16_at(b, 0)? != id {
            return Err(other("unexpected answer"));
        }
        let flags = u16_at(b, 2)?;
        if flags & 0x0200 != 0 {
            return Ok(None);
        }
        match flags & 0x000f {
            0 => {}
            3 => return Err(Fail::NoSuchHost),
            rc => return Err(other(format!("server answered rcode {rc}"))),
        }
        let (qd, an) = (u16_at(b, 4)?, u16_at(b, 6)?);
        let mut i = 12;
        for _ in 0..qd {
            i = skip_name(b, i)? + 4;
        }
        let mut out = Vec::new();
        for _ in 0..an {
            i = skip_name(b, i)?;
            let (typ, len) = (u16_at(b, i)?, usize::from(u16_at(b, i + 8)?));
            i += 10;
            let data = b.get(i..i + len).ok_or_else(|| other("short answer"))?;
            i += len;
            if typ != TXT {
                continue;
            }
            let mut txt = Vec::new();
            let mut j = 0;
            while j < data.len() {
                let l = usize::from(data[j]);
                let s = data
                    .get(j + 1..j + 1 + l)
                    .ok_or_else(|| other("short answer"))?;
                txt.extend_from_slice(s);
                j += 1 + l;
            }
            out.push(String::from_utf8_lossy(&txt).into_owned());
        }
        if out.is_empty() {
            return Err(Fail::NoSuchHost);
        }
        Ok(Some(out))
    }

    pub async fn lookup_txt(server: &str, name: &str) -> Result<Vec<String>, Fail> {
        let mut idb = [0u8; 2];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut idb)
            .map_err(|_| other("random"))?;
        let id = u16::from_be_bytes(idb);
        let q = query(id, name)?;
        let udp = async {
            let bind = if server.starts_with('[') {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            let sock = tokio::net::UdpSocket::bind(bind).await.map_err(other)?;
            sock.connect(server).await.map_err(other)?;
            sock.send(&q).await.map_err(other)?;
            let mut buf = vec![0u8; 4096];
            let n = sock.recv(&mut buf).await.map_err(other)?;
            parse(&buf[..n], id)
        };
        let res = tokio::time::timeout(TIMEOUT, udp)
            .await
            .map_err(|_| other("i/o timeout"))??;
        if let Some(v) = res {
            return Ok(v);
        }
        let tcp = async {
            let mut c = tokio::net::TcpStream::connect(server)
                .await
                .map_err(other)?;
            let mut msg = (q.len() as u16).to_be_bytes().to_vec();
            msg.extend_from_slice(&q);
            c.write_all(&msg).await.map_err(other)?;
            let n = c.read_u16().await.map_err(other)?;
            let mut buf = vec![0u8; usize::from(n)];
            c.read_exact(&mut buf).await.map_err(other)?;
            parse(&buf, id)?.ok_or_else(|| other("truncated answer over TCP"))
        };
        tokio::time::timeout(TIMEOUT, tcp)
            .await
            .map_err(|_| other("i/o timeout"))?
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn reads_txt_answers() {
            let q = query(7, "_armada-verify.example.org").ok().unwrap();
            let mut a = q.clone();
            a[2] = 0x81;
            a[3] = 0x80;
            a[7] = 1;
            a.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 60, 0, 8, 3]);
            a.extend_from_slice(b"abc");
            a.push(3);
            a.extend_from_slice(b"def");
            let got = parse(&a, 7).ok().flatten().unwrap();
            assert_eq!(got, vec!["abcdef".to_string()]);
            let mut nx = q.clone();
            nx[3] = 0x83;
            assert!(matches!(parse(&nx, 7), Err(Fail::NoSuchHost)));
        }
    }
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// ACMEIssuer.issuerKey: the storage key of a CA's directory URL, its host
/// and its path as one component.
pub fn issuer_key(ca: &str) -> String {
    let Ok(u) = armada_node::queue::url::parse(ca) else {
        return ca.to_string();
    };
    let mut key = String::from_utf8_lossy(&u.host).into_owned();
    let path = String::from_utf8_lossy(&u.path).into_owned();
    if !path.is_empty() {
        let p = path.replace(['/', '\\'], "-");
        let p = p.trim_matches('-');
        if !p.is_empty() {
            key.push('-');
            key.push_str(p);
        }
    }
    key
}

/// KeyBuilder.Safe: a storage key component.
pub fn safe(s: &str) -> String {
    let s = s.to_lowercase();
    let s = s.trim();
    // At each position the first old string that matches is replaced,
    // left to right.
    let mut out = String::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let rest = &s[i..];
        if rest.starts_with(' ') {
            out.push('_');
            i += 1;
        } else if rest.starts_with('+') {
            out.push_str("_plus_");
            i += 1;
        } else if rest.starts_with('*') {
            out.push_str("wildcard_");
            i += 1;
        } else if rest.starts_with(':') {
            out.push('-');
            i += 1;
        } else if rest.starts_with("..") {
            i += 2;
        } else {
            let c = rest.chars().next().expect("not at the end");
            out.push(c);
            i += c.len_utf8();
        }
    }
    // Anything but ASCII letters, digits, _, @, ., and - removed.
    out.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '@' | '.' | '-'))
        .collect()
}

/// StorageKeys.SiteCert.
pub fn site_cert(issuer: &str, name: &str) -> String {
    let n = safe(name);
    format!("certificates/{}/{n}/{n}.crt", safe(issuer))
}

/// StorageKeys.SitePrivateKey.
pub fn site_private_key(issuer: &str, name: &str) -> String {
    let n = safe(name);
    format!("certificates/{}/{n}/{n}.key", safe(issuer))
}

/// The certificate of name followed by its key, as the
/// proxies take it.
pub async fn load_bundle(s: &EtcdStorage, issuer: &str, name: &str) -> Option<Vec<u8>> {
    let crt = s.load(&site_cert(issuer, name)).await.ok()??;
    let key = s.load(&site_private_key(issuer, name)).await.ok()??;
    let mut out = crt;
    if out.last().is_some_and(|c| *c != b'\n') {
        out.push(b'\n');
    }
    out.extend_from_slice(&key);
    Some(out)
}

/// How long a lock outlives a crashed holder.
const LOCK_TTL: i64 = 60;

/// What [`EtcdStorage::stat`] finds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    pub key: String,
    /// Unix nanoseconds of the last write; 0 for a directory.
    pub modified: i64,
    pub size: i64,
    pub terminal: bool,
}

/// certmagic's data in etcd: each value is an
/// 8-byte big-endian modification time (Unix nanoseconds) followed by the
/// data, under `<prefix>data/`, and locks are etcd mutexes under
/// `<prefix>locks/` on a session with a 60-second lease, so a lock one
/// server takes holds against every other.
pub struct EtcdStorage {
    c: Client,
    prefix: String,
    st: tokio::sync::Mutex<LockState>,
}

#[derive(Default)]
struct LockState {
    session: Option<Arc<Session>>,
    locks: BTreeMap<String, EtcdMutex>,
}

impl EtcdStorage {
    /// NewEtcdStorage under prefix (e.g. "/armada-acme/").
    pub fn new(c: Client, prefix: &str) -> Result<EtcdStorage> {
        if !prefix.ends_with('/') {
            return Err(Error::other("certs: etcd prefix must end with /"));
        }
        Ok(EtcdStorage {
            c,
            prefix: prefix.to_string(),
            st: tokio::sync::Mutex::new(LockState::default()),
        })
    }

    fn key(&self, k: &str) -> String {
        format!("{}data/{}", self.prefix, k.trim_matches('/'))
    }

    /// Store.
    pub async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or_default();
        let mut b = now.to_be_bytes().to_vec();
        b.extend_from_slice(value);
        self.c.put(&self.key(key), &b).await.map(|_| ())
    }

    async fn get(&self, key: &str) -> Result<Option<(Vec<u8>, i64)>> {
        let r = self.c.range(op::get(&self.key(key), 0)).await?;
        let Some(kv) = r.kvs.first() else {
            return Ok(None);
        };
        if kv.value.len() < 8 {
            return Err(Error::other(format!("certs: corrupt value at {key}")));
        }
        let mut t = [0u8; 8];
        t.copy_from_slice(&kv.value[..8]);
        Ok(Some((kv.value[8..].to_vec(), u64::from_be_bytes(t) as i64)))
    }

    /// Load: None when the key does not exist.
    pub async fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.get(key).await?.map(|(b, _)| b))
    }

    /// Delete: the key and, like a directory, everything below it.
    pub async fn delete(&self, key: &str) -> Result<()> {
        let k = self.key(key);
        let below = format!("{k}/");
        let end = String::from_utf8_lossy(&op::prefix_end(&below)).into_owned();
        self.c
            .txn(armada_proto::etcd::etcdserverpb::TxnRequest {
                compare: Vec::new(),
                success: vec![op::delete(&k), op::delete_range(&below, &end)],
                failure: Vec::new(),
            })
            .await
            .map(|_| ())
    }

    /// Stat: None when neither the key nor anything below it exists.
    pub async fn stat(&self, key: &str) -> Result<Option<KeyInfo>> {
        if let Some((b, m)) = self.get(key).await? {
            return Ok(Some(KeyInfo {
                key: key.to_string(),
                modified: m,
                size: b.len() as i64,
                terminal: true,
            }));
        }
        let mut r = op::get_prefix(&format!("{}/", self.key(key)), 0);
        r.count_only = true;
        let n = self.c.range(r).await?.count;
        if n == 0 {
            return Ok(None);
        }
        Ok(Some(KeyInfo {
            key: key.to_string(),
            modified: 0,
            size: 0,
            terminal: false,
        }))
    }

    /// Exists.
    pub async fn exists(&self, key: &str) -> bool {
        matches!(self.stat(key).await, Ok(Some(_)))
    }

    /// List: the keys under dir, one level or all of them, sorted; None
    /// when there are none.
    pub async fn list(&self, dir: &str, recursive: bool) -> Result<Option<Vec<String>>> {
        let d = dir.trim_matches('/');
        let base = if d.is_empty() {
            format!("{}data/", self.prefix)
        } else {
            format!("{}/", self.key(dir))
        };
        let mut r = op::get_prefix(&base, 0);
        r.keys_only = true;
        let resp = self.c.range(r).await?;
        if resp.kvs.is_empty() {
            return Ok(None);
        }
        let mut seen = std::collections::BTreeSet::new();
        for kv in &resp.kvs {
            let k = String::from_utf8_lossy(&kv.key);
            let mut rel = k.strip_prefix(&base).unwrap_or(&k).to_string();
            if !recursive && let Some((first, _)) = rel.split_once('/') {
                rel = first.to_string();
            }
            seen.insert(
                armada_spec::go::clean_path(&format!("{d}/{rel}"))
                    .trim_start_matches('/')
                    .to_string(),
            );
        }
        Ok(Some(seen.into_iter().collect()))
    }

    /// Lock: an etcd mutex on `<prefix>locks/<name>`, tied to a lease.
    pub async fn lock(&self, name: &str) -> Result<()> {
        let session = self.session().await?;
        let mut m = EtcdMutex::new(
            session,
            &format!("{}locks/{}", self.prefix, name.trim_matches('/')),
        );
        m.lock().await?;
        self.st.lock().await.locks.insert(name.to_string(), m);
        Ok(())
    }

    /// Lock, given up when `stop` ends first: the waiting key is removed
    /// and Ok(false) returned.
    pub async fn lock_unless(
        &self,
        name: &str,
        stop: impl std::future::Future<Output = ()>,
    ) -> Result<bool> {
        let session = self.session().await?;
        let mut m = EtcdMutex::new(
            session,
            &format!("{}locks/{}", self.prefix, name.trim_matches('/')),
        );
        let won = tokio::select! {
            r = m.lock() => Some(r),
            _ = stop => None,
        };
        match won {
            Some(r) => {
                r?;
                self.st.lock().await.locks.insert(name.to_string(), m);
                Ok(true)
            }
            None => {
                let _ = m.unlock().await;
                Ok(false)
            }
        }
    }

    async fn session(&self) -> Result<Arc<Session>> {
        let mut st = self.st.lock().await;
        if st.session.as_ref().is_some_and(|s| s.is_done()) {
            st.session = None;
        }
        match &st.session {
            Some(s) => Ok(s.clone()),
            None => {
                let s = Arc::new(
                    Session::new(&self.c, LOCK_TTL)
                        .await
                        .map_err(|e| Error::other(format!("certs: lock session: {e}")))?,
                );
                st.session = Some(s.clone());
                Ok(s)
            }
        }
    }

    /// Unlock.
    pub async fn unlock(&self, name: &str) -> Result<()> {
        let m = self.st.lock().await.locks.remove(name);
        match m {
            None => Err(Error::other(format!("certs: {name} is not locked"))),
            Some(mut m) => m.unlock().await,
        }
    }

    /// Close: releases the locks' lease.
    pub async fn close(&self) -> Result<()> {
        let s = self.st.lock().await.session.take();
        match s {
            Some(s) => s.close().await,
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_as_certmagic_writes_them() {
        assert_eq!(
            issuer_key("https://acme-staging-v02.api.letsencrypt.org/directory"),
            "acme-staging-v02.api.letsencrypt.org-directory"
        );
        assert_eq!(
            issuer_key("https://localhost:14000/dir"),
            "localhost:14000-dir"
        );
        assert_eq!(
            site_cert("localhost:14000-dir", "*.Apps.Example.com"),
            "certificates/localhost-14000-dir/wildcard_.apps.example.com/wildcard_.apps.example.com.crt"
        );
        assert_eq!(safe("a..b/c d+e"), "abc_d_plus_e");
    }

    #[test]
    fn dns_keys_hide_the_token() {
        let d = Dns {
            provider: "cloudflare".into(),
            token: "secret".into(),
        };
        assert!(d.key().starts_with("dns:"));
        assert_eq!(d.key().len(), 4 + 64);
        assert!(!format!("{d:?}").contains("secret"));
    }
}

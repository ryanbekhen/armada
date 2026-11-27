//! The registry protocol as containerd's docker resolver speaks it:
//! resolving a reference (HEAD, then GET when the registry
//! sends no digest), fetching manifests and blobs, the retries of
//! doWithRetries, and the authorizer (bearer tokens from the token service
//! a challenge names, basic credentials) with the credentials the app gave
//! only for the registry they were given for.

use super::digest::Digest;
use super::http::{self, Client, Request, Response, Url};
use super::reference::{Reference, RegistryAuth, registry_host};
use std::collections::HashMap;
use std::io::Read;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const MEDIA_DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
pub const MEDIA_DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
pub const MEDIA_DOCKER_SCHEMA1: &str = "application/vnd.docker.distribution.manifest.v1+prettyjws";
pub const MEDIA_OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const MEDIA_OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";

/// docker.MaxManifestSize (4 × 1048 × 1048, as containerd writes it).
pub const MAX_MANIFEST_SIZE: u64 = 4 * 1048 * 1048;
const MAX_ATTEMPTS: u32 = 5;

pub fn is_manifest(mt: &str) -> bool {
    mt == MEDIA_DOCKER_MANIFEST || mt == MEDIA_OCI_MANIFEST
}

pub fn is_index(mt: &str) -> bool {
    mt == MEDIA_DOCKER_LIST || mt == MEDIA_OCI_INDEX
}

/// What went wrong talking to the registry. NotFound is errdefs.NotFound,
/// which the driver's messages tell apart.
#[derive(Debug)]
pub struct Error {
    pub msg: String,
    pub not_found: bool,
}

impl Error {
    pub fn new(msg: impl Into<String>) -> Error {
        Error {
            msg: msg.into(),
            not_found: false,
        }
    }
    fn not_found(msg: impl Into<String>) -> Error {
        Error {
            msg: msg.into(),
            not_found: true,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl From<http::Error> for Error {
    fn from(e: http::Error) -> Error {
        Error::new(e.msg)
    }
}

/// A descriptor, as the OCI image spec writes it.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct Descriptor {
    #[serde(rename = "mediaType", default)]
    pub media_type: String,
    pub digest: Digest,
    #[serde(default)]
    pub size: i64,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "crate::runtime::nullable"
    )]
    pub urls: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "std::collections::BTreeMap::is_empty",
        deserialize_with = "crate::runtime::nullable"
    )]
    pub annotations: std::collections::BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "base64_data")]
    pub data: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<super::platform::Platform>,
    #[serde(
        rename = "artifactType",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub artifact_type: String,
}

mod base64_data {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_str(&super::http::base64(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let Some(s) = Option::<String>::deserialize(d)? else {
            return Ok(None);
        };
        decode(&s)
            .map(Some)
            .ok_or_else(|| serde::de::Error::custom("illegal base64 data"))
    }

    fn decode(s: &str) -> Option<Vec<u8>> {
        let val = |c: u8| -> Option<u32> {
            Some(match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => return None,
            } as u32)
        };
        let b = s.as_bytes();
        if !b.len().is_multiple_of(4) {
            return None;
        }
        let mut out = Vec::with_capacity(b.len() / 4 * 3);
        for c in b.chunks(4) {
            let pad = c.iter().rev().take_while(|x| **x == b'=').count();
            if pad > 2 {
                return None;
            }
            let mut n = 0u32;
            for (i, x) in c.iter().enumerate() {
                n <<= 6;
                if i < 4 - pad {
                    n |= val(*x)?;
                }
            }
            out.push((n >> 16) as u8);
            if pad < 2 {
                out.push((n >> 8) as u8);
            }
            if pad < 1 {
                out.push(n as u8);
            }
        }
        Some(out)
    }
}

/// A WWW-Authenticate challenge (auth.Challenge).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Scheme {
    Basic = 1,
    Digest = 2,
    Bearer = 4,
}

struct Challenge {
    scheme: Scheme,
    params: HashMap<String, String>,
}

fn is_token(c: u8) -> bool {
    c > 31 && c < 127 && !b" \t\"(),/:;<=>?@[]\\{}".contains(&c)
}

/// auth.ParseAuthHeader: bearer first, then digest, then basic.
fn parse_challenges(values: &[&str]) -> Vec<Challenge> {
    let mut out = Vec::new();
    for h in values {
        let (value, params) = parse_value_and_params(h);
        let scheme = match value.as_str() {
            "basic" => Scheme::Basic,
            "digest" => Scheme::Digest,
            "bearer" => Scheme::Bearer,
            _ => continue,
        };
        out.push(Challenge { scheme, params });
    }
    out.sort_by(|a, b| b.scheme.cmp(&a.scheme));
    out
}

fn parse_value_and_params(h: &str) -> (String, HashMap<String, String>) {
    let mut params = HashMap::new();
    let b = h.as_bytes();
    let token = |i: &mut usize| {
        let s = *i;
        while *i < b.len() && is_token(b[*i]) {
            *i += 1;
        }
        String::from_utf8_lossy(&b[s..*i]).into_owned()
    };
    let skip_space = |i: &mut usize| {
        while *i < b.len() && b" \t\r\n".contains(&b[*i]) {
            *i += 1;
        }
    };
    let mut i = 0;
    let value = token(&mut i);
    if value.is_empty() {
        return (value, params);
    }
    let value = value.to_lowercase();
    loop {
        skip_space(&mut i);
        let key = token(&mut i);
        if key.is_empty() || i >= b.len() || b[i] != b'=' {
            return (value, params);
        }
        i += 1;
        let v = if i < b.len() && b[i] == b'"' {
            i += 1;
            let mut out = Vec::new();
            let mut closed = false;
            while i < b.len() {
                match b[i] {
                    b'"' => {
                        i += 1;
                        closed = true;
                        break;
                    }
                    b'\\' if i + 1 < b.len() => {
                        out.push(b[i + 1]);
                        i += 2;
                    }
                    c => {
                        out.push(c);
                        i += 1;
                    }
                }
            }
            if !closed {
                params.insert(key.to_lowercase(), String::new());
                return (value, params);
            }
            String::from_utf8_lossy(&out).into_owned()
        } else {
            token(&mut i)
        };
        params.insert(key.to_lowercase(), v);
        skip_space(&mut i);
        if i >= b.len() || b[i] != b',' {
            return (value, params);
        }
        i += 1;
    }
}

enum Handler {
    Basic {
        username: String,
        secret: String,
    },
    Bearer {
        realm: String,
        service: String,
        scopes: Vec<String>,
        username: String,
        secret: String,
        tokens: HashMap<String, (String, Option<Instant>)>,
    },
}

/// One registry repository a pull talks to.
pub struct Registry<'a> {
    client: &'a Client,
    /// The host requests go to (registry-1.docker.io for docker.io).
    host: String,
    /// The repository's path ("library/nginx").
    repository: String,
    auth: Option<RegistryAuth>,
    handlers: Mutex<HashMap<String, Handler>>,
}

/// One request's outcome as doWithRetries tells it: the response and
/// what the attempts saw.
struct Seen {
    status: u16,
    method: String,
    url: Url,
}

impl<'a> Registry<'a> {
    pub fn new(client: &'a Client, r: &Reference, auth: Option<RegistryAuth>) -> Registry<'a> {
        let host = if r.domain == "docker.io" {
            "registry-1.docker.io".to_string()
        } else {
            r.domain.clone()
        };
        Registry {
            client,
            host,
            repository: r.path.clone(),
            auth,
            handlers: Mutex::new(HashMap::new()),
        }
    }

    /// The registry's credentials for host: the app's only for the
    /// registry they were given for.
    fn credentials(&self, host: &str) -> Option<(String, String)> {
        let a = self.auth.as_ref()?;
        if registry_host(host) == registry_host(&a.server_address) {
            Some((a.username.clone(), a.password.clone()))
        } else {
            Some((String::new(), String::new()))
        }
    }

    fn url(&self, parts: &[&str]) -> Url {
        let mut path = format!("/v2/{}", self.repository);
        for p in parts {
            path.push('/');
            path.push_str(p);
        }
        Url::parse(&format!("https://{}{path}", self.host)).unwrap_or(Url {
            scheme: "https".into(),
            userinfo: None,
            host: self.host.clone(),
            port: None,
            path,
        })
    }

    fn scope(&self) -> String {
        format!("repository:{}:pull", self.repository)
    }

    /// doWithRetries.
    fn do_with_retries(&self, method: &str, url: &Url, accept: &str) -> Result<Response, Error> {
        let mut method = method.to_string();
        let mut attempts = MAX_ATTEMPTS;
        let mut seen: Vec<Seen> = Vec::new();
        loop {
            let resp = loop {
                attempts -= 1;
                match self.do_once(&method, url, accept) {
                    Ok(r) => break r,
                    Err(e) if e.transient && attempts > 0 => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(e) => return Err(Error::new(format!("failed to do request: {}", e.msg))),
                }
            };
            seen.push(Seen {
                status: resp.status,
                method: method.clone(),
                url: resp.url.clone(),
            });
            let retry = self.retry_request(&resp, &seen, &mut method, url)?;
            if retry && attempts > 0 {
                continue;
            }
            return Ok(resp);
        }
    }

    fn do_once(&self, method: &str, url: &Url, accept: &str) -> Result<Response, http::Error> {
        let mut headers = vec![("Accept".to_string(), accept.to_string())];
        if let Some(a) = self.authorize(&url.authority())? {
            headers.push(("Authorization".into(), a));
        }
        self.client.send(&Request {
            method: method.into(),
            url: url.clone(),
            headers,
            body: None,
        })
    }

    /// retryRequest.
    fn retry_request(
        &self,
        last: &Response,
        seen: &[Seen],
        method: &mut String,
        url: &Url,
    ) -> Result<bool, Error> {
        match last.status {
            401 => match self.add_responses(last, seen) {
                Ok(()) => Ok(true),
                Err(None) => Ok(false),
                Err(Some(e)) => Err(e),
            },
            405 if method == "HEAD" && url.path.contains("/manifests/") => {
                *method = "GET".into();
                Ok(true)
            }
            408 | 429 => Ok(true),
            // The same failure twice in a row gives up; one is retried.
            500 | 503 | 504 => Ok(!(seen.len() > 1 && seen[seen.len() - 2].status == last.status)),
            _ => Ok(false),
        }
    }

    /// AddResponses: Err(None) is ErrNotImplemented (no scheme it knows).
    fn add_responses(&self, last: &Response, seen: &[Seen]) -> Result<(), Option<Error>> {
        let host = last.url.authority();
        let mut handlers = self.handlers.lock().unwrap_or_else(|p| p.into_inner());
        for c in parse_challenges(&last.header_values("www-authenticate")) {
            match c.scheme {
                Scheme::Bearer => {
                    if let Some(err) = c.params.get("error").filter(|e| !e.is_empty()) {
                        let n = seen.len();
                        let same = n > 1
                            && seen[n - 2].method == seen[n - 1].method
                            && seen[n - 2].url == seen[n - 1].url;
                        if !same {
                            handlers.remove(&host);
                        } else {
                            handlers.remove(&host);
                            return Err(Some(Error::new(format!(
                                "server message: {err}: authorization failed"
                            ))));
                        }
                    }
                    if handlers.contains_key(&host) {
                        return Ok(());
                    }
                    let (username, secret) = self.credentials(&host).unwrap_or_default();
                    let Some(realm) = c.params.get("realm") else {
                        return Err(Some(Error::new(
                            "no realm specified for token auth challenge",
                        )));
                    };
                    let realm = Url::parse(realm).map_err(|e| {
                        Some(Error::new(format!(
                            "invalid token auth challenge realm: {e}"
                        )))
                    })?;
                    let scopes = c
                        .params
                        .get("scope")
                        .map(|s| s.split(' ').map(str::to_string).collect())
                        .unwrap_or_default();
                    handlers.insert(
                        host,
                        Handler::Bearer {
                            realm: realm.to_string(),
                            service: c.params.get("service").cloned().unwrap_or_default(),
                            scopes,
                            username,
                            secret,
                            tokens: HashMap::new(),
                        },
                    );
                    return Ok(());
                }
                Scheme::Basic if self.auth.is_some() => {
                    let (username, secret) = self.credentials(&host).unwrap_or_default();
                    if username.is_empty() || secret.is_empty() {
                        return Err(Some(Error::new(
                            "authorization failed: no basic auth credentials",
                        )));
                    }
                    handlers.insert(host, Handler::Basic { username, secret });
                    return Ok(());
                }
                _ => {}
            }
        }
        Err(None)
    }

    /// Authorize: the Authorization header for a request to host, if a
    /// challenge from it set one up.
    fn authorize(&self, host: &str) -> Result<Option<String>, http::Error> {
        let mut handlers = self.handlers.lock().unwrap_or_else(|p| p.into_inner());
        let Some(h) = handlers.get_mut(host) else {
            return Ok(None);
        };
        match h {
            Handler::Basic { username, secret } => Ok(Some(format!(
                "Basic {}",
                http::base64(format!("{username}:{secret}").as_bytes())
            ))),
            Handler::Bearer {
                realm,
                service,
                scopes,
                username,
                secret,
                tokens,
            } => {
                let mut all: Vec<String> = vec![self.scope()];
                all.extend(scopes.iter().cloned());
                all.sort();
                all.dedup();
                let key = all.join(" ");
                if let Some((t, exp)) = tokens.get(&key)
                    && exp.is_none_or(|e| e > Instant::now())
                {
                    return Ok(Some(format!("Bearer {t}")));
                }
                let (token, expires) = self.fetch_token(realm, service, &all, username, secret)?;
                let exp =
                    (expires > 0).then(|| Instant::now() + Duration::from_secs(expires as u64));
                tokens.insert(key, (token.clone(), exp));
                Ok(Some(format!("Bearer {token}")))
            }
        }
    }

    /// doBearerAuth: with a secret, the OAuth form first and the GET token
    /// endpoint where the service refuses it; without, the GET endpoint.
    fn fetch_token(
        &self,
        realm: &str,
        service: &str,
        scopes: &[String],
        username: &str,
        secret: &str,
    ) -> Result<(String, i64), http::Error> {
        let fail = |m: String| http::Error {
            msg: m,
            transient: false,
        };
        let realm_url = Url::parse(realm).map_err(fail)?;
        if !secret.is_empty() {
            let scope = scopes.join(" ");
            let mut form: Vec<(&str, &str)> = Vec::new();
            if !scopes.is_empty() {
                form.push(("scope", &scope));
            }
            form.push(("service", service));
            form.push(("client_id", "containerd-client"));
            if username.is_empty() {
                form.push(("grant_type", "refresh_token"));
                form.push(("refresh_token", secret));
            } else {
                form.push(("grant_type", "password"));
                form.push(("username", username));
                form.push(("password", secret));
            }
            let resp = self.client.send(&Request {
                method: "POST".into(),
                url: realm_url.clone(),
                headers: vec![(
                    "Content-Type".into(),
                    "application/x-www-form-urlencoded; charset=utf-8".into(),
                )],
                body: Some(http::form_encode(&form).into_bytes()),
            })?;
            if (200..400).contains(&resp.status) {
                let t: TokenResponse = read_token(resp)?;
                if t.access_token.is_empty() {
                    return Err(fail("failed to fetch oauth token: authorization server did not include a token in the response".into()));
                }
                return Ok((t.access_token, t.expires_in));
            }
            let s = resp.status;
            if !((s == 405 && !username.is_empty()) || s == 404 || s == 401 || s == 400) {
                return Err(fail(format!(
                    "failed to fetch oauth token: unexpected status from POST request to {}: {}",
                    redacted(&resp.url),
                    resp.status_text()
                )));
            }
            return self.get_token(realm_url, service, scopes, username, secret);
        }
        self.get_token(realm_url, service, scopes, username, secret)
            .map_err(|e| fail(format!("failed to fetch anonymous token: {}", e.msg)))
    }

    fn get_token(
        &self,
        mut url: Url,
        service: &str,
        scopes: &[String],
        username: &str,
        secret: &str,
    ) -> Result<(String, i64), http::Error> {
        let mut query: Vec<(String, String)> = match url.path.split_once('?') {
            Some((_, q)) => q
                .split('&')
                .filter(|kv| !kv.is_empty())
                .map(|kv| {
                    let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                    (unescape(k), unescape(v))
                })
                .collect(),
            None => Vec::new(),
        };
        if !service.is_empty() {
            query.push(("service".into(), service.into()));
        }
        for s in scopes {
            query.push(("scope".into(), s.clone()));
        }
        // url.Values.Encode: keys sorted, values in order.
        query.sort_by(|a, b| a.0.cmp(&b.0));
        let base = url.path.split('?').next().unwrap_or("/").to_string();
        let pairs: Vec<(&str, &str)> = query
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let q: Vec<String> = pairs
            .iter()
            .map(|(k, v)| format!("{}={}", http::query_escape(k), http::query_escape(v)))
            .collect();
        url.path = if q.is_empty() {
            base
        } else {
            format!("{base}?{}", q.join("&"))
        };
        let mut headers = Vec::new();
        if !secret.is_empty() {
            headers.push((
                "Authorization".into(),
                format!(
                    "Basic {}",
                    http::base64(format!("{username}:{secret}").as_bytes())
                ),
            ));
        }
        let resp = self.client.send(&Request {
            method: "GET".into(),
            url,
            headers,
            body: None,
        })?;
        if !(200..400).contains(&resp.status) {
            return Err(http::Error {
                msg: format!(
                    "unexpected status from GET request to {}: {}",
                    redacted(&resp.url),
                    resp.status_text()
                ),
                transient: false,
            });
        }
        let t = read_token(resp)?;
        let token = if t.access_token.is_empty() {
            t.token
        } else {
            t.access_token
        };
        if token.is_empty() {
            return Err(http::Error {
                msg: "authorization server did not include a token in the response".into(),
                transient: false,
            });
        }
        Ok((token, t.expires_in))
    }

    /// Resolve: the descriptor ref names.
    pub fn resolve(&self, r: &Reference) -> Result<Descriptor, Error> {
        let accept = [
            MEDIA_DOCKER_MANIFEST,
            MEDIA_DOCKER_LIST,
            MEDIA_OCI_MANIFEST,
            MEDIA_OCI_INDEX,
            "*/*",
        ]
        .join(", ");
        let digest = r.digest.clone();
        let mut paths: Vec<Vec<String>> = Vec::new();
        match &digest {
            Some(d) => {
                paths.push(vec!["manifests".into(), d.to_string()]);
                paths.push(vec!["blobs".into(), d.to_string()]);
            }
            None => paths.push(vec!["manifests".into(), r.tag.clone()]),
        }
        let mut first: Option<Error> = None;
        let mut priority = 0;
        for parts in &paths {
            if priority > 2 {
                break;
            }
            let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
            let url = self.url(&parts);
            let resp = match self.do_with_retries("HEAD", &url, &accept) {
                Ok(r) => r,
                Err(e) => {
                    let e = if e.msg.contains("authorization failed") {
                        Error::new(format!(
                            "pull access denied, repository does not exist or may require authorization: {}",
                            e.msg
                        ))
                    } else {
                        e
                    };
                    if priority < 1 {
                        first = Some(e);
                        priority = 1;
                    }
                    continue;
                }
            };
            if resp.status > 299 {
                if resp.status == 404 {
                    if priority < 2 {
                        first = Some(Error::not_found(format!("{r}: not found")));
                        priority = 2;
                    }
                    continue;
                }
                if resp.status > 399 {
                    if priority < 3 {
                        first = Some(unexpected(resp, "HEAD"));
                        priority = 3;
                    }
                    continue;
                }
                return Err(unexpected(resp, "HEAD"));
            }
            let mut size = resp.content_length.map(|n| n as i64).unwrap_or(-1);
            let mut media_type = manifest_media_type(&resp);
            let mut dgst = digest.clone();
            if dgst.is_none()
                && let Some(h) = resp
                    .header("docker-content-digest")
                    .filter(|h| !h.is_empty())
                && size != -1
            {
                dgst =
                    Some(Digest::parse(h).map_err(|e| {
                        Error::new(format!("{h:?} in header not a valid digest: {e}"))
                    })?);
            }
            if dgst.is_none() || size == -1 {
                let resp = self.do_with_retries("GET", &url, &accept)?;
                if resp.status >= 400 {
                    return Err(unexpected(resp, "GET"));
                }
                media_type = manifest_media_type(&resp);
                let mut body = resp.body.take(MAX_MANIFEST_SIZE + 1);
                if dgst.is_some() {
                    size = std::io::copy(&mut body, &mut std::io::sink())
                        .map_err(|e| Error::new(e.to_string()))? as i64;
                } else {
                    if media_type == MEDIA_DOCKER_SCHEMA1 {
                        return Err(Error::new(format!(
                            "media type {MEDIA_DOCKER_SCHEMA1:?} is no longer supported, please rebuild the image as {MEDIA_DOCKER_MANIFEST:?} or {MEDIA_OCI_MANIFEST:?}"
                        )));
                    }
                    let mut h = super::digest::Algorithm::Sha256.hasher();
                    size = std::io::copy(&mut body, &mut h)
                        .map_err(|e| Error::new(e.to_string()))? as i64;
                    dgst = Some(h.finish());
                }
            }
            if size as u64 > MAX_MANIFEST_SIZE {
                if priority < 4 {
                    first = Some(Error::not_found(format!(
                        "rejecting {size} byte manifest for {r}: not found"
                    )));
                    priority = 4;
                }
                continue;
            }
            return Ok(Descriptor {
                media_type,
                digest: dgst.expect("set above"),
                size,
                urls: Vec::new(),
                annotations: Default::default(),
                data: None,
                platform: None,
                artifact_type: String::new(),
            });
        }
        Err(first.unwrap_or_else(|| Error::not_found(format!("{r}: not found"))))
    }

    /// Fetch: the content of desc, from the manifests endpoint for
    /// manifests and indexes, else from the blobs endpoint. Layer URLs a
    /// manifest names are ignored.
    pub fn fetch(&self, desc: &Descriptor) -> Result<Box<dyn Read + Send>, Error> {
        if desc.size < 0 {
            return Err(Error::new(format!("invalid descriptor size {}", desc.size)));
        }
        let accept = if desc.media_type.is_empty() {
            "*/*".to_string()
        } else {
            format!("{}, */*", desc.media_type)
        };
        // Layer URLs a manifest names (non-distributable layers) are never
        // fetched, so every blob comes from the registry.
        let endpoint = if is_manifest(&desc.media_type) || is_index(&desc.media_type) {
            "manifests"
        } else {
            "blobs"
        };
        let url = self.url(&[endpoint, &desc.digest.to_string()]);
        let resp = self.do_with_retries("GET", &url, &accept)?;
        if resp.status == 404 {
            let e = Error::not_found(format!(
                "content at {} not found: not found",
                redacted(&resp.url)
            ));
            if endpoint == "blobs" {
                return Err(Error::not_found(format!(
                    "could not fetch content descriptor {} ({}) from remote: not found",
                    desc.digest, desc.media_type
                )));
            }
            return Err(e);
        }
        if resp.status > 299 {
            return Err(unexpected(resp, "GET"));
        }
        if let Some(enc) = resp.header("content-encoding")
            && !enc
                .split([' ', '\t', ','])
                .all(|e| e.is_empty() || e.eq_ignore_ascii_case("identity"))
        {
            // No Accept-Encoding is sent, so a registry must not encode.
            return Err(Error::new(format!(
                "unsupported Content-Encoding algorithm: {enc}"
            )));
        }
        Ok(resp.body)
    }
}

fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(v) => {
                    out.push(v);
                    i += 3;
                    continue;
                }
                Err(_) => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(serde::Deserialize, Default)]
struct TokenResponse {
    #[serde(default)]
    token: String,
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    expires_in: i64,
}

fn read_token(resp: Response) -> Result<TokenResponse, http::Error> {
    let mut b = Vec::new();
    resp.body
        .take(1 << 20)
        .read_to_end(&mut b)
        .map_err(|e| http::Error {
            msg: format!("unable to decode token response: {e}"),
            transient: false,
        })?;
    serde_json::from_slice(&b).map_err(|e| http::Error {
        msg: format!("unable to decode token response: {e}"),
        transient: false,
    })
}

/// getManifestMediaType.
fn manifest_media_type(resp: &Response) -> String {
    let ct = resp.header("content-type").unwrap_or("");
    let ct = ct.split(';').next().unwrap_or("").to_string();
    if ct == "text/plain" {
        MEDIA_DOCKER_SCHEMA1.into()
    } else {
        ct
    }
}

fn redacted(u: &Url) -> String {
    let mut u = u.clone();
    if let Some((base, _)) = u.path.split_once('?') {
        u.path = format!("{base}?REDACTED");
    }
    u.to_string()
}

/// unexpectedResponseErr: the status, and the registry's own errors when
/// its body names them.
fn unexpected(resp: Response, method: &str) -> Error {
    let mut msg = format!(
        "unexpected status from {method} request to {}: {}",
        redacted(&resp.url),
        resp.status_text()
    );
    let mut b = Vec::new();
    let _ = resp.body.take(64000).read_to_end(&mut b);
    #[derive(serde::Deserialize)]
    struct Errs {
        #[serde(default)]
        errors: Vec<Errc>,
    }
    #[derive(serde::Deserialize)]
    struct Errc {
        #[serde(default)]
        code: String,
        #[serde(default)]
        message: String,
    }
    if let Ok(e) = serde_json::from_slice::<Errs>(&b)
        && !e.errors.is_empty()
    {
        let one = |c: &Errc| {
            const KNOWN: &[&str] = &[
                "UNKNOWN",
                "UNSUPPORTED",
                "UNAUTHORIZED",
                "DENIED",
                "UNAVAILABLE",
                "TOOMANYREQUESTS",
                "DIGEST_INVALID",
                "SIZE_INVALID",
                "NAME_INVALID",
                "TAG_INVALID",
                "NAME_UNKNOWN",
                "MANIFEST_UNKNOWN",
                "MANIFEST_INVALID",
                "MANIFEST_UNVERIFIED",
                "MANIFEST_BLOB_UNKNOWN",
                "BLOB_UNKNOWN",
                "BLOB_UPLOAD_UNKNOWN",
                "BLOB_UPLOAD_INVALID",
                "PAGINATION_NUMBER_INVALID",
                "RANGE_INVALID",
            ];
            let code = if KNOWN.contains(&c.code.as_str()) {
                c.code.as_str()
            } else {
                "UNKNOWN"
            };
            format!("{}: {}", code.replace('_', " ").to_lowercase(), c.message)
        };
        let text = if e.errors.len() == 1 {
            one(&e.errors[0])
        } else {
            let mut s = String::from("errors:\n");
            for c in &e.errors {
                s.push_str(&one(c));
                s.push('\n');
            }
            s
        };
        msg.push('\n');
        msg.push_str(&text);
    }
    Error {
        msg,
        not_found: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenges_as_containerd() {
        let c = parse_challenges(&[
            r#"Basic realm="x""#,
            r#"Bearer realm="https://auth.test/token",service="registry.test",scope="repository:a/b:pull repository:c:pull""#,
        ]);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].scheme, Scheme::Bearer);
        assert_eq!(c[0].params["realm"], "https://auth.test/token");
        assert_eq!(
            c[0].params["scope"],
            "repository:a/b:pull repository:c:pull"
        );
        assert_eq!(c[1].scheme, Scheme::Basic);
        let (_, p) = parse_value_and_params(r#"Bearer error="insufficient_scope",x=y"#);
        assert_eq!(p["error"], "insufficient_scope");
        assert_eq!(p["x"], "y");
    }

    #[test]
    fn descriptor_data_round_trips() {
        let d: Descriptor = serde_json::from_str(&format!(
            r#"{{"mediaType":"x","digest":"{}","size":3,"data":"YWJj"}}"#,
            Digest::sha256(b"abc")
        ))
        .unwrap();
        assert_eq!(d.data.as_deref(), Some(&b"abc"[..]));
    }
}

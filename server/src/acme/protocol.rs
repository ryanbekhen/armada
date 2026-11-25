//! An ACME client (RFC 8555), a port of what certmagic uses of acmez's
//! `acme` package: the directory (kept 12 hours per URL), nonces, JWS
//! (ES256 with the account's JWK or key ID), POSTs retried on badNonce and
//! server errors, problems (RFC 7807) with acmez's texts, accounts,
//! orders, authorizations, challenges, finalization with polling, the
//! certificate chain with its "up" and "alternate" links, and renewal
//! information (ARI, RFC 9773). Requests go through armada-node's guarded
//! HTTPS client (no plain HTTP, the machine's roots, the environment's
//! proxy) on blocking threads, each bounded to 30 s as certmagic's
//! HTTPTimeout bounds them.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use armada_node::http::{Client as HttpClient, Request, Url};
use armada_spec::gotime::Time;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::keys::EcKey;
use super::{Cancel, b64url};

/// HTTPTimeout: a request's whole time.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// The largest body read (acmez reads whole bodies; this only bounds a
/// misbehaving server).
const MAX_BODY: u64 = 16 << 20;
/// defaultPollInterval and defaultPollTimeout (certmagic leaves
/// CertObtainTimeout at 0, so the poll timeout is acmez's).
const POLL_INTERVAL: Duration = Duration::from_millis(250);
pub const POLL_TIMEOUT: Duration = Duration::from_secs(300);

pub const PROBLEM_NS: &str = "urn:ietf:params:acme:error:";

/// An error with acmez's wording, and the problem it carries, as
/// errors.As finds one in Go's chain.
#[derive(Clone, Debug)]
pub struct Fail {
    pub msg: String,
    pub problem: Option<Box<Problem>>,
    /// ErrNoRetry: doWithRetry stops at it.
    pub no_retry: bool,
    /// The status of the response the error came with, if any.
    pub status: u16,
}

impl Fail {
    pub fn new(msg: impl Into<String>) -> Fail {
        Fail {
            msg: msg.into(),
            problem: None,
            no_retry: false,
            status: 0,
        }
    }

    /// fmt.Errorf("PREFIX: %w", err).
    pub fn wrap(mut self, prefix: &str) -> Fail {
        self.msg = format!("{prefix}: {}", self.msg);
        self
    }

    /// Any other wrapping of the message.
    pub fn map(mut self, f: impl FnOnce(&str) -> String) -> Fail {
        self.msg = f(&self.msg);
        self
    }

    fn from_problem(p: Problem) -> Fail {
        Fail {
            msg: p.to_string(),
            problem: Some(Box::new(p)),
            no_retry: false,
            status: 0,
        }
    }

    pub fn is(&self, typ: &str) -> bool {
        self.problem
            .as_ref()
            .is_some_and(|p| p.typ == format!("{PROBLEM_NS}{typ}"))
    }
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

/// An identifier (acme.Identifier).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Identifier {
    #[serde(rename = "type", default)]
    pub typ: String,
    #[serde(default)]
    pub value: String,
}

/// A problem document (acme.Problem).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Problem {
    #[serde(rename = "type", default)]
    pub typ: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub status: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub instance: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subproblems: Vec<Subproblem>,
    /// The authorization a failed validation belongs to (Problem.Resource).
    #[serde(skip)]
    pub authz: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Subproblem {
    #[serde(rename = "type", default)]
    pub typ: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub status: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub instance: String,
    #[serde(default)]
    pub identifier: Identifier,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

impl std::fmt::Display for Problem {
    /// Problem.Error.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP {} {} - {}", self.status, self.typ, self.detail)?;
        for v in &self.subproblems {
            write!(
                f,
                ", problem {}: {}",
                armada_spec::go::quote(&v.typ),
                v.detail
            )?;
            if !v.identifier.typ.is_empty() || !v.identifier.value.is_empty() {
                write!(
                    f,
                    " ({}_identifier={})",
                    v.identifier.typ, v.identifier.value
                )?;
            }
        }
        if !self.instance.is_empty() {
            write!(f, ", url: {}", self.instance)?;
        }
        Ok(())
    }
}

/// The directory (acme.Directory).
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Directory {
    #[serde(rename = "newNonce", default)]
    pub new_nonce: String,
    #[serde(rename = "newAccount", default)]
    pub new_account: String,
    #[serde(rename = "newOrder", default)]
    pub new_order: String,
    #[serde(rename = "renewalInfo", default)]
    pub renewal_info: String,
}

/// directories: each directory URL's document, kept 12 hours.
static DIRECTORIES: LazyLock<tokio::sync::Mutex<HashMap<String, (Directory, Instant)>>> =
    LazyLock::new(Default::default);

/// An account (acme.Account). The key is the account's; Location is its
/// URL.
#[derive(Clone, Default)]
pub struct Account {
    pub status: String,
    pub contact: Vec<String>,
    pub terms_agreed: bool,
    pub orders: String,
    pub location: String,
    pub key: Option<Arc<EcKey>>,
}

impl Account {
    /// The account's JSON as encoding/json writes acme.Account, indented
    /// with tabs when `indent` (saveAccount), compact otherwise.
    pub fn to_json(&self, indent: bool) -> Vec<u8> {
        #[derive(Serialize)]
        struct J<'a> {
            #[serde(skip_serializing_if = "str::is_empty")]
            status: &'a str,
            #[serde(skip_serializing_if = "<[String]>::is_empty")]
            contact: &'a [String],
            #[serde(rename = "termsOfServiceAgreed", skip_serializing_if = "is_false")]
            terms: bool,
            #[serde(skip_serializing_if = "str::is_empty")]
            orders: &'a str,
            #[serde(skip_serializing_if = "str::is_empty")]
            location: &'a str,
        }
        let j = J {
            status: &self.status,
            contact: &self.contact,
            terms: self.terms_agreed,
            orders: &self.orders,
            location: &self.location,
        };
        if indent {
            go_indent(&j)
        } else {
            go_marshal(&j)
        }
    }

    /// json.Unmarshal of an account into a, which keeps what the JSON
    /// leaves out.
    pub fn merge(&mut self, v: &Value) {
        if let Some(s) = v.get("status").and_then(Value::as_str) {
            self.status = s.to_string();
        }
        if let Some(c) = v.get("contact") {
            self.contact = c
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
        }
        if let Some(b) = v.get("termsOfServiceAgreed").and_then(Value::as_bool) {
            self.terms_agreed = b;
        }
        if let Some(s) = v.get("orders").and_then(Value::as_str) {
            self.orders = s.to_string();
        }
        if let Some(s) = v.get("location").and_then(Value::as_str) {
            self.location = s.to_string();
        }
    }

    fn key(&self) -> Result<&EcKey, Fail> {
        self.key
            .as_deref()
            .ok_or_else(|| Fail::new("account has no private key"))
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// An order (acme.Order), the fields certmagic reads.
#[derive(Clone, Debug, Default)]
pub struct Order {
    pub status: String,
    pub identifiers: Vec<Identifier>,
    pub replaces: String,
    pub error: Option<Problem>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: String,
    pub location: String,
}

impl Order {
    fn merge(&mut self, v: &Value) {
        if let Some(s) = v.get("status").and_then(Value::as_str) {
            self.status = s.to_string();
        }
        if let Some(ids) = v.get("identifiers") {
            self.identifiers = serde_json::from_value(ids.clone()).unwrap_or_default();
        }
        if let Some(s) = v.get("replaces").and_then(Value::as_str) {
            self.replaces = s.to_string();
        }
        if let Some(e) = v.get("error") {
            self.error = serde_json::from_value(e.clone()).ok();
        }
        if let Some(a) = v.get("authorizations") {
            self.authorizations = serde_json::from_value(a.clone()).unwrap_or_default();
        }
        if let Some(s) = v.get("finalize").and_then(Value::as_str) {
            self.finalize = s.to_string();
        }
        if let Some(s) = v.get("certificate").and_then(Value::as_str) {
            self.certificate = s.to_string();
        }
    }

    /// The new order's payload as encoding/json writes acme.Order: a
    /// zero expiry, no authorizations (null), empty URLs.
    fn payload(&self) -> String {
        let mut s = String::from(r#"{"expires":"0001-01-01T00:00:00Z","identifiers":"#);
        s.push_str(&String::from_utf8_lossy(&go_marshal(&self.identifiers)));
        if !self.replaces.is_empty() {
            s.push_str(r#","replaces":"#);
            s.push_str(&String::from_utf8_lossy(&go_marshal(&self.replaces)));
        }
        s.push_str(r#","authorizations":null,"finalize":"","certificate":""}"#);
        s
    }
}

/// A challenge (acme.Challenge), written to storage as encoding/json
/// writes it for distributed solving.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Challenge {
    #[serde(rename = "type", default)]
    pub typ: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub validated: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Problem>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token: String,
    #[serde(
        rename = "keyAuthorization",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub key_authorization: String,
    #[serde(default)]
    pub identifier: Identifier,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub from: String,
}

impl Challenge {
    /// DNS01KeyAuthorization.
    pub fn dns01_key_authorization(&self) -> String {
        b64url(
            ring::digest::digest(&ring::digest::SHA256, self.key_authorization.as_bytes()).as_ref(),
        )
    }
}

/// An authorization (acme.Authorization).
#[derive(Clone, Debug, Default)]
pub struct Authorization {
    pub identifier: Identifier,
    pub status: String,
    pub challenges: Vec<Challenge>,
    pub wildcard: bool,
    pub location: String,
}

impl Authorization {
    /// IdentifierValue.
    pub fn identifier_value(&self) -> String {
        if self.wildcard {
            format!("*.{}", self.identifier.value)
        } else {
            self.identifier.value.clone()
        }
    }

    fn merge(&mut self, v: &Value) {
        if let Some(i) = v.get("identifier") {
            if let Some(t) = i.get("type").and_then(Value::as_str) {
                self.identifier.typ = t.to_string();
            }
            if let Some(t) = i.get("value").and_then(Value::as_str) {
                self.identifier.value = t.to_string();
            }
        }
        if let Some(s) = v.get("status").and_then(Value::as_str) {
            self.status = s.to_string();
        }
        if let Some(c) = v.get("challenges") {
            self.challenges = serde_json::from_value(c.clone()).unwrap_or_default();
        }
        if let Some(w) = v.get("wildcard").and_then(Value::as_bool) {
            self.wildcard = w;
        }
    }

    /// fillChallengeFields.
    fn fill(&mut self, account: &Account) -> Result<(), Fail> {
        let thumb = account.key()?.thumbprint();
        for c in &mut self.challenges {
            c.identifier = self.identifier.clone();
            if c.key_authorization.is_empty() {
                c.key_authorization = format!("{}.{thumb}", c.token);
            }
        }
        Ok(())
    }
}

/// Renewal information (acme.RenewalInfo) with certmagic's own fields.
#[derive(Clone, Debug, Default)]
pub struct RenewalInfo {
    pub start: Option<Time>,
    pub end: Option<Time>,
    pub explanation_url: String,
    pub unique_identifier: String,
    pub retry_after: Option<Time>,
    pub selected: Option<Time>,
}

fn time_json(t: &Option<Time>) -> String {
    match t {
        Some(t) => t.rfc3339_nano(),
        None => "0001-01-01T00:00:00Z".to_string(),
    }
}

fn parse_time(v: Option<&Value>) -> Option<Time> {
    let t = armada_spec::gotime::parse_rfc3339(v?.as_str()?)?;
    (!t.is_zero()).then_some(t)
}

impl RenewalInfo {
    /// HasWindow.
    pub fn has_window(&self) -> bool {
        self.start.is_some() && self.end.is_some()
    }

    /// NeedsRefresh.
    pub fn needs_refresh(&self, now: &Time) -> bool {
        if !self.has_window() {
            return false;
        }
        match &self.retry_after {
            None => true,
            Some(r) => now.after(r),
        }
    }

    /// SameWindow.
    pub fn same_window(&self, o: &RenewalInfo) -> bool {
        let eq = |a: &Option<Time>, b: &Option<Time>| match (a, b) {
            (None, None) => true,
            (Some(a), Some(b)) => a.unix == b.unix && a.nsec == b.nsec,
            _ => false,
        };
        eq(&self.start, &o.start) && eq(&self.end, &o.end)
    }

    pub fn from_json(v: &Value) -> RenewalInfo {
        let w = v.get("suggestedWindow");
        RenewalInfo {
            start: parse_time(w.and_then(|w| w.get("start"))),
            end: parse_time(w.and_then(|w| w.get("end"))),
            explanation_url: v
                .get("explanationURL")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            unique_identifier: v
                .get("_uniqueIdentifier")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            retry_after: parse_time(v.get("_retryAfter")),
            selected: parse_time(v.get("_selectedTime")),
        }
    }

    /// The JSON encoding/json writes for acme.RenewalInfo.
    pub fn to_json(&self) -> String {
        let mut s = format!(
            r#"{{"suggestedWindow":{{"start":"{}","end":"{}"}}"#,
            time_json(&self.start),
            time_json(&self.end)
        );
        if !self.explanation_url.is_empty() {
            s.push_str(r#","explanationURL":"#);
            s.push_str(&String::from_utf8_lossy(&go_marshal(&self.explanation_url)));
        }
        if !self.unique_identifier.is_empty() {
            s.push_str(r#","_uniqueIdentifier":"#);
            s.push_str(&String::from_utf8_lossy(&go_marshal(
                &self.unique_identifier,
            )));
        }
        if self.retry_after.is_some() {
            s.push_str(&format!(
                r#","_retryAfter":"{}""#,
                time_json(&self.retry_after)
            ));
        }
        s.push_str(&format!(
            r#","_selectedTime":"{}"}}"#,
            time_json(&self.selected)
        ));
        s
    }
}

/// A certificate chain as acme.Certificate (the issuer's metadata).
#[derive(Clone, Debug, Default)]
pub struct CertChain {
    pub url: String,
    pub chain_pem: Vec<u8>,
    pub ca: String,
    pub account: String,
    pub renewal_info: Option<RenewalInfo>,
}

impl CertChain {
    /// json.Marshal of acme.Certificate.
    pub fn metadata_json(&self) -> String {
        let mut s = format!(
            r#"{{"url":{}"#,
            String::from_utf8_lossy(&go_marshal(&self.url))
        );
        if !self.ca.is_empty() {
            s.push_str(r#","ca":"#);
            s.push_str(&String::from_utf8_lossy(&go_marshal(&self.ca)));
        }
        if !self.account.is_empty() {
            s.push_str(r#","account":"#);
            s.push_str(&String::from_utf8_lossy(&go_marshal(&self.account)));
        }
        if let Some(r) = &self.renewal_info {
            s.push_str(r#","renewal_info":"#);
            s.push_str(&r.to_json());
        }
        s.push('}');
        s
    }

    /// json.Unmarshal of the metadata into acme.Certificate.
    pub fn from_metadata(v: &Value) -> CertChain {
        CertChain {
            url: str_of(v, "url"),
            chain_pem: Vec::new(),
            ca: str_of(v, "ca"),
            account: str_of(v, "account"),
            renewal_info: v
                .get("renewal_info")
                .filter(|r| !r.is_null())
                .map(RenewalInfo::from_json),
        }
    }
}

fn str_of(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// encoding/json's Marshal: serde's compact encoding with Go's escapes of
/// <, >, &, U+2028, and U+2029 (which only appear inside strings).
pub fn go_marshal<T: Serialize + ?Sized>(v: &T) -> Vec<u8> {
    go_escape(serde_json::to_vec(v).expect("JSON of plain data"))
}

/// json.MarshalIndent(v, "", "\t").
pub fn go_indent<T: Serialize + ?Sized>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(b"\t");
    let mut ser = serde_json::Serializer::with_formatter(&mut out, fmt);
    v.serialize(&mut ser).expect("JSON of plain data");
    go_escape(out)
}

fn go_escape(b: Vec<u8>) -> Vec<u8> {
    let s = String::from_utf8(b).expect("serde writes UTF-8");
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out.into_bytes()
}

/// A response with its whole body.
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .unwrap_or_default()
    }

    /// parseMediaType.
    fn media_type(&self) -> String {
        let ct = self.header("content-type");
        match ct.find(';') {
            Some(i) => ct[..i].trim().to_string(),
            None => ct.to_string(),
        }
    }

    /// extractLinks.
    fn links(&self, rel: &str) -> Vec<String> {
        let mut out = Vec::new();
        for (k, v) in &self.headers {
            if !k.eq_ignore_ascii_case("link") {
                continue;
            }
            // <(.+?)>;\s*rel="(.+?)", all matches in the value.
            let mut rest = v.as_str();
            while let Some(start) = rest.find('<') {
                let after = &rest[start + 1..];
                let Some(end) = after[1.min(after.len())..].find('>').map(|i| i + 1) else {
                    break;
                };
                let url = &after[..end];
                let tail = &after[end + 1..];
                let Some(t) = tail.strip_prefix(';') else {
                    rest = &after[end..];
                    continue;
                };
                let t = t.trim_start_matches([' ', '\t', '\n', '\r', '\x0c']);
                let Some(t) = t.strip_prefix("rel=\"") else {
                    rest = &after[end..];
                    continue;
                };
                let Some(q) = t[1.min(t.len())..].find('"').map(|i| i + 1) else {
                    break;
                };
                if &t[..q] == rel {
                    out.push(url.to_string());
                }
                rest = &t[q + 1..];
            }
        }
        out
    }
}

/// One HTTP request on a blocking thread, bounded by HTTP_TIMEOUT. The
/// error is Go's client error text ("performing request: ..." is added by
/// the caller).
pub async fn send(
    http: &Arc<HttpClient>,
    method: &str,
    url: &str,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
) -> Result<Resp, String> {
    let u = Url::parse(url).map_err(|e| format!("{} {:?}: {e}", go_op(method), url))?;
    let req = Request {
        method: method.to_string(),
        url: u,
        headers,
        body,
    };
    let http = http.clone();
    let task = tokio::task::spawn_blocking(move || -> Result<Resp, String> {
        use std::io::Read;
        let resp = http.send(&req).map_err(|e| e.msg)?;
        let mut body = Vec::new();
        resp.body
            .take(MAX_BODY)
            .read_to_end(&mut body)
            .map_err(|e| format!("reading response body: {e}"))?;
        Ok(Resp {
            status: resp.status,
            headers: resp.headers,
            body,
        })
    });
    match tokio::time::timeout(HTTP_TIMEOUT, task).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!(
            "{} {:?}: context deadline exceeded (Client.Timeout exceeded while awaiting headers)",
            go_op(method),
            url
        )),
    }
}

fn go_op(method: &str) -> String {
    let lower = method.to_ascii_lowercase();
    let mut c = lower.chars();
    match c.next() {
        Some(f) => f.to_ascii_uppercase().to_string() + c.as_str(),
        None => "Get".into(),
    }
}

/// What a request's body is decoded into.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Want {
    Nothing,
    /// JSON, into the Go type named (for acmez's error).
    Json(&'static str),
    Bytes,
}

/// The decoded body.
enum Out {
    None,
    Json(Value),
    Bytes(Vec<u8>),
}

impl Out {
    fn json(self) -> Value {
        match self {
            Out::Json(v) => v,
            _ => Value::Null,
        }
    }
}

/// acme.Client: one directory, its nonces.
pub struct Client {
    pub directory: String,
    http: Arc<HttpClient>,
    dir: tokio::sync::Mutex<Option<Directory>>,
    nonces: Mutex<Vec<String>>,
    /// The caller's cancellation: waits end at it and no request starts
    /// after it ("context canceled").
    cancel: Cancel,
}

impl Client {
    pub(crate) fn new(directory: &str, http: Arc<HttpClient>, cancel: Cancel) -> Client {
        Client {
            directory: directory.to_string(),
            http,
            dir: tokio::sync::Mutex::new(None),
            nonces: Mutex::new(Vec::new()),
            cancel,
        }
    }

    /// provision: the directory, from the 12-hour cache or the server.
    pub async fn provision(&self) -> Result<Directory, Fail> {
        let mut mine = self.dir.lock().await;
        if let Some(d) = &*mine
            && !d.new_nonce.is_empty()
        {
            return Ok(d.clone());
        }
        let mut cache = DIRECTORIES.lock().await;
        if let Some((d, at)) = cache.get(&self.directory)
            && at.elapsed() < Duration::from_secs(12 * 3600)
        {
            *mine = Some(d.clone());
            return Ok(d.clone());
        }
        let (_, out) = self
            .http_req(
                "GET",
                &self.directory,
                None,
                Want::Json("*acme.Directory"),
                "",
            )
            .await
            .map_err(|e| e.wrap("provisioning client"))?;
        let d: Directory = serde_json::from_value(out.json()).unwrap_or_default();
        if d.new_order.is_empty() {
            return Err(Fail::new(format!(
                "provisioning client: server did not return error headers, but required directory fields are missing: {d:?}"
            )));
        }
        cache.insert(self.directory.clone(), (d.clone(), Instant::now()));
        *mine = Some(d.clone());
        Ok(d)
    }

    fn push_nonce(&self, n: &str) {
        if n.is_empty() {
            return;
        }
        let mut s = self.nonces.lock().unwrap_or_else(|p| p.into_inner());
        if s.len() < 64 {
            s.push(n.to_string());
        }
    }

    async fn nonce(&self, dir: &Directory) -> Result<String, Fail> {
        if let Some(n) = self.nonces.lock().unwrap_or_else(|p| p.into_inner()).pop() {
            return Ok(n);
        }
        if dir.new_nonce.is_empty() {
            return Err(Fail::new("directory missing newNonce endpoint"));
        }
        let (resp, _) = self
            .http_req("HEAD", &dir.new_nonce, None, Want::Nothing, &dir.new_nonce)
            .await
            .map_err(|e| e.wrap("fetching new nonce from server"))?;
        Ok(resp.header("replay-nonce").to_string())
    }

    /// httpReq: up to 3 tries of a request that failed in transport, or a
    /// GET answered with a server error problem.
    async fn http_req(
        &self,
        method: &str,
        url: &str,
        jose: Option<Vec<u8>>,
        want: Want,
        new_nonce: &str,
    ) -> Result<(Resp, Out), Fail> {
        let mut last: Option<(Option<Resp>, Fail)> = None;
        for attempt in 0..3 {
            if attempt > 0 {
                self.cancel.sleep(Duration::from_millis(250)).await?;
            }
            self.cancel.check()?;
            let mut headers = Vec::new();
            if jose.as_ref().is_some_and(|b| !b.is_empty()) {
                headers.push((
                    "Content-Type".to_string(),
                    "application/jose+json".to_string(),
                ));
            }
            let resp = match send(&self.http, method, url, headers, jose.clone()).await {
                Ok(r) => r,
                Err(e) => {
                    last = Some((None, Fail::new(format!("performing request: {e}"))));
                    continue;
                }
            };
            if method != "HEAD" || url != new_nonce {
                self.push_nonce(resp.header("replay-nonce"));
            }
            match resp.status {
                200..=299 => {}
                400..=599 => {
                    let body = String::from_utf8_lossy(&resp.body).into_owned();
                    if resp.media_type() == "application/problem+json" {
                        let mut p: Problem = match serde_json::from_slice(&resp.body) {
                            Ok(p) => p,
                            Err(e) => {
                                return Err(Fail::new(format!(
                                    "HTTP {}: JSON-decoding problem details: {e} (raw='{body}')",
                                    resp.status
                                )));
                            }
                        };
                        if resp.status >= 500 && jose.is_none() {
                            let status = resp.status;
                            let mut f = Fail::from_problem(p);
                            f.status = status;
                            last = Some((Some(resp), f));
                            continue;
                        }
                        if p.status == 0 {
                            p.status = i64::from(resp.status);
                        }
                        return Err(with_resp(Fail::from_problem(p), resp));
                    }
                    let status = resp.status;
                    return Err(with_resp(Fail::new(format!("HTTP {status}: {body}")), resp));
                }
                s => {
                    return Err(with_resp(
                        Fail::new(format!("unexpected status code: HTTP {s}")),
                        resp,
                    ));
                }
            }
            let out = match want {
                Want::Nothing => Out::None,
                Want::Json(go_type) => {
                    let ct = resp.media_type();
                    if ct != "application/json" {
                        return Err(with_resp(
                            Fail::new(format!(
                                "response Content-Type is {ct} but target container is not io.Writer: {go_type}"
                            )),
                            resp,
                        ));
                    }
                    match serde_json::from_slice::<Value>(&resp.body) {
                        Ok(v) => Out::Json(v),
                        Err(e) => {
                            return Err(with_resp(
                                Fail::new(format!("JSON-decoding response body: {e}")),
                                resp,
                            ));
                        }
                    }
                }
                Want::Bytes => {
                    if resp.media_type() == "application/json" {
                        return Err(with_resp(
                            Fail::new(
                                "JSON-decoding response body: json: Unmarshal(non-pointer bytes.Buffer)",
                            ),
                            resp,
                        ));
                    }
                    Out::Bytes(resp.body.clone())
                }
            };
            return Ok((resp, out));
        }
        let (_, f) = last.expect("three tries");
        Err(f)
    }

    /// httpPostJWS: a POST signed with key, retried on badNonce (10 tries)
    /// and on server errors (3).
    async fn post_jws(
        &self,
        key: &EcKey,
        kid: &str,
        url: &str,
        payload: Option<&str>,
        want: Want,
    ) -> Result<(Resp, Out), Fail> {
        let dir = self.provision().await?;
        let mut server_errors = 0;
        let mut attempts = 1;
        let mut last = Fail::new("no attempt");
        while attempts <= 10 {
            if attempts > 1 {
                self.cancel.sleep(Duration::from_millis(250)).await?;
            }
            let nonce = self.nonce(&dir).await?;
            let body = jws(key, kid, &nonce, url, payload)
                .map_err(|e| Fail::new(format!("encoding payload: {e}")))?;
            match self
                .http_req("POST", url, Some(body), want, &dir.new_nonce)
                .await
            {
                Ok(r) => return Ok(r),
                Err(f) => {
                    let status = f.status;
                    last = f;
                    if last.is("badNonce") {
                        attempts += 1;
                        continue;
                    }
                    if status >= 500 {
                        server_errors += 1;
                        if server_errors < 3 {
                            attempts += 1;
                            continue;
                        }
                    }
                    break;
                }
            }
        }
        let n = attempts.min(11);
        Err(last.map(|m| format!("attempt {n}: {url}: {m}")))
    }

    /// NewAccount.
    pub async fn new_account(&self, account: &Account) -> Result<Account, Fail> {
        let dir = self.provision().await?;
        let key = account.key()?;
        let payload = String::from_utf8_lossy(&account.to_json(false)).into_owned();
        let (resp, out) = self
            .post_jws(
                key,
                "",
                &dir.new_account,
                Some(&payload),
                Want::Json("*acme.Account"),
            )
            .await?;
        let mut a = account.clone();
        a.merge(&out.json());
        a.location = resp.header("location").to_string();
        Ok(a)
    }

    /// NewOrder.
    pub async fn new_order(&self, account: &Account, order: &Order) -> Result<Order, Fail> {
        let dir = self.provision().await?;
        let (resp, out) = self
            .post_jws(
                account.key()?,
                &account.location,
                &dir.new_order,
                Some(&order.payload()),
                Want::Json("*acme.Order"),
            )
            .await?;
        let mut o = order.clone();
        o.merge(&out.json());
        o.location = resp.header("location").to_string();
        Ok(o)
    }

    /// GetAuthorization.
    pub async fn get_authorization(
        &self,
        account: &Account,
        url: &str,
    ) -> Result<Authorization, Fail> {
        let (_, out) = self
            .post_jws(
                account.key()?,
                &account.location,
                url,
                None,
                Want::Json("*acme.Authorization"),
            )
            .await?;
        let mut a = Authorization::default();
        a.merge(&out.json());
        a.location = url.to_string();
        a.fill(account)?;
        Ok(a)
    }

    /// PollAuthorization.
    pub async fn poll_authorization(
        &self,
        account: &Account,
        authz: &mut Authorization,
    ) -> Result<(), Fail> {
        let start = Instant::now();
        let mut interval = POLL_INTERVAL;
        if !authz.status.is_empty()
            && let (true, r) = authz_finalized(authz)
        {
            return r;
        }
        while start.elapsed() < POLL_TIMEOUT {
            self.cancel.sleep(interval).await?;
            let (resp, out) = self
                .post_jws(
                    account.key()?,
                    &account.location,
                    &authz.location.clone(),
                    None,
                    Want::Json("*acme.Authorization"),
                )
                .await
                .map_err(|e| e.wrap("checking authorization status"))?;
            authz.merge(&out.json());
            if let (true, r) = authz_finalized(authz) {
                return r;
            }
            interval = retry_after(&resp, interval)?;
        }
        Err(Fail::new("authorization took too long"))
    }

    /// DeactivateAuthorization.
    pub async fn deactivate_authorization(&self, account: &Account, url: &str) -> Result<(), Fail> {
        if url.is_empty() {
            return Err(Fail::new("empty authz url"));
        }
        self.post_jws(
            account.key()?,
            &account.location,
            url,
            Some(r#"{"status":"deactivated"}"#),
            Want::Json("*acme.Authorization"),
        )
        .await
        .map(|_| ())
    }

    /// InitiateChallenge with an empty payload.
    pub async fn initiate_challenge(
        &self,
        account: &Account,
        chal: &Challenge,
    ) -> Result<(), Fail> {
        self.post_jws(
            account.key()?,
            &account.location,
            &chal.url,
            Some("{}"),
            Want::Json("*acme.Challenge"),
        )
        .await
        .map(|_| ())
    }

    /// FinalizeOrder: the CSR, then polling until the order is finished.
    pub async fn finalize_order(
        &self,
        account: &Account,
        order: &mut Order,
        csr: &[u8],
    ) -> Result<(), Fail> {
        let payload = format!(r#"{{"csr":"{}"}}"#, b64url(csr));
        let key = account.key()?;
        let mut resp = match self
            .post_jws(
                key,
                &account.location,
                &order.finalize.clone(),
                Some(&payload),
                Want::Json("*acme.Order"),
            )
            .await
        {
            Ok((resp, out)) => {
                order.merge(&out.json());
                Some(resp)
            }
            Err(f) if f.is("orderNotReady") => None,
            Err(f) => return Err(f),
        };
        if let Some(r) = &resp {
            let loc = r.header("location");
            if !loc.is_empty() {
                order.location = loc.to_string();
            }
        }
        if let (true, r) = order_finished(order) {
            return r;
        }
        let start = Instant::now();
        while start.elapsed() < POLL_TIMEOUT {
            let interval = match &resp {
                Some(r) => retry_after(r, POLL_INTERVAL)?,
                None => POLL_INTERVAL,
            };
            self.cancel.sleep(interval).await?;
            let (r, out) = self
                .post_jws(
                    key,
                    &account.location,
                    &order.location.clone(),
                    None,
                    Want::Json("*acme.Order"),
                )
                .await
                .map_err(|e| e.wrap("polling order status"))?;
            order.merge(&out.json());
            let loc = r.header("location");
            if !loc.is_empty() {
                order.location = loc.to_string();
            }
            resp = Some(r);
            if let (true, res) = order_finished(order) {
                return res;
            }
        }
        Err(Fail::new("order took too long"))
    }

    /// GetCertificateChain: the chain at url and its alternates.
    pub async fn get_certificate_chain(
        &self,
        account: &Account,
        url: &str,
    ) -> Result<Vec<CertChain>, Fail> {
        let mut chains = Vec::new();
        let resp = self.add_chain(account, url, &mut chains).await?;
        for alt in resp.links("alternate") {
            let before = chains.len();
            if self.add_chain(account, &alt, &mut chains).await.is_err() {
                chains.truncate(before);
            }
        }
        Ok(chains)
    }

    fn add_chain<'a>(
        &'a self,
        account: &'a Account,
        url: &'a str,
        chains: &'a mut Vec<CertChain>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Resp, Fail>> + Send + 'a>> {
        Box::pin(async move {
            let dir = self.provision().await?;
            let (resp, out) = self
                .post_jws(account.key()?, &account.location, url, None, Want::Bytes)
                .await?;
            let ct = resp.media_type();
            if ct != "application/pem-certificate-chain" {
                return Err(Fail::new(format!(
                    "unrecognized Content-Type from server: {ct}"
                )));
            }
            let chain_pem = match out {
                Out::Bytes(b) => b,
                _ => Vec::new(),
            };
            let mut chain = CertChain {
                url: url.to_string(),
                chain_pem,
                ca: self.directory.clone(),
                account: account.location.clone(),
                renewal_info: None,
            };
            if !dir.renewal_info.is_empty()
                && let Some(block) = armada_pki::encoding::pem_decode(&chain.chain_pem)
                && block.kind == "CERTIFICATE"
            {
                let leaf = Leaf::parse(&block.bytes)
                    .map_err(|e| Fail::new(format!("invalid first PEM block of chain: {e}")))?;
                let ari = self.get_renewal_info(&leaf).await.unwrap_or_default();
                chain.renewal_info = Some(ari);
            }
            chains.push(chain);
            for up in resp.links("up") {
                let mut ups = Vec::new();
                self.add_chain_up(account, &up, &mut ups)
                    .await
                    .map_err(|e| {
                        e.map(|m| format!("retrieving next certificate in chain: {up}: {m}"))
                    })?;
                let last = chains.len() - 1;
                for u in ups {
                    chains[last].chain_pem.extend_from_slice(&u.chain_pem);
                }
            }
            Ok(resp)
        })
    }

    /// GetCertificateChain of an "up" link (alternates included, as acmez
    /// recurses through the whole call).
    async fn add_chain_up(
        &self,
        account: &Account,
        url: &str,
        out: &mut Vec<CertChain>,
    ) -> Result<(), Fail> {
        let got = self.get_certificate_chain(account, url).await?;
        out.extend(got);
        Ok(())
    }

    /// GetRenewalInfo.
    pub async fn get_renewal_info(&self, leaf: &Leaf) -> Result<RenewalInfo, Fail> {
        let dir = self.provision().await?;
        if dir.renewal_info.is_empty() {
            return Err(Fail::new(
                "unsupported by ACME server: directory does not indicate ARI support (missing renewalInfo)",
            ));
        }
        let cert_id = leaf.ari_id()?;
        let url = format!("{}/{cert_id}", dir.renewal_info);
        let mut last_err: Option<Fail> = None;
        let mut got: Option<(Resp, RenewalInfo)> = None;
        let mut have_window = false;
        let mut ari = RenewalInfo::default();
        for i in 0..3u64 {
            if i > 0 {
                self.cancel.sleep(Duration::from_secs(i * i + 1)).await?;
            }
            match self
                .http_req("GET", &url, None, Want::Json("*acme.RenewalInfo"), "")
                .await
            {
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
                Ok((resp, out)) => {
                    last_err = None;
                    ari = RenewalInfo::from_json(&out.json());
                    let bad = match (&ari.start, &ari.end) {
                        (Some(s), Some(e)) => {
                            (s.unix == e.unix && s.nsec == e.nsec) || e.unix - s.unix - 1 <= 0
                        }
                        _ => true,
                    };
                    got = Some((resp, ari.clone()));
                    if bad {
                        continue;
                    }
                    ari.unique_identifier = cert_id.clone();
                    have_window = true;
                    break;
                }
            }
        }
        let resp = match (last_err, got) {
            (None, Some((resp, _))) => resp,
            (e, _) => {
                return Err(Fail::new(format!(
                    "could not get a valid ARI response; last error: {}",
                    e.map(|e| e.msg).unwrap_or_else(|| "<nil>".to_string())
                )));
            }
        };
        if !have_window {
            return Err(Fail::new(format!(
                "server did not return a usable ARI window in 3 attempts; last window: {} to {}",
                go_time_string(&ari.start),
                go_time_string(&ari.end)
            )));
        }
        if let Some(t) = retry_after_time(&resp) {
            ari.retry_after = Some(t);
        }
        let start = ari.start.as_ref().map(|t| t.unix + 1).unwrap_or(1);
        let end = ari.end.as_ref().map(|t| t.unix).unwrap_or(0);
        let utc = armada_spec::gotime::Location::utc();
        let at = |s: i64| Time {
            unix: s,
            nsec: 0,
            loc: utc.clone(),
        };
        if end > start {
            ari.selected = Some(at(random_below((end - start) as u64) as i64 + start));
        } else if start > 0 {
            ari.selected = Some(at(start));
        } else if end > 0 {
            ari.selected = Some(at(end));
        }
        Ok(ari)
    }
}

/// time.Time.String for the ARI error.
fn go_time_string(t: &Option<Time>) -> String {
    match t {
        None => "0001-01-01 00:00:00 +0000 UTC".to_string(),
        Some(t) => {
            let c = t.civil();
            let off = t.loc.offset(t.unix);
            let sign = if off < 0 { '-' } else { '+' };
            let a = off.abs();
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02} {sign}{:02}{:02} {}",
                c.year,
                c.month,
                c.day,
                c.hour,
                c.minute,
                c.second,
                a / 3600,
                a % 3600 / 60,
                t.loc.name()
            )
        }
    }
}

/// A uniform random number in [0, n).
pub fn random_below(n: u64) -> u64 {
    use ring::rand::SecureRandom;
    if n == 0 {
        return 0;
    }
    let zone = u64::MAX - u64::MAX % n;
    loop {
        let mut b = [0u8; 8];
        ring::rand::SystemRandom::new()
            .fill(&mut b)
            .expect("the system's random source");
        let v = u64::from_be_bytes(b);
        if v < zone {
            return v % n;
        }
    }
}

/// The error with the status of the response it came with (httpPostJWS
/// reads resp.StatusCode beside the error).
fn with_resp(mut f: Fail, resp: Resp) -> Fail {
    f.status = resp.status;
    f
}

/// jwsEncodeJSON: the flattened JWS of payload ("" for POST-as-GET).
fn jws(
    key: &EcKey,
    kid: &str,
    nonce: &str,
    url: &str,
    payload: Option<&str>,
) -> Result<Vec<u8>, String> {
    let q = |s: &str| armada_spec::go::quote(s);
    let mut head = r#"{"alg":"ES256""#.to_string();
    if kid.is_empty() {
        head.push_str(&format!(r#","jwk":{}"#, key.jwk()));
    } else {
        head.push_str(&format!(r#","kid":{}"#, q(kid)));
    }
    if !nonce.is_empty() {
        head.push_str(&format!(r#","nonce":{}"#, q(nonce)));
    }
    head.push_str(&format!(r#","url":{}}}"#, q(url)));
    let phead = b64url(head.as_bytes());
    let payload = payload.map(|p| b64url(p.as_bytes())).unwrap_or_default();
    let sig = key.sign(format!("{phead}.{payload}").as_bytes())?;
    Ok(format!(
        r#"{{"protected":"{phead}","payload":"{payload}","signature":"{}"}}"#,
        b64url(&sig)
    )
    .into_bytes())
}

/// authzIsFinalized: (finished, its outcome).
fn authz_finalized(a: &Authorization) -> (bool, Result<(), Fail>) {
    match a.status.as_str() {
        "pending" => (false, Ok(())),
        "valid" => (true, Ok(())),
        "invalid" => {
            let mut p = a
                .challenges
                .iter()
                .find_map(|c| c.error.clone())
                .unwrap_or_default();
            p.authz = Some(a.identifier_value());
            let mut f = Fail::from_problem(p);
            f.msg = format!("authorization failed: {}", f.msg);
            (true, Err(f))
        }
        "expired" | "deactivated" | "revoked" => {
            (true, Err(Fail::new(format!("authorization {}", a.status))))
        }
        "" => (false, Err(Fail::new("status unknown"))),
        s => (
            true,
            Err(Fail::new(format!(
                "server set unrecognized authorization status: {s}"
            ))),
        ),
    }
}

/// orderIsFinished.
fn order_finished(o: &Order) -> (bool, Result<(), Fail>) {
    match o.status.as_str() {
        "invalid" => {
            let p = o
                .error
                .as_ref()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "%!w(*acme.Problem=<nil>)".to_string());
            (
                true,
                Err(Fail {
                    msg: format!("final order is invalid: {p}"),
                    problem: o.error.clone().map(Box::new),
                    no_retry: false,
                    status: 0,
                }),
            )
        }
        "pending" => (
            true,
            Err(Fail::new(format!(
                "order pending, authorizations remaining: [{}]",
                o.authorizations.join(" ")
            ))),
        ),
        "ready" => (
            true,
            Err(Fail::new(
                "unexpected state: ready - order already finalized",
            )),
        ),
        "processing" => (false, Ok(())),
        "valid" => (true, Ok(())),
        s => (
            true,
            Err(Fail::new(format!("unrecognized order status: {s}"))),
        ),
    }
}

/// retryAfter: how long the response asks to wait, else fallback.
fn retry_after(resp: &Resp, fallback: Duration) -> Result<Duration, Fail> {
    let h = resp.header("retry-after");
    if h.is_empty() {
        return Ok(fallback);
    }
    match retry_after_time(resp) {
        Some(t) => {
            let now = armada_store::gojson::now();
            let ns = (t.unix - now.unix) as i128 * 1_000_000_000 + (t.nsec - now.nsec) as i128;
            Ok(Duration::from_nanos(ns.max(0) as u64))
        }
        None => Err(Fail::new(format!(
            "response had invalid Retry-After header: parsing time {:?} as \"Mon, 02 Jan 2006 15:04:05 GMT\": cannot parse",
            h
        ))),
    }
}

/// retryAfterTime: seconds from now, or an HTTP date.
fn retry_after_time(resp: &Resp) -> Option<Time> {
    let h = resp.header("retry-after");
    if h.is_empty() {
        return None;
    }
    if let Ok(secs) = h.parse::<i64>()
        && secs >= 0
    {
        return Some(armada_store::gojson::now().add(secs * 1_000_000_000));
    }
    parse_http_date(h)
}

/// time.Parse(http.TimeFormat, s): "Mon, 02 Jan 2006 15:04:05 GMT".
fn parse_http_date(s: &str) -> Option<Time> {
    let rest = s.get(5..)?;
    let parts: Vec<&str> = rest.split(' ').collect();
    if parts.len() != 5 || parts[4] != "GMT" {
        return None;
    }
    let day: i64 = parts[0].parse().ok()?;
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| *m == parts[1])? as i64
        + 1;
    let year: i64 = parts[2].parse().ok()?;
    let hms: Vec<i64> = parts[3]
        .split(':')
        .map(|x| x.parse().ok())
        .collect::<Option<_>>()?;
    if hms.len() != 3 {
        return None;
    }
    Some(Time::date(
        year,
        month,
        day,
        hms[0],
        hms[1],
        hms[2],
        0,
        &armada_spec::gotime::Location::utc(),
    ))
}

/// What certmagic reads of a leaf certificate.
#[derive(Clone, Debug)]
pub struct Leaf {
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    pub serial: Vec<u8>,
    pub aki: Vec<u8>,
    pub dns_names: Vec<String>,
}

impl Leaf {
    pub fn parse(der: &[u8]) -> Result<Leaf, String> {
        use x509_parser::extensions::{GeneralName, ParsedExtension};
        let (_, c) = x509_parser::parse_x509_certificate(der).map_err(|e| e.to_string())?;
        let mut aki = Vec::new();
        let mut dns_names = Vec::new();
        for ext in c.extensions() {
            match ext.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(a) => {
                    if let Some(k) = &a.key_identifier {
                        aki = k.0.to_vec();
                    }
                }
                ParsedExtension::SubjectAlternativeName(san) => {
                    for n in &san.general_names {
                        if let GeneralName::DNSName(d) = n {
                            dns_names.push(d.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(Leaf {
            not_before: c.validity().not_before.timestamp(),
            not_after: c.validity().not_after.timestamp(),
            serial: c.raw_serial().to_vec(),
            aki,
            dns_names,
        })
    }

    /// parseCertsFromPEMBundle's first certificate.
    pub fn from_bundle(pem: &[u8]) -> Result<Leaf, String> {
        let mut rest = pem;
        loop {
            let Some(b) = armada_pki::encoding::pem_decode(rest) else {
                return Err("no certificates found in bundle".to_string());
            };
            if b.kind == "CERTIFICATE" {
                return Leaf::parse(&b.bytes);
            }
            // pem_decode found a block: skip past its END line.
            let marker = format!("-----END {}-----", b.kind);
            let pos = rest
                .windows(marker.len())
                .position(|w| w == marker.as_bytes())
                .ok_or_else(|| "no certificates found in bundle".to_string())?;
            rest = &rest[pos + marker.len()..];
        }
    }

    /// ARIUniqueIdentifier.
    pub fn ari_id(&self) -> Result<String, Fail> {
        if self.serial.is_empty() {
            return Err(Fail::new("no serial number"));
        }
        Ok(format!("{}.{}", b64url(&self.aki), b64url(&self.serial)))
    }

    /// expiresAt: NotAfter plus the second its encoding cannot show.
    pub fn expires(&self) -> i64 {
        self.not_after + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problems_read_as_acmez_writes_them() {
        let p: Problem = serde_json::from_str(
            r#"{"type":"urn:ietf:params:acme:error:rejectedIdentifier","detail":"no","status":400,
            "subproblems":[{"type":"urn:ietf:params:acme:error:caa","detail":"caa","identifier":{"type":"dns","value":"a.test"}}]}"#,
        )
        .unwrap();
        assert_eq!(
            p.to_string(),
            "HTTP 400 urn:ietf:params:acme:error:rejectedIdentifier - no, problem \"urn:ietf:params:acme:error:caa\": caa (dns_identifier=a.test)"
        );
    }

    #[test]
    fn link_headers() {
        let r = Resp {
            status: 200,
            headers: vec![(
                "Link".into(),
                r#"<https://a/up>;rel="up", <https://a/alt/1>; rel="alternate""#.into(),
            )],
            body: Vec::new(),
        };
        assert_eq!(r.links("up"), vec!["https://a/up".to_string()]);
        assert_eq!(r.links("alternate"), vec!["https://a/alt/1".to_string()]);
    }

    #[test]
    fn orders_as_encoding_json_writes_them() {
        let o = Order {
            identifiers: vec![Identifier {
                typ: "dns".into(),
                value: "a.test".into(),
            }],
            ..Default::default()
        };
        assert_eq!(
            o.payload(),
            r#"{"expires":"0001-01-01T00:00:00Z","identifiers":[{"type":"dns","value":"a.test"}],"authorizations":null,"finalize":"","certificate":""}"#
        );
        let ri = RenewalInfo::default();
        assert_eq!(
            ri.to_json(),
            r#"{"suggestedWindow":{"start":"0001-01-01T00:00:00Z","end":"0001-01-01T00:00:00Z"},"_selectedTime":"0001-01-01T00:00:00Z"}"#
        );
        assert_eq!(
            String::from_utf8(go_marshal("a<b&")).unwrap(),
            "\"a\\u003cb\\u0026\""
        );
    }
}

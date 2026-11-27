//! Notices about cluster events to people (ADR 0045): a JSON webhook,
//! Slack, Discord, Telegram, or email over SMTP. Requests go out on a small
//! HTTP/1.1 client and SMTP client of this module (no redirects followed,
//! errors never holding the channel's secret).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use armada_node::net::addr::Addr;
use armada_spec::gotime::Time;
use serde::{Deserialize, Serialize};

/// Channel types.
pub const WEBHOOK: &str = "webhook";
pub const SLACK: &str = "slack";
pub const DISCORD: &str = "discord";
pub const TELEGRAM: &str = "telegram";
pub const EMAIL: &str = "email";
const TYPES: [&str; 5] = [WEBHOOK, SLACK, DISCORD, TELEGRAM, EMAIL];

/// MaxChannels bounds the channels of a cluster.
pub const MAX_CHANNELS: usize = 32;
/// MaxSecret bounds a URL, token, or password.
pub const MAX_SECRET: usize = 4096;
const MAX_RECIPIENTS: usize = 10;
const MAX_FILTERS: usize = 64;
pub const SEND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REPLY: usize = 256;
const DISCORD_MAX: usize = 2000;
const TELEGRAM_MAX: usize = 4096;

/// TelegramAPI: the Bot API's address.
pub const TELEGRAM_API: &str = "https://api.telegram.org";

/// Notice kinds.
pub const KIND_EVENT: &str = "event";
pub const KIND_RESOLVED: &str = "resolved";
pub const KIND_TEST: &str = "test";
pub const KIND_SUMMARY: &str = "summary";

/// Where notices go. Secret is the URL (webhook, slack, discord), the bot
/// token (telegram), or the SMTP password (email); never logged or shown,
/// and never stored with the channel (it is sealed beside it).
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Channel {
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty", rename = "chatId")]
    pub chat_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty", rename = "smtpHost")]
    pub smtp_host: String,
    #[serde(default, skip_serializing_if = "String::is_empty", rename = "smtpUser")]
    pub smtp_user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub from: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    #[serde(skip)]
    pub secret: Vec<u8>,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.kind)
    }
}

/// `^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`, or with `max` for spaces.
fn valid_label(s: &str, max: usize) -> bool {
    let b = s.as_bytes();
    let al = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    !b.is_empty()
        && b.len() <= max
        && al(&b[0])
        && al(&b[b.len() - 1])
        && b.iter().all(|c| al(c) || *c == b'-')
}

/// `^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`.
fn valid_chat_id(s: &str) -> bool {
    if let Some(rest) = s.strip_prefix('@') {
        let b = rest.as_bytes();
        return (5..=32).contains(&b.len())
            && b[0].is_ascii_alphabetic()
            && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_');
    }
    let d = s.strip_prefix('-').unwrap_or(s);
    (1..=20).contains(&d.len()) && d.bytes().all(|c| c.is_ascii_digit())
}

/// `^[A-Za-z]{1,64}$`.
fn valid_reason(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphabetic())
}

/// `^[0-9]{1,20}:[A-Za-z0-9_-]{20,200}$`.
fn valid_bot_key(s: &[u8]) -> bool {
    let Some(i) = s.iter().position(|c| *c == b':') else {
        return false;
    };
    let (id, key) = (&s[..i], &s[i + 1..]);
    (1..=20).contains(&id.len())
        && id.iter().all(u8::is_ascii_digit)
        && (20..=200).contains(&key.len())
        && key
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-')
}

/// CheckName validates a channel name.
pub fn check_name(n: &str) -> Result<(), String> {
    if !valid_label(n, 32) {
        return Err(format!(
            "invalid channel name {}: lower case letters, digits, and dashes, at most 32",
            armada_spec::go::quote(n)
        ));
    }
    Ok(())
}

impl Channel {
    /// NeedsSecret: whether the type cannot work without one.
    pub fn needs_secret(&self) -> bool {
        self.kind != EMAIL
    }

    /// Check validates everything but the secret's presence.
    pub fn check(&self) -> Result<(), String> {
        check_name(&self.name)?;
        if !TYPES.contains(&self.kind.as_str()) {
            return Err(format!(
                "unknown channel type {} (want {})",
                armada_spec::go::quote(&self.kind),
                TYPES.join(", ")
            ));
        }
        if self.kind != TELEGRAM && !self.chat_id.is_empty() {
            return Err("--chat-id is only for telegram".into());
        }
        if self.kind != EMAIL
            && (!self.smtp_host.is_empty()
                || !self.smtp_user.is_empty()
                || !self.from.is_empty()
                || !self.to.is_empty())
        {
            return Err("--smtp-host, --smtp-user, --from, and --to are only for email".into());
        }
        match self.kind.as_str() {
            TELEGRAM if !valid_chat_id(&self.chat_id) => {
                return Err(
                    "telegram needs --chat-id: a chat ID such as -1001234567890, or @channelname"
                        .into(),
                );
            }
            EMAIL => {
                check_smtp_host(&self.smtp_host)?;
                check_printable("SMTP user", &self.smtp_user, 254)?;
                check_address(&self.from).map_err(|e| format!("--from: {e}"))?;
                if self.to.is_empty() || self.to.len() > MAX_RECIPIENTS {
                    return Err(format!("email needs --to: 1 to {MAX_RECIPIENTS} addresses"));
                }
                for a in &self.to {
                    check_address(a).map_err(|e| format!("--to: {e}"))?;
                }
            }
            _ => {}
        }
        if self.spaces.len() > MAX_FILTERS || self.reasons.len() > MAX_FILTERS {
            return Err(format!(
                "at most {MAX_FILTERS} spaces and {MAX_FILTERS} reasons"
            ));
        }
        for s in &self.spaces {
            if !valid_label(s, 30) {
                return Err(format!("invalid space {}", armada_spec::go::quote(s)));
            }
        }
        for r in &self.reasons {
            if !valid_reason(r) {
                return Err(format!("invalid reason {}", armada_spec::go::quote(r)));
            }
        }
        Ok(())
    }

    /// CheckSecret validates the secret for the channel's type. Errors
    /// never repeat it.
    pub fn check_secret(&self, secret: &[u8]) -> Result<(), String> {
        if secret.len() > MAX_SECRET {
            return Err(format!("secret is longer than {MAX_SECRET} bytes"));
        }
        let text = std::str::from_utf8(secret);
        if text.is_err() || secret.iter().any(|b| *b < 0x20 || *b == 0x7f) {
            return Err("secret must be one line of printable characters".into());
        }
        if secret.is_empty() {
            if self.needs_secret() {
                return Err(format!(
                    "{} needs {} from a file or stdin (--{} -)",
                    self.kind,
                    secret_what(&self.kind),
                    secret_flag(&self.kind)
                ));
            }
            return Ok(());
        }
        match self.kind.as_str() {
            WEBHOOK | SLACK | DISCORD => check_url(text.unwrap_or_default()),
            TELEGRAM if !valid_bot_key(secret) => {
                Err("telegram bot token must look like 123456:ABC-DEF".into())
            }
            _ => Ok(()),
        }
    }

    /// Wants: whether the channel takes a notice about reason in space
    /// ("" for events with no app).
    pub fn wants(&self, reason: &str, space: &str) -> bool {
        if !self.spaces.is_empty() && !self.spaces.iter().any(|s| s == space) {
            return false;
        }
        if self.reasons.is_empty() {
            return warning(reason);
        }
        self.reasons.iter().any(|r| r == "all" || r == reason)
    }
}

fn secret_what(t: &str) -> &'static str {
    match t {
        TELEGRAM => "a bot token",
        EMAIL => "a password",
        _ => "a URL",
    }
}

/// SecretFlag: the CLI flag that reads the type's secret.
pub fn secret_flag(t: &str) -> &'static str {
    match t {
        TELEGRAM => "token",
        EMAIL => "password",
        _ => "url",
    }
}

/// CheckURL accepts https://, or http:// to a private or loopback IP.
pub fn check_url(raw: &str) -> Result<(), String> {
    let bad =
        || "channel URL must be https://host/path, with no user and password in it".to_string();
    let u = armada_node::queue::url::parse(raw).map_err(|_| bad())?;
    if u.host.is_empty() || !u.opaque.is_empty() || u.user.is_some() {
        return Err(bad());
    }
    match u.scheme.as_str() {
        "https" => Ok(()),
        "http" => {
            let host = String::from_utf8_lossy(u.hostname()).to_string();
            if let Some(ip) = Addr::parse(&host)
                && (ip.is_private() || ip.is_loopback())
            {
                return Ok(());
            }
            Err(
                "http:// channel URLs are only allowed for a private IP address; use https://"
                    .into(),
            )
        }
        _ => Err("channel URL must start with https://".into()),
    }
}

fn split_host_port(hp: &str) -> Option<(String, String)> {
    if let Some(r) = hp.strip_prefix('[') {
        let (h, rest) = r.split_once(']')?;
        let p = rest.strip_prefix(':')?;
        if h.contains(['[', ']']) || p.contains(['[', ']']) {
            return None;
        }
        return Some((h.to_string(), p.to_string()));
    }
    let (h, p) = hp.rsplit_once(':')?;
    if h.contains([':', '[', ']']) || p.contains(['[', ']']) {
        return None;
    }
    Some((h.to_string(), p.to_string()))
}

/// CheckSMTPHost accepts host:port; port 465 is TLS, any other needs
/// STARTTLS unless the host is a private IP address.
pub fn check_smtp_host(hp: &str) -> Result<(), String> {
    let Some((host, port)) = split_host_port(hp).filter(|(h, _)| !h.is_empty()) else {
        return Err("--smtp-host must be host:port, such as smtp.example.com:587".into());
    };
    match armada_node::gostr::atoi(&port) {
        Ok(n) if (1..=65535).contains(&n) => {}
        _ => return Err("--smtp-host has an invalid port".into()),
    }
    if host.contains([' ', '/', '\\', '@']) || host.len() > 253 {
        return Err("--smtp-host has an invalid host".into());
    }
    Ok(())
}

/// mail's isVchar, isAtext, and isDtext.
fn is_vchar(c: char) -> bool {
    ('!'..='~').contains(&c) || c as u32 >= 0x80
}
fn is_atext(c: char) -> bool {
    match c {
        '.' => true,
        '(' | ')' | '<' | '>' | '[' | ']' | ':' | ';' | '@' | '\\' | ',' | '"' => false,
        c => is_vchar(c),
    }
}

fn dot_atom(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(is_atext)
        && !s.starts_with('.')
        && !s.ends_with('.')
        && !s.contains("..")
}

/// A domain literal as net/mail's consumeDomainLiteral accepts it.
fn domain_literal(s: &str) -> bool {
    let Some(d) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) else {
        return false;
    };
    if !d
        .chars()
        .all(|c| c != '[' && c != ']' && c != '\\' && is_vchar(c))
    {
        return false;
    }
    if let Some(v6) = d.strip_prefix("IPv6:") {
        return v6.parse::<std::net::Ipv6Addr>().is_ok();
    }
    match d.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => true,
        Ok(IpAddr::V6(v6)) => v6.to_ipv4_mapped().is_some(),
        Err(_) => false,
    }
}

/// CheckAddress accepts one plain email address: what mail.ParseAddress
/// reads as an address equal to the text, a dot-atom local part at a
/// dot-atom domain or a domain literal.
pub fn check_address(a: &str) -> Result<(), String> {
    let bad = || format!("invalid email address {}", armada_spec::go::quote(a));
    if a.contains(['\r', '\n', '<', '>', ',', ';']) || a.len() > 254 {
        return Err(bad());
    }
    let Some((local, domain)) = a.rsplit_once('@') else {
        return Err(bad());
    };
    if !dot_atom(local) || !(dot_atom(domain) || domain_literal(domain)) {
        return Err(bad());
    }
    Ok(())
}

fn check_printable(what: &str, v: &str, max: usize) -> Result<(), String> {
    if v.len() > max {
        return Err(format!("{what} is too long"));
    }
    if v.chars().any(|c| (c as u32) < 0x21 || c as u32 == 0x7f) {
        return Err(format!("{what} must be printable, with no spaces"));
    }
    Ok(())
}

/// One thing to tell people.
#[derive(Clone, Debug, Serialize)]
pub struct Notice {
    /// event, resolved, test, or summary.
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cluster: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub object: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub space: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub app: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub node: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub count: i64,
    #[serde(with = "armada_store::gojson::time_text")]
    pub time: Time,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

impl Notice {
    pub fn new(kind: &str, time: Time) -> Notice {
        Notice {
            kind: kind.to_string(),
            cluster: String::new(),
            reason: String::new(),
            object: String::new(),
            space: String::new(),
            app: String::new(),
            node: String::new(),
            message: String::new(),
            count: 0,
            time,
        }
    }

    /// Title: one line for subjects and headings.
    pub fn title(&self) -> String {
        let mut prefix = "[armada".to_string();
        if !self.cluster.is_empty() {
            prefix.push(' ');
            prefix.push_str(&self.cluster);
        }
        prefix.push_str("] ");
        let t = match self.kind.as_str() {
            KIND_RESOLVED => format!("{prefix}Resolved: {}: {}", self.reason, self.object),
            KIND_TEST => format!("{prefix}Test notice"),
            KIND_SUMMARY => format!("{prefix}{}", self.message),
            _ => format!("{prefix}{}: {}", self.reason, self.object),
        };
        one_line(&t)
    }

    /// Text: the whole notice as plain text.
    pub fn text(&self) -> String {
        let mut b = String::new();
        match self.kind.as_str() {
            KIND_RESOLVED => b.push_str("✅ "),
            KIND_EVENT => b.push_str("⚠️ "),
            _ => {}
        }
        b.push_str(&self.title());
        if !self.message.is_empty() && self.kind != KIND_SUMMARY {
            b.push('\n');
            b.push_str(&self.message);
        }
        let mut place = Vec::new();
        for (k, v) in [
            ("space", &self.space),
            ("app", &self.app),
            ("node", &self.node),
        ] {
            if !v.is_empty() {
                place.push(format!("{k}: {v}"));
            }
        }
        if !place.is_empty() {
            b.push('\n');
            b.push_str(&place.join(" · "));
        }
        let c = utc(&self.time).civil();
        b.push_str(&format!(
            "\n{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            c.year, c.month, c.day, c.hour, c.minute, c.second
        ));
        if self.count > 1 {
            b.push_str(&format!(" ({} times)", self.count));
        }
        b
    }
}

fn utc(t: &Time) -> Time {
    t.in_loc(&armada_spec::gotime::Location::utc())
}

/// Control characters as spaces.
fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| {
            if (c as u32) < 0x20 || c as u32 == 0x7f {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Keeps text plain in Slack, whose <!here> and <url|label>
/// would be mentions and links.
pub fn slack_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
    out
}

/// Keeps text plain in Discord: a backslash before every
/// Markdown character; at most max runes, an escape never cut from its
/// character.
pub fn discord_escape(s: &str, max: usize) -> String {
    let mut b = String::new();
    let mut runes = 0;
    for (i, c) in s.char_indices() {
        let n = if "\\*_~|[]()<>#`".contains(c) { 2 } else { 1 };
        if runes + n > max || (runes + n == max && i + c.len_utf8() < s.len()) {
            b.push('…');
            break;
        }
        if n == 2 {
            b.push('\\');
        }
        b.push(c);
        runes += n;
    }
    b
}

fn cut(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let mut out: String = s.chars().take(n - 1).collect();
    out.push('…');
    out
}

/// clean makes text one printable line without the secret.
fn clean(s: &str, secret: &[u8]) -> String {
    let mut s = s.to_string();
    if !secret.is_empty() {
        s = s.replace(&*String::from_utf8_lossy(secret), "[secret]");
    }
    let mut s = armada_spec::go::fields(&one_line(&s)).join(" ");
    if s.len() > MAX_REPLY {
        let mut end = MAX_REPLY;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

/// The reasons a channel gets when it names none: what needs a person.
const WARNINGS: &[&str] = &[
    "Crashed",
    "Failed",
    "Lost",
    "OutOfMemory",
    "Unschedulable",
    "ReconcileFailed",
    "ProxyNotUpdated",
    "AddressConflict",
    "RouteConflict",
    "DNSTokenUnavailable",
    "MostUnreachable",
    "NotVerified",
    "QueueUnread",
    "QueueReadFailed",
    "LogExportFailing",
    "PeerUnreachable",
    "WireGuardUserspace",
    "VolumeUnavailable",
    "VolumesSplit",
    "VolumeOnCordonedNode",
    "VolumeBackupFailed",
    "VolumeBackupUnsupported",
    "VolumeFailedOver",
    "VolumeFailoverFailed",
    "ControlPlaneBackupFailed",
];

/// Warning: whether reason needs a person.
pub fn warning(reason: &str) -> bool {
    WARNINGS.contains(&reason)
}

/// Compact JSON with <, >, &, U+2028, and U+2029 escaped.
fn go_json<T: Serialize>(v: &T) -> Vec<u8> {
    let s = serde_json::to_string(v).unwrap_or_default();
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

/// Where a sender's requests go: the Bot API's address (tests name a
/// stand-in).
#[derive(Clone)]
pub struct Endpoints {
    pub telegram_api: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Endpoints {
            telegram_api: TELEGRAM_API.to_string(),
        }
    }
}

/// Delivers notices to one channel.
#[derive(Clone)]
pub struct Sender {
    c: Arc<Channel>,
    ends: Endpoints,
    tls: Arc<rustls::ClientConfig>,
}

impl Sender {
    pub fn new(c: Channel, ends: Endpoints, tls: Arc<rustls::ClientConfig>) -> Sender {
        Sender {
            c: Arc::new(c),
            ends,
            tls,
        }
    }

    /// Send delivers n. Errors never carry the secret.
    pub async fn send(&self, n: &Notice) -> Result<(), String> {
        let c = self.c.clone();
        let res = match c.kind.as_str() {
            WEBHOOK => self.post(secret_text(&c), go_json(n)).await,
            SLACK => {
                let body = serde_json::json!({"text": slack_escape(&n.text())});
                self.post(secret_text(&c), go_json(&body)).await
            }
            DISCORD => {
                let body = serde_json::json!({
                    "allowed_mentions": {"parse": []},
                    "content": discord_escape(&n.text(), DISCORD_MAX),
                });
                self.post(secret_text(&c), go_json(&body)).await
            }
            TELEGRAM => {
                let body = serde_json::json!({
                    "chat_id": c.chat_id,
                    "disable_web_page_preview": true,
                    "text": cut(&n.text(), TELEGRAM_MAX),
                });
                let target = format!(
                    "{}/bot{}/sendMessage",
                    self.ends.telegram_api,
                    secret_text(&c)
                );
                self.post(target, go_json(&body)).await
            }
            EMAIL => {
                let tls = self.tls.clone();
                let msg = message(&c, n);
                let c2 = c.clone();
                run_blocking(move |deadline| mail(&c2, &tls, &msg, deadline)).await
            }
            other => Err(format!(
                "unknown channel type {}",
                armada_spec::go::quote(other)
            )),
        };
        res.map_err(|e| clean(&e, &c.secret))
    }

    async fn post(&self, target: String, body: Vec<u8>) -> Result<(), String> {
        let tls = self.tls.clone();
        let secret = self.c.secret.clone();
        let (status, reply) =
            run_blocking(move |deadline| http_post(&tls, &target, &body, deadline)).await?;
        if status / 100 == 2 {
            return Ok(());
        }
        let mut msg = format!("channel answered {status}");
        let r = clean(&String::from_utf8_lossy(&reply), &secret);
        if !r.is_empty() {
            msg.push_str(": ");
            msg.push_str(&r);
        }
        Err(msg)
    }
}

fn secret_text(c: &Channel) -> String {
    String::from_utf8_lossy(&c.secret).to_string()
}

/// Runs f on a blocking thread within SEND_TIMEOUT; f gets the deadline
/// for its socket timeouts.
async fn run_blocking<T: Send + 'static>(
    f: impl FnOnce(Instant) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let deadline = Instant::now() + SEND_TIMEOUT;
    let task = tokio::task::spawn_blocking(move || f(deadline));
    match tokio::time::timeout(SEND_TIMEOUT, task).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("context deadline exceeded".into()),
    }
}

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

fn left(deadline: Instant) -> Result<Duration, String> {
    let d = deadline.saturating_duration_since(Instant::now());
    if d.is_zero() {
        return Err("i/o timeout".into());
    }
    Ok(d)
}

/// Dials host:port within the deadline: every address in turn until one
/// connects.
fn dial(host: &str, port: u16, deadline: Instant) -> Result<TcpStream, String> {
    let addrs: Vec<SocketAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => (host, port)
            .to_socket_addrs()
            .map_err(|e| format!("dial tcp: lookup {host}: {e}"))?
            .collect(),
    };
    let mut last = format!("dial tcp: lookup {host}: no such host");
    for a in addrs {
        match TcpStream::connect_timeout(&a, left(deadline)?) {
            Ok(s) => {
                let t = Some(left(deadline)?);
                let _ = s.set_read_timeout(t);
                let _ = s.set_write_timeout(t);
                return Ok(s);
            }
            Err(e) => last = format!("dial tcp {a}: connect: {}", io_text(&e)),
        }
    }
    Err(last)
}

/// An io error, the common ones worded as the system's error strings
/// (e.g. "connection refused").
fn io_text(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::ConnectionRefused => "connection refused".into(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => "i/o timeout".into(),
        std::io::ErrorKind::ConnectionReset => "connection reset by peer".into(),
        std::io::ErrorKind::UnexpectedEof => "EOF".into(),
        _ => {
            let s = e.to_string();
            s.split(" (os error").next().unwrap_or(&s).to_lowercase()
        }
    }
}

fn tls_wrap(
    tls: &Arc<rustls::ClientConfig>,
    inner: TcpStream,
    host: &str,
) -> Result<Box<dyn Stream>, String> {
    use rustls::pki_types::ServerName;
    let name = match host.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(host.to_string()).map_err(|e| format!("tls: {e}"))?,
    };
    let conn = rustls::ClientConnection::new(tls.clone(), name).map_err(|e| format!("tls: {e}"))?;
    let mut s = rustls::StreamOwned::new(conn, inner);
    while s.conn.is_handshaking() {
        s.conn
            .complete_io(&mut s.sock)
            .map_err(|e| format!("tls: {}", io_text(&e)))?;
    }
    Ok(Box::new(s))
}

/// One POST; the status and up to MAX_REPLY bytes of the body. Redirects
/// are not followed: one could take the secret elsewhere.
fn http_post(
    tls: &Arc<rustls::ClientConfig>,
    target: &str,
    body: &[u8],
    deadline: Instant,
) -> Result<(u16, Vec<u8>), String> {
    let u = armada_node::http::Url::parse(target).map_err(|_| "invalid channel URL".to_string())?;
    if u.scheme != "http" && u.scheme != "https" {
        return Err(format!(
            "unsupported protocol scheme {}",
            armada_spec::go::quote(&u.scheme)
        ));
    }
    let tcp = dial(&u.host, u.effective_port(), deadline)?;
    let mut s: Box<dyn Stream> = if u.scheme == "https" {
        tls_wrap(tls, tcp, &u.host)?
    } else {
        Box::new(tcp)
    };
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: armada\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
        u.path,
        u.authority(),
        body.len()
    );
    s.write_all(head.as_bytes())
        .and_then(|()| s.write_all(body))
        .and_then(|()| s.flush())
        .map_err(|e| io_text(&e))?;
    let mut r = BufReader::new(s);
    let mut line = String::new();
    let status = loop {
        line.clear();
        r.read_line(&mut line).map_err(|e| io_text(&e))?;
        let mut parts = line.split_whitespace();
        let proto = parts.next().unwrap_or_default();
        let code: u16 = parts
            .next()
            .and_then(|c| c.parse().ok())
            .filter(|_| proto.starts_with("HTTP/"))
            .ok_or_else(|| {
                format!(
                    "malformed HTTP response {}",
                    armada_spec::go::quote(line.trim_end())
                )
            })?;
        let mut chunked = false;
        let mut length: Option<usize> = None;
        loop {
            let mut h = String::new();
            r.read_line(&mut h).map_err(|e| io_text(&e))?;
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                let k = k.trim().to_ascii_lowercase();
                let v = v.trim();
                if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
                    chunked = true;
                } else if k == "content-length" {
                    length = v.parse().ok();
                }
            }
        }
        // 1xx answers precede the real one.
        if (100..200).contains(&code) {
            continue;
        }
        break (code, chunked, length);
    };
    let (code, chunked, length) = status;
    let mut reply = Vec::new();
    if chunked {
        while reply.len() < MAX_REPLY {
            let mut size = String::new();
            if r.read_line(&mut size).unwrap_or(0) == 0 {
                break;
            }
            let n = usize::from_str_radix(size.trim().split(';').next().unwrap_or("0"), 16)
                .unwrap_or(0);
            if n == 0 {
                break;
            }
            let mut chunk = vec![0; n];
            if r.read_exact(&mut chunk).is_err() {
                break;
            }
            reply.extend_from_slice(&chunk);
            let mut crlf = String::new();
            let _ = r.read_line(&mut crlf);
        }
        reply.truncate(MAX_REPLY);
    } else {
        let want = length.unwrap_or(MAX_REPLY).min(MAX_REPLY);
        let _ = r.take(want as u64).read_to_end(&mut reply);
    }
    Ok((code, reply))
}

/// message renders n as an email; headers hold only checked addresses and
/// an encoded subject, so no text can add a header.
pub fn message(c: &Channel, n: &Notice) -> Vec<u8> {
    let mut b = String::new();
    b.push_str(&format!("From: {}\r\n", c.from));
    b.push_str(&format!("To: {}\r\n", c.to.join(", ")));
    b.push_str(&format!("Subject: {}\r\n", q_encode(&one_line(&n.title()))));
    b.push_str(&format!("Date: {}\r\n", rfc1123z(&n.time)));
    b.push_str("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\nAuto-Submitted: auto-generated\r\n\r\n");
    let mut out = b.into_bytes();
    out.extend_from_slice(&quoted_printable(n.text().replace('\n', "\r\n").as_bytes()));
    out.extend_from_slice(b"\r\n");
    out
}

/// RFC 1123 with a numeric zone (`Mon, 02 Jan 2006 15:04:05 +0000`), in
/// UTC.
fn rfc1123z(t: &Time) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let c = utc(t).civil();
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} +0000",
        DAYS[c.weekday as usize],
        c.day,
        MONTHS[(c.month - 1) as usize],
        c.year,
        c.hour,
        c.minute,
        c.second
    )
}

const UPPERHEX: &[u8; 16] = b"0123456789ABCDEF";

/// mime.QEncoding.Encode("utf-8", s).
pub fn q_encode(s: &str) -> String {
    if !s.chars().any(|c| !(' '..='~').contains(&c) && c != '\t') {
        return s.to_string();
    }
    const MAX_CONTENT: usize = 75 - "=?UTF-8?q?".len() - "?=".len();
    let mut out = String::from("=?utf-8?q?");
    let mut len = 0;
    for c in s.chars() {
        let b = c as u32;
        let mut buf = [0u8; 4];
        let bytes = c.encode_utf8(&mut buf).as_bytes();
        let plain = (0x20..=0x7e).contains(&b) && c != '=' && c != '?' && c != '_';
        let enc = if plain { 1 } else { 3 * bytes.len() };
        if len + enc > MAX_CONTENT {
            out.push_str("?= =?utf-8?q?");
            len = 0;
        }
        for &x in bytes {
            match x {
                b' ' => out.push('_'),
                b'!'..=b'~' if x != b'=' && x != b'?' && x != b'_' => out.push(x as char),
                _ => {
                    out.push('=');
                    out.push(UPPERHEX[(x >> 4) as usize] as char);
                    out.push(UPPERHEX[(x & 15) as usize] as char);
                }
            }
        }
        len += enc;
    }
    out.push_str("?=");
    out
}

/// mime/quotedprintable's Writer (text mode), written then closed.
pub fn quoted_printable(p: &[u8]) -> Vec<u8> {
    const LINE_MAX: usize = 76;
    struct W {
        out: Vec<u8>,
        line: Vec<u8>,
        cr: bool,
    }
    impl W {
        fn flush(&mut self) {
            self.out.append(&mut self.line);
        }
        fn crlf(&mut self) {
            self.line.extend_from_slice(b"\r\n");
            self.flush();
        }
        fn soft(&mut self) {
            self.line.push(b'=');
            self.crlf();
        }
        fn encode(&mut self, b: u8) {
            if LINE_MAX - 1 - self.line.len() < 3 {
                self.soft();
            }
            self.line.extend_from_slice(&[
                b'=',
                UPPERHEX[(b >> 4) as usize],
                UPPERHEX[(b & 15) as usize],
            ]);
        }
        fn check_last(&mut self) {
            if let Some(&b) = self.line.last()
                && (b == b' ' || b == b'\t')
            {
                self.line.pop();
                self.encode(b);
            }
        }
        fn write(&mut self, p: &[u8]) {
            for &b in p {
                if b == b'\n' || b == b'\r' {
                    if self.cr && b == b'\n' {
                        self.cr = false;
                        continue;
                    }
                    if b == b'\r' {
                        self.cr = true;
                    }
                    self.check_last();
                    self.crlf();
                    continue;
                }
                if self.line.len() == LINE_MAX - 1 {
                    self.soft();
                }
                self.line.push(b);
                self.cr = false;
            }
        }
    }
    let mut w = W {
        out: Vec::new(),
        line: Vec::new(),
        cr: false,
    };
    let mut n = 0;
    for (i, &b) in p.iter().enumerate() {
        if (b'!'..=b'~').contains(&b) && b != b'=' {
            continue;
        }
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            continue;
        }
        if i > n {
            w.write(&p[n..i]);
        }
        w.encode(b);
        n = i + 1;
    }
    if n < p.len() {
        w.write(&p[n..]);
    }
    w.check_last();
    w.flush();
    w.out
}

/// An SMTP connection: plain until STARTTLS, or TLS.
enum Conn {
    Plain(TcpStream),
    Tls(Box<dyn Stream>),
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            Conn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            Conn::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

/// An SMTP connection as net/smtp's Client reads and writes it.
struct Smtp {
    r: BufReader<Conn>,
    ext: Vec<(String, String)>,
    did_hello: bool,
}

impl Smtp {
    fn new(s: Conn) -> Result<Smtp, String> {
        let mut c = Smtp {
            r: BufReader::new(s),
            ext: Vec::new(),
            did_hello: false,
        };
        c.response(220)?;
        Ok(c)
    }

    /// textproto's ReadResponse: the code and the lines' text.
    fn response(&mut self, expect: u16) -> Result<(u16, String), String> {
        let mut msg = String::new();
        let mut code = 0;
        loop {
            let mut line = String::new();
            let n = self.r.read_line(&mut line).map_err(|e| io_text(&e))?;
            if n == 0 {
                return Err("EOF".into());
            }
            let line = line.trim_end_matches(['\r', '\n']);
            if line.len() < 4 && line.len() != 3 {
                return Err(format!("short response: {line}"));
            }
            let c: u16 = line[..3]
                .parse()
                .map_err(|_| format!("invalid response code: {line}"))?;
            if code != 0 && c != code {
                return Err(format!("invalid response code: {line}"));
            }
            code = c;
            let cont = line.as_bytes().get(3) == Some(&b'-');
            let text = line.get(4..).unwrap_or_default();
            if !msg.is_empty() {
                msg.push('\n');
            }
            msg.push_str(text);
            if !cont {
                break;
            }
        }
        let ok = match expect {
            0 => true,
            e if e < 10 => code / 100 == e,
            e if e < 100 => code / 10 == e,
            e => code == e,
        };
        if !ok {
            return Err(format!("{code:03} {msg}"));
        }
        Ok((code, msg))
    }

    fn cmd(&mut self, expect: u16, line: &str) -> Result<(u16, String), String> {
        let s = self.r.get_mut();
        s.write_all(format!("{line}\r\n").as_bytes())
            .and_then(|()| s.flush())
            .map_err(|e| io_text(&e))?;
        self.response(expect)
    }

    fn hello(&mut self) -> Result<(), String> {
        if self.did_hello {
            return Ok(());
        }
        self.did_hello = true;
        match self.cmd(250, "EHLO localhost") {
            Ok((_, msg)) => {
                self.ext.clear();
                for line in msg.split('\n').skip(1) {
                    let mut it = line.splitn(2, ' ');
                    let k = it.next().unwrap_or_default().to_string();
                    let v = it.next().unwrap_or_default().to_string();
                    self.ext.push((k, v));
                }
                Ok(())
            }
            Err(_) => self.cmd(250, "HELO localhost").map(|_| ()),
        }
    }

    fn extension(&mut self, name: &str) -> Result<bool, String> {
        self.hello()?;
        let n = name.to_ascii_uppercase();
        Ok(self.ext.iter().any(|(k, _)| *k == n))
    }
}

fn smtp_err(e: String) -> String {
    format!("smtp: {e}")
}

/// mail sends n over SMTP: TLS on 465, else STARTTLS when offered (and
/// required unless the host is a private IP), PLAIN authentication only
/// over TLS.
fn mail(
    c: &Channel,
    tls: &Arc<rustls::ClientConfig>,
    msg: &[u8],
    deadline: Instant,
) -> Result<(), String> {
    let (host, port) = split_host_port(&c.smtp_host).unwrap_or_default();
    let port_n: u16 = port.parse().unwrap_or(0);
    let tcp = dial(&host, port_n, deadline).map_err(smtp_err)?;
    let mut encrypted = false;
    let stream = if port == "465" {
        encrypted = true;
        Conn::Tls(tls_wrap(tls, tcp, &host).map_err(smtp_err)?)
    } else {
        Conn::Plain(tcp)
    };
    let mut s = Smtp::new(stream).map_err(smtp_err)?;
    if !encrypted {
        if s.extension("STARTTLS").map_err(smtp_err)? {
            s.cmd(220, "STARTTLS").map_err(smtp_err)?;
            // Nothing is buffered after the answer.
            let Conn::Plain(tcp) = s.r.into_inner() else {
                return Err(smtp_err("STARTTLS on a TLS connection".into()));
            };
            let t = tls_wrap(tls, tcp, &host).map_err(smtp_err)?;
            s = Smtp {
                r: BufReader::new(Conn::Tls(t)),
                ext: Vec::new(),
                did_hello: false,
            };
            s.hello().map_err(smtp_err)?;
            encrypted = true;
        } else {
            let private = Addr::parse(&host).is_some_and(|ip| ip.is_private() || ip.is_loopback());
            if !private {
                return Err(
                    "smtp: the server offers no STARTTLS; use port 465 or a server that does"
                        .into(),
                );
            }
        }
    }
    if !c.smtp_user.is_empty() {
        if !encrypted {
            return Err("smtp: refusing to send the password without TLS".into());
        }
        s.hello().map_err(smtp_err)?;
        let mut resp = vec![0u8];
        resp.extend_from_slice(c.smtp_user.as_bytes());
        resp.push(0);
        resp.extend_from_slice(&c.secret);
        let line = format!("AUTH PLAIN {}", armada_node::http::base64(&resp));
        let (code, msg) = s.cmd(0, &line).map_err(smtp_err)?;
        match code {
            235 => {}
            334 => {
                let _ = s.cmd(501, "*");
                return Err("smtp: unexpected SMTP challenge".into());
            }
            _ => {
                let _ = s.cmd(501, "*");
                return Err(smtp_err(format!("{code:03} {msg}")));
            }
        }
    }
    s.hello().map_err(smtp_err)?;
    let mut from = format!("MAIL FROM:<{}>", c.from);
    if s.ext.iter().any(|(k, _)| k == "8BITMIME") {
        from.push_str(" BODY=8BITMIME");
    }
    if s.ext.iter().any(|(k, _)| k == "SMTPUTF8") {
        from.push_str(" SMTPUTF8");
    }
    s.cmd(250, &from).map_err(smtp_err)?;
    for to in &c.to {
        s.cmd(25, &format!("RCPT TO:<{to}>")).map_err(smtp_err)?;
    }
    s.cmd(354, "DATA").map_err(smtp_err)?;
    let body = dot_encode(msg);
    {
        let w = s.r.get_mut();
        w.write_all(&body)
            .and_then(|()| w.flush())
            .map_err(|e| smtp_err(io_text(&e)))?;
    }
    s.response(250).map_err(smtp_err)?;
    s.cmd(221, "QUIT").map_err(smtp_err)?;
    Ok(())
}

/// textproto's DotWriter: lines starting with a dot get another, every
/// line ends in CRLF, and the data ends with a lone dot.
fn dot_encode(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + 8);
    let mut bol = true;
    let mut i = 0;
    while i < msg.len() {
        let b = msg[i];
        if bol && b == b'.' {
            out.push(b'.');
        }
        if b == b'\r' && msg.get(i + 1) == Some(&b'\n') {
            out.extend_from_slice(b"\r\n");
            i += 2;
            bol = true;
            continue;
        }
        if b == b'\n' {
            out.extend_from_slice(b"\r\n");
            bol = true;
        } else {
            out.push(b);
            bol = false;
        }
        i += 1;
    }
    if !bol {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks() {
        assert!(check_name("ops-1").is_ok());
        assert!(check_name("A!").is_err());
        assert!(check_address("a.b@example.com").is_ok());
        assert!(check_address("a@[10.0.0.1]").is_ok());
        assert!(check_address("Name <a@b>").is_err());
        assert!(check_address("a..b@c").is_err());
        assert!(check_address("\"a\"@b").is_err());
        assert!(check_url("http://127.0.0.1:9/x").is_ok());
        assert!(check_url("http://example.com/x").is_err());
        assert!(check_url("https://u:p@example.com/x").is_err());
        assert!(check_smtp_host("smtp.example.com:587").is_ok());
        assert!(check_smtp_host("smtp.example.com").is_err());
        assert!(valid_bot_key(b"123456:ABCDEFGHIJKLMNOPQRSTUVWX"));
        assert!(valid_chat_id("-1001234567890") && valid_chat_id("@channel"));
    }

    #[test]
    fn escapes() {
        assert_eq!(slack_escape("<!here> & x"), "&lt;!here&gt; &amp; x");
        assert_eq!(discord_escape("[a](b)", 100), "\\[a\\]\\(b\\)");
        assert_eq!(discord_escape("abcdef", 4), "abc…");
        assert_eq!(cut("abcdef", 4), "abc…");
        assert_eq!(clean("a  b\nc s3cret", b"s3cret"), "a b c [secret]");
    }

    #[test]
    fn mail_encodings() {
        assert_eq!(q_encode("plain"), "plain");
        assert_eq!(q_encode("café ok"), "=?utf-8?q?caf=C3=A9_ok?=");
        assert_eq!(
            quoted_printable(b"a=b \r\nc\t"),
            b"a=3Db=20\r\nc=09".to_vec()
        );
        assert_eq!(dot_encode(b".a\r\nb"), b"..a\r\nb\r\n.\r\n".to_vec());
    }
}

//! Stand-ins the scenarios reach besides the server: an HTTP server for
//! webhooks, Slack, Discord, and the Telegram Bot API, an SMTP server, and
//! an S3 bucket; and a client of the metrics endpoint.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use super::gojson;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// One HTTP/1.1 request.
struct Request {
    method: String,
    path: String,
    query: String,
    host: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

/// Reads a request (a body by Content-Length); None at the connection's
/// end.
async fn read_request(r: &mut BufReader<TcpStream>) -> Option<Request> {
    let mut line = String::new();
    if r.read_line(&mut line).await.ok()? == 0 {
        return None;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut headers = HashMap::new();
    loop {
        let mut h = String::new();
        if r.read_line(&mut h).await.ok()? == 0 {
            return None;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let n: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; n];
    r.read_exact(&mut body).await.ok()?;
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    Some(Request {
        method,
        path,
        query,
        host: headers.get("host").cloned().unwrap_or_default(),
        headers,
        body,
    })
}

async fn respond(w: &mut BufReader<TcpStream>, code: u16, ctype: &str, body: &[u8]) -> bool {
    let reason = match code {
        200 => "OK",
        204 => "No Content",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Error",
    };
    let mut head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\n",
        body.len()
    );
    if !ctype.is_empty() {
        head += &format!("Content-Type: {ctype}\r\n");
    }
    head += "\r\n";
    let s = w.get_mut();
    s.write_all(head.as_bytes()).await.is_ok() && s.write_all(body).await.is_ok()
}

/// Serves each connection of l with f, request after request.
fn serve<F>(l: TcpListener, f: Arc<F>)
where
    F: Fn(Request) -> (u16, String, Vec<u8>) + Send + Sync + 'static,
{
    tokio::spawn(async move {
        while let Ok((c, _)) = l.accept().await {
            let f = f.clone();
            tokio::spawn(async move {
                let mut r = BufReader::new(c);
                while let Some(req) = read_request(&mut r).await {
                    let (code, ctype, body) = f(req);
                    if !respond(&mut r, code, &ctype, &body).await {
                        return;
                    }
                }
            });
        }
    });
}

/// Percent-decoding of a path (plus, of a query value, `+` as a space).
fn unescape(s: &str, query: bool) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => match (hex(b[i + 1]), hex(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' if query => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query(q: &str) -> HashMap<String, String> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (unescape(k, true), unescape(v, true)),
            None => (unescape(p, true), String::new()),
        })
        .collect()
}

/// Replaces every match of a pattern found by m (its length at a start),
/// left to right, as regexp.ReplaceAllString does.
fn replace_all(s: &str, m: impl Fn(&[u8]) -> Option<usize>, with: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    let mut from = 0;
    while i < b.len() {
        if let Some(n) = m(&b[i..]) {
            out.push_str(&s[from..i]);
            out.push_str(with);
            i += n;
            from = i;
        } else {
            i += 1;
        }
    }
    out.push_str(&s[from..]);
    out
}

fn digits(b: &[u8], n: usize) -> bool {
    b.len() >= n && b[..n].iter().all(u8::is_ascii_digit)
}

/// `\d{4}-\d\d-\d\d` at the start of b.
fn date(b: &[u8]) -> bool {
    digits(b, 4)
        && b.get(4) == Some(&b'-')
        && digits(&b[5..], 2)
        && b.get(7) == Some(&b'-')
        && digits(&b[8..], 2)
}

/// `\d\d:\d\d:\d\d UTC` at the start of b.
fn clock_utc(b: &[u8]) -> bool {
    digits(b, 2)
        && b.get(2) == Some(&b':')
        && digits(&b[3..], 2)
        && b.get(5) == Some(&b':')
        && digits(&b[6..], 2)
        && b[8..].starts_with(b" UTC")
}

/// `\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC`.
fn sink_time(b: &[u8]) -> Option<usize> {
    (b.len() >= 23 && date(b) && b[10] == b' ' && clock_utc(&b[11..])).then_some(23)
}

/// `\d{4}-\d\d-\d\d =?\r?\n?\d\d:\d\d:\d\d UTC`.
fn sink_time_q(b: &[u8]) -> Option<usize> {
    if b.len() < 11 || !date(b) || b[10] != b' ' {
        return None;
    }
    let mut i = 11;
    for c in *b"=\r\n" {
        if b.get(i) == Some(&c) {
            i += 1;
        }
    }
    (b.len() >= i + 12 && clock_utc(&b[i..])).then_some(i + 12)
}

/// `(?m)^Date: .*\r$` replaced by `Date: <date>\r`.
fn sink_date(s: &str) -> String {
    s.split('\n')
        .map(|l| {
            if l.starts_with("Date: ") && l.ends_with('\r') {
                "Date: <date>\r".to_string()
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The alert channels' stand-ins.
pub struct Sinks {
    pub url: String,
    pub smtp: String,
    got: Arc<Mutex<HashMap<String, Vec<String>>>>,
    fail: Arc<Mutex<HashMap<String, bool>>>,
}

impl Sinks {
    pub async fn start() -> Result<Sinks, String> {
        let got: Arc<Mutex<HashMap<String, Vec<String>>>> = Arc::default();
        let fail: Arc<Mutex<HashMap<String, bool>>> = Arc::default();
        let l = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let url = format!("http://{}", l.local_addr().map_err(|e| e.to_string())?);
        {
            let got = got.clone();
            let fail = fail.clone();
            serve(
                l,
                Arc::new(move |r: Request| {
                    if lock(&fail).get(&r.path).copied().unwrap_or(false) {
                        // The whole URL, the channel's secret, which errors
                        // never repeat.
                        let q = if r.query.is_empty() {
                            String::new()
                        } else {
                            format!("?{}", r.query)
                        };
                        let body = format!("no access for http://{}{}{q}", r.host, r.path);
                        return (401, "text/plain; charset=utf-8".into(), body.into_bytes());
                    }
                    let mut v = serde_json::from_slice::<Value>(&r.body)
                        .ok()
                        .filter(Value::is_object)
                        .unwrap_or(Value::Null);
                    if let Some(m) = v.as_object_mut() {
                        for x in m.values_mut() {
                            if let Value::String(s) = x {
                                *s = replace_all(s, sink_time, "<time> UTC");
                            }
                        }
                    }
                    let h = |k: &str| r.headers.get(k).cloned().unwrap_or_default();
                    let line =
                        gojson::marshal(&json!({"method": r.method, "type": h("content-type"),
                        "agent": h("user-agent"), "query": r.query, "body": v}));
                    lock(&got).entry(r.path.clone()).or_default().push(line);
                    (200, String::new(), Vec::new())
                }),
            );
        }
        let l = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let smtp = l.local_addr().map_err(|e| e.to_string())?.to_string();
        {
            let got = got.clone();
            tokio::spawn(async move {
                while let Ok((c, _)) = l.accept().await {
                    tokio::spawn(smtp_session(c, got.clone()));
                }
            });
        }
        Ok(Sinks {
            url,
            smtp,
            got,
            fail,
        })
    }

    pub fn set_fail(&self, path: &str, on: bool) {
        lock(&self.fail).insert(path.to_string(), on);
    }

    /// Waits until path received n notices; they come sorted.
    pub async fn wait(&self, path: &str, n: usize) -> Result<Vec<String>, String> {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let mut got = lock(&self.got).get(path).cloned().unwrap_or_default();
            if got.len() >= n {
                got.sort();
                return Ok(got);
            }
            if std::time::Instant::now() > deadline {
                return Err(format!(
                    "{} notices at {path}, want {n}: {got:?}",
                    got.len()
                ));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// A plain SMTP server's session: no STARTTLS and no authentication.
async fn smtp_session(c: TcpStream, got: Arc<Mutex<HashMap<String, Vec<String>>>>) {
    let mut r = BufReader::new(c);
    let mut lines = Vec::new();
    macro_rules! say {
        ($l:expr) => {
            if r.get_mut()
                .write_all(format!("{}\r\n", $l).as_bytes())
                .await
                .is_err()
            {
                return;
            }
        };
    }
    say!("220 standin ESMTP");
    loop {
        let mut line = String::new();
        match r.read_line(&mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let line = line.trim_end_matches(['\r', '\n']).to_string();
        lines.push(line.clone());
        let cmd = line
            .split(' ')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        match cmd.as_str() {
            "EHLO" => {
                say!("250-standin");
                say!("250 SIZE 1000000");
            }
            "HELO" | "MAIL" | "RCPT" | "RSET" | "NOOP" => say!("250 ok"),
            "DATA" => {
                say!("354 go on");
                let mut data = String::new();
                loop {
                    let mut l = String::new();
                    match r.read_line(&mut l).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                    if l == ".\r\n" {
                        break;
                    }
                    data.push_str(&l);
                }
                let msg = sink_date(&data);
                lines.push(replace_all(&msg, sink_time_q, "<time> UTC"));
                say!("250 queued");
            }
            "QUIT" => {
                say!("221 bye");
                lock(&got)
                    .entry("smtp".into())
                    .or_default()
                    .push(lines.join("\n"));
                return;
            }
            _ => say!("502 not here"),
        }
    }
}

/// Days from 1970-01-01 to a civil date.
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// ms as `YYYY-MM-DDTHH:MM:SS.mmmZ` in UTC.
fn s3_time(ms: i64) -> String {
    let (secs, milli) = (ms.div_euclid(1000), ms.rem_euclid(1000));
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{milli:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// A bucket's objects by key: their data and when they were written (ms).
type Objects = Arc<Mutex<BTreeMap<String, (Vec<u8>, i64)>>>;

/// Bucket "backups" as an S3 endpoint answers path-style requests, its
/// objects stamped with the scenario's clock.
pub struct Bucket {
    pub addr: String,
    objs: Objects,
}

impl Bucket {
    pub async fn start(clock: Arc<AtomicI64>) -> Result<Bucket, String> {
        let objs: Objects = Arc::default();
        let l = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let addr = l.local_addr().map_err(|e| e.to_string())?.to_string();
        let o = objs.clone();
        serve(
            l,
            Arc::new(move |r: Request| {
                let fail = |code: u16, s3: &str| {
                    let body = format!(
                        r#"<?xml version="1.0" encoding="UTF-8"?><Error><Code>{s3}</Code><Message>no</Message></Error>"#
                    );
                    (code, "application/xml".to_string(), body.into_bytes())
                };
                let p = r.path.trim_start_matches('/');
                let (bucket, key) = p.split_once('/').unwrap_or((p, ""));
                if bucket != "backups" {
                    return fail(404, "NoSuchBucket");
                }
                let key = unescape(key, false);
                let q = query(&r.query);
                let mut objs = lock(&o);
                match r.method.as_str() {
                    "GET" if key.is_empty() && q.contains_key("location") => (
                        200,
                        String::new(),
                        br#"<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>"#.to_vec(),
                    ),
                    "PUT" if !key.is_empty() => {
                        objs.insert(key, (r.body, clock.load(Ordering::SeqCst)));
                        (200, String::new(), Vec::new())
                    }
                    "GET" if key.is_empty() => {
                        let prefix = q.get("prefix").cloned().unwrap_or_default();
                        let after = q.get("continuation-token").cloned().unwrap_or_default();
                        let mut keys: Vec<&String> = objs
                            .keys()
                            .filter(|k| k.starts_with(&prefix) && k.as_str() > after.as_str())
                            .collect();
                        let mut next = String::new();
                        if keys.len() > 3 {
                            keys.truncate(3);
                            next = keys[2].clone();
                        }
                        let mut x = format!(
                            "<ListBucketResult><Name>backups</Name><Prefix>{}</Prefix><KeyCount>{}</KeyCount><IsTruncated>{}</IsTruncated>",
                            xml_escape(&prefix),
                            keys.len(),
                            !next.is_empty()
                        );
                        if !next.is_empty() {
                            x += &format!("<NextContinuationToken>{}</NextContinuationToken>", xml_escape(&next));
                        }
                        for k in keys {
                            let (data, at) = &objs[k];
                            x += &format!(
                                "<Contents><Key>{}</Key><Size>{}</Size><LastModified>{}</LastModified></Contents>",
                                xml_escape(k),
                                data.len(),
                                s3_time(*at)
                            );
                        }
                        x += "</ListBucketResult>";
                        (200, "application/xml".into(), x.into_bytes())
                    }
                    "GET" => match objs.get(&key) {
                        Some((data, _)) => (200, String::new(), data.clone()),
                        None => fail(404, "NoSuchKey"),
                    },
                    "DELETE" => {
                        objs.remove(&key);
                        (204, String::new(), Vec::new())
                    }
                    _ => fail(405, "MethodNotAllowed"),
                }
            }),
        );
        Ok(Bucket { addr, objs })
    }

    /// What the bucket holds by kind (cpBucket.summary).
    pub fn summary(&self) -> Value {
        let mut out = serde_json::Map::new();
        for k in lock(&self.objs).keys() {
            let kind = match k.strip_prefix("armada/_control-plane/") {
                None => "elsewhere",
                Some("config") => "config",
                Some(r) if r.starts_with("snapshots/") => "snapshots",
                Some(r) if r.starts_with("chunks/") => "chunks",
                Some(_) => "other",
            };
            let n = out.get(kind).and_then(Value::as_i64).unwrap_or(0);
            out.insert(kind.into(), json!(n + 1));
        }
        Value::Object(out)
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

/// A scrape of the metrics endpoint: the status and body (any `go_`
/// families left out, as the recordings leave them out), or an error.
pub async fn scrape(
    addr: &str,
    mut tls: rustls::ClientConfig,
    method: &str,
    path: &str,
) -> Result<(u16, String), String> {
    tls.alpn_protocols.clear();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
    let name = rustls_pki_types::ServerName::try_from(armada_pki::SERVER_NAME)
        .map_err(|e| e.to_string())?;
    let go = async {
        let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
        let mut s = connector
            .connect(name, tcp)
            .await
            .map_err(|e| e.to_string())?;
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );
        s.write_all(req.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&buf).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").ok_or("no response")?;
        let status: u16 = head
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .ok_or("no status")?;
        let keep: Vec<&str> = body
            .split('\n')
            .filter(|l| {
                !(l.starts_with("go_")
                    || l.starts_with("# HELP go_")
                    || l.starts_with("# TYPE go_"))
            })
            .collect();
        Ok::<_, String>((status, keep.join("\n")))
    };
    tokio::time::timeout(Duration::from_secs(10), go)
        .await
        .map_err(|_| "timed out".to_string())?
}

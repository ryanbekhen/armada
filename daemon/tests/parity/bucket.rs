//! The control plane's bucket stand-in: bucket
//! "backups" answering the path-style S3 requests armada-node sends
//! (ARMADA_NODE_TEST_BUCKET_ADDR), over plain HTTP/1.1 with keep-alive.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

type Objects = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

pub struct Bucket {
    pub addr: String,
    objs: Objects,
}

impl Bucket {
    pub fn start() -> Bucket {
        let lis = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = lis.local_addr().unwrap().to_string();
        let objs: Objects = Arc::default();
        let o = objs.clone();
        std::thread::spawn(move || {
            for c in lis.incoming().flatten() {
                let o = o.clone();
                std::thread::spawn(move || serve(c, o));
            }
        });
        Bucket { addr, objs }
    }

    /// Replaces what the bucket holds.
    pub fn load(&self, objs: BTreeMap<String, Vec<u8>>) {
        *self.objs.lock().unwrap() = objs;
    }
}

fn unhex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// s with its %XX escapes decoded (and + as a space in a query).
fn unescape(s: &str, query: bool) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => match (unhex(b[i + 1]), unhex(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            b'+' if query => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

struct Req {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    body: Vec<u8>,
    close: bool,
}

fn read_req(r: &mut BufReader<TcpStream>, w: &mut TcpStream) -> Option<Req> {
    let mut line = String::new();
    if r.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut len = 0usize;
    let mut close = false;
    let mut cont = false;
    loop {
        let mut h = String::new();
        if r.read_line(&mut h).ok()? == 0 {
            return None;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            match k.as_str() {
                "content-length" => len = v.parse().unwrap_or(0),
                "connection" => close = v.eq_ignore_ascii_case("close"),
                "expect" => cont = v.eq_ignore_ascii_case("100-continue"),
                _ => {}
            }
        }
    }
    if cont {
        let _ = w.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
    }
    let mut body = vec![0; len];
    r.read_exact(&mut body).ok()?;
    let (path, q) = target.split_once('?').unwrap_or((&target, ""));
    let mut query = BTreeMap::new();
    for kv in q.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        query
            .entry(unescape(k, true))
            .or_insert_with(|| unescape(v, true));
    }
    Some(Req {
        method,
        path: unescape(path, false),
        query,
        body,
        close,
    })
}

fn respond(w: &mut TcpStream, code: u16, ctype: &str, body: &[u8]) {
    let reason = match code {
        200 => "OK",
        204 => "No Content",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "",
    };
    let mut head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\n",
        body.len()
    );
    if !ctype.is_empty() {
        head.push_str(&format!("Content-Type: {ctype}\r\n"));
    }
    head.push_str("\r\n");
    let _ = w.write_all(head.as_bytes());
    let _ = w.write_all(body);
    let _ = w.flush();
}

fn fail(w: &mut TcpStream, code: u16, s3: &str) {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{s3}</Code><Message>no</Message></Error>"
    );
    respond(w, code, "application/xml", body.as_bytes());
}

fn serve(c: TcpStream, objs: Objects) {
    let mut w = c.try_clone().unwrap();
    let mut r = BufReader::new(c);
    while let Some(req) = read_req(&mut r, &mut w) {
        handle(&mut w, &req, &objs);
        if req.close {
            return;
        }
    }
}

const MODIFIED: &str = "2026-11-23T03:00:00.000Z";

fn handle(w: &mut TcpStream, req: &Req, objs: &Objects) {
    let p = req.path.trim_start_matches('/');
    let (bucket, key) = p.split_once('/').unwrap_or((p, ""));
    if bucket != "backups" {
        return fail(w, 404, "NoSuchBucket");
    }
    let mut o = objs.lock().unwrap();
    let q = &req.query;
    match req.method.as_str() {
        "GET" if key.is_empty() && q.contains_key("location") => respond(
            w,
            200,
            "text/xml; charset=utf-8",
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></LocationConstraint>",
        ),
        "PUT" if !key.is_empty() => {
            o.insert(key.to_string(), req.body.clone());
            respond(w, 200, "", b"");
        }
        "GET" if key.is_empty() => {
            let prefix = q.get("prefix").cloned().unwrap_or_default();
            let token = q.get("continuation-token").cloned().unwrap_or_default();
            let mut keys: Vec<&String> = o
                .keys()
                .filter(|k| k.starts_with(&prefix) && k.as_str() > token.as_str())
                .collect();
            let truncated = keys.len() > 3;
            keys.truncate(3);
            let mut res = String::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><Name>backups</Name>",
            );
            res.push_str(&format!(
                "<KeyCount>{}</KeyCount><IsTruncated>{truncated}</IsTruncated>",
                keys.len()
            ));
            if truncated {
                res.push_str(&format!(
                    "<NextContinuationToken>{}</NextContinuationToken>",
                    keys[keys.len() - 1]
                ));
            }
            for k in &keys {
                res.push_str(&format!(
                    "<Contents><Key>{k}</Key><Size>{}</Size><LastModified>{MODIFIED}</LastModified></Contents>",
                    o[*k].len()
                ));
            }
            res.push_str("</ListBucketResult>");
            respond(w, 200, "application/xml", res.as_bytes());
        }
        "GET" => match o.get(key) {
            Some(b) => {
                let b = b.clone();
                respond(w, 200, "application/octet-stream", &b);
            }
            None => fail(w, 404, "NoSuchKey"),
        },
        "DELETE" => {
            o.remove(key);
            respond(w, 204, "", b"");
        }
        _ => fail(w, 405, "MethodNotAllowed"),
    }
}

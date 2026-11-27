//! Cloudflare's DNS API as libdns/cloudflare (v0.2.2) uses it for TXT
//! records: the zone's ID by name (kept per provider), a record created
//! with its content quoted, and deleted after a lookup by type, name, and
//! content. The token goes only in the Authorization header and never in
//! an error. The API's address is Cloudflare's unless a test names
//! another.

use std::collections::HashMap;
use std::sync::Arc;

use armada_node::http::{Client as HttpClient, form_encode};
use serde_json::Value;

use super::protocol::send;

pub const API: &str = "https://api.cloudflare.com/client/v4";

/// A TXT record as AppendRecords returns it (libdns.TXT, its name relative
/// to the zone).
#[derive(Clone, Debug)]
pub struct TxtRecord {
    pub name: String,
    pub text: String,
}

/// The provider for one API token.
pub struct Provider {
    token: String,
    api: String,
    http: Arc<HttpClient>,
    zones: tokio::sync::Mutex<HashMap<String, (String, String)>>,
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cloudflare (token redacted)")
    }
}

pub fn relative_name(fqdn: &str, zone: &str) -> String {
    let f = fqdn.strip_suffix('.').unwrap_or(fqdn);
    let z = zone.strip_suffix('.').unwrap_or(zone);
    let rel = f.strip_suffix(z).unwrap_or(f);
    let rel = rel.strip_suffix('.').unwrap_or(rel);
    if rel.is_empty() && !fqdn.is_empty() && !zone.is_empty() {
        return "@".to_string();
    }
    rel.to_string()
}

pub fn absolute_name(name: &str, zone: &str) -> String {
    if zone.is_empty() {
        return name.trim_matches('.').to_string();
    }
    if name.is_empty() || name == "@" {
        return zone.to_string();
    }
    if name.ends_with('.') {
        return name.to_string();
    }
    format!("{name}.{zone}")
}

/// A TXT value in double quotes (" and \ escaped, non-printable runes as
/// \x, \u, or \U escapes), unless already quoted.
fn wrap(content: &str) -> String {
    if !content.starts_with('"') && !content.ends_with('"') {
        armada_spec::go::quote(content)
    } else {
        content.to_string()
    }
}

fn unwrap(content: &str) -> String {
    if content.len() >= 2 && content.starts_with('"') && content.ends_with('"') {
        content[1..content.len() - 1].to_string()
    } else if content == "\"" {
        String::new()
    } else {
        content.to_string()
    }
}

impl Provider {
    pub fn new(token: &str, api: &str, http: Arc<HttpClient>) -> Provider {
        Provider {
            token: token.to_string(),
            api: api.trim_end_matches('/').to_string(),
            http,
            zones: Default::default(),
        }
    }

    /// One API request: the response's result, or the error text.
    async fn api(
        &self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(Value, Value), String> {
        let mut headers = vec![(
            "Authorization".to_string(),
            format!("Bearer {}", self.token),
        )];
        if body.is_some() {
            headers.push(("Content-Type".to_string(), "application/json".to_string()));
        }
        let resp = send(&self.http, method, url, headers, body).await?;
        let data: Value = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
        let errors = data.get("errors").cloned().unwrap_or(Value::Null);
        if resp.status >= 400 {
            return Err(format!(
                "got error status: HTTP {}: {}",
                resp.status,
                go_errors(&errors)
            ));
        }
        if errors.as_array().is_some_and(|a| !a.is_empty()) {
            return Err(format!(
                "got errors: HTTP {}: {}",
                resp.status,
                go_errors(&errors)
            ));
        }
        let result = data.get("result").cloned().unwrap_or(Value::Null);
        let info = data.get("result_info").cloned().unwrap_or(Value::Null);
        Ok((result, info))
    }

    /// The zone's ID and name (as Cloudflare writes it).
    async fn zone(&self, zone: &str) -> Result<(String, String), String> {
        let mut zones = self.zones.lock().await;
        if let Some(z) = zones.get(zone) {
            return Ok(z.clone());
        }
        let url = format!("{}/zones?{}", self.api, form_encode(&[("name", zone)]));
        let (result, _) = self.api("GET", &url, None).await?;
        let list = result.as_array().cloned().unwrap_or_default();
        if list.len() != 1 {
            return Err(format!("expected 1 zone, got {} for {zone}", list.len()));
        }
        let id = list[0]
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let name = list[0]
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        zones.insert(zone.to_string(), (id.clone(), name.clone()));
        Ok((id, name))
    }

    /// Creates one TXT record.
    pub async fn append_txt(
        &self,
        zone: &str,
        name: &str,
        text: &str,
    ) -> Result<TxtRecord, String> {
        let (id, _) = self.zone(zone).await?;
        // Zero times and the data's tag are never left out.
        let body = format!(
            r#"{{"type":"TXT","name":{},"content":{},"created_on":"0001-01-01T00:00:00Z","modified_on":"0001-01-01T00:00:00Z","data":{{"tag":""}}}}"#,
            json_str(name),
            json_str(&wrap(text))
        );
        let url = format!("{}/zones/{id}/dns_records", self.api);
        let (result, _) = self.api("POST", &url, Some(body.into_bytes())).await?;
        let rname = result
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let content = result
            .get("content")
            .and_then(Value::as_str)
            .unwrap_or_default();
        Ok(TxtRecord {
            name: relative_name(rname, zone),
            text: unwrap(content),
        })
    }

    /// DeleteRecords of one TXT record: the records of its type, name, and
    /// content, each deleted.
    pub async fn delete_txt(&self, zone: &str, rec: &TxtRecord) -> Result<(), String> {
        let (id, zname) = self.zone(zone).await?;
        let content = wrap(&rec.text);
        let unwrapped = unwrap(&content);
        let abs = absolute_name(&rec.name, &zname);
        let q = form_encode(&[
            ("type", "TXT"),
            ("name", &abs),
            ("content.contains", &unwrapped),
        ]);
        let url = format!("{}/zones/{id}/dns_records?{q}", self.api);
        // A failed lookup of TXT records counts as no matches, so it
        // deletes nothing and reports nothing.
        let list = match self.api("GET", &url, None).await {
            Ok((result, _)) => result.as_array().cloned().unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        let content_of = |r: &Value| {
            r.get("content")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let matched = list
            .iter()
            .find(|r| content_of(r) == content)
            .or_else(|| list.iter().find(|r| content_of(r) == unwrapped));
        if let Some(r) = matched {
            let rid = r.get("id").and_then(Value::as_str).unwrap_or_default();
            let url = format!("{}/zones/{id}/dns_records/{rid}", self.api);
            self.api("DELETE", &url, None).await?;
        }
        Ok(())
    }
}

fn json_str(s: &str) -> String {
    String::from_utf8_lossy(&super::protocol::go_marshal(s)).into_owned()
}

/// The response's errors as text: [{Code:N Message:TEXT ErrorChain:[...]}].
fn go_errors(v: &Value) -> String {
    let one = |e: &Value, chain: bool| {
        let code = e.get("code").and_then(Value::as_i64).unwrap_or_default();
        let msg = e.get("message").and_then(Value::as_str).unwrap_or_default();
        if !chain {
            return format!("{{Code:{code} Message:{msg}}}");
        }
        let links: Vec<String> = e
            .get("error_chain")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|l| {
                        format!(
                            "{{Code:{} Message:{}}}",
                            l.get("code").and_then(Value::as_i64).unwrap_or_default(),
                            l.get("message").and_then(Value::as_str).unwrap_or_default()
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        format!(
            "{{Code:{code} Message:{msg} ErrorChain:[{}]}}",
            links.join(" ")
        )
    };
    let items: Vec<String> = v
        .as_array()
        .map(|a| a.iter().map(|e| one(e, true)).collect())
        .unwrap_or_default();
    format!("[{}]", items.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_as_libdns_writes_them() {
        assert_eq!(
            relative_name("_acme-challenge.a.example.com.", "example.com."),
            "_acme-challenge.a"
        );
        assert_eq!(relative_name("example.com.", "example.com."), "@");
        assert_eq!(
            absolute_name("_acme-challenge.a", "example.com"),
            "_acme-challenge.a.example.com"
        );
        assert_eq!(wrap("abc"), "\"abc\"");
        assert_eq!(unwrap("\"abc\""), "abc");
        assert_eq!(
            go_errors(&serde_json::json!([{"code": 9109, "message": "Invalid access token"}])),
            "[{Code:9109 Message:Invalid access token ErrorChain:[]}]"
        );
    }
}

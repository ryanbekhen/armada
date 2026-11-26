//! JSON over HTTPS for `armada-pack outdated`: GitHub's API and OSV's.
//! curl does the transfer, as for downloads (fetch.rs): HTTPS only, for
//! the request and every redirect. A GitHub token, when given, reaches
//! curl on its standard input as a config line, never as an argument.

use std::io::Write;
use std::process::{Command, Stdio};

use serde::de::DeserializeOwned;

/// The largest answer accepted.
const MAX_ANSWER: u64 = 64 << 20;

/// What to send.
pub enum Body<'a> {
    None,
    Json(&'a str),
}

/// request: url's answer as T. headers are added as given; token, when
/// set, is sent as a bearer token.
pub fn request<T: DeserializeOwned>(
    url: &str,
    body: Body,
    headers: &[&str],
    token: Option<&str>,
) -> Result<T, String> {
    let b = request_bytes(url, body, headers, token)?;
    serde_json::from_slice(&b).map_err(|e| format!("{url}: {e}"))
}

fn request_bytes(
    url: &str,
    body: Body,
    headers: &[&str],
    token: Option<&str>,
) -> Result<Vec<u8>, String> {
    if !url.starts_with("https://") {
        return Err(format!("refusing non-HTTPS URL {url}"));
    }
    // The config curl reads on stdin: the token's header, if any.
    let mut config = String::new();
    if let Some(t) = token {
        if !t
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.')
        {
            return Err("the GitHub token holds characters a token never has".into());
        }
        config.push_str(&format!("header = \"Authorization: Bearer {t}\"\n"));
    }
    let mut cmd = Command::new("curl");
    cmd.args([
        "-sSL",
        "--fail-with-body",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--retry",
        "3",
        "--max-time",
        "120",
        "--max-filesize",
        &MAX_ANSWER.to_string(),
        "-A",
        "armada-pack",
        "-K",
        "-",
    ]);
    for h in headers {
        cmd.arg("-H").arg(h);
    }
    if let Body::Json(b) = body {
        cmd.args(["-H", "Content-Type: application/json", "--data-binary"]);
        cmd.arg(b);
    }
    cmd.arg("--").arg(url);
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("curl: {e}"))?;
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(config.as_bytes())
        .map_err(|e| format!("curl: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("curl: {e}"))?;
    if !out.status.success() {
        let answer = String::from_utf8_lossy(&out.stdout);
        let answer: String = answer.trim().chars().take(300).collect();
        return Err(format!(
            "{url}: curl {}: {} {answer}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

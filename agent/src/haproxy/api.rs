//! HAProxy's Runtime API over its Unix socket: one command
//! per connection, payloads as `cmd <<` blocks, and answers that start with
//! one of HAProxy's error words returned as errors.

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::proxy::BoxFut;

/// The Runtime API as the driver uses it.
pub trait Api: Send + Sync + 'static {
    fn command<'a>(&'a self, cmd: &'a str) -> BoxFut<'a, Result<String, String>>;
    fn payload<'a>(&'a self, cmd: &'a str, payload: &'a str) -> BoxFut<'a, Result<String, String>>;
}

/// The largest answer read: show stat of many backends is large.
pub const MAX_RESPONSE: usize = 128 << 20;

const ERROR_PREFIXES: [&str; 12] = [
    "no such",
    "unknown",
    "require",
    "can't",
    "cannot",
    "missing",
    "invalid",
    "error",
    "failed",
    "unable",
    "not found",
    "permission denied",
];

/// The admin socket of the running HAProxy.
pub struct Socket {
    pub path: PathBuf,
    /// 0: five seconds.
    pub timeout: Duration,
}

/// An empty line would end the payload early.
pub fn check_payload(payload: &str) -> Result<(), String> {
    if payload.trim_end_matches('\n').contains("\n\n") {
        return Err("payload must not contain empty lines".into());
    }
    Ok(())
}

/// The PEM without its empty lines.
pub fn pem_payload(b: &[u8]) -> String {
    let text = String::from_utf8_lossy(b);
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        if line.trim().is_empty() {
            continue;
        }
        out.push_str(line.trim_end_matches(['\r', '\n']));
        out.push('\n');
    }
    out
}

fn single(cmd: &str) -> Result<(), String> {
    if cmd.contains(['\r', '\n', ';']) {
        return Err("runtime API command must be a single statement".into());
    }
    Ok(())
}

impl Socket {
    async fn send(&self, msg: String) -> Result<String, String> {
        let timeout = if self.timeout.is_zero() {
            Duration::from_secs(5)
        } else {
            self.timeout
        };
        let call = async {
            let mut c = tokio::net::UnixStream::connect(&self.path)
                .await
                .map_err(|e| format!("haproxy runtime API: {e}"))?;
            c.write_all(msg.as_bytes())
                .await
                .map_err(|e| format!("haproxy runtime API: {e}"))?;
            let mut b = Vec::new();
            (&mut c)
                .take(MAX_RESPONSE as u64 + 1)
                .read_to_end(&mut b)
                .await
                .map_err(|e| format!("haproxy runtime API: {e}"))?;
            Ok::<_, String>(b)
        };
        let b = tokio::time::timeout(timeout, call)
            .await
            .map_err(|_| "haproxy runtime API: i/o timeout".to_string())??;
        if b.len() > MAX_RESPONSE {
            return Err(format!(
                "haproxy runtime API: reply larger than {MAX_RESPONSE} bytes"
            ));
        }
        let out = String::from_utf8_lossy(&b).trim().to_string();
        let lower = out.to_lowercase();
        if ERROR_PREFIXES.iter().any(|p| lower.starts_with(p)) {
            return Err(format!("haproxy runtime API: {out}"));
        }
        Ok(out)
    }
}

impl Api for Socket {
    fn command<'a>(&'a self, cmd: &'a str) -> BoxFut<'a, Result<String, String>> {
        Box::pin(async move {
            single(cmd)?;
            self.send(format!("{cmd}\n")).await
        })
    }

    fn payload<'a>(&'a self, cmd: &'a str, payload: &'a str) -> BoxFut<'a, Result<String, String>> {
        Box::pin(async move {
            single(cmd)?;
            let payload = payload.trim_end_matches('\n');
            check_payload(payload)?;
            self.send(format!("{cmd} <<\n{payload}\n\n")).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::net::UnixListener;

    #[test]
    fn payloads() {
        assert_eq!(pem_payload(b"a\r\n\n\nb\n  \n"), "a\nb\n");
        assert!(check_payload("a\n\nb").is_err());
        assert!(check_payload("a\nb\n\n").is_ok());
    }

    #[tokio::test]
    async fn socket_sends_one_statement() {
        let dir = std::env::temp_dir().join(format!("armada-hapi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("admin.sock");
        let l = UnixListener::bind(&path).unwrap();
        let got = Arc::new(Mutex::new(Vec::<String>::new()));
        let rec = got.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut c, _)) = l.accept().await else {
                    return;
                };
                let mut b = vec![0u8; 4096];
                let n = c.read(&mut b).await.unwrap();
                let req = String::from_utf8_lossy(&b[..n]).to_string();
                rec.lock().unwrap().push(req.clone());
                let answer = if req.starts_with("bad") {
                    "Unknown command\n"
                } else {
                    "  done \n"
                };
                c.write_all(answer.as_bytes()).await.unwrap();
            }
        });
        let s = Socket {
            path,
            timeout: Duration::ZERO,
        };
        assert_eq!(s.command("show info").await.unwrap(), "done");
        assert_eq!(
            s.command("bad").await.unwrap_err(),
            "haproxy runtime API: Unknown command"
        );
        assert!(s.command("a;b").await.is_err());
        assert_eq!(s.payload("add map @1 x", "a b\n\n").await.unwrap(), "done");
        assert_eq!(
            got.lock().unwrap().clone(),
            vec!["show info\n", "bad\n", "add map @1 x <<\na b\n\n"]
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}

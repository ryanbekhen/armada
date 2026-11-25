//! A small structured logger in the shape of Go's log/slog text handler
//! (armada-server's): `time=... level=INFO msg="..." key=value ...` on
//! stderr. Values are quoted when they hold spaces, quotes, `=`, or control
//! characters. Secrets are never passed to it.

use std::io::Write;
use std::sync::Arc;

/// Where log lines go: stderr, or nowhere (Go's slog.DiscardHandler).
#[derive(Clone)]
pub struct Logger {
    out: Option<Arc<std::sync::Mutex<()>>>,
    debug: bool,
    attrs: Vec<(String, String)>,
}

impl Logger {
    /// A logger that writes nothing.
    pub fn discard() -> Logger {
        Logger {
            out: None,
            debug: false,
            attrs: Vec::new(),
        }
    }

    /// A logger writing to stderr.
    pub fn stderr(debug: bool) -> Logger {
        Logger {
            out: Some(Arc::new(std::sync::Mutex::new(()))),
            debug,
            attrs: Vec::new(),
        }
    }

    /// Go's Logger.With.
    pub fn with(&self, k: &str, v: &str) -> Logger {
        let mut l = self.clone();
        l.attrs.push((k.to_string(), v.to_string()));
        l
    }

    #[allow(dead_code)]
    pub fn debug(&self, msg: &str, kv: &[(&str, String)]) {
        if self.debug {
            self.write("DEBUG", msg, kv);
        }
    }

    pub fn info(&self, msg: &str, kv: &[(&str, String)]) {
        self.write("INFO", msg, kv);
    }

    pub fn warn(&self, msg: &str, kv: &[(&str, String)]) {
        self.write("WARN", msg, kv);
    }

    pub fn error(&self, msg: &str, kv: &[(&str, String)]) {
        self.write("ERROR", msg, kv);
    }

    fn write(&self, level: &str, msg: &str, kv: &[(&str, String)]) {
        let Some(lock) = &self.out else { return };
        let mut line = format!(
            "time={} level={level} msg={}",
            crate::clock::rfc3339_nano(std::time::SystemTime::now()),
            quote(msg)
        );
        for (k, v) in self
            .attrs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .chain(kv.iter().map(|(k, v)| (*k, v.as_str())))
        {
            line.push(' ');
            line.push_str(k);
            line.push('=');
            line.push_str(&quote(v));
        }
        line.push('\n');
        let _g = lock.lock().unwrap_or_else(|p| p.into_inner());
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
}

fn quote(v: &str) -> String {
    let plain = !v.is_empty()
        && v.chars()
            .all(|c| !c.is_control() && c != ' ' && c != '"' && c != '=' && c != '\\');
    if plain {
        return v.to_string();
    }
    armada_pki::go_quote(v)
}

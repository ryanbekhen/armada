//! The fake armada-node of the agent's replayed scenarios (agent/tests,
//! ADR 0055 item 20): a port of fakeNode in internal/agent/parity_side_test.go.
//! It answers volume, NFS, and connection tracking calls from the script
//! in $ARMADA_FAKE_NODE_ROOT/script.json and records each call with its
//! request in node.log there. Never part of a release.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, Read, Write};
use std::os::fd::FromRawFd;
use std::path::Path;

use serde_json::Value;

/// encoding/json's Marshal of a decoded value: keys sorted, <, >, and &
/// escaped, numbers as float64 writes them for whole numbers.
fn go_json(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => match n.as_f64() {
            Some(f) if f.fract() == 0.0 && f.abs() < 1e21 => out.push_str(&format!("{f:.0}")),
            _ => out.push_str(&n.to_string()),
        },
        Value::String(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                        out.push_str(&format!("\\u{:04x}", c as u32))
                    }
                    c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                go_json(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                go_json(&Value::String((*k).clone()), out);
                out.push(':');
                go_json(&m[*k], out);
            }
            out.push('}');
        }
    }
}

/// Go's strconv.Quote, for what the calls carry.
fn quote(b: &[u8]) -> String {
    let mut out = String::from("\"");
    for c in String::from_utf8_lossy(b).chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn fd(n: i32) -> File {
    // SAFETY: the agent starts this program with descriptor n open for
    // it (volume archive and restore); nothing else here owns it.
    unsafe { File::from_raw_fd(n) }
}

fn raw(v: &Value) -> Vec<u8> {
    // A json.RawMessage written as it was read: null too.
    v.to_string().into_bytes()
}

fn run(root: &Path, args: &[String]) -> i32 {
    let sc: Value = std::fs::read(root.join("script.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);
    let Ok(mut log) = OpenOptions::new()
        .append(true)
        .create(true)
        .open(root.join("node.log"))
    else {
        return 2;
    };
    let root_s = root.display().to_string();
    let mut rec = |s: String| {
        let _ = writeln!(log, "{}", s.replace(&root_s, "$ROOT"));
    };
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let request = |input: &mut dyn BufRead| -> String {
        let mut line = String::new();
        let _ = input.read_line(&mut line);
        let Ok(Value::Object(mut m)) = serde_json::from_str::<Value>(&line) else {
            return line.trim().to_string();
        };
        m.remove("now");
        m.remove("timeoutMs");
        if let Some(Value::Array(z)) = m.get("zone") {
            let n = z.len();
            m.insert("zone".into(), Value::from(n));
        }
        let mut out = String::new();
        go_json(&Value::Object(m), &mut out);
        out
    };
    let answer = |key: &str, def: &str| -> String {
        sc["answers"][key]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| def.to_string())
    };
    if args.len() < 2 {
        return 2;
    }
    let op = format!("{} {}", args[0], args[1]);
    let mut stdout = std::io::stdout();
    match op.as_str() {
        "volume archive" => {
            rec(format!("volume archive {}", args[2]));
            let _ = stdout.write_all(sc["archive"].as_str().unwrap_or("").as_bytes());
            let _ = stdout.flush();
            let _ = fd(3).write_all(&raw(&sc["archiveAnswer"]));
        }
        "volume restore" => {
            let mut fd3 = fd(3);
            let _ = fd3.write_all(b"ready\n");
            let mut data = Vec::new();
            let _ = input.read_to_end(&mut data);
            let mut session = Vec::new();
            let _ = fd(4).read_to_end(&mut session);
            rec(format!(
                "volume restore {} stdin={} session={}",
                args[2],
                quote(&data),
                String::from_utf8_lossy(&session)
            ));
            let _ = fd3.write_all(&raw(&sc["restoreAnswer"]));
        }
        "volume size" => {
            let sizes: Vec<usize> = args[2..]
                .iter()
                .map(|d| {
                    100 * Path::new(d)
                        .file_name()
                        .map(|n| n.len())
                        .unwrap_or_default()
                })
                .collect();
            rec(format!("volume size {}", args[2..].join(" ")));
            let sizes = if sizes.is_empty() {
                "null".to_string()
            } else {
                serde_json::to_string(&sizes).unwrap()
            };
            let _ = writeln!(stdout, "{{\"sizes\":{sizes}}}");
        }
        "volume snapshot" | "volume prune" | "volume snapshots" => {
            let r = request(&mut input);
            rec(format!("{op} {r}"));
            let _ = writeln!(stdout, "touched");
            let _ = writeln!(stdout, "{}", answer(&op, "{}"));
        }
        "volume restore-snapshot" => {
            let r = request(&mut input);
            rec(format!("{op} {r}"));
            let ready = sc["readySnapshot"].as_str().unwrap_or("");
            if ready.is_empty() {
                let _ = writeln!(stdout, "{}", answer(&op, "{}"));
                return 0;
            }
            let _ = writeln!(stdout, "ready {ready}");
            let _ = stdout.flush();
            let mut go = String::new();
            let _ = input.read_line(&mut go);
            rec(format!("restore-snapshot then {}", quote(go.as_bytes())));
            let _ = writeln!(stdout, "touched");
            let _ = writeln!(stdout, "{}", answer(&op, "{}"));
        }
        "nfs source" | "nfs unmount" | "nfs mount" | "conntrack read" | "conntrack raise" => {
            let r = request(&mut input);
            rec(format!("{op} {r}"));
            let _ = writeln!(stdout, "{}", answer(&op, "{}"));
        }
        _ => {
            rec(format!("unknown {args:?}"));
            return 2;
        }
    }
    let _ = stdout.flush();
    0
}

fn main() {
    let root = std::env::var("ARMADA_FAKE_NODE_ROOT").unwrap_or_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(run(Path::new(&root), &args));
}

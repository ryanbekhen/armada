//! The agent's parity scenarios, recorded once from Go's agent
//! (internal/agent/parity_record_test.go: go test ./internal/agent -run
//! 'TestAgentParity' -record-scenarios) and replayed here against the Rust
//! agent's parity program with the fakes ported to Rust (ADR 0055, item
//! 20). ARMADA_REPLAY_ONLY=TEXT replays only the scenarios whose name
//! holds TEXT.

mod replay;

use std::sync::Arc;

use serde_json::{Value, json};

use replay::fake::Fake;
use replay::program::Program;

#[test]
fn agent_parity() {
    replay::replay_all("TestAgentParity");
}

#[test]
fn agent_parity_ingress() {
    replay::replay_all("TestAgentParityIngress");
}

#[test]
fn agent_parity_side() {
    replay::replay_all("TestAgentParitySide");
}

#[test]
fn agent_parity_hello() {
    replay::replay_all("TestAgentParityHello");
}

fn read(name: &str) -> Vec<Value> {
    let b = std::fs::read(replay::testdata().join(name)).unwrap();
    serde_json::from_slice(&b).unwrap()
}

fn program() -> Program {
    Program::start(Arc::new(Fake::new(0, String::new(), true, vec![])))
}

/// The spec hash of every spec Go hashed.
#[test]
fn agent_parity_spec_hash() {
    let prog = program();
    let mut bad = Vec::new();
    for c in read("hash.json") {
        let ans = prog.request("hash", json!({"spec": c["spec"]})).unwrap();
        if ans["hash"] != c["hash"] {
            bad.push(format!(
                "{}: go {} rust {}",
                c["spec"], c["hash"], ans["hash"]
            ));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// The reconnect waits Go worked out (a failover's wait without Go's
/// jitter, as the program is asked without one).
#[test]
fn agent_parity_reconnect() {
    let prog = program();
    let mut bad = Vec::new();
    for c in read("reconnect.json") {
        let ans = prog
            .request(
                "reconnect",
                json!({"accepted": c["accepted"], "backoffNs": c["backoffNs"],
                    "lostNs": c["lostNs"], "nowNs": c["nowNs"]}),
            )
            .unwrap();
        if ans["waitNs"] != c["waitNs"]
            || ans["backoffNs"] != c["wantBackoffNs"]
            || ans["lostNs"] != c["wantLostNs"]
        {
            bad.push(format!("{c}: rust {ans}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Serves what parity_session_test.go's check server serves: /ok, a
/// redirect at /moved, a second's wait at /slow, 503 elsewhere.
fn check_server() -> String {
    use std::io::{BufRead, BufReader, Write};
    let lis = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = lis.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for conn in lis.incoming() {
            let Ok(mut conn) = conn else { break };
            std::thread::spawn(move || {
                let mut r = BufReader::new(conn.try_clone().unwrap());
                let mut line = String::new();
                if r.read_line(&mut line).is_err() {
                    return;
                }
                loop {
                    let mut h = String::new();
                    if r.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                        break;
                    }
                }
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                let resp = match path.as_str() {
                    "/ok" => "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nfine".to_string(),
                    "/moved" => {
                        "HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\n\r\n"
                            .to_string()
                    }
                    "/slow" => {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string()
                    }
                    _ => {
                        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".to_string()
                    }
                };
                let _ = conn.write_all(resp.as_bytes());
            });
        }
    });
    addr
}

/// The health check's answers Go gave, addresses aside.
#[test]
fn agent_parity_check() {
    let prog = program();
    let addr = check_server();
    let refused = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    };
    let mut bad = Vec::new();
    for c in read("check.json") {
        let a = c["addr"]
            .as_str()
            .unwrap()
            .replace("$ADDR", &addr)
            .replace("$REFUSED", &refused);
        let ans = prog
            .request(
                "check",
                json!({"addr": a, "path": c["path"], "timeoutMs": c["timeoutMs"]}),
            )
            .unwrap();
        let got = ans["error"]
            .as_str()
            .unwrap_or("")
            .replace(&addr, "$ADDR")
            .replace(&refused, "$REFUSED");
        if got != c["error"].as_str().unwrap() {
            bad.push(format!(
                "check {} {}: go {}, rust {got:?}",
                c["addr"], c["path"], c["error"]
            ));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// A whole session over mTLS: both Hellos, and the first report and the
/// last before the control plane ends the first session.
#[test]
fn agent_parity_session() {
    use armada_proto::armada::v1 as pb;
    let dir = replay::temp_dir("session");
    let sh = replay::side::Side::start(dir.clone());
    let asg: pb::Assignment = serde_json::from_value(json!({"replicas": [{
        "id": "web-r1-a", "app": "web", "revision": "web--r1", "image": "nginx:1",
        "command": ["/bin/web"], "args": ["--x"],
        "env": [{"name": "A", "value": "1"}, {"name": "S", "value": "secret", "ref": "s/v1"}],
        "memoryBytes": "268435456", "pidsLimit": "1024", "nanoCpus": "500000000",
        "cpuReserveMillis": "100",
    }]}))
    .unwrap();
    sh.set_session(asg);
    let prog = program();
    prog.request(
        "config",
        json!({"config": {"nodeId": "n1", "privateIp": "10.0.0.2", "cpuMillis": 2000,
            "memoryBytes": 1i64 << 30, "nowNs": replay::T0_NS, "os": "linux", "arch": "amd64",
            "caps": {"members": true, "exec": true, "stats": true, "logs": true}}}),
    )
    .unwrap();
    prog.request("run", sh.connect()).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while sh.session().hellos.len() < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "the agent never came back for a second session"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let s = sh.session();
    let mut got = Vec::new();
    for h in &s.hellos {
        let mut v = serde_json::to_value(h).unwrap();
        v["version"] = json!("VERSION");
        got.push(format!("hello {v}"));
    }
    got.push(format!(
        "first {}",
        serde_json::to_value(&s.reports[0]).unwrap()
    ));
    got.push(format!(
        "last {}",
        serde_json::to_value(s.reports.last().unwrap()).unwrap()
    ));
    let want: Vec<String> =
        serde_json::from_slice(&std::fs::read(replay::testdata().join("session.json")).unwrap())
            .unwrap();
    let canon =
        |v: &[String]| -> Vec<String> { v.iter().map(|l| replay::gofmt::canon_line(l)).collect() };
    assert_eq!(canon(&want), canon(&got));
    drop(sh);
    let _ = std::fs::remove_dir_all(dir);
}

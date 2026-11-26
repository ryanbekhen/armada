//! The client's parity cases recorded from Go (ADR 0055, item 20),
//! replayed against this armada.
//!
//! Go's TestClientParity, before the Go code was removed, ran
//! every case of Go's client parity harness (the cases written for it,
//! every example line of every command, and every command's help) against
//! Go's armada alone and wrote testdata/parity.jsonl.gz: each case's
//! arguments, environment, standard input, files, and starting client
//! config, the time Go's run started, the scripted answers of the fake
//! AdminService, and Go's outcome. Each case runs here against the armada
//! built with the test-hooks feature (its clock starts at the recorded
//! time) and a stand-in AdminService of this test's (server.rs: mTLS with
//! certificates issued for the run, the same answers), and its exit code,
//! standard output and error, the requests the stand-in received, the
//! client config left, and the files left with their modes are compared
//! with Go's, normalized as Go's harness compares (norm.rs).
//!
//! This test is its own harness (`harness = false`), since its binary is
//! also the ssh(1) the cases reach the API through, as Go's sshtest is:
//! started as `ssh -o ExitOnForwardFailure=yes -W ADDR -- DEST`, it
//! relays to ADDR when DEST is bastion.test. An argument, or
//! ARMADA_PARITY_CASE, runs only the cases whose names contain it;
//! ARMADA_PARITY_VERBOSE=1 prints each case's outcome.

mod norm;
mod server;

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/testdata/parity.jsonl.gz"
);

/// The host the ssh stand-in reaches (Go's sshtest.Host).
const SSH_HOST: &str = "bastion.test";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 7 && args[1] == "-o" && args[3] == "-W" && args[5] == "--" {
        ssh(&args[4], &args[6]);
    }
    // The recording's: what the client makes without a mode of its own.
    // SAFETY: umask only sets this process's file mode mask.
    unsafe { libc::umask(0o022) };
    let filter = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with('-'))
        .cloned()
        .or_else(|| std::env::var("ARMADA_PARITY_CASE").ok())
        .unwrap_or_default();
    std::process::exit(run(&filter));
}

/// The ssh stand-in (Go's sshtest.Main).
fn ssh(addr: &str, dest: &str) -> ! {
    if dest != SSH_HOST && dest != format!("ops@{SSH_HOST}") {
        eprintln!("ssh: Could not resolve hostname {dest}: Name or service not known");
        std::process::exit(255);
    }
    let c = match TcpStream::connect(addr) {
        Ok(c) => c,
        Err(e) => {
            let why = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                "connect: connection refused".to_string()
            } else {
                e.to_string()
            };
            eprintln!("channel 0: open failed: connect failed: dial tcp {addr}: {why}");
            std::process::exit(255);
        }
    };
    let mut w = c.try_clone().unwrap();
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut std::io::stdin(), &mut w);
        let _ = w.shutdown(std::net::Shutdown::Write);
    });
    // Stdout is line-buffered: every chunk is flushed as it comes.
    let mut r = c;
    let mut out = std::io::stdout().lock();
    let mut buf = [0u8; 32 * 1024];
    while let Ok(n) = r.read(&mut buf) {
        if n == 0 || out.write_all(&buf[..n]).is_err() || out.flush().is_err() {
            break;
        }
    }
    std::process::exit(0);
}

pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes() {
        let v = T.iter().position(|&t| t == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// What differs between Go's recording and this run.
struct Places {
    pairs: Vec<(String, String)>,
}

impl Places {
    fn new(certs: &server::Certs, addr: &str, dir: &Path) -> Places {
        let mut pairs = Vec::new();
        for (v, name) in [
            (&certs.ca, "CA"),
            (&certs.cert, "CERT"),
            (&certs.key, "KEY"),
        ] {
            pairs.push((v.clone(), format!("{{{name}}}")));
            pairs.push((v.replace('\n', "\\n"), format!("{{{name}_JSON}}")));
        }
        pairs.push((dir.display().to_string(), "{DIR}".into()));
        pairs.push((addr.to_string(), "{ADDR}".into()));
        Places { pairs }
    }

    /// This run's values in the recording's place.
    fn expand(&self, s: &str) -> String {
        let mut s = s.to_string();
        for (v, p) in &self.pairs {
            s = s.replace(p, v);
        }
        s
    }

    fn expand_value(&self, v: &Value) -> Value {
        match v {
            Value::String(s) => Value::String(self.expand(s)),
            Value::Array(a) => Value::Array(a.iter().map(|x| self.expand_value(x)).collect()),
            Value::Object(o) => Value::Object(
                o.iter()
                    .map(|(k, x)| (k.clone(), self.expand_value(x)))
                    .collect(),
            ),
            v => v.clone(),
        }
    }

    /// The recording's placeholders for this run's values.
    fn hide(&self, s: &str) -> String {
        let mut s = s.to_string();
        for (v, p) in &self.pairs {
            s = s.replace(v, p);
        }
        s
    }
}

/// A case's outcome, as the recording writes Go's.
#[derive(Debug)]
struct Outcome {
    code: i32,
    stdout: String,
    stderr: String,
    calls: Vec<server::Call>,
    config: String,
    files: Vec<String>,
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

fn answers(v: &Value, places: &Places) -> HashMap<String, Vec<server::Answer>> {
    let mut out = HashMap::new();
    let Some(o) = v.as_object() else { return out };
    for (method, list) in o {
        let list = list
            .as_array()
            .map(|l| {
                l.iter()
                    .map(|a| server::Answer {
                        msg: a.get("msg").map(|m| places.expand_value(m)),
                        code: a.get("code").and_then(Value::as_i64).unwrap_or(0) as i32,
                        text: places.expand(&s(a, "text")),
                        servers: places.expand(&s(a, "servers")),
                        stream: a.get("stream").map(|st| {
                            st.as_array()
                                .map(|l| {
                                    l.iter()
                                        .map(|m| (!m.is_null()).then(|| places.expand_value(m)))
                                        .collect()
                                })
                                .unwrap_or_default()
                        }),
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.insert(method.clone(), list);
    }
    out
}

/// os.MkdirAll(p, 0o700): every directory it makes is 0700.
fn mkdir(p: &Path) {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(p)
        .unwrap();
}

fn write(p: &Path, body: &[u8], mode: u32) {
    std::fs::write(p, body).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn config_path(dir: &Path) -> PathBuf {
    dir.join("home").join(".armada").join("config")
}

/// Go's prepare: the case's files and config afresh.
fn prepare(dir: &Path, case: &Value, places: &Places) {
    if dir.exists() {
        // Directories a case left read-only come back writable first.
        let _ = Command::new("chmod")
            .arg("-R")
            .arg("u+rwx")
            .arg(dir)
            .status();
        std::fs::remove_dir_all(dir).unwrap();
    }
    mkdir(dir);
    mkdir(&dir.join("home").join(".armada"));
    mkdir(&dir.join("cache"));
    if let Some(files) = case.get("files").and_then(Value::as_object) {
        for (name, body) in files {
            let p = dir.join(name);
            let parent = p.parent().unwrap();
            if !parent.exists() {
                mkdir(parent);
            }
            write(
                &p,
                places.expand(body.as_str().unwrap_or("")).as_bytes(),
                0o600,
            );
        }
    }
    if let Some(c) = case.get("config").filter(|c| !c.is_null()) {
        let mode = c.get("mode").and_then(Value::as_u64).unwrap_or(0o600) as u32;
        write(
            &config_path(dir),
            places.expand(&s(c, "text")).as_bytes(),
            mode,
        );
    }
}

/// Every other file and directory the command left, with its mode, as
/// Go's collect lists them (filepath.WalkDir's order).
fn files(dir: &Path, case: &Value, places: &Places) -> Vec<String> {
    let given: Vec<String> = case
        .get("files")
        .and_then(Value::as_object)
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    let mut out = Vec::new();
    fn walk(
        dir: &Path,
        rel: &str,
        given: &[String],
        cfg: &Path,
        out: &mut Vec<String>,
        places: &Places,
    ) {
        let mut names: Vec<_> = match std::fs::read_dir(dir.join(rel)) {
            Ok(r) => r
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => return,
        };
        names.sort();
        for n in names {
            let r = if rel.is_empty() {
                n.clone()
            } else {
                format!("{rel}/{n}")
            };
            let p = dir.join(&r);
            if p == cfg || r == "cache" {
                continue;
            }
            let Ok(md) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if !given.contains(&r) {
                let mut entry = format!("{r} {:04o}", md.permissions().mode() & 0o777);
                if md.is_file() {
                    let b = std::fs::read(&p).unwrap_or_default();
                    entry.push('\n');
                    entry.push_str(&places.hide(&norm::private_keys(&String::from_utf8_lossy(&b))));
                }
                out.push(entry);
            }
            if md.is_dir() {
                walk(dir, &r, given, cfg, out, places);
            }
        }
    }
    walk(dir, "", &given, &config_path(dir), &mut out, places);
    out
}

fn run_case(
    bin: &str,
    ssh_dir: &Path,
    dir: &Path,
    case: &Value,
    fake: &server::Fake,
    places: &Places,
) -> Outcome {
    prepare(dir, case, places);
    fake.reset(answers(case.get("answers").unwrap_or(&Value::Null), places));
    let mut env: BTreeMap<String, String> = [
        ("HOME", dir.join("home").display().to_string()),
        (
            "PATH",
            format!(
                "{}:{}",
                ssh_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        ),
        ("XDG_CACHE_HOME", dir.join("cache").display().to_string()),
        ("TZ", "UTC".into()),
        ("ARMADA_NO_UPDATE_CHECK", "1".into()),
        ("ARMADA_CONFIG", String::new()),
        ("ARMADA_SPACE", String::new()),
        ("CI", String::new()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    if let Some(e) = case.get("env").and_then(Value::as_object) {
        for (k, v) in e {
            env.insert(k.clone(), places.expand(v.as_str().unwrap_or("")));
        }
    }
    let now = case.get("now").and_then(Value::as_i64).unwrap_or(0);
    env.insert("ARMADA_CLIENT_TEST_NOW".into(), now.to_string());
    let args: Vec<String> = case
        .get("args")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|x| places.expand(x.as_str().unwrap_or("")))
                .collect()
        })
        .unwrap_or_default();
    let started = Instant::now();
    let mut child = Command::new(bin)
        .args(&args)
        .current_dir(dir)
        .env_clear()
        .envs(&env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = places.expand(&s(case, "stdin"));
    let mut w = child.stdin.take().unwrap();
    let feeder = std::thread::spawn(move || {
        let _ = w.write_all(stdin.as_bytes());
    });
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let ro = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        b
    });
    let re = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err.read_to_end(&mut b);
        b
    });
    let code = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st.code().unwrap_or(-1);
        }
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            let _ = child.wait();
            break -1;
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    let _ = feeder.join();
    let stdout = String::from_utf8_lossy(&ro.join().unwrap()).into_owned();
    let stderr = String::from_utf8_lossy(&re.join().unwrap()).into_owned();
    // Requests' times are worked out from the client's clock, which began
    // at the recorded time.
    let client_now = i128::from(now) + started.elapsed().as_nanos() as i128;
    let calls = fake
        .calls()
        .into_iter()
        .map(|mut c| {
            if let Some(r) = c.request.take() {
                let hidden: Value = serde_json::from_str(&places.hide(&r.to_string())).unwrap();
                c.request = Some(norm::request(hidden, client_now));
            }
            if let Some(st) = c.start.take() {
                c.start = Some(serde_json::from_str(&places.hide(&st.to_string())).unwrap());
            }
            c
        })
        .collect();
    let cfg = config_path(dir);
    let config = match std::fs::read(&cfg) {
        Ok(b) => {
            let mode = std::fs::metadata(&cfg).unwrap().permissions().mode() & 0o777;
            places.hide(&format!(
                "{mode:04o}\n{}",
                norm::private_keys(&String::from_utf8_lossy(&b))
            ))
        }
        Err(_) => String::new(),
    };
    Outcome {
        code,
        stdout: places.hide(&stdout),
        stderr: places.hide(&stderr),
        calls,
        files: files(dir, case, places),
        config,
    }
}

/// A recorded call in the stand-in's terms.
fn recorded_call(c: &Value) -> server::Call {
    let json_or_string =
        |s: &str| serde_json::from_str::<Value>(s).unwrap_or_else(|_| Value::String(s.to_string()));
    let method = s(c, "method");
    let mut call = server::Call {
        method: method.clone(),
        request: None,
        start: None,
        data: None,
        rest: None,
    };
    match method.as_str() {
        "RestoreVolume" => {
            let st = s(c, "start");
            call.start = Some(if st.is_empty() {
                Value::Null
            } else {
                json_or_string(&st)
            });
            call.data = base64_decode(&s(c, "data"));
        }
        "ExecInput" => {
            call.data = base64_decode(&s(c, "data"));
            call.rest = Some(
                c.get("rest")
                    .and_then(Value::as_array)
                    .map(|l| {
                        l.iter()
                            .map(|x| json_or_string(x.as_str().unwrap_or("")))
                            .collect()
                    })
                    .unwrap_or_default(),
            );
        }
        _ => {
            let r = s(c, "request");
            call.request = (!r.is_empty()).then(|| json_or_string(&r));
        }
    }
    call
}

/// The differences between Go's outcome and this run's.
fn compare(want: &Value, got: &Outcome) -> Vec<String> {
    let mut d = Vec::new();
    let code = want.get("code").and_then(Value::as_i64).unwrap_or(0) as i32;
    if code != got.code {
        d.push(format!("exit code: Go {code}, Rust {}", got.code));
    }
    for (name, w, g) in [
        ("stdout", s(want, "stdout"), &got.stdout),
        ("stderr", s(want, "stderr"), &got.stderr),
    ] {
        if norm::normalize(&w) != norm::normalize(g) {
            d.push(format!("{name} differs:\n--- Go\n{w}--- Rust\n{g}"));
        }
    }
    let calls: Vec<server::Call> = want
        .get("calls")
        .and_then(Value::as_array)
        .map(|l| l.iter().map(recorded_call).collect())
        .unwrap_or_default();
    let numbers = |c: &server::Call| {
        let mut c = c.clone();
        c.request = c.request.map(norm::go_numbers);
        c.start = c.start.map(norm::go_numbers);
        c.rest = c
            .rest
            .map(|r| r.into_iter().map(norm::go_numbers).collect());
        c
    };
    let (wc, gc): (Vec<_>, Vec<_>) = (
        calls.iter().map(numbers).collect(),
        got.calls.iter().map(numbers).collect(),
    );
    if wc != gc {
        d.push(format!(
            "requests differ:\n--- Go\n{wc:?}\n--- Rust\n{gc:?}"
        ));
    }
    let config = s(want, "config");
    if config != got.config {
        d.push(format!(
            "client config differs:\n--- Go\n{config}\n--- Rust\n{}",
            got.config
        ));
    }
    let files: Vec<String> = want
        .get("files")
        .and_then(Value::as_array)
        .map(|l| {
            l.iter()
                .map(|x| x.as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default();
    if files != got.files {
        d.push(format!(
            "files written differ:\n--- Go\n{}\n--- Rust\n{}",
            files.join("\n"),
            got.files.join("\n")
        ));
    }
    d
}

fn run(filter: &str) -> i32 {
    let bin = env!("CARGO_BIN_EXE_armada");
    let work = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "client-parity-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let ssh_dir = work.join("ssh");
    mkdir(&ssh_dir);
    std::os::unix::fs::symlink(std::env::current_exe().unwrap(), ssh_dir.join("ssh")).unwrap();
    let dir = work.join("case");

    let mut text = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(FIXTURE).expect("the recording"))
        .read_to_string(&mut text)
        .unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let certs = server::Certs::new();
    let fake = server::Fake::default();
    let addr = rt.block_on(server::start(fake.clone(), &certs));
    let places = Places::new(&certs, &addr, &dir);
    let verbose = std::env::var("ARMADA_PARITY_VERBOSE").is_ok_and(|v| !v.is_empty());

    let (mut ran, mut failed) = (0, Vec::new());
    for line in text.lines() {
        let case: Value = serde_json::from_str(line).unwrap();
        let name = s(&case, "name");
        if !name.contains(filter) {
            continue;
        }
        ran += 1;
        let got = run_case(bin, &ssh_dir, &dir, &case, &fake, &places);
        if verbose {
            println!(
                "{name}: exit {}\n--- stdout\n{}--- stderr\n{}",
                got.code, got.stdout, got.stderr
            );
        }
        let diffs = compare(case.get("go").unwrap_or(&Value::Null), &got);
        if !diffs.is_empty() {
            println!("FAIL {name}\n{}\n", diffs.join("\n"));
            failed.push(name);
        }
    }
    let _ = std::fs::remove_dir_all(&work);
    drop(rt);
    println!("{ran} cases, {} failed", failed.len());
    if ran == 0 {
        println!("no case matches {filter:?}");
        return 1;
    }
    if failed.is_empty() {
        0
    } else {
        for f in &failed {
            println!("  {f}");
        }
        1
    }
}

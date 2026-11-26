//! The daemon's parity cases recorded from Go (ADR 0055, item 20),
//! replayed against this armadad.
//!
//! Go's TestDaemonParity, before the Go code was removed, ran every case of Go's
//! daemon parity harness (the cases written for it, doctor's, the state
//! commands', the commands that set a machine up, every example line and
//! every command's help, and the units' cases) and wrote
//! testdata/parity.jsonl.gz: each case's arguments and environment as the
//! Rust armadad is run with them, its standard input, the case directory
//! as prepared, the state it needs, and the outcome it must give (Go's
//! through rustWants; for the paths of the Rust armadad alone, its own once
//! the case's checks passed). Each case runs here against the armadad
//! built with the test-hooks feature, with the same stand-ins first in
//! PATH (systemctl, cosign, timedatectl, ufw), the control plane's bucket
//! (bucket.rs), a server's running member where the case has one
//! (member.rs, the pinned etcd of ARMADA_ETCD_DIR), and doctor's clock at
//! the recorded time (ARMADA_DAEMON_TEST_NOW); its exit code, standard
//! output and error, and every file left (described.rs's collect) are
//! compared as compareDaemon compares them.
//!
//! This test is its own harness (`harness = false`): the cases run one
//! after another, an argument (or ARMADA_PARITY_CASE) runs only those
//! whose names contain it, ARMADA_PARITY_VERBOSE=1 prints each outcome.
//! Without ARMADA_ETCD_DIR the cases that need the pinned etcd are skipped.

mod bucket;
mod describe;
mod member;

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/testdata/parity.jsonl.gz"
);

/// The PATH after the stand-ins, the recording's (recordPath): what any
/// Linux machine has.
const RECORD_PATH: &str = "/usr/bin:/bin";

fn main() {
    // The recording's: files the stand-ins make are 0644.
    // SAFETY: umask only sets this process's file mode mask.
    unsafe { libc::umask(0o022) };
    let args: Vec<String> = std::env::args().collect();
    let filter = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with('-'))
        .cloned()
        .or_else(|| std::env::var("ARMADA_PARITY_CASE").ok())
        .unwrap_or_default();
    std::process::exit(run(&filter));
}

fn base64_decode(s: &str) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.trim_end_matches('=').bytes() {
        let v = T.iter().position(|&t| t == c).expect("base64") as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn s<'v>(v: &'v Value, k: &str) -> &'v str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn flag(v: &Value, k: &str) -> bool {
    v.get(k).and_then(Value::as_bool).unwrap_or(false)
}

/// What differs between Go's recording and this run.
struct Places {
    pairs: Vec<(String, String)>,
    ports: Option<(u16, u16)>,
}

impl Places {
    fn expand(&self, v: &str) -> String {
        let mut v = v.to_string();
        for (p, real) in &self.pairs {
            v = v.replace(p, real);
        }
        if let Some((a, b)) = self.ports {
            v = v
                .replace("{PORT0}", &a.to_string())
                .replace("{PORT1}", &b.to_string());
        }
        v
    }

    fn hide(&self, v: &str) -> String {
        let mut v = v.to_string();
        for (p, real) in &self.pairs {
            if !real.is_empty() && p != "{PATH}" {
                v = v.replace(real, p);
            }
        }
        if let Some((a, b)) = self.ports {
            v = v.replace(&format!("{a},{b}"), "{PORT0},{PORT1}");
            v = v.replace(&format!(":{a}"), ":{PORT0}");
            v = v.replace(&format!(":{b}"), ":{PORT1}");
        }
        v
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn set_mode(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// The case directory as recorded: directories first writable, their
/// modes set last, deepest first.
fn prepare(dir: &Path, tree: &[Value], blobs: &HashMap<String, Vec<u8>>, places: &Places) {
    if dir.exists() {
        let _ = Command::new("chmod")
            .arg("-R")
            .arg("u+rwx")
            .arg(dir)
            .status();
        std::fs::remove_dir_all(dir).unwrap();
    }
    std::fs::create_dir_all(dir).unwrap();
    let mut dirs = Vec::new();
    for e in tree {
        let p = dir.join(s(e, "path"));
        let mode = e.get("mode").and_then(Value::as_u64).unwrap_or(0) as u32;
        match s(e, "kind") {
            "dir" => {
                std::fs::create_dir_all(&p).unwrap();
                set_mode(&p, 0o700);
                dirs.push((p, mode));
            }
            "link" => std::os::unix::fs::symlink(places.expand(s(e, "target")), &p).unwrap(),
            _ => {
                let body = match e.get("blob").and_then(Value::as_str) {
                    Some(b) => blobs[b].clone(),
                    None => places.expand(s(e, "text")).into_bytes(),
                };
                std::fs::write(&p, body).unwrap();
                set_mode(&p, mode);
            }
        }
    }
    for (p, mode) in dirs.iter().rev() {
        set_mode(p, *mode);
    }
}

/// flock(LOCK_EX) on the member's database, as a running member holds it
/// (Go's holdDB).
fn hold_db(dir: &Path) -> std::fs::File {
    use std::os::fd::AsRawFd;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.join("data/etcd/data/member/snap/db"))
        .unwrap();
    // SAFETY: flock on a descriptor this function owns.
    assert_eq!(unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) }, 0);
    f
}

struct Outcome {
    code: i32,
    stdout: String,
    stderr: String,
    files: Vec<String>,
}

struct Run<'a> {
    bin: &'a str,
    work: PathBuf,
    standins: PathBuf,
    etcd_dir: Option<PathBuf>,
    bucket: bucket::Bucket,
    bucket_objs: BTreeMap<String, Vec<u8>>,
    blobs: HashMap<String, Vec<u8>>,
    master_key_id: String,
    interfaces: String,
    fs_type: String,
    rt: tokio::runtime::Runtime,
}

impl Run<'_> {
    fn case(&self, case: &Value) -> Result<Outcome, String> {
        let dir = self.work.join("case");
        let state = case.get("state");
        let ports = state.map(|_| (free_port(), free_port()));
        let mut pairs = vec![
            ("{DIR}".to_string(), dir.display().to_string()),
            (
                "{STANDINS}".to_string(),
                self.standins.display().to_string(),
            ),
            ("{BUCKET}".to_string(), self.bucket.addr.clone()),
            ("{PATH}".to_string(), RECORD_PATH.to_string()),
        ];
        if let Some(e) = &self.etcd_dir {
            pairs.push(("{ETCD_DIR}".to_string(), e.display().to_string()));
        }
        let places = Places { pairs, ports };
        let tree = case
            .get("tree")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        prepare(&dir, &tree, &self.blobs, &places);

        let state = state.cloned().unwrap_or(Value::Null);
        if flag(&state, "bucket") {
            self.bucket.load(self.bucket_objs.clone());
        } else {
            self.bucket.load(BTreeMap::new());
        }
        let member = if flag(&state, "member") {
            let etcd = self
                .etcd_dir
                .as_ref()
                .ok_or("no ARMADA_ETCD_DIR")?
                .join("etcd");
            let conf = self.work.join("member.yaml");
            Some(self.rt.block_on(member::Member::start(
                &etcd,
                &dir.join("data"),
                ports.unwrap(),
                conf,
                &self.master_key_id,
            ))?)
        } else {
            None
        };
        let held = flag(case, "holdDB").then(|| hold_db(&dir));

        let mut env: BTreeMap<String, String> = BTreeMap::new();
        if let Some(e) = case.get("env").and_then(Value::as_object) {
            for (k, v) in e {
                env.insert(k.clone(), places.expand(v.as_str().unwrap_or("")));
            }
        }
        if self.etcd_dir.is_none() {
            env.remove("ARMADA_DAEMON_TEST_ETCD_DIR");
        }
        let now = case.get("now").and_then(Value::as_i64).unwrap_or(0);
        env.insert("ARMADA_DAEMON_TEST_NOW".into(), now.to_string());
        env.insert(
            "ARMADA_DAEMON_TEST_INTERFACES".into(),
            self.interfaces.clone(),
        );
        env.insert("ARMADA_DAEMON_TEST_FS_TYPE".into(), self.fs_type.clone());
        // The cases were recorded on a machine whose kernel has VXLAN and
        // WireGuard and whose route to the internet leaves by wg0 (MTU
        // 1420); doctor's checks of them must not read this one's.
        env.insert(
            "ARMADA_NODE_TEST_KERNEL_MODULES".into(),
            "vxlan,wireguard".into(),
        );
        env.insert(
            "ARMADA_NODE_TEST_ROUTE_UPLINK".into(),
            "wg0:1420".into(),
        );
        let args: Vec<String> = case
            .get("args")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|x| places.expand(x.as_str().unwrap_or("")))
                    .collect()
            })
            .unwrap_or_default();
        let stdin = case
            .get("stdin")
            .and_then(Value::as_str)
            .map(|b| self.blobs[b].clone())
            .unwrap_or_default();

        let started = Instant::now();
        let mut child = Command::new(self.bin)
            .args(&args)
            .current_dir(&dir)
            .env_clear()
            .envs(&env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        let mut w = child.stdin.take().unwrap();
        let feeder = std::thread::spawn(move || {
            let _ = w.write_all(&stdin);
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
            if started.elapsed() > Duration::from_secs(120) {
                let _ = child.kill();
                let _ = child.wait();
                break -1;
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        let _ = feeder.join();
        let stdout = ro.join().unwrap();
        let stderr = describe::go_lossy(&re.join().unwrap());
        drop(held);
        if let Some(m) = &member {
            self.rt.block_on(m.record(&dir))?;
        }
        drop(member);
        let real_now = describe::unix_now();
        let stdout = if flag(&state, "archiveOut") {
            describe::describe_archive(&stdout, real_now)
        } else {
            describe::go_lossy(&stdout)
        };
        // An archive the case started with, unchanged, was recent when the
        // case was recorded; any other when this run made it.
        let recorded_now = now / 1_000_000_000;
        let given: HashMap<String, &Vec<u8>> = tree
            .iter()
            .filter_map(|e| {
                Some((
                    s(e, "path").to_string(),
                    self.blobs.get(e.get("blob")?.as_str()?)?,
                ))
            })
            .collect();
        let when = |rel: &str, b: &[u8]| {
            if given.get(rel).is_some_and(|g| g.as_slice() == b) {
                recorded_now
            } else {
                real_now
            }
        };
        let files = describe::collect(&dir, &when)
            .iter()
            .map(|f| places.hide(f))
            .collect();
        Ok(Outcome {
            code,
            stdout: places.hide(&stdout),
            stderr: places.hide(&stderr),
            files,
        })
    }
}

fn compare(want: &Value, got: &Outcome) -> Vec<String> {
    let mut d = Vec::new();
    let code = want.get("code").and_then(Value::as_i64).unwrap_or(0) as i32;
    if code != got.code {
        d.push(format!("exit code: want {code}, Rust {}", got.code));
    }
    for (name, w, g) in [
        ("stdout", s(want, "stdout"), &got.stdout),
        ("stderr", s(want, "stderr"), &got.stderr),
    ] {
        if describe::normalize(w) != describe::normalize(g) {
            d.push(format!("{name} differs:\n--- want\n{w}--- Rust\n{g}"));
        }
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
            "files differ:\n--- want\n{}\n--- Rust\n{}",
            files.join("\n"),
            got.files.join("\n")
        ));
    }
    d
}

fn run(filter: &str) -> i32 {
    let mut text = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(FIXTURE).expect("the recording"))
        .read_to_string(&mut text)
        .unwrap();
    let mut lines = text.lines();
    let head: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    let blobs: HashMap<String, Vec<u8>> = head["blobs"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), base64_decode(v.as_str().unwrap())))
        .collect();
    let bucket_objs = head["bucket"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), blobs[v.as_str().unwrap()].clone()))
        .collect();

    // The recording machine's addresses as Go read them, for the armadad
    // run and for this process's member certificates alike.
    let interfaces = s(&head, "interfaces").to_string();
    // SAFETY: no other thread runs yet.
    unsafe { std::env::set_var("ARMADA_DAEMON_TEST_INTERFACES", &interfaces) };
    let work = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "daemon-parity-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let standins = work.join("standins");
    std::fs::create_dir_all(&standins).unwrap();
    for (name, body) in head["standins"].as_object().unwrap() {
        let p = standins.join(name);
        std::fs::write(&p, body.as_str().unwrap()).unwrap();
        set_mode(&p, 0o755);
    }
    let etcd_dir = std::env::var("ARMADA_ETCD_DIR")
        .ok()
        .filter(|d| Path::new(d).join("etcdutl").exists())
        .map(|d| std::fs::canonicalize(d).unwrap());
    let r = Run {
        bin: env!("CARGO_BIN_EXE_armadad"),
        work: work.clone(),
        standins,
        etcd_dir,
        bucket: bucket::Bucket::start(),
        bucket_objs,
        blobs,
        master_key_id: s(&head, "masterKeyId").to_string(),
        interfaces,
        fs_type: s(&head, "fsType").to_string(),
        rt: tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap(),
    };
    let verbose = std::env::var("ARMADA_PARITY_VERBOSE").is_ok_and(|v| !v.is_empty());
    let (mut ran, mut skipped, mut failed) = (0, 0, Vec::new());
    for line in lines {
        let case: Value = serde_json::from_str(line).unwrap();
        let name = s(&case, "name").to_string();
        if !name.contains(filter) {
            continue;
        }
        // The pinned etcd: for the armadad, or for the server's member.
        if r.etcd_dir.is_none()
            && case
                .get("state")
                .is_some_and(|st| flag(st, "etcd") || flag(st, "member"))
        {
            skipped += 1;
            continue;
        }
        ran += 1;
        let diffs = match r.case(&case) {
            Ok(got) => {
                if verbose {
                    println!(
                        "{name}: exit {}\n--- stdout\n{}--- stderr\n{}--- files\n{}",
                        got.code,
                        got.stdout,
                        got.stderr,
                        got.files.join("\n")
                    );
                }
                compare(case.get("want").unwrap_or(&Value::Null), &got)
            }
            Err(e) => vec![format!("the case did not run: {e}")],
        };
        if !diffs.is_empty() {
            println!("FAIL {name}\n{}\n", diffs.join("\n"));
            failed.push(name);
        }
    }
    let _ = Command::new("chmod")
        .arg("-R")
        .arg("u+rwx")
        .arg(&work)
        .status();
    let _ = std::fs::remove_dir_all(&work);
    println!(
        "{ran} cases, {} failed, {skipped} skipped (no ARMADA_ETCD_DIR)",
        failed.len()
    );
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

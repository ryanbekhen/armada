//! The supervisor runtime without root: a stand-in [`Host`], stand-in
//! CNI plugins and systemd-run (shell scripts that record what they were
//! given), and a stand-in armada-shim that speaks the shim's protocol on
//! the sockets systemd-run was asked to start. Images come from a store
//! written here as armada-node writes it.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::*;

/// The result every stand-in plugin answers ADD with (NETNS replaced).
pub const PLUGIN_RESULT: &str = r#"{"cniVersion":"1.0.0","interfaces":[{"name":"armada0","mac":"02:41:0a:79:00:01"},{"name":"veth1","mac":"aa:bb:cc:dd:ee:ff"},{"name":"eth0","mac":"0a:58:0a:79:00:05","sandbox":"NETNS"}],"ips":[{"interface":2,"address":"10.121.0.5/24","gateway":"10.121.0.1"}],"routes":[{"dst":"0.0.0.0/0"}],"dns":{}}"#;

/// Writes an executable script.
pub fn script(p: &Path, body: &str) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Stand-in CNI plugins recording each call into log: a numbered file
/// holding "PLUGIN COMMAND ID NETNS IFNAME PATH", then the input.
pub fn cni_plugins(dir: &Path, log: &Path) {
    fs::create_dir_all(log).unwrap();
    let result = PLUGIN_RESULT.replace("NETNS", "%s");
    for p in ["bridge", "portmap", "firewall", "loopback"] {
        script(
            &dir.join(p),
            &format!(
                r#"d={log}
n=$(ls "$d" | wc -l)
f="$d/$(printf %03d "$n")"
{{ echo "$(basename "$0") $CNI_COMMAND $CNI_CONTAINERID $CNI_NETNS $CNI_IFNAME $CNI_PATH $CNI_ARGS"; cat; }} > "$f"
if [ "$CNI_COMMAND" = ADD ]; then printf '{result}' "$CNI_NETNS"; fi"#,
                log = log.display()
            ),
        );
    }
}

/// The plugin calls recorded in log, in order: (head line, input).
pub fn plugin_calls(log: &Path) -> Vec<(String, String)> {
    let mut names: Vec<_> = fs::read_dir(log)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    names.sort();
    names
        .iter()
        .map(|p| {
            let t = fs::read_to_string(p).unwrap();
            let (head, body) = t.split_once('\n').unwrap();
            (head.to_string(), body.to_string())
        })
        .collect()
}

/// A stand-in for the machine.
pub struct FakeHost {
    pub rootfs: PathBuf,
    pub calls: Mutex<Vec<String>>,
    n: AtomicUsize,
    /// SELinux on, with a policy whose container types the kernel knows
    /// unless their type is in unknown_types.
    pub selinux: std::sync::atomic::AtomicBool,
    pub unknown_types: Mutex<Vec<String>>,
    /// Files' labels as set.
    pub file_labels: Mutex<BTreeMap<PathBuf, String>>,
}

impl FakeHost {
    pub fn new(rootfs: PathBuf) -> FakeHost {
        FakeHost {
            rootfs,
            calls: Mutex::new(Vec::new()),
            n: AtomicUsize::new(0),
            selinux: std::sync::atomic::AtomicBool::new(false),
            unknown_types: Mutex::new(Vec::new()),
            file_labels: Mutex::new(BTreeMap::new()),
        }
    }

    fn note(&self, s: String) {
        self.calls.lock().unwrap().push(s);
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl Host for FakeHost {
    fn new_netns(&self, dir: &Path) -> Result<String, String> {
        let p = dir.join(format!(
            "cni-fake-{}",
            self.n.fetch_add(1, Ordering::SeqCst)
        ));
        fs::write(&p, b"").map_err(|e| e.to_string())?;
        self.note(format!(
            "netns {}",
            p.file_name().unwrap().to_string_lossy()
        ));
        Ok(p.display().to_string())
    }
    fn remove_netns(&self, path: &str) -> Result<(), String> {
        let _ = fs::remove_file(path);
        self.note(format!(
            "netns remove {}",
            Path::new(path).file_name().unwrap().to_string_lossy()
        ));
        Ok(())
    }
    fn new_pinned_netns(&self, path: &Path) -> Result<(), String> {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .and_then(|mut f| f.write_all(b"netns"))
            .map_err(|e| super::os_err("open", path, &e))?;
        self.note(format!(
            "pinned {}",
            path.file_name().unwrap().to_string_lossy()
        ));
        Ok(())
    }
    fn is_netns(&self, path: &Path) -> bool {
        fs::read(path).is_ok_and(|b| b == b"netns")
    }
    fn ensure_bridge(&self, b: &cni::Bridge, mtu: u32) -> Result<(), String> {
        self.note(format!("bridge {}/{} mtu {mtu}", b.gateway, b.subnet.bits));
        Ok(())
    }
    fn forget_connections(&self, addr: std::net::Ipv4Addr) -> Result<(), String> {
        self.note(format!("forget {addr}"));
        Ok(())
    }
    fn mount_all(&self, _mounts: &[Mount], _target: &Path) -> Result<(), String> {
        Ok(())
    }
    fn unmount_all(&self, _target: &Path) -> Result<(), (String, i32)> {
        Ok(())
    }
    fn with_rootfs(
        &self,
        _mounts: &[Mount],
        f: &mut dyn FnMut(&str) -> Result<Vec<u8>, String>,
    ) -> Result<Vec<u8>, String> {
        f(&self.rootfs.display().to_string())
    }
    fn apparmor_supported(&self) -> bool {
        false
    }
    fn load_apparmor(&self, _name: &str, _text: &str) -> Result<(), String> {
        unreachable!()
    }
    fn selinux_enabled(&self) -> bool {
        self.selinux.load(Ordering::SeqCst)
    }
    fn selinux_contexts(&self) -> Option<Vec<u8>> {
        Some(
            b"process = \"system_u:system_r:container_t:s0\"\nfile = \"system_u:object_r:container_file_t:s0\"\nro_file=\"system_u:object_r:container_ro_file_t:s0\"\n"
                .to_vec(),
        )
    }
    fn selinux_check_context(&self, label: &str) -> Result<(), String> {
        let t = label.split(':').nth(2).unwrap_or_default();
        if self.unknown_types.lock().unwrap().iter().any(|u| u == t) {
            return Err("write /sys/fs/selinux/context: invalid argument".into());
        }
        Ok(())
    }
    fn lfile_label(&self, p: &Path) -> std::io::Result<String> {
        fs::symlink_metadata(p)?;
        Ok(self
            .file_labels
            .lock()
            .unwrap()
            .get(p)
            .cloned()
            .unwrap_or_default())
    }
    fn lset_file_label(&self, p: &Path, label: &str) -> std::io::Result<()> {
        fs::symlink_metadata(p)?;
        self.file_labels
            .lock()
            .unwrap()
            .insert(p.to_path_buf(), label.to_string());
        Ok(())
    }
    fn set_file_label(&self, p: &Path, label: &str) -> std::io::Result<()> {
        let p = fs::canonicalize(p)?;
        self.file_labels
            .lock()
            .unwrap()
            .insert(p, label.to_string());
        Ok(())
    }
    fn port_free(&self, _ip: &str, _port: u16) -> bool {
        true
    }
    fn resolv_conf(&self) -> Vec<u8> {
        b"nameserver 10.0.0.2\nsearch example.org\n".to_vec()
    }
}

#[derive(Clone, Debug)]
struct Task {
    status: &'static str,
    n: i64,
    env: Vec<String>,
}

#[derive(Default)]
struct ShimState {
    /// By socket: its containers.
    tasks: HashMap<String, BTreeMap<String, Task>>,
    lines: Vec<String>,
    bound: Vec<String>,
    next_pid: i64,
}

/// A stand-in armada-shim serving every socket systemd-run was asked to
/// start.
pub struct FakeShim {
    st: Arc<(Mutex<ShimState>, Condvar)>,
}

impl FakeShim {
    /// Watches log (what the systemd-run stand-in writes) for shims to
    /// serve.
    pub fn start(log: PathBuf) -> FakeShim {
        let st: Arc<(Mutex<ShimState>, Condvar)> = Arc::default();
        st.0.lock().unwrap().next_pid = 100;
        let s = st.clone();
        std::thread::spawn(move || {
            let mut seen = 0;
            loop {
                let text = fs::read_to_string(&log).unwrap_or_default();
                let lines: Vec<&str> = text.lines().collect();
                for l in &lines[seen..] {
                    let w: Vec<&str> = l.split_whitespace().collect();
                    let Some(i) = w.iter().position(|x| *x == "serve") else {
                        continue;
                    };
                    let sock = w[i + 1].to_string();
                    let _ = fs::remove_file(&sock);
                    let listener = UnixListener::bind(&sock).unwrap();
                    s.0.lock().unwrap().bound.push(sock.clone());
                    let s2 = s.clone();
                    std::thread::spawn(move || {
                        for c in listener.incoming() {
                            let Ok(c) = c else { break };
                            let s3 = s2.clone();
                            let sock = sock.clone();
                            std::thread::spawn(move || serve(&s3, &sock, c));
                        }
                    });
                }
                seen = lines.len();
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        FakeShim { st }
    }

    /// The request lines every shim was sent ("list" left out).
    pub fn lines(&self) -> Vec<String> {
        self.st.0.lock().unwrap().lines.clone()
    }

    pub fn bound(&self) -> usize {
        self.st.0.lock().unwrap().bound.len()
    }

    /// Stops answering on every socket (the shims went away).
    pub fn vanish(&self) {
        let g = self.st.0.lock().unwrap();
        for s in &g.bound {
            let _ = fs::remove_file(s);
        }
    }
}

fn env_of(bundle: &str) -> Vec<String> {
    let spec: Value = serde_json::from_slice(
        &fs::read(Path::new(bundle).join("config.json")).unwrap_or_default(),
    )
    .unwrap_or(Value::Null);
    spec["process"]["env"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn env_value(env: &[String], k: &str) -> Option<i64> {
    env.iter()
        .find_map(|e| e.strip_prefix(&format!("{k}=")))
        .and_then(|v| v.parse().ok())
}

fn serve(st: &Arc<(Mutex<ShimState>, Condvar)>, sock: &str, c: UnixStream) {
    let mut line = String::new();
    if BufReader::new(&c).read_line(&mut line).is_err() {
        return;
    }
    let w: Vec<String> = line.split_whitespace().map(String::from).collect();
    let (m, cv) = &**st;
    let mut g = m.lock().unwrap();
    if w[0] != "list" {
        g.lines.push(w.join(" "));
    }
    let answer = match w[0].as_str() {
        "list" => {
            let tasks = g.tasks.get(sock).cloned().unwrap_or_default();
            let mut out = String::from("ok");
            for (id, t) in tasks {
                out.push_str(&format!(" {id} {}:{}", t.status, t.n));
            }
            out
        }
        "create" => {
            g.next_pid += 1;
            let pid = g.next_pid;
            let env = env_of(&w[2]);
            g.tasks.entry(sock.to_string()).or_default().insert(
                w[1].clone(),
                Task {
                    status: "created",
                    n: pid,
                    env,
                },
            );
            format!("ok {pid}")
        }
        id_cmd => {
            let id = w.get(1).cloned().unwrap_or_default();
            let found = g.tasks.get(sock).and_then(|t| t.get(&id)).cloned();
            match (id_cmd, found) {
                (_, None) => format!("err container {id} not found"),
                ("state", Some(t)) => format!("ok {} {}", t.status, t.n),
                ("start", Some(t)) => {
                    let t2 = g.tasks.get_mut(sock).unwrap().get_mut(&id).unwrap();
                    match env_value(&t.env, "TEST_EXIT") {
                        Some(code) => {
                            t2.status = "exited";
                            t2.n = code;
                        }
                        None => t2.status = "running",
                    }
                    cv.notify_all();
                    "ok".into()
                }
                ("wait", Some(_)) => loop {
                    match g.tasks.get(sock).and_then(|t| t.get(&id)) {
                        Some(t) if t.status == "exited" => break format!("ok {}", t.n),
                        None => break format!("err container {id} not found"),
                        _ => g = cv.wait(g).unwrap(),
                    }
                },
                ("kill", Some(t)) => {
                    let sig: i64 = w[2].parse().unwrap();
                    if t.status != "running" {
                        format!("err container {id} is not running")
                    } else {
                        if !(sig == 15 && env_value(&t.env, "TEST_IGNORE_TERM").is_some()) {
                            let t2 = g.tasks.get_mut(sock).unwrap().get_mut(&id).unwrap();
                            t2.status = "exited";
                            t2.n = 128 + sig;
                            cv.notify_all();
                        }
                        "ok".into()
                    }
                }
                ("delete", Some(_)) => {
                    g.tasks.get_mut(sock).unwrap().remove(&id);
                    cv.notify_all();
                    "ok".into()
                }
                _ => "err unknown request".into(),
            }
        }
    };
    drop(g);
    let _ = (&c).write_all(format!("{answer}\n").as_bytes());
}

/// The SHA-256 of b in lower-case hex.
fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|c| format!("{c:02x}"))
        .collect()
}

/// An image record in armada-node's store, with no layers.
pub fn write_image(images: &Path, name: &str, config: &str) {
    let blob = config.as_bytes();
    let hex = sha256_hex(blob);
    let blobs = images.join("content/blobs/sha256");
    fs::create_dir_all(&blobs).unwrap();
    fs::write(blobs.join(&hex), blob).unwrap();
    let idx_path = images.join("index.json");
    let mut idx: Value = fs::read(&idx_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| serde_json::json!({"version": 1, "images": {}}));
    let manifest = serde_json::json!({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": format!("sha256:{}", sha256_hex(name.as_bytes())), "size": 1});
    idx["images"][name] = serde_json::json!({
        "name": name, "target": manifest, "manifest": manifest,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": format!("sha256:{hex}"), "size": blob.len()},
        "layers": [], "diffIDs": [], "chainID": "",
        "labels": {"armada.pulled-with/anyone": "1"},
        "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z"});
    fs::write(idx_path, serde_json::to_vec(&idx).unwrap()).unwrap();
}

/// A node's directories, stand-ins, and runtime.
pub struct Lab {
    pub root: PathBuf,
    pub host: Arc<FakeHost>,
    pub shim: FakeShim,
    pub rt: Supervisor,
}

impl Lab {
    pub fn new(name: &str) -> Lab {
        let root = std::env::temp_dir().join(format!("armada-sup-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let bin = root.join("data/runtime/current/bin");
        fs::create_dir_all(&bin).unwrap();
        for p in [
            "armada-shim",
            "crun",
            "runc",
            "tini",
            "armada-log",
            "armada-node",
        ] {
            script(&bin.join(p), "exit 0");
        }
        cni_plugins(&bin.join("cni"), &root.join("cni-log"));
        let rootfs = root.join("rootfs");
        fs::create_dir_all(rootfs.join("etc")).unwrap();
        fs::write(
            rootfs.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/sh\napp:x:1000:1000::/app:/bin/sh\n",
        )
        .unwrap();
        fs::write(rootfs.join("etc/group"), "root:x:0:\napp:x:1000:\n").unwrap();
        let sd_log = root.join("systemd-run.log");
        script(
            &root.join("systemd-run"),
            &format!("echo \"$@\" >> {}", sd_log.display()),
        );
        write_image(
            &root.join("data/node/images"),
            "docker.io/library/app:1",
            r#"{"architecture":"amd64","os":"linux","config":{"Env":["PATH=/usr/bin"],"Cmd":["/app"]},"rootfs":{"type":"layers","diff_ids":[]}}"#,
        );
        write_image(
            &root.join("data/node/images"),
            "docker.io/library/side:1",
            r#"{"architecture":"amd64","os":"linux","config":{"Cmd":["/side"]},"rootfs":{"type":"layers","diff_ids":[]}}"#,
        );
        let host = Arc::new(FakeHost::new(rootfs));
        let mut cfg = Config::new(root.join("data"), root.join("run"), Logger::discard());
        cfg.host = host.clone();
        cfg.systemd_run = root.join("systemd-run").display().to_string();
        cfg.mtu = 1450;
        cfg.cgroup_root = root.join("cgroup");
        cfg.proc_root = root.join("proc");
        let shim = FakeShim::start(sd_log);
        let rt = Supervisor::new(cfg).unwrap();
        Lab {
            root,
            host,
            shim,
            rt,
        }
    }

    pub fn data(&self) -> PathBuf {
        self.root.join("data")
    }

    pub fn record(&self, id: &str) -> Value {
        serde_json::from_slice(
            &fs::read(
                self.data()
                    .join("supervisor/containers")
                    .join(id)
                    .join("record.json"),
            )
            .unwrap(),
        )
        .unwrap()
    }

    pub fn config(&self, id: &str) -> Value {
        serde_json::from_slice(
            &fs::read(
                self.data()
                    .join("supervisor/containers")
                    .join(id)
                    .join("config.json"),
            )
            .unwrap(),
        )
        .unwrap()
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        self.shim.vanish();
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn labels(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
    kv.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn web_spec() -> ContainerSpec {
    ContainerSpec {
        name: "web-r1".into(),
        image: "app:1".into(),
        env: vec!["A=1".into()],
        labels: labels(&[
            ("armada.managed", "true"),
            ("armada.app", "web"),
            ("armada.replica", "web-r1"),
            ("armada.revision", "web-1"),
        ]),
        port: 8080,
        host_ip: "10.0.0.5".into(),
        memory_bytes: 64 << 20,
        dns: vec!["10.121.0.1".into()],
        dns_search: vec!["internal".into()],
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runs_lists_stops_and_removes_a_container() {
    let lab = Lab::new("run");
    let rt = &lab.rt;
    rt.ping().await.unwrap();
    let id = rt.run(&web_spec()).await.unwrap();
    assert!(
        id.starts_with("web-r1-") && id.len() == "web-r1-".len() + 8,
        "{id}"
    );

    // The record: the spec's labels and the driver's own.
    let rec = lab.record(&id);
    assert_eq!(rec["image"], "docker.io/library/app:1");
    assert_eq!(rec["group"], "web@current");
    let l = &rec["labels"];
    assert_eq!(l["armada.runtime/kind"], "app");
    assert_eq!(l["armada.runtime/name"], "web-r1");
    assert_eq!(l["armada.runtime/host-ip"], "10.0.0.5");
    assert_eq!(l["armada.runtime/port"], "8080");
    assert_eq!(l["armada.runtime/ip"], "10.121.0.5");
    assert!(
        l["armada.runtime/netns"]
            .as_str()
            .unwrap()
            .ends_with("/run/netns/cni-fake-0")
    );
    let hp: u16 = l["armada.runtime/host-port"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((20000..=32767).contains(&hp));
    assert!(parse_time(l["armada.runtime/started"].as_str().unwrap()).is_some());

    // The spec: the shim's group, its cgroup, its namespace and files.
    let c = lab.config(&id);
    assert_eq!(c["root"], serde_json::json!({"path": "rootfs"}));
    assert_eq!(
        c["annotations"]["io.containerd.runc.v2.group"],
        "web@current"
    );
    assert_eq!(c["linux"]["cgroupsPath"], format!("/armada/{id}"));
    assert_eq!(c["hostname"], "web-r1");
    assert_eq!(
        c["process"]["args"],
        serde_json::json!(["/sbin/armada-init", "--", "/app"])
    );
    assert_eq!(c["linux"]["resources"]["memory"]["limit"], 64 << 20);
    let netns = c["linux"]["namespaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["type"] == "network")
        .unwrap();
    assert_eq!(netns["path"], l["armada.runtime/netns"]);
    let files = lab.data().join("containers").join(&id);
    assert_eq!(
        fs::read_to_string(files.join("resolv.conf")).unwrap(),
        "nameserver 10.121.0.1\nsearch internal example.org\n"
    );
    assert_eq!(
        fs::read_to_string(files.join("hosts")).unwrap(),
        "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n10.121.0.5\tweb-r1\n"
    );
    assert_eq!(
        fs::read_to_string(files.join("hostname")).unwrap(),
        "web-r1\n"
    );
    assert_eq!(
        fs::metadata(files.join("hosts"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert!(lab.data().join(format!("logs/history/{id}.meta")).exists());

    // The plugins in order, the port only for portmap.
    let calls = plugin_calls(&lab.root.join("cni-log"));
    let heads: Vec<String> = calls
        .iter()
        .map(|(h, _)| h.split(' ').take(2).collect::<Vec<_>>().join(" "))
        .collect();
    assert_eq!(
        heads,
        ["bridge ADD", "portmap ADD", "firewall ADD", "loopback ADD"]
    );
    let portmap: Value = serde_json::from_str(&calls[1].1).unwrap();
    assert_eq!(portmap["runtimeConfig"]["portMappings"][0]["hostPort"], hp);
    assert_eq!(portmap["prevResult"]["ips"][0]["address"], "10.121.0.5/24");
    assert!(!calls[0].1.contains("prevResult"));
    assert!(
        lab.root
            .join(format!("run/cni/cache/results/armada-{id}-eth0"))
            .exists()
    );

    // The shim was started through systemd-run and asked to create, then
    // start.
    assert_eq!(lab.shim.bound(), 1);
    let sd = fs::read_to_string(lab.root.join("systemd-run.log")).unwrap();
    assert!(sd.starts_with(&format!(
        "--unit=armada-shim-{} --collect --quiet --property=OOMScoreAdjust=-999",
        armada_node::runtime::container::shim::shim_name("web@current")
    )));
    // The shim runs crun beside runc (ADR 0056), each named last.
    let bin = lab.data().join("runtime/current/bin");
    assert!(
        sd.trim_end().ends_with(&format!(
            "{} {} {}",
            bin.join("runc").display(),
            bin.join("armada-log").display(),
            bin.join("crun").display()
        )),
        "{sd}"
    );
    // A new container: created with crun, which its record names.
    assert_eq!(lab.record(&id)["runtime"], "crun");
    assert_eq!(
        lab.shim.lines(),
        [
            format!(
                "create {id} {} {} crun",
                lab.data().join("supervisor/containers").join(&id).display(),
                lab.data().join("logs").display()
            ),
            format!("start {id}"),
        ]
    );

    let cs = rt.list(&labels(&[("armada.app", "web")])).await.unwrap();
    assert_eq!(cs.len(), 1);
    let got = &cs[0];
    assert_eq!(got.id, id);
    assert_eq!(got.name, "web-r1");
    assert_eq!(got.state, STATE_RUNNING);
    assert_eq!(got.ip, "10.121.0.5");
    assert_eq!(got.oci_runtime, "crun");
    assert_eq!(rt.runtime_agent().await.unwrap().runc_containers, 0);
    assert_eq!(
        (got.host_ip.as_str(), got.host_port),
        ("10.0.0.5", i64::from(hp))
    );
    assert!(!got.labels.keys().any(|k| k.starts_with("armada.runtime/")));
    assert!(
        rt.list(&labels(&[("armada.app", "api")]))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(rt.inspect(&id).await.unwrap(), cs[0]);

    rt.stop(&id, Duration::from_secs(5)).await.unwrap();
    let c = rt.inspect(&id).await.unwrap();
    assert_eq!((c.state.as_str(), c.exit_code), (STATE_EXITED, 143));

    rt.remove(&id).await.unwrap();
    assert_eq!(rt.inspect(&id).await.unwrap_err(), Error::NotFound);
    assert!(!files.exists());
    assert!(!lab.data().join("supervisor/containers").join(&id).exists());
    assert!(!lab.data().join("node/images/active").join(&id).exists());
    let calls = plugin_calls(&lab.root.join("cni-log"));
    let dels: Vec<String> = calls[4..]
        .iter()
        .map(|(h, _)| h.split(' ').take(3).collect::<Vec<_>>().join(" "))
        .collect();
    assert_eq!(
        dels,
        [
            format!("loopback DEL {id}"),
            format!("firewall DEL {id}"),
            format!("portmap DEL {id}"),
            format!("bridge DEL {id}"),
        ]
    );
    let del: Value = serde_json::from_str(&calls[4].1).unwrap();
    assert_eq!(del["prevResult"]["ips"][0]["address"], "10.121.0.5/24");
    assert!(
        !lab.root
            .join(format!("run/cni/cache/results/armada-{id}-eth0"))
            .exists()
    );
    let host = lab.host.calls();
    assert_eq!(host[0], "bridge 10.121.0.1/24 mtu 1450");
    assert!(host.contains(&"forget 10.121.0.5".to_string()));
    assert_eq!(host.last().unwrap(), "netns remove cni-fake-0");
    let lines = lab.shim.lines();
    assert!(lines.contains(&format!("kill {id} 15")));
    assert_eq!(lines.last().unwrap(), &format!("delete {id}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_container_ignoring_sigterm_is_killed_after_its_grace() {
    let lab = Lab::new("grace");
    let mut s = web_spec();
    s.port = 0;
    s.env.push("TEST_IGNORE_TERM=1".into());
    let id = lab.rt.run(&s).await.unwrap();
    lab.rt.stop(&id, Duration::from_millis(50)).await.unwrap();
    let c = lab.rt.inspect(&id).await.unwrap();
    assert_eq!((c.state.as_str(), c.exit_code), (STATE_EXITED, 137));
    let kills: Vec<String> = lab
        .shim
        .lines()
        .into_iter()
        .filter(|l| l.starts_with("kill"))
        .collect();
    assert_eq!(kills, [format!("kill {id} 15"), format!("kill {id} 9 all")]);
}

fn member(name: &str, image: &str, env: &[&str]) -> MemberSpec {
    MemberSpec {
        name: name.into(),
        image: image.into(),
        env: env.iter().map(|s| s.to_string()).collect(),
        memory_bytes: 64 << 20,
        ..Default::default()
    }
}

async fn wait_state(rt: &Supervisor, id: &str, want: &str) -> Container {
    for _ in 0..400 {
        let c = rt.inspect(id).await.unwrap();
        if c.state == want {
            return c;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{id} never became {want}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn init_containers_and_sidecars_start_in_order() {
    let lab = Lab::new("pod");
    let mut s = web_spec();
    s.port = 0;
    s.init = vec![
        member("migrate", "app:1", &["TEST_EXIT=0"]),
        member("seed", "app:1", &["TEST_EXIT=0"]),
    ];
    s.sidecars = vec![member("proxy", "side:1", &[])];
    let id = lab.rt.run(&s).await.unwrap();
    let c = wait_state(&lab.rt, &id, STATE_RUNNING).await;
    let roles: Vec<(String, String, String)> = c
        .members
        .iter()
        .map(|m| (m.name.clone(), m.role.clone(), m.state.clone()))
        .collect();
    assert_eq!(
        roles,
        [
            ("migrate".into(), "init".into(), "exited".into()),
            ("seed".into(), "init".into(), "exited".into()),
            ("proxy".into(), "sidecar".into(), "running".into()),
        ]
    );
    // Each init container ran to its end before the next was created;
    // the sidecar then, and the replica's own process last.
    let order: Vec<String> = lab
        .shim
        .lines()
        .into_iter()
        // A wait is asked beside the start, as Go's goroutine asks it.
        .filter(|l| l.starts_with("create") || l.starts_with("start"))
        .map(|l| {
            let w: Vec<&str> = l.split(' ').collect();
            let who = if w[1] == id {
                "replica".to_string()
            } else {
                w[1].rsplit_once('-').unwrap().0.to_string()
            };
            format!("{} {who}", w[0])
        })
        .collect();
    assert_eq!(
        order,
        [
            "create replica",
            "create armada-migrate",
            "start armada-migrate",
            "create armada-seed",
            "start armada-seed",
            "create armada-proxy",
            "start armada-proxy",
            "start replica",
        ]
    );
    // Members share the replica's network namespace and files, in cgroups
    // of their own, with the replica's labels and their own.
    let proxy = &c.members[2];
    let mc = lab.config(&proxy.id);
    assert_eq!(mc["linux"]["cgroupsPath"], format!("/armada/{}", proxy.id));
    assert_eq!(mc["hostname"], "web-r1");
    let ml = &lab.record(&proxy.id)["labels"];
    assert_eq!(ml["armada.runtime/pod"], id.as_str());
    assert_eq!(ml["armada.runtime/kind"], "member");
    assert_eq!(ml["armada.role"], "sidecar");
    assert_eq!(ml["armada.app"], "web");
    // The list nests them under the replica.
    let cs = lab
        .rt
        .list(&labels(&[("armada.app", "web")]))
        .await
        .unwrap();
    assert_eq!(cs.len(), 1);
    assert_eq!(cs[0].members.len(), 3);

    // Stop ends the replica, then its sidecars; remove takes them all.
    lab.rt.stop(&id, Duration::from_secs(1)).await.unwrap();
    let c = lab.rt.inspect(&id).await.unwrap();
    assert_eq!(c.members[2].state, STATE_EXITED);
    lab.rt.remove(&id).await.unwrap();
    assert!(lab.rt.list(&BTreeMap::new()).await.unwrap().is_empty());
    assert!(
        fs::read_dir(lab.data().join("supervisor/containers"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_init_container_gives_the_start_up() {
    let lab = Lab::new("initfail");
    let mut s = web_spec();
    s.port = 0;
    s.init = vec![member("migrate", "app:1", &["TEST_EXIT=3"])];
    s.sidecars = vec![member("proxy", "side:1", &[])];
    let id = lab.rt.run(&s).await.unwrap();
    let c = wait_state(&lab.rt, &id, STATE_EXITED).await;
    assert_eq!(c.exit_code, 255);
    assert_eq!(c.start_error, "");
    let f = c.failed_init().unwrap();
    assert_eq!((f.name.as_str(), f.exit_code), ("migrate", 3));
    // Neither the sidecar nor the replica started.
    assert!(!lab.shim.lines().iter().any(|l| l == &format!("start {id}")));
    assert_eq!(c.members.len(), 1);
    lab.rt.remove(&id).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_that_fails_is_undone() {
    let lab = Lab::new("undo");
    let mut s = web_spec();
    s.image = "missing:1".into();
    assert_eq!(
        lab.rt.run(&s).await.unwrap_err().to_string(),
        "image missing:1: image docker.io/library/missing:1: not found"
    );
    let mut s = web_spec();
    s.init = vec![member("x", "missing:2", &[])];
    assert_eq!(
        lab.rt.run(&s).await.unwrap_err().to_string(),
        "container x: image missing:2: image docker.io/library/missing:2: not found"
    );
    // A plugin that fails: the network is released and nothing is kept.
    script(
        &lab.data().join("runtime/current/bin/cni/firewall"),
        "cat >/dev/null; [ \"$CNI_COMMAND\" = ADD ] && { echo '{\"code\":11,\"msg\":\"no table\",\"details\":\"x\"}'; exit 1; }; exit 0",
    );
    let err = lab.rt.run(&web_spec()).await.unwrap_err().to_string();
    assert_eq!(
        err,
        "container network: plugin type=\"firewall\" failed (add): no table; x"
    );
    assert!(
        fs::read_dir(lab.data().join("supervisor/containers"))
            .map_or(true, |mut d| d.next().is_none())
    );
    assert!(
        fs::read_dir(lab.root.join("run/netns"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shim_that_is_gone_leaves_its_containers_exited() {
    let lab = Lab::new("gone");
    let mut s = web_spec();
    s.port = 0;
    let id = lab.rt.run(&s).await.unwrap();
    lab.shim.vanish();
    let c = lab.rt.inspect(&id).await.unwrap();
    assert_eq!((c.state.as_str(), c.exit_code), (STATE_EXITED, 255));
    let cs = lab.rt.list(&BTreeMap::new()).await.unwrap();
    assert_eq!(cs[0].state, STATE_EXITED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn samples_containers() {
    let lab = Lab::new("stats");
    let mut s = web_spec();
    s.port = 0;
    let id = lab.rt.run(&s).await.unwrap();
    let cg = lab.root.join("cgroup/armada").join(&id);
    fs::create_dir_all(&cg).unwrap();
    fs::write(cg.join("cpu.stat"), "usage_usec 2500\n").unwrap();
    fs::write(cg.join("memory.stat"), "inactive_file 1024\n").unwrap();
    fs::write(cg.join("memory.events"), "oom_kill 2\n").unwrap();
    fs::write(cg.join("memory.current"), "5120\n").unwrap();
    let pid = lab
        .rt
        .inner
        .shims
        .state("web@current", &id)
        .await
        .unwrap()
        .pid;
    let nd = lab.root.join("proc").join(pid.to_string()).join("net");
    fs::create_dir_all(&nd).unwrap();
    fs::write(nd.join("dev"), "h\nh\n  eth0: 1 0 0 0 0 0 0 0 4096 0\n").unwrap();
    let got = lab
        .rt
        .stats_batch(&[id.clone(), "nope".to_string()])
        .await
        .unwrap();
    assert_eq!(
        got[0],
        Ok(Stats {
            cpu: Duration::from_micros(2500),
            memory_bytes: 4096,
            egress_bytes: 4096,
            network_lost: false,
            oom_kills: 2,
        })
    );
    assert_eq!(got[1], Err(Error::NotFound));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runs_system_containers() {
    let lab = Lab::new("system");
    let mut l = BTreeMap::new();
    l.insert(LABEL_SYSTEM.to_string(), "haproxy".to_string());
    let etc = lab.root.join("hap/etc");
    fs::create_dir_all(&etc).unwrap();
    let spec = SystemSpec {
        name: "armada-haproxy".into(),
        image: "app:1".into(),
        labels: l.clone(),
        mounts: vec![crate::haproxy::engine::Mount {
            source: etc.display().to_string(),
            target: "/usr/local/etc/haproxy".into(),
            read_only: true,
        }],
        user: "0:0".into(),
        cap_add: vec!["NET_BIND_SERVICE".into()],
    };
    let id = lab.rt.run_system(&spec).await.unwrap();
    let c = lab.config(&id);
    assert_eq!(
        c["root"],
        serde_json::json!({"path": "rootfs", "readonly": true})
    );
    assert_eq!(
        c["process"]["capabilities"]["bounding"],
        serde_json::json!(["CAP_NET_BIND_SERVICE"])
    );
    assert!(c["annotations"].is_null());
    let rec = lab.record(&id);
    assert_eq!(rec["group"], id.as_str());
    assert_eq!(rec["labels"]["armada.runtime/kind"], "system");
    // No network of its own.
    assert!(plugin_calls(&lab.root.join("cni-log")).is_empty());
    let cs = lab.rt.list(&l).await.unwrap();
    assert_eq!(
        (cs[0].id.as_str(), cs[0].state.as_str()),
        (id.as_str(), STATE_RUNNING)
    );

    lab.rt.signal(&id, "SIGUSR2").await.unwrap();
    assert!(lab.shim.lines().contains(&format!("kill {id} 12")));
    assert_eq!(
        lab.rt
            .signal(&id, "SIGWINCH")
            .await
            .unwrap_err()
            .to_string(),
        "unsupported signal \"SIGWINCH\""
    );

    // haproxy -c through armada-node runtime exec (a stand-in).
    let req = lab.root.join("exec.json");
    script(
        &lab.data().join("runtime/current/bin/armada-node"),
        &format!(
            "cat <&3 >{}\necho '{{\"spawned\":true}}' >&4\necho 'Configuration file is valid' >&6\necho '{{\"exit\":0}}' >&4\necho '{{\"drained\":true}}' >&4",
            req.display()
        ),
    );
    let cmd: Vec<String> = ["haproxy", "-c", "-f", "/x"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let (out, code) = lab.rt.exec_system(&id, &cmd).await.unwrap();
    assert_eq!((out.as_str(), code), ("Configuration file is valid\n", 0));
    let r: Value = serde_json::from_slice(&fs::read(&req).unwrap()).unwrap();
    assert_eq!(
        r["bundle"],
        lab.data()
            .join("supervisor/containers")
            .join(&id)
            .display()
            .to_string()
    );
    assert_eq!(
        r["root"],
        lab.root
            .join("run/shim")
            .join(armada_node::runtime::container::shim::shim_name(&id))
            .join("crun")
            .display()
            .to_string()
    );
    assert_eq!(
        r["runtime"],
        lab.data()
            .join("runtime/current/bin/crun")
            .display()
            .to_string()
    );
    assert_eq!(r["drainGraceMs"], 0);
    assert_eq!(r["consoleSocket"], true);

    // The log's last lines.
    let line = |s: &str| {
        format!("{{\"log\":\"{s}\\n\",\"stream\":\"stderr\",\"time\":\"2026-01-01T00:00:00Z\"}}\n")
    };
    fs::create_dir_all(lab.data().join("logs")).unwrap();
    fs::write(
        lab.data().join("logs").join(format!("{id}.log")),
        line("a") + &line("[ALERT] b"),
    )
    .unwrap();
    assert_eq!(lab.rt.log_tail(&id, 1).await.unwrap(), "[ALERT] b\n");
    assert_eq!(
        lab.rt.log_tail("other", 1).await.unwrap_err(),
        Error::NotFound
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prunes_images_no_container_uses() {
    let lab = Lab::new("prune");
    let mut s = web_spec();
    s.port = 0;
    lab.rt.run(&s).await.unwrap();
    let removed = lab
        .rt
        .prune_images(&[], Duration::ZERO)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(removed, ["docker.io/library/side:1"]);
    let st = lab.rt.runtime_agent().await.unwrap();
    assert_eq!(st.agent, "supervisor-rust");
    assert!(!st.go_images);
}

#[test]
fn times_parse_as_go() {
    let t = parse_time("2026-01-01T00:00:00.000005Z").unwrap();
    assert_eq!(t, UNIX_EPOCH + Duration::new(1_767_225_600, 5_000));
    assert_eq!(
        parse_time("2026-01-01T07:00:00+07:00").unwrap(),
        UNIX_EPOCH + Duration::new(1_767_225_600, 0)
    );
    assert!(parse_time("").is_none());
    assert!(parse_time("2026-13-01T00:00:00Z").is_none());
    assert_eq!(crate::clock::rfc3339_nano(t), "2026-01-01T00:00:00.000005Z");
}

#[test]
fn ids_and_exec_commands() {
    assert_eq!(
        new_id("bad name").unwrap_err(),
        "invalid container name \"bad name\""
    );
    assert_eq!(check_exec_command(&[]).unwrap_err(), "command is empty");
    assert_eq!(
        check_exec_command(&["a".into(), "b\0".into()]).unwrap_err(),
        "argument 1 contains a NUL byte"
    );
    let mut ms = vec![
        Member {
            role: "sidecar".into(),
            started_at: Some(UNIX_EPOCH),
            ..Default::default()
        },
        Member {
            role: "init".into(),
            started_at: Some(UNIX_EPOCH + Duration::from_secs(2)),
            ..Default::default()
        },
        Member {
            role: "init".into(),
            started_at: Some(UNIX_EPOCH + Duration::from_secs(1)),
            ..Default::default()
        },
    ];
    sort_members(&mut ms);
    let r: Vec<_> = ms.iter().map(|m| (m.role.as_str(), m.started_at)).collect();
    assert_eq!(
        r,
        [
            ("init", Some(UNIX_EPOCH + Duration::from_secs(1))),
            ("init", Some(UNIX_EPOCH + Duration::from_secs(2))),
            ("sidecar", Some(UNIX_EPOCH)),
        ]
    );
}

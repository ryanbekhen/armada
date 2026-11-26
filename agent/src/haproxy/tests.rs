//! The driver against Go's: the scenarios Go's driver ran, recorded
//! before the Go code was removed (tests/testdata/haproxy), replayed here with the same stand-ins for the
//! engine and the Runtime API, compared step by step: the error, the
//! commands, starts, reloads, configuration checks, every file written, and
//! the load.

use std::collections::BTreeMap;
use std::sync::Mutex as StdMutex;

use serde::Deserialize;

use super::*;

/// Records what the driver asks of HAProxy (Go's fakeEngine).
#[derive(Default)]
struct FakeEngine {
    st: StdMutex<EngineSt>,
}

#[derive(Default)]
struct EngineSt {
    running: bool,
    starts: i64,
    reloads: i64,
    validations: Vec<String>,
    validate_err: Option<String>,
    /// Whether runc runs it, and how often it was moved to crun.
    runc: bool,
    moves: i64,
}

impl Engine for FakeEngine {
    fn running(&self) -> BoxFut<'_, Result<bool, String>> {
        let r = self.st.lock().unwrap().running;
        Box::pin(async move { Ok(r) })
    }
    fn start(&self) -> BoxFut<'_, Result<(), String>> {
        let mut st = self.st.lock().unwrap();
        st.starts += 1;
        st.running = true;
        Box::pin(async { Ok(()) })
    }
    fn validate<'a>(&'a self, file: &'a str) -> BoxFut<'a, Result<(), String>> {
        let mut st = self.st.lock().unwrap();
        st.validations.push(file.to_string());
        let r = st.validate_err.clone();
        Box::pin(async move { r.map_or(Ok(()), Err) })
    }
    fn reload(&self) -> BoxFut<'_, Result<(), String>> {
        self.st.lock().unwrap().reloads += 1;
        Box::pin(async { Ok(()) })
    }
    fn on_runc(&self) -> BoxFut<'_, Result<bool, String>> {
        let r = self.st.lock().unwrap().runc;
        Box::pin(async move { Ok(r) })
    }
    fn replace_on_crun(&self) -> BoxFut<'_, Result<(), String>> {
        let mut st = self.st.lock().unwrap();
        st.moves += 1;
        st.runc = false;
        Box::pin(async { Ok(()) })
    }
}

/// Records commands and answers from a table (Go's fakeAPI).
#[derive(Default)]
struct FakeApi {
    st: StdMutex<ApiSt>,
}

#[derive(Default)]
struct ApiSt {
    cmds: Vec<String>,
    err: Option<String>,
    replies: BTreeMap<String, String>,
    /// Answers to show info in turn, then the table's.
    infos: Vec<String>,
}

impl Api for FakeApi {
    fn command<'a>(&'a self, cmd: &'a str) -> BoxFut<'a, Result<String, String>> {
        let mut st = self.st.lock().unwrap();
        st.cmds.push(cmd.to_string());
        let reply = if cmd == "show info" && !st.infos.is_empty() {
            st.infos.remove(0)
        } else if let Some(r) = st.replies.get(cmd) {
            r.clone()
        } else if cmd.starts_with("prepare map") {
            "New version created: 7".to_string()
        } else {
            String::new()
        };
        let res = match &st.err {
            Some(e) => Err(e.clone()),
            None => Ok(reply),
        };
        Box::pin(async move { res })
    }
    fn payload<'a>(&'a self, cmd: &'a str, payload: &'a str) -> BoxFut<'a, Result<String, String>> {
        if let Err(e) = api::check_payload(payload) {
            return Box::pin(async move { Err(e) });
        }
        let line = format!("{cmd} <<payload:{}", payload.len());
        Box::pin(async move { self.command(&line).await })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Step {
    op: String,
    #[serde(default)]
    config: Option<pb::ProxyConfig>,
    #[serde(default)]
    clients: Option<BTreeMap<String, String>>,
    #[serde(default)]
    running: Option<bool>,
    #[serde(default)]
    api_err: String,
    #[serde(default)]
    validate_err: String,
    #[serde(default)]
    replies: Option<BTreeMap<String, String>>,
    #[serde(default)]
    listeners: Option<Vec<String>>,
    err: String,
    cmds: Vec<String>,
    starts: i64,
    reloads: i64,
    validations: Vec<String>,
    files: BTreeMap<String, String>,
    #[serde(default)]
    load: Option<BTreeMap<String, GoLoad>>,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct GoLoad {
    in_flight: i64,
    total: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Scenario {
    #[serde(rename = "privateIP")]
    private_ip: String,
    #[serde(rename = "internalIP")]
    internal_ip: String,
    subnet: String,
    steps: Vec<Step>,
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "armada-haproxy-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn files(dir: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let etc = etc_dir(dir);
    let mut stack = vec![etc.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let rel = p.strip_prefix(&etc).unwrap().to_string_lossy().into_owned();
            if rel == DEFAULT_CERT_FILE {
                continue;
            }
            out.insert(
                rel,
                String::from_utf8_lossy(&std::fs::read(&p).unwrap()).into_owned(),
            );
        }
    }
    out
}

type Listeners = Arc<StdMutex<Vec<SocketAddr>>>;

fn driver(
    sc: &Scenario,
    dir: &Path,
    e: &Arc<FakeEngine>,
    a: &Arc<FakeApi>,
    l: &Listeners,
) -> Driver {
    let l = l.clone();
    Driver::new(DriverConfig {
        dir: dir.to_path_buf(),
        private_ip: sc.private_ip.clone(),
        internal_ip: sc.internal_ip.clone(),
        subnet: sc.subnet.clone(),
        engine: e.clone(),
        api: Some(a.clone()),
        listeners: Some(Arc::new(move || Ok(l.lock().unwrap().clone()))),
        logger: Logger::discard(),
        reload_wait: Duration::ZERO,
    })
    .unwrap()
}

async fn replay(name: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/testdata/haproxy")
        .join(format!("{name}.json"));
    let sc: Scenario = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let dir = tmp(name).join("haproxy");
    let (e, a) = (
        Arc::new(FakeEngine::default()),
        Arc::new(FakeApi::default()),
    );
    let l: Listeners = Arc::default();
    let mut d = driver(&sc, &dir, &e, &a, &l);
    for (i, s) in sc.steps.iter().enumerate() {
        let at = format!("{name} step {i} ({})", s.op);
        if let Some(r) = s.running {
            e.st.lock().unwrap().running = r;
        }
        if let Some(r) = &s.replies {
            a.st.lock().unwrap().replies = r.clone();
        }
        if let Some(ls) = &s.listeners {
            *l.lock().unwrap() = ls.iter().map(|x| x.parse().unwrap()).collect();
        }
        {
            let mut st = a.st.lock().unwrap();
            st.cmds.clear();
            st.err = (!s.api_err.is_empty()).then(|| s.api_err.clone());
        }
        e.st.lock().unwrap().validate_err =
            (!s.validate_err.is_empty()).then(|| s.validate_err.clone());
        let mut load = None;
        let res = match s.op.as_str() {
            "apply" => d.apply(s.config.as_ref().unwrap()).await,
            "clients" => {
                let c: Clients = s
                    .clients
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| (k.parse().unwrap(), v.clone()))
                    .collect();
                d.set_clients(&c).await
            }
            "load" => Proxy::load(&d).await.map(|l| {
                load = Some(
                    l.into_iter()
                        .map(|(k, v)| {
                            (
                                k,
                                GoLoad {
                                    in_flight: v.in_flight,
                                    total: v.total,
                                },
                            )
                        })
                        .collect::<BTreeMap<_, _>>(),
                );
            }),
            "health" => d.health().await,
            "restart" => {
                d = driver(&sc, &dir, &e, &a, &l);
                Ok(())
            }
            op => panic!("unknown op {op}"),
        };
        assert_eq!(res.err().unwrap_or_default(), s.err, "{at}: error");
        assert_eq!(a.st.lock().unwrap().cmds, s.cmds, "{at}: commands");
        {
            let st = e.st.lock().unwrap();
            assert_eq!(
                (st.starts, st.reloads),
                (s.starts, s.reloads),
                "{at}: starts, reloads"
            );
            assert_eq!(st.validations, s.validations, "{at}: checks");
        }
        let got = files(&dir);
        assert_eq!(
            got.keys().collect::<Vec<_>>(),
            s.files.keys().collect::<Vec<_>>(),
            "{at}: files"
        );
        for (k, v) in &s.files {
            assert!(
                got[k] == *v,
                "{at}: {k} differs:\n--- Go\n{v}\n--- Rust\n{}",
                got[k]
            );
        }
        if s.op == "load" {
            assert_eq!(load, s.load, "{at}: load");
        }
    }
    let _ = std::fs::remove_dir_all(dir.parent().unwrap());
}

#[tokio::test]
async fn go_scenario_lifecycle() {
    replay("lifecycle").await;
}

#[tokio::test]
async fn go_scenario_network() {
    replay("network").await;
}

#[tokio::test]
async fn go_scenario_takeover() {
    replay("takeover").await;
}

#[test]
fn prepares_its_directories() {
    let dir = tmp("new").join("haproxy");
    let e: Arc<dyn Engine> = Arc::new(FakeEngine::default());
    let cfg = |subnet: &str, ip: &str| DriverConfig {
        dir: dir.clone(),
        private_ip: ip.into(),
        internal_ip: String::new(),
        subnet: subnet.into(),
        engine: e.clone(),
        api: None,
        listeners: None,
        logger: Logger::discard(),
        reload_wait: Duration::ZERO,
    };
    Driver::new(cfg("", "10.0.0.2")).unwrap();
    for p in [
        dir.clone(),
        etc_dir(&dir),
        etc_dir(&dir).join(CERT_DIR),
        run_dir(&dir),
        etc_dir(&dir).join(DEFAULT_CERT_FILE),
    ] {
        armada_fsutil::check_private(&p).unwrap();
    }
    let pem = std::fs::read(etc_dir(&dir).join(DEFAULT_CERT_FILE)).unwrap();
    assert_eq!(config::check_pem(&pem), Ok(()));
    assert!(Driver::new(cfg("", "nope")).is_err());
    for bad in ["nope", "8.8.8.0/24", "10.120.3.1/24", "10.120.3.0/24\n"] {
        assert!(Driver::new(cfg(bad, "")).is_err(), "{bad}");
    }
    let _ = std::fs::remove_dir_all(dir.parent().unwrap());
}

#[tokio::test(start_paused = true)]
async fn reload_waits_for_the_new_process() {
    let dir = tmp("reload").join("haproxy");
    let (e, a) = (
        Arc::new(FakeEngine::default()),
        Arc::new(FakeApi::default()),
    );
    let sc = Scenario {
        private_ip: "10.0.0.2".into(),
        internal_ip: String::new(),
        subnet: String::new(),
        steps: Vec::new(),
    };
    let l: Listeners = Arc::default();
    let d = driver(&sc, &dir, &e, &a, &l);
    let mut st = St::default();
    a.st.lock().unwrap().infos = vec!["Pid: 1".into(), "Pid: 1".into(), "Pid: 2".into()];
    d.reload(&mut st).await.unwrap();
    assert_eq!(a.st.lock().unwrap().cmds.len(), 3);
    a.st.lock()
        .unwrap()
        .replies
        .insert("show info".into(), "Pid: 3".into());
    st.sig = "x".into();
    let err = d.reload(&mut st).await.unwrap_err();
    assert_eq!(
        err,
        "reload haproxy: the new process did not answer within 10s"
    );
    assert!(st.sig.is_empty());
    let _ = std::fs::remove_dir_all(dir.parent().unwrap());
}

/// The move to crun (ADR 0056): the engine replaces the container, then a
/// reload makes sure the Runtime API is the new process's; nothing when
/// runc does not run it.
#[tokio::test(start_paused = true)]
async fn moves_to_crun_then_reloads() {
    let dir = tmp("crun").join("haproxy");
    let (e, a) = (
        Arc::new(FakeEngine::default()),
        Arc::new(FakeApi::default()),
    );
    let sc = Scenario {
        private_ip: "10.0.0.2".into(),
        internal_ip: String::new(),
        subnet: String::new(),
        steps: Vec::new(),
    };
    let l: Listeners = Arc::default();
    let d = driver(&sc, &dir, &e, &a, &l);
    let counts = || {
        let st = e.st.lock().unwrap();
        (st.moves, st.reloads)
    };
    assert!(Proxy::moves_to_crun(&d));
    d.move_to_crun().await.unwrap();
    assert_eq!(counts(), (0, 0));
    e.st.lock().unwrap().runc = true;
    a.st.lock().unwrap().infos = vec!["Pid: 1".into(), "Pid: 1".into(), "Pid: 2".into()];
    assert!(Proxy::on_runc(&d).await.unwrap());
    Proxy::move_to_crun(&d).await.unwrap();
    assert_eq!(counts(), (1, 1));
    assert!(!Proxy::on_runc(&d).await.unwrap());
    let _ = std::fs::remove_dir_all(dir.parent().unwrap());
}

#[test]
fn map_chunks_at_line_ends() {
    assert_eq!(
        map_chunks(b"aa\nbb\ncc\n", 6),
        vec![&b"aa\nbb\n"[..], b"cc\n"]
    );
    assert_eq!(
        map_chunks(b"aaaaaaaa\nb\n", 4),
        vec![&b"aaaaaaaa\n"[..], b"b\n"]
    );
    assert_eq!(map_chunks(b"aaaaaaaa", 4), vec![&b"aaaaaaaa"[..]]);
    assert!(map_chunks(b"", 4).is_empty());
}

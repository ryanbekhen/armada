//! armada-store-parity: the program the store's recordings drive
//! (tests/replay.rs). Never packed.
//!
//! It reads one JSON request per line on stdin and answers each with one
//! line on stdout, `{"id", "value"?, "error"?, "kind"?}`, running requests
//! at the same time (a campaign waits while others go on). Values are the
//! store's answers with the recordings' field names; the replay compares
//! them with the recorded answers.
//!
//! Requests (`op`): `open` (handle, endpoint and dir, or socket, prefix), `fenced`
//! (handle, from, key, rev), `setNow` (handle, ms), `call` (handle, method,
//! args, repeat, parallel), `reencode` (handle), `campaign` (handle,
//! endpoint, dir, ttl, name), `resign` (handle), `leader` (endpoint, dir),
//! `lock`/`tryLock` (handle, endpoint, dir, ttl, prefix), `unlock` (handle).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use armada_spec::gotime::{Location, Time};
use armada_store::election::{self, Leadership, Mutex as EtcdMutex, Session};
use armada_store::*;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

#[derive(Default)]
struct State {
    clients: Mutex<HashMap<String, Client>>,
    stores: Mutex<HashMap<String, Etcd>>,
    leaders: Mutex<HashMap<String, Leadership>>,
    mutexes: Mutex<HashMap<String, (Arc<Session>, EtcdMutex)>>,
}

use armada_store::parity_call::*;

/// The member's client: `endpoint` and `dir` (its TLS files), or
/// `socket`, a member on a Unix socket without TLS, for the replay of the
/// recordings (tests/replay.rs).
async fn client(stt: &State, req: &Value) -> Result<Client> {
    let sock = s(req, "socket");
    let ep = if sock.is_empty() {
        s(req, "endpoint")
    } else {
        format!("unix:{sock}")
    };
    let mut cs = stt.clients.lock().await;
    if let Some(c) = cs.get(&ep) {
        return Ok(c.clone());
    }
    let c = if sock.is_empty() {
        Client::connect(&ep, Path::new(&s(req, "dir")))?
    } else {
        Client::connect_unix(Path::new(&sock))?
    };
    cs.insert(ep, c.clone());
    Ok(c)
}

async fn store(stt: &State, h: &str) -> Result<Etcd> {
    stt.stores
        .lock()
        .await
        .get(h)
        .cloned()
        .ok_or_else(|| Error::other(format!("no store {h}")))
}

/// The clocks and random sources of the handles: a test sets every
/// handle's clock alike, and all follow one sequence of random bytes.
#[derive(Default)]
struct Hooks {
    now: HashMap<String, Arc<AtomicI64>>,
    rand: HashMap<String, Arc<AtomicU64>>,
}

static HOOKS: std::sync::OnceLock<std::sync::Mutex<Hooks>> = std::sync::OnceLock::new();

fn hooks() -> std::sync::MutexGuard<'static, Hooks> {
    HOOKS
        .get_or_init(|| std::sync::Mutex::new(Hooks::default()))
        .lock()
        .expect("not poisoned")
}

async fn handle(stt: &State, req: &Value) -> Result<Value> {
    let h = s(req, "handle");
    match s(req, "op").as_str() {
        "open" => {
            let c = client(stt, req).await?;
            let mut st = Etcd::new(c, &s(req, "prefix")).await?;
            let now = Arc::new(AtomicI64::new(i(req, "ms")));
            let ctr = Arc::new(AtomicU64::new(0));
            let n = now.clone();
            st.set_now(Arc::new(move || {
                let ms = n.load(Ordering::SeqCst);
                Time {
                    unix: ms.div_euclid(1000),
                    nsec: ms.rem_euclid(1000) * 1_000_000,
                    loc: Location::utc(),
                }
            }));
            let r = ctr.clone();
            st.set_random(Arc::new(move |buf: &mut [u8]| {
                let c = r.fetch_add(1, Ordering::SeqCst) + 1;
                for (j, x) in buf.iter_mut().enumerate() {
                    *x = (c.wrapping_mul(31).wrapping_add(j as u64) & 0xff) as u8;
                }
            }));
            {
                let mut hk = hooks();
                hk.now.insert(h.clone(), now);
                hk.rand.insert(h.clone(), ctr);
            }
            stt.stores.lock().await.insert(h, st);
            Ok(Value::Null)
        }
        "fenced" => {
            let from = store(stt, &s(req, "from")).await?;
            let f = from.fenced(&s(req, "key"), i(req, "rev"));
            stt.stores.lock().await.insert(h, f);
            Ok(Value::Null)
        }
        "setNow" => {
            let n = hooks()
                .now
                .get(&h)
                .cloned()
                .ok_or_else(|| Error::other("no clock"))?;
            n.store(i(req, "ms"), Ordering::SeqCst);
            Ok(Value::Null)
        }
        "call" => {
            let st = store(stt, &h).await?;
            let method = s(req, "method");
            let args = req.get("args").cloned().unwrap_or(Value::Null);
            let repeat = i(req, "repeat").max(1);
            let parallel = i(req, "parallel").max(1);
            if repeat == 1 {
                return call(&st, &method, &args).await;
            }
            let per = repeat / parallel;
            let mut tasks = Vec::new();
            for _ in 0..parallel {
                let st = st.clone();
                let (m, a) = (method.clone(), args.clone());
                tasks.push(tokio::spawn(async move {
                    for _ in 0..per {
                        call(&st, &m, &a).await?;
                    }
                    Ok::<(), Error>(())
                }));
            }
            for t in tasks {
                t.await.map_err(|e| Error::other(e.to_string()))??;
            }
            Ok(Value::Null)
        }
        "reencode" => {
            let st = store(stt, &h).await?;
            let d = st.reencode().await?;
            Ok(Value::Array(
                d.into_iter()
                    .map(|d| json!({"key": d.key, "stored": d.stored, "encoded": d.encoded}))
                    .collect(),
            ))
        }
        "campaign" => {
            let c = client(stt, req).await?;
            let l = Leadership::campaign(
                &c,
                Duration::from_secs(i(req, "ttl").max(1) as u64),
                &s(req, "name"),
            )
            .await?;
            let (key, rev) = l.fence();
            stt.leaders.lock().await.insert(h, l);
            Ok(json!({"key": key, "rev": rev}))
        }
        "resign" => {
            let l = stt
                .leaders
                .lock()
                .await
                .remove(&h)
                .ok_or_else(|| Error::other("no leadership"))?;
            l.resign().await?;
            Ok(Value::Null)
        }
        "leader" => {
            let c = client(stt, req).await?;
            Ok(Value::String(election::leader(&c).await?))
        }
        "lock" | "tryLock" => {
            let c = client(stt, req).await?;
            let sess = Arc::new(Session::new(&c, i(req, "ttl")).await?);
            let mut m = EtcdMutex::new(sess.clone(), &s(req, "prefix"));
            let r = if s(req, "op") == "lock" {
                m.lock().await
            } else {
                m.try_lock().await
            };
            if let Err(e) = r {
                let _ = sess.close().await;
                return Err(e);
            }
            let key = m.key().to_string();
            stt.mutexes.lock().await.insert(h, (sess, m));
            Ok(Value::String(key))
        }
        "unlock" => {
            let (sess, mut m) = stt
                .mutexes
                .lock()
                .await
                .remove(&h)
                .ok_or_else(|| Error::other("no lock"))?;
            m.unlock().await?;
            sess.close().await?;
            Ok(Value::Null)
        }
        op => Err(Error::other(format!(
            "armada-store-parity: unknown op {op}"
        ))),
    }
}

#[tokio::main]
async fn main() {
    let stt = Arc::new(State::default());
    let out = Arc::new(Mutex::new(tokio::io::stdout()));
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("armada-store-parity: {e}");
                continue;
            }
        };
        let (stt, out) = (stt.clone(), out.clone());
        tokio::spawn(async move {
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            let answer = match handle(&stt, &req).await {
                Ok(v) => json!({"id": id, "value": v}),
                Err(e) => json!({"id": id, "error": e.msg, "kind": e.kind.name()}),
            };
            let mut line = serde_json::to_vec(&answer).expect("answers encode");
            line.push(b'\n');
            let mut o = out.lock().await;
            let _ = o.write_all(&line).await;
            let _ = o.flush().await;
        });
    }
}

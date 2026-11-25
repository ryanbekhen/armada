//! Leadership terms (Go's lead, term, and runTerm in internal/daemon's
//! serve.go): a control plane node campaigns for leadership and, while it
//! leads, runs one server after another on a store fenced on its election
//! key. A change of the cluster's server settings (ADR 0031) runs the
//! term's server again, keeping the leadership.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use armada_store::election::{self, Leadership};
use armada_store::{Client, Etcd, SCHEMA};
use tokio::sync::watch;

use crate::log::Logger;

/// Go's leaderLease.
pub const LEADER_LEASE: Duration = Duration::from_secs(10);
/// Go's leadReadyPoll.
const LEAD_READY_POLL: Duration = Duration::from_secs(5);

/// How a term ended.
#[derive(Debug)]
pub enum TermEnd {
    /// The server may not lead yet (errStandBy).
    StandBy,
    /// A failure that ends the control plane.
    Failed(String),
}

/// Whether this server may lead (ADR 0012): a binary that knows a newer
/// state schema than the cluster uses waits until every server knows it;
/// state written by a newer binary is an error (Go's leadReady).
pub async fn lead_ready(st: &Etcd, mine: i64) -> Result<(bool, Vec<String>), String> {
    let stored = st.stored_schema().await.map_err(|e| e.to_string())?;
    if stored > mine {
        return Err(format!(
            "the state was written by a newer Armada (schema {stored}, this binary knows {mine}); run the newer version (downgrades are not supported)"
        ));
    }
    if stored == mine {
        return Ok((true, Vec::new()));
    }
    let old: Vec<String> = st
        .list_servers()
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|s| s.schema < mine)
        .map(|s| s.name)
        .collect();
    Ok((old.is_empty(), old))
}

/// Blocks until lead_ready allows this server to lead.
pub async fn wait_lead_ready(
    st: &Etcd,
    log: &Logger,
    stop: &mut watch::Receiver<bool>,
) -> Result<(), String> {
    let mut waiting = String::new();
    loop {
        let (ok, old) = lead_ready(st, SCHEMA).await?;
        if ok {
            return Ok(());
        }
        let w = old.join(",");
        if w != waiting {
            log.warn(
                "standing by: the state migrates to this version's schema once these servers are upgraded",
                &[("servers", w.clone())],
            );
            waiting = w;
        }
        tokio::select! {
            _ = crate::stopped(stop) => return Err("stopped".to_string()),
            _ = tokio::time::sleep(LEAD_READY_POLL) => {}
        }
    }
}

/// Runs at the start of a term on the fenced store: checks again that this
/// server may lead and migrates the state (Go's upgradeState).
pub async fn upgrade_state(st: &Etcd, log: &Logger) -> Result<(), TermEnd> {
    let (ok, _) = lead_ready(st, SCHEMA).await.map_err(TermEnd::Failed)?;
    if !ok {
        return Err(TermEnd::StandBy);
    }
    let from = st
        .migrate()
        .await
        .map_err(|e| TermEnd::Failed(e.to_string()))?;
    if from != SCHEMA {
        log.info(
            "state migrated",
            &[
                ("from_schema", from.to_string()),
                ("to_schema", SCHEMA.to_string()),
            ],
        );
    }
    Ok(())
}

/// One run of a term's server: the fenced store, a restart function the
/// server calls when the cluster's settings changed, and the signal that
/// ends the run. It returns Ok when the run ended because it was told to.
pub type Restart = Arc<dyn Fn() + Send + Sync>;

/// A term (Go's term): the state upgraded on the fenced store, then the
/// server run again whenever its settings change, until stop. A run that
/// fails right after a restart because its listener is still in use is
/// tried again (the last run's listeners close as it ends).
pub async fn term<F, Fut>(
    st: &Etcd,
    lead: &Leadership,
    log: &Logger,
    stop: watch::Receiver<bool>,
    mut run: F,
) -> Result<(), TermEnd>
where
    F: FnMut(Etcd, Restart, watch::Receiver<bool>) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let (key, rev) = lead.fence();
    let fenced = st.fenced(&key, rev);
    upgrade_state(&fenced, log).await?;
    let mut restarting = false;
    let mut tries = 0;
    loop {
        let (tstop_tx, tstop) = watch::channel(false);
        let again = Arc::new(AtomicBool::new(false));
        let restart: Restart = {
            let again = again.clone();
            let tx = tstop_tx.clone();
            Arc::new(move || {
                again.store(true, Ordering::SeqCst);
                let _ = tx.send(true);
            })
        };
        let mut outer = stop.clone();
        let fwd = {
            let tx = tstop_tx.clone();
            tokio::spawn(async move {
                crate::stopped(&mut outer).await;
                let _ = tx.send(true);
            })
        };
        let res = run(fenced.clone(), restart, tstop).await;
        fwd.abort();
        let _ = tstop_tx.send(true);
        if *stop.borrow() {
            return res.map_err(TermEnd::Failed);
        }
        if again.load(Ordering::SeqCst) {
            log.info("cluster settings changed; applying them", &[]);
            restarting = true;
            tries = 0;
        } else if let Err(e) = &res
            && restarting
            && e.contains("Address already in use")
            && tries < 20
        {
            tries += 1;
        } else {
            return match res {
                Ok(()) => Err(TermEnd::Failed(
                    "control plane stopped unexpectedly".to_string(),
                )),
                Err(e) => Err(TermEnd::Failed(e)),
            };
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Campaigns for leadership and runs a term while this node leads, until
/// stop (Go's lead). A term that ends because leadership was lost is
/// followed by a new campaign; a term that fails is fatal.
pub async fn lead<R, RF, T, TF>(
    c: &Client,
    name: &str,
    ttl: Duration,
    log: &Logger,
    mut stop: watch::Receiver<bool>,
    mut ready: R,
    mut term: T,
) -> Result<(), String>
where
    R: FnMut() -> RF,
    RF: Future<Output = Result<(), String>>,
    T: FnMut(Arc<Leadership>, watch::Receiver<bool>) -> TF,
    TF: Future<Output = Result<(), TermEnd>>,
{
    let log = log.with("component", "control-plane");
    loop {
        if let Err(e) = ready().await {
            if *stop.borrow() {
                return Ok(());
            }
            return Err(e);
        }
        if let Ok(l) = election::leader(c).await
            && !l.is_empty()
            && l != name
        {
            log.info("standing by", &[("leader", l)]);
        }
        let l = tokio::select! {
            _ = crate::stopped(&mut stop) => return Ok(()),
            l = Leadership::campaign(c, ttl, name) => l,
        };
        let l = match l {
            Ok(l) => Arc::new(l),
            Err(e) => {
                log.warn(
                    "leader election failed; retrying",
                    &[("err", e.to_string())],
                );
                tokio::select! {
                    _ = crate::stopped(&mut stop) => return Ok(()),
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
                continue;
            }
        };
        log.info("elected leader", &[]);
        let (tstop_tx, tstop) = watch::channel(false);
        let watcher = {
            let l = l.clone();
            let mut outer = stop.clone();
            let tx = tstop_tx.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = l.done() => {}
                    _ = crate::stopped(&mut outer) => {}
                }
                let _ = tx.send(true);
            })
        };
        let res = term(l.clone(), tstop.clone()).await;
        let lost = *tstop.borrow() && !*stop.borrow();
        watcher.abort();
        if let Ok(l) = Arc::try_unwrap(l) {
            let _ = tokio::time::timeout(Duration::from_secs(5), l.resign()).await;
        }
        if *stop.borrow() {
            return Ok(());
        }
        match res {
            Err(TermEnd::StandBy) => log.info("standing by until every server is upgraded", &[]),
            _ if lost => log.warn("lost leadership; standing by", &[]),
            Err(TermEnd::Failed(e)) => return Err(e),
            Ok(()) => return Err("control plane stopped unexpectedly".to_string()),
        }
    }
}

//! Stream checks (Go's streamguard.go): a user's or service's AdminService
//! stream stays within the access the cluster gives it now, not only when
//! it opened (ADR 0033). Every recheck interval the principal's roles are
//! read again, as a new call would, and the checks the handler asked for
//! run with them; once the certificate is refused, the method is no
//! longer reached, a check fails, or the certificate expires, the stream
//! ends with that error.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use armada_pki::{Certificate, Identity};
use tokio::sync::watch;
use tonic::{Code, Status};

use crate::Server;
use crate::access::Access;

type Check = Box<dyn Fn(&Access) -> Result<(), Status> + Send + Sync>;

struct State {
    acc: Access,
    checks: Vec<Check>,
    err: Option<Status>,
}

/// The guard of one stream.
pub struct Guard {
    srv: Server,
    pid: Identity,
    cert: Arc<Certificate>,
    method: String,
    st: Mutex<State>,
    cancel: watch::Sender<bool>,
}

impl Guard {
    /// Starts a guard for a principal's stream (guardStream).
    pub(crate) fn start(
        srv: &Server,
        acc: Access,
        cert: Arc<Certificate>,
        method: &str,
    ) -> Arc<Guard> {
        let (cancel, _) = watch::channel(false);
        let g = Arc::new(Guard {
            srv: srv.clone(),
            pid: acc.id.clone(),
            cert,
            method: method.to_string(),
            st: Mutex::new(State {
                acc,
                checks: Vec::new(),
                err: None,
            }),
            cancel,
        });
        let w = g.clone();
        tokio::spawn(async move { w.watch().await });
        g
    }

    async fn watch(self: Arc<Self>) {
        let mut done = self.cancel.subscribe();
        let left = (UNIX_EPOCH + Duration::from_secs(self.cert.not_after.max(0) as u64))
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        let expiry = tokio::time::sleep(left);
        tokio::pin!(expiry);
        let every = self.srv.0.stream_recheck;
        let mut t = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        loop {
            tokio::select! {
                _ = crate::stopped(&mut done) => return,
                _ = &mut expiry => {
                    self.end(Status::new(Code::Unauthenticated, format!("the certificate of {} expired", self.pid)));
                    return;
                }
                _ = t.tick() => {
                    if self.recheck().await.is_err() {
                        return;
                    }
                }
            }
        }
    }

    /// Reads the principal's access again and runs the handler's checks
    /// with it, ending the stream on a refusal. A store that cannot be
    /// read leaves the stream as it is until the next check.
    pub async fn recheck(&self) -> Result<(), Status> {
        let res = self
            .srv
            .method_access(&self.pid, &self.cert, &self.method)
            .await;
        let err = match res {
            Err(e) if e.code() == Code::Unavailable => return Ok(()),
            Err(e) => Some(e),
            Ok(acc) => {
                let st = self.st.lock().unwrap_or_else(|p| p.into_inner());
                let mut err = None;
                for c in &st.checks {
                    if let Err(e) = c(&acc) {
                        err = Some(e);
                        break;
                    }
                }
                drop(st);
                if err.is_none() {
                    self.st.lock().unwrap_or_else(|p| p.into_inner()).acc = acc;
                }
                err
            }
        };
        match err {
            Some(e) => {
                self.end(e.clone());
                Err(e)
            }
            None => Ok(()),
        }
    }

    /// Runs check with the stream's access now and on every recheck.
    pub fn require(
        &self,
        check: impl Fn(&Access) -> Result<(), Status> + Send + Sync + 'static,
    ) -> Result<(), Status> {
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        check(&st.acc)?;
        st.checks.push(Box::new(check));
        Ok(())
    }

    /// The access as of the last check.
    pub fn current(&self) -> Access {
        self.st
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .acc
            .clone()
    }

    /// Records why the stream ends, first reason only, and cancels it.
    pub fn end(&self, err: Status) {
        {
            let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
            if st.err.is_none() {
                st.err = Some(err);
            }
        }
        self.cancel.send_replace(true);
    }

    /// The error that ended the stream, if any.
    pub fn ended(&self) -> Option<Status> {
        self.st
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .err
            .clone()
    }

    /// Resolves once the stream is cancelled.
    pub async fn cancelled(&self) {
        let mut rx = self.cancel.subscribe();
        crate::stopped(&mut rx).await;
    }

    /// Ends the watcher once the handler returned.
    pub fn stop(&self) {
        self.cancel.send_replace(true);
    }
}

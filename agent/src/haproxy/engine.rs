//! HAProxy as a host-network system container (engine.go): the driver's
//! [`Engine`] over the runtime's system containers, which the supervisor
//! runtime provides through [`SystemRunner`].

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use super::{CONTAINER_CONF_DIR, CONTAINER_RUN_DIR, Engine, etc_dir, run_dir};
use crate::proxy::BoxFut;
use crate::runtime::{self, LABEL_SYSTEM, Runtime, STATE_RUNNING};

/// The HAProxy image, pinned by digest (3.2 LTS, Alpine): Go's
/// haproxy.Image.
pub const IMAGE: &str =
    "haproxy:3.2-alpine@sha256:5893840576071e6217cd52ebdcc14f454c6f7a631056fa6f4e0f40d3cac4215b";

const CONTAINER_NAME: &str = "armada-haproxy";
const SYSTEM_LABEL: &str = "haproxy";
/// The configured image reference, which the runtime may report in another
/// form.
const IMAGE_LABEL: &str = "armada.image";
/// The host directory mounted into the container.
const DIR_LABEL: &str = "armada.dir";

/// A host directory mounted into a system container.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mount {
    pub source: String,
    pub target: String,
    pub read_only: bool,
}

/// A system container (runtime.SystemSpec): host network, the user and
/// capabilities given, nothing else.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SystemSpec {
    pub name: String,
    pub image: String,
    pub labels: BTreeMap<String, String>,
    pub mounts: Vec<Mount>,
    pub user: String,
    pub cap_add: Vec<String>,
}

/// A runtime that runs system containers (runtime.SystemRunner, and the
/// tail of a container's log).
pub trait SystemRunner: Runtime {
    fn run_system(&self, spec: &SystemSpec)
    -> impl Future<Output = runtime::Result<String>> + Send;
    /// Runs cmd in a system container; its output and exit code.
    fn exec_system(
        &self,
        id: &str,
        cmd: &[String],
    ) -> impl Future<Output = runtime::Result<(String, i64)>> + Send;
    /// Sends the named signal to the container's process.
    fn signal(&self, id: &str, signal: &str) -> impl Future<Output = runtime::Result<()>> + Send;
    /// The last lines of the container's output.
    fn log_tail(
        &self,
        id: &str,
        lines: usize,
    ) -> impl Future<Output = runtime::Result<String>> + Send;
}

/// HAProxy run by the node's runtime.
pub struct ContainerEngine<R: SystemRunner> {
    pub runtime: Arc<R>,
    /// The driver's directory.
    pub dir: PathBuf,
    /// "" for IMAGE.
    pub image: String,
    /// How long start waits to see HAProxy stay up; 0 for two seconds.
    pub start_wait: Duration,
    /// How long the old HAProxy of a move to crun gets to finish its
    /// connections; 0 for RETIRE_WAIT.
    pub retire_wait: Duration,
}

/// How long an outgoing HAProxy finishes its connections when it moves to
/// crun (ADR 0056), and how often the engine looks.
pub const RETIRE_WAIT: Duration = Duration::from_secs(30);
const RETIRE_POLL: Duration = Duration::from_millis(250);

impl<R: SystemRunner> ContainerEngine<R> {
    fn image(&self) -> &str {
        if self.image.is_empty() {
            IMAGE
        } else {
            &self.image
        }
    }

    fn dir(&self) -> String {
        self.dir.to_string_lossy().into_owned()
    }

    async fn find(&self) -> runtime::Result<Vec<runtime::Container>> {
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_SYSTEM.to_string(), SYSTEM_LABEL.to_string());
        self.runtime.list(&labels).await
    }

    async fn running_id(&self) -> Result<String, String> {
        let cs = self.find().await.map_err(|e| e.to_string())?;
        cs.into_iter()
            .find(|c| c.state == STATE_RUNNING)
            .map(|c| c.id)
            .ok_or_else(|| "haproxy container is not running".to_string())
    }

    fn spec(&self) -> SystemSpec {
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_SYSTEM.to_string(), SYSTEM_LABEL.to_string());
        labels.insert(IMAGE_LABEL.to_string(), self.image().to_string());
        labels.insert(DIR_LABEL.to_string(), self.dir());
        SystemSpec {
            name: CONTAINER_NAME.into(),
            image: self.image().into(),
            labels,
            mounts: vec![
                Mount {
                    source: etc_dir(&self.dir).to_string_lossy().into_owned(),
                    target: CONTAINER_CONF_DIR.into(),
                    read_only: true,
                },
                Mount {
                    source: run_dir(&self.dir).to_string_lossy().into_owned(),
                    target: CONTAINER_RUN_DIR.into(),
                    read_only: false,
                },
            ],
            // Root inside the container uses the 0700 host directories;
            // every capability but binding :80/:443 is dropped.
            user: "0:0".into(),
            cap_add: vec!["NET_BIND_SERVICE".into()],
        }
    }

    fn start_wait(&self) -> Duration {
        if self.start_wait.is_zero() {
            Duration::from_secs(2)
        } else {
            self.start_wait
        }
    }

    /// Runs a new HAProxy container and waits to see it stay up; one that
    /// exits is an error with the end of its output.
    async fn run_new(&self) -> Result<String, String> {
        self.runtime
            .pull(self.image(), None)
            .await
            .map_err(|e| e.to_string())?;
        let id = self
            .runtime
            .run_system(&self.spec())
            .await
            .map_err(|e| e.to_string())?;
        tokio::time::sleep(self.start_wait()).await;
        let c = self.runtime.inspect(&id).await.map_err(|e| e.to_string())?;
        if c.state != STATE_RUNNING {
            let tail = match self.runtime.log_tail(&id, 20).await {
                Ok(t) => t.trim().to_string(),
                Err(_) => "no logs".to_string(),
            };
            return Err(format!("haproxy exited (code {}): {tail}", c.exit_code));
        }
        Ok(id)
    }

    async fn start_now(&self) -> Result<(), String> {
        for c in self.find().await.map_err(|e| e.to_string())? {
            let _ = self.runtime.stop(&c.id, Duration::from_secs(5)).await;
            match self.runtime.remove(&c.id).await {
                Ok(()) | Err(runtime::Error::NotFound) => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        self.run_new().await.map(|_| ())
    }

    /// The overlapping replacement (ADR 0056): HAProxy binds its listeners
    /// with SO_REUSEPORT, so a new HAProxy on crun listens beside the old
    /// one before the old one is told to stop listening and finish its
    /// connections (SIGUSR1, a soft stop); one still running after
    /// RETIRE_WAIT is stopped. When the new HAProxy does not stay up
    /// beside the old one, the old one is stopped first, as for any start:
    /// a gap of about the time a start takes.
    async fn replace_now(&self) -> Result<(), String> {
        let old: Vec<runtime::Container> = self
            .find()
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|c| c.on_runc())
            .collect();
        if old.is_empty() {
            return Ok(());
        }
        if let Err(e) = self.run_new().await {
            // Most likely the listeners: the old HAProxy goes first, as
            // for any start. The new container took the directories'
            // SELinux label, so the old one could not reload anyway.
            return match self.start_now().await {
                Ok(()) => Ok(()),
                Err(e2) => Err(format!(
                    "start haproxy on crun beside the old one: {e}; and after it: {e2}"
                )),
            };
        }
        for c in &old {
            if c.state == STATE_RUNNING
                && let Err(e) = self.runtime.signal(&c.id, "SIGUSR1").await
                && e != runtime::Error::NotFound
            {
                return Err(format!("stop the old haproxy: {e}"));
            }
        }
        let deadline = tokio::time::Instant::now() + self.retire_wait();
        for c in &old {
            while tokio::time::Instant::now() < deadline {
                match self.runtime.inspect(&c.id).await {
                    Ok(x) if x.state == STATE_RUNNING => {}
                    _ => break,
                }
                tokio::time::sleep(RETIRE_POLL).await;
            }
            let _ = self.runtime.stop(&c.id, Duration::from_secs(5)).await;
            match self.runtime.remove(&c.id).await {
                Ok(()) | Err(runtime::Error::NotFound) => {}
                Err(e) => return Err(format!("remove the old haproxy: {e}")),
            }
        }
        Ok(())
    }

    fn retire_wait(&self) -> Duration {
        if self.retire_wait.is_zero() {
            RETIRE_WAIT
        } else {
            self.retire_wait
        }
    }
}

impl<R: SystemRunner> Engine for ContainerEngine<R> {
    fn running(&self) -> BoxFut<'_, Result<bool, String>> {
        Box::pin(async move {
            let cs = self.find().await.map_err(|e| e.to_string())?;
            let dir = self.dir();
            Ok(cs.iter().any(|c| {
                c.state == STATE_RUNNING
                    && c.label(IMAGE_LABEL) == self.image()
                    && c.label(DIR_LABEL) == dir
            }))
        })
    }

    fn start(&self) -> BoxFut<'_, Result<(), String>> {
        Box::pin(self.start_now())
    }

    fn validate<'a>(&'a self, file: &'a str) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async move {
            let id = self.running_id().await?;
            let cmd: Vec<String> = ["haproxy", "-c", "-f", file]
                .iter()
                .map(|s| s.to_string())
                .collect();
            let (out, code) = self
                .runtime
                .exec_system(&id, &cmd)
                .await
                .map_err(|e| e.to_string())?;
            if code != 0 {
                return Err(format!("haproxy -c: {}", out.trim()));
            }
            Ok(())
        })
    }

    fn reload(&self) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async move {
            let id = self.running_id().await?;
            self.runtime
                .signal(&id, "SIGUSR2")
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn on_runc(&self) -> BoxFut<'_, Result<bool, String>> {
        Box::pin(async move {
            let cs = self.find().await.map_err(|e| e.to_string())?;
            Ok(cs.iter().any(|c| c.on_runc()))
        })
    }

    fn replace_on_crun(&self) -> BoxFut<'_, Result<(), String>> {
        Box::pin(self.replace_now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// System containers in memory; records what the engine did.
    #[derive(Default)]
    struct Fake {
        containers: Mutex<Vec<runtime::Container>>,
        calls: Mutex<Vec<String>>,
        specs: Mutex<Vec<SystemSpec>>,
        /// The state a started container is in.
        starts_as: Mutex<String>,
        exec: Mutex<(String, i64)>,
        /// Whether a soft stop ends the container at once.
        soft_stops: Mutex<bool>,
    }

    impl Fake {
        fn call(&self, s: String) {
            self.calls.lock().unwrap().push(s);
        }
    }

    impl Runtime for Fake {
        async fn ping(&self) -> runtime::Result<()> {
            Ok(())
        }
        async fn pull(
            &self,
            image: &str,
            _auth: Option<&runtime::RegistryAuth>,
        ) -> runtime::Result<runtime::Image> {
            self.call(format!("pull {image}"));
            Ok(runtime::Image::default())
        }
        async fn run(&self, _spec: &runtime::ContainerSpec) -> runtime::Result<String> {
            Err(runtime::Error::other("not here"))
        }
        async fn stop(&self, id: &str, _grace: Duration) -> runtime::Result<()> {
            self.call(format!("stop {id}"));
            Ok(())
        }
        async fn remove(&self, id: &str) -> runtime::Result<()> {
            self.call(format!("remove {id}"));
            self.containers.lock().unwrap().retain(|c| c.id != id);
            Ok(())
        }
        async fn list(
            &self,
            labels: &BTreeMap<String, String>,
        ) -> runtime::Result<Vec<runtime::Container>> {
            Ok(self
                .containers
                .lock()
                .unwrap()
                .iter()
                .filter(|c| labels.iter().all(|(k, v)| c.label(k) == v))
                .cloned()
                .collect())
        }
        async fn inspect(&self, id: &str) -> runtime::Result<runtime::Container> {
            self.containers
                .lock()
                .unwrap()
                .iter()
                .find(|c| c.id == id)
                .cloned()
                .ok_or(runtime::Error::NotFound)
        }
    }

    impl SystemRunner for Fake {
        async fn run_system(&self, spec: &SystemSpec) -> runtime::Result<String> {
            self.specs.lock().unwrap().push(spec.clone());
            let id = format!("hap-{}", self.specs.lock().unwrap().len());
            self.containers.lock().unwrap().push(runtime::Container {
                id: id.clone(),
                labels: spec.labels.clone(),
                state: self.starts_as.lock().unwrap().clone(),
                exit_code: 1,
                ..Default::default()
            });
            Ok(id)
        }
        async fn exec_system(&self, id: &str, cmd: &[String]) -> runtime::Result<(String, i64)> {
            self.call(format!("exec {id} {}", cmd.join(" ")));
            Ok(self.exec.lock().unwrap().clone())
        }
        async fn signal(&self, id: &str, signal: &str) -> runtime::Result<()> {
            self.call(format!("signal {id} {signal}"));
            if signal == "SIGUSR1" && *self.soft_stops.lock().unwrap() {
                for c in self.containers.lock().unwrap().iter_mut() {
                    if c.id == id {
                        c.state = runtime::STATE_EXITED.into();
                    }
                }
            }
            Ok(())
        }
        async fn log_tail(&self, _id: &str, lines: usize) -> runtime::Result<String> {
            Ok(format!("  last {lines} lines \n"))
        }
    }

    fn engine(rt: &Arc<Fake>, dir: &str) -> ContainerEngine<Fake> {
        ContainerEngine {
            runtime: rt.clone(),
            dir: PathBuf::from(dir),
            image: String::new(),
            start_wait: Duration::ZERO,
            retire_wait: Duration::ZERO,
        }
    }

    /// A HAProxy runc runs, as an upgraded node has it.
    fn old_haproxy(rt: &Fake, dir: &str) {
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_SYSTEM.to_string(), SYSTEM_LABEL.to_string());
        labels.insert(IMAGE_LABEL.to_string(), IMAGE.to_string());
        labels.insert(DIR_LABEL.to_string(), dir.to_string());
        rt.containers.lock().unwrap().push(runtime::Container {
            id: "old".into(),
            labels,
            state: STATE_RUNNING.into(),
            oci_runtime: runtime::OCI_RUNC.into(),
            ..Default::default()
        });
    }

    /// The move to crun (ADR 0056): the new HAProxy serves beside the old
    /// one before the old one stops listening; one still running after its
    /// wait is stopped.
    #[tokio::test(start_paused = true)]
    async fn moves_haproxy_to_crun_beside_the_old_one() {
        let rt = Arc::new(Fake::default());
        *rt.starts_as.lock().unwrap() = STATE_RUNNING.into();
        *rt.soft_stops.lock().unwrap() = true;
        let e = engine(&rt, "/d");
        assert!(!e.on_runc().await.unwrap());
        old_haproxy(&rt, "/d");
        assert!(e.on_runc().await.unwrap());
        e.replace_on_crun().await.unwrap();
        assert_eq!(
            rt.calls.lock().unwrap().clone(),
            vec![
                format!("pull {IMAGE}"),
                "signal old SIGUSR1".into(),
                "stop old".into(),
                "remove old".into(),
            ]
        );
        let left = rt.containers.lock().unwrap().clone();
        assert_eq!(left.len(), 1);
        assert_eq!(
            (left[0].id.as_str(), left[0].state.as_str()),
            ("hap-1", STATE_RUNNING)
        );
        assert!(!e.on_runc().await.unwrap());
        // Nothing on runc: nothing to do.
        e.replace_on_crun().await.unwrap();
        assert_eq!(rt.specs.lock().unwrap().len(), 1);

        // An old HAProxy that keeps its connections past the wait.
        let rt = Arc::new(Fake::default());
        *rt.starts_as.lock().unwrap() = STATE_RUNNING.into();
        old_haproxy(&rt, "/d");
        let e = engine(&rt, "/d");
        let began = tokio::time::Instant::now();
        e.replace_on_crun().await.unwrap();
        assert!(began.elapsed() >= RETIRE_WAIT);
        assert_eq!(
            rt.calls.lock().unwrap()[1..],
            ["signal old SIGUSR1", "stop old", "remove old"]
        );
    }

    /// A new HAProxy that does not stay up beside the old one: the old one
    /// goes first, as for any start.
    #[tokio::test(start_paused = true)]
    async fn falls_back_to_a_plain_start() {
        let rt = Arc::new(Fake::default());
        *rt.starts_as.lock().unwrap() = runtime::STATE_EXITED.into();
        old_haproxy(&rt, "/d");
        let e = engine(&rt, "/d");
        assert_eq!(
            e.replace_on_crun().await.unwrap_err(),
            "start haproxy on crun beside the old one: haproxy exited (code 1): last 20 lines; and after it: haproxy exited (code 1): last 20 lines"
        );
        assert_eq!(
            rt.calls.lock().unwrap().clone(),
            vec![
                format!("pull {IMAGE}"),
                "stop old".into(),
                "remove old".into(),
                "stop hap-1".into(),
                "remove hap-1".into(),
                format!("pull {IMAGE}"),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn runs_haproxy_as_a_system_container() {
        let rt = Arc::new(Fake::default());
        *rt.starts_as.lock().unwrap() = STATE_RUNNING.into();
        let e = engine(&rt, "/var/lib/armada/haproxy");
        assert!(!e.running().await.unwrap());
        assert_eq!(
            e.reload().await.unwrap_err(),
            "haproxy container is not running"
        );
        e.start().await.unwrap();
        assert!(e.running().await.unwrap());
        let spec = rt.specs.lock().unwrap()[0].clone();
        assert_eq!(spec.name, "armada-haproxy");
        assert_eq!(spec.user, "0:0");
        assert_eq!(spec.cap_add, vec!["NET_BIND_SERVICE"]);
        assert_eq!(spec.labels["armada.system"], "haproxy");
        assert_eq!(spec.labels["armada.image"], IMAGE);
        assert_eq!(spec.labels["armada.dir"], "/var/lib/armada/haproxy");
        assert_eq!(
            spec.mounts,
            vec![
                Mount {
                    source: "/var/lib/armada/haproxy/etc".into(),
                    target: CONTAINER_CONF_DIR.into(),
                    read_only: true
                },
                Mount {
                    source: "/var/lib/armada/haproxy/run".into(),
                    target: CONTAINER_RUN_DIR.into(),
                    read_only: false
                },
            ]
        );
        *rt.exec.lock().unwrap() = ("[ALERT] bad line\n".into(), 1);
        assert_eq!(
            e.validate("/usr/local/etc/haproxy/haproxy.cfg.new")
                .await
                .unwrap_err(),
            "haproxy -c: [ALERT] bad line"
        );
        e.reload().await.unwrap();
        // Another directory: not this engine's HAProxy; a start replaces it.
        let other = engine(&rt, "/elsewhere");
        assert!(!other.running().await.unwrap());
        *rt.starts_as.lock().unwrap() = runtime::STATE_EXITED.into();
        assert_eq!(
            other.start().await.unwrap_err(),
            "haproxy exited (code 1): last 20 lines"
        );
        assert_eq!(
            rt.calls.lock().unwrap().clone(),
            vec![
                format!("pull {IMAGE}"),
                "exec hap-1 haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg.new".into(),
                "signal hap-1 SIGUSR2".into(),
                "stop hap-1".into(),
                "remove hap-1".into(),
                format!("pull {IMAGE}"),
            ]
        );
    }
}

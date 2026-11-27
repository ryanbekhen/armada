//! A server's running member for a case: the pinned etcd
//! started for the case's data directory on loopback ports, as
//! etcdmember::prepare_start describes it, its state seeded as the
//! recording says, and what it holds of
//! users written into the case directory afterwards.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use armada_daemon::agentconfig::{FILE_CA_CERT, FILE_CA_KEY};
use armada_daemon::etcdmember::{self, Config};
use armada_store::{Client, Etcd};

const PREFIX: &str = "/armada/";

pub struct Member {
    child: Child,
    client: Client,
    conf: PathBuf,
}

impl Drop for Member {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.conf);
    }
}

impl Member {
    /// Starts the member of data (the case's data directory), its
    /// configuration file at conf (outside the case directory).
    pub async fn start(
        etcd: &Path,
        data: &Path,
        ports: (u16, u16),
        conf: PathBuf,
        master_key_id: &str,
    ) -> Result<Member, String> {
        let ca = armada_pki::Ca::load(
            &std::fs::read(data.join(FILE_CA_CERT)).map_err(|e| e.to_string())?,
            &std::fs::read(data.join(FILE_CA_KEY)).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let mut cfg = Config {
            dir: data.join("etcd"),
            name: "s1".into(),
            addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            client_port: ports.0,
            peer_port: ports.1,
            ca: Some(ca),
            initial_cluster: String::new(),
        };
        let p = etcdmember::prepare_start(&mut cfg)?;
        std::fs::write(&conf, &p.file).map_err(|e| e.to_string())?;
        let child = Command::new(etcd)
            .arg("--config-file")
            .arg(&conf)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        let client = Client::connect(&p.client_url, &p.dir).map_err(|e| e.to_string())?;
        let mut m = Member {
            child,
            client,
            conf,
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_secs(3), m.client.status()).await
            {
                break;
            }
            if let Ok(Some(st)) = m.child.try_wait() {
                return Err(format!("etcd ended: {st}"));
            }
            if Instant::now() > deadline {
                return Err("etcd did not become ready within a minute".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // Server s1 and the master key's ID, as init records
        // them.
        let st = Etcd::new(m.client.clone(), PREFIX)
            .await
            .map_err(|e| e.to_string())?;
        st.upsert_server(&armada_store::Server {
            name: "s1".into(),
            private_ip: "10.0.0.5".into(),
            api_addr: "10.0.0.5:7443".into(),
            join_addr: String::new(),
            member_id: 0,
            schema: 0,
            version: String::new(),
            created_at: armada_spec::gotime::Time::zero(),
        })
        .await
        .map_err(|e| e.to_string())?;
        st.set_meta("master_key_id", master_key_id)
            .await
            .map_err(|e| e.to_string())?;
        Ok(m)
    }

    /// The users the member holds, written in the recording's form.
    pub async fn record(&self, dir: &Path) -> Result<(), String> {
        let st = Etcd::new(self.client.clone(), PREFIX)
            .await
            .map_err(|e| e.to_string())?;
        let users = st
            .list_principals("user")
            .await
            .map_err(|e| e.to_string())?;
        let lines: Vec<String> = users
            .iter()
            .map(|u| {
                let roles: Vec<String> = u.roles.iter().map(|g| g.to_string()).collect();
                format!("user {} roles [{}]", u.name, roles.join(" "))
            })
            .collect();
        let p = dir.join("state-users.txt");
        std::fs::write(&p, format!("{}\n", lines.join("\n"))).map_err(|e| e.to_string())?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())
    }
}

//! The AdminService client of a command: the config
//! loaded, the channel dialed, every answer's armada-servers header kept in
//! the config (`ServerSync`), and errors shown as `rpc_error` shows them.

use std::future::Future;

use armada_proto::armada::v1::admin_service_client::AdminServiceClient;
use tonic::transport::Channel;
use tonic::{Response, Status};

use crate::config;

/// The client of one command run.
pub struct Admin {
    client: AdminServiceClient<Channel>,
    sync: ServerSync,
}

/// The leader's list of servers, written back to the config
/// once per run when it differs.
struct ServerSync {
    path: String,
    servers: Vec<String>,
    done: bool,
}

impl Admin {
    /// dialAdmin.
    pub fn dial(config_path: &str) -> Result<Admin, String> {
        let cc = config::load(config_path)?;
        let ch = crate::dial::dial(&cc)?;
        Ok(Admin {
            client: AdminServiceClient::new(ch)
                .max_decoding_message_size(usize::MAX)
                .max_encoding_message_size(usize::MAX),
            sync: ServerSync {
                path: config_path.to_string(),
                servers: cc.servers,
                done: false,
            },
        })
    }

    /// A unary call: f gets a clone of the client.
    pub async fn call<R, F, Fut>(&mut self, f: F) -> Result<R, Status>
    where
        F: FnOnce(AdminServiceClient<Channel>) -> Fut,
        Fut: Future<Output = Result<Response<R>, Status>>,
    {
        let resp = f(self.client.clone()).await?;
        if let Some(v) = resp.metadata().get(config::SERVERS_HEADER)
            && let Ok(s) = v.to_str()
        {
            self.sync.observe(s);
        }
        Ok(resp.into_inner())
    }
}

impl ServerSync {
    fn observe(&mut self, header: &str) {
        if self.path.is_empty() {
            return;
        }
        let addrs = config::parse_servers(header);
        if !config::check_servers(&addrs) {
            return;
        }
        if self.done
            || config::same_servers(&addrs, &self.servers)
            || tunnelled(&self.servers, &addrs)
        {
            return;
        }
        self.done = true;
        let Ok(mut cc) = config::load(&self.path) else {
            return;
        };
        cc.servers = addrs.clone();
        if cc.save_file(&self.path).is_ok() {
            self.servers = addrs;
        }
    }
}

/// tunnelled: the config reaches the control plane through a loopback
/// address that is no server's own, such as an SSH tunnel.
pub fn tunnelled(servers: &[String], actual: &[String]) -> bool {
    servers.iter().any(|a| {
        config::parse_addr_port(a).is_some_and(|(ip, _)| config::is_loopback(&ip))
            && !actual.contains(a)
    })
}

/// printable: control characters replaced, so a message cannot move the
/// cursor or forge lines.
pub fn printable(s: &str) -> String {
    s.chars()
        .map(|c| {
            if armada_spec::go::is_control(c) {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// A status's message, each line made printable.
pub fn rpc_error(s: &Status) -> String {
    s.message()
        .split('\n')
        .map(printable)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Calls a method of AdminService on an [`Admin`] within a command:
/// `rpc!(ctx, admin, list_apps, req)` is the answer or the status.
#[macro_export]
macro_rules! rpc {
    ($ctx:expr, $admin:expr, $method:ident, $req:expr) => {{
        let req = $req;
        $ctx.block_on($admin.call(move |mut c| async move { c.$method(req).await }))
    }};
}

//! armadad join and armadad server join:
//! this machine joins a cluster as a node, or as a control plane server,
//! through the leader's join listener, the CA pinned by its hash.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use armada_client::cli::{Ctx, Error, Result};
use armada_client::config::{self as clientconfig, GROUP, SYSTEM_PATH};
use armada_pki::{
    Ca, Certificate, ExtKeyUsage, Identity, IssueRequest, KIND_NODE, KIND_SERVER, KIND_USER,
    parse_cert_pem,
};
use armada_proto::armada::v1 as pb;
use pb::join_service_client::JoinServiceClient;

use crate::agentconfig::{
    self, AgentConfig, DIR_ETCD, FILE_AGENT, FILE_CA_CERT, FILE_CA_KEY, FILE_ETCD_INITIAL,
    FILE_SERVER_CERT,
};
use crate::joinclient;
use crate::machine::{
    self, FILE_MASTER_KEY, FILE_NODE_CERT, FILE_NODE_KEY, FILE_SERVER_KEY, RuntimeFlags,
};

fn msg(s: impl Into<String>) -> Error {
    Error::Msg(s.into())
}

fn s<E: ToString>(e: E) -> Error {
    Error::Msg(e.to_string())
}

/// The token, CA pin, and the reading of both.
fn read_token(ctx: &mut Ctx<'_>) -> Result<(armada_pki::JoinToken, String)> {
    let file = ctx.str("token-file");
    let raw =
        armada_client::commands::secret::read_secret_value(ctx, &file).map_err(|e| match e {
            Error::Msg(m) => msg(format!("read token: {m}")),
            other => other,
        })?;
    let tok =
        armada_pki::parse_join_token(armada_spec::go::trim_space(&String::from_utf8_lossy(&raw)))
            .map_err(s)?;
    let pin = armada_pki::parse_ca_hash(&ctx.str("ca-hash")).map_err(s)?;
    Ok((tok, pin))
}

/// Refuses a data directory that already holds one of names.
fn check_fresh(data_dir: &str, names: &[&str]) -> Result {
    armada_fsutil::mkdir_private(Path::new(data_dir)).map_err(|e| msg(format!("data dir: {e}")))?;
    for f in names {
        let p = Path::new(data_dir).join(f);
        match std::fs::symlink_metadata(&p) {
            Ok(_) => {
                return Err(msg(format!(
                    "{data_dir} already belongs to a cluster (found {f})"
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(msg(format!(
                    "stat {}: {}",
                    p.display(),
                    armada_fsutil::errno_text(&e)
                )));
            }
        }
    }
    Ok(())
}

fn write_files(data_dir: &str, files: &[(&str, &[u8])]) -> Result {
    for (name, data) in files {
        armada_fsutil::write_file_atomic(&Path::new(data_dir).join(name), data, 0o600)
            .map_err(s)?;
    }
    Ok(())
}

/// The CA the answer carries is the pinned one.
fn same_ca(pem: &[u8], pinned: &Certificate) -> bool {
    parse_cert_pem(pem).is_ok_and(|c| c.fingerprint() == pinned.fingerprint())
}

fn version() -> String {
    armada_client::commands::version::get().version.to_string()
}

fn rpc(e: tonic::Status) -> Error {
    msg(armada_client::rpc::rpc_error(&e))
}

/// The node name from --node-name or --name, else the hostname's.
fn name_flag(ctx: &Ctx<'_>, flag: &str, err: &str) -> Result<String> {
    let mut name = ctx.str(flag);
    if name.is_empty() {
        name = machine::sanitize_name(&machine::hostname(), "");
        if name.is_empty() {
            return Err(msg(err));
        }
    }
    Ok(name)
}

/// armadad join.
pub fn node(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let addr = args[0].clone();
    let data_dir = ctx.str("data-dir");
    let (ip, mut mesh) = {
        let c = |n: &str| ctx.changed(n);
        machine::prepare_join(
            &c,
            &addr,
            &ctx.str("private-ip"),
            &ctx.str("endpoint"),
            ctx.bool("no-private-ip"),
            false,
        )
        .map_err(msg)?
    };
    let mtu = ctx.int("mtu");
    machine::check_uplink_mtu(mtu).map_err(msg)?;
    let (tok, pin) = read_token(ctx)?;
    let rt = RuntimeFlags::from(ctx);
    let mut ac = AgentConfig::default();
    rt.apply(&mut ac, ip.as_ref()).map_err(msg)?;
    let node_name = name_flag(
        ctx,
        "node-name",
        "cannot derive a node name from the hostname; pass --node-name",
    )?;
    armada_pki::parse_identity(&Identity::new(KIND_NODE, &node_name).to_string()).map_err(s)?;
    check_fresh(&data_dir, &[FILE_NODE_KEY, FILE_AGENT, FILE_CA_KEY])?;
    mesh.load_key(&data_dir).map_err(msg)?;

    let rtm = crate::commands::server::runtime()?;
    let res = rtm.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let ca = joinclient::fetch_pinned_ca(&addr, &pin)
                .await
                .map_err(msg)?;
            let ch = joinclient::join_channel(&addr, &ca).map_err(msg)?;
            let (key_pem, csr) = armada_pki::new_node_csr(&node_name).map_err(s)?;
            let resp = JoinServiceClient::new(ch)
                .join(pb::JoinRequest {
                    token_id: tok.id.clone(),
                    token_secret: tok.secret().to_string(),
                    node_name: node_name.clone(),
                    private_ip: machine::ip_string(ip.as_ref()),
                    csr,
                    version: version(),
                    network_key: mesh.key.clone(),
                    endpoint: mesh.endpoint_text(),
                    behind_nat: mesh.behind_nat,
                })
                .await
                .map_err(rpc)?
                .into_inner();
            Ok::<_, Error>((ca, key_pem, resp))
        })
        .await
        .unwrap_or_else(|_| Err(msg("context deadline exceeded")))
    });
    let (ca, key_pem, resp) = res?;
    // The server must hand back the CA pinned and a certificate for this
    // key and name.
    if !same_ca(&resp.ca_cert, &ca) {
        return Err(msg("server returned a different CA than the pinned one"));
    }
    if !clientconfig::check_servers(&resp.servers) {
        return Err(msg(servers_error(&resp.servers)));
    }
    let servers = resp.servers.clone();
    let ip = mesh
        .address(ip, &resp.network_mode, &resp.mesh_ip)
        .map_err(msg)?;
    let note = rt
        .use_node_subnet(&mut ac, &resp.node_subnet, &resp.network_mode, Some(&ip))
        .map_err(msg)?;
    // agent.json last: its presence marks a completed join.
    write_files(
        &data_dir,
        &[
            (FILE_CA_CERT, &resp.ca_cert),
            (FILE_NODE_KEY, key_pem.expose()),
            (FILE_NODE_CERT, &resp.node_cert),
        ],
    )?;
    ac.node_id = node_name.clone();
    ac.private_ip = ip.to_string();
    ac.servers = Some(servers.clone());
    ac.behind_nat = mesh.behind_nat;
    ac.mtu = mtu;
    if mesh.on {
        // The servers are at mesh addresses, or in another site: the
        // tunnels come up with the cluster's peer list before the agent
        // starts (ADR 0049, ADR 0050).
        ac.endpoint = mesh.endpoint_text();
        let net = resp.network.clone().unwrap_or_default();
        ac.cluster_cidr = net.cluster_cidr.clone();
        ac.mesh_cidr = net.mesh_cidr.clone();
        let log = armada_agent::log::Logger::discard();
        rtm.block_on(machine::up_mesh(&data_dir, &ac, resp.network.clone(), &log))
            .map_err(|e| {
                msg(format!(
                    "{e}; fix it and run `armada node delete {node_name}` on the cluster before trying again"
                ))
            })?;
    }
    agentconfig::save(&data_dir, &ac).map_err(msg)?;
    if let Err(e) = armada_agent::creds::Credentials::load(Path::new(&data_dir), &node_name) {
        for f in [FILE_AGENT, FILE_NODE_CERT, FILE_NODE_KEY, FILE_CA_CERT] {
            let _ = std::fs::remove_file(Path::new(&data_dir).join(f));
        }
        return Err(msg(format!("server returned an unusable certificate: {e}")));
    }
    let mut out = format!(
        "Joined as node {node_name} ({ip}); control plane {}.\n",
        servers.join(", ")
    );
    if !resp.node_subnet.is_empty() {
        out.push_str(&format!("Container subnet: {}.\n", resp.node_subnet));
    }
    out.push_str(&note);
    out.push_str(&machine::next_step("agent", &data_dir));
    ctx.print(&out);
    Ok(())
}

/// clientconfig.CheckServers' error.
pub fn servers_error(list: &[String]) -> String {
    if list.is_empty() {
        return "server returned no control plane address".to_string();
    }
    for a in list {
        if let Err(e) = crate::netutil::check_private_listen(a) {
            return format!("server address: {e}");
        }
    }
    "invalid control plane list".to_string()
}

/// What a server returned to a joining control plane
/// node is the pinned CA with its key, and certificates for name.
fn check_joined_server(
    resp: &pb::JoinServerResponse,
    pinned: &Certificate,
    name: &str,
) -> std::result::Result<(), String> {
    if !same_ca(&resp.ca_cert, pinned) {
        return Err("server returned a different CA than the pinned one".to_string());
    }
    Ca::load(&resp.ca_cert, &resp.ca_key)
        .map_err(|e| format!("server returned an unusable CA key: {e}"))?;
    armada_server::tls::ServerCert::new(&resp.ca_cert, &resp.server_cert, &resp.server_key)
        .map_err(|e| format!("server returned an unusable server certificate: {e}"))?;
    let leaf = parse_cert_pem(&resp.server_cert)
        .map_err(|_| "server returned a certificate for another server".to_string())?;
    match leaf.identity() {
        Ok(id) if id.kind == KIND_SERVER && id.name == name => {}
        _ => return Err("server returned a certificate for another server".to_string()),
    }
    leaf.verify(
        pinned,
        None,
        ExtKeyUsage::ServerAuth,
        std::time::SystemTime::now(),
    )
    .map_err(|e| format!("server certificate is not signed by the cluster CA: {e}"))?;
    if resp.initial_cluster.is_empty() {
        return Err("server returned no etcd cluster".to_string());
    }
    Ok(())
}

/// The user of the client config a joining server writes;
/// "" when not run as root (none is written).
fn join_user_name(flag: &str) -> std::result::Result<String, String> {
    if machine::euid() != 0 {
        return Ok(String::new());
    }
    let mut name = flag.to_string();
    if name.is_empty() {
        name = "admin".to_string();
        if let Some(p) = machine::sudo_user() {
            name = machine::sanitize_name(&p.name, "admin");
        } else {
            let cur = machine::current_user_name();
            if !cur.is_empty() {
                name = machine::sanitize_name(&cur, "admin");
            }
        }
    }
    armada_pki::parse_identity(&Identity::new(KIND_USER, &name).to_string())
        .map_err(|e| e.to_string())?;
    Ok(name)
}

/// The machine's shared admin config, kept when it
/// exists, for user_name once the leader recorded the name.
fn joined_client_configs(
    resp: &pb::JoinServerResponse,
    servers: &[String],
    user_name: &str,
) -> std::result::Result<Vec<String>, String> {
    if user_name.is_empty() {
        return Ok(Vec::new());
    }
    if !resp.user_recorded {
        return Err(format!(
            "the leader did not record user {user_name} (it may run an older Armada), so no client config was written; once every server is upgraded, create the user with `armada user create {user_name} --role cluster-admin -o FILE`"
        ));
    }
    let ca = Ca::load(&resp.ca_cert, &resp.ca_key).map_err(|e| e.to_string())?;
    let (cert, key) = ca
        .issue(&IssueRequest {
            identity: Identity::new(KIND_USER, user_name),
            client: true,
            ..Default::default()
        })
        .map_err(|e| e.to_string())?;
    let cc = clientconfig::Config {
        servers: servers.to_vec(),
        ca: String::from_utf8_lossy(&resp.ca_cert).into_owned(),
        cert: String::from_utf8_lossy(&cert).into_owned(),
        key: String::from_utf8_lossy(key.expose()).into_owned(),
        ..Default::default()
    };
    let mut written = Vec::new();
    if matches!(std::fs::metadata(SYSTEM_PATH), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        machine::save_shared(&cc, SYSTEM_PATH)?;
        written.push(format!("{SYSTEM_PATH} ({user_name})"));
    }
    Ok(written)
}

/// armadad server join.
pub fn server(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let addr = args[0].clone();
    let data_dir = ctx.str("data-dir");
    let (ip, mut mesh) = {
        let c = |n: &str| ctx.changed(n);
        machine::prepare_join(
            &c,
            &addr,
            &ctx.str("private-ip"),
            &ctx.str("endpoint"),
            ctx.bool("no-private-ip"),
            true,
        )
        .map_err(msg)?
    };
    let port = ctx.int("port");
    if !(1..=65534).contains(&port) {
        return Err(msg(format!("invalid --port {port}")));
    }
    let mut join_port = ctx.int("join-port");
    if join_port == 0 {
        join_port = port + 1;
    }
    if !(0..=65535).contains(&join_port) {
        return Err(msg(format!("invalid --join-port {join_port}")));
    }
    let (tok, pin) = read_token(ctx)?;
    let rt = RuntimeFlags::from(ctx);
    let mut ac = AgentConfig::default();
    rt.apply(&mut ac, ip.as_ref()).map_err(msg)?;
    let name = name_flag(
        ctx,
        "name",
        "cannot derive a name from the hostname; pass --name",
    )?;
    for id in [
        Identity::new(KIND_SERVER, &name),
        Identity::new(KIND_NODE, &name),
    ] {
        armada_pki::parse_identity(&id.to_string()).map_err(s)?;
    }
    check_fresh(
        &data_dir,
        &[
            FILE_CA_KEY,
            FILE_NODE_KEY,
            FILE_AGENT,
            FILE_MASTER_KEY,
            DIR_ETCD,
        ],
    )?;
    mesh.load_key(&data_dir).map_err(msg)?;
    // The user of the client configs written below: the leader records
    // it before this machine signs its certificate.
    let client_user = join_user_name(&ctx.str("user-name")).map_err(msg)?;
    let peer_port = crate::etcdmember::member_config(&data_dir).peer_port;

    let rtm = crate::commands::server::runtime()?;
    let res = rtm.block_on(async {
        tokio::time::timeout(Duration::from_secs(60), async {
            let ca = joinclient::fetch_pinned_ca(&addr, &pin)
                .await
                .map_err(msg)?;
            let ch = joinclient::join_channel(&addr, &ca).map_err(msg)?;
            let (node_key, csr) = armada_pki::new_node_csr(&name).map_err(s)?;
            let resp = JoinServiceClient::new(ch)
                .join_server(pb::JoinServerRequest {
                    token_id: tok.id.clone(),
                    token_secret: tok.secret().to_string(),
                    name: name.clone(),
                    private_ip: machine::ip_string(ip.as_ref()),
                    node_csr: csr,
                    version: version(),
                    api_port: port as i32,
                    join_port: join_port as i32,
                    etcd_peer_port: i32::from(peer_port),
                    user_name: client_user.clone(),
                    network_key: mesh.key.clone(),
                    endpoint: mesh.endpoint_text(),
                })
                .await
                .map_err(rpc)?
                .into_inner();
            Ok::<_, Error>((ca, node_key, resp))
        })
        .await
        .unwrap_or_else(|_| Err(msg("context deadline exceeded")))
    });
    let (ca, node_key, resp) = res?;
    let again = |e: String| {
        msg(format!(
            "{e}; run `armada server delete {name}` on the cluster before trying again"
        ))
    };
    check_joined_server(&resp, &ca, &name).map_err(again)?;
    if !clientconfig::check_servers(&resp.servers) {
        return Err(msg(servers_error(&resp.servers)));
    }
    let servers = resp.servers.clone();
    let ip: IpAddr = mesh
        .address(ip, &resp.network_mode, &resp.mesh_ip)
        .map_err(again)?;
    let note = rt
        .use_node_subnet(&mut ac, &resp.node_subnet, &resp.network_mode, Some(&ip))
        .map_err(again)?;
    // agent.json last: its presence marks a completed join.
    write_files(
        &data_dir,
        &[
            (FILE_CA_CERT, &resp.ca_cert),
            (FILE_CA_KEY, &resp.ca_key),
            (FILE_SERVER_CERT, &resp.server_cert),
            (FILE_SERVER_KEY, &resp.server_key),
            (FILE_NODE_KEY, node_key.expose()),
            (FILE_NODE_CERT, &resp.node_cert),
        ],
    )?;
    armada_secrets::write_key_file(
        &Path::new(&data_dir).join(FILE_MASTER_KEY),
        &armada_secrets::Value::new(&resp.master_key),
    )
    .map_err(|e| msg(format!("master key: {e}")))?;
    armada_fsutil::mkdir_private(&Path::new(&data_dir).join(DIR_ETCD)).map_err(s)?;
    write_files(
        &data_dir,
        &[(
            FILE_ETCD_INITIAL,
            format!("{}\n", resp.initial_cluster).as_bytes(),
        )],
    )?;
    ac.node_id = name.clone();
    ac.private_ip = ip.to_string();
    ac.servers = Some(servers.clone());
    if mesh.on {
        // etcd and the API listen on the node's address, which the other
        // servers reach only through the tunnels in a mesh cluster or from
        // another site (ADR 0050).
        ac.endpoint = mesh.endpoint_text();
        let net = resp.network.clone().unwrap_or_default();
        ac.cluster_cidr = net.cluster_cidr.clone();
        ac.mesh_cidr = net.mesh_cidr.clone();
        let log = armada_agent::log::Logger::discard();
        rtm.block_on(machine::up_mesh(&data_dir, &ac, resp.network.clone(), &log))
            .map_err(|e| {
                msg(format!(
                    "{e}; fix it and run `armada server delete {name}` on the cluster before trying again"
                ))
            })?;
    }
    agentconfig::save(&data_dir, &ac).map_err(msg)?;
    armada_agent::creds::Credentials::load(Path::new(&data_dir), &name)
        .map_err(|e| msg(format!("server returned an unusable node certificate: {e}")))?;
    // Like init: the machine's cluster-admins, and the person who ran this
    // through sudo, can use armada here at once. The cluster already
    // exists, so a failure only warns.
    let configs = match joined_client_configs(&resp, &servers, &client_user) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(ctx.err, "warning: client config: {e}");
            Vec::new()
        }
    };
    let mut group_note = String::new();
    if let Some(person) = machine::sudo_user()
        && !client_user.is_empty()
    {
        match machine::join_admin_group(&person) {
            Err(e) => {
                let _ = writeln!(
                    ctx.err,
                    "warning: add {0} to the {GROUP} group yourself (sudo usermod -aG {GROUP} {0}): {e}",
                    person.name
                );
            }
            Ok(true) => group_note = machine::admin_group_note(&person.name),
            Ok(false) => {}
        }
    }
    let mut out = format!("Joined as control plane node {name} ({ip}).\n");
    for c in &configs {
        out.push_str(&format!("Client config: {c}\n"));
    }
    if !group_note.is_empty() {
        out.push_str(&format!("{group_note}.\n"));
    }
    if !resp.node_subnet.is_empty() {
        out.push_str(&format!("Container subnet: {}.\n", resp.node_subnet));
    }
    out.push_str(&note);
    out.push_str(&machine::next_step("server", &data_dir));
    if servers.len() == 2 {
        out.push_str("With two control plane nodes, losing either one stops the control plane; add a third.\n");
    }
    ctx.print(&out);
    Ok(())
}

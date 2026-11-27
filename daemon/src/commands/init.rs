//! armadad init: a new cluster on this machine. The state is written
//! through the pack's etcd, started from the configuration file `armadad
//! etcd` writes for the command's length (ADR 0055), or, with `--state kv`,
//! through a new armada-kv cluster (ADR 0057) opened in this process, whose
//! member armada-kv.service runs afterwards.

use std::net::IpAddr;
use std::path::Path;

use armada_client::cli::{Ctx, Error, Result};
use armada_client::config::{self as clientconfig, ENV_PATH, SYSTEM_PATH};
use armada_pki::{Ca, Identity, IssueRequest, KIND_NODE, KIND_SERVER, KIND_USER, NODE_VALIDITY};
use armada_proto::armada::v1 as pb;
use armada_spec::go::{Prefix, parse_addr, quote};
use armada_store::{Etcd, Network, Node, NodeCert, Server};

use crate::agentconfig::{
    self, AgentConfig, DIR_ETCD, DIR_KV, FILE_CA_CERT, FILE_CA_KEY, FILE_SERVER_CERT, NETWORK_MESH,
};
use crate::machine::{
    self, FILE_MASTER_KEY, FILE_NETWORK_KEY, FILE_NODE_CERT, FILE_NODE_KEY, FILE_SERVER_KEY,
    META_CLUSTER, META_MASTER_KEY, NETWORK_PLAIN, NETWORK_WIREGUARD, NODE_SUBNET_BITS,
    RuntimeFlags, WIREGUARD_PORT,
};
use crate::{backup, netutil, state};

fn msg(s: impl Into<String>) -> Error {
    Error::Msg(s.into())
}

fn s<E: ToString>(e: E) -> Error {
    Error::Msg(e.to_string())
}

/// --cluster-cidr and --network for a cluster whose
/// first node has private_ip.
fn cluster_network(
    cidr: &str,
    mode: &str,
    private_ip: &IpAddr,
) -> std::result::Result<(String, Prefix), String> {
    if mode != NETWORK_PLAIN && mode != NETWORK_WIREGUARD && mode != NETWORK_MESH {
        return Err(format!(
            "invalid --network {}: plain, wireguard, or mesh",
            quote(mode)
        ));
    }
    let p =
        machine::parse_prefix_checked(cidr).map_err(|e| format!("invalid --cluster-cidr: {e}"))?;
    armada_store::network::check_cluster_cidr(&Some(p.clone()))
        .map_err(|e| format!("invalid --cluster-cidr: {e}"))?;
    if let Some(a) = parse_addr(&private_ip.to_string())
        && p.contains(&a)
    {
        return Err(format!(
            "--cluster-cidr {} contains the private IP {private_ip}; pick a range the network does not use",
            p.string()
        ));
    }
    Ok((mode.to_string(), p))
}

/// The node subnet the state gives a cluster's first node.
fn first_subnet(cluster: &Prefix) -> Prefix {
    Prefix::from(&cluster.addr, NODE_SUBNET_BITS)
}

/// Whether two prefixes overlap (Prefix.Overlaps).
fn overlaps(a: &Prefix, b: &Prefix) -> bool {
    let bits = a.bits.min(b.bits);
    Prefix::from(&a.addr, bits).masked() == Prefix::from(&b.addr, bits).masked()
}

/// --state: where the cluster keeps its state.
fn state_store(flag: &str) -> std::result::Result<state::Store, String> {
    match flag {
        "etcd" => Ok(state::Store::Etcd),
        "kv" => Ok(state::Store::Kv),
        other => Err(format!("invalid --state {}: etcd or kv", quote(other))),
    }
}

pub fn run(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let store = state_store(&ctx.str("state")).map_err(msg)?;
    let mode = ctx.str("network");
    let data_dir = ctx.str("data-dir");
    let port = ctx.int("port");
    let mesh_cidr = ctx.str("mesh-cidr");
    // A mesh cluster's first node takes the first mesh address and is
    // reached at its public endpoint (ADR 0049).
    let mut ep = None;
    let mut mesh_prefix = None;
    let ip: IpAddr = if mode == NETWORK_MESH {
        if ctx.changed("private-ip") {
            return Err(msg(
                "--private-ip does not apply to the mesh mode: nodes get mesh addresses of --mesh-cidr",
            ));
        }
        ep = Some(machine::resolve_endpoint(&ctx.str("endpoint")).map_err(msg)?);
        let p = machine::parse_prefix_checked(&mesh_cidr)
            .map_err(|e| msg(format!("invalid --mesh-cidr: {e}")))?;
        armada_store::network::check_mesh_cidr(&Some(p.clone()))
            .map_err(|e| msg(format!("invalid --mesh-cidr: {e}")))?;
        let first = machine::next4(&p.addr);
        mesh_prefix = Some(p);
        netutil::to_std(&first)
    } else {
        if ctx.changed("endpoint") || ctx.changed("mesh-cidr") {
            return Err(msg("--endpoint and --mesh-cidr are for --network mesh"));
        }
        let ip = machine::resolve_private_ip(&ctx.str("private-ip")).map_err(msg)?;
        if !ip.is_ipv4() {
            // Every new cluster has a cluster network, which is IPv4 only.
            return Err(msg(format!(
                "--private-ip {ip} is not an IPv4 address: the cluster network carries IPv4 only"
            )));
        }
        ip
    };
    let rt = RuntimeFlags::from(ctx);
    let mut ac = AgentConfig::default();
    rt.apply(&mut ac, Some(&ip)).map_err(msg)?;
    if rt.subnet_changed {
        return Err(msg(
            "--container-subnet does not apply to init: every node gets a subnet of --cluster-cidr",
        ));
    }
    let (net_mode, cluster) = cluster_network(&ctx.str("cluster-cidr"), &mode, &ip).map_err(msg)?;
    if let Some(mp) = &mesh_prefix {
        if overlaps(mp, &cluster) {
            return Err(msg(format!(
                "--mesh-cidr {} overlaps --cluster-cidr {}",
                mp.string(),
                cluster.string()
            )));
        }
        let epa = parse_addr(&ep.map(|e| e.to_string()).unwrap_or_default());
        if epa.is_some_and(|a| cluster.contains(&a) || mp.contains(&a)) {
            return Err(msg(format!(
                "the endpoint {} is inside the cluster's own ranges",
                ep.map(|e| e.to_string()).unwrap_or_default()
            )));
        }
    }
    if !(1..=65535).contains(&port) {
        return Err(msg(format!("invalid --port {port}")));
    }
    let mut node_name = ctx.str("node-name");
    if node_name.is_empty() {
        node_name = machine::sanitize_name(&machine::hostname(), "node-1");
    }
    // The person who ran init through sudo is the first user, with
    // cluster-admin, under their own name (ADR 0033).
    let person = machine::sudo_user();
    let mut user_name = ctx.str("user-name");
    if user_name.is_empty() {
        user_name = "admin".to_string();
        if let Some(p) = &person {
            user_name = machine::sanitize_name(&p.name, "admin");
        } else {
            let cur = machine::current_user_name();
            if !cur.is_empty() {
                user_name = machine::sanitize_name(&cur, "admin");
            }
        }
    }
    for id in [
        Identity::new(KIND_NODE, &node_name),
        Identity::new(KIND_USER, &user_name),
    ] {
        armada_pki::parse_identity(&id.to_string()).map_err(s)?;
    }
    let listen = match ip {
        IpAddr::V4(v) => format!("{v}:{port}"),
        IpAddr::V6(v) => format!("[{v}]:{port}"),
    };
    let dd = Path::new(&data_dir);
    armada_fsutil::mkdir_private(dd).map_err(|e| msg(format!("data dir: {e}")))?;
    for f in [FILE_CA_KEY, DIR_ETCD, DIR_KV, FILE_MASTER_KEY] {
        match std::fs::symlink_metadata(dd.join(f)) {
            Ok(_) => {
                return Err(msg(format!(
                    "{data_dir} is already initialized (found {f})"
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(msg(format!(
                    "stat {}: {}",
                    dd.join(f).display(),
                    armada_fsutil::errno_text(&e)
                )));
            }
        }
    }
    // The admin config goes where every cluster-admin of this machine
    // finds it, unless the operator names another file.
    let mut config_path = ctx.g.config_path.clone();
    if !ctx.changed("config") && std::env::var(ENV_PATH).unwrap_or_default().is_empty() {
        config_path = SYSTEM_PATH.to_string();
    }
    if std::fs::metadata(&config_path).is_ok() {
        return Err(msg(format!(
            "client config {config_path} already exists; move it away or pass --config"
        )));
    }

    let ca = Ca::new(&node_name).map_err(s)?;
    let ca_key = ca.key_pem();
    let (srv_cert, srv_key) = ca
        .issue(&IssueRequest {
            identity: Identity::new(KIND_SERVER, &node_name),
            dns_names: vec![armada_pki::SERVER_NAME.to_string()],
            ips: vec![ip],
            server: true,
            ..Default::default()
        })
        .map_err(s)?;
    let (node_key, csr) = armada_pki::new_node_csr(&node_name).map_err(s)?;
    let node_cert = ca
        .sign_node_csr(&csr, &node_name, NODE_VALIDITY)
        .map_err(s)?;
    let (admin_cert, admin_key) = ca
        .issue(&IssueRequest {
            identity: Identity::new(KIND_USER, &user_name),
            client: true,
            ..Default::default()
        })
        .map_err(s)?;
    for (name, data) in [
        (FILE_CA_CERT, ca.cert_pem.as_slice()),
        (FILE_CA_KEY, ca_key.expose()),
        (FILE_SERVER_CERT, srv_cert.as_slice()),
        (FILE_SERVER_KEY, srv_key.expose()),
        (FILE_NODE_CERT, node_cert.pem.as_slice()),
        (FILE_NODE_KEY, node_key.expose()),
    ] {
        armada_fsutil::write_file_atomic(&dd.join(name), data, 0o600).map_err(s)?;
    }
    armada_secrets::generate_key_file(&dd.join(FILE_MASTER_KEY))
        .map_err(|e| msg(format!("master key: {e}")))?;

    let fingerprint = ca.cert.fingerprint();
    let ip_text = ip.to_string();
    let ep_text = ep.map(|e| e.to_string()).unwrap_or_default();
    let mesh_text = mesh_prefix.as_ref().map(Prefix::string).unwrap_or_default();
    let cluster_text = cluster.string();
    let first = first_subnet(&cluster).string();
    let rtm = crate::commands::server::runtime()?;
    let net_log = armada_agent::log::Logger::discard();
    let (node, ac) = rtm
        .block_on(async {
            let mut ac = ac;
            let mut mesh_key = String::new();
            if mode == NETWORK_MESH {
                // etcd listens on the mesh address: the tunnel comes up with
                // this node alone, on the first node subnet, which the state
                // gives the first node below.
                ac.node_id = node_name.clone();
                ac.private_ip = ip_text.clone();
                ac.endpoint = ep_text.clone();
                ac.network = NETWORK_MESH.to_string();
                ac.cluster_cidr = cluster_text.clone();
                ac.mesh_cidr = mesh_text.clone();
                let k = armada_node::net::key::load_or_create(&dd.join(FILE_NETWORK_KEY))
                    .map_err(|e| format!("cluster network key: {e}"))?;
                mesh_key = k.public().to_string();
                let cfg = pb::NetworkConfig {
                    mode: NETWORK_MESH.to_string(),
                    cluster_cidr: cluster_text.clone(),
                    mesh_cidr: mesh_text.clone(),
                    peers: vec![pb::NetworkPeer {
                        node: node_name.clone(),
                        private_ip: ip_text.clone(),
                        subnet: first.clone(),
                        public_key: mesh_key.clone(),
                        endpoint: ep_text.clone(),
                        ..Default::default()
                    }],
                    ..Default::default()
                };
                machine::up_mesh(&data_dir, &ac, Some(cfg), &net_log).await?;
            }
            let member = state::start(&data_dir, store).await?;
            let st = Etcd::new(member.client.clone(), backup::ETCD_PREFIX)
                .await
                .map_err(|e| e.to_string())?;
            let e = |e: armada_store::Error| e.to_string();
            st.upsert_server(&Server {
                name: node_name.clone(),
                private_ip: ip_text.clone(),
                api_addr: listen.clone(),
                join_addr: String::new(),
                member_id: member.member_id,
                schema: 0,
                version: String::new(),
                created_at: armada_spec::gotime::Time::zero(),
                kv_peer_url: String::new(),
            })
            .await
            .map_err(e)?;
            st.set_meta(META_CLUSTER, &fingerprint).await.map_err(e)?;
            let keys = armada_secrets::load_key_file(&dd.join(FILE_MASTER_KEY))
                .map_err(|e| e.to_string())?;
            st.set_meta(META_MASTER_KEY, keys.id()).await.map_err(e)?;
            st.init_network(&Network {
                mode: net_mode.clone(),
                cluster_cidr: Some(cluster.clone()),
                isolate_default: false,
                mesh_cidr: mesh_prefix.clone(),
                switch: None,
            })
            .await
            .map_err(e)?;
            let mut me = Node {
                id: node_name.clone(),
                private_ip: ip_text.clone(),
                ..Default::default()
            };
            if mode == NETWORK_MESH {
                me.network_key = mesh_key;
                me.endpoint = ep_text.clone();
            }
            st.upsert_node(&me).await.map_err(e)?;
            let node = st.get_node(&node_name).await.map_err(e)?;
            rt.use_node_subnet(&mut ac, &node.subnet, &net_mode, Some(&ip))?;
            if mode == NETWORK_MESH && node.subnet != first {
                return Err(format!(
                    "the first node got subnet {}, not the one its tunnel came up with",
                    node.subnet
                ));
            }
            ac.node_id = node_name.clone();
            ac.private_ip = ip_text.clone();
            ac.servers = Some(vec![listen.clone()]);
            agentconfig::save(&data_dir, &ac)?;
            // The first user is on record with cluster-admin (ADR 0033), with
            // every certificate of its name accepted.
            st.know_user(&user_name).await.map_err(e)?;
            st.record_node_cert(
                &node_name,
                &NodeCert {
                    serial: node_cert.serial.clone(),
                    not_after: armada_store::gojson::from_unix(node_cert.not_after),
                },
                "",
            )
            .await
            .map_err(e)?;
            member.close().await;
            Ok::<_, String>((node, ac))
        })
        .map_err(msg)?;
    let _ = ac;

    let cc = clientconfig::Config {
        servers: vec![listen.clone()],
        ca: String::from_utf8_lossy(&ca.cert_pem).into_owned(),
        cert: String::from_utf8_lossy(&admin_cert).into_owned(),
        key: String::from_utf8_lossy(admin_key.expose()).into_owned(),
        ..Default::default()
    };
    let mut group_note = String::new();
    if config_path == SYSTEM_PATH {
        machine::save_shared(&cc, &config_path).map_err(msg)?;
        // The person reads it through the group: one file, which the
        // server renews. The cluster exists by now: a failure here only
        // warns.
        if let Some(p) = &person {
            match machine::join_admin_group(p) {
                Err(e) => {
                    let _ = writeln!(
                        ctx.err,
                        "warning: add {0} to the {1} group yourself (sudo usermod -aG {1} {0}): {e}",
                        p.name,
                        clientconfig::GROUP
                    );
                }
                Ok(true) => group_note = machine::admin_group_note(&p.name),
                Ok(false) => {}
            }
        }
    } else {
        cc.save(&config_path).map_err(msg)?;
    }

    let mut out = String::from("Cluster initialized.\n\n");
    out.push_str(&format!(
        "  node:        {node_name} ({ip}), containers {}\n",
        node.subnet
    ));
    out.push_str(&format!("  api:         {listen}\n"));
    out.push_str(&format!("  network:     {net_mode}, {cluster_text}\n"));
    if store == state::Store::Kv {
        out.push_str("  state:       armada-kv (ADR 0057)\n");
    }
    if mode == NETWORK_MESH {
        out.push_str(&format!(
            "  mesh:        {mesh_text} at {ip}, endpoint {ep_text} (open UDP {WIREGUARD_PORT} to every address)\n"
        ));
    }
    out.push_str(&format!(
        "  user:        {user_name}, cluster-admin ({config_path})\n"
    ));
    if !group_note.is_empty() {
        out.push_str(&format!("               {group_note}\n"));
    }
    out.push_str(&format!("  CA SHA-256:  {fingerprint}\n\n"));
    out.push_str(&next_step(store, &data_dir));
    out.push_str(&format!(
        "Back up {data_dir} with `armadad backup`: without it, secrets are lost.\n"
    ));
    ctx.print(&out);
    Ok(())
}

/// What to start after init or server join: the server, and on a cluster
/// on armada-kv its member's unit too (armada-server.service wants
/// armada-etcd.service, not armada-kv.service).
pub fn next_step(store: state::Store, data_dir: &str) -> String {
    if store == state::Store::Etcd {
        return machine::next_step("server", data_dir);
    }
    if data_dir == machine::DEFAULT_DATA_DIR {
        "Next: sudo systemctl enable --now armada-kv armada-server\n".to_string()
    } else {
        format!(
            "Next: armadad kv --data-dir {data_dir}, and beside it armadad server --data-dir {data_dir}\n"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_flag() {
        assert_eq!(state_store("etcd"), Ok(state::Store::Etcd));
        assert_eq!(state_store("kv"), Ok(state::Store::Kv));
        assert_eq!(
            state_store("redb").unwrap_err(),
            "invalid --state \"redb\": etcd or kv"
        );
        assert_eq!(
            next_step(state::Store::Kv, machine::DEFAULT_DATA_DIR),
            "Next: sudo systemctl enable --now armada-kv armada-server\n"
        );
        assert_eq!(
            next_step(state::Store::Etcd, machine::DEFAULT_DATA_DIR),
            machine::next_step("server", machine::DEFAULT_DATA_DIR)
        );
    }
}

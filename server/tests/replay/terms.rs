//! The control plane's terms (internal/server's TestArmadaServerTerms,
//! which needs no Go to compare with: it checks the Rust server alone):
//! armada-server-parity in election mode campaigns on the member, runs a
//! term on a store fenced on its key (migrating the keyspace first: here
//! one schema behind, which shows the migration ran),
//! runs the term's server again when the cluster's server settings
//! change, keeping the leadership, and resigns when it stops.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use armada_pki::{Ca, Identity, IssueRequest, SERVER_NAME};
use armada_store::{Client, Etcd, election};
use serde_json::{Value, json};

use super::grpc::{self, Item, Stream};
use super::methods::encode_request;
use super::program::{Cluster, Program};

const SET: &str = "/armada.v1.AdminService/SetClusterConfig";
const GET: &str = "/armada.v1.AdminService/GetClusterConfig";

async fn call(ch: &tonic::transport::Channel, path: &str, req: Value) -> Result<(), String> {
    let mut s = Stream::open(ch.clone(), path);
    s.send(encode_request(path, &req)?);
    s.close_send();
    match s.recv().await {
        Item::Msg(_) => Ok(()),
        Item::Err(st) => Err(st.message().to_string()),
        Item::Eof => Err("no answer".into()),
    }
}

/// Waits for the program's next event named name.
async fn wait(prog: &Program, name: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        match prog.event(Duration::from_secs(1)).await {
            Some(e) if e["event"] == "failed" => {
                return Err(format!("the program failed: {}", e["error"]));
            }
            Some(e) if e["event"] == name => return Ok(()),
            _ => {}
        }
    }
    Err(format!("no {name}"))
}

/// The terms' checks; an error says which failed.
pub async fn terms(client: Client, socket: &std::path::Path) -> Result<(), String> {
    let prefix = "/terms/";
    let st = Etcd::new(client.clone(), prefix)
        .await
        .map_err(|e| e.to_string())?;
    st.know_user("ryan").await.map_err(|e| e.to_string())?;
    // A keyspace one schema behind: opening a store writes the current
    // schema on a fresh one, so only a term's migration brings it up.
    client
        .put(
            &format!("{prefix}schema"),
            (armada_store::SCHEMA - 1).to_string().as_bytes(),
        )
        .await
        .map_err(|e| e.to_string())?;
    if st.stored_schema().await.map_err(|e| e.to_string())? != armada_store::SCHEMA - 1 {
        return Err("the keyspace is not one schema behind".into());
    }
    let ca = Ca::new("test").map_err(|e| e.to_string())?;
    let (server_cert, server_key) = ca
        .issue(&IssueRequest {
            identity: Identity::new("server", "cp-1"),
            dns_names: vec![SERVER_NAME.to_string()],
            ips: Vec::new(),
            server: true,
            client: false,
            validity: Duration::ZERO,
        })
        .map_err(|e| e.to_string())?;
    let api = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        l.local_addr().map_err(|e| e.to_string())?.to_string()
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default();
    let conf = json!({
        "etcdSocket": socket, "prefix": prefix, "elect": true, "leaseSeconds": 2,
        "caCert": String::from_utf8_lossy(&ca.cert_pem), "caKey": String::from_utf8_lossy(ca.key_pem().expose()),
        "serverCert": String::from_utf8_lossy(&server_cert),
        "serverKey": String::from_utf8_lossy(server_key.expose()),
        "name": "cp-1", "apiListen": api, "nowMs": now, "resyncMs": 3_600_000,
        "verbose": std::env::var_os("ARMADA_SERVER_VERBOSE").is_some(),
    });
    let mut prog = Program::start(&conf, Arc::new(Mutex::new(Cluster::new())), &[]).await?;
    wait(&prog, "leading").await?;
    let leader = election::leader(&client).await.map_err(|e| e.to_string())?;
    if leader != "cp-1" {
        return Err(format!("leader {leader:?}"));
    }
    let schema = st.stored_schema().await.map_err(|e| e.to_string())?;
    if schema != armada_store::SCHEMA {
        return Err(format!("schema {schema}: the term migrates the keyspace"));
    }
    let (cert, key) = ca
        .issue(&IssueRequest {
            identity: Identity::new("user", "ryan"),
            dns_names: Vec::new(),
            ips: Vec::new(),
            server: false,
            client: true,
            validity: Duration::ZERO,
        })
        .map_err(|e| e.to_string())?;
    let ch = grpc::channel(&api, grpc::tls(&ca.cert_pem, Some((&cert, key.expose())))?);
    call(
        &ch,
        SET,
        json!({"setNodeLostTimeout": true, "config": {"nodeLostTimeoutSeconds": 60}}),
    )
    .await
    .map_err(|e| format!("set the node-lost timeout: {e}"))?;
    // The settings changed: the term's server runs again, still leading.
    wait(&prog, "leading").await?;
    let leader = election::leader(&client).await.map_err(|e| e.to_string())?;
    if leader != "cp-1" {
        return Err(format!("leader after the restart {leader:?}"));
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match call(&ch, GET, json!({})).await {
            Ok(()) => break,
            Err(e) if Instant::now() > deadline => return Err(format!("GetClusterConfig: {e}")),
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    // Stopping resigns: the election is free at once, well before the
    // two-second lease would have run out.
    prog.stop();
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        if election::leader(&client)
            .await
            .map_err(|e| e.to_string())?
            .is_empty()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err("the leadership was not given up".into())
}

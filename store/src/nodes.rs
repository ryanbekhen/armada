//! Meta, nodes, join tokens, servers, node certificates, and the audit log
//! (etcd.go).

use std::collections::BTreeMap;

use armada_spec::gotime::Time;
use armada_spec::validate::{MAX_NODE_LABELS, check_label_value};

use crate::client::op;
use crate::error::{Error, Kind, Result, conflict, not_found, precondition};
use crate::gojson::{decode, from_ms, ms, unix_milli};
use crate::records::{AuditRec, CertRec, NodeRec, ReplicaRec, ServerRec, TokenRec, VolumeRec};
use crate::tx::*;
use crate::types::*;

/// auditKeep: how many audit events are retained.
const AUDIT_KEEP: i64 = 10_000;

/// nodeSeenEvery: how stale a node's stored LastSeen may get while nothing
/// else about it changes (milliseconds).
const NODE_SEEN_EVERY_MS: i64 = 30_000;

pub(crate) fn bad_token() -> Error {
    Error::wrap(
        Kind::NotFound,
        "join token is invalid, expired, or already used",
    )
}

/// labelString: "k=v,k2=v2", sorted by key.
pub(crate) fn label_string(labels: &BTreeMap<String, String>) -> String {
    labels
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// networkDetail: the audit detail of a node with a subnet.
pub(crate) fn network_detail(ip: &str, subnet: &str) -> String {
    let s = format!("{ip}, subnet {subnet}");
    s.strip_suffix(", subnet ").map(str::to_string).unwrap_or(s)
}

/// time.Format("2006-01-02T15:04Z") of t in UTC.
fn minute_utc(t: &Time) -> String {
    let c = t.in_loc(&armada_spec::gotime::Location::utc()).civil();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}Z",
        c.year, c.month, c.day, c.hour, c.minute
    )
}

impl Etx<'_> {
    pub(crate) async fn audit(
        &mut self,
        at: &Time,
        actor: &str,
        action: &str,
        target: &str,
        detail: &str,
    ) -> Result<()> {
        let seq = self.get::<i64>(KEY_AUDIT_SEQ).await?.unwrap_or(0) + 1;
        self.put(KEY_AUDIT_SEQ, &seq)?;
        if seq > AUDIT_KEEP && seq % 100 == 0 {
            // Drop the oldest events in batches, with one operation.
            self.delete_range(PFX_AUDIT, &format!("{PFX_AUDIT}{:020}", seq - AUDIT_KEEP));
        }
        self.put(
            &format!("{PFX_AUDIT}{seq:020}"),
            &AuditRec {
                id: seq,
                at: unix_milli(at),
                actor: actor.to_string(),
                action: action.to_string(),
                target: target.to_string(),
                detail: detail.to_string(),
            },
        )
    }

    pub(crate) async fn node(&self, id: &str) -> Result<Option<NodeRec>> {
        self.get(&format!("{PFX_NODES}{id}")).await
    }

    pub(crate) async fn to_node(&self, n: NodeRec) -> Result<Node> {
        let mut latest = 0;
        for (_, c) in self
            .list_into::<CertRec>(&format!("{PFX_CERTS}{}/", n.id))
            .await?
        {
            latest = latest.max(c.not_after);
        }
        Ok(Node {
            id: n.id,
            private_ip: n.private_ip,
            cpu_millis: n.cpu_millis,
            memory_bytes: n.memory_bytes,
            state: n.state,
            last_seen: from_ms(n.last_seen),
            created_at: from_ms(n.created_at),
            cordoned: n.cordoned,
            version: n.version,
            cert_not_after: from_ms(latest),
            labels: if n.labels.is_empty() {
                None
            } else {
                Some(n.labels)
            },
            os: n.os,
            arch: n.arch,
            restricted: n.restricted,
            jobs: n.jobs,
            volumes: n.volumes,
            containers: n.containers,
            nfs: n.nfs,
            subnet: n.subnet,
            network_key: n.network_key,
            endpoint: n.endpoint,
            site: n.site,
            mesh_address: n.mesh_address,
            behind_nat: n.behind_nat,
            relay: n.relay,
        })
    }

    async fn need_node(&self, id: &str) -> Result<NodeRec> {
        self.node(id).await?.ok_or_else(|| not_found!("node {id}"))
    }

    /// Whether another node than id holds key.
    async fn key_taken(&self, id: &str, key: &str) -> Result<bool> {
        Ok(self
            .list_into::<NodeRec>(PFX_NODES)
            .await?
            .iter()
            .any(|(_, r)| r.id != id && r.network_key == key))
    }

    pub(crate) async fn put_server(&mut self, srv: &Server, now: &Time) -> Result<()> {
        let k = format!("{PFX_SERVERS}{}", srv.name);
        let created = match self.get::<ServerRec>(&k).await? {
            Some(old) => old.created_at,
            None => unix_milli(now),
        };
        self.put(
            &k,
            &ServerRec {
                name: srv.name.clone(),
                private_ip: srv.private_ip.clone(),
                api_addr: srv.api_addr.clone(),
                join_addr: srv.join_addr.clone(),
                member_id: srv.member_id,
                schema: srv.schema,
                version: srv.version.clone(),
                created_at: created,
                kv_peer_url: srv.kv_peer_url.clone(),
            },
        )
    }

    pub(crate) fn put_cert(&mut self, node: &str, c: &NodeCert, now: &Time) -> Result<()> {
        self.put(
            &format!("{PFX_CERTS}{node}/{}", c.serial),
            &CertRec {
                serial: c.serial.clone(),
                node: node.to_string(),
                not_after: unix_milli(&c.not_after),
                created_at: unix_milli(now),
            },
        )
    }
}

impl Etcd {
    /// GetMeta returns a cluster-level setting.
    pub async fn get_meta(&self, key: &str) -> Result<String> {
        let mut v = String::new();
        view!(self, |t| {
            match t.get::<String>(&format!("{PFX_META}{key}")).await? {
                None => return Err(not_found!("meta {key}")),
                Some(s) => v = s,
            }
            Ok(())
        })?;
        Ok(v)
    }

    /// SetMeta stores a cluster-level setting.
    pub async fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        tx!(self, |t| { t.put(&format!("{PFX_META}{key}"), value) })
    }

    /// UpsertNode creates or replaces a node record. A new node gets a
    /// subnet when the cluster has a network (ADR 0025).
    pub async fn upsert_node(&self, n: &Node) -> Result<()> {
        let mut n = n.clone();
        if n.created_at.is_zero() {
            n.created_at = self.now();
        }
        if n.state.is_empty() {
            n.state = NODE_UNKNOWN.to_string();
        }
        let n = &n;
        tx!(self, |t| {
            let cur = t.node(&n.id).await?;
            let mut rec = NodeRec {
                id: n.id.clone(),
                private_ip: n.private_ip.clone(),
                cpu_millis: n.cpu_millis,
                memory_bytes: n.memory_bytes,
                state: n.state.clone(),
                last_seen: ms(&n.last_seen),
                created_at: ms(&n.created_at),
                ..Default::default()
            };
            match cur {
                Some(cur) => {
                    rec.created_at = cur.created_at;
                    rec.cordoned = cur.cordoned;
                    rec.legacy_certs = cur.legacy_certs;
                    rec.version = cur.version;
                    rec.labels = cur.labels;
                    rec.restricted = cur.restricted;
                    rec.os = cur.os;
                    rec.arch = cur.arch;
                    rec.subnet = cur.subnet;
                    rec.network_key = cur.network_key;
                    rec.endpoint = cur.endpoint;
                    rec.site = cur.site;
                    rec.mesh_address = cur.mesh_address;
                    rec.behind_nat = cur.behind_nat;
                    rec.relay = cur.relay;
                }
                None => {
                    rec.site = n.site.clone();
                    rec.mesh_address = n.mesh_address;
                    rec.behind_nat = n.behind_nat;
                    rec.subnet = t.new_node_network(&n.private_ip, n.mesh_address).await?;
                    rec.network_key = n.network_key.clone();
                    rec.endpoint = n.endpoint.clone();
                }
            }
            if let Some(l) = &n.labels {
                rec.labels = l.clone();
            }
            if !n.os.is_empty() || !n.arch.is_empty() {
                rec.os = n.os.clone();
                rec.arch = n.arch.clone();
            }
            rec.restricted = rec.restricted || n.restricted;
            t.put(&format!("{PFX_NODES}{}", n.id), &rec)
        })
    }

    /// GetNode returns one node.
    pub async fn get_node(&self, id: &str) -> Result<Node> {
        let mut out = None;
        view!(self, |t| {
            let n = t.need_node(id).await?;
            out = Some(t.to_node(n).await?);
            Ok(())
        })?;
        Ok(out.expect("set by the view"))
    }

    /// ListNodes returns all nodes ordered by ID.
    pub async fn list_nodes(&self) -> Result<Vec<Node>> {
        let mut out = Vec::new();
        view!(self, |t| {
            out.clear();
            for (_, n) in t.list_into::<NodeRec>(PFX_NODES).await? {
                out.push(t.to_node(n).await?);
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// SetNodeStatus updates runtime information for an existing node.
    pub async fn set_node_status(&self, id: &str, st: &NodeStatus) -> Result<()> {
        tx!(self, |t| {
            let mut n = t.need_node(id).await?;
            let before = n.clone();
            n.state = st.state.clone();
            n.last_seen = ms(&st.last_seen);
            n.cpu_millis = st.cpu_millis;
            n.memory_bytes = st.memory_bytes;
            n.jobs = st.jobs;
            n.volumes = st.volumes;
            n.containers = st.containers;
            n.nfs = st.nfs;
            if !st.version.is_empty() {
                n.version = st.version.clone();
            }
            if !st.os.is_empty() {
                n.os = st.os.clone();
            }
            if !st.arch.is_empty() {
                n.arch = st.arch.clone();
            }
            if !st.network_key.is_empty() && st.network_key != n.network_key {
                if t.key_taken(id, &st.network_key).await? {
                    return Err(conflict!(
                        "node {id}: network key already used by another node"
                    ));
                }
                n.network_key = st.network_key.clone();
            }
            if st.behind_nat {
                n.endpoint.clear();
                n.behind_nat = true;
                n.relay = false;
            } else if !st.endpoint.is_empty() {
                n.endpoint = st.endpoint.clone();
                n.behind_nat = false;
            }
            // A report that changes nothing but a recent LastSeen writes
            // nothing.
            let seen = n.last_seen - before.last_seen;
            if (0..NODE_SEEN_EVERY_MS).contains(&seen) {
                let mut same = before.clone();
                same.last_seen = n.last_seen;
                if same == n {
                    return Ok(());
                }
            }
            t.put(&format!("{PFX_NODES}{id}"), &n)
        })
    }

    /// SetNodeCordoned marks a node (un)schedulable.
    pub async fn set_node_cordoned(&self, id: &str, cordoned: bool, actor: &str) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            let mut n = t.need_node(id).await?;
            n.cordoned = cordoned;
            t.put(&format!("{PFX_NODES}{id}"), &n)?;
            let action = if cordoned {
                "node.cordon"
            } else {
                "node.uncordon"
            };
            t.audit(&now, actor, action, id, "").await
        })
    }

    /// SetNodeLabels sets and removes a node's admin labels and returns the
    /// result (None for no labels).
    pub async fn set_node_labels(
        &self,
        id: &str,
        set: &BTreeMap<String, String>,
        remove: &[String],
        actor: &str,
    ) -> Result<Option<BTreeMap<String, String>>> {
        let now = self.now();
        let mut out = None;
        tx!(self, |t| {
            let mut n = t.need_node(id).await?;
            let mut labels = n.labels.clone();
            for k in remove {
                labels.remove(k);
            }
            for (k, v) in set {
                labels.insert(k.clone(), v.clone());
            }
            if labels.len() > MAX_NODE_LABELS {
                return Err(precondition!(
                    "node {id} would have {} labels (at most {MAX_NODE_LABELS})",
                    labels.len()
                ));
            }
            out = if labels.is_empty() {
                None
            } else {
                Some(labels.clone())
            };
            let detail = label_string(&labels);
            n.labels = labels;
            t.put(&format!("{PFX_NODES}{id}"), &n)?;
            t.audit(&now, actor, "node.label", id, &detail).await
        })?;
        Ok(out)
    }

    /// SetNodeSite moves a node to another site (ADR 0050); "" is the first.
    pub async fn set_node_site(&self, id: &str, site: &str, actor: &str) -> Result<()> {
        if !site.is_empty() {
            check_label_value(site).map_err(|e| precondition!("site: {e}"))?;
        }
        let now = self.now();
        tx!(self, |t| {
            let mut n = t.need_node(id).await?;
            if n.site == site {
                return Ok(());
            }
            let net: crate::records::NetworkRec = t
                .get(crate::network::KEY_NETWORK)
                .await?
                .unwrap_or_default();
            if let Some(sw) = &net.switch {
                return Err(precondition!(
                    "the network is switching to {}; set sites once it is done",
                    sw.to
                ));
            }
            n.site = site.to_string();
            n.relay = false;
            t.put(&format!("{PFX_NODES}{id}"), &n)?;
            let detail = if site.is_empty() {
                "(first site)"
            } else {
                site
            };
            t.audit(&now, actor, "node.site", id, detail).await
        })
    }

    /// SetNodeRelay makes a node its site's chosen relay, or drops the
    /// choice (ADR 0050); it returns the nodes whose choice it replaced.
    pub async fn set_node_relay(&self, id: &str, on: bool, actor: &str) -> Result<Vec<String>> {
        let now = self.now();
        let mut replaced = Vec::new();
        tx!(self, |t| {
            replaced.clear();
            let n = t.need_node(id).await?;
            if on && n.behind_nat {
                return Err(precondition!(
                    "node {id} is behind NAT: a relay needs an endpoint"
                ));
            }
            let mut changed = false;
            for (_, mut r) in t.list_into::<NodeRec>(PFX_NODES).await? {
                let want = on && r.id == id;
                if r.site != n.site || r.relay == want {
                    continue;
                }
                if on && r.id != id {
                    replaced.push(r.id.clone());
                }
                r.relay = want;
                changed = true;
                t.put(&format!("{PFX_NODES}{}", r.id), &r)?;
            }
            if !changed {
                return Ok(());
            }
            let mut site = if n.site.is_empty() {
                "(first site)".to_string()
            } else {
                n.site.clone()
            };
            if on {
                if !replaced.is_empty() {
                    site += &format!(" in place of {}", replaced.join(", "));
                }
                return t.audit(&now, actor, "node.relay", id, &site).await;
            }
            t.audit(&now, actor, "node.relay.clear", id, &site).await
        })?;
        Ok(replaced)
    }

    /// SetNodeNetworkKey records a node's new network key after a rotation.
    pub async fn set_node_network_key(&self, id: &str, key: &str) -> Result<()> {
        tx!(self, |t| {
            let mut n = t.need_node(id).await?;
            if n.network_key == key {
                return Ok(());
            }
            if t.key_taken(id, key).await? {
                return Err(conflict!(
                    "node {id}: network key already used by another node"
                ));
            }
            n.network_key = key.to_string();
            t.put(&format!("{PFX_NODES}{id}"), &n)
        })
    }

    /// SetNodeRestricted makes a node restricted or open.
    pub async fn set_node_restricted(&self, id: &str, restricted: bool, actor: &str) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            let mut n = t.need_node(id).await?;
            n.restricted = restricted;
            t.put(&format!("{PFX_NODES}{id}"), &n)?;
            let action = if restricted {
                "node.restrict"
            } else {
                "node.open"
            };
            t.audit(&now, actor, action, id, "").await
        })
    }

    /// RemoveNode deletes a node and its certificates.
    pub async fn remove_node(&self, id: &str, force: bool, actor: &str) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            let mut on_node = Vec::new();
            for (k, r) in t.list_into::<ReplicaRec>(PFX_REPLICAS).await? {
                if r.node_id == id {
                    on_node.push(k);
                }
            }
            if !on_node.is_empty() && !force {
                return Err(precondition!(
                    "node {id} still runs {} replicas",
                    on_node.len()
                ));
            }
            let mut vols = Vec::new();
            for (_, v) in t.list_into::<VolumeRec>(PFX_VOLUMES).await? {
                if v.node == id {
                    vols.push(format!("{}/{}", v.app, v.name));
                }
            }
            if !vols.is_empty() && !force {
                return Err(precondition!(
                    "node {id} holds volumes {}; back them up and restore them on another node first, or remove the node with --force",
                    vols.join(", ")
                ));
            }
            t.need_node(id).await?;
            for k in &on_node {
                t.delete(k);
            }
            for (k, _) in t.list(&format!("{PFX_CERTS}{id}/")).await? {
                t.delete(&k);
            }
            t.delete(&format!("{PFX_NODES}{id}"));
            let detail = if on_node.is_empty() {
                String::new()
            } else {
                format!("forced, {} replicas deleted", on_node.len())
            };
            t.audit(&now, actor, "node.remove", id, &detail).await
        })
    }

    /// CreateJoinToken stores a join token.
    pub async fn create_join_token(&self, tok: &JoinToken) -> Result<()> {
        if !tok.site.is_empty() {
            check_label_value(&tok.site).map_err(|e| precondition!("site: {e}"))?;
        }
        let now = self.now();
        tx!(self, |t| {
            // Expired and used tokens are of no further use.
            for (k, r) in t.list_into::<TokenRec>(PFX_TOKENS).await? {
                if r.expires_at < unix_milli(&now) || r.used_at != 0 {
                    t.delete(&k);
                }
            }
            let key = format!("{PFX_TOKENS}{}", tok.id);
            if t.get_raw(&key).await?.is_some() {
                return Err(conflict!("join token {} exists", tok.id));
            }
            t.put(
                &key,
                &TokenRec {
                    id: tok.id.clone(),
                    secret_hash: tok.secret_hash.clone(),
                    expires_at: unix_milli(&tok.expires_at),
                    created_at: unix_milli(&now),
                    created_by: tok.created_by.clone(),
                    server: tok.server,
                    labels: tok.labels.clone(),
                    from: tok.from.clone(),
                    site: tok.site.clone(),
                    ..Default::default()
                },
            )?;
            let mut detail = format!("expires {}", minute_utc(&tok.expires_at));
            if tok.server {
                detail = format!("server, {detail}");
            }
            if !tok.labels.is_empty() {
                detail += &format!(", labels {}", label_string(&tok.labels));
            }
            if !tok.from.is_empty() {
                detail += &format!(", from {}", tok.from);
            }
            if !tok.site.is_empty() {
                detail += &format!(", site {}", tok.site);
            }
            t.audit(&now, &tok.created_by, "token.create", &tok.id, &detail)
                .await
        })
    }

    /// OpenJoinTokens returns the unused, unexpired tokens without their
    /// secret hashes.
    pub async fn open_join_tokens(&self) -> Result<Vec<JoinToken>> {
        let now = unix_milli(&self.now());
        let mut out = Vec::new();
        view!(self, |t| {
            out.clear();
            for (_, r) in t.list_into::<TokenRec>(PFX_TOKENS).await? {
                if r.used_at == 0 && r.expires_at > now {
                    out.push(JoinToken {
                        id: r.id,
                        secret_hash: String::new(),
                        expires_at: from_ms(r.expires_at),
                        created_at: from_ms(r.created_at),
                        created_by: r.created_by,
                        server: r.server,
                        labels: r.labels,
                        from: r.from,
                        site: r.site,
                    });
                }
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// RedeemJoinToken consumes token id for node n in one transaction.
    pub async fn redeem_join_token(
        &self,
        id: &str,
        check: &(dyn Fn(&str) -> bool + Sync),
        n: &Node,
        issue: &(dyn Fn() -> Result<NodeCert> + Sync),
    ) -> Result<()> {
        self.redeem(id, check, None, n, issue).await
    }

    /// RedeemServerToken is RedeemJoinToken for a server token.
    pub async fn redeem_server_token(
        &self,
        id: &str,
        check: &(dyn Fn(&str) -> bool + Sync),
        srv: &Server,
        n: &Node,
        issue: &(dyn Fn() -> Result<NodeCert> + Sync),
    ) -> Result<()> {
        self.redeem(id, check, Some(srv), n, issue).await
    }

    async fn redeem(
        &self,
        id: &str,
        check: &(dyn Fn(&str) -> bool + Sync),
        srv: Option<&Server>,
        n: &Node,
        issue: &(dyn Fn() -> Result<NodeCert> + Sync),
    ) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            let key = format!("{PFX_TOKENS}{id}");
            let tok = t.get::<TokenRec>(&key).await?;
            // The secret first, so a guessed ID alone reveals nothing.
            let Some(mut tok) = tok else {
                return Err(bad_token());
            };
            if !check(&tok.secret_hash)
                || tok.used_at != 0
                || unix_milli(&now) >= tok.expires_at
                || tok.server != srv.is_some()
            {
                return Err(bad_token());
            }
            if t.node(&n.id).await?.is_some() {
                return Err(conflict!(
                    "node {} already exists; remove it first or pick another name",
                    n.id
                ));
            }
            let (mut taken, mut key_taken) = (false, false);
            for (_, other) in t.list_into::<NodeRec>(PFX_NODES).await? {
                taken = taken || other.private_ip == n.private_ip;
                key_taken =
                    key_taken || (!n.network_key.is_empty() && other.network_key == n.network_key);
            }
            if taken {
                return Err(conflict!(
                    "private IP {} is already used by another node",
                    n.private_ip
                ));
            }
            if key_taken {
                return Err(conflict!("the network key is already used by another node"));
            }
            let subnet = t.new_node_network(&n.private_ip, n.mesh_address).await?;
            if let Some(srv) = srv {
                if t.get_raw(&format!("{PFX_SERVERS}{}", srv.name))
                    .await?
                    .is_some()
                {
                    return Err(conflict!("server {} already exists", srv.name));
                }
                t.put_server(srv, &now).await?;
            }
            tok.used_at = unix_milli(&now);
            tok.used_by = n.id.clone();
            t.put(&key, &tok)?;
            let cert = issue()?;
            let state = if n.state.is_empty() {
                NODE_UNKNOWN.to_string()
            } else {
                n.state.clone()
            };
            t.put(
                &format!("{PFX_NODES}{}", n.id),
                &NodeRec {
                    id: n.id.clone(),
                    private_ip: n.private_ip.clone(),
                    state,
                    created_at: unix_milli(&now),
                    labels: tok.labels.clone(),
                    subnet: subnet.clone(),
                    network_key: n.network_key.clone(),
                    endpoint: n.endpoint.clone(),
                    site: tok.site.clone(),
                    mesh_address: n.mesh_address,
                    behind_nat: n.behind_nat,
                    ..Default::default()
                },
            )?;
            t.put_cert(&n.id, &cert, &now)?;
            let action = if srv.is_some() {
                "server.join"
            } else {
                "node.join"
            };
            t.audit(
                &now,
                &format!("token:{id}"),
                action,
                &n.id,
                &network_detail(&n.private_ip, &subnet),
            )
            .await
        })
    }

    /// UpsertServer records a control plane node.
    pub async fn upsert_server(&self, srv: &Server) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            if let Some(old) = t
                .get::<ServerRec>(&format!("{PFX_SERVERS}{}", srv.name))
                .await?
                && old.private_ip == srv.private_ip
                && old.api_addr == srv.api_addr
                && old.join_addr == srv.join_addr
                && old.member_id == srv.member_id
                && old.schema == srv.schema
                && old.version == srv.version
                && old.kv_peer_url == srv.kv_peer_url
            {
                return Ok(());
            }
            t.put_server(srv, &now).await
        })
    }

    /// ListServers lists the control plane nodes, sorted by name.
    pub async fn list_servers(&self) -> Result<Vec<Server>> {
        let mut out = Vec::new();
        view!(self, |t| {
            out.clear();
            for (_, r) in t.list_into::<ServerRec>(PFX_SERVERS).await? {
                out.push(Server {
                    name: r.name,
                    private_ip: r.private_ip,
                    api_addr: r.api_addr,
                    join_addr: r.join_addr,
                    member_id: r.member_id,
                    schema: r.schema.max(1),
                    version: r.version,
                    created_at: from_ms(r.created_at),
                    kv_peer_url: r.kv_peer_url,
                });
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// RemoveServer deletes a control plane node's record.
    pub async fn remove_server(&self, name: &str, actor: &str) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            let k = format!("{PFX_SERVERS}{name}");
            if t.get_raw(&k).await?.is_none() {
                return Err(not_found!("server {name}"));
            }
            t.delete(&k);
            t.audit(&now, actor, "server.remove", name, "").await
        })
    }

    /// RecordNodeCert records a certificate issued to an existing node and
    /// prunes expired ones; a non-empty keep revokes every other one.
    pub async fn record_node_cert(&self, node: &str, c: &NodeCert, keep: &str) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            let mut n = t.need_node(node).await?;
            if n.legacy_certs {
                n.legacy_certs = false;
                t.put(&format!("{PFX_NODES}{node}"), &n)?;
            }
            for (k, rec) in t
                .list_into::<CertRec>(&format!("{PFX_CERTS}{node}/"))
                .await?
            {
                if rec.not_after < unix_milli(&now) || (!keep.is_empty() && rec.serial != keep) {
                    t.delete(&k);
                }
            }
            t.put_cert(node, c, &now)
        })
    }

    /// NodeCertAllowed reports whether serial is a valid certificate of an
    /// existing node.
    pub async fn node_cert_allowed(&self, node: &str, serial: &str) -> Result<bool> {
        let mut allowed = false;
        view!(self, |t| {
            allowed = false;
            let Some(n) = t.node(node).await? else {
                return Ok(());
            };
            if n.legacy_certs {
                allowed = true;
                return Ok(());
            }
            let c = t
                .get::<CertRec>(&format!("{PFX_CERTS}{node}/{serial}"))
                .await?;
            allowed = c.is_some_and(|c| c.not_after > unix_milli(&self.now()));
            Ok(())
        })?;
        Ok(allowed)
    }

    /// setLegacyCerts marks every node as accepting legacy certificates
    /// (tests model nodes created before certificates were recorded).
    pub async fn set_legacy_certs(&self) -> Result<()> {
        tx!(self, |t| {
            for (k, mut n) in t.list_into::<NodeRec>(PFX_NODES).await? {
                n.legacy_certs = true;
                t.put(&k, &n)?;
            }
            Ok(())
        })
    }

    /// RecordAudit logs a change that has no transaction of its own.
    pub async fn record_audit(
        &self,
        actor: &str,
        action: &str,
        target: &str,
        detail: &str,
    ) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            t.audit(&now, actor, action, target, detail).await
        })
    }

    /// ListAudit returns the newest audit events first.
    pub async fn list_audit(&self, limit: i64) -> Result<Vec<AuditEvent>> {
        let limit = if limit <= 0 { 100 } else { limit };
        let mut r = op::get_prefix(&format!("{}{PFX_AUDIT}", self.prefix), 0);
        r.sort_order = armada_proto::etcd::etcdserverpb::range_request::SortOrder::Descend as i32;
        r.sort_target = armada_proto::etcd::etcdserverpb::range_request::SortTarget::Key as i32;
        r.limit = limit;
        let resp = self.c.range(r).await?;
        let mut out = Vec::with_capacity(resp.kvs.len());
        for kv in resp.kvs {
            let a: AuditRec = decode(&String::from_utf8_lossy(&kv.key), &kv.value)?;
            out.push(AuditEvent {
                id: a.id,
                at: from_ms(a.at),
                actor: a.actor,
                action: a.action,
                target: a.target,
                detail: a.detail,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn details() {
        let mut l = BTreeMap::new();
        l.insert("zone".to_string(), "a".to_string());
        l.insert("disk".to_string(), "ssd".to_string());
        assert_eq!(label_string(&l), "disk=ssd,zone=a");
        assert_eq!(network_detail("10.0.0.1", ""), "10.0.0.1");
        assert_eq!(
            network_detail("10.0.0.1", "10.120.0.0/24"),
            "10.0.0.1, subnet 10.120.0.0/24"
        );
        let t = Time {
            unix: 1_772_359_200,
            nsec: 5,
            loc: armada_spec::gotime::Location::utc(),
        };
        assert_eq!(minute_utc(&t), "2026-03-01T10:00Z");
        assert_eq!(
            bad_token().to_string(),
            "join token is invalid, expired, or already used: not found"
        );
    }
}

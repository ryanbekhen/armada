//! armada cluster and armada domain.

use armada_proto::armada::v1::{
    BackupKeep, ClusterConfig, ClusterStatusRequest, ClusterStatusResponse,
    ControlPlaneBackupStatus, Domain, GetClusterConfigRequest, ListDomainsRequest, NodeSwitchWait,
    SetClusterConfigRequest, VerifyDomainRequest,
};
use armada_spec as spec;
use armada_spec::go;

use super::{
    Output, dash, date_time, disk_bytes, human_bytes, human_duration, output_flag, print_json,
    read_token_arg, rpc_err, unix_ts,
};
use crate::cli::flags::Flag;
use crate::cli::tabwriter::TabWriter;
use crate::cli::{Args, Ctx, Error, Node, Result, Tree};
use crate::rpc;
use crate::rpc::printable;

const UPDATE_LONG: &str =
    "Change cluster settings. They are kept in the cluster's state, so every server
uses them, also after another one takes over as leader (ADR 0031).

With --root-domain, every app with external ingress is reachable at
https://<app>.<root-domain>. Point a wildcard DNS record (*.<root-domain>)
at your nodes first.

With --trusted-proxies, requests from these prefixes keep the client address
headers they carry (X-Forwarded-For, CF-Connecting-IP, and the like). Every
other request loses them, so a client cannot claim another address. The
cluster's container addresses are never trusted, even inside a listed range.

With --proxy-protocol, connections from these prefixes (TCP load balancers
that hide the client's address) must start with a PROXY protocol header,
whose client address then counts as the connection's own. Connections from
anywhere else must not send one. Container addresses are never listed.

Certificates, the DNS provider and its token, the metrics port, and the
node-lost timeout apply within seconds: the leader restarts its control plane
with them while apps keep serving; the command waits until it answers again.
The token is read from a file or stdin (--dns-token -), stored encrypted, and
never shown.

--log-retention and --log-max-disk bound the log history every node keeps for
`armada app logs --since` (ADR 0043); 0 restores the default (7 days; 10% of
the disk, at most 5Gi). They apply without a restart.

--log-export loki|otlp with --log-endpoint sends every app's output from every
node to that push URL as well (ADR 0044), from now on; none stops it.
--log-token - reads a token from stdin, stored encrypted: a bearer token, or
the password of --log-export-user. --log-export-tenant sets Loki's tenant.

--network wireguard (or plain) switches the cluster network's mode while
everything runs (ADR 0050): every node brings the new transport up beside the
current one, routes move once every node reaches every other over it, and the
old one goes. armada cluster status shows how far it is and which nodes it
waits for. Naming the current mode before the routes move gives the switch up.

--mesh-cidr sets the range machines with no private network take their
addresses from when they join from another site (ADR 0050; default
10.122.0.0/16), before the first of them joins. It must not hold any node's
address.

--backup-url and --backup-key turn on backups of the control plane to an
S3-compatible bucket (ADR 0051), taken by the leader --backup-every D (5m to
168h) or on --backup-schedule CRON in --backup-time-zone, deduplicated and
encrypted with the key, keeping what --backup-keep says: a number of the
latest, or last=N,hourly=N,daily=N,weekly=N,monthly=N. Both read a file (mode
0600) or stdin (-, one of them): the URL is https://KEY:SECRET@host/bucket[/prefix]
and the key at least 32 bytes. They are stored encrypted and never shown. The
first backup runs at once; armada cluster status shows the last one.
--backup none turns them off; the bucket keeps what it holds.";

pub fn add_cluster(t: &mut Tree) -> usize {
    let n = t.add(
        0,
        Node::new("cluster", "The cluster's status, settings, and events").noun(),
    );
    t.add(
        n,
        Node::new("status", "Summarize the cluster: nodes, apps, and what needs attention")
            .long("Summarize the cluster in one line, then list the apps that are not ready\n(at most 20) and the nodes that are not ready, if any.")
            .args(Args::No)
            .example("  armada cluster status       # nodes, apps, and what needs attention\n  armada cluster status -o json")
            .flag(output_flag(false))
            .run(status),
    );
    t.add(
        n,
        Node::new("show", "Show cluster settings")
            .args(Args::No)
            .example("  armada cluster show")
            .flag(output_flag(false))
            .run(show),
    );
    t.add(
        n,
        Node::new("update", "Change cluster settings, for every server at once")
            .long(UPDATE_LONG)
            .args(Args::No)
            .example("  armada cluster update --root-domain apps.example.com\n  armada cluster update --acme-email ops@example.com\n  armada cluster update --trusted-proxies 173.245.48.0/20,103.21.244.0/22\n  armada cluster update --log-retention 336h --log-max-disk 2Gi")
            .flags(update_flags())
            .run(update),
    );
    t.add(n, super::streams::events_node(true));
    n
}

fn update_flags() -> Vec<Flag> {
    vec![
        Flag::string(
            "root-domain",
            None,
            "",
            "root domain for app URLs (empty to clear)",
        ),
        Flag::string_slice(
            "trusted-proxies",
            None,
            "address prefixes of proxies in front of the nodes, comma separated (empty to clear)",
        ),
        Flag::string_slice(
            "proxy-protocol",
            None,
            "address prefixes of TCP load balancers in front of the nodes that send the PROXY protocol, comma separated (empty to clear)",
        ),
        Flag::bool(
            "tls",
            None,
            true,
            "obtain and renew certificates with ACME; false serves apps over plain HTTP on port 80 instead of redirecting to HTTPS",
        ),
        Flag::string("acme-email", None, "", "contact email for the ACME account"),
        Flag::string(
            "acme-ca",
            None,
            "",
            "ACME directory: letsencrypt, letsencrypt-staging, or an https:// URL",
        ),
        Flag::string(
            "dns-provider",
            None,
            "",
            "DNS provider for the root domain and the names under it, including a wildcard: cloudflare, or none",
        ),
        Flag::string(
            "dns-token",
            None,
            "",
            "file holding the DNS provider's API token, or - for stdin; an empty file removes it",
        ),
        Flag::int(
            "metrics-port",
            None,
            0,
            "port of the Prometheus metrics endpoint on each server's private address; 0 turns it off",
        ),
        Flag::duration(
            "node-lost-timeout",
            None,
            0,
            "how long a node may be unreachable before its replicas move to other nodes",
        ),
        Flag::duration(
            "log-retention",
            None,
            0,
            "how long each node keeps log history, e.g. 168h (0 for the default, 7 days)",
        ),
        Flag::string(
            "log-max-disk",
            None,
            "",
            "log history each node keeps at most, e.g. 5Gi (0 for the default: 10% of the disk, at most 5Gi)",
        ),
        Flag::string(
            "log-export",
            None,
            "",
            "send every app's output to a log store as well: loki, otlp, or none",
        ),
        Flag::string(
            "log-endpoint",
            None,
            "",
            "push URL of the log store, e.g. https://logs.example.com/loki/api/v1/push or https://otlp.example.com/v1/logs",
        ),
        Flag::string(
            "log-export-user",
            None,
            "",
            "user for basic authentication at the log store, with --log-token as the password (empty for a bearer token)",
        ),
        Flag::string(
            "log-export-tenant",
            None,
            "",
            "Loki tenant (X-Scope-OrgID), for a multi-tenant Loki",
        ),
        Flag::string(
            "log-token",
            None,
            "",
            "file holding the log store's token, or - for stdin; an empty file removes it",
        ),
        Flag::string(
            "network",
            None,
            "",
            "switch the cluster network's mode while it runs: plain or wireguard",
        ),
        Flag::string(
            "mesh-cidr",
            None,
            "",
            "private IPv4 range of the addresses machines with no private network get, before the first joins (/8 to /24)",
        ),
        Flag::duration(
            "backup-every",
            None,
            0,
            "back the control plane up this often, e.g. 1h (5m to 168h)",
        ),
        Flag::string(
            "backup-schedule",
            None,
            "",
            "back the control plane up on this cron schedule (five fields), instead of --backup-every",
        ),
        Flag::string(
            "backup-time-zone",
            None,
            "",
            "time zone of --backup-schedule and of the hours, days, weeks, and months --backup-keep counts (default UTC)",
        ),
        Flag::string(
            "backup-keep",
            None,
            "",
            "control plane backups to keep: a number of the latest, or last=N,hourly=N,daily=N,weekly=N,monthly=N",
        ),
        Flag::string(
            "backup-url",
            None,
            "",
            "file holding the bucket URL for control plane backups (https://KEY:SECRET@host/bucket[/prefix]), or - for stdin",
        ),
        Flag::string(
            "backup-key",
            None,
            "",
            "file holding the key control plane backups are encrypted with (at least 32 bytes), or - for stdin",
        ),
        Flag::string("backup", None, "", "none turns control plane backups off"),
    ]
}

/// The flags whose change restarts the leader's
/// control plane (ADR 0031).
const RESTARTING_SETTINGS: [&str; 7] = [
    "tls",
    "acme-email",
    "acme-ca",
    "dns-provider",
    "dns-token",
    "metrics-port",
    "node-lost-timeout",
];
const LOG_EXPORT_FLAGS: [&str; 4] = [
    "log-export",
    "log-endpoint",
    "log-export-user",
    "log-export-tenant",
];
const BACKUP_PLAN_FLAGS: [&str; 3] = ["backup-every", "backup-schedule", "backup-time-zone"];
const OTHER_FLAGS: [&str; 19] = [
    "root-domain",
    "trusted-proxies",
    "proxy-protocol",
    "tls",
    "acme-email",
    "acme-ca",
    "dns-provider",
    "dns-token",
    "metrics-port",
    "node-lost-timeout",
    "log-retention",
    "log-max-disk",
    "log-token",
    "network",
    "mesh-cidr",
    "backup",
    "backup-keep",
    "backup-url",
    "backup-key",
];

/// settingsSettle and settingsWait: how long cluster update waits before
/// asking whether the API is back, and at most.
const SETTINGS_SETTLE: std::time::Duration = std::time::Duration::from_secs(1);
const SETTINGS_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

fn update(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let ch = |name: &str| ctx.changed(name);
    let mut req = SetClusterConfigRequest {
        config: Some(ClusterConfig {
            root_domain: ctx.str("root-domain"),
            trusted_proxies: ctx.strs("trusted-proxies"),
            proxy_protocol: ctx.strs("proxy-protocol"),
            tls: ctx.bool("tls"),
            acme_email: ctx.str("acme-email"),
            acme_ca: ctx.str("acme-ca"),
            dns_provider: ctx.str("dns-provider"),
            metrics_port: ctx.int("metrics-port") as i32,
            node_lost_timeout_seconds: ctx.duration("node-lost-timeout") / go::SECOND,
            network: ctx.str("network"),
            mesh_cidr: ctx.str("mesh-cidr"),
            ..Default::default()
        }),
        set_root_domain: ch("root-domain"),
        set_trusted_proxies: ch("trusted-proxies"),
        set_proxy_protocol: ch("proxy-protocol"),
        set_tls: ch("tls"),
        set_acme_email: ch("acme-email"),
        set_acme_ca: ch("acme-ca"),
        set_dns_provider: ch("dns-provider"),
        set_metrics_port: ch("metrics-port"),
        set_node_lost_timeout: ch("node-lost-timeout"),
        set_dns_token: ch("dns-token"),
        set_log_retention: ch("log-retention"),
        set_log_max_bytes: ch("log-max-disk"),
        set_log_export: LOG_EXPORT_FLAGS.iter().any(|f| ch(f)),
        set_log_token: ch("log-token"),
        set_network: ch("network"),
        set_mesh_cidr: ch("mesh-cidr"),
        set_backup_plan: BACKUP_PLAN_FLAGS.iter().any(|f| ch(f)),
        set_backup_keep: ch("backup-keep"),
        set_backup_url: ch("backup-url"),
        set_backup_key: ch("backup-key"),
        set_backup_off: ch("backup"),
        ..Default::default()
    };
    if !OTHER_FLAGS.iter().any(|f| ch(f)) && !req.set_log_export && !req.set_backup_plan {
        return Err("nothing to change; see armada cluster update --help".into());
    }
    let log_max_disk = ctx.str("log-max-disk");
    {
        let c = req.config.as_mut().expect("config");
        c.log_retention_seconds = ctx.duration("log-retention") / go::SECOND;
        if ctx.changed("log-max-disk") && log_max_disk != "0" {
            c.log_max_bytes = spec::validate::parse_memory(&log_max_disk)
                .map_err(|e| Error::Msg(format!("--log-max-disk: {e}")))?;
        }
    }
    if ctx.changed("dns-token") {
        // Never from an argument: shell history keeps those.
        let arg = ctx.str("dns-token");
        req.dns_token = read_token_arg(ctx, "--dns-token", &arg)?;
    }
    if ctx.changed("log-token") {
        let arg = ctx.str("log-token");
        req.log_token = read_token_arg(ctx, "--log-token", &arg)?;
    }
    backup_request(ctx, &mut req)?;
    let mut admin = ctx.admin()?;
    if req.set_log_export {
        // The four go together: keep the ones not given.
        let cur =
            rpc!(ctx, admin, get_cluster_config, GetClusterConfigRequest {}).map_err(rpc_err)?;
        let pick = |flag: &str, old: &str| {
            if ctx.changed(flag) {
                ctx.str(flag)
            } else {
                old.to_string()
            }
        };
        let (a, b, c, d) = (
            pick("log-export", &cur.log_export),
            pick("log-endpoint", &cur.log_endpoint),
            pick("log-export-user", &cur.log_export_user),
            pick("log-export-tenant", &cur.log_export_tenant),
        );
        let cfg = req.config.as_mut().expect("config");
        (
            cfg.log_export,
            cfg.log_endpoint,
            cfg.log_export_user,
            cfg.log_export_tenant,
        ) = (a, b, c, d);
    }
    if req.set_backup_plan {
        // Every, schedule, and time zone go together: keep the ones not
        // given.
        let cur =
            rpc!(ctx, admin, get_cluster_config, GetClusterConfigRequest {}).map_err(rpc_err)?;
        let every = ctx.duration("backup-every");
        let schedule = ctx.str("backup-schedule");
        let tz = ctx.str("backup-time-zone");
        let (ch_every, ch_schedule, ch_tz) = (
            ctx.changed("backup-every"),
            ctx.changed("backup-schedule"),
            ctx.changed("backup-time-zone"),
        );
        let cfg = req.config.as_mut().expect("config");
        if ch_every {
            cfg.backup_every_seconds = every / go::SECOND;
        } else if ch_schedule {
            cfg.backup_schedule = schedule;
        } else {
            cfg.backup_every_seconds = cur.backup_every_seconds;
            cfg.backup_schedule = cur.backup_schedule.clone();
        }
        cfg.backup_time_zone = if ch_tz { tz } else { cur.backup_time_zone };
    }
    let cc = rpc!(ctx, admin, set_cluster_config, req).map_err(rpc_err)?;
    if RESTARTING_SETTINGS.iter().any(|f| ctx.changed(f)) {
        // The leader restarts its control plane with them right after
        // answering; the next command would find no API.
        wait_for_api(ctx, &mut admin)?;
    }
    let text = cluster_config_text(&cc);
    ctx.print(&text);
    Ok(())
}

/// Until the control plane answers again after a change of
/// its settings.
fn wait_for_api(ctx: &mut Ctx<'_>, admin: &mut crate::rpc::Admin) -> Result {
    let deadline = std::time::Instant::now() + SETTINGS_WAIT;
    let mut wait = SETTINGS_SETTLE;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() || wait > left {
            if !left.is_zero() {
                std::thread::sleep(left);
            }
            return Err(Error::Msg(format!(
                "the settings are saved, but the control plane did not answer within {} after applying them; see armada cluster status",
                go::format_duration(SETTINGS_WAIT.as_nanos() as i64)
            )));
        }
        std::thread::sleep(wait);
        let limit = std::time::Duration::from_secs(3)
            .min(deadline.saturating_duration_since(std::time::Instant::now()));
        let ok = ctx.block_on(async {
            tokio::time::timeout(
                limit,
                admin.call(|mut c| async move {
                    c.get_cluster_config(GetClusterConfigRequest {}).await
                }),
            )
            .await
        });
        if matches!(ok, Ok(Ok(_))) {
            return Ok(());
        }
        wait = std::time::Duration::from_millis(500);
    }
}

/// The backup flags checked, and the keep policy, URL, and
/// key put in the request.
fn backup_request(ctx: &mut Ctx<'_>, req: &mut SetClusterConfigRequest) -> Result {
    if ctx.changed("backup") && ctx.str("backup") != "none" {
        return Err("--backup takes only none, which turns control plane backups off".into());
    }
    if ctx.changed("backup-every") && ctx.changed("backup-schedule") {
        return Err("give --backup-every or --backup-schedule, not both".into());
    }
    let (url, key) = (ctx.str("backup-url"), ctx.str("backup-key"));
    if ctx.changed("backup-url") && ctx.changed("backup-key") && url == "-" && key == "-" {
        return Err("only one of --backup-url and --backup-key can read stdin".into());
    }
    if ctx.changed("backup-keep") {
        let k = parse_backup_keep(&ctx.str("backup-keep"))?;
        req.config.as_mut().expect("config").backup_keep = Some(k);
    }
    if ctx.changed("backup-url") {
        // Never from an argument: the URL holds the bucket's keys.
        req.backup_url = read_token_arg(ctx, "--backup-url", &url)?;
    }
    if ctx.changed("backup-key") {
        req.backup_key = read_token_arg(ctx, "--backup-key", &key)?;
    }
    Ok(())
}

/// A decimal 32-bit integer with an optional sign.
fn parse_i32(s: &str) -> Option<i32> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse::<i32>().ok()
}

/// a number of the latest, or
/// last=N,hourly=N,daily=N,weekly=N,monthly=N.
fn parse_backup_keep(s: &str) -> Result<BackupKeep> {
    let s = go::trim_space(s);
    if let Some(n) = parse_i32(s) {
        return Ok(BackupKeep {
            last: n,
            ..Default::default()
        });
    }
    let mut k = BackupKeep::default();
    for part in s.split(',') {
        let part = go::trim_space(part);
        let (name, v) = part.split_once('=').unwrap_or((part, ""));
        let n = match (part.contains('='), parse_i32(v)) {
            (true, Some(n)) => n,
            _ => {
                return Err(Error::Msg(format!(
                    "--backup-keep {}: want a number, or last=N,hourly=N,daily=N,weekly=N,monthly=N",
                    go::quote(s)
                )));
            }
        };
        match name {
            "last" => k.last = n,
            "hourly" => k.hourly = n,
            "daily" => k.daily = n,
            "weekly" => k.weekly = n,
            "monthly" => k.monthly = n,
            _ => {
                return Err(Error::Msg(format!(
                    "--backup-keep: unknown {} (want last, hourly, daily, weekly, or monthly)",
                    go::quote(name)
                )));
            }
        }
    }
    Ok(k)
}

/// What a keep policy keeps.
fn keep_text(k: Option<&BackupKeep>) -> String {
    let d = BackupKeep::default();
    let k = k.unwrap_or(&d);
    let parts: Vec<String> = [
        (k.last, "latest"),
        (k.hourly, "hourly"),
        (k.daily, "daily"),
        (k.weekly, "weekly"),
        (k.monthly, "monthly"),
    ]
    .iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, what)| format!("{n} {what}"))
    .collect();
    if parts.is_empty() {
        return "-".to_string();
    }
    parts.join(", ")
}

/// When the control plane is backed up.
fn backup_when(cc: &ClusterConfig) -> String {
    let mut when = format!(
        "every {}",
        human_duration(cc.backup_every_seconds.wrapping_mul(go::SECOND))
    );
    if !cc.backup_schedule.is_empty() {
        when = format!("on {}", cc.backup_schedule);
    }
    if !cc.backup_time_zone.is_empty() {
        when.push_str(&format!(" ({})", cc.backup_time_zone));
    }
    when
}

/// How the control plane's backups go.
fn backup_status_line(b: &ControlPlaneBackupStatus) -> String {
    let mut line = format!("backups: to {}", b.bucket);
    if let Some(t) = &b.last_at {
        line.push_str(&format!(
            ", last {} on {} ({}, {} kept, {} stored)",
            date_time(Some(t)),
            dash(&b.last_server),
            disk_bytes(b.last_size_bytes),
            b.snapshots,
            disk_bytes(b.stored_bytes)
        ));
    } else {
        line.push_str(", none yet");
    }
    if let Some(t) = &b.next_at {
        line.push_str(&format!(", next {}", date_time(Some(t))));
    }
    if !b.error.is_empty() {
        line.push_str(&format!(
            "\nbackup failed at {}: {}",
            date_time(b.failed_at.as_ref()),
            printable(&b.error)
        ));
    }
    line
}

fn show(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let mut admin = ctx.admin()?;
    let cc = rpc!(ctx, admin, get_cluster_config, GetClusterConfigRequest {}).map_err(rpc_err)?;
    if o.json() {
        return print_json(ctx, &cc);
    }
    let text = cluster_config_text(&cc);
    ctx.print(&text);
    Ok(())
}

/// printClusterConfig.
fn cluster_config_text(cc: &ClusterConfig) -> String {
    let metrics = if cc.metrics_port > 0 {
        format!("port {} on each server's private address", cc.metrics_port)
    } else {
        "off".to_string()
    };
    let token = if cc.dns_token_set { "set" } else { "not set" };
    let certs = if cc.tls {
        format!("on, {}", dash(&cc.acme_ca))
    } else {
        "off".to_string()
    };
    let mut logs = "7 days (default)".to_string();
    if cc.log_retention_seconds > 0 {
        logs = human_duration(cc.log_retention_seconds.wrapping_mul(go::SECOND));
    }
    if cc.log_max_bytes > 0 {
        logs.push_str(&format!(
            ", at most {} per node",
            human_bytes(cc.log_max_bytes)
        ));
    } else {
        logs.push_str(", at most 10% of the disk (5Gi) per node");
    }
    let mut export = "none".to_string();
    if !cc.log_export.is_empty() {
        export = format!("{} to {}", cc.log_export, cc.log_endpoint);
        if !cc.log_export_user.is_empty() {
            export.push_str(&format!(", user {}", cc.log_export_user));
        }
        if !cc.log_export_tenant.is_empty() {
            export.push_str(&format!(", tenant {}", cc.log_export_tenant));
        }
        export.push_str(if cc.log_token_set {
            " (token set)"
        } else {
            " (no token)"
        });
    }
    let mut backups = "off".to_string();
    if !cc.backup_bucket.is_empty() {
        backups = format!(
            "to {}, {}, keeping {}",
            cc.backup_bucket,
            backup_when(cc),
            keep_text(cc.backup_keep.as_ref())
        );
    }
    let mut network = if cc.network.is_empty() {
        "none".to_string()
    } else {
        cc.network.clone()
    };
    if !cc.network_switch_to.is_empty() {
        network.push_str(&format!(
            ", switching to {} (armada cluster status)",
            cc.network_switch_to
        ));
    }
    if !cc.mesh_cidr.is_empty() {
        network.push_str(&format!(", mesh addresses from {}", cc.mesh_cidr));
    }
    let provider = if cc.dns_provider.is_empty() {
        "none"
    } else {
        cc.dns_provider.as_str()
    };
    format!(
        "root domain:       {}\ntrusted proxies:   {}\nproxy protocol:    {}\ncertificates:      {}\nacme email:        {}\ndns provider:      {} (token {})\nmetrics:           {}\nnode lost timeout: {}\nlog history:       {}\nlog export:        {}\nnetwork:           {}\nbackups:           {}\n",
        dash(&cc.root_domain),
        dash(&cc.trusted_proxies.join(",")),
        dash(&cc.proxy_protocol.join(",")),
        certs,
        dash(&cc.acme_email),
        provider,
        token,
        metrics,
        go::format_duration(cc.node_lost_timeout_seconds.wrapping_mul(go::SECOND)),
        logs,
        export,
        network,
        backups
    )
}

fn status(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let mut admin = ctx.admin()?;
    let resp = rpc!(ctx, admin, cluster_status, ClusterStatusRequest {}).map_err(rpc_err)?;
    if o.json() {
        return print_json(ctx, &resp);
    }
    let text = cluster_status_text(&resp);
    ctx.print(&text);
    Ok(())
}

/// printClusterStatus.
fn cluster_status_text(r: &ClusterStatusResponse) -> String {
    let mut out = format!(
        "nodes {}/{} ready · apps {} · ready {} · rolling out {} · failing {} · jobs {}\n",
        r.nodes_ready, r.nodes, r.apps, r.apps_ready, r.apps_progressing, r.apps_failing, r.jobs
    );
    let mut tw = TabWriter::new(0, 2);
    if !r.attention.is_empty() {
        tw.write("\nNAME\tREADY\tSTATE\tMESSAGE\n");
        for a in &r.attention {
            tw.write(&format!(
                "{}\t{}/{}\t{}\t{}\n",
                a.name,
                a.ready,
                a.desired,
                a.state,
                dash(&printable(&a.message))
            ));
        }
        let more = r.attention_total as i64 - r.attention.len() as i64;
        if more > 0 {
            tw.write(&format!("and {more} more\n"));
        }
    }
    if !r.nodes_not_ready.is_empty() {
        tw.write("\nNODE NOT READY\n");
        for n in &r.nodes_not_ready {
            tw.write(&format!("{n}\n"));
        }
    }
    if let Some(b) = &r.control_plane_backup {
        tw.write(&format!("\n{}\n", backup_status_line(b)));
    }
    if let Some(sw) = &r.network_switch {
        let step = match sw.step.as_str() {
            "prepare" => format!("bringing it up beside {}", sw.from),
            "move" => "moving the routes to it".to_string(),
            _ => String::new(),
        };
        tw.write(&format!(
            "\nnetwork: switching from {} to {}, {} (since {})\n",
            sw.from,
            sw.to,
            dash(&step),
            date_time(Some(&unix_ts(sw.since_unix)))
        ));
        if !sw.waiting.is_empty() {
            tw.write("NODE\tWAITING FOR\n");
            for w in &sw.waiting {
                tw.write(&format!("{}\t{}\n", w.node, switch_wait(w)));
            }
            let more = sw.waiting_total as i64 - sw.waiting.len() as i64;
            if more > 0 {
                tw.write(&format!("and {more} more\n"));
            }
        }
    }
    out.push_str(&tw.finish());
    out
}

/// What a network switch waits for on one node.
fn switch_wait(w: &NodeSwitchWait) -> String {
    if w.unsupported {
        "an upgrade: its agent cannot switch the network".to_string()
    } else if w.disconnected {
        "the node to connect again (or to be lost)".to_string()
    } else if !w.error.is_empty() {
        printable(&w.error)
    } else if !w.unreached.is_empty() {
        format!("a path to {}", w.unreached.join(", "))
    } else {
        "its report".to_string()
    }
}

// ---- domain ----

pub fn add_domain(t: &mut Tree) -> usize {
    let n = t.add(
        0,
        Node::new("domain", "List and verify custom domains")
            .aliases(&["domains"])
            .noun(),
    );
    t.add(
        n,
        Node::new("list", "List custom domains and the DNS records that prove ownership")
            .aliases(&["ls"])
            .args(Args::No)
            .example("  armada domain list               # every custom domain, with its TXT record\n  armada domain list --app web")
            .flag(Flag::string("app", None, "", "only domains used by this app"))
            .flag(output_flag(false))
            .run(domain_list),
    );
    t.add(
        n,
        Node::new("verify DOMAIN", "Check a domain's TXT record now")
            .args(Args::Exact(1))
            .example("  armada domain verify www.example.com")
            .flag(output_flag(false))
            .run(domain_verify),
    );
    n
}

fn domain_list(ctx: &mut Ctx<'_>, _: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let mut id = ctx.str("app");
    if !id.is_empty() {
        id = ctx.app_id(&id).map_err(Error::Msg)?;
    }
    let mut admin = ctx.admin()?;
    let mut resp =
        rpc!(ctx, admin, list_domains, ListDomainsRequest { app: id }).map_err(rpc_err)?;
    if !ctx.g.all_spaces {
        resp.domains
            .retain(|d| d.apps.iter().any(|a| ctx.listed(a)));
    }
    if o.json() {
        return print_json(ctx, &resp);
    }
    print_domains(ctx, &resp.domains);
    Ok(())
}

fn domain_verify(ctx: &mut Ctx<'_>, args: &[String]) -> Result {
    let o = Output::of(ctx, false);
    o.check()?;
    let mut admin = ctx.admin()?;
    let req = VerifyDomainRequest {
        name: args[0].clone(),
    };
    let d = rpc!(ctx, admin, verify_domain, req).map_err(rpc_err)?;
    if o.json() {
        return print_json(ctx, &d);
    }
    print_domains(ctx, std::slice::from_ref(&d));
    Ok(())
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

/// The table to stdout, what needs doing to stderr.
fn print_domains(ctx: &mut Ctx<'_>, ds: &[Domain]) {
    let mut tw = TabWriter::new(0, 2);
    tw.write("DOMAIN\tAPPS\tVERIFIED\tTLS\n");
    for d in ds {
        tw.write(&format!(
            "{}\t{}\t{}\t{}\n",
            d.name,
            dash(&d.apps.join(",")),
            yes_no(d.verified),
            yes_no(d.tls_ready)
        ));
    }
    let out = tw.finish();
    ctx.print(&out);
    let pending: Vec<&Domain> = ds.iter().filter(|d| !d.verified).collect();
    if pending.is_empty() {
        return;
    }
    let mut w =
        String::from("\nTo verify ownership, create these DNS records (checked every minute):\n");
    for d in pending {
        w.push_str(&format!(
            "  TXT  {}  {}\n",
            d.txt_name,
            go::quote(&d.txt_value)
        ));
        if !d.message.is_empty() {
            w.push_str(&format!("       last check: {}\n", printable(&d.message)));
        }
    }
    let _ = ctx.err.write_all(w.as_bytes());
}

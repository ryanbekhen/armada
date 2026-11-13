# Monitor the cluster and get alerts

You want to know when an app stops serving, a rollout fails, a node drops
out, or a volume backup stops working, before your users tell you. This
guide turns on Armada's Prometheus endpoint, scrapes it, and adds alert
rules you can copy. It also shows the commands for a quick look without
Prometheus.

**You will use:** the [metrics endpoint](../operations.md#metrics),
[`armada metrics credentials`](../cli/armada-metrics.md#armada-metrics-credentials),
[events](../operations.md#events), [`armada app top`](../cli/armada-app.md#armada-app-top)
and [`armada node top`](../cli/armada-node.md#armada-node-top)
**Before you start:** a running cluster ([quickstart](../quickstart.md)),
`cluster-admin` access, and a Prometheus server on the private network that
reaches the control plane servers.

> **No Prometheus?** For messages in Slack, Discord, Telegram, or email when
> a node is lost, a replica runs out of memory, or a rollout fails, one
> command is enough: see [Get alerts](alerts.md). This guide is for
> thresholds and dashboards on top of that.

## The setup

```
  Prometheus ---- TLS 1.3 + client certificate (metrics:prometheus) ----+
      |                                                                 |
      |  scrapes all three servers                                      v
      +---> 10.0.0.5:9443   10.0.0.6:9443 (leader)   10.0.0.7:9443   /metrics
                 |                |                        |
               down             answers                  down
```

Only the leader serves `/metrics`, so the endpoint follows it when another
server takes over. Every series comes from one place: no per-node
exporters are needed for Armada's own state.

## 1. Turn the endpoint on

```bash
armada cluster set --metrics-port 9443
```

Each server listens on its own private address at that port; `0` turns it
off. The setting is kept in the cluster, so servers you add later use it.
A server that should listen on another of its addresses takes
`--metrics-listen IP:PORT` in its `/etc/armada/server.env`.

## 2. Create the scraper's certificate

The endpoint answers only TLS 1.3 clients with a certificate from the
cluster CA. Create one that can only scrape, on the Prometheus machine (or
copy the directory there):

```bash
armada metrics credentials prometheus -o /etc/prometheus/armada
```

```
/etc/prometheus/armada/ca.pem
/etc/prometheus/armada/cert.pem
/etc/prometheus/armada/key.pem
```

The key is made on this machine and never sent to the server. The
certificate (`metrics:prometheus`) is refused by every API call, so a
leaked key exposes metrics, not the cluster. It lasts a year and cannot be
revoked short of replacing the cluster CA: keep the key with Prometheus
only, and create a new one before the year is out.

## 3. Scrape every server

```yaml
# prometheus.yml
scrape_configs:
  - job_name: armada
    scheme: https
    scrape_interval: 15s
    tls_config:
      ca_file: /etc/prometheus/armada/ca.pem
      cert_file: /etc/prometheus/armada/cert.pem
      key_file: /etc/prometheus/armada/key.pem
      server_name: armada-server
    static_configs:
      - targets: ["10.0.0.5:9443", "10.0.0.6:9443", "10.0.0.7:9443"]
```

- `server_name: armada-server` is the name in every server's certificate;
  the addresses are not.
- One target is up at a time, the leader. The others are down, and that is
  normal. Alert on all of them being down (below), never on one.
- The leader reads the cluster's state for the endpoint at most once every
  10 seconds, so an interval below 10s shows nothing new.

### Reading the endpoint from your own program

A dashboard or script that reads `/metrics` itself has the same rule to
follow: only the leader answers, and the leader changes when a server
restarts. Give the program every server's address, not one, and have it try
them in turn until one answers:

```
https://10.0.0.5:9443/metrics,https://10.0.0.6:9443/metrics,https://10.0.0.7:9443/metrics
```

- A server that is not the leader refuses the connection, so moving on is
  quick. Keep a short timeout (a few seconds) for servers that do not
  answer at all.
- Verify the server's certificate against `ca.pem` with the name
  `armada-server`, as Prometheus does above; the addresses are not in the
  certificate.
- When you add or remove a server, update the list (`armada server list`
  shows the addresses).

## 4. Know the metrics that matter

| Metric | What to watch |
| --- | --- |
| `armada_app_replicas_ready`, `armada_app_replicas_desired` | ready below desired: replicas crash, fail probes, or cannot be placed |
| `armada_app_rollout{state="failed"}` | 1 when an app's last rollout failed (the old revision keeps serving) |
| `armada_replica_restarts_total`, `armada_replica_last_restart_timestamp_seconds{reason}` | crash loops, and why: `exited`, `out_of_memory`, `liveness`, `startup`, `network`, `volume`, `machine_restart` (the machine rebooted), `other`, `unknown` |
| `armada_replica_memory_usage_bytes`, `armada_replica_memory_limit_bytes` | replicas close to their limit get killed |
| `armada_replica_ready`, `armada_replica_draining` | a replica that is not ready and not draining is one that has not come up yet; a draining one is an old replica on its way out |
| `armada_node_ready`, `armada_node_cordoned` | a node that is not connected, and nodes drained by hand |
| `armada_node_cpu_reserved_cores`, `armada_node_cpu_allocatable_cores` (and `memory`) | room left for new replicas |
| `armada_node_conntrack_entries`, `armada_node_conntrack_max` | a full table drops new connections |
| `armada_volume_backup_failing`, `armada_volume_backup_last_success_timestamp_seconds` | scheduled volume backups |
| `armada_volume_used_bytes` | volume size (there is no quota) |
| `armada_job_last_success_timestamp_seconds`, `armada_job_runs_total{result}` | scheduled jobs that stopped succeeding |
| `armada_events_total{kind,reason}` | everything else the cluster records, such as `certificate` / `Failed` |
| `armada_server_leader`, `armada_agents_connected` | which server leads, and how many agents it hears from |
| `armada_reconcile_errors_total` | the control plane failing to converge |

The [operations guide](../operations.md#metrics) lists every metric. Label
values are names Armada validated (apps by ID, such as `api.shop`),
replica addresses, and image references; never domains, environment
values, or secrets.

## 5. Add alert rules

```yaml
# armada-alerts.yml
groups:
  - name: armada
    rules:
      - alert: ArmadaMetricsDown
        expr: sum(up{job="armada"}) == 0
        for: 5m
        annotations:
          summary: "No Armada server serves metrics: the control plane may have no leader"

      - alert: ArmadaAppNotReady
        expr: armada_app_replicas_ready < armada_app_replicas_desired
        for: 10m
        annotations:
          summary: "{{ $labels.app }}: {{ $value }} ready replicas, fewer than desired"

      - alert: ArmadaRolloutFailed
        expr: armada_app_rollout{state="failed"} == 1
        annotations:
          summary: "{{ $labels.app }}: the last rollout failed; the previous revision serves"

      - alert: ArmadaReplicaCrashLooping
        expr: increase(armada_replica_restarts_total[15m]) > 3
        annotations:
          summary: "{{ $labels.replica }} on {{ $labels.node }} restarted {{ $value }} times in 15m"

      - alert: ArmadaReplicaNearMemoryLimit
        expr: armada_replica_memory_usage_bytes / armada_replica_memory_limit_bytes > 0.9
        for: 15m
        annotations:
          summary: "{{ $labels.replica }} uses over 90% of its memory limit"

      - alert: ArmadaOutOfMemory
        expr: increase(armada_events_total{reason="OutOfMemory"}[15m]) > 0
        annotations:
          summary: "Processes were killed at a replica's memory limit (armada app events)"

      - alert: ArmadaNodeNotReady
        expr: armada_node_ready == 0
        for: 2m
        annotations:
          summary: "Node {{ $labels.node }} is not connected"

      - alert: ArmadaNodeFull
        expr: armada_node_memory_reserved_bytes / armada_node_memory_allocatable_bytes > 0.9
        for: 30m
        annotations:
          summary: "Node {{ $labels.node }} has under 10% of its memory left for new replicas"

      - alert: ArmadaConntrackHigh
        expr: armada_node_conntrack_entries / armada_node_conntrack_max > 0.8
        for: 10m
        annotations:
          summary: "Node {{ $labels.node }} tracks over 80% of its connection limit"

      - alert: ArmadaVolumeBackupFailing
        expr: armada_volume_backup_failing == 1
        for: 30m
        annotations:
          summary: "Backups of volume {{ $labels.volume }} of {{ $labels.app }} fail (armada app events)"

      - alert: ArmadaVolumeBackupStale
        expr: time() - armada_volume_backup_last_success_timestamp_seconds > 3 * 3600
        annotations:
          summary: "Volume {{ $labels.volume }} of {{ $labels.app }} has no backup newer than 3 hours"

      - alert: ArmadaJobNotSucceeding
        expr: time() - armada_job_last_success_timestamp_seconds > 25 * 3600
        annotations:
          summary: "Daily job {{ $labels.job }} has not succeeded in 25 hours"

      - alert: ArmadaCertificateFailed
        expr: increase(armada_events_total{kind="certificate", reason="Failed"}[1h]) > 0
        annotations:
          summary: "A certificate could not be obtained or renewed (armada cluster events)"

      - alert: ArmadaReconcileErrors
        expr: increase(armada_reconcile_errors_total[15m]) > 5
        annotations:
          summary: "The control plane keeps failing to reconcile (journalctl -u armada-server on the leader)"
```

Adjust these to your cluster:

- **Backups.** Set the staleness threshold to a few times the volume's
  `backup.every` (3 hours suits `every: 1h`). The timestamp is absent until
  a volume's first backup succeeds.
- **Jobs.** 25 hours suits a daily job. Filter by `job` for others, or
  leave out jobs that run only on demand.
- **Counters from events.** `armada_events_total` and
  `armada_job_runs_total` start again from zero when the leader changes;
  `increase()` handles that.
- **Certificates.** There is no expiry metric. Armada renews app
  certificates about 30 days before they expire, and a failure is a
  `Failed` event of kind `certificate`, which the rule above catches. Node
  certificates renew themselves; `armada node list` shows when each
  expires. User, service, and metrics certificates are renewed by hand;
  `armadad doctor` warns about the user certificate in the client config.

## 6. Look without Prometheus

**Events** tell you what the cluster did in the last 24 hours:

```bash
armada cluster status                    # one line, then apps and nodes that are not ready
armada cluster events --since 6h         # what happened, oldest first
armada cluster events -f                 # keep printing new events
armada app events api                    # one app and its replicas
armada cluster events --node node2       # one node and its replicas
```

```
TIME      KIND     OBJECT        REASON     COUNT  MESSAGE
10:01:50  rollout  api--r8       Started        1  rolling out api--r8 (image ghcr.io/acme/api:1.4.3)
10:02:11  replica  api-r8-k3j9a  Restarted      4  restarted: exited with code 1
10:05:20  rollout  api--r8       Failed         1  no progress within 3m30s; api-r8-k3j9a: exited with code 1; restarting in 8s; api--r7 keeps serving
10:58:03  node     node2         Lost           1  no contact for 5m0s; moving its replicas
```

Events are kept for 24 hours. For longer history, ship them to your log
system as JSON, one event per line:

```bash
armada cluster events -f -o json >> /var/log/armada-events.jsonl
```

Run it as a service with a config of its own; a cluster-wide `viewer`
user is enough to see every app's events, but events about nodes need
`cluster-admin`. If the command exits, for example when it loses its
connection, start it again with `--since` covering the gap.

**Usage** comes from samples every node takes every 10 seconds:

```bash
armada app top                 # per app: measured replicas, CPU used/reserved, memory used/limit
armada app top api             # per replica
armada node top                # per node: used, reserved, and what the node can give
armada app top --spaces      # per space, with requests and bytes sent
```

```
NODE   REPLICAS  CPU USED  CPU RESERVED  MEMORY USED  MEMORY RESERVED
node1  6         412m      1100m/1800m   1.4Gi        2.5Gi/3.6Gi
node2  5         388m      900m/1800m    1.1Gi        2.0Gi/3.6Gi
```

`CPU RESERVED` and `MEMORY RESERVED` show what replicas reserve against
what the node can give them; a new replica only starts where its
reservation fits.

## Check that it works

```bash
curl -s --cacert /etc/prometheus/armada/ca.pem --cert /etc/prometheus/armada/cert.pem \
  --key /etc/prometheus/armada/key.pem --resolve armada-server:9443:10.0.0.6 \
  https://armada-server:9443/metrics | grep armada_server_leader
```

```
armada_server_leader{server="cp-2"} 1
```

Run it against each server: the leader answers, the others refuse the
connection. In Prometheus, `armada_app_replicas_ready` should list every
app.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Every target is down | The metrics port is not set, or Prometheus cannot reach the private addresses | `armada cluster show`; check the provider firewall between Prometheus and the servers |
| TLS errors in Prometheus | `server_name` missing, or files from another cluster | Set `server_name: armada-server`; create the credentials again |
| `403` with a message about a metrics certificate | Prometheus presents another certificate (a node's, say) | Use the files `armada metrics credentials` wrote |
| Gaps of a few seconds | The leader changed; another server now answers | Nothing to do; scrape every server |
| A replica's usage is missing | No sample yet, or its node is disconnected | Wait 10 to 20 seconds after a start; check `armada node list` |

## Next steps

- [Get alerts](alerts.md): notices in chat or email without Prometheus.
- [Troubleshooting](troubleshooting.md): what to do when an alert fires.
- [Disaster recovery](disaster-recovery.md): backups the alerts above watch.
- [Teams and access](teams-and-access.md): read-only users for on call.
- [Operations guide: metrics](../operations.md#metrics), the full list.

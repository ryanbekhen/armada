# Read, search, and keep your apps' logs

Your app printed something an hour ago, on a replica that a deploy has
since replaced, and you need to find it. Or you want to watch only the
errors as they happen, or keep months of logs in Loki or another log
store. This guide covers all three, from the command line.

**You will use:** [`armada app logs`](../cli/armada-app.md#armada-app-logs),
[`armada job logs`](../cli/armada-job.md#armada-job-logs), and
[`armada cluster set`](../cli/armada-cluster.md#armada-cluster-set)
**Before you start:** a running cluster ([quickstart](../quickstart.md))
with an app (here `api`), and `viewer` access to its space. Sending logs to
a log store needs `cluster-admin`.

## How logs work

```
 app (stdout, stderr) ──> node: current files ──> history (7 days) ──> searched by --since
                                    │                                   
                                    ├──> armada app logs -f (live)      
                                    └──> Loki / OTLP (if you set one)   
```

- Armada keeps what an app writes to **stdout and stderr**. Write your logs
  there, not to files in the container.
- Each node stores its containers' output once, on its own disk. The newest
  part is read live; older parts, and the output of replicas that are
  gone, stay in the node's **history** for 7 days (at most 10% of the disk,
  5 GiB).
- Nothing is copied twice: the live view, the history search, and sending
  to a log store all read the same files.
- History and sending cover containers created by a version that has them.
  After upgrading the nodes, containers that were already running join once
  they are recreated, for example by the next deploy.
- An app that writes more than 1 MiB a second loses the excess, with one
  line saying how much; this keeps one app from filling a node's disk.

## 1. Watch logs live

```bash
armada app logs api                     # the last 100 lines of every replica
armada app logs api -f                  # then keep streaming
armada app logs api -f --grep error     # only lines containing "error" (any case)
armada app logs api -f --timestamps     # with the time each line was written
```

```
2026-11-13T09:41:07.512+07:00 api-r8-q2k0d | GET /orders 500 timeout talking to db
2026-11-13T09:41:09.020+07:00 api-r8-x7m1p | GET /orders 500 timeout talking to db
```

- Every line starts with its replica. One replica: `--replica api-r8-q2k0d`.
- With `-f`, replicas that start later, after a deploy or a scale-up, join
  the stream on their own. Stop it with Ctrl-C.
- `--grep` is plain text, not a pattern, and ignores case. It runs on the
  nodes, so lines that do not match never cross the network.
- `--tail 500` shows more lines first; with `--grep`, it counts matching
  lines.
- A sidecar or init container: `--container NAME`.

## 2. Search the past

`--since` searches the history of every node, including replicas that no
longer exist:

```bash
armada app logs api --since 2h --grep error                      # the last two hours
armada app logs api --since 2026-11-13T09:00:00+07:00 --until 30m --timestamps
armada app logs api --since 1d --replica api-r8-q2k0d --limit 2000
armada app logs api --since 10m -f                               # the last ten minutes, then live
```

- `--since` and `--until` take a duration back from now (`30m`, `2h`,
  `3d`) or a time (`2026-11-13T09:00:00+07:00`).
- A search shows the newest 500 lines (`--limit`, at most 5000), merged by
  time across nodes.
- Each node reads at most 1 GiB of output for one search, within 30
  seconds. When it stops early it says so in a last line; narrow the
  search with `--until`, `--replica`, or `--grep`.

Jobs work the same way:

```bash
armada job logs backup                 # the newest run
armada job logs backup --run 12 --task 3
armada job logs backup --since 3d --grep failed
```

### Keep history longer, or smaller

```bash
armada cluster set --log-retention 336h --log-max-disk 10Gi   # 14 days, at most 10 GiB per node
armada cluster set --log-retention 0 --log-max-disk 0          # back to the defaults
armada cluster show                                             # log history: ...
```

Every node applies it within a minute, without a restart. The oldest output
goes first when the size is reached.

## 3. Send logs to a log store

For months of logs, dashboards, or searching across everything at once,
every node can also send its apps' output to **Loki** or to any
**OpenTelemetry (OTLP/HTTP)** endpoint, such as an OpenTelemetry
Collector or a hosted service that takes OTLP.

### Loki

```bash
# a hosted Loki with basic authentication: the user and token your provider gives you
armada cluster set --log-export loki \
  --log-endpoint https://logs.example.com/loki/api/v1/push \
  --log-export-user 123456 --log-token - < loki-token

# your own Loki on the private network, multi-tenant
armada cluster set --log-export loki \
  --log-endpoint http://10.0.0.20:3100/loki/api/v1/push --log-export-tenant platform
```

Logs arrive with these labels, so a query such as
`{app="api", space="default"} |= "error"` finds them:

| Label | Value |
| --- | --- |
| `app` | the app's name |
| `space` | its space |
| `container` | `app`, or the sidecar or init container |
| `stream` | `stdout` or `stderr` |
| `node` | the node |
| `source` | `armada` |

`replica` and `revision` come as structured metadata, so the number of
streams does not grow with every new replica: `{app="api"} | replica="api-r8-q2k0d"`.
This needs Loki 3 or later.

### OTLP

```bash
armada cluster set --log-export otlp \
  --log-endpoint https://otlp.example.com/v1/logs --log-token - < otlp-token
```

Each replica's container is one resource: `service.name` (the app),
`service.namespace` (the space), `service.instance.id` (the replica),
`service.version` (the revision), `host.name` (the node), and
`container.name`; each line carries `log.iostream` (`stdout` or `stderr`).

### The rules

- The endpoint must be `https://`, or `http://` to a private IP address.
  Put no user, password, or query in the URL: use `--log-export-user` and
  `--log-token`. The token is stored encrypted and never shown.
- Without `--log-export-user` the token is sent as a bearer token; with it,
  as the password of basic authentication.
- Logs are sent from the moment you set the export; older output stays only
  in history.
- Every node must reach the endpoint.
- Delivery is at least once: when the endpoint is down, output waits in the
  node's history and is sent when it is back, so a line may arrive twice
  after an outage, never lost while the history still holds it.

Change one field, and the others stay:

```bash
armada cluster set --log-export-tenant team-b
armada cluster set --log-token - < new-token
armada cluster set --log-export none          # stop sending; the token is removed
```

## Check that it works

```bash
armada app logs api --tail 5                  # live output reaches you
armada app logs api --since 1h --limit 5      # history answers from every node
armada cluster show                           # log export: loki to https://... (token set)
armada cluster events | grep LogExportFailing # nothing: every node can send
```

In Loki, `{source="armada"}` should show lines within a few seconds of an
app writing them.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `--since` or the log store misses a replica | The replica's container was created before the nodes were upgraded | The next deploy recreates it; to do it now, change anything, such as `armada app update api --env RESTARTED_AT=$(date +%s)` |
| `[armada] node n2: searched the newest 1024 MiB of output on this node; narrow it ...` | A busy app; the node stopped reading | Narrow with `--until`, `--replica`, or `--grep` |
| `[armada] node n2: did not answer` | The node is not connected | `armada node list`; its history is searched once it is back |
| A line `[armada: dropped N bytes of output over the log rate limit ...]` | The app writes more than 1 MiB a second | Log less, or send fewer debug lines |
| `LogExportFailing` events, `log endpoint answered 401` | Wrong token or user | `armada cluster set --log-token - < token` |
| `log endpoint answered 400 ... structured metadata` | Loki older than 3, or structured metadata turned off | Upgrade Loki, or allow structured metadata |
| `LogExportFailing`, `connection refused` or a timeout | The node cannot reach the endpoint | Check the node's outbound access to the endpoint |
| `-f --grep` shows nothing | No new line matches yet | Leave out `--grep` to see that lines arrive |

## Next steps

- [Get alerts](alerts.md): a message when a replica crashes or runs out of
  memory, with the logs above to find out why.
- [Troubleshooting](troubleshooting.md): reading logs together with events.
- [ADR 0043](../adr/0043-log-history.md) and
  [ADR 0044](../adr/0044-log-export.md): how history and export work.

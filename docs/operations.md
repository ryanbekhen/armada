# Operations: control plane, backup, restore, and upgrades

Armada's control plane keeps the cluster's state in etcd, embedded in
`armada server`. A cluster runs one control plane server or, for high
availability, three (see below). With one server, its data directory
(`/var/lib/armada` by default) is the cluster: lose it without a backup and
you have to build a new cluster and redeploy everything. With three, any
one can fail, but a mistake (a deleted app, a bad secret) is replicated to
all of them. Back up either way.

## Control plane: one server or three

| Servers | Tolerates the loss of | Use |
| --- | --- | --- |
| 1 | none: while it is down, apps keep serving but nothing can be changed | small clusters, labs |
| 2 | none, and losing **either** stops changes | avoid: worse than one |
| 3 | one server | recommended for production |
| 5 | two servers | large clusters |

The servers elect a leader, which serves the API and runs the reconcilers
and certificate renewal; the others stand by with a replica of the state.
When the leader is stopped, another takes over within about a second; when
it crashes or loses the network, within 10–15 seconds. Agents and the CLI
know every server and follow the leader on their own. Apps keep serving
throughout. See [ADR 0010](adr/0010-ha-control-plane.md).

**Network:** control plane nodes must reach each other on the private
network on ports 2379 and 2380 (etcd, mutual TLS) and 7443/7444 (API and
join listener). Allow these between servers only; nothing on the public
interface.

### Adding a server

On a machine with Armada installed (steps 1–2 of the
[quickstart](quickstart.md)), in the same private network:

```bash
armada token create --server           # anywhere with the admin config
sudo armada server join 10.0.0.2:7444 --ca-hash sha256:...   # on the new machine; paste the token
sudo systemctl enable --now armada-server
armada server list                     # waits for "voting"; updates ~/.armada/config
```

The new server receives the cluster CA key and the secrets master key over
the CA-pinned connection, so the server token is as sensitive as those keys:
it works once and lasts 15 minutes by default (at most an hour). Start the
server right after the join. Add servers one at a time, and go from one
straight to three: with two, losing either stops the control plane.

`armada server list` shows each server's role and status: `voting`,
`catching up` (just joined), `unreachable` (its etcd member does not
answer), or `not a member` (removed, or a join that never started).
It also writes the servers' addresses into your client config, leader
first, so the CLI keeps working when a server goes away. Run it on every
admin machine after adding or removing servers.

### Removing a server

```bash
sudo systemctl disable --now armada-server   # on the server being removed
armada server remove NAME                     # once another server leads
armada node remove NAME                       # its agent, if you no longer want it as a node
```

The leader cannot remove itself: stop it first, and run the command once
another server leads. Then **wipe the removed server's data directory**: it
still holds the CA key and the master key. Remove a dead server before
adding its replacement, so the cluster never counts a member that will not
come back.

## What is in the data directory

| File | What it is | Without it |
| --- | --- | --- |
| `etcd/` | The embedded etcd member: apps, revisions, replicas, nodes, domains, encrypted secrets, the ACME account and certificates | No cluster (unless other servers have it) |
| `master.key` | Encrypts every secret in the state | Secrets are unrecoverable |
| `ca.crt`, `ca.key` | Cluster CA: signs node, admin, and server certificates | Every node must join again; every admin config is invalid |
| `server.crt`, `server.key` | Control plane TLS identity | Re-issuable from the CA |
| `node.crt`, `node.key`, `agent.json` | Identity of the agent on the control plane node, and its container runtime | The node must join again |
| `runtime/`, `containerd/`, `containers/`, `logs/` | The embedded runtime: extracted binaries, images, per-container files, container output | Recreated: the binaries are extracted again, images pulled again, and the agent recreates its containers |

`armada backup` includes all of these except the runtime directories (the state as an etcd snapshot; the
member's own certificate is issued again from the CA). With several
servers, back up on any one of them: they hold the same state. It does not include
`~/.armada/config` (your admin credentials): keep a copy of that file
somewhere safe as well. It stays valid after a restore because the CA is
the same.

## Backup

```bash
sudo armada backup -o /root/armada-$(date +%F).tar.gz
```

- Safe while the server is running: the state is copied as a consistent
  etcd snapshot through the running server's etcd member (if the server is
  stopped, `backup` starts the member itself). Before the archive is
  written, the snapshot is restored into a scratch member and checked, so
  a backup that could not be restored fails now and not when you need it.
- The archive is created with mode `0600` and never overwrites an existing
  file. It starts with a manifest (Armada version, schema version, master
  key ID, CA fingerprint, and a SHA-256 for every file).
- **The archive contains the CA key and the master key in plaintext.**
  Anyone who has it controls the cluster and can read every secret. Encrypt
  it before it leaves the machine, for example with
  [age](https://age-encryption.org):

  ```bash
  sudo armada backup -o - | age -r age1yourpublickey... > armada-$(date +%F).tar.gz.age
  ```

  `-o -` refuses to write to a terminal.

A daily backup with a systemd timer:

```ini
# /etc/systemd/system/armada-backup.service
[Unit]
Description=Back up the Armada control plane

[Service]
Type=oneshot
UMask=0077
ExecStart=/bin/sh -c 'armada backup -o - | age -r age1yourpublickey... > /var/backups/armada/armada-$(date +%%F-%%H%%M).tar.gz.age'
```

```ini
# /etc/systemd/system/armada-backup.timer
[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Copy the encrypted archives off the machine (object storage, another
provider), and test a restore now and then.

## Restore

A restore is for when the state is lost: a single server is gone, or a
majority of the servers is. (If one of three servers fails, you do not need
a backup: remove it and join a new one.)

Restore onto a machine that has **the same private IP** as the server the
backup was taken on. Nodes connect to that address and the server
certificate is issued for it. Most providers let you choose the private IP
of a new machine or move a reserved one; moving a server to a different IP
is not supported in v0.1.

1. Make sure every old control plane server is stopped for good. A
   restored server must never run next to servers of the old cluster.
2. Install Armada (see the [quickstart](quickstart.md)) and run
   `armada doctor`.
3. Restore into an empty data directory:

   ```bash
   age -d -i key.txt armada-2026-10-31.tar.gz.age | sudo armada restore -
   # or: sudo armada restore /root/armada-2026-10-31.tar.gz
   ```

   The archive is extracted into a temporary directory and checked before
   anything is moved into place: only known file names are accepted
   (no paths outside the data directory, no links), sizes are capped,
   every file must match its checksum in the manifest, the etcd snapshot
   must pass its own checksum and open as Armada state this version
   understands, the master key must be the one the state was encrypted
   with, and the server certificate must be signed by the CA. If any check
   fails, nothing is changed. `restore` never writes into a data directory
   that is not empty.

4. Start the server: `sudo systemctl enable --now armada-server`.
5. Check: `armada node list` and `armada status`. Agents reconnect on their
   own within seconds.
6. With several servers before: the restored server forms a cluster of one.
   `armada server list` shows the others as `not a member`; remove them with
   `armada server remove`, wipe their data directories, and join them again
   as new servers.

Everything that changed after the backup is gone:

- Nodes that joined after the backup are unknown and must join again.
  Nodes removed after the backup come back in the list; remove them again.
- Apps, revisions, scale changes, and secrets set after the backup must be
  deployed or set again.
- Agents adopt the containers that are still running and converge to the
  restored state, so replicas of apps deployed after the backup are
  removed.

## Upgrades

Within v0.x, run the same Armada version on every node. Mixed versions are
expected only while an upgrade is in progress. Upgrade the control plane
servers first, one at a time, then the other nodes one at a time.

1. **Back up** (see above) and read the release notes.
2. **Control plane servers**, one at a time (wait for `armada server list`
   to show the upgraded one as `voting` before the next):

   ```bash
   sudo ARMADA_VERSION=v0.2.0 sh install.sh
   sudo systemctl restart armada-server
   armada version && armada node list && armada status
   ```

   `armada server list` shows each server's version. When a release
   changes the layout of the state (the release notes say so), upgraded
   servers stand by and the servers still on the old version keep leading
   until the last one is upgraded; then an upgraded server leads and
   migrates the state (ADR 0012). Until then `armada server list` names
   the servers it waits for. A server that is gone for good but still
   listed blocks the migration: remove it with `armada server remove`.
   An older binary refuses state written by a newer one instead of
   misreading it, so the backup from step 1 is your way back.

   While a server restarts, apps keep serving: every node's HAProxy and
   containers keep running. With one server, deploys and other changes are
   unavailable for those seconds; with three, another server leads in the
   meantime. Agents reconnect on their own.

3. **Every other node**, one at a time:

   ```bash
   sudo ARMADA_VERSION=v0.2.0 sh install.sh
   sudo systemctl restart armada-agent
   ```

   Containers keep running; the restarted agent adopts them, and
   `armada node list` shows the node's new version. The embedded
   runtime (`armada-runtime.service`) picks up a new containerd from the
   upgraded binary at its next restart (`sudo systemctl restart
   armada-runtime`); restarting it also leaves containers running. Internal
   names (`<app>.internal`) on that node do not resolve for the second or
   two it takes the agent to start its DNS server again.

### Rolling back an upgrade

An older binary refuses state that a newer one has already changed to a
newer layout, instead of misreading it. To go back:

- If the layout did not change, reinstall the older version and restart.
- If it did, stop the server, move the data directory aside, reinstall the
  older version, and restore the backup taken before the upgrade. Changes
  made since the upgrade are lost.

## Node labels and placement

Nodes carry labels that apps choose them by
([ADR 0014](adr/0014-node-labels-and-placement.md)):

```bash
armada node label raspi-mks region=sulawesi kind=raspi   # set
armada node label raspi-mks kind-                         # remove
armada token create --label region=sulawesi              # nodes joining with it get the label
armada node restrict gpu-1                               # only apps that ask for its labels
armada node open gpu-1
armada node list                                         # LABELS column, "restricted" in STATE
```

Every node also has `armada.os`, `armada.arch`, and `armada.runtime`, which
its agent reports.
Label keys and values are yours to choose; Armada gives no name a meaning.
Apps select nodes with `placement.require` and spread over a label's values
with `placement.spreadBy` (see the
[spec reference](spec-reference.md#placement)). Only admins set labels; a
node cannot label itself.

To survive the loss of a site, label every node with where it is and
spread apps by that label:

```bash
armada node label node-1 site=jakarta
armada node label node-2 site=jakarta
armada node label node-3 site=makassar
```

An app with `placement.spreadBy: site` then runs half of its replicas in
each site. Nodes without the label get none of its replicas, so label
every node.

Changing a node's labels or restricting it moves the replicas it may no
longer run, the same way a cordon does: a replacement starts on an allowed
node first, then the old replica is drained. When no allowed node has room,
the replica stays where it is until one does, and `armada status` says so.

Every replica reserves its `resources.cpu` (100m when unset) and
`resources.memory` on its node, and nodes are never overcommitted; see the
[spec reference](spec-reference.md#resources). Armada keeps 100m of CPU
and 128Mi of memory on each node for itself, and another 100m on control
plane servers. Replicas that no longer fit after an upgrade keep running;
only new ones need room. If a rollout waits for a node, `armada status`
names what is short: scale another app down, lower its reservation, or add
a node.

Clusters may mix architectures (amd64 and arm64, say): each app stays on
the nodes its image has a variant for, as reported by the first node that
pulls it (`armada revisions APP` shows the platforms). If no node can run
an image, `armada status` names the platforms it is built for.

Nodes may be far apart: agents cope with latency. Keep the **control plane
servers** close to each other (the same city or region), since every change
needs a round trip between them.

## Running commands in replicas

`armada exec` runs a command in one replica of an app and exits with the
command's exit code ([ADR 0017](adr/0017-exec.md)):

```bash
armada exec web -it -- sh                     # interactive shell
armada exec web -- cat /etc/resolv.conf       # one command, stdout and stderr kept apart
armada exec web -i -- sh -c 'cat > /tmp/x' < x # pass standard input
armada exec web --replica web-r1-5muie -- env # a specific replica (armada status lists them)
```

- Without `--replica`, Armada picks a running, ready replica of the
  serving revision.
- The command runs with the container's own user, capabilities,
  `no-new-privileges`, seccomp profile, limits, and namespaces; there is no
  option to run it with more privileges.
- Exec is for diagnosis. What a command changes inside a container is lost
  when the replica is replaced; change the spec or the image instead.
- Every session is recorded in the audit log with the admin, the app, the
  replica, and the command's name, never its arguments. Still, prefer
  reading secret values from files over passing them as arguments.
- A node runs at most 8 sessions at once, and a session without input or
  output for 30 minutes is ended. Sessions also end when the control
  plane's leader changes.
- Nodes whose runtime driver lacks the exec capability refuse it.

## Resource usage

`armada top` shows what replicas use, from samples every agent takes every
10 seconds ([ADR 0018](adr/0018-top.md)):

```bash
armada top            # per app
armada top web        # per replica of web
armada top --nodes    # per node
armada top -o json    # everything, with the time of each sample
```

```
REPLICA          NODE   STATE    CPU        MEMORY
web-r1-5muie     node1  running  37m/250m   61Mi/256Mi
web-r1-q2k0d     node2  running  41m/250m   58Mi/256Mi
```

- CPU is `used/reserved` in millicores, averaged over the last 10 seconds.
  The reservation (`resources.cpu`, 100m by default) is also the limit when
  the app sets one; a replica may use more than its reservation when the
  node has CPU to spare and no limit is set.
- Memory is `used/limit`: memory in use without page cache the kernel can
  reclaim, the figure that counts toward the limit. A replica that stays
  close to its limit is killed and restarted when it goes over; raise
  `resources.memory`.
- `--nodes` shows what each node's replicas use and reserve, and what the
  node can give replicas after what Armada keeps for itself.
- `-` means no recent sample: the replica is not running yet, the node is
  disconnected, or its runtime driver lacks the stats capability. Numbers
  appear 10 to 20 seconds after a replica starts or the control plane's
  leader changes, since samples are kept in the leader's memory only.

## Autoscaling

An app with `scale.rules` scales itself between `scale.min` and
`scale.max` ([ADR 0022](adr/0022-autoscaling.md); rules in the
[spec reference](spec-reference.md#autoscaling)).

```
$ armada status web
APP  REVISION  READY  INGRESS   IMAGE
web  web--r4   4/4    external  ghcr.io/acme/web:1.4

web: autoscale 2-10, http 41/50, cpu 38%/70%: steady: http 41 of 50 per replica, cpu 38 of 70%
```

- **Rules with no data.** A rule shows `-` while it has no data. CPU and
  memory need the runtime to sample containers (`armada top`). `http` needs
  a proxy on at least one node.
- **Events.** Scaling is recorded as `ScaledUp` or `ScaledDown` events, and
  audited as `armada:autoscaler`.
- **Capacity.** Plan room for `scale.max`, because replicas reserve CPU and
  memory as usual. Replicas that do not fit wait, with an `Unschedulable`
  event.
- **Leader changes.** After the leader changes, the app does not scale
  down for 5 minutes.
- **Scale to zero.** Apps with `scale.min: 0` show `0/0` and
  `scaled to zero; the next request wakes it` while asleep. `armada events`
  shows `ScaledToZero`, and `Woken` with the node whose proxy took the
  request. The first request after a quiet period waits for a whole cold
  start, so keep `min: 1` for apps where that delay matters.
- **No ready replicas.** The autoscaler counts only ready replicas. If
  every replica fails its readiness probe under load, it holds until one is
  ready again, so give replicas enough CPU to answer their probes when
  busy.
- **Alerts.** Watch `armada_app_replicas_desired` reach the max.

## Traffic splitting

Apps with `revisions.mode: multiple` split their requests between
revisions ([ADR 0024](adr/0024-traffic-splitting.md); fields in the
[spec reference](spec-reference.md#revisions)). A canary looks like this:

```bash
armada deploy -f web.yaml            # traffic: web--r3 90, latest 10 (label canary)
armada status web                    # the split, replicas per revision, the label's URL
armada traffic web r3=50 r4=50       # more traffic to the new revision
armada traffic web r4=100            # all of it; r3 drains and stops
```

```
web: traffic web--r3 90%, web--r4 10% (canary)

APP  URL
web  https://web.example.com/
web  https://canary--web.example.com/ (web--r4)
```

- **Comparing revisions.** `armada logs`, `armada top`, and the replica
  metrics carry the revision. `armada_app_traffic_weight` shows the split.
- **Events and audit.** Each change is a `TrafficChanged` event and an
  audit entry.
- **Lasting changes.** `armada traffic` lasts until the next deploy, so put
  lasting weights in the spec.
- **Finishing.** To finish a canary, deploy the spec in single mode. That
  is a rolling update, and every revision in the traffic serves until the
  new one is ready.
- **Capacity.** Every revision in the traffic runs at least one replica and
  reserves its CPU and memory.

## Jobs

Jobs run a container to completion, on demand or on a schedule
([ADR 0021](adr/0021-jobs.md); fields in the
[spec reference](spec-reference.md#jobs)):

```bash
armada deploy -f backup.yaml     # kind: job; changes apply to the next runs
armada job run db-backup         # start a run now
armada job ls                    # schedule, latest run, next run
armada job runs db-backup        # runs, newest first
armada logs db-backup            # the newest run's output (--run N for another)
armada job cancel db-backup      # stop the active run
armada job rm db-backup          # delete the job, its runs, and their logs
```

```
RUN  STATE      TRIGGER   ATTEMPTS  NODE   STARTED  DURATION  EXIT  MESSAGE
12   succeeded  schedule  1         node2  7h ago   2m        0     -
11   failed     schedule  3         node1  1d ago   30m       -     timed out after 30m0s
```

- Runs go to nodes that the job's placement allows and that have room for
  its reservation, like replicas. A run that cannot be placed waits, and
  fails when its timeout passes.
- A failed attempt is retried while `retries` allow, possibly on another
  node. Only the latest attempt's logs are kept.
- Runs keep going when their node is cordoned; a run on a lost node counts
  as failed and is retried.
- Jobs do not appear in `armada status`. `armada events JOB` shows their
  runs, and `armada top` shows the resources a running job uses.
- Alert on `time() - armada_job_last_success_timestamp_seconds > 90000`
  for a daily job that has not succeeded in 25 hours.

## Events

`armada events` shows what the cluster did in the last hour
([ADR 0020](adr/0020-event-history.md)): replicas scheduled, started,
restarted, or moved; rollouts started, completed, or failed; nodes
connected, lost, or cordoned; apps that cannot be placed or that the
autoscaler scaled, scaled to zero, or woke; traffic changes; job runs;
domains and certificates.

```bash
armada events                    # the last hour, everything
armada events web                # only web and its replicas
armada events --node node2       # only node2 and its replicas
armada events --since 6h -f      # six hours back, then new events as they happen
armada events -o json            # one JSON object per line
```

```
TIME            KIND         OBJECT                        REASON           COUNT  MESSAGE
10:01:50        rollout      web--r2                       Started              1  rolling out web--r2 (image nginx:1.27)
10:02:11        replica      web-r2-k3j9a                  Restarted            4  restarted: exit code 137
10:58:03        node         node2                         Lost                 1  no contact for 5m0s; moving its replicas
```

- An event that repeats within 10 minutes is counted (`COUNT`) instead of
  shown again; `TIME` is its last occurrence.
- Events are kept for 24 hours, at most 2000 of them. For longer history,
  run `armada events -f -o json` into your log system, or alert on
  `armada_events_total` from the metrics endpoint.
- Messages from nodes are shortened to 512 bytes, with control characters
  replaced.

## Metrics

The leader serves Prometheus metrics ([ADR 0019](adr/0019-metrics-endpoint.md))
when servers run with `--metrics-listen`. Give every server the same flag in
`/etc/armada/server.env`, with its own private address:

```bash
ARMADA_SERVER_FLAGS="... --metrics-listen 10.0.0.5:9443"
```

The endpoint needs a client certificate. Create one for the scraper from any
machine with admin credentials:

```bash
armada metrics credentials prometheus -o /etc/prometheus/armada   # ca.pem, cert.pem, key.pem
```

The key is generated on that machine and never sent to the server. The
certificate (`metrics:prometheus`) can only scrape: the API refuses it. It
lasts a year; create a new one before it expires. Admin certificates may
scrape too.

Scrape every server. Only the leader answers, so exactly one target is up:

```yaml
scrape_configs:
  - job_name: armada
    scheme: https
    tls_config:
      ca_file: /etc/prometheus/armada/ca.pem
      cert_file: /etc/prometheus/armada/cert.pem
      key_file: /etc/prometheus/armada/key.pem
      server_name: armada-server
    static_configs:
      - targets: ["10.0.0.5:9443", "10.0.0.6:9443", "10.0.0.7:9443"]
```

| Metric | Labels | Meaning |
| --- | --- | --- |
| `armada_server_leader` | `server` | 1 on the server that serves the endpoint |
| `armada_agents_connected` | | agents connected to the leader |
| `armada_reconcile_duration_seconds` | | histogram of reconcile times |
| `armada_reconcile_errors_total` | | failed reconciles |
| `armada_app_autoscale_current`, `armada_app_autoscale_target` | `app`, `rule` | an autoscaling rule's average per ready replica (absent while unmeasured) and its target |
| `armada_app_traffic_weight` | `app`, `revision` | a revision's percent of the app's requests in multiple revision mode |
| `armada_job_runs_total` | `job`, `result` | job runs that ended: `succeeded`, `failed`, `cancelled`; resets when the leader changes |
| `armada_job_runs_active` | `job` | runs pending or running |
| `armada_job_last_success_timestamp_seconds` | `job` | when the newest kept successful run finished |
| `armada_events_total` | `kind`, `reason` | events the leader recorded (see [Events](#events)); resets when the leader changes |
| `armada_app_replicas_desired`, `armada_app_replicas_ready` | `app` | desired replicas, and those running, ready, and not draining |
| `armada_app_rollout` | `app`, `state` | 1 for the current rollout state: `idle`, `progressing`, `failed` |
| `armada_replica_ready` | `app`, `replica`, `revision`, `node` | 1 when the replica serves |
| `armada_replica_cpu_usage_cores`, `armada_replica_memory_usage_bytes` | `app`, `replica`, `node` | usage from the latest sample (absent without one) |
| `armada_replica_cpu_reserved_cores`, `armada_replica_cpu_limit_cores`, `armada_replica_memory_limit_bytes` | `app`, `replica`, `node` | reservation and limits (CPU limit only when set) |
| `armada_node_ready`, `armada_node_cordoned` | `node` | node state |
| `armada_node_replicas` | `node` | replicas assigned to the node |
| `armada_node_cpu_allocatable_cores`, `armada_node_memory_allocatable_bytes` | `node` | what the node can give replicas |
| `armada_node_cpu_reserved_cores`, `armada_node_memory_reserved_bytes` | `node` | what its replicas reserve |
| `armada_node_cpu_usage_cores`, `armada_node_memory_usage_bytes` | `node` | what its replicas use |

Example alerts: `armada_app_replicas_ready < armada_app_replicas_desired`
for 10 minutes, `armada_app_rollout{state="failed"} == 1`,
`armada_replica_memory_usage_bytes / armada_replica_memory_limit_bytes > 0.9`,
`increase(armada_events_total{reason="Restarted"}[10m]) > 3`, and
`armada_node_ready == 0`.

## When a node fails

| What fails | What happens |
| --- | --- |
| A node (machine down, network gone) | Within about 4 seconds the HAProxy on every other node stops sending it traffic; requests that hit it meanwhile are retried on another replica after 2 seconds. After `--node-lost-timeout` (default 5 minutes) the node is shown as `lost` and its replicas are started on other nodes that their app's placement allows; the old ones are removed once the new ones serve. When the node comes back, its old containers are cleaned up and apps left unevenly spread move replicas back to it, one at a time. See [ADR 0008](adr/0008-self-healing.md) and [ADR 0013](adr/0013-replica-rebalancing.md). |
| HAProxy on a node (crashed or killed) | The agent notices within about 10 seconds and starts a new HAProxy container with the current configuration; that node's public ports are down until it serves again. |
| More than half of the nodes at once | Nothing is rescheduled: the control plane assumes it is the one cut off. Replicas move once enough nodes are reachable again, or with `armada node remove --force`. |
| One of three control plane servers | Another server leads within 1–15 seconds; nothing else changes. Remove the failed server and join a replacement when convenient. |
| The only control plane server, or a majority of them | Apps keep serving: every node's HAProxy and containers keep running. Deploys, scaling, rescheduling, and certificate renewal wait until a majority is back; certificates have weeks of margin. Restore from a backup if the servers are gone. |

Run at least two replicas of anything that must stay up, so a node failure
costs capacity, not availability. Your DNS records point at every node's
public IP; a dead node's IP keeps receiving the share of visitors that DNS
sends it until you remove it or put a health-checked load balancer (from
your provider, or DNS with health checks) in front of the nodes.

## Container runtime drivers

Nodes run containers through Armada's embedded runtime unless they are set
up with an external driver, a separate program that runs containers on
another engine for the agent
([ADR 0015](adr/0015-external-runtime-drivers.md)). Install the driver
first, following its own instructions. The documented drivers pass Armada's
conformance suite:

| Driver | Engine | `--runtime` |
| --- | --- | --- |
| [armada-driver-docker](https://github.com/ryanbekhen/armada-driver-docker) | Docker Engine (Linux, cgroup v2; macOS on Apple silicon with the engine in a Linux virtual machine) | `docker` |
| [armada-driver-apple](https://github.com/ryanbekhen/armada-driver-apple) | Apple's `container` tool (macOS on Apple silicon; VM isolation, at least 200 MiB per replica) | `apple` |

On Linux a driver runs as root under its own systemd unit,
`armada-driver-NAME.service`, and listens on
`/run/armada/drivers/NAME.sock` (macOS: see [macOS nodes](#macos-nodes)).
Then set the node up with it:

```bash
sudo armada join ADDR --ca-hash sha256:... --runtime NAME              # or: armada init --runtime NAME
sudo armada join ADDR --ca-hash sha256:... --runtime NAME --proxy none # a driver without system containers
armada doctor                                      # checks the driver's socket
```

A driver has the agent's trust on the node: install only drivers you trust
as much as Armada. The agent connects only to a socket that its own user
(root on Linux) owns, in a directory closed to other users, served by a
process running as that user. It checks every container spec before
sending it, and the driver library checks it again on arrival.

- `--container-subnet` belongs to the embedded runtime; the driver chooses
  its container network.
- A driver that cannot run system containers cannot run HAProxy: give the
  node `--proxy none`. It runs replicas, and the other nodes route traffic
  to them. `armada doctor` warns about such a driver.
- A driver without the bridge capability leaves internal DNS off on the
  node, so its containers cannot resolve `<app>.internal`.
- A driver without the exec capability refuses `armada exec` for the
  replicas on its node.
- A driver without the stats capability reports no usage, so `armada top`
  shows `-` for the replicas on its node.
- The node's `armada.runtime` label names the driver, so apps can require
  it (or `embedded`). `armada.os` and `armada.arch` are the platform the
  driver's engine runs containers on.
- `armada-runtime.service` exits at once on such a node, and
  `armada runtime reset` removes Armada's containers through the driver,
  leaving the engine's other containers alone.
- A driver may declare **VM isolation**: every container runs in its own
  virtual machine with its own kernel, and the driver leaves out
  `no-new-privileges`, seccomp, and the PID limit, which guard a kernel
  shared with the host ([ADR 0016](adr/0016-macos-nodes.md)). Memory and
  CPU limits and the dropped capabilities still apply, and the
  conformance suite checks that containers really get separate kernels.
- A driver may declare a **minimum memory limit**. Replicas whose
  `resources.memory` is below it are not placed on that node, and
  `armada status` says so when no other node can take them.
- A driver may declare a **capacity** smaller than the machine's, such as
  the size of the virtual machine its engine runs containers in. The node
  then reports that CPU and memory (`armada status`), and reservations
  only fill what the engine can give.

## macOS nodes

A Mac with Apple silicon can join a cluster as a **compute node**: it runs
replicas, which HAProxy on the other nodes serves over the Mac's private
IP, but not the control plane, HAProxy, or internal DNS
([ADR 0016](adr/0016-macos-nodes.md)). Container images hold Linux
programs, so a Mac runs them in Linux virtual machines; how depends on the
driver:

- **A driver with VM isolation** (one light virtual machine per
  container) is the lightest way to run replicas on a Mac. It suits trying
  Armada out, and production use where its consequences are acceptable:
  containers rely on the virtual machine boundary instead of
  `no-new-privileges`, seccomp, and a PID limit, and the engine may refuse
  small memory limits.
- **A driver on a container engine that runs every container in one
  Linux virtual machine** keeps all of Armada's container defaults, at
  the cost of a heavier virtual machine. Use it when VM isolation's
  consequences are a problem. The node reports the virtual machine's CPUs
  and memory, so size the virtual machine for the replicas it should
  hold.
- **A Linux virtual machine on the Mac** can instead join as an ordinary
  Linux node, with every feature, including HAProxy and internal DNS. It
  needs an address on the private network, such as a bridged interface.

The drivers table above says which drivers support macOS.

A macOS node runs as one dedicated user, not root, because the Mac's
container engines serve the logged-in user. Set it up as that user:

1. Create a standard user for the node (say `armada`), keep it for the
   node only, and log in as it. Whoever holds this account controls the
   node, as root does on Linux. The node runs while the user is logged
   in: turn on automatic login for it, or log in after every restart
   (macOS does not allow automatic login with FileVault on).
2. Install Armada from an administrator account (`sudo sh install.sh`;
   on a Mac it installs only the binary), and the driver as its
   instructions say. A driver on macOS runs as a LaunchAgent of the
   node's user.
3. As the node's user, without sudo:

   ```bash
   armada join ADDR --ca-hash sha256:... --runtime NAME   # writes the agent's LaunchAgent
   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/io.github.ryanbekhen.armada.agent.plist
   armada doctor
   ```

On the Mac:

- The data directory is `~/Library/Application Support/Armada` (mode
  `0700`), and driver sockets are in its `run/drivers`.
- Secret files go to a 64 MiB RAM disk that the agent mounts on the data
  directory's `secrets` when it starts. The RAM disk ignores file
  ownership, so the agent refuses it unless the data directory is closed
  to other users.
- The agent logs to `~/Library/Logs/Armada/agent.log`; logs never contain
  secret values. macOS does not rotate the file.
- `armada init`, `armada server`, `armada server join`, `armada backup`,
  `armada restore`, and `armada runtime` refuse to run.
- Containers on the Mac cannot resolve or reach `<app>.internal`; call
  other apps through their public domains.

To keep apps off Mac nodes unless they ask for one, restrict the node and
give it a label that those apps require:

```bash
armada node label mac-1 kind=mac
armada node restrict mac-1
```

Removing a Mac node: `armada node remove NODE` on the control plane, then
as the node's user `launchctl bootout gui/$(id -u)/io.github.ryanbekhen.armada.agent`,
`armada runtime reset`, eject the RAM disk (`diskutil eject` on the device
mounted at the secrets directory, or restart), and delete the data
directory.

## Removing a node

```bash
armada node remove NODE    # on the control plane: moves replicas, revokes the certificate
```

Then, on that node:

```bash
sudo systemctl disable --now armada-agent
sudo armada runtime reset                  # removes Armada's containers
sudo systemctl disable --now armada-runtime
sudo ip link delete armada0
```

and delete its data directory. On a node with an external driver, skip the
last two commands and remove the driver as its instructions say.

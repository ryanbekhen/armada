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
| `volumes/` | App volumes held by this node (on every node, not only servers) | The apps' data, unless backed up with `armada volume backup` |

`armada backup` includes all of these except the runtime directories and volumes (the state as an etcd snapshot; the
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

   Containers keep running and keep serving; the restarted agent adopts
   them, and
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

## Projects

A project holds apps, jobs, secrets, domains, and volumes, and names only
need to be unique within one (ADR 0026). Every cluster has the project
`default`, which holds everything deployed without a project.

```bash
armada project create staging
armada deploy -f web.yaml --project staging
armada status --project staging          # only the project's apps
armada secret set web db-password --project staging < password.txt
armada secret import web .env --project staging   # many at once: DATABASE_URL becomes database-url
armada project list
armada project remove staging            # only once it is empty
```

Every command that names an app or a job takes `--project` (or
`ARMADA_PROJECT`), or the app's ID, `NAME.PROJECT`: `armada scale
web.staging 3`. Status, events, and metrics show apps of other projects by
that ID, and so do their revisions (`web.staging--r1`) and replicas.
Without `--project`, names are in `default` and listings show every
project. Internal apps of a project are reached at
`NAME.PROJECT.internal`, and external apps without domains at
`NAME.PROJECT.<root domain>`, with a certificate of their own (a wildcard
certificate covers only one level).

### Network isolation

On a cluster with the cluster network (`armada init --cluster-cidr`, ADR
0025), every node keeps apps and projects apart (ADR 0026):

- A container reaches another app only through its internal name
  (`http://NAME.internal`, `http://NAME.PROJECT.internal`): traffic straight
  to another app's container address is dropped, on one node and between
  nodes. Replicas of the same app still reach each other directly.
- A container resolves only the internal names of its own project, and
  its node's proxy routes an internal name only for containers of that
  app's project, whatever `Host` header they send. `ingress.allow` in a
  spec narrows an internal app to the listed apps of its project (see the
  spec reference). Anything else, the node itself included, gets a 404.
- Containers of every project but `default` are isolated from the platform:
  they reach the internet, their node's DNS server, and internal and public
  ingress, and nothing else. The nodes, the control plane, the private
  network and every machine on it, and the cloud's metadata service
  (`169.254.169.254`) are out of reach.

`default` is not isolated from the platform unless you turn it on, so apps
that use a database on the private network keep working:

```bash
armada project set default --network-isolation        # once its apps no longer need the private network
armada project set default --network-isolation=false
armada project list                                   # the NETWORK column
```

`armada doctor` checks that the firewall tables are in place (`isolation`;
the kernel needs nf_tables). Connections opened before a change keep going
until they end. Clusters without the cluster network are not filtered.

### Sharing a cluster

Containers of every project share each node's kernel, so projects separate
apps you operate together; they do not contain code someone hostile wrote.
For that, use a separate cluster or restricted nodes. Projects also share the
cluster's capacity: `scale.max` bounds what an app can take, and `armada top
--projects` shows what each project uses.

Container output is limited on every node: each container may write 1 MiB
per second (4 MiB at once) to its log, kept in 3 files of 10 MB; `armada
logs` shows a line such as `[armada: dropped 52428800 bytes of output over
the log rate limit ...]` where output was dropped.

### Automation identities

A tool that manages projects on your behalf, such as a CI system or a
self-service portal, gets an automation identity instead of an admin
certificate. It manages the apps, jobs, secrets, domains, and volumes of
the projects in its scope, and nothing else: not nodes, tokens, servers,
backups, the network, or the default project. It sees only its projects in
listings, and no nodes.

```bash
armada automation set portal --create-projects --project staging --label tier=shared
armada automation credentials portal -o portal.json   # 0600; keep it with the tool
armada --config portal.json deploy -f web.yaml --project staging
armada --config portal.json automation renew          # before the 90 days run out
armada automation list
armada automation remove portal                       # its certificates stop working at once
```

`--create-projects` lets the tool create projects, which join its scope,
and remove the ones it manages. `--label KEY=VALUE` is a node label its
apps may require, for nodes you keep for some projects (restricted
nodes). `set` replaces the scope and keeps the certificates. The tool
reaches the API on the private network like the CLI.

A domain serves one project: an app cannot use a domain that an app of
another project uses, and a domain another project left behind needs a
new TXT record.

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

Every node also has `armada.os` and `armada.arch`, which its agent
reports.
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

Nodes keep only the images they need: every 10 minutes each agent removes
images that no container uses and that no replica assigned to the node
names, once they were pulled more than an hour ago. Rolling back to a
revision whose image is gone pulls it again, so its registry credentials
must still work.

Clusters may mix architectures (amd64 and arm64, say): each app stays on
the nodes its image has a variant for, as reported by the first node that
pulls it (`armada revisions APP` shows the platforms). If no node can run
an image, `armada status` names the platforms it is built for.

Nodes may be far apart: agents cope with latency. Keep the **control plane
servers** close to each other (the same city or region), since every change
needs a round trip between them.

## One agent per node

`armada server` already runs the agent of its own machine, so do not also
start `armada agent` there. A second agent on a node refuses to start and says
why: two would take turns replacing each other's connection to the control
plane and fail each other's replicas.
## Removing an app

```sh
armada app rm web --yes
```

The app stops taking new requests at once, its replicas drain like those of any
rollout, and then the app is gone with its revisions and secrets. This cannot be
undone; `armada status` shows the app as being removed until then, and deploying
the same name waits until it is gone.

Its volumes and their data stay. Remove them with `armada volume rm` or deploy
the same name again to use them. A project can be removed once it holds no apps
and no volumes.

## Container network

Every node's containers live on the node's own bridge subnet, a /24 of
the cluster CIDR (`armada init --cluster-cidr`, default `10.120.0.0/16`,
[ADR 0025](adr/0025-cluster-network.md)). The leader gives a node its
subnet when it joins, and `armada join` prints it. A node removed from the
cluster frees its subnet for the next one. The cluster CIDR is set once,
holds from 16 (a /20) to 4096 (a /12) nodes, must be a private range, and
must not contain the nodes' private IPs or overlap routes on them
(`armada doctor` checks the node's subnet).

A node takes at most 250 replicas, whatever CPU and memory it has left: a /24
has no more addresses to give. With every node at that limit, new replicas wait and
`armada status` says so. Add a node to make room.

Container addresses are unique in the cluster, and the bridge's gateway
(where `<app>.internal` and the node's DNS answer) differs per node. Every
Linux node routes the other nodes' subnets over its `armada-net` interface,
so containers and nodes reach a container on any node at its own address,
and a replica sees the caller's real address. `armada init --network`
chooses, once, how that traffic travels:

| Mode | Tunnel | Port to allow between nodes | Overhead |
| --- | --- | --- | --- |
| `plain` (default) | VXLAN, not encrypted | UDP 4789 | 50 bytes |
| `wireguard` | WireGuard, encrypted and authenticated | UDP 51820 | 80 bytes |

Choose `wireguard` when you do not trust the private network (shared or
provider-managed networks) or must encrypt traffic between machines. It
costs CPU on every node that sends or receives traffic between nodes: on
two vCPUs, about 2 Gbit/s between containers of two nodes against 14 Gbit/s
in `plain`, and about half the throughput of a large upload. Requests that
stay on their node (local-first routing) do not pay it. Where the kernel
has no WireGuard, the agent runs it in userspace, which is markedly slower,
and traffic between nodes pauses while that agent restarts; `armada doctor`
warns about it.

Allow the mode's port between the nodes in the provider firewall; Armada
accepts it on each node only on the private IP and only from the other
nodes. In the `wireguard` mode each node keeps its key in `network.key` in
the data directory (not in backups; a restored node makes a new one) and
announces the public half; a node that announces another node's key is
refused. To give a node a new key, remove `network.key` and restart its
agent.

The tunnel takes its overhead from each packet: the bridge and containers
get the MTU of the interface that holds the private IP less 50 or 80 (at
least 1280 is required). Containers created before the node joined the tunnel keep
their old MTU until they are replaced. `armada doctor` shows the MTU,
whether `armada-net` is up and routes every other node, and in the
`wireguard` mode whether every peer has a recent handshake. `armada runtime
reset` on a removed node takes the interface and its firewall rules off.

Replicas publish no port: the agent reports each at its own address and
the app's port (`armada status` shows `10.120.x.y:PORT`), and every node's
HAProxy reaches it there, through the tunnel for other nodes' replicas.
Other machines on the private network cannot reach containers at all, not
even by routing a node's subnet through its private IP. Replicas started
before a node joined the tunnel keep their published port until they are
replaced. Clusters created
by an Armada without the cluster network keep one bridge subnet on every
node (`--container-subnet`, default `10.121.0.0/24`).

## How requests reach replicas

Every node's HAProxy serves the app's public domains and `<app>.internal`,
and sends each request to one of the app's ready replicas. It prefers the
replicas on its own node while they are about as busy as the app's other
replicas, and spreads the rest over every replica
([ADR 0024](adr/0024-local-first-routing.md)). At low load a request never
leaves the node that received it; under load, and when the node has no
replica up, the others take the excess. Apps that split traffic between
revisions are balanced over every replica by weight instead.

So point public DNS at every node that should take traffic: a node that
receives more requests keeps its replicas somewhat busier.

Long-lived connections have their own limits: a silent WebSocket closes after
1 hour, and the old proxy process that a reload leaves behind for open
connections stops at most 1 hour after the reload, closing what it still holds.
See [`ingress`](spec-reference.md#ingress) for what clients should do.

### Behind a proxy or CDN

Public ingress removes the headers that name a client's address
(`Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`,
`True-Client-IP`), then adds the connection's own address to
`X-Forwarded-For`, so an app sees who really connected and nobody can claim
another address. When a proxy or CDN sits in front of your nodes, list its
address ranges so requests from it keep those headers:

```bash
armada cluster set --trusted-proxies 192.0.2.0/24,198.51.100.0/24
armada cluster set --trusted-proxies ""    # no proxy trusted again
```

Requests from anywhere else still lose them. A range that matches every
address is refused. The list is a cluster setting, audited, and applied with a
proxy reload. Keep it current with the provider's published ranges.

To stop clients going around the proxy altogether, limit ports 80 and 443 on
the nodes to the same ranges in your firewall: HAProxy runs on the host's
network, so firewall rules on the host apply to it.

The internal frontend leaves these headers alone, so an app that proxies to
another one can pass its client's address on.

## Running commands in replicas

`armada exec` runs a command in one replica of an app and exits with the
command's exit code ([ADR 0015](adr/0015-exec.md)):

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

## Resource usage

`armada top` shows what replicas use, from samples every agent takes every
10 seconds ([ADR 0016](adr/0016-top.md)):

```bash
armada top            # per app
armada top web        # per replica of web
armada top --nodes    # per node
armada top --projects # per project
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
- `--projects` adds up each project's replicas and volumes, and counts the
  requests the proxies sent to its replicas and the bytes its containers
  sent over their network, replies and traffic to other replicas included.
  An automation identity sees only its own projects.
- Requests and egress count from when the control plane's leader started, the
  time the listing prints, and start over when the leader changes. They are
  sums of samples: what a container sends in its first and last 10 seconds
  can be missed, and so can what the last sample before a lost connection
  or a crashed proxy did not cover. For history, scrape the
  [metrics](#metrics) and use `rate()` or `increase()`.
- `-` means no recent sample: the replica is not running yet or the node is
  disconnected. Numbers appear 10 to 20 seconds after a replica starts or
  the control plane's leader changes, since samples are kept in the
  leader's memory only.

## Autoscaling

An app with `scale.rules` scales itself between `scale.min` and
`scale.max` ([ADR 0020](adr/0020-autoscaling.md); rules in the
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
revisions ([ADR 0022](adr/0022-traffic-splitting.md); fields in the
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
([ADR 0019](adr/0019-jobs.md); fields in the
[spec reference](spec-reference.md#jobs)):

```bash
armada deploy -f backup.yaml     # kind: job; changes apply to the next runs
armada job run db-backup         # start a run now
armada job run db-backup --wait  # and wait: exits non-zero unless the run succeeded
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
([ADR 0018](adr/0018-event-history.md)): replicas scheduled, started,
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

The leader serves Prometheus metrics ([ADR 0017](adr/0017-metrics-endpoint.md))
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
| `armada_app_replicas_min`, `armada_app_replicas_max` | `app` | an autoscaled app's bounds |
| `armada_replica_ready` | `app`, `replica`, `revision`, `node` | 1 when the replica serves |
| `armada_replica_start_time_seconds` | `app`, `replica`, `node` | when the replica was scheduled |
| `armada_replica_restarts_total` | `app`, `replica`, `node` | how often its container was recreated (crash, out of memory, failed probe) |
| `armada_replica_last_restart_timestamp_seconds` | `app`, `replica`, `node`, `reason` | when it last was, and why: `exited`, `out_of_memory`, `liveness`, `startup`, `network`, `volume`, `other`, `unknown` |
| `armada_replica_cpu_usage_cores`, `armada_replica_memory_usage_bytes` | `app`, `replica`, `node` | usage from the latest sample (absent without one) |
| `armada_replica_cpu_reserved_cores`, `armada_replica_cpu_limit_cores`, `armada_replica_memory_limit_bytes` | `app`, `replica`, `node` | reservation and limits (CPU limit only when set) |
| `armada_project_replicas` | `project` | replicas of the project's apps |
| `armada_project_cpu_usage_cores`, `armada_project_memory_usage_bytes` | `project` | what they use (absent without a sample) |
| `armada_project_cpu_reserved_cores`, `armada_project_memory_reserved_bytes` | `project` | what they reserve |
| `armada_project_volume_used_bytes` | `project` | bytes in the project's volumes, from their latest measurements |
| `armada_project_requests_total`, `armada_project_egress_bytes_total` | `project` | requests the proxies sent to its replicas and bytes its containers sent; reset when the leader changes |
| `armada_node_ready`, `armada_node_cordoned` | `node` | node state |
| `armada_node_replicas` | `node` | replicas assigned to the node |
| `armada_node_cpu_allocatable_cores`, `armada_node_memory_allocatable_bytes` | `node` | what the node can give replicas |
| `armada_node_cpu_reserved_cores`, `armada_node_memory_reserved_bytes` | `node` | what its replicas reserve |
| `armada_node_cpu_usage_cores`, `armada_node_memory_usage_bytes` | `node` | what its replicas use |
| `armada_node_conntrack_entries`, `armada_node_conntrack_max` | `node` | connections its kernel tracks, and the limit |

Example alerts: `armada_app_replicas_ready < armada_app_replicas_desired`
for 10 minutes, `armada_app_rollout{state="failed"} == 1`,
`armada_replica_memory_usage_bytes / armada_replica_memory_limit_bytes > 0.9`,
`increase(armada_events_total{reason="Restarted"}[10m]) > 3`,
`armada_node_conntrack_entries / armada_node_conntrack_max > 0.8`, and
`armada_node_ready == 0`.

### Connection tracking

The kernel tracks every connection through a node, and keeps a closed one for
two minutes. Past the limit it drops new connections, and clients wait a
second or more for a retransmit, so requests slow down with no error anywhere.
Clients that open a new connection per request fill the table fastest: each
one takes two entries, one on each side of the proxy.

The agent raises `net.netfilter.nf_conntrack_max` to 262144, or to one entry
per 4 KiB of memory on machines under 1 GiB, and never lowers a higher limit.
A full table then takes about 6% of the memory at most. Raise it further with
`sysctl` on nodes that need more; check `dmesg` for `table full` and
`armada doctor` (`conntrack`), which warns at 80%.

## Volumes

Volumes keep an app's data on the node that runs its single replica
([ADR 0023](adr/0023-persistent-volumes.md); fields in the
[spec reference](spec-reference.md#volumes)). On a node they live in
`/var/lib/armada/volumes/<app>/<name>`.

```bash
armada volume ls                                   # app, volume, node, path, size
armada volume backup db data -o db-data.tar.gz     # copy while the app runs
armada volume backup db data -o db-data.tar.gz --stop   # consistent: stops the app meanwhile
armada volume restore db data db-data.tar.gz       # replace the contents; stops the app meanwhile
armada volume rm db data --yes                     # delete the data; only once no spec mounts it
```

```
APP  VOLUME  NODE   PATH                      USED    AGE
db   data    node2  /var/lib/postgresql/data  1.2GiB  14d
```

- **Deploys have downtime.** The old replica stops (after its drain)
  before the new one starts, on the same node.
- **Live backups may be inconsistent.** Files written during a backup may
  be copied half-written. For databases, use their own dump tool through
  `armada exec` (for example `armada exec db -- pg_dump -U postgres app`),
  or `--stop`.
- **Back up regularly, off the node.** `armada backup` holds where volumes
  are, not their contents. Archives hold the app's data as it is: encrypt
  them like control plane backups. For example, from a machine with admin
  credentials:

  ```bash
  armada volume backup db data -o - | age -r age1yourpublickey... > db-data-$(date +%F).tar.gz.age
  ```

- **Cordoning or draining a node** does not move apps with volumes;
  `armada node remove` refuses a node that holds volumes unless `--force`
  is given.
- **Watch disk use.** There is no quota: alert on
  `armada_volume_used_bytes` against the node's disk.

### Recovering an app whose node is gone

If the node holding an app's volumes is lost for good, the app stays down
until its data is restored somewhere else:

```bash
armada node remove node2 --force                     # if the node is gone for good
armada volume restore db data db-data.tar.gz --node node3
```

The volume is restored onto `node3` and bound to it, and the app starts
there. This is refused while the old node is still connected. Data written
after the backup is lost.

## When a node fails

| What fails | What happens |
| --- | --- |
| A node (machine down, network gone) | Within about 4 seconds the HAProxy on every other node stops sending it traffic; requests that hit it meanwhile are retried on another replica after 2 seconds. After `--node-lost-timeout` (default 5 minutes) the node is shown as `lost` and its replicas are started on other nodes that their app's placement allows; the old ones are removed once the new ones serve. When the node comes back, its old containers are cleaned up and apps left unevenly spread move replicas back to it, one at a time. See [ADR 0008](adr/0008-self-healing.md) and [ADR 0013](adr/0013-replica-rebalancing.md). |
| HAProxy on a node (crashed or killed) | The agent notices within about 10 seconds and starts a new HAProxy container with the current configuration; that node's public ports are down until it serves again. |
| The node holding an app's volumes | The app stays down: its data is on that node, so it is not started elsewhere. A `VolumeUnavailable` event says so. It comes back with the node, or with a restore onto another node (see [Volumes](#volumes)). |
| More than half of the nodes at once | Nothing is rescheduled: the control plane assumes it is the one cut off. Replicas move once enough nodes are reachable again, or with `armada node remove --force`. |
| One of three control plane servers | Another server leads within 1–15 seconds; nothing else changes. Remove the failed server and join a replacement when convenient. |
| The only control plane server, or a majority of them | Apps keep serving: every node's HAProxy and containers keep running. Deploys, scaling, rescheduling, and certificate renewal wait until a majority is back; certificates have weeks of margin. Restore from a backup if the servers are gone. |

Run at least two replicas of anything that must stay up, so a node failure
costs capacity, not availability. Your DNS records point at every node's
public IP; a dead node's IP keeps receiving the share of visitors that DNS
sends it until you remove it or put a health-checked load balancer (from
your provider, or DNS with health checks) in front of the nodes.

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

and delete its data directory.

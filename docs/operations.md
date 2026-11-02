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

Every node also has `armada.os` and `armada.arch`, which its agent reports.
Apps select nodes with `placement.require` (see the
[spec reference](spec-reference.md#placement)). Only admins set labels; a
node cannot label itself.

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

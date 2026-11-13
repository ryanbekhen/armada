# Back up the cluster and recover from failures

Machines die, disks fail, and people delete the wrong thing. This guide
sets up the backups that let you recover, then walks through each kind of
failure: a lost control plane server, a lost node with app data, and a lost
cluster. It ends with a drill you can run before you need any of it.

**You will use:** [`armadad backup`](../cli/armadad-backup.md) and
[`armadad restore`](../cli/armadad-restore.md),
[scheduled volume backups](../spec-reference.md#volumesbackup) with
`failover: restore`, [`armada volume`](../cli/armada-volume.md),
[control plane servers](../operations.md#control-plane-one-server-or-three)
**Before you start:** a running cluster ([quickstart](../quickstart.md)),
root on a control plane server, an S3-compatible bucket for volume backups,
and [age](https://age-encryption.org) (or another tool) to encrypt archives.

## The setup

```
  control plane server(s)                          off the cluster
  +-------------------------------+
  | /var/lib/armada               |  armadad backup  +------------------------+
  |  state, master.key, CA, certs |----------------->| armada-*.tar.gz.age    |
  +-------------------------------+   (daily timer)  | (encrypted, 0600)      |
                                                     |                        |
  node with a volume                                 |                        |
  +-------------------------------+  backup.every    | bucket: chunks +       |
  | /var/lib/armada/volumes/db/.. |----------------->| snapshots (encrypted)  |
  +-------------------------------+                  +------------------------+

  kept somewhere else again: the age key, each volume's backup key,
  the admin config, and your specs (in git)
```

## 1. Know what to back up

| What | Holds | How |
| --- | --- | --- |
| Control plane | apps, revisions, secrets (encrypted), nodes, domains, ACME certificates, the CA and master keys | `armadad backup` on any server, on a timer (step 2) |
| Volume contents | your apps' data on the nodes | `backup` in the volume's spec (step 3), or `armada volume backup` archives |
| The keys to those backups | the age key for control plane archives, each volume's `keySecretRef` value | outside the cluster, for example in a password manager |
| An admin client config | a way back into the cluster | a copy of a `cluster-admin` config; it stays valid after a restore, since the CA is the same |
| Specs | how each app is deployed | in git (see [spec files and environments](spec-files-and-environments.md)) |

`armadad backup` does not hold volume contents, NFS exports, or the
container images; nodes pull images again.

## 2. Back up the control plane every day

The archive holds the CA key and the master key in plaintext: anyone with
it controls the cluster and reads every secret. Encrypt it before it is
written:

```ini
# /etc/systemd/system/armada-backup.service
[Unit]
Description=Back up the Armada control plane

[Service]
Type=oneshot
UMask=0077
ExecStart=/bin/sh -c 'armadad backup -o - | age -r age1yourpublickey... > /var/backups/armada/armada-$(date +%%F-%%H%%M).tar.gz.age'
```

```ini
# /etc/systemd/system/armada-backup.timer
[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo install -d -m 0700 /var/backups/armada
sudo systemctl daemon-reload
sudo systemctl enable --now armada-backup.timer
sudo systemctl start armada-backup.service      # one now, to see it work
```

- It is safe while the server runs: the state is copied as a consistent
  snapshot, which is restored into a scratch member and checked before
  the archive is written. A backup that could not be restored fails now.
- With three servers, run it on one of them (they hold the same state), or
  on each for redundancy.
- Copy the archives off the machine (object storage, another provider)
  with the tool you already use, and keep the age private key elsewhere.

## 3. Back up volumes on a schedule

Give every volume that matters a `backup`. Add `failover: restore` when the
app should come back on another node by itself:

```yaml
# db.yaml
name: db
image: postgres:17
env:
  - name: POSTGRES_PASSWORD
    secretRef: postgres-password
ingress:
  type: internal
  port: 5432
  protocol: tcp
volumes:
  - name: data
    path: /var/lib/postgresql/data
    owner: "999:999"
    backup:
      every: 1h
      keep: {hourly: 24, daily: 7, weekly: 4}
      urlSecretRef: backup-url
      keySecretRef: backup-key
    failover: restore
resources:
  memory: 1Gi
```

```bash
armada space use shop
printf '%s' "$POSTGRES_PASSWORD" | armada secret set db postgres-password
printf '%s' 'https://ACCESS_KEY:SECRET_KEY@s3.example.com/acme-backups/armada' | armada secret set db backup-url
openssl rand -base64 48 | tr -d '\n' > db-backup-key.txt   # keep a copy outside the cluster
armada secret set db backup-key --from-file db-backup-key.txt
armada app create --file db.yaml --wait
```

```bash
armada volume snapshot create db data     # one now, instead of waiting for the first
armada volume list
```

```
APP      VOLUME  NODE   PATH                      USED    LAST BACKUP  BACKUPS      AGE
db.shop  data    node2  /var/lib/postgresql/data  1.2GiB  1m ago       1 (410MiB)   3m
```

- Each backup uploads only what the bucket does not hold yet, encrypted
  with the key. **Without the key, the backups cannot be read**: keep it
  outside the cluster too.
- The copy is taken while Postgres runs. Files it writes meanwhile may be
  copied half-written; Postgres recovers from such a copy like from a
  crash. For a copy you can trust without that, add `stop: true` (the app
  stops while its volume is read), or also keep logical dumps, for example
  with a [scheduled job](scheduled-jobs.md) that runs `pg_dump`.
- The bucket must accept requests from the node's own address. Give the
  access key only this bucket; versioning or object lock on the bucket keeps
  backups even from someone who holds the key.
- Alert on failing and stale backups (see
  [monitoring and alerts](monitoring-and-alerts.md#5-add-alert-rules)); a
  failure is also a `VolumeBackupFailed` event.

## 4. Recover

### A node without volumes is lost

Nothing to do. After the node-lost timeout (5 minutes by default,
`armada cluster set --node-lost-timeout`) its replicas start on other
nodes, and the old ones are removed once the new ones serve. Run at least
two replicas of anything that must stay up, so a lost node costs capacity,
not availability. When the machine is gone for good:

```bash
armada node delete node3 --force
```

### A node with volumes is lost

With `failover: restore`, the cluster handles it:

1. The lost node stops the app itself after half the node-lost timeout
   without contact, so two copies never write at once.
2. After the node-lost timeout, the leader restores each volume's latest
   backup on another node the app may run on, binds the volumes there,
   and starts the app.

```bash
armada app events db
```

```
TIME      KIND  OBJECT   REASON             COUNT  MESSAGE
03:12:40  app   db.shop  VolumeUnavailable      1  its volumes are on node node2, which is unreachable or removed; their latest backups are being restored on another node (failover: restore)
03:13:05  app   db.shop  VolumeFailedOver       1  node node2 was lost; restored data on node3
```

Writes since the last backup are lost. If it cannot fail over (no backup
yet, no node with room, the bucket refuses), a `VolumeFailoverFailed`
event says why, and it tries again every 5 minutes.

Without `failover`, the app stays down with a `VolumeUnavailable` event
until the node comes back or you restore its data elsewhere:

```bash
armada node delete node2 --force                                  # if it is gone for good
armada volume restore db data --snapshot latest --node node3      # from the bucket
armada volume restore db data db-data.tar.gz --node node3         # or from an archive
```

The restore is refused while the old node is still connected, so a node
that is only slow cannot end up with a second copy. If the machine comes
back later, its old copy of the volume stays in its volumes directory,
unused.

### One of three control plane servers is lost

The other two keep a majority and one of them leads within seconds; apps
and changes keep working. You do not need a backup:

```bash
armada server list                    # the lost one shows "unreachable"
armada server delete cp-3             # remove it before you add its replacement
armada node delete cp-3 --force       # its agent, if the machine is gone
armada server join-token              # then join a new machine, as in the operations guide
```

Remove the dead server first, so the cluster never counts a member that
will not come back. If the old machine still exists, wipe its data
directory: it holds the CA key and the master key. See
[adding a server](../operations.md#adding-a-server).

### The only server, or a majority of servers, is lost

Apps keep serving: every node's HAProxy and containers keep running. Deploys,
scaling, rescheduling, and certificate renewal wait. Restore from the
latest backup onto a machine with **the same private IP** as the server the
backup was taken on (nodes connect to that address, and the server
certificate is issued for it):

1. Make sure every old control plane server is stopped for good. A
   restored server must never run next to servers of the old cluster.
2. Install Armada on the new machine ([quickstart](../quickstart.md)) and
   run `armadad doctor`.
3. Restore into an empty data directory, and start it:

   ```bash
   age -d -i key.txt armada-2026-11-10-0300.tar.gz.age | sudo armadad restore -
   sudo systemctl enable --now armada-server
   ```

4. Check, from a machine with your admin config:

   ```bash
   armada node list        # agents reconnect on their own within seconds
   armada cluster status
   armada server list      # former servers show "not a member"
   ```

5. Delete the former servers with `armada server delete`, wipe their data
   directories, and join them (or new machines) again as servers.

Everything that changed after the backup is gone: deploy those apps and set
those secrets again, join nodes that joined since, and delete nodes you had
removed. Replicas of apps deployed after the backup are removed. This is
why a daily backup, or one after each larger change, pays off.

### The whole cluster is lost

With the control plane archive, restore the first server as above (same
private IP), then join new nodes. Apps, secrets, and settings come back
from the archive, and their replicas start on the new nodes once the old
ones count as lost. Apps with volumes stay bound to their old nodes: with
`failover: restore` they move by themselves; otherwise remove the old
nodes and restore their volumes from the buckets:

```bash
armada node delete node2 --force
armada volume snapshot list db data
armada volume restore db data --snapshot latest --node node3
```

Without any control plane archive, build a new cluster, deploy your specs
from git, set every secret again (including each volume's `backup-url` and
the same `backup-key`), and restore the volumes from their buckets. A
volume's backups live under `<prefix>/<app>/<volume>/` in the bucket
(`<app>.<space>` outside `default`), so create the app with the same name
in a space of the same name to find them.

### Someone deleted an app

`armada app delete` removes the app with its revisions and secrets; its
volumes stay. Create the app again from its spec, set its secrets, and it
finds its volumes. Restoring a control plane backup to undo a single
mistake also undoes everything else since that backup, so prefer
redeploying.

## Check that it works: a recovery drill

Run this every few months, and after upgrades:

- [ ] `ls -l /var/backups/armada` shows today's archive, and a copy exists
      off the machine.
- [ ] The archive decrypts and restores: on a machine with Armada
      installed that is not a control plane server, restore into a scratch
      directory, then delete it (it holds the cluster's keys). `restore`
      runs every check a real restore runs, and starts nothing.

      ```bash
      age -d -i key.txt armada-2026-11-10-0300.tar.gz.age | sudo armadad restore - --data-dir /var/tmp/armada-drill
      sudo rm -rf /var/tmp/armada-drill
      ```

- [ ] `armada volume list` shows a recent `LAST BACKUP` for every volume (not `never` or `failing`),
      and `armada volume snapshot list APP VOLUME` lists backups.
- [ ] A volume backup restores: create a copy of the app in a space of
      its own (`armada app create --file db.yaml --space shop-drill`, with
      its secrets), copy the data into it, and check the data there:

      ```bash
      armada volume backup db data -o - --space shop | armada volume restore db data - --space shop-drill
      ```
- [ ] Every volume's backup key and the age key are where you expect,
      outside the cluster, and someone besides you can get to them.
- [ ] A spare `cluster-admin` config works: `armada --config spare.config
      cluster status`.
- [ ] `armada server list` shows every server `voting`, and
      `armada node list` shows no `lost` nodes.
- [ ] Your alerts for stale backups fire: point one at a test volume with
      a bucket URL that refuses writes, and wait.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `armadad restore` refuses to write | The data directory is not empty | Move it aside, or restore with `--data-dir` into an empty one |
| `armadad restore` fails a check | The archive is damaged, from another version, or its master key does not match | Use another archive; nothing was changed |
| Nodes do not reconnect after a restore | The new server has another private IP | Restore onto a machine with the old server's private IP |
| `VolumeFailoverFailed: ...; trying again in 5m0s` | No backup yet, no node with room or allowed by placement, or the bucket refuses | Read the message; `armada volume snapshot list`; `armada node top` |
| `VolumeBackupFailed` | The bucket refuses the node's address or the key, or is full | Check the URL secret and the bucket's policy; old backups stay as they were |
| `armada volume restore --node` is refused | The old node is still connected | Wait until it is lost, or delete it with `armada node delete --force` if it is gone for good |

More in [troubleshooting](troubleshooting.md).

## Next steps

- [Monitoring and alerts](monitoring-and-alerts.md): alerts on stale backups and lost nodes.
- [App with a database](app-with-a-database.md): the database this guide backs up.
- [Operations guide: backup and restore](../operations.md#backup).
- [`volumes[].backup`](../spec-reference.md#volumesbackup) in the spec reference.

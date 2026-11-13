# Run an app with a PostgreSQL database

You will run PostgreSQL as an app next to your API, in the same space:
its data on a volume, reachable only by the API over private TCP, backed up
to an S3-compatible bucket every hour, and brought back on another node by
itself when its node is lost. At the end you rehearse a restore, and you
learn when a database is better kept outside the cluster.

**You will use:** [volumes](../spec-reference.md#volumes) with
[`owner`](../spec-reference.md#volumes),
[internal TCP ingress](../operations.md#tcp-apps-inside-the-cluster),
[`ingress.allow`](../spec-reference.md#ingress),
[secrets](../cli/armada-secret.md),
[volume backups](../spec-reference.md#volumesbackup) with
`failover: restore`, and
[`armada volume snapshot`](../cli/armada-volume.md#armada-volume-snapshot).

**Before you start:**

- A running cluster created with the cluster network
  (`armadad init --cluster-cidr`, see the [quickstart](../quickstart.md)):
  internal TCP apps need it.
- At least two nodes, if you want failover to have somewhere to go.
- An S3-compatible bucket, and an access key that may read, write, list,
  and delete in it. The bucket must accept connections from your nodes'
  addresses: backups leave each node from its own address, not through the
  cluster network.
- The right to create a space (`space-creator` or `cluster-admin`).

## The setup

```
                 internet
                    |
          https://api.shop.<root domain>
                    |
   space shop     v
  +----------------------------------------------+
  |   api (2 replicas)                           |
  |      |                                       |
  |      |  db.shop.internal:5432 (TCP)          |
  |      v                                       |
  |   db (1 replica, postgres:17)                |
  |      volume "data" on its node  ---------+   |
  +------------------------------------------|---+
                                             | every hour, encrypted,
                                             v only new chunks
                                    S3-compatible bucket
```

The database is an app like any other. Three things make it a database:

- A **volume** keeps its files across restarts, deploys, and reboots. A
  volume lives on one node, so the app runs exactly one replica there.
- **`protocol: tcp`** makes it reachable as plain TCP at
  `<name>.<space>.internal:<port>` from apps of its space, and from
  nowhere else: not from the internet, not from the nodes' addresses.
- **`backup`** on the volume copies it off the node, so losing the node does
  not lose the data.

## 1. Create the space

A space gives the apps their own namespace and keeps their containers
away from other spaces, the nodes, and the private network.

```bash
armada space create shop
armada space use shop      # the commands below work in shop
```

Internal names include the space outside `default`: the database will be
`db.shop.internal`. In the `default` space it would be `db.internal`.

## 2. Set the passwords

Secrets belong to one app, so each app that needs the password gets its
own copy. Generate it once and give it to both:

```bash
PASSWORD=$(openssl rand -hex 24)
printf %s "$PASSWORD" | armada secret set db postgres-password
printf 'postgres://app:%s@db.shop.internal:5432/app' "$PASSWORD" | armada secret set api database-url
unset PASSWORD
```

Values come from standard input, never from arguments, so they stay out of
your shell history. You can set secrets before the app exists; the first
deploy picks them up.

## 3. Deploy the database

```yaml
# db.yaml
name: db
image: postgres:17
env:
  - name: POSTGRES_USER
    value: app
  - name: POSTGRES_DB
    value: app
  - name: POSTGRES_PASSWORD
    secretRef: postgres-password
ingress:
  type: internal
  protocol: tcp
  port: 5432
  allow: [api]               # only the api app may connect
probes:
  readiness:
    command: ["pg_isready", "-U", "app", "-d", "app"]
    period: 10s
    timeout: 5s
resources:
  cpu: "1"
  memory: 1Gi
volumes:
  - name: data
    path: /var/lib/postgresql/data
    owner: "999:999"         # the postgres user of the image
```

```bash
armada app create --file db.yaml --wait
```

Why each part matters:

- **`owner`.** A new volume belongs to root with mode 0700. The postgres
  image runs the server as uid 999, so the volume's directory is handed to
  `999:999` every time a replica starts. The files inside are left alone.
- **`allow: [api]`.** Without `allow`, every app of the space may connect.
  With it, the proxy closes connections from anyone else at once. Add the
  name of every app or job that needs the database, a migration job for
  example.
- **No `scale`.** An app with a volume on its node runs exactly one replica;
  `scale` may only say `min: 1` and `max: 1`.
- **The readiness probe** runs `pg_isready` inside the container, so the
  replica only counts as ready once PostgreSQL accepts connections, not
  just once the port is open.

Check it:

```
$ armada app show db
Name:     db.shop
Revision: db.shop--r1
Image:    postgres:17
Ready:    1/1
Ingress:  internal
URLs:     tcp://db.shop.internal:5432

REPLICA               REVISION     NODE   STATE    RESTARTS  ADDRESS           MESSAGE
db.shop-r1-x7k2p      db.shop--r1  node2  running  0         10.120.2.14:5432  -
```

```
$ armada volume list
APP      VOLUME  NODE   PATH                      USED    LAST BACKUP  BACKUPS  AGE
db.shop  data    node2  /var/lib/postgresql/data  46.3Mi  -            -        1m
```

The volume now lives on `node2`, and the app always runs there.

## 4. Deploy the API

```yaml
# api.yaml
name: api
image: ghcr.io/acme/api:1.4.2
env:
  - name: DATABASE_URL
    secretRef: database-url
ingress:
  type: external
  port: 3000
probes:
  readiness:
    path: /healthz
scale:
  min: 2
```

```bash
armada app create --file api.yaml --wait
```

The API reaches the database at `db.shop.internal:5432`, the host in its
`DATABASE_URL`. Every node's proxy listens for it on the node's container
bridge, so the connection never leaves the node unless the database
replica runs elsewhere, and then it crosses the cluster network.

Connections through the proxy close after an hour with no data in either
direction, and connections opened before a proxy reload close at most an
hour after it. Configure your connection pool to use TCP keepalives or to
reconnect.

## 5. Back the volume up to a bucket

Create two more secrets on `db`: the bucket's URL with its access key, and
an encryption key.

```bash
printf %s 'https://ACCESS_KEY:SECRET_KEY@s3.example.com/acme-backups/armada?region=eu-central-1' \
  | armada secret set db backup-url --no-rollout
openssl rand -base64 48 > backup-key.txt
armada secret set db backup-key --from-file backup-key.txt --no-rollout
```

The URL is path-style: `https://ACCESS_KEY:SECRET_KEY@host[:port]/bucket[/prefix][?region=R]`.
`http://` is accepted only for a private IP address.

**Store `backup-key.txt` outside the cluster** (a password manager, a vault)
and then delete the local file. The backups are encrypted with it, and
without it nobody, you included, can read them after losing the cluster.

Now add `backup` and `failover` to the volume in `db.yaml`:

```yaml
# db.yaml
name: db
image: postgres:17
env:
  - name: POSTGRES_USER
    value: app
  - name: POSTGRES_DB
    value: app
  - name: POSTGRES_PASSWORD
    secretRef: postgres-password
ingress:
  type: internal
  protocol: tcp
  port: 5432
  allow: [api]
probes:
  readiness:
    command: ["pg_isready", "-U", "app", "-d", "app"]
    period: 10s
    timeout: 5s
resources:
  cpu: "1"
  memory: 1Gi
volumes:
  - name: data
    path: /var/lib/postgresql/data
    owner: "999:999"
    backup:
      every: 1h
      keep: {hourly: 24, daily: 7, weekly: 4}
      urlSecretRef: backup-url
      keySecretRef: backup-key
      stop: true
    failover: restore
```

```bash
armada app update db --file db.yaml --wait
```

What these fields do:

- **`every: 1h`** backs the volume up an hour after the last success. Use
  `schedule: "0 3 * * *"` with `timeZone` instead to back up at fixed times.
- **`keep`** keeps the newest backup of each of the last 24 hours, 7 days,
  and 4 weeks. A backup any rule keeps stays; the rest are deleted after
  each new backup.
- **`stop: true`** stops the database while the volume is read, so the copy
  is consistent. Without it, PostgreSQL may write files while they are being
  copied, and a database restored from such a copy may not start. The cost
  is a short outage on every backup: the whole volume is read each time
  (only new chunks are uploaded), so the pause grows with the size of the
  database. Time one with `armada volume snapshot create` (below) before
  choosing `every`.
- **`failover: restore`**: see step 7.

Each backup uploads only chunks the bucket does not hold yet, compressed
and encrypted with your key. The repository is
`<prefix>/db.shop/data/` in the bucket. Both secrets stay out of the
database's environment, even with `envFrom: secrets`.

The first backup runs within about a minute of the update. A failed backup
is tried again after 5 minutes.

## 6. Look at the backups

```
$ armada volume list
APP      VOLUME  NODE   PATH                      USED    LAST BACKUP  BACKUPS        AGE
db.shop  data    node2  /var/lib/postgresql/data  1.2Gi   12m ago      31 (1.9Gi)     14d
```

`BACKUPS` is how many backups the bucket holds and how much they take
together. `LAST BACKUP` ends in `, failing` while backups fail.

```
$ armada volume snapshot list db data
ID                                    TIME                 AGE
20261110T030000.412Z-5c0e9a1b         2026-11-10 10:00:00  1d
20261111T010000.087Z-a41f77d0         2026-11-11 08:00:00  3h
20261111T020000.233Z-0b9d2e64         2026-11-11 09:00:00  2h
20261111T030000.951Z-e7c41a08         2026-11-11 10:00:00  1h
```

Take one now, before a risky change such as a major upgrade or a large
migration:

```
$ armada volume snapshot create db data
Backed up volume data of db.shop as 20261111T041503.120Z-9f3a1c2e: 1287 files, 1.2Gi, 3.4Mi new; the bucket holds 32 backups in 1.9Gi.
```

Watch backups with metrics and events rather than by looking:

- `armada_volume_backup_failing` is 1 while backups of a volume fail, and
  `armada_volume_backup_last_success_timestamp_seconds` tells you how old
  the newest one is. Alert on both (see
  [Monitoring and alerts](monitoring-and-alerts.md)).
- `armada app events db` shows `VolumeBackupFailed` once when backups start
  failing, with the reason.

## 7. Failover when the node is lost

With `failover: restore` on every volume of the app, losing the database's
node no longer leaves it down until you act:

1. A node that cannot reach the control plane for half the node-lost
   timeout stops the database itself. A node that is only cut off, and still
   reachable by clients, stops writing before a copy starts anywhere else.
2. Once the node is `lost` (after `--node-lost-timeout`, 5 minutes by
   default), the leader picks another node the app may run on, restores the
   latest backup there, binds the volume to that node, and starts the app.
   A `VolumeFailedOver` event names the node and the backup.
3. If that fails (no backup yet, no node with room, the bucket refuses), a
   `VolumeFailoverFailed` event says why, and it is tried again every 5
   minutes.

Writes since the last backup are lost when the database moves: with
`every: 1h`, up to an hour of them. When the old node comes back, its copy
of the volume stays on its disk, untouched and unused.

One consequence to plan for: the database also stops when its node cannot
reach the control plane because the control plane is down. Apps without
failover keep running then. Run three control plane servers if that
matters to you.

## 8. Rehearse a restore

A backup you have never restored is a hope, not a backup. Rehearse on a
second cluster, such as a staging cluster, so the drill cannot touch
production:

1. In the bucket, create an access key that may only **read and list**.
   The drill cluster then cannot write or prune the production backups: its
   own scheduled backups fail, and a failed backup deletes nothing.
2. On the drill cluster, create the same space and app name, since the
   repository's path in the bucket comes from them (`db.shop`):

   ```bash
   armada space create shop
   armada space use shop
   openssl rand -hex 24 | armada secret set db postgres-password
   printf %s 'https://READONLY_KEY:READONLY_SECRET@s3.example.com/acme-backups/armada?region=eu-central-1' \
     | armada secret set db backup-url
   armada secret set db backup-key --from-file backup-key.txt   # the same key, from where you keep it
   armada app create --file db.yaml --wait
   ```

   The app starts with an empty database, which creates the volume on a
   node. `armada app events db` shows `VolumeBackupFailed`: that is the
   read-only key doing its job.
3. Restore the newest production backup:

   ```bash
   armada volume snapshot list db data
   armada volume restore db data --snapshot latest
   ```

   ```
   Restored volume data of db.shop on node1 from backup 20261111T030000.951Z-e7c41a08.
   ```

   The database is stopped while the files are written and started again
   afterwards. A broken backup leaves the volume as it was.
4. Check the data:

   ```bash
   armada app exec db -- psql -U app -d app -c 'select count(*) from orders'
   ```

   The restored database keeps the production password: the one you set for
   the drill only mattered for the empty database.
5. Delete the drill: `armada app delete db --yes`, then
   `armada volume delete db data --yes`.

Write down how long step 3 took. That is roughly how long a restore will
take on the day you need one.

To restore production itself, to undo a bad migration for example, run the
same `armada volume restore db data --snapshot ID` on the production
cluster. The database is down while it runs, and everything written after
that backup is gone.

## Check that it works

- `armada app show db` shows `Ready: 1/1` and the URL
  `tcp://db.shop.internal:5432`.
- `armada app exec api -- nc -zv db.shop.internal 5432` succeeds, if the
  API's image has `nc`. From an app not in `allow`, the connection is
  closed at once.
- `armada volume list` shows a recent `LAST BACKUP` and a growing
  `BACKUPS` count.
- `armada volume snapshot list db data` lists backups at the interval you
  chose.

## Variations

**A database dump instead of a stopped copy.** If no outage per backup is
acceptable, leave out `stop`, and dump the database from inside it on a
schedule, for example with a [scheduled job](scheduled-jobs.md) that runs
`pg_dump` against `db.shop.internal` and uploads the file itself (add the
job's name to `allow`). For an occasional copy to your own machine:

```bash
armada app exec db -- pg_dump -U app -d app > app-$(date +%F).sql
```

**Backups at fixed times.** Replace `every` with a schedule:

```yaml
    backup:
      schedule: "30 2 * * *"
      timeZone: Asia/Jakarta
      keep: 14
      urlSecretRef: backup-url
      keySecretRef: backup-key
      stop: true
```

**Recovering by hand.** Without `failover`, an app whose node is lost for
good stays down until you restore it elsewhere:

```bash
armada node delete node2 --force
armada volume restore db data --snapshot latest --node node3
```

This is refused while the old node is still connected.

## When to keep the database outside the cluster

A database as an Armada app is simple and cheap, and right for many apps.
Its limits come from the volume:

- **One replica, one node.** There is no replication. A deploy, a restart,
  or a backup with `stop` is downtime: the old replica stops before the new
  one starts.
- **Failover loses recent writes**: everything since the last backup.
- **Backups are file copies.** They need `stop: true` or a dump to be
  consistent, and every backup reads the whole volume.
- **No quota.** The volume grows until the node's disk is full; alert on
  `armada_volume_used_bytes`.

Keep the database outside the cluster when you need a standby that takes
over within seconds, no data loss on a node failure, point-in-time
recovery, or more disk than one node has. Run it on machines of its own or
use a hosted database, and give the app its URL as a secret as above.

From inside the cluster, mind network isolation: containers of every space
except `default` cannot reach the nodes' private network. A database on a
private address is only reachable from apps in `default` (while its network
isolation is off), and a database outside reaches every space over its
public address, so use TLS and a password there.

## Troubleshooting

| What you see | Why | What to do |
| --- | --- | --- |
| The database keeps restarting; its logs say `Permission denied` on `/var/lib/postgresql/data` | The volume belongs to root without `owner` | Set `owner: "999:999"` and update the app |
| Create or update refused for `protocol: tcp` | The cluster has no cluster network | TCP apps need a cluster created with `armadad init --cluster-cidr` |
| The API cannot resolve `db.internal` | Outside `default` the name includes the space | Use `db.shop.internal` |
| The API's connections are closed at once | The API is not in the database's `allow` | Add its name to `ingress.allow` |
| Connections drop after an idle hour, or after a deploy of another app | Idle TCP connections close after an hour; connections from before a proxy reload close within an hour of it | Use TCP keepalives or reconnect in the pool |
| `LAST BACKUP` says `failing`; `VolumeBackupFailed` event | Wrong URL or key in `backup-url`, the bucket refuses the node's address, or the bucket is full | Read the event's message, fix the secret or the bucket; the next try is within 5 minutes |
| `VolumeFailoverFailed` | No backup yet, no other node with room or allowed by placement, or the bucket cannot be read | Read the message; it is tried again every 5 minutes |
| `VolumeUnavailable` and the database is down | Its node is lost and the volume has no `failover` | Restore with `--node` (see Variations) |

## Next steps

- [Migrations and sidecars](migrations-and-sidecars.md): run schema
  migrations before the API starts.
- [Scheduled jobs](scheduled-jobs.md): dumps and maintenance on a schedule.
- [Disaster recovery](disaster-recovery.md): the control plane's own
  backups, and coming back after losing a server.
- [Monitoring and alerts](monitoring-and-alerts.md): alerts on backups and
  disk use.
- Reference: [`volumes`](../spec-reference.md#volumes),
  [`volumes[].backup`](../spec-reference.md#volumesbackup),
  [`armada volume`](../cli/armada-volume.md),
  [ADR 0041](../adr/0041-volume-backups.md).

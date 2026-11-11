# 0041. Scheduled volume backups to object storage

- Status: Accepted
- Date: 2026-11-11

## Context

A volume lives on one node (ADR 0023). `armada volume backup` streams a
tar of it to the person who asks, and nothing else keeps a copy: if the
node's disk dies, the data since the last manual backup is gone. Backups
have to run by themselves, leave the node, and be cheap enough to keep many
of them: a full copy every hour of a 2 GiB volume, kept for a day, is
48 GiB in the bucket.

## Decision

A volume names an S3-compatible bucket, a schedule, and how many backups
to keep. The volume's node writes deduplicated, encrypted backups there;
the leader schedules them and records the outcome.

```yaml
volumes:
  - name: data
    path: /data
    backup:
      every: 1h                    # or schedule: "0 2 * * *" (+ timeZone)
      keep: 24                     # or {last: 3, hourly: 24, daily: 7, weekly: 4, monthly: 6}
      urlSecretRef: backup-url     # https://KEY:SECRET@host[:port]/bucket[/prefix][?region=R]
      keySecretRef: backup-key     # at least 32 bytes; encrypts the backups
      stop: false                  # true: the app is stopped while its volume is read
```

### Spec

- `every` (5 minutes to 7 days) or `schedule` (cron, with `timeZone`, as
  jobs, ADR 0019); one of them.
- `keep`: a number keeps that many of the latest backups. The long form
  keeps the latest `last`, and the newest backup of each of the latest
  `hourly` hours, `daily` days, `weekly` ISO weeks, and `monthly` months
  (in `timeZone`, else UTC); a backup kept by any rule stays. Each count is
  at most 1000 and at least one is set.
- `urlSecretRef` and `keySecretRef` name secrets of the app; revisions pin
  them like every secret (ADR 0006).
  - The URL is `https://` (or `http://` only for a private address), with
    the access key and secret key as user and password, the bucket as the
    first path segment, an optional prefix after it, and `region` as a
    query parameter. Path-style requests, so any S3-compatible store works.
  - The key is any value of at least 32 bytes. **Whoever loses it loses the
    backups**: Armada keeps it only as the app's secret, so it must be kept
    elsewhere too, to restore after losing the cluster.
  - Neither secret reaches the app's containers: `envFrom: secrets` leaves
    them out, like registry and file secrets. They are decrypted only into
    the request to the volume's node and never logged.

### Format

Each volume has a repository of its own under
`<prefix>/<app ID>/<volume>/` in the bucket:

- `config`: version, a random repository ID, and a check value that tells
  a wrong key from a damaged repository. Not encrypted, no secrets.
- `chunks/<2 hex>/<64 hex>`: file contents, cut into chunks at
  content-defined boundaries (a gear rolling hash, 512 KiB to 8 MiB,
  about 2 MiB on average), so an insertion into a file moves no other
  boundary. A chunk's name is the HMAC-SHA-256 of its plaintext; a chunk
  already in the bucket is never uploaded again. Each is compressed (zstd),
  then sealed with AES-256-GCM under a random nonce, with its name as
  additional data.
- `snapshots/<UTC time>-<random>`: one per backup, sealed the same way (its
  name as additional data): the tree (names, types, modes, owners, times,
  link targets) and each file's chunk names.

Keys come from the key secret through HKDF-SHA-256, salted with the
repository ID: one for sealing, one for chunk names, one for the chunk
boundaries' gear table. Without the key the bucket shows only how many
chunks there are and their sizes; chunk names reveal nothing about content
to someone without it. Standard library primitives only (`crypto/aes`,
`crypto/cipher`, `crypto/hmac`, `crypto/hkdf`, `crypto/rand`).

### Backing up

- The leader checks every 30 seconds which volumes are due (`every` after
  the last success, or the schedule's last fire since then) and, when the
  volume's node is connected and its agent announces
  `Hello.volume_backups`, sends it a `VolumeRequest` (`OP_SNAPSHOT`) with
  the decrypted URL and key. A volume's first backup waits until its node
  has reported the volume's directory (its size, measured every minute).
  At most one backup per volume runs, and at most one scheduled backup per
  node at a time. A failed backup is tried again after 5 minutes, or the
  interval when shorter.
- The agent walks the volume (regular files, directories, and links;
  sockets, devices, and pipes are left out, as `armada volume backup`
  does), uploads the chunks the repository lacks, then writes the snapshot.
  Only after the snapshot is written does it apply `keep`: snapshots no rule
  keeps are deleted, then chunks no kept snapshot names and older than an
  hour (a backup still uploading is never cut short). A failed backup
  deletes nothing; its chunks are reused by the next one.
- `stop: true` stops the app's container while the volume is read (the
  pause of ADR 0023). Without it, files written during the backup may be
  copied half-written: databases should use their own dump.
- The outcome is kept on the volume's record: last success, last error,
  bytes stored in the repository, and how many backups it holds.
  `armada volume list` shows them; a failure is a `VolumeBackupFailed`
  condition (one event until a backup succeeds again). Metrics:
  `armada_volume_backup_last_success_timestamp_seconds`,
  `armada_volume_backup_stored_bytes`, `armada_volume_backup_snapshots`,
  and `armada_volume_backup_failing`.

### Restoring

- `armada volume snapshot list APP VOL` lists a volume's backups (ID and
  time); `armada volume snapshot create APP VOL` takes one now and says
  what it held and added.
- `armada volume restore APP VOL --snapshot ID|latest [--node N]` restores
  one on the volume's node (or binds the volume to `N`, refused while the
  old node is connected, as with an archive). The agent downloads and
  checks every chunk (the seal and its name), writes into a sibling
  directory, and swaps it in only when everything was written, with the
  app stopped, as with an archive.
- Repository operations go to the volume's node. When it is not connected,
  listing goes to any connected node that backs volumes up, and restoring
  with `--node` to that node.

### Failover

`failover: restore` on every volume of an app (each needs `backup`) makes
the app come back by itself when the node holding its volumes is lost:

```yaml
volumes:
  - name: data
    path: /data
    backup: {every: 1h, keep: 24, urlSecretRef: backup-url, keySecretRef: backup-key}
    failover: restore
```

- **Fencing first.** Replicas of such apps carry a fence time, half the
  node-lost timeout (`ReplicaSpec.fence_after_seconds`, also a container
  label, outside the spec hash). An agent that has had no session with the
  control plane for that long stops them, also after its own restart before
  any assignment, and starts them again at once when it is back in touch.
  A node that is only cut off, and still reachable by clients, therefore
  stops writing before the leader restores the volume anywhere else.
- **Restore elsewhere.** Once the node is lost (`--node-lost-timeout`,
  with more nodes ready than lost, as for any rescheduling, ADR 0008), the
  leader picks a node the app may run on, with room, whose agent backs
  volumes up, restores each volume's latest backup there, and binds the
  volumes to it (audited as `armada:failover`); the app then starts there.
  A `VolumeFailedOver` event names the node and the backups. If the old
  node reconnects before the volumes are bound, nothing is bound.
- **Failures** (no backup yet, no node fits, the bucket refuses) are a
  `VolumeFailoverFailed` condition and are tried again every 5 minutes. The
  app stays down meanwhile, as without failover.
- **When the old node returns**, its replica is no longer assigned and is
  removed. Its copy of the volume stays in its volumes directory, untouched
  and unused.

## Consequences

- Backups reach the bucket from the node's own address, not through the
  cluster network; the bucket must accept it.
- Up to one interval of writes can be lost when a node dies.
- A volume is read whole on every backup (only new chunks are uploaded):
  the time a backup takes grows with the volume, not with what changed.
- The key protects the backups only as well as the app's secrets: whoever
  may read the app's secrets may read its backups.
- Deleting a volume does not delete its repository; it stays in the bucket
  until removed there.
- A bucket that fills up or refuses writes fails backups without touching
  the backups already there.
- With `failover: restore`, writes since the last backup are lost when the
  app moves, and the app stops on its node whenever that node cannot reach
  the control plane for half the node-lost timeout, also when it is the
  control plane that is down. Apps without failover keep running then.

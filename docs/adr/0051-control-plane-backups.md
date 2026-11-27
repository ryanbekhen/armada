# 0051. Scheduled control plane backups to object storage

- Status: Accepted
- Date: 2026-11-21

## Context

`armadad backup -o FILE` writes a consistent archive of a control plane
server, and `armadad restore FILE` brings it back (see the operations
guide). Nothing runs it: operators write a timer, pipe the archive through
an encryption tool, and copy it off the machine themselves. Each archive
is a full copy, and it holds the CA key and the master key, so a copy that
is left unencrypted anywhere gives the cluster away.

Volumes already back themselves up to an S3-compatible bucket, encrypted
and deduplicated, on a schedule the leader keeps (ADR 0041). The control
plane can use the same repository format.

## Decision

The leader backs the control plane up to a bucket on a schedule the
cluster's settings hold, and `armadad restore` restores from the bucket.

```bash
armada cluster set --backup-url url.txt --backup-key key.txt \
  --backup-every 1h --backup-keep last=24,daily=7,weekly=4
armada cluster set --backup-schedule "0 3 * * *" --backup-time-zone Asia/Jakarta
armada cluster set --backup none
```

### Settings

- They live in the meta record `control-plane-backup`, beside the other
  cluster settings (ADR 0031), set through `SetClusterConfig`
  (cluster-admin only, audited as `cluster.backup`): `set_backup_plan`
  (`backup_every_seconds`, or `backup_schedule` with `backup_time_zone`),
  `set_backup_keep` (`BackupKeep`), `set_backup_url`, `set_backup_key`, and
  `set_backup_off`. No restart: a change wakes the leader's loop.
- When and what to keep are checked exactly as a volume's `backup` is:
  `every` 5 minutes to 7 days, or a five-field
  cron schedule in a time zone; `keep` a number of the latest backups, or
  `last`, `hourly`, `daily`, `weekly`, `monthly` (each at most 1000, at
  least one).
- The bucket URL (`https://KEY:SECRET@host[:port]/bucket[/prefix][?region=R]`,
  `http://` only for a private IP address, never loopback, link-local,
  unspecified, or multicast) and the key (at least
  32 bytes) are read by the client from a file (mode `0600`) or stdin, never
  from an argument, and sealed with the master key like the DNS token
  (scope `cluster`, names `backup-url` and `backup-key`, versioned). They
  are never logged, audited, put in events, or returned: the configuration
  shows only the endpoint, bucket, and prefix. Turning backups on needs all
  of them; `--backup none` forgets the URL and the key, and the bucket
  keeps what it holds.

### Backups

- Every server's configuration knows how to write its
  own backup: it stages the files
  `armadad backup` puts into an archive (the checked etcd snapshot, the
  master key, the CA, the server certificate and key, the node identity,
  and the manifest) as plain owner-only files into a temporary directory
  inside the data directory, which is removed afterwards.
- The leader's `control_plane_backup_loop` runs once at the start of its term,
  every `Config.BackupInterval` (30 s) after, and when the settings change.
  It runs one backup at a time and stops with the term, so only the leader
  writes; a backup cut short by a lost leadership records nothing. A backup
  is due on the plan after the last success, and after a failure no later
  than min(5 minutes, `every`).
- The files go into a volume backup repository (ADR 0041: content-defined chunks
  named by HMAC, zstd, AES-256-GCM, keys through HKDF from the key salted
  with the repository's ID) at `<prefix>_control-plane/`. App IDs never
  hold an underscore, so the repository never meets a volume's
  (`<prefix><app ID>/<volume>/`), whose pruning lists only its own root.
  The etcd snapshot changes little between backups, so most chunks are
  already in the bucket.
- After a backup the repository is pruned with the keep policy (counted in
  the time zone); chunks are deleted only after every kept snapshot was
  read, and never when younger than an hour.
- The snapshot's manifest names the server it was taken on. Each server's
  backup holds its own server certificate, so a restore brings that server
  back, with its private IP.

### Visibility

- The meta record `control-plane-backup-state` keeps the last success (time,
  ID, server, bytes of its files, what the repository holds) and the last
  failure with its message. It counts only for the settings' URL and key
  versions: a new bucket or key starts afresh and backs up at once.
- A failure starts the condition `ControlPlaneBackupFailed` (kind
  `cluster`, object `control-plane`): one event until a backup works again,
  then a resolved notice; alert channels get it by default (ADR 0045).
- `armada cluster status` shows the bucket, the last backup, the next one,
  and the last error; `armada cluster show` the settings.
- Metrics (ADR 0017): `armada_control_plane_backup_last_success_timestamp_seconds`,
  `armada_control_plane_backup_last_size_bytes`, and the counter
  `armada_control_plane_backup_failures_total` (since the leader's term
  began).

### Restore

- `armadad backup list --backup-url FILE --backup-key FILE` lists the
  snapshots with their time, server, and size.
- `armadad restore --backup-url FILE --backup-key FILE [--snapshot ID|latest]`
  restores one into an empty data directory. Both flags read a file or `-`
  for stdin (one of them). The snapshot's files go through the same checks
  as an archive (one restorer, shared by both): only known names and
  regular files, the size limits, every checksum in the manifest, the CA,
  the server certificate, the snapshot opened as state this version
  understands, the master key against the state; nothing reaches the data
  directory unless all of it verifies. Every chunk is also checked against
  its name.
- The flag names are those of `armada cluster set`, so the same two files
  serve both.

### Compatibility

No record changes, so no schema bump: the settings and the state are new
meta records. A leader of an older version ignores them and backs nothing
up until it is upgraded; `armada cluster status` of an older leader shows
no backups.

## Consequences

- A cluster backs itself up, off its machines, without a timer or an
  encryption tool, and a backup takes little room in the bucket.
- Whoever holds the bucket and the key holds the cluster: the snapshots hold
  the CA key and the master key. The key exists only in the cluster's
  state (sealed) and wherever the operator keeps it; lose both and the
  backups cannot be read. The access key should be limited to the bucket,
  and versioning or object lock keeps backups from someone who holds it.
- The leader reaches the bucket from its own address. The bucket on a
  private address is a cluster-admin's choice, as everything in
  `cluster set` is.
- Each backup checks its snapshot in a scratch etcd member on the leader,
  as `armadad backup` does: a backup that could not be restored fails at
  once, at the cost of a short burst of work.
- Restore still needs a machine with the backed-up server's private IP.

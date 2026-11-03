# 0025. Persistent volumes

- Status: Accepted
- Date: 2026-11-03

## Context

A replica's container starts from its image every time: anything it writes
is gone when the container is recreated by a deploy, a crash, or a reboot.
Apps that keep state, such as a database, a queue, or an upload directory,
need a directory that outlives their containers. The spec format had no
way to ask for one.

## Decision

An app may list volumes. Each is a directory on the node that runs the
app's replica, created on first use, bound to that node, and mounted into
the container at the same path on every start.

### Spec

```yaml
volumes:
  - name: data
    path: /var/lib/postgresql/data
    owner: "999:999"   # optional: uid:gid of the directory when created
```

- **Entries.** At most 8. A name is a name like an app's, unique within the
  app. The path follows the rules for secret file paths: absolute, clean,
  not `/`, nothing under `/proc`, `/sys`, or `/dev`, and none of the files
  the runtime writes. Volume paths may not overlap each other or a secret
  file.
- **Owner.** `uid:gid`, numbers from 0 to 2³¹−1, applied to the volume's
  directory (not its contents) whenever a replica starts, so an owner added
  later applies too. Without it a new directory belongs to root. The
  directory is mode 0700, so an image that runs as another user names its
  owner. An agent run by a user (macOS nodes, ADR 0016) cannot give files
  away and skips it; there the driver's file sharing decides ownership.
- **One replica.** An app with volumes runs exactly one replica: its
  `scale` may only say `min: 1` and `max: 1`, with no rules. Scale to zero,
  multiple revision mode, and jobs with volumes are rejected. Two containers
  never write the same volume.
- **No host paths.** A volume is always a directory Armada creates under
  its own data directory; a spec cannot mount an arbitrary host path.

### Binding to a node

- **Where data lives.** On a node, volume `NAME` of app `APP` is
  `<data dir>/volumes/APP/NAME` (`/var/lib/armada/volumes/...` on Linux).
  The parent directories are mode 0700 and owned by root.
- **First placement.** The first replica is placed like any other, among
  nodes that can mount volumes. Creating that replica writes a volume
  record bound to its node in the same transaction (`volumes/<app>/<name>`
  in etcd). From then on every replica of the app goes to that node, and
  the store refuses one on any other.
- **Nodes that can mount volumes.** The agent announces it in `Hello` when
  its runtime can and it has a volume directory. The embedded runtime can.
  External drivers declare `CAPABILITY_VOLUMES` (`driverkit.VolumeMounter`),
  and the conformance suite checks that a volume is the host directory,
  writable, and still `nosuid` and `nodev` in the container when its
  source is on a filesystem with those flags, as the agent's is. A node without it is never
  chosen for an app with volumes.
- **Kept.** A volume stays when the app is redeployed without it, or
  deleted, until `armada volume rm`. Redeploying an app with the same name
  and volume uses the same data on the same node.

### Behaviour

- **Recreate rollouts.** A deploy stops the old replica (it is drained and
  removed) before the new one starts on the same node. The app is down from
  the end of the old replica's drain until the new one is ready. A rollout
  that makes no progress is aborted as usual (ADR 0005), and the serving
  revision is started again.
- **Cordoned nodes.** Cordoning a node does not move an app whose volumes
  are on it, and the app may restart there. A `VolumeOnCordonedNode` event
  says so.
- **Lost nodes.** If the node holding an app's volumes is lost or removed,
  the app stays down: its data is on that node. A `VolumeUnavailable` event
  says so. The app comes back when the node does, or when a backup is
  restored onto another node.
- **Removing a node.** `armada node rm` refuses a node that holds volumes
  unless `--force` is given. With `--force` the volume records stay, still
  bound to the removed node, so a backup can be restored elsewhere.
- **Rebalancing and evacuation** never move an app with volumes.
- **Mount.** When the agent starts it mounts its volume directory
  (`<data dir>/volumes`) onto itself with `nosuid` and `nodev`, unless its
  filesystem already has both; if it cannot, the node announces no
  volumes. A bind mount keeps the flags of the mount it comes from, so
  every volume is `nosuid,nodev` in its container whatever the runtime, and
  drivers can bind the directory as it is. Each volume is bind mounted
  read-write, and the embedded runtime also sets `nosuid` and `nodev` on
  its own mount. With SELinux, the embedded runtime relabels it to the
  container's MCS label on every start, so only that container can use it.

### Usage

- **Measured, not limited.** The agent adds up the size of the files in
  each volume once a minute and reports it with its usage samples. The
  leader keeps the latest measurement in memory only, like other usage
  (ADR 0018).
- **Shown.** `armada volume ls` lists volumes with their node, path, and
  size, and `armada_volume_used_bytes{app,volume,node}` is on the metrics
  endpoint.
- **No quota.** A volume can fill its node's disk. Operators watch the
  metric.

### Backup, restore, and removal

- **Backup.** `armada volume backup APP NAME -o FILE [--stop]` streams a
  gzipped tar of the volume from its node through the leader to the CLI,
  the way logs and exec are routed (ADR 0017). By default it is taken while
  the app runs. With `--stop` the agent stops the app's container for the
  backup and starts it again afterwards. The archive keeps owners, modes,
  times, and symbolic links, and leaves out sockets, devices, and pipes.
- **Restore.** `armada volume restore APP NAME FILE [--node N]` streams an
  archive to the volume's node.
  - The agent stops the app's container and unpacks the archive into a new
    directory next to the volume. It then swaps the two, so a broken
    archive leaves the volume as it was.
  - It accepts only directories, regular files, and symbolic links, with
    relative names that stay inside the volume, and never writes through a
    link.
  - With `--node`, the archive is restored onto that node, the volume is
    bound to it, and the app follows. This is refused while the volume's
    current node is connected, so two copies are never both written.
- **Removal.** `armada volume rm APP NAME --yes` deletes the data on the
  node, then the record. It is refused while the app's spec, or any of its
  replicas, still mounts the volume. When the volume's node was removed
  from the cluster, only the record goes.
- **Control plane backups.** `armada backup` holds volume records but not
  their contents. Volume data is backed up with `armada volume backup`.
- **Records.** Backups, restores, binds, and removals are audited and
  recorded as events. Only admin certificates can use these RPCs.

### State schema

The schema moves to 5 with no rewrite. Servers that would start a replica
without its volume, or on another node, can no longer lead (ADR 0012).

## Alternatives considered

- **Host paths in the spec**: they would let any spec author mount any
  directory of a node, including Armada's own keys, into a container.
- **Several replicas sharing a volume**: most stateful software does not
  support two processes writing one data directory, and failures would
  corrupt data quietly.
- **Rolling updates with surge**: the new replica would start while the old
  one still writes the volume.
- **Moving data automatically when a node is lost**: the data is only on
  that node. Copying it in advance means replication, which belongs to the
  app (a database's own replicas) or to network storage.
- **Backups through the agent's own listener**: a new network port on every
  node. Routing through the leader reuses the existing mTLS streams and the
  admin's identity.

## Consequences

- Stateful apps run on Armada, one replica each, tied to a node. Their
  availability is that node's.
- Deploys of such apps have downtime: the old replica's drain plus the new
  one's start.
- Losing a node loses its volumes' data since the last backup. Operators
  schedule `armada volume backup` (for example from cron outside the
  cluster) or use the app's own replication.
- External drivers that do not declare `CAPABILITY_VOLUMES` run no apps
  with volumes.

# 0042. NFS volumes

- Status: Accepted
- Date: 2026-11-11

## Context

A volume is a directory on one node (ADR 0023). That binds the app to the
node and to a single replica, and a deploy stops the old replica before
the new one starts. Some data has to be shared instead: uploads that every
replica of a web app serves, or files several apps read.

## Decision

A volume may name an NFS export instead of being a directory on the node:

```yaml
volumes:
  - name: uploads
    path: /app/uploads
    nfs:
      server: 10.0.0.20        # a private IP address
      path: /exports/uploads
      readOnly: false
```

- **Spec.**
  - `server` is an IP address in a private range (10/8, 172.16/12,
    192.168/16, 100.64/10, or fc00::/7). Host names, loopback, link-local,
    and public addresses are refused, so the spec cannot point nodes at
    anything outside the private network.
  - `path` is absolute and clean, made of letters, digits, `.`, `_`, `-`,
    and `/`, at most 256 characters.
  - `owner`, `backup`, and `failover` are refused: ownership and backups
    belong to the server. Exports must be NFSv4.
- **Not bound to a node.** An app whose volumes are all NFS volumes is
  placed, scaled, autoscaled, and rolled out like any other: any number of
  replicas, rolling updates, rebalancing, and evacuation. A node-local
  volume next to an NFS volume keeps ADR 0023's rules for the whole app.
  NFS volumes have no record and do not appear in `armada volume list`.
- **Nodes.** Agents announce `Hello.nfs` when the volumes directory works
  and the kernel has an NFSv4 client (loaded, or a module). Apps with NFS
  volumes are placed only on such nodes. `armadad doctor` reports the check
  as `nfs`.
- **Mounting.**
  - The agent mounts each export once per node and volume at
    `<data dir>/nfs/<app ID>/<volume>` (a 0700 mount point under 0700
    directories). It calls the kernel's NFSv4 client directly, with no
    helper program: `nosuid`, `nodev`, `hard`, TCP, version 4.2, then 4.1,
    then 4.0.
  - On SELinux hosts the mount gets the `container_file_t:s0` context, so
    the app's containers may use it. The runtime does not relabel it, since
    other replicas share it.
  - Each replica bind-mounts it (`rbind`, `nosuid`, `nodev`, and `ro` with
    `readOnly`), and so do the init containers and sidecars that name it.
  - The agent checks the server, path, app ID, and volume name again before
    mounting. A mount that does not finish within two minutes fails the
    start, which is retried with crash backoff.
- **Who may add an export.** Nodes mount exports from their own
  addresses, so the NFS server cannot tell spaces apart. Adding an
  export to an app, or making one writable, needs cluster-admin; a deploy
  that keeps the exports the app's serving or rolling-out revision already
  mounts (or makes one read-only) needs only the right to deploy the app.
- **Unmounting.** An export no replica on the node names any more is
  unmounted, lazily, so containers still using it keep it, and its mount
  point is removed. A spec that changes the export or `readOnly` remounts
  it.

## Consequences

- Data shared between replicas needs the app's own care for concurrent
  writes (locks, unique file names); NFS does not order them.
- File ownership and permissions are the server's: containers act on the
  export with their own user and group IDs (`AUTH_SYS`). Servers usually
  map root to an anonymous user (root squash).
- A `hard` mount makes processes wait while the server is away instead of
  failing their writes; they continue when it is back. A server that is
  gone for good leaves those processes waiting until the replica is
  replaced.
- The nodes reach the server from their own addresses, not through the
  cluster network, and Armada's firewall does not stand between them: the
  server's exports and firewall decide which nodes may mount what.
- Exports are reached by address only (`AUTH_SYS`, no Kerberos): once a
  cluster-admin gives an app an export, the export is that app's to read
  and write, whatever the server's own users and groups say.

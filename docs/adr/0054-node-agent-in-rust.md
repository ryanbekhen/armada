# 0054. armada-node does the node's work

- Status: Accepted
- Date: 2026-11-23

## Context

Every machine of a cluster runs Armada's node agent: it holds the session
with the control plane, starts and watches containers, renders HAProxy's
configuration, sets up the cluster network and its firewall, serves exec,
logs, and volume sessions, and reports usage. Much of that work touches
the kernel, the file system, or the network of a container directly, and
some of it must run as a process of its own: a mount that never returns
must not hold the agent, an exec becomes the OCI runtime, and a dial must
start inside a container's network namespace.

Three parts of the node already run as small programs of their own, with
the standard library only: `armada-log` (ADR 0011, 0043, 0044),
`armada-shim` (ADR 0046), and `armada-dns` (ADR 0053).

## Decision

The node's work is `armada-node` (`node/`, crate `armada-node`): a program
shipped in the runtime pack and also a library the agent (`agent/`) links.

### What it does

- **Images and root filesystems:** pulls (HTTPS only, registry
  credentials only for the registry they name, every layer checked
  against its diff ID), the image store under `<data dir>/node/images`
  (`index.json`, `content/blobs`, `layers/<chain ID>`, `active/<key>`),
  unpacking with whiteouts as overlayfs reads them, prunes, and the
  overlay root filesystems of containers (`runtime pull|images|prune|
  prepare|release|snapshots`).
- **Containers:** OCI specs and bundles (`runtime spec|bundle`), the
  shims (`runtime shim call|start|abandon`), exec sessions through the
  container's OCI runtime (`runtime exec`), statistics from cgroup files
  (`runtime stats`), and dials from a container's or sandbox's network
  namespace, the socket handed back over `SCM_RIGHTS` (`runtime dial`).
- **The cluster network:** VXLAN, kernel WireGuard over generic netlink,
  routes, the iptables chains, nftables isolation encoded by hand, the
  switch probe, unreachable peers, key rotation, and doctor's network
  checks (`net plan|apply|up|probe|unreachable|key|cache|diagnose|
  remove|firewall`). `network.key` and `mesh.json` are its files.
- **HAProxy's configuration:** `proxy render` writes `haproxy.cfg`, the
  route maps, and `local.map` from a validated proxy configuration.
- **Volumes:** archives and restores (`volume archive|restore`), sizes,
  and backups to S3-compatible buckets (`volume snapshot|prune|snapshots|
  restore-snapshot`, ADR 0041); control plane backups (ADR 0051) use the
  same repository code as a library.
- **NFS mounts** (`nfs source|mount|unmount`), **connection tracking**
  (`conntrack read|raise`), and **queue readings** from a container's
  namespace (`queue redis|rabbitmq`, ADR 0034, ADR 0040).

The agent calls the library in process for pure work (rendering, network
passes, pulls, bundles, statistics, volume archives and backups,
connection tracking). It runs the `armada-node` program where a process of
its own is the point: exec, dials and queue readings from a namespace, the
network switch's probe, and NFS mounts. Input goes over stdin or file
descriptors as JSON, never as arguments, so credentials and URLs never
show in a process list; answers are JSON, and errors never carry a
secret.

`armada-log`, `armada-shim`, and `armada-dns` stay separate programs with
the standard library only: they run once per container or must outlive
every restart, so they stay small.

### Dependencies

Unlike those three, `armada-node` uses libraries: an async runtime
(tokio), gRPC and protobuf (tonic, prost) generated from
`api/armada/v1/armada.proto`, TLS (rustls on ring), and compression
(flate2, ruzstd). Netlink, nftables, WireGuard's generic netlink, the
HTTP/1.1 client for registries and buckets, S3, and the tar reader are
written by hand. Every crate is under Apache-2.0, MIT, BSD-2/3, ISC,
MPL-2.0, CC0-1.0, or Unicode-3.0 (Unicode data), checked in CI from
`Cargo.lock` (`cargo deny`), pinned with `--locked`, and listed in
`THIRD_PARTY_NOTICES.md`, since they are linked into the program.

### Test hooks

`make node-test-hooks` builds a variant that reads `ARMADA_NODE_TEST_*`
hooks and takes `--extra-ca` for tests. It is never packed: release builds
ignore the hooks and refuse `--extra-ca`, and the agent leaves the hooks
out of armada-node's environment.

## Consequences

- No node process runs a garbage collector: memory follows what the node
  runs, with no pauses.
- Work that may hang or must run in another namespace is a process of its
  own, bounded by the caller's deadline and killed with it.
- The repository builds with libraries: their licenses are checked in CI,
  and their notices ship with every release.

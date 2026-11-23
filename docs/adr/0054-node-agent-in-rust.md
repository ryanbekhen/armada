# 0054. The node agent moves to Rust

- Status: Accepted
- Date: 2026-11-23

## Context

Every machine of a cluster runs Armada's node agent: it holds the session
with the control plane, starts and watches containers, renders HAProxy's
configuration, sets up the cluster network and its firewall, serves exec,
logs, and volume sessions, and reports usage. It is written in Go, runs in
`armadad agent` on nodes and inside `armadad server` on servers, and costs
about 125 MiB of memory on a server with etcd (measured on a production
cluster); a garbage-collected runtime sets how much of that is held and
when it is returned.

Three parts of the node already run as Rust programs: `armada-log` (ADR
0011, 0043, 0044), `armada-shim` (ADR 0046), and `armada-dns` (ADR 0053).
Each replaced a piece of Go with a program that uses less memory, keeps
its latency steady, and was checked against the Go code it replaced, byte
for byte, before the Go code stopped being used.

The goal is a node agent with no garbage collector: memory that follows
what the node runs, no pauses, and one language for everything that runs
on every machine. The agent is about 30,000 lines of Go; its control
plane counterpart (the server and its embedded etcd) is out of scope here.

What makes a gradual move possible:

- The agent talks to the control plane only over gRPC (`AgentService`:
  `Connect`, `PushLogs`, `ExecSession`, `VolumeSession`,
  `RenewCertificate`, `GetCertificates`), also inside `armadad server`:
  nothing is shared in memory. A Rust agent speaking the same protocol
  mixes with Go servers and Go agents.
- `Hello` announces what an agent can do (jobs, volumes, held replicas,
  queue sandboxes, and so on), and the leader places nothing on a node that
  did not announce it. A Rust agent that lacks a feature yet stays correct.
- Inside the agent, its parts meet at interfaces (`runtime.Driver`,
  `proxy.Driver`, the network's `Apply`, `InternalDNS`, `LogTailer`) that a
  separate process can serve.

## Decision

The node agent moves to Rust in steps, each one a release that leaves
mixed clusters working and each part checked against the Go code it
replaces before that code is removed.

### One program

The new Rust code builds one program, `armada-node` (`node/`), shipped in
the runtime pack like `armada-log`. It grows by subcommands: first the
parts the Go agent hands work to, last the agent itself (`armada-node
agent`). `armada-log`, `armada-shim`, and `armada-dns` stay separate
programs with the standard library only: they run once per container or
must outlive every restart, so they stay small.

### Dependencies

Unlike those three, `armada-node` needs libraries: an async runtime
(tokio), gRPC and protobuf (tonic, prost) generated from the same
`api/armada/v1/armada.proto`, TLS (rustls), netlink, nftables, and
WireGuard. They follow the license policy of the Go modules (Apache-2.0,
MIT, BSD-2/3, ISC, MPL-2.0, CC0-1.0, and Unicode-3.0 for Unicode data),
checked in CI from `Cargo.lock` (`cargo deny`), pinned with `--locked`,
and listed in `THIRD_PARTY_NOTICES.md`, since they are linked into the
program.

### Order

1. **The program and its checks.** `node/` with the license check, the
   build for amd64 and arm64, and its place in the runtime pack.
2. **HAProxy's configuration.** `armada-node proxy render` takes a proxy
   configuration and writes what the Go renderer writes. The renderer's
   golden files and fuzz corpus check both; the Go driver keeps running
   HAProxy and calls the program, falling back to Go while both exist.
3. **The cluster network.** `armada-node net`: VXLAN, WireGuard (kernel
   through netlink, userspace through a Rust implementation), routes,
   nftables isolation, and the iptables chains, behind the agent's
   `Network` interface. `network.key` and `mesh.json` keep their formats.
   The integration tests in network namespaces run against both.
   Status: the default since the lab end-to-end tests passed with it on
   every machine; `"netAgent": "go"` in `agent.json` keeps a node on Go's
   code while it remains. The Go agent runs `armada-node net` for its passes,
   the switch probe (beside the agent, as Go's runs), unreachable peers,
   key rotation, `armadad doctor`'s network checks, and `armadad runtime
   reset`, handing it the state Go keeps between passes and taking it
   back, and does a pass itself when armada-node fails. The userspace
   WireGuard device stays in Go for now: a pass that needs it is Go's.
   Go's code is removed after a release in which no node fell back to it.
4. **The container runtime.** The supervisor runtime in Rust: image
   pulls and layers, OCI bundles, `runc` and `armada-shim`, CNI, and
   cgroup statistics, behind the `runtime.Driver` interface. Nodes on the
   containerd runtime move to the supervisor first (`armadad runtime
   migrate`); the Rust agent supports the supervisor only. Images already
   on a node are kept where the format allows, pulled again otherwise.
   First part: `armada-node runtime spec` builds a container's OCI
   runtime spec as the Go driver does (containerd's default spec, the
   driver's options, the image's users and groups, seccomp, AppArmor),
   and `armada-node runtime check` applies `CheckContainerSpec`; no node
   uses them yet. Second part: `armada-node runtime pull`, `images`, and
   `prune` pull images into the Rust runtime's image store (below) as the
   Go driver pulls them; no node uses them yet. Third part: a pull
   unpacks every layer into `layers/<chain ID hex>/` as containerd's
   applier unpacks it for the overlay snapshotter (the first layer of a
   chain as a plain directory where whiteouts remove what they name,
   every later one as an overlay upper directory over its parents, where
   whiteouts become character devices 0/0, opaque markers the
   `trusted.overlay.opaque` attribute, and implicitly created
   directories take their parents' owner, mode, times, and attributes);
   names are resolved within the layer's directory as Go resolves them,
   and every change goes through a descriptor of its parent directory
   opened beneath that directory with no symbolic link followed, so no
   entry writes outside it. `armada-node runtime mounts` names an image's
   lower directories in overlay's order, and `runtime prune` also removes
   layers no kept image needs. On the Go side, `supervisor.ConvertImages`
   converts a supervisor store into this layout (below); nothing calls it
   yet.

### The runtime's move: image store and migration

The Rust runtime owns its own store. Every node, once upgraded, has its
images in that store and its containers run by the Rust runtime; no node
is left on Go's runtime, and moving does not pull every image again.

**The image store** lives under `<data dir>/node/images/`:

- `content/blobs/<algorithm>/<hex>`: every blob (indexes, manifests,
  configs, layers) as a plain read-only file named by its digest, the
  layout of the content store the supervisor runtime keeps today, so
  moving a blob is a hard link or a rename on the same file system, never
  a copy. A download goes to `content/ingest/` first and is renamed into
  place only once its size and digest match.
- `index.json`: one record per image name (the normalized reference):
  the target the name resolved to, the manifest chosen for the node's
  platform, its config, layers, diff IDs, and chain ID, the platforms the
  image offers, labels (`armada.pulled-with/<key>`, which say whose
  credentials the registry let read the image), and when it was pulled
  and last changed; beside the records, the layer blobs shown to
  decompress to a diff ID, so a layer is checked once per node. It is
  written whole to a temporary file and renamed.
- `layers/<chain ID hex>/`: one unpacked layer per chain ID, the
  directories overlay mounts name as lower directories (third part). A
  layer is unpacked into a directory of its own under `layers/` and
  renamed into place once it is complete and its uncompressed digest
  matches its diff ID; a chain whose directory exists is kept, its layer
  blob checked against its diff ID instead.
- `pull.lock` and `index.lock`: a pull holds the first shared from its
  first fetch to its record, a collection of unused blobs and layers holds
  it exclusively (a collection that would wait is left to the last pull
  to end); the second guards each change of `index.json`, so separate
  `armada-node` processes share the store safely.

Pulls keep every rule of the Go driver: HTTPS only (redirects and token
services included), at most 10 redirects, no connection to a link-local,
unspecified, multicast, or broadcast address, an HTTPS proxy only when the
environment names one, credentials only to the registry they were given
for, the platform chosen as Go chooses it, every blob checked against its
digest, every layer checked to decompress to its diff ID, a blob this
pull did not download used only when an image pulled with the same
credentials holds it, and a digest-pinned image on the node reused only
under the same credentials (or once the registry answered for them).

**Migration on upgrade.** The release that makes the Rust runtime a
node's runtime converts the node while Go still ships:

1. Before the runtime starts, `armadad` (Go) reads the supervisor store
   (`<data dir>/supervisor/images`: the content store, the overlay
   snapshotter's `metadata.db`, and `images.json`) and writes the Rust
   layout: blobs hard-linked into `content/`, each record converted with
   its labels, committed snapshots renamed to `layers/<chain ID hex>/`
   (same file system; a running container's overlay mount keeps the
   directories it was mounted with, since the kernel holds them, not their
   paths, until the container is recreated), and the index written last.
2. It verifies the result: every blob's digest, every record's manifest,
   config, and layers present, every chain ID's directory present. An
   image that cannot be converted (a blob or layer missing, a record that
   does not parse) is left out and pulled again when a replica needs it;
   nothing else is pulled again. Records already in the Rust store are
   kept, and what a left-out image brought along goes with the Rust
   store's next collection. `supervisor.ConvertImages` does steps 1 and
   2 and returns what it converted and what it left out, and why.
3. The old store is collected once no container uses it: running
   containers keep their root filesystems (their active snapshots) where
   they are; each one goes with its container, and the rest of
   `<data dir>/supervisor/images` goes with the last.
4. Nodes still on the containerd runtime are moved to the supervisor
   first, automatically and one node at a time: the leader drains the
   node (its replicas start elsewhere first), the node runs `armadad
   runtime migrate`, and the replicas come back, since every container on
   such a node has to be recreated. A cluster with one node waits for its
   operator.
5. Each node reports where it stands (containerd, converting, converted,
   images left to pull again), shown per node by `armada cluster status`
   and on the machine by `armadad doctor`.

Go's runtime code is removed only once every node of a cluster reports
converted; a node that has not is refused by a release without it
(`armadad upgrade` and `armadad doctor` say why).
5. **Sessions and readings.** Exec, volume archives and backups (the
   repository format of ADR 0041, which the Go control plane also writes),
   NFS mounts, queue lengths, usage, and connection tracking.
6. **The agent.** `armada-node agent`: the `Connect` session, `Hello`,
   reconciliation, probes, fencing, held replicas, jobs, init containers
   and sidecars, secret files, wake, certificates, and `agent.json`.
   Nodes run it from `armada-agent.service`; `armadad server` runs it as a
   unit of its own next to the control plane, like `armada-dns`. It is
   chosen per node (`agent.json`) until it has run one release as the
   default, then the Go agent is removed.

Each step that touches the node is tested end to end in the lab before it
is merged, and the Go code it replaces is removed only once the Rust code
has run as the default for a release.

### Not decided here

The control plane (`armadad server`, its reconcilers, and the embedded
etcd) stays in Go. Moving it is a separate decision, made after the node
agent has moved: replacing etcd changes how the cluster stores its state,
which needs its own design and a path for every existing cluster. The
`armada` client is another separate step.

## Consequences

- Every node stops running a garbage collector once step 6 is done;
  servers still run one for the control plane.
- During the move a node may run Go and Rust for the same work; each
  step's fallback to Go keeps a node working when the Rust part fails,
  until the Go part is removed.
- The repository builds Rust with libraries for the first time: their
  licenses are checked like Go modules, and their notices ship with every
  release.
- Contributors need Rust for the node and Go for the control plane and the
  client until those move too.
- New features for the node during the move are written once, in the
  language of the part they touch; parts that have moved are not changed
  in Go any more.

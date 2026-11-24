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
   yet. Fourth part: the container lifecycle under the Go driver, opt-in
   per node with `"runtimeAgent": "rust"` in `agent.json` (supervisor
   nodes only; never the default in this part). The driver keeps
   everything above its backend: it builds each container's spec, runs
   its network, logs, and exec, and reads its statistics. armada-node
   pulls and prunes images (`runtime pull`, `prune`), makes and removes
   containers' root filesystems on its layers (`runtime prepare`,
   `release`: `active/<container ID>/` with `fs/`, `work/`, and
   `snapshot.json` naming the layers, made and mounted as the overlay
   snapshotter makes them, and kept from collection while they stand),
   writes, lists, relabels, and removes bundles (`runtime bundle`: the
   files and bytes `supervisor.Bundles` writes, under the same
   directory), and sends every request to `armada-shim`, starting and
   abandoning shims as `supervisor.Shims` does (`runtime shim`: the same
   unit, `systemd-run` arguments and limits, and rules for when a shim is
   gone). Bundles, records, shim sockets, and runc's state are Go's, so a
   node switches either way and adopts the containers the other made;
   each side removes the other's root filesystem of a container it
   deletes. Go does a bundle or shim call armada-node fails; image and
   root filesystem calls have no Go fallback, since the stores differ,
   and a node whose pack has no armada-node stays on Go's code. Images
   on a node that opts in are pulled again into armada-node's store
   (`ConvertImages` runs with the release that makes it the default), and
   Go's image store is opened beside it only to release the root
   filesystems of containers Go made. Fifth part, on the same opt-in:
   statistics and dials from containers. The agent samples every
   replica of a round in one call (`runtime.StatsBatcher`; `armada-node
   runtime stats`): for each container its record, its shim's state, its
   cgroup v2 files, and `/proc/PID/net/dev`, a replica's init containers
   and sidecars added, with the numbers Go computes. A container Go would
   answer with an error, or whose shim Go would find gone (and then end
   its containers), is answered "redo" and sampled by Go, so errors and
   what is done about a gone shim stay Go's. Queue readers dial from a
   container's or a sandbox's network namespace through `armada-node
   runtime dial`: Go checks the address and picks the socket's family as
   its dialer does, keeping zones, service names, and a family the
   network does not take; armada-node, single-threaded, switches into the
   namespace (not when it already is in it), makes and connects the
   socket with Go's options, and sends it back over `SCM_RIGHTS` on a
   Unix socket the agent passes as descriptor 3; the agent wraps it with
   `net.FileConn`, which sets what its dialer sets (no delay, keepalive),
   and rebuilds a failure as its dialer words it (`net.OpError` with the
   system call and errno). Go dials or samples itself when armada-node
   fails. Sixth part, on the same opt-in: exec. `armada app exec`,
   command probes, `queue` rules, and the exec into system containers
   start `runc exec` through `armada-node runtime exec`, which then
   becomes runc. The agent makes the streams as before (the caller's
   FIFOs, or a pseudo-terminal whose other end it keeps) and starts
   armada-node with them as its standard streams and, with a terminal,
   as its controlling terminal in a session of its own; the request
   (the container's bundle, the exec's directory, runc and its root, and
   the arguments, terminal, and size the exec sets) comes on descriptor
   3, never on the command line. armada-node reads the container's
   process spec from its `config.json`, writes `process.json` as Go
   writes it (the container's process with those three fields replaced,
   the other fields kept as their bytes, json.Marshal's field order and
   omissions; 0600 in a 0700 directory), writes `exec` on descriptor 4,
   which closes on exec, and replaces itself with `runc exec` and Go's
   arguments. From then on the process the agent started is runc, so
   waiting, exit codes (a signal as 128 plus its number), kills, the
   terminal and its size changes, the drain of output after the process
   ends, and cleanup are the agent's own code on the same process, and
   runc gets the same streams, descriptors, session, signal mask, and
   environment as when Go starts it. (Step 5's last part replaced this
   start with the whole session in armada-node.) A runc that cannot be
   run is answered with its errno and becomes Go's error for it; a
   failure before that (no answer, an unreadable answer, a `config.json`
   or a directory that cannot be read or written) is redone by Go on the
   same streams, the failures of armada-node logged once per distinct
   error and counted (`StoodIn("exec")`). Nothing armada-node answers
   names the command's arguments or the environment. Seventh part: the
   default. A supervisor node runs its containers through armada-node
   whenever the pack has it; `"runtimeAgent": "go"` in `agent.json`
   keeps Go's code while it remains (any other value, or none, is
   armada-node; containerd nodes are not affected). The agent's start
   moves the images (steps 1 to 3 and 5 below; the leader moves
   containerd nodes, step 4), and
   `ConvertImages` no longer counts a record already in armada-node's
   store as left out.

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
   The root filesystem of every container that exists (its active
   snapshot, running or not) moves too, renamed into armada-node's
   `active/<container ID>/` with the `snapshot.json` its prepare writes,
   so no container restarts.
2. It verifies the result: every blob's digest, every record's manifest,
   config, and layers present, every chain ID's directory present. An
   image that cannot be converted (a blob or layer missing, a record that
   does not parse) is left out and pulled again when a replica needs it;
   nothing else is pulled again. Records already in the Rust store are
   kept, and what a left-out image brought along goes with the Rust
   store's next collection. `supervisor.ConvertImages` does steps 1 and
   2 and returns what it converted and what it left out, and why.
3. The old store is removed once no container uses it, which after step 1
   is at once: a container whose root filesystem could not move keeps it
   until the container goes.
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

How steps 1 to 3 and 5 are built (the seventh part of step 4 above):

- Only the agent's start moves images (`containerd.Config.Agent`), never
  a command that opens the runtime beside a running agent, such as
  doctor. With armada-node, `supervisor.MoveImages` runs before either
  store is opened: `ConvertImages`, then the root filesystems
  (`moveActive`), then `<data dir>/node/converted.json` (0600: when,
  images converted, images left out with why, layers and root
  filesystems moved, containers left with why, and whether Go's store is
  gone), then the removal of Go's store, then the record again with
  `collected`. A node with no Go store gets a record at once. A
  conversion that fails is logged, the node runs on armada-node anyway
  (images it needs are pulled), and the next start tries again.
  `<data dir>/node` is not in `armadad backup`.
- `moveActive` takes every bundle (`<data dir>/supervisor/containers`)
  whose container ID is an active snapshot in Go's overlay snapshotter.
  Its layers not in `layers/` yet move there from their committed
  snapshots; `snapshot.json` (`{"image", "parents"}`: the bundle's image
  and the chain ID hexes, the top first) is written into the snapshot's
  directory; the directory (`fs/`, `work/`) is renamed to
  `active/<container ID>/`, the key armada-node's prepare and release
  use for that container. A running container's overlay mount holds its
  upper, work, and lower directories, not their paths, so it reads and
  writes on through the renames; nothing else names them: the bundle's
  `config.json` names its `rootfs` mount point, which does not move, and
  `bundle remove` unmounts by it, after which armada-node's `release`
  removes the directory like one it prepared (it keeps the layers a
  `snapshot.json` names from collection). Crash safety needs no journal:
  every step is found done by looking (a layer in `layers/`, a snapshot
  directory gone from Go's store and present under `active/`), a
  `snapshot.json` written before a rename that did not happen is written
  again, and a record without `collected` repeats the root filesystems
  and the removal at the next start. A container whose layer is in
  neither store keeps Go's store (named in the record and the log).
- Go's store is opened only when it is left, to release the root
  filesystems of containers Go made. After each release, and at the
  agent's start, it is removed whole once the record exists and no
  bundle has its root filesystem in it (a moved one is under `active/`;
  `Store.CollectGo`).
- A node sent back to Go's code (`"runtimeAgent": "go"`) runs
  `supervisor.RevertImages` at the agent's start. With Go's store gone
  (the usual case), nothing comes back: Go pulls into a new store, the
  containers made before keep running from armada-node's store, and Go
  removes their root filesystems with them (`Store.NodeImages`). With
  Go's store still there, every committed snapshot whose directory left
  gets it back from `layers/`, every active snapshot of Go's metadata
  whose directory is under `active/` is renamed back (its
  `snapshot.json` removed), armada-node's records of images whose layers
  left are dropped (a later move converts them again), snapshots whose
  layers are in neither store are removed with the records of the images
  on them (Go pulls those again). The record is removed either way.
- Each agent reports how its node runs containers in every usage report
  (`UsageReport.runtime`, `RuntimeStatus`: `containerd`,
  `supervisor-go`, or `supervisor-rust`, whether anything of Go's store
  is left, images left out and not pulled again yet, and a conversion's
  error), read by the runtime through `runtime.AgentReporter`; older
  agents send none. The leader keeps the latest in memory with the
  node's usage (bounded: unknown runtimes dropped, errors cut and
  cleaned), shows it in `NodeStatus.runtime` (`armada node show`) and
  sums it in `ClusterStatusResponse.runtime` (`armada cluster status`:
  `runtime: 3 of 4 nodes on armada-node; lab4 on containerd`, at most 20
  others named). A node counts as moved once it runs on armada-node with
  nothing of Go's store left and no image to pull again. `armadad
  doctor`'s `runtime-agent` check says the same on the machine.

How step 4 is built (the leader moves containerd nodes):

- **Who moves, and when.** Only the leader, from its reconcile pass
  (`advanceRuntimeMove`, `internal/server/runtimemove.go`), and only nodes
  whose agent reported `containerd` in its latest usage report and
  announced `Hello.runtime_move` (an agent whose runtime is containerd
  sets `agent.Config.MoveRuntime`; older agents are never asked and wait
  for their operator: "upgrade it"). One node moves at a time, and none
  starts while a node is away or lost or a network switch runs (the
  status names the reason, `held`). Workers go first, then servers, the
  leader's own machine last (`moveOrder`: by `store.Server.PrivateIP`, the
  leader by its name); by name within each. A move that ends starts the
  next one only in the next pass, which sees the moved node take replicas
  again.
- **Nodes that wait for their operator.** The cluster's only node that
  takes replicas (a cluster of one node, or every other node cordoned):
  draining it would stop everything. A node holding local volumes (ADR
  0023: an app with volumes runs only on its volume's node, so draining
  never moves it, and the move would stop the app until its containers come
  back): it is skipped, not moved with downtime; the operator moves it by
  hand (or moves the volume first with `armada volume restore --node`).
  These say so in `armada cluster status` and the node's doctor. Nodes that
  wait for the move to come round: those the other nodes have no room for
  (`roomFor` places each of the node's replicas, job attempts aside, on the
  other eligible nodes with `pickNodeBy`, as the scheduler would), those
  not ready or not connected, and those whose last move was given up (for
  `Config.RuntimeMoveBackoff`, an hour).
- **The record.** Meta key `runtime-move` (`runtimeMoveRec`): `off` (the
  setting), the move under way (`node`, `step`, `since`, `stepSince`, Unix
  milliseconds), and `givenUp` (node → when and why). The pass and
  `SetClusterConfig` change it under `Server.moveMu`; only the leader
  writes it, through its fenced store. A new leader reads it and carries on
  from the step its predecessor reached.
- **Draining.** The node under move is marked cordoned in the pass's copy
  of the nodes (`cordonMoving`, right after `ListNodes`), never in its
  record: every scheduling path sees a cordoned node, so no replica is
  placed there and its replicas are replaced elsewhere and retired without
  dropping below the serving count (the normal cordon path), while an
  admin's cordon in the record stays as it is and the move never has to
  lift one. Job attempts are not moved: the step waits for them to end.
  The step ends when no replica but finished job attempts is left on the
  node (`migrating`), or after `Config.RuntimeDrainLimit` (15 minutes),
  when the move is given up. Turning the move off in this step ends it,
  and the node takes replicas again.
- **Migrating.** Once the record says `migrating`, the leader sends the
  node `ServerMessage.move_runtime` (`MoveRuntime{to: "supervisor"}`) on
  its session after the pass's assignments, so the agent holds the
  assignment without the replicas first, and again every 30 seconds and on
  every new session until the node moves (`askToMove`; memory only, so a
  new leader asks again). The agent (`internal/agent/runtimemove.go`)
  runs one move at a time: under `reconcileMu`, so nothing starts, it
  refuses when it has no assignment yet, when a replica other than a
  finished job attempt is assigned, or while a volume operation runs; the
  refusal, or the move's own error, goes in `RuntimeStatus.move_error` of
  its next usage reports, which the leader shows. Otherwise, before taking
  `reconcileMu` (so the node's proxy keeps following the cluster), the
  agent runs `Config.PrepareRuntimeMove` (`nodeMove.prepare`): while
  containerd still runs everything, the node's HAProxy included, the
  pack's armada-node pulls the pinned HAProxy image (`haproxy.Image`, by
  digest, no credentials) into armada-node's store
  (`<data dir>/node/images`) with the same call the supervisor runtime's
  `Driver.Pull` makes (`pullIntoNode` → `supervisor.Native.Pull`,
  `runtime pull ROOT`), bounded by `prePullTimeout` (5 minutes) within the
  move's `moveRuntimeTimeout` (10 minutes). The restarted agent's pull of that digest-pinned
  reference then finds a record pulled by anyone and asks no registry
  (the pulled-with rule), and nothing at the agent's start touches that
  store on a node with no Go image store (`MoveImages` only writes its
  record), so the node's own address is down only for the restart, the
  first assignment, and the proxy's start. Nothing is pulled when the
  node will not run containers through armada-node (`runtimeAgent: "go"`,
  a pack without it) or runs no proxy; a failed pull is logged and the
  move goes on, the restarted agent pulling the image itself. Replicas'
  images are not pulled ahead: none is assigned by then, and they come
  back through rebalancing. Then, under `reconcileMu` and checked again,
  the daemon's hook (`nodeMove`, `internal/daemon/runtimemove.go`) does what `armadad
  runtime migrate --to supervisor` does (`migrateRuntime`, shared with the
  command): every container and network sandbox Armada runs, the node's
  HAProxy included, is removed from containerd, `agent.json` records
  `runtime: supervisor`, containerd's unit stops, and the node's own unit
  restarts (`systemctl --no-block restart armada-server` on a server
  machine, `armada-agent` elsewhere). Only the runtime field changes, in
  `agent.json` as it is on disk then (`updateAgentConfig`: read, change,
  write, in order within the process), never the copy the agent started
  with: every writer of a running node's `agent.json` (the control plane
  list, the network's mode, the runtime, `armadad endpoint set`) changes
  only its own fields that way. systemctl ended by systemd's stop of the
  unit (SIGTERM or SIGKILL) is the restart itself; any other failure makes
  the process exit, and the unit's `Restart=always` starts it again. The data
  containerd left in `<data dir>/containerd` stays, as with the command.
  The agent that starts runs containers on the supervisor runtime through
  armada-node (the seventh part of step 4) and reports `supervisor-rust`.
- **Done or given up.** The move is done when the node reports either
  supervisor runtime (`RuntimeMoveDone`; the node takes replicas again,
  and rebalancing brings replicas back to it), also when an operator moved
  it by hand meanwhile. It is given up when the node does not report the
  supervisor within `Config.RuntimeMigrateLimit` (10 minutes) of the step,
  with the node's own `move_error` as the reason when it gave one, or when
  the node is removed. A given-up node takes replicas again at once, stays
  on containerd, and is tried again after the backoff; the condition
  `RuntimeMoveGivenUp` (an alert warning) says why until it moves. The move
  never leaves a node out of service: the cordon is the record's, and it
  ends with the move.
- **Events.** `RuntimeMoveStarted`, `RuntimeMoveDraining` (when the node
  holds replicas), `RuntimeMoveMigrating`, `RuntimeMoveDone`, and
  `RuntimeMoveGivenUp`, each about the node.
- **Server machines.** A server's agent runs inside `armada-server`, so
  moving the machine restarts its control plane: its etcd member, and on
  the leader's machine the leadership, which costs one election (there is
  no handover; the leader's machine moves last, and the new leader carries
  on from the record, waiting for the old one's report). A server
  machine's agent starts with `agent.json`'s control plane list followed by
  every server's API address the state records (`knownServers`), so it
  finds the new leader even when its saved list names only its own
  machine, whose standby control plane serves no API. One machine moves
  at a time, so a cluster of three servers keeps its quorum; one of two
  servers loses it for the seconds a server restarts, as with any restart,
  and a cluster's single server leaves the API down for those seconds while
  containers on other nodes keep running and serving.
- **The ingress gap.** The node's HAProxy is one of the containers removed
  in the migrating step and is started again once the agent runs on the
  supervisor runtime, its image pulled into armada-node's store. Until
  then, connections to that node's public address fail. The node holds no
  replicas by then, so traffic arriving through the other nodes is not
  affected; a load balancer or DNS record that sends clients to every
  node's address should health-check the nodes (operations guide).
- **Setting.** `armada cluster update --runtime-move=false` turns the move
  off (`SetClusterConfigRequest.set_runtime_move` with
  `ClusterConfig.runtime_move_off`, cluster-admin only like every cluster
  setting, audited as `cluster.runtime_move`), `=true` on again; on is the
  default. `armada cluster show` prints it.
- **Status.** `ClusterStatusResponse.runtime_move` (`RuntimeMoveStatus`:
  off, the node, step, and times of the move under way, the node's
  `move_error`, the cluster's `held` reason, and the waiting containerd
  nodes with their reason and whether they wait for their operator, at
  most 20), worked out by each pass and kept in memory
  (`Server.moveSeen`); unset when no node runs on containerd and none
  moves. Each containerd node whose agent announced the capability gets
  its own plan in `Assignment.runtime_move` (`RuntimeMovePlan`: queued,
  moving, waiting with the reason and whether it waits for its operator,
  or off); the agent writes it to `<data dir>/runtime-move.json` (0600,
  not backed up), and doctor's `runtime-agent` check on a containerd node
  says what the cluster will do with the node and why, and how to move it
  by hand.

Removing Go's runtime code comes next.
5. **Sessions and readings.** Exec, volume archives and backups (the
   repository format of ADR 0041, which the Go control plane also writes),
   NFS mounts, queue lengths, usage, and connection tracking.
   First part, the readings, on the runtime's knob (a supervisor node
   whose pack has armada-node, unless `"runtimeAgent": "go"`; containerd
   nodes keep Go's code), with Go doing a call armada-node fails (logged
   once per distinct failure, counted with `StoodIn`):
   - Connection tracking: `armada-node conntrack read|raise` reads the
     table's use and limit and raises the limit to the node's target,
     never lowering it, as `internal/conntrack` does (same files, same
     error texts). `armadad doctor` still reads it in Go.
   - NFS mounts: `armada-node nfs mount` checks the export's server and
     path again and mounts it as the agent does (`nfs4`, nosuid and
     nodev, read-only when asked, hard over TCP, 4.2 then 4.1 then 4.0
     on `EPROTONOSUPPORT` or `EINVAL`, the SELinux context when SELinux
     is on, bounded by the start's two minutes); `nfs source` reads
     `/proc/self/mountinfo` for what is mounted on a volume's mount
     point and whether it is read-only, and `nfs unmount` detaches it.
     Two readings differ from the Go code they replaced, which was fixed
     alike: a mountinfo escape is decoded only as the kernel writes it (a
     backslash and three octal digits; anything else is kept, never half
     decoded), and the read-only flag's statfs is bounded (10 seconds,
     then "does not answer"), since a hard mount whose server is gone
     never returns.
     The agent keeps deciding what to mount and where.
   - Queue lengths: `armada-node queue redis|rabbitmq` reads a Redis
     list's length (RESP, AUTH and SELECT, replies of at most 512 bytes)
     or a RabbitMQ queue's ready messages (an AMQP 0-9-1 handshake and a
     passive Queue.Declare, written by hand as amqp091-go speaks it: the
     same URL rules, mechanisms, negotiated limits, and the same failure
     reported as the same error, except where amqp091-go reads a URL or a
     failure wrongly, which `internal/queuelen` now reads as armada-node
     does: a URL with no host is not valid (never localhost), a user
     without a password logs in with an empty password (never "guest"),
     an unknown `auth_mechanism` is the URL's mistake and a broker
     offering none of the URL's mechanisms says so, and a refused
     Connection.Open is the virtual host's; the one difference left is a
     broker closing Connection.Open with 403, which only armada-node can
     tell from refused credentials. A Redis URL with a user and no
     password authenticates as that user with an empty password, as the
     common clients do, on both sides), over TLS with the machine's roots for
     `rediss://` and `amqps://`, from inside the replica's or the job
     sandbox's network namespace as `runtime dial` enters it. The URL,
     which holds the broker's credentials, comes on stdin with the
     reading, never on the command line, and no answer repeats it or
     anything the broker sent. A broker named by a name is resolved by
     Go first, from the same namespace through the containers'
     nameserver as before, and its addresses are passed along;
     armada-node leaves a reading to Go only for a name with no
     addresses, an address with a zone, or a shim that is gone. `queue`
     rules stay an exec. Why a reading failed (a fixed text, never the
     URL) is logged by the agent once per change and, for a job's queue
     trigger, reported to the leader (`SandboxQueue.error`), which records
     `QueueReadFailed` while it lasts.
   Second part: volume archives, the default on every node whose pack
   has armada-node (`"volumeAgent": "go"` in `agent.json` keeps Go's
   code while it remains). `armada-node volume archive DIR` writes a
   volume as the gzipped tar the agent sends (the tar Go's archive/tar
   writes for the same tree, byte for byte: USTAR while every field fits,
   PAX records otherwise, times rounded to the second; the gzip around it
   is the Rust library's, so the compressed bytes differ), walking it as
   `volbackup.Walk` does: every lookup beneath the volume's directory
   (openat2 `RESOLVE_BENEATH`, as Go's `os.Root` resolves), every entry
   opened without blocking and refused unless it is the entry just looked
   up, errors naming the entry quoted. `armada-node volume restore DIR`
   reads a gzipped tar and restores it as `restoreArchive` does, with the
   same refusals, the reserve of free space, and the swap of a new
   directory on success; Go's gzip and tar readers are followed where
   they decide what is accepted (a gzip trailer is checked only when a
   read reaches it, which a restore that stops at the tar's end never
   does). `armada-node volume size DIR...` measures volumes for usage
   reports in one call. The agent keeps the volume session, the pause and
   resume of the app, and the 64 KiB messages: it copies the program's
   output to the session and the session's data to its input. A failure
   of the session is handed to the restore on descriptor 4 before its
   input ends, so the restore fails where Go's reader would have, rather
   than taking an early end for the archive's end. Go does a call itself
   when armada-node fails before the stream is touched: an archive before
   it wrote a byte, a restore before Go handed it one (it says "ready"
   first), and a size; past that, the bytes cannot be had again and the
   failure is the call's.
   Third part: volume backups to S3-compatible buckets (ADR 0041), on the
   same knob as archives. `armada-node volume snapshot`, `prune`,
   `snapshots`, and `restore-snapshot` do what volbackup's Backup, Prune,
   Snapshots, and Restore do, in the same repository: the same `config`,
   keys derived with HKDF-SHA-256 salted with the repository's ID, the
   same keyed gear table and so the same chunk boundaries and names
   (HMAC-SHA-256 of the plaintext) for the same content, chunks and
   manifests compressed with zstd and sealed with AES-256-GCM under
   their object's name, and manifests as Go's encoding/json writes them;
   either side reads, restores, and prunes what the other wrote. The
   bucket is reached by a client of its own: path-style requests signed
   with Signature Version 4 from the URL's static keys, Content-MD5 on
   writes, ListObjectsV2, the bucket's region asked once when the URL
   names none, the retries of the Go client, plain HTTP only for the
   private addresses ParseTarget allows, TLS with the machine's roots
   otherwise, never a proxy from the environment, and every address
   dialled refused when it reaches the node itself. The request, with
   the URL and the key, is read on stdin, never from the command line,
   and no answer or log line repeats them. The agent keeps the
   per-volume lock, the pause and resume of the app, and the session; a
   restore names the snapshot it will restore (`latest` resolved) before
   the agent pauses the app, then waits for it. The keep policy's time
   zone reaches armada-node as Go's offsets from UTC and the times they
   start (1900 to 2300), so no zone database is read. armada-node says
   "touched" before its first write to the bucket or the volume; Go does
   a call itself when armada-node failed before that, never after. The
   control plane's backups (ADR 0051) stay with the control plane, in
   Go. Usage sampling (`runtime stats`) moved with step 4.
   Last part: exec's sessions, on the runtime's knob, for every exec
   the driver runs (`armada app exec`, command probes, `queue` rules,
   and the exec into system containers). The agent keeps the gRPC
   session, auditing, its limits, and the caller's context; it hands
   `armada-node runtime exec` the request on descriptor 3 (never on the
   command line), a control socket on descriptor 4, and a pipe for each
   stream the caller has (input on 5, output on 6, error output on 7).
   armada-node writes `process.json` as before, starts `runc exec`
   with Go's arguments on pipes of its own or on a pseudo-terminal it
   makes as Go does (runc's controlling terminal in a session of its
   own, sized before the start), and says "spawned". From then on it
   does what Go's process and drain did: it copies the caller's input
   to runc (its end closes runc's pipe, or is an end-of-transmission
   character on a terminal) and runc's output to the agent's pipes,
   which are the output's activity; it reads the pid file as the
   start's wait does (ten seconds at most), changes the terminal's size
   and kills the process and runc when the agent asks, waits for runc
   (a signal as 128 plus its number), keeps copying a terminal's output
   while it moves (two seconds of quiet end it, even while a child
   holds the terminal), removes the exec's directory, says "exit" with
   the code, keeps copying the output while it moves (the drain's grace)
   and says "drained". The agent keeps the timers that belong to the
   caller and words the outcome as before: the context's error before
   the exit, "exec output cut short" with the exit code when the context
   ends during the drain, the cleanup's kill and its five seconds, and
   closing the control socket, which armada-node reads as giving up:
   runc killed, nothing more copied. Go runs the session itself, with
   its own process and FIFOs, only when armada-node failed before it
   said "spawned" (logged once per distinct failure, counted with
   `StoodIn`), so no byte of the caller's has moved; after that a
   failure is the call's. Nothing armada-node answers names the
   arguments or the environment.
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

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
   Status: built, and opt-in per node with `"netAgent": "rust"` in
   `agent.json`: the Go agent then runs `armada-node net` for its passes,
   the switch probe (beside the agent, as Go's runs), unreachable peers,
   key rotation, `armadad doctor`'s network checks, and `armadad runtime
   reset`, handing it the state Go keeps between passes and taking it
   back, and does a pass itself when armada-node fails. The userspace
   WireGuard device stays in Go for now: a pass that needs it is Go's.
   It becomes the default once the lab end-to-end tests pass with it on
   every machine (`E2E_NET_AGENT=rust`).
4. **The container runtime.** The supervisor runtime in Rust: image
   pulls and layers, OCI bundles, `runc` and `armada-shim`, CNI, and
   cgroup statistics, behind the `runtime.Driver` interface. Nodes on the
   containerd runtime move to the supervisor first (`armadad runtime
   migrate`); the Rust agent supports the supervisor only. Images already
   on a node are kept where the format allows, pulled again otherwise.
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

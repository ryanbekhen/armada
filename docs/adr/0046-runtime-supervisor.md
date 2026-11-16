# 0046. Armada's own container supervisor

- Status: Proposed
- Date: 2026-11-16

## Context

Every node runs Armada's own containerd (ADR 0011): a daemon that keeps the
image store, the snapshots, and container metadata, and one runc shim per
app that is the parent of the app's containers. Measured on a
node of a three-node production cluster and in a two-node lab:

| Process | Proportional set size | Of which anonymous |
| --- | --- | --- |
| containerd | 47–54 MiB | 15 MiB |
| runc shim, per app | 6–8 MiB | 4 MiB |
| `armada-log`, per container | 0.2–0.3 MiB | 0.1 MiB |
| `armadad server` (control plane, etcd, agent) | 77–95 MiB | 21–38 MiB |

The file-backed part is the program text the kernel may drop and read again;
the anonymous part is memory the process holds. A node running four apps
spends about 30 MiB of held memory and about 50 MiB of program text on
containerd and its shims. Armada uses a small part of what containerd
offers: no CRI, no plugins, no other clients, one namespace, one
snapshotter.

What containerd does for Armada today:

1. Pulls images over HTTPS with registry credentials, keeps their content,
   and unpacks layers into overlayfs snapshots.
2. Keeps container records (spec, labels, snapshot) so the agent can adopt
   containers after it restarts.
3. Through the shim: creates containers with runc, stays their parent
   while the agent and containerd restart, collects exit codes, wires
   output to `armada-log`, runs exec processes, and stops containers.
4. Reports task state and cgroup statistics.

## Decision (proposed)

Replace containerd and its shim with two parts Armada owns, keeping runc,
the CNI plugins, tini, and `armada-log`:

- **The agent keeps images and container records itself (Go).** Pulling
  and unpacking move into the agent, through the registry and layer
  libraries Armada already depends on, into a content store and overlayfs
  layers under `<data-dir>/images`. Container records (spec, labels, root
  filesystem, log directory) are files under `<data-dir>/containers/<id>`,
  written atomically. Everything containerd's metadata held that Armada
  reads (labels such as `armada.pulled-with/<key>`, the published port, the
  role) moves there with the same meaning. Image pruning, digest checks
  against credentials, and platform detection keep their current rules.
- **`armada-shim` (Rust, standard library plus the minimum the kernel
  interface needs) supervises containers.** One process per app per node
  and runtime pack, like the shim it replaces. It is started by the agent,
  detaches from it (own session, subreaper), creates and starts containers
  with `runc create`/`runc start`, holds their output pipes and hands them
  to `armada-log`, waits for exits and keeps the exit code, runs exec
  processes with `runc exec`, and serves a small request protocol on a
  root-only Unix socket in `/run/armada/shim/`. It never reads images or
  registry credentials. When it exits, every container it supervises is
  killed, the same as a shim today; the agent recreates them like any
  crashed replica.
- **Statistics are read from cgroup files directly** by the agent, as
  containerd does today.
- `runtime.Driver` stays the interface. The new implementation lives next
  to the containerd one, and the conformance suite
  (`go test -tags integration -run Conformance`) runs against both until
  containerd is removed.

### Moving nodes

A node changes runtime only by replacing its containers: the agent records
`"runtime": "supervisor"` in `agent.json` only after it has drained and
removed every containerd container on the node and started them again
under the new runtime, one replica at a time, so an app with more than one
replica keeps serving. Upgrading a release does not do this by itself;
`armadad runtime migrate` does it, and `armadad doctor` says which runtime
a node runs. Both runtimes ship in the same releases until every supported
release has moved, then containerd leaves the runtime pack.

### Work, in order

1. `armada-shim` with runc, behind the conformance suite, in the lab only.
2. Image store and container records in the agent; the driver for the new
   runtime; adoption after an agent restart.
3. Exec, statistics, sandboxes (ADR 0040), members (ADR 0038), system
   containers (HAProxy).
4. `armadad runtime migrate`, doctor, the operations guide; end to end on
   real machines with every scenario of `test/e2e`.
5. Containerd removed from the pack after a release in which every node
   ran the new runtime.

Each step is measured against the numbers above before the next starts.
If the new runtime does not cut held memory per node by at least 20 MiB
for four apps, the work stops at that step and containerd stays.

## What stays out of scope

- The control plane (server, etcd, ACME, access control) stays in Go. Its
  held memory is mostly the Go runtime around a live heap of 7–14 MiB, and
  a lower `GOGC` (50, about 4 MiB less) addresses that without a rewrite.
- runc stays the OCI runtime: it runs only while it creates, starts, or
  execs, so it holds no memory between those calls, and replacing it would
  mean taking over the most security-sensitive code on the node.

## Alternatives considered

- **Keep containerd.** No work and no risk; the 30 MiB per node and the
  program text stay.
- **A Rust OCI runtime library instead of runc.** Removes the runc calls,
  but brings namespaces, seccomp, and AppArmor/SELinux setup into code
  Armada would own, for no gain in held memory.
- **One supervisor per node instead of one per app.** Less memory still,
  but a crash or upgrade of that one process would end every container on
  the node; one per app keeps the blast radius where it is today.
- **Rewrite the whole of Armada in Rust.** The memory that matters is
  held by containerd and the shims, not by Armada's own code, and the
  control plane depends on etcd, which has no equivalent of the same
  maturity.

## Consequences

- Armada owns image pulling and unpacking, which containerd's maintainers
  own today, including its security fixes.
- Two runtimes ship side by side for a while, and the conformance suite
  and end-to-end tests run against both.
- `ctr` can no longer inspect a node's containers once it moved; `armada`
  and `armadad doctor` are the interface.

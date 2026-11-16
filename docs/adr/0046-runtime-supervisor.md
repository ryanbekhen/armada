# 0046. Armada's own container supervisor

- Status: Accepted (experimental)
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

## Decision

Nodes can run containers without containerd, on the **supervisor**
runtime, chosen per node (`--runtime supervisor` on `armadad init`, `join`,
and `server join`, recorded as `"runtime"` in `agent.json`). It is
experimental: the embedded containerd stays the default. runc, the CNI
plugins, tini, and `armada-log` are the same on both.

- **The agent keeps images and container records itself (Go,
  `internal/runtime/supervisor`).** Pulling and unpacking run in the agent
  through containerd's own libraries, with no daemon: a content store, the
  overlay snapshotter, and the layer applier under
  `<data-dir>/supervisor/images`, at most two blobs fetched at once
  (pulling three images peaks at a 10 MiB heap and leaves 3 MiB). Images
  are recorded in `images.json` with their labels (`armada.pulled-with/<key>`
  keeps its meaning, and a name pulled again to another target starts
  with none); a layer already unpacked is reused for a new image only
  once its blob is shown to decompress to the image's diff ID, as with
  containerd (ADR 0011). Removing an image removes the layers and blobs no
  other image uses, once no pull is running (the last pull to end does
  it otherwise). Each container is an OCI bundle under
  `<data-dir>/supervisor/containers/<id>`: its root filesystem mounted from
  a snapshot, `config.json`, and `record.json` (labels, image, shim group),
  written last.
- **`armada-shim` (Rust, standard library only, `shim/`) supervises
  containers.** One per app and runtime pack on a node (the group the spec
  annotation names), started by the agent as a transient systemd unit
  (`armada-shim-<hash>`): `armada-server` stops every process it started
  when it restarts, a unit of its own does not. It is the child subreaper
  of its containers, creates and starts them with `runc create`/`runc
  start`, hands their output to `armada-log` as containerd's shim does,
  keeps exit codes until delete, and answers one line per connection on a
  0600 socket in `/run/armada/shim/` (`create`, `start`, `state`, `wait`,
  `kill`, `kill all`, `delete`, `list`). It exits 10 seconds after its last
  container is gone, removing its socket and state. It never reads images
  or credentials. It refuses a process ID of 0 or 1 from runc's pid file
  (and deletes a container whose pid file it cannot read), and keeps at
  most 4096 exit codes nobody asked for, never dropping a container's
  own. The unit runs with the limits of `armada-runtime.service`
  (`OOMScoreAdjust=-999`, `LimitNOFILE`, `LimitNPROC`, `LimitCORE`, and
  `TasksMax` unlimited), which its containers inherit. Before the agent
  starts a group's shim, containers a shim that ended left in runc's state
  are killed and deleted, so they end with their shim as on containerd, and
  the agent starts them again. A shim counts as ended only when nothing
  listens on its socket or its unit is no longer active: one that is slow
  or busy (a timeout, a closed connection) keeps its containers, and the
  agent asks again on its next pass. Starting and abandoning a group's
  shim are serialized per group, so two callers never start two shims or
  abandon one that was just started.
- **The driver is shared.** `internal/runtime/containerd` reaches
  containers, tasks, and images through a `backend` interface; the
  supervisor offers containerd's client types (`Container`, `Task`,
  `Process`, `Image`), so networking, host files, SELinux labels, ports,
  logs, init containers, sidecars, and system containers are one code path.
  Exec runs `runc exec` from the agent in the foreground (a pseudo-terminal
  the agent holds for `-t`, so size changes reach the process); statistics
  are read from the container's cgroup files. The conformance suite runs
  against both.
- **The runtime pack carries `armada-shim`.** On a supervisor node the
  agent installs the pack itself at start, so an upgrade brings the new
  shim and runc; `armadad runtime` installs it and exits instead of
  starting containerd.

### Moving nodes

A node changes runtime by replacing its containers: drain it, stop its
service, run `armadad runtime migrate --to supervisor` (or `--to embedded`),
which removes every container Armada runs there from the current runtime,
records the new one, and stops containerd when leaving it; then start the
service and resume the node, which pulls its images again. The command
refuses while the agent runs. Upgrading a release never changes a node's
runtime.

### Measured

In a two-machine lab with the supervisor and no containerd process, the
conformance suite and the end-to-end scenarios pass, and an app's
`armada-shim` holds 0.2–0.3 MiB (0.07 MiB anonymous) where containerd's
shim held 7.5–8.5 MiB (4 MiB) and containerd 47 MiB (15 MiB): about 30 MiB
less held memory on a node with four apps, against the 20 MiB this work
had to save.

Containerd leaves the runtime pack only after a release in which every
node runs the supervisor.

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
- `ctr` cannot inspect a supervisor node's containers; `armada` and
  `armadad doctor` are the interface.

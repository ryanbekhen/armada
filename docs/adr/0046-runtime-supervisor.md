# 0046. Armada's own container supervisor

- Status: Accepted; the OCI runtime is crun since [0056](0056-crun.md) (runc stays for the containers it created), the rest stands
- Date: 2026-11-16

## Context

Every node ran Armada's own containerd (ADR 0011): a daemon that keeps the
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

What containerd did for Armada:

1. Pulls images over HTTPS with registry credentials, keeps their content,
   and unpacks layers into overlayfs snapshots.
2. Keeps container records (spec, labels, snapshot) so the agent can adopt
   containers after it restarts.
3. Through the shim: creates containers with runc, stays their parent
   while the agent and containerd restart, collects exit codes, wires
   output to `armada-log`, runs exec processes, and stops containers.
4. Reports task state and cgroup statistics.

## Decision

Nodes run containers without containerd, on the **supervisor** runtime
(`--runtime supervisor` on `armadad init`, `join`, and `server join`, the
default and the only value, recorded as `"runtime"` in `agent.json`). The
OCI runtime, the CNI plugins, tini, and `armada-log` are the ones ADR 0011
brought.

It started as an experiment beside containerd, became the default on
2026-11-22, and is now the only runtime: containerd and its shim have left
the runtime pack.

- **armada-node keeps images and container records (ADR 0054).** Pulls and
  unpacking run in the pack's `armada-node`, with no daemon: a content
  store, unpacked layers, and root filesystems under
  `<data-dir>/node/images` (`index.json`, `content/blobs`, `layers/<chain
  ID>`, `active/<container>`), at most two blobs fetched at once. Images
  are recorded with their labels (`armada.pulled-with/<key>` keeps its
  meaning, and a name pulled again to another target starts with none); a
  layer already unpacked is reused for a new image only once its blob is
  shown to decompress to the image's diff ID (ADR 0011). Removing an image
  removes the layers and blobs no other image or root filesystem uses,
  once no pull is running (the last pull to end does it otherwise). Each
  container is an OCI bundle under `<data-dir>/supervisor/containers/<id>`:
  its root filesystem mounted from the image's layers, `config.json`, and
  `record.json` (labels, image, shim group, OCI runtime), written last.
- **`armada-shim` (Rust, standard library only, `shim/`) supervises
  containers.** One per app and runtime pack on a node (the group the spec
  annotation names), started by the agent as a transient systemd unit
  (`armada-shim-<hash>`): a service stops every process it started when it
  restarts, a unit of its own does not. It is the child subreaper of its
  containers, creates and starts them with the OCI runtime's `create` and
  `start`, hands their output to `armada-log`, keeps exit codes until
  delete, and answers one line per connection on a 0600 socket in
  `/run/armada/shim/` (`create`, `start`, `state`, `wait`, `kill`, `kill
  all`, `delete`, `list`). It exits 10 seconds after its last container is
  gone, removing its socket and state. It never reads images or
  credentials. It refuses a process ID of 0 or 1 from the runtime's pid
  file (and deletes a container whose pid file it cannot read), and keeps
  at most 4096 exit codes nobody asked for, never dropping a container's
  own. The unit runs with the limits of `armada-runtime.service`
  (`OOMScoreAdjust=-999`, `LimitNOFILE`, `LimitNPROC`, `LimitCORE`, and
  `TasksMax` unlimited), which its containers inherit. Before the agent
  starts a group's shim, containers a shim that ended left in the
  runtime's state are killed and deleted, so they end with their shim, and
  the agent starts them again. A shim counts as ended only when nothing
  listens on its socket or its unit is no longer active: one that is slow
  or busy (a timeout, a closed connection) keeps its containers, and the
  agent asks again on its next pass. Starting and abandoning a group's
  shim are serialized per group, so two callers never start two shims or
  abandon one that was just started.
- **The agent drives the rest.** Networking, host files, SELinux labels,
  ports, logs, init containers, sidecars, and system containers are the
  agent's (`agent/src/supervisor`). Exec runs through `armada-node runtime
  exec`, which starts the OCI runtime's `exec` in the foreground (a
  pseudo-terminal for `-t`, so size changes reach the process); statistics
  are read from the container's cgroup files. The conformance suite runs
  against it on a lab node.
- **The runtime pack carries `armada-shim`.** The agent installs the pack
  itself at start, so an upgrade brings the new shim and OCI runtime;
  `armadad runtime` installs it and exits.

### Nodes set up on containerd

A node whose `agent.json` names `"runtime": "embedded"`, or no runtime, was
set up on containerd by an earlier release. This release cannot run it: its
agent starts nothing and logs why, and `armadad doctor` fails its `runtime`
check, both telling the operator to upgrade through v0.1.0-alpha.44 first,
which moves such a node to the supervisor runtime. `--runtime embedded` is
an invalid value.

### Measured

In a two-machine lab with the supervisor and no containerd process, the
conformance suite and the end-to-end scenarios pass, and an app's
`armada-shim` holds 0.2–0.3 MiB (0.07 MiB anonymous) where containerd's
shim held 7.5–8.5 MiB (4 MiB) and containerd 47 MiB (15 MiB): about 30 MiB
less held memory on a node with four apps, against the 20 MiB this work
had to save.

## What stays out of scope

- The OCI runtime stays a program of its own (runc, then crun since ADR
  0056): it runs only while it creates, starts, or execs, so it holds no
  memory between those calls, and replacing it would mean taking over the
  most security-sensitive code on the node.

## Alternatives considered

- **Keep containerd.** No work and no risk; the 30 MiB per node and the
  program text stay.
- **An OCI runtime library inside Armada instead of a runtime program.**
  Removes the runtime calls, but brings namespaces, seccomp, and
  AppArmor/SELinux setup into code Armada would own, for no gain in held
  memory.
- **One supervisor per node instead of one per app.** Less memory still,
  but a crash or upgrade of that one process would end every container on
  the node; one per app keeps the blast radius small.

## Consequences

- Armada owns image pulling and unpacking, including their security fixes.
- `ctr` cannot inspect a node's containers; `armada` and `armadad doctor`
  are the interface.

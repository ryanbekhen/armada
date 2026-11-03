# 0011. Embedded container runtime

- Status: Accepted
- Date: 2026-11-01

## Context

Every node runs containers. If that depended on a container engine the
operator installs separately, every node would need one more thing to
install and keep compatible, and the behaviour Armada relies on (networking,
restart behaviour, logging, security defaults) would change between
releases outside Armada's control. A node should need nothing but the
Armada binary, and Armada should own the behaviour it depends on.

Runtime access sits behind interfaces (`runtime.Driver`,
`runtime.SystemRunner`, `runtime.BridgeInspector`), so reconciliation,
rollouts, probes, and self-healing do not depend on how containers are run.

## Decision

Armada brings its own container runtime: a containerd instance that only
Armada uses, started from binaries embedded in the Armada binary.
`agent.json` records `"runtime": "embedded"`; any other value names an
external driver (ADR 0015).

Other engines can be supported as **external drivers** (ADR 0015);
the embedded runtime stays the default and the reference implementation.

### What is bundled

Release builds embed upstream release binaries, pinned by version and
SHA-256 in `internal/runtime/embedded/lock.go`:

| Component | Why |
| --- | --- |
| containerd (static) and `containerd-shim-runc-v2` | Image store, snapshots, container lifecycle |
| runc | OCI runtime (needs CGO and C, so it cannot be compiled into Armada) |
| CNI plugins `bridge`, `host-local`, `loopback`, `portmap`, `firewall` | Container networking |
| tini (static) | PID 1 in every app container: reaps zombies and forwards signals |

No `ctr` binary is bundled.

- `make runtime-bundle` downloads the pinned artifacts over HTTPS, refuses
  any whose SHA-256 differs from the lock, and packs them per
  architecture. The maintainer who bumps a version verifies the upstream
  signatures (runc and tini publish GPG signatures) before recording the
  new checksums; builds trust the pinned checksums. Release builds embed
  the pack with `go:embed` (build tag `bundle`); without the tag
  (development, unit tests) `armada runtime --bin-dir DIR` uses binaries
  from a directory.
- At start the pack is extracted to `<data-dir>/runtime/<pack sha256>/bin`
  (root-owned, `0700`), every file is checked against the pack's manifest
  on every start, and `<data-dir>/runtime/current` is switched to it
  atomically. Older pack directories are removed.
- The release SBOM lists the bundled components. A security fix in any of
  them is an Armada patch release; `govulncheck` does not see these
  binaries, so the release process checks their advisories explicitly.

### Running containerd

- A separate systemd unit, `armada-runtime.service`, runs
  `armada runtime`, which extracts the bundle and execs containerd. It
  uses `KillMode=process` and `Delegate=yes`, so restarting or upgrading
  containerd (or the agent) leaves running containers and their shims
  alone. `armada-server` and `armada-agent` want and start after it; on a
  node that is not initialized yet it exits at once.
- It is Armada's own containerd instance, never the host's: root
  `<data-dir>/containerd`, state `/run/armada/containerd`, socket
  `/run/armada/containerd/containerd.sock` (directory `0700`), namespace
  `armada`. No TCP listener, no CRI plugin, no metrics listener, and no
  configuration imported from the host. Other container software on the
  host is unaffected.
- containerd's restart manager is disabled. A container whose process
  exits stays stopped, with its exit code, until the agent sees it and
  recreates it with crash backoff (ADR 0008); after a reboot the agent
  recreates every replica, because network namespaces and NAT rules do not
  survive one. While the agent is down nothing is restarted: replicas that
  keep running are unaffected, crashed ones wait for the agent, which
  systemd restarts within seconds.

### Containers

The driver builds the OCI spec itself, so the security defaults are
Armada's and visible in one place:

- containerd's default spec (the usual default capability set, masked and
  read-only kernel paths), minus `NET_RAW`, `MKNOD`, and `AUDIT_WRITE`;
  `no-new-privileges`; containerd's default seccomp profile; Armada's
  AppArmor profile where AppArmor is enabled. Never privileged, never host
  namespaces for apps, no devices beyond the defaults. Every container,
  HAProxy included, has its own cgroup namespace; apps see their own cgroup
  read-only at `/sys/fs/cgroup`, so programs can read their limits, and
  never the host's hierarchy.
- On SELinux hosts every container, HAProxy included, runs as
  `container_t` with MCS categories of its own (two random categories,
  unique among the node's containers; an agent that restarts reserves the
  categories of the containers it adopts). The root filesystem is mounted
  with the matching `container_file_t` context, so image files need no
  labels on disk, and the files Armada bind-mounts are relabelled for
  that container: its `/etc/resolv.conf`, `/etc/hosts`, `/etc/hostname`,
  its secret files, and HAProxy's configuration and socket directories.
  tini gets the read-only label all containers share. Host files mounted
  into HAProxy keep their labels. A container that escapes its namespaces
  still cannot read the host's files or another container's. Hosts whose
  policy lacks the container types (no container policy package) run
  containers with the runtime's label; `armada doctor` warns about it.
- cgroup v2 limits under `/armada/<container>`: memory (swap limited to
  the same value), CPU quota, PIDs; the open-file limit is 1048576. cgroup
  v1 hosts are refused by `armada doctor` and at start.
- tini is bind-mounted read-only and wraps the entrypoint.
- `/etc/resolv.conf`, `/etc/hosts`, and `/etc/hostname` are generated per
  container. Without explicit DNS servers the host's upstream resolvers are
  used (the systemd-resolved stub on 127.0.0.53 is not reachable from a
  container, so its upstream file is read instead).
- System containers (HAProxy) have their own code path: host network
  namespace, all capabilities dropped except the listed ones, read-only
  root filesystem, explicit bind mounts.
- Images are pulled into containerd's content store over HTTPS with the
  registry credentials from the app's secrets and unpacked with the
  overlayfs snapshotter; `Pull` returns the digest-pinned reference.

### Networking

- One bridge per node, `armada0`, on the node's own subnet of the cluster
  network (ADR 0027): a /24 of `--cluster-cidr`, default `10.120.0.0/16`,
  given when the node joins. In clusters created before the cluster
  network, every node uses the same subnet (`--container-subnet`, default
  `10.121.0.0/24`). The agent creates it at
  start, so internal DNS and the internal ingress (ADR 0007) can bind to
  its gateway before any container exists. The bridge gets a fixed,
  locally administered hardware address derived from its gateway.
  Otherwise the kernel gives it the lowest address of its ports, which
  changes as containers come and go. Containers would then send to an old
  address until their ARP entry expires, and connections to their
  published ports would hang for seconds.
- Containers join it through the CNI chain `bridge` (gateway, masquerade
  for egress) + `host-local` IPAM + `portmap` + `firewall`. IPAM state and
  the plugin cache live on tmpfs under `/run/armada/cni`, since the
  namespaces they describe do not survive a reboot. The replica's port is
  published only on the node's private IP: the driver picks a free host
  port (20000–32767, below the kernel's ephemeral range), records it in a
  container label, and `portmap` adds the DNAT rule. Nothing is ever
  published on a wildcard or public address.
- `armada doctor` checks cgroup v2, overlayfs, the `iptables` tooling the
  CNI plugins call, and that the node's container subnet does not overlap
  a host route.

### Logs

The shim writes container output through a logging binary, Armada itself
(`armada runtime-log`, a hidden command), into
`<data-dir>/logs/<container>.log` as JSON lines with the stream and a
timestamp, rotated at 10 MB with 3 files kept. `armada logs` reads and
follows these files.

## External drivers

Other engines run containers for the agent as external drivers: separate
programs behind a versioned gRPC protocol on a root-only Unix socket, with
the same spec checks and security defaults. ADR 0015 describes them; the
embedded runtime stays the default and runs in the agent's process.

## Alternatives considered

- **Require a container engine installed by the operator:** one more
  installation per node, and the behaviour Armada depends on changes
  outside its control.
- **Use the host's containerd:** its version and configuration vary per
  distribution, and other software may own it.
- **Compile containerd into the Armada binary:** fewer files to extract,
  but containerd's daemon pulls in a large dependency tree and some plugins
  expect CGO; runc must be a separate binary anyway. Upstream release
  binaries are built, tested, and signed by their maintainers.
- **Our own networking (netlink, IPAM, nftables) instead of CNI:** less to
  bundle, but bridge, IPAM, masquerading, and port mapping are exactly what
  the CNI plugins have been hardened for.

## Consequences

- A node needs only the Armada binary, a Linux kernel with cgroup v2 and
  overlayfs, and `iptables`.
- The binary grows by roughly 40 MB (compressed bundle).
- Armada owns updates of containerd, runc, the CNI plugins, and tini.
- `armada status` and `armada logs` are the interface to containers (an
  upstream `ctr` can inspect the instance with `--address` set to the
  socket above and `--namespace armada`).

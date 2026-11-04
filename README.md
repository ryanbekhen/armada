<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/armada-logo-dark.svg">
    <img src="docs/assets/armada-logo-light.svg" alt="Armada logo" width="96" height="96">
  </picture>
</p>

# Armada

> **Status: pre-alpha.** Not ready for production use yet.

Armada turns a handful of Linux machines into a container platform: apps, revisions,
rolling updates, domains, and automatic TLS.
One binary, one install command.

```yaml
name: web
image: ghcr.io/acme/web:1.4.2
ingress:
  type: external
  port: 8080
probes:
  readiness:
    path: /healthz
scale:
  min: 2
```

```bash
armada deploy -f web.yaml    # → https://web.apps.example.com
```

## What it does

- **Desired state, reconciled.** The CLI writes what you want; the control
  plane and an agent on every node converge to it and keep it there.
- **Rolling updates and rollback.** Revisions pin the image digest and the
  secret versions. New replicas take traffic only once their probes pass,
  and old ones are drained, not killed.
- **Traffic splitting.** `revisions.mode: multiple` splits requests between
  revisions by weight, with a URL of their own for labelled revisions,
  for canaries and previews.
- **HTTPS by default.** HAProxy on every node, certificates from Let's
  Encrypt (HTTP-01, or DNS-01 with Cloudflare for a wildcard), custom
  domains after TXT ownership verification.
- **Internal services.** `ingress: internal` apps are reachable from any
  container in the cluster at `http://<app>.internal`, never from outside.
- **Local-first routing.** Each node sends requests to its own replicas
  while they are no busier than the rest, and spreads the excess over every
  node, so most requests never cross the network.
- **Cluster network.** Each node's containers get their own subnet of one
  private range, routed between nodes over a tunnel on the private
  network, so a container reaches any other at its own address and sees
  its caller's real one.
- **Secrets.** Encrypted at rest, versioned, delivered as env vars or as
  read-only files on tmpfs.
- **Logs and exec.** `armada logs` streams a replica's output;
  `armada exec web -it -- sh` opens a shell in one, with the container's
  own security settings, and every session is audited.
- **Usage.** `armada top` shows the CPU and memory each app, replica, and
  node uses next to what it reserves, sampled every 10 seconds.
- **Autoscaling.** `scale.rules` keep an app between `scale.min` and
  `scale.max` by requests in progress, CPU, or memory per replica. With
  `scale.min: 0`, an idle app stops its last replica and the next request
  starts it again.
- **Jobs.** `kind: job` runs a container to completion, on demand or on a
  cron schedule with a time zone, with timeouts, retries, and run history.
- **Volumes.** `volumes` keep an app's data on its node across deploys,
  crashes, and reboots, for databases and uploads; `armada volume backup`
  and `restore` copy it out and back, onto another node if its own is gone.
- **Events.** `armada events` shows what the cluster did over the last day:
  crashes and restarts, rollouts, lost nodes, replicas moved, certificates;
  `-f` follows new ones.
- **Metrics.** The leader serves Prometheus metrics (apps, replicas, nodes,
  usage, reconciles) on a private address, only to client certificates that
  `armada metrics credentials` creates.
- **Multiple nodes.** Join with a single-use token; nodes get short-lived
  mTLS certificates that they renew themselves. Cordon, evacuate, remove.
  Replicas of a lost node are started elsewhere, and apps spread out again,
  one replica at a time, when a node returns or joins.
- **Placement.** Label nodes (by hand or in the join token), keep apps to
  the nodes they require, and spread them evenly over a label's values
  (sites, racks); restricted nodes run only the apps that ask for them. Every node reports its OS, architecture, and container runtime as labels, and apps
  run only on nodes their image is built for. Replicas reserve CPU and
  memory on their node, and no node is overcommitted.
- **Highly available control plane.** One server works; three survive the
  loss of any one. Servers elect a leader, agents and the CLI follow it,
  and certificates are not re-issued on failover.
- **Rolling upgrades.** Upgrade servers, then nodes, one at a time while
  apps keep serving; state migrations wait until every server runs the new
  version, and downgrades onto migrated state are refused.
- **Confined containers.** Dropped capabilities, `no-new-privileges`,
  seccomp, AppArmor or SELinux (each container in its own MCS categories),
  and memory, CPU, and PID limits.
- **Runtime drivers.** A node can run containers on another engine
  through an external driver: a separate program behind a local protocol
  that carries the same security defaults, with a public Go library and a
  conformance suite for driver authors.
  [armada-driver-docker](https://github.com/ryanbekhen/armada-driver-docker)
  runs a node's containers on the Docker Engine.
- **macOS compute nodes.** A Mac with Apple silicon can join as a node
  that runs replicas through a driver, as a dedicated user with secrets on
  a RAM disk; the control plane and HAProxy stay on Linux.
  [armada-driver-apple](https://github.com/ryanbekhen/armada-driver-apple)
  runs them through Apple's `container` tool, each in its own virtual
  machine; armada-driver-docker runs them on a Docker Engine in one Linux
  virtual machine, with every container default.

Armada needs Linux machines (cloud instances, VMs, or bare metal) with a
private network between them, and nothing else (Macs can add compute
nodes): the binary embeds its own
container runtime (containerd, runc, CNI plugins) and
its state store (etcd).

## Documentation

- [Quickstart](docs/quickstart.md): empty machines to an HTTPS app
- [App spec reference](docs/spec-reference.md)
- [Operations](docs/operations.md): control plane servers, backup, restore, upgrades, runtime drivers
- [Threat model](docs/threat-model.md), including the accepted limitations
- [Architecture decisions](docs/adr/README.md)
- [Releasing and verifying releases](docs/releasing.md)
- [Security policy](SECURITY.md): report vulnerabilities privately

## Tested environments

| Environment | Status |
| --- | --- |
| Cloudflare DNS-01 with Let's Encrypt staging | Tested: wildcard certificate for the root domain |
| Local lab: Linux VMs (arm64), Pebble ACME, 1–2 nodes | Tested end to end: deploys, rolling update, secret files, internal ingress and DNS, crash recovery, containerd restart with containers kept running, reboot recovery, rolling upgrade with a state migration, rebalancing after uncordon under HTTPS load without errors, replicas across nodes |
| Oracle Cloud (arm64, Oracle Linux 9, SELinux enforcing), one server, Let's Encrypt staging | Tested end to end: install.sh with systemd, doctor, wildcard certificate over Cloudflare DNS-01, rolling update under load without errors, crash recovery, containerd restart, reboot recovery, SELinux-confined apps and HAProxy, HAProxy restarted after a crash |
| depa.id (amd64, Ubuntu 24.04), three control plane servers and one node, Let's Encrypt staging | Tested end to end with [test/e2e](test/e2e/README.md): server and node joins, only HAProxy public, certificates on every node, secrets, rolling update, rollback, and agent restart under load without errors, leader stop and SIGKILL under load, node loss and rebalancing under load, backup, all machines rebooted at once |
| Local lab: a Linux server (arm64) on armada-driver-docker and a Mac (macOS 27, Apple silicon) as a node on armada-driver-apple | Tested end to end: Mac join with secrets on a RAM disk, replicas placed only on the Mac, internal ingress on the server balancing across them, a rolling update, secret files and environment, adoption after restarting the driver and agent, replicas below 200 MiB refused with a reason, `armada runtime reset` leaving other containers alone |
| Local lab: a Linux server (arm64) on armada-driver-docker and a Mac (macOS 27, Apple silicon) as a node on armada-driver-docker with the engine in a virtual machine (colima) | Tested end to end: the node reporting the virtual machine's capacity and refusing replicas beyond it, secret files from the RAM disk read-only with every container default, internal ingress on the server balancing across the Mac's replicas, a rolling update, adoption after restarting the driver and agent, `armada runtime reset` |
| Mixed architectures: three depa.id servers (amd64, Ubuntu 24.04) and an Oracle Cloud node (arm64, Oracle Linux 9, SELinux enforcing), Let's Encrypt staging | Tested end to end with [test/e2e](test/e2e/README.md): every scenario above except the reboot, plus placement under load and images built for one architecture running only on nodes of that architecture |

Reports from other providers are welcome.

## Development

Requires Go (see `go.mod`), `golangci-lint` v2, `govulncheck`, and `protoc` (only for `make proto`).

```bash
make build    # ./bin/armada
make test     # unit tests with the race detector
make check    # vet + lint + test + govulncheck (what CI runs)
```

[test/e2e](test/e2e/README.md) builds a cluster on real machines and tests
it end to end: rolling updates and failover under load, node loss, reboots.

## License

[Apache License 2.0](LICENSE)

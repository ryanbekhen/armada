<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/armada-logo-dark.svg">
    <img src="docs/assets/armada-logo-light.svg" alt="Armada logo" width="96" height="96">
  </picture>
</p>

# Armada

> **Status: alpha.** Specs, flags, and the state format may still change between releases.

Armada turns a handful of Linux machines into a container platform: apps, revisions,
rolling updates, domains, and automatic TLS.
One install command: `armadad` runs each machine, `armada` manages apps
from anywhere, Linux or macOS.

```bash
curl -fsSL https://raw.githubusercontent.com/ryanbekhen/armada/main/install.sh | sudo sh
armada app create web --image ghcr.io/acme/web:1.4.2 --port 8080 --ingress external --replicas 2
# → https://web.apps.example.com
armada app show web -o yaml > web.yaml    # the spec it runs, to keep in git
armada app update web --file web.yaml
```

## What it does

- **Flags or files.** `armada app create` and `armada app update` write a
  spec from flags or take one from a file; `armada app show -o yaml`
  exports it, and `update --diff` shows what a change would do. Every
  command is `armada <noun> <verb>`.
- **Desired state, reconciled.** The CLI writes what you want; the control
  plane and an agent on every node converge to it and keep it there.
- **Rolling updates and rollback.** Revisions pin the image digest and the
  secret versions. New replicas take traffic only once their probes pass,
  and old ones are drained, not killed.
- **Traffic splitting.** `revisions.mode: multiple` splits requests between
  revisions by weight, with a URL of their own for labelled revisions,
  for canaries and previews.
- **HTTPS by default.** HAProxy on every node, certificates from Let's
  Encrypt (HTTP-01, or DNS-01 with Cloudflare for the root domain and a wildcard), custom
  domains after TXT ownership verification.
- **Cluster settings in one place.** `armada cluster set` changes
  certificates, the DNS provider, metrics, and timeouts for every server at
  once, and they hold after a failover.
- **Internal services.** `ingress: internal` apps are reachable from any
  container in the cluster at `http://<app>.internal`, never from outside.
  Databases, brokers, and caches take plain TCP with `protocol: tcp`: the
  apps of their project connect to `<app>.internal:<port>`, balanced and
  health checked by each node's proxy, which listens for them only on the
  container bridge.
- **Client address rules.** `ingress.ipAllow` lets only chosen addresses
  reach an external app, and `ipDeny` keeps some out. Behind a CDN, only
  the address a trusted proxy appended counts, so a client cannot claim
  another one in a header.
- **Local-first routing.** Each node sends requests to its own replicas
  while they are about as busy as the rest, and spreads the excess over every
  node, so most requests never cross the network.
- **Cluster network.** Each node's containers get their own subnet of one
  private range, routed between nodes over a tunnel on the private
  network, so replicas are reached at their own address and see their
  caller's real one; `--network wireguard` encrypts it. Apps reach each
  other only through their internal names.
- **Projects.** Apps, jobs, secrets, domains, and volumes belong to a
  project, so `web` can run in `staging` and in `default` side by side.
  Each project resolves and reaches
  only its own internal names (`ingress.allow` narrows an app to chosen
  callers), and its containers are kept away from the nodes, the private
  network, and the cloud's metadata service.
- **Access control.** People (users) and tools (services) each get a
  certificate under their own name and hold roles: `viewer`, `deployer`,
  or `admin` in a project, `project-creator`, or `cluster-admin`
  (`armada rbac`). The audit log names them, and one person's access is
  taken back at once.
- **Secrets.** Encrypted at rest, versioned, delivered as env vars or as
  read-only files on tmpfs; `envFrom: secrets` turns all of an app's
  secrets into variables.
- **One spec, several environments.** `${NAME}` in a spec is filled in
  from `armada app create --file web.yaml --vars production.env --var TAG=...`.
- **Logs and exec.** `armada app logs` streams a replica's output, rotated
  and rate limited on the node so no app can flood its disk;
  `armada app exec web -it -- sh` opens a shell in one, with the container's
  own security settings, and every session is audited.
- **Usage.** `armada app top` and `armada node top` show the CPU and
  memory each app, replica, and node uses next to what it reserves, sampled every 10 seconds, and per
  project also its volumes, requests, and egress.
- **Autoscaling.** `scale.rules` keep an app between `scale.min` and
  `scale.max` by requests in progress, CPU, or memory per replica, by the
  length of its queue (a Redis list, a RabbitMQ queue, or any queue a
  command in the app reads), or by a schedule. With
  `scale.min: 0`, an idle app stops its last replica and the next request
  starts it again.
- **Jobs.** `kind: job` runs a container to completion, on demand or on a
  cron schedule with a time zone, with timeouts, retries, and run history.
  A job can also start from a Redis list or RabbitMQ queue: while messages
  wait, runs start, each taking a batch, and nothing runs while it is empty.
- **Volumes.** `volumes` keep an app's data on its node across deploys,
  crashes, and reboots, for databases and uploads; deploys pull the new
  image before the old replica stops. Scheduled backups go to an
  S3-compatible bucket, deduplicated and encrypted, keeping the backups
  `keep` names, and an app whose node is lost comes back on another node
  from its latest backup; `armada volume backup` and `restore` copy a
  volume out and back. A volume can also be an export of an NFS server you
  run, shared by any number of replicas.
- **Init containers and sidecars.** `initContainers` run to completion
  before an app's container starts (a migration, a seed step); `sidecars`
  run beside it on its localhost (a proxy, a log shipper), with the app's
  volumes and secret files they name and the same security defaults.
- **Events.** `armada cluster events` shows what the cluster did over the last day:
  crashes and restarts, rollouts, lost nodes, replicas moved, certificates;
  `-f` follows new ones.
- **Metrics.** The leader serves Prometheus metrics (apps, replicas, nodes,
  usage, reconciles) on a private address, only to client certificates that
  `armada metrics credentials` creates.
- **Multiple nodes.** Join with a single-use token; nodes get short-lived
  mTLS certificates that they renew themselves, and servers renew their own. Drain, evacuate, delete.
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
- **Rolling upgrades.** `armada version` and `armadad doctor` say when a
  newer release is out, and `sudo armadad upgrade` installs it, verified,
  on a machine. Upgrade servers, then nodes, one at a time while
  apps keep serving; state migrations wait until every server runs the new
  version, and downgrades onto migrated state are refused.
- **Confined containers.** Dropped capabilities, `no-new-privileges`,
  seccomp, AppArmor or SELinux (each container in its own MCS categories),
  and memory, CPU, and PID limits.

Armada needs Linux machines (cloud instances, VMs, or bare metal) with a
private network between them, and nothing else: `armadad` embeds its own
container runtime (containerd, runc, CNI plugins) and its state store
(etcd). The `armada` client needs no root and also runs on macOS.

## Documentation

- [Quickstart](docs/quickstart.md): empty machines to an HTTPS app
- [App spec reference](docs/spec-reference.md)
- [Operations guide](docs/operations.md): day-to-day running of a cluster: control plane, backup, upgrades, access control, nodes, network, apps, monitoring
- [Threat model](docs/threat-model.md), including the accepted limitations
- [Architecture decisions](docs/adr/README.md)
- [Releasing and verifying releases](docs/releasing.md)
- [Security policy](SECURITY.md): report vulnerabilities privately

## Tested environments

| Environment | Status |
| --- | --- |
| Cloudflare DNS-01 with Let's Encrypt staging | Tested on depa.id (amd64, Ubuntu 24.04): certificates for the root domain and a wildcard, domain verification, challenge records removed afterwards, the token kept out of logs and events, and requests through the Cloudflare proxy with trusted proxies (the client's address kept, forged headers from elsewhere dropped) |
| Local lab: Linux VMs (arm64), Pebble ACME, 1–2 nodes | Tested end to end: deploys, rolling update, secret files, internal ingress and DNS, crash recovery, containerd restart with containers kept running, reboot recovery, rolling upgrade with a state migration, rebalancing after a drained node resumed under HTTPS load without errors, replicas across nodes |
| Oracle Cloud (arm64, Oracle Linux 9, SELinux enforcing), one server, Let's Encrypt staging | Tested end to end: install.sh with systemd, doctor, wildcard certificate over Cloudflare DNS-01, rolling update under load without errors, crash recovery, containerd restart, reboot recovery, SELinux-confined apps and HAProxy, HAProxy restarted after a crash |
| depa.id (amd64, Ubuntu 24.04), three control plane servers and one node, Let's Encrypt staging | Tested end to end with [test/e2e](test/e2e/README.md): server and node joins, only HAProxy public, certificates on every node, secrets, rolling update, rollback, and agent restart under load without errors, leader stop and SIGKILL under load, node loss and rebalancing under load, backup, all machines rebooted at once |
| Mixed architectures: three depa.id servers (amd64, Ubuntu 24.04) and an Oracle Cloud node (arm64, Oracle Linux 9, SELinux enforcing), Let's Encrypt staging | Tested end to end with [test/e2e](test/e2e/README.md): every scenario above except the reboot, plus placement under load and images built for one architecture running only on nodes of that architecture |
| depa.id (amd64, Ubuntu 24.04, kernel 6.8), two machines on a private network, `--network wireguard` | Tested: the kernel WireGuard device on both nodes, handshakes in `armadad doctor`, requests between replicas on different nodes, only encrypted traffic on the private network, the tunnel staying up while an agent is stopped, the same key after an agent restart, and recovery after a node reboot |

Reports from other providers are welcome.

## Development

Requires Go (see `go.mod`), `golangci-lint` v2, `govulncheck`, and `protoc` (only for `make proto`).

```bash
make build    # ./bin/armada (client) and ./bin/armadad (daemon)
make test     # unit tests with the race detector
make check    # vet + lint + test + govulncheck (what CI runs)
```

[test/e2e](test/e2e/README.md) builds a cluster on real machines and tests
it end to end: rolling updates and failover under load, node loss, reboots.

## License

[Apache License 2.0](LICENSE)

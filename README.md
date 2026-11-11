<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/armada-logo-dark.svg">
    <img src="docs/assets/armada-logo-light.svg" alt="Armada logo" width="112" height="112">
  </picture>
</p>

<h1 align="center">Armada</h1>

<p align="center">
  <b>Turn a few Linux machines into a container platform.</b><br>
  Apps with HTTPS, rolling updates, autoscaling, jobs, and volumes, from two binaries and nothing else to install.
</p>

<p align="center">
  <a href="https://github.com/ryanbekhen/armada/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/ryanbekhen/armada/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/ryanbekhen/armada/releases"><img alt="Release" src="https://img.shields.io/github/v/release/ryanbekhen/armada?include_prereleases&sort=semver"></a>
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-blue"></a>
  <a href="go.mod"><img alt="Go version" src="https://img.shields.io/github/go-mod/go-version/ryanbekhen/armada"></a>
</p>

<p align="center">
  <a href="docs/quickstart.md">Quickstart</a> ·
  <a href="docs/README.md">Documentation</a> ·
  <a href="docs/guides/README.md">Guides</a> ·
  <a href="docs/cli/armada.md">CLI reference</a> ·
  <a href="docs/spec-reference.md">Spec reference</a> ·
  <a href="https://github.com/ryanbekhen/armada/releases">Releases</a>
</p>

---

> [!NOTE]
> **Armada is in alpha.** It is tested end to end on real machines before
> every release, but specs, flags, and the state format may still change
> between releases.

## In one minute

```bash
# On each machine: install
curl -fsSL https://raw.githubusercontent.com/ryanbekhen/armada/main/install.sh | sudo sh

# On the first machine: create the cluster
sudo armadad init
sudo systemctl enable --now armada-server
armada cluster set --acme-email you@example.com --root-domain apps.example.com

# Deploy an app: two replicas behind HTTPS
armada app create web --image ghcr.io/acme/web:1.4.2 --port 8080 --ingress external --replicas 2
# → https://web.apps.example.com
```

Ship a new version, watch it roll out, and go back if you need to:

```bash
armada app update web --image ghcr.io/acme/web:1.5.0 --wait
armada app rollback web
```

Keep the app as a file in git and change it from there:

```yaml
# web.yaml, from: armada app show web -o yaml
name: web
image: ghcr.io/acme/web:1.5.0
ingress:
  type: external
  port: 8080
  domains: [shop.example.com]
env:
  - name: DATABASE_URL
    secretRef: database-url
scale:
  min: 2
  max: 10
  rules:
    - type: http
      concurrent: 50
probes:
  readiness:
    path: /healthz
```

```bash
armada app update web --file web.yaml --diff   # what would change
armada app update web --file web.yaml --wait
```

## Why Armada

- **Small and complete.** `armadad` runs on every machine and brings its own
  container runtime, state store, and proxy. `armada` is the client, for
  Linux and macOS, and needs no root.
- **Safe by default.** HTTPS with automatic certificates, rolling updates
  that send traffic only to ready replicas, drained shutdowns, confined
  containers, encrypted secrets, and mTLS between every component.
- **Grows with you.** Start on one machine. Add nodes with a one-time token,
  and two more servers for a control plane that survives losing one.
- **Everything is a spec.** Apps and jobs are YAML files you keep in git.
  `armada app show -o yaml` exports what runs, and `--diff` shows a change
  before it happens.

## Features

| | |
| --- | --- |
| **Deploy** | Rolling updates, rollback, revisions pinned to image digests, traffic splitting for canaries and previews |
| **Traffic** | HTTPS on every node, custom domains, internal services at `<app>.internal`, internal TCP for databases, IP allow and deny lists, CORS, sticky sessions |
| **Scale** | Autoscaling on requests, CPU, memory, queue length, or a schedule; scale to zero and back on the next request |
| **Run** | Jobs and cron jobs, jobs started by a queue, init containers, sidecars, `exec` into replicas, logs |
| **Data** | Volumes, scheduled encrypted backups to an S3-compatible bucket, failover to another node, NFS exports |
| **Operate** | Highly available control plane, self-healing, placement by labels, projects, users and roles, events, Prometheus metrics, verified upgrades |

Read the [full feature list](docs/features.md).

## Learn

| | |
| --- | --- |
| **[Quickstart](docs/quickstart.md)** | From empty machines to an app on HTTPS |
| **[Concepts](docs/concepts.md)** | Apps, revisions, replicas, nodes, projects: how Armada thinks |
| **[Guides](docs/guides/README.md)** | Complete recipes: a web app, a database, workers, cron jobs, canaries, CI/CD, and more |
| **[CLI reference](docs/cli/armada.md)** | Every `armada` and `armadad` command and flag |
| **[Spec reference](docs/spec-reference.md)** | Every field of an app or job spec |
| **[Operations guide](docs/operations.md)** | Running a cluster day to day: upgrades, backups, nodes, networking, monitoring |
| **[Security](docs/threat-model.md)** | The threat model, and how to [report a vulnerability](SECURITY.md) |

## Requirements

- Linux machines (amd64 or arm64): cloud instances, VMs, or bare metal, with
  a private network between them and systemd.
- A domain whose DNS you control, for HTTPS.
- The `armada` client runs on Linux and macOS.

Armada is [tested on real machines](docs/tested-environments.md) before
each release.

## Contributing

Bug reports, ideas, and pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md)
explains how to build Armada and run its tests, and the
[architecture decisions](docs/adr/README.md) explain why it works the way it
does.

## License

[Apache License 2.0](LICENSE)

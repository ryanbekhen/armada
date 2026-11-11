# End-to-end tests

`cluster.sh` builds an Armada cluster on real machines and checks the
behaviour that unit tests cannot: certificates, traffic under change, the
control plane losing its leader, nodes going away, and reboots. It runs from
your workstation over SSH and does not depend on any provider. Run it before
a release and after changes to the runtime, the proxy, the scheduler, or the
control plane. It does not run in CI.

## What you need

- Two or more fresh Linux machines (four is best: three control plane servers
  and one node) on a private network, reachable as root over SSH with a key
  (or set `E2E_SUDO=sudo`). They get Armada installed and are changed freely:
  throw them away afterwards.
- A root domain whose wildcard record points at the machines' public IPs, so
  HTTP-01 can issue the test app's certificate. The script always talks to
  every node directly, so the record may name just one of them.
- `ssh`, `scp`, `curl`, `jq`, and `openssl` on your workstation.
- Linux binaries for the machines' architecture: `make build-bundle` (add
  `GOARCH=arm64` for arm64) builds `armadad` with the runtime embedded and
  the `armada` client next to it. `ARMADA_BIN` names the `armadad` binary;
  the script installs the client from the same directory. A cluster may mix
  amd64 and arm64 machines: build both and pass them as `ARMADA_BIN_AMD64`
  and `ARMADA_BIN_ARM64`.

## Running

List the machines, one per line, in a hosts file:

```
# NAME  SSH-TARGET        PRIVATE-IP  PUBLIC-IP
e2e1    root@203.0.113.10  10.0.0.1    203.0.113.10
e2e2    root@203.0.113.11  10.0.0.2    203.0.113.11
e2e3    root@203.0.113.12  10.0.0.3    203.0.113.12
e2e4    root@203.0.113.13  10.0.0.4    203.0.113.13
```

```bash
make build-bundle
ARMADA_BIN=bin/armadad-linux-amd64 E2E_DOMAIN=e2e.example.org \
E2E_ACME_EMAIL=you@example.org sh test/e2e/cluster.sh hosts
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `ARMADA_BIN` | required unless both below are set | Binary to install on every machine |
| `ARMADA_BIN_AMD64`, `ARMADA_BIN_ARM64` | `ARMADA_BIN` | Binary for machines of that architecture |
| `E2E_DOMAIN` | required | Root domain for the test app (`hello.<domain>`) |
| `E2E_ACME_EMAIL` | required | ACME account email |
| `E2E_ACME_CA` | `letsencrypt-staging` | Passed to `--acme-ca`; the production endpoint is refused |
| `E2E_SSH_OPTS` | empty | Extra `ssh`/`scp` options, such as `-o UserKnownHostsFile=...` |
| `E2E_SUDO` | empty | `sudo` when the SSH user is not root |
| `E2E_ONLY` | empty (every scenario) | Comma-separated scenarios to run, for example `isolation,rollout` (see below) |
| `E2E_LIST` | empty | `1` prints the scenario names and exits |
| `E2E_REBOOT` | `1` | `0` skips rebooting every machine at once |
| `E2E_BRIDGE_GW` | read from each node | Container bridge address (each node has its own container subnet) |
| `E2E_SERVER_FLAGS` | empty | Extra `armadad server` flags |
| `E2E_CONFORMANCE` | empty | Driver conformance test binary for the last machine's architecture, built with `GOOS=linux go test -c -tags integration -o bin/conformance ./internal/runtime/containerd/`; runs the suite on that node's embedded runtime once the cluster is ready |

The script stops at the first failure and prints `armada server list`,
`armada cluster status`, and `armada app list -A`. A full run on four small machines takes about 10 minutes
once the binaries have been copied to them.

## Running only some scenarios

Building the cluster and deploying the test app always run: every scenario
needs them. `E2E_ONLY` then picks what follows, so a change is tested where
it can break without waiting for the rest:

```bash
E2E_ONLY=isolation,rollout ARMADA_BIN=... sh test/e2e/cluster.sh hosts
```

| Scenario | What it checks (numbers below) | Run it for changes to |
| --- | --- | --- |
| `listeners` | 2 | listeners, ports, the firewall |
| `project-secret` | 3 (a project's secret) | secrets, projects |
| `conntrack` | the connection tracking limit | connection tracking, usage reports |
| `isolation` | 4 | the cluster network (VXLAN, WireGuard, netlink), nftables, internal DNS, HAProxy's internal frontend |
| `load` | 5 (steady load) | the path from clients to the nodes |
| `rollout` | 5 (rolling update and rollback) | rollouts, readiness, draining, the proxy's live updates |
| `agent-restart` | 5 (agent restart) | the agent, adopting containers and a running proxy, certificates |
| `failover` | 6 | the control plane, etcd, elections |
| `node-loss` | 7 | self-healing, rebalancing |
| `backup` | 8 | `armadad backup` |
| `placement` | 9 | labels, restricted nodes, scheduling |
| `platforms` | 10 | image platforms |
| `cpu` | 11 | CPU reservations, capacity |
| `spread` | 12 | `placement.spreadBy` |
| `ip-rules` | 15 | `ingress.ipAllow`/`ipDeny`, trusted proxies, client address headers |
| `sticky` | 16 | `ingress.sticky`, the proxy's cookie |
| `cors` | 17 | `ingress.cors`, the proxy's preflight answers |
| `queues` | 14 | autoscaling on queues and schedules, dialling from containers |
| `reboot` | 13 | start-up order, units, state after a crash |

A release runs every scenario.

## What it checks

1. `armadad doctor` passes on every machine; the cluster forms with three
   voting servers and every node ready. With `E2E_CONFORMANCE`, the driver
   conformance suite passes on the last node's embedded runtime, next to
   its running agent.
2. Nothing but SSH and HAProxy (80/443) listens outside the private,
   loopback, and bridge addresses.
3. The test app gets a certificate for its host name on every node; a secret
   reaches the container's environment and appears in no journal.
4. Isolation while replicas and apps come and go: a replica reaches its own
   app's replicas and itself on localhost; another app of its project reaches
   them only through the internal name; another project reaches them in no way;
   a project's app cannot reach a node's private IP; a removed app's address
   stays blocked. Both projects are removed afterwards.
5. A minute of load while nothing changes serves every request (if this
   fails, look at the network between your workstation and the machines
   first). Then a rolling update, a rollback, and an agent restart serve
   every request (round robin over all public IPs) with HTTP 200; the
   restart adopts the running containers instead of replacing them.
6. Stopping the leader and killing the next one with SIGKILL: a new leader
   takes over, accepts a scale change, the old one rejoins, and traffic stays
   at 200.
7. A node that stops reporting is marked lost after 30 seconds (the script
   sets `--node-lost-timeout 30s`), its replicas move to other nodes, and
   once it returns the app is rebalanced onto it; traffic stays at 200.
8. `armadad backup` writes a `0600` archive.
9. Placement: every node reports `armada.arch`; restricting a labelled node
   moves the app off it under load with every request at 200; an app that
   requires the label runs only there; once the label is gone, `armada
   status` explains why that app has nowhere to go; reopening the node
   spreads the app back.
10. Image platforms: `armada app revision list` lists every node architecture for
   the test app; an image built only for amd64, and one built only for
   arm64, each run only on nodes of that architecture, or, when the
   cluster has none, nowhere, with `armada app show` naming the platform.
11. CPU reservations: the test app's containers get a CPU weight from
    their default 100m reservation; an app reserving 64 cores runs nowhere,
    and `armada app show` says CPU is short.
12. Spreading over a label: with every node but the last in one zone and
    the last alone in another, an app spread by zone puts half of its
    replicas on the last node.
13. After rebooting every machine at once, the control plane, the nodes, and
   the app come back on their own.
14. Autoscaling on queues (runs before 13):
    - A Redis list of 25, read with a password from the app's secret, scales
      its app to 2.
    - A RabbitMQ queue of 25 does the same.
    - Both brokers listen only on 127.0.0.1 inside their own container, so
      the rule must connect from the replica's network namespace.
    - A command that prints 15 is read.
    - A schedule window that opens every minute holds its app at 2.
    - The Redis password appears in no journal.
15. Client address rules (runs before 14 and 13), with the last machine as a
    trusted proxy in front of the cluster:
    - An app open only to one range refuses the others, also when they claim
      an allowed address in `X-Forwarded-For`.
    - Through the trusted proxy, only the address it appended counts:
      - an address the client put before it is ignored;
      - a trusted proxy in the chain is stepped over;
      - a proxy that names no valid client is refused.
    - `ipDeny` refuses one machine and lets the others in.
16. A sticky app with three replicas: a client that keeps the cookie reaches
    one replica through every node, and requests without it are balanced
    over several (runs before 14 and 13).
17. CORS: the proxy answers a preflight from a listed origin with the
    policy, the app's answer to it carries the headers, and an unlisted origin
    gets none, preflight or not (runs before 14 and 13).

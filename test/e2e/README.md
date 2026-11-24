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
| `E2E_RUNTIME` | empty (the supervisor) | Container runtime of every machine: `supervisor` or `embedded` (containerd, for nodes set up before the supervisor became the default); run both before releases |
| `E2E_NET_AGENT` | `rust` | the cluster network runs through the runtime pack's `armada-node` on every machine (ADR 0054): the run checks each machine applies it so, runs doctor's network checks through it, and fails if Go had to stand in anywhere. `go`: once the cluster is up, each machine in turn gets `"netAgent": "go"` in its `agent.json` and its service restarted, so Go's own code runs it (the fallback, while it remains) |
| `E2E_RUNTIME_AGENT` | `rust` | supervisor machines run containers through the runtime pack's `armada-node` (ADR 0054): the run checks every machine reports it (`armada node list -o json`, `.runtime.agent`), that doctor's `runtime-agent` check is ok, and that `armada cluster status` counts every node on armada-node (with `E2E_RUNTIME=embedded`, that every machine reports containerd instead). `go`: once the cluster is up, each machine in turn gets `"runtimeAgent": "go"` in its `agent.json` and its service restarted, and must report Go's code |
| `E2E_MOVE_GAP` | `60` | `runtime-containerd-move`: the most seconds a moved node's own public IP may go on failing after its `RuntimeMoveDone` event (its proxy is started again on the supervisor runtime) |
| `E2E_MOVE_OUTAGE` | `30` | `runtime-containerd-move`: the most seconds a moving node's own public IP may fail, from its first failed request to its first 200 again (the node pulls its proxy's image before it removes its containers) |
| `E2E_CONFORMANCE` | empty | Driver conformance test binary for the last machine's architecture, built with `GOOS=linux go test -c -tags integration -o bin/conformance ./internal/runtime/containerd/`; runs the suite on that node's runtime once the cluster is ready |

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
| `space-secret` | 3 (a space's secret) | secrets, spaces |
| `conntrack` | the connection tracking limit | connection tracking, usage reports |
| `network-key` | `armada node rotate-key` on a node: a new key file and a `NetworkKeyRotated` event | node keys, the agent's network (`nodeNet`), WireGuard |
| `isolation` | 4 | the cluster network (VXLAN, WireGuard, netlink), nftables, internal DNS (armada-dns), HAProxy's internal frontend |
| `load` | 5 (steady load) | the path from clients to the nodes |
| `rollout` | 5 (rolling update and rollback) | rollouts, readiness, draining, the proxy's live updates |
| `agent-restart` | 5 (agent restart) | the agent, adopting containers and a running proxy, certificates, armada-dns outliving armadad, log history search |
| `failover` | 6 | the control plane, etcd, elections |
| `node-loss` | 7 | self-healing, rebalancing |
| `backup` | 8 | `armadad backup` |
| `placement` | 9 | labels, restricted nodes, scheduling |
| `platforms` | 10 | image platforms |
| `cpu` | 11 | CPU reservations, capacity |
| `spread` | 12 | `placement.spreadBy` |
| `ip-rules` | 15 | `ingress.ipAllow`/`ipDeny`, trusted proxies, the PROXY protocol, client address headers, `X-Real-IP` |
| `plain-http` | 15 (plain HTTP without certificates) | `--tls`, the proxy's port 80 frontend |
| `sticky` | 16 | `ingress.sticky`, the proxy's cookie |
| `cors` | 17 | `ingress.cors`, the proxy's preflight answers |
| `sidecars` | 18 | init containers, sidecars, the shared network namespace |
| `tcp` | 19 | internal TCP ingress: HAProxy's TCP listeners, the clients map, nftables on the gateway, internal DNS |
| `queues` | 14 | autoscaling on queues and schedules, dialling from containers |
| `queue-jobs` | 20 | jobs started by a queue, network sandboxes, their isolation |
| `volume-backups` | 21 | volumes, rollouts of apps with volumes (images pulled first), backups to a bucket, restores from it |
| `volume-failover` | 22 (4 machines or more) | `failover: restore`, fencing of a node cut off from the control plane |
| `nfs` | 23 | NFS volumes: mounting with the kernel client, sharing between nodes, unmounting |
| `runtime-move` | 24 (supervisor through armada-node only) | the move from Go's image store to armada-node's: conversion at the agent's start, `converted.json`, removal of Go's store, the runtime report in `node list`, `cluster status`, and doctor |
| `runtime-containerd-move` | 25 (`E2E_RUNTIME=embedded` and 3 machines or more only) | the leader's move of containerd nodes to the supervisor runtime: draining one node at a time, `MoveRuntime`, the agent's migration and restart, `cluster status`, doctor |
| `reboot` | 13 | start-up order, units, state after a crash |

A release runs every scenario.

## What it checks

1. `armadad doctor` passes on every machine; the cluster forms with three
   voting servers and every node ready. With `E2E_CONFORMANCE`, the driver
   conformance suite passes on the last node's runtime, next to
   its running agent.
2. Nothing but SSH and HAProxy (80/443) listens outside the private,
   loopback, and bridge addresses.
3. The test app gets a certificate for its host name on every node; a secret
   reaches the container's environment and appears in no journal.
4. Isolation while replicas and apps come and go: a replica reaches its own
   app's replicas and itself on localhost; another app of its space reaches
   them only through the internal name, full or alone (`web`); another space
   reaches them in no way, and `web` from it is not this space's app;
   a space's app cannot reach a node's private IP; a removed app's address
   stays blocked. Both spaces are removed afterwards.
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
10. Image platforms: `armada revision list` lists every node architecture for
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
    - PROXY protocol, with the last machine as a TCP load balancer: the
      client its header names is `X-Real-IP` and what `ipAllow` judges; a
      machine that is not listed cannot send the header, and a listed one
      cannot connect without it.
    - Plain HTTP (`plain-http`): with certificates port 80 redirects; after
      `cluster update --tls=false` it serves the app with `X-Real-IP` and
      `X-Forwarded-Proto: http` set by the proxy, port 443 still serves, and
      `app show` gives the `http://` URL; turning certificates back on
      restores the redirect.
16. A sticky app with three replicas: a client that keeps the cookie reaches
    one replica through every node, and requests without it are balanced
    over several (runs before 14 and 13).
17. CORS: the proxy answers a preflight from a listed origin with the
    policy, the app's answer to it carries the headers, and an unlisted origin
    gets none, preflight or not (runs before 14 and 13).
18. Init containers and sidecars: an app with both runs; the init
    container's output is in its logs; the sidecar reaches the app on
    127.0.0.1; a failing init container keeps its app from starting and says
    why (runs before 14 and 13).
19. Internal TCP: an echo server with `protocol: tcp` on port 7000 and
    `allow: [client]` answers every connection from `client` of its space
    at `tcp-echo.e2e-tcp.internal:7000` and at `tcp-echo:7000`; another app of the space is
    refused, and an app of another space neither resolves the name nor gets
    an answer at its gateway; port 7000 is open on no node's private address
    (runs before 14 and 13).
20. Jobs started by a queue (runs after 14, before 13). The first machine
    needs `python3`, which runs a stand-in broker that answers like Redis on
    its private IP, port 6390: apps reach other apps' containers only through
    internal names over HTTP, so the broker lives outside the cluster.
    - A job in the default space has its empty queue read from a network
      sandbox and runs nothing.
    - 25 messages at 10 per run start 3 runs (`parallelism: 3`); once they
      finish on an emptied queue, no run follows.
    - The same job in an isolated space gets a node to read from, but its
      sandbox cannot reach a node's private IP, like the job's containers:
      the queue is never read and nothing runs.
    - The broker's password is in no journal, and no sandbox is left on any
      node once both jobs are deleted.
21. Volume backups (runs after 20, before 13). An S3-compatible gateway runs
    as an app (`versity/versitygw`); nodes reach its container's address.
    - An app with a volume (placed on the last machine by a label) gets its
      first backup by itself, and one on demand; both are listed from the
      bucket, which holds sealed chunks and snapshots and no file names.
    - A file changed after the last backup is back after
      `armada volume restore --snapshot latest`.
    - A rollout to another image keeps the app on its volume's node and the
      volume's contents.
22. Volume failover. The other machines get the label, and the last machine
    is cut off from the control plane (outgoing TCP to port 7443 dropped)
    while it stays up: its agent stops the app itself, the leader restores
    the latest backup on another machine and the app runs there
    (`VolumeFailedOver`) with the backup's contents. Once the rule is gone,
    the node is ready again and no longer runs the app.
23. NFS volumes. The last machine installs an NFS server
    (`nfs-kernel-server`) and exports a directory. `armadad doctor` finds an
    NFSv4 client; an app with two replicas on two nodes mounts the export,
    a file one replica writes is read by the other and is on the server, NFS
    volumes are not listed as node volumes, and the export is unmounted once
    the app is deleted.
24. The runtime's move (ADR 0054; runs after 23, before 13). The last machine
    gets `"runtimeAgent": "go"` and reports Go's code; an app pinned to it
    (`busybox:1.36`, an image no other scenario uses) runs from Go's image
    store and writes a file. Back on armada-node, the agent's start
    converts the store: its log names the conversion with nothing left
    out, and `converted.json` counts the images and the moved root
    filesystems and says the store is collected. Right then, before any
    restart: Go's store is gone, `armada cluster status` counts every node
    on armada-node, the app's replica is the same, reads the file it wrote
    and writes another (found in its root filesystem's new place), and the
    test app serves on every node. Every image armada-node's store did not
    have keeps the record Go made when it pulled it, also after
    armada-node recreated the replicas (no pull again), and doctor's
    `runtime-agent` check is ok. This stands in for an upgrade from a
    release that ran the supervisor runtime on Go's code: the script
    installs one release on every machine and has no step that upgrades
    from an older one, and the proxy's container in this run was made by
    armada-node (an upgrade moves one Go made the same way).
25. The leader's move of containerd nodes (ADR 0054, step 4; only with
    `E2E_RUNTIME=embedded` and three machines or more; runs after 24,
    before 13). An embedded run turns the move off right after `armadad
    init` (`cluster update --runtime-move=false`), so every scenario before
    this one runs on containerd. Turned on again, the leader moves every
    node: `RuntimeMoveStarted`, `RuntimeMoveMigrating`, and
    `RuntimeMoveDone` for each, one move after another and none given up;
    every node then reports armada-node, `agent.json` records the
    supervisor, `armada cluster status` counts every node on armada-node,
    doctor's `runtime-agent` check is ok, and the control plane has every
    voting member. Requests round robin over every public IP all return
    200, except those to a moving node's own IP from its
    `RuntimeMoveMigrating` event until it answers 200 again (its proxy is
    removed with its containers; at most `E2E_MOVE_GAP` seconds after its
    `RuntimeMoveDone` event, and at most `E2E_MOVE_OUTAGE` seconds from its
    first failed request); each node's journal shows it pulled its proxy's
    image before the move removed anything. Run it with
    `E2E_RUNTIME=embedded E2E_ONLY=runtime-containerd-move`; it leaves every
    machine on the supervisor runtime, so later scenarios run there.

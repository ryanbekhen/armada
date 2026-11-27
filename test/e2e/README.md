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
  `ARCH=arm64` for arm64) builds `armadad` with the runtime pack and
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
| `reboot` | 13 | start-up order, units, state after a crash |

A release runs every scenario.

## What it checks

1. `armadad doctor` passes on every machine; the cluster forms with three
   voting servers and every node ready. Every machine has `armada-node` in
   its runtime pack, its agent's journal shows `armada-node applies the
   cluster network`, and doctor's network checks pass. Every container
   record on every machine names crun, runc left no state, and doctor's
   `runtime` check is ok. At the end of the run, no agent's journal shows
   `armada-node failed`, which the agent logs with the operation and the
   error whenever armada-node fails a pass of the cluster network.
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

## Servers' units

A server machine runs three units (ADR 0055): `armada-etcd` (its etcd
member), `armada-server`, and `armada-agent`, which `armada-server.service`
wants. `cluster.sh` installs all four units on every machine and restarts,
stops, and reads the journal of `armada-agent` wherever a scenario is about
the node's agent, servers included, so it tests a release whose server
runs no agent of its own.

## Upgrading in place (`upgrade.sh`)

`upgrade.sh` builds a cluster on the release upgrades come from and
upgrades it machine by machine to the release under test. It needs five
fresh machines (three servers, two nodes) in a hosts file like
`cluster.sh`'s, and the same domain and ACME settings.

```bash
E2E_TO=v0.2.0 E2E_ETCDCTL=bin/etcdctl E2E_DOMAIN=e2e.example.org \
E2E_ACME_EMAIL=you@example.org sh test/e2e/upgrade.sh hosts
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `E2E_FROM` | `v0.1.0-alpha.44` | Release the cluster is built on (installed with `install.sh`) |
| `E2E_TO` | required | Release to upgrade to |
| `E2E_RELEASES` | empty (GitHub) | Local directory laid out as the release downloads (`TAG/armada_<version>_linux_<arch>.tar.gz`, `TAG/checksums.txt`, and the signature bundle), holding `E2E_FROM` and `E2E_TO`; copied to every machine and used through `ARMADA_DOWNLOAD_BASE=file://` by both `install.sh` and `armadad upgrade` |
| `E2E_ETCDCTL` | required | Linux `etcdctl` for the first machine's architecture, from the etcd release archive the runtime pack pins (`pack/lock.json`); reads the keyspace and the member IDs with the member's certificate |
| `E2E_ONLY`, `E2E_LIST` | | As for `cluster.sh`: the one scenario is `upgrade` |
| `E2E_ACME_CA`, `E2E_SSH_OPTS`, `E2E_SUDO` | | As for `cluster.sh` |

What it checks:

1. The cluster forms on `E2E_FROM` with three voting servers and two
   nodes in the `wireguard` network mode, and runs a public app (five
   replicas, a certificate for `hello.<domain>`), in a space of
   its own an internal HTTP app, an internal TCP echo server that only the
   prober app may reach, the prober (five replicas, counting
   what both answer through each node's resolver and proxy), an app with a
   volume holding a file, and a job that runs every minute.
2. `upgrade`: once no machine has a container runc created left (their
   records name no runtime; `E2E_FROM` moves them to crun and `E2E_TO`
   carries no runc, ADR 0056), with requests round robin over every
   public IP and the probers' internal requests running, `armadad upgrade
   --version E2E_TO` on the standby servers, the leader's machine, then
   the nodes, each waiting for every server to vote and every node to be
   ready. Afterwards no machine has a container or a state directory of
   runc's (`/run/armada/shim/*/runc/*`). Every
   public request returns 200 and no internal one fails; armada-node's
   image records keep the time each image was pulled; every etcd member ID
   is the same; and the keyspace is the same but for `servers/`, events,
   the commit and audit counters, the job's record, runs, and attempts,
   nodes' last seen and agent version, and what replica reports change
   (each replica's container, address, readiness, and restarts). The volume keeps its file, no run of the job failed, it runs
   on, servers run `armada-etcd`, `armada-server`, and `armada-agent`,
   nodes `armada-agent`, and `armadad doctor` passes.

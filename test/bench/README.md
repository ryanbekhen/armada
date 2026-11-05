# Network benchmark

`network.sh` measures how traffic between two nodes performs: container to
container throughput, HTTP through HAProxy for different replica
placements, and a large upload. It compares the cluster on the machines'
private network with a prototype where the nodes reach each other over a
WireGuard tunnel, to inform the design of Armada's cluster network. It runs
from your workstation over SSH and does not run in CI.

## What you need

- Exactly two Linux machines with systemd, reachable as root over SSH with a
  key (or set `BENCH_SUDO=sudo`). **The script removes any Armada state on
  them** (`/var/lib/armada`, `/etc/armada`, Armada's containers); it refuses
  to start on a machine that has some unless `BENCH_WIPE=yes`. Use machines
  you can throw away, not ones that serve anything.
- `curl` on both machines. For the `wireguard` mode, `wireguard-tools` (`wg`)
  and either the kernel's WireGuard module or `wireguard-go`, and the UDP
  port `BENCH_WG_PORT` open between the machines (the script opens it in
  firewalld when that runs; a provider's firewall is up to you).
- Outbound internet access from the machines (images and Alpine packages).
- `ssh`, `scp`, `jq`, `awk`, and `go` on your workstation (`go` builds the
  `hey` load generator for machine A).
- A Linux binary with the runtime embedded for each architecture:
  `make build-bundle` (add `GOARCH=arm64` for arm64).

## Running

List the two machines in a hosts file, as for `test/e2e`:

```
# NAME  SSH-TARGET        PRIVATE-IP  PUBLIC-IP
bench1  root@203.0.113.10  10.0.0.1    203.0.113.10
bench2  root@203.0.113.11  10.0.0.2    203.0.113.11
```

```bash
make build-bundle
ARMADA_BIN=bin/armada-linux-amd64 BENCH_WIPE=yes sh test/bench/network.sh hosts
```

Machines without a private network between them (or in different
providers) can still run the tunnel over their public addresses:

```bash
ARMADA_BIN_AMD64=bin/armada-linux-amd64 ARMADA_BIN_ARM64=bin/armada-linux-arm64 \
BENCH_MODES=wireguard BENCH_WG_UNDERLAY=public BENCH_WIPE=yes sh test/bench/network.sh hosts
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `ARMADA_BIN` | required unless both below are set | Binary for both machines |
| `ARMADA_BIN_AMD64`, `ARMADA_BIN_ARM64` | `ARMADA_BIN` | Binary for machines of that architecture |
| `BENCH_MODES` | `plain wireguard` | Modes to run, in order |
| `BENCH_WG_UNDERLAY` | `private` | Addresses the tunnel runs over: `private` or `public` |
| `BENCH_WG_PORT` | `51820` | UDP port of the tunnel |
| `BENCH_WG_MTU` | `auto` | MTU of the tunnel interface; `auto` is the smaller underlay MTU of the two machines less 80 bytes |
| `BENCH_WG_NET` | `10.99.0` | Tunnel addresses (`.1` for A, `.2` for B); must not clash with the machines' networks |
| `BENCH_DURATION` | `30` | Seconds per HTTP run |
| `BENCH_CONCURRENCY` | `32` | Concurrent requests of the loaded HTTP run |
| `BENCH_IPERF_SECONDS` | `20` | Seconds per iperf3 run |
| `BENCH_UPLOAD_MB` | `1024` | Size of the upload |
| `BENCH_BRIDGE_GW` | read from A | Container bridge address on A (each node has its own container subnet) |
| `BENCH_OUT` | `bench-DATE` | Directory for the results and raw output |
| `BENCH_SSH_OPTS` | empty | Extra `ssh`/`scp` options |
| `BENCH_SUDO` | empty | `sudo` when the SSH user is not root |
| `BENCH_WIPE` | empty | `yes` lets the script remove existing Armada state |

A run takes about 10 minutes per mode once the binary has been copied. When
it ends, for any reason, the script removes the cluster and the tunnel from
both machines and leaves the binary installed.

## What it measures

Machine A (the first line) runs the control plane, the clients, and the
load; machine B is the node with the "remote" replicas. For each mode the
script builds a two-node cluster:

- `plain`: the nodes use the `PRIVATE-IP` column, as clusters do today.
- `wireguard`: the script creates a WireGuard interface on each machine
  (keys made on the machine, only public keys copied) and builds the cluster
  with the tunnel addresses as the nodes' private IPs, so everything
  between the nodes (the control plane, HAProxy to replicas, published
  ports) goes through the tunnel. This is a prototype of the encryption and
  encapsulation cost, not the final design.

Then, with the CPU use of both machines sampled around each run:

1. **Container to container**: `iperf3` from a container on A to one on B
   through B's published port, with 1 and 4 streams, in both directions.
2. **Upload**: a file of `BENCH_UPLOAD_MB` posted from A through A's
   HAProxy to a replica on B. A transfer that fails or stalls until the
   timeout points at an MTU problem on the path.
3. **HTTP through HAProxy**: `hey` on A sends requests to A's internal
   frontend (`web.internal`, as a container on A would), once with one
   request at a time and once with `BENCH_CONCURRENCY`, for four placements
   of the app (nginx answering `200`):
   - `remote`: one replica, on B: every request crosses to the other node.
   - `local`: one replica, on A: no request leaves A.
   - `local-first`: one replica on each machine, routed as Armada routes
     today ([ADR 0024](../../docs/adr/0024-local-first-routing.md)).
   - `round-robin`: one replica on each machine, served from one weighted
     pool (a traffic split with one revision at 100%), as before local-first
     routing.

The results are a Markdown table in `BENCH_OUT/results.md` (also printed at
the end), next to the raw `iperf3` JSON and `hey` output. The CPU columns
are the busy share of all CPUs of each machine during the run, including
the load generator on A. Below the table, each machine's MTU towards the
other node and on the container bridge: a path MTU smaller than the
bridge's is the usual reason for transfers that stall or fail while small
requests work. The mode names the tunnel's underlay, and says when a
machine used `wireguard-go` instead of the kernel's WireGuard.

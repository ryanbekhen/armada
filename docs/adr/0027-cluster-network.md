# 0027. Cluster network

- Status: Proposed
- Date: 2026-11-04

## Context

Every node puts its containers on the same bridge subnet (`armada0`,
`10.121.0.0/24` by default, ADR 0011). Container addresses are therefore
neither unique across nodes nor routable between them, so everything that
crosses nodes goes through a port published on the node's private IP (CNI
`portmap`, a host port from 20000–32767). That has costs:

- Traffic between nodes (HAProxy to replicas, health checks) is plain HTTP
  on the private network, and every published port can be reached by any
  machine on that network, not only by the cluster (threat model T56).
- Replicas cannot reach each other directly, apps cannot be reached over
  TCP, and nothing restricts which app may call which (T13).
- The bridge's MTU is 1500 whatever the node's uplink. On a private network
  with a smaller MTU, large transfers depend on path MTU discovery.

The benchmark in `test/bench` measured, on two machines of one provider's
private network (MTU 1450), container to container and through HAProxy:

| | 1 vCPU, plain | 1 vCPU, WireGuard | 2 vCPU, plain | 2 vCPU, WireGuard |
| --- | --- | --- | --- | --- |
| iperf3, 1 stream | 6.1 Gbit/s | 0.47 Gbit/s | 14.6 Gbit/s | 2.1 Gbit/s |
| 1 GB upload through HAProxy | 74 MB/s | 32 MB/s | 149 MB/s | 76 MB/s |
| HTTP to a remote replica, 1 at a time | 1511 req/s | 1305 req/s | 2635 req/s | 1724 req/s |
| HTTP, local-first (ADR 0026), 1 at a time | 2073 req/s | 2037 req/s | 3176 req/s | 3159 req/s |

Encryption between nodes costs CPU that small machines feel. A bulk
transfer runs at about a seventh of the plain rate. Requests answered on
the receiving node (local-first) do not pay it at all. A lab run with an
underlay MTU of 1280 and a tunnel MTU of 1420 stalled every bulk transfer
while small requests worked.

## Decision

Containers get addresses that are unique in the cluster and routed between
nodes. Each node has its own subnet. Every node is connected to every other
over a tunnel that Armada sets up: plain by default, encrypted on request.
HAProxy reaches replicas at their container address, and nothing is
published on the private IP any more.

### Address plan

- **Cluster CIDR.** `armada init --cluster-cidr` sets it once for the
  cluster. The default is `10.120.0.0/16`, chosen so that it does not
  overlap the legacy bridge subnet during migration. It allows a prefix
  from /12 to /20.
- **Node subnet.** Each node gets a /24 from the cluster CIDR (253
  containers). The leader allocates it when the node joins, in the same
  transaction that registers the node. It is stored on the node record and
  freed when the node is removed. `armada0` takes the subnet's first
  address as its gateway. Internal ingress and DNS bind there (ADR 0007),
  so the address differs per node.
- **Overlap check.** The agent refuses to bring the network up when the
  cluster CIDR overlaps a route or address on the host (the tunnel's own
  routes excepted). `armada doctor` reports the same, and `armada join`
  checks it before the node joins.
- IPv6 is out of scope.

### Transport

The cluster CIDR is routed between nodes over one interface per node,
`armada-net`, in one of two modes chosen at `armada init --network`:

- **`plain`, the default.** It uses kernel VXLAN (no encryption, 50 bytes
  of overhead).
  - The socket is bound to the node's private IP. The forwarding entries
    are static, one per peer, with no multicast and no learning.
  - nftables accepts the VXLAN port only from current peers' private IPs.
  - Traffic between nodes is not encrypted. A machine on the private network
    can read it, and one that forges peer packets can inject traffic. That
    is the trust Armada already places in the private network today (T56).
  - It needs a private network between the nodes, like every cluster today.
  - Before release, the benchmark gains a `vxlan` mode to confirm its cost.
- **`wireguard`, for encryption between nodes.** It uses the kernel's
  WireGuard through netlink (pure Go, no CGO).
  - Each peer is another node, with the peer's private IP as its endpoint.
    Its allowed addresses are exactly the peer's node subnet, so the kernel
    drops any packet whose inner source is not that node's.
  - One UDP port, `--wireguard-port`, default 51820.
  - Kernel WireGuard cannot bind to one address. The agent therefore adds
    an nftables rule that accepts the port only on the private IP and only
    from the current peers' addresses. WireGuard never answers a packet
    that does not authenticate.
  - Where the kernel has no WireGuard, the agent runs the pure Go userspace
    implementation, embedded in the binary. It records the fallback on the
    node, and `armada doctor` and `armada status` warn about it, because it
    is markedly slower.
  - It is the mode for private networks the operator does not trust
    (shared or provider-managed networks), and for compliance needs.
  - It costs CPU: see the numbers above.

Routes for each peer's subnet point at `armada-net`, with the node's
gateway address as the source. Traffic within the cluster CIDR is never
masqueraded, so a replica sees the real source address of the caller.
Egress to everywhere else is masqueraded as today.

### Keys

Agents generate and announce a key in both modes, so that sites added
later (see "More than one site") need no migration. The WireGuard interface
exists only where a pair of nodes uses it.

- Each agent generates its WireGuard key pair the first time the network
  comes up. The private key is stored as `<data dir>/network.key` (`0600`
  in the `0700` data directory, checked when read), and never leaves the
  node or appears in logs.
- The public key travels in `Hello` over the existing mTLS stream. The
  server stores it on the node record and accepts it only from that node's
  certificate (T8).
- The leader sends each node its peer list in the node's proxy and network
  configuration on the Connect stream: name, public key, endpoint, and
  subnet. It sends that list again whenever a node joins, changes its key,
  or is removed.
- **No scheduled rotation.** WireGuard renews session keys every two
  minutes. The static key only proves which node a peer is, as the node
  certificate does. Such a key leaks only together with root on the node,
  and the response then is `armada node remove`, which drops the peer from
  every node within one configuration push. `armada node rotate-key NODE`
  makes the agent generate a new pair. Each peer then cuts over within
  seconds, with a short gap.
- **Not in backups.** The key belongs to the node, not to the control
  plane. After a restore, agents keep their keys and the leader rebuilds the
  peer lists from the node records.

### MTU

- The agent sets the MTU of `armada-net` to its uplink's MTU (the
  interface of the route to the peers) minus 80 for WireGuard or minus 50
  for VXLAN. `armada0` and every container interface get the same value
  (`mtu` in the CNI bridge configuration).
- Nodes whose uplinks differ get different tunnel MTUs. Each side sends
  packets that fit its own path, and TCP's MSS takes the smaller of the two.
- `armada doctor` sends unfragmented probes of the tunnel MTU to every peer
  and reports a path that drops them.

### Replica addresses and HAProxy

- Replicas publish no ports. An app's ingress port is its container port.
  The agent reports a replica's address as `<container IP>:<port>`. The
  server accepts only addresses in that node's subnet (T21 is updated), and
  HAProxy on every node targets them directly through `armada-net`.
- Local-first routing (ADR 0026) compares a server's address with the
  node's subnet instead of its private IP.
- Rollouts, drain, weights, health checks, and scale to zero are unchanged:
  only the address form changes.

### Access between apps

- **Direct traffic is denied by default.** nftables in the forward path
  accepts traffic from one container straight to another only in two
  cases:
  - between replicas of the same app;
  - to an app whose spec lists the caller in `ingress.allow: [app, ...]`.

  The rules key on address sets per app. The agent keeps those sets from
  the cluster-wide replica list that the leader sends in the network
  configuration.
- **Through `<app>.internal`.** HAProxy on the host reaches every replica,
  and containers call `<app>.internal` through their own node's HAProxy
  (ADR 0007).
  - For an app with `ingress.allow`, HAProxy admits only the listed apps.
    It checks the caller's source address against the same sets.
  - An app without `ingress.allow` stays callable by every app through
    `<app>.internal`, as today (T13 narrows to those apps).
- **Spoofing.** Each container's veth accepts only that container's address
  as a source. Across nodes, WireGuard's allowed addresses check the source
  node. In `plain` mode, the source check across nodes is only as strong as
  the private network.

### TCP apps and replica names

- `ingress.protocol: tcp` serves an app at a stable virtual address.
  - The leader allocates one address per app from `--service-cidr`
    (default `10.119.0.0/16`), set at `armada init` and stored on the app
    record.
  - Every node holds the service addresses on a dummy interface. HAProxy
    serves each app in `mode tcp` on `<service address>:<port>`.
  - `<app>.internal` resolves to that address, so `db.internal:5432` works
    with health checks, drain, and local-first like HTTP.
- `<replica>.<app>.internal` resolves to the replica's container address,
  for workloads whose members find each other. It answers for replicas that
  are `running`, and the same `ingress.allow` rules apply. Stable ordinal
  names are outside this ADR.
- Both get their own spec reference and threat model entries in the pull
  requests that implement them. Until then the spec rejects
  `ingress.protocol` and `ingress.allow` with a clear message.

### Peers that cannot be reached

- Agents report the last handshake per peer in `UsageReport`. The leader
  keeps it in memory, as it does other usage.
- A peer with no handshake for 3 minutes raises a `PeerUnreachable`
  condition event (ADR 0020) for both nodes. `armada status` and the
  metrics endpoint show it.
- HAProxy health checks already mark the replicas behind a broken path as
  down, and local-first keeps requests on the node. Scheduling does not
  change, because the control plane can still reach both nodes. A node the
  control plane loses is handled by self-healing (ADR 0008) as today.

### Nodes without the cluster network

- **Linux nodes with an external driver.** They always join the network at
  host level, because the routes, the tunnel, and HAProxy belong to the
  agent. Their containers join the node subnet only when the driver
  declares a new capability, `CAPABILITY_NODE_SUBNET`.
  - The agent passes the subnet, gateway, and MTU in a new field of the
    bridge request.
  - Driver changes go to the driver repositories, and `driverkit` grows by
    addition only.
  - A driver without the capability keeps publishing ports on the private
    IP. Its replicas are reported as `<private IP>:<port>`, which HAProxy on
    other nodes reaches over the private network, with T56 still applying
    to them.
- **macOS nodes (ADR 0016).** They stay on the model of published ports.
  The agent there runs as a user and cannot create the tunnel. Its
  replicas are reached at `<private IP>:<port>` and run with `--proxy
  none`. Containers on a Mac cannot call `<app>.internal`, as today.
  Default deny cannot filter traffic to them, so an app with
  `ingress.allow` is not placed on such nodes.

### More than one site

This ADR covers nodes that share one private network: one site. Nodes in
another provider, or behind NAT with no public address (a machine at home,
say), are left to a later ADR. This ADR prepares for them so that adding
them needs no new schema or migration:

- **Site.** Each node record has a site. Every node is in the cluster's one
  site until the later ADR adds a way to set it.
- **Endpoints.** Each node record has a list of endpoints, the addresses
  peers use to reach it. Today the list is only the private IP. A later
  node may announce a public endpoint, or none when it is behind NAT and
  starts every connection itself.
- **Transport per pair.** The agent chooses the transport for each peer
  rather than once for the node. Today every pair is in the same site and
  uses the cluster's mode. Pairs in different sites will always use
  WireGuard, whatever the mode.
- **Keys in both modes.** Every node already has a WireGuard key (see
  Keys).

The later ADR settles how such nodes join and reach the control plane
without exposing the main API, how traffic is relayed between nodes that
cannot reach each other, and how routing prefers the same site.

### Migration of running clusters

- A binary that knows this ADR bumps the state schema to 6: node subnets,
  the cluster network record, and service addresses. As with ADR 0012,
  nothing changes until every server runs it.
- Upgraded clusters stay on the legacy network until an admin runs
  `armada network enable [--network wireguard|plain]`. New clusters start
  with the network on. Enabling it proceeds in this order:
  1. The leader allocates every node's subnet. Each agent brings up
     `armada-net` and the routes, with no container changes yet. The command
     waits until every node reports a handshake with every peer and reports
     any pair that has none.
  2. One node at a time, the leader evacuates the node, as for a cordon,
     without dropping below the serving count. The agent then recreates
     `armada0` on the node subnet, and the node takes replicas again, now
     without published ports.
     - During this step, servers mix both address forms. Every node already
       has routes to every subnet, so every node's HAProxy reaches both
       kinds of replica.
     - An app with a volume (ADR 0025) is recreated in place, with the same
       short outage as a deploy.
  3. When every node is done, the network record is marked complete, and
     the firewall rules for published ports are removed.
- `armada network enable` can be resumed after an interruption: each node's
  state is recorded. Going back to the legacy network is not supported.
  Operators back up before enabling (ADR 0012).

### `armada doctor`

Doctor checks that:

- in the `wireguard` mode, the kernel has WireGuard, or warns that the
  userspace fallback will run;
- the UDP port is free and allowed by the host firewall;
- the cluster CIDR and service CIDR do not overlap the host's routes;
- each peer has a recent handshake;
- the tunnel MTU path to each peer passes unfragmented probes.

## Alternatives considered

- **Always encrypted, with no `plain` mode.** At about 2 Gbit/s on two
  vCPUs and 0.5 Gbit/s on one, encryption would cap every cluster on
  trusted networks for no gain there.
- **Encrypted by default.** Every cluster would pay the CPU cost above,
  including the many that run on a private network they already trust,
  where today's traffic is plaintext too. Encryption is one flag away, and
  `armada init` and the quickstart say what `plain` means.
- **Routing node subnets through the private network without a tunnel.**
  Many providers' networks drop packets for addresses they did not assign,
  so it would work only on some networks, and it would need a route table
  per provider.
- **Keeping published ports and encrypting each hop with TLS from HAProxy
  to replicas.** This needs a certificate per replica, still leaves replicas
  unable to reach each other or serve TCP, and does nothing for
  access between apps.
- **Scheduled key rotation.** Rotation would cut traffic between nodes on a
  timer for little gain, since session keys already renew every two minutes
  (see Keys).

## Consequences

- Nothing an app runs is published on the private IP any more, and apps can
  be isolated from each other (T13).
- By default, traffic between nodes stays plaintext on the private network,
  as today. T56 then narrows to reading that traffic and to forged VXLAN
  packets from the private network. The `wireguard` mode closes both.
  `armada init` prints the mode in use. `armada status` shows it, and the
  operations guide explains when to choose `wireguard`.
- Encryption costs CPU on every node that sends or receives traffic between
  nodes. The operations guide states the numbers above.
- Each node opens one UDP port to the other nodes: 51820 for `wireguard`,
  4789 for `plain`. Provider firewalls must allow it, and the docs and
  doctor say so.
- The cluster CIDR and the service CIDR cannot be changed after `init`.
- Nodes in other providers or behind NAT need the later ADR. The records and
  the agent already allow for them.
- The implementation lands in stages:
  1. the network, routing, MTU, and doctor;
  2. replicas without published ports;
  3. default deny and `ingress.allow`;
  4. TCP apps;
  5. replica names.

  Each pull request updates ADR 0007, ADR 0011, the threat model, and the
  guides for what it changes.

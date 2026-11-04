# 0027. Cluster network

- Status: Accepted
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
  - The socket is bound to the node's private IP (UDP 4789, VXLAN network
    identifier 7027). The forwarding entries are static, one per peer, with
    no multicast and no learning: each node's tunnel end has an address and
    a hardware address derived from its subnet, so peers need nothing more
    than the peer list.
  - A firewall rule accepts the VXLAN port on the private IP only from
    current peers' private IPs (iptables, which the container networking
    plugins already use on every node).
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
  - One UDP port, 51820. Every peer keeps its session up with a keepalive
    every 25 seconds, so the first packet after a quiet spell does not wait
    for a handshake, and a peer that stops answering shows.
  - A node that has not announced a key yet is left out of the others'
    peer lists until it does.
  - The agent changes only what differs from the device's current peers,
    so sessions survive every reconcile pass.
  - Kernel WireGuard cannot bind to one address. The agent therefore adds
    a firewall rule that accepts the port only on the private IP and only
    from the current peers' addresses. WireGuard never answers a packet
    that does not authenticate.
  - Where the kernel has no WireGuard, the agent runs the pure Go userspace
    implementation, embedded in the binary, with the usual root-only
    control socket. The agent logs a warning and `armada doctor` reports
    it, because it is markedly slower. The device lives as long as the
    agent, so traffic between nodes stops while the agent restarts.
  - It is the mode for private networks the operator does not trust
    (shared or provider-managed networks), and for compliance needs.
  - It costs CPU: see the numbers above.

Routes for each peer's subnet point at `armada-net`, through the peer's
tunnel end: the network address of the peer's subnet, which the bridge
never hands to a container. Each node holds its own tunnel end's address on
`armada-net`, so traffic the host itself sends to other nodes' containers
(HAProxy, health checks) leaves from that address. Traffic within the
cluster CIDR is never masqueraded, so a replica sees the real source
address of the caller. Egress to everywhere else is masqueraded as today.
Packets that arrive through the tunnel are forwarded only to the container
bridge.

The control plane sends every node the peer list (name, private IP, subnet)
in its assignment. The agent checks it again before it touches the host
(names, private addresses outside the cluster CIDR, subnets inside it, no
duplicates, the node itself listed at its own address), applies it on every
reconcile pass, and removes routes and entries of nodes that left.
`armada runtime reset` takes the interface and the firewall rules off a
removed node.

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
  certificate (T8), only when it is a well-formed key, and never when
  another node holds it: such an agent is refused until it makes a new
  key. The agent refuses a peer list with a malformed or repeated key.
- The leader sends each node its peer list in the node's proxy and network
  configuration on the Connect stream: name, public key, endpoint, and
  subnet. It sends that list again whenever a node joins, changes its key,
  or is removed.
- **No scheduled rotation.** WireGuard renews session keys every two
  minutes. The static key only proves which node a peer is, as the node
  certificate does. Such a key leaks only together with root on the node,
  and the response then is `armada node remove`, which drops the peer from
  every node within one configuration push. A later `armada node
  rotate-key NODE` makes the agent generate a new pair; until then,
  removing `network.key` and restarting the agent does the same. Each peer
  then cuts over within seconds, with a short gap.
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
- The agent refuses an uplink below 1280 bytes.
- `armada doctor` sends unfragmented probes of the tunnel MTU to every peer
  and reports a path that drops them (a later stage).

### Replica addresses and HAProxy

- Replicas publish no ports. An app's ingress port is its container port.
  The agent reports a replica's address as `<container IP>:<port>`. The
  server accepts only addresses in that node's subnet (T21 is updated), and
  HAProxy on every node targets them directly through `armada-net`.
- Local-first routing (ADR 0026) compares a server's address with the
  node's subnet instead of its private IP.
- Rollouts, drain, weights, health checks, and scale to zero are unchanged:
  only the address form changes.
- Only replicas of the embedded runtime on a node of the cluster network
  publish nothing; replicas started before stay on their port until they
  are replaced (the change is outside the spec hash, so nothing restarts).
- The node drops new connections into the container bridge that come
  neither through the tunnel nor through a published port (DNAT), so no
  other machine reaches containers by routing a node's subnet through its
  private IP.

### Access between apps

- **Direct traffic is denied by default.** nftables in the forward path
  accepts traffic from one container straight to another only between
  replicas of the same app. Every other call between apps goes through
  `<app>.internal`, where HAProxy applies the rules below.

  The rules key on address sets per app. Agents report each replica's
  container address, the server keeps only addresses in the node's own
  subnet, and the leader sends every node the cluster-wide list in the
  network configuration (`endpoints`). The agent adds its own containers as
  soon as they start, and validates the list again.
  - The `ip` table's forward chain sees traffic between nodes; a `bridge`
    table on `armada0` sees traffic between containers of one node, where
    it passes ARP and drops everything but IPv4.
  - Replies of known connections pass first, so a replica answers a proxy
    on another node, whose source is that node's tunnel end. Sources that
    are a node's own (tunnel end, bridge) pass.
  - Traffic to an address no app holds is dropped. An address two apps
    claim (one record stale) is left out of every set.
- **Through `<app>.internal`.** HAProxy on the host reaches every replica,
  and containers call `<app>.internal` through their own node's HAProxy
  (ADR 0007).
  - The agent writes the same address list, its own containers merged in,
    to a HAProxy map (`clients.map`: address → project and app) and
    replaces it through the Runtime API without a reload. The internal
    frontend looks the caller's source address up and each internal rule
    matches only callers of the app's project.
  - `ingress.allow: [app, ...]` narrows an app to the listed apps of its
    project (and its own replicas). An app without it stays callable by
    every app of its project.
  - A caller the map does not know matches no rule, so a container that
    has just started, the node itself, and anything else on the bridge get
    a 404 until its address is known (fail closed). The check needs the
    node's own subnet; nodes without one route internal names as before.
- **Spoofing.** Containers run without `NET_ADMIN` and `NET_RAW`, so they
  cannot change their address or send packets from another one. Across nodes, WireGuard's allowed addresses check the source
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
  are `running`, and the same project and `ingress.allow` rules apply. Stable ordinal
  names are outside this ADR.
- Both get their own spec reference and threat model entries in the pull
  requests that implement them. Until then the spec rejects
  `ingress.protocol` with a clear message.

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
  Default deny cannot filter traffic to their published ports, so
  `ingress.allow` only covers calls through `<app>.internal` for replicas
  there.

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

- the uplink's MTU leaves room for the tunnel, and reports the MTU
  containers get;
- in the `plain` mode, the kernel has VXLAN, and `armada-net` is up with a
  route for each peer;
- in the `wireguard` mode, the kernel has WireGuard, or a warning that the
  userspace fallback runs, and each peer has a handshake from the last
  three minutes;
- the node's subnet does not overlap the host's routes.

Later stages add:

- the UDP port is free and allowed by the host firewall;
- the cluster CIDR and service CIDR do not overlap the host's routes;
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
  `armada init --network` chooses the mode and prints it, and the
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
  1. the network, routing, MTU, and doctor: node subnets, the `plain`
     tunnel with routes, MTU, and firewall, and the `wireguard` mode with
     node keys (done);
  2. replicas without published ports (done for the embedded runtime;
     drivers follow with `CAPABILITY_NODE_SUBNET`);
  3. default deny and `ingress.allow`, between projects too (ADR 0029)
     (done);
  4. TCP apps;
  5. replica names.

  Each pull request updates ADR 0007, ADR 0011, the threat model, and the
  guides for what it changes.

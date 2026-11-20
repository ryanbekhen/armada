# ADR 0049: A WireGuard mesh over public addresses

## Status

Accepted

## Context

Every cluster needs a private network between its machines: the control
plane API, the join listener, etcd, and the cluster network bind only to
private addresses (security rule 4), and `armadad init` and `join` refuse a
machine without one. Many providers offer machines with a public address
and no private network, and machines of different providers or sites never
share one. Operators then build a private network themselves (a VPN mesh
with a key and a peer entry per machine, edited on every machine whenever
one is added) before Armada can start.

The `wireguard` mode of the cluster network (ADR 0025) already keeps a
WireGuard full mesh between all nodes: each node makes its key, the leader
hands every node the others' keys, and agents add and remove peers as
nodes join and leave. But the tunnel runs over the private network
(each peer's endpoint is its private IP) and carries only container
traffic, so it encrypts a private network the operator does not trust; it
cannot stand in for one that does not exist. That is the wrong way round:
the mesh Armada already keeps is what such machines lack.

## Decision

A cluster may be created as a **mesh**: `armadad init --network mesh`, a
third network mode beside `plain` and `wireguard`. Its nodes reach each other only over the WireGuard mesh, whose
peers' endpoints are the nodes' public addresses, and everything between
nodes (control plane API, etcd, HTTP-01 forwarding, metrics, container
traffic) goes through it. Clusters in the `plain` and `wireguard` modes keep
working as today; the mode is chosen once at `init`. One mode rather than
a flag beside `wireguard` keeps the choice a single answer to one
question, how the machines reach each other: a trusted private network
(`plain`), an untrusted one (`wireguard`), or none (`mesh`).

### Addresses

- **Mesh range.** `init --mesh-cidr` (default `10.122.0.0/16`, distinct
  from the default cluster CIDR and from the bridge subnet of nodes without
  a cluster network, `10.121.0.0/24`, and refused when it overlaps the
  cluster CIDR) is stored in `store.Network`. Each node gets
  one address of it (`/32`) from the leader, in the same transaction that
  gives it its container subnet.
- **The node's address is its mesh address.** It takes the place of the
  private IP everywhere the private IP is used today (`store.Node.PrivateIP`,
  the API, join and HTTP-01 listeners after joining, the etcd member, the
  metrics listener, the HAProxy and firewall rules that name nodes), so
  most code is unchanged and binding internal services to a private
  address still holds: the mesh address is private, and it exists only on
  the node's `armada-net`.
- **Endpoint.** Each node records the address its peers send WireGuard
  packets to (`store.Node.Endpoint`): the single public IPv4 address of its
  interfaces, or `--endpoint IP` on `init` and `join` (needed behind
  one-to-one NAT, where the public address is on no interface, and when a
  machine has several). The node announces it in `Hello`; the leader
  re-validates it (a unicast address that is not loopback, link-local, or
  multicast). WireGuard's own roaming updates a peer's endpoint from the
  last authenticated packet, so a changed address heals as soon as either
  side sends.
- A peer's allowed addresses are its mesh address and its container
  subnet, so the kernel drops anything else the peer sends.
- The mesh needs the kernel's WireGuard (Linux 5.6 or later): the
  userspace device of the `wireguard` mode lives inside the agent, and the
  mesh must be up before the agent and etcd start.

### Joining

A new machine has no mesh yet, so its first contact goes over the public
address:

- In a mesh cluster the leader binds the join listener (7444) to its
  endpoint, and only while at least one join token is unexpired and
  unused. Tokens are single use, so the listener closes as soon as the
  last one is redeemed, or when it expires: node and server tokens of a
  mesh cluster last 10 minutes by default and at most 1 hour. A token may
  name the address the machine joins from (`join-token --from IP`); the
  listener then closes a connection from any other address as soon as it
  is accepted, before TLS, while every open token names one. The leader
  looks at the tokens when one is created or redeemed and every 5 seconds;
  closing lets a join in flight finish its answer.
  Everything else about it stays as today: server-only TLS whose CA the
  joining machine pins by hash, `JoinService` only, rate limits, bounded
  connections, idle and total time limits, and tokens stored as hashes.
- `JoinRequest` and `JoinServerRequest` carry the machine's WireGuard
  public key and endpoint. The answer adds its mesh address and the
  current peer list (every node's mesh address, endpoint, key, and
  subnet). The machine brings up `armada-net` with those peers, and only
  then dials the API at the servers' mesh addresses. Nothing else is ever
  served on a public address.
- `armada node join-token` and `server join-token` print the leader's
  endpoint as the address to join.

### Starting without the control plane

Etcd and the API need the mesh before the control plane can tell anyone
about it, for instance when every machine restarts at once. Each node keeps
the last peer list it applied in `<data dir>/mesh.json` (0600, written on
every change, not in backups since it is learned again) and brings
`armada-net` up from it before it starts etcd or dials a server. The
assignment's peer list replaces it as soon as one arrives. A machine whose
servers all changed address while it was down needs `armadad join` again.

### Firewall

- The WireGuard port (51820/udp) is open to every address in a mesh
  cluster: peers' public addresses change, and WireGuard answers nothing
  that does not authenticate.
- The mesh range is reachable only through `armada-net`: the raw chain
  (`ARMADA-NET-PRE`) drops packets to or from mesh addresses that arrive on
  any other interface, so a machine on the provider's network cannot reach
  a node's internal services by routing the mesh range to it.
- `armadad doctor` checks that only 80/443, the WireGuard port, and the
  join port while a token is valid answer on the public address, that the
  mesh has a recent handshake with every peer, and that the endpoint is
  reachable.

### Unchanged

The client reaches a mesh cluster like any other: from a machine in the
mesh, or through SSH to a node (ADR 0048), with the servers' mesh addresses
in its config. Ingress stays on 80/443 of each node's public address.
Apps, spaces, isolation, and the internal DNS do not change.

## Consequences

- A cluster needs only machines with a public address: no private network,
  no VPN set up beforehand, and machines of several providers or sites can
  form one cluster.
- Security rule 4 gains two public ports in mesh clusters: the WireGuard
  port, which stays silent without a valid key, and the join port, only
  while a join token is valid. The threat model gains an entry for both.
- Every byte between nodes, the control plane's included, pays for
  encryption (ADR 0025's numbers). The benchmark in `test/bench` is run
  again with the mesh before release, and the documentation states the
  cost.
- Latency between nodes is the internet's. Etcd on servers far apart
  slows every write; the documentation recommends servers in one region,
  while nodes may be anywhere.
- An existing cluster cannot become a mesh, and a mesh cannot drop its
  mesh: the addresses of every node change. Moving means a new cluster.
- The `wireguard` mode over a private network stays for clusters that have
  one they do not trust.

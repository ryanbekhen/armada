# ADR 0050: Sites, switching the network mode, and nodes behind NAT

## Status

Accepted

## Context

A cluster's network mode is chosen once, at `init` (ADR 0025, ADR 0049):

- `plain` and `wireguard` need one private network between all machines;
- `mesh` needs a public address on every machine, gives each a mesh
  address, and cannot be added to an existing cluster, since every node's
  address would change.

Three kinds of cluster fall outside these modes:

- **A cluster that wants encryption later.** A `plain` cluster whose private
  network is no longer trusted has to be built again to become `wireguard`,
  although nothing about its nodes' addresses would change.
- **A cluster that grows past one site.** Machines at another provider, in
  another region, or at an office never share the first site's private
  network. A `plain` or `wireguard` cluster cannot take them, and a `mesh`
  cluster encrypts and routes over the internet even between machines that
  share a private network.
- **Machines behind NAT.** A machine in an office or at home usually has no
  public address anyone can reach: its router, or the provider's
  carrier-grade NAT, only lets connections out. No mode takes it today.

ADR 0025 prepared for this ("More than one site"): a site per node,
endpoints per node, a transport chosen per pair of nodes, keys in every
mode. Those parts were never built. This ADR settles them.

## Decision

Three steps, each useful alone, implemented in this order:

1. the mode of a running `plain` or `wireguard` cluster can be switched;
2. nodes belong to **sites**: within a site, nodes talk over their
   private network in the cluster's mode, and between sites always over
   WireGuard between public addresses;
3. a node may be **behind NAT**: it starts every connection, and traffic
   between two nodes that cannot reach each other is relayed through a
   node with a public address.

Node addresses never change in any step. That is what makes these
possible on running clusters, where turning a cluster into a `mesh` is
not.

### 1. Switching between `plain` and `wireguard`

`armada cluster set --network wireguard` (or `plain`) switches a running
cluster. The leader records the switch in `store.Network`:
- the target mode;
- the step it has reached;
- when it began.

It proceeds in steps, so traffic between nodes never stops:

1. **Prepare.** Every agent brings up the target transport beside the
   current one, on a second interface, `armada-next`. Toward `wireguard`,
   the WireGuard device is configured with every peer: keys already exist
   in both modes (ADR 0025, Keys). The firewall opens the target's port to
   peers. Routes still use the current transport, except a route to each
   peer's tunnel address over `armada-next`. Every 5 seconds the agent
   pings those addresses and counts a peer as reached only when its answer
   comes in through `armada-next`. It reports, in its `UsageReport`, which
   peers it does not reach yet.
2. **Move.** Once every node that is not lost reaches every peer on the
   target transport, the leader records the move. Agents point each peer's
   routes at the target transport and report when they have. The current
   transport stays up for peers that have not moved yet.
3. **Clean up.** Once every node reports the move, the cluster's mode
   becomes the target. Agents remove the old transport and its firewall
   rules, and rename `armada-next` to `armada-net`, which takes the
   interface down for a moment. Each agent records the new mode in
   `agent.json`.

A node that was lost during the switch applies the cluster's mode when it
returns, and loses traffic to its peers for at most one reconcile pass.

How it is shown and when it is refused:

- `armada cluster status` shows the step and the nodes the switch waits
  for, with the peers each cannot reach yet.
- A second switch is refused while one runs.
- A switch is refused while a node runs a version that does not announce it
  (`Hello.network_switch`).
- A switch to `wireguard` needs the kernel's WireGuard on every node: the
  userspace device's control socket would not follow the rename.
- A server that does not know switches ignores one, so its nodes stay on
  (or go back to) the cluster's mode if it becomes the leader.
- `mesh` clusters are refused: their nodes' addresses depend on the mode.

MTU:

- WireGuard's MTU is 30 bytes smaller than VXLAN's.
- After a switch to `wireguard`, the bridge and the containers keep the
  larger MTU. Containers created after the agent's next start use the
  tunnel's.
- In every mode, the agent clamps the MSS of TCP connections leaving
  through the tunnel to its MTU, so TCP is never affected.
- Other protocols rely on the "fragmentation needed" message the node
  sends back.

### 2. Sites

Every node belongs to one site, recorded in `store.Node.Site`.

**Naming and setting a site:**

- Names are like label values.
- An empty site is the cluster's first site, so every existing cluster is
  one site, as today.
- An admin sets the site of a new machine on its join token
  (`armada node join-token --site office`, also on `server join-token`).
- `armada node site NODE NAME` moves a node to another site.
- The site decides how peers reach a node, so only admins set it; the
  agent never reports it.
- Nodes carry the site as the reserved label `armada.site`, so placement
  can require a site or spread replicas over sites (`spreadBy: armada.site`,
  ADR 0014).

**Transport per pair.** The transport between two nodes depends on their
sites:

| Pair | Transport |
| --- | --- |
| Same site | The cluster's mode: VXLAN in `plain`, WireGuard in `wireguard`, both over the nodes' private addresses. In `mesh`, WireGuard over the private addresses when both nodes have one in the site (below), else over their endpoints. |
| Different sites | Always WireGuard between the nodes' endpoints, whatever the mode. |

- A `plain` cluster with a second site runs both transports.
- Same-site peers go over VXLAN on `armada-net`. Peers in other sites go
  over a second device, `armada-wg`, with each peer's node address and
  container subnet as its allowed addresses.
- In `wireguard` and `mesh` clusters, one WireGuard device holds every
  peer, each with the endpoint its pair calls for.

**Addresses.**

- A node keeps the address it joined with:
  - in `plain` and `wireguard` clusters, its private IP;
  - in `mesh` clusters, its mesh address.
- A machine that joins a `plain` or `wireguard` cluster without a private
  network gets a mesh address, as a `mesh` node does. The cluster's mesh
  range (`--mesh-cidr` on `cluster set`, default `10.122.0.0/16`) is
  recorded with the first such node and may not overlap the cluster CIDR or
  any node's address.
- Node addresses must be unique across the cluster. A joining node whose
  private IP another node holds is refused, and it can join with a mesh
  address instead (`join --no-private-ip`).
- `doctor` compares the peer list the node keeps (`mesh.json`) with the
  networks on its own interfaces, and warns when another site's node
  address lies inside one of them: that host on the local network becomes
  unreachable from the node. The check runs on the node itself, so nothing
  about its local networks leaves it.
- In a `mesh` cluster, a node may also announce its private address
  (`--private-ip`, or the only one detected) for peers in its own site.

**Endpoints.**

- A node with peers in other sites needs an endpoint, as in ADR 0049:
  - the only public IPv4 address on its interfaces;
  - `--endpoint` on `init`, `join`, and `server join`;
  - or, on a running machine, `armadad endpoint set IP`, which writes
    `agent.json` and restarts the service.
- `armadad endpoint set` also covers a machine whose public address changed
  for good, which ADR 0049 left to joining again.
- The node announces its endpoint in `Hello.endpoint`, checked by the
  leader as in ADR 0049.

**Joining from another site.**

- A machine outside the first site cannot reach the private join listener.
  The leader then binds the join listener to its endpoint while a token is
  open, exactly as in a `mesh` cluster (ADR 0049, Joining):
  - single-use tokens, 10 minutes by default and at most 1 hour;
  - `--from`;
  - closed before TLS.
- The join token prints the leader's private address for a token of the
  leader's site, and its endpoint for any other site.
- A leader with no endpoint cannot hand out tokens for other sites. The
  token command says so.
- The joining machine receives its address and the peer list, and brings up
  its WireGuard device before it dials the API, as in ADR 0049.
- Each node keeps the peer list of its WireGuard peers in `mesh.json`, so
  the tunnels between sites come up before etcd after a restart.

**Firewall.**

- While a cluster has one site, nothing changes. Once it has a second site,
  every node opens the WireGuard port to every address, as in a `mesh`
  cluster: other sites' endpoints may change, and WireGuard answers nothing
  that does not authenticate.
- The raw chain drops packets from another site's node addresses, and from
  the mesh range, that arrive on any interface but the WireGuard device, so
  a host on the local network cannot pose as a node of another site.

**Servers and latency.**

- Servers may be in any site with an endpoint. Etcd waits for a majority on
  every write, so the documentation recommends servers in one site, or in
  sites close together.
- Local-first routing (ADR 0024) keeps requests on the node when it can.
  Preferring the same site over another site in HAProxy is left for later;
  placement by `armada.site` keeps apps that call each other together.

### 3. Nodes behind NAT

**Joining behind NAT.**

- A node joins behind NAT with `--endpoint none`: it has no address
  others can reach.
- Servers need an endpoint, so `server join --endpoint none` is refused.

**Who connects to whom.**

- **Node behind NAT to a node with an endpoint.** The node behind NAT
  configures the endpoint and sends a keepalive every 25 seconds. That
  keeps the NAT's mapping open and lets the other node reply through it.
  The other node configures the peer with no endpoint and uses the one
  WireGuard learns from the authenticated packets.
- **Two nodes behind NAT in the same site.** They reach each other over
  their private addresses, as any pair in a site.
- **Two nodes behind NAT in different sites.** They cannot reach each other
  directly, so their traffic goes through a **relay**.

**Choosing the relay.**

- The relay is a node with an endpoint. The leader picks one per site that
  has nodes behind NAT, by rendezvous hash over eligible nodes with an
  endpoint (ready, not cordoned), so the choice stays stable as nodes come
  and go.
- `armada node relay NODE` pins a choice; `--clear` drops it.
- The relay of each site is sent in `Assignment.network`.

**Routing through the relay.**

- With WireGuard's allowed addresses, no other protocol is needed. On a
  node behind NAT, the relay's peer entry also allows the addresses and
  subnets of every node the node cannot reach directly, and those nodes
  have no peer entry of their own. On the relay, each such node's entry
  stays as it is.
- The relay forwards between peers on its WireGuard device. Its
  `ARMADA-NET-FWD` accepts traffic from the device back into it, and
  nothing else changes.

**What the relay sees.** The relay decrypts what it forwards and encrypts
it again. It sees the traffic between the two nodes as any node sees its
own. The relay is a member of the cluster holding a node certificate, so
this adds no new party, but it widens what one compromised node sees. The
threat model records it.

**Ingress and MTU.**

- A node behind NAT receives no public traffic. HTTPS for the cluster's
  domains reaches only nodes that the operator's DNS names, which must have
  public addresses. `armada node list` marks nodes behind NAT.
- Connections from the internet reach replicas on nodes behind NAT through
  the proxies of public nodes, like any replica on another node.
- Lines behind NAT often have a smaller MTU (PPPoE). A node's tunnel MTU
  follows its own uplink as today, and `--mtu` on `join` sets a smaller one.
  The MSS clamp of step 1 keeps TCP working across paths of different MTU.

### Diagnostics

`armadad doctor` and `armada node show` report for every peer:
- the transport and endpoint in use;
- whether the peer is reached directly or through the relay;
- the last handshake.

A peer unreachable for 3 minutes raises `PeerUnreachable`, as ADR 0025
planned.

## Consequences

- A `plain` cluster can be encrypted without being built again, and go back.
- A cluster can grow across providers, regions, offices, and homes while
  every node keeps its address. Within a site, traffic keeps the cost of the
  cluster's mode; between sites, it is encrypted and pays for it.
- Turning an existing cluster into a `mesh` stays unsupported (ADR 0049).
  Sites give a running cluster what the `mesh` gave new ones.
- Security rule 4 changes: in a cluster with more than one site, the
  WireGuard port faces the public, and the leader's join listener faces it
  while a token for another site is open. The threat model gains an entry
  for sites and relays.
- A relay carries the traffic between its site's nodes behind NAT and the
  other sites' nodes behind NAT, which costs it CPU and bandwidth. Keeping
  it on a node with capacity is the operator's choice (`armada node relay`).
- The state schema grows (`Node.Site`, the switch in `Network`, relays). As
  with ADR 0012, nothing changes until every server runs a binary that knows
  it.
- Each step needs tests on real machines:
  - a switch both ways under load;
  - two sites;
  - nodes behind a NAT gateway in two sites.

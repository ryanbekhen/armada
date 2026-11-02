# 0014. Node labels and app placement

- Status: Accepted
- Date: 2026-11-01

## Context

A cluster can mix very different machines: large servers next to small
single-board computers, amd64 next to arm64, machines in different cities
joined over one private network. Until now the scheduler treated every
ready node alike. It checked that the memory fits and spread each app by
replica count, so:

- an app could not be kept to a group of machines ("only the small boards
  in one region");
- a machine could not be kept for particular apps;
- an image built for one architecture could land on a node of another and
  fail to start there forever;
- a one-core board received as many replicas as a sixteen-core server.

## Decision

### Labels

- Every node has **labels**, `key=value` pairs. Admins set them with
  `armada node label NODE key=value ... [key-]`, or put them in a join token
  (`armada token create --label key=value`) so a node carries them from its
  first moment; the node never chooses its own labels. A compromised node
  could otherwise label itself to attract an app and its secrets.
- The agent reports its OS and architecture; the server shows them as the
  labels `armada.os` and `armada.arch`. The `armada.` prefix is reserved:
  admins cannot set or remove such keys.
- Keys are lowercase letters, digits, `.`, `-`, `_` and `/` (at most 63
  characters, starting and ending with a letter or digit); values the same
  without `/`. At most 32 admin labels per node. Labels are validated on
  the server and again where they are read.

### Restricted nodes

- A node is **open** (the default: any app may run there) or
  **restricted** (`armada node restrict NODE`, undone by `armada node open`).
  A restricted node only runs apps whose placement names at least one of
  its admin labels. Keeping a machine for one app means giving it a label
  only that app asks for.

### Placement in the app spec

```yaml
placement:
  require:            # every key must match; a list matches any of its values
    region: sulawesi
    kind: [raspi, small]
```

- `placement.require` is a hard rule. A node is eligible for an app when it
  is ready, not cordoned, matches every required label, fits the replica,
  and, if restricted, is named by one of the app's required labels.
- If no node is eligible, the replica is not placed anywhere else: it stays
  missing, `armada status` says why (no node matches, or matching nodes are
  full), and a rollout that cannot place its replicas fails as before,
  leaving the old revision serving.
- Placement is part of the revision. Changing it rolls the app out to
  eligible nodes.
- A replica whose node stops being eligible (a label removed, the node
  restricted) is handled like a replica on a cordoned node: a replacement is
  placed on an eligible node first, then the replica is drained. A replica
  that gets no traffic (it failed to start, for example) is retired at
  once, on a cordoned node too, so it never holds the surge its
  replacement needs.
- Self-healing (ADR 0008), cordon evacuation, and rebalancing (ADR 0013)
  only ever choose eligible nodes; rebalancing spreads an app over its
  eligible nodes only.

### Image platforms

- The control plane never contacts registries: agents pull images, with
  the app's registry credentials, as before. When an agent pulls a
  revision's image it reports the image's platforms (`os/arch`, from the
  index, or from the config of a single-platform image). When the image
  has no variant for the node, the agent reads the platforms from the
  registry without pulling, fails the replica with a message naming them,
  and reports them too.
- The server keeps the first valid list for the revision (like the
  digest) and shows it in `armada revisions`. From then on a node is
  eligible only if its `armada.os`/`armada.arch` is in the list; a replica
  on a node that is not, which has failed to start, is replaced on one
  that is. A node that does not report its platform is not ruled out.
- Until the first report, replicas may land on a node that cannot run the
  image; that replica fails fast and teaches the server. If no node can run
  the image, nothing is placed, `armada status` says which platforms the
  image is built for, and the rollout fails as usual, leaving the old
  revision serving. A deploy is therefore not refused up front.

### CPU and memory reservations

Every replica reserves CPU and memory on its node, and nothing is
overcommitted: a node takes a replica only if what its replicas reserve,
draining ones included, leaves room for it.

- **Memory** reserves `resources.memory` (default `256Mi`), which is also
  the limit.
- **CPU** reserves `resources.cpu` when the spec sets it, which is also
  the limit. A spec without it reserves 100m and has no limit, so small
  apps fit many to a core and can use idle CPU.
- Containers get a CPU weight in proportion to their reservation, so on a
  busy node each gets at least its share.
- Armada keeps 100m of CPU and 128Mi of memory on every node for the
  agent, containerd, and HAProxy, and another 100m on control plane
  servers. The rest is what replicas share.
- Capacity is what the agent reports, bounded by the server. A node that
  reports none (0) is not checked.
- Reservations only gate new replicas. Replicas that no longer fit, after
  an upgrade or a smaller capacity report, keep running.
- Spreading is unchanged: an app's replicas first, then the number of
  replicas on the node; free memory and then free CPU only break ties, so
  an inflated capacity report cannot attract more than a node's share.
- `armada status` names what is short when no allowed node has room
  ("none has 300m of CPU free").

### Implemented in later steps

- **`placement.spreadBy`:** spread an app's replicas over the values of a
  label (cities, racks).

Until these steps land, the spec rejects `spreadBy`.

### Topology

Nodes may be far apart: agents tolerate latency. Control plane servers
should be close to each other (the same city or region), because etcd
commits need a round trip between them.

## Alternatives considered

- **Nodes label themselves at join:** simpler, but a node holding a join
  token could claim any label and attract apps meant for other machines.
- **A per-node list of allowed app names:** grows with every app and goes
  stale; one label per purpose does the same job with one concept.
- **Soft preferences ("prefer this region"):** useful, but weights and
  their interplay with spreading are hard to explain; the spec leaves room
  for `placement.prefer` later.
- **Leaving architecture to the user:** every failure would appear only on
  the node, after the rollout started.
- **Spreading replicas in proportion to node capacity:** bigger machines
  would take more of the cluster's work, but capacity is self-reported, and
  a compromised node advertising more would attract replicas, and with
  them secrets, of apps it would not otherwise run. Spreading by count
  with capacity as a tie-break bounds that to a node's share.
- **A separate CPU request and limit:** more control, but two numbers for
  every app and a new meaning for an existing field; one value that is
  both, with a burstable default, covers the common cases.
- **The server reads image platforms at deploy and refuses impossible
  deploys:** it would need outbound access to every registry an app names,
  the registry credentials on the control plane for a new purpose, and
  reachability of registries that only the nodes may reach.

## Consequences

- Apps can be kept to groups of machines, and machines to apps, with one
  concept that `armada node list` shows.
- A label change can move replicas, through the same replace-then-drain
  path as a cordon, never dropping below the serving count.
- Node records gain fields that older servers would drop when they rewrite
  a node, so the state schema moves to 2 (ADR 0012): once migrated, older
  servers cannot lead.
- Restricting a node or narrowing a placement can leave replicas with
  nowhere to go; `armada status` reports it instead of placing them on an
  unsuitable node.
- Image platforms are self-reported by agents, like digests: a compromised
  agent can report a wrong list for a revision and keep it off nodes that
  could run it. Revisions gain a field; a server that predates it drops it
  when it records a digest, and agents report it again, so no schema change
  is needed.

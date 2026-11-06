# 0024. Local-first routing

- Status: Accepted
- Date: 2026-11-03

## Context

Every node's HAProxy serves the public ingress and `<app>.internal`. Balancing
an app's requests in turn over all of its ready replicas sends about two of
every three requests across the private network when the app has replicas on
three nodes, even when a replica on the node that received the request is idle.
Each crossing adds a network round trip and puts the request on the private
network.

Sending every request to the node's own replicas would be just as wrong: public
DNS often points at one node, which would then serve the app alone while the
other replicas idle.

A frontend also runs its rules for every request, so routing must not need
rules per app: a request's cost would then grow with the apps of the cluster.

## Decision

Each node's HAProxy prefers the replicas on its own node while they are about as
busy as the app's other replicas, and spreads the rest over every replica.

- **Weighted least connections.** A local-first app's backend uses
  `balance leastconn`, which picks the server with the fewest requests in
  progress for its weight. On each node a replica weighs 11 when its address is
  on the node's private IP or, with the cluster network (ADR 0025), in the node's
  container subnet, and 10 otherwise. Under load a local replica takes at most
  about a tenth more than a replica elsewhere.
- **Idle apps stay on the node.** Servers with no request in progress tie
  whatever their weight, so the backend has one rule of its own: with no other
  request in progress, `use-server` picks a local replica through the local map
  (`local.map`: `<backend>/<n> <slot>`, four entries per backend taking the local
  slots in turn, one chosen at random). As soon as that replica is busy the others
  are idle, and they take the next request.
  - A slot the map does not have, or a server that is down, falls through to
    balancing, so with no local replica up every request goes to the others.
  - Only the requests through this node's proxy count. Each proxy balances its
    own traffic and needs no state from other nodes.
- **No rule per app in a frontend.** The choice happens inside the app's backend,
  so a request runs only its own app's rule.
- **No reload.** A weight is a server property set through the Runtime API like
  its address (ADR 0002), and the local map is replaced the same way, so the
  first replica arriving on a node and the last one leaving it change nothing
  else.
- **Which apps.** The control plane marks each backend `local_first` in the proxy
  configuration. It does so for every app except one that splits traffic between
  revisions (ADR 0022): there every server keeps its weight and the backend takes
  turns, because preferring a node's replicas would skew the split. Label
  backends (`<label>--<app>`) are not local-first. A node that does not know its
  private IP treats nothing as local.
- **Compatibility.** A control plane that does not know `local_first` leaves it
  unset, and agents then balance in turn. An agent that does not know it ignores
  it. No state schema change.

## Alternatives considered

- **Failover only** (other nodes only when no local replica is up): one node
  behind public DNS would serve the whole app.
- **A fixed concurrency per replica** (`maxconn`) before spilling over: needs a
  number per app that most apps do not have, and a wrong one either overloads
  replicas or gives up locality.
- **Weights with balancing in turn**: they bias the share of requests but send a
  fixed part away at any load.
- **Weights alone with least connections**: idle servers tie, so an idle app's
  requests would take turns over every node.
- **A second backend per app with only its local servers, picked by comparing
  the load of both**: HAProxy can only name a backend's load in a rule, so every
  frontend runs rules for every app with a replica on the node. It also checks
  each local replica twice, and needs a reload for an app's first local replica.

## Consequences

- Requests stay on the node that received them unless its replicas are busier
  than the others, which cuts latency and traffic between nodes.
- A request's cost does not grow with the apps of the cluster, and each replica
  is health checked once by each node's HAProxy, every 2 seconds.
- Balance across nodes depends on how traffic arrives: a node receiving more
  requests runs its replicas somewhat busier.
- Least connections also balances long-lived requests, which balancing in turn
  does not.

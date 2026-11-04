# 0026. Local-first routing

- Status: Accepted
- Date: 2026-11-03

## Context

Every node's HAProxy serves the public ingress and `<app>.internal`. It
balanced each app's requests round robin over all of the app's ready
replicas, on every node. With replicas on three nodes, about two of every
three requests crossed the private network to another node, even when a
replica on the node that received the request was idle. Each crossing adds
a network round trip and puts the request on the private network.

Sending every request to the node's own replicas would be just as wrong:
public DNS often points at one node, which would then serve the app alone
while the other replicas idle.

## Decision

Each node's HAProxy prefers the replicas on its own node while they are no
busier than the app's replicas overall, and spreads the rest over every
replica.

- **Local backend.** Next to `be_<app>`, which holds all of an app's
  servers, each node renders `lo_<app>` with the servers whose address is
  on its own private IP, or with the cluster network (ADR 0027) in its own
  container subnet. Both use the same slots, health checks, and
  Runtime API updates (ADR 0002). `lo_<app>` is rendered even while empty,
  so a replica arriving on a node or leaving it never needs a reload.
- **Choice per request.** Let L be the requests in progress on the N local
  replicas, and R the requests in progress through `be_<app>` on all M
  replicas. A request goes to `lo_<app>` while N > 0 and
  L/N ≤ (L+R)/M, compared as L·M − (L+R)·N ≤ 0 in integers with HAProxy
  variables. Otherwise it goes to `be_<app>`, which may still pick a local
  replica.
  - At low load every request stays on the node.
  - Under load the excess spreads over all replicas.
  - When the node has no replica that is up, every request goes to the
    others.
  - Only the requests through this node's proxy count. Each proxy balances
    its own traffic and needs no state from other nodes.
- **Which apps.** The control plane marks each backend `local_first` in the
  proxy configuration. It does so for every app except one that splits
  traffic between revisions (ADR 0024): there every server must keep its
  weight, and preferring a node's replicas would skew the split. Label
  backends (`<label>--<app>`) are not local-first. Scale to zero (ADR 0023)
  still checks `be_<app>`.
- **Usage.** A replica's load for autoscaling and scale to zero (ADRs 0022,
  0023) is the sum of its rows in both backends.
- **Compatibility.** A control plane that does not know `local_first`
  leaves it unset, and agents then route as before. An agent that does not
  know it ignores it. No state schema change.

## Alternatives considered

- **Failover only** (other nodes only when no local replica is up): one
  node behind public DNS would serve the whole app.
- **A fixed concurrency per replica** (`maxconn`) before spilling over:
  needs a number per app that most apps do not have, and a wrong one either
  overloads replicas or gives up locality.
- **Weights favouring local servers**: they bias the share of requests but
  still send a fixed part away at any load, and they would conflict with
  the weights of traffic splitting.

## Consequences

- Requests stay on the node that received them unless its replicas are
  busier than average, which cuts latency and traffic between nodes.
- Each local replica is health checked twice by its node's HAProxy (once in
  each backend), every 2 seconds.
- Balance across nodes depends on how traffic arrives: a node receiving
  more requests runs its replicas busier, up to the average of all.

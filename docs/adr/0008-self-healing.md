# 0008. Self-healing: rescheduling replicas from lost nodes

- Status: Accepted
- Date: 2026-10-31

## Context

When a machine dies, HAProxy health checks on the other nodes stop sending it
traffic within seconds, but its replicas used to stay scheduled
there: an app ran below its desired count until the node came back or an
operator ran `armada node remove --force`, and an app with one replica on
that node stayed down. A platform that runs apps
unattended has to replace them on its own.

The control plane only sees a node through the agent's stream, so it
cannot tell a dead node from a network partition between itself and that
node. A node cut off from the control plane may still serve traffic.

## Decision

- A node is **lost** once it has been disconnected for `--node-lost-timeout`
  (default 5 minutes, at least 10 seconds). Disconnection is detected
  through the stream ending or gRPC keepalives (about 40 seconds for a node
  that vanishes without closing its connection). `armada node list` shows
  the node as `lost`.
- Replicas on a lost node no longer count toward the app's desired count or
  the rollout surge, so replacements are scheduled on ready nodes right
  away.
- The lost replicas themselves are retired (drained, then removed) only
  once enough replacements serve, through the same path as cordon
  evacuation. If the node was only partitioned, it keeps serving until its
  replacements take over; a single-replica app is never left without a
  replica because its only copy was dropped first. This holds for apps that
  publish no port as well: their running, ready replicas count as serving
  without an address.
- **Partition guard:** if more nodes are lost than ready, nothing is
  rescheduled. In that situation the control plane is more likely the one
  cut off, and rescheduling would empty healthy nodes.
- When a lost node comes back, its agent receives an assignment without the
  old replicas and removes their containers. Apps left unevenly spread are
  then rebalanced one replica at a time (ADR 0013).
- **A lost network.** A replica's container whose network interface is gone
  can reach nothing and answers no probe, and restarting its process would not
  bring the interface back. When two usage samples in a row find no interface,
  the agent recreates the container.

## Alternatives considered

- **Delete lost replicas immediately.** Faster, but drops a partitioned
  node's in-flight requests and can leave an app with no replica while the
  replacement starts.
- **Readiness from HAProxy health checks across nodes.** Would distinguish
  "unreachable from the control plane" from "unreachable from peers", but
  needs status aggregation from every node; possible later.
- **Fencing (stopping containers on a node that lost the control plane).**
  Would avoid duplicates during a partition, but turns a control plane
  outage into an application outage. Armada's apps are stateless replicas
  behind a load balancer, where a short-lived duplicate is harmless.

## Consequences

- An app with replicas spread over several nodes loses capacity for at most
  the lost timeout plus the replacement's startup, and keeps serving
  throughout.
- During a partition, a replica may briefly run twice (old on the cut-off
  node, new elsewhere). Apps must tolerate this, as they already do during
  rolling updates.
- A node that flaps around the timeout causes replicas to move; the default
  of 5 minutes favours stability over speed.
- Self-reported node capacity still influences where replacements go (see
  threat model T28).

# 0013. Replica rebalancing

- Status: Accepted
- Date: 2026-11-01

## Context

The scheduler spreads an app's replicas when it places them, but it only
places replicas when an app scales up or rolls out. After a node is lost
and comes back (ADR 0008), after a node is uncordoned, or when a new node
joins, existing replicas stay where they are: an app can end up with all
its replicas on one machine while another sits empty, and the next
failure of that machine takes the whole app down.

Moving a replica means replacing it, which must not reduce the number of
serving replicas, and moves must not pile up: a node that joins a
cluster with many apps should not receive dozens of new containers at
once.

## Decision

- An app is **unevenly spread** when the node holding the most of its
  replicas has at least two more than the node the scheduler would pick
  for a new replica (the same choice as for scaling up: ready, not
  cordoned, fits the memory, fewest replicas of the app). A difference of
  one is as even as the count allows.
- Only stable apps are rebalanced: no rollout in progress, exactly the
  desired number of replicas, all of them serving, no replica on a lost
  or cordoned node, and no lost node in the cluster.
- **One move in the whole cluster at a time.** The scheduler marks one
  replica of the most loaded node as moving (recorded on the replica, so
  a new leader continues the move). From there it is handled like a
  replica on a cordoned node: a replacement is scheduled with the usual
  surge of one, and the moving replica is drained and removed only once
  the replacement has served through the warm-up.
- If the replacement does not serve within the rollout progress deadline
  (plus the readiness probe budget), the move is given up: the moving
  replica stays, replacements that do not serve are retired, and the app
  is not rebalanced again for 10 minutes. The backoff is kept in the
  leader's memory; after a failover the move may be tried once more.
- Only the spread of each app is balanced, not the total number of
  replicas per node: new replicas already go to the least loaded nodes,
  and moving replicas of evenly spread apps would only add restarts.

## Alternatives considered

- **Rebalance on command only:** operators would have to notice uneven
  spread themselves, and after an unattended recovery nobody does.
- **Move several replicas at once:** faster on large clusters, but every
  move costs a container start and a warm-up on the target node, and a
  bad node would receive many replacements before the first one fails.
- **Balance total load per node:** more moves for a smaller gain in
  availability; the spread of each app is what decides whether a node
  failure takes an app down.

## Consequences

- After a node returns or joins, apps spread out again on their own, one
  replica at a time, without ever serving with fewer replicas than
  desired.
- A replica that is moved is restarted on another node; apps must already
  tolerate that, as rollouts and cordons do the same.
- Large clusters take a while to settle: each move waits for the
  replacement's readiness and warm-up.

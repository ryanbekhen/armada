# 0036. Sticky sessions

- Status: Accepted
- Date: 2026-11-11

## Context

Each request to an app goes to one of its ready replicas, chosen on its own
(ADR 0024), and with traffic splitting, by revision weight (ADR 0022). Some
apps keep a user's session in a replica's memory, or hold a long
conversation with one client over several requests, and break when the next
request lands on another replica.

## Decision

`ingress.sticky: true` sends each client back to the replica that answered
its first request:
- **How it works.** HAProxy sets a cookie on the response (`insert
  indirect nocache httponly secure`, `SameSite=Lax`) and routes requests
  that carry it to the same server.
  - The cookie's value is the server slot's name (`s1`, `s2`), which says
    nothing about the replica.
  - Its name is `armada_` and a short hash of the backend, so two sticky
    apps on one host keep their own, and the name does not give the app
    away.
- **Replicas going away.** A cookie for a slot that is down or empty sends
  the client to another server (`option redispatch`), and that answer sets a
  new cookie. Stickiness is a preference, never a reason to fail a request.
  A rollout therefore moves clients to new replicas as old ones drain.
- **No local-first routing.** A sticky app has no local-first routing (ADR
  0024): each node's proxy would otherwise pick its own local replica first
  and split one client over several replicas.
- **Traffic splitting.** With traffic splitting, the first request is
  balanced by revision weight, and the client then stays on that revision's
  replica. Revision label backends are sticky too.
- **Changing it.** `armada app create`/`update --sticky`, `--sticky=false`
  to stop. A change reloads the proxy (the setting is part of the
  structural signature).

## Consequences

- **Only clients that keep cookies stick.** Browsers do, and so do most HTTP
  clients that keep a cookie jar. Others are balanced as before.
- **Load can be uneven.** Long sessions stay where they started, so new
  replicas take only new clients until the old ones leave. Autoscaling still
  counts load per replica, so it keeps adding capacity.
- **Not a substitute for shared state.** A replica that restarts or moves
  loses what it held in memory. Apps that cannot lose a session should keep
  it in a store.

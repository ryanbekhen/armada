# 0021. Scale to zero

- Status: Accepted
- Date: 2026-11-03

## Context

Autoscaling (ADR 0020) keeps an app between `scale.min` and `scale.max`,
with `min` at least 1. Many apps (previews, internal tools, rarely used
APIs) sit idle most of the day and still hold a replica's CPU and memory
reservation on some node. The spec format has reserved `scale.min: 0` from
the start and rejected it until now.

Running no replica means some component must take a request while no
replica serves, start the app, and pass the request on once a replica is
ready, without opening anything new to the network.

## Decision

An autoscaled app with ingress may set `scale.min: 0`. It scales to zero
after `scale.idleAfter` without requests, and the next request wakes it.

### Spec

```yaml
ingress:
  type: external        # or internal; required
scale:
  min: 0
  max: 5
  idleAfter: 15m        # default 15m, 1m to 24h
  rules:
    - type: http
      concurrent: 20
```

- `min: 0` needs `scale.rules`, which take over once a replica runs. It also
  needs ingress, because a request is what wakes the app.
- `idleAfter` is only valid with `min: 0`.
- A first deploy starts one replica, so the deploy shows the image runs. The
  app then scales to zero when it stays idle.

### Going to zero

- **Request counts.** Each agent's proxy sample (ADR 0020) also reports, per
  replica, the requests sent since the previous sample. This is the change
  in HAProxy's total sessions; a counter that went backwards after a reload
  starts over.
- **Last request.** The leader keeps the last time any node reported a
  request in progress or a finished request for each replica, so a report
  missed between evaluations loses nothing.
- **Idleness.** An app scales to zero when no request was seen for
  `idleAfter`. That time counts from the leader's start too, so a new
  leader waits a full `idleAfter`.
  - If no node's proxy was read, nothing counts as idle.
  - Autoscaling rules never take an app below one replica; only idleness
    does.
- **Write and record.** The count goes to 0 through the same conditional
  write as autoscaling. The leader records `ScaledToZero`, and replicas
  drain as usual.

### Waking up

- **Wake socket.** The agent listens on a Unix socket, `wake.sock`, in
  HAProxy's run directory. The directory is root-only (0700) and already
  mounted into the HAProxy container, and the socket has mode 0600. No
  network port is opened.
- **HAProxy configuration.** For an app that scales to zero, HAProxy gets a
  second backend `wk_<app>`. That backend sets `X-Armada-Wake: <app>`,
  overwriting any value from the client, and sends the request to the
  socket.
  - Each route of the app selects it with `{ nbsrv(be_<app>) eq 0 }`, ahead
    of the app's own backend. So the wake path is taken only while no
    server of the app is up.
  - Going from zero to one replica and back needs no reload: only the slots
    of `be_<app>` change, through the Runtime API.
- **Holding the request.** The agent holds the request: at most 1000 per
  node, each for at most 60 seconds.
  - It sends `Wake{app}` to the leader on its control stream, at most every
    5 seconds per app, again while the request waits.
  - It forwards the request as soon as the proxy configuration it applied
    has a replica of the app. This is a reverse proxy that keeps the path,
    host, and forwarding headers, and reads the body only then.
  - If no replica is ready within 60 seconds, the agent answers `503` with
    `Retry-After`. The wake backend's server timeout covers the wait plus a
    normal response.
- **The leader.** It rate limits wakes per node (a burst of 20, then one a
  second) and ignores them for unknown apps and apps that do not scale to
  zero. A wake counts as activity. If the app is at 0, the leader raises it
  to 1 with a conditional write and records `Woken`.
- **After waking.** Once a replica is in the proxy, requests go straight to
  it. When every replica of an app that scales to zero fails its health
  check, requests take the same wake path and wait for one to recover
  instead of failing at once.

### Rollouts

A deploy while the app is at zero keeps it at zero, so the new revision
becomes active without starting a replica. The next request wakes the new
revision.

## Alternatives considered

- **A network listener for held requests**: simpler to reach from HAProxy,
  but it would be one more port on the node, reachable by anything on the
  private network or the bridge, and it would need its own
  authentication.
- **Redirect the client after waking**: no request held in the agent, but
  clients and methods that do not follow redirects would fail, and POST
  bodies would be sent twice.
- **A backup server in the app's own backend**: no second backend, but
  HAProxy counts a backup server as usable, so the agent could not tell an
  app that is down from one that serves.

## Consequences

- A request that wakes an app waits for a whole cold start: placing the
  replica, pulling the image if the node does not have it, starting it, and
  its readiness probe. Small images and fast probes keep that short.
- **Compromised nodes.**
  - A compromised node can wake any app that scales to zero. It is limited
    to one replica, rate limited, and the app scales down again after
    `idleAfter`.
  - It can also keep such an app awake by reporting requests, which is the
    same as reporting load (ADR 0020).
- Nodes without a proxy (`--proxy none`) take no part. Agents
  that predate this decision report no request counts, so idleness counts
  only what newer agents see.
- Only HTTP requests through Armada's proxy wake an app; non-HTTP traffic
  and queues do not.

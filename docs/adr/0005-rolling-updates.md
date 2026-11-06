# 0005. Rolling updates with agent-side readiness and time-based drain

- Status: Accepted
- Date: 2026-10-31

## Context

Phase 1 replaces all replicas at once on deploy. Phase 2 lab testing showed the consequence: as soon as a new revision fails to start, the app immediately answers 503. Phase 3 requires deploys and rollbacks with 0 failed requests under load, plus automatic aborts for broken revisions.

The questions are: who decides a replica is ready, how traffic is shifted without gaps, and when a rollout counts as failed.

## Decision

- **Two revisions per app.** `active_revision` serves traffic; `target_revision` is being rolled out (apps in multiple revision mode split traffic between several revisions instead, ADR 0022). A deploy only changes the target. An app's first revision becomes active immediately. Deploying a spec identical to the active revision cancels the rollout.
- **The agent decides readiness.** The agent runs startup → readiness/liveness probes against the container's IP on the bridge network (or the published port if there is no IP) and reports `ready`. Without a readiness probe, an app with a port is considered ready once the port accepts TCP connections, checked every second until it does, about every 10 seconds while it does (a node runs this for every replica, and HAProxy checks replicas too), and every second again from the first failure; an app without a port is ready once the container is running. A liveness or startup probe that keeps failing up to its threshold makes the agent recreate the container.
- **A restarted agent keeps what the server knows.** A container older than the agent stays out of its reports until the probes reach a first verdict: the server keeps the replica's status, so restarting an agent takes nothing out of the proxies, and a replica found failing is reported at once.
- **The server only adds `running` + `ready` replicas to the proxy.** HAProxy still runs its own health checks as a second layer.
- **maxSurge = 1, maxUnavailable = 0.** An old replica is released only if the number of *serving* replicas stays ≥ the requested count. *Serving* = ready for at least `warmup` (default 3 seconds), so that every HAProxy has installed and checked the new replica before the old one leaves. Replicas being drained do not count toward the surge.
- **Time-based drain.** A replica that has ever received traffic is not deleted immediately: it is removed from the proxy config (HAProxy slot → `maint`, in-flight requests complete), stays scheduled for `drainTimeout` (default 10 seconds), and only then is deleted and its container stopped with a grace period. The HAProxy driver always enables new servers before disabling old ones.
- **Progress deadline.** A rollout fails if no new replica becomes serving within 3 minutes + the time the startup/readiness probes can reasonably need (initialDelay + period × failureThreshold), counted from the start of the rollout or the last progress. On failure: the target reverts to the active revision, the new replicas are discarded, and a message with the cause is stored and displayed.
- **Rollback = an ordinary rollout** to an older revision that is still stored, using the recorded image digest. Without arguments: cancels the running rollout, or goes back to the revision before the active one.
- **Stopped-container recovery.** The agent recreates containers in state `exited`/`dead`/`created` with exponential backoff (1 second up to 5 minutes, reset after 10 minutes without a crash). The runtime restarts nothing on its own (ADR 0011), so this is the only restart path: a crashed container, one left exited by a reboot, or one that failed to start.

## Rejected alternatives

- **Readiness from HAProxy health checks (via `show servers state`).** Requires aggregating status from every node, and HAProxy knows nothing about startup/liveness. The agent is closer to the container and already has a stream to the server.
- **Drain that waits for connections to finish (`show sess`/`stats`).** More precise, but needs cross-node coordination; a fixed timeout is simple and sufficient for ordinary HTTP requests. Can be added later.
- **Detecting permanent failures (e.g. `manifest unknown`) to fail faster.** Distinguishing permanent from transient registry errors is fragile; a single deadline is more predictable.

## Consequences

- Deploy and rollback were tested in the lab with 0 failed requests (about 145 thousand requests per scenario), including an HAProxy reload mid-rollout. A revision that never became ready was aborted after 3 minutes 30 seconds with no failed requests.
- Rollouts are slow for apps with infrequent readiness probes (default period 10 seconds): one early failure delays by one period. Users can shorten `period`.
- During drain, one extra replica still uses memory on the node.
- `drain` in the spec sets an app's drain (1s to 1h, default 10 seconds). Warmup and progress deadline cannot yet be set from the spec or flags; the values above are hardcoded as defaults.

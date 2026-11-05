# 0020. Autoscaling

- Status: Accepted
- Date: 2026-11-03

## Context

`scale.min` fixes an app's replica count, and `armada scale` changes it by
hand. Load changes during the day, so operators either run enough replicas
for the peak all the time or watch and scale by hand. The spec format has
reserved `scale.rules` from the start and rejected it until now.

Armada already measures what replicas use: agents sample CPU and memory
every 10 seconds for `armada top` (ADR 0016). Every node's proxy routes to
every replica of an app with ingress, and knows how many requests each is
serving.

## Decision

With `scale.rules`, the leader keeps an app between `scale.min` and
`scale.max`. The count follows the replicas' average load per rule.

### Spec

```yaml
scale:
  min: 2
  max: 10
  rules:
    - type: http
      concurrent: 50     # requests in progress per replica
    - type: cpu
      utilization: 70    # percent of resources.cpu
    - type: memory
      utilization: 80    # percent of resources.memory
```

- **Rule types.** There are three rule types: `http`, `cpu`, and `memory`.
  Each type may appear at most once.
- **`http` needs ingress.** The rule counts requests at the proxy, so the
  app needs `ingress.type` external or internal.
- **Bounds.** `max` must be greater than `min`.
- **Reserved types.** The queue fields (`list`, `length`) and the schedule
  fields (`schedule`, `timezone`, `replicas`) are rejected as not
  implemented:
  - A queue rule would make the control plane connect to services outside
    the cluster.
  - Schedules are a separate decision.

### Samples

- **CPU and memory.** These come from the usage samples that already exist.
  A replica counts only when its sample comes from the node it is assigned
  to. CPU is a percentage of the replica's CPU reservation, and memory a
  percentage of its memory limit.
- **Requests.** The agent also reads its proxy every 10 seconds through the
  optional `proxy.LoadReader`. HAProxy reports this through the Runtime API
  as `show stat`: current sessions plus the queue, per server slot, mapped
  back to replicas.
  - The agent sends these counts for every replica its proxy routes to, in
    the same `UsageReport`, with `load_measured` set.
  - The leader adds up the counts for each replica from every node whose
    report is recent. That includes requests to `<app>.internal`.
- **Memory only.** Samples stay in the leader's memory, as in ADR 0016, and
  never go to etcd.

### Decision rule

Every 15 seconds, for each autoscaled app that is not rolling out, the
leader takes these steps:

1. **Average.** It takes the app's ready, non-draining replicas of the
   active revision and averages each rule's value over them.
   - An `http` rule is measured when at least one node's proxy was read.
   - A `cpu` or `memory` rule is measured when at least half of the
     replicas have a sample from their own node.
2. **Per-rule count.** For each measured rule, the count is
   ⌈ready × average ÷ target⌉. A rule within 10% of its target keeps the
   current count.
3. **Combine.** The highest count among the rules wins.
   - The count is capped at twice the ready replicas, so replicas that
     cannot be placed do not compound.
   - It is then held within `min`..`max`.
4. **Apply.**
   - **Up:** a higher count is applied at once.
   - **Down:** a lower count is applied only when it is the highest
     recommendation of the last 5 minutes.
   - **New leader:** a new leader waits 5 minutes before scaling down,
     because its history is empty.
5. **Hold.** With no measured rule, no ready replica, or a rollout in
   progress, the count stays as it is.

The change goes through the same desired count as `armada scale`:

- The write is conditional: if the count or the revision changed since the
  leader looked, the decision is dropped.
- Writes happen only when the count changes. Each is audited as the actor
  `armada:autoscaler` and recorded as an `app` event, `ScaledUp` or
  `ScaledDown`, with the rule values.

Scaling down removes replicas through the usual drain (ADR 0005), and
scaling up places replicas through `eligible()` and the capacity checks
(ADR 0014). If no node fits a new replica, it waits with the existing
`Unschedulable` event.

### Interaction with the rest

- `armada scale` refuses an autoscaled app; change `scale.min`/`max`
  instead.
- A deploy of an autoscaled app keeps the current count, held within the
  new bounds. A deploy that removes the rules sets `scale.min` again.
  Rollback works the same way with the target revision's bounds.
- A rollout freezes the count, and the new revision starts with it.
- Interfaces:
  - `armada status` shows each rule's current value and target, and what
    the autoscaler last decided (`AppStatus.autoscale`).
  - Metrics: `armada_app_autoscale_current` and
    `armada_app_autoscale_target` (`app`, `rule`).

## Alternatives considered

- **Requests per second instead of requests in progress**: easy to read,
  but its right value depends on how long requests take; concurrency
  tracks saturation directly.
- **Agents decide for their own replicas**: no leader involvement, but
  load is split across every node's proxy, and only the leader sees the
  whole.
- **Keep samples in etcd**: a new leader could scale down at once, at the
  cost of a write every few seconds; waiting one window is cheaper.

## Consequences

- An app scales only as fast as samples arrive (10 to 25 seconds) and as
  its replicas become ready. Bursts shorter than that are absorbed by
  the replicas already running.
- Request counts are reported by every node for every replica, so a
  compromised node can report a high load for any app. Effects:
  - It can scale that app up to `scale.max`, but no further.
  - Lowering an app's count is harder: a decision to scale down needs every
    recent recommendation in the window to be lower.
  - CPU and memory samples count only from a replica's own node.
- The state schema does not change. Servers that predate this decision
  read an autoscaled app as one with a fixed count. While one of them
  leads during a rolling upgrade, nothing scales, and the app keeps its
  count. Agents that predate it send no request counts, so `http` rules
  see only the nodes that do.
- Queue rules, schedules, and custom metrics are not part of this
  decision. Scale to zero builds on it in ADR 0021.

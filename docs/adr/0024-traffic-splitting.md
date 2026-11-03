# 0024. Traffic splitting

- Status: Accepted
- Date: 2026-11-03

## Context

A rolling update (ADR 0005) moves all of an app's traffic from one revision
to the next as soon as the new replicas are ready. That leaves no way to
send a small share of requests to a new revision first and watch it, or to
reach a new revision by itself before it takes any traffic. The spec format
has reserved `revisions.mode: multiple` and `revisions.traffic` from the
start and rejected them until now.

## Decision

An app with ingress may set `revisions.mode: multiple`. Its traffic then
lists the revisions that serve, each with a weight and an optional label.

### Spec

```yaml
ingress:
  type: external        # or internal; required
revisions:
  mode: multiple
  traffic:
    - revision: web--r3
      weight: 90
    - revision: latest  # the revision this deploy creates
      weight: 10
      label: canary     # canary--web.<root domain>, canary--web.internal
```

- **Targets.** There are 1 to 10 targets. Each names a revision of the
  app, or `latest`, at most once. Weights are percent, 0 to 100, and add up
  to 100.
- **Labels.** A label is a name like an app's, unique within the app. It
  is required for weight 0: such a revision runs and is reached only
  through its label.
  - `<label>--<app>` must fit in 63 characters.
  - App names cannot contain `--`, so a label's host never collides with an
    app's.
- **Not part of a revision.** Traffic is stored with the app, not in the
  revision. A deploy that changes only the weights or labels creates no
  revision; it moves traffic.
- **Every named revision must exist.** The store refuses a deploy that
  names a revision it does not have.
- **`scale.min: 0` cannot be combined with multiple mode**, so a sleeping
  app always has one revision to wake.

### Behaviour

- **No rollout.** A deploy makes the new revision current and applies the
  traffic at once. Replicas of each revision start and become ready as
  usual. A revision's replicas take requests once they are ready, and its
  share goes to the others until then.
- **Replica counts.** Each revision runs
  `max(1, round(replicas × weight ÷ 100))` replicas. Here `replicas` is
  `scale.min`, `armada scale`, or the autoscaler's count. A revision with
  weight 0 runs one.
  - Each revision is reconciled like an app of its own: placement,
    self-healing, evacuation, and rebalancing.
  - A revision that leaves the traffic is drained and removed.
  - Revisions in the traffic are never pruned.
- **Proxy.** The revisions with a weight share the app's backend.
  - Each server's weight is its revision's weight divided among the
    revision's ready replicas, scaled to HAProxy's 1–256. Each revision then
    gets its share of requests whatever its replica count.
  - Weights change through the Runtime API without a reload.
  - Each label gets a backend of its own with only its revision's replicas.
    It is served at `<label>--<app>.internal`, and for external apps at
    `<label>--<app>.<root domain>`, which the wildcard certificate covers.
    Labels do not apply to custom domains.
  - Health checks use the newest revision's readiness path.
  - Each request is balanced on its own; there are no sticky sessions.
- **Autoscaling.** It counts the ready replicas of the revisions with a
  weight, and CPU and memory are measured against the newest revision's
  reservation.
- **`armada traffic APP REV=WEIGHT…`** changes the weights until the next
  deploy, like `armada scale`. It keeps each revision's label, takes the
  revisions that exist, and refuses an app in single mode.
  - `armada rollback` refuses an app in multiple mode. Traffic moves back
    through `armada traffic` or the spec.
- **Back to single mode.** Deploying a spec without `mode: multiple` is a
  rolling update. Every revision in the traffic keeps serving until the new
  one is ready, then they drain. During that rollout, replicas share
  requests equally.

### Visibility and records

- **Status and metrics.** `armada status` shows the split, each label's
  URL, and the replicas per revision. `armada_app_traffic_weight{app,revision}`
  is on the metrics endpoint.
- **Events and audit.** A deploy in multiple mode and `armada traffic`
  record `TrafficChanged`. The audit log records the split.
- **State schema.** The schema moves to 4 with no rewrite. Servers that
  would drop an app's traffic when they rewrite it can no longer lead
  (ADR 0012).

## Alternatives considered

- **One backend per revision chosen by a random number in HAProxy**: weights
  would live in the rendered configuration, so every change would need a
  reload.
- **Splitting by replica count only**: no weights on servers, but a 10%
  canary would need ten replicas, and the split would drift whenever a
  replica is not ready.
- **Traffic in the revision**: every weight change would create a revision.
  A canary would then be a series of revisions that differ only in
  traffic, and `latest` would point at a revision with nothing new.

## Consequences

- A canary is a deploy, then edits of the weights (in the spec or with
  `armada traffic`), then a deploy in single mode, or a split of 100% to
  the new revision.
- Each revision in the traffic holds at least one replica's reservation.
- Revisions in the traffic keep their own spec and pinned secret versions.
  The app's routes, domains, and health check come from the newest
  revision.
- No automation decides on weights: no automatic promotion, no rollback on
  error rates, and no routing by header or cookie.

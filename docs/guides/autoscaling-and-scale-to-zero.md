# Scale apps with load, by the clock, and down to zero

Let Armada choose an app's replica count between bounds you set: from the
requests in progress, from CPU or memory use, from a schedule, and down to
zero for apps nobody uses at night. This guide walks through three common
cases and how to pick the numbers.

**You will use:** [`scale.rules`](../spec-reference.md#autoscaling)
(`http`, `cpu`, `memory`, `schedule`),
[scale to zero](../spec-reference.md#scale-to-zero) (`scale.min: 0`,
`idleAfter`), [`resources`](../spec-reference.md#resources),
[`armada app show`](../cli/armada-app.md#armada-app-show),
[`armada app events`](../cli/armada-app.md#armada-app-events),
[operations: autoscaling](../operations.md#autoscaling)

**Before you start:**

- A running cluster (see the [quickstart](../quickstart.md)) and an app
  deployed from a spec file (see [deploy-a-web-app.md](deploy-a-web-app.md)).
- Room in the cluster for `scale.max` replicas: each replica reserves its
  CPU and memory, and replicas that do not fit wait.

## How the autoscaler decides

Every 15 seconds, the control plane's leader looks at each autoscaled app:

- It averages each rule's metric over the app's **ready** replicas and
  asks for `⌈ready × average ÷ target⌉` replicas. The rule that asks for
  the most wins.
- **Up** happens at once, at most doubling per step.
- **Down** happens only after the load has stayed lower for 5 minutes, so
  short dips do not shrink the app.
- Changes within 10% of the target are ignored, and the count is frozen
  during a rollout.
- The count always stays between `scale.min` and `scale.max`.

| Rule | Field | Measures |
| --- | --- | --- |
| `http` | `concurrent` | requests in progress per replica, counted at every node's proxy (needs ingress) |
| `cpu` | `utilization` | percent of `resources.cpu` used |
| `memory` | `utilization` | percent of `resources.memory` used |
| `schedule` | `schedule`, `timeZone`, `duration`, `replicas` | at least `replicas` for `duration` after each fire of `schedule` |

Rules for queue lengths (`queue`, `redis`, `rabbitmq`) are covered in
[background-workers.md](background-workers.md).

## Case A: an API, scaled by concurrent requests

An HTTP API whose replicas are busy while they wait on a database or other
services. Requests in progress is the best signal: it rises the moment
traffic rises, whatever the CPU does.

```yaml
name: api
image: ghcr.io/acme/api:1.4.2
ingress:
  type: external
  port: 3000
  domains: [api.example.com]
probes:
  readiness:
    path: /healthz
    period: 5s
resources:
  cpu: 500m
  memory: 512Mi
scale:
  min: 2
  max: 10
  rules:
    - type: http
      concurrent: 30
```

```bash
armada app update api --file api.yaml --wait
```

The same from flags, without a file (one rule at most):

```bash
armada app update api --min 2 --max 10 --scale-http 30
```

With 2 replicas and 140 requests in progress in all (70 each), the rule
asks for `⌈2 × 70 ÷ 30⌉ = 5`; doubling allows 4 in this step, and 5 in the
next one if the load holds.

`min: 2` keeps a replica serving when a node is lost. The readiness probe
matters here: the autoscaler counts only ready replicas, and a new replica
takes requests only once it is ready.

## Case B: a CPU-heavy service

An internal service that resizes images: each request keeps a core busy,
and requests in progress say little about how loaded a replica is.

```yaml
name: thumbnailer
image: ghcr.io/acme/thumbnailer:3.1.0
ingress:
  type: internal
  port: 8080
  timeout: 2m
probes:
  readiness:
    path: /healthz
    timeout: 2s
resources:
  cpu: "1"
  memory: 1Gi
scale:
  min: 2
  max: 8
  rules:
    - type: cpu
      utilization: 70
```

- `utilization` is a percent of `resources.cpu`. Set `cpu` explicitly:
  without it a replica reserves only 100m, and 70% of that is reached by
  almost any work. With `cpu: "1"`, the app scales out when its replicas
  use 0.7 cores on average.
- `cpu` is also the replica's limit, so a replica never takes more than its
  core from its neighbours.
- `ingress.timeout: 2m` lets a slow resize finish instead of getting `504`
  after the default 60 seconds.
- A readiness probe with `timeout: 2s` gives a busy replica time to answer
  it. If every replica fails its readiness probe under load, the autoscaler
  has no ready replicas to measure and holds.

A `memory` rule works the same way against `resources.memory`. Use it only
for apps whose memory falls again when load falls; many runtimes keep the
memory they once used, and such an app would never scale down.

## Case C: an internal tool that sleeps at night

A reporting tool used by staff during office hours. Outside them it should
cost nothing.

```yaml
name: reports
image: ghcr.io/acme/reports:5.0.1
ingress:
  type: external
  port: 8080
  domains: [reports.example.com]
  ipAllow:
    - range: 203.0.113.0/24
      name: office
      description: the office network
    - range: 198.51.100.14
      name: vpn
      description: the VPN gateway staff use from home
probes:
  readiness:
    path: /healthz
resources:
  memory: 512Mi
scale:
  min: 0
  max: 2
  idleAfter: 30m
  rules:
    - type: http
      concurrent: 20
    - type: schedule
      schedule: "0 8 * * 1-5"
      timeZone: Asia/Jakarta
      duration: 10h
      replicas: 1
```

- **`min: 0`** lets the app stop its last replica after `idleAfter` (here
  30 minutes, default 15m, 1m to 24h) without requests. It needs at least
  one rule and ingress, external or internal. Creating the app starts one
  replica.
- **The schedule** keeps at least one replica from 08:00 to 18:00, Monday
  to Friday, Jakarta time: it starts the app when the window opens, and the
  app does not fall asleep during a long meeting. While its window is open,
  the app does not scale to zero. After
  it closes, the app follows the `http` rule and sleeps after 30 quiet
  minutes. Up to 8 schedule rules, for example one more for Saturdays.
- **`ipAllow`** keeps strangers out. A refused client gets `403` from the
  proxy and wakes nothing, so scanners on the internet do not keep the app
  up. See [spa-and-api.md](spa-and-api.md) for named rules.

### The wake path

While the app is at zero, every node's proxy sends its requests to the
node's agent instead of a replica:

```
 request ──▶ HAProxy (no ready replica) ──▶ agent holds the request
                                              │  asks the leader: wake reports
                                              ▼
                       leader: 0 → 1 replica, placed and started as usual
                                              │
 response ◀── HAProxy ◀── replica ready ◀─────┘
```

- A request waits up to 60 seconds while a replica starts, then gets its
  answer as usual. If no replica is ready by then, it gets `503` with
  `Retry-After`.
- The wait is a whole cold start: placement, image pull (the first time on
  that node), start, readiness probe. Small images and a quick readiness
  probe shorten it.
- Only HTTP requests through Armada's proxy count, from outside or from
  other apps through `http://reports.internal`. Requests refused by
  `ipAllow` and CORS preflight requests never wake the app.
- Keep `min: 1` for apps where the first request of the day must not wait.

### Waking it before people arrive

The schedule also starts the app: when its window opens at 08:00 and the
app is asleep, the autoscaler raises it to the window's `replicas` within
about 15 seconds, so the first person of the day does not wait for a cold
start. `armada app events reports` shows it as `ScaledUp` with
`schedule 1 until ...`.

## What `armada app show` tells you

```bash
armada app show api
```

```
Name:         api
Revision:     api--r6
Image:        ghcr.io/acme/api:1.4.2
Ready:        4/4
Ingress:      external
Autoscale:    2-10 replicas, http 26/30: steady: http 26 of 30 per replica
Last scaled:  12m ago
URLs:         https://api.apps.example.com/
              https://api.example.com/
```

The `Autoscale` line lists the bounds, each rule's current value against
its target, and what the autoscaler is doing:

| Message | Meaning |
| --- | --- |
| `steady: ...` | The count fits the load |
| `scaling up to N: ...` | It is adding replicas now |
| `would scale down to N once the load stays lower for 5m0s: ...` | Load is lower, the 5-minute window has not passed |
| `holding while a rollout is in progress` | Frozen until the rollout ends |
| `holding: no ready replicas` | Nothing to measure; check probes and capacity |
| `scaling to zero: no requests for 30m0s` | Going to sleep (`min: 0`) |
| `scaled to zero; the next request wakes it` | Asleep; `Ready` shows `0/0` |
| `waiting for the first evaluation` | Just deployed, or the leader just changed |

A rule shows `-` instead of a value while it has no data, and a schedule
rule shows `schedule 1 until Fri 18:00` while its window is open and
`schedule 1 (closed)` otherwise:

```
Autoscale:    0-2 replicas, http 3/20, schedule 1 until Fri 18:00: steady: http 3 of 20 per replica, schedule 1 until Fri 18:00 WIB
```

The history is in the events:

```bash
armada app events reports --since 24h
```

```
TIME      KIND  OBJECT   REASON        COUNT  MESSAGE
07:55:02  app   reports  Woken         1      a request at node2 started it from zero
18:31:15  app   reports  ScaledToZero  1      scaled down from 1 to 0: no requests for 30m0s
```

`ScaledUp` and `ScaledDown` record the other changes with the rule that
caused them; the audit log names the actor `armada:autoscaler`. With the
[metrics endpoint](monitoring-and-alerts.md), alert when
`armada_app_replicas_desired` stays at `scale.max`.

## Choosing the numbers

- **`concurrent`.** Find how many requests in progress one replica handles
  before its latency grows: load-test a single replica, or read it from
  production at a busy hour (requests per second × average duration in
  seconds = requests in progress). Set the target at about two thirds of
  that, so the 15-second evaluation and a replica's start time fit before
  latency suffers.
- **`utilization`.** 60 to 75 leaves the same headroom for CPU. Higher
  values use fewer replicas and react later.
- **`min`.** Enough replicas to serve when one node is lost, usually 2 for
  anything users wait on. `0` only for apps where a cold start is fine.
- **`max`.** What your nodes can hold next to everything else, and what a
  downstream service (a database's connection limit) can take. `armada node
  top` shows what nodes have left.
- **`idleAfter`.** Longer than the usual gap between uses, so the app does
  not fall asleep between two people using it.
- After a change, watch `armada app show` and `armada app events` for a
  day. An app that scales up and down every few minutes needs a higher
  target or a higher `min`.

## Changing the count by hand

- `armada app scale` refuses an autoscaled app, because the autoscaler
  would undo it. Change the bounds: `armada app update api --min 4` keeps
  at least 4.
- `armada app update api --replicas 3` stops autoscaling at a fixed count;
  it removes the rules.
- A later `armada app update --file` sets the bounds and rules the file
  names again. An update keeps the current count within the new bounds.
- After the control plane's leader changes, apps do not scale down for 5
  minutes: the new leader watches the load first.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `scale.max: must be greater than scale.min when scale.rules are set` | Rules need room to move | Raise `max` |
| `--min and --max bound autoscaling: add one of --scale-cpu, --scale-memory, and --scale-http` | Bounds from flags without a rule | Add one `--scale-*` flag, or put the rules in the file |
| A `cpu` or `memory` rule shows `-` | No samples yet (10 to 20 seconds after a start or a leader change), or the node's runtime cannot measure containers | Wait; `armada app top APP` shows the same samples |
| An `http` rule shows `-` | No proxy has reported load yet | Check that the app has ingress and that requests go through the proxy |
| The count stays at `max` | Load is higher than `max × target`, or the target is too low | Raise `max` or the target; check capacity with `armada node top` |
| Replicas stay unplaced, `Unschedulable` events | No room for more replicas | Add nodes, lower `resources`, or lower `max` |
| The app never scales to zero | Requests keep coming (health checks from outside, crawlers), a schedule window is open, or rules have no data | `armada app events`; restrict clients with `ipAllow`; a monitor that polls the app keeps it awake |
| First request after a quiet period gets `503` | The cold start took longer than 60 seconds | Smaller image, faster readiness probe, or `min: 1` |
| `revisions.mode: multiple cannot be combined with scale.min: 0` | A canary on an app that sleeps | Use `min: 1` during the canary |

## Next steps

- [background-workers.md](background-workers.md): scale workers on the length
  of their queue.
- [canary-releases.md](canary-releases.md): autoscaling with split traffic.
- [monitoring-and-alerts.md](monitoring-and-alerts.md).
- [Spec reference: autoscaling](../spec-reference.md#autoscaling) and
  [scale to zero](../spec-reference.md#scale-to-zero).

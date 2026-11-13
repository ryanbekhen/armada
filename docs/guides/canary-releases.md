# Release in steps with canaries and previews

Send a small share of real requests to a new revision, watch it, then move
the rest over, or move everything back in one command. The same mechanism
gives a new revision its own host name before it takes any traffic, for a
preview. Use it for releases where a rolling update moves traffic too fast.

**You will use:** [traffic splitting](../spec-reference.md#revisions)
(`revisions.mode: multiple`, weights, labels),
[`armada app traffic`](../cli/armada-app.md#armada-app-traffic),
[`armada app revision`](../cli/armada-app.md#armada-app-revision),
[events](../operations.md#events)

**Before you start:**

- A running cluster with a root domain (see the [quickstart](../quickstart.md)).
  Labels get their host names under it. Here: `apps.example.com`.
- An app with external or internal ingress whose spec you keep in a file
  (see [deploy-a-web-app.md](deploy-a-web-app.md#7-keep-the-spec-in-git)).
  Here: `web`, serving `www.example.com`, with 4 replicas, running
  `ghcr.io/acme/web:2.0.4` as revision `web--r3`.
- Room in the cluster for a few more replicas: every revision in the
  traffic runs at least one.

## The setup

```
                              ┌── 90% ──▶ web--r3  (2.0.4)  4 replicas
 https://www.example.com ─────┤
                              └── 10% ──▶ web--r4  (2.1.0)  1 replica
 https://canary--web.apps.example.com ──▶ web--r4 only
```

In multiple mode, every node's proxy balances each request by revision
weight, whatever the number of replicas each revision has. A label gives a
revision a host name of its own that reaches only that revision.

## 1. Start the canary

Change the image and add `revisions` to the app's spec, `web.yaml`:

```yaml
name: web
image: ghcr.io/acme/web:2.1.0
ingress:
  type: external
  port: 8080
  domains: [www.example.com]
probes:
  readiness:
    path: /healthz
scale:
  min: 4
  max: 4
revisions:
  mode: multiple
  traffic:
    - revision: web--r3   # what runs now (armada app revision list web)
      weight: 90
    - revision: latest    # the revision this deploy creates
      weight: 10
      label: canary
```

```bash
armada app update web --file web.yaml --wait
```

```
Updated web (revision web--r4).
web--r4: 0/1 ready
web--r4 is live (1/1 ready)
```

There is no rollout: the split applies at once, and `web--r4` takes its
share as its replica becomes ready. Until then its share goes to `web--r3`.

- **Weights** are percent and add up to 100. `revision` is a revision of
  the app (`web--r3`, from `armada app revision list web`) or `latest`.
  Up to 10 targets.
- **Replicas.** Each revision runs `max(1, round(replicas × weight ÷ 100))`.
  With 4 replicas: `web--r3` runs 4 (3.6 rounded), `web--r4` runs 1, so 5
  in all while the canary lasts.
- **Requirements.** Multiple mode needs ingress, and cannot be combined
  with `scale.min: 0`.

## 2. Watch it

```bash
armada app show web
```

```
Name:      web
Revision:  web--r4
Image:     ghcr.io/acme/web:2.1.0
Ready:     5/5
Ingress:   external
Traffic:   web--r3 90%, web--r4 10% (canary)
URLs:      https://web.apps.example.com/
           https://www.example.com/
           https://canary--web.apps.example.com/ (web--r4)

REPLICA       REVISION  NODE   STATE    RESTARTS  ADDRESS           MESSAGE
web-r3-5muie  web--r3   node1  running  0         10.120.0.14:8080  -
web-r3-q2k0d  web--r3   node2  running  0         10.120.1.9:8080   -
web-r3-h7d1x  web--r3   node1  running  0         10.120.0.15:8080  -
web-r3-0zm4c  web--r3   node2  running  0         10.120.1.10:8080  -
web-r4-k3j9a  web--r4   node1  running  0         10.120.0.16:8080  -
```

Compare the revisions:

```bash
curl https://canary--web.apps.example.com/   # only the canary
armada app logs web -f                       # each line starts with the replica ID, which names its revision
armada app logs web --replica web-r4-k3j9a -f
armada app top web                           # CPU and memory per replica
armada app events web                        # restarts, OutOfMemory, TrafficChanged
```

With the [metrics endpoint](monitoring-and-alerts.md),
`armada_app_traffic_weight` shows the split, and replica metrics carry the
revision, so you can compare error rates and latency per revision in your
dashboards.

Armada does not decide for you: there is no automatic promotion and no
rollback on error rates. You move the weights.

## 3. Move more traffic

Two ways, for two purposes:

```bash
armada app traffic web r3=50 r4=50
```

```
Traffic of web: web--r3 50%, web--r4 50% (canary).
```

`armada app traffic` changes the weights at once, through the proxies'
runtime API, with no reload and no new revision. It lasts until the next
update of the app. Revisions are given by number (`r4`) or full name
(`web--r4`), and labels stay as the spec set them.

For a change that should last, edit the weights in `web.yaml` and deploy
it. A deploy that changes only `traffic` creates no revision, and `latest`
still means `web--r4`:

```yaml
revisions:
  mode: multiple
  traffic:
    - revision: web--r3
      weight: 50
    - revision: latest
      weight: 50
      label: canary
```

```bash
armada app update web --file web.yaml
```

Each change is recorded as a `TrafficChanged` event and in the audit log.

## 4. Promote

Send everything to the new revision:

```bash
armada app traffic web r4=100
```

A revision left out of the traffic stops serving: `web--r3` drains (no new
requests, stopped after `drain`) and its replicas are removed. `web--r4`
now runs all 4 replicas.

Then finish the canary by going back to single mode. Remove `revisions`
from `web.yaml` (or set `mode: single`), keep the new image, and deploy:

```bash
armada app update web --file web.yaml --wait
```

This is an ordinary rolling update to a new revision, `web--r5`, with the
same image: `web--r4` serves until `web--r5` is ready. From here on,
updates roll out as usual, and `armada app rollback` works again.

## 5. Or roll back

If the canary misbehaves, send everything back to the old revision:

```bash
armada app traffic web r3=100
```

`web--r4` stops taking requests at once and drains. `armada app rollback`
refuses apps in multiple mode; traffic moves back through `armada app
traffic` or the spec.

To make it last, deploy the spec in single mode with the old image. To be
sure you get exactly the image that ran before, even if its tag has moved
since, pin the digest `armada app revision show web--r3` prints:

```yaml
image: ghcr.io/acme/web:2.0.4@sha256:4b1d...   # the full digest from revision show
```

## Previews: a revision with no traffic

A revision with weight 0 runs one replica and is reached only through its
label. Use it to check a release candidate on the real cluster before any
user sees it:

```yaml
name: web
image: ghcr.io/acme/web:2.2.0-rc.1
ingress:
  type: external
  port: 8080
  domains: [www.example.com]
probes:
  readiness:
    path: /healthz
scale:
  min: 4
  max: 4
revisions:
  mode: multiple
  traffic:
    - revision: web--r5
      weight: 100
      label: stable
    - revision: latest
      weight: 0
      label: preview
```

```bash
armada app update web --file web.yaml --wait
curl https://preview--web.apps.example.com/   # the release candidate
curl https://stable--web.apps.example.com/    # what users get
```

From inside the cluster, other apps of the space reach the preview at
`http://preview--web.internal`. When it is good, start a canary with
`armada app traffic web r5=90 r6=10`, or go to 100 and back to single mode
as above.

Label rules: lowercase letters, digits, and single hyphens, and
`<label>--<app>` must fit in 63 characters. Label host names exist only
under the root domain (and `.internal`), not under custom domains. Each
gets a certificate: the wildcard certificate of the root domain with a DNS
provider set, else one of its own through HTTP-01, which needs the name to
resolve to your nodes (the root domain's wildcard DNS record from the
quickstart does that).

## Variations

**A canary on an autoscaled app.** The autoscaler counts the ready replicas
of every revision with a weight, and the shares follow its count. CPU and
memory rules are measured against the newest revision's reservation.

**Keeping users on one revision.** Each request is balanced on its own, so
a user can see the old and new revision on two clicks. With
`ingress.sticky: true`, a client stays on the replica, and so the revision,
it first reached:

```yaml
ingress:
  type: external
  port: 8080
  sticky: true
```

**An internal service.** Multiple mode works the same with
`type: internal`. Labels are then reached at `<label>--<app>.internal` only.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `revisions.traffic: weights must add up to 100, not 90` | Weights in the spec do not add up | Fix the weights |
| `revisions.traffic[1].label: is required for weight 0` | A revision with weight 0 is reachable only through a label | Add a `label` |
| `revisions.mode: multiple cannot be combined with scale.min: 0` | A sleeping app must have one revision to wake | Use `min: 1` or more during the canary |
| `armada app rollback` refuses the app | Rollback does not apply to multiple mode | `armada app traffic web r3=100`, then deploy in single mode |
| No label URL in `app show` | The cluster has no root domain | `armada cluster set --root-domain apps.example.com` |
| The canary's replicas stay unplaced | No room for the extra replicas | Free capacity or lower `scale.min` for the canary; `armada app show web` says which resource is short |
| Routes or domains changed with the canary affect both revisions | Routes, domains, and the health check path come from the newest revision | Change them in a separate update, not together with a canary |
| Weights went back after an update | `armada app traffic` lasts until the next update | Put lasting weights in the spec |

## Next steps

- [autoscaling-and-scale-to-zero.md](autoscaling-and-scale-to-zero.md).
- [ci-cd.md](ci-cd.md): run the canary steps from a pipeline.
- [monitoring-and-alerts.md](monitoring-and-alerts.md): metrics per revision.
- [Operations: traffic splitting](../operations.md#traffic-splitting).

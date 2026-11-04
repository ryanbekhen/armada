# App spec reference

`armada deploy -f app.yaml` takes one app or job spec in YAML. Parsing is strict:
an unknown field is an error, and a field that exists in the format but is
not implemented in this version is rejected with a message saying so, never
ignored.

```yaml
apiVersion: armada.dev/v1alpha1   # optional; must match if present
kind: app                         # optional; app (default) or job, see "Jobs" below
name: web
image: ghcr.io/acme/web:1.4.2     # tag or @sha256 digest
command: ["/app/server"]          # optional, replaces the image entrypoint
args: ["--port", "8080"]          # optional
env:
  - name: LOG_LEVEL
    value: info
  - name: DATABASE_URL
    secretRef: database-url       # from `armada secret set web database-url`
secretFiles:
  - secretRef: tls-client-key
    path: /run/secrets/client.key # read-only file on tmpfs
registry:                         # optional, for private images
  server: ghcr.io
  username: acme-bot
  passwordSecretRef: ghcr-token
ingress:
  type: external                  # external | internal | none
  port: 8080
  domains: [www.example.com]
  routes:
    - path: /api
      stripPrefix: true
probes:
  readiness:
    path: /healthz
scale:
  min: 2
resources:
  memory: 512Mi
  cpu: "0.5"
placement:                        # optional: only nodes with these labels
  require:
    region: sulawesi
revisions:                        # optional: split traffic between revisions
  mode: single                    # single (default) | multiple
volumes:                          # optional: data kept on the replica's node
  - name: uploads
    path: /app/uploads
    owner: "1000:1000"
```

## Fields

### `name` (required)

Lowercase letters, digits, and single hyphens, starting with a letter, at
most 63 characters. It names the app's URL (`<name>.<root domain>` or
`<name>.internal`), its containers, and its secrets.

The project is not part of the file: `armada deploy --project NAME` puts
the app in a project, where its URLs become `<name>.<project>.<root
domain>` and `<name>.<project>.internal` (ADR 0029). A `project` field in
the file is refused.

### `image` (required)

An OCI image reference with an optional registry host, tag, and
`@sha256:` digest, at most 512 characters. On the first deploy of a
revision, the image is resolved to a digest and every replica of that
revision runs exactly that digest, even if the tag moves later.

### `command`, `args`

Lists of strings (at most 256 entries of 4 KiB each). `command` replaces the
image's entrypoint, `args` its default arguments.

### `env`

Up to 512 variables. A name is `[A-Za-z_][A-Za-z0-9_]*` and must not start
with `ARMADA_` (reserved). Each entry has either `value` (at most 32 KiB) or
`secretRef`, the name of a secret of this app.

Environment variables are visible to anyone with root on the node (in the
container runtime's metadata). Prefer `secretFiles` for sensitive values.

### `secretFiles`

Each entry mounts the secret `secretRef` read-only at `path`, an absolute
path of letters, digits, `.`, `_`, `-`, and `/`. `/etc/hosts`,
`/etc/hostname`, `/etc/resolv.conf` and anything under `/proc`, `/sys`, or
`/dev` are refused. The node must have its secrets directory on tmpfs (see
`armada doctor`); otherwise replicas that need secret files fail to start
with a clear message.

### `registry`

Credentials for pulling a private image: `server` (a host name with an
optional port), `username`, and `passwordSecretRef`. The password is always
a secret; there is no inline password field.

### `ingress`

| Field | Meaning |
| --- | --- |
| `type` | `external`: reachable from the internet through HAProxy on every node, over HTTPS. `internal`: reachable only from containers in the cluster at `http://<name>.internal`; with the cluster network, only containers of the same project resolve the name (ADR 0029). `none` (the default): no traffic is routed to the app. |
| `port` | The container port that serves HTTP, 1–65535. Required for `external` and `internal`. |
| `domains` | `external` only. Up to 32 lowercase, fully qualified host names (no IP addresses, wildcards, or trailing dot). Each domain is routed and gets a certificate only after its ownership is verified: publish the TXT record shown by `armada domain list`, then run `armada domain verify <domain>`. |
| `routes` | Up to 32 path prefixes (`/` or `/a/b`, URL-safe characters, no `.` or `..` segments). Without routes the app gets every path of its hosts. `stripPrefix: true` removes the prefix before the request reaches the app (not allowed for `/`). The longest matching prefix wins. |

Apps with `type: external` are reachable at `https://<name>.<root domain>`
once a root domain is set with `armada cluster set --root-domain`, plus
their verified custom domains. HTTP redirects to HTTPS.

### `probes`

`startup`, `readiness`, and `liveness`, each with:

| Field | Default | Range |
| --- | --- | --- |
| `path` (required) | | starts with `/`, URL-safe characters, optional query |
| `port` | `ingress.port` | 1–65535 |
| `initialDelay` | `0s` | 0–10m |
| `period` | `10s` | 1s–5m |
| `timeout` | `1s` | at least 1s, not longer than `period` |
| `failureThreshold` | 30 for startup, 3 otherwise | 1–100 |

Durations are strings such as `"500ms"`, `"10s"`, `"2m"`. The agent probes
the container directly. A replica receives traffic only once it is ready:
its readiness probe passes or, without one, its port accepts TCP
connections. A failing startup or liveness probe recreates the container.
During a rolling update, old replicas keep serving until the new ones are
ready; see [ADR 0005](adr/0005-rolling-updates.md).

### `scale`

`min` is the number of replicas to run, 0–100 (default 1; 0 only with
`rules`, see "Scale to zero" below). `max` defaults to
`min` and must not be lower; it only matters with `rules` (see
"Autoscaling" below). Replicas are spread across ready, uncordoned
nodes that the app's `placement` allows (a rollout spreads the new
revision the same way), and spread out again, one at a time, when a node
joins, returns, or is uncordoned. `armada scale <app> <n>` changes the
count without a new revision.

#### Autoscaling

With `rules`, Armada keeps the app between `min` and `max`, following the
average load of its ready replicas
([ADR 0022](adr/0022-autoscaling.md)):

```yaml
scale:
  min: 2
  max: 10
  rules:
    - type: http
      concurrent: 50
    - type: cpu
      utilization: 70
```

| Rule | Field | Meaning |
| --- | --- | --- |
| `http` | `concurrent` (1–10000) | requests in progress per replica, counted at every node's proxy; needs `ingress.type` external or internal |
| `cpu` | `utilization` (1–100) | percent of `resources.cpu` (default 100m) |
| `memory` | `utilization` (1–100) | percent of `resources.memory` (default 256Mi) |

- **Several rules.** The rule that asks for the most replicas wins.
- **Bounds.** `max` must be greater than `min`, and each type may appear
  once.
- **How the count changes.** It is evaluated every 15 seconds:
  - **Up:** it rises at once, at most doubling per step.
  - **Down:** it falls only after the load has stayed lower for 5 minutes.
  - **Hold:** changes within 10% of the target are ignored, and the count
    is frozen during a rollout.
- **Deploys and manual scaling.** A redeploy keeps the current count
  within the new bounds. `armada scale` refuses an autoscaled app.
- **What to watch.** `armada status` shows each rule's current value
  against its target, and `armada events APP` shows `ScaledUp` and
  `ScaledDown` with the reason.
- **Reserved rules.** `queue` rules (`list`, `length`) and `schedule` rules
  are rejected as not implemented yet.

#### Scale to zero

With `min: 0`, an app stops its last replica after `idleAfter` without
requests, and the next request starts it again
([ADR 0023](adr/0023-scale-to-zero.md)):

```yaml
ingress:
  type: internal
  port: 8080
scale:
  min: 0
  max: 5
  idleAfter: 30m      # default 15m, 1m to 24h
  rules:
    - type: http
      concurrent: 20
```

- **Requirements.** `min: 0` needs `rules` and ingress (external or
  internal). `idleAfter` is only valid with `min: 0`.
- **First deploy.** A first deploy starts one replica.
- **Waking up.** While the app is at zero, a request waits up to 60
  seconds while Armada starts a replica, then gets its answer as usual. If
  no replica is ready by then, it gets `503` with `Retry-After`. The wait is
  a whole cold start (placement, image pull, start, readiness probe), so
  small images and quick probes help.
- **What counts as a request.** Only HTTP requests through Armada's proxy
  count and wake the app.

### `resources`

| Field | Default | Range |
| --- | --- | --- |
| `memory` | `256Mi` | 16Mi–64Gi; suffixes `Ki`, `Mi`, `Gi`, `K`, `M`, `G` |
| `cpu` | 100m reserved, no limit | 10m–64; `"250m"` or cores such as `"0.5"` |

Each value is both what a replica reserves on its node and its limit.
Without `cpu`, a replica reserves 100m and may use any idle CPU. A node only
takes a replica that fits in what its other replicas leave free, after
Armada keeps 100m of CPU and 128Mi of memory for itself (another 100m on
control plane servers). On a busy node, containers share CPU in proportion
to what they reserve. When no node has room, `armada status` says which
resource is short.

Every container also gets a PID limit of 1024, `no-new-privileges`, and a
reduced capability set, and never runs privileged, on the host network, or
with access to the container runtime's socket. On nodes whose driver runs
each container in its own virtual machine (macOS nodes, say), the virtual
machine takes the place of the PID limit and `no-new-privileges`, and a
replica is only placed there if its `memory` is at least what the driver
accepts (see [operations](operations.md#macos-nodes)).

### `placement`

Keeps the app on nodes with given labels (set with `armada node label`, or
by the join token; see [operations](operations.md#node-labels-and-placement)).

```yaml
placement:
  require:
    region: sulawesi          # the node must have region=sulawesi
    kind: [raspi, small]      # and kind=raspi or kind=small
    armada.arch: arm64        # labels Armada sets: armada.os, armada.arch, armada.runtime
```

A node runs the app only if it has every key with one of the listed values
(and the `spreadBy` key, below).
If no node qualifies, or the qualifying nodes are full, the replicas are not
placed anywhere else: `armada status` says why, a rollout fails and leaves
the old revision serving. Placement belongs to the revision, so changing it
rolls the app out onto the new set of nodes. A **restricted** node runs only
apps whose `require` names one of its own labels (`armada.*` labels do not
count).

`spreadBy` names one label key and spreads the replicas evenly over its
values, then over the nodes within each value:

```yaml
placement:
  require:
    region: [java, sulawesi]  # optional fence: never elsewhere
  spreadBy: region            # even over the regions it may use
```

Four replicas on three `java` nodes and one `sulawesi` node run two in each
region. Only nodes with the label get replicas. The spread is soft: when no
node of a value has room, or its nodes are down, replicas go to the other
values (`armada status` says so) and move back once there is room. Use
`require` for values an app must never leave. Label names mean nothing to
Armada: `region`, `rack`, or `city` are whatever your nodes are labelled
with.

Keys are lowercase letters, digits, `.`, `-`, `_`, and `/` (up to 63
characters); values the same without `/`. Up to 16 keys, each with up to 16
values. A placement needs `require`, `spreadBy`, or both.

In a cluster that mixes architectures, Armada keeps each app on nodes its
image is built for: the first node to pull the image reports its
platforms (`armada revisions` shows them), and from then on only nodes
with a matching `armada.os`/`armada.arch` get replicas. A replica that
landed on another node before that fails fast and is replaced.

### `revisions`

By default (`mode: single`) a deploy rolls the app out to the new revision
([ADR 0005](adr/0005-rolling-updates.md)). With `mode: multiple`, the app
splits its requests between revisions ([ADR 0024](adr/0024-traffic-splitting.md)):

```yaml
ingress:
  type: external
  port: 8080
revisions:
  mode: multiple
  traffic:
    - revision: web--r3   # an existing revision (armada revisions web)
      weight: 90
    - revision: latest    # the revision this deploy creates
      weight: 10
      label: canary       # https://canary--web.<root domain>
```

- **Requirements.** Multiple mode needs ingress (external or internal).
  It cannot be combined with `scale.min: 0`.
- **`traffic`.** 1 to 10 targets.
  - `revision` is a revision of the app (`web--r3`) or `latest`, each at
    most once.
  - `weight` is percent, 0 to 100, and the weights add up to 100.
- **Labels.** `label` serves the revision alone at `<label>--<app>.internal`,
  and for external apps at `https://<label>--<app>.<root domain>` (not on
  custom domains).
  - A label is lowercase letters, digits, and single hyphens, and
    `<label>--<app>` fits in 63 characters.
  - Weight 0 needs a label: the revision runs and is reached only through
    it.
- **What a deploy does.** No rollout: the traffic applies at once, and
  each revision takes requests as its replicas become ready. Changing only
  `traffic` creates no new revision.
- **Replicas.** Each revision runs `max(1, round(replicas × weight ÷ 100))`
  replicas, where `replicas` is `scale.min`, `armada scale`, or the
  autoscaler's count.
- **Changing weights.** `armada traffic web web--r3=50 web--r4=50` (or
  `r3=50 r4=50`) changes the weights until the next deploy. A revision left
  out stops serving. `armada rollback` refuses apps in multiple mode.
- **Leaving multiple mode.** Deploy with `mode: single` (or no
  `revisions`) for a rolling update. Every revision in the traffic serves
  until the new one is ready.
- **Shared settings.** Routes, domains, and the health check path come from
  the newest revision. Each request is balanced on its own, with no sticky
  sessions.

### `volumes`

Directories that keep their contents across restarts, deploys, and
reboots ([ADR 0025](adr/0025-persistent-volumes.md)).

```yaml
name: db
image: postgres:17
env:
  - name: POSTGRES_PASSWORD
    secretRef: postgres-password
volumes:
  - name: data
    path: /var/lib/postgresql/data
    owner: "999:999"
```

| Field | Meaning |
| --- | --- |
| `name` | A name like an app's, unique within the app. |
| `path` | Where the volume appears in the container. It follows the same rules as a secret file's path, and volumes may not overlap each other or a secret file. |
| `owner` | Optional `uid:gid` of the volume's directory, applied whenever a replica starts (its contents are left alone). Without it a new directory belongs to root, with mode 0700; an image that runs as another user (postgres runs as 999, nginx's workers as 101) needs its owner. Not applied on macOS nodes, whose driver decides ownership. |

- An app has at most 8 volumes.
- **One replica.** An app with volumes runs exactly one replica. `scale`
  may only say `min: 1` and `max: 1`, without `rules`; scale to zero,
  `revisions.mode: multiple`, and jobs with volumes are rejected.
- **Bound to a node.** The first replica is placed on a node that can mount
  volumes, and its volumes are created there. From then on the app always
  runs on that node. It is not moved off a cordoned node, and it stays down
  while that node is lost: see "Volumes" in the
  [operations guide](operations.md#volumes) for recovery.
- **Deploys stop the old replica before starting the new one.** The app is
  down for the old replica's drain plus the new one's start.
- **Kept until removed.** A volume stays when the app is redeployed without
  it or deleted, until `armada volume rm`. Its size is shown by
  `armada volume ls`; there is no quota.

## Jobs

A spec of `kind: job` describes work that runs to completion
([ADR 0021](adr/0021-jobs.md)). Each run starts one container; it starts
with `armada job run JOB` or on a schedule.

```yaml
kind: job
name: db-backup
image: ghcr.io/acme/backup:1.4
command: ["/backup.sh"]
env:
  - name: DB_PASSWORD
    secretRef: db-password
schedule: "0 3 * * *"        # optional
timeZone: Asia/Jakarta        # optional
timeout: 30m
retries: 2
concurrency: forbid
history: 5
resources:
  memory: 512Mi
```

| Field | Default | Meaning |
| --- | --- | --- |
| `schedule` | none (manual runs only) | Five cron fields: minute, hour, day of month, month, day of week (`*/15 * * * *`, `0 3 * * 1-5`). Descriptors such as `@daily` and `CRON_TZ=` are rejected. |
| `timeZone` | `UTC` | IANA zone of the schedule, such as `Asia/Jakarta`; needs `schedule`. |
| `timeout` | `1h` | How long one attempt may take from placement (pulling the image included), `1s` to `24h`; then it is stopped and counts as failed. |
| `retries` | `0` | Further attempts after a failed one (non-zero exit, start failure, lost node, timeout), 0 to 10, after 10s, 20s, 40s, and so on up to 5 minutes. |
| `concurrency` | `forbid` | What happens when a run is due while another is active: `forbid` skips the new one (and `armada job run` refuses); `replace` cancels the active run. |
| `history` | `5` | Finished runs kept, 1 to 50. The container of a finished run is kept 24 hours for `armada logs`. |

- `env`, `secretFiles`, `registry`, `resources`, and `placement` mean the
  same as for apps. `ingress`, `probes`, `scale`, `revisions`, and
  `volumes` are rejected, and these job fields are rejected on apps.
- A job and an app cannot share a name.
- A deploy changes the job at once: runs that start afterwards use the new
  spec, and a run in progress keeps its own.
- If the control plane is down when a run is due, the run starts when it is
  back, as long as that is within an hour; otherwise it is skipped.
- The container gets `ARMADA_JOB_RUN` (the run number) besides
  `ARMADA_APP`, `ARMADA_REVISION`, and `ARMADA_REPLICA`.
- Runs are at least once: in rare failures (a node cut off mid-run, an
  agent restarting at the moment the container exits) a run can be
  attempted again, so make jobs safe to repeat.

## Not available in v0.1

These fields are part of the format and are rejected with an explicit error
until they are implemented:

| Field | Planned |
| --- | --- |
| `scale.rules` of type `queue` or `schedule` | later |

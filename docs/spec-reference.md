# App spec reference

`armada deploy -f app.yaml` takes one app spec in YAML. Parsing is strict:
an unknown field is an error, and a field that exists in the format but is
not implemented in this version is rejected with a message saying so, never
ignored.

```yaml
apiVersion: armada.dev/v1alpha1   # optional; must match if present
kind: app                         # optional; "app" is the only kind in v0.1
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
```

## Fields

### `name` (required)

Lowercase letters, digits, and single hyphens, starting with a letter, at
most 63 characters. It names the app's URL (`<name>.<root domain>` or
`<name>.internal`), its containers, and its secrets.

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
| `type` | `external`: reachable from the internet through HAProxy on every node, over HTTPS. `internal`: reachable only from containers in the cluster at `http://<name>.internal`. `none` (the default): no traffic is routed to the app. |
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

`min` is the number of replicas to run, 1–100 (default 1). `max` defaults to
`min` and must not be lower. Replicas are spread across ready, uncordoned
nodes that the app's `placement` allows (a rollout spreads the new
revision the same way), and spread out again, one at a time, when a node
joins, returns, or is uncordoned. `armada scale <app> <n>` changes the
count without a new revision.

### `resources`

| Field | Default | Range |
| --- | --- | --- |
| `memory` | `256Mi` | 16Mi–64Gi; suffixes `Ki`, `Mi`, `Gi`, `K`, `M`, `G` |
| `cpu` | no limit | 10m–64; `"250m"` or cores such as `"0.5"` |

Every container also gets a PID limit of 1024, `no-new-privileges`, and a
reduced capability set, and never runs privileged, on the host network, or
with access to the container runtime's socket.

### `placement`

Keeps the app on nodes with given labels (set with `armada node label`, or
by the join token; see [operations](operations.md#node-labels-and-placement)).

```yaml
placement:
  require:
    region: sulawesi          # the node must have region=sulawesi
    kind: [raspi, small]      # and kind=raspi or kind=small
    armada.arch: arm64        # labels Armada sets: armada.os, armada.arch
```

A node runs the app only if it has every key with one of the listed values.
If no node qualifies, or the qualifying nodes are full, the replicas are not
placed anywhere else: `armada status` says why, a rollout fails and leaves
the old revision serving. Placement belongs to the revision, so changing it
rolls the app out onto the new set of nodes. A **restricted** node runs only
apps whose `require` names one of its own labels (`armada.*` labels do not
count).

Keys are lowercase letters, digits, `.`, `-`, `_`, and `/` (up to 63
characters); values the same without `/`. Up to 16 keys, each with up to 16
values.

In a cluster that mixes architectures, Armada keeps each app on nodes its
image is built for: the first node to pull the image reports its
platforms (`armada revisions` shows them), and from then on only nodes
with a matching `armada.os`/`armada.arch` get replicas. A replica that
landed on another node before that fails fast and is replaced.

## Not available in v0.1

These fields are part of the format and are rejected with an explicit error
until they are implemented:

| Field | Planned |
| --- | --- |
| `kind: job` | v0.2 |
| `revisions.mode: multiple`, `revisions.traffic` (traffic splitting) | v0.2 |
| `scale.rules` (autoscaling) | v0.2 |
| `scale.min: 0` (scale to zero) | v0.3 |
| `placement.spreadBy` (spread over label values) | later |

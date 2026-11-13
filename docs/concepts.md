# Concepts

A handful of ideas explain almost everything Armada does. Read this once,
and the commands and spec fields will feel obvious.

## The big picture

```
                         you
                          │  armada (client): mTLS to the control plane
                          ▼
 ┌────────────────────────────────────────────────────────────────────┐
 │ control plane: 1 or 3 servers (armadad server)                     │
 │   stores what you asked for, decides where replicas run, and       │
 │   sends each node its assignment                                   │
 └───────────────┬───────────────────────────────┬────────────────────┘
                 │ assignments                    │
        ┌────────▼─────────┐            ┌─────────▼────────┐
        │ node             │    ...     │ node             │
        │ agent            │            │ agent            │
        │ containers       │◀──────────▶│ containers       │  cluster network
        │ HAProxy :80 :443 │            │ HAProxy :80 :443 │
        └────────▲─────────┘            └─────────▲────────┘
                 └───────────── the internet ─────┘
```

- **`armadad`** runs on every machine, as root. On a **server** it runs the
  control plane; on every machine it runs the **agent**, which starts
  containers with Armada's own container runtime and runs the node's
  HAProxy. A server is also a node.
- **`armada`** is the client you work with. It never touches containers
  itself: it tells the control plane what you want.

## Desired state

You never "run a container". You describe what should exist, and Armada
makes it so and keeps it so.

```bash
armada app create web --image ghcr.io/acme/web:1.4.2 --replicas 3 ...
```

This records *"web: 3 replicas of this image"*. The leader decides which
nodes run them; each node's agent starts its containers, checks them, and
reports back. When a container crashes, a node is lost, or a node joins,
the same loop corrects the difference. Every command works this way, which
is why the same command can be run twice safely and why the cluster heals
itself.

## Apps and specs

An **app** is a long-running service, described by a **spec**: image,
ports, environment, secrets, scaling, probes, volumes, and so on.

```yaml
name: web
image: ghcr.io/acme/web:1.4.2
ingress:
  type: external
  port: 8080
```

You can write the spec with flags (`armada app create`, `armada app update
--image ...`) or as a file (`--file web.yaml`). Either way the result is
the same spec, which `armada app show web -o yaml` prints. Keeping it in
git is the usual way to work. The [spec reference](spec-reference.md) lists
every field.

A **job** (`kind: job`) is a spec for a container that runs to completion:
on demand, on a cron schedule, or while a queue has messages. Each time it
runs is a **run**, with its own logs and exit code.

## Revisions and rollouts

Every change to an app's spec makes a new **revision** (`web--r7`). A
revision never changes. It pins:

- the image's **digest**, so every replica runs exactly the same image
  even if its tag moves;
- the **versions of the secrets** it uses.

Moving from one revision to the next is a **rollout**. New replicas start
first, take traffic only once their readiness probe passes, and then old
replicas are drained (no new requests, current ones finish) and removed.
A rollout that makes no progress is abandoned, and the old revision keeps
serving. `armada app rollback` goes back to an earlier revision the same
way.

## Replicas

A **replica** is one running copy of an app's revision on one node: the
app's container, plus any init containers and sidecars the spec names.
Replicas reserve the CPU and memory the spec asks for, and no node takes
more than it has. Armada spreads an app's replicas over nodes, moves them
off nodes that are lost or drained, and spreads them out again when nodes
come back.

## Ingress: how requests arrive

`ingress.type` decides who can reach an app.

| Type | Reached at | From |
| --- | --- | --- |
| `external` | `https://web.<root domain>` and its `domains` | The internet, through HAProxy on every node |
| `internal` | `http://web` from its space, `http://web.internal` in full | Containers in the cluster only |
| `none` | Nowhere | A worker that only makes outgoing connections |

Every node's HAProxy serves every app, so DNS can point at all nodes.
HAProxy prefers replicas on its own node and sends the rest across the
cluster. Certificates come from Let's Encrypt by themselves.

Internal apps can also take plain TCP (`protocol: tcp`), so a database or
cache in the cluster is reached at `db:5432` (or `db.internal:5432`) by the
apps of its space.

## Spaces

A **space** is a namespace for apps, jobs, secrets, domains, and volumes.
Every cluster has `default`; create others for environments or teams.

- Names only need to be unique within a space. An app's full **ID** is
  `NAME.SPACE` (just `NAME` in `default`): `web.staging`.
- Internal names follow: `web.staging.internal`. Apps of the same space
  just use the name: `http://web` from an app of `staging` is
  `web.staging`.
- Apps resolve and reach only the internal apps of their own space.
  Spaces other than `default` are kept away from the nodes and the
  private network.
- Roles are given per space, so a person can deploy to `staging` but
  only read `production`.

`armada space use staging` makes it the space of later commands;
`--space` changes it for one.

## Secrets

Secrets belong to an app, are encrypted at rest, and have versions. A spec
uses them by name, as an environment variable (`secretRef`) or a file
(`secretFiles`); `envFrom: secrets` turns every secret of the app into a
variable. Values never appear in output, logs, or events, and are read
from stdin or a file, never from a command line. Changing a secret rolls
the app out with the new version, unless you ask it not to.

## Volumes

A **volume** keeps data across restarts and deploys.

- A **node volume** is a directory on the node that runs the app. The app
  then runs exactly one replica, always on that node. It can back up to an
  S3-compatible bucket on a schedule and, if its node is lost, come back on
  another node from the latest backup.
- An **NFS volume** mounts an NFS export. It binds the app to no node, so
  any number of replicas share it.

## Scaling

An app runs `scale.min` replicas, or, with `scale.rules`, between `min`
and `max`, following requests in progress, CPU, memory, a queue's length,
or a schedule. With `min: 0` an idle app stops entirely, and the next
request starts it again.

## Nodes, labels, and placement

Nodes join with a one-time token and carry **labels**: their OS and
architecture by themselves, and any you add (`region=jakarta`). A spec can
require labels (`placement.require`) or spread replicas over a label's
values (`placement.spreadBy`). A node can be **drained** (its replicas
move elsewhere) or **restricted** (it runs only apps that ask for it).

## Who may do what

People are **users** and tools are **services**. Each has a certificate
under its own name and holds **roles**: `viewer`, `deployer`, or `admin`
in a space, and `space-creator` or `cluster-admin` for the whole
cluster. Every change is in the audit log under the name of whoever made
it.

## Seeing what happens

- `armada app show APP`: the app, its revisions, and each replica's state.
- `armada app logs APP`, `armada app exec APP -- sh`: a replica's output, a
  shell in it.
- `armada cluster events`: what the cluster did and why: crashes, rollouts,
  lost nodes, moved replicas, certificates.
- `armada app top`, `armada node top`: CPU and memory in use.
- Prometheus metrics for dashboards and alerts.

## Where next

- [Quickstart](quickstart.md), if you have not built a cluster yet.
- [Guides](guides/README.md), for complete recipes.
- [CLI reference](cli/armada.md) and [spec reference](spec-reference.md).

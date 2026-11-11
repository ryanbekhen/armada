# 0038. Init containers and sidecars

- Status: Accepted
- Date: 2026-11-11

## Context

A replica has been one container. Some work belongs next to an app rather
than in its image: a migration or a seed step that must finish before the
app starts, a log shipper that reads the app's files, a local proxy that
terminates TLS or adds authentication in front of the app. Putting these in
the app's image couples their release to the app's; running them as apps of
their own puts them on other nodes, out of reach of the app's localhost and
volumes.

## Decision

A spec takes `initContainers` and `sidecars`, at most 4 of each:

```yaml
initContainers:
  - name: migrate
    image: ghcr.io/acme/web:1.4
    command: ["./migrate"]
    env:
      - name: DATABASE_URL
        secretRef: database-url
    resources: { memory: 256Mi }
sidecars:
  - name: log-shipper
    image: ghcr.io/acme/shipper:2
    volumes: [data]
    secretFiles: [/run/secrets/token]
    resources: { cpu: 100m, memory: 64Mi }
```

- **What a container gets.** Its own `image`, `command`, `args`, `env`
  (secret references allowed), and `resources`; the app's `env` and
  `envFrom` are not inherited, and `PORT` is not set. Armada adds
  `ARMADA_APP`, `ARMADA_REVISION`, `ARMADA_REPLICA` (and `ARMADA_JOB_RUN`),
  and `ARMADA_CONTAINER` with the container's name. It mounts only the app's
  volumes it names in `volumes` and the app's secret files it names, by
  path, in `secretFiles`, at the app's paths. Names are lowercase DNS
  labels of at most 30 characters, unique, and never `app`, which names the
  app's own container. Probes and ports are not part of a container (the
  spec refuses them as unknown fields).
- **Images.** Each image is pulled as written, with the app's `registry`
  credentials when its registry is the same, anonymously otherwise. Unlike
  the app's image, it is not pinned to a digest after the first pull:
  pin it in the spec (`@sha256:`) where every replica must run the same
  bits. An image without a variant for the node fails the start like any
  other pull error; it does not teach the scheduler platforms.
- **One network namespace.** The runtime creates the replica's own
  container first, with its network namespace, host files (`/etc/hosts`,
  `/etc/resolv.conf`, `/etc/hostname`), and SELinux label, and every init
  container and sidecar joins them. They reach each other on 127.0.0.1, share
  the replica's address and the firewall rules that apply to it, and resolve
  the same names. Each is still a container of its own: its own root
  filesystem, cgroup, memory, CPU and PID limits, and the same security
  defaults as the app's (dropped capabilities, no-new-privileges, seccomp,
  AppArmor where available, no host paths, no runtime socket).
- **SELinux.** The containers of one replica share its MCS categories: they
  share its volumes and secret files, which carry that label, and are one
  unit of trust, like the processes of one container. Other replicas, of the
  same app or another, keep categories of their own.
- **Order.** The agent's `Run` returns once the replica's container exists,
  and the runtime then runs the init containers one after the other, each to
  its end, starts the sidecars, and starts the app's container. Meanwhile the
  replica is `starting` and the agent's reconcile pass goes on: a long
  migration holds neither the node's start slots nor its other replicas.
  An init container that exits with anything but 0 ends the start: nothing
  else starts, and the replica's containers are kept, stopped, so
  `armada app logs APP --container NAME` shows its output; the agent then
  recreates the replica with crash backoff, rerunning every init
  container. The runtime keeps no state across an agent restart: a replica
  found half started is recreated.
- **Sidecars.** A sidecar that exits restarts the replica, all of its
  containers, with crash backoff, like the app's own container exiting
  does. Stopping a replica (drain, scale down, rollout, volume backup) stops
  the app's container first, then its sidecars, each with the grace period,
  so a proxy or log shipper outlives the app.
- **Jobs.** A job attempt may have both. Init containers run before the
  job's container; one that fails ends the attempt with its exit code. The
  attempt ends when the job's container exits; a sidecar that exits before
  that is not restarted, and the agent stops the rest once the attempt is
  over.
- **Resources.** A replica reserves its container and its sidecars
  together, or its largest init container if that needs more, since init
  containers run alone before the others: per resource, `max(app + sidecars,
  largest init container)`. Containers without `resources.memory` get 64Mi;
  without `resources.cpu` they reserve 10m and have no CPU limit. Placement,
  capacity, and `armada app top` use this total, and a replica's usage is the
  sum of its containers (its egress is measured once: they share the
  interface).
- **Logs and exec.** `armada app logs APP --container NAME` and
  `armada job logs JOB --container NAME` read an init container's or
  sidecar's output; `armada app exec APP --container NAME` runs a command in
  a running sidecar. Empty or `app` means the app's own container.
- **Adoption.** Init containers and sidecars carry the replica's `armada.*`
  labels plus `armada.role` (`init` or `sidecar`) and `armada.container`,
  and the runtime lists them with the replica's container. One whose
  replica's container is gone is removed.
- **Rollout.** Agents announce `Hello.containers`; replicas with init
  containers or sidecars are placed only on nodes whose agent runs them.
  State schema 10 keeps servers that would start such a replica without
  its other containers from leading. A replica without them keeps its spec
  hash, so an upgrade restarts nothing.

## Consequences

- An app's helpers ship with it and share its localhost and volumes, with
  the same isolation from everything else that the app has.
- A crashing sidecar takes its app's replica down with it, and a failing
  init container keeps the replica from starting; both show in the
  replica's status and events with the container's name.
- Each container counts toward the node's reservation, so a replica with
  sidecars needs more room.

## Not done

- Probes on sidecars, and a sidecar restarted by itself without its
  replica.
- Init containers that run once per revision rather than per replica.

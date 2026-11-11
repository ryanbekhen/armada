# Run migrations before the app starts, and helpers beside it

You will add more containers to each replica of an app: an init container
that migrates the database before the app's own container starts, and
sidecars that run next to the app for its whole life, such as a connection
pooler on localhost or a log shipper reading the app's files.

**You will use:** [`initContainers` and
`sidecars`](../spec-reference.md#initcontainers-sidecars),
[`armada app logs --container`](../cli/armada-app.md#armada-app-logs) and
[`armada app exec --container`](../cli/armada-app.md#armada-app-exec), and
[resource usage](../operations.md#resource-usage).

**Before you start:** a running cluster (see the
[quickstart](../quickstart.md)) and a database the app uses. This guide
uses the `db` app of [An app with a PostgreSQL
database](app-with-a-database.md), at `db.shop.internal:5432` in the
project `shop`.

## How a replica runs several containers

```
replica api-r4-...   (one address, one localhost, one set of DNS names)

  1. init: migrate     runs to its end, exit 0
  2. sidecar: pooler   starts, keeps running        127.0.0.1:6432
  3. app               starts, keeps running        :3000, takes requests
```

- **Init containers** run one after the other, each to its end, before
  anything else starts. If one exits with anything but 0, the replica does
  not start.
- **Sidecars** start next, then the app's own container. They run for the
  replica's life. When the replica stops, the app's container stops first
  and its sidecars after it, so a proxy or log shipper outlives the app.
- **All of them share the replica's network:** they reach each other on
  `127.0.0.1`, and have the replica's address, host name, and DNS. To the
  rest of the cluster they are the app: `allow` lists and network isolation
  treat a sidecar's connections as the app's.
- **Each is still its own container**: its own image, root filesystem,
  limits, and the same security defaults as the app's. It gets only the
  `env` you give it (the app's `env` and `envFrom` do not apply, and `PORT`
  is not set), and only the app's volumes and secret files it names.

At most 4 init containers and 4 sidecars. They have no probes and no ports
of their own: the app's probes decide whether the replica is ready.

## 1. Set the secrets

Secret references in init containers and sidecars name secrets of the app.
The migration connects to the database directly; the app goes through a
pooler on localhost, which connects to the database:

```bash
armada project use shop
PASSWORD=...   # the database password, from where you keep it
printf 'postgres://app:%s@db.shop.internal:5432/app' "$PASSWORD" | armada secret set api direct-database-url
printf 'postgres://app:%s@db.shop.internal:5432/app' "$PASSWORD" | armada secret set api upstream-url
printf 'postgres://app:%s@127.0.0.1:6432/app' "$PASSWORD" | armada secret set api database-url
unset PASSWORD
```

## 2. The spec

```yaml
# api.yaml
name: api
image: ghcr.io/acme/api:1.4.2
env:
  - name: DATABASE_URL
    secretRef: database-url        # 127.0.0.1:6432, the pooler
ingress:
  type: external
  port: 3000
probes:
  readiness:
    path: /healthz
scale:
  min: 3
resources:
  cpu: 500m
  memory: 512Mi
initContainers:
  - name: migrate
    image: ghcr.io/acme/api:1.4.2
    command: ["./bin/migrate", "up"]
    env:
      - name: DATABASE_URL
        secretRef: direct-database-url
    resources:
      memory: 256Mi
sidecars:
  - name: pooler
    image: ghcr.io/acme/db-pooler:1.23.1   # your connection pooler, listening on 127.0.0.1:6432
    env:
      - name: UPSTREAM_URL
        secretRef: upstream-url
      - name: LISTEN
        value: 127.0.0.1:6432
    resources:
      cpu: 100m
      memory: 64Mi
```

```bash
armada app update api --file api.yaml --wait
```

Add `api` to the database's `allow` if it is not there: the pooler and the
migration connect as `api`.

## 3. Migrations as an init container

Every replica runs `migrate` before its app starts: the first replica of a
new revision applies the migrations, and the others find nothing to do.

What to get right:

- **Make migrations safe to run more than once, and at once.** Each replica
  start runs every init container again: three replicas run it three times,
  and a restarted replica runs it again. Use a migration tool that records
  what it applied and takes a lock in the database, so two replicas never
  migrate at the same time.
- **Keep the old revision working.** A rollout starts new replicas while the
  old ones still serve, so the old code runs against the new schema until
  the rollout ends. Add columns and tables first; remove what the old code
  uses only in a later release.
- **A failed migration stops the rollout, not the app.** The new replica
  does not start, the old revision keeps serving, and `armada app show api`
  says why:

  ```
  Rollout:  rolling out api.shop--r5; api.shop--r4 serves until it is ready
  ...
  REPLICA            REVISION      NODE   STATE   RESTARTS      ADDRESS  MESSAGE
  api.shop-r5-k2l9q  api.shop--r5  node2  exited  3 (14s ago)   -        init container migrate exited with code 1
  ```

  The replica is started again, from the first init container, after the
  same growing delay as a crash (1s, 2s, 4s, up to 5 minutes). Its stopped
  containers are kept until then, so the output is still there:

  ```bash
  armada app logs api --container migrate
  armada app logs api --container migrate -f     # follow the next attempt
  ```

  Fix the migration and deploy again, or go back with
  `armada app rollback api`.
- **Pin the init container's image.** The app's image is pinned to a digest
  on a revision's first deploy; an init container's image is pulled as
  written each time. If a tag can move, write `image@sha256:...` so every
  replica migrates with the same code. Images from the app's registry use
  its `registry` credentials.

### Or a migration job before the deploy

An init container suits migrations that are quick and safe to repeat. For a
long migration, or one you want to run exactly once and watch, use a job
and run it before the deploy; the deploy only starts if it succeeded:

```bash
armada job run migrate --wait --timeout 30m && armada app update api --image ghcr.io/acme/api:1.4.3 --wait
```

See [Scheduled jobs](scheduled-jobs.md#one-off-tasks).

## 4. A sidecar on localhost

The `pooler` sidecar listens on `127.0.0.1:6432`, inside the replica, and
the app connects there. Nothing outside the replica reaches it: it is not
the app's `ingress.port`, and sidecars have no ports of their own.

Look at it:

```bash
armada app logs api --container pooler
armada app exec api --container pooler -- sh            # a shell in the sidecar, if its image has one
armada app exec api --replica api.shop-r5-k2l9q --container pooler -- ps
```

`armada app exec` runs in a running sidecar (or, without `--container`,
the app's own container). Init containers have already ended: read their
output with `armada app logs --container`.

If the sidecar exits, the whole replica restarts with all of its
containers, like the app's own container exiting does, and
`armada app show` says `sidecar pooler exited with code N`.

## 5. A sidecar that reads the app's files

A log shipper reads files the app writes. The two share a directory only
through a volume of the app, which the sidecar names in `volumes`; secret
files are shared the same way, by path, in `secretFiles`.

```yaml
# legacy.yaml
name: legacy
image: ghcr.io/acme/legacy:7.2.0
ingress:
  type: internal
  port: 8080
volumes:
  - name: logs
    path: /var/log/legacy
secretFiles:
  - secretRef: shipper-token
    path: /run/secrets/shipper-token
sidecars:
  - name: log-shipper
    image: ghcr.io/acme/shipper:2.0.3
    args: ["--dir", "/var/log/legacy", "--token-file", "/run/secrets/shipper-token"]
    volumes: [logs]
    secretFiles: [/run/secrets/shipper-token]
    resources:
      cpu: 50m
      memory: 64Mi
```

Mind what a volume brings: a volume on the node binds the app to one node
and one replica, and deploys stop the old replica before the new one
starts. That is fine for an app like this one. For an app that must run
several replicas, have it log to standard output (read with
`armada app logs`), or share an [NFS volume](shared-files-with-nfs.md),
which any number of replicas may mount.

## 6. What a replica reserves

A replica reserves, for CPU and for memory each, its app container plus its
sidecars, or its largest init container if that is more: init containers
run alone, before the others. A container without `resources.memory` gets
64Mi, and one without `resources.cpu` reserves 10m with no CPU limit.

For the `api` spec above:

| Container | CPU | Memory |
| --- | --- | --- |
| app | 500m | 512Mi |
| pooler (sidecar) | 100m | 64Mi |
| migrate (init) | 10m (default) | 256Mi |
| **Replica reserves** | max(500m + 100m, 10m) = **600m** | max(512Mi + 64Mi, 256Mi) = **576Mi** |

Each container keeps its own limits: the pooler is killed if it goes over
64Mi, even when the app has memory to spare. Nodes take a replica only if
the whole reservation fits.

`armada app top api` shows each replica's use as the sum of its containers
against that reservation:

```
REPLICA            NODE   STATE    CPU         MEMORY
api.shop-r5-k2l9q  node2  running  212m/600m   301Mi/576Mi
```

## In jobs

Jobs take init containers and sidecars too:

- Init containers run before each attempt. One that fails ends the attempt
  with its exit code, and `retries` apply.
- The attempt ends when the job's own container exits. A sidecar that
  exits earlier is not restarted; the others are stopped when the attempt
  ends.
- `armada job logs JOB --container NAME` reads one of them.

## Check that it works

- `armada app show api` lists replicas `running` and ready; while init
  containers run they are `starting`.
- `armada app logs api --container migrate` shows the migration's output
  for a replica.
- `armada app exec api --container pooler -- ps` shows the pooler running.
- `armada app events api` has no `init container ... exited` or
  `sidecar ... exited` messages.

## Troubleshooting

| What you see | Why | What to do |
| --- | --- | --- |
| Replicas stay `starting` | An init container is still running, a slow migration for example | Follow it: `armada app logs APP --container NAME -f` |
| `init container migrate exited with code 1`; rollout does not finish | The migration failed | Read `armada app logs APP --container migrate`, fix, deploy again or roll back |
| `sidecar NAME exited with code N`; replicas restart | The sidecar crashed, and a sidecar's exit restarts its replica | Read `armada app logs APP --container NAME` |
| The sidecar cannot read a file the app writes | The sidecar does not name the volume or secret file | Add it to the sidecar's `volumes` or `secretFiles` |
| The sidecar lacks a variable the app has | The app's `env` does not apply to it | Give the sidecar its own `env` |
| Deploy refused: name `app` | `app` names the app's own container | Pick another name |
| `armada app exec --container migrate` fails | Init containers are not running after they finish | Use `armada app logs --container migrate` |
| `armada app show` says no node fits | The reservation of all containers does not fit, or nodes run an agent too old for init containers and sidecars | Lower `resources`, add room, or upgrade the nodes |
| Replicas of one revision migrate with different code | The init container's tag moved | Pin it with `@sha256:` |

## Next steps

- [An app with a PostgreSQL database](app-with-a-database.md): the
  database this guide migrates.
- [Scheduled jobs](scheduled-jobs.md): migrations and maintenance as jobs.
- [Deploy from CI](ci-cd.md): migrations in a pipeline.
- Reference: [`initContainers`,
  `sidecars`](../spec-reference.md#initcontainers-sidecars),
  [Init containers and sidecars](../operations.md#init-containers-and-sidecars),
  [ADR 0038](../adr/0038-init-containers-and-sidecars.md).

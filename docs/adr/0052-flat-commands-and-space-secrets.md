# 0052. Flat commands and secrets owned by a space

- Status: Proposed
- Date: 2026-11-21

## Context

The client follows `armada <noun> <verb>` (ADR 0032), but several nouns
grew a third level (`armada app revision list`, `armada job run show`,
`armada volume snapshot create`, `armada rbac assignment create`,
`armada alert channel update`). A third level hides commands: `armada
--help` does not show them, and a person has to guess which noun holds
which.

Commands also ask for names the client never shows. `armada app exec`
takes `--replica ID` and `--container NAME`, but no command lists a
replica's containers, and a replica ID is long. `armada secret list`
takes an app, which nothing in its help says until the command fails.
Help texts open with paragraphs instead of the line a person would type.

Secrets belong to one app. An app's secrets cannot be shared: two apps of
a space that use the same database password each hold a copy, and
changing the password means changing every copy. `armada secret import`
has to run once per app.

Clusters already run with today's commands, specs, and secrets. Nothing in
this change may break them: commands and scripts keep working, specs keep
their meaning, and a rolling upgrade keeps every app serving.

## Decision

### Words

The client, the help, and the documentation use these words, and only
these, for the things a person handles:

| Word | Meaning |
| --- | --- |
| space | A group of apps, jobs, secrets, and volumes, isolated from other spaces (ADR 0026). |
| app | A service that keeps running: a spec, its revisions, and its replicas. |
| revision | One version of an app's spec, made by each deploy. |
| replica | One running copy of a revision on a node. |
| container | One process image inside a replica: the app's own container (`app`), its sidecars, and its init containers (ADR 0038). |
| job | Work that runs to completion, now, on a schedule, or from a queue (ADR 0019). |
| run | One start of a job; a run with tasks has several (ADR 0019). |
| secret | A named set of keys and encrypted values in a space. |
| volume | Storage of an app that outlives its replicas (ADR 0023). |

### Every command is two words

Every command is `armada NOUN VERB`. No noun has nouns below it. The root
help groups the nouns:

```text
Apps
  app        deploy, list, show, logs, exec, restart, rollback, ...
  revision   list and show an app's revisions
  replica    list an app's replicas and their containers
  job        deploy, start, list, show, logs, cancel, delete
  run        list and show a job's runs
  secret     keys and values apps in a space share
  volume     list, back up, restore, delete
  snapshot   list and create volume backups in a bucket
  domain     list and verify custom domains

Cluster
  cluster    status, events, show, update
  node       machines that run replicas
  server     control plane servers
  space      create, list, show, use, update, delete

Access
  user       people, each with a certificate of their own
  service    programs, each with a certificate of their own
  role       list roles, grant and revoke them

Monitoring
  alert      where notices about events go
  metrics    Prometheus scrapers
  version    this client, the servers, and the latest release
```

The verbs:

| Noun | Verbs |
| --- | --- |
| `app` | `list`, `show APP`, `deploy APP`, `delete APP`, `restart APP`, `rollback APP`, `logs APP`, `exec APP`, `top [APP]`, `events [APP]`, `traffic APP` |
| `revision` | `list APP`, `show REVISION` |
| `replica` | `list [APP]` |
| `job` | `list`, `show JOB`, `deploy JOB`, `delete JOB`, `start JOB`, `cancel JOB`, `logs JOB` |
| `run` | `list JOB`, `show JOB RUN` |
| `secret` | `list`, `show SECRET`, `create SECRET`, `set SECRET KEY`, `unset SECRET KEY`, `delete SECRET` |
| `volume` | `list`, `backup APP VOLUME`, `restore APP VOLUME`, `delete APP VOLUME` |
| `snapshot` | `list APP VOLUME`, `create APP VOLUME` |
| `domain` | `list`, `verify DOMAIN` |
| `cluster` | `status`, `events`, `show`, `update` |
| `node` | as today |
| `server` | as today |
| `space` | `list`, `show SPACE`, `use SPACE`, `create SPACE`, `update SPACE`, `delete SPACE` |
| `user` | `list`, `show USER`, `create USER`, `update USER`, `delete USER`, `credentials USER`, `renew` |
| `service` | `list`, `show SERVICE`, `create SERVICE`, `update SERVICE`, `delete SERVICE`, `credentials SERVICE`, `renew SERVICE` |
| `role` | `list`, `show ROLE`, `grant ROLE`, `revoke ROLE` |
| `alert` | `list`, `create NAME`, `update NAME`, `delete NAME`, `test NAME` |
| `metrics` | as today |

New behaviour comes with three verbs:

- `app deploy` creates the app when it does not exist and updates it when
  it does, from flags or `--file`, so one command serves both. Flags change
  only their fields on an existing app, as `app update` does now. `--new`
  refuses an app that exists, as `app create` does now.
- `app restart APP` makes a new revision of the same spec with the latest
  secret values and rolls it out. It is how an app picks up a changed
  secret.
- `replica list [APP]` shows each replica with its short name, node, state,
  revision, and containers.

### Every name a command asks for can be found

A flag or argument that names something is accepted in the form a list
shows, and the help says which command lists it:

```text
$ armada replica list api
REPLICA  NODE    STATE    REVISION  CONTAINERS
k3p9     app-01  running  r12       app, log-ship
x7q2     app-02  running  r12       app, log-ship

$ armada app exec api --replica k3p9 --container log-ship
```

`--replica` takes the short name `replica list` prints (the end of the
replica ID; the full ID still works). `app exec` with no command opens a
shell (`/bin/sh`), and it is interactive with a terminal whenever stdin is
one, so `-i` and `-t` are only needed to override that.

Arguments and flag values complete on Tab from the cluster (apps,
revisions, replicas, containers, jobs, runs, secrets, keys, volumes,
spaces, nodes, users, roles), through `armada completion bash|zsh|fish`.
Completion never offers a secret's value.

### Help starts with examples

Each command's help opens with its usage line and two to four examples a
person can copy, then one or two sentences, then the flags:

```text
$ armada app exec --help
Usage:
  armada app exec APP [--replica R] [--container C] [-- COMMAND...]

Examples:
  armada app exec api                       # a shell in one of api's replicas
  armada app exec api -- env                # run one command
  armada app exec api --container log-ship  # a shell in a sidecar

Runs in a ready replica of the serving revision unless --replica picks one.
`armada replica list api` shows the replicas and their containers.

Flags:
  ...
```

### Errors say what to type next

An error names what is wrong and, when the person picked from a set, the
set:

```text
$ armada app exec api --container logship
Error: api has no container "logship"; its containers: app, log-ship

$ armada secret show dbb
Error: space default has no secret "dbb"; its secrets: api, db, mail

$ armada app scale api 3
Error: unknown command "scale" for "armada app"
The replica count is part of the spec: armada app deploy api --min 3
```

Argument errors already name the missing argument and print the usage
line (`explain`, ADR 0032). An error never repeats a value a person typed
in a place where a secret could be, as before.

### Secrets belong to a space

A secret is a named set of keys in a space. Each key holds one value, and
values stay encrypted, versioned, and opened only for the nodes that run a
replica that uses them (ADR 0006). Every app and job of the space can use
every secret of the space; no app can use a secret of another space.

```bash
armada secret create db --from-env-file db.env    # DATABASE_URL=..., PASSWORD=...
armada secret set db PASSWORD                     # one key, from stdin or a hidden prompt
armada secret show db                             # keys, versions, which apps use them
armada secret unset db OLD_KEY
armada secret delete db --yes                     # refused while a revision uses it
```

Secret names follow the rules of today's secret names. A key is a
variable name (`DATABASE_URL`) or a secret name of today (`database-url`),
at most 63 characters, and a secret holds at most 512 keys.

A spec names a key with `SECRET/KEY` wherever it names a secret today
(`env[].secretRef`, `secretFiles[].secretRef`, `registry.passwordSecretRef`,
`volumes[].backup.urlSecretRef`/`keySecretRef`, queue rules' and triggers'
`urlSecretRef`, `ingress.dns.tokenSecretRef`), and `envFrom` lists whole
secrets:

```yaml
envFrom:
  - secret: db          # every key of db becomes a variable
  - secret: mail
env:
  - name: REDIS_URL
    secretRef: cache/url
secretFiles:
  - path: /run/tls/key.pem
    secretRef: tls/key
```

Under `envFrom`, a key that is a valid variable name is used as it is; any
other key becomes a variable as today (`database-url` becomes
`DATABASE_URL`). Variables the spec sets in `env` win, as today.

A revision pins the version of every key it uses, as it pins secret
versions today, so a rollback brings back the values it ran with. Setting
a key changes no running replica until the app's next deploy, `app
restart`, or `secret set --rollout`, which restarts every app of the space
whose serving revision uses that key.

Access stays on the space: whoever may deploy in a space may create, set,
and delete its secrets; whoever may view it sees secret names, keys, and
versions, never values (ADR 0033).

### What keeps working

**An app's secrets become the secret named after the app.** The secret
`db-pass` of the app `api` is the key `db-pass` of the secret `api` in
`api`'s space. A reference with no `/` names a key of the secret named
after the app or job, so every spec written today keeps its meaning:

| Written today | Means |
| --- | --- |
| `secretRef: db-pass` (any of the fields above) | key `db-pass` of the secret `api` |
| `envFrom: secrets` | every key of the secret `api` |
| `armada secret set api db-pass` | the same words, the same key |
| `armada secret import api .env` | sets keys of the secret `api` (`DATABASE_URL` still becomes `database-url`) |

Every app name is a valid secret name, so every app has its secret name
free. `app delete` deletes the secret named after the app only when no
other app or job of the space uses it, and says so when it keeps it.

**Old commands keep working.** Every command of today keeps its arguments,
flags, output, and exit codes as a hidden command that prints one line to
stderr, never to stdout:

```text
note: "armada app create" is now "armada app deploy --new"
```

| Today | From now on |
| --- | --- |
| `app create NAME` | `app deploy NAME --new` |
| `app update NAME` | `app deploy NAME` |
| `app revision list APP` / `show REV` | `revision list APP` / `show REV` |
| `job create` / `job update` | `job deploy` |
| `job run JOB` | `job start JOB` |
| `job run list JOB` / `show JOB RUN` | `run list JOB` / `show JOB RUN` |
| `secret list APP` | `secret show APP` |
| `secret delete APP NAME` | `secret unset APP NAME` |
| `secret import APP FILE` | `secret set APP --from-env-file FILE` (keys kept as written) |
| `volume snapshot list` / `create` | `snapshot list` / `create` |
| `rbac user ...` / `rbac service ...` | `user ...` / `service ...` |
| `rbac role list` / `show` | `role list` / `show` |
| `rbac assignment create` / `delete` | `role grant` / `revoke` |
| `rbac assignment list` | `role list` (shows who holds each role) |
| `alert channel create\|update\|list\|delete` | `alert create\|update\|list\|delete` |
| `cluster set` | `cluster update` |
| `space set` | `space update` |

`secret set APP NAME`, `secret delete SECRET` with one argument, and every
other command not in the table keep their words. The hidden commands stay
until 1.0; their removal is announced in the release notes of the
pre-release before it.

**Old clients and old servers keep working.** The API keeps `SetSecret`,
`ListSecrets`, and `DeleteSecret` with today's meaning (an app's secret is
a key of the secret named after it), so an older client works against a
newer cluster. Secrets of a space come through new RPCs (`CreateSecret`,
`SetSecretKey`, `UnsetSecretKey`, `ShowSecret`, `ListSpaceSecrets`,
`DeleteSpaceSecret`); a newer client facing an older server gets
`Unimplemented` and says the servers need upgrading first. The agent
protocol does not change: the leader still sends each node the opened
values.

**A rolling upgrade keeps serving.** Secrets move under a new etcd schema
(15) with a migration (ADR 0012) that runs once every server runs the new
binary: each app's secrets, with every version and the last version
number, become the keys of the secret named after it, and each revision's
pins are rewritten to name them. Until it has run, the new RPCs answer
`FailedPrecondition` and say which servers still run an older version;
everything else keeps working as before. As with every schema change, a
server never runs an older binary on a migrated keyspace; going back means
restoring a backup taken before.

## Consequences

- Every command shows up in `armada --help`, under one of four groups.
- Apps of a space share secrets; changing a password is one `secret set`
  and one restart per app, or one `secret set --rollout`.
- Existing scripts and specs keep working without a change; scripts see
  one more line on stderr until they move to the new words.
- Bare references keep meaning the app's own secret, so a space secret
  named like an app is that app's secret too. `secret show` lists which
  apps use each key, so this stays visible.
- The client carries two sets of commands until 1.0. `TestCommandAliases`
  checks that every hidden command maps to a visible one.
- ADR 0032's command list and ADR 0006's "per app" secrets are superseded
  by this record; both keep their other decisions.

## Plan

Each step is its own pull request, with its documents:

1. Space secrets: schema 15, migration, new RPCs, `SECRET/KEY`
   references, `envFrom` list form, `secret` commands, an upgrade test
   from the last release.
2. Flat commands: the new nouns and verbs, hidden old commands with
   their notes, grouped root help.
3. Discoverable names: `replica list`, short replica names, `app exec`
   defaults, errors that list choices, completion from the cluster.
4. Help: examples first in every command; `make docs`, guides, and the
   quickstart moved to the new words.

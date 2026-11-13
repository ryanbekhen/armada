# 0032. The command line

- Status: Accepted
- Date: 2026-11-10

## Context

The `armada` client grew one command at a time. App commands sat at the
root (`deploy`, `status`, `scale`, `rollback`, `revisions`, `logs`, `exec`,
`traffic`, `top`, `events`) while `app` had only `remove`; jobs were split
between `job` and the root; verbs differed (`remove`, `rm`, `add`, `set`);
and the only way to see apps was `status`, which printed every replica of
every app. Apps could only be created from a YAML file, so trying Armada
started with writing one. Armada is alpha, so the command line can still
change at once instead of keeping old names around.

## Decision

**Shape.** Every command is `armada <noun> <verb>`. The root holds only the
nouns and `version`. A noun nested in another is part of it (`app
revision`, `job run`).

**Verbs.** `create` and `update` (apps and jobs, from flags or `--file`),
`list` (one line per item), `show` (one item in detail), `set` (settings of
something that exists), `delete`; and verbs whose meaning is plain where
they fit: `scale`, `rollback`, `traffic`, `logs`, `exec`, `top`, `events`,
`run`, `cancel`, `drain`, `resume`, `restrict`, `unrestrict`, `label`,
`backup`, `restore`, `verify`, `renew`, `credentials`, `join-token`, `use`.
`ls` and `rm` stay accepted for `list` and `delete`.

```
armada
├── app        create | update | list | show | scale | rollback | traffic | logs | exec | top | events | delete
│   └── revision   list | show
├── job        create | update | list | show | run | logs | cancel | delete
│   └── run        list
├── secret     set | import | list | delete
├── domain     list | verify
├── volume     list | backup | restore | delete
├── space    create | list | show | set | use | delete
├── node       list | show | top | label | drain | resume | restrict | unrestrict | join-token | delete
├── server     list | join-token | delete
├── cluster    status | show | set | events
├── rbac       (ADR 0033)
│   ├── user       create | list | show | credentials | renew | update | delete
│   ├── service    create | list | show | credentials | renew | update | delete
│   ├── role       list | show
│   └── assignment create | list | delete
├── metrics    credentials
└── version
```

**Commands and files are one thing.** `app create` and `app update` (and
the same for jobs) build a spec, the same spec a file holds, and deploy it
as a new revision: rollouts, rollbacks, pinned secrets, and the audit log
work the same whichever way it was written.

- `create NAME` with flags makes a spec from them; with `--file` it imports
  one. It refuses a name that exists.
- `update NAME` with flags changes only what the flags name in the spec the
  app runs; with `--file` it replaces the whole spec. `--diff` prints what
  would change and changes nothing. `--create-if-missing` creates the app
  when it does not exist, so a script needs one command.
- An update says which revision it started from, and the server refuses it
  when another change landed in between, instead of losing that change.
- `show NAME -o yaml` prints the spec the app runs, ready for `create
  --file` or `update --file` on any cluster: export and import.

Flags cover what is changed often. The rest (custom probes, routes with
`stripPrefix`, secret files, volumes, placement, traffic splitting) stays in
`--file`; an exported spec carries it.

| Flag (`app create` / `app update`) | Spec |
| --- | --- |
| `--image` | `image` |
| `--port`, `--ingress external\|internal\|none` | `ingress.port`, `ingress.type` |
| `--domain D` (repeatable), `--remove-domain D` | `ingress.domains` |
| `--env K=V`, `--secret-env K=SECRET`, `--remove-env K` | `env` |
| `--env-from-secrets[=false]` | `envFrom` |
| `--command`, `--args` | `command`, `args` |
| `--replicas N`, or `--min N --max N --scale-cpu P \| --scale-memory P \| --scale-http N` | `scale` |
| `--cpu`, `--memory` | `resources` |
| `--health-path P` | `probes.readiness.path` |
| `--registry-user U --registry-secret S` | `registry` |

`job create` / `job update` take `--image`, `--command`, `--args`, `--env`,
`--secret-env`, `--remove-env`, `--env-from-secrets`, `--schedule`,
`--time-zone`, `--timeout`, `--retries`, `--concurrency`, `--cpu`,
`--memory`, and the registry flags.

**Spaces.** `--space` names the space of a command; without it, the
space `armada space use NAME` saved in the client config, else
`default`. `--all-spaces` (`-A`) lists every space.

**Output.**

- `list` prints a table with one line per item and nothing else; detail is
  `show`'s.
- An action that worked prints one line saying what happened, no advice.
- Warnings only when something needs doing.
- `-o json` on every command that prints data; `show` of apps and jobs also
  takes `-o yaml`.

**Server support.** Lists are filtered and paged on the server
(`ListApps`), `cluster status` is a bounded summary (`ClusterStatus`), and
`app show` reads only that app's records, so none of them grows with the
cluster beyond what it prints.

## Consequences

- Scripts written for earlier alphas need the new names; the release notes
  list them.
- A first app needs no YAML; a team that keeps specs in git exports once
  and works from files.
- `update` with flags and `update --file` differ: the first changes some
  fields, the second all of them. `--diff` shows which.

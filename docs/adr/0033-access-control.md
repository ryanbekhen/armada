# 0033. Access control: users, services, and roles

- Status: Accepted
- Date: 2026-11-10
- Supersedes: the administrator records of [0028](0028-administrators.md)
  and the automation identities of [0026](0026-spaces-and-network-isolation.md)

## Context

Two kinds of identity could call the API. An administrator (ADR 0028) could
do everything. An automation identity (ADR 0026) could manage the apps of
some spaces and nothing else. Nothing in between could be expressed: a
person who should only deploy one space needed full control, a tool
could not be limited to reading, and the two kinds were managed with two
command groups that did the same things differently.

## Decision

Access is granted by **roles** given to **principals**.

**Principals.**

- A **user** is a person. Their certificate (kind `user`, one year) is
  made from a key that never leaves their machine. A user on record whose
  certificate was issued before their latest one (`Since`) or who was
  deleted is refused, as administrators were. A replacement records the
  new certificate's serial and when it was recorded: from then on only
  that certificate and ones issued in a later second are accepted, so a
  certificate the old key renewed just before, even in the same second,
  is refused. A user's own renewal is checked and recorded in one
  transaction with that record, and is rate limited per name. Every path that signs a
  user certificate outside the API records the name first, with
  cluster-admin unless it is on record: `armadad init`, `armadad user
  renew`, and `armadad server join` (through the leader, `JoinServerRequest.
  user_name`; a leader that does not record it gets no config written).
  A certificate of a name with no record keeps full control only when it
  was issued before the keyspace moved to schema 14 (`meta/user-cutoff`,
  compared with NotBefore plus the CA's backdating), as such administrator
  certificates did; a later one, or any on a keyspace created at schema
  14, is refused, and cannot renew into a record. This keeps a restore
  from turning a user created after the backup, whom the restored state
  no longer knows, into a cluster-admin; users and services are as of the
  backup, and changes made since must be made again.
- A **service** is a tool: a CI system, a portal. Its certificates (kind
  `service`, 90 days) are recorded by serial, and only recorded ones are
  accepted; it renews its own, which revokes its others.
- Both may carry **allowed node labels**: the label values their apps'
  `placement.require` may name (`armada.*` labels are always allowed).
- Certificates of the old kinds stay valid: `admin` is read as `user` and
  `automation` as `service`, under the same name.

**Roles.** Built in, not editable:

| Role | Scope | May |
| --- | --- | --- |
| `viewer` | the cluster (every space) or one space | list and show apps, jobs, revisions, specs, secret names, domains, volumes; logs, usage, events |
| `deployer` | one space, not `default` | what a viewer may, and deploy, scale, roll back, split traffic, set and delete secrets, run and cancel jobs, verify domains |
| `admin` | one space, not `default` | what a deployer may, and exec, back up, restore, and delete volumes, delete apps and jobs |
| `space-creator` | the cluster | create spaces (becoming `admin` of each) and delete those it is `admin` of once they are empty |
| `cluster-admin` | the cluster | everything: nodes, servers, cluster settings, join tokens, metrics credentials, and access control |

A principal holds any number of **assignments** (a role, and a space when
the role is scoped to one). Its rights in a space are the most its
assignments give there. The `default` space's containers may reach the
platform unless isolated, so only `viewer` can be given in it; deploying
there needs `cluster-admin`.

**Checks.** Every API method has one entry in a table: the role level it
needs in the space it names (`viewer`, `deployer`, `admin`), creating
spaces, the caller's own certificate (renewal), or `cluster-admin`. A
method missing from the table is for `cluster-admin` only, so a new method
is closed until it is placed; a test walks the whole service descriptor.
Handlers check the space of every app, job, volume, and domain they touch
against the level, and listings show only what the caller may see.
Principals that are not `cluster-admin` see no nodes, servers, or cluster
events. The metrics endpoint accepts metrics certificates and principals
with `cluster-admin`. Roles are read on every call, and again every few
seconds while a stream stays open (an events or logs follow, an exec
session, a volume transfer): a stream ends once its certificate is
refused (the principal deleted, its certificate replaced) or expires, or
once no role reaches the method or the app it serves, and an events follow
stops showing spaces whose role was taken back. A logs follow also checks
before it adds a replica that started later.

**Safety.** A caller cannot delete themselves or remove their own
`cluster-admin` assignment, so the cluster always keeps one. Every change
to principals and assignments is audited.

**Commands.**

```
armada rbac user        create | list | show | credentials | renew | update | delete
armada rbac service     create | list | show | credentials | renew | update | delete
armada rbac role        list | show
armada rbac assignment  create | list | delete
```

`armadad init` makes the first user, with `cluster-admin`.

**Upgrade.** State schema 9 moves every administrator on record to a user
with `cluster-admin` (removed ones stay refused), and every automation
identity to a service with `admin` in each of its spaces, plus
`space-creator` when it could create spaces. Nobody gains or loses a
right.

## Consequences

- One model for people and tools; giving someone less than full control
  is one command.
- The `admin` and `automation` command groups, and their API methods, are
  gone; `armadad admin renew` is `armadad user renew`.
- Roles are fixed. Custom roles can come later on the same table.

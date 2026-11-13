# 0026. Spaces and network isolation

- Status: Accepted; automation identities superseded by [0033](0033-access-control.md) (services with roles)
- Date: 2026-11-04

## Context

A cluster usually runs more than one kind of work: staging next to
production, or several unrelated apps. Names, secrets, domains, and
`<app>.internal` should not have to be unique across all of them. A vulnerable
dependency in one app should not hand over the others, the nodes, the control
plane, or the machine's cloud credentials. And a CI system should be able to
deploy what it is responsible for without holding the keys to the whole
cluster.

## Decision

### Spaces

- A **space** holds apps, jobs, secrets, domains, and volumes. Names are
  unique within a space, so `api` can exist in two spaces.
- **The name.** "Space" says only that its apps are kept apart from the
  others. It does not suggest a stage like dev or production (clusters
  often hold one stage each), it does not read like `env` and `--env`, and
  it leaves room to group apps inside a space later without the grouping
  taking the same name. Records written while spaces were called projects
  are moved at schema 11 (`migrateSpaces`), and a client config's
  `project` is read as its space.
- Space names follow the app name rules, at most 30 characters.
  `default` exists in every cluster without a record and holds everything
  deployed without a space.
- **App IDs.** Everywhere past the API, an app is named by its ID
  (`spec.AppID`): its name in `default`, `<name>.<space>` in any other
  space. App names have no dots, so IDs never collide. The ID is the store
  key (`apps/<id>`, and the same for revisions, replicas, secrets, runs, and
  volumes), and everything built from it carries the space without a
  field of its own:
  - revision and replica names (`web.staging--r1`, `web.staging-r1-…`)
    and so container names and labels;
  - HAProxy backend names (`be_web.staging`);
  - the internal host name (`web.staging.internal`);
  - volume directories (`<data dir>/volumes/web.staging/<name>`);
  - metrics and event labels.
  A space of at most 30 characters keeps container names within the
  runtime's limit.
- Domains stay cluster-wide (`domains/<domain>`) and record the space
  that owns them: a domain verified by one space cannot be claimed by
  another.
- Administrators, and automation identities allowed to (see below), create
  or remove spaces. Removing a space requires it to be empty.

### Who manages spaces

Armada has no accounts for people. Anything that needs them belongs to the
tools built on Armada's API, which call it with one identity of their own.

- **Administrators** (`admin:`) keep full control, including every space.
- **Automation identities** (`automation:<name>`) are for tools such as CI
  systems. An administrator issues one with `armada automation credentials
  NAME`, which signs a CSR made on the tool's machine (the private key never
  leaves it), like metrics credentials (ADR 0017). Each has a scope (`armada
  automation set`), set and changed only by administrators:
  - the spaces it manages: a fixed list, plus every space it creates;
  - whether it may create spaces, and remove the ones it manages;
  - the node label values its apps' `placement.require` may name
    (`armada.*` labels are always allowed), so restricted nodes kept for
    one space stay out of others' reach.
- Automation certificates last 90 days. The tool renews with its current
  one (`armada automation renew`), which revokes every other certificate
  of the identity. Like node certificates, they are accepted only while
  their serial is recorded, so `armada automation remove NAME` cuts a tool
  off at once. The scope is read from the store on every call, never from
  the certificate. A removed space leaves every scope, so a space
  created later under its name is not handed over.
- Within its spaces an automation identity may do what an administrator
  may do to apps: deploy, scale, rollback, traffic, jobs, secrets, domains,
  volumes, exec, logs, events, and top. It may never touch nodes, join
  tokens, servers, backups, the network, the `default` space, or a space
  outside its scope.

### The space API

- Automation identities call `AdminService` on the same private listener
  as the CLI, where every RPC already names an app by its ID. The
  interceptor lets them reach only an allowlist of methods
  (`automationMethods`): any method not on it, including any added later,
  is refused before its handler runs. Each allowed handler checks the app
  or space of the request against the scope (`access`), with the same
  answer whether or not the app exists, and listings (status, top, jobs,
  volumes, domains, spaces, events) hold only the scope's apps. Nodes
  are left out of status and top, and node events, node arguments (volume
  restores elsewhere), and events of the cluster are refused.
- Specs sent by automation identities are narrower than an
  administrator's: `placement.require` must stay within the scope's labels.
- A domain serves one space: an app cannot name a domain that an app of
  another space uses, and a domain left behind by another space is
  verified afresh with a new token.
- Exec, logs, and volume sessions are checked against the replica's
  space on every hop.
- Events and the audit log record the space and the caller. Automation
  identities see only their spaces' events; the audit log stays admin
  only.
- No new listener: tools reach the API on the private network like the CLI
  does, and nothing new faces the internet.

### Network isolation

Spaces build on the cluster network (ADR 0025) and its access rules:

- **Between spaces.** Direct traffic from a container of one space to
  a container of another is dropped, on the same node and across nodes.
  `ingress.allow` (ADR 0025 stage 3) only names apps of the same space.
- **Internal ingress and DNS.** Internal names carry the space:
  `<app>.<space>.internal`, and the `default` space has
  `<app>.internal`; within its own space a container may use the app's
  name alone (ADR 0007: its space's zone is its search domain, and the
  internal frontend completes a `Host` without a dot with the caller's
  space). The agent's DNS server answers a container only for
  its own space's names: it knows each container's app from its address
  (the same list its firewall uses), and answers no internal name to an
  address it does not know. HAProxy's internal frontend admits a request
  only from addresses of the app's space (and, with `ingress.allow`, only
  the listed apps).
- **Away from the platform.** A space container may reach the internet,
  its node's DNS server and internal ingress on the bridge gateway (the
  ports of internal TCP apps included, ADR 0039), and the
  containers its rules allow, and nothing else. Dropped in the forward and
  input paths of every node:
  - the private addresses of every node and server (API, join, etcd,
    metrics, the tunnel);
  - the link-local range (`169.254.0.0/16`, the cloud metadata service);
  - every other private, shared, and loopback range outside the cluster
    CIDR (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7`), so
    the private network and the machines on it are out of reach;
  - every other port on the node's own addresses.

  A new container's address is known to its node's firewall as soon as it
  starts; until then, and for any address the node does not know, the
  node treats it as isolated. Connections opened before a rule changed
  keep going until they end.

  These rules apply to every space. In `default` they apply once the
  administrator turns them on (`armada space set default
  --network-isolation`, stored with the cluster network), for apps that use
  the private network. `armada space list` shows which spaces are
  isolated.
- **Spoofing.** Containers run without `NET_ADMIN` and `NET_RAW` (ADR
  0025), so a container cannot pose as another space's. Across nodes, in
  the `plain` mode, the source of a packet is only as trustworthy as the
  private network (a machine on it can forge VXLAN packets, T57); the
  `wireguard` mode closes that gap.

### Sharing a node

- Containers of every space share each node's kernel, confined by
  namespaces, cgroups, seccomp, no new privileges, and SELinux where
  enforcing. Spaces separate apps that are operated together; they are
  not a boundary for code someone hostile wrote.
- **Dedicated nodes.** A space's placement can require node labels on
  restricted nodes (ADR 0014), so a space gets nodes no other space
  uses.
- Every replica reserves CPU and memory with no overcommit and has memory
  and PID limits. Spaces share the cluster's capacity first come, first
  served; `scale.max` bounds what an app can take.
- Log volume is limited per container, so one app cannot fill a node's disk
  or take its disk bandwidth: besides rotation (3 files of 10 MB), the log
  writer drops output past 1 MiB per second (4 MiB burst) and writes one
  line saying how much it dropped.

### Usage per space

`armada top --spaces` and the metrics endpoint (`armada_space_*`)
aggregate usage per space: CPU, memory, reservations, and volume bytes
from the samples agents already send (ADR 0016), and two counters, requests
and egress bytes. `AdminService.Top` lists only the spaces the caller may
manage, so an automation identity sees its own usage and only administrators
see every space.

Egress is what a container's `eth0` sent, read from the network namespace's
counters (`/proc/PID/net/dev` of the task). It therefore includes replies
through the proxies and traffic to other replicas. Agents report what was
sent since the previous sample; requests come from the per-replica deltas of
ADR 0021.

Replicas come and go, so the counters cannot be summed when read: the leader
adds each report to a per-space total as it arrives. So that a report
still costs no store access, the reconciler hands the usage store the owner
of every replica on each pass, and a report only counts for replicas in that
list; egress also only from the replica's own node. Like all usage the
totals live in the leader's memory and start over with a new leader, which
Prometheus counters handle as a reset. Keeping them in etcd would mean a
store write per space every 10 seconds for no gain over scraping them.

### Schema

Schema 7 is a gate with nothing to rewrite (ADR 0012): the apps of `default`
keep their keys, names, hostnames (`<app>.internal`), domains, and container
names. Servers that would read `<name>.<space>` as an app name can no
longer lead.

## Alternatives considered

- **A cluster per group of apps.** The strongest separation, but every
  group pays for its own control plane and nodes, and capacity cannot be
  shared. Dedicated nodes inside one cluster give most of the separation
  where it is worth the cost.
- **Spaces as names only.** Simpler, but a compromised app would still
  reach every other app, the nodes, and the cloud metadata service.
- **A control plane per space.** Separates the API and the state, but the
  workloads still share nodes, at the cost of running many control planes.
- **Accounts and roles for people in Armada.** Sign-in, invitations, and
  per-person roles would make Armada an identity system and add a listener
  meant for people outside the private network. Tools built on the API
  already have their own accounts; Armada only needs to bound what such a
  tool can do.
- **Tools with admin certificates.** Simplest, but a compromised tool would
  then control nodes, tokens, and backups, which hold the cluster's keys.

## Consequences

- Staging and production, or unrelated apps, can share a cluster with
  separate names and no network path between them.
- A compromised app, or a compromised tool, stays away from the nodes, the
  control plane, and the private network, on every space but `default`.
- Apps of a space share the node's kernel. Code from people the operator
  does not trust needs a cluster of its own, or dedicated nodes.
- One space can take the cluster's free capacity, so another's deploy
  waits for room.
- Every RPC, store key, label, and metric carries a space, which touches
  most of the server.
- The network rules depend on knowing every container's space from its
  address. The leader sends every replica's address and app to every node
  (ADR 0025).
- Watch: the cost of the per-space rule sets on large clusters.

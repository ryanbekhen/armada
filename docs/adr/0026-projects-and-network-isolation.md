# 0026. Projects and network isolation

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

### Projects

- A **project** holds apps, jobs, secrets, domains, and volumes. Names are
  unique within a project, so `api` can exist in two projects.
- Project names follow the app name rules, at most 30 characters.
  `default` exists in every cluster without a record and holds everything
  deployed without a project.
- **App IDs.** Everywhere past the API, an app is named by its ID
  (`spec.AppID`): its name in `default`, `<name>.<project>` in any other
  project. App names have no dots, so IDs never collide. The ID is the store
  key (`apps/<id>`, and the same for revisions, replicas, secrets, runs, and
  volumes), and everything built from it carries the project without a
  field of its own:
  - revision and replica names (`web.staging--r1`, `web.staging-r1-…`)
    and so container names and labels;
  - HAProxy backend names (`be_web.staging`);
  - the internal host name (`web.staging.internal`);
  - volume directories (`<data dir>/volumes/web.staging/<name>`);
  - metrics and event labels.
  A project of at most 30 characters keeps container names within the
  runtime's limit.
- Domains stay cluster-wide (`domains/<domain>`) and record the project
  that owns them: a domain verified by one project cannot be claimed by
  another.
- Administrators, and automation identities allowed to (see below), create
  or remove projects. Removing a project requires it to be empty.

### Who manages projects

Armada has no accounts for people. Anything that needs them belongs to the
tools built on Armada's API, which call it with one identity of their own.

- **Administrators** (`admin:`) keep full control, including every project.
- **Automation identities** (`automation:<name>`) are for tools such as CI
  systems. An administrator issues one with `armada automation credentials
  NAME`, which signs a CSR made on the tool's machine (the private key never
  leaves it), like metrics credentials (ADR 0017). Each has a scope (`armada
  automation set`), set and changed only by administrators:
  - the projects it manages: a fixed list, plus every project it creates;
  - whether it may create projects, and remove the ones it manages;
  - the node label values its apps' `placement.require` may name
    (`armada.*` labels are always allowed), so restricted nodes kept for
    one project stay out of others' reach.
- Automation certificates last 90 days. The tool renews with its current
  one (`armada automation renew`), which revokes every other certificate
  of the identity. Like node certificates, they are accepted only while
  their serial is recorded, so `armada automation remove NAME` cuts a tool
  off at once. The scope is read from the store on every call, never from
  the certificate. A removed project leaves every scope, so a project
  created later under its name is not handed over.
- Within its projects an automation identity may do what an administrator
  may do to apps: deploy, scale, rollback, traffic, jobs, secrets, domains,
  volumes, exec, logs, events, and top. It may never touch nodes, join
  tokens, servers, backups, the network, the `default` project, or a project
  outside its scope.

### The project API

- Automation identities call `AdminService` on the same private listener
  as the CLI, where every RPC already names an app by its ID. The
  interceptor lets them reach only an allowlist of methods
  (`automationMethods`): any method not on it, including any added later,
  is refused before its handler runs. Each allowed handler checks the app
  or project of the request against the scope (`access`), with the same
  answer whether or not the app exists, and listings (status, top, jobs,
  volumes, domains, projects, events) hold only the scope's apps. Nodes
  are left out of status and top, and node events, node arguments (volume
  restores elsewhere), and events of the cluster are refused.
- Specs sent by automation identities are narrower than an
  administrator's: `placement.require` must stay within the scope's labels.
- A domain serves one project: an app cannot name a domain that an app of
  another project uses, and a domain left behind by another project is
  verified afresh with a new token.
- Exec, logs, and volume sessions are checked against the replica's
  project on every hop.
- Events and the audit log record the project and the caller. Automation
  identities see only their projects' events; the audit log stays admin
  only.
- No new listener: tools reach the API on the private network like the CLI
  does, and nothing new faces the internet.

### Network isolation

Projects build on the cluster network (ADR 0025) and its access rules:

- **Between projects.** Direct traffic from a container of one project to
  a container of another is dropped, on the same node and across nodes.
  `ingress.allow` (ADR 0025 stage 3) only names apps of the same project.
- **Internal ingress and DNS.** Internal names carry the project:
  `<app>.<project>.internal`, and the `default` project has
  `<app>.internal`. The agent's DNS server answers a container only for
  its own project's names: it knows each container's app from its address
  (the same list its firewall uses), and answers no internal name to an
  address it does not know. HAProxy's internal frontend admits a request
  only from addresses of the app's project (and, with `ingress.allow`, only
  the listed apps).
- **Away from the platform.** A project container may reach the internet,
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

  These rules apply to every project. In `default` they apply once the
  administrator turns them on (`armada project set default
  --network-isolation`, stored with the cluster network), for apps that use
  the private network. `armada project list` shows which projects are
  isolated.
- **Spoofing.** Containers run without `NET_ADMIN` and `NET_RAW` (ADR
  0025), so a container cannot pose as another project's. Across nodes, in
  the `plain` mode, the source of a packet is only as trustworthy as the
  private network (a machine on it can forge VXLAN packets, T57); the
  `wireguard` mode closes that gap.

### Sharing a node

- Containers of every project share each node's kernel, confined by
  namespaces, cgroups, seccomp, no new privileges, and SELinux where
  enforcing. Projects separate apps that are operated together; they are
  not a boundary for code someone hostile wrote.
- **Dedicated nodes.** A project's placement can require node labels on
  restricted nodes (ADR 0014), so a project gets nodes no other project
  uses.
- Every replica reserves CPU and memory with no overcommit and has memory
  and PID limits. Projects share the cluster's capacity first come, first
  served; `scale.max` bounds what an app can take.
- Log volume is limited per container, so one app cannot fill a node's disk
  or take its disk bandwidth: besides rotation (3 files of 10 MB), the log
  writer drops output past 1 MiB per second (4 MiB burst) and writes one
  line saying how much it dropped.

### Usage per project

`armada top --projects` and the metrics endpoint (`armada_project_*`)
aggregate usage per project: CPU, memory, reservations, and volume bytes
from the samples agents already send (ADR 0016), and two counters, requests
and egress bytes. `AdminService.Top` lists only the projects the caller may
manage, so an automation identity sees its own usage and only administrators
see every project.

Egress is what a container's `eth0` sent, read from the network namespace's
counters (`/proc/PID/net/dev` of the task). It therefore includes replies
through the proxies and traffic to other replicas. Agents report what was
sent since the previous sample; requests come from the per-replica deltas of
ADR 0021.

Replicas come and go, so the counters cannot be summed when read: the leader
adds each report to a per-project total as it arrives. So that a report
still costs no store access, the reconciler hands the usage store the owner
of every replica on each pass, and a report only counts for replicas in that
list; egress also only from the replica's own node. Like all usage the
totals live in the leader's memory and start over with a new leader, which
Prometheus counters handle as a reset. Keeping them in etcd would mean a
store write per project every 10 seconds for no gain over scraping them.

### Schema

Schema 7 is a gate with nothing to rewrite (ADR 0012): the apps of `default`
keep their keys, names, hostnames (`<app>.internal`), domains, and container
names. Servers that would read `<name>.<project>` as an app name can no
longer lead.

## Alternatives considered

- **A cluster per group of apps.** The strongest separation, but every
  group pays for its own control plane and nodes, and capacity cannot be
  shared. Dedicated nodes inside one cluster give most of the separation
  where it is worth the cost.
- **Projects as names only.** Simpler, but a compromised app would still
  reach every other app, the nodes, and the cloud metadata service.
- **A control plane per project.** Separates the API and the state, but the
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
  control plane, and the private network, on every project but `default`.
- Apps of a project share the node's kernel. Code from people the operator
  does not trust needs a cluster of its own, or dedicated nodes.
- One project can take the cluster's free capacity, so another's deploy
  waits for room.
- Every RPC, store key, label, and metric carries a project, which touches
  most of the server.
- The network rules depend on knowing every container's project from its
  address. The leader sends every replica's address and app to every node
  (ADR 0025).
- Watch: the cost of the per-project rule sets on large clusters.

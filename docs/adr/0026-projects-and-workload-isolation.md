# 0026. Projects and workload isolation

- Status: Accepted
- Date: 2026-11-04

## Context

Every app in a cluster shares one space: names, secrets, domains, and
`<app>.internal` are cluster-wide, and every `admin:` identity can do
everything. Containers share each node's kernel, can call every other app,
and reach whatever the node's network reaches: other nodes' private
addresses, the private network, and the cloud metadata service. That is
fine while one person runs a few apps they wrote, and falls short as soon
as any of these holds:

- **An app is compromised.** A vulnerable dependency or a remote code
  execution bug in one app should not hand over the other apps, the nodes,
  the control plane, or the machine's cloud credentials.
- **Environments share a cluster.** Staging and production, or experiments
  and the apps people depend on, should not be able to touch each other.
- **Tools act for people.** A CI system, or a self-service portal someone
  builds on Armada's API for the people and teams who share a cluster,
  should manage the projects it is responsible for without holding the
  keys to the whole cluster. If such a tool is compromised, the nodes and
  the control plane must stay out of reach.
- **Code is not fully trusted.** Third-party images, previews built from
  pull requests, and jobs that run code someone submitted are written by
  people the operator does not control.

Least privilege and defense in depth, the rules the rest of Armada follows,
call for a boundary that holds even when a workload inside it is hostile.
Such a boundary is only real if every layer enforces it: access to the API,
the network, the kernel, and the shared resources. A boundary that depends
on the operator assembling and remembering each layer fails at the layer
they forget, so Armada builds every layer in and turns it on together.

## Decision

### Projects

- A **project** holds apps, jobs, secrets, domains, and volumes. Names are
  unique within a project, so `api` can exist in two projects.
- Project names follow the app name rules, at most 30 characters.
  `default` exists in every cluster without a record and holds everything
  created before projects (see Migration).
- **App IDs.** Everywhere past the API, an app is named by its ID
  (`spec.AppID`): its name in `default`, `<name>.<project>` in any other
  project. App names have no dots, so IDs never collide, and the IDs of
  `default` are the names apps already have. The ID is the store key
  (`apps/<id>`, and the same for revisions, replicas, secrets, runs, and
  volumes), and everything built from it carries the project without a
  field of its own:
  - revision and replica names (`web.staging--r1`, `web.staging-r1-…`)
    and so container names and labels;
  - HAProxy backend names (`be_web.staging`, validated like today);
  - the internal host name (`web.staging.internal`);
  - volume directories (`<data dir>/volumes/web.staging/<name>`);
  - metrics and event labels.
  A project of at most 30 characters keeps container names within the
  runtime's limit.
- Domains stay cluster-wide (`domains/<domain>`) and record the project
  that owns them: a domain verified by one project cannot be claimed by
  another.
- A project record holds its settings: isolation level, quotas, placement,
  and limits. Administrators, and automation identities allowed to (see
  below), create, change, or remove projects. Removing a project requires
  it to be empty.

### Who manages projects

Armada has no accounts for people. Anything that needs them (sign-in,
teams, permissions per person) belongs to the tools built on Armada's API,
which call it with one identity of their own. Armada's job is to make sure
that identity can reach only what it manages.

- **Administrators** (`admin:`) keep full control, including every project.
- **Automation identities** (`automation:<name>`) are for tools such as CI
  systems and portals. An administrator issues one with `armada automation
  credentials NAME`, which signs a CSR made on the tool's machine (the
  private key never leaves it), like metrics credentials (ADR 0017). Each
  has a scope (`armada automation set`), set and changed only by
  administrators:
  - the projects it manages: a fixed list, plus every project it creates;
  - whether it may create projects, and remove the ones it manages;
  - the node label values its apps' `placement.require` may name
    (`armada.*` labels are always allowed), so restricted nodes kept for
    one project stay out of others' reach;
  - with the features that bring them, the lowest isolation level and the
    largest quota.
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
  tokens, servers, backups, the network, the `default` project, a project
  outside its scope, or the cluster's limits, and it cannot set a project
  below the limits of its scope.

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
  administrator's: `placement.require` must stay within the scope's
  labels, and isolation and quotas within its limits.
- A domain serves one project: an app cannot name a domain that an app of
  another project uses, and a domain left behind by another project is
  verified afresh with a new token.
- Exec, logs, and volume sessions are checked against the replica's
  project on every hop, like the node check today.
- Events and the audit log record the project and the caller. Automation
  identities see only their projects' events; the audit log stays admin
  only.
- No new listener: tools reach the API on the private network like the CLI
  does, and nothing new faces the internet.

### Network isolation

Projects build on the cluster network (ADR 0025) and its access rules,
which become project-aware:

- **Between projects.** Direct traffic from a container of one project to
  a container of another is dropped, on the same node and across nodes.
  `ingress.allow` (ADR 0025 stage 3) only names apps of the same project.
- **Internal ingress and DNS.** Internal names gain the project:
  `<app>.<project>.internal`, and the `default` project keeps
  `<app>.internal`. The agent's DNS server answers a container only for
  its own project's names: it knows each container's app from its address
  (from its own containers, the same list its firewall uses), and answers
  no internal name to an address it does not know. HAProxy's internal
  frontend admits a request only from addresses of the app's project (and,
  with `ingress.allow`, only the listed apps).
- **Away from the platform.** A project container may reach the internet,
  its node's DNS server and internal ingress on the bridge gateway, and the
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
  --network-isolation`, stored with the cluster network), so running
  clusters do not break. `armada project list` shows which projects are
  isolated.
- **Spoofing.** Containers run without `NET_ADMIN` and `NET_RAW` (ADR
  0025), so a container cannot pose as another project's. Across nodes, in
  the `plain` mode, the source of a packet is only as trustworthy as the
  private network (a machine on it can forge VXLAN packets, T57); the
  `wireguard` mode closes that gap.

### Kernel isolation

A shared kernel is the boundary that a single bug crosses, so a project
chooses how its containers are isolated from the node, and an administrator
sets the minimum:

| `isolation` | What runs | Needs |
| --- | --- | --- |
| `container` | Containers as today: namespaces, cgroups, seccomp, no new privileges, SELinux where enforcing | nothing |
| `sandbox` | Each replica in a userspace kernel (gVisor's `runsc`), so the workload's system calls never reach the node's kernel directly | the embedded runtime |
| `vm` | Each replica in its own light virtual machine with its own kernel, run by the embedded runtime (designed in a later decision) | a node with hardware virtualization |

- `sandbox` is the default for every project except `default`. The
  embedded runtime ships `runsc` and the sentry it runs, pinned and
  verified like the other runtime binaries (`internal/runtime/embedded`).
  The runc shim that runs every other container drives `runsc` through the
  same OCI commands (gVisor's own shim cannot hand output to Armada's log
  writer), so output, exec, stats, and probes keep their path. The OCI
  spec Armada builds stays the same, so every security default still
  applies inside the sandbox, with one exception: gVisor refuses SELinux
  labels, so a sandboxed container runs without one, confined by the
  sentry that serves its system calls and the sentry's own seccomp filter.
  The memory and PID limits bound the whole sandbox in its cgroup on the
  host.
- The level is a project setting: `armada project create NAME
  [--isolation L]` and `armada project set NAME --isolation L`. Only
  administrators set `container` on a project other than `default` or
  change a level; automation identities create projects at the default,
  `sandbox`, and change no level, so the projects a tool manages never
  run below it.
- Every revision pins its project's level when it is deployed, like its
  secret versions, and the agent gets it in the replica's spec (part of
  the spec hash). A changed level applies to revisions deployed afterwards:
  deploying the same spec again makes a new revision, rolled out like any
  other, so replicas move to the new level without dropping traffic. A
  rollback or traffic weight that names a revision weaker than the
  project's current level is refused.
- Agents announce whether they run sandboxed containers (`Hello.sandbox`,
  shown in `armada node list`), and `placementAllows` places a replica
  only on a node that supports its revision's level; an agent also refuses
  to start a sandboxed replica it cannot run. A project that requires a
  level no node supports gets a `NoIsolation` condition, never a weaker
  level.
- The conformance suite gains a `Sandbox` option: the embedded runtime
  runs the whole suite with every container in gVisor, which also checks
  that each container has a kernel of its own (the boot ID differs). The
  limits and a volume's mount flags apply on the host, where the sandbox
  cannot show them, so the runtime's integration test checks them there.
- Exec, stats, logs, volumes, and probes work at every level; features
  that a level cannot support are refused when the project is set, not
  silently ignored.
- **Dedicated nodes.** A project's placement can require node labels on
  restricted nodes (ADR 0014), so a project gets nodes no other project
  uses. That is the strongest separation and also composes with the levels
  above.

### Quotas and limits

- A project's quota bounds the sum of its reservations: CPU, memory,
  replicas (counting autoscaling's maximum), the volumes its apps declare,
  domains, secrets, and concurrent job attempts. A job counts one attempt's
  reservation. Every check runs in the same store transaction that would
  exceed it (deploy, scale, rollback, a new secret, an attempt's
  creation), so concurrent requests cannot overrun it; autoscaling never
  goes past `scale.max`, which is already counted. A zero limit is
  unlimited.
- A quota lowered below what a project uses keeps what runs: only changes
  that grow a dimension past its limit are refused (`ErrQuota`, a failed
  precondition naming the dimension). Job attempts over the limit wait,
  with a `QuotaExceeded` condition, within the run's timeout.
- Administrators set quotas (`armada project create|set --quota`). An
  automation identity's scope carries a quota (`armada automation set
  --quota`) that every project it creates gets; it can neither choose nor
  change one. Schema 9 gates servers that would not enforce quotas.
- A quota may also carry `egress`, which is not a total but a limit on
  each replica and job attempt: the bits per second its container may
  send (1M to 10G). Like the kernel isolation level it is pinned into
  every revision at deploy (`Revision.EgressBits`): a changed limit makes
  the same spec a new revision, which rolls out without dropping traffic,
  and rollback or traffic to a revision deployed without the limit or
  above it is refused. Replicas with a limit run only on nodes whose agent
  announced that it can shape traffic (`Hello.egress`: the bundled CNI
  `bandwidth` plugin and the kernel's ifb, ingress qdisc, u32, mirred,
  and tbf modules); the agent refuses them elsewhere, and with no such
  node they wait with a `NoIsolation` condition. The plugin redirects what
  the container sends from its veth to an ifb device with a token bucket
  filter (100 ms burst), outside the container, which has no
  `CAP_NET_ADMIN`; it covers everything the container sends, responses
  through ingress included. Schema 10 gates servers that would not pin or
  place by the limit.
- A quota may also carry `requests` and `connections`, limits on each app
  at each node's proxy rather than totals: the requests per second it may
  receive there, and the requests it may have in progress there at once.
  They are not pinned: `buildProxy` reads the project's quota, so a
  change applies to running apps at once (a reload). Every backend of the
  app (`proxy.BackendApp`: revision labels included) shares one counter in
  a stick table keyed by app ID (`st_armada_limits`), on the public and
  internal frontends alike; the counter is tracked per request
  (`http-request track-sc0`), so it counts requests in progress whatever
  the client's connections, and requests past a limit get 429 before they
  reach a replica or wake one. The limit holds per node: an app served by
  three nodes' proxies may receive three times as much. Schema 11 gates
  servers that would not send the limits.
- Per-replica limits stay as today and every project container gets them
  (memory, PIDs, CPU weight); `sandbox` also bounds the sandbox's own
  memory.
- Shared paths get limits a project cannot raise:
  - egress bandwidth per replica (the CNI `bandwidth` plugin, pinned like
    the others; the quota's `egress`, above; done);
  - connections and request rate per app in HAProxy, set by the
    administrator per project (the quota's `requests` and `connections`,
    above; done);
  - log volume per replica, so one project cannot fill a node's disk or
    take its disk bandwidth: besides rotation (3 files of 10 MB), the
    log writer drops output past 1 MiB per second (4 MiB burst) and
    writes one line saying how much it dropped (done).

### Usage per project

`armada top --projects` and the metrics endpoint (`armada_project_*`)
aggregate usage per project: CPU, memory, reservations, and volume bytes
from the samples agents already send (ADR 0016), and two counters, requests
and egress bytes. `AdminService.Top` lists only the projects the caller may
manage, so an automation identity sees its own usage and only administrators
see every project.

Egress is what a container's `eth0` sent, read from the network namespace's
counters (`/proc/PID/net/dev` of the task, which also holds in the sandbox,
where the userspace kernel sends through the same interface). It therefore
includes replies through the proxies and traffic to other replicas. Agents
report what was sent since the previous sample; requests come from the
per-replica deltas of ADR 0021.

Replicas come and go, so the counters cannot be summed when read: the leader
adds each report to a per-project total as it arrives. So that a report
still costs no store access, the reconciler hands the usage store the owner
of every replica on each pass, and a report only counts for replicas in that
list; egress also only from the replica's own node. Like all usage the
totals live in the leader's memory and start over with a new leader, which
Prometheus counters handle as a reset. Keeping them in etcd would mean a
store write per project every 10 seconds for no gain over scraping them.

### Migration

- Schema 7 is a gate with nothing to rewrite (ADR 0012): the apps of
  `default` keep their keys, names, hostnames (`<app>.internal`), domains,
  and container names, so a running cluster changes nothing until an
  administrator creates a project. Servers that would read
  `<name>.<project>` as an app name can no longer lead.
- `default` keeps `isolation: container` and no network isolation until the
  administrator changes them.
- Schema 8 brings kernel isolation: projects created before it keep
  `container`, written into their records by the migration, and servers
  that would start a sandboxed revision's replicas as plain containers can
  no longer lead.

### Order

Each step ships on its own and refuses what is not built yet with a clear
message:

1. projects, store layout, automation identities, and `ProjectService`;
2. network isolation between projects and away from the platform, built as
   ADR 0025's access stage: the firewall between apps and projects, the
   rules away from the platform, per-project DNS, the project check in
   HAProxy's internal frontend, and `ingress.allow` (done);
3. `isolation: sandbox` in the embedded runtime: the runtime and node
   support, the project setting, and placement (done);
4. quotas (done), shared-path limits (done), and usage per project (done);
5. `isolation: vm` in the embedded runtime.

## Alternatives considered

- **A cluster per group of apps.** The strongest separation, but every
  group pays for its own control plane and nodes, and capacity cannot be
  shared. Dedicated nodes inside one cluster give most of the separation
  where it is worth the cost.
- **Projects as names only, with isolation left to the operator.** Names
  and roles without network, kernel, and resource enforcement look like a
  boundary but stop nothing a hostile workload does. It is also the failure
  mode this design exists to avoid: one forgotten layer opens all of them.
- **A control plane per project.** Separates the API and the state, but the
  workloads still share nodes, so the network and kernel layers are needed
  anyway, at the cost of running many control planes.
- **Only virtual machine isolation.** The strongest kernel boundary, but it
  needs hardware virtualisation, which most cloud machines do not expose.
  `sandbox` works on any Linux node; `vm` is there where the hardware is.
- **Only system call filtering and mandatory access control.** Armada
  already applies seccomp, no new privileges, and SELinux where enforcing.
  They shrink the kernel's surface but leave it shared: one kernel bug
  still crosses every container on the node.
- **Accounts and roles for people in Armada.** Sign-in, invitations, and
  per-person roles would make Armada an identity system and add a listener
  meant for people outside the private network. Tools built on the API
  already have their own accounts; Armada only needs to bound what such a
  tool can do.
- **Tools with admin certificates.** Simplest, but a compromised tool would
  then control nodes, tokens, and backups, which hold the cluster's keys.

## Consequences

- One cluster can host workloads that do not trust each other, with
  boundaries at the API, the network, the kernel, and shared resources,
  all on by default for every project but `default`.
- `sandbox` costs performance: system calls, file I/O, and networking go
  through a userspace kernel. CPU-bound work runs close to native speed;
  I/O-heavy work can be markedly slower. `container` stays available where
  an administrator accepts the trade-off.
- The release grows by the sandbox binaries (both architectures). Their
  updates follow the same pinning, checksum, and review as containerd's.
- Every RPC, store key, label, and metric gains a project, which touches
  most of the server. The migration must keep `default` byte-for-byte
  compatible for running clusters.
- Armada stays a foundation: anything built on it (a portal, a CI
  integration) manages accounts itself and uses an automation identity
  whose damage, if compromised, stays inside its projects and limits.
- The network rules depend on knowing every container's project from its
  address. The leader already sends every replica's address to every node
  (ADR 0025); the project is added to it.
- Watch: sandbox compatibility with images that rely on unusual system
  calls (surfaced as a start failure with the sandbox's reason), the cost
  of the per-project rule sets on large clusters, and quota checks staying
  inside one transaction as more resources are counted.

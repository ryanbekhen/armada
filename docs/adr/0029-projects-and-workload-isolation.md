# 0029. Projects and workload isolation

- Status: Proposed
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
- **Several people or teams share a cluster.** Each should manage only
  their own apps and see only their own logs, secrets, and events, without
  being cluster administrators.
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
- Project names follow the app name rules. `default` exists in every
  cluster and holds everything created before projects (see Migration).
- Store keys gain the project: `apps/<project>/<app>`, and the same for
  revisions, replicas, secrets, runs, and volumes. Domains stay
  cluster-wide (`domains/<domain>`) and record the project that owns them:
  a domain verified by one project cannot be claimed by another.
- Objects that leave the store carry the project too:
  - container labels (`armada.project`) and container names;
  - HAProxy backend names (`be_<project>--<app>`, validated like today);
  - volume directories (`<data dir>/volumes/<project>/<app>/<name>`);
  - metrics and event labels.
- A project record holds its settings: isolation level, quotas, placement,
  and members. Only administrators create, change, or remove projects.
  Removing a project requires it to be empty.

### Identities and roles

- A new certificate identity, `user:<name>`, belongs to a person, not to a
  node or a cluster. Administrators keep `admin:`.
- A user is added to projects with one role each:

  | Role | May |
  | --- | --- |
  | `viewer` | status, logs, events, top, list secrets by name |
  | `deployer` | everything `viewer` may, plus deploy, scale, rollback, traffic, run jobs, exec |
  | `owner` | everything `deployer` may, plus secrets, domains, volume backup/restore/remove, and the project's members |

- **Onboarding** works like joining a node: an administrator (or a project
  owner, for their project) creates a single-use, expiring invitation
  token, stored only as a hash. The user runs `armada login` on their own
  machine. The CLI makes the key pair locally, pins the CA by hash, and
  sends a CSR with the token to the login listener (server-only TLS,
  rate limited, the same handling as the join listener). The private key
  never leaves the user's machine.
- User certificates last 30 days and the CLI renews them. Like node
  certificates they are accepted only while their serial is recorded
  (`user_certs`), so removing a user, or their last membership, revokes
  them at once. Membership is checked on every call, never cached in the
  certificate.
- Users never get node, server, etcd, metrics, or admin identities, and no
  RPC that names a node, the cluster, or another project.

### The project API

- A new `ProjectService` serves users. Every request names a project; the
  server checks the caller's membership and role first, then runs the same
  code as the matching admin RPC with the project fixed. Admin RPCs stay
  admin only, and `AdminService` gains a project argument with `default`
  as the default.
- What users may put in a spec is narrower than for administrators:
  - `placement.require` can only narrow the project's own placement, never
    widen it;
  - node names and node labels other than those the project's placement
    allows are hidden from users (`status` shows replicas, not nodes'
    private addresses);
  - exec, logs, and volume sessions are checked against the replica's
    project on every hop, like the node check today.
- Events and the audit log record the project and the user. Users see only
  their project's events; the audit log stays admin only.
- **Where users reach the API.** The admin API stays on the private
  address. `--project-listen IP:PORT` opens a separate listener that serves
  only `ProjectService` and the login handshake, with strict mTLS for
  everything but login and per-identity rate limits. It may be bound to a
  public address: it is the one listener besides HAProxy meant to face
  users who have no access to the private network. Without the flag users
  reach `ProjectService` on the main API.

### Network isolation

Projects build on the cluster network (ADR 0027) and its access rules,
which become project-aware:

- **Between projects.** Direct traffic from a container of one project to
  a container of another is dropped, on the same node and across nodes.
  `ingress.allow` (ADR 0027 stage 3) only names apps of the same project.
- **Internal ingress and DNS.** Internal names gain the project:
  `<app>.<project>.internal`, and the `default` project keeps
  `<app>.internal`. The agent's DNS server answers a container only for
  its own project's names (it knows each container's project from its
  address). HAProxy's internal frontend admits a request only from
  addresses of the app's project (and, with `ingress.allow`, only the
  listed apps).
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

  These rules apply to every project. In `default` they apply once the
  administrator turns them on (`armada project set default
  --network-isolation`), so running clusters do not break.
- **Spoofing.** Each container's interface accepts only its own address as
  a source (ADR 0027), so a container cannot pose as another project's.
  Projects that require isolation on a cluster in `plain` mode get a
  warning in `armada doctor`: across nodes the source check is only as
  strong as the private network, and `wireguard` closes that gap.

### Kernel isolation

A shared kernel is the boundary that a single bug crosses, so a project
chooses how its containers are isolated from the node, and an administrator
sets the minimum:

| `isolation` | What runs | Needs |
| --- | --- | --- |
| `container` | Containers as today: namespaces, cgroups, seccomp, no new privileges, SELinux where enforcing | nothing |
| `sandbox` | Each replica in a userspace kernel (gVisor's `runsc`), so the workload's system calls never reach the node's kernel directly | the embedded runtime |
| `vm` | Each replica in its own virtual machine through a driver that declares `vm_isolation` (ADR 0016) | a node with such a driver |

- `sandbox` is the default for every project except `default`. The
  embedded runtime ships `runsc` and its containerd shim, pinned and
  verified like the other runtime binaries (`internal/runtime/embedded`),
  and registers it as a second runtime. The OCI spec Armada builds stays
  the same, so every security default still applies inside the sandbox.
- Agents announce which levels they support (`Hello.isolation`), and
  `placementAllows` places a replica only on a node that supports its
  project's level. A project that requires a level no node supports gets
  a `NoIsolation` condition, never a weaker level.
- The conformance suite gains a check that a `sandbox` container does not
  see the node's kernel (version and boot ID differ).
- Exec, stats, logs, volumes, and probes work at every level; features
  that a level cannot support are refused when the project is set, not
  silently ignored.
- **Dedicated nodes.** A project's placement can require node labels on
  restricted nodes (ADR 0014), so a project gets nodes no other project
  uses. That is the strongest separation and also composes with the levels
  above.

### Quotas and limits

- A project's quota bounds the sum of its reservations: CPU, memory,
  replicas (counting autoscaling's maximum), volumes and their count,
  domains, secrets, and concurrent job attempts. Every check runs in the
  same store transaction that would exceed it (deploy, scale, autoscaling,
  run creation, volume binding), so concurrent requests cannot overrun it.
- Per-replica limits stay as today and every project container gets them
  (memory, PIDs, CPU weight); `sandbox` also bounds the sandbox's own
  memory.
- Shared paths get limits a project cannot raise:
  - egress bandwidth per replica (the CNI `bandwidth` plugin, pinned like
    the others);
  - connections and request rate per route in HAProxy, set by the
    administrator per project;
  - log volume per replica, so one project cannot fill a node's disk.

### Usage per project

`armada top` and the metrics endpoint aggregate usage per project (CPU,
memory, volume bytes, requests, egress bytes), from the samples agents
already send (ADR 0018). `ProjectService.Top` shows a project its own
usage; the totals per project are admin only.

### Migration

- Schema 7 moves every record into the `default` project in one gated
  migration (ADR 0012). Names, hostnames (`<app>.internal`), domains, and
  container names of `default` keep working, so a running cluster changes
  nothing until an administrator creates a project.
- `default` keeps `isolation: container` and no network isolation until the
  administrator changes them.

### Order

Each step ships on its own and refuses what is not built yet with a clear
message:

1. projects, store layout, `user:` identities, roles, login, and
   `ProjectService`;
2. network isolation between projects and away from the platform, built as
   ADR 0027's access stage;
3. `isolation: sandbox` in the embedded runtime;
4. quotas, shared-path limits, and usage per project;
5. `isolation: vm` through drivers.

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
- **Users on the admin API.** One listener is simpler, but it would put the
  admin surface on whatever address users can reach. A separate listener
  that serves only `ProjectService` keeps the admin API private.

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
- The project listener is a new internet-facing surface. It gets its own
  threat model entries, fuzzing of the login handshake, and rate limits,
  and serves nothing an administrator can do.
- The network rules depend on knowing every container's project from its
  address. The leader already sends every replica's address to every node
  (ADR 0027); the project is added to it.
- Watch: sandbox compatibility with images that rely on unusual system
  calls (surfaced as a start failure with the sandbox's reason), the cost
  of the per-project rule sets on large clusters, and quota checks staying
  inside one transaction as more resources are counted.

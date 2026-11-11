# 0010. Highly available control plane

- Status: Accepted
- Date: 2026-10-31

## Context

With the state in etcd (ADR 0009), several control plane nodes can share
it. What is missing is everything around the store: adding and removing
control plane nodes, deciding which of them acts, letting agents and the
CLI find it, and keeping two of them from acting at once. The goal is that
one server keeps working as before and three servers survive the loss of
any one without an operator.

## Decision

### One leader, elected through etcd

Every control plane node runs `armadad server` and its etcd member. The
nodes campaign in an etcd election (`concurrency.Election` under
`/armada-leader/`, lease TTL 10 s). The leader serves the gRPC API and the
join listener and runs everything that acts: the reconciler, domain
verification, ACME issuance and renewal, the HTTP-01 responder, and the
promotion of joining members. The others only run their etcd member and
their node's agent; their API port is closed.

- A new term starts with a fresh `server.Server`: in-memory state (agent
  sessions, rollout progress) never crosses terms.
- Nodes recorded as ready but not connected to the new leader are set to
  `unknown`, last seen at the start of the term. A node that died together
  with the old leader is then still found lost after `--node-lost-timeout`,
  and one that reconnects is ready again at once.
- A leader that is stopped resigns, so another takes over within about a
  second. A leader that crashes or is cut off loses its lease after 10 s,
  and another is elected then.
- A term that fails (for example the API address cannot be bound) stops
  the process instead of campaigning again, so a misconfigured node does
  not keep winning elections and failing.

### Fencing

A leader that lost its lease without noticing (a paused process, a
partition) must not overwrite what the new leader decides. The leader's
store is fenced: every commit carries an extra compare that the election
key still exists with the creation revision of this term. Once the term is
over, writes fail with `ErrNotLeader` (gRPC `Unavailable`) and change
nothing.

### Joining and removing servers

- `armada token create --server` creates a single-use **server token**
  (default 15 minutes, at most one hour). Node tokens and server tokens are
  not interchangeable.
- `armadad server join ADDR --ca-hash ...` on the new machine pins the CA
  like a node join and calls `JoinServer` on the join listener. The leader
  redeems the token, registers the server and its node, adds the new etcd
  member as a **learner**, and returns the CA certificate and key, the
  secrets master key, a server certificate for the new node's name and IP,
  its node certificate, the etcd initial cluster, and the API addresses.
  If adding the member fails, the registration is undone. Run as root, the
  join also writes the machine's admin config and the sudo user's, like
  `armadad init`, with a user certificate it signs with the CA it received.
- The new node writes these files and `etcd/initial-cluster`; the first
  `armadad server` start joins the etcd cluster with it and waits until the
  leader promotes the learner (once it has caught up), then removes the
  file. A learner does not count towards quorum, so a join that never
  completes cannot stop the cluster. A first start that fails half-way
  (no write-ahead log yet) starts over instead of founding a cluster of
  its own.
- `armada server remove NAME` removes the etcd member and the record. The
  leader refuses to remove itself; stop it first and remove it once
  another server leads. A removed server still holds the keys: wipe its
  data directory.
- `armada server list` shows each server's role (leader, standby) and
  status (voting, catching up, unreachable, not a member), and writes the
  addresses into the client config, leader first.

### Finding the leader

- Agents know every control plane address: `agent.json` holds the list,
  joins return it, and every assignment carries the current one, which the
  agent saves and applies to its live connection. The CLI's config holds a
  list as well, which the client keeps current: the leader sends the API
  addresses of its last reconcile pass in the `armada-servers` header of
  every AdminService answer, and the CLI writes a list with other addresses
  back to the config once per run. An agent run as root from the default
  data directory writes its list to `/etc/armada/servers` (root's, `0644`),
  and the CLI dials the addresses there that its config lacks after its own,
  so a config unused since servers were added still reaches the leader.
- Clients use one gRPC connection with a static resolver over all
  addresses and the `pick_first` policy: followers refuse connections, so
  the client ends up at the leader, and moves on when it goes away.
  Reconnect backoff is capped at 5 s so agents follow a failover quickly.

### etcd membership and certificates

- etcd listens on the server's private IP (client 2379, peer 2380) from
  the first server on, so a cluster can grow without restarting the first
  member. A member whose address changed updates its peer URL on start.
- Every member certificate carries one shared identity, `etcd:member`
  (`pki.EtcdMember`), and etcd accepts only that common name from the
  cluster CA. A new server therefore needs no change on the existing
  members. The Armada API never authorizes this identity.
- etcd checks that a peer connects from an address its certificate names.
  A machine with several addresses connects from whichever its routing
  picks, so the member certificate names every private address of the
  machine, and is re-issued when that set changes.

### Certificates in etcd

certmagic's storage (ACME account, certificates, keys, challenge tokens,
locks) moves from `<data-dir>/certs` into etcd under `/armada-acme/`
(`certs.EtcdStorage`), with locks as lease-backed etcd mutexes. A new
leader serves and renews the same certificates without issuing new ones,
and backups (etcd snapshots) contain them. Only the leader runs certmagic;
a node that loses leadership stops its certificate cache.

## Alternatives considered

- **Every server serving the API and forwarding:** agent streams and log
  relays live on one server, so followers would have to proxy them. A
  closed port on followers is simpler and has less attack surface.
- **Distributing keys by hand (copying `ca.key` and `master.key`):** error
  prone, and the most sensitive files would travel by whatever channel the
  operator picks. The join reuses the CA-pinned TLS channel and a
  short-lived single-use token instead.
- **Per-server etcd identities (`server:<name>`) with `AllowedCNs`:** the
  list is fixed when a member starts, so every join would require
  restarting every member.
- **Skipping etcd's client SAN check:** simpler for machines with several
  addresses, but drops a check; naming the machine's addresses keeps it.
- **etcd on loopback until a second server joins:** would require
  restarting the first member mid-join to move its peer URL.

## Consequences

- One server works as before. Two servers are worse than one for
  availability (losing either stops writes); the CLI and docs say so and
  recommend three.
- Control plane failover takes about a second when the leader is stopped
  and about 10–15 s when it crashes. Apps keep serving throughout: HAProxy
  and containers on every node keep running.
- Ports 2379 and 2380 must be open between control plane nodes on the
  private network, and nowhere else.
- A server token is as sensitive as the CA key while it is valid.
- Restoring a backup creates a single-member cluster; the other servers
  are removed (`armada server remove`) and join again.

# 0009. Embedded etcd as the state store

- Status: Accepted
- Date: 2026-10-31
- Amended by: [0010](0010-ha-control-plane.md) (member identity, listen address)

## Context

The control plane needs a state store that ships inside the Armada binary
(no external database to install) and does not need CGO. A single control
plane is a single point of failure: when its machine is gone, nothing can
be deployed, scaled, or rescheduled until it is restored from a backup. The
goal is a platform that can run with one server and survive the loss of a
server when three are available. That needs replicated state, and
replicated state is the hard part: it must stay consistent across a network
partition and never accept two different histories.

## Decision

The state lives in **etcd, embedded in `armada server`** (`go.etcd.io/etcd`
v3.7), behind the `store.Store` interface.

- etcd is a widely deployed Raft-replicated key-value store with a watch
  API, consistent snapshots, and membership changes, and a single member is
  fast enough for the control plane. Writing and maintaining our own Raft
  layer would be the riskiest code in the project.
- Embedded, not a separate service: installation stays one binary. The
  member lives in `<data-dir>/etcd/` (`0700`).
- One server runs a single-member cluster; three (or five) servers form an
  HA cluster that tolerates the loss of one (or two). One server is
  supported; three are recommended for production.
- Records are JSON values under `/armada/` with a `schema` key. The store
  refuses a keyspace written by a newer schema.
- Transactions are optimistic and serializable: a transaction reads one etcd
  revision, buffers its writes, and commits them in a single etcd `Txn` that
  succeeds only if a commit key is unchanged since the read; otherwise it
  runs again. All control plane writes are therefore serialized, which
  keeps every multi-record invariant (unique routes, single-use join
  tokens, revision and secret pruning) as simple as with one writer. The
  control plane writes a few times per second at most, so this costs
  nothing.
- Backups are etcd snapshots (`Maintenance.Snapshot`, with a SHA-256
  trailer) restored with `etcdutl`. A backup is verified by restoring it
  into a scratch member before it is written, and again before a restore
  replaces anything.

### Security

- Client and peer connections are TLS 1.3 with client certificates from the
  cluster CA (`ClientCertAuth`), and etcd additionally checks the
  certificate's common name against `AllowedCNs`: only the etcd member
  identity (`etcd:member`, see ADR 0010), which only control plane nodes
  hold, is accepted. Node, admin, and server certificates, although signed
  by the same CA, cannot talk to etcd.
- The member has its own certificate (`etcd/member.crt`, `0600`), issued
  from the CA and re-issued when it is missing, close to expiry, or does
  not match the machine's addresses.
- etcd listens on the server's private IP (ADR 0010), never on a public or
  wildcard address. The HTTP/JSON gateway and the separate metrics listener
  are disabled; the few HTTP endpoints left on the client port (health,
  metrics) need the same client certificate.
- Secret values reach etcd only encrypted (ADR 0006).

## Alternatives considered

- **An embedded local database or key-value store:** fast and simple, but
  local only; HA would mean writing replication ourselves.
- **An embedded database plus our own Raft log:** keeps a query language,
  but the state machine, snapshots, and membership handling become our
  code, with all their edge cases.
- **External etcd or a database server:** another service to install,
  secure, and back up; against the single-binary goal.

## Consequences

- etcd adds about 15 MB to the binary.
- The store is key-value: relational lookups are scans of small prefixes.
  At the expected scale (tens of nodes, hundreds of apps) this is
  negligible.
- The watch API is available for later work (e.g. pushing changes instead
  of polling).
- HA (joining further servers, agents that know every server, leader-only
  reconcilers) builds on this: see ADR 0010.

# 0012. Upgrades and state schema migrations

- Status: Accepted
- Date: 2026-11-01

## Context

A cluster is upgraded one machine at a time, so for a while servers and
agents of two versions run side by side. Apps must keep serving throughout,
and the control plane should stay available whenever more than one server
exists.

The cluster state in etcd (ADR 0009) has a schema version. When a release
changes records incompatibly, the state must be migrated, and two things
must never happen: a binary misreading records written in a layout it does
not know, or a server writing an old layout into state that was already
migrated. In a cluster with three servers, the second is a real risk: if an
upgraded leader migrated the state and then failed, a server still running
the old version could win the next election and write old records.

## Decision

### Who may lead

- Every server records, in its `servers/` entry at start, the newest
  schema its binary understands and its Armada version.
- A server whose binary knows a **newer** schema than the state does not
  campaign for leadership until **every** recorded server knows that
  schema. During a rolling upgrade the servers still on the old version
  keep leading; upgraded servers stand by and log which servers they wait
  for. A removed or dead server that is still recorded blocks the
  migration until it is upgraded or removed (`armada server remove`).
- When it wins an election, the server checks again on the store fenced
  to its term; if a server with an old binary appeared meanwhile it ends
  the term and stands by.
- A binary that finds state written by a **newer** schema refuses to start
  (and refuses to lead, should the state change while it runs).
  Downgrades are not supported; the way back is the backup taken before
  the upgrade.

### Migrations

- Migrations are ordered steps, each moving the state from schema N to
  N+1 inside one transaction that also writes the new schema number, on
  the store fenced to the leader's term. A step either commits completely
  or not at all; a leader that loses its term mid-way cannot commit
  further steps, and the next leader continues from the recorded schema.
- They run when a server that may lead wins its first term, before it
  serves the API or runs reconcilers.
- Records under `servers/` and `meta/` are written by every server at
  start, whatever its version, so their layout only ever gains optional
  fields and never needs a migration.

### Agents

- Agents report their version when they connect; `armada node list` and
  `armada server list` show the version of every node and server, and
  `armada server list` explains a pending migration.
- The agent protocol only gains fields. An agent older than the server
  ignores fields it does not know; a feature that would be unsafe on an
  agent that ignores it must be gated on capabilities the agent declares,
  and the scheduler must not place such replicas on agents without them.

## Alternatives considered

- **Migrate as soon as the first upgraded server leads:** the old servers
  could then lead again and write old records into migrated state.
- **Refuse to start a server with an old binary once the state is
  migrated, but migrate immediately:** safe for the state, but servers
  still on the old version crash-loop and their etcd members drop out,
  which can cost quorum in the middle of an upgrade.
- **Make every release read and write the previous schema:** every format
  change has to be implemented twice and tested in mixed clusters.

## Consequences

- Upgrades need no flag day: upgrade servers one at a time, then nodes.
- While a migration is pending, the control plane relies on the servers
  that are not yet upgraded; if all of them fail before the upgrade is
  finished, deploys wait until the remaining servers are upgraded. Apps
  keep serving either way.
- A single server migrates right after its own upgrade.

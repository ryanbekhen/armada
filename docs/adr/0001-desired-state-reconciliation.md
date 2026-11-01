# 0001. Desired state + reconciliation model

- Status: Accepted
- Date: 2026-10-30

## Context

Armada must stay correct when the server, an agent, or the container runtime restarts mid-operation, and v0.2 adds self-healing (moving replicas when a node dies). Imperative commands ("run container X now") leave half-finished state behind when a process dies partway through.

## Decision

- The CLI only writes **desired state** to the server, in a single transaction.
- The server-side reconciler computes per-node assignments; the agent-side reconciler brings local containers in line with the assignment.
- Every resource is identified by deterministic labels (`armada.app`, `armada.revision`, `armada.replica`), so the reconciler can adopt containers that already exist.
- Deploy, scale, rollback, and crash recovery all go through the same path.

## Alternatives considered

- **Imperative commands + an operation log:** simpler at first, but every failure mode needs its own recovery code.
- **Full event sourcing:** too heavy for v0.1.

## Consequences

- Operations are eventually consistent; the CLI needs to wait and show progress (`status --watch`).
- Reconcilers must be idempotent and tested with fake drivers.
- Self-healing in v0.2 comes almost for free: a dead node means its assignments get moved.

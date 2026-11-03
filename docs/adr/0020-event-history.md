# 0020. Event history

- Status: Accepted
- Date: 2026-11-03

## Context

`armada status` shows the cluster as it is now. When something went wrong
an hour ago (a replica crashed and restarted, a node was lost and its
replicas moved, a rollout failed), the state no longer shows it, and the
server logs are spread over every control plane server and mixed with
routine messages. The audit log records who changed desired state, not
what the system did about it.

Operators need a short, searchable history of what the cluster did, read
with the same credentials as the rest of the CLI.

## Decision

The leader records events and `armada events` shows them.

### What is recorded

Changes of state, never routine checks:

| Kind | Reasons |
| --- | --- |
| `replica` | `Scheduled`, `Started`, `Ready`, `NotReady`, `Restarted`, `Crashed`, `Failed`, `Evacuating`, `Rebalancing`, `Removed` |
| `rollout` | `Started`, `Completed`, `Failed`, `RolledBack` |
| `node` | `Joined`, `Connected`, `Disconnected`, `Lost`, `MostUnreachable`, `Cordoned`, `Uncordoned`, `Removed` |
| `app` | `Unschedulable`, `ScaledUp`, `ScaledDown` (ADR 0022) |
| `job` | `Deployed`, `Started`, `Succeeded`, `Failed`, `Retrying`, `Cancelled`, `Skipped`, `Missed`, `Unschedulable`, `Deleted` (ADR 0021) |
| `domain` | `Verified`, `NotVerified` |
| `certificate` | `Obtained`, `Failed` |

- Events come from transitions the leader already sees: its reconcilers,
  the agents' replica reports, and the API calls it serves. The agent
  protocol does not change.
- Conditions that last (a lost node, an app that cannot be placed, a domain
  that is not verified) are recorded when they start, not on every
  reconcile.
- An event that repeats for the same object and reason within 10 minutes
  updates the stored event (its count and last time) instead of adding one,
  so a crash loop is one line.

### Storage

- Events live in etcd under `events/`, ordered by their last occurrence,
  with an etcd lease: they expire after 24 hours (one lease per hour, so
  between 24 and 25 hours). At most 2000 are kept; the oldest go first.
- Writes bypass the state transaction, since events take no part in its
  invariants, but are fenced on the leader's term like every other write.
- Recording never holds up the work it describes: a failed write is logged
  and the reconcile goes on.
- Events are separate from the audit log, which keeps recording changes to
  desired state and who made them.
- Older binaries ignore the prefix, so it needs no schema step.

### Reading

- `AdminService.Events` streams the events of the last hour (at most 24),
  filtered by app or node, oldest first. With `follow`, new events follow
  until the caller cancels. A follower that falls behind by 256 events is
  disconnected with an error rather than slowing the leader.
- Only admin certificates may call it.
- `armada events [APP] [--node NODE] [--since DURATION] [-f] [-o json]`.
- The metrics endpoint (ADR 0019) counts events in
  `armada_events_total{kind,reason}`.

### Untrusted text

Messages may carry text from agents (exit codes, probe errors). The leader
cuts them to 512 bytes and replaces control characters before storing them,
and the CLI replaces control characters again before printing. Events never
carry environment values, secrets, or exec arguments: replica messages are
the same ones `armada status` already shows.

## Alternatives considered

- **Events in the server logs only**: no new storage, but each server's log
  holds only its own terms, and reading it needs a shell on the machine.
- **Events in the audit log**: one history, but audit events are kept for
  long and recorded in the state transaction; system events are frequent
  and only useful for a day.
- **Agents send events**: more detail from the node, but a new protocol
  message, and a node could fill the store; the leader already sees every
  transition that matters.
- **Memory only on the leader**: simpler, but the history would vanish on
  every leader change, exactly when it is most useful.

## Consequences

- History reaches back one day. Longer retention belongs in a log or metrics
  system: scrape `armada_events_total`, or run `armada events -f -o json`
  into one.
- A leader change starts a new deduplication window, so a repeating event
  may appear once more.
- Events written by a leader just before it lost its term may be missing;
  events are a record, not a source of truth.

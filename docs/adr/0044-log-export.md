# 0044. Sending logs elsewhere

- Status: Accepted
- Date: 2026-11-13

## Context

Log history (ADR 0043) keeps a bounded past on each node and searches it
by reading files. It has no index, keeps days rather than months, and
lives on the machines it describes, so a lost node takes its history with
it. Teams that already run a log store want every app's output there, with
labels to filter by, without adding a collector to each app or running one
on every machine themselves.

Containers cannot ship their own output: they mount no host paths, and an
app's own shipper would see only itself.

## Decision

Each node's agent sends the output of the app containers on it to one
endpoint the cluster names, as well as keeping it on disk.

### Setting it

- `armada cluster set --log-export loki|otlp --log-endpoint URL
  [--log-export-user U] [--log-export-tenant T] [--log-token FILE|-]`;
  `--log-export none` stops it and removes the token. Cluster-admin only,
  like every cluster setting, audited without the token, and applied
  without a restart.
- `loki` posts to a Loki push URL (`/loki/api/v1/push`); `otlp` posts
  OTLP/HTTP JSON to a logs URL (`/v1/logs`). Both are JSON, gzipped; no
  client library is added.
- The URL is `https://`, or `http://` only to a private or loopback IP
  address. It may not hold credentials or a query, so it can be shown and
  audited. A token is sent as a bearer token, or, with a user, as the
  password of basic authentication. `--log-export-tenant` sets Loki's
  `X-Scope-OrgID`. Redirects are not followed.
- The token is read from a file or stdin, sealed with the master key like
  the DNS token (ADR 0031), and opened only to build assignments:
  `Assignment.logs.export` carries it to the agents over their mTLS
  stream.

### On the node

- The runtime (`runtime.LogTailer`, embedded: `embedded.TailLogs`) reads
  what app containers wrote since the last round, from the same files the
  history keeps, and remembers per container where it stopped (inode and
  offset, and the time of the last entry) in
  `<logs>/history/export.json` (0600). Following a file by inode keeps
  rotation and removal into history from losing or repeating output.
- A new destination (any `--log-export*` change, even to the same values,
  and a new export after `none`; not a new token) starts at the end of the
  output of containers that already exist; containers
  created after it start at their beginning. Output written before a
  destination was set is not sent.
- Every 2 seconds the agent sends what is new, at most 8 MiB per round,
  in requests of at most 2000 lines or 1 MiB, then records it as sent. A
  failed request is retried with backoff up to a minute, from the same
  place: delivery is at least once, so a retry may repeat lines. When the
  endpoint stays down longer than the node keeps history, the oldest
  output is lost; the agent goes on from the time it last sent.
- Labels: Loki streams carry `app`, `space`, `container`, `stream`
  (stdout/stderr), `node`, and `source="armada"`, with `replica` and
  `revision` as structured metadata, so streams do not grow with every
  replica (Loki 3 or later). OTLP gives each replica container a resource
  with `service.name` (app), `service.namespace` (space),
  `service.instance.id` (replica), `service.version` (revision),
  `host.name` (node), `container.name`, and the same names under
  `armada.*`; each line has `log.iostream`. No severity is guessed.
- System containers (HAProxy) have no meta file and are not sent.
- Usage reports carry `LogExportStatus`; the leader records a
  `LogExportFailing` condition event per node with the reason (never the
  token), cleared once sending works again.

## Consequences

- Every app's output can reach a store with an index and long retention,
  with no agent or sidecar per app, and history on the node still works
  when the store is down.
- Logs leave the cluster. They can hold anything an app prints, so the
  endpoint is a cluster-admin decision, the URL must use TLS unless it is
  a private address, and the token is stored encrypted. Every node needs
  to reach the endpoint.
- Output over the log rate limit (ADR 0011) is dropped before it is
  stored, and so never sent.
- One endpoint for the whole cluster; per-space destinations are not part
  of this decision.

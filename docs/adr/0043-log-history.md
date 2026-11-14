# 0043. Log history

- Status: Accepted
- Date: 2026-11-13

## Context

Each container's output is stored on its node as JSON lines, rotated at
`runtime.LogMaxSize` × `LogMaxFiles` (ADR 0011). `armada app logs` reads the
containers that still exist. A container recreated by a deploy, a crash, a
probe, or a move takes its output with it, and a busy container keeps only
its last 30 MB. Finding what an app printed when something went wrong an
hour ago, across its replicas, is often impossible.

Containers cannot collect the logs themselves: they mount no host paths.

## Decision

Nodes keep a bounded history of every app container's output, and `armada
app logs` searches it across the cluster. No database is added.

### On the node

- The runtime keeps `<runtime data dir>/logs/history/` (root, 0700). When a
  container is created, the driver writes `<id>.meta` there (app ID,
  replica, revision, container name, and when it was created; 0600). System
  containers get none.
- When a live log file is rotated out, `armadad runtime-log` moves it into
  history as `<id>.<unix nanoseconds>.log` instead of deleting it. When a
  container with a meta file is removed, its live files move there too.
- The agent prunes history every minute (`runtime.LogPruner`): files older
  than the retention go first, then the oldest files until history fits its
  size; a meta file goes once no log file of its container is left and the
  container is gone. Retention defaults to 7 days; the size to 10% of the
  log directory's file system, at most 5 GiB. `armada cluster set
  --log-retention D --log-max-disk SIZE` sets both for every node (ADR
  0031), sent to agents in `Assignment.logs`.

### Searching

- `armada app logs APP --since D [--until D] [--grep TEXT] [--replica R]
  [--container C] [--limit N] [--timestamps]` (and `armada job logs`) asks
  every connected node that announced `Hello.log_history` for the app's
  entries in the window (`LogRequest.query`). `--grep` matches plain text,
  ignoring case; it is never a regular expression.
- Each node reads its history and live files of the app's containers
  (`runtime.LogSearcher`), keeps the newest `limit` matching entries, and
  sends them oldest first with their time and replica. A node reads at
  most `maxSearchBytes` (1 GiB) per search, and stops after 30 seconds;
  either way it says so in a final notice. It runs at most 2 searches at
  once and answers more with a notice.
- The leader merges the answers by time and sends the newest `limit`
  (default 500, at most 5000). With `--follow`, it then streams live
  output as before. It runs at most 4 searches at once, 2 per caller
  (more are refused with `ResourceExhausted`), keeps at most 32 MiB of
  one node's answer, and keeps only entries of the queried app's replicas
  (the asked one, if any) inside the window, not more than a minute
  ahead, so a node cannot answer for apps it never ran.
- Access is the same as for logs today: a viewer of the app's space.
  The app must exist; history of a deleted app expires with retention.

### Not in this step

Sending logs elsewhere (OTLP, Loki) is a separate decision: ADR 0044.

## Consequences

- An app's recent past is searchable after its containers are gone,
  without anything to run besides Armada.
- History costs disk, bounded per node, and old output goes first. A
  container over the log rate limit (1 MiB/s) still loses output.
- Logs can hold sensitive data. History has the same permissions as live
  logs and is never sent anywhere but to an authorised `armada` client.
- A search reads files on every node, so it is bounded by bytes and time
  rather than indexed. Searching days of a very chatty app is slow; that is
  what sending logs elsewhere is for.

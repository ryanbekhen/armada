# 0019. Metrics endpoint

- Status: Accepted
- Date: 2026-11-03

## Context

`armada status` and `armada top` (ADR 0018) answer questions at the moment
they are asked. Operators also need history and alerts: how memory grew
over a week, whether an app had fewer ready replicas than desired during
the night, how long reconciles take. Prometheus is the common format for
that, and a scraper is something operators already run.

An endpoint that exposes the cluster's state is a new listener. Armada's
listeners bind only to private addresses, and everything except joining
requires a client certificate from the cluster CA (ADR 0003). A metrics
endpoint names every app, replica, node, and revision, so it should not be
open to anything that can reach the private network.

## Decision

The leader serves Prometheus metrics at `GET /metrics` on
`armada server --metrics-listen IP:PORT`. The endpoint is off by default.

### Access

- The listener binds only to a private address, like every other listener,
  and uses TLS 1.3 with the API's server certificate
  (`armada-server` name).
- It requires a client certificate from the cluster CA and serves it only
  to two identities: `metrics:<name>` and `admin:<name>`. Node and server
  certificates get `403`, and handshakes without a certificate fail.
- `metrics:<name>` is a new identity kind that may only scrape. The API
  refuses it for every RPC, and etcd refuses it as it refuses every identity
  but its members.
- `armada metrics credentials NAME` creates the key on the admin's machine
  and sends only a certificate request through
  `AdminService.IssueMetricsCertificate`. It writes `ca.pem`, `cert.pem`,
  and `key.pem` (`0600`) to a new directory (`0700`).
  - The CA decides the identity from the requested name, whatever the
    request says.
  - Issuing is recorded in the audit log.
  - The certificate lasts a year, like admin certificates.

### Where it runs

- Only the leader serves it, with the same lifetime as the API: the
  listener opens when a server starts leading and closes when it stops.
  The data is the leader's (the store, the agents' sessions, the usage
  samples).
- Operators scrape every server. Only the leader answers; the others refuse
  the connection, and Prometheus' `up` shows which one leads.

### Metrics

Metrics are read from the same sources as `armada status` and `armada top`
on every scrape. No new state is kept.

- **Control plane:**
  - `armada_server_leader{server}`
  - `armada_agents_connected`
  - `armada_reconcile_duration_seconds` (histogram)
  - `armada_reconcile_errors_total`
  - Go runtime metrics
- **Apps:**
  - `armada_app_replicas_desired{app}` and `armada_app_replicas_ready{app}`
  - `armada_app_rollout{app,state}`, which is 1 for the current state
    (`idle`, `progressing`, or `failed`)
- **Replicas:**
  - `armada_replica_ready{app,replica,revision,node}`
  - `armada_replica_cpu_usage_cores` and
    `armada_replica_memory_usage_bytes`, both from the latest sample
  - `armada_replica_cpu_reserved_cores` and
    `armada_replica_memory_limit_bytes`
  - `armada_replica_cpu_limit_cores`, for apps that set a CPU limit
- **Nodes:**
  - `armada_node_ready{node}` and `armada_node_cordoned{node}`
  - `armada_node_replicas`
  - `armada_node_cpu_allocatable_cores` and
    `armada_node_memory_allocatable_bytes`
  - `armada_node_cpu_reserved_cores` and `armada_node_memory_reserved_bytes`
  - `armada_node_cpu_usage_cores` and `armada_node_memory_usage_bytes`

Label values are only names the store has already validated: apps, replicas,
revisions, nodes, servers. They never include image references, domains,
environment values, or anything else a spec or an agent could make up.

## Alternatives considered

- **Plain HTTP on the private address**: simpler to scrape, but anyone on
  the private network would see every app and node name. Every other Armada
  listener that serves cluster data needs a client certificate.
- **Admin certificates only**: no new identity, but the scraper would then
  hold a credential that can deploy, read secrets' names, and run commands
  in replicas.
- **Metrics on every server**: would need standby servers to read the store
  and would duplicate every series; the usage samples live only on the
  leader anyway.
- **Metrics on agents**: each node would open a listener; the leader
  already has everything the endpoint shows.

## Consequences

- Prometheus needs the client certificate and the cluster CA in its TLS
  configuration, with `server_name: armada-server`.
- A metrics certificate can only be revoked by replacing the cluster CA,
  like an admin certificate. Its holder sees names and resource numbers,
  nothing more.
- There is a short gap in the series when the leader changes.
- Series grow with replicas. Each replica has about seven series, which is
  small at the sizes Armada targets.

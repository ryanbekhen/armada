# 0031. Cluster settings

- Status: Accepted
- Date: 2026-11-10

## Context

Several `armadad server` flags only make sense when every server has the
same value, because any server can become the leader: whether and how to
obtain certificates (`--tls`, `--acme-ca`, `--acme-email`), the DNS provider
and its token for the root domain, the metrics endpoint, and the node-lost
timeout. They lived in `/etc/armada/server.env` on each server. Nothing
kept the copies alike: a server with another value behaved differently once
it led (for example HTTP-01 instead of a wildcard certificate after a
failover), and a change meant editing every server and restarting each one.

## Decision

These settings are part of the cluster's state, set with `armada cluster
set` and shown by `armada cluster show`, like the root domain and the
trusted proxies already were:

- `--tls`, `--acme-ca`, `--acme-email`, `--dns-provider cloudflare|none`,
  `--dns-token FILE|-`, `--metrics-port`, and `--node-lost-timeout`.
- One record (`settings` in the meta keys). The DNS token is sealed with the
  master key like an app secret, bound to its own scope and a version; it is
  read from a file or stdin, never an argument, and never returned, logged,
  or audited.
- Only administrators may change them, and each change is audited.

**Applying a change.** The leader stores it, answers, and then restarts its
term in the same process: the gRPC listener, the certificate manager, the
metrics endpoint, and the reconcilers start again with the new settings,
keeping the leadership. Apps keep serving; the API and the agents reconnect
within a second or two. Other servers read the settings when they lead.
The root domain and trusted proxies keep applying without a restart.

**Precedence.** The cluster's value wins over a server's flag, and a flag
over the default. The metrics setting is a port: each server listens on its
own private address, unless its `--metrics-listen` names another one.
Flags that belong to one machine (`--acme-listen`, `--join-listen`,
`--proxy`, and the like) stay flags.

**Moving existing clusters.** When a leader starts and the cluster has no
value for a setting, it takes the one its own flags give (reading the token
from `--dns-token-file` and sealing it), stores it, and audits that it did.
From then on the flags no longer decide: a server whose flags disagree logs
it, and `armadad doctor` warns about cluster flags left in `server.env`.

## Consequences

- A setting is changed once, from any machine with admin credentials, and
  holds after every failover.
- New servers need no copied `server.env` or token file.
- The DNS token moves from a root-only file on each server into the state,
  encrypted with the master key that already protects every secret; it is
  in backups with the rest of the state.
- Changing a setting briefly restarts the leader's control plane, so it is
  meant for occasional changes, not automation in a loop.

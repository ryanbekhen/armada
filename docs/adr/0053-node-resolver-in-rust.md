# 0053. The node's resolver runs as armada-dns

- Status: Accepted
- Date: 2026-11-23

## Context

Every node runs a resolver for its containers (ADR 0007, ADR 0026): it
answers `<app>.internal` with the internal ingress address, only for the
asking container's own space, and forwards every other name to the host's
resolvers. Every lookup a container makes passes through it. It ran inside
`armadad`, so:

- It stopped while `armadad` restarted (an upgrade, a configuration change,
  a crash): lookups from running containers went unanswered for the seconds
  the next process took to start, and containers that resolve on every
  request saw errors though nothing about their apps changed.
- It shared the process with etcd, the reconcilers, and the agent: their
  garbage collection and scheduling showed in its latency.

Measured on one machine with the resolver held to two CPUs, 64 clients:

| Lookup | Inside `armadad` (Go) | armada-dns (Rust) |
| --- | --- | --- |
| `<app>.internal` | 94,000 per second, 0.68 ms | 221,000 per second, 0.29 ms |
| forwarded | 47,000 per second, 1.35 ms | 78,000 per second, 0.82 ms |

Request traffic itself never passes through Go: HAProxy and the kernel
carry it. The resolver is the one part of `armadad` on the path of a
container's work, which is what makes it worth its own program.

## Decision

The resolver is `armada-dns` (`dns/`), written in Rust with the standard
library only, like `armada-log` and `armada-shim` (ADR 0046), and shipped
in the runtime pack.

1. **A unit of its own.** The agent runs it with `systemd-run` as a
   transient service `armada-dns-<hash>` (`Restart=always`), outside
   `armadad`'s cgroup, so it keeps answering while `armadad` restarts. The
   hash covers the program and its settings (listen address, client range,
   upstreams); an agent that finds its unit running uses it.
2. **The agent tells it what it knows.** Over a root-only Unix socket
   under `/run/armada/dns/`, one request line per connection: `names` (the
   apps that resolve), `clients` (the node's container addresses and their
   apps), `epoch` (which process answers), `state`, and `drain`. The agent
   remembers what it sent and sends it all again to a process with another
   epoch (one that restarted); it checks every 5 seconds. The process also
   saves what it knows beside its socket (`<hash>.state`, `0600`, in
   `/run`), so the unit systemd starts again after a crash (100 ms later)
   answers at once.
3. **Same behaviour as before.** The rules of the Go resolver carry over
   and are tested against both programs (`internal/dnsserver`, run on
   `armada-dns` with `ARMADA_DNS_BIN`): answers only the bridge subnet,
   silent to everyone else; names only within the caller's space; a lookup
   from an address the agent has not named waits up to 3 seconds, and
   before the first names up to 10; at most 128 forwards at once and 16 per
   client, the client's share checked first; at most 16 TCP connections per
   client (and 1024 in all); no cache; a 2-second timeout per upstream, and
   the next upstream at once when one refuses.
4. **Lookups are forwarded from an event loop.** A thread per CPU (at most
   4) reads the shared socket through epoll and forwards each lookup on a
   socket of its own, so every upstream query has a fresh source port.
5. **Upgrades hand over without a lost lookup.** A new program or new
   settings make a new unit. It reads the old process's names and clients
   (`--take-over`) before it binds the port, both listen on it
   (`SO_REUSEPORT`), the old one is told to `drain` (its UDP socket stops
   taking new datagrams and it answers what it holds), and only then is it
   stopped.
6. **Fallback.** A pack without `armada-dns` (builds without the runtime
   bundle) or a unit that does not start leaves the resolver inside
   `armadad`, as before. `armadad runtime reset` stops the units.

## Consequences

- An `armadad` restart no longer interrupts name resolution in containers.
- One more program in the runtime pack, under the same rules as the other
  two: standard library only, checked by `TestLoggerStandardLibraryOnly`,
  listed in `THIRD_PARTY_NOTICES.md`, built for both architectures by
  `make dns`, linted and tested in CI.
- The resolver keeps its last names and clients while `armadad` is down.
  Containers removed meanwhile keep resolving until the agent is back; the
  firewall and the internal frontend, which check every connection, are
  unchanged by this.
- Measured in a two-node lab with two containers resolving three names
  every 50 ms: four `armadad` restarts (the leader's included) and an
  upgrade to another `armada-dns` on each node lost no lookup; a crash of
  `armada-dns` (`kill -9`) lost the lookups of its 100 ms restart.
- A machine reboot ends the unit like every other; the agent starts it
  again before its first configuration, and lookups wait for it as before.

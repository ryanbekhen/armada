# 0007. Internal ingress and DNS on the container bridge

- Status: Accepted
- Date: 2026-10-31

## Context

Apps with `ingress: internal` must be reachable by other apps in the cluster as `http://<app>.internal`, from any node, but never from the internet. Replicas run on the node's container bridge and publish their port on the node's private IP. Every node already runs HAProxy (host network), which load balances and health checks every app's replicas across all nodes (preferring its own node's replicas since ADR 0026).

The obvious design binds an internal HAProxy frontend to the node's private IP on port 80. That address is not a reliable boundary. On providers with 1:1 NAT (the public address is not on the interface), internet traffic to port 80 arrives with the private IP as its destination. A provider load balancer on the private network forwards public traffic from private source addresses. Either way, public traffic could reach the internal frontend.

## Decision

- **Internal frontend on the bridge gateway.** Each node's HAProxy gets a `frontend internal` bound to `<bridge gateway>:80` (the first address of the node's container subnet, which differs per node with the cluster network of ADR 0027), next to the public `bind :80`. Linux delivers connections to the most specific bound address, so traffic to the gateway reaches the internal frontend and everything else reaches the public one (verified in the lab). The gateway exists only on the node: other machines, NAT, and load balancers cannot route to it. Containers on other nodes do not reach it: the firewall between apps (ADR 0029) drops traffic from a container to another node's gateway, and each container's own node serves the same internal routes; the DNS server answers only its own bridge subnet.
- **Routing.** Every app with an ingress port (external or internal) gets internal rules for `<app>.internal`, with its routes and strip-prefix settings, sent as `ProxyRule.internal = true`. Internal rules appear only in the internal frontend, and public rules only in the public frontends. Internal apps get no `<app>.<root>` name, no custom domains (rejected in the spec), and no certificates. The `.internal` zone is reserved: user domains under it are rejected, and the agent revalidates that internal hosts are exactly `<app>.internal`.
- **Node-local DNS in the agent.** The agent runs a resolver (`miekg/dns`, UDP and TCP) on `<bridge gateway>:53`. It answers only clients in the bridge subnet, and sends no reply to anyone else, so it cannot be used as an open resolver or reflector. `<app>.internal` resolves to the gateway for exactly the apps the local HAProxy routes, with a 5-second TTL. Other names in `.internal` get NXDOMAIN. On a cluster with the cluster network, a container resolves only the names of its own project (ADR 0029): the agent knows each of its containers' apps by address, and answers no internal name to an address it does not know. Every other query is forwarded to the host's resolvers from `/etc/resolv.conf`, which includes `127.0.0.53`: the agent runs on the host and can reach it, which Docker's default DNS cannot.
- **Containers use it.** New containers are started with `--dns <gateway>`. The setting is not part of the replica spec hash, so enabling it does not restart running replicas; they pick it up on their next replacement (any deploy).
- **Optional and fail-safe.** If the runtime cannot report the bridge, the host has no resolvers, or port 53 on the gateway is taken, the agent logs why and runs without internal ingress and DNS (containers keep the host's upstream resolvers). `--internal-dns=false` turns it off, and so does `--proxy none`.

## Alternatives considered

- **Internal frontend on the private IP** (the original plan): reachable from the internet behind NAT or a load balancer, as described above.
- **Filtering on source address** (only private sources may use internal names): defeated by load balancers and proxies on the private network.
- **DNS answers pointing at replicas directly:** no health checks, no load balancing, stale answers during rollouts, and every replica port would have to be reachable from every node's containers.
- **Per-node DNS in the container runtime:** only works within one node; names across nodes would need an overlay network, which is out of scope.

## Consequences

- An internal app is "not public", not "only for specific apps": every container on every node can call it (threat model T13). With the cluster network (ADR 0027, ADR 0029), the internal frontend admits only callers of the app's project, and only the apps listed in `ingress.allow` when it is set; the node itself no longer gets an answer.
- Host firewalls must accept traffic from the bridge (`armada0`) to the host on TCP 80 and UDP/TCP 53. A default-deny INPUT policy (for example ufw) blocks internal names; `armada doctor` warns about an active ufw.
- While the agent restarts (a few seconds), containers on that node cannot resolve names. Containers deliberately get no fallback nameserver, because resolvers that query servers in parallel (musl) could take an upstream NXDOMAIN for an internal name.
- Traffic from a container to its node's HAProxy and on to replicas is plain HTTP over the bridge and the private network, the same as the existing hop from HAProxy to replicas.

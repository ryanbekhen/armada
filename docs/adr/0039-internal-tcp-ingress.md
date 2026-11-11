# 0039. Internal TCP ingress

- Status: Accepted
- Date: 2026-11-11

## Context

Internal ingress (ADR 0007) serves HTTP: other apps call
`http://<app>.internal`, and the internal frontend picks the app by its
`Host` header. Apps that speak something else, such as a database, a message
broker, a cache, gRPC without HTTP routing, or SMTP, can only be reached
today by their replicas' container addresses. Those change with every
replica, are not balanced or health checked, and, with network isolation
(ADR 0026), are closed to every other app anyway.

Such services are for the apps of a cluster, not for the internet. Opening
TCP ports to the outside would also break a rule Armada keeps: only the
proxy on ports 80 and 443 faces the public.

## Decision

An app can take plain TCP connections from other apps of its project:

```yaml
ingress:
  type: internal
  protocol: tcp        # default http
  port: 5432           # where the app listens, and where callers connect
  allow: [api]         # optional, as for HTTP
```

Callers connect to `<app>.internal:<port>` (`<app>.<project>.internal` in a
project other than `default`).

- **Internal only.** `protocol: tcp` needs `type: internal`; with
  `external` the spec is refused ("tcp is internal only"). Nothing listens
  for TCP apps anywhere but the bridge gateway.
- **One listener per port, shared by projects.** TCP carries no host name,
  so the proxy cannot tell apps apart by name the way the internal HTTP
  frontend does. Each port gets one `mode tcp` frontend, `tcp_<port>`,
  bound to `<bridge gateway>:<port>` on every node. The caller's project,
  from its address in the clients map (ADR 0026), picks the backend: within a
  project a port belongs to one app, and another project can use the same
  port for its own app. The store refuses a second app of a project on a
  port in the deploy (or rollback) transaction, over the live specs of the
  project, as it does for routes on custom domains; during a rollout both
  the active and the target port count. Giving each app an address of its
  own was the other option: it would cost an address per app on every node
  out of a /24 that also holds the replicas, and DNS answers per app, for no
  gain over picking by project.
- **Callers.** The frontend sets the caller's project and app from
  `src,map_ip(clients.map)` at `tcp-request connection`, picks the
  backend of that project (and, with `allow`, only for the listed apps and
  the app itself), and rejects the connection before reading anything when
  none matches: an address the node does not know (the node itself
  included), another project, or an app that is not allowed. So TCP ingress
  needs the cluster network (ADR 0025), where nodes know their callers; a
  deploy in a cluster without one is refused, and a node without a subnet
  renders no TCP listener.
- **Backends.** A TCP app's backend is the same slotted backend as an HTTP
  app's (`be_<app>`, the same layout, Runtime API address and weight
  changes, local-first weights and the local map, ADR 0024), in `mode tcp`,
  with `balance leastconn` (connections last), TCP health checks, and no
  HTTP settings. TCP frontends and backends follow their own `defaults tcp`
  section: `timeout client` and `timeout server` of 1 hour, as long as a
  reload lets an old process keep its connections (`hard-stop-after 1h`).
  A connection silent for longer is closed; clients that keep pools open
  should use TCP keepalives or reconnect. A new TCP app, a port change, or a
  change of `allow` reloads the proxy; replicas coming and going do not.
- **What does not apply.** Routes, domains, sticky sessions, CORS, client
  address rules, `ingress.timeout`, scaling to zero (no request to wake
  on), `http` autoscaling rules, and `revisions.mode: multiple` (labels are
  host names) are refused for TCP apps. CPU and memory rules work.
- **Ports.** 1 to 65535, except the ports Armada uses on a node, so a
  caller never mistakes one for the other: 22, 53, 80, 443, 2379, 2380,
  4789, 7443, 7444, 7480, 8404, 51820 (`spec.ReservedTCPPorts`).
- **A port another program has.** HAProxy runs on the host network. If
  another program on the node listens on a TCP app's port on every address
  (or on the gateway itself), binding it would fail, and with it the whole
  reload. Before rendering, the agent reads the node's listening sockets
  (`/proc/net/tcp`, `tcp6`) and leaves such ports out, logging which; the
  ports the running proxy holds (from its configuration file) are its own.
  The app is then not reachable from that node until the port is free.
- **Firewall.** For isolated containers the gateway accepted only DNS and
  TCP 80/443 (ADR 0026). The leader now sends the ports of TCP apps in
  `NetworkConfig.tcp_ports` (taken from the proxy configuration of the same
  pass); the agent checks them like the proxy does and keeps them in an
  nftables set, changed in place. The input rule accepts TCP to the gateway
  on those ports only while the socket that takes the packet is bound to a
  specific address (`socket wildcard 0`), which is the proxy's listener: a
  program on the node that listens on every address is never reached
  through a TCP app's port. The rule exists only while there are TCP ports,
  so nodes without TCP apps need nothing new from the kernel.
- **DNS.** `<app>.internal` resolves to the gateway for TCP apps like for
  HTTP apps, within the asker's project only.
- **Command line.** `armada app create|update --protocol tcp|http`;
  `armada app show` lists `tcp://<app>.internal:<port>` as the app's URL.

## Consequences

- Databases, brokers, and other TCP services get a stable name, balancing
  over ready replicas, health checks, and failover across nodes, with the
  same project boundary and `allow` as HTTP apps.
- Nothing new faces the internet: the listeners are on the bridge gateway,
  which only the node's containers reach, and the firewall opens only the
  ports of TCP apps there.
- A port is a cluster-wide resource only within a project; two projects can
  run their own app on 5432.
- The proxy sees TCP, not requests: no per-request logging, retries, or
  limits. Connections through a node's proxy to a replica on another node
  cross the cluster network like HTTP traffic does.
- TCP ingress needs a kernel with `nft_socket` and its wildcard key
  (Linux 5.6 or later), and the cluster network.

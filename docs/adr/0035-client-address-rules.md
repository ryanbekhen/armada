# 0035. Client address rules

- Status: Accepted
- Date: 2026-11-11

## Context

Some apps should only be reachable from known places: an admin console from
the office, a webhook endpoint from a payment provider's ranges, a staging
site from the team's VPN. Others need to keep a few abusive networks out.
`ingress.allow` (ADR 0026) chooses which apps may call an app inside the
cluster, but nothing limited who reaches an app from outside.

A rule on a client's address is only as good as the address. Requests often
arrive through a proxy or CDN in front of the nodes, so the connection's
address is the proxy's, and the client's is in a header. A header is
whatever the sender writes. A rule that believes it can be passed by any
client typing an allowed address into `X-Forwarded-For`.

## Decision

`ingress.ipAllow` or `ingress.ipDeny`, at most one, on apps with
`ingress.type: external`:

```yaml
ingress:
  type: external
  port: 8080
  ipAllow:
    - range: 203.0.113.0/24
      name: office
      description: the VPN the admins use
    - 2001:db8::/32
    - 198.51.100.7
```

- **Names.** A rule may carry a `name` (unique, up to 64 characters) and a
  `description` (up to 256), printable text, so whoever reads the spec, or
  `armada app show`, knows what each range is for. A bare range is the
  short form.
  - Only the range reaches the proxy. Names and descriptions stay in the
    spec and the status, never in HAProxy's configuration.
- **Entries.** An address (one client) or a prefix, IPv4 or IPv6, at most 64.
  They are stored as written and sent to the proxies as masked prefixes.
  - Refused: zones, IPv4-mapped IPv6 (write IPv4 as IPv4), prefixes that
    match a whole address family (leave the rule out instead), and
    duplicates.
  - The proxy's `Validate` checks the same again, and each entry must be in
    canonical form, as every value that reaches HAProxy's configuration is
    (security rule 2).
- **`ipAllow`**: only clients in the ranges reach the app from outside.
- **`ipDeny`**: every client but those does.
- **Refused clients** get `403` from the proxy. The app never sees the
  request, and an app scaled to zero is not woken by it.
- **Where the rules apply.**
  - They apply to the app's public names: its domains, its root-domain name,
    and the names of its revision labels (ADR 0022).
  - They do not apply to `<app>.internal`. Apps of the space call that
    name, and `ingress.allow` chooses those.
- **Changing them.** The rules are part of the app's spec, so they change
  with a deploy and roll back with a rollback.
  - `armada app create`/`update` take `--ip-allow` and `--ip-deny`
    (repeatable, `RANGE[,name=NAME][,description=TEXT]`, the description last so it may hold commas). Each replaces the list, because who may reach an app is
    safer stated in full than pieced together. `--no-ip-rules` lets everyone
    in again.

### The client's address

HAProxy's public frontend works out one address per request, `txn.client`,
on every request:
1. **First, address headers are removed** from any connection that is not
   from a trusted proxy (`armada cluster set --trusted-proxies`, as before):
   `Forwarded`, `X-Forwarded-For`, and the CDN-specific ones. `X-Real-IP` is
   removed from every request (point 8).
2. **Not a trusted proxy:** the client is the connection's own address. No
   header counts.
3. **A trusted proxy:** the client is the **last** address in
   `X-Forwarded-For`. A proxy appends the address it received the
   connection from, so the last entry is the one the trusted proxy wrote.
   Everything before it came from the client and is ignored.
4. **Proxies in a row:** if that last address is itself a trusted proxy, the
   one before it counts, and so on, for at most four proxies in a row.
5. **Fail closed:** a trusted proxy that sends no `X-Forwarded-For`, a last
   entry that is not an address, or a chain of only trusted proxies leaves
   the client unknown. Both `ipAllow` and `ipDeny` refuse an unknown client.
6. **No other header counts.** `Forwarded` and the CDN-specific headers are
   left for the app.
7. **A workload is never a trusted proxy.** Containers reach the public
   frontend on their node's addresses, from the cluster CIDR (or the default
   bridge subnet, `10.121.0.0/24`, on a cluster without a cluster network).
   The leader takes those addresses out of the trusted prefixes before they
   reach the proxies, so a broad range such as
   `10.0.0.0/8` trusts the load balancers in it but no container. A prefix
   that holds only container addresses is refused.
8. **Apps get it as `X-Real-IP`.** The frontend removes `X-Real-IP` from
   every request, a trusted proxy's included, and sets it to `txn.client`,
   so an app reads one header instead of working
   out `X-Forwarded-For` itself, and what it reads is the address the rules
   judge. An unknown client (point 5) leaves no `X-Real-IP`. The internal
   frontend sets none: its callers are containers.
9. **TCP load balancers name clients with the PROXY protocol.** A load
   balancer that forwards TCP and replaces the source address hides the
   client from every header. The cluster setting `--proxy-protocol` lists
   such load balancers (`ProxyConfig.proxy_protocol`, canonical prefixes,
   no prefix matching every address, container ranges taken out like
   trusted proxies). Both public frontends start with
   `tcp-request connection expect-proxy layer4 if { src ... }`: a
   connection from a listed address must begin with a PROXY header (v1 or
   v2, read before TLS), and its client address becomes `src` for every
   rule after it, so the points above apply to the client as if it had
   connected directly. A connection from anywhere else is read as it is: a
   PROXY header from it is not HTTP and is refused.

Each backend of the app (and its wake backend) starts with one
`http-request deny deny_status 403` rule that tests `txn.client` against
the ranges, written into the configuration. A change reloads the proxy:
the rules are part of the structural signature, so old rules never keep
applying.
- The internal frontend never sets the marker the rules test (`txn.ext`), so
  internal callers pass.
- The internal frontend binds only to the container bridge, so outside
  clients cannot reach it.

### Bypasses considered

- **Direct to a replica.** On the cluster network, replicas publish no
  ports (ADR 0025), so the proxy is the only way in from outside. Older
  clusters publish ports only on the private IP.
- **Another of the app's names.** The rule is in the app's backend, not in
  any route, so every name and path that leads to the app checks it.
- **A rule change that does not reach a node.** The configuration is
  reloaded, as for a new route. A node that cannot apply new configuration
  keeps serving with its last valid one (ADR 0004 and `ProxyNotUpdated`).
- **HTTP on port 80** only redirects to HTTPS and serves ACME challenges,
  so it reaches no app, unless the cluster obtains no certificates: then it
  routes with the same client address handling as port 443, so the rules
  apply there alike.

## Consequences

- **The rules are only as strict as the trusted proxies.**
  - A trusted proxy that lets its own users choose the address it appends
    can pass the rules for them.
  - Trust only proxies you control or whose appended address you rely on.
    Behind a shared CDN, an app open to a range is open to anyone who can
    make that CDN connect for them from such an address.
  - For a firm limit, combine the rules with the CDN's own access controls.
- **Proxies that write only another header are not supported.** Behind a
  proxy that does not write `X-Forwarded-For`, every client is unknown, and
  apps with rules refuse everyone and get no `X-Real-IP`. Without rules,
  nothing else changes. Behind a TCP load balancer that neither keeps the
  source address nor sends the PROXY protocol, every client is the load
  balancer.
- **A PROXY protocol source is trusted completely.** Whoever controls a
  listed address names any client; list only load balancers you run.
- **No per-path rules.** A path that needs different rules is a separate
  app.
- **Cost.** Working out the address and setting `X-Real-IP` take a few
  rules per request in the public frontend; the rules run once per request,
  in the backend that serves it, and only for apps that have them.
- **An `X-Real-IP` from a proxy in front is replaced.** A proxy that set it
  to the client already gets the same value back; one that set it to
  something else no longer reaches the app.

# 0047. DNS credentials for an app's custom domains

- Status: Accepted
- Date: 2026-11-18

## Context

A cluster has one DNS provider and one token (ADR 0031), for the root
domain and the names under it: those are the cluster's own names,
`<app>.<root domain>`. Custom domains are the names an app's owners bring
because they do not want the default one. They get certificates through
HTTP-01, which needs the name to point at the nodes and port 80 to answer
the ACME CA. That fails when a CDN or load balancer in front answers HTTP
itself, or the name points elsewhere until a cut-over.

The DNS of a custom domain belongs to whoever owns the domain, usually in
an account the cluster's operators do not hold. Its token belongs with the
app that serves the domain, managed by the people who deploy it, not in a
cluster setting only cluster-admins can change.

## Decision

An app names the DNS provider of its custom domains and an app secret
holding the provider's token:

```yaml
ingress:
  type: external
  domains: [shop.example, www.shop.example]
  dns:
    provider: cloudflare
    tokenSecretRef: cf-token
```

- `ingress.dns` needs `type: external` and at least one custom domain.
  `provider` is `cloudflare`; `tokenSecretRef` names an app secret, set
  like any other (`armada secret set shop cf-token`). CLI:
  `--dns-token-secret NAME` and `--no-dns` on `app create`/`app update`.
- The secret is pinned by the revision like every secret the spec names
  (`SecretRefs`), so a new token takes effect with the next revision and a
  rollback brings the old one back. It never reaches the app: `envFrom:
  secrets` leaves it out.
- On each pass the leader opens the token the active revision pins
  (through the revision cache that keeps opened secrets in
  memory only) and hands every verified custom domain of the app to the
  certificate manager with it. The
  app's host under the root domain keeps the cluster's provider. When two
  apps of a space serve one domain, the first that names credentials for
  it is used.
- The certificate manager makes one DNS-01 solver per distinct token
  (keyed by a SHA-256 of provider and token), shared by the names that use it and kept while any
  does. A name whose credentials change starts over with the new ones;
  issued certificates stay valid. A name whose provider cannot be made
  keeps HTTP-01. The credentials redact their token when printed or logged.
- A token the leader cannot open is a `DNSTokenUnavailable` condition on
  the app; its domains keep HTTP-01.
- Ownership is unchanged: a custom domain is routed and gets a certificate
  only after its TXT record is verified, so an app's token is only ever
  used for names its space proved it owns. The token decides how a
  certificate is obtained, not who may route a name.

## Consequences

- Owners of a custom domain get certificates without port 80 reaching the
  nodes, with a token they manage next to the app, under the same access
  control as the app's other secrets (deployers of the space).
- The cluster keeps one DNS provider, for its own root domain.
- The leader holds the tokens of apps with `ingress.dns` in memory, as it
  holds the secrets it puts into assignments. Whoever controls the control
  plane can use them on their zones (T88); a token limited to its zone's
  DNS records bounds that.

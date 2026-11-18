# 0047. DNS credentials per zone

- Status: Accepted
- Date: 2026-11-18

## Context

A cluster has one DNS provider and one token (ADR 0031). They obtain
certificates through DNS-01 for the root domain, the names under it, and
a wildcard. Every other custom domain uses HTTP-01, which needs the name to
point at the nodes and port 80 to reach them.

Many clusters serve domains whose DNS lives somewhere else: another
account at the same provider, or a domain a team manages with its own
token. HTTP-01 does not work for them when port 80 does not reach the
nodes (a CDN or load balancer that redirects or answers itself, a name
that points elsewhere until a cut-over), and the cluster's token should
not reach zones it was never meant to touch.

## Decision

A cluster keeps DNS credentials per zone. Every certificate for a name in
a zone is obtained through DNS-01 with that zone's provider and token.

- `armada cluster dns create ZONE --provider cloudflare --token FILE|-`
  adds a zone, `update` replaces its provider and token, `list` shows the
  zones without tokens (as does `armada cluster show`), and `delete`
  removes one. RPCs `SetDNSZone` (`must_create`/`must_exist`) and
  `DeleteDNSZone`, cluster-admin only; changes are audited without the
  token. At most 64 zones.
- A zone is a valid domain name with at least two labels, stored in lower
  case without a trailing dot; not a wildcard.
- Zones live in the cluster settings (`Settings.DNSZones`, meta record
  `settings`). Each token is sealed with the master key under scope
  `cluster`, name `dns-zone-<zone>`, and a version from `DNSZoneSeq`,
  which counts every zone token ever sealed, so no version is used twice,
  also after a zone is deleted and created again.
- The leader restarts its control plane after a change, as for the DNS
  provider (ADR 0031): `resolveSettings` opens each zone's token, and the
  certificate manager gets one DNS-01 solver per zone
  (`certs.Options.Zones`). A token that does not open, or an unknown
  provider, leaves its zone out with an error in the log; it never stops
  the control plane.
- Which credentials a name uses (`certs.ACME.via`): the longest zone that
  holds it (the zone itself or a name under it; a wildcard counts as the
  name it covers). The root domain's provider holds the root domain and
  the names under it when it is longer than every zone that does; an
  equally long zone wins. A wildcard in no zone uses the root domain's
  provider. Everything else uses HTTP-01. A name whose credentials change
  starts over with the new ones; issued certificates stay valid.
- Custom domains still prove ownership with their TXT record: credentials
  decide how a certificate is obtained, not which space may route a name.
- Cloudflare is the only provider, as for the root domain.

## Consequences

- A custom domain whose DNS is in another account gets certificates
  without port 80 reaching the nodes, with a token that touches only its
  zone.
- The leader holds every zone token in memory, as it holds the root
  domain's token. Whoever controls the control plane can use them on
  their zones (T88); a token limited to its zone's DNS records bounds
  that.
- Nothing changes for clusters with no zones.

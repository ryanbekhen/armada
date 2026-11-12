# Run apps behind a CDN or proxy

Put a CDN (or a proxy of your own) in front of your nodes and keep what
depends on the client's address working: apps see the visitor's address,
`ipAllow` checks the right one, and nobody can claim another address by
sending a header. Certificates come from DNS-01, with one wildcard
certificate for every app. The worked example uses Cloudflare, the DNS
provider Armada supports, with its proxy turned on.

**You will use:** [`armada cluster set`](../cli/armada-cluster.md#armada-cluster-set)
(`--trusted-proxies`, `--dns-provider`, `--dns-token`, `--root-domain`),
[client address headers](../operations.md#behind-a-proxy-or-cdn),
[`ingress.ipAllow`](../operations.md#who-may-reach-an-app),
[certificates](../quickstart.md#certificates)

**Before you start:**

- A running cluster (see the [quickstart](../quickstart.md)) and
  `cluster-admin`: cluster settings are cluster-wide.
- The zone `example.com` on Cloudflare, and an API token for it with
  `Zone / DNS / Edit` and `Zone / Zone / Read`, limited to that zone (and
  ideally to your control plane servers' public IPs).

## The setup

```
 visitor 192.0.2.44
    │ HTTPS (Cloudflare's certificate)
    ▼
 Cloudflare edge 172.70.x.x      appends 192.0.2.44 to X-Forwarded-For,
    │ HTTPS (Armada's certificate)       sets CF-Connecting-IP
    ▼
 node: HAProxy :443  ── connection from a trusted proxy? keep the headers
    │                   ipAllow checks 192.0.2.44 (last X-Forwarded-For entry)
    ▼                   appends 172.70.x.x to X-Forwarded-For
 replica
```

TLS ends twice: at the CDN, and again on your nodes with Armada's
certificate. Armada never hands its certificates or keys to the CDN.

## 1. Certificates through DNS-01

With the proxy on, the CDN answers for your names, so get certificates
through DNS records instead of HTTP-01 on port 80. Give the cluster the
token from stdin, never on a command line:

```bash
read -rs TOKEN && printf '%s' "$TOKEN" | armada cluster set --dns-provider cloudflare --dns-token -; unset TOKEN
armada cluster set --root-domain example.com
```

- The cluster keeps the token encrypted with its master key and never
  shows it. The leader restarts its control plane within a second or two to
  use it, and the command waits for it; apps keep serving.
- The root domain gets one wildcard certificate, `*.example.com`. Every
  app's `<app>.example.com`, every verified custom domain one label under
  the root (`www.example.com`), and every traffic label
  (`canary--web.example.com`) is served with it, so new apps need no new
  certificate.
- The root domain itself, used as a custom domain, and deeper names under it
  (`shop.staging.example.com`, the URL of an app in project `staging`) get
  certificates of their own, also through DNS-01.
- Custom domains outside the root domain keep HTTP-01, which needs the ACME
  CA to reach port 80 of your nodes through the CDN. Prefer names under the
  root domain.
- `armada cluster set --dns-provider none` goes back to HTTP-01.

## 2. Point DNS through the CDN

In the zone, a wildcard record to every node, proxied:

```
*.example.com.  A  203.0.113.10   proxied
*.example.com.  A  203.0.113.11   proxied
```

Records you set for specific names (`www`, `admin`) work the same way.
Two rules come from the CDN, not from Armada:

- **Proxy only names one level under the zone** (`shop.example.com`). The
  CDN's free certificate does not cover `shop.staging.example.com`: keep
  such names, and a root domain like `apps.example.com`, "DNS only".
- **Set the zone's SSL/TLS mode to Full (strict)**, so the CDN checks the
  certificate your nodes serve. Anything weaker lets someone between the
  CDN and your nodes read the traffic.

## 3. Trust the CDN's addresses

Public ingress removes every header that names a client's address
(`Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`,
`True-Client-IP`) and adds the connection's own address to
`X-Forwarded-For`. Behind a CDN, that address is the CDN's edge, so your
apps would see only the CDN. List its address ranges, so requests from it
keep those headers:

```bash
armada cluster set --trusted-proxies "$(
  { curl -fsS https://www.cloudflare.com/ips-v4; echo; curl -fsS https://www.cloudflare.com/ips-v6; echo; } | grep . | paste -sd, -
)"
armada cluster show
```

```
root domain:       example.com
trusted proxies:   103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,104.16.0.0/13,...
certificates:      on, letsencrypt
acme email:        ops@example.com
dns provider:      cloudflare (token set)
metrics:           off
node lost timeout: 5m0s
```

- Up to 64 prefixes, comma separated. A prefix that matches every address
  (`0.0.0.0/0`) is refused.
- The setting applies to every node with a proxy reload, without
  restarting the control plane, and is audited.
- Requests from anywhere else still lose the headers, so a client that
  reaches a node directly cannot claim an address.
- The CDN publishes changes to its ranges. Run the command again when they
  change, for example from a monthly job of your own; it replaces the list.
- `armada cluster set --trusted-proxies ""` trusts no proxy again.

## 4. What your apps see

For a request from `192.0.2.44` through the edge `172.70.1.9`:

| Header | Value | Use it? |
| --- | --- | --- |
| `CF-Connecting-IP` | `192.0.2.44` | Yes: the CDN set it, and only trusted proxies' headers survive |
| `X-Forwarded-For` | `192.0.2.44, 172.70.1.9` | The entry **before the last** is the visitor; the last is the edge that connected to the node |

Entries before the visitor's are whatever the client sent and mean
nothing: never take the first entry of `X-Forwarded-For`. If your framework
works out the client from `X-Forwarded-For`, configure it for two proxies
in front of the app (the CDN and Armada's), and check the result with the
`whoami` app below.

The internal frontend leaves these headers alone, so an app that calls
another app through `<app>.internal` can pass its client's address on.

To see it for yourself, deploy an app that prints request headers and
remove it after:

```bash
armada app create whoami --image traefik/whoami:v1.10 --port 80 --ingress external --wait
curl -s https://whoami.example.com/ | grep -i -e forwarded -e connecting
armada app delete whoami --yes
```

## 5. What `ipAllow` sees

```yaml
name: admin
image: ghcr.io/acme/admin:1.9.0
ingress:
  type: external
  port: 8080
  ipAllow:
    - range: 203.0.113.0/24
      name: office
      description: office network, as the CDN reports it
probes:
  readiness:
    path: /login
```

For each request, the proxy works out one client address:

1. A connection not from a trusted proxy: its own address. No header
   counts.
2. A connection from a trusted proxy: the **last** address in
   `X-Forwarded-For`, the one that proxy appended. With Cloudflare, the
   visitor's.
3. If that address is itself a trusted proxy, the one before it, for up to
   four proxies in a row.
4. **Fail closed.** A trusted proxy that sends no valid `X-Forwarded-For`
   leaves the client unknown, and both `ipAllow` and `ipDeny` refuse it with
   `403`.

`CF-Connecting-IP`, `Forwarded`, and `X-Real-IP` are never read for the
rules: only `X-Forwarded-For`, and only from trusted proxies.

The rules are only as strict as your trusted proxies. A CDN that other
customers can point at your nodes, or that lets its users choose the
address it appends, can bring them in from its own addresses. For a firm
limit on a sensitive app, combine `ipAllow` with the CDN's own access rules,
or keep that app's name "DNS only" so the rule sees the real connection.

## 6. Close the way around the CDN

The CDN's protections mean little if clients can reach your nodes
directly. Limit ports 80 and 443 on the nodes to the same ranges in your
firewall. HAProxy runs on the host's network, so the host's firewall rules
apply to it. Keep in mind:

- names kept "DNS only" (deeper names, apps you exempt above) then stop
  working for direct clients;
- HTTP-01 for custom domains outside the root domain needs the ACME CA to
  reach port 80 through the CDN.

## Check that it works

- `armada cluster show` lists the trusted proxies and `dns provider:
  cloudflare (token set)`.
- `armada domain list` shows `TLS yes` for verified custom domains, and
  `armada cluster events` shows `Obtained` for `*.example.com`.
- The `whoami` app above shows your address in `CF-Connecting-IP` and as the
  entry before the last in `X-Forwarded-For`.
- From an allowed network, `curl -s -o /dev/null -w '%{http_code}\n'
  https://admin.example.com/login` prints `200`; from elsewhere, `403`.

## Variations

**A proxy of your own in front.** For a load balancer or proxy you run, on
fixed addresses, that writes `X-Forwarded-For` by appending the address it
received the connection from:

```bash
armada cluster set --trusted-proxies 10.0.0.5/32,10.0.0.6/32
```

**Two proxies in a row** (a CDN, then a proxy of yours): list both. The
client is found by stepping over trusted addresses at the end of
`X-Forwarded-For`, up to four.

**A proxy that writes only its own header** (not `X-Forwarded-For`): apps
still get that header once its addresses are trusted, but `ipAllow` and
`ipDeny` cannot use it and refuse every client. Do not combine such a proxy
with address rules.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Apps see only CDN addresses | The CDN's ranges are not trusted, so its headers are removed | `armada cluster set --trusted-proxies ...` as in step 3 |
| Every client gets `403` from an app with `ipAllow` | The CDN's ranges are not trusted (the rule sees the edge), or a trusted proxy sends no valid `X-Forwarded-For` | Trust the ranges; check the proxy writes `X-Forwarded-For` |
| Some visitors get `403` now and then | The CDN added ranges you do not trust yet | Refresh the list from the CDN |
| Browser shows a CDN error about the origin certificate | Full (strict) mode and the node's certificate is from the staging CA, or not obtained yet | `armada cluster set --acme-ca letsencrypt`; check `armada cluster events` for certificate `Failed` |
| Certificate `Failed` with a DNS error | The token lacks a permission or the zone | A token with `Zone / DNS / Edit` and `Zone / Zone / Read` for the zone; set it again from stdin |
| `trusted proxy "0.0.0.0/0" matches every address` | Trusting everyone would let any client choose its address | List the proxy's ranges |
| `at most 64 trusted proxies` | Too many prefixes | Merge ranges where the CDN allows it |
| A name two levels deep fails in the browser through the CDN | The CDN's free certificate covers one level | Keep that name "DNS only" |

## Next steps

- [spa-and-api.md](spa-and-api.md): CORS, named `ipAllow` rules, sticky
  sessions.
- [deploy-a-web-app.md](deploy-a-web-app.md): custom domains.
- [Operations: behind a proxy or CDN](../operations.md#behind-a-proxy-or-cdn)
  and [cluster settings](../operations.md#cluster-settings).
- [Threat model](../threat-model.md) for what trusting a proxy means.

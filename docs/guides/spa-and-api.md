# Serve a single-page app and its API on two domains

Run a browser app on `app.example.com` that calls its API on
`api.example.com`, plus an admin panel only your staff can reach. Along the
way you set up CORS in the proxy, health probes that keep bad replicas out,
request timeouts for slow endpoints, sticky sessions for the panel, and
named client address rules.

**You will use:** [`ingress.cors`](../spec-reference.md#ingress),
[`ingress.ipAllow`](../operations.md#who-may-reach-an-app),
[`ingress.sticky`](../operations.md#how-requests-reach-replicas),
[`ingress.timeout`](../spec-reference.md#ingress),
[`probes`](../spec-reference.md#probes), [`drain`](../spec-reference.md#drain)

**Before you start:**

- A running cluster (see the [quickstart](../quickstart.md)).
- Three images of your own: the built single-page app served by a static
  web server (`ghcr.io/acme/web:2.3.0`, port 8080), the API
  (`ghcr.io/acme/api:1.4.2`, port 3000), and the admin panel
  (`ghcr.io/acme/admin:1.9.0`, port 8080).
- DNS for `app.example.com`, `api.example.com`, and `admin.example.com`
  pointing at your nodes. Each domain is verified once, as in
  [deploy-a-web-app.md](deploy-a-web-app.md#3-add-your-own-domain).

## The setup

```
 browser on https://app.example.com
   │  GET /            ──▶ web    (static files)
   │  fetch() with cookies
   └─ https://api.example.com ──▶ api   CORS answered by the proxy
 staff on 203.0.113.0/24 or the VPN
   └─ https://admin.example.com ──▶ admin  ipAllow, sticky
 everyone else ──▶ admin.example.com: 403 from the proxy
```

Each app is a separate spec file; they share nothing but the cluster.

## 1. The single-page app

`web.yaml`:

```yaml
name: web
image: ghcr.io/acme/web:2.3.0
ingress:
  type: external
  port: 8080
  domains: [app.example.com]
probes:
  readiness:
    path: /
    period: 5s
scale:
  min: 2
  max: 2
resources:
  cpu: 100m
  memory: 64Mi
```

```bash
armada app create --file web.yaml --wait
```

A static server needs little: a readiness probe on `/` and small
resources. Two replicas keep the app up while a node restarts. Make your
static server answer unknown paths with `index.html` so client-side routes
work on reload; that is the image's job, not the proxy's.

## 2. The API, with CORS

The page on `https://app.example.com` calls `https://api.example.com`, a
different origin, so the browser asks the API first (a preflight `OPTIONS`
request) and reads answers only if the API allows that origin. Armada's
proxy does this for the app.

`api.yaml`:

```yaml
name: api
image: ghcr.io/acme/api:1.4.2
envFrom: secrets
ingress:
  type: external
  port: 3000
  domains: [api.example.com]
  timeout: 2m
  cors:
    allowOrigins:
      - https://app.example.com
      - http://localhost:5173
    allowMethods: [GET, HEAD, POST, PUT, PATCH, DELETE]
    allowHeaders: [Authorization, Content-Type, X-Request-Id]
    exposeHeaders: [X-Request-Id]
    maxAge: 10m
    allowCredentials: true
probes:
  startup:
    path: /healthz
    period: 2s
    failureThreshold: 30
  readiness:
    path: /healthz
    period: 5s
  liveness:
    path: /livez
    period: 10s
    timeout: 2s
    failureThreshold: 3
scale:
  min: 2
  max: 6
  rules:
    - type: http
      concurrent: 40
resources:
  cpu: 500m
  memory: 512Mi
drain: 2m
```

```bash
armada app create --file api.yaml --wait
```

### CORS

- **`allowOrigins`** lists exact origins, `https://host` or
  `http://host:port`, no paths or wildcards; up to 32. `http://localhost:5173`
  lets a developer's local dev server call the real API; leave it out of
  production if you do not want that.
- **`allowMethods`** defaults to `GET, HEAD, POST`. **`allowHeaders`** lists
  the request headers the page sends beyond the simple ones, here the
  bearer token and JSON bodies. **`exposeHeaders`** lists response headers
  the page may read.
- **`maxAge`** lets the browser reuse a preflight answer, up to `24h`.
- **`allowCredentials: true`** lets the page send cookies. It cannot be
  combined with `allowOrigins: ["*"]`; `*` alone suits a public API that
  takes no cookies.

The proxy answers preflight requests from listed origins itself with
`204`: they never reach the API and never wake an app scaled to zero. It
adds `Access-Control-Allow-Origin` with the exact origin, and `Vary: Origin`,
to every answer, its own `403` and `503` included, so the browser shows the
real status instead of a CORS error. Other origins get no CORS headers.

Check it from your machine:

```bash
curl -si -X OPTIONS https://api.example.com/v1/orders \
  -H 'Origin: https://app.example.com' \
  -H 'Access-Control-Request-Method: POST'
```

```
HTTP/2 204
access-control-allow-origin: https://app.example.com
access-control-allow-methods: GET, HEAD, POST, PUT, PATCH, DELETE
access-control-allow-headers: Authorization, Content-Type, X-Request-Id
access-control-max-age: 600
access-control-allow-credentials: true
vary: Origin
```

CORS only tells browsers which pages may read answers. It keeps no client
out: `curl` from anywhere still reaches the API. Use the API's own
authentication, or `ipAllow` (below), for that. The origin list alone can
be changed from the command line; the rest stays in the file:

```bash
armada app update api --cors-origin https://app.example.com --cors-origin https://beta.example.com
armada app update api --no-cors
```

### Probes

The three probes answer different questions:

| Probe | Question | On failure |
| --- | --- | --- |
| `startup` | Has the process finished starting? Here up to 60 seconds (`2s × 30`) for migrations or warm caches. | The container is recreated |
| `readiness` | Should this replica get requests now? | It gets none until it passes again; nothing is restarted |
| `liveness` | Is the process stuck for good? | The container is recreated |

- Point `readiness` at an endpoint that checks what a request needs, for
  example the database connection. A replica that loses it then stops
  getting requests instead of answering with errors, and a rollout waits
  for new replicas to pass it.
- Keep `liveness` cheap and local (`/livez` answers if the process can
  answer at all). If it checked the database, an outage of the database
  would restart every replica.
- `timeout` defaults to 1 second; give a probe more when the app is busy.
  The autoscaler counts only ready replicas.

### Timeouts and drain

- **`ingress.timeout: 2m`.** A request gets `504` when the app sends
  nothing for this long, 60 seconds by default, 1s to 1h. Raise it for an
  API with slow endpoints such as exports. It applies to the whole app; a
  path that needs much longer is better as a separate app or a
  [job](scheduled-jobs.md).
- **`drain: 2m`.** A replica that leaves (a deploy, scale down, a drained
  node) takes no new requests and is stopped after `drain`, 10 seconds by
  default. Set it above the longest request, so deploys never cut one off.
- A WebSocket closes after an hour with no data in either direction, and
  connections opened before a proxy reload close at most an hour after
  it. Clients should ping and reconnect.

## 3. The admin panel: allowed addresses and sticky sessions

`admin.yaml`:

```yaml
name: admin
image: ghcr.io/acme/admin:1.9.0
envFrom: secrets
ingress:
  type: external
  port: 8080
  domains: [admin.example.com]
  sticky: true
  ipAllow:
    - range: 203.0.113.0/24
      name: office
      description: Jakarta office network
    - range: 198.51.100.14
      name: vpn
      description: the VPN gateway staff use from home
    - range: 2001:db8:1200::/48
      name: office-v6
probes:
  readiness:
    path: /login
scale:
  min: 2
  max: 2
```

```bash
armada app create --file admin.yaml --wait
armada app show admin
```

```
Name:          admin
Revision:      admin--r1
Image:         ghcr.io/acme/admin:1.9.0
Ready:         2/2
Ingress:       external
Allowed from:  203.0.113.0/24  office: Jakarta office network
               198.51.100.14  vpn: the VPN gateway staff use from home
               2001:db8:1200::/48  office-v6
URLs:          https://admin.apps.example.com/
               https://admin.example.com/
```

### Who may reach it

- **`ipAllow`** lets only clients from these addresses or prefixes in,
  IPv4 or IPv6, up to 64 rules. Everyone else gets `403` from the proxy; the
  app never sees them. `ipDeny` is the opposite (everyone except the
  listed ranges); an app uses one or the other.
- **Names and descriptions** are for people: `armada app show` lists them,
  so whoever reads the spec next knows what `198.51.100.14` is. They never
  reach the proxy. A bare address (`- 203.0.113.7`) works too.
- **The rule applies to every name of the app**, its custom domain and its
  root domain URL alike. Calls from other apps through `admin.internal` are
  not affected; `ingress.allow` chooses those.
- **The address checked** is the connection's own. Behind a proxy or CDN,
  list it with `armada cluster set --trusted-proxies` first, or every
  request comes from the CDN's addresses: see
  [behind-a-cdn.md](behind-a-cdn.md).

From the command line, each flag replaces the whole list, because who may
reach an app is safer stated in full:

```bash
armada app update admin \
  --ip-allow '203.0.113.0/24,name=office,description=Jakarta office network' \
  --ip-allow '198.51.100.14,name=vpn,description=the VPN gateway staff use from home'
armada app update admin --no-ip-rules     # everyone again
```

The description comes last in a flag, so it may contain commas.

### Sticky sessions

`sticky: true` sends each client back to the replica that answered it first,
through a cookie the proxy sets (`armada_<hash>`, `httponly`, `secure`,
`SameSite=Lax`). Use it for an app that keeps sessions in a replica's
memory, as many admin frameworks do by default. A client whose replica is
gone (a deploy, a lost node) moves to another one and loses that session,
so an app that can keep sessions in a database or cache should do that
instead and leave `sticky` off. Sticky apps do not get local-first routing.

```bash
armada app update admin --sticky=false    # turn it off
```

## Check that it works

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://app.example.com/          # 200
curl -s -o /dev/null -w '%{http_code}\n' https://api.example.com/healthz   # 200
curl -s -o /dev/null -w '%{http_code}\n' https://admin.example.com/login   # 200 from the office, 403 elsewhere
curl -s -c - -o /dev/null https://admin.example.com/login | grep armada_   # the sticky cookie
```

In the browser's developer tools, the API calls from `app.example.com`
show the preflight answered with `204` and no CORS errors.

## Variations

**One domain, no CORS.** Serve the API under a path of the app's own
domain, and the browser makes same-origin calls with no preflight at all.
Give the API a route and leave `web` with every other path:

```yaml
name: api
image: ghcr.io/acme/api:1.4.2
ingress:
  type: external
  port: 3000
  domains: [app.example.com]
  routes:
    - path: /api
      stripPrefix: true
probes:
  readiness:
    path: /healthz
```

The longest matching prefix wins, so `app.example.com/api/...` goes to
`api`, with `/api` removed, and everything else to `web`. Two apps cannot
route the same domain and path; the second deploy is refused with
`app.example.com/api is already routed to app ...`. The readiness probe
talks to the container directly, so its path has no prefix.

**A public API.** `allowOrigins: ["*"]` without `allowCredentials`, for an
API any site may call with tokens but no cookies.

**Keeping a few clients out.** `ipDeny` with the offending addresses keeps
everyone else in:

```bash
armada app update api --ip-deny '198.51.100.7,name=scraper,description=ignores rate limits'
```

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Browser: "No 'Access-Control-Allow-Origin' header" | The page's origin is not listed exactly (scheme, host, and port count; no trailing `/`) | Add the origin as the browser sends it in `Origin` |
| `ingress.cors.allowOrigins[0]: "*" cannot be combined with allowCredentials` | `*` would let every site read answers with the user's cookies | List the origins |
| `ingress.cors.allowOrigins[0]: "https://app.example.com/" is not an origin` | Origins have no path | Remove the trailing `/` |
| Preflight passes, the real request fails in the browser | The page sends a header not in `allowHeaders`, or reads one not in `exposeHeaders` | Add it |
| Everyone gets `403` from an app with `ipAllow` | The nodes sit behind a proxy or CDN, so every request comes from its addresses, or a trusted proxy sends no valid `X-Forwarded-For` | [behind-a-cdn.md](behind-a-cdn.md) |
| `ingress: ipAllow and ipDeny require type external` | Rules apply to outside clients only | Use `ingress.allow` for internal callers |
| Long requests end with `504` after 60 seconds | `ingress.timeout` is the default | Raise `timeout`, and `drain` with it |
| Users of the admin panel are logged out after a deploy | Sessions live in the replica's memory, and the replica was replaced | Store sessions outside the replica; sticky sessions only help while replicas live |
| Replicas restart in a loop at start | The startup or liveness probe gives up before the app is ready | Raise `failureThreshold` of `startup`, or `initialDelay` |

## Next steps

- [behind-a-cdn.md](behind-a-cdn.md): the same apps behind a CDN.
- [autoscaling-and-scale-to-zero.md](autoscaling-and-scale-to-zero.md).
- [app-with-a-database.md](app-with-a-database.md): give the API its
  database.
- [Operations: how requests reach replicas](../operations.md#how-requests-reach-replicas).

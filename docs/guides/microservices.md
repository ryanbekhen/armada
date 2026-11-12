# Run services that talk to each other privately

You will split an application into services that call each other over the
cluster's private network: a public frontend, internal APIs only it may
call, a shared cache over plain TCP, and two teams whose services are kept
apart by projects.

**You will use:** [internal ingress](../spec-reference.md#ingress)
(`type: internal`), [`ingress.allow`](../spec-reference.md#ingress),
[internal TCP](../operations.md#tcp-apps-inside-the-cluster)
(`protocol: tcp`), [projects](../operations.md#projects) and
[network isolation](../operations.md#network-isolation), and
[roles](../operations.md#access-control).

**Before you start:**

- A running cluster created with the cluster network
  (`armadad init --cluster-cidr`, see the [quickstart](../quickstart.md)).
  Without it, internal names still work, but `allow`, TCP apps, and the
  isolation between apps and projects do not.
- A root domain for the public frontend (`armada cluster set --root-domain`).

## How services find each other

Every app with `ingress.type: internal` gets a private name:

| Called from | HTTP | TCP (`protocol: tcp`) |
| --- | --- | --- |
| an app of the same project | `http://NAME` | `NAME:PORT` |
| full name, project `default` | `http://NAME.internal` | `NAME.internal:PORT` |
| full name, another project such as `shop` | `http://NAME.shop.internal` | `NAME.shop.internal:PORT` |

- The name alone always means an app of the caller's own project: `orders`
  called from `web.shop` is `orders.shop`, never an `orders` of another
  project. Each container has its project's zone as its DNS search domain,
  and the proxy completes a `Host` without a dot the same way. Replicas
  started before the cluster ran a release with this get it on their next
  deploy.

- The name resolves through the node's DNS server to the node's own proxy,
  which sends the request to a ready replica of the app, preferring
  replicas on the same node. HTTP goes to port 80 of the name; the proxy
  knows the app's port.
- The name resolves only for containers of the same project. Another
  project's container gets no answer, and the proxy refuses it with a 404
  whatever `Host` header it sends.
- A container cannot reach another app's container address directly: the
  firewall drops it, on one node and between nodes. The internal name is
  the only way in, so the proxy decides who gets through.
- Internal HTTP is plain HTTP. Traffic between nodes is encrypted only with
  the `wireguard` network mode (`armadad init --network wireguard`).

## Case A: a frontend and two APIs

```
            internet
               |
   https://web.shop.<root domain>
               |
  project shop v
  +---------------------------------------------+
  |  web ----------------> orders               |
  |   |   http://orders                |        |
  |   |                                |        |
  |   +------------------> users <-----+        |
  |       http://users                          |
  +---------------------------------------------+
```

`web` is public. `orders` and `users` are internal; only `web` may call
`orders`, and only `web` and `orders` may call `users`.

### 1. Create the project

```bash
armada project create shop
armada project use shop
```

### 2. Deploy the internal APIs

```yaml
# users.yaml
name: users
image: ghcr.io/acme/users:2.3.0
ingress:
  type: internal
  port: 8080
  allow: [web, orders]
probes:
  readiness:
    path: /healthz
scale:
  min: 2
```

```yaml
# orders.yaml
name: orders
image: ghcr.io/acme/orders:1.9.1
env:
  - name: USERS_URL
    value: http://users
ingress:
  type: internal
  port: 8080
  allow: [web]
probes:
  readiness:
    path: /healthz
scale:
  min: 2
```

```bash
armada app create --file users.yaml --wait
armada app create --file orders.yaml --wait
```

`allow` lists up to 32 apps of the same project. The app's own replicas may
always call it. Without `allow`, every app of the project may. A caller
not on the list gets a 404 from the proxy, and the app never sees the
request.

### 3. Deploy the frontend

```yaml
# web.yaml
name: web
image: ghcr.io/acme/web:4.0.2
env:
  - name: ORDERS_URL
    value: http://orders
  - name: USERS_URL
    value: http://users
ingress:
  type: external
  port: 3000
probes:
  readiness:
    path: /healthz
scale:
  min: 2
```

```bash
armada app create --file web.yaml --wait
armada app show web
```

```
Name:     web.shop
Revision: web.shop--r1
Image:    ghcr.io/acme/web:4.0.2
Ready:    2/2
Ingress:  external
URLs:     https://web.shop.example.com/
...
```

### 4. Check who may call what

From `web`, both APIs answer:

```bash
armada app exec web -- wget -qO- http://orders/healthz
armada app exec web -- wget -qO- http://users/healthz
```

From `orders`, `users` answers, and nothing else does. Calling `orders`
from `users` gets a 404, because `users` is not in `orders`' `allow`:

```bash
armada app exec users -- wget -qO- http://orders/healthz
# wget: server returned error: HTTP/1.1 404 Not Found
```

(Use whatever HTTP client your images have; `wget` and `curl` are common.)

### Scaling internal services

Internal apps scale like public ones, and the proxy counts their requests
too, so `http` autoscaling rules work for them:

```bash
armada app update orders --min 2 --max 8 --scale-http 40
```

`min: 0` works as well: an internal app at zero wakes on the first request
to its internal name. See [Autoscaling and scale to
zero](autoscaling-and-scale-to-zero.md).

## Case B: a shared cache over TCP

Redis speaks its own protocol over TCP, not HTTP. `protocol: tcp` makes an
internal app take plain TCP at `NAME.PROJECT.internal:PORT`.

Generate a password and give it to the cache and to each caller. Secrets
belong to one app, so each caller gets the cache's URL as its own secret:

```bash
PASSWORD=$(openssl rand -hex 24)
printf %s "$PASSWORD" | armada secret set cache redis-password
for app in orders users; do
  printf 'redis://:%s@cache:6379/0' "$PASSWORD" | armada secret set "$app" redis-url --no-rollout
done
unset PASSWORD
```

```yaml
# cache.yaml
name: cache
image: redis:7-alpine
command: ["sh", "-c", "exec redis-server --requirepass \"$REDIS_PASSWORD\" --save '' --appendonly no"]
env:
  - name: REDIS_PASSWORD
    secretRef: redis-password
ingress:
  type: internal
  protocol: tcp
  port: 6379
  allow: [orders, users]
resources:
  memory: 512Mi
```

```bash
armada app create --file cache.yaml --wait
```

```
$ armada app show cache
Name:     cache.shop
...
URLs:     tcp://cache.shop.internal:6379
```

Then give the callers the URL as a variable (each update rolls the app
out):

```bash
armada app update orders --secret-env REDIS_URL=redis-url
armada app update users --secret-env REDIS_URL=redis-url
```

Things to know about TCP apps:

- **Never reachable from outside.** Each node's proxy listens for them only
  on the node's container bridge, which only that node's containers reach.
- **One app per port and project.** A second app of `shop` on port 6379 is
  refused; another project may use 6379 for its own app.
- **`allow` closes the connection** of any other caller at once.
- **Long connections.** A connection with no data in either direction for an
  hour is closed, and so is one opened before a proxy reload, at most an
  hour after it. Turn on TCP keepalives in the client, or let it reconnect.
- **Armada's own ports are refused:** 22, 53, 80, 443, 2379, 2380, 4789,
  7443, 7444, 7480, 8404, and 51820.
- **One replica.** This cache keeps no data, and every connection may land
  on a different replica, so more replicas would be separate caches. Keep a
  cache like this at one replica. For data that must survive restarts,
  give the app a volume (see [An app with a PostgreSQL
  database](app-with-a-database.md)).

## Case C: two teams, two projects

The shop team runs `web`, `orders`, `users`, and `cache` in `shop`. The
payments team runs its services in `payments`. Neither should be able to
reach, or break, the other's services.

```bash
armada project create payments
```

What projects give you, on a cluster with the cluster network:

- **Separate names.** Both teams may have an app called `api`; their IDs
  are `api.shop` and `api.payments`.
- **Separate networks.** A container in `payments` resolves no name of
  `shop` and is refused by the proxy for `shop`'s internal apps, TCP apps
  included. Calling another project's app directly by address is dropped.
- **Kept away from the platform.** Containers of every project except
  `default` reach the internet, their node's DNS server, and Armada's
  ingress, and nothing else: not the nodes, not the private network, not
  the cloud's metadata service.
- **Separate rights.** Give each team a role in its own project only:

  ```bash
  armada rbac user create ana -o ana.config --role deployer --project shop
  armada rbac user create budi -o budi.config --role deployer --project payments
  ```

  Ana deploys and reads logs in `shop`, and sees nothing of `payments`. See
  [Teams and access](teams-and-access.md) for the other roles.

- **Usage per project.** `armada app top --projects` shows what each
  project's replicas use and reserve, with its requests and egress.

### When teams must talk to each other

Internal names do not cross projects. If `shop` calls `payments`, either:

- **Put the services that call each other in one project.** Projects are
  for things you want kept apart; services that work as one belong
  together.
- **Or call the other team's public API**: make the `payments` service
  `type: external` and have it authenticate its callers, with a token as a
  secret of each caller. External apps of a project without a custom domain
  are at `https://NAME.PROJECT.<root domain>`.

Projects share each node's kernel. They separate services you operate; they
do not contain code someone hostile wrote. For that, use restricted nodes
or a separate cluster.

## Check that it works

- `armada app list` shows every service ready.
- From each caller, the names it should reach answer; from an app not in
  `allow`, HTTP gets a 404 and TCP connections are closed.
- From an app of `payments`, `orders.shop.internal` does not resolve
  (`armada app exec api --project payments -- nslookup orders.shop.internal`,
  if its image has `nslookup`).
- `armadad doctor` on a node reports the `isolation` check as `ok`.

## Troubleshooting

| What you see | Why | What to do |
| --- | --- | --- |
| `orders.internal` does not resolve | Outside `default` the name includes the project | Use `orders.shop.internal` |
| A caller gets 404 from an internal app that runs | The caller is not in the app's `allow`, or is in another project | Add it to `allow`, or move it into the project |
| A TCP client is disconnected right after connecting | The caller is not in `allow` | Add it to `allow` |
| Calling a replica's address (`10.120.x.y:8080`) times out | Direct traffic between apps is dropped | Use the internal name |
| `create` with `protocol: tcp` is refused | No cluster network, the port is Armada's own, or another app of the project has the port | Pick another port, or create the cluster with the cluster network |
| An app in another project cannot reach a server on the private network | Projects other than `default` are isolated from the private network | Run that service as an app, or use `default` (with its isolation off) for apps that need the private network |
| Connections to a TCP app drop after an idle hour | Idle connections close after an hour | Use TCP keepalives or reconnect |

## Next steps

- [An app with a PostgreSQL database](app-with-a-database.md): a TCP app
  with a volume and backups.
- [Workers that scale on a queue](background-workers.md): workers that read
  a queue in the shared Redis.
- [Teams and access](teams-and-access.md): users, roles, and projects.
- Reference: [`ingress`](../spec-reference.md#ingress),
  [Projects](../operations.md#projects),
  [ADR 0026](../adr/0026-projects-and-network-isolation.md),
  [ADR 0039](../adr/0039-internal-tcp-ingress.md).

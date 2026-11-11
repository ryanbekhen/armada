# Deploy a web app with a custom domain

Take your own container image from nothing to an app on its own domain with
HTTPS, then update it, watch the rollout, roll back, and keep its spec in
git. This is the guide to follow for the first real app on a new cluster.

**You will use:** [`armada app create`](../cli/armada-app.md#armada-app-create),
[external ingress](../spec-reference.md#ingress),
[custom domains](../cli/armada-domain.md),
[readiness probes](../spec-reference.md#probes),
[rolling updates and rollbacks](../cli/armada-app.md#armada-app-rollback),
[spec export](../cli/armada-app.md#armada-app-show)

**Before you start:**

- A running cluster with a root domain and an ACME email set (see the
  [quickstart](../quickstart.md), steps 1 to 6). This guide uses the root
  domain `apps.example.com`.
- An image of your app that serves HTTP on one port and answers a health
  check. Here: `ghcr.io/acme/shop:1.4.2`, listening on port 8080, with
  `GET /healthz` returning `200` once it can serve. A private image needs
  registry credentials first: see [private-registry.md](private-registry.md).
- A domain whose DNS you control. Here: `shop.example.com`.

## The setup

```
                       ┌─ node1: HAProxy :443 ──▶ shop replica
 https://shop.example.com
                       └─ node2: HAProxy :443 ──▶ shop replica
```

Every node runs HAProxy on ports 80 and 443 and routes requests for the
app's names to its ready replicas. Point DNS at every node that should take
traffic.

## 1. Create the app

```bash
armada app create shop \
  --image ghcr.io/acme/shop:1.4.2 \
  --port 8080 \
  --ingress external \
  --replicas 2 \
  --health-path /healthz \
  --env LOG_LEVEL=info \
  --wait
```

```
Created shop (revision shop--r1).
shop--r1: 0/2 ready
shop--r1: 1/2 ready
shop--r1 is live (2/2 ready)
```

- `--port` is the port your process listens on inside the container.
  Armada also sets `PORT` to it.
- `--ingress external` makes the app reachable from the internet over
  HTTPS. Use `internal` for an app only other apps call, and `none` for an
  app with no traffic, such as a worker.
- `--health-path` sets the readiness probe. A replica gets requests only
  once the probe passes, and during an update the old replicas keep serving
  until the new ones are ready. Without it, Armada only checks that the port
  accepts connections.
- `--wait` waits until every replica is ready, and fails if the rollout is
  aborted.

The image tag is resolved to a digest on the first deploy, so every replica
of `shop--r1` runs exactly the same image, even if the tag moves later.

## 2. Check it

```bash
armada app show shop
```

```
Name:      shop
Revision:  shop--r1
Image:     ghcr.io/acme/shop:1.4.2
Ready:     2/2
Ingress:   external
URLs:      https://shop.apps.example.com/

REPLICA        REVISION  NODE   STATE    RESTARTS  ADDRESS           MESSAGE
shop-r1-5muie  shop--r1  node1  running  0         10.120.0.14:8080  -
shop-r1-q2k0d  shop--r1  node2  running  0         10.120.1.9:8080   -
```

The app already has a URL under the root domain, with a certificate of its
own:

```bash
curl https://shop.apps.example.com/    # add -k while the cluster uses the ACME staging CA
```

## 3. Add your own domain

Add the domain to the app:

```bash
armada app update shop --domain shop.example.com
```

The domain is not routed yet. Armada first wants proof that you own it.
`armada domain list` prints the TXT record to publish:

```bash
armada domain list
```

```
DOMAIN            APPS  VERIFIED  TLS
shop.example.com  shop  no        no

To verify ownership, create these DNS records (checked every minute):
  TXT  _armada-verify.shop.example.com  "3f9c2a7e0b14d6c8a5e9f1b2c4d7e8a0"
       last check: TXT record _armada-verify.shop.example.com not found
```

At your DNS provider, create two records:

```
_armada-verify.shop.example.com.  TXT  "3f9c2a7e0b14d6c8a5e9f1b2c4d7e8a0"
shop.example.com.                 A    203.0.113.10    # the public IP of every node
shop.example.com.                 A    203.0.113.11
```

A `CNAME` to a name that resolves to your nodes works as well as the `A`
records. Armada checks the TXT record every minute. To check it now:

```bash
armada domain verify shop.example.com
```

```
DOMAIN            APPS  VERIFIED  TLS
shop.example.com  shop  yes       no
```

Once the domain is verified, every node routes it to the app and the
cluster requests a certificate for it from the ACME CA through HTTP-01, so
port 80 of your nodes must be reachable from the internet. `TLS` turns to
`yes` when the certificate is in place, usually within a minute. A verified
domain is not checked again.

```bash
armada domain list --app shop
curl https://shop.example.com/
```

`armada cluster events` shows the domain's `Verified` event and the
certificate's `Obtained` event, or `Failed` with the reason.

A domain belongs to one project. When you add it to an app of another
project, that project has to verify it again with a new token.

## 4. Update the image and watch the rollout

Every change is a new revision, rolled out replica by replica:

```bash
armada app update shop --image ghcr.io/acme/shop:1.4.3 --wait
```

```
Updated shop (revision shop--r3).
shop--r3: 0/2 ready
shop--r3: 1/2 ready
shop--r3 is live (2/2 ready)
```

(`shop--r2` was the domain change.) While it runs, `armada app show shop`
says `Rollout: rolling out shop--r3; shop--r2 serves until it is ready`, and
lists the replicas of both revisions. Replicas of the old revision keep
serving until the new ones are ready, then drain: they take no new requests
and stop after `drain` (10 seconds by default).

If the new replicas never become ready, the rollout fails and the old
revision keeps serving. `--wait` then exits non-zero:

```
Error: rollout of shop--r3 failed: shop--r3 made no progress within ...; shop--r2 stays active
```

To follow what happens, in another terminal:

```bash
armada app events shop -f
```

## 5. Read logs and run commands

```bash
armada app logs shop                 # the last 100 lines of each replica, prefixed with its ID
armada app logs shop -f              # keep streaming
armada app logs shop --replica shop-r3-8xk2p --tail 500
armada app exec shop -- env          # one command in a ready replica
armada app exec shop -it -- sh       # a shell, if the image has one
```

`exec` runs with the container's own user and security settings, and what
you change inside a container is lost when its replica is replaced. Use it
to look around, and change the image or the spec to fix things. Each
session is recorded in the audit log with the command's name, never its
arguments.

## 6. Roll back

```bash
armada app revision list shop
```

```
REVISION  STATUS  CREATED              IMAGE                    PLATFORMS    DIGEST
shop--r1  -       2026-11-10 09:12:04  ghcr.io/acme/shop:1.4.2  linux/amd64  sha256:4b1d...
shop--r2  -       2026-11-10 09:20:47  ghcr.io/acme/shop:1.4.2  linux/amd64  sha256:4b1d...
shop--r3  active  2026-11-10 10:02:31  ghcr.io/acme/shop:1.4.3  linux/amd64  sha256:9e0c...
```

```bash
armada app rollback shop --wait            # back to the revision before the active one
armada app rollback shop --to r1 --wait    # or to a given revision
```

A rollback is a rolling update to a stored revision, with its pinned image
digest, so it runs exactly what ran before. During a rollout, `armada app
rollback shop` without `--to` cancels it instead.

A rollback lasts until the next update. If the next update is made from
flags, it starts from the spec the app runs after the rollback.

## 7. Keep the spec in git

Flags are quick, but a file in your repository is the record of what runs.
Export the spec the app runs now:

```bash
armada app show shop -o yaml > shop.yaml
```

```yaml
kind: app
name: shop
image: ghcr.io/acme/shop:1.4.3
env:
  - name: LOG_LEVEL
    value: info
ingress:
  type: external
  port: 8080
  domains:
    - shop.example.com
revisions:
  mode: single
probes:
  readiness:
    path: /healthz
    port: 8080
    period: 10s
    timeout: 1s
    failureThreshold: 3
scale:
  min: 2
  max: 2
resources:
  memory: 256Mi
```

The export spells out the defaults (`kind`, `revisions`, the probe's
timing, the memory limit), so the file says exactly what runs. Edit it for
what flags cannot set, for example a liveness probe, a faster readiness
check, CPU, more memory, and a longer drain for slow requests:

```yaml
kind: app
name: shop
image: ghcr.io/acme/shop:1.4.3
env:
  - name: LOG_LEVEL
    value: info
ingress:
  type: external
  port: 8080
  domains:
    - shop.example.com
    - www.example.com
revisions:
  mode: single
probes:
  readiness:
    path: /healthz
    port: 8080
    period: 5s
    timeout: 1s
    failureThreshold: 3
  liveness:
    path: /livez
    port: 8080
    period: 10s
    timeout: 1s
    failureThreshold: 3
scale:
  min: 2
  max: 2
resources:
  cpu: 500m
  memory: 512Mi
drain: 30s
```

See what an update would change, then apply it:

```bash
armada app update shop --file shop.yaml --diff
```

```
    port: 8080
    domains:
      - shop.example.com
+     - www.example.com
  revisions:
    mode: single
  probes:
    readiness:
      path: /healthz
      port: 8080
+     period: 5s
+     timeout: 1s
+     failureThreshold: 3
+   liveness:
+     path: /livez
+     port: 8080
      period: 10s
      timeout: 1s
      failureThreshold: 3
@@
    min: 2
    max: 2
  resources:
-   memory: 256Mi
+   cpu: 500m
+   memory: 512Mi
+ drain: 30s
```

`+` lines are added, `-` lines removed, and `@@` separates parts of the
file that are far apart.

```bash
armada app update shop --file shop.yaml --wait
```

`--diff` changes nothing; it prints `No changes.` when the file matches.
`--file` replaces the whole spec: a field left out of the file goes back to
its default, and a change someone made with flags since you exported is
undone unless it is in the file. Run `--diff` first, and make changes in the
file from now on. `www.example.com` is new, so verify it as in step 3.

The same file creates the app on another cluster with
`armada app create --file shop.yaml`.

## 8. Delete the app

```bash
armada app delete shop --yes
```

```
Deleting shop: it is gone once its replicas have drained.
```

The app stops taking requests at once, its replicas drain, and then it is
deleted with its revisions and secrets. This cannot be undone. Its volumes,
if it had any, stay until `armada volume delete`.

## Check that it works

- `armada app show shop` shows `Ready: 2/2` and both URLs.
- `armada domain list --app shop` shows `VERIFIED yes` and `TLS yes`.
- `curl -sI https://shop.example.com/` answers from your app, and
  `curl -sI http://shop.example.com/` redirects to HTTPS.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `VERIFIED no`, `last check: TXT record ... not found` | The TXT record is missing, has another name, or has not propagated | Create `_armada-verify.<domain>` exactly as printed, wait for DNS, run `armada domain verify <domain>` |
| `last check: ... does not contain the expected token` | The record holds another value, for example from an earlier attempt or another project | Copy the value `armada domain list` prints now |
| `VERIFIED yes`, `TLS no` for more than a few minutes | The ACME CA cannot reach port 80 of the node the domain points to, or the domain does not point at your nodes | Check the `A` records and the firewall; `armada cluster events` shows the certificate's `Failed` event with the reason |
| Browser warns about the certificate | The cluster uses `letsencrypt-staging` | `armada cluster set --acme-ca letsencrypt` once everything works |
| `--wait` ends with `rollout of ... failed` | New replicas never became ready: crash, wrong port, failing probe | `armada app show shop` (the replica's message), `armada app logs shop`, `armada app events shop`; the old revision keeps serving meanwhile |
| Replicas stay `running (not ready)` | The readiness probe fails, or the app listens on another port than `--port` | `armada app exec shop -- wget -qO- localhost:8080/healthz` (if the image has `wget`), then fix the path or port |
| `Placement:` line in `app show`, replicas not placed | No node has room for the replicas' CPU or memory, or none matches `placement` | Lower `resources`, add a node, or check `armada node top` |
| `Error: shop exists; change it with update` | `app create` refuses an existing name | `armada app update shop ...` |
| `Error: shop changed since shop--r3 (now shop--r4); run the command again` | Someone deployed between reading and writing the spec (flag updates only) | Run the command again; it starts from the new spec |

## Next steps

- [spec-files-and-environments.md](spec-files-and-environments.md): one spec
  for staging and production, with secrets.
- [canary-releases.md](canary-releases.md): send a share of requests to a new
  revision first.
- [autoscaling-and-scale-to-zero.md](autoscaling-and-scale-to-zero.md):
  scale with load.
- [app-with-a-database.md](app-with-a-database.md) and
  [ci-cd.md](ci-cd.md).
- The [spec reference](../spec-reference.md) lists every field.

# Troubleshoot apps, nodes, and the network

Something does not work and you want to find out why. This guide starts
with the few commands that show most problems, then goes through the
common ones: what you see, how to confirm it, and how to fix it. Event
reasons and messages are quoted as Armada prints them, so you can search
this page for what your terminal shows.

**You will use:** [`armada app show`](../cli/armada-app.md#armada-app-show),
[events](../operations.md#events), [`armada app logs`](../cli/armada-app.md#armada-app-logs),
[`armada app exec`](../cli/armada-app.md#armada-app-exec),
[`armadad doctor`](../cli/armadad-doctor.md)
**Before you start:** access to the space the app is in. Node and
network problems need `cluster-admin` and a shell on the node.

## First look

```bash
armada cluster status            # one line, then apps and nodes that are not ready
armada app show api              # revision, Ready, Rollout, Placement, and each replica's message
armada app events api            # what happened to it in the last hour (--since 24h for more)
armada app logs api --tail 200   # what the app printed (--replica ID, --container NAME, -f)
armada app logs api --since 2h --grep error   # its history, replicas that are gone included
armada cluster events            # everything, with nodes and certificates (cluster-admin)
sudo armadad doctor              # on a node: runtime, network, firewall, certificates, clock
```

`armada app show` answers most questions. The lines to read:

```
Name:       api
Revision:   api--r7
Image:      ghcr.io/acme/api:1.4.3
Ready:      2/3
Ingress:    external
Rollout:    api--r8 failed, api--r7 kept serving: no progress within 3m30s; api-r8-q2k0d: readiness probe failed: HTTP 500
Placement:  waiting for a node: 2 node(s) may run the app, none has 512Mi of memory free

REPLICA       REVISION  NODE   STATE                RESTARTS     ADDRESS           MESSAGE
api-r7-5muie  api--r7   node1  running              0            10.120.1.7:3000   -
api-r7-k3j9a  api--r7   node2  running              0            10.120.2.4:3000   -
api-r8-q2k0d  api--r8   node1  running (not ready)  0            10.120.1.9:3000   readiness probe failed: HTTP 500
```

- `Rollout` appears while a revision rolls out, and after one failed.
- `Placement` appears when replicas wait for a node, and says why.
- `MESSAGE` is what the replica's node reports: probe failures, exit codes,
  pull errors.

## App never becomes ready

**You see:** replicas `running (not ready)`, or `exited` with `RESTARTS`
going up; `Ready: 0/2`; `NotReady`, `Crashed`, or `Restarted` events.

**Confirm:**

```bash
armada app show api                       # the MESSAGE column
armada app logs api --replica api-r8-q2k0d --tail 200
armada app exec api --replica api-r8-q2k0d -- wget -qO- http://127.0.0.1:3000/healthz   # if the image has wget
```

| Message | Cause | Fix |
| --- | --- | --- |
| `readiness probe failed: HTTP 500` (or 404, 503) | The probe path answers with an error, or does not exist | Fix the endpoint, or point `probes.readiness.path` (`--health-path`) at one that answers 2xx or 3xx |
| `readiness probe failed: dial tcp 10.120.1.9:3000: connect: connection refused` | The app does not listen on `ingress.port`, or listens on 127.0.0.1 only | Listen on `0.0.0.0` and the port Armada sets in `PORT`, or set `--port` to the port the app uses |
| `readiness probe failed: ... context deadline exceeded` | The probe takes longer than its `timeout` (1s by default) | Make the endpoint cheaper, or raise `timeout` |
| `startup probe failed: ...` or `liveness probe failed: ...`, with restarts | A failing startup or liveness probe recreates the container | A slow start needs a `startup` probe with enough `failureThreshold` × `period`; keep liveness checks cheap |
| `exited with code 1; restarting in 8s` | The process exits: a crash, a missing variable, a failed connection | Read `armada app logs`; the delay doubles up to 5 minutes |
| `init container migrate exited with code 1` | An init container failed, so the app never starts | `armada app logs api --container migrate` |
| `this node cannot mount secret files: ...` | The node has no tmpfs secrets directory | `armadad doctor` on that node (`secrets-tmpfs`) |

A spec with probes sized for a slow start:

```yaml
# api.yaml
name: api
image: ghcr.io/acme/api:1.4.2
ingress:
  type: external
  port: 3000
probes:
  startup:
    path: /healthz
    period: 5s
    failureThreshold: 60      # up to 5 minutes to start
  readiness:
    path: /ready
    period: 5s
    timeout: 2s
  liveness:
    path: /healthz
    period: 10s
    timeout: 2s
resources:
  memory: 512Mi
```

Without a readiness probe, a replica is ready once its port accepts TCP
connections. See [`probes`](../spec-reference.md#probes).

## Rollout failed

**You see:** `armada app update --wait` exits with `rollout of api--r8
failed, api--r7 keeps serving: ...`; a `Failed` event of kind `rollout`;
`Rollout: api--r8 failed, api--r7 kept serving: ...` in `armada app show`;
`armada_app_rollout{state="failed"}` is 1.

**What happened:** the new revision made no progress (no new replica became
ready) within 3 minutes plus the time its startup and readiness probes may
take. Armada stopped the rollout and the old revision kept serving the
whole time: users saw nothing. The message names one replica and its last
message, which points to one of the sections on this page (not ready,
image pull, no node).

**Fix:** fix the cause and deploy again. To return to an older revision on
purpose, `armada app rollback api --to r6 --wait`. While a rollout is still
in progress, `armada app rollback api` cancels it.

## Image pull fails

**You see:** replicas `failed`, a `Failed` replica event, and a message
that starts with `pull` and the image, such as
`pull ghcr.io/acme/api:1.4.3: ...`.

| In the message | Cause | Fix |
| --- | --- | --- |
| `401`, `403`, `unauthorized`, `denied` | No credentials, or wrong ones, for a private image | Set `registry` and its password secret (see [private registry](private-registry.md)); check `registry.server` |
| `not found` | The tag does not exist, or the repository name is wrong | Check the tag; push it before you deploy |
| A timeout or name resolution error | The node cannot reach the registry | Check the node's outbound network and DNS |

A replica that keeps failing to start for a minute (outside a rollout) is
replaced on another node, so one node's network problem does not keep an
app down. Init container and sidecar images are pulled with the app's
`registry` credentials only when they are on the same registry.

### Image built for another platform

**You see:** `image ghcr.io/acme/api:1.4.3 has no linux/arm64 variant (it
has linux/amd64)`, then `Placement: waiting for a node: no ready node can
run the image, which is built for linux/amd64`.

The first node that pulls an image reports which platforms it has, and the
app then runs only on nodes that match; `armada app revision list api`
shows them (`PLATFORMS`). Build a multi-platform image, or keep the app on
matching nodes with `placement.require: {armada.arch: amd64}`.

## Replicas wait for a node

**You see:** an `Unschedulable` event with `no node can fit another replica
(1 of 3 placed); see armada node top`, and a `Placement` line in
`armada app show`.

| Placement message | Cause | Fix |
| --- | --- | --- |
| `waiting for a node: 2 node(s) may run the app, none has 512Mi of memory free` (or CPU, or both) | Every allowed node's capacity is reserved | `armada node top`; lower `resources`, scale something down, or add a node |
| `no ready node matches the placement (tier=shop)` | No ready node carries the labels `placement.require` asks for | `armada node list` (`LABELS`); `armada node label NODE tier=shop` |
| `no ready node accepts the app (every ready node is cordoned or restricted)` | Nodes are drained, or restricted to apps that name their labels | `armada node resume NODE`, or name the restricted node's label in `placement.require` |
| `no ready node can run the image, which is built for ...` | See [image built for another platform](#image-built-for-another-platform) | |
| `... each already runs 250 replicas` | Each node has room for 250 replicas, whatever its size | Add a node |

```bash
armada node top
```

```
NODE   REPLICAS  CPU USED  CPU RESERVED  MEMORY USED  MEMORY RESERVED
node1  9         610m      1700m/1800m   2.9Gi        3.5Gi/3.6Gi
node2  8         540m      1600m/1800m   2.7Gi        3.4Gi/3.6Gi
```

Nodes are never overcommitted: a replica reserves its `resources.cpu`
(100m by default) and `resources.memory` (256Mi by default), and only
starts where both fit. Armada keeps 100m of CPU and 128Mi of memory on
every node for itself, and another 100m on control plane servers. Replicas
with sidecars reserve those too. During a rollout, the new revision needs
room next to the old one until old replicas leave.

## Out of memory

**You see:** a replica message `out of memory at its limit, exited with
code 137; restarting in 4s`, restarts going up, or an `OutOfMemory` event
`processes killed at the memory limit: 1` (a child process was killed and
the container kept running, as with nginx workers).

**Confirm:**

```bash
armada app top api      # MEMORY used/limit per replica
armada app events api
```

**Fix:** raise the limit, which is also what the replica reserves:

```bash
armada app update api --memory 1Gi --wait
```

Or make the app use less (a smaller heap, fewer workers). Memory counts
what the app's processes use, without page cache the kernel can reclaim.

## Certificate not issued

**You see:** the browser warns about the certificate, `armada domain list`
shows `TLS no`, or `armada cluster events` shows a `Failed` event of kind
`certificate` with the ACME error.

Check, in this order:

1. **Staging CA.** `armada cluster show`. With `letsencrypt-staging`,
   certificates are issued but not trusted. Switch when ready:
   `armada cluster set --acme-ca letsencrypt`.
2. **The domain is verified** (custom domains only, see the next section).
   Names under the root domain need no verification.
3. **DNS points at your nodes.** The name must resolve to the public IPs of
   nodes that run Armada's proxy.
4. **HTTP-01 reaches a node.** Without a DNS provider, Let's Encrypt
   fetches `http://<domain>/.well-known/acme-challenge/...`: port 80 must be
   open from the internet on every node the name points to, and nodes must
   reach the leader's private address on port 7480, where challenges are
   answered.
5. **DNS-01 with Cloudflare** (the root domain and names under it, when
   `--dns-provider cloudflare` is set): the token needs `Zone / DNS / Edit`
   and `Zone / Zone / Read` on the zone. Set it again from stdin with
   `armada cluster set --dns-token -`.
6. **Rate limits.** Repeated failures against Let's Encrypt production hit
   its rate limits. Test with `letsencrypt-staging` first.

The leader keeps trying and renews certificates about 30 days before they
expire, so a fixed cause is picked up without a deploy.

## Domain not verified

**You see:** `armada domain list` shows `VERIFIED no`, the domain is not
routed, and a `NotVerified` event of kind `domain` says
`TXT record _armada-verify.www.example.com not found` or
`... does not contain the expected token`.

```bash
armada domain list
```

```
DOMAIN           APPS  VERIFIED  TLS
www.example.com  web   no        no

To verify ownership, create these DNS records (checked every minute):
  TXT  _armada-verify.www.example.com  "..."
       last check: TXT record _armada-verify.www.example.com not found
```

Publish the TXT record exactly as printed, wait for DNS to serve it
(`dig +short TXT _armada-verify.www.example.com`), then check now instead
of waiting a minute:

```bash
armada domain verify www.example.com
```

A domain serves one space. A deploy that names a domain an app of
another space uses is refused, and a domain another space left behind
needs a new TXT record.

## 403 from an app with ipAllow

**You see:** clients you expect to let in get `403 Forbidden` from the
proxy; the app's logs show nothing (the app never sees refused requests).

The proxy checks the connection's own address, or, only when the
connection comes from a trusted proxy, the **last** address in
`X-Forwarded-For`. No other header counts.

| Cause | Fix |
| --- | --- |
| A CDN or load balancer sits in front, and its ranges are not trusted, so every client looks like the CDN | `armada cluster set --trusted-proxies RANGE,...` with its published ranges |
| A trusted proxy sends no valid `X-Forwarded-For` | Make the proxy append the client address; Armada fails closed |
| The client's address changed (a new office IP, IPv6 instead of IPv4) | `armada app show APP` lists the rules; add the range with `--ip-allow` (each flag replaces the whole list) |

Check from the client: `curl -s -o /dev/null -w '%{http_code}'
https://admin.example.com/`. Calls through `<app>.internal` are not
affected; `ingress.allow` chooses those. See
[behind a CDN](behind-a-cdn.md).

## CORS errors in the browser

**You see:** the browser console says the response has no
`Access-Control-Allow-Origin` header, or a preflight (`OPTIONS`) fails,
while `curl` works.

With `ingress.cors`, the proxy answers preflight requests itself and adds
the headers to responses for listed origins only. Check:

| Cause | Fix |
| --- | --- |
| The page's origin is not listed exactly (scheme, host, and port: `https://app.example.com`, `http://localhost:3000`) | `armada app update api --cors-origin https://app.example.com` (replaces the origins) |
| The request uses a method outside `GET, HEAD, POST` | Add it to `allowMethods` in the spec |
| The request sends a header the browser must ask about (`Authorization`, `Content-Type: application/json`) | Add it to `allowHeaders` |
| The page sends cookies or credentials | `allowCredentials: true`, which does not work with `*` |
| The page reads a response header | Add it to `exposeHeaders` |

```bash
curl -si -X OPTIONS https://api.example.com/v1/orders \
  -H 'Origin: https://app.example.com' -H 'Access-Control-Request-Method: PUT' | head -20
```

A listed origin gets `204` with `Access-Control-Allow-*` headers. See
[`ingress.cors`](../spec-reference.md#ingress) and
[a SPA and its API](spa-and-api.md).

## An app with volumes is down

**You see:** one of these events for the app:

| Reason | Message | Fix |
| --- | --- | --- |
| `VolumeUnavailable` | `its volumes are on node node2, which is unreachable or removed; it stays down until the node returns or a volume backup is restored on another node (armada volume restore --node)` | Bring the node back, or restore elsewhere (below) |
| `VolumeUnavailable` | `... their latest backups are being restored on another node (failover: restore)` | Wait for `VolumeFailedOver` |
| `VolumeFailoverFailed` | why, then `trying again in 5m0s` | No backup yet, no node with room, or the bucket refuses: fix that |
| `VolumeOnCordonedNode` | `node node2 is cordoned, but the app keeps running there because its volumes are on it` | Nothing to fix; apps with volumes do not move off drained nodes |
| `VolumesSplit` | `its volumes are bound to different nodes; restore them onto one node (armada volume restore --node)` | Restore every volume onto one node |

An app with volumes on its node runs one replica, bound to that node. When
the node is gone for good:

```bash
armada node delete node2 --force
armada volume restore db data --snapshot latest --node node3   # from the volume's bucket
```

The restore is refused while the old node is still connected. Writes after
the backup are lost. See [disaster recovery](disaster-recovery.md).

Deploys of such apps have a short downtime (the old replica stops before
the new one starts); that is expected, not a failure.

## Node not ready or lost

**You see:** `armada node list` shows a node `unknown` or `lost`;
`Disconnected`, then `Lost` (`no contact for 5m0s; moving its replicas`)
events; `armada_node_ready` is 0.

After the node-lost timeout (5 minutes by default), the node's replicas
start on other nodes. On the node:

```bash
systemctl status armada-agent       # armada-server on a control plane server
journalctl -u armada-agent -n 100
sudo armadad doctor
```

| Cause | Fix |
| --- | --- |
| The machine is down or off the network | Bring it back; its old containers are cleaned up and replicas move back over time |
| The agent cannot reach a server on port 7443 over the private network | Check the provider firewall between the node and the servers |
| The node certificate expired (`CERT EXPIRES` in `armada node list`): a node off for more than 30 days | `armada node delete NODE`, then join it again |
| The clock is off (`clock` in doctor) | Turn on NTP |
| The embedded runtime is down (`runtime` in doctor) | `systemctl status armada-runtime` |

A `MostUnreachable` event (`... nodes lost and ... ready: not moving their
replicas (is the control plane cut off?)`) means more than half the nodes
dropped at once. Armada assumes the control plane is the one cut off and
moves nothing until enough nodes are back; check the control plane's
network first. To move replicas off nodes that are really gone, delete them
with `armada node delete NODE --force`.

## Cluster network problems

**You see:** requests that land on one node fail or time out when the
replica is on another node, `<app>.internal` works on some nodes only, or
large responses stall while small ones work.

Run doctor on the nodes involved:

```bash
sudo armadad doctor
```

```
[ok  ] network        armada-net routes 2 other node subnet(s) over VXLAN (UDP 4789 on 10.0.0.5, open it to the other nodes)
[ok  ] network-mtu    eth1 has MTU 1450; the tunnel and containers use 1400
[ok  ] isolation      the nftables tables that keep apps and spaces apart are in place
```

| Doctor says | Cause | Fix |
| --- | --- | --- |
| `network` routes fewer subnets than you have other nodes, or `... have no recent handshake ...; allow UDP 51820 between the nodes` | The tunnel port is blocked between nodes | Allow UDP 4789 (`plain`) or UDP 51820 (`wireguard`) between the nodes' private addresses |
| `armada-net is not set up yet` | The agent has not connected since joining | Check the agent (previous section) |
| `the kernel has no WireGuard: the agent runs it in userspace` | No kernel WireGuard | Works, but slower; use a kernel with WireGuard |
| `network-mtu` failure, or large transfers stall | The private interface's MTU leaves too little for the tunnel's overhead (50 bytes in `plain`, 80 in `wireguard`) | Raise the MTU of the private interface; containers created earlier keep their old MTU until they are replaced |
| `isolation` failure | The nftables tables are missing | The kernel needs nf_tables; restart the agent |
| `subnet` failure: `container subnet ... overlaps route ...` | The node's container subnet clashes with a route on the machine | Remove the clashing route (the cluster CIDR is chosen once, at `armadad init`) |

Isolation is not a fault: a container reaches another app only through its
internal name, resolves only its own space's names, and gets `404` from
the proxy for apps of other spaces or apps whose `ingress.allow` leaves
it out. If `armada app exec web -- wget -qO- http://api.internal/` gets a
404, check that both apps are in the same space and that `allow` lists
the caller.

## Commands are refused

| Message | Fix |
| --- | --- |
| `user:alice may not see space billing` (or `deploy to`, `manage`) | Work in a space you hold a role in: `armada space use shop`; `armada rbac assignment list` (cluster-admin) |
| `user:alice has no role that allows ...` | The method needs a higher role; see [teams and access](teams-and-access.md) |
| `app api references secrets that are not set: ...` | `armada secret set api NAME` before you deploy |
| `api changed since api--r7 (now api--r8); run the command again` | Another change landed while the command ran; flag updates refuse to overwrite it. Run it again |

## Next steps

- [Monitoring and alerts](monitoring-and-alerts.md): find out before users do.
- [Disaster recovery](disaster-recovery.md): backups and lost machines.
- [Operations guide](../operations.md): how each part works.
- [Spec reference](../spec-reference.md): every field and its limits.

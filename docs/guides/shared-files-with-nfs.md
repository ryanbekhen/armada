# Share uploaded files between replicas with NFS

You will give a web app an uploads directory that every replica, on every
node, reads and writes: a file uploaded through one replica is served by
all of them. The data lives on an NFS server, so the app keeps its rolling
updates and may run any number of replicas.

**You will use:** [`volumes[].nfs`](../spec-reference.md#volumesnfs),
[NFS volumes in the operations guide](../operations.md#nfs-volumes), and
the `nfs` check of [`armadad doctor`](../cli/armadad-doctor.md).

**Before you start:**

- A running cluster (see the [quickstart](../quickstart.md)).
- An NFS server on the nodes' private network that exports a directory over
  NFSv4. Setting one up is outside this guide; step 1 says what Armada needs
  from it.
- A user with `cluster-admin` for the first deploy (step 3 explains why).

## Why NFS and not a volume on the node

A volume on the node ([ADR 0023](../adr/0023-persistent-volumes.md)) binds
an app to one node and to one replica, and a deploy stops the old replica
before the new one starts. That suits a database. It does not suit a web
app that should run three replicas on three nodes and roll out without
downtime.

An NFS volume keeps the data on the server instead:

| | Volume on the node | NFS volume |
| --- | --- | --- |
| Replicas | exactly 1 | any number, autoscaling included |
| Deploys | the old replica stops first: downtime | rolling updates |
| Nodes | bound to one node | any node with an NFSv4 client |
| Backups | `volumes[].backup` to a bucket | on the NFS server |
| Ownership | `owner` in the spec | the server's files and permissions |

```
                     https://web.example.com
                               |
          +--------------------+--------------------+
          v                    v                    v
   node1: web replica   node2: web replica   node3: web replica
      /app/uploads         /app/uploads         /app/uploads
          \                    |                    /
           +----------- NFSv4, TCP 2049 -----------+
                               |
                 10.0.0.20:/exports/uploads
```

## 1. Prepare the export

What Armada expects of the server:

- **NFSv4.** Nodes mount with version 4.2, then 4.1, then 4.0, over TCP.
  NFSv3 exports are not supported.
- **Exported to every node that may run the app**, by the nodes' private
  addresses. Nodes mount from their own addresses, not through the
  cluster network, and Armada's firewall does not stand between nodes and
  the server: the server's exports and firewall decide which nodes may
  mount what.
- **A private address.** The spec takes the server's IP address in
  10/8, 172.16/12, 192.168/16, 100.64/10, or fc00::/7. Host names and public
  addresses are refused.
- **Ownership that matches the image.** Containers act on the export with
  their own user and group IDs. If the app runs as uid 1000, give the
  exported directory to `1000:1000` on the server.
- **Root squash.** Servers usually map root to an anonymous user. An image
  that runs as root then writes as that anonymous user and is refused
  where it has no rights. Run the app as a non-root user and give the
  directory to that user.

On each node, check that its kernel has an NFSv4 client:

```
$ sudo armadad doctor
...
[ok  ] nfs            the kernel has an NFSv4 client: apps with NFS volumes may run here
```

A node that reports `warn` here gets no replicas of apps with NFS
volumes. Nothing else is needed on the node: the agent mounts through the
kernel directly, with no client package.

## 2. Write the spec

```yaml
# web.yaml
name: web
image: ghcr.io/acme/web:1.4.2
env:
  - name: UPLOAD_DIR
    value: /app/uploads
ingress:
  type: external
  port: 8080
  domains: [web.example.com]
probes:
  readiness:
    path: /healthz
scale:
  min: 3
volumes:
  - name: uploads
    path: /app/uploads
    nfs:
      server: 10.0.0.20
      path: /exports/uploads
```

- **`domains`** is served once you have verified the domain (see [Deploy a
  web app](deploy-a-web-app.md)); leave it out to use the app's URL under
  the root domain.
- **`nfs.server`** is the server's IP address, and **`nfs.path`** the
  exported directory, absolute.
- **No `owner`, `backup`, or `failover`.** They are refused for NFS
  volumes: the server owns the data.
- **`scale.min: 3`** is allowed because the app has no volume on a node. An
  app that has a volume on its node next to an NFS volume keeps the
  one-replica rules for the whole app.

## 3. Deploy it as a cluster-admin

```bash
armada app create --file web.yaml --wait
```

Adding an export to an app, or making an export writable, needs
`cluster-admin`. Nodes mount exports from their own addresses, so the NFS
server cannot tell one space from another: an export in a spec reaches
storage outside the cluster, and whoever may name one could read any
export the nodes may mount. A `deployer` who tries gets:

```
volume uploads: adding an NFS export (10.0.0.20:/exports/uploads) or making one writable needs cluster-admin, since it reaches storage outside the cluster
```

Once the app has the export, a `deployer` may deploy it again, with a new
image for example, as long as the deploy keeps the exports the app already
mounts, or makes one read-only. That keeps day-to-day deploys, from CI as
well, with the team, and new exports with the cluster's admins.

## 4. Share it read-only with another app

A second app can mount the same export. A thumbnailer that only reads the
uploads gets it read-only:

```yaml
# thumbnailer.yaml
name: thumbnailer
image: ghcr.io/acme/thumbnailer:0.9.0
ingress:
  type: internal
  port: 8080
volumes:
  - name: uploads
    path: /data/uploads
    nfs:
      server: 10.0.0.20
      path: /exports/uploads
      readOnly: true
```

With `readOnly: true`, the replica's mount is read-only, whatever the
server allows. Mounting the export in a new app still needs `cluster-admin`,
even read-only.

Init containers and sidecars may mount the export too, by naming the
volume in their `volumes` (see [Migrations and
sidecars](migrations-and-sidecars.md)). Jobs cannot have volumes.

## Check that it works

Write through one replica and read through another:

```
$ armada app show web
...
REPLICA          REVISION  NODE   STATE    RESTARTS  ADDRESS           MESSAGE
web-r1-5muie     web--r1   node1  running  0         10.120.1.12:8080  -
web-r1-q2k0d     web--r1   node2  running  0         10.120.2.9:8080   -
web-r1-x81na     web--r1   node3  running  0         10.120.3.17:8080  -
```

```bash
armada app exec web --replica web-r1-5muie -- sh -c 'date > /app/uploads/hello.txt'
armada app exec web --replica web-r1-x81na -- cat /app/uploads/hello.txt
armada app exec web -- id     # the uid and gid the app writes with
```

Then roll out a new image and watch the replicas change one at a time
while the files stay:

```bash
armada app update web --image ghcr.io/acme/web:1.4.3 --wait
armada app exec web -- ls /app/uploads
```

NFS volumes are not listed by `armada volume list`: Armada keeps no record
of them, since the server holds the data.

## Things to know

- **Concurrent writes are the app's job.** NFS does not order writes from
  several replicas. Use unique file names (a UUID per upload), write to a
  temporary name and rename, or lock.
- **When the server is away**, processes that read or write the export wait
  until it is back, instead of getting errors (a `hard` mount). Requests
  that touch files hang meanwhile, and continue afterwards. A server that is
  gone for good leaves them waiting until the replica is replaced.
- **A mount that takes over two minutes** fails the replica's start, which
  is retried with the same growing delay as a crash.
- **One mount per node.** Each node mounts an export once per app and
  volume, under `/var/lib/armada/nfs/<app>/<volume>`, and bind-mounts it
  into each replica with `nosuid` and `nodev`. When no replica on the node
  needs it any more, it is unmounted.
- **SELinux** hosts label the mount so containers may use it; nothing to do.
- **Backups** happen on the NFS server: Armada's volume backups are for
  volumes on nodes.
- **The export belongs to the app.** Exports are reached by address only,
  with no Kerberos. Once a cluster-admin gives an app an export, the app can
  read and write all of it with the IDs it runs as.

## Troubleshooting

| What you see | Why | What to do |
| --- | --- | --- |
| Deploy refused: `adding an NFS export ... needs cluster-admin` | You are not cluster-admin, and the deploy adds an export or makes one writable | Have a cluster-admin deploy it once; later deploys with the same exports need only `deployer` |
| Deploy refused on `nfs.server` | A host name, or an address outside the private ranges | Use the server's private IP address |
| Deploy refused on `owner` or `backup` | They do not apply to NFS volumes | Remove them; set ownership and backups on the server |
| `armada app show` says the app waits for a node | No ready node has an NFSv4 client | Run `armadad doctor` on the nodes and look at the `nfs` check |
| Replicas fail to start with `mount NFS export ...` | The server does not export the path to that node's address, NFSv4 is off, or a firewall blocks TCP 2049 from the node | Fix the export or firewall on the server; the start is retried |
| `Permission denied` when writing | The directory on the server belongs to another user, or root squash maps a root container to an anonymous user | Give the directory to the uid the image runs as (`armada app exec web -- id`) |
| Requests hang, logs stop | The NFS server is unreachable; the mount waits for it | Bring the server back; processes continue by themselves |
| An app with an NFS and a local volume runs one replica | A volume on the node keeps the one-replica rules | Move that data to NFS too, or keep one replica |

## Next steps

- [An app with a PostgreSQL database](app-with-a-database.md): volumes on
  the node, with backups and failover.
- [Migrations and sidecars](migrations-and-sidecars.md): helpers that share
  the app's volumes.
- [Teams and access](teams-and-access.md): who is `cluster-admin` and who
  is `deployer`.
- Reference: [`volumes[].nfs`](../spec-reference.md#volumesnfs),
  [NFS volumes](../operations.md#nfs-volumes),
  [ADR 0042](../adr/0042-nfs-volumes.md).

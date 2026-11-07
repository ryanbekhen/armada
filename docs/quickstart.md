# Quickstart

From empty machines to an app served over HTTPS. This guide uses three
Linux machines (cloud instances, VMs, or bare metal) on the same private
network; one is enough to start, and the others can join later as nodes or
as control plane servers.

> **Status.** Armada is pre-alpha. Every step below is exercised in a local
> lab (Linux VMs with Pebble as the ACME server), but not yet on a
> real cloud provider with Let's Encrypt. Start with the Let's Encrypt
> staging environment (step 4) and report what breaks.

## What you need

- Linux machines (amd64 or arm64) with a **private network** between them
  (VPC, private networking, vSwitch, or a LAN), each with a private IP.
- Nothing else to install: Armada brings its own container runtime
  (containerd, runc, and the CNI plugins, embedded in the binary). The
  kernel needs cgroup v2 (the default on current distributions) and
  overlayfs, and `iptables` must be installed. Other container software
  on the host is left alone.
- A domain whose DNS you control, for example `example.com`.
- Root access.

Ports:

| Port | Who must reach it |
| --- | --- |
| 80, 443/tcp | The internet (HAProxy on every node) |
| 7443/tcp | Every node, on the private network only (control plane API) |
| 7444/tcp | New nodes while they join, private network only |
| 2379, 2380/tcp | Other control plane servers only (embedded etcd) |
| 4789/udp | Every node, on the private network only (cluster network, `plain` mode) |
| 51820/udp | Every node, on the private network only (cluster network, `wireguard` mode) |

Never expose 7443, 7444, 2379, 2380, 4789, or 51820 to the internet. Armada binds them to the private
IP only, but on providers that map the public IP onto the private interface
(1:1 NAT), restrict them in the provider firewall as well.

## 1. Install

On every machine:

```bash
curl -fsSLO https://raw.githubusercontent.com/ryanbekhen/armada/main/install.sh
less install.sh     # read what you are about to run as root
sudo sh install.sh
```

The installer downloads the release for your architecture, verifies its
SHA-256 checksum, and, if [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
is installed, verifies that the checksums were signed by this repository's
release workflow. Set `ARMADA_REQUIRE_SIGNATURE=1` to refuse installing
without that signature, and `ARMADA_VERSION=v0.1.0` to pin a version. It
installs `/usr/local/bin/armada` and the systemd units
`armada-server.service` and `armada-agent.service` (not started).

On RHEL-family distributions (RHEL, Oracle Linux, Rocky, Alma), `sudo`
does not search `/usr/local/bin`; the installer warns about it. Install with
`ARMADA_PREFIX=/usr`, or run the commands below from a root shell
(`sudo -i`).

## 2. Check the host

```bash
sudo install -d -m 0700 /run/armada/secrets
sudo armada doctor
```

`doctor` checks the container runtime (cgroup v2, overlayfs, `iptables`,
whether SELinux can confine containers on SELinux hosts), the
private IP, ports listening publicly, file
permissions, the secrets tmpfs, the clock, the firewall, and how full the
connection tracking table is. Fix every
`FAIL`; read every `warn`. Secret files live under `/run/armada`, which
must be on tmpfs so plaintext never reaches a disk; `/run` is tmpfs on
systemd distributions, and the units recreate the directory at start.

If the host has several private addresses, pass the right one with
`--private-ip` here and in `init`/`join`.

## 3. Create the cluster (first machine)

```bash
sudo armada init
```

This creates the cluster CA, the certificates, the state (embedded etcd), the
secrets master key, and an admin config in `~/.armada/config`. Each node
gets its own container subnet, a /24 of `10.120.0.0/16`; if your network
uses that range, pick another private one with `--cluster-cidr` (it cannot
change later). Traffic between nodes' containers is not encrypted unless you
add `--network wireguard`, also fixed at init (see
[operations](operations.md#container-network)). Note the **CA SHA-256** it prints. Once the server runs, set up backups with
`armada backup` (see [operations](operations.md)): the data directory is the
cluster, and without `master.key` secrets cannot be recovered.

## 4. Start the control plane

```bash
sudo install -d -m 0700 /etc/armada
echo 'ARMADA_SERVER_FLAGS="--acme-email you@example.com --acme-ca letsencrypt-staging"' \
  | sudo tee /etc/armada/server.env
sudo systemctl enable --now armada-server
```

The first machine runs the control plane and an agent, so it also serves apps.
Once everything works, remove `--acme-ca letsencrypt-staging` and restart
to get trusted certificates.

## 5. Point DNS at your nodes

Apps with external ingress are served at `<app>.<root domain>`. The root
domain can be any domain you control: the zone itself (`example.com` gives
`hello.example.com`) or a subdomain that keeps Armada's apps apart from
your other records (`apps.example.com` gives `hello.apps.example.com`).
This guide uses `apps.example.com`.

Create a wildcard record pointing at the **public** IPs of your nodes, so
new apps work without touching DNS again:

```
*.apps.example.com.  A  203.0.113.10
*.apps.example.com.  A  203.0.113.11
```

Then tell Armada:

```bash
armada cluster set --root-domain apps.example.com
```

The wildcard is a convenience, not a requirement: an A record per app
(`hello.apps.example.com`) works the same. You can also skip the root
domain entirely and list each app's host names under `ingress.domains`
(see "Custom domain" below).

Each app gets its own certificate through HTTP-01. For a single wildcard
certificate, or when HTTP-01 cannot reach your nodes, start the server with
`--dns-provider cloudflare --dns-token-file /etc/armada/cloudflare.token` (a
`0600` file holding a Cloudflare API token). The root domain itself and every
name under it then use DNS-01; other custom domains keep HTTP-01. Create a custom token with the permissions
`Zone / DNS / Edit` and `Zone / Zone / Read`, limited to your zone, and
ideally with client IP filtering set to your control plane servers' public
IPs. Never paste the token on a command line; write the file with
`read -rs` or from the clipboard.

> **Cloudflare: use "DNS only" (grey cloud).** Armada terminates TLS on
> your nodes with its own Let's Encrypt certificates. With the Cloudflare
> proxy (orange cloud) in front, Cloudflare's free Universal SSL covers
> only `example.com` and `*.example.com`, so a two-level name such as
> `hello.apps.example.com` fails TLS at Cloudflare's edge unless you buy
> an advanced certificate. Proxying through Cloudflare is not tested with
> Armada yet. Other DNS providers have no such setting; plain A records
> are all Armada needs.

## 6. Deploy an app

```yaml
# hello.yaml
name: hello
image: traefik/whoami:v1.10
ingress:
  type: external
  port: 80
probes:
  readiness:
    path: /health
scale:
  min: 2
```

```bash
armada deploy -f hello.yaml
armada status hello
curl https://hello.apps.example.com    # add -k while on the staging CA
```

Change the image and deploy again for a rolling update. `armada revisions
hello` lists revisions and `armada rollback hello` returns to the previous
one. See the [spec reference](spec-reference.md) for every field.

## 7. Add nodes

On the first machine:

```bash
armada token create
```

It prints a single-use token (valid for one hour) and the exact `armada
join` command. On the new machine, after steps 1 and 2:

```bash
sudo armada join 10.0.0.2:7444 --ca-hash sha256:...   # paste the token when asked
sudo systemctl enable --now armada-agent
armada node list                                       # on the first machine
```

The token is read from a prompt, stdin, or `--token-file`, never from the
command line. The new node pins the CA by its hash, receives a 30-day
certificate that it renews on its own, and starts taking replicas.

## 8. Make the control plane highly available (optional)

One control plane server is fine to start with: if it goes down, apps keep
serving, but nothing can be changed until it is back. Three servers survive
the loss of any one. Add two more, one at a time, on machines prepared with
steps 1 and 2 (they also run apps, like the first):

```bash
armada token create --server                                 # on the first machine
sudo install -d -m 0700 /etc/armada                          # on the new machine:
sudo cp server.env /etc/armada/server.env                    #   the same flags as the first server
sudo armada server join 10.0.0.2:7444 --ca-hash sha256:...   #   paste the token when asked
sudo systemctl enable --now armada-server
armada server list                                           # on the first machine: all "voting"
```

Every server can become the leader, so each needs the same
`/etc/armada/server.env` (and the DNS token file, if you use one). A server
token hands over the cluster's keys: it works once and expires after 15
minutes. Do not stop at two servers: with two, losing either one stops the
control plane. See [operations](operations.md#control-plane-one-server-or-three).

## Day two

| Task | Command |
| --- | --- |
| Logs | `armada logs hello -f` |
| Shell in a replica | `armada exec hello -it -- sh` (a single command: `armada exec hello -- env`) |
| Scale with load | add `scale.max` and `scale.rules` (`http`, `cpu`, `memory`) to the spec (see [spec reference](spec-reference.md#autoscaling)); `scale.min: 0` stops idle apps until the next request ([scale to zero](spec-reference.md#scale-to-zero)) |
| Keep data | add `volumes` to the spec (one replica, bound to its node; see [spec reference](spec-reference.md#volumes)); `armada volume ls`, `armada volume backup hello data -o -` |
| Run a job | deploy a `kind: job` spec, then `armada job run NAME` (or set `schedule`); `armada job runs NAME`, `armada logs NAME` (see [spec reference](spec-reference.md#jobs)) |
| What happened | `armada events` (one app: `armada events hello`; keep following: `-f`) |
| CPU and memory use | `armada top` (one app's replicas: `armada top hello`; nodes: `armada top --nodes`) |
| Prometheus metrics | add `--metrics-listen PRIVATE_IP:9443` to `ARMADA_SERVER_FLAGS`, then `armada metrics credentials prometheus` for the scraper (see [operations](operations.md#metrics)) |
| Scale | `armada scale hello 3` |
| Canary | `revisions.mode: multiple` with weights in the spec, then `armada traffic hello r2=50 r3=50` (see [spec reference](spec-reference.md#revisions)) |
| Secrets | `armada secret set hello api-key < key.txt`, or `armada secret import hello .env` for many (`API_KEY` becomes `api-key`), then reference them with `secretRef` |
| Custom domain | add it under `ingress.domains`, publish the TXT record from `armada domain list`, run `armada domain verify www.example.com` |
| Internal service | `ingress.type: internal`; other containers call `http://<app>.internal` |
| Maintenance | `armada node cordon NODE` moves replicas away; `armada node uncordon NODE` (replicas spread back to it on their own) |
| Choose nodes | `armada node label NODE region=sulawesi`, then `placement.require` in the spec; `armada node restrict NODE` keeps a node for apps that ask for it |
| Remove a node | `armada node remove NODE` (revokes its certificate) |
| Control plane servers | `armada server list`, `armada server remove NAME` |
| Back up / upgrade | `armada backup -o -` (control plane; volumes: `armada volume backup`), then see [operations](operations.md) |

Short forms work everywhere: `ls` for `list`, `rm` or `delete` for
`remove`, and plural group names (`armada nodes ls`, `armada servers ls`,
`armada secrets ls hello`). `armada <command> --help` lists them.

Read the [threat model](threat-model.md), in particular the accepted
limitations, before running anything you care about.

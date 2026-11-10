# Quickstart

From empty Linux machines to an app served over HTTPS. One machine is
enough to start; more can join later as nodes or control plane servers.

> **Status.** Armada is alpha. Every step below is exercised on real cloud
> machines with Let's Encrypt staging before each release. Start with the
> staging environment (step 4) and report what breaks.

## How it fits together

```
 your laptop (Linux or macOS)            Linux machines on a private network
 ┌────────────┐   mTLS, port 7443    ┌──────────────────────────────────────┐
 │  armada    │ ───────────────────▶ │ armadad server  (control plane)      │
 │  (client)  │   private IP only    │ armadad agent   (runs containers)    │
 └────────────┘                      │ HAProxy on 80/443 ◀── the internet   │
                                     └──────────────────────────────────────┘
```

- **`armadad`** runs on every machine, as root. It is the control plane,
  the node agent, and the container runtime, and it sets machines up
  (`init`, `join`) and checks them (`doctor`).
- **`armada`** is the client you manage apps with. It needs no root and
  runs on the machines themselves or on your own computer. It talks to the
  control plane's **private** IP on port 7443; that port is never public,
  so from elsewhere you reach it through a VPN or an SSH tunnel
  ([step 9](#9-use-armada-from-your-own-computer)).

## What you need

- Linux machines (amd64 or arm64) with a **private network** between them
  (VPC, private networking, vSwitch, or a LAN), each with a private IP.
- systemd, cgroup v2, overlayfs, and `iptables` (current distributions
  have them). Nothing else: Armada brings its own container runtime and
  leaves other container software on the host alone.
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

Armada binds everything except 80 and 443 to the private IP. On providers
that map the public IP onto the private interface (1:1 NAT), block those
ports in the provider's firewall as well.

## 1. Install

On every machine:

```bash
curl -fsSL https://raw.githubusercontent.com/ryanbekhen/armada/main/install.sh | sudo sh
```

To read the script before running it as root:

```bash
curl -fsSLO https://raw.githubusercontent.com/ryanbekhen/armada/main/install.sh
less install.sh
sudo sh install.sh
```

The installer only installs or upgrades; you set the machine up in the
next steps. It:

- downloads the release for your architecture and checks its SHA-256
  checksum, and, when [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
  is installed, that this repository's release workflow signed it
  (`ARMADA_REQUIRE_SIGNATURE=1` refuses to install without the signature);
- installs `armadad`, `armada`, and the systemd units (not started);
- creates the `armada` group (see step 3).

`ARMADA_VERSION=v0.1.0` pins a version. On macOS the script installs only
the client; on a Linux computer that only needs the client, run it as
`sudo ARMADA_CLIENT_ONLY=1 sh`.

On RHEL, Oracle Linux, Rocky, and Alma, `sudo` does not search
`/usr/local/bin` (the installer warns): install with `ARMADA_PREFIX=/usr`,
or run the `armadad` commands from a root shell (`sudo -i`).

## 2. Check the machine

```bash
sudo install -d -m 0700 /run/armada/secrets
sudo armadad doctor
```

Fix every `FAIL` and read every `warn`. `doctor` checks the container
runtime, the private IP, ports open to the public, file permissions, the
tmpfs for secrets, the clock, the firewall, and connection tracking.

**Private IP.** Armada finds it on its own when the machine has exactly
one (container, VM, and VPN interfaces such as `docker0` or `wg0` do not
count). With several, it lists them and asks for `--private-ip`: pass the
address the other machines reach, here and in `init` or `join`. It cannot
change later.

## 3. Create the cluster (first machine)

```bash
sudo armadad init
```

This creates the cluster: its CA and certificates, the state, the key that
encrypts secrets, and two copies of the admin config:

| File | For |
| --- | --- |
| `~/.armada/config` | You, the user who ran `sudo armadad init`: `armada` works without `sudo` |
| `/etc/armada/admin.config` | root and members of the `armada` group |

Two choices are fixed here and cannot change later:

- `--cluster-cidr`: the private range for containers, a /24 of it per node
  (default `10.120.0.0/16`). Pick another if your network uses it.
- `--network wireguard`: encrypt traffic between nodes' containers
  (default: not encrypted, see [operations](operations.md#container-network)).

Note the **CA SHA-256** it prints; nodes check it when they join.

## 4. Start the control plane

```bash
sudo systemctl enable --now armada-server
armada status    # give it a few seconds to start
armada cluster set --acme-email you@example.com --acme-ca letsencrypt-staging
```

The first machine runs the control plane and an agent, so it also serves
apps. `armada cluster set` keeps settings in the cluster, so every server
uses them, also those you add later; `armada cluster show` lists them.
Once everything works, `armada cluster set --acme-ca letsencrypt` gets
trusted certificates.

**Back up now.** The data directory (`/var/lib/armada`) is the cluster:
without its `master.key`, secrets cannot be recovered. See
[backup](operations.md#backup) for `armadad backup` on a timer.

## 5. Point DNS at your nodes

Apps with external ingress are served at `<app>.<root domain>`. The root
domain is any domain you control: the zone itself (`example.com` gives
`hello.example.com`) or a subdomain that keeps Armada's apps apart
(`apps.example.com` gives `hello.apps.example.com`). This guide uses
`apps.example.com`.

Point a wildcard record at the **public** IPs of your nodes, so new apps
need no DNS changes, then tell Armada:

```
*.apps.example.com.  A  203.0.113.10
*.apps.example.com.  A  203.0.113.11
```

```bash
armada cluster set --root-domain apps.example.com
```

An A record per app works the same. You can also skip the root domain and
list each app's host names under `ingress.domains` (see "Custom domain"
under [Day two](#day-two)).

### Certificates

Each app gets its own Let's Encrypt certificate through HTTP-01, which
needs port 80 reachable from the internet. For one wildcard certificate,
or when HTTP-01 cannot reach your nodes, use DNS-01 with Cloudflare.
Create a custom API token with `Zone / DNS / Edit` and `Zone / Zone /
Read`, limited to your zone (and ideally to your control plane servers'
public IPs), and give it to the cluster from stdin, never on a command
line:

```bash
read -rs TOKEN && printf '%s' "$TOKEN" | armada cluster set --dns-provider cloudflare --dns-token -; unset TOKEN
```

The cluster keeps the token encrypted and never shows it. The root domain
and every name under it then use DNS-01; other custom domains keep
HTTP-01. `armada cluster set --dns-provider none` goes back to HTTP-01.

### Cloudflare proxy (orange cloud)

Armada terminates TLS on your nodes either way. If you proxy:

- Proxy only names one level under the zone (`hello.example.com`).
  Cloudflare's free certificate does not cover `hello.apps.example.com`;
  keep such names "DNS only".
- Set the zone's SSL/TLS mode to **Full (strict)** and use DNS-01 (above).
- List Cloudflare's address ranges with `armada cluster set
  --trusted-proxies`, so apps see the visitor's address in
  `CF-Connecting-IP` and `X-Forwarded-For` (see
  [operations](operations.md#behind-a-proxy-or-cdn)).

Other DNS providers need nothing but plain A records.

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
one. The [spec reference](spec-reference.md) lists every field.

## 7. Add nodes

On the first machine:

```bash
armada token create
```

It prints a single-use token (valid for an hour) and the exact commands for
the new machine. There, after steps 1 and 2:

```bash
sudo armadad join 10.0.0.2:7444 --ca-hash sha256:...   # paste the token when asked
sudo systemctl enable --now armada-agent
```

`armada node list` on the first machine shows it. The node gets a 30-day
certificate that it renews on its own, and starts taking replicas.

## 8. Make the control plane highly available (optional)

With one control plane server, apps keep serving while it is down, but
nothing can be changed until it is back. Three servers survive the loss of
any one; two are worse than one. Add two more, one at a time, on machines
prepared with steps 1 and 2:

```bash
armada token create --server                                 # on the first machine
sudo armadad server join 10.0.0.2:7444 --ca-hash sha256:...   # on the new machine; paste the token when asked
sudo systemctl enable --now armada-server
armada server list                                           # all "voting"
```

Every server can become the leader, and each one uses the settings of
`armada cluster set`: nothing to copy. A server token hands over the
cluster's keys: it works once and expires after 15 minutes. See [operations](operations.md#control-plane-one-server-or-three).

## 9. Use armada from your own computer

Install the client (on macOS the script installs only the client):

```bash
curl -fsSL https://raw.githubusercontent.com/ryanbekhen/armada/main/install.sh | sudo ARMADA_CLIENT_ONLY=1 sh
```

Give yourself a certificate of your own. On a server where `armada` works:

```bash
armada admin add yourname -o yourname.config
```

Copy the file to your computer privately (it is full control of the
cluster) and keep it as `~/.armada/config`:

```bash
install -d -m 0700 ~/.armada
install -m 0600 yourname.config ~/.armada/config
```

`armada` now talks to the address in that file: a control plane server's
**private** IP on port 7443. Your computer has to reach it, in one of two
ways.

**Through a VPN into the private network** (WireGuard or any other). If
your computer already reaches the private IPs, run `armada status` and you
are done. If the VPN ends on the server itself, also route the server's
private IP into the tunnel and let the tunnel reach port 7443, for example
with WireGuard and ufw:

```ini
# on your computer, the server's [Peer] section
AllowedIPs = 10.8.0.1/32, 10.0.0.2/32    # the server's VPN address and its private IP
```

```bash
sudo ufw allow in on wg0 to any port 7443 proto tcp    # on the server
```

Do not put the VPN address in the config: the API listens only on the
private IP.

**Through an SSH tunnel**, when there is no VPN:

```bash
ssh -N -L 7443:10.0.0.2:7443 you@203.0.113.10    # keep it open; 10.0.0.2 is the private IP
```

Then set `"servers": ["127.0.0.1:7443"]` in `~/.armada/config`. The
certificate checks still pass: the client verifies the server's name,
not its address. `armada server list` writes the servers' real addresses
back into the file, so set it again afterwards.

## 10. Give others access

Give every person who administers the cluster a certificate of their own,
the same way as in step 9: `armada admin add alice -o alice.config`. The
audit log names them, and you can take one person's access back without
touching anyone else's:

```bash
armada admin ls               # who has access
armada admin rm alice --yes   # refuse every certificate of alice at once
```

Certificates last a year; each person renews their own with `armada admin
renew`. Tools such as a CI system get [automation
identities](operations.md#automation-identities) instead, which manage
only the projects you give them.

On a server, people with an account can also use the shared
`/etc/armada/admin.config` by joining the `armada` group (`sudo usermod
-aG armada NAME`). That counts only in sessions started afterwards, so
they log out and in again; until then `armada` says so. Membership is full
control of the cluster under the first administrator's name, so prefer
certificates of their own.

## Day two

| Task | Command |
| --- | --- |
| Logs | `armada logs hello -f` |
| Shell in a replica | `armada exec hello -it -- sh` (a single command: `armada exec hello -- env`) |
| Scale | `armada scale hello 3` |
| Scale with load | add `scale.max` and `scale.rules` (`http`, `cpu`, `memory`) to the spec (see [spec reference](spec-reference.md#autoscaling)); `scale.min: 0` stops idle apps until the next request ([scale to zero](spec-reference.md#scale-to-zero)) |
| Secrets | `armada secret set hello api-key < key.txt`, or `armada secret import hello .env` for many (`API_KEY` becomes `api-key`), then reference them with `secretRef` |
| Custom domain | add it under `ingress.domains`, publish the TXT record from `armada domain list`, run `armada domain verify www.example.com` |
| Internal service | `ingress.type: internal`; other containers call `http://<app>.internal` |
| Keep data | add `volumes` to the spec (one replica, bound to its node; see [spec reference](spec-reference.md#volumes)); `armada volume ls`, `armada volume backup hello data -o -` |
| Run a job | deploy a `kind: job` spec, then `armada job run NAME` (or set `schedule`); `armada job runs NAME`, `armada logs NAME` (see [spec reference](spec-reference.md#jobs)) |
| Canary | `revisions.mode: multiple` with weights in the spec, then `armada traffic hello r2=50 r3=50` (see [spec reference](spec-reference.md#revisions)) |
| What happened | `armada events` (one app: `armada events hello`; keep following: `-f`) |
| CPU and memory use | `armada top` (one app's replicas: `armada top hello`; nodes: `armada top --nodes`) |
| Prometheus metrics | `armada cluster set --metrics-port 9443` (each server's private address), then `armada metrics credentials prometheus` for the scraper (see [operations](operations.md#metrics)) |
| Maintenance | `armada node cordon NODE` moves replicas away; `armada node uncordon NODE` (replicas spread back to it on their own) |
| Choose nodes | `armada node label NODE region=sulawesi`, then `placement.require` in the spec; `armada node restrict NODE` keeps a node for apps that ask for it |
| Remove a node | `armada node remove NODE` (revokes its certificate) |
| Administrators | `armada admin add NAME -o FILE`, `armada admin ls`, `armada admin rm NAME --yes` (see [step 10](#10-give-others-access)) |
| Control plane servers | `armada server list`, `armada server remove NAME` |
| Back up | `armadad backup -o -` (control plane; volumes: `armada volume backup`; see [operations](operations.md#backup)) |
| Upgrade | `armada version` shows the latest release; `sudo armadad upgrade` on each machine, servers first, one at a time (see [operations](operations.md#upgrades)) |

Short forms work everywhere: `ls` for `list`, `rm` or `delete` for
`remove`, and plural group names (`armada nodes ls`, `armada servers ls`,
`armada secrets ls hello`). `armada <command> --help` lists them.

Read the [threat model](threat-model.md), in particular the accepted
limitations, before running anything you care about.

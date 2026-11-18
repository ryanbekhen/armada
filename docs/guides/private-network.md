# Apps on a private network without a domain

Run Armada on machines that only a private network reaches (a home lab,
VMs on a laptop, an office LAN, a VPN) and open apps from a browser there,
with no public domain, no DNS provider, and no certificates. Apps answer
over plain HTTP on port 80 under a name your computer resolves to a node.

**You will use:** [`armada cluster set`](../cli/armada-cluster.md#armada-cluster-set)
(`--root-domain`, `--tls`),
[`armada app create`](../cli/armada-app.md#armada-app-create),
[`ingress.ipAllow`](../operations.md#who-may-reach-an-app)

**Before you start:**

- A running cluster (see the [quickstart](../quickstart.md)) and
  `cluster-admin`: cluster settings are cluster-wide.
- The machines' addresses on your network, here `192.168.122.11` to
  `192.168.122.15`. On a node, `ip -4 addr` shows its address.

Apps that only other apps call need none of this: `ingress.type: internal`
reaches them at `http://<app>` from apps of their space, and workers that
take no requests use `ingress.type: none`.

## How a request finds an app

Every node's proxy picks the app by the name in the request's `Host`
header, `<app>.<root domain>`, so a browser has to open a name, not an
address: `http://192.168.122.11/` answers `404` because it names no app.
You choose the root domain, and something on your computer has to turn
`<app>.<root domain>` into a node's address. Any node will do: every node
routes every app.

| Way | What you set up | Works for |
| --- | --- | --- |
| [A: sslip.io](#a-sslipio-nothing-to-set-up) | Nothing | Every computer that uses public DNS |
| [B: `/etc/hosts`](#b-one-line-per-app-in-etchosts) | One line per app | One computer, a few apps |
| [C: a wildcard on your Mac](#c-every-app-at-once-on-a-mac) | dnsmasq and one resolver file | One Mac, every app |
| [D: a wildcard on your network](#d-every-app-for-every-computer-on-the-network) | Your network's DNS server | Every computer on the network |
| [E: a domain you own, with HTTPS](#e-a-domain-you-own-with-https) | A DNS record and a token | Every computer, with real certificates |

## 1. An app

```bash
armada app create hello --image traefik/whoami:v1.10 --port 80 --ingress external
```

## 2. A root domain, no certificates

Pick one way to resolve names below, then set its root domain. Every
external app is then served at `http://<app>.<root domain>`:

```bash
armada cluster set --root-domain <root domain> --tls=false
armada app show hello      # URL: http://hello.<root domain>/
```

- The root domain needs no TXT record: only custom domains in
  `ingress.domains` are verified.
- With `--tls=false` the cluster asks for no certificates, and port 80
  serves the apps instead of redirecting to HTTPS. Port 443 still answers,
  with a self-signed certificate.
- The leader restarts its control plane within a second or two, and the
  command waits for it; apps keep serving.

### A: sslip.io, nothing to set up

[sslip.io](https://sslip.io) is a public DNS service that answers every
name with the address written in it: `hello.192-168-122-11.sslip.io`
resolves to `192.168.122.11`. Put a node's address, with dashes, in the
root domain:

```bash
armada cluster set --root-domain 192-168-122-11.sslip.io --tls=false
curl http://hello.192-168-122-11.sslip.io/
```

Nothing changes on your computer, and every app gets a name at once.

- The name carries one node's address. If that node is down, set the root
  domain to another node's address; apps keep serving through it.
- Some routers and DNS resolvers refuse public names that resolve to a
  private address (DNS rebinding protection), and then the name does not
  resolve. Use B, C, or D, or allow `sslip.io` in the router's settings.
- Lookups go to a public DNS service. On a network with no internet
  access, use B, C, or D.

### B: one line per app in `/etc/hosts`

Pick a name that is not a real domain, such as `lab.test` or `home.arpa`
(a single word such as `lab` is refused):

```bash
armada cluster set --root-domain lab.test --tls=false
```

Then, on the computer that opens the app (macOS and Linux alike):

```bash
echo '192.168.122.11  hello.lab.test' | sudo tee -a /etc/hosts
curl http://hello.lab.test/
```

`/etc/hosts` has no wildcards: each new app needs its own line.

### C: every app at once on a Mac

macOS asks a resolver of your choice for one domain only, through a file
in `/etc/resolver`. A local dnsmasq answers every name under `lab.test`
with the node's address:

```bash
armada cluster set --root-domain lab.test --tls=false

# On the Mac:
brew install dnsmasq
echo 'address=/lab.test/192.168.122.11' >> "$(brew --prefix)/etc/dnsmasq.conf"
sudo brew services start dnsmasq
sudo mkdir -p /etc/resolver
echo 'nameserver 127.0.0.1' | sudo tee /etc/resolver/lab.test

curl http://hello.lab.test/
```

Every app under `lab.test` now resolves, and other names keep using your
usual DNS. `scutil --dns | grep -A2 lab.test` shows the resolver is in
place. Tools that do their own DNS lookups instead of asking macOS may not
follow `/etc/resolver`; browsers and `curl` do.

On a Linux desktop the same idea is a dnsmasq answering `lab.test`, set as
the resolver for that domain (with systemd-resolved:
`resolvectl dns <link> 127.0.0.1` and `resolvectl domain <link> ~lab.test`).

### D: every app for every computer on the network

Add a wildcard to the DNS server your network already uses (a router, a
Pi-hole, an office DNS server). With dnsmasq:

```
address=/lab.test/192.168.122.11
```

Every computer that uses that DNS server then reaches every app, with
nothing to set up on the computers themselves.

### E: a domain you own, with HTTPS

A public DNS record may point at a private address. Nodes never have to be
reachable from the internet, because certificates come through DNS-01:
the ACME CA checks a TXT record that Armada writes through your DNS
provider's API, not a request to the nodes.

1. At your DNS provider, add a wildcard record, for example
   `*.lab.example.com  A  192.168.122.11` (on Cloudflare: DNS only, not
   proxied).
2. Make an API token that may edit the DNS of `example.com`, and set the
   cluster's root domain and DNS provider:

   ```bash
   armada cluster set --root-domain lab.example.com --tls=true --acme-email ops@example.com
   printf '%s' "$CF_TOKEN" | armada cluster set --dns-provider cloudflare --dns-token -
   curl https://hello.lab.example.com/
   ```

Apps get real certificates (a wildcard for `*.lab.example.com`) and
`https://` URLs, and every computer that uses public DNS opens them. The
same rebinding note as in A applies.

## 3. Keep it on your network

Plain HTTP is not encrypted. If a node also has a public address, port 80
answers there too: block it in the machine's or the provider's firewall, or
let only your network in:

```bash
armada app update hello --ip-allow 192.168.122.0/24 --ip-allow 10.8.0.0/24,name=vpn
```

Apps read the client's address from `X-Real-IP`, as on HTTPS.

## Check that it works

```bash
armada app show hello                    # READY 1/1 and the URL
curl -i http://hello.<root domain>/      # 200 from the app
curl -i http://192.168.122.11/           # 404: no app named, as expected
curl -H 'Host: hello.<root domain>' http://192.168.122.11/   # the app, without any DNS
```

## Moving to a public domain later

```bash
armada cluster set --root-domain apps.example.com --tls=true --acme-email ops@example.com
```

Apps then get certificates, port 80 redirects to HTTPS again, and their
URLs start with `https://`. See [Deploy a web app](deploy-a-web-app.md).

## When something is off

| Symptom | Cause | Fix |
| --- | --- | --- |
| `http://<app>.<root domain>` redirects to `https://` | Certificates are still on | `armada cluster set --tls=false`; `armada cluster show` shows the setting |
| `404` from every node | The name in `Host` is not `<app>.<root domain>`, or you opened the node's IP | Check `armada app show APP` for the URL, and open that name |
| The name does not resolve | Nothing on your computer knows the root domain | Use A, or add the name as in B, C, or D |
| An sslip.io name does not resolve, other sites do | The router or resolver refuses public names with private addresses | Use B, C, or D, or allow `sslip.io` in the router |
| `/etc/resolver/lab.test` is ignored | dnsmasq is not running, or the tool does its own DNS | `sudo brew services restart dnsmasq`; `dig hello.lab.test @127.0.0.1` checks dnsmasq itself |
| `ERR_CONNECTION_REFUSED` or a timeout | A firewall between your computer and the node blocks port 80 | Open port 80 on the node and in the VM or network settings |
| A sticky app forgets its clients | A cookie set over HTTPS before certificates were turned off | Clear the site's cookies once |
| `the image does not exist, or it is private` | The image name is wrong, or the image exists only on your laptop | See [Your own image from your laptop](images-from-your-laptop.md) |

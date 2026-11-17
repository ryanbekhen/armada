# Apps on a private network without a domain

Run Armada on machines that only a private network reaches (a home lab,
VMs on a laptop, an office LAN, a VPN) and open apps from a browser there,
with no public domain, no DNS provider, and no certificates. Apps answer
over plain HTTP on port 80 under a name only your network resolves.

**You will use:** [`armada cluster set`](../cli/armada-cluster.md#armada-cluster-set)
(`--root-domain`, `--tls`),
[`armada app create`](../cli/armada-app.md#armada-app-create),
[`ingress.ipAllow`](../operations.md#who-may-reach-an-app)

**Before you start:**

- A running cluster (see the [quickstart](../quickstart.md)) and
  `cluster-admin`: cluster settings are cluster-wide.
- The machines' addresses on your network, here `192.168.122.11` to
  `192.168.122.15`.

Apps that only other apps call need none of this: `ingress.type: internal`
reaches them at `http://<app>` from apps of their space, and workers that
take no requests use `ingress.type: none`.

## 1. A root domain your network resolves, no certificates

```bash
armada cluster set --root-domain lab.test --tls=false
```

- Every external app is served at `http://<app>.lab.test`. The root domain
  needs no TXT record: only custom domains in `ingress.domains` are
  verified.
- With `--tls=false` the cluster asks for no certificates, and port 80
  serves the apps instead of redirecting to HTTPS. Port 443 still answers,
  with a self-signed certificate.
- The leader restarts its control plane within a second or two, and the
  command waits for it; apps keep serving.

Pick a name that is not a real domain: `lab.test`, `home.arpa`, or a
subdomain of a domain you own. A single word such as `lab` is refused.

## 2. An app

```bash
armada app create hello --image traefik/whoami:v1.10 --port 80 --ingress external
armada app show hello
```

`app show` lists the URL, `http://hello.lab.test/`.

## 3. Resolve the names

Point the names at any node; every node routes every app. For one
computer, add a line to its `/etc/hosts`:

```
192.168.122.11  hello.lab.test
```

For every app at once and every computer on the network, add a wildcard to
the network's DNS server. With dnsmasq:

```
address=/lab.test/192.168.122.11
```

Then:

```bash
curl http://hello.lab.test/
```

Without touching DNS, `curl -H 'Host: hello.lab.test' http://192.168.122.11/`
works too. The proxy picks the app by the name in `Host`, so a bare
`http://192.168.122.11/` answers `404`.

## 4. Keep it on your network

Plain HTTP is not encrypted. If a node also has a public address, port 80
answers there too: block it in the machine's or the provider's firewall, or
let only your network in:

```bash
armada app update hello --ip-allow 192.168.122.0/24 --ip-allow 10.8.0.0/24,name=vpn
```

Apps read the client's address from `X-Real-IP`, as on HTTPS.

## Moving to a public domain later

```bash
armada cluster set --root-domain apps.example.com --tls=true --acme-email ops@example.com
```

Apps then get certificates, port 80 redirects to HTTPS again, and their
URLs start with `https://`. See [Deploy a web app](deploy-a-web-app.md).

## When something is off

| Symptom | Cause | Fix |
| --- | --- | --- |
| `http://<app>.lab.test` redirects to `https://` | Certificates are still on | `armada cluster set --tls=false`; `armada cluster show` shows the setting |
| `404` from every node | The name in `Host` is not `<app>.<root domain>`, or you used the node's IP | Check `armada app show APP` for the URL, and resolve that name |
| The name does not resolve | Nothing on your network knows `lab.test` | Add it to `/etc/hosts` or your DNS server (step 3) |
| A sticky app forgets its clients | A cookie set over HTTPS before certificates were turned off | Clear the site's cookies once |

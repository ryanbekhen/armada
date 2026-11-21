# Machines in more than one site

A cluster can span places that do not share a private network: two data
centers, an office and a cloud provider, or a few machines rented
elsewhere. Each place is a **site**. Nodes in one site reach each other
over their private network as usual; nodes in different sites reach each
other over WireGuard between their public addresses
([ADR 0050](../adr/0050-sites.md)).

You will add two machines to a running `plain` or `wireguard` cluster in
the first site:

- `c` in site `office`, with a private network of its own;
- `d` in site `cloud`, with no private network at all, as a control
  plane server;
- a machine behind NAT, at home or in an office.

## Before you start

- Every node that talks to another site runs a kernel with WireGuard
  (Linux 5.6 or later). `armadad doctor` checks it.
- The leader, and every machine you add, has a public IPv4 address. A node
  finds its own when it is the only public address on its interfaces;
  otherwise set it on each machine of the cluster that talks to another
  site:

  ```bash
  sudo armadad endpoint show
  sudo armadad endpoint set 203.0.113.10
  ```

- In the providers' firewalls, allow from anywhere:
  - UDP 51820 to every node (it answers nothing without a valid key);
  - TCP 7444 to the leader, only needed while machines join.
- Install Armada on the new machines (quickstart
  [step 1](../quickstart.md#1-install)).
- Node addresses must be unique across sites. If `c`'s private address is
  already taken by a node of the first site, join it with
  `--no-private-ip` (step 3).

## 1. Add a node from another site

On a machine with the client, create a token for the site:

```bash
armada node join-token --site office --from 198.51.100.21
```

The printed command names the leader's public address. The join port
opens there now and closes again once the token is used or expires (10
minutes by default, at most `--ttl 1h`); with `--from`, connections from
any other address are closed before TLS.

On `c`, run the printed command and paste the token:

```bash
sudo armadad join 203.0.113.10:7444 --ca-hash sha256:...
sudo systemctl enable --now armada-agent
```

`c` sends its private address and its public one, brings up its tunnels
to the other site, and joins. Every node of the first site adds it as a
peer within seconds:

```bash
armada node list
armada node show c      # Site: office
```

## 2. Add a control plane server from another site

A server token works the same way:

```bash
armada server join-token --site cloud --from 198.51.100.22
```

`d` has no private network, so it joins with a **mesh address**, which
every other node reaches over WireGuard:

```bash
sudo armadad server join 203.0.113.10:7444 --ca-hash sha256:... --no-private-ip
sudo systemctl enable --now armada-server
```

`d`'s etcd member and API listen on its mesh address (`10.122.0.1`, from
the range `10.122.0.0/16`). If a private network of the cluster uses
that range, pick another before the first such machine joins:

```bash
armada cluster update --mesh-cidr 10.123.0.0/16
```

Every write to the cluster's state waits for a majority of servers. Keep
the servers in one site, or in sites close together.

## 3. Keep apps in a site

Nodes outside the first site carry their site as the label `armada.site`.
Pin an app to a site, or spread it over sites, with placement:

```yaml
name: reports
image: ghcr.io/example/reports:1.4
ingress: {type: internal, port: 8080}
placement:
  require: {armada.site: office}
```

Apps reach each other through their internal names wherever they run;
calls to another site cross the internet, encrypted. Nodes of the first
site have no `armada.site` label, so to spread an app over every site,
give every node a site first:

```bash
armada node site a dc1
armada node site b dc1
```

## 4. Add a machine behind NAT

A machine at home or in an office usually has no public address anyone can
reach: its router only lets connections out. It joins with `--endpoint
none` and starts every connection itself:

```bash
armada node join-token --site home
```

On the machine:

```bash
sudo armadad join 203.0.113.10:7444 --ca-hash sha256:... --endpoint none
sudo systemctl enable --now armada-agent
```

Add `--mtu 1492` on a PPPoE line, or the MTU of whatever smaller link its
packets cross.

- It reaches every node with a public address directly, and nodes of its
  own site over their private network.
- Two nodes behind NAT in different sites cannot reach each other, so
  their traffic goes through a **relay**: a node with a public address
  that the leader picks, in one of their sites or, when neither has one,
  in another. The relay sees that traffic as any node sees its own.
- It takes no public traffic: point DNS only at nodes with a public
  address.

```bash
armada node list                 # STATE: ready,behind-nat / ready,relay
armada node show d               # Relay: yes (picked by the leader)
armada node relay d              # pin the relay of d's site
armada node relay d --clear      # let the leader pick again
```

A node already in the cluster goes behind NAT with `sudo armadad endpoint
set none`, and back with `sudo armadad endpoint set IP`. Servers always
need a public address.

## 5. Check it

On any node:

```bash
sudo armadad doctor
```

- `network-sites` (in a `plain` cluster) or `network`: every peer in
  another site has a recent handshake. If not, UDP 51820 is blocked
  between them.
- `sites`: no node of another site has an address inside one of this
  machine's local networks. If one does, a host at that address on the
  local network becomes unreachable from the node: join that node again
  with `--no-private-ip`.
- `relay`, on a node behind NAT: which relay carries its traffic to nodes
  behind NAT in other sites; on a relay, how many pairs it forwards for.
  It fails when no relay can reach a node: give one of the sites a node
  with a public address.

## Good to know

- A machine whose public address changes for good keeps its place:
  `sudo armadad endpoint set NEW-IP` writes it and restarts the service.
- `armada node site NODE SITE` moves a node to another site;
  `--clear` brings it back to the first.
- A cluster with nodes in another site cannot switch between `plain` and
  `wireguard`; move every node to the first site first.

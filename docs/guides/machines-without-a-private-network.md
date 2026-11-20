# Machines without a private network

Some providers rent machines with a public address and no private network
between them, and machines of different providers or sites never share
one. A **mesh** cluster needs only the public addresses: Armada connects
every machine to every other over WireGuard, gives each a private mesh
address, and runs the control plane, etcd, and the traffic between
containers through the tunnel ([ADR 0049](../adr/0049-mesh-over-public-addresses.md)).

You will build a cluster of three machines, `a`, `b`, and `c`, each with
one public IPv4 address.

## Before you start

- Every machine runs a kernel with WireGuard (Linux 5.6 or later; current
  distributions have it). `armadad doctor` checks it.
- In the provider's firewall, allow from anywhere:
  - TCP 80 and 443 (your apps);
  - UDP 51820 (the mesh; it answers nothing without a valid key);
  - TCP 7444 to the first machine, only needed while machines join.
- Install Armada on every machine (quickstart [step 1](../quickstart.md#1-install)).

The mesh is chosen once, when the cluster is created. An existing cluster
cannot switch to it.

## 1. Create the cluster on the first machine

```bash
sudo armadad init --network mesh
sudo systemctl enable --now armada-server
armada node list
```

`init` finds the machine's public address. When it is behind one-to-one
NAT (the public address is on no interface) or has several, name it:

```bash
sudo armadad init --network mesh --endpoint 203.0.113.10
```

The output shows the mesh: the machine is `10.122.0.1`, the first address
of the default mesh range `10.122.0.0/16` (`--mesh-cidr` picks another).
The API listens on that address only; nothing but 80, 443, and UDP 51820
faces the internet.

## 2. Add a node

On the first machine, create a token for the new machine's public address:

```bash
armada node join-token --from 203.0.113.11
```

It prints the join command with the first machine's public address. The
join port opens now and closes again when the token is used or expires
(10 minutes by default, at most `--ttl 1h`). With `--from`, connections
from any other address are closed before TLS.

On the new machine, run the printed command and paste the token:

```bash
sudo armadad join 203.0.113.10:7444 --ca-hash sha256:...
sudo systemctl enable --now armada-agent
```

The machine gets the next mesh address (`10.122.0.2`) and the list of
every other machine, brings its tunnel up, and joins. Every other machine
adds it as a peer within seconds.

## 3. Add control plane servers

Three servers keep the cluster running when one fails. Add the second and
third the same way, with a server token:

```bash
armada server join-token --from 203.0.113.12
```

```bash
sudo armadad server join 203.0.113.10:7444 --ca-hash sha256:...
sudo systemctl enable --now armada-server
```

Each server's etcd member and API listen on its mesh address. Keep the
servers in one region: etcd waits for a majority on every write, so
servers far apart slow every change. Nodes may be anywhere.

## 4. Check it

```bash
armada node list          # every machine ready, at its mesh address
sudo armadad doctor       # on each machine
```

`doctor` reports the kernel's WireGuard, a recent handshake with every
peer, and that no cluster port listens on a public address.

## Using the cluster from your computer

The API is on mesh addresses, which only the machines reach. Give your
config an SSH host, any machine of the cluster
([quickstart step 9](../quickstart.md#9-use-armada-from-your-own-computer)):

```bash
armada rbac user create alex --role cluster-admin -o alex.config --ssh admin@203.0.113.10
```

## What to expect

- Every byte between machines is encrypted. On two machines with two
  vCPUs each, WireGuard over public addresses measured about 1.9 Gbit/s
  between containers and 93 MB/s for a large upload, against 3.4 Gbit/s
  and 148 MB/s unencrypted on a private network
  ([operations](../operations.md#container-network)).
- When a machine's public address changes, its peers follow it as soon as
  it sends a packet, which it does every 25 seconds. The cluster still
  records the address it joined with, so give machines fixed addresses; a
  machine whose address changes for good joins again.
- When every machine restarts at once, each brings its tunnel up from the
  last peer list it kept (`/var/lib/armada/mesh.json`) before etcd starts.
- A machine restored from a backup comes up alone and gets its peers once
  the control plane answers.

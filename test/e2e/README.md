# End-to-end tests

`cluster.sh` builds an Armada cluster on real machines and checks the
behaviour that unit tests cannot: certificates, traffic under change, the
control plane losing its leader, nodes going away, and reboots. It runs from
your workstation over SSH and does not depend on any provider. Run it before
a release and after changes to the runtime, the proxy, the scheduler, or the
control plane. It does not run in CI.

## What you need

- Two or more fresh Linux machines (four is best: three control plane servers
  and one node) on a private network, reachable as root over SSH with a key
  (or set `E2E_SUDO=sudo`). They get Armada installed and are changed freely:
  throw them away afterwards.
- A root domain whose wildcard record points at the machines' public IPs, so
  HTTP-01 can issue the test app's certificate. The script always talks to
  every node directly, so the record may name just one of them.
- `ssh`, `scp`, `curl`, `jq`, and `openssl` on your workstation.
- A Linux binary with the runtime embedded for the machines' architecture:
  `make build-bundle` (add `GOARCH=arm64` for arm64).

## Running

List the machines, one per line, in a hosts file:

```
# NAME  SSH-TARGET        PRIVATE-IP  PUBLIC-IP
e2e1    root@203.0.113.10  10.0.0.1    203.0.113.10
e2e2    root@203.0.113.11  10.0.0.2    203.0.113.11
e2e3    root@203.0.113.12  10.0.0.3    203.0.113.12
e2e4    root@203.0.113.13  10.0.0.4    203.0.113.13
```

```bash
make build-bundle
ARMADA_BIN=bin/armada-linux-amd64 E2E_DOMAIN=e2e.example.org \
E2E_ACME_EMAIL=you@example.org sh test/e2e/cluster.sh hosts
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `ARMADA_BIN` | required | Binary to install on every machine |
| `E2E_DOMAIN` | required | Root domain for the test app (`hello.<domain>`) |
| `E2E_ACME_EMAIL` | required | ACME account email |
| `E2E_ACME_CA` | `letsencrypt-staging` | Passed to `--acme-ca`; the production endpoint is refused |
| `E2E_SSH_OPTS` | empty | Extra `ssh`/`scp` options, such as `-o UserKnownHostsFile=...` |
| `E2E_SUDO` | empty | `sudo` when the SSH user is not root |
| `E2E_REBOOT` | `1` | `0` skips rebooting every machine at once |
| `E2E_BRIDGE_GW` | `10.121.0.1` | Container bridge address, if you pass `--container-subnet` |
| `E2E_SERVER_FLAGS` | empty | Extra `armada server` flags |

The script stops at the first failure and prints `armada server list` and
`armada status`. A full run on four small machines takes about 10 minutes
once the binary has been copied to them.

## What it checks

1. `armada doctor` passes on every machine; the cluster forms with three
   voting servers and every node ready.
2. Nothing but SSH and HAProxy (80/443) listens outside the private,
   loopback, and bridge addresses.
3. The test app gets a certificate for its host name on every node; a secret
   reaches the container's environment and appears in no journal.
4. A rolling update, a rollback, and an agent restart serve every request
   (round robin over all public IPs) with HTTP 200; the restart adopts the
   running containers instead of replacing them.
5. Stopping the leader and killing the next one with SIGKILL: a new leader
   takes over, accepts a scale change, the old one rejoins, and traffic stays
   at 200.
6. A node that stops reporting is marked lost after 30 seconds (the script
   sets `--node-lost-timeout 30s`), its replicas move to other nodes, and
   once it returns the app is rebalanced onto it; traffic stays at 200.
7. `armada backup` writes a `0600` archive.
8. After rebooting every machine at once, the control plane, the nodes, and
   the app come back on their own.

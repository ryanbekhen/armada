# Tested environments

Every release is tested end to end on real machines with [test/e2e](../test/e2e/README.md). These are the environments Armada has been run in.

| Environment | Status |
| --- | --- |
| Cloudflare DNS-01 with Let's Encrypt staging | Tested on depa.id (amd64, Ubuntu 24.04): certificates for the root domain and a wildcard, domain verification, challenge records removed afterwards, the token kept out of logs and events, and requests through the Cloudflare proxy with trusted proxies (the client's address kept, forged headers from elsewhere dropped) |
| Local lab: Linux VMs (arm64), Pebble ACME, 1–2 nodes | Tested end to end: deploys, rolling update, secret files, internal ingress and DNS, crash recovery, containerd restart with containers kept running, reboot recovery, rolling upgrade with a state migration, rebalancing after a drained node resumed under HTTPS load without errors, replicas across nodes |
| Oracle Cloud (arm64, Oracle Linux 9, SELinux enforcing), one server, Let's Encrypt staging | Tested end to end: install.sh with systemd, doctor, wildcard certificate over Cloudflare DNS-01, rolling update under load without errors, crash recovery, containerd restart, reboot recovery, SELinux-confined apps and HAProxy, HAProxy restarted after a crash |
| depa.id (amd64, Ubuntu 24.04), three control plane servers and one node, Let's Encrypt staging | Tested end to end with [test/e2e](../test/e2e/README.md): server and node joins, only HAProxy public, certificates on every node, secrets, rolling update, rollback, and agent restart under load without errors, leader stop and SIGKILL under load, node loss and rebalancing under load, backup, all machines rebooted at once |
| Mixed architectures: three depa.id servers (amd64, Ubuntu 24.04) and an Oracle Cloud node (arm64, Oracle Linux 9, SELinux enforcing), Let's Encrypt staging | Tested end to end with [test/e2e](../test/e2e/README.md): every scenario above except the reboot, plus placement under load and images built for one architecture running only on nodes of that architecture |
| depa.id (amd64, Ubuntu 24.04, kernel 6.8), two machines on a private network, `--network wireguard` | Tested: the kernel WireGuard device on both nodes, handshakes in `armadad doctor`, requests between replicas on different nodes, only encrypted traffic on the private network, the tunnel staying up while an agent is stopped, the same key after an agent restart, and recovery after a node reboot |

Reports from other providers are welcome.


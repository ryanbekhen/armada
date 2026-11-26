//! The armadad command tree, as Go's NewRootCommand builds it: names,
//! help, examples, flags, and argument checks (generated once from Go's
//! tree, then kept by hand).

use armada_client::cli::flags::Flag;
use armada_client::cli::{Args, Node, Tree};

use crate::commands;

/// NewRootCommand.
#[allow(unused_mut, unused_variables)]
pub fn root() -> Tree {
    let mut n = Node::new("armadad", "Run and set up an Armada machine")
        .long("armadad runs on every machine of an Armada cluster: the control plane\n(`armadad server`), the node agent (`armadad agent`), and, on nodes set up\non containerd, the embedded runtime (`armadad runtime`), each under systemd. It also sets a\nmachine up (init, join) and inspects it (doctor). It runs as root.\nManage apps with `armada`.")
        .noun();
    n.persistent = vec![Flag::string(
        "config",
        None,
        &crate::config_default(),
        "client config file",
    )];
    let mut t = Tree::new(n);
    let mut n = Node::new("agent", "Run the node agent")
        .example("  sudo systemctl enable --now armada-agent    # how it normally runs, after join\n  sudo armadad agent -v                       # in the foreground, with debug logs")
        .args(Args::No)
        .run(commands::agent::run)
        .flag(Flag::string("data-dir", None, "/var/lib/armada", "directory holding the node certificate"))
        .flag(Flag::bool("internal-dns", None, true, "serve <app>.internal to containers on this node (needs --proxy haproxy)"))
        .flag(Flag::string("log-format", None, "text", "log format: text or json"))
        .flag(Flag::string("proxy", None, "haproxy", "ingress proxy: haproxy or none"))
        .flag(Flag::string("secrets-dir", None, "/run/armada/secrets", "tmpfs directory for secret files"))
        .flag(Flag::string_slice("server", None, "control plane addresses (default: from agent.json, kept up to date by the server)"))
        .flag(Flag::bool("verbose", Some('v'), false, "debug logging"));
    let i_root_agent = t.add(0, n);
    let mut n = Node::new("backup -o FILE", "Back up the control plane (state, keys, certificates)")
        .long("Writes a consistent backup of the control plane: a snapshot of the state\n(etcd), the secrets master key, the cluster CA, the server certificate,\nACME certificates, and this node's agent identity. Safe to run while the\nserver is running.\n\nThe archive contains the CA key and the master key in plaintext. It is\ncreated with mode 0600; encrypt it before it leaves the machine, e.g.\n\n  armadad backup -o - | age -r age1... > armada-$(date +%F).tar.gz.age\n\nTo have the leader back the control plane up to a bucket on a schedule\ninstead, see armada cluster update --backup-url (ADR 0051); armadad backup\nlist shows what the bucket holds.")
        .example("  sudo armadad backup -o cp-$(date +%F).tar     # the control plane, on a server\n  sudo armadad backup list --backup-url url.txt --backup-key key.txt")
        .args(Args::No)
        .run(commands::backup::run)
        .flag(Flag::string("data-dir", None, "/var/lib/armada", "control plane data directory"))
        .flag(Flag::string("output", Some('o'), "", "archive to create (never overwritten), or - for stdout"));
    let i_root_backup = t.add(0, n);
    let mut n = Node::new("list --backup-url FILE --backup-key FILE", "List the control plane's backups in its bucket")
        .long("Lists the backups the leader keeps of the control plane in its bucket\n(armada cluster update --backup-url, ADR 0051), oldest first, with the server\neach was taken on: armadad restore --snapshot ID restores one onto a\nmachine with that server's private IP. Both flags take a file (mode 0600)\nholding the URL or the key, or - for stdin (one of them).")
        .example("  sudo armadad backup list --backup-url url.txt --backup-key key.txt")
        .args(Args::No)
        .run(commands::backup::list)
        .flag(Flag::string("backup-key", None, "", "file holding the key the control plane's backups are encrypted with, or - for stdin"))
        .flag(Flag::string("backup-url", None, "", "file holding the URL of the bucket the control plane backs itself up to, or - for stdin"))
        .flag(Flag::string("output", Some('o'), "", "json for JSON"));
    let i_root_backup_list = t.add(i_root_backup, n);
    let mut n = Node::new("doctor", "Check that this host is ready to run Armada safely")
        .long("Runs pre-flight checks on this host: the container runtime, the private IP,\nports bound publicly, file permissions in the data directory, the certificates on\nthis machine and in the client config (--config), the secrets tmpfs, the clock, and\nthe host firewall. Exits non-zero if a check fails.")
        .example("  sudo armadad doctor                          # before init or join, and when something is off\n  sudo armadad doctor --private-ip 10.0.0.5")
        .args(Args::No)
        .run(commands::doctor::run)
        .flag(Flag::string("data-dir", None, "/var/lib/armada", "Armada data directory"))
        .flag(Flag::string("private-ip", None, "", "this node's private (VPC) IP (default: the node's own, else the only private IPv4 address)"))
        .flag(Flag::string("secrets-dir", None, "/run/armada/secrets", "tmpfs directory for secret files"));
    let i_root_doctor = t.add(0, n);
    let mut n = Node::new("endpoint", "Show or set the public address other sites' nodes reach this machine at")
        .long("A machine's endpoint is the public IPv4 address WireGuard packets from nodes in\nother sites, or from every node in a mesh cluster, are sent to (ADR 0049, ADR\n0050). Without one set, a node announces the only public IPv4 address on its\ninterfaces. Set it behind one-to-one NAT (the public address is on no\ninterface), on a machine with several, or when its address changed for good.\n\n`set none` says the machine is behind NAT: it has no address others reach, and\nit starts every connection to other sites; nodes behind NAT in two sites reach\neach other through a relay (ADR 0050). Servers need an endpoint.")
        .noun();
    n.persistent = vec![Flag::string(
        "data-dir",
        None,
        "/var/lib/armada",
        "data directory",
    )];
    let i_root_endpoint = t.add(0, n);
    let mut n = Node::new("set IP|none", "Set the endpoint and restart this machine's Armada service")
        .example("  sudo armadad endpoint set 203.0.113.7    # the public address other sites reach this machine at\n  sudo armadad endpoint set none           # behind NAT")
        .args(Args::Exact(1))
        .run(commands::endpoint::set)
        .flag(Flag::bool("no-restart", None, false, "only record the endpoint; restart the service yourself"));
    let i_root_endpoint_set = t.add(i_root_endpoint, n);
    let mut n = Node::new("show", "Show the endpoint this machine announces")
        .example("  sudo armadad endpoint show")
        .args(Args::No)
        .run(commands::endpoint::show);
    let i_root_endpoint_show = t.add(i_root_endpoint, n);
    let mut n = Node::new("etcd", "Run this server's etcd member from the runtime pack (started by systemd)")
        .long("etcd runs this server's etcd member with the etcd program of the runtime pack\ninstead of inside `armadad server` (ADR 0055). It works the member out as the\nserver does (name, data, addresses, certificate), writes etcd's configuration\nfile (etcd/etcd.yaml, 0600) beside it, and replaces itself with etcd.\nBefore etcd first runs on a member the server ran, it copies the member's data\nto etcd/data.before-unit once. It refuses while another process holds the\nmember. For now only lab machines run it, with `armadad server --etcd-member unit`.\nFlags it does not know (the server's, from ARMADA_SERVER_FLAGS) are ignored.")
        .example("  sudo systemctl status armada-etcd                 # started by systemd on lab servers (ADR 0055)\n  sudo armadad etcd --bin-dir /opt/etcd-v3.7.4       # a build without the runtime pack")
        .args(Args::No)
        .run(commands::etcd::run)
        .flag(Flag::string("bin-dir", None, "", "use the etcd program in this directory (builds without the runtime pack)"))
        .flag(Flag::string("data-dir", None, "/var/lib/armada", "Armada data directory"));
    n.unknown_flags = true;
    let i_root_etcd = t.add(0, n);
    let mut n = Node::new("init", "Initialize a new cluster on this machine")
        .long("init creates the cluster CA, server and node certificates, the state database,\nand the admin client config /etc/armada/admin.config (read by root and the armada\ngroup; the server renews its certificate). Run through sudo, it adds that user to\nthe group: log in again or run `newgrp armada` to use armada without sudo.\nRun it once on the first machine, then start `armadad server`.")
        .example("  sudo armadad init                                  # a cluster on this machine, its first server\n  sudo armadad init --network wireguard              # containers' traffic between nodes encrypted\n  sudo armadad init --runtime embedded               # containers on containerd instead of the supervisor")
        .args(Args::No)
        .run(commands::init::run)
        .flag(Flag::string("cluster-cidr", None, "10.120.0.0/16", "private IPv4 range for containers; each node gets a /24 of it (set once, /12 to /20)"))
        .flag(Flag::string("container-subnet", None, "10.121.0.0/24", "private IPv4 subnet for this node's containers (clusters without a cluster network; others give each node a subnet)"))
        .flag(Flag::string("data-dir", None, "/var/lib/armada", "directory for cluster state and keys"))
        .flag(Flag::string("endpoint", None, "", "--network mesh: this machine's public IPv4 address, which other nodes send WireGuard packets to (default: the only public IPv4 address; behind one-to-one NAT, the mapped address)"))
        .flag(Flag::string("mesh-cidr", None, "10.122.0.0/16", "--network mesh: private IPv4 range of the nodes' mesh addresses (/8 to /24; set once)"))
        .flag(Flag::string("network", None, "plain", "how traffic between nodes travels: plain (VXLAN over the private network, not encrypted), wireguard (encrypted, over the private network), or mesh (WireGuard between public addresses, no private network needed); set once"))
        .flag(Flag::string("node-name", None, "", "node name (default: hostname)"))
        .flag(Flag::int("port", None, 7443, "control plane port on the private IP"))
        .flag(Flag::string("private-ip", None, "", "this node's private IP (default: the only private IPv4 address; not with --network mesh)"))
        .flag(Flag::string("runtime", None, "supervisor", "container runtime: supervisor (no containerd daemon, ADR 0046), or embedded (containerd)"))
        .flag(Flag::string("user-name", None, "", "name of the first user, who gets cluster-admin (default: the user running it)"));
    let i_root_init = t.add(0, n);
    let mut n = Node::new("join ADDR --ca-hash sha256:HEX", "Join this machine to a cluster as a node")
        .long("Join this machine to a cluster as a node. Get ADDR, TOKEN, and the CA hash\nfrom `armada node join-token`. The CA hash pins the cluster CA, so a machine in\nthe middle cannot pose as the server. Afterwards, run `armadad agent`.\n\nThe token is read from --token-file, a hidden prompt, or stdin; never from\nan argument, which would leak into shell history.")
        .example("  sudo armadad join 10.0.0.2:7444 --ca-hash sha256:3f1c...   # from armada node join-token; paste the token\n  sudo armadad join 10.0.0.2:7444 --ca-hash sha256:3f1c... --token-file /root/token")
        .args(Args::Exact(1))
        .run(commands::join::node)
        .flag(Flag::string("ca-hash", None, "", "cluster CA hash, sha256:..."))
        .flag(Flag::string("container-subnet", None, "10.121.0.0/24", "private IPv4 subnet for this node's containers (clusters without a cluster network; others give each node a subnet)"))
        .flag(Flag::string("data-dir", None, "/var/lib/armada", "directory for the node certificate"))
        .flag(Flag::string("endpoint", None, "", "joins over a public ADDR (mesh clusters, other sites): this machine's public IPv4 address, which other nodes send WireGuard packets to (default: the only public IPv4 address; behind one-to-one NAT, the mapped address); none: the machine is behind NAT and starts every connection to other sites"))
        .flag(Flag::int("mtu", None, 0, "the largest packet this machine's line to other nodes carries, when it is below its interface's (a PPPoE line: 1492); tunnels and containers take their overhead from it"))
        .flag(Flag::bool("no-private-ip", None, false, "joining from another site: send no private IP, and get a mesh address the other nodes reach over WireGuard (the default when the machine has no private IPv4 address)"))
        .flag(Flag::string("node-name", None, "", "node name (default: hostname)"))
        .flag(Flag::string("private-ip", None, "", "this node's private IP (default: the only private IPv4 address; a mesh cluster gives the node a mesh address instead)"))
        .flag(Flag::string("runtime", None, "supervisor", "container runtime: supervisor (no containerd daemon, ADR 0046), or embedded (containerd)"))
        .flag(Flag::string("token-file", None, "", "file holding the join token (default: prompt or stdin)"));
    n.required = vec!["ca-hash"];
    let i_root_join = t.add(0, n);
    let mut n = Node::new("restore FILE | --backup-url FILE --backup-key FILE [--snapshot ID|latest]", "Restore the control plane from a backup")
        .long("Restores a backup made with 'armadad backup' into an empty data directory\n(\"-\" reads the archive from stdin). The archive is verified completely\nbefore anything is written to the data directory. Stop any other control\nplane of this cluster first: two servers must never run at the same time.\n\nWith --backup-url and --backup-key, the backup comes from the bucket the\ncontrol plane backs itself up to (armada cluster update --backup-url, ADR 0051)\ninstead of an archive: --snapshot names one (armadad backup list), latest by\ndefault. Both flags take a file (mode 0600) holding the URL or the key, or\n- for stdin (one of them). The snapshot is checked exactly like an archive.")
        .example("  sudo armadad restore cp-2026-11-22.tar                               # from an archive\n  sudo armadad restore --backup-url url.txt --backup-key key.txt         # the latest in the bucket\n  sudo armadad restore --backup-url url.txt --backup-key key.txt --snapshot 20261122T030000.000Z-1a2b3c4d")
        .args(Args::Max(1))
        .run(commands::backup::restore)
        .flag(Flag::string("backup-key", None, "", "file holding the key the control plane's backups are encrypted with, or - for stdin"))
        .flag(Flag::string("backup-url", None, "", "file holding the URL of the bucket the control plane backs itself up to, or - for stdin"))
        .flag(Flag::string("data-dir", None, "/var/lib/armada", "data directory to restore into (must not exist or be empty)"))
        .flag(Flag::string("snapshot", None, "latest", "backup to restore from the bucket: an ID from armadad backup list, or latest"));
    let i_root_restore = t.add(0, n);
    let mut n = Node::new("runtime", "Run the embedded container runtime (started by systemd)")
        .long("runtime extracts the bundled containerd, runc, CNI plugins, and tini into the\ndata directory, verifies them, and replaces itself with containerd. It does\nnothing on nodes that are not initialized yet.")
        .example("  sudo systemctl status armada-runtime   # started by systemd on containerd nodes\n  sudo armadad runtime reset             # remove every container Armada runs here")
        .args(Args::No)
        .run(commands::runtime::run)
        .flag(Flag::string("bin-dir", None, "", "use runtime binaries from this directory (builds without the bundle)"))
        .flag(Flag::string("data-dir", None, "/var/lib/armada", "Armada data directory"));
    let i_root_runtime = t.add(0, n);
    let mut n = Node::new("migrate --to embedded|supervisor", "Move this node to another container runtime (ADR 0046)")
        .long("migrate moves this node between the embedded containerd and the supervisor,\nwhich runs containers without containerd (ADR 0046). It removes every\ncontainer Armada runs here from the current runtime and records the new one;\nthe agent then starts its replicas on the new runtime, pulling their images\nagain. First drain the node (armada node drain NODE) and stop its service\n(systemctl stop armada-server, or armada-agent); afterwards start the service\nand resume the node (armada node resume NODE).\n\nMoving to the supervisor stops containerd and leaves its data in\n<data-dir>/containerd, which can be removed once the node runs.\n\nThe cluster's leader moves containerd nodes to the supervisor by itself, one\nat a time (ADR 0054; armada cluster status shows it). Run this for a node it\ndoes not move: a cluster's only node, a node holding volumes, or any node\nwhile the move is turned off (armada cluster update --runtime-move=false).")
        .example("  sudo armadad runtime migrate --to supervisor   # drain the node and stop its service first\n  sudo armadad runtime migrate --to embedded")
        .args(Args::No)
        .run(commands::runtimecmd::migrate)
        .flag(Flag::string("data-dir", None, "/var/lib/armada", "Armada data directory"))
        .flag(Flag::string("to", None, "", "runtime to move to: embedded or supervisor"));
    n.required = vec!["to"];
    let i_root_runtime_migrate = t.add(i_root_runtime, n);
    let mut n = Node::new("reset", "Remove every container Armada runs on this node")
        .long("reset stops and removes all of Armada's containers on this node (those with\nArmada's labels), the network sandboxes job queues are read from,\nthe node's resolver (armada-dns), and the cluster network's interface\nand firewall rules.\nUse it after `armada node delete`, with the agent (or server) stopped first,\nor it starts its replicas again.")
        .example("  sudo systemctl stop armada-agent && sudo armadad runtime reset")
        .args(Args::No)
        .run(commands::runtimecmd::reset)
        .flag(Flag::string("data-dir", None, "/var/lib/armada", "Armada data directory"));
    let i_root_runtime_reset = t.add(i_root_runtime, n);
    let mut n = Node::new("runtime-log DIR", "")
        .args(Args::Exact(1))
        .run(commands::runtimelog::run);
    n.hidden = true;
    let i_root_runtime_log = t.add(0, n);
    let mut n = Node::new("server", "Run the control plane")
        .long("Run the control plane.\n\nEvery control plane node runs `armadad server`. They elect a leader, which serves\nthe API and runs the reconcilers; the others stand by and take over within\nseconds if it fails. Add control plane nodes with `armadad server join`.\n\nOn a server machine, systemd runs this server's etcd member (armada-etcd, `armadad\netcd`) and the node's agent (armada-agent, `armadad agent`) as units of their own;\nstarting armada-server starts both.")
        .example("  sudo systemctl enable --now armada-server   # how it normally runs, after init or server join\n  sudo armadad server -v                      # in the foreground, with debug logs")
        .args(Args::No)
        .run(commands::server::run)
        .aliases(&["servers"])
        .flag(Flag::string("acme-ca", None, "letsencrypt", "ACME directory: letsencrypt, letsencrypt-staging, or an https:// URL"))
        .flag(Flag::string("acme-email", None, "", "contact email for the ACME account"))
        .flag(Flag::string("acme-listen", None, "", "private ip:port for HTTP-01 challenges forwarded by HAProxy (default: <server ip>:7480)"))
        .flag(Flag::bool("agent", None, true, "kept for server.env files of before: armada-agent.service runs the node's agent").hide())
        .flag(Flag::string("data-dir", None, "/var/lib/armada", "directory for cluster state and keys"))
        .flag(Flag::string("dns-provider", None, "", "DNS provider for certificates of the root domain and the names under it, including a wildcard: cloudflare"))
        .flag(Flag::string("dns-token-file", None, "", "file (mode 0600) holding the DNS provider API token"))
        .flag(Flag::string("etcd-member", None, "unit", "where this server's etcd member runs: unit (armada-etcd.service, the only choice of this armadad; ADR 0055)").hide())
        .flag(Flag::bool("internal-dns", None, true, "kept for server.env files of before: set it for armada-agent in agent.env").hide())
        .flag(Flag::string("join-listen", None, "", "private ip:port for joining nodes (default: API port + 1; \"off\" disables joining)"))
        .flag(Flag::string("log-format", None, "text", "log format: text or json"))
        .flag(Flag::string("metrics-listen", None, "", "private ip:port for the Prometheus metrics endpoint, served by the leader to metrics and admin certificates (default: off)"))
        .flag(Flag::duration("node-lost-timeout", None, 5 * 60 * 1_000_000_000, "how long a node may be unreachable before its replicas move to other nodes"))
        .flag(Flag::string("proxy", None, "haproxy", "kept for server.env files of before: set it for armada-agent in agent.env").hide())
        .flag(Flag::string("secrets-dir", None, "/run/armada/secrets", "kept for server.env files of before: set it for armada-agent in agent.env").hide())
        .flag(Flag::bool("tls", None, true, "obtain and renew TLS certificates with ACME"))
        .flag(Flag::bool("verbose", Some('v'), false, "debug logging"));
    let i_root_server = t.add(0, n);
    let mut n = Node::new("join ADDR --ca-hash sha256:HEX", "Add this machine to the cluster as a control plane node")
        .long("Add this machine to the cluster as a control plane node. Get ADDR, the token,\nand the CA hash from `armada server join-token`. The CA hash pins the\ncluster CA, so a machine in the middle cannot pose as the server.\n\nThe new server receives the cluster CA key and the secrets master key, so the\ntoken is as sensitive as they are. It is read from --token-file, a hidden\nprompt, or stdin; never from an argument. Afterwards, run `armadad server`.\n\nLike `armadad init`, it writes /etc/armada/admin.config for the machine's\ncluster-admins (group armada), with a certificate for --user-name signed by\nthe cluster CA that the server renews, and adds the person running it through\nsudo to the group.\nThe certificate has the rights the cluster gives that user; a name the cluster\nhas no record of is recorded as a cluster-admin, as the first user is (a leader\ntoo old to record it gets no config written). An existing file stays.\n\nRun three control plane nodes to tolerate the loss of one; with two, losing\neither stops the control plane.")
        .example("  sudo armadad server join 10.0.0.2:7444 --ca-hash sha256:3f1c...   # from armada server join-token\n  sudo armadad server join 10.0.0.2:7444 --ca-hash sha256:3f1c... --name server2")
        .args(Args::Exact(1))
        .run(commands::join::server)
        .flag(Flag::string("ca-hash", None, "", "cluster CA hash, sha256:..."))
        .flag(Flag::string("container-subnet", None, "10.121.0.0/24", "private IPv4 subnet for this node's containers (clusters without a cluster network; others give each node a subnet)"))
        .flag(Flag::string("data-dir", None, "/var/lib/armada", "directory for cluster state and keys"))
        .flag(Flag::string("endpoint", None, "", "joins over a public ADDR (mesh clusters, other sites): this machine's public IPv4 address, which other nodes send WireGuard packets to (default: the only public IPv4 address; behind one-to-one NAT, the mapped address)"))
        .flag(Flag::int("join-port", None, 0, "join listener port on the private IP (default: --port + 1)"))
        .flag(Flag::string("name", None, "", "server and node name (default: hostname)"))
        .flag(Flag::bool("no-private-ip", None, false, "joining from another site: send no private IP, and get a mesh address the other nodes reach over WireGuard (the default when the machine has no private IPv4 address)"))
        .flag(Flag::int("port", None, 7443, "control plane port on the private IP"))
        .flag(Flag::string("private-ip", None, "", "this machine's private IP (default: the only private IPv4 address; not in a mesh cluster)"))
        .flag(Flag::string("runtime", None, "supervisor", "container runtime: supervisor (no containerd daemon, ADR 0046), or embedded (containerd)"))
        .flag(Flag::string("token-file", None, "", "file holding the server token (default: prompt or stdin)"))
        .flag(Flag::string("user-name", None, "", "user named in the client config written here (default: the user running it)"));
    n.required = vec!["ca-hash"];
    let i_root_server_join = t.add(i_root_server, n);
    let mut n = Node::new("upgrade [--version vX.Y.Z]", "Upgrade this machine to the latest (or a given) release and restart its service")
        .long("upgrade downloads a release, verifies its checksum (and its signature when cosign is\ninstalled), replaces armadad and armada and the systemd units, and restarts\narmada-runtime (containers keep running), armada-etcd, armada-server, and armada-agent,\neach where it runs. Upgrade servers first, one at a time, then the other\nnodes (docs/operations.md#upgrades). ARMADA_DOWNLOAD_BASE points at a mirror.\n\nIt refuses older releases but one: --version v0.1.0-alpha.42, the last release\nbefore armadad moved to Rust, rolls this machine back to it (stops armada-server,\narmada-agent, and armada-etcd, removes the units that release lacks, installs\nit, and starts its service; docs/operations.md#rolling-back-to-the-last-go-release).")
        .example("  sudo armadad upgrade                       # the latest release; servers first, one at a time\n  sudo armadad upgrade --version v0.1.0-alpha.40\n  sudo armadad upgrade --no-restart          # install only; restart the services later")
        .args(Args::No)
        .run(commands::upgrade::run)
        .flag(Flag::bool("no-restart", None, false, "install only; restart the service yourself"))
        .flag(Flag::bool("require-signature", None, false, "fail unless cosign verifies the release signature (or ARMADA_REQUIRE_SIGNATURE=1)"))
        .flag(Flag::string("version", None, "", "release to install (default: the latest)"));
    let i_root_upgrade = t.add(0, n);
    let mut n = Node::new("user", "Recover a user's credentials on a server").noun();
    let i_root_user = t.add(0, n);
    let mut n = Node::new("renew", "Renew a user certificate with the cluster CA on this server")
        .long("Get a new one-year certificate for a new key, under the same name, signed\nby the cluster CA in the data directory, and rewrite the client config\n(--config, default ~/.armada/config, else /etc/armada/admin.config; another\nuser's config stays theirs, a shared one stays shared).\nFor a certificate that has already expired; while it is valid,\n`armada user renew` does the same through the control plane.\nThe user keeps the roles on record; a name the cluster has no record of\nis recorded first, with cluster-admin (the cluster refuses certificates\nof names it has no record of). It needs the cluster state: run it on a\nserver whose control plane is running or can start.")
        .example("  sudo armadad user renew    # an expired certificate in /etc/armada/admin.config")
        .args(Args::No)
        .run(commands::user::renew)
        .flag(Flag::string("data-dir", None, "/var/lib/armada", "server data directory holding the cluster CA"));
    let i_root_user_renew = t.add(i_root_user, n);
    let mut n = Node::new("version", "Print build information and the latest release")
        .example("  armadad version")
        .args(Args::No)
        .run(commands::version::run)
        .flag(Flag::string(
            "output",
            Some('o'),
            "text",
            "output format: text or json",
        ));
    let i_root_version = t.add(0, n);
    t
}

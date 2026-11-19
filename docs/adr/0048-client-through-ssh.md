# ADR 0048: The client reaches the control plane through SSH

## Status

Accepted

## Context

The API listens only on the servers' private addresses (security rule 4),
so a person's computer outside the private network reaches it through a
VPN or an SSH tunnel they open and keep open themselves, with the config
pointed at the tunnel's local ports. Several servers mean several
forwards, since only the leader serves and the leader moves. People wrote
the same tunnel script again for every computer and every cluster.

## Decision

A client config may name an SSH destination, `ssh` (`clientconfig.Config.SSH`):
`[user@]host`, a host alias from `~/.ssh/config`, or
`ssh://[user@]host[:port]`. With it, every connection to a control plane
address runs the user's own `ssh -o ExitOnForwardFailure=yes -W ADDR -- DEST`
and speaks gRPC over its standard input and output, the way git reaches an
SSH remote (`clientconfig.sshDialer`).

- The servers in the config are the servers' own private addresses, as
  the SSH host reaches them, and the client tries them in order like any
  other config: a leader change needs nothing new. The machine's
  `/etc/armada/servers` is not added, since it is this computer's view.
- mTLS runs end to end inside the SSH connection: the SSH host relays
  bytes and holds no key of the cluster's. Authentication to the SSH host
  is ssh's own (keys, agent, `known_hosts`, `ProxyJump`); Armada carries no
  SSH implementation and stores no SSH secret.
- `CheckSSH` accepts only destinations that cannot be read as an ssh
  option (no leading `-`, no spaces or shell characters; `--` ends the
  options), on load and on the flags. The forwarded address is the value
  of `-W`, and an address starting with `-` is refused. ssh's own last
  error line is shown when a connection fails (it never prints keys).
- `armada rbac user create` and `credentials` take `--ssh DEST`: the
  written config names the cluster's server addresses (`ListServers`,
  leader first) and the destination, so it works from any computer that
  can SSH to that host.

## Consequences

- No new port faces the public: the only way in is the SSH service the
  machines already run. Security rule 4 holds.
- Every command pays an SSH connection (about a second); a person who
  runs many can turn on ssh's connection sharing (`ControlMaster`) in
  `~/.ssh/config`.
- Whoever controls the SSH host can stop or delay the traffic, as with any
  network path, but cannot read it or pose as a server: the client checks
  the server certificate against the cluster CA.
- The client needs an `ssh` program for such configs (present on Linux,
  macOS, and WSL).

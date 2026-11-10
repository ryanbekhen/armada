# 0027. Client and daemon binaries

- Status: Accepted
- Date: 2026-11-08

## Context

Armada shipped one binary, `armada`, for everything: the services systemd runs
on every machine (control plane, node agent, embedded container runtime), the
commands that set a machine up or inspect it as root (`init`, `join`,
`doctor`, `backup`, `restore`, `runtime reset`), and the client that deploys
and manages apps through the control plane's API.

That mix has costs:

- The client links what only a machine needs: the embedded containerd, runc,
  and CNI plugins, etcd, HAProxy management, the cluster network. A release
  binary is about 75 MB, and the client cannot be built for systems Armada does
  not run on, so an operator on a workstation that is not Linux cannot use it.
- One command list mixes daily work (`deploy`, `logs`, `status`) with commands
  that need root and change the machine. Which is which is not visible, and
  `sudo armada ...` became the habit for both.

## Decision

Armada ships two binaries from one module:

- **`armadad`** (`cmd/armadad`, package `internal/daemon`) runs on every
  machine and needs root: `server`, `agent`, `runtime`, and the hidden
  `runtime-log` (what systemd and the container runtime run), `init`,
  `join`, `server join`, `doctor`, `backup`, `restore`, `runtime reset`, and
  `admin renew`, which signs an administrator certificate with the CA on a
  server's disk once it has expired. Release builds embed the runtime bundle
  (ADR 0011) in it. The systemd units run `armadad`.
- **`armada`** (`cmd/armada`, package `internal/cli`) is the client: every
  command that only talks to the control plane over mTLS with the
  credentials in `~/.armada/config`. It needs no root and builds for Linux
  and macOS. `armada server list|remove` stay client commands; running and
  adding a server are `armadad` commands.

`internal/cli` never imports `internal/daemon`, and a test checks that the
client does not depend on the runtime, the agent, the server, etcd, or the
cluster network. `internal/daemon` may use the client's exported helpers
(`cli.Run`, `cli.RPCError`, `cli.ReadSecretValue`, `cli.NewVersionCommand`).
Both print the same `version`.

Releases carry one archive per Linux platform with both binaries and the
units, and a client-only archive per macOS platform. `install.sh` installs
both on Linux and only the client on macOS or with `ARMADA_CLIENT_ONLY=1`.
It only installs: creating or joining the cluster stays an `armadad`
command the operator runs and configures. `armada token create` prints the
install line pinned to the server's release, then the `armadad` command.

`armadad init` writes the admin config to `/etc/armada/admin.config`, owned
by root with mode 0640 and group `armada`, which the installer creates
(`/etc/armada` gets search permission only, so the file is reached by name
and the directory cannot be listed). Members of the group run `armada`
without root and without a copy of their own; membership is full control
of the cluster, like the file itself. The client reads `$ARMADA_CONFIG`,
else `~/.armada/config` when it exists, else `/etc/armada/admin.config`, and
accepts a group-readable config only when root owns it with exactly that
mode and group. Rewriting a config (`admin renew`, `server list`) keeps its
owner, group, and mode; a member who cannot write the shared file is told to
use sudo, and `server list` still prints. Without the group, `init` leaves
the file 0600. `--config` or `ARMADA_CONFIG` still writes a private config
wherever the operator wants.

Joining a group counts only in login sessions that start afterwards, so the
person who runs `sudo armadad init` would otherwise need `sudo` or a new
login before `armada` works. `init` therefore also writes the config as
`~/.armada/config` of that user (`SUDO_USER`, only when it matches
`SUDO_UID` and is not root), with the first administrator certificate named
after them. It creates the file with `O_EXCL` and the directory through
`os.Root` on the home directory, so it never replaces a file or follows a
link out of the home, and gives both to the user (0600 and 0700); a failure
there only warns, since the cluster already exists. When the shared file
cannot be read, the client says whether the account is outside the group or
joined it after the session started.

## Consequences

- The client is about 15 MB and runs on an operator's workstation, Linux or
  macOS, as long as it reaches the control plane's private address.
- Machine commands are visibly separate: `sudo armadad ...` on a machine,
  `armada ...` anywhere.
- An upgrade from a release with one binary is the usual one (`install.sh`,
  then restart the units): the installer adds `armadad` and rewrites the
  units, and `armada` becomes the client. Scripts that ran machine commands
  through `armada` must call `armadad`.
- Tests that run a server in process and drive client commands live in
  `internal/daemon` and send each command to the binary that has it.

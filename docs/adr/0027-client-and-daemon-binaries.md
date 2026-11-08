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

`armadad init` writes the admin config for the user that runs it (root) and
says how to copy it to another user, who then runs `armada` without root.
`armadad admin renew` keeps the owner of a config it rewrites.

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

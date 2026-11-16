# 0030. Release checks and machine upgrades

- Status: Accepted
- Date: 2026-11-10

## Context

Operators learned about new releases only by watching the repository, and
upgrading a machine meant running the installer with a pinned version and
restarting the right service by hand. Upgrades are rolling (ADR 0012):
servers first, one at a time, then nodes.

## Decision

**Finding out.** `internal/release` asks GitHub's API for the latest release:
the latest stable one, else, while there is none, the newest published
pre-release by version among the last 100 (the installer's rule; the API
does not list releases in version order), within 3 seconds, believing only a tag
shaped like a release. Versions compare by semantic versioning, with
pre-releases before their release. It is asked by:

- `armada version`, which also shows the servers' versions;
- `armadad doctor`, whose `release` check warns when the machine is behind;
- the client, at most once a day per user and only when a person reads
  its stderr (a terminal), with a one-line notice after the command. The
  time of the last look is written before asking, so a blocked or slow
  network costs one try a day and never more than a second of waiting.

`ARMADA_NO_UPDATE_CHECK=1` turns all of it off, and so does `CI`. Servers
and agents never ask: a cluster does not depend on reaching GitHub.

**Upgrading.** `sudo armadad upgrade [--version vX]` upgrades the machine it
runs on, and nothing else. It downloads the release over HTTPS (or from a
`file://` mirror named by `ARMADA_DOWNLOAD_BASE`), verifies it exactly as
the installer does (the cosign signature of the checksum file by this
repository's release workflow for that tag when cosign is installed, made
mandatory by `--require-signature`, then the archive's checksum), takes only
the two binaries and the systemd units from the archive, replaces each file
atomically, reloads systemd, and restarts `armada-runtime` when it runs, so
the node uses the runtime pack (containerd, runc, `armada-log`; ADR 0011)
the new `armadad` carries (its unit kills only containerd: containers and
their shims keep running), then whichever of `armada-server` and
`armada-agent` runs. Without that, a node kept the pack it extracted when
the runtime last started, so runtime fixes in a release never reached it;
`armadad doctor` warns (`runtime-pack`) when the running pack is not the
binary's. It refuses a release older than the running one,
because state migrations only go forward (ADR 0012).

Armada's services restart only when `armadad upgrade` or the operator asks.
On machines with needrestart (Debian, Ubuntu), `armadad upgrade` and the
installer write `/etc/needrestart/conf.d/armada.conf`, so a package upgrade
lists `armada-*` services but never restarts them. Without it, needrestart
restarts `armada-runtime` at the next package upgrade after every Armada
upgrade, because the containers' log processes still run the replaced
binary.

The control plane does not upgrade machines itself. A cluster-wide upgrade
pushed from the leader would turn one bad release, or one stolen
administrator certificate, into code running as root on every machine at
once; one command per machine keeps the operator in charge of the order
and of when to stop.

## Consequences

- One command per machine replaces the installer line and the restart;
  the operations guide lists the order.
- Releases from before this command upgrade once more with the
  installer.
- A machine without access to GitHub upgrades from a mirror; the checks
  are the same.
- The client and doctor make an HTTPS request to GitHub that reveals that
  someone runs Armada; the variable above stops it.

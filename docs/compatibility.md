# Compatibility and deprecation

What stays the same from one release to the next, what may change, and
how a change that breaks something is announced. Armada holds the state of
the apps you run, so upgrades are planned around one rule: **an upgrade
never stops an app that was serving, and never changes what it runs.**

## Release stages

Versions follow [semantic versioning](https://semver.org): `vMAJOR.MINOR.PATCH`,
with a pre-release suffix during development.

| Stage | Tags | What may change |
| --- | --- | --- |
| Alpha | `v0.1.0-alpha.N` | Anything, including commands, spec fields, and the API. Each change that breaks something is named in the release notes with what to do. Running clusters and their apps keep working across the upgrade. |
| Beta | `v0.1.0-beta.N` | Features are frozen: fixes only. Nothing that this page calls stable changes, unless a security fix needs it. |
| Stable | `v0.1.0`, `v0.1.1`, ... | Patch releases fix bugs and security issues and never break what this page calls stable. |
| Next minor | `v0.2.0` | May remove what an earlier minor release deprecated (see [Deprecation](#deprecation)), never without a release in between that warned. |

Before `v1.0.0`, a minor release (`0.1` to `0.2`) is where deprecated
things go away; from `v1.0.0` on, only a major release removes anything.

## What is stable

From the first beta, these keep working across upgrades within the stable
rules above:

- **App and job specs.** Every field keeps its name and meaning. New
  fields are optional and leave existing specs as they were. Specs are
  parsed strictly, so a spec using a field from a newer release is refused
  by an older one with an error that names the field. A spec exported with
  `armada app show -o yaml` deploys on any release of the same minor line
  or newer.
- **Revisions already stored.** A revision runs as it was deployed,
  whatever release reads it: a rollback to it, a restart, or a secret
  rollout never reinterprets its spec.
- **The command line.** Commands (`armada NOUN VERB`), their arguments,
  and their flags keep their names and meaning. New flags are optional.
  Errors and table output are for people and may change; scripts read
  `-o json`, whose fields are only added to (see [the API](#the-api)).
  Exit codes keep their meaning: 0 for success, and for `armada app exec`
  the command's own.
- **The API.** The gRPC service in `api/armada/v1` only gains methods and
  fields. Field numbers are never reused; a removed field is reserved.
- **Metrics, events, and audit records.** Metric names and their labels,
  event reasons, and audit actions keep their names. New ones are added;
  one that goes away is deprecated first.
- **Machine commands.** `armadad` commands, their flags, the files they
  write under `/etc/armada` and the data directory, and the systemd units.

Not stable: anything named experimental in its documentation, and
behaviour the documentation does not describe.

## Versions side by side

A cluster is upgraded one machine at a time, so versions mix for a while
([operations guide](operations.md#upgrades)):

- **Servers and agents.** Agents of the release before the servers' keep
  running their replicas and taking new ones; the agent protocol only
  gains fields, and a feature an older agent cannot run safely is placed
  only on agents that announce it. Upgrade the servers first, then the
  nodes, one at a time.
- **State.** When a release changes the layout of the state, upgraded
  servers wait until every server is upgraded before one of them leads
  and migrates it ([ADR 0012](adr/0012-upgrades-and-state-schema.md)). A
  feature that needs the new layout is refused with an error naming it
  until then.
- **The client and the cluster.** An `armada` client works with servers of
  the same release and the release before. A command the servers do not
  know yet fails with an error and changes nothing; an older client sees
  everything except the fields added since.
- **Skipping releases.** Upgrading from any earlier release of the same
  minor line straight to the latest works: state migrations run in order.
  Across minor lines, upgrade to the latest patch of each minor line in
  turn.

## What never happens on an upgrade

- No app restarts because of the upgrade itself. `armadad upgrade`
  restarts Armada's own services; containers keep running and are adopted
  by the new agent. A change that needs containers recreated (a new
  runtime, a new network mode) is a separate step a person takes, one
  node or app at a time. An upgrade may move work between Armada's own
  programs on a machine: supervisor nodes move to `armada-node`, whose
  agent converts the node's image store at its start without pulling
  images again or stopping containers
  ([operations guide](operations.md#containers-in-armada-node)).
  One exception, for the containerd runtime's removal below: the leader
  moves nodes still on containerd (running v0.1.0-alpha.42) to the
  supervisor runtime by itself, one node at a time, draining each first
  so its apps keep serving elsewhere
  ([operations guide](operations.md#container-runtimes)).
  `armada cluster update --runtime-move=false` turns that off, but a
  node left on containerd cannot be upgraded.
- No setting changes. The container runtime (but for the move above), the
  network mode, spaces, roles, secrets, and specs stay as they were; new
  defaults apply to what is created after the upgrade.
- No downgrade. A binary refuses state written by a newer release instead
  of misreading it, and `armadad upgrade` refuses older releases. The way
  back is the backup taken before the upgrade (`armadad backup`, or the
  scheduled one in the bucket).
- One exception: v0.1.0-alpha.42, the last release of Go's `armadad`, is a
  rollback target for the release that moved Armada to Rust (ADR 0055).
  `sudo armadad upgrade --version v0.1.0-alpha.42` rolls one machine back
  in place: it stops `armada-server`, `armada-agent`, and `armada-etcd`,
  removes the units that release lacks, installs it, and starts its
  service; the state, the containers, and the images stay
  ([operations guide](operations.md#rolling-back-to-the-last-go-release)).
  No other older release is a rollback target.

## Deprecation

When something stable has to go:

1. The release that deprecates it says so in its notes, with what to use
   instead. The documentation marks it deprecated.
2. Using it keeps working and warns where a person sees it, with the
   replacement named: a line on the CLI's standard error, or a warning
   from `armadad doctor` for what lives on a machine.
3. It goes away no earlier than the next minor release (before `v1.0.0`)
   or the next major release (from `v1.0.0` on), and never in a patch
   release.

A security fix may break something sooner, when keeping it would leave
clusters exposed; its release notes say so and why.

Nothing is deprecated now.

Removed:

- **The containerd runtime** (`--runtime embedded`), deprecated since the
  supervisor runtime became the default
  ([ADR 0046](adr/0046-runtime-supervisor.md)), left the runtime pack
  with the release after v0.1.0-alpha.42 (ADR 0055): `armadad init`,
  `join`, and `server join` refuse `--runtime embedded`, and `armadad
  runtime migrate` is gone. Move every node still on containerd to the
  supervisor runtime **before** upgrading it: with the servers upgraded
  first, the leader moves nodes that still run v0.1.0-alpha.42 by itself,
  one at a time, or run v0.1.0-alpha.42's `armadad runtime migrate --to
  supervisor` on the node ([operations guide](operations.md#container-runtimes)).
  On a node upgraded while still on containerd, the agent starts and
  removes nothing and `armadad doctor` fails; roll it back to
  v0.1.0-alpha.42 and move it, or remove it and join it again.

## Platforms

Armada runs on Linux machines, amd64 and arm64, with systemd, cgroup v2,
and overlayfs ([quickstart](quickstart.md)); the client also runs on macOS
and in WSL 2. A release that drops a platform is a minor release, and the
one before it warns. [Tested environments](tested-environments.md) lists
where each release was tested end to end.

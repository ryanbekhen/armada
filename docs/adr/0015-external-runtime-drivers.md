# 0015. External runtime drivers

- Status: Accepted
- Date: 2026-11-02

## Context

Armada runs containers through its own embedded containerd (ADR 0011).
That keeps every node the same and the security defaults under Armada's
control, but some machines already have a container engine their operators
want to keep, and some platforms cannot run containerd at all (macOS runs
containers in lightweight virtual machines). Building each engine into the
core would tie Armada's releases and security posture to engines whose
behaviour changes outside its control.

ADR 0011 left room for **external drivers**: separate programs that run
containers for the agent through a stable protocol. This ADR settles that
protocol, who starts drivers, how the agent trusts them, and how a driver
proves it keeps Armada's security defaults.

## Decision

### The protocol

- A driver serves the gRPC service `armada.driver.v1.Driver`
  (`api/armada/driver/v1`) on a Unix socket. It mirrors the agent's
  `runtime.Driver`, `runtime.SystemRunner`, and `runtime.BridgeInspector`:
  `Info`, `Ping`, `Pull`, `Run`, `Stop`, `Remove`, `List`, `Inspect`,
  `Logs` (a server stream), `RunSystem`, `Exec`, `Signal`, and `Bridge`.
- `Info` is the handshake. It returns the protocol version, the driver's
  name and version, the node platform as the driver's engine sees it, and
  the optional capabilities the driver has:
  - **system containers** (`RunSystem`, `Exec`, `Signal`), which the node's
    HAProxy needs. Without them the node must run with `--proxy none`: it
    runs replicas, and HAProxy on the other nodes routes to them over the
    private network.
  - **bridge** (`Bridge`), which internal DNS and internal ingress need on
    the node (ADR 0007). Without it, containers on that node cannot resolve
    `<app>.internal`.
- The agent refuses a driver whose protocol major version differs from its
  own, and a node set up for a capability the driver lacks. New optional
  features are added as new capabilities and fields, never by changing the
  meaning of existing ones.

### Starting and trusting a driver

- A driver is installed with its own systemd unit
  (`armada-driver-NAME.service`) and listens on
  `/run/armada/drivers/NAME.sock`. The agent never starts programs itself:
  it only connects to that socket.
- A driver runs as root and has the agent's trust: installing one is a
  decision of the same weight as installing Armada. The agent connects only
  when the socket and its directory are owned by root and closed to group
  and others, and when the process on the other end runs as uid 0 (peer
  credentials). There is no TCP transport.
- Driver names are lowercase letters, digits, and `-`, up to 32
  characters; `embedded` is reserved for the built-in runtime.

### Keeping the security defaults

- The agent still checks every container spec (`runtime.CheckContainerSpec`:
  private publish addresses and DNS servers, regular files as the only
  mounts) before it reaches a driver, and the driver library checks it again
  on arrival.
- The protocol's container spec carries the defaults as explicit fields
  that a driver must apply or refuse: no new privileges, the capabilities
  to drop, the memory, CPU, and PID limits, read-only file mounts, and no
  host network, privileged mode, or engine socket. Nothing in the protocol
  can ask for less.
- A **conformance suite** (`driverkit/conformance`) runs containers through
  a driver and checks the defaults from inside them (no-new-privileges,
  dropped capabilities, limits, read-only mounts, the publish address),
  along with labels, adoption of existing containers, logs, and errors.
  Drivers that Armada documents must pass it, and the embedded runtime runs
  it too.

### The driver library

- `github.com/ryanbekhen/armada/driverkit` is a small public Go package for
  driver authors, the one exception to keeping Go code under `internal/`.
  It defines the interface a driver implements with its own types, serves
  it over the protocol with the checks above, and holds the conformance
  suite. It does not depend on any engine.
- Drivers live in their own repositories, released and signed on their
  own. The first one, for the Docker Engine API, is the reference driver
  and is held to the same rules as anyone else's.

### On the node

- `armada init` and `armada join` take `--runtime NAME` (default
  `embedded`) and record it in `agent.json`; the agent waits for the
  driver's socket as it waits for the embedded runtime.
- Every node reports its runtime as the label `armada.runtime`, so apps can
  `require` one (ADR 0014). A node with a driver reports the platform the
  driver's engine runs containers on as `armada.os` and `armada.arch`.
- `--container-subnet` belongs to the embedded runtime; a driver chooses
  its own container network. `armada runtime reset` works through the
  driver and removes only containers with Armada's labels, since the
  engine may run others. `armada doctor` checks the driver's socket and
  warns when it cannot run system containers.
- The embedded runtime stays in the agent's process: it is the default and
  the reference, and moving it behind a socket would add a hop and a
  failure mode for no gain.

## Alternatives considered

- **The agent starts driver programs from a directory:** one unit fewer,
  but the agent would gain a path to execute programs, and a driver's
  lifetime would be tied to the agent's.
- **Loading drivers into the agent's process:** a broken driver would
  crash the agent, and in-process plugins in Go need CGO and an exact
  toolchain match.
- **One engine's API as the protocol:** drivers for other engines would
  have to emulate it, and its security knobs are not Armada's.
- **Only publishing the protobuf definitions:** every driver would rewrite
  the checks and the serving code, and some would get them wrong.
- **Drivers in Armada's repository:** easier to release together, but the
  core would again carry engine code, which ADR 0011 removed.

## Consequences

- Operators can run Armada on machines whose container engine they keep,
  and platforms that cannot run containerd can join as compute nodes.
- A driver is trusted like root: the threat model covers what a malicious
  or buggy one can do, and the conformance suite is how a driver earns a
  place in the documentation.
- The protocol is a public interface: it changes only by adding
  capabilities and fields, and a new major version is a new service.

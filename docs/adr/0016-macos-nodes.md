# 0016. macOS nodes

- Status: Accepted
- Date: 2026-11-02

## Context

Container images hold Linux programs, and the isolation Armada relies on
(namespaces, cgroups, seccomp, `no-new-privileges`) is part of the Linux
kernel. macOS has neither, so a Mac can only run Armada's containers inside
Linux virtual machines. There are two ways to do that:

- **A Linux virtual machine on the Mac as the node.** It runs Armada like
  any other Linux machine, with every default and feature. It needs no
  change to Armada.
- **The Mac itself as the node**, with a runtime that starts every
  container in its own lightweight virtual machine: Apple's `container`
  tool on Apple silicon. This is what external drivers (ADR 0015) were left
  room for, but the tool differs from Linux runtimes in ways that touch
  Armada's rules:
  - It cannot set `no-new-privileges`, a seccomp profile, or a PID limit
    inside a container, and refuses less than 200 MiB of memory.
  - It serves only the logged-in user who started it, not root.
  - Containers have no host network, so HAProxy cannot run on the Mac.
  - A process that is not root cannot bind a port below 1024 on the
    container network's gateway, where internal DNS listens.
  - macOS has no tmpfs for secret files.

A Docker Engine for macOS runs all containers in one Linux virtual machine,
so the usual defaults hold there, but it is heavier than the per-container
virtual machines.

This ADR settles how a Mac joins as a node and what that node does not do.

## Decision

### Supported ways

- The documentation describes, from lightest to fullest:
  - **The Mac itself as a compute node through `armada-driver-apple`**
    (its own repository, built on `driverkit`, runtime name `apple`). It
    is the lightest way to run replicas on a Mac and suits trying Armada
    out, or production use by operators who accept its consequences
    (below).
  - **The Mac as a compute node through `armada-driver-docker`** on a
    Docker Engine for macOS. Its containers share one Linux kernel inside
    the engine's virtual machine, so they keep `no-new-privileges`,
    seccomp, and the PID limit. This is the way to use when the Apple
    driver's consequences are a problem.
  - **A Linux virtual machine on the Mac as a full node**, with every
    feature, including HAProxy and internal DNS.
- Both drivers run on the agent side described below; supporting macOS in
  `armada-driver-docker` is a change in that driver's repository.

### The agent on macOS

- `armada join` and `armada agent` run on macOS (darwin/arm64); `armada
  init`, `armada server`, `server join`, and `armada runtime` refuse to,
  since the control plane, etcd, and the embedded runtime stay on Linux. A
  macOS node always uses an external driver and `--proxy none`.
- The agent and the driver run as **one dedicated macOS user**, not root,
  each as a LaunchAgent in that user's login session, because the
  container tool only serves the logged-in user. The node runs while that
  user is logged in; after a restart the Mac needs automatic login (or a
  login) for the node to come back.
- The agent's data lives in that user's home
  (`~/Library/Application Support/Armada`, mode `0700`, files `0600`), and
  the driver socket in `run/drivers/NAME.sock` below it.
- **Driver trust follows the agent's own user**: the agent connects only
  when the driver directory and socket are owned by the agent's uid and
  closed to group and others, and the peer process runs as that same uid.
  On Linux the agent runs as root, so the rule there is unchanged (uid 0).
  Whoever holds the macOS account controls the node, as root does on
  Linux.
- **Secret files** go to a RAM disk the agent creates and mounts on the
  secrets directory, owned by the agent's user with mode `0700`; the agent
  refuses to write secrets anywhere else, as it refuses a non-tmpfs
  directory on Linux.

### What the driver declares

- The handshake gains three optional fields:
  - **VM isolation**: every container runs in its own virtual machine with
    its own kernel. Only a driver that declares it may leave out
    `no-new-privileges` and the PID limit, which guard a kernel shared with
    the host and other containers; the VM's memory and CPU limits still
    apply, and capabilities are still dropped. `driverkit` keeps refusing
    specs without the defaults, so the agent sends the same spec to every
    driver.
  - **Minimum memory**: the smallest memory limit the driver accepts. The
    node reports it, and the scheduler does not place a replica whose
    memory limit is below it on that node, rather than raising the limit
    behind the reservation's back.
  - **Capacity**: the CPU and memory the engine can give containers, when
    that is less than the machine has. An engine that runs every container
    in one virtual machine of fixed size accepts limits beyond that
    machine, so the node reports the smaller of the machine's and the
    driver's capacity, and the scheduler never reserves more than the
    virtual machine holds. A larger value than the machine's is ignored.
- The conformance suite checks the claim: with VM isolation it checks that
  two containers run on different kernels (different boot IDs) instead of
  checking `no-new-privileges` and the PID limit from inside them.
- `armada-driver-apple` declares neither system containers nor bridge:
  the node runs with `--proxy none`, and containers on it cannot resolve
  or reach `<app>.internal`. Apps on the Mac are still served through
  HAProxy on the other nodes, over their published ports on the Mac's
  private IP.

### Platform

- The node reports `armada.os=linux`, `armada.arch=arm64`, and
  `armada.runtime=apple`: placement treats it like any other arm64 node,
  and apps can require or avoid the runtime. Images without a linux/arm64
  variant do not run there.

## Alternatives considered

- **Only the Linux virtual machine:** no rule needs relaxing, but a Mac
  could never run replicas without the operator managing a VM.
- **Armada starting its own virtual machine on the Mac:** the smoothest
  setup, but the macOS virtualization framework needs CGO, which the core
  does not allow; it would have to be a separate program, a larger project
  than a driver.
- **Running the agent as root and the driver as a user:** keeps uid 0 for
  the agent, but the agent would trust a socket that a user process
  controls, which is the same trust with more moving parts.
- **Raising small memory limits to the driver's minimum:** replicas would
  use more memory than the control plane reserved for them.

## Consequences

- A Mac can run replicas as a compute node without a VM to manage. A Mac
  node does not run HAProxy or internal DNS, its containers cannot call
  `<app>.internal`, and it runs only while its user is logged in; with the
  Apple driver, apps below 200 MiB of memory are not placed on it.
- Containers on an Apple driver node rely on a VM boundary instead of
  `no-new-privileges`, seccomp, and a PID limit. The threat model records
  this, apps that should not run that way can avoid the runtime with
  placement, and operators who need those defaults on a Mac use the Docker
  driver or a Linux virtual machine.
- Driver trust is now "the agent's own user" rather than "root". The
  protocol and the Linux behaviour do not change.

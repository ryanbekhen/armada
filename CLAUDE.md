# CLAUDE.md

Guidance for Claude Code when working in this repository.

## About the project

Armada is a multi-machine container platform (cloud instances, VMs, or bare metal; do not describe it as VPS-specific). Docs describe Armada on its own terms: do not compare it with or name other products unless a component or protocol really needs naming. A single Go binary has two roles: `armada server` (control plane) and `armada agent` (runs on every node and runs containers through Armada's embedded containerd, ADR 0011, or through an external driver, ADR 0015). Ingress uses HAProxy as a system container managed by Armada.

- **Architecture decisions:** `docs/adr/`. **Threat model:** `docs/threat-model.md`

When the design changes, add or update an ADR in the same change. Never let code and documents contradict each other (see "Keeping documents current" below).

## Status

Phases 0–6 are done and tested end to end in local lab VMs (Pebble ACME) and in the cloud: a single server on Oracle Cloud (Oracle Linux 9, SELinux enforcing, Let's Encrypt staging, HTTP-01 and Cloudflare DNS-01 wildcard) three control plane servers on depa.id (leader stop and SIGKILL under load, rolling update through the new leader, all machines rebooted at once), and a mixed cluster of those servers (amd64) with the Oracle machine (arm64) as a node. Phase 7 (hardening, documentation, release) is in progress: security review fixes, `armada doctor`, signed release pipeline (GoReleaser + cosign + SBOM + provenance), `install.sh`, `armada backup`/`restore`, self-healing (ADR 0008), the embedded etcd state store (ADR 0009), the HA control plane (ADR 0010), the embedded container runtime (ADR 0011), quickstart, spec reference and operations guide are done. Roadmap stage 1 is in progress: rolling upgrades with gated state migrations (ADR 0012), SELinux confinement of containers, replica rebalancing (ADR 0013), and the cloud end-to-end test (`test/e2e`) are done; placement (ADR 0014) is in progress: node labels, restricted nodes, `placement.require`, image platforms, CPU and memory reservations, and `spreadBy` are done. External runtime drivers (ADR 0015) are in progress: the protocol, `driverkit` with its conformance suite, the agent side (`--runtime NAME`, `armada.runtime`) are done; the Docker driver lives in its own repository (`github.com/ryanbekhen/armada-driver-docker`, passes the conformance suite and a smoke test of a cluster on it in its CI); macOS nodes come next. More roadmap stages come before the first tagged release. Do not build features outside the agreed scope unless asked.

Module path: `github.com/ryanbekhen/armada`. The toolchain is pinned with `toolchain` in `go.mod` (a patch release with no govulncheck findings); golangci-lint must be built with the same toolchain.

## Commands

Keep this section up to date.

```bash
make check          # vet + lint + test + govulncheck (same as CI)
make build          # build the binary into ./bin/armada
make test           # go test ./... -race
make lint           # golangci-lint run, also with GOOS=linux (v2.15.0+)
make fmt            # golangci-lint fmt (gofmt + goimports)
make proto          # protoc + plugins pinned in go.mod (api/armada/v1, api/armada/driver/v1)
make vuln           # govulncheck ./...
make runtime-bundle # download + checksum the pinned runtime binaries into packs (both arches)
make build-bundle   # Linux binary with the runtime embedded (GOARCH=arm64 for arm64)
go test ./internal/spec/... -run TestName      # a single test
go test ./internal/proxy/haproxy -update        # update golden files
go test ./internal/proxy/haproxy -fuzz FuzzRender -fuzztime 30s
go test -tags integration -run Integration ./internal/proxy/haproxy/   # haproxy -c on rendered configs (dev only; needs a container CLI)
sudo ARMADA_BIN=/usr/local/bin/armada go test -tags integration -run Conformance ./internal/runtime/containerd/   # driver conformance suite on the embedded runtime (on a node)
goreleaser check                                 # validate .goreleaser.yaml
shellcheck install.sh scripts/*.sh test/e2e/*.sh && sh test/install_test.sh # shell scripts + installer tests (Linux)
sh scripts/check-commits.sh origin/main..HEAD    # commit subjects (Conventional Commits, checked in CI)
sh scripts/sync-labels.sh                        # create/update repo labels from .github/labels.json (also done by CI)
sh test/e2e/cluster.sh HOSTS                     # end to end on real machines (test/e2e/README.md; before releases)
armada doctor                                    # pre-flight checks on a node
armada backup -o FILE / armada restore FILE      # control plane backup and restore
armada runtime [--bin-dir DIR] / armada runtime reset   # embedded containerd (systemd unit) / remove Armada's containers
armada init|join --runtime NAME                  # use an external driver (/run/armada/drivers/NAME.sock)
```

## Architecture in brief

- **Desired state + reconciliation**: the CLI only writes desired state to the server; reconcilers on the server and agents converge actual state. Every operation goes through this path; never add a "just run the container" path from the CLI.
- Agents open the gRPC (mTLS) connection to the server; the server sends assignments over a bidirectional stream.
- Nodes (ADR 0003): joining goes through a separate join listener (server-only TLS, serves only `JoinService`, rate limited); the main API is always strict mTLS. The joining node pins the CA by hash without `InsecureSkipVerify`. Node certificates last 30 days, are renewed by the agent, and are only accepted while their serial is recorded in `node_certs` (removing a node revokes them). Cordoned nodes get no new replicas and are evacuated without dropping below the desired serving count. Unevenly spread apps are rebalanced one replica at a time across the cluster through the same path (ADR 0013). Placement (ADR 0014): admin-only node labels (CLI or join token; `armada.os`/`armada.arch` reported by the agent, `armada.` reserved), restricted nodes, `placement.require`, and `placement.spreadBy` (soft: even over a label's values, then nodes; yields to capacity; only labelled nodes; rebalancing compares values first, then nodes within a value); every scheduling path (scale, rollout, self-healing, evacuation, rebalancing) only picks nodes from `eligible()`, and replicas on nodes that stop being eligible move like cordoned ones. Image platforms are learned from agents after a pull (or from the registry when the image has no variant for the node; `runtime.PlatformError`), kept once per revision like the digest, and restrict `eligible()`; the control plane never contacts registries. Replicas reserve CPU (`resources.cpu`, default 100m, also the limit when set) and memory with no overcommit; `allocatable()` subtracts what Armada keeps (100m CPU and 128Mi per node, 100m more on servers) before `pickNode`, and capacity only fits and breaks ties, never outranks the replica count (T28). `ReplicaSpec.cpu_reserve_millis` sets the container's CPU weight and stays out of the agent's spec hash.
- Internal ingress (ADR 0007): `<app>.internal` is served by a HAProxy `frontend internal` bound to the container bridge gateway (`armada0`) (never the private IP: NAT and load balancers make that reachable from the internet) and resolved by the agent's DNS server (`internal/dnsserver`) on the same address, which answers only the bridge subnet. Internal and public rules never mix; the `.internal` zone is reserved.
- Container runtime (ADR 0011): the only runtime is Armada's own containerd, run from binaries pinned in `internal/runtime/embedded/lock.go` and embedded in release builds (build tag `bundle`); `armada-runtime.service` runs `armada runtime`, which extracts and verifies the pack and execs containerd (own root, socket `/run/armada/containerd/containerd.sock`, namespace `armada`, config format 4 with `imports = []`, no CRI/NRI/TCP/debug/metrics, restart monitor disabled). `internal/runtime/containerd` builds the OCI spec itself (shared checks in `runtime.CheckContainerSpec`), uses CNI (`armada0`, host-local IPAM on tmpfs with a default route, portmap on the private IP, firewall), unique container IDs per creation (`<name>-<hex>`), and logs through `armada runtime-log`. `agent.json` records `"runtime": "embedded"` or a driver name.
- External drivers (ADR 0015): other engines run containers through a separate program serving `armada.driver.v1.Driver` (`api/armada/driver/v1`) on `/run/armada/drivers/NAME.sock` under its own systemd unit; the agent never executes drivers. `internal/runtime/remote` implements `runtime.Driver` over it and connects only when the directory and socket are root-owned and closed to others and the peer is uid 0 (peer credentials replace TLS on this local socket; no TCP). The handshake (`Info`) checks the protocol version and name and declares capabilities: system containers (else the node needs `--proxy none`) and bridge (else no internal DNS). The public package `driverkit` (the only Go code outside `internal/`) is what drivers build on: it serves the protocol, re-checks every spec (security defaults are explicit fields), and holds `driverkit/conformance`, which the embedded runtime also runs (integration build tag). Nodes report `armada.runtime`; `runtime reset` removes only containers with Armada's labels. Engines are never built into the core again.
- Interfaces sit at boundaries that will change: `runtime.Driver`, `proxy.Driver`, `store.Store`, the DNS provider for certmagic. Code outside the implementing package depends only on the interface.
- HAProxy: structural changes (new app/domain/route) = re-render + `haproxy -c` + reload; deploy/scale/drain/certificates = Runtime API over a Unix socket. Do not use the Data Plane API.
- Rollouts (ADR 0005): an app has an `active_revision` (serving) and a `target_revision` (rolling out). Agents decide readiness through probes; the server only puts `running` + `ready` replicas in the proxy, retires old replicas after the warm-up, and deletes them after the drain timeout. Never delete a replica that serves traffic without draining it.
- Secrets (ADR 0006): per app, versioned, encrypted with `internal/secrets` (envelope AES-256-GCM, master key `master.key`). Revisions pin secret versions. The server decrypts only while building a node's assignment; the agent writes secret files only to its tmpfs secrets directory. Never log `ReplicaSpec`, `Assignment`, or `SetSecretRequest` (protobuf-go ignores `debug_redact`), and never put secret values in container labels or the spec hash.
- Armada's containers and resources are identified by `armada.*` labels and must be idempotent: an agent can restart at any time and adopt existing containers.
- State lives in etcd embedded in `armada server` (ADR 0009; `internal/etcd` runs the member, `store.Etcd` implements `store.Store`): JSON records under `/armada/`, optimistic serializable transactions (`Etcd.tx`; the callback may run more than once, so no side effects outside it). etcd accepts only TLS 1.3 client certificates with the shared `etcd:member` identity (the Armada API refuses it) and listens on the server's private IP, never publicly; the member certificate names every private address of the machine (do not skip etcd's client SAN check). Incompatible record changes bump `etcdSchema` with a migration; a binary refuses a newer schema. Tests use a shared embedded member per package (`store/storetest`, `TestMain`). Do not add dependencies that need CGO. A new file in the data directory must be added to `internal/backup` (a test checks the layout).
- Control plane topology (ADR 0010): one server is supported, three are recommended. Servers elect a leader through etcd (`etcd.Campaign`); only the leader serves the API/join listener and runs reconcilers and certmagic, each term with a fresh `server.Server` and a store fenced on the election key (`Etcd.Fenced`, `ErrNotLeader`). Servers join with a single-use server token (`token create --server`, `server join`), which hands over the CA and master keys; new members start as etcd learners and are promoted by the leader. Agents and the CLI hold every server address and dial with `pick_first`. ACME data lives in etcd (`certs.EtcdStorage`, `/armada-acme/`).

## Code conventions

- Everything is in **English**: code, identifiers, comments, commit messages, error messages, and all documentation (open source project for a global audience).
- Commit subjects follow Conventional Commits, `type(scope)!: description`, because the release notes are grouped by type (`.goreleaser.yaml`) and CI rejects other subjects (`scripts/check-commits.sh`). Types: `feat`, `fix`, `security`, `perf`, `docs`, `deps`, then `refactor`, `test`, `ci`, `build`, `chore`, `style`, `revert`; `!` marks a breaking change. Write the description for the people reading the release notes. `main` only changes through pull requests that pass every CI job (repository ruleset; see docs/releasing.md).
- Idiomatic Go: `context.Context` as the first argument for I/O, errors wrapped with `fmt.Errorf("...: %w", err)`, logging with `log/slog`.
- All code lives in `internal/` except the protobuf definitions in `api/` and the public driver library `driverkit/` (ADR 0015), whose API is a public interface: change it only by adding.
- YAML specs are parsed strictly (unknown field = error). Features whose types exist but are not implemented yet must be rejected with a clear message, never silently ignored.
- Tests live next to the code (`_test.go`). Reconciler logic is tested with fake drivers/stores, not a real runtime. HAProxy renderer changes require golden files.
- Development and CI always use ACME staging or Pebble, never the Let's Encrypt production endpoint.

## Keeping documents current (mandatory)

Every change updates, in the same commit or pull request, every document it makes stale. A change is not done until its documents are; do not leave it for a follow-up. Before committing, check at least:

- `README.md`: the feature list, the tested environments table, and the document links.
- `CLAUDE.md`: Status, Commands, Architecture in brief, and these conventions.
- `docs/`: quickstart, operations guide, spec reference, `threat-model.md` for anything that changes the attack surface or a mitigation, and `docs/adr/` for design decisions (a new ADR, or an update to the one the change supersedes, plus the index in `docs/adr/README.md`).
- CLI help text and error messages that describe the changed behaviour.

## Security rules (mandatory)

This is infrastructure software that holds root on every node. Treat these rules as merge requirements, not suggestions:

1. **Never weaken mTLS** (no `InsecureSkipVerify`, no `--insecure` flag, no plaintext fallback), including for development or tests.
2. **User input into the HAProxy configuration** (domains, paths, app names) must pass whitelist validation in `internal/spec` and be validated again in the renderer. Never interpolate user strings into templates without validation, and never turn them into regular expressions.
3. **Secrets:** never print plaintext to logs, errors, CLI output, or the audit log. Secret types must redact themselves through `String()`/`LogValue()`. Never accept secret values as CLI arguments (they end up in shell history); read them from stdin or a file.
4. **Bind interfaces:** agent/server gRPC, internal DNS, HAProxy stats, and container ports bind only to private IPs. Only HAProxy on ports 80/443 faces the public. Never bind internal services to `0.0.0.0`.
5. **Sensitive files** (CA key, master key, TLS private keys, `~/.armada/config`, state DB) are created with `0600`/`0700` permissions. Check permissions when reading them.
6. **Cryptography:** use Go's standard `crypto/*` packages and `crypto/rand`. Never invent cryptographic schemes. Compare tokens with `subtle.ConstantTimeCompare`. Store join tokens only as hashes.
7. **Secure container defaults:** `no-new-privileges`, no `--privileged`, no host network, no container runtime socket mount, memory/PID limits. Any relaxation must be explicit in the spec.
8. **System images** (HAProxy) are pinned by digest, not by tag.
9. **Authorization** is based on the identity in the client certificate: an agent may only access agent RPCs and data for its own node.
10. Changes touching `internal/pki`, `internal/secrets`, `internal/certs`, the proxy renderer, or API auth must come with tests for negative cases (malicious input, wrong certificates, expired tokens) and, where relevant, an update to `docs/threat-model.md`.

If a request conflicts with these rules, explain the risk and offer a safe alternative before doing the work.

# 0003. Internal CA and node bootstrap with join tokens

- Status: Accepted
- Date: 2026-10-30 (revised 2026-10-31 for the phase 5 implementation)

## Context

The server and agents talk over gRPC with mTLS inside a VPC that is not fully trusted (see threat model T5–T9). A new node must be able to join with a single command, without copying certificate files by hand.

## Decision

- `armada init` creates an internal CA (ECDSA P-256) and issues the server and admin certificates, plus the first node's certificate (through a CSR, like any other node). It does not create a join token.
- `armada token create` (admin) creates a join token `<id>.<secret>`: a 48-bit public ID and a 256-bit secret from `crypto/rand`. It is single-use, valid for 1 hour by default (1 minute to 24 hours), stored only as the SHA-256 hash of the secret, and compared with `subtle.ConstantTimeCompare`. Redeeming it, issuing the certificate, and registering the node happen in one transaction, so a token can never be used twice. The command prints the token once, together with the join address and the CA hash (`sha256:<hex>` of the CA certificate).
- **Separate join listener.** A node without a certificate cannot reach the main API, which always requires client certificates. The server therefore opens a second listener on a private address (default: API port + 1, `--join-listen`, `off` to disable) that uses server-only TLS and serves nothing but `JoinService.Join`. Other services are not registered there, attempts are rate limited (token bucket), and messages are capped at 64 KiB. The main API stays strict mTLS.
- **Pinning without skipping verification.** `armada join` first handshakes with an empty root pool. The handshake fails verification, and the CA certificate is taken from the presented (unverified) chain. It is accepted only if its hash equals the pin from the join command, it is a CA, and the server certificate verifies against it for the server name. Only then does the client connect again with normal verification against that CA and send the token. `InsecureSkipVerify` is never set. A wrong pin aborts before the token leaves the machine.
- **The token is not a command-line argument.** `armada join` reads it from a hidden prompt, stdin, or `--token-file`, so it does not end up in shell history.
- **The key stays on the node.** The node sends a CSR (ECDSA P-256 only). The CA ignores the CSR's subject and SANs and issues `node:<name>`, with the name chosen at join time and checked against the same rules as app names, for client authentication only.
- **Short-lived node certificates.** They are valid for 30 days. The agent renews over its existing mTLS connection (`AgentService.RenewCertificate`, always for the caller's own identity) once a certificate enters the last third of its lifetime, writes the new key and certificate atomically, and reconnects. The server ends any agent stream when the certificate that authenticated it expires.
- **Revocation by allowlist.** The server records the serial and expiry of every node certificate it issues, and on every RPC it accepts a node certificate only if its serial is recorded for that node. Removing a node deletes its serials, which revokes every certificate it ever had at once. A certificate signed by the CA but never recorded (for example one minted with a stolen CA key outside the server) is also refused. Expired serials are pruned when a node renews.
- **Removing nodes.** `armada node remove` cordons the node, waits until its replicas run elsewhere (drained like a rolling update), then removes it and disconnects its agent. `--force` deletes the node and its replicas immediately, for a node that is gone for good.
- **Upgrades.** Nodes registered before this change are marked `legacy_certs`, and their one-year certificates are accepted until they first renew. Agents renew such certificates immediately, because their lifetime exceeds 30 days.

## Alternatives considered

- **Trust on first use (TOFU):** vulnerable to MITM during join.
- **Copying certificates manually:** contradicts the "one command" goal.
- **SPIFFE/SPIRE:** too heavy for 1–20 nodes.
- **Accepting unauthenticated clients on the main listener** (`VerifyClientCertIfGiven`) and allowing only `Join` without a certificate: one misconfigured method would expose the API. A separate listener makes the boundary structural.
- **A CRL/OCSP revocation list:** more moving parts than an allowlist in the same database the server already reads.

## Consequences

- The CA key becomes the most sensitive asset. CA rotation is not supported in v0.1 (documented).
- Every node RPC costs one lookup in the state store.
- Node clocks must be roughly in sync (NTP). Certificates are backdated by 5 minutes to tolerate small skew.
- A node that stays offline for more than 30 days must rejoin with a new token.

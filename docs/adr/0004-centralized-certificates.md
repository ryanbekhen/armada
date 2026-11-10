# 0004. Certificates managed centrally in the control plane

- Status: Accepted
- Date: 2026-10-30

## Context

Every node runs HAProxy, which terminates TLS. Certificates could be requested by each node individually, or by the control plane and then distributed.

## Decision

- `certmagic` runs only on the server (`internal/certs`, `certs.Manager` interface). Storage: `<data-dir>/certs` (`0700`, files `0600`).
- HTTP-01: HAProxy on every node forwards `/.well-known/acme-challenge/` to the server's responder on a private IP. TLS-ALPN is disabled because TLS is terminated by HAProxy.
- DNS-01 is used only for root domain wildcards, with a provider from `libdns` (Cloudflare first).
- The combined PEM (chain + key) reaches the agent over mTLS; the agent writes the file and installs it via the Runtime API without a reload if the certificate name has not changed. `Assignment.proxy.certificates` names each certificate with the SHA-256 of its PEM, and the agent fetches the ones it lacks or whose digest changed with `AgentService.GetCertificates` (at most 256 per call, only names the cluster serves, node certificates only), checks each against its digest, and keeps them in memory. So an assignment does not grow with every certificate of the cluster, which on a large cluster without a wildcard went past what an agent accepts in one message. Agents from before this (no `Hello.certificate_refs`) still get the PEMs in the assignment.

## Consequences

- One ACME account, one place where rate limits are counted, and no cross-node coordination for challenges.
- App private keys are copied to every node (T16). Accepted, because every node has to terminate TLS for that domain anyway.
- If the server is down, no new issuance or renewal happens, but HAProxy keeps serving the last certificate (the 90-day validity leaves time to recover).

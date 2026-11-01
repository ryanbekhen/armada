# 0002. HAProxy via the Runtime API, not the Data Plane API

- Status: Accepted
- Date: 2026-10-30

## Context

Zero-downtime rolling updates need a way to add, drain, and remove servers from a backend without reloading. The product design picks HAProxy and rules out the Data Plane API (a separate program).

## Decision

- HAProxy runs as a system container with a digest-pinned image, host network, and master-worker mode.
- Structural changes (new app/domain/route): render the file → `haproxy -c` → atomic rename → reload. If validation fails, the old file stays in use.
- Deploy/scale/drain/certificates: Runtime API over a `0600` Unix socket, using pre-allocated `server-template` slots.
- This logic lives behind `proxy.Driver` so Nginx can be added in v0.2.

## Alternatives considered

- **Data Plane API:** an extra process and more attack surface.
- **Reload on every change:** simple, but health state and counters are lost on every deploy.

## Consequences

- Runtime API state must be kept in sync with the config file so the next reload does not discard changes (the file is always rendered from the same desired state).
- The number of slots caps `scale.max` without a reload; going beyond it triggers a reload.

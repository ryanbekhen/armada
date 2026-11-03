# Architecture Decision Records

Every architectural decision that is hard to reverse is recorded here. Copy `0000-template.md`, give it the next number, and change its status through a PR.

| No | Title | Status |
| --- | --- | --- |
| [0001](0001-desired-state-reconciliation.md) | Desired state + reconciliation model | Accepted |
| [0002](0002-haproxy-runtime-api.md) | HAProxy via the Runtime API, not the Data Plane API | Accepted |
| [0003](0003-pki-and-node-bootstrap.md) | Internal CA and node bootstrap with join tokens | Accepted |
| [0004](0004-centralized-certificates.md) | Certificates managed centrally in the control plane | Accepted |
| [0005](0005-rolling-updates.md) | Rolling updates with agent-side readiness and time-based drain | Accepted |
| [0006](0006-secrets.md) | App secrets: envelope encryption, pinned versions, tmpfs files | Accepted |
| [0007](0007-internal-ingress-and-dns.md) | Internal ingress and DNS on the container bridge | Accepted |
| [0008](0008-self-healing.md) | Self-healing: rescheduling replicas from lost nodes | Accepted |
| [0009](0009-etcd-state-store.md) | Embedded etcd as the state store | Accepted |
| [0010](0010-ha-control-plane.md) | Highly available control plane | Accepted |
| [0011](0011-embedded-container-runtime.md) | Embedded container runtime (containerd, runc, CNI) | Accepted |
| [0012](0012-upgrades-and-state-schema.md) | Upgrades and state schema migrations | Accepted |
| [0013](0013-replica-rebalancing.md) | Replica rebalancing | Accepted |
| [0014](0014-node-labels-and-placement.md) | Node labels and app placement | Accepted |
| [0015](0015-external-runtime-drivers.md) | External runtime drivers | Accepted |
| [0016](0016-macos-nodes.md) | macOS nodes | Accepted |
| [0017](0017-exec.md) | Running commands in replicas | Accepted |
| [0018](0018-top.md) | Resource usage of replicas | Accepted |
| [0019](0019-metrics-endpoint.md) | Metrics endpoint | Accepted |
| [0020](0020-event-history.md) | Event history | Accepted |

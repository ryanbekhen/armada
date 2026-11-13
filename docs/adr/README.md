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
| [0015](0015-exec.md) | Running commands in replicas | Accepted |
| [0016](0016-top.md) | Resource usage of replicas | Accepted |
| [0017](0017-metrics-endpoint.md) | Metrics endpoint | Accepted |
| [0018](0018-event-history.md) | Event history | Accepted |
| [0019](0019-jobs.md) | Jobs | Accepted |
| [0020](0020-autoscaling.md) | Autoscaling | Accepted; queue and schedule rules in 0034 |
| [0021](0021-scale-to-zero.md) | Scale to zero | Accepted |
| [0022](0022-traffic-splitting.md) | Traffic splitting | Accepted |
| [0023](0023-persistent-volumes.md) | Persistent volumes | Accepted |
| [0024](0024-local-first-routing.md) | Local-first routing | Accepted |
| [0025](0025-cluster-network.md) | Cluster network | Accepted |
| [0026](0026-spaces-and-network-isolation.md) | Spaces and network isolation | Accepted; automation identities superseded by 0033 |
| [0027](0027-client-and-daemon-binaries.md) | Client and daemon binaries | Accepted |
| [0028](0028-administrators.md) | Administrators | Superseded by 0033 |
| [0029](0029-spec-variables-and-env-from-secrets.md) | Spec variables and variables from secrets | Accepted |
| [0030](0030-release-checks-and-upgrades.md) | Release checks and machine upgrades | Accepted |
| [0031](0031-cluster-settings.md) | Cluster settings | Accepted |
| [0032](0032-command-line.md) | The command line | Accepted |
| [0033](0033-access-control.md) | Access control: users, services, and roles | Accepted |
| [0034](0034-queue-and-schedule-autoscaling.md) | Autoscaling on queues and schedules | Accepted |
| [0035](0035-client-address-rules.md) | Client address rules | Accepted |
| [0036](0036-sticky-sessions.md) | Sticky sessions | Accepted |
| [0037](0037-cors.md) | Cross-origin requests at the proxy | Accepted |
| [0038](0038-init-containers-and-sidecars.md) | Init containers and sidecars | Accepted |
| [0039](0039-internal-tcp-ingress.md) | Internal TCP ingress | Accepted |
| [0040](0040-queue-triggered-jobs.md) | Jobs started by a queue | Accepted |
| [0041](0041-volume-backups.md) | Scheduled volume backups to object storage | Accepted |
| [0042](0042-nfs-volumes.md) | NFS volumes | Accepted |
| [0043](0043-log-history.md) | Log history | Accepted |

Commands in records before 0032 carry the names of their time; ADR 0032
lists the command line as it is now.

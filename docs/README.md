# Armada documentation

Armada turns Linux machines into a container platform. These pages take you
from the first install to running production apps.

## Start here

1. **[Quickstart](quickstart.md)**: install Armada, create a cluster, and
   serve your first app over HTTPS.
2. **[Concepts](concepts.md)**: the handful of ideas everything else builds
   on.
3. **[Deploy a web app](guides/deploy-a-web-app.md)**: your own app with a
   domain, updates, and rollbacks.

## Guides

Complete recipes for the things people build most. Each one starts from a
running cluster and ends with something that works.

| Building | Guide |
| --- | --- |
| A website or API | [Deploy a web app](guides/deploy-a-web-app.md) · [A single-page app and its API](guides/spa-and-api.md) · [Behind a CDN or proxy](guides/behind-a-cdn.md) |
| Staging and production | [Spec files and environments](guides/spec-files-and-environments.md) · [Canary releases and previews](guides/canary-releases.md) · [Deploy from CI](guides/ci-cd.md) |
| Something with data | [An app with a PostgreSQL database](guides/app-with-a-database.md) · [Shared files over NFS](guides/shared-files-with-nfs.md) |
| Several services | [Microservices](guides/microservices.md) · [Migrations and sidecars](guides/migrations-and-sidecars.md) · [A private registry](guides/private-registry.md) |
| Background work | [Workers that scale on a queue](guides/background-workers.md) · [Scheduled jobs](guides/scheduled-jobs.md) · [Autoscaling and scale to zero](guides/autoscaling-and-scale-to-zero.md) |
| A team and its cluster | [Teams and access](guides/teams-and-access.md) · [Logs](guides/logs.md) · [Get alerts](guides/alerts.md) · [Monitoring and alerts](guides/monitoring-and-alerts.md) · [Disaster recovery](guides/disaster-recovery.md) · [Troubleshooting](guides/troubleshooting.md) |

All guides: [guides/](guides/README.md).

## Reference

- **[CLI reference](cli/armada.md)**: every `armada` command and flag, and
  [`armadad`](cli/armadad.md) for the machines. Generated from the commands.
- **[Spec reference](spec-reference.md)**: every field of app and job specs.
- **[Features](features.md)**: everything Armada does.

## Running a cluster

- **[Operations guide](operations.md)**: cluster settings, the control
  plane, backups, upgrades, certificates, access control, spaces, nodes,
  networking, and what happens when something fails.
- **[Tested environments](tested-environments.md)**: where Armada has been
  tested end to end.
- **[Releasing](releasing.md)**: how releases are built, signed, and
  verified.

## Design and security

- **[Architecture decisions](adr/README.md)**: why Armada works the way it
  does, one decision at a time.
- **[Threat model](threat-model.md)**: what Armada defends against, and its
  accepted limits. Report vulnerabilities as [SECURITY.md](../SECURITY.md)
  says.

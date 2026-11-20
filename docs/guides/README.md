# Guides

Complete recipes for the things people build with Armada. Each guide starts
from a running cluster (see the [quickstart](../quickstart.md)) and ends
with something that works, with every command and spec ready to copy.

New to Armada? Read [Concepts](../concepts.md), then
[Deploy a web app](deploy-a-web-app.md).

## Apps and traffic

| Guide | You will learn |
| --- | --- |
| [Deploy a web app](deploy-a-web-app.md) | Your own app on HTTPS with a custom domain, updates, rollbacks, logs, and a spec in git |
| [Spec files and environments](spec-files-and-environments.md) | One spec for staging and production, with variables, spaces, and secrets |
| [Canary releases and previews](canary-releases.md) | Sending a share of traffic to a new revision, preview URLs, promoting and rolling back |
| [Autoscaling and scale to zero](autoscaling-and-scale-to-zero.md) | Scaling on requests, CPU, memory, or a schedule, and stopping idle apps |
| [A single-page app and its API](spa-and-api.md) | CORS, sticky sessions, an IP allowlist for an admin panel, timeouts, probes |
| [Behind a CDN or proxy](behind-a-cdn.md) | Trusted proxies, real client addresses, wildcard certificates over DNS-01 |
| [Apps on a private network without a domain](private-network.md) | A lab, laptop VMs, or office cluster: names through sslip.io, `/etc/hosts`, a wildcard on a Mac or the network, or a domain you own with HTTPS |
| [Your own image from your laptop](images-from-your-laptop.md) | Building for the nodes' architecture, pushing to a registry, and deploying it |

## Data and background work

| Guide | You will learn |
| --- | --- |
| [An app with a PostgreSQL database](app-with-a-database.md) | A database with a volume, internal TCP, backups to a bucket, failover, and a restore drill |
| [Microservices](microservices.md) | Services that talk privately, narrowed callers, a shared cache, teams in spaces |
| [Workers that scale on a queue](background-workers.md) | Scaling on a Redis list or RabbitMQ queue, and jobs started by a queue |
| [Scheduled jobs](scheduled-jobs.md) | Cron jobs with time zones, retries, history, and one-off tasks |
| [Shared files over NFS](shared-files-with-nfs.md) | Uploads that every replica, on every node, sees |
| [Migrations and sidecars](migrations-and-sidecars.md) | Database migrations before the app starts, and helpers beside it |

## Teams and operations

| Guide | You will learn |
| --- | --- |
| [Machines without a private network](machines-without-a-private-network.md) | A cluster of machines with only public addresses, over a WireGuard mesh, with joins that open the port only while a token is valid |
| [Machines in more than one site](more-than-one-site.md) | A cluster across data centers, an office, and a cloud provider: nodes and servers joining from another site, mesh addresses, apps kept in a site, and doctor's checks |
| [A private registry](private-registry.md) | Pulling your images with registry credentials kept as secrets |
| [Deploy from CI](ci-cd.md) | A service identity for your pipeline, deploys that fail the build on a bad rollout |
| [Teams and access](teams-and-access.md) | Users, roles, and spaces for a team |
| [Read, search, and keep logs](logs.md) | Live logs filtered as they arrive, searching replicas that are gone, sending logs to Loki or OTLP |
| [Get alerts](alerts.md) | Notices in Slack, Discord, Telegram, email, or a webhook when something needs you |
| [Monitoring and alerts](monitoring-and-alerts.md) | Prometheus metrics, ready-made alerts, events, and usage |
| [Disaster recovery](disaster-recovery.md) | Backing up the control plane and volumes, and coming back from losing a server or a node |
| [Troubleshooting](troubleshooting.md) | Common problems: what you see, why, and how to fix it |

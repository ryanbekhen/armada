# 0034. Autoscaling on queues and schedules

- Status: Accepted
- Date: 2026-11-11
- Extends: [0020](0020-autoscaling.md), whose queue and schedule fields were
  reserved

## Context

Autoscaling (ADR 0020) follows requests, CPU, and memory. Workers that take
jobs from a queue have no requests, and their CPU says little until they are
already behind. They need to grow with the work that waits. Other apps have
load that follows the clock: office hours, a nightly batch, a weekly sale.
They should be ready before the load arrives, not one evaluation after it.

ADR 0020 kept the fields for both and rejected them. A queue rule would have
made the control plane connect to services outside the cluster, with their
credentials, and know every queue's protocol.

## Decision

Four more rule types for `scale.rules`: `queue`, `redis`, `rabbitmq`, and
`schedule`.

```yaml
scale:
  min: 1
  max: 8
  rules:
    - type: queue
      command: ["bun", "queue-length.ts"]   # prints the queue's length
      length: 100                           # items one replica handles
    - type: redis
      urlSecretRef: redis-url               # redis://:password@redis-01:6379/0
      list: mail:outbox                     # LLEN of this list
      length: 50
    - type: rabbitmq
      urlSecretRef: amqp-url                # amqp://user:password@mq:5672/vhost
      queue: emails                         # messages ready in this queue
      length: 20
    - type: schedule
      schedule: "0 8 * * 1-5"               # when the window opens
      timeZone: Asia/Jakarta
      duration: 10h                         # how long it stays open
      replicas: 3                           # at least this many meanwhile
```

### Queue

- **The app measures its own queue.** The agent runs `command` in one of the
  app's replicas, as it runs a command probe (ADR 0015): with the
  container's own process settings, user, and limits. The command prints
  the queue's length as a whole number.
  - Armada never connects to the queue, holds its credentials, or knows its
    protocol. The replica already has all three.
  - Any queue works: a list in a key-value store, a table, a stream, or an
    HTTP call the command makes.
- **One replica per node.** Every 15 seconds the agent picks, for each app
  with a queue rule, the ready replica on its node with the lowest ID.
  - The command has 10 seconds and may print at most 64 bytes.
  - Anything other than a whole number between 0 and 2^40 is ignored, as is
    a non-zero exit. The previous reading then ages out.
  - The command's arguments and output never reach logs or events.
  - The agent runs at most 32 queue commands per pass.
- **The reading travels with the usage report**, as `UsageReport.queues`
  (replica and length). The leader keeps it in memory with the node's
  sample (ADR 0016). It counts only for a replica assigned to that node, and
  is bounded. The queue is shared, so the leader takes the largest recent
  reading of the app's replicas.
- **Decision.** The app needs ⌈length ÷ `length`⌉ replicas, with the same
  10% tolerance, doubling limit, and five-minute scale-down window as the
  other rules. An app with no reading holds.
- **`scale.min` of at least 1.** The length is read in a running replica, so
  an app with a queue rule cannot scale to zero.

### Redis lists and RabbitMQ queues

Many workers read a Redis list or a RabbitMQ queue. For those, no command
is needed:
- **What is read.** `redis` reads `LLEN` of `list`. `rabbitmq` declares
  `queue` passively over AMQP 0-9-1 and reads the messages ready in it, the
  ones no consumer holds.
- **The URL comes from the app's own secret** (`urlSecretRef`), with its
  password: `redis://`, `rediss://` (TLS), `amqp://`, or `amqps://`. Deploys
  pin the secret's version like any other secret reference, the server
  decrypts it only into the node's assignment (`QueueProbe.url`), and it is
  never logged.
- **The agent dials from the replica's network namespace.**
  - `runtime.ContainerDialer`: a thread switched into the namespace creates
    the socket, which keeps the container's routes and firewall.
  - Names resolve through the nameserver containers use, also from inside.
  - A rule therefore reaches exactly what its app can reach, and an
    isolated project's rule reaches nothing outside it. The agent's own
    network position gives the spec nothing.
- **TLS** uses the node's root certificates. Certificate paths in the URL
  are ignored, so a URL cannot make the agent read files on the node.
- **Same limits as a command.** Each reading has 10 seconds, and lengths
  above 2^40 are refused. The agent's log names only the kind of failure:
  unreachable, refused credentials, unexpected answer, or missing queue.
  Neither the URL nor anything the broker sent appears there.
- **Each type at most once per app.** Each is decided like `queue`.

### Schedule

- **A window.** Each fire of `schedule` (five cron fields, the same syntax
  and `timeZone` as jobs, ADR 0019) opens a window of `duration`, between
  one minute and seven days. A fire inside an open window keeps it open for
  `duration` from that fire.
- **While a window is open**, the rule asks for `replicas`, which must lie
  between 1 and `scale.max`. The app gets the largest of every rule's
  answer, so other rules can still add more.
  - An open window also keeps an app that scales to zero (ADR 0021) from
    doing so.
  - A metric rule without samples never stops an open window from raising
    the count.
- **When the window closes**, the rule asks for nothing.
  - The five-minute window of ADR 0020 then lets the count fall.
  - An app with only schedule rules goes back to `scale.min`.
  - An app with metric rules that have no samples holds, as before.
- **Up to eight schedule rules per app**, for example weekdays and Saturdays.
  The other types stay one per app.
- **The schedule is evaluated on every pass**, from the spec and the leader's
  clock. Nothing new is stored, and a new leader knows the window at once.

### Status and metrics

- **`AutoscaleRule`** carries:
  - for `queue`: the length as `current` and `length` as `target`;
  - for `schedule`: `replicas` as `target`, the replicas asked for now as
    `current` (0 when closed), and `until`, when an open window closes.
- **`armada app show`** prints, for example,
  `queue 450/100 per replica, schedule 3 until Wed 18:00`.
- **Metrics.** `armada_app_autoscale_current` and
  `armada_app_autoscale_target` carry the same values with `rule="queue"`
  or `rule="schedule"`.
- **The agent** gets the command as `ReplicaSpec.queue`. It is outside the
  spec hash, so adding or changing the rule recreates no container.

## Consequences

- **Queues.** Workers scale on the work that waits, with no connection from
  the control plane to anything outside the cluster, and no new
  credentials.
- **The app chooses its own scale.** A replica that prints a large number
  gets its app up to `scale.max`, no further. It is the same trust as the
  load an app can cause itself. A command that fails or prints nonsense
  leaves the count where it is.
- **The command runs every 15 seconds** in one replica per node, so it
  should be cheap. A command that starts a runtime costs that runtime's
  start-up each time.
- **Scaling down is gradual.** After a window closes, the count falls through
  the usual five-minute window. Load that ends exactly at the close still
  has replicas for a few minutes.
- **Not done:**
  - other brokers (they work through `queue` with a command);
  - Redis streams;
  - scaling a queue worker from zero;
  - custom metrics from the metrics endpoint.

  A worker that should cost nothing while idle can be a job that its queue
  starts (ADR 0040) instead.

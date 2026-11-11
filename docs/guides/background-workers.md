# Run workers that scale on a queue

You will run background work that follows a queue: a worker app that adds
replicas as a Redis list grows and removes them as it drains, and a job
that only runs while messages wait, costing nothing in between. The guide
ends with how to choose between the two.

**You will use:** [queue autoscaling rules](../spec-reference.md#autoscaling)
(`redis`, `rabbitmq`, `queue`),
[command probes](../spec-reference.md#probes),
[jobs started by a queue](../spec-reference.md#trigger) (`trigger.queue`),
and [internal TCP](../operations.md#tcp-apps-inside-the-cluster) for the
broker.

**Before you start:**

- A running cluster created with the cluster network
  (`armadad init --cluster-cidr`, see the [quickstart](../quickstart.md)).
  Jobs started by a queue need it, and so does the broker as a TCP app.
- Your worker image: a program that takes messages from the queue and
  handles them.

## The setup

```
  project shop
  +-------------------------------------------------------------------+
  |  api --LPUSH--> queue (redis, TCP 6379) <--BRPOP-- worker x1..10  |
  |                    ^         ^                                    |
  |                    |         +-- length read every 15s:           |
  |                    |             worker scales on jobs:resize     |
  |                    |                                              |
  |                    +-- length read every 30s:                     |
  |                        mailer runs start while mail:outbox        |
  |                        holds messages                             |
  +-------------------------------------------------------------------+
```

## 1. Run the broker

Skip this step if you already run Redis or RabbitMQ that your apps can
reach. Here the broker is an app of the same project, with a volume so
queued messages survive a restart:

```bash
armada project create shop
armada project use shop
PASSWORD=$(openssl rand -hex 24)
printf %s "$PASSWORD" | armada secret set queue redis-password
for app in api worker mailer; do
  printf 'redis://:%s@queue.shop.internal:6379/0' "$PASSWORD" | armada secret set "$app" redis-url
done
unset PASSWORD
```

```yaml
# queue.yaml
name: queue
image: redis:7
command: ["sh", "-c", "exec redis-server --requirepass \"$REDIS_PASSWORD\" --appendonly yes"]
env:
  - name: REDIS_PASSWORD
    secretRef: redis-password
ingress:
  type: internal
  protocol: tcp
  port: 6379
  allow: [api, worker, mailer]
volumes:
  - name: data
    path: /data
    owner: "999:999"
resources:
  memory: 512Mi
```

```bash
armada app create --file queue.yaml --wait
```

Apps of `shop` reach it at `queue.shop.internal:6379`. `allow` lists
everything that connects: the API that pushes messages, the worker, and
the `mailer` job. Armada reads the queue's length from inside the worker's
and the job's networks, so those reads need `allow` too. The [database
guide](app-with-a-database.md) shows how to back such a volume up.

## 2. A worker that scales on the length of a list

```yaml
# worker.yaml
name: worker
image: ghcr.io/acme/worker:2.1.0
command: ["node", "dist/worker.js"]
env:
  - name: REDIS_URL
    secretRef: redis-url
  - name: QUEUE
    value: jobs:resize
probes:
  liveness:
    command: ["node", "dist/health.js"]
    initialDelay: 30s
    period: 30s
    timeout: 10s
resources:
  cpu: 500m
  memory: 512Mi
scale:
  min: 1
  max: 10
  rules:
    - type: redis
      urlSecretRef: redis-url
      list: jobs:resize
      length: 100
```

```bash
armada app create --file worker.yaml --wait
```

How it works:

- **No `ingress`.** A worker takes no requests; it pulls from the queue.
  Its readiness needs no port.
- **A command probe.** Without a port there is nothing to check over HTTP;
  `liveness` runs a command in the container instead, and a worker that
  hangs is recreated. Give the command a realistic `timeout`: the default
  of 1 second is short for most programs.
- **The rule.** Every 15 seconds the agent reads `LLEN jobs:resize` from
  inside one ready replica's network, with the URL from the `redis-url`
  secret. The app wants ⌈length ÷ 100⌉ replicas, between `min` and `max`.
  1,000 waiting messages ask for 10 replicas; 250 for 3.
- **Up fast, down slowly.** The count rises at once, at most doubling per
  step. It falls only after the queue has stayed shorter for 5 minutes, so
  a burst does not make replicas come and go.
- **`min` is at least 1.** The length is read from a running replica, so a
  worker with a queue rule never scales to zero. For work that should run
  nothing while idle, use a job (step 4).

Watch it:

```
$ armada app show worker
Name:       worker.shop
Revision:   worker.shop--r1
Image:      ghcr.io/acme/worker:2.1.0
Ready:      4/4
Ingress:    none
Autoscale:  1-10 replicas, redis 340/100 per replica
...
```

```bash
armada app events worker      # ScaledUp and ScaledDown, with the reason
```

The rule shows `-` while it has no reading: the replica cannot reach the
broker, the URL or password is wrong, or the list does not exist yet. The
app then holds its count.

## 3. Other queues

**RabbitMQ.** The rule counts the messages ready in a queue (AMQP 0-9-1),
not the ones consumers hold:

```yaml
scale:
  min: 1
  max: 20
  rules:
    - type: rabbitmq
      urlSecretRef: amqp-url        # amqp://user:password@mq.shop.internal:5672/vhost, or amqps://
      queue: emails
      length: 20
```

**Anything else: a command.** For a queue in a database table, or a broker
without a built-in rule, the worker's image can report the length itself.
The command runs in one ready replica every 15 seconds and must print a
whole number within 10 seconds:

```yaml
scale:
  min: 1
  max: 8
  rules:
    - type: queue
      command: ["node", "dist/queue-length.js"]   # prints e.g. 340
      length: 100
```

Anything other than a number, or a non-zero exit, counts as no reading.
Run it yourself to see what it prints:

```bash
armada app exec worker -- node dist/queue-length.js
```

Keep it cheap: it runs every 15 seconds.

**Busy hours known in advance.** Add `schedule` rules next to the queue
rule to start replicas before the work arrives; the rule that asks for the
most replicas wins:

```yaml
scale:
  min: 1
  max: 10
  rules:
    - type: redis
      urlSecretRef: redis-url
      list: jobs:resize
      length: 100
    - type: schedule
      schedule: "0 8 * * 1-5"
      timeZone: Asia/Jakarta
      duration: 10h
      replicas: 3
```

## 4. A job that runs while messages wait

Mail goes out in bursts: a newsletter, then nothing for hours. A job with
`trigger.queue` has no container while `mail:outbox` is empty, and starts
runs, each handling a batch, while it is not:

```yaml
# mailer.yaml
kind: job
name: mailer
image: ghcr.io/acme/mailer:3.0.1
command: ["node", "dist/send-batch.js"]
env:
  - name: REDIS_URL
    secretRef: redis-url
  - name: BATCH_SIZE
    value: "50"
trigger:
  queue:
    type: redis
    urlSecretRef: redis-url
    list: mail:outbox
    perRun: 50
  pollingInterval: 30s
  parallelism: 5
timeout: 15m
retries: 1
history: 20
resources:
  memory: 256Mi
```

```bash
armada job create --file mailer.yaml
```

- **`perRun: 50`** is how many messages one run handles. Each reading
  starts ⌈length ÷ 50⌉ runs, at most `parallelism`, less the runs already
  active: 120 waiting messages start 3 runs.
- **A run takes its batch and exits.** Write the program to take up to
  `BATCH_SIZE` messages and end. If messages are left, the next reading
  starts more runs.
- **`pollingInterval: 30s`**: a message waits up to one interval plus a
  container start before a run picks it up.
- **`parallelism: 5`** bounds the runs at once, manual runs
  (`armada job run mailer`) included.
- **No `schedule` or `concurrency`**: a job starts on a clock or on a
  queue, not both, and `parallelism` replaces `concurrency`.
- **Runs are at least once.** A run can, rarely, be attempted again; make
  handling a message safe to repeat.

One node reads the queue, from a network sandbox: an address on that node
that the firewall treats as one of the job's containers, with no container
behind it. It reaches exactly what the job's containers would, which is
why `mailer` is in the broker's `allow`.

```
$ armada job show mailer
Name:         mailer.shop
Revision:     mailer.shop--r1
Image:        ghcr.io/acme/mailer:3.0.1
Trigger:      redis list mail:outbox, 50 per run, at most 5 at once, read every 30s
Queue:        120 waiting, read 12s ago from node2
Last run:     41, succeeded, finished 3m ago
Active runs:  3
```

```
$ armada job run list mailer
RUN  STATE      TRIGGER  ATTEMPTS  NODE   STARTED  DURATION  EXIT  MESSAGE
44   running    queue    1         node1  20s ago  -         -     -
43   running    queue    1         node3  20s ago  -         -     -
42   running    queue    1         node2  20s ago  -         -     -
41   succeeded  queue    1         node2  4m ago   38s       0     -
```

For RabbitMQ, set `type: rabbitmq` and `queue:` instead of `list:`. Command
queues (`type: queue`) are not available for jobs: a command needs a
container to run in.

## Choosing: a worker app or a job

| | Worker app with a queue rule | Job with `trigger.queue` |
| --- | --- | --- |
| While the queue is empty | at least 1 replica runs | nothing runs |
| Delay before work starts | none: a replica is already waiting on the queue | up to `pollingInterval` (10s to 10m) plus a container start |
| Shape of the work | a steady stream, long-lived consumers, connections kept open | bursts, batches that can end |
| How it grows | replicas, ⌈length ÷ `length`⌉, up to `max` (100) | runs, ⌈length ÷ `perRun`⌉, up to `parallelism` (50) |
| Queues | `redis`, `rabbitmq`, any queue through a command | `redis`, `rabbitmq` |
| Failed work | the worker's own retry logic | `retries` and `timeout` per run, logs per run |
| Needs | `min` of at least 1 | a cluster network |

A rule of thumb: if messages must be handled within seconds, or arrive all
day, run a worker. If they arrive in bursts and can wait half a minute,
use a job.

## Check that it works

- Push test messages and watch the count follow:

  ```bash
  armada app exec queue -- sh -c 'for i in $(seq 1 500); do redis-cli -a "$REDIS_PASSWORD" --no-auth-warning LPUSH jobs:resize "$i" >/dev/null; done'
  armada app show worker        # redis 500/100 per replica, rising to 5 replicas
  ```

- `armada job show mailer` shows `Queue: N waiting, read ... from NODE`.
- `armada job list` shows `N waiting` in the `NEXT RUN` column for
  triggered jobs.
- Metrics: `armada_app_autoscale_current{rule="redis"}` for the worker,
  `armada_job_queue_length` and `armada_job_runs_active` for the job.

## Troubleshooting

| What you see | Why | What to do |
| --- | --- | --- |
| The rule shows `redis -/100` and the worker holds | The replica cannot reach the broker, the URL or password is wrong, or the worker is not in the broker's `allow` | Check the URL in the secret, `allow`, and that the worker reaches the broker; the agent's debug log names the kind of failure, never the URL |
| `queue -/100` | The command fails, takes over 10 seconds, or prints something other than a number | Run it with `armada app exec` and look at what it prints |
| The worker never goes below 1 | Queue rules need `min` of at least 1 | Use a job with `trigger.queue` for zero while idle |
| `Queue: not read yet, from node2` for long | The sandbox cannot reach the broker, or the URL is wrong | Add the job to the broker's `allow`; read the agent's log on that node |
| `Queue: not read: no node can` and a `QueueUnread` event | No connected node of the cluster network may run the job (placement, cordons) | Check the job's placement and the nodes |
| Job create refused for `trigger` | No cluster network, or `schedule`/`concurrency` set with it | Remove those fields; triggers need `armadad init --network` |
| `armada job run mailer` refused | `parallelism` runs are already active | Wait, or raise `parallelism` |
| A broker on the private network is unreachable from `shop` | Projects other than `default` cannot reach the private network | Run the broker as an app of the project, or use `default` with its isolation off |
| Replicas wait with an `Unschedulable` event as the queue grows | No node has room for another replica's reservation | Plan room for `max` replicas, lower `resources`, or add a node |

## Next steps

- [Scheduled jobs](scheduled-jobs.md): jobs on a clock, retries, and
  history.
- [Autoscaling and scale to zero](autoscaling-and-scale-to-zero.md):
  scaling on requests, CPU, and memory.
- [Microservices](microservices.md): the broker as a shared TCP app.
- Reference: [Autoscaling](../spec-reference.md#autoscaling),
  [`trigger`](../spec-reference.md#trigger),
  [ADR 0034](../adr/0034-queue-and-schedule-autoscaling.md),
  [ADR 0040](../adr/0040-queue-triggered-jobs.md).

# 0040. Jobs started by a queue

- Status: Accepted
- Date: 2026-11-11
- Extends: [0019](0019-jobs.md) (jobs) and
  [0034](0034-queue-and-schedule-autoscaling.md) (queue rules)

## Context

Jobs (ADR 0019) start on demand or on a schedule. Much batch work arrives
in a queue instead: mail to send, images to resize, exports to build. A
worker app with a queue rule (ADR 0034) follows such a queue, but it keeps
at least one replica running, because the length is read from inside a
running replica. Work that comes in bursts, with long quiet hours between,
then pays for an idle container all day.

A job costs nothing while no run is active. What it lacks is a way to know
that work waits. The length must be read without a container, and still
from exactly where the job's containers would stand on the network:
reading it from the node's own network would give the job the node's reach
(other projects, the platform, the provider's metadata service) and bypass
project isolation (ADR 0026).

## Decision

A job takes `trigger.queue`: while a Redis list or a RabbitMQ queue holds
messages, the leader starts runs, each handling a batch, up to a parallel
limit. Nothing runs while the queue is empty.

```yaml
kind: job
name: mailer
image: ghcr.io/acme/mailer:3
trigger:
  queue:
    type: redis                 # or rabbitmq
    urlSecretRef: redis-url     # the job's secret: redis://:password@redis-01:6379/0
    list: mail:outbox           # queue: emails, for rabbitmq
    perRun: 50                  # messages one run handles
  pollingInterval: 30s          # 10s to 10m, default 30s
  parallelism: 5                # most runs at once, 1 to 50, default 1
```

### Spec

- **The queue** is named as in a queue rule: `redis` reads `LLEN` of `list`,
  `rabbitmq` the messages ready in `queue`. The URL comes from the job's own
  secret and is pinned per revision, like any secret reference.
- **`perRun`** (1 to 10^9, required) is how many messages one run handles.
- **`schedule` and `trigger` exclude each other.** A job starts on a clock or
  on a queue; both at once would leave unclear which one `parallelism`
  bounds.
- **`concurrency` is rejected with a trigger.** Runs of a queue overlap by
  design; `parallelism` bounds them instead. A manual run (`armada job run`)
  counts toward it and is refused when it is reached.
- **Command queues** (`type: queue` in ADR 0034) are refused: a command
  needs a container to run in.
- **A cluster network is required.** Deploying a trigger to a cluster
  without one is refused, for the reason in the next section.

### Where the queue is read: a network sandbox

- **One node per job reads the queue.** The leader picks it among the nodes
  the job may run on (`eligible()`: placement, cordons, restrictions), that
  have a subnet of the cluster network, that are connected, and whose agent
  announced `Hello.queue_sandboxes`. Of those it takes the one whose hash
  with the job's ID is highest.
  - Every leader picks the same node with no state stored.
  - Jobs spread over nodes.
  - A job moves only when its node stops fitting.
  - Without such a node nothing is read, nothing runs, and the cluster
    records `QueueUnread` once.
- **The assignment carries the sandbox.** `Assignment.queue_sandboxes`
  lists, for that node only, each job's ID, the queue (type, name, the URL
  decrypted from the pinned secret, and the secret's version), and the
  polling interval. The URL is outside any hash and never logged.
- **The agent keeps a network sandbox per job** (`runtime.NetworkSandboxer`).
  A sandbox is a network namespace with no container and no process, wired
  into the node's container network exactly like a container's:
  - the same network plugins on `armada0`, an address of the node's subnet,
    the default route through the gateway, the plugins' firewall rules;
  - the namespace is pinned at `<run dir>/sandboxes/<job ID>`, and its
    address is the plugins' cached result for `sandbox-<job ID>`;
  - it costs one namespace, one interface pair, and one address.
- **The sandbox is an endpoint of the job.** The agent adds its address to
  the node's own containers, as the job's ID, before anything is dialled
  from it: the firewall (ADR 0026), the internal DNS server, and the proxy's
  internal frontend treat it as one of the job's containers. The agent
  reports it in `UsageReport.sandboxes`, and the leader adds it to
  `NetworkConfig.endpoints` for every node, checked against the node's
  subnet like a replica's address. So the sandbox reaches exactly what the
  job's containers could: in an isolated project, nothing outside the
  project.
- **The agent dials from inside.** A thread switched into the sandbox's
  namespace creates the socket, as for queue rules (ADR 0034). Names
  resolve through the containers' nameserver, also from inside. Only IP
  addresses over TCP or UDP are dialled there.
- **Only on a cluster network.** The agent keeps sandboxes only when its
  containers live in the node's subnet of a cluster network (ADR 0025) and
  its runtime has the network plugins. Without them the job would have no
  address the firewall knows, so the agent never falls back to the node's
  own network.
- **Restarts.** A sandbox outlives its agent. An agent that restarts lists
  the pinned namespaces and adopts the ones its next assignment names. It
  removes the others once that assignment arrives, never before, like
  containers. A namespace left half made is made again. `armadad runtime
  reset` removes them. Run directories are on tmpfs, so a reboot leaves
  none.

### Reading

- **Every `pollingInterval`** the agent reads each sandbox's queue, with
  the same limits as queue rules: 10 seconds per reading, at most eight at
  once, lengths above 2^40 refused, TLS with the node's roots and never
  certificate paths from the URL. A log line names only the kind of
  failure, once per change.
- **Each usage report** carries every sandbox's address and, if recent (two
  intervals), its latest length with its age and a reading number.
- **The leader keeps it in memory** with the node's sample (ADR 0016),
  bounded (256 entries, valid IDs, ages up to an hour), and reconciles at
  once when a report brings a new reading. It counts a reading only from
  the node it picked for the job, and only while it is younger than two
  polling intervals and the node's sample is fresh.

### Starting runs

- **Once per reading**, the leader wants ⌈length ÷ `perRun`⌉ runs, at most
  `parallelism`. It starts that many less the job's active runs, through
  the usual path: run records with trigger `queue`, attempts as replicas,
  placement, retries, timeouts, and history (ADR 0019).
- **Acting once per reading** means runs that end between two readings are
  not replaced on the strength of a length that is already out of date.
  The next reading decides.
- **No reading, no runs.** A stale, missing, or unreadable length starts
  nothing.
- **A new leader** acts on the next reading. Active runs already count, so
  it starts no more than one leader would.
- **Events.** `QueueTriggered` says how many runs started and why, without
  the queue's URL or contents. `QueueUnread` says that no node can read the
  queue.

### Interfaces

- `armada job list` shows `queue (redis mail:outbox)` as the job's trigger
  and the waiting messages as its next run.
- `armada job show` adds the trigger and what was last read: how many wait,
  when, and from which node.
- `JobInfo.trigger` (`JobTrigger`) carries the same.
- The metric `armada_job_queue_length{job}` is the last length read.
- The run's trigger is `queue` in `armada job run list`.

### Upgrades

- No state schema change. The trigger is part of the spec. A server
  without this change refuses it on deploy. As a leader it starts no runs
  from the queue: work waits, and no run starts that should not.
- A server without this change that rolls the job forward (`armada secret
  set`) writes a revision without the trigger. Upgrade every server before
  giving jobs a trigger.
- Older agents do not announce sandboxes and are never picked.

## Alternatives considered

- **Read the queue from the leader or the agent's own network.** No
  sandbox needed, but the job would reach what the node reaches, outside its
  project's isolation. Refused for that.
- **Keep one container of the job running to read from.** That is a worker
  app with a queue rule (ADR 0034), with the idle cost this decision
  removes.
- **Start a short-lived container to read the queue.** No new runtime
  interface, but a pull and a start per reading, on every interval, for
  every job.
- **Store the chosen node.** A record per job and a write per move. Hashing
  gives every leader the same answer with nothing stored.
- **Recompute runs on every pass from the last length.** Simpler, but runs
  that end quickly would be replaced again and again until the next reading
  showed the queue empty.

## Consequences

- **Bursty work costs nothing while idle.** A job with an empty queue has no
  container, only a network namespace on one node.
- **Runs follow the queue at the polling interval's pace.** A message that
  arrives just after a reading waits up to one interval. A short interval
  costs one broker connection per interval and job.
- **The job decides its own load**, up to `parallelism`. A run that leaves
  messages in the queue gets followers; one that takes more than `perRun`
  makes later readings smaller. Runs are at least once, as before.
- **The first reading from a new sandbox** may fail once on other nodes'
  firewalls, until they learn its address from the leader; it is read again
  at the next interval.
- **Not done:** command queues, Redis streams, other brokers, and clusters
  without a cluster network.

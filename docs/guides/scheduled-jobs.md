# Run scheduled jobs and one-off tasks

You will run work that starts, finishes, and exits: a nightly report on a
cron schedule in your time zone, with a timeout and retries; a sync every
15 minutes that must never overlap itself; and one-off maintenance tasks
you start by hand and wait for.

**You will use:** [jobs](../spec-reference.md#jobs) (`kind: job`) with
`schedule`, `timeZone`, `timeout`, `retries`, `concurrency`, and
`history`, and the [`armada job`](../cli/armada-job.md) commands.

**Before you start:** a running cluster (see the
[quickstart](../quickstart.md)) and an image that does the work and exits:
exit code 0 means success, anything else failure.

## How a job runs

A job is a spec of `kind: job`. Each **run** starts one container, by
schedule or by hand. If the container fails (non-zero exit, a start
failure, a lost node, or the timeout), the run makes another **attempt**
while `retries` allow. A finished run keeps its record, and its container
is kept 24 hours for its logs.

```
schedule "0 2 * * *"  ->  run 12  ->  attempt 1 (failed, exit 1)
                                  ->  10s later: attempt 2 (succeeded)
```

Jobs take no traffic: no `ingress`, `probes`, `scale`, or `volumes`.
`env`, secrets, `resources`, `placement`, `initContainers`, and `sidecars`
work as for apps.

## 1. A nightly report

```bash
printf %s 'postgres://report:...@db.internal:5432/app' | armada secret set nightly-report database-url
```

```yaml
# nightly-report.yaml
kind: job
name: nightly-report
image: ghcr.io/acme/reports:2.4.0
command: ["./bin/report", "--yesterday"]
env:
  - name: DATABASE_URL
    secretRef: database-url
schedule: "0 2 * * *"         # 02:00 every day
timeZone: Asia/Jakarta        # in this zone, not UTC
timeout: 30m
retries: 2
concurrency: forbid
history: 10
resources:
  cpu: 500m
  memory: 512Mi
```

```bash
armada job create --file nightly-report.yaml
```

What each field does:

| Field | Here | Default | Meaning |
| --- | --- | --- | --- |
| `schedule` | `0 2 * * *` | none: manual runs only | Five cron fields: minute, hour, day of month, month, day of week. `@daily` and `CRON_TZ=` are refused. |
| `timeZone` | `Asia/Jakarta` | `UTC` | The IANA zone the schedule is read in. |
| `timeout` | `30m` | `1h` | How long one attempt may take, from placement, so pulling the image counts. Then it is stopped and counts as failed. `1s` to `24h`. |
| `retries` | `2` | `0` | Further attempts after a failed one, after 10s, 20s, 40s, and so on up to 5 minutes. Up to 10. |
| `concurrency` | `forbid` | `forbid` | What happens when a run is due while one is active: `forbid` skips the new one, `replace` cancels the active one. |
| `history` | `10` | `5` | Finished runs kept, 1 to 50. |

A few schedules:

| Schedule | Runs |
| --- | --- |
| `*/15 * * * *` | every 15 minutes |
| `0 2 * * *` | at 02:00 every day |
| `30 6 * * 1-5` | at 06:30, Monday to Friday |
| `0 3 1 * *` | at 03:00 on the first day of each month |

## 2. Look at it

```
$ armada job list
NAME            SCHEDULE                      LAST RUN  STATE  FINISHED  NEXT RUN
nightly-report  0 2 * * * (Asia/Jakarta)      -         -      -         in 14h
```

```
$ armada job show nightly-report
Name:         nightly-report
Revision:     nightly-report--r1
Image:        ghcr.io/acme/reports:2.4.0
Schedule:     0 2 * * * (Asia/Jakarta)
Next run:     2026-11-12 02:00:00 (in 14h)
Last run:     -
Active runs:  0
```

`armada job show nightly-report -o yaml` prints the spec it runs, ready for
`armada job update --file`.

## 3. Run it now and wait

Do not wait until 02:00 to find out it works:

```
$ armada job run nightly-report --wait
Started run 1 of nightly-report.
Run 1 of nightly-report succeeded.
```

With `--wait` the command ends when the run does and exits non-zero unless
the run succeeded. `--timeout` (default 15 minutes) bounds how long it
waits; a run still going after that keeps going.

A manual run counts like a scheduled one: with `concurrency: forbid`,
`armada job run` is refused while a run is active.

## 4. Runs and logs

```
$ armada job run list nightly-report
RUN  STATE      TRIGGER   ATTEMPTS  NODE   STARTED  DURATION  EXIT  MESSAGE
3    succeeded  schedule  2         node1  7h ago   4m        0     -
2    failed     schedule  3         node2  1d ago   30m       -     timed out after 30m0s
1    succeeded  manual    1         node3  2d ago   3m        0     -
```

```bash
armada job logs nightly-report            # the newest run
armada job logs nightly-report --run 2    # another run
armada job logs nightly-report -f         # follow a run in progress
```

- Only the latest attempt's logs are kept. In run 2 above, the logs are
  those of its third attempt.
- A finished run's logs are kept for 24 hours, and runs beyond `history`
  are removed.
- `armada app events nightly-report` shows the job's runs starting,
  retrying, and ending.

## 5. Change it

```bash
armada job update nightly-report --schedule "0 3 * * *"     # flags change only what they name
armada job update nightly-report --image ghcr.io/acme/reports:2.4.1
armada job update nightly-report --file nightly-report.yaml --diff   # what the file would change
armada job update nightly-report --file nightly-report.yaml
```

Changes apply to runs that start afterwards; a run in progress keeps its
spec. `--schedule ""` clears the schedule and leaves a job you only run by
hand.

## Overlapping runs: `forbid` or `replace`

A sync every 15 minutes usually takes two. On a slow day it takes twenty,
and the next one is due while it runs.

- **`forbid`** (the default) skips the new run. Choose it when two runs at
  once would do the same work twice or fight over the same rows.
- **`replace`** cancels the active run and starts the new one. Choose it
  when only the newest data matters and a stuck run should not hold up the
  next.

```yaml
# sync-prices.yaml
kind: job
name: sync-prices
image: ghcr.io/acme/sync:1.2.0
schedule: "*/15 * * * *"
timeout: 14m
concurrency: forbid
history: 20
```

A `timeout` shorter than the interval keeps a stuck run from skipping
every following one.

## One-off tasks

For maintenance you run once, such as a reindex, a data fix, or a
migration, create a job without a schedule, run it, and wait:

```bash
printf %s 'postgres://app:...@db.internal:5432/app' | armada secret set reindex database-url
armada job create reindex --image ghcr.io/acme/api:1.4.2 --command ./bin/reindex \
  --secret-env DATABASE_URL=database-url --timeout 2h --memory 1Gi
armada job run reindex --wait --timeout 2h
armada job logs reindex
armada job delete reindex
armada secret delete reindex database-url
```

`armada job delete` removes the job, its runs, and their logs, but keeps
its secrets, hence the last line.

A migration you run before every deploy can stay as a job. A deploy script
stops if it fails:

```bash
armada job update migrate --image ghcr.io/acme/api:1.4.3
armada job run migrate --wait --timeout 10m
armada app update api --image ghcr.io/acme/api:1.4.3 --wait
```

To run migrations as part of each replica's start instead, see
[Migrations and sidecars](migrations-and-sidecars.md).

To stop runs in progress: `armada job cancel JOB`.

## Split a big run into tasks

A run that works through many items, such as a report per customer, can
be split into tasks that run side by side. Each task is a container told
its index, and takes its share of the items:

```yaml
kind: job
name: monthly-reports
image: ghcr.io/acme/worker:2.1
command: ["./bin/monthly-reports"]
schedule: "0 2 1 * *"
timeZone: Asia/Jakarta
tasks: 10          # ten tasks per run
parallelism: 5     # at most five at once, to spare the database
retries: 2         # per task
timeout: 1h        # per attempt of a task
```

```ts
const task = Number(process.env.ARMADA_JOB_TASK)    // 0 to 9
const tasks = Number(process.env.ARMADA_JOB_TASKS)  // 10
const customers = await db.query("SELECT id FROM customers WHERE id % $1 = $2", [tasks, task])
```

A failed task is retried on its own; the others keep going. The run
succeeds when all ten did, and fails once a task has no retries left (the
rest are stopped). Flags do the same: `armada job update monthly-reports
--tasks 10 --parallelism 5`.

```bash
armada job run show monthly-reports 4       # the run with each task's state
armada job logs monthly-reports --run 4 --task 7
```

## Things to know

- **At least once.** In rare failures (a node cut off mid-run, an agent
  restarting just as the container exits), a run can be attempted again.
  Make jobs safe to repeat: skip what is done, use upserts.
- **When the control plane is down.** A run due while it is down starts
  when it is back, if that is within an hour; otherwise it is skipped, with
  a `Missed` event.
- **Placement and room.** A run goes to a node that its `placement` allows
  and that has room for its `resources`, like a replica. A run that cannot
  be placed waits, and fails when its timeout passes.
- **Drained nodes.** Runs keep going on a node being drained. A run on a
  lost node counts as failed and is retried.
- **Names.** A job and an app cannot share a name. Jobs do not appear in
  `armada app list`; `armada job list` lists them.
- **Each run gets `ARMADA_JOB_RUN`**, the run number, as a variable,
  besides `ARMADA_APP`, `ARMADA_REVISION`, and `ARMADA_REPLICA`.

## Check that it works

- `armada job run JOB --wait` succeeds.
- `armada job list` shows the next run at the time you expect, in your
  time zone.
- After the first scheduled run, `armada job run list JOB` shows it with
  the trigger `schedule`.
- Alert on jobs that stop succeeding. For a daily job, this fires after 25
  hours without a success:

  ```
  time() - armada_job_last_success_timestamp_seconds{job="nightly-report"} > 90000
  ```

  `armada_job_runs_total{result="failed"}` counts failed runs. See
  [Monitoring and alerts](monitoring-and-alerts.md).

## Troubleshooting

| What you see | Why | What to do |
| --- | --- | --- |
| The job runs at the wrong hour | The schedule is read in UTC | Set `timeZone` |
| Create refused: `@daily`, or `CRON_TZ=` in the schedule | Only five cron fields are accepted | Write `0 0 * * *` and use `timeZone` |
| A run failed with `timed out after ...` | The attempt took longer than `timeout`, image pull included | Raise `timeout`, or make the work faster |
| `armada job run` is refused | `concurrency: forbid` and a run is active | Wait, or `armada job cancel JOB` |
| Scheduled runs are skipped | A run is still active under `forbid` | Look at `armada job run list`; lower the work per run, or use `replace` |
| A run stays pending, then fails at its timeout | No node allowed by placement has room for its resources | Check `armada app events JOB` and `armada node top` |
| `armada job logs` has nothing for an old run | Logs are kept 24 hours | Ship logs elsewhere if you need them longer |
| `armada job run --wait` says the run is gone | The run left the job's `history` before it was read | Raise `history` |

## Next steps

- [Workers that scale on a queue](background-workers.md): jobs that start
  when a queue holds messages.
- [Migrations and sidecars](migrations-and-sidecars.md): init containers
  and sidecars, also in jobs.
- [Deploy from CI](ci-cd.md): running a migration job from a pipeline.
- Reference: [Jobs](../spec-reference.md#jobs),
  [`armada job`](../cli/armada-job.md), [ADR 0019](../adr/0019-jobs.md).

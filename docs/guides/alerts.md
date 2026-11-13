# Get alerts in Slack, Discord, Telegram, or email

You want a message when a node drops out, a replica runs out of memory, a
rollout fails, or a backup stops working: in the chat your team already
reads, without running anything besides Armada. This guide adds an alert
channel, sends a test notice, and narrows what it receives.

**You will use:** [`armada alert`](../cli/armada-alert.md) and
[events](../operations.md#events)
**Before you start:** a running cluster ([quickstart](../quickstart.md))
and `cluster-admin` access. The control plane servers must reach the
channel: the internet for Slack, Discord, and Telegram, or your mail
server.

## How it works

```
  something happens ──> event (armada cluster events)
                             │
                             │  needs a person? (or the reasons you chose)
                             v
        leader ──> ops (Slack) · oncall (Telegram) · mail (email) · hook (webhook)
```

- Armada already records what the cluster does as
  [events](../operations.md#events). The leader sends a **notice** for each
  new event a channel wants.
- By default a channel gets only the events that need a person (the
  [list](#what-is-sent) is below). Deploys, scaling, and replicas starting
  are not sent.
- A lasting problem, such as a lost node, sends one notice when it starts
  and one **Resolved** notice when it is over, not one a minute.
- The same event again within 10 minutes is not sent again. A channel gets
  at most 20 notices a minute; the rest are summed up in one notice
  ("12 more notices were held back").
- A notice that cannot be sent is tried three times over about 12 seconds.
  `armada alert channel list` shows how sending went.

## 1. Add a channel

Pick the one your team uses. The URL, token, or password is read from a
file or from stdin (`-`), never from the command line, because shell
history keeps that. It is stored encrypted and never shown again.

### Slack

1. In Slack, create an app at <https://api.slack.com/apps> → **Incoming
   Webhooks** → turn it on → **Add New Webhook to Workspace** → pick the
   channel. Copy the URL (`https://hooks.slack.com/services/...`).
2. Add it to Armada:

```bash
armada alert channel create ops --type slack --url -
# paste the URL, then Enter and Ctrl-D
```

### Discord

1. In Discord: **Server Settings → Integrations → Webhooks → New
   Webhook**, pick the channel, **Copy Webhook URL**.
2. Add it:

```bash
armada alert channel create ops --type discord --url - < discord-webhook-url
```

Notices never ping anyone: `@everyone` in a message stays plain text.

### Telegram

1. Talk to [@BotFather](https://t.me/BotFather): `/newbot`, and copy the
   token it gives you (`123456789:AA...`).
2. Add the bot to your group (or channel, as an admin) and send it a
   message.
3. Find the chat ID: open
   `https://api.telegram.org/bot<token>/getUpdates` in a browser and read
   `"chat":{"id":-100...}`. Groups have negative IDs. A public channel can
   use `@channelname` instead.
4. Add it:

```bash
armada alert channel create oncall --type telegram --chat-id -1001234567890 --token - < bot-token
```

### Email

Any SMTP server works: your company's, or a sending service. Port 465
uses TLS; other ports (587, 25) must offer STARTTLS. Plain SMTP without
TLS is only allowed to a private IP address, such as a relay inside your
network.

```bash
armada alert channel create mail --type email \
  --smtp-host smtp.example.com:587 --smtp-user alerts@example.com --password - \
  --from alerts@example.com --to ops@example.com,cto@example.com < smtp-password
```

- `--to` takes up to 10 addresses. The subject reads
  `[armada example.com] Lost: node app-02`.
- Leave out `--smtp-user` and `--password` for a relay that needs no login.
  A password is only ever sent over TLS.
- Mail providers that use two-step sign-in usually want an app password
  here, not the account's password; their SMTP documentation names the
  host and port.

### Your own webhook

Anything that takes an HTTP POST: an incident tool, a chat bridge, a small
script.

```bash
armada alert channel create hook --type webhook --url - < hook-url
```

Each notice is one JSON object:

```json
{
  "type": "event",
  "cluster": "example.com",
  "reason": "OutOfMemory",
  "object": "app api.shop",
  "space": "shop",
  "app": "api",
  "node": "",
  "message": "processes were killed at the memory limit (512Mi)",
  "count": 1,
  "time": "2026-11-13T07:40:00Z"
}
```

`type` is `event`, `resolved` (the problem is over), `summary` (notices
held back by the rate limit), or `test`. A `2xx` answer counts as sent.
Redirects are not followed.

URLs must be `https://`, or `http://` to a private IP address. The
cluster's name in each notice is its root domain, or the leader's name
when there is none.

## 2. Send a test notice

```bash
armada alert test ops
```

```
Sent a test notice to ops.
```

The command waits for the channel to answer. A wrong URL, token, chat, or
mail server shows here at once, with the reason (without the secret):

```
Error: the test notice was not sent: channel answered 403: {"ok":false,"error_code":403,"description":"Forbidden: bot is not a member of the group chat"}
```

## 3. Choose what each channel gets

```bash
# only events of the apps in these spaces (node and certificate events are left out then)
armada alert channel update ops --space shop,billing

# only these reasons, instead of the default
armada alert channel update oncall --reason Lost,OutOfMemory,Crashed

# every event, deploys included (busy!)
armada alert channel update audit --reason all

# back to the default
armada alert channel update ops --space '' --reason ''
```

A common setup: one channel per team with `--space`, plus one on-call
channel with the default reasons for everything.

## 4. See how sending goes

```bash
armada alert channel list
```

```
CHANNEL  TYPE      TO                               SPACES  REASONS             SENT  FAILED  LAST SENT  LAST ERROR
mail     email     ops@example.com,cto@example.com  -       warnings               3       0  2h ago     -
oncall   telegram  -1001234567890                   -       Lost,OutOfMemory       1       0  1d ago     -
ops      slack     -                                shop    warnings              12       1  5m ago     channel answered 500
```

`SENT` and `FAILED` count from when the current leader started. With
Prometheus, `armada_alerts_sent_total`, `armada_alerts_failed_total`, and
`armada_alerts_dropped_total` (by `channel`) show the same; alert on
`increase(armada_alerts_failed_total[1h]) > 0` to learn that alerts
themselves stopped working.

Change a secret, or remove a channel:

```bash
armada alert channel update ops --url - < new-url
armada alert channel delete ops
```

## What is sent

Without `--reason`, a channel gets these. Each is also an
[event](../operations.md#events) you can read with `armada cluster events`
or `armada app events`.

| Reason | Means |
| --- | --- |
| `Lost` | A node stopped reporting; its replicas move (Resolved when it is back) |
| `Crashed` | A replica's container exited and is restarted |
| `OutOfMemory` | Processes in a replica were killed at its memory limit |
| `Failed` | A rollout made no progress, a job run failed, or a certificate could not be obtained |
| `Unschedulable` | No node has room or matches the placement for a replica |
| `MostUnreachable` | Most nodes stopped reporting at once; the leader holds back |
| `ReconcileFailed` | The control plane could not converge an app |
| `ProxyNotUpdated` | The ingress configuration could not be rebuilt; the last good one serves |
| `NotVerified` | A custom domain's DNS record is missing |
| `QueueUnread` | No node can read the queue that starts a job |
| `LogExportFailing` | A node cannot send logs to the log store |
| `VolumeUnavailable`, `VolumesSplit`, `VolumeOnCordonedNode` | An app with a volume cannot run where its volume is |
| `VolumeBackupFailed`, `VolumeBackupUnsupported` | Scheduled volume backups do not work |
| `VolumeFailedOver`, `VolumeFailoverFailed` | A volume was restored on another node, or could not be |

Any other reason can be named with `--reason`, such as `Deployed`,
`Scheduled`, `Restarted`, `NotReady`, `RolledBack` (someone ran `armada app rollback`), or `Joined`.

## Check that it works

1. `armada alert test ops` answers `Sent a test notice to ops.` and the
   message is in the chat.
2. For an end-to-end check, stop the agent of a test node that runs
   nothing important: `sudo systemctl stop armada-agent` on that node. After the node-lost timeout (`armada cluster show`) a `Lost`
   notice arrives; start the agent again and a `Resolved` notice follows.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `channel answered 404` (Slack, Discord) | The webhook was deleted or the URL is cut | Create a new webhook; `armada alert channel update NAME --url -` |
| `channel answered 400: chat not found` (Telegram) | Wrong chat ID, or the bot was never added to the chat | Add the bot, send it a message, read the ID from `getUpdates` again |
| `channel answered 403` (Telegram) | The bot was removed, or cannot post in the channel | Add it again; in channels make it an admin |
| `smtp: 535 ...` | Wrong user or password, or the provider needs an app password | Check the login; `--password -` to replace it |
| `smtp: the server offers no STARTTLS` | Plain SMTP to a public server | Use port 465, or a port with STARTTLS |
| `context deadline exceeded`, `connection refused` | The servers cannot reach the channel | Check outbound access from the control plane servers (firewall, proxy) |
| Nothing arrives, `SENT` stays 0 | Nothing happened that the channel wants | `armada alert test NAME`; check `--space` and `--reason` in the list |
| Notices stop for a moment when servers restart | Notices waiting in the old leader's memory are lost when it stops | Nothing to do; `armada cluster events` still has every event for 24 hours |

## Next steps

- [Monitoring and alerts](monitoring-and-alerts.md): Prometheus metrics and
  rules for thresholds that are not events, such as a node almost full.
- [Troubleshooting](troubleshooting.md): what to do when a notice arrives.
- [ADR 0045](../adr/0045-alerts.md): how alerts are designed.

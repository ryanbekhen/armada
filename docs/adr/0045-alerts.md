# 0045. Alerts

- Status: Accepted
- Date: 2026-11-13

## Context

The leader records what the cluster does as events (ADR 0018), and the
metrics endpoint (ADR 0017) lets Prometheus alert on them. A team without
Prometheus and Alertmanager, which is most small teams, learns about a
lost node or a crashing app only when it looks, or when users complain.
The events that need a person are already known to the leader the moment
they happen.

## Decision

The leader sends a notice about events that need a person to channels the
cluster names: a JSON webhook, Slack, Discord, Telegram, or email over
SMTP. Nothing runs besides Armada, and agents are unchanged.

### Channels

- `armada alert channel create NAME --type webhook|slack|discord|telegram|email`
  with the type's fields (`--chat-id`; `--smtp-host`, `--smtp-user`,
  `--from`, `--to`), and its secret from a file or stdin: `--url` (webhook,
  Slack, Discord), `--token` (Telegram bot token), or `--password` (SMTP).
  `update` changes only the fields given (the type stays), `list` shows
  each channel with how sending went since the leader started, `delete`
  removes it, and `armada alert test NAME` sends a test notice and waits
  for the answer. At most 32 channels.
- Channels live in the meta record `alerts`; each secret is sealed with
  the master key (scope `cluster`, name `alert-<channel>`, versioned),
  opened only by the leader to send. Only cluster-admins call these RPCs;
  changes are audited without the secret.
- URLs are `https://`, or `http://` to a private IP address, with no
  credentials before the host. Redirects are not followed. Telegram posts
  to the Bot API's `sendMessage`. Email uses TLS on port 465 and STARTTLS
  on other ports; plain SMTP is allowed only to a private IP address, and a
  password is only sent over TLS. Headers carry only checked addresses
  and a subject with control characters replaced.

### What is sent

- A channel gets the events whose reason needs a person (`alert.Warning`:
  `Lost`, `Crashed`, `OutOfMemory`, `Failed`, `Unschedulable`,
  `MostUnreachable`, `ReconcileFailed`, `ProxyNotUpdated`, `NotVerified`,
  `QueueUnread`, `LogExportFailing`, and the volume failures), unless it
  names its own reasons (`--reason`, `all` for every one). `--space` keeps
  only events of those spaces' apps.
- `Server.record` queues a notice for a new event; a repeat that the event
  history folds into an earlier event (same object and reason within 10
  minutes) is not sent again. When a condition (`Server.condition`, such
  as a lost node) clears, a `resolved` notice follows.
- Notices carry the cluster's root domain (else the leader's name), the
  reason, the object, space, app, node, the event's message, its count,
  and its time; never anything events do not already hold.

### Delivery

- Each channel has its own queue (256) and worker on the leader, so a slow
  channel holds up no other and recording an event never waits. A full
  queue drops the notice and counts it.
- At most 20 notices go per channel at once, refilled at 20 a minute; the
  ones held back are summed up in one notice before the next that goes.
- A notice is tried three times (waits of 2 s and 10 s). Counts and the
  last error are kept in memory and shown by `armada alert channel list`
  and the metrics `armada_alerts_sent_total`,
  `armada_alerts_failed_total`, `armada_alerts_dropped_total` by channel.
- Notices waiting when a leader stops are lost; the events stay in the
  event history.

## Consequences

- A team learns about trouble in the chat it reads, with one command and
  no other software.
- The control plane servers need to reach the channels: the internet for
  the hosted ones, or a mail server.
- Notices leave the cluster: what events say about apps and nodes is sent
  to a third party. Events never hold secrets or environment values (ADR
  0018), so neither do notices.
- Thresholds that are not events (a node almost full, a backup that is
  stale) still need Prometheus rules.

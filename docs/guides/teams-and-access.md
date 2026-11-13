# Give a team access to one space

Several people work on the cluster, and not all of them should be able to
do everything. This guide gives each person a certificate of their own,
lets a developer deploy to one space and read nothing else, and shows
how to take access back and see who did what.

**You will use:** [spaces](../operations.md#spaces),
[access control](../operations.md#access-control) (users, roles,
assignments), [`armada rbac`](../cli/armada-rbac.md)
**Before you start:** a running cluster ([quickstart](../quickstart.md)) and
a client config with `cluster-admin` (the user `armadad init` created has
it). Only `cluster-admin` manages access.

## The setup

```
  space shop                     space billing
  +---------------------------+    +---------------------------+
  | api, web, worker          |    | invoices                  |
  |                           |    |                           |
  | alice: deployer           |    | bob: admin                |
  | bob:   viewer             |    |                           |
  +---------------------------+    +---------------------------+

  carol: viewer over the whole cluster (on call)
  dana:  space-creator (makes spaces of her own)
  ops:   cluster-admin (you: nodes, servers, settings, access)
```

Each person is a **user** with a certificate under their own name, valid
for a year. What they may do comes from **assignments**: a role, and the
space it applies in.

## 1. Know the roles

```bash
armada rbac role list
```

| Role | Given in | Allows |
| --- | --- | --- |
| `viewer` | a space, or the whole cluster | apps, jobs, revisions, specs, secret names, domains, volumes, logs, usage, events |
| `deployer` | a space (not `default`) | what a viewer may, and deploy, scale, roll back, split traffic, set secrets, run jobs, verify domains |
| `admin` | a space (not `default`) | what a deployer may, and exec, volume backup, restore, and delete, deleting apps and jobs |
| `space-creator` | the cluster | creating spaces (becoming `admin` of each) and deleting empty ones it is `admin` of |
| `cluster-admin` | the cluster | everything: nodes, servers, cluster settings, tokens, metrics credentials, access control |

`armada rbac role show deployer` lists the API methods a role allows. A
person's rights in a space are the most their assignments give there.

Only `viewer` can be given in the `default` space: its containers may
reach the platform unless you isolate it, so deploying there needs
`cluster-admin`. Put team apps in spaces of their own.

## 2. Create the space and the user

```bash
armada space create shop
armada rbac user create alice -o alice.config --role deployer --space shop
```

```
Wrote alice.config for user:alice (valid until 2027-11-11); it holds a private key, hand it over privately.
```

The file holds Alice's private key, made on your machine. Hand it over
the way you would hand over a password, and delete your copy afterwards.
Never let two people share one file: the audit log and revocation work per
name.

## 3. Alice sets up her computer

Alice installs the client and keeps the file as her config:

```bash
curl -fsSL https://raw.githubusercontent.com/ryanbekhen/armada/main/install.sh | sudo ARMADA_CLIENT_ONLY=1 sh
install -d -m 0700 ~/.armada
install -m 0600 alice.config ~/.armada/config
armada space use shop
armada app list
```

Her computer must reach a control plane server's private address on port
7443, through a VPN or an SSH tunnel (see the
[quickstart](../quickstart.md#9-use-armada-from-your-own-computer)).

She sees only `shop`: `armada space list` lists the spaces she holds a
role in, `armada app events` and `armada cluster events` show only events
of apps she may see, `armada node list` shows no nodes, and commands that
need `cluster-admin` (`armada server list`, `armada cluster events
--node`, node and access commands) are refused.

## 4. Give more roles

```bash
armada rbac user create bob -o bob.config --role admin --space billing
armada rbac assignment create --user bob --role viewer --space shop
armada rbac user create carol -o carol.config --role viewer         # every space, read only
armada rbac user create dana -o dana.config --role space-creator  # dana creates her own spaces
armada rbac assignment list
```

```
KIND  NAME   ROLE             SPACE
user  alice  deployer         shop
user  bob    admin            billing
user  bob    viewer           shop
user  carol  viewer           (cluster)
user  dana   space-creator  (cluster)
user  ops    cluster-admin    (cluster)
```

A role applies to the next command the person runs; nothing needs to be
reissued. A user with `space-creator` becomes `admin` of each space
she creates, and may delete it once it is empty.

## 5. Let a team use its own nodes

When some nodes are kept for a team with a label and `armada node
restrict`, its apps name the label in `placement.require`. A person
without `cluster-admin` may only name labels you allow them:

```bash
armada node label node-4 tier=shop
armada node restrict node-4
armada rbac user update alice --allow-label tier=shop
```

```yaml
# web.yaml
name: web
image: ghcr.io/acme/web:2.1.0
ingress:
  type: external
  port: 8080
placement:
  require:
    tier: shop
```

Without the allowance, `armada app create --file web.yaml` is refused with
`user:alice may not require node label tier=shop`. `armada.os` and
`armada.arch` are always allowed. `--clear-labels` takes every allowance
back.

## 6. Take access back

| You want to | Run |
| --- | --- |
| Take one role away | `armada rbac assignment delete --user bob --role viewer --space shop` |
| Replace a lost or leaked key | `armada rbac user credentials alice -o alice.config` (her older certificates stop working at once) |
| Remove a person | `armada rbac user delete alice --yes` (every certificate of `alice` is refused, on every server) |

A deleted user stays in `armada rbac user list` as `deleted`, so the name
keeps its history. Nobody can delete themselves or take their own
`cluster-admin`, so the cluster always keeps one.

Removing access does not change what a person deployed: the apps keep
running under the space.

## 7. See who did what

```bash
armada rbac user list
```

```
NAME   ROLES                                STATUS        CREATED BY
alice  deployer in shop                     active        user:ops
bob    admin in billing, viewer in shop     active        user:ops
carol  viewer                               active        user:ops
dana   space-creator                      active        user:ops
ops    cluster-admin                        active (you)  -
```

- Every change through the API (deploys, scaling, secrets, exec sessions,
  role changes, removals) is written to the cluster's audit log with the
  caller's name, such as `user:alice`. This version has no command that
  lists the audit log; the leader's log carries the same names
  (`journalctl -u armada-server`, look for `by=user:alice`; `armada server
  list` shows which server leads).
- `armada secret list APP` names who set each secret (`BY`), and
  `armada space list` who created each space.
- `armada app events` records removals with the caller, for example
  `Removing  by user:alice`.
- Exec sessions are audited with the command's name, never its arguments.

## 8. Renew certificates

A user certificate lasts a year. Each person renews their own before it
expires:

```bash
armada rbac user renew
```

```
Renewed user:alice (valid until 2028-11-10).
```

`armadad doctor` warns 30 days ahead about the certificate in the client
config. An expired certificate cannot renew itself; renew it on a control
plane server as root, with the CA in its data directory, and hand the file
over again:

```bash
sudo armadad user renew --config /home/alice/.armada/config   # on a server, a copy of her file
```

Roles stay as they are on record.

## Check that it works

From Alice's computer:

```bash
armada app list                       # shop's apps
armada app list --space billing     # refused: user:alice may not see space billing
armada app scale web --replicas 3     # allowed: deployer
armada app exec web -- env            # refused: exec needs admin
```

## Variations

**On call.** A cluster-wide `viewer` sees every space's apps, logs, and
events, but no nodes. Give on-call people `cluster-admin` only if they
must drain nodes or restore backups.

**Staging and production.** Create `shop-staging` and `shop`, give the
team `deployer` in staging and `viewer` in production, and let the
[CI pipeline](ci-cd.md) deploy to production with a service of its own.

**People on a server.** Members of the `armada` group on a server can use
the shared `/etc/armada/admin.config`. That is full control under the first
user's name, so prefer a certificate per person.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `user:alice may not deploy to space default` | No space chosen, so the command works in `default` | `armada space use shop`, or `--space shop` |
| `user:alice has no role that allows ...` | The method needs a role she does not hold (exec, node commands) | Give the role, or run it yourself |
| `... has mode 0644, want 0600` | The config file is readable by others | `chmod 600 ~/.armada/config` |
| `armada rbac user renew` fails with an expired certificate | Expired certificates cannot renew themselves | `sudo armadad user renew --config FILE` on a server |

## Next steps

- [Deploy from CI](ci-cd.md): a service with its own role.
- [Monitoring and alerts](monitoring-and-alerts.md): a metrics certificate that can only scrape.
- [Spaces and network isolation](../operations.md#spaces).
- [`armada rbac`](../cli/armada-rbac.md) reference.
